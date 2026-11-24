//! Connection setup: NEGOTIATE, SESSION_SETUP (NTLMv2 through SPNEGO), key
//! derivation, TREE_CONNECT, FSCTL_VALIDATE_NEGOTIATE_INFO, LOGOFF.

use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_smb_proto::auth::{AuthStep, Authenticator, NtlmConfig, NtlmCredentials, SpnegoClient};
use fsfast_smb_proto::crypto::{
    Cipher, PreauthHasher, Signer, SigningAlgorithm, SmbCipher, derive_session_keys, random_bytes,
};
use fsfast_smb_proto::fscc::AccessMask;
use fsfast_smb_proto::header::{Command, Header};
use fsfast_smb_proto::msg::{
    CipherId, FsctlData, HashAlgorithm, IoctlRequest, IoctlResponse, LogoffRequest,
    LogoffResponse, Message, NegotiateContext, NegotiateRequest, NegotiateResponse,
    SessionFlags, SessionSetupRequest, SessionSetupResponse, ShareFlags, ShareType,
    SigningAlgorithmId, TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest,
    TreeDisconnectResponse, ValidateNegotiateInfoRequest, ValidateNegotiateInfoResponse,
    encode_message, fsctl,
};
use fsfast_smb_proto::{Capabilities, Dialect, FileId, Guid, NtStatus, SecurityMode};

use crate::config::SmbConfig;
use crate::conn::{Connection, Negotiated, Security, SessionCrypto, recv_all};

/// A connected share.
#[derive(Debug)]
pub(crate) struct Tree {
    pub tree_id: u32,
    /// Requests on this tree go inside a TRANSFORM_HEADER.
    pub encrypt: bool,
    /// Kept for `Debug` output (logs).
    #[allow(dead_code)]
    pub share: String,
    #[allow(dead_code)]
    pub flags: ShareFlags,
    #[allow(dead_code)]
    pub maximal_access: AccessMask,
}

/// A request header for `cmd` carrying the request's credit charge.
pub(crate) fn header_for<M: Message>(
    body: &M,
    session_id: u64,
    tree_id: u32,
    multi_credit: bool,
) -> Header {
    let mut h = Header::request(M::COMMAND);
    h.session_id = session_id;
    h.set_tree_id(tree_id);
    h.credit_charge = if multi_credit { body.credit_charge() } else { 0 };
    h
}

/// Send one request and wait for its response.
async fn call<M: Message>(
    conn: &Connection,
    body: &M,
    session_id: u64,
    tree_id: u32,
    sec: &Security,
) -> Result<fsfast_smb_proto::msg::RawMessage> {
    let h = header_for(body, session_id, tree_id, conn.shared.multi_credit());
    let m = encode_message(&h, body)?;
    let r = conn.shared.send(vec![m], sec).await?;
    Ok(recv_all(r).await?.remove(0))
}

/// NEGOTIATE ([MS-SMB2] §3.2.4.2.2.2): offers the configured dialects with
/// 3.1.1 contexts (SHA-512 preauth integrity, AES-128-GCM preferred
/// encryption, AES-GMAC preferred signing). Returns the negotiated
/// parameters and the preauth hash after NEGOTIATE (3.1.1).
pub(crate) async fn negotiate(conn: &Connection, cfg: &SmbConfig) -> Result<(Negotiated, PreauthHasher)> {
    let dialects = cfg.dialects();
    if dialects.is_empty() {
        return Err(Error::invalid_input("smb: no dialect in the configured range"));
    }
    let mut security_mode = SecurityMode::SIGNING_ENABLED;
    if cfg.require_signing {
        security_mode |= SecurityMode::SIGNING_REQUIRED;
    }
    let mut capabilities = Capabilities::empty();
    if dialects.iter().any(|d| d.supports_multi_credit()) {
        capabilities |= Capabilities::LARGE_MTU;
    }
    if dialects.iter().any(|d| d.is_smb3()) {
        capabilities |= Capabilities::ENCRYPTION;
    }
    // [MS-SMB2] §2.2.3: ClientGuid is zero when only 2.0.2 is offered.
    let client_guid = if dialects == [Dialect::SMB_2_0_2] {
        Guid::default()
    } else {
        Guid::random()
    };
    let mut contexts = Vec::new();
    if dialects.contains(&Dialect::SMB_3_1_1) {
        let mut salt = [0u8; 32];
        random_bytes(&mut salt);
        contexts.push(NegotiateContext::PreauthIntegrity {
            hash_algorithms: vec![HashAlgorithm::SHA512],
            salt: Bytes::copy_from_slice(&salt),
        });
        // AES-128-GCM first: fastest with AES-NI/PCLMUL and what Windows
        // prefers; the others for servers configured differently.
        contexts.push(NegotiateContext::Encryption {
            ciphers: vec![
                CipherId::AES_128_GCM,
                CipherId::AES_128_CCM,
                CipherId::AES_256_GCM,
                CipherId::AES_256_CCM,
            ],
        });
        contexts.push(NegotiateContext::Signing {
            algorithms: vec![
                SigningAlgorithmId::AES_GMAC,
                SigningAlgorithmId::AES_CMAC,
                SigningAlgorithmId::HMAC_SHA256,
            ],
        });
        contexts.push(NegotiateContext::NetName(cfg.connect_host().to_owned()));
    }
    let req = NegotiateRequest {
        security_mode,
        capabilities,
        client_guid,
        dialects: dialects.clone(),
        negotiate_contexts: contexts,
    };
    let h = Header::request(Command::NEGOTIATE);
    let m = encode_message(&h, &req)?;
    let (r, sent) = conn.shared.send_capture(vec![m], &Security::none()).await?;
    let raw = recv_all(r).await?.remove(0);
    if raw.is_error_response() {
        return Err(raw.status().to_error(None));
    }
    let n: NegotiateResponse = raw.decode()?;
    let dialect = n.dialect_revision;
    if !dialects.contains(&dialect) {
        return Err(Error::protocol(format!(
            "SMB server selected dialect {dialect}, which was not offered"
        ))
        .with_retryable(false));
    }
    let mut preauth = PreauthHasher::new();
    let cipher = if dialect.is_3_1_1() {
        match n.preauth_integrity() {
            Some((HashAlgorithm::SHA512, _)) => {}
            _ => {
                return Err(Error::protocol(
                    "SMB 3.1.1 server did not select SHA-512 preauth integrity",
                )
                .with_retryable(false));
            }
        }
        preauth.update(&sent[0]);
        preauth.update(raw.bytes());
        n.cipher().and_then(Cipher::from_id)
    } else if dialect.is_smb3() && n.capabilities.contains(Capabilities::ENCRYPTION) {
        Some(Cipher::Aes128Ccm)
    } else {
        None
    };
    if cfg.encrypt == Some(true) && cipher.is_none() {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!(
                "SMB encryption was requested but the server ({dialect}) does not support it"
            ),
        )
        .with_retryable(false));
    }
    tracing::debug!(
        conn = conn.shared.id,
        %dialect,
        max_read = n.max_read_size,
        max_write = n.max_write_size,
        ?cipher,
        signing = ?n.signing_algorithm(),
        "SMB negotiated"
    );
    Ok((
        Negotiated {
            dialect,
            max_read_size: n.max_read_size,
            max_write_size: n.max_write_size,
            max_transact_size: n.max_transact_size,
            server_guid: n.server_guid,
            server_security_mode: n.security_mode,
            server_capabilities: n.capabilities,
            client_guid,
            client_security_mode: security_mode,
            client_capabilities: capabilities,
            offered_dialects: dialects,
            cipher,
            signing_algorithm: n.signing_algorithm(),
            security_buffer: n.security_buffer.clone(),
        },
        preauth,
    ))
}

/// Credentials for NTLM: `DOMAIN\user`, `user@REALM`, and fsfast also
/// accepts fsspec's URL form `workgroup;user`. No user name means an
/// anonymous (null) session.
pub(crate) fn credentials(cfg: &SmbConfig) -> NtlmCredentials {
    match cfg.username.as_deref().filter(|u| !u.is_empty()) {
        None => NtlmCredentials::anonymous(),
        Some(user) => {
            let pw = cfg.password.as_deref().unwrap_or("");
            match user.split_once(';') {
                Some((domain, u)) if !user.contains('\\') => {
                    NtlmCredentials::with_domain(domain, u, pw)
                }
                _ => NtlmCredentials::new(user, pw),
            }
        }
    }
}

/// SESSION_SETUP with NTLMv2 through SPNEGO ([MS-SMB2] §3.2.4.2.3,
/// §3.2.5.3), then key derivation and the signing/encryption policy.
pub(crate) async fn session_setup(
    conn: &Connection,
    cfg: &SmbConfig,
    neg: &Negotiated,
    conn_preauth: &PreauthHasher,
) -> Result<Arc<SessionCrypto>> {
    let creds = credentials(cfg);
    let anonymous = creds.is_anonymous();
    let ntlm_cfg = NtlmConfig {
        target_spn: Some(format!("cifs/{}", cfg.connect_host())),
        ..Default::default()
    };
    let mut auth = SpnegoClient::ntlm_with_config(creds, ntlm_cfg);
    let mut step = auth.step(&neg.security_buffer)?;
    let mut preauth = conn_preauth.clone();
    let mut security_mode = SecurityMode::SIGNING_ENABLED;
    if cfg.require_signing {
        security_mode |= SecurityMode::SIGNING_REQUIRED;
    }
    let dialect = neg.dialect;
    let mut session_id = 0u64;
    loop {
        let token = step
            .token()
            .ok_or_else(|| Error::protocol("SPNEGO produced no token to send"))?
            .to_vec();
        let req = SessionSetupRequest {
            security_mode,
            security_buffer: Bytes::from(token),
            ..Default::default()
        };
        let h = header_for(&req, session_id, 0, conn.shared.multi_credit());
        let m = encode_message(&h, &req)?;
        let (r, sent) = conn.shared.send_capture(vec![m], &Security::none()).await?;
        let raw = recv_all(r).await?.remove(0);
        if dialect.is_3_1_1() {
            preauth.update(&sent[0]);
        }
        if session_id == 0 {
            session_id = raw.header().session_id;
        }
        match raw.status() {
            NtStatus::MORE_PROCESSING_REQUIRED => {
                if dialect.is_3_1_1() {
                    preauth.update(raw.bytes());
                }
                let r: SessionSetupResponse = raw.decode()?;
                step = auth.step(&r.security_buffer)?;
                if step.is_done() && step.token().is_none() {
                    return Err(Error::protocol(
                        "authentication finished on the client before the server",
                    ));
                }
            }
            NtStatus::SUCCESS => {
                let r: SessionSetupResponse = raw.decode()?;
                if !auth.is_complete() {
                    match auth.step(&r.security_buffer)? {
                        AuthStep::Done(None) => {}
                        _ => {
                            return Err(Error::protocol(
                                "server accepted the session before authentication completed",
                            ));
                        }
                    }
                }
                let guest = r.session_flags.contains(SessionFlags::IS_GUEST);
                let null = r.session_flags.contains(SessionFlags::IS_NULL) || anonymous;
                let server_requires_signing = neg
                    .server_security_mode
                    .contains(SecurityMode::SIGNING_REQUIRED);
                let encrypt_all =
                    r.session_flags.contains(SessionFlags::ENCRYPT_DATA) || cfg.encrypt == Some(true);
                if guest || null {
                    // [MS-SMB2] §3.2.5.3.1: guest and anonymous sessions have no
                    // usable keys, so they can neither sign nor encrypt.
                    if cfg.require_signing || server_requires_signing || encrypt_all {
                        return Err(Error::permission_denied(format!(
                            "the SMB server granted a {} session, which cannot be signed or \
                             encrypted (set require_signing=False to allow unsigned guest access)",
                            if guest { "guest" } else { "anonymous" }
                        ))
                        .with_retryable(false));
                    }
                    tracing::warn!(peer = %conn.shared.peer, guest, "unsigned SMB {} session",
                        if guest { "guest" } else { "anonymous" });
                    return Ok(Arc::new(SessionCrypto {
                        session_id,
                        signer: None,
                        signing: false,
                        encryptor: None,
                        decryptor: None,
                        encrypt_all: false,
                    }));
                }
                let key = auth
                    .session_key()
                    .ok_or_else(|| Error::protocol("authentication produced no session key"))?;
                let hash = dialect.is_3_1_1().then(|| *preauth.value());
                let keys = derive_session_keys(dialect, key, hash.as_ref(), neg.cipher)?;
                let alg = SigningAlgorithm::for_dialect(dialect, neg.signing_algorithm)?;
                let signer = Signer::new(alg, &keys.signing_key[..])?;
                // The final response is signed with the new key: always in
                // 3.1.1, otherwise when signing is in use.
                if raw.header().is_signed() {
                    signer.verify(raw.bytes()).map_err(|e| {
                        Error::from(e).with_retryable(false)
                    })?;
                } else if dialect.is_3_1_1() {
                    return Err(Error::protocol(
                        "SMB 3.1.1 server did not sign the final SESSION_SETUP response",
                    )
                    .with_retryable(false));
                }
                let (encryptor, decryptor) = match (neg.cipher, &keys.encryption_key, &keys.decryption_key)
                {
                    (Some(c), Some(ek), Some(dk)) => {
                        (Some(SmbCipher::new(c, ek)?), Some(SmbCipher::new(c, dk)?))
                    }
                    _ => (None, None),
                };
                if encrypt_all && encryptor.is_none() {
                    return Err(Error::new(
                        ErrorKind::Unsupported,
                        "the SMB session requires encryption but no cipher was negotiated",
                    )
                    .with_retryable(false));
                }
                let signing = cfg.require_signing || server_requires_signing;
                tracing::debug!(
                    conn = conn.shared.id,
                    session = format_args!("{session_id:#x}"),
                    ?alg,
                    signing,
                    encrypt_all,
                    "SMB session established"
                );
                return Ok(Arc::new(SessionCrypto {
                    session_id,
                    signer: Some(signer),
                    signing,
                    encryptor,
                    decryptor,
                    encrypt_all,
                }));
            }
            status => {
                let e = status.to_error(None);
                // Bad credentials are never worth retrying.
                return Err(if e.kind() == ErrorKind::PermissionDenied {
                    e.with_retryable(false)
                } else {
                    e
                });
            }
        }
    }
}

/// TREE_CONNECT to `\\host\share`.
pub(crate) async fn tree_connect(
    conn: &Connection,
    crypto: &Arc<SessionCrypto>,
    cfg: &SmbConfig,
    share: &str,
) -> Result<Tree> {
    let req = TreeConnectRequest {
        path: format!("\\\\{}\\{}", cfg.connect_host(), share),
        ..Default::default()
    };
    let sec = Security {
        session: Some(crypto.clone()),
        encrypt: crypto.encrypt_all,
        force_sign: false,
    };
    let raw = call(conn, &req, crypto.session_id, 0, &sec).await?;
    let share_path = format!("/{share}");
    if raw.is_error_response() {
        return Err(raw.status().to_error(Some(&share_path)));
    }
    let tc: TreeConnectResponse = raw.decode()?;
    let tree_id = raw.header().tree_id().unwrap_or(0);
    if tc.share_type != ShareType::DISK {
        return Err(Error::new(
            ErrorKind::Unsupported,
            format!("SMB share {share:?} is not a disk share"),
        )
        .with_path(share_path));
    }
    let encrypt = crypto.encrypt_all || tc.share_flags.contains(ShareFlags::ENCRYPT_DATA);
    if encrypt && crypto.encryptor.is_none() {
        return Err(Error::permission_denied(format!(
            "SMB share {share:?} requires encryption, which this session cannot do"
        ))
        .with_path(share_path));
    }
    tracing::debug!(conn = conn.shared.id, share, tree_id, encrypt, flags = ?tc.share_flags, "SMB tree connected");
    Ok(Tree {
        tree_id,
        share: share.to_owned(),
        encrypt,
        flags: tc.share_flags,
        maximal_access: tc.maximal_access,
    })
}

/// FSCTL_VALIDATE_NEGOTIATE_INFO ([MS-SMB2] §3.2.5.14.12), required for
/// 3.0 and 3.0.2 on signed sessions: detects a man in the middle that
/// downgraded the NEGOTIATE.
pub(crate) async fn validate_negotiate(
    conn: &Connection,
    crypto: &Arc<SessionCrypto>,
    tree: &Tree,
) -> Result<()> {
    let n = conn.neg();
    let req = ValidateNegotiateInfoRequest {
        capabilities: n.client_capabilities,
        guid: n.client_guid,
        security_mode: n.client_security_mode,
        dialects: n.offered_dialects.clone(),
    };
    let io = IoctlRequest::fsctl(
        fsctl::VALIDATE_NEGOTIATE_INFO,
        FileId::RELATED,
        req.to_bytes()?,
        24,
    );
    let sec = Security {
        session: Some(crypto.clone()),
        encrypt: tree.encrypt,
        force_sign: true,
    };
    let raw = call(conn, &io, crypto.session_id, tree.tree_id, &sec).await?;
    let fail = |why: String| {
        conn.kill(&why);
        Err(Error::protocol(format!("SMB secure negotiate failed: {why}")).with_retryable(false))
    };
    // The response must be authenticated (signed, or inside an encrypted
    // frame on an encrypted tree), or the check is worthless.
    if !raw.header().is_signed() && !tree.encrypt {
        return fail("VALIDATE_NEGOTIATE_INFO response is not signed".into());
    }
    if raw.is_error_response() {
        // Servers that predate the FSCTL answer with these statuses (signed,
        // which `recv` verified); anything else is a failure.
        return match raw.status() {
            NtStatus::NOT_SUPPORTED | NtStatus::INVALID_DEVICE_REQUEST | NtStatus::FILE_CLOSED => {
                Ok(())
            }
            s => fail(format!("VALIDATE_NEGOTIATE_INFO returned {s}")),
        };
    }
    let resp: IoctlResponse = raw.decode()?;
    let v = ValidateNegotiateInfoResponse::decode(&resp.output)?;
    if v.dialect != n.dialect
        || v.guid != n.server_guid
        || v.security_mode != n.server_security_mode
        || v.capabilities != n.server_capabilities
    {
        return fail(format!(
            "server reported {:?}/{:?}/{:?}, NEGOTIATE said {}/{:?}/{:?}",
            v.dialect, v.security_mode, v.capabilities, n.dialect, n.server_security_mode,
            n.server_capabilities
        ));
    }
    Ok(())
}

/// TREE_DISCONNECT (best effort).
pub(crate) async fn tree_disconnect(conn: &Connection, crypto: &Arc<SessionCrypto>, tree: &Tree) {
    let sec = Security {
        session: Some(crypto.clone()),
        encrypt: tree.encrypt,
        force_sign: false,
    };
    if let Ok(raw) = call(conn, &TreeDisconnectRequest, crypto.session_id, tree.tree_id, &sec).await
    {
        let _: Option<TreeDisconnectResponse> = raw.into_result().ok();
    }
}

/// LOGOFF (best effort).
pub(crate) async fn logoff(conn: &Connection, crypto: &Arc<SessionCrypto>) {
    let sec = Security {
        session: Some(crypto.clone()),
        encrypt: crypto.encrypt_all,
        force_sign: false,
    };
    if let Ok(raw) = call(conn, &LogoffRequest, crypto.session_id, 0, &sec).await {
        let _: Option<LogoffResponse> = raw.into_result().ok();
    }
}
