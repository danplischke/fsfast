//! Live interoperability smoke test against a real SMB server (Samba from
//! `scripts/test-services.sh`).
//!
//! Gated on `FSFAST_TEST_SMB_HOST`; also reads `FSFAST_TEST_SMB_PORT`,
//! `FSFAST_TEST_SMB_USER`, `FSFAST_TEST_SMB_PASSWORD`,
//! `FSFAST_TEST_SMB_SHARE` (signing-required share) and
//! `FSFAST_TEST_SMB_ENC_SHARE` (encryption-required share).
//!
//! For every dialect from 2.0.2 to 3.1.1 (and every 3.1.1 signing algorithm
//! and cipher) it negotiates, authenticates with NTLMv2 through SPNEGO,
//! derives the session keys, and then talks to the shares with signed (or
//! encrypted) requests while verifying every server signature: tree
//! connects, compound CREATE+WRITE+CLOSE and CREATE+QUERY_INFO+READ+CLOSE
//! chains, directory listings in several information classes, file system
//! information, VALIDATE_NEGOTIATE_INFO, deletion through SET_INFO and
//! NTSTATUS error mapping. Blocking `std::net` I/O is fine here: the codec
//! is I/O free and the test owns its thread.

use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use fsfast_core::ErrorKind;
use fsfast_smb_proto::auth::{AuthStep, Authenticator, NtlmConfig, NtlmCredentials, SpnegoClient};
use fsfast_smb_proto::compound::{CompoundBuilder, split_compound};
use fsfast_smb_proto::crypto::{
    Cipher, PreauthHasher, SessionKeys, Signer, SigningAlgorithm, SmbCipher, derive_session_keys,
};
use fsfast_smb_proto::framing::FrameDecoder;
use fsfast_smb_proto::fscc::{
    AccessMask, CreateAction, CreateDisposition, CreateOptions, FileAllInformation, FileAttributes,
    FileDispositionInformation, FileFsAttributeInformation, FileFsFullSizeInformation,
    FileInfoClass, FileNetworkOpenInformation, ImpersonationLevel, OplockLevel, ShareAccess,
};
use fsfast_smb_proto::header::{Command, Header, HeaderFlags, TRANSFORM_PROTOCOL_ID};
use fsfast_smb_proto::msg::*;
use fsfast_smb_proto::types::{Capabilities, Dialect, FileId, SecurityMode};
use fsfast_smb_proto::{Guid, NtStatus};

struct Env {
    host: String,
    port: u16,
    user: String,
    password: String,
    share: String,
    enc_share: String,
}

fn env() -> Option<Env> {
    let host = match std::env::var("FSFAST_TEST_SMB_HOST") {
        Ok(h) if !h.is_empty() => h,
        _ => {
            eprintln!("skipping live SMB test: FSFAST_TEST_SMB_HOST is not set");
            return None;
        }
    };
    let get = |k: &str, d: &str| std::env::var(k).unwrap_or_else(|_| d.to_owned());
    Some(Env {
        host,
        port: get("FSFAST_TEST_SMB_PORT", "445")
            .parse()
            .expect("FSFAST_TEST_SMB_PORT"),
        user: get("FSFAST_TEST_SMB_USER", "fsfast"),
        password: get("FSFAST_TEST_SMB_PASSWORD", "fsfastpw"),
        share: get("FSFAST_TEST_SMB_SHARE", "data"),
        enc_share: get("FSFAST_TEST_SMB_ENC_SHARE", "enc"),
    })
}

/// What to offer in NEGOTIATE.
#[derive(Clone)]
struct Offer {
    dialects: Vec<Dialect>,
    ciphers: Vec<CipherId>,
    signing: Option<Vec<SigningAlgorithmId>>,
}

/// A minimal blocking SMB client built only from codec pieces.
struct Client {
    sock: TcpStream,
    decoder: FrameDecoder,
    rbuf: BytesMut,
    host: String,
    next_mid: u64,
    dialect: Dialect,
    session_id: u64,
    tree_id: u32,
    signer: Option<Signer>,
    encryptor: Option<SmbCipher>,
    decryptor: Option<SmbCipher>,
    encrypt_tree: bool,
    /// Whether the last request frame went out encrypted (its responses
    /// must then be encrypted too, [MS-SMB2] §3.3.4.1.4).
    sent_encrypted: bool,
    /// Whether the last response frame arrived encrypted.
    last_encrypted: bool,
    keys: Option<SessionKeys>,
    conn_preauth: PreauthHasher,
    negotiate: Option<NegotiateResponse>,
    client_guid: Guid,
    offer: Option<Offer>,
}

impl Client {
    fn connect(e: &Env) -> Client {
        let sock = TcpStream::connect((e.host.as_str(), e.port)).expect("connect to SMB server");
        sock.set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        sock.set_nodelay(true).unwrap();
        Client {
            sock,
            decoder: FrameDecoder::new(),
            rbuf: BytesMut::with_capacity(1 << 16),
            host: e.host.clone(),
            next_mid: 0,
            dialect: Dialect::default(),
            session_id: 0,
            tree_id: 0,
            signer: None,
            encryptor: None,
            decryptor: None,
            encrypt_tree: false,
            sent_encrypted: false,
            last_encrypted: false,
            keys: None,
            conn_preauth: PreauthHasher::new(),
            negotiate: None,
            client_guid: Guid::random(),
            offer: None,
        }
    }

    fn header(&mut self, cmd: Command) -> Header {
        let mut h = Header::request(cmd);
        h.message_id = self.next_mid;
        self.next_mid += 1;
        h.credits = 64;
        h.credit_charge = u16::from(self.dialect.supports_multi_credit());
        h.session_id = self.session_id;
        h.set_tree_id(self.tree_id);
        h
    }

    /// Sign (or encrypt) and send messages as one frame. Returns the exact
    /// bytes of each message as sent (for the preauth hash).
    fn send(&mut self, mut msgs: Vec<EncodedMessage>) -> Vec<Vec<u8>> {
        let encrypt = self.encrypt_tree && self.encryptor.is_some();
        self.sent_encrypted = encrypt;
        if !encrypt && let Some(s) = &self.signer {
            for m in &mut msgs {
                if m.header().command != Command::NEGOTIATE && m.header().session_id != 0 {
                    s.sign(m).unwrap();
                }
            }
        }
        let sent: Vec<Vec<u8>> = msgs
            .iter()
            .map(|m| m.clone().into_contiguous().to_vec())
            .collect();
        let frame = if encrypt {
            let enc = self
                .encryptor
                .as_ref()
                .unwrap()
                .encrypt_messages(self.session_id, &msgs)
                .unwrap();
            OutgoingFrame::from_bytes(enc.freeze()).unwrap()
        } else {
            OutgoingFrame::from_messages(msgs).unwrap()
        };
        self.sock.write_all(&frame.to_vec()).unwrap();
        sent
    }

    fn read_frame(&mut self) -> BytesMut {
        loop {
            if let Some(f) = self.decoder.decode(&mut self.rbuf).unwrap() {
                return f;
            }
            let mut tmp = [0u8; 65536];
            let n = self.sock.read(&mut tmp).expect("read from SMB server");
            assert!(n > 0, "server closed the connection");
            self.rbuf.extend_from_slice(&tmp[..n]);
        }
    }

    /// Receive the responses to one request frame, decrypting and
    /// verifying signatures. Interim (STATUS_PENDING) responses are skipped.
    fn recv(&mut self, expected: usize) -> Vec<RawMessage> {
        let mut out = Vec::new();
        while out.len() < expected {
            let frame = self.read_frame();
            let (plain, encrypted) = if frame.starts_with(&TRANSFORM_PROTOCOL_ID) {
                let dec = self
                    .decryptor
                    .as_ref()
                    .expect("encrypted response without keys");
                // Exercise both decryption paths: into caller memory and in place.
                let mut copy = vec![0u8; frame.len()];
                let (_, n) = dec.decrypt_into(&frame, &mut copy).expect("decrypt_into");
                // ... and split: header to scratch, the rest elsewhere (how a
                // client lands READ data directly in the caller's buffer).
                let split = 64.min(n);
                let (mut head, mut rest) = (vec![0u8; split], vec![0u8; n - split]);
                dec.decrypt_into_parts(&frame, &mut [&mut head, &mut rest])
                    .expect("decrypt_into_parts");
                assert_eq!([head, rest].concat(), &copy[..n]);
                let (hdr, plain) = dec.decrypt_in_place(frame).expect("decrypt in place");
                assert_eq!(hdr.session_id, self.session_id);
                assert_eq!(&copy[..n], &plain[..]);
                (plain.freeze(), true)
            } else {
                (frame.freeze(), false)
            };
            self.last_encrypted = encrypted;
            assert!(
                encrypted || !self.sent_encrypted,
                "unencrypted response to an encrypted request"
            );
            for m in split_compound(plain) {
                let m = m.expect("well-formed compound response");
                if m.header().is_interim() {
                    continue;
                }
                if encrypted {
                    // [MS-SMB2] §3.2.5.1.3: a decrypted message is already
                    // authenticated by the AEAD tag; its signature is not
                    // verified. Samba sets SIGNED (with no valid signature)
                    // on the encrypted ACCESS_DENIED it returns for an
                    // unencrypted request on an encryption-required tree.
                } else if m.header().is_signed() {
                    self.signer
                        .as_ref()
                        .expect("signed response before keys exist")
                        .verify(m.bytes())
                        .unwrap_or_else(|e| panic!("signature of {:?} response: {e}", m.command()));
                } else if self.signer.is_some()
                    && m.header().session_id != 0
                    && !matches!(m.command(), Command::SESSION_SETUP | Command::OPLOCK_BREAK)
                {
                    panic!(
                        "unsigned {:?} response on a signing-required session",
                        m.command()
                    );
                }
                out.push(m);
            }
        }
        out
    }

    fn call<M: Message>(&mut self, cmd_body: &M) -> RawMessage {
        let h = self.header(M::COMMAND);
        let m = encode_message(&h, cmd_body).unwrap();
        self.send(vec![m]);
        self.recv(1).pop().unwrap()
    }

    fn negotiate(&mut self, offer: &Offer) -> NegotiateResponse {
        let mut contexts = Vec::new();
        if offer.dialects.contains(&Dialect::SMB_3_1_1) {
            let mut salt = [0u8; 32];
            fsfast_smb_proto::crypto::random_bytes(&mut salt);
            contexts.push(NegotiateContext::PreauthIntegrity {
                hash_algorithms: vec![HashAlgorithm::SHA512],
                salt: Bytes::copy_from_slice(&salt),
            });
            contexts.push(NegotiateContext::Encryption {
                ciphers: offer.ciphers.clone(),
            });
            if let Some(s) = &offer.signing {
                contexts.push(NegotiateContext::Signing {
                    algorithms: s.clone(),
                });
            }
            contexts.push(NegotiateContext::NetName(self.host.clone()));
        }
        let req = NegotiateRequest {
            security_mode: SecurityMode::SIGNING_ENABLED,
            capabilities: Capabilities::DFS
                | Capabilities::LARGE_MTU
                | Capabilities::LEASING
                | Capabilities::ENCRYPTION,
            client_guid: self.client_guid,
            dialects: offer.dialects.clone(),
            negotiate_contexts: contexts,
        };
        let h = self.header(Command::NEGOTIATE);
        let m = encode_message(&h, &req).unwrap();
        let sent = self.send(vec![m]);
        let resp = self.recv(1).pop().unwrap();
        assert_eq!(resp.status(), NtStatus::SUCCESS, "NEGOTIATE failed");
        let n: NegotiateResponse = resp.into_result().unwrap();
        self.dialect = n.dialect_revision;
        if self.dialect.is_3_1_1() {
            self.conn_preauth.update(&sent[0]);
            self.conn_preauth.update(resp.bytes());
        }
        self.negotiate = Some(n.clone());
        self.offer = Some(offer.clone());
        n
    }

    fn cipher(&self) -> Option<Cipher> {
        let n = self.negotiate.as_ref().unwrap();
        if self.dialect.is_3_1_1() {
            n.cipher().and_then(Cipher::from_id)
        } else if self.dialect.is_smb3() && n.capabilities.contains(Capabilities::ENCRYPTION) {
            Some(Cipher::Aes128Ccm)
        } else {
            None
        }
    }

    fn session_setup(&mut self, e: &Env) -> SessionFlags {
        let cfg = NtlmConfig {
            target_spn: Some(format!("cifs/{}", self.host)),
            workstation: Some("FSFAST-TEST".into()),
            ..Default::default()
        };
        let mut auth =
            SpnegoClient::ntlm_with_config(NtlmCredentials::new(&e.user, &e.password), cfg);
        let hint = self.negotiate.as_ref().unwrap().security_buffer.clone();
        let mut step = auth.step(&hint).expect("SPNEGO initial token");
        let mut preauth = self.conn_preauth.clone();
        loop {
            let token = step.token().expect("token to send").to_vec();
            let req = SessionSetupRequest {
                security_mode: SecurityMode::SIGNING_ENABLED,
                capabilities: Capabilities::DFS,
                security_buffer: Bytes::from(token),
                ..Default::default()
            };
            let h = self.header(Command::SESSION_SETUP);
            let m = encode_message(&h, &req).unwrap();
            let sent = self.send(vec![m]);
            preauth.update(&sent[0]);
            // Read without signature checks: keys do not exist yet.
            let frame = self.read_frame().freeze();
            let resp = RawMessage::parse(frame).unwrap();
            if self.session_id == 0 {
                self.session_id = resp.header().session_id;
            }
            match resp.status() {
                NtStatus::MORE_PROCESSING_REQUIRED => {
                    preauth.update(resp.bytes());
                    let r: SessionSetupResponse = resp.into_result().unwrap();
                    step = auth.step(&r.security_buffer).expect("SPNEGO step");
                    assert!(matches!(step, AuthStep::Continue(_)));
                }
                NtStatus::SUCCESS => {
                    let r: SessionSetupResponse = resp.into_result().unwrap();
                    let done = auth.step(&r.security_buffer).expect("final SPNEGO step");
                    assert_eq!(done, AuthStep::Done(None));
                    assert!(auth.is_complete());
                    let key = auth.session_key().expect("session key");
                    let hash = self.dialect.is_3_1_1().then(|| *preauth.value());
                    let keys = derive_session_keys(self.dialect, key, hash.as_ref(), self.cipher())
                        .unwrap();
                    let alg = SigningAlgorithm::for_dialect(
                        self.dialect,
                        self.negotiate.as_ref().unwrap().signing_algorithm(),
                    )
                    .unwrap();
                    let signer = Signer::new(alg, &keys.signing_key[..]).unwrap();
                    // The final SESSION_SETUP response is signed with the new
                    // keys (always in 3.1.1; with mandatory signing otherwise).
                    if self.dialect.is_3_1_1() {
                        assert!(
                            resp.header().is_signed(),
                            "3.1.1 final SESSION_SETUP response must be signed"
                        );
                    }
                    if resp.header().is_signed() {
                        signer
                            .verify(resp.bytes())
                            .expect("final SESSION_SETUP response signature");
                    }
                    if let (Some(c), Some(ek), Some(dk)) =
                        (self.cipher(), &keys.encryption_key, &keys.decryption_key)
                    {
                        self.encryptor = Some(SmbCipher::new(c, ek).unwrap());
                        self.decryptor = Some(SmbCipher::new(c, dk).unwrap());
                    }
                    eprintln!(
                        "  session {:#x}: {} signing={:?} cipher={:?} preauth={:?}",
                        self.session_id,
                        self.dialect,
                        alg,
                        self.cipher(),
                        hash.map(|h| h[0])
                    );
                    self.signer = Some(signer);
                    self.keys = Some(keys);
                    return r.session_flags;
                }
                s => panic!("SESSION_SETUP failed: {s}"),
            }
        }
    }

    fn tree_connect(&mut self, share: &str) -> TreeConnectResponse {
        self.tree_id = 0;
        self.encrypt_tree = false;
        let req = TreeConnectRequest {
            path: format!("\\\\{}\\{}", self.host, share),
            ..Default::default()
        };
        let resp = self.call(&req);
        let tc: TreeConnectResponse = resp
            .into_result()
            .unwrap_or_else(|e| panic!("TREE_CONNECT {share}: {e}"));
        self.tree_id = resp.header().tree_id().unwrap();
        self.encrypt_tree = tc.share_flags.contains(ShareFlags::ENCRYPT_DATA);
        tc
    }

    /// TREE_CONNECT sent inside a TRANSFORM_HEADER (allowed whenever the
    /// session has encryption keys); the response must come back encrypted.
    fn tree_connect_encrypted(&mut self, share: &str) -> TreeConnectResponse {
        assert!(self.encryptor.is_some(), "no encryption keys");
        self.tree_id = 0;
        self.encrypt_tree = true;
        let req = TreeConnectRequest {
            path: format!("\\\\{}\\{}", self.host, share),
            ..Default::default()
        };
        let resp = self.call(&req);
        assert!(
            self.last_encrypted,
            "encrypted TREE_CONNECT answered in clear"
        );
        let tc: TreeConnectResponse = resp
            .into_result()
            .unwrap_or_else(|e| panic!("encrypted TREE_CONNECT {share}: {e}"));
        self.tree_id = resp.header().tree_id().unwrap();
        tc
    }

    fn logoff(&mut self) {
        self.tree_id = 0;
        self.encrypt_tree = false;
        let resp = self.call(&LogoffRequest);
        let _: LogoffResponse = resp.into_result().unwrap();
    }
}

fn file_create(name: &str, disposition: CreateDisposition, access: AccessMask) -> CreateRequest {
    CreateRequest {
        requested_oplock_level: OplockLevel::NONE,
        impersonation_level: ImpersonationLevel::IMPERSONATION,
        desired_access: access,
        file_attributes: FileAttributes::NORMAL,
        share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
        create_disposition: disposition,
        create_options: CreateOptions::NON_DIRECTORY_FILE,
        name: name.into(),
        contexts: vec![
            CreateRequestContext::QueryMaximalAccess { timestamp: None },
            CreateRequestContext::QueryOnDiskId,
        ],
        ..Default::default()
    }
}

fn dir_create(name: &str) -> CreateRequest {
    CreateRequest {
        impersonation_level: ImpersonationLevel::IMPERSONATION,
        desired_access: AccessMask::FILE_LIST_DIRECTORY
            | AccessMask::FILE_READ_ATTRIBUTES
            | AccessMask::SYNCHRONIZE,
        share_access: ShareAccess::READ | ShareAccess::WRITE | ShareAccess::DELETE,
        create_disposition: CreateDisposition::OPEN,
        create_options: CreateOptions::DIRECTORY_FILE,
        name: name.into(),
        ..Default::default()
    }
}

/// File operations on the current tree: write, read back, list, stat,
/// delete, and check NTSTATUS mapping.
fn exercise_files(c: &mut Client, tag: &str) {
    let name = format!("fsfast-smoke-{tag}-{:08x}.bin", rand_u32());
    // 2.0.2 servers cap READ/WRITE at 64 KiB; newer ones get a multi-credit
    // request.
    let neg = c.negotiate.as_ref().unwrap();
    let len = neg.max_write_size.min(neg.max_read_size).min(200_000);
    let payload: Bytes = (0..len)
        .map(|i| (i % 251) as u8)
        .collect::<Vec<u8>>()
        .into();

    // CREATE + WRITE + CLOSE in one related compound (zero-copy payload).
    let mut chain = CompoundBuilder::new();
    let mut create = file_create(
        &name,
        CreateDisposition::OVERWRITE_IF,
        AccessMask::GENERIC_READ | AccessMask::GENERIC_WRITE | AccessMask::DELETE,
    );
    let mut lease_key = [0u8; 16];
    fsfast_smb_proto::crypto::random_bytes(&mut lease_key);
    let state = LeaseState::READ_CACHING | LeaseState::HANDLE_CACHING | LeaseState::WRITE_CACHING;
    // Leases exist from 2.1 on; lease v2 from 3.0.
    if c.dialect.is_smb3() {
        create.requested_oplock_level = OplockLevel::LEASE;
        create
            .contexts
            .push(CreateRequestContext::RequestLease(Lease::V2 {
                key: lease_key,
                state,
                flags: 0,
                duration: 0,
                parent_key: [0; 16],
                epoch: 0,
            }));
        create
            .contexts
            .push(CreateRequestContext::DurableHandleRequestV2 {
                timeout: 0,
                flags: 0,
                create_guid: Guid::random(),
            });
    } else if c.dialect == Dialect::SMB_2_1 {
        create.requested_oplock_level = OplockLevel::LEASE;
        create
            .contexts
            .push(CreateRequestContext::RequestLease(Lease::V1 {
                key: lease_key,
                state,
                flags: 0,
                duration: 0,
            }));
        create
            .contexts
            .push(CreateRequestContext::DurableHandleRequest);
    }
    let h = c.header(Command::CREATE);
    chain.push(h, &create).unwrap();
    let write = WriteRequest {
        file_id: FileId::RELATED,
        offset: 0,
        data: payload.clone(),
        ..Default::default()
    };
    let mut h = c.header(Command::WRITE);
    h.credit_charge = if c.dialect.supports_multi_credit() {
        write.credit_charge()
    } else {
        0
    };
    // Multi-credit requests consume extra message ids.
    c.next_mid += u64::from(h.credit_charge.max(1)) - 1;
    chain.push_related(h, &write).unwrap();
    let h = c.header(Command::CLOSE);
    chain
        .push_related(
            h,
            &CloseRequest {
                flags: CloseFlags::POSTQUERY_ATTRIB,
                file_id: FileId::RELATED,
            },
        )
        .unwrap();
    c.send(chain.finish());
    let r = c.recv(3);
    let cr: CreateResponse = r[0]
        .into_result()
        .unwrap_or_else(|e| panic!("CREATE {name}: {e}"));
    assert!(
        matches!(
            cr.create_action,
            CreateAction::CREATED | CreateAction::OVERWRITTEN
        ),
        "{cr:?}"
    );
    assert!(
        cr.maximal_access().is_some(),
        "MxAc context missing: {:?}",
        cr.contexts
    );
    eprintln!(
        "    create contexts: {:?}",
        cr.contexts.iter().map(context_kind).collect::<Vec<_>>()
    );
    let wr: WriteResponse = r[1].into_result().unwrap();
    assert_eq!(wr.count as usize, payload.len());
    let cl: CloseResponse = r[2].into_result().unwrap();
    assert_eq!(cl.end_of_file, payload.len() as u64);

    // CREATE + QUERY_INFO + READ + CLOSE: READ data is a slice of the frame.
    let mut chain = CompoundBuilder::new();
    let h = c.header(Command::CREATE);
    chain
        .push(
            h,
            &file_create(&name, CreateDisposition::OPEN, AccessMask::GENERIC_READ),
        )
        .unwrap();
    let h = c.header(Command::QUERY_INFO);
    chain
        .push_related(
            h,
            &QueryInfoRequest::for_class::<FileAllInformation>(FileId::RELATED, 4096),
        )
        .unwrap();
    let read = ReadRequest {
        file_id: FileId::RELATED,
        length: payload.len() as u32,
        ..Default::default()
    };
    let mut h = c.header(Command::READ);
    h.credit_charge = if c.dialect.supports_multi_credit() {
        read.credit_charge()
    } else {
        0
    };
    c.next_mid += u64::from(h.credit_charge.max(1)) - 1;
    chain.push_related(h, &read).unwrap();
    let h = c.header(Command::QUERY_INFO);
    chain
        .push_related(
            h,
            &QueryInfoRequest::for_class::<FileNetworkOpenInformation>(FileId::RELATED, 56),
        )
        .unwrap();
    let h = c.header(Command::CLOSE);
    chain
        .push_related(
            h,
            &CloseRequest {
                flags: CloseFlags::empty(),
                file_id: FileId::RELATED,
            },
        )
        .unwrap();
    c.send(chain.finish());
    let r = c.recv(5);
    let cr: CreateResponse = r[0].into_result().unwrap();
    assert_eq!(cr.end_of_file, payload.len() as u64);
    let all: FileAllInformation = r[1]
        .into_result::<QueryInfoResponse>()
        .unwrap()
        .decode_as()
        .unwrap();
    assert_eq!(all.standard.end_of_file, payload.len() as u64);
    assert!(
        all.name.file_name.ends_with(&name),
        "FileAllInformation name {:?}",
        all.name.file_name
    );
    let rd: ReadResponse = r[2].into_result().unwrap();
    assert_eq!(rd.data, payload, "read back different bytes");
    let net: FileNetworkOpenInformation = r[3]
        .into_result::<QueryInfoResponse>()
        .unwrap()
        .decode_as()
        .unwrap();
    assert_eq!(net.end_of_file, payload.len() as u64);
    assert!(net.last_write_time.to_system_time().is_some());
    let _: CloseResponse = r[4].into_result().unwrap();

    // Directory listing in several information classes + FS info.
    let classes = [
        FileInfoClass::ID_BOTH_DIRECTORY,
        FileInfoClass::BOTH_DIRECTORY,
        FileInfoClass::DIRECTORY,
        FileInfoClass::FULL_DIRECTORY,
        FileInfoClass::ID_FULL_DIRECTORY,
        FileInfoClass::ID_EXTD_DIRECTORY,
    ];
    for class in classes {
        let mut chain = CompoundBuilder::new();
        let h = c.header(Command::CREATE);
        chain.push(h, &dir_create("")).unwrap();
        let h = c.header(Command::QUERY_DIRECTORY);
        let q = QueryDirectoryRequest {
            file_information_class: class,
            flags: QueryDirectoryFlags::RESTART_SCANS,
            file_id: FileId::RELATED,
            file_name: "*".into(),
            output_buffer_length: 65536,
            ..Default::default()
        };
        chain.push_related(h, &q).unwrap();
        let h = c.header(Command::QUERY_INFO);
        chain
            .push_related(
                h,
                &QueryInfoRequest::for_class::<FileFsFullSizeInformation>(FileId::RELATED, 32),
            )
            .unwrap();
        let h = c.header(Command::QUERY_INFO);
        chain
            .push_related(
                h,
                &QueryInfoRequest::for_class::<FileFsAttributeInformation>(FileId::RELATED, 1024),
            )
            .unwrap();
        let h = c.header(Command::CLOSE);
        chain
            .push_related(
                h,
                &CloseRequest {
                    file_id: FileId::RELATED,
                    ..Default::default()
                },
            )
            .unwrap();
        c.send(chain.finish());
        let r = c.recv(5);
        let _: CreateResponse = r[0].into_result().unwrap();
        match r[1].into_result::<QueryDirectoryResponse>() {
            Ok(qd) => {
                let entries: Vec<_> = qd
                    .entries(class)
                    .unwrap()
                    .collect::<Result<_, _>>()
                    .unwrap();
                assert!(
                    entries.iter().any(|e| e.file_name.is_dot()),
                    "{class:?}: no '.' entry"
                );
                let mine = entries
                    .iter()
                    .find(|e| e.file_name.to_string_lossy() == name)
                    .unwrap_or_else(|| panic!("{class:?}: {name} not listed"));
                assert_eq!(mine.end_of_file, payload.len() as u64);
                assert!(!mine.is_directory());
                if class == FileInfoClass::ID_BOTH_DIRECTORY {
                    assert!(mine.file_id.is_some());
                }
            }
            // Older Samba versions lack FileIdExtdDirectoryInformation.
            Err(e) if class == FileInfoClass::ID_EXTD_DIRECTORY => {
                eprintln!("    {class:?} unsupported: {e}")
            }
            Err(e) => panic!("QUERY_DIRECTORY {class:?}: {e}"),
        }
        let fs: FileFsFullSizeInformation = r[2]
            .into_result::<QueryInfoResponse>()
            .unwrap()
            .decode_as()
            .unwrap();
        assert!(fs.total_allocation_units > 0 && fs.unit_size() > 0);
        let attr: FileFsAttributeInformation = r[3]
            .into_result::<QueryInfoResponse>()
            .unwrap()
            .decode_as()
            .unwrap();
        assert!(!attr.file_system_name.is_empty());
        let _: CloseResponse = r[4].into_result().unwrap();
    }

    // Delete through SET_INFO(FileDispositionInformation).
    let mut chain = CompoundBuilder::new();
    let h = c.header(Command::CREATE);
    chain
        .push(
            h,
            &file_create(
                &name,
                CreateDisposition::OPEN,
                AccessMask::DELETE | AccessMask::FILE_READ_ATTRIBUTES,
            ),
        )
        .unwrap();
    let h = c.header(Command::SET_INFO);
    let set = SetInfoRequest::new(
        FileId::RELATED,
        &FileDispositionInformation {
            delete_pending: true,
        },
    )
    .unwrap();
    chain.push_related(h, &set).unwrap();
    let h = c.header(Command::CLOSE);
    chain
        .push_related(
            h,
            &CloseRequest {
                file_id: FileId::RELATED,
                ..Default::default()
            },
        )
        .unwrap();
    c.send(chain.finish());
    let r = c.recv(3);
    let _: CreateResponse = r[0].into_result().unwrap();
    let _: SetInfoResponse = r[1].into_result().unwrap();
    let _: CloseResponse = r[2].into_result().unwrap();

    // The file is gone: the error maps to NotFound with the NTSTATUS attached.
    let resp = c.call(&file_create(
        &name,
        CreateDisposition::OPEN,
        AccessMask::GENERIC_READ,
    ));
    assert!(resp.is_error_response());
    assert_eq!(resp.status(), NtStatus::OBJECT_NAME_NOT_FOUND);
    let err = resp.status().to_error(Some(&name));
    assert_eq!(err.kind(), ErrorKind::NotFound);
    let err: fsfast_core::Error = resp.into_result::<CreateResponse>().unwrap_err().into();
    assert_eq!(err.kind(), ErrorKind::NotFound);
    // A missing directory component.
    let resp = c.call(&file_create(
        "no-such-dir\\x",
        CreateDisposition::OPEN,
        AccessMask::GENERIC_READ,
    ));
    assert_eq!(
        resp.status().kind(),
        ErrorKind::NotFound,
        "{}",
        resp.status()
    );
}

fn context_kind(c: &CreateResponseContext) -> &'static str {
    match c {
        CreateResponseContext::DurableHandleResponse => "DHnQ",
        CreateResponseContext::DurableHandleResponseV2 { .. } => "DH2Q",
        CreateResponseContext::MaximalAccess { .. } => "MxAc",
        CreateResponseContext::OnDiskId { .. } => "QFid",
        CreateResponseContext::Lease(_) => "RqLs",
        CreateResponseContext::Raw { .. } => "raw",
    }
}

fn rand_u32() -> u32 {
    let mut b = [0u8; 4];
    fsfast_smb_proto::crypto::random_bytes(&mut b);
    u32::from_le_bytes(b)
}

fn all_ciphers() -> Vec<CipherId> {
    vec![
        CipherId::AES_128_GCM,
        CipherId::AES_128_CCM,
        CipherId::AES_256_GCM,
        CipherId::AES_256_CCM,
    ]
}

/// Full session on one dialect/algorithm combination.
fn run_session(e: &Env, offer: &Offer, label: &str) {
    eprintln!("== {label}");
    let mut c = Client::connect(e);
    let n = c.negotiate(offer);
    assert!(
        offer.dialects.contains(&n.dialect_revision),
        "server picked {}",
        n.dialect_revision
    );
    let flags = c.session_setup(e);
    assert!(
        !flags.contains(SessionFlags::IS_GUEST) && !flags.contains(SessionFlags::IS_NULL),
        "{flags:?}"
    );

    // ECHO (unsigned, no session).
    let sid = std::mem::replace(&mut c.session_id, 0);
    let echo = c.call(&EchoRequest);
    let _: EchoResponse = echo.into_result().unwrap();
    c.session_id = sid;

    let tc = c.tree_connect(&e.share);
    assert_eq!(tc.share_type, ShareType::DISK);
    eprintln!(
        "  tree {:#x} {:?} access={:?}",
        c.tree_id, tc.share_flags, tc.maximal_access
    );

    if c.dialect.is_smb3() && !c.dialect.is_3_1_1() {
        // FSCTL_VALIDATE_NEGOTIATE_INFO (mandatory for 3.0/3.0.2 clients).
        let o = c.offer.clone().unwrap();
        let vni = ValidateNegotiateInfoRequest {
            capabilities: Capabilities::DFS
                | Capabilities::LARGE_MTU
                | Capabilities::LEASING
                | Capabilities::ENCRYPTION,
            guid: c.client_guid,
            security_mode: SecurityMode::SIGNING_ENABLED,
            dialects: o.dialects,
        };
        let req = IoctlRequest::fsctl(
            fsctl::VALIDATE_NEGOTIATE_INFO,
            FileId::RELATED,
            vni.to_bytes().unwrap(),
            24,
        );
        let resp = c.call(&req);
        let io: IoctlResponse = resp.into_result().unwrap();
        let v = ValidateNegotiateInfoResponse::decode(&io.output).unwrap();
        let neg = c.negotiate.as_ref().unwrap();
        assert_eq!(v.dialect, neg.dialect_revision);
        assert_eq!(v.guid, neg.server_guid);
        assert_eq!(v.security_mode, neg.security_mode);
        assert_eq!(v.capabilities, neg.capabilities);
        eprintln!("  VALIDATE_NEGOTIATE_INFO ok");
    }

    exercise_files(&mut c, label);

    let resp = c.call(&TreeDisconnectRequest);
    let _: TreeDisconnectResponse = resp.into_result().unwrap();

    if c.encryptor.is_some() {
        let tc = c.tree_connect(&e.enc_share);
        assert!(
            tc.share_flags.contains(ShareFlags::ENCRYPT_DATA),
            "{:?}",
            tc.share_flags
        );
        eprintln!("  encrypted tree {:#x} with {:?}", c.tree_id, c.cipher());
        assert!(c.encrypt_tree);

        // A signed but unencrypted request on an encryption-required tree
        // must be refused ([MS-SMB2] §3.3.5.2.11) and must not be served.
        // (Samba sends the refusal encrypted; either form is accepted.)
        c.encrypt_tree = false;
        let resp = c.call(&dir_create(""));
        assert_eq!(
            resp.status(),
            NtStatus::ACCESS_DENIED,
            "unencrypted CREATE on an encrypted share"
        );
        assert!(resp.is_error_response());
        c.encrypt_tree = true;

        exercise_files(&mut c, &format!("{label}-enc"));
        let resp = c.call(&TreeDisconnectRequest);
        let _: TreeDisconnectResponse = resp.into_result().unwrap();

        // TREE_CONNECT itself encrypted, then an encrypted round trip on
        // the new tree.
        let tc = c.tree_connect_encrypted(&e.enc_share);
        assert!(tc.share_flags.contains(ShareFlags::ENCRYPT_DATA));
        let resp = c.call(&dir_create(""));
        assert!(c.last_encrypted);
        let cr: CreateResponse = resp.into_result().unwrap();
        assert!(cr.is_directory());
        let resp = c.call(&CloseRequest {
            file_id: cr.file_id,
            ..Default::default()
        });
        let _: CloseResponse = resp.into_result().unwrap();
        let resp = c.call(&TreeDisconnectRequest);
        let _: TreeDisconnectResponse = resp.into_result().unwrap();
        eprintln!("  encrypted TREE_CONNECT round trip ok");
    }
    c.logoff();
}

#[test]
fn live_samba_all_dialects_signing_and_encryption() {
    let Some(e) = env() else { return };
    let only = |d: Dialect| vec![d];
    run_session(
        &e,
        &Offer {
            dialects: Dialect::ALL.to_vec(),
            ciphers: all_ciphers(),
            signing: Some(vec![
                SigningAlgorithmId::AES_GMAC,
                SigningAlgorithmId::AES_CMAC,
                SigningAlgorithmId::HMAC_SHA256,
            ]),
        },
        "3.1.1-gmac",
    );
    run_session(
        &e,
        &Offer {
            dialects: only(Dialect::SMB_3_1_1),
            ciphers: all_ciphers(),
            signing: Some(vec![SigningAlgorithmId::AES_CMAC]),
        },
        "3.1.1-cmac-ctx",
    );
    run_session(
        &e,
        &Offer {
            dialects: only(Dialect::SMB_3_1_1),
            ciphers: all_ciphers(),
            signing: None,
        },
        "3.1.1-nosignctx",
    );
    for cipher in all_ciphers() {
        run_session(
            &e,
            &Offer {
                dialects: only(Dialect::SMB_3_1_1),
                ciphers: vec![cipher],
                signing: Some(vec![SigningAlgorithmId::AES_GMAC]),
            },
            &format!("3.1.1-cipher-{:04x}", cipher.0),
        );
    }
    for d in [
        Dialect::SMB_3_0_2,
        Dialect::SMB_3_0,
        Dialect::SMB_2_1,
        Dialect::SMB_2_0_2,
    ] {
        run_session(
            &e,
            &Offer {
                dialects: only(d),
                ciphers: vec![],
                signing: None,
            },
            &format!("{d}").replace(' ', "-"),
        );
    }
}

#[test]
fn live_samba_bad_password_maps_to_permission_denied() {
    let Some(e) = env() else { return };
    let mut c = Client::connect(&e);
    c.negotiate(&Offer {
        dialects: vec![Dialect::SMB_3_1_1],
        ciphers: all_ciphers(),
        signing: None,
    });
    let mut auth = SpnegoClient::ntlm(NtlmCredentials::new(&e.user, "definitely-wrong"));
    let hint = c.negotiate.as_ref().unwrap().security_buffer.clone();
    let mut step = auth.step(&hint).unwrap();
    loop {
        let req = SessionSetupRequest {
            security_mode: SecurityMode::SIGNING_ENABLED,
            security_buffer: Bytes::from(step.token().unwrap().to_vec()),
            ..Default::default()
        };
        let resp = c.call(&req);
        c.session_id = resp.header().session_id;
        if resp.status() == NtStatus::MORE_PROCESSING_REQUIRED {
            let r: SessionSetupResponse = resp.into_result().unwrap();
            step = auth.step(&r.security_buffer).unwrap();
            continue;
        }
        assert_eq!(resp.status(), NtStatus::LOGON_FAILURE);
        let err: fsfast_core::Error = resp
            .into_result::<SessionSetupResponse>()
            .unwrap_err()
            .into();
        assert_eq!(err.kind(), ErrorKind::PermissionDenied);
        assert!(
            err.details()
                .contains(&fsfast_core::Detail::NtStatus(NtStatus::LOGON_FAILURE.0))
        );
        break;
    }
}

#[test]
fn live_samba_bad_share_and_flags() {
    let Some(e) = env() else { return };
    let mut c = Client::connect(&e);
    c.negotiate(&Offer {
        dialects: Dialect::ALL.to_vec(),
        ciphers: all_ciphers(),
        signing: Some(vec![SigningAlgorithmId::AES_GMAC]),
    });
    c.session_setup(&e);
    let req = TreeConnectRequest {
        path: format!("\\\\{}\\no-such-share", e.host),
        ..Default::default()
    };
    let resp = c.call(&req);
    assert_eq!(resp.status(), NtStatus::BAD_NETWORK_NAME);
    assert_eq!(resp.status().kind(), ErrorKind::NotFound);
    // The signed flag on our requests was honoured: the server answered.
    assert!(resp.header().flags.contains(HeaderFlags::SERVER_TO_REDIR));
    c.logoff();
}
