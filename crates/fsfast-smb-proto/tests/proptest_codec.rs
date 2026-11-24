//! Property tests for the codec.
//!
//! * Every decoder is fed arbitrary bytes and must return `Ok` or `Err`,
//!   never panic or loop.
//! * Every SMB2 message type, and the NTLM/SPNEGO/FSCC/FSCTL structures,
//!   round-trip: `decode(encode(x)) == x` for generated `x` (or, for
//!   structures whose fields depend on a class, `encode(decode(encode(x)))
//!   == encode(x)`).
//! * Framing, compound splitting, signing and encryption preserve their
//!   input and detect tampering.

use bytes::{Bytes, BytesMut};
use proptest::collection::vec;
use proptest::prelude::*;

use fsfast_smb_proto::auth::der::DerReader;
use fsfast_smb_proto::auth::ntlm::{
    AuthenticateMessage, AvPair, AvPairs, ChallengeMessage, NegotiateFlags, NegotiateMessage,
    NtlmVersion,
};
use fsfast_smb_proto::auth::spnego::{NegState, NegTokenInit, NegTokenResp, NegotiationToken};
use fsfast_smb_proto::auth::{Authenticator, NtlmClient, NtlmCredentials, SpnegoClient};
use fsfast_smb_proto::compound::{CompoundBuilder, split_compound};
use fsfast_smb_proto::crypto::{
    Cipher, CompressionTransform, Signer, SigningAlgorithm, SmbCipher, TransformHeader,
};
use fsfast_smb_proto::framing::{FrameDecoder, transport_header};
use fsfast_smb_proto::fscc::*;
use fsfast_smb_proto::header::{Command, HEADER_LEN, Header, HeaderFlags, HeaderId};
use fsfast_smb_proto::msg::*;
use fsfast_smb_proto::types::{Capabilities, Dialect, FileId, SecurityMode};
use fsfast_smb_proto::{Guid, NtStatus};

// ---------------------------------------------------------------------------
// Strategy helpers
// ---------------------------------------------------------------------------

fn bytes(max: usize) -> impl Strategy<Value = Bytes> {
    vec(any::<u8>(), 0..max).prop_map(Bytes::from)
}

fn file_id() -> impl Strategy<Value = FileId> {
    (any::<u64>(), any::<u64>()).prop_map(|(p, v)| FileId::new(p, v))
}

fn ft() -> impl Strategy<Value = FileTime> {
    any::<u64>().prop_map(FileTime)
}

fn guid() -> impl Strategy<Value = Guid> {
    any::<[u8; 16]>().prop_map(Guid)
}

/// Printable strings (no NUL, which SMB treats as a terminator in places).
fn name() -> impl Strategy<Value = String> {
    "\\PC{0,12}"
}

fn header_for<M: Message>() -> Header {
    let mut h = Header::request(M::COMMAND);
    h.message_id = 42;
    h.session_id = 7;
    if M::RESPONSE {
        h.flags = HeaderFlags::SERVER_TO_REDIR;
    }
    h
}

fn round_trip<M: Message + PartialEq + std::fmt::Debug>(m: &M) -> Result<(), TestCaseError> {
    let enc = encode_message(&header_for::<M>(), m)
        .map_err(|e| TestCaseError::fail(format!("encode: {e}")))?;
    let raw = RawMessage::parse(enc.into_contiguous().freeze()).unwrap();
    let d: M = raw
        .decode()
        .map_err(|e| TestCaseError::fail(format!("decode: {e}")))?;
    prop_assert_eq!(&d, m);
    Ok(())
}

/// A message with a valid header for `M` and an arbitrary body.
fn with_body<M: Message>(body: &[u8]) -> RawMessage {
    let mut b = header_for::<M>().to_bytes().to_vec();
    b.extend_from_slice(body);
    RawMessage::parse(Bytes::from(b)).unwrap()
}

/// Arbitrary body bytes that usually start with a real StructureSize, so
/// decoders get past the first check and exercise their offset handling.
fn body_for_any() -> impl Strategy<Value = Vec<u8>> {
    const SIZES: [u16; 17] = [
        2, 4, 9, 16, 17, 24, 25, 33, 36, 41, 44, 48, 49, 57, 60, 65, 89,
    ];
    (any::<bool>(), 0..SIZES.len(), vec(any::<u8>(), 0..300)).prop_map(|(fix, i, mut b)| {
        if fix && b.len() >= 2 {
            b[..2].copy_from_slice(&SIZES[i].to_le_bytes());
        }
        b
    })
}

macro_rules! no_panic_decode {
    ($body:expr, $($t:ty),+ $(,)?) => {{
        $(
            let raw = with_body::<$t>($body);
            let _ = raw.decode::<$t>();
            let _ = raw.is_error_response();
            let _ = raw.decode_error();
            let _ = raw.into_result::<$t>();
        )+
    }};
}

// ---------------------------------------------------------------------------
// Decoders never panic
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn message_decoders_never_panic(body in body_for_any()) {
        no_panic_decode!(&body,
            NegotiateRequest, NegotiateResponse, SessionSetupRequest, SessionSetupResponse, LogoffRequest,
            LogoffResponse, TreeConnectRequest, TreeConnectResponse, TreeDisconnectRequest, TreeDisconnectResponse,
            CreateRequest, CreateResponse, CloseRequest, CloseResponse, FlushRequest, FlushResponse, ReadRequest,
            ReadResponse, WriteRequest, WriteResponse, LockRequest, LockResponse, IoctlRequest, IoctlResponse,
            CancelRequest, EchoRequest, EchoResponse, QueryDirectoryRequest, QueryDirectoryResponse,
            ChangeNotifyRequest, ChangeNotifyResponse, QueryInfoRequest, QueryInfoResponse, SetInfoRequest,
            SetInfoResponse, OplockBreakNotification, OplockBreakAck, OplockBreakResponse, LeaseBreakNotification,
            LeaseBreakAck, LeaseBreakResponse,
        );
        let raw = with_body::<OplockBreakNotification>(&body);
        let _ = BreakMessage::decode(&raw);
    }

    #[test]
    fn frame_and_header_decoders_never_panic(data in vec(any::<u8>(), 0..400), chunk in 1usize..64) {
        let _ = Header::decode(&data);
        let _ = RawMessage::parse(Bytes::from(data.clone()));
        for m in split_compound(Bytes::from(data.clone())).flatten() {
            let _ = m.decode::<CreateResponse>();
            let _ = BreakMessage::decode(&m);
        }
        let mut dec = FrameDecoder::with_max_frame_len(1 << 16);
        let mut buf = BytesMut::new();
        for c in data.chunks(chunk) {
            buf.extend_from_slice(c);
            while let Ok(Some(_)) = dec.decode(&mut buf) {}
        }
        let _ = TransformHeader::decode(&data);
        let _ = CompressionTransform::parse(&Bytes::from(data.clone())).map(|t| t.decompress());
        for c in [Cipher::Aes128Ccm, Cipher::Aes128Gcm, Cipher::Aes256Ccm, Cipher::Aes256Gcm] {
            let k = SmbCipher::new(c, &vec![1u8; c.key_len()]).unwrap();
            let _ = k.decrypt_in_place(BytesMut::from(&data[..]));
            let mut out = vec![0u8; data.len()];
            let _ = k.decrypt_into(&data, &mut out);
        }
    }

    #[test]
    fn fscc_and_fsctl_decoders_never_panic(data in vec(any::<u8>(), 0..400)) {
        let _ = FileBasicInformation::decode(&data);
        let _ = FileStandardInformation::decode(&data);
        let _ = FileAllInformation::decode(&data);
        let _ = FileNetworkOpenInformation::decode(&data);
        let _ = FileAttributeTagInformation::decode(&data);
        let _ = FileRenameInformation::decode(&data);
        let _ = FileRenameInformationEx::decode(&data);
        let _ = FileLinkInformation::decode(&data);
        let _ = FileStreamInformation::decode(&data);
        let _ = FileNameInformation::decode(&data);
        let _ = FileIdInformation::decode(&data);
        let _ = FileFsSizeInformation::decode(&data);
        let _ = FileFsFullSizeInformation::decode(&data);
        let _ = FileFsAttributeInformation::decode(&data);
        let _ = FileFsVolumeInformation::decode(&data);
        let _ = FileFsDeviceInformation::decode(&data);
        let _ = FileFsSectorSizeInformation::decode(&data);
        for class in [
            FileInfoClass::DIRECTORY, FileInfoClass::FULL_DIRECTORY, FileInfoClass::BOTH_DIRECTORY,
            FileInfoClass::ID_BOTH_DIRECTORY, FileInfoClass::ID_FULL_DIRECTORY, FileInfoClass::ID_EXTD_DIRECTORY,
            FileInfoClass::NAMES,
        ] {
            // Bounded: a malformed chain ends after at most one error.
            let n = DirectoryEntries::new(class, Bytes::from(data.clone())).unwrap().take(1000).count();
            prop_assert!(n < 1000);
        }
        let _ = ValidateNegotiateInfoRequest::decode(&data);
        let _ = ValidateNegotiateInfoResponse::decode(&data);
        let _ = SrvRequestResumeKeyResponse::decode(&data);
        let _ = SrvCopyChunkCopy::decode(&data);
        let _ = SrvCopyChunkResponse::decode(&data);
        let _ = DfsReferralRequest::decode(&data);
        let _ = DfsReferralRequestEx::decode(&data);
        let _ = DfsReferralResponse::decode(&data);
        let _ = decode_network_interfaces(&data);
        let _ = decode_notify_information(&data);
        let _ = SymlinkErrorResponse::decode(&data);
        let _ = ShareRedirect::decode(&data);
    }

    #[test]
    fn auth_decoders_never_panic(data in vec(any::<u8>(), 0..400), prefix in any::<bool>()) {
        let mut d = data.clone();
        if prefix && d.len() >= 12 {
            d[..8].copy_from_slice(b"NTLMSSP\0");
        }
        let _ = AvPairs::decode(&d);
        let _ = NegotiateMessage::decode(&d);
        let _ = ChallengeMessage::decode(&d);
        let _ = AuthenticateMessage::decode(&d);
        let _ = NegotiationToken::decode(&d);
        let mut r = DerReader::new(&d);
        while !r.is_empty() {
            if r.read().is_err() {
                break;
            }
        }
        // Authenticators fed garbage server tokens fail cleanly.
        let mut ntlm = NtlmClient::new(NtlmCredentials::new("u", "p"));
        ntlm.step(&[]).unwrap();
        let _ = ntlm.step(&d);
        let mut sp = SpnegoClient::ntlm(NtlmCredentials::new("u", "p"));
        let _ = sp.step(&d);
        let _ = sp.step(&d);
        let _ = sp.step(&d);
    }
}

// ---------------------------------------------------------------------------
// Message round trips
// ---------------------------------------------------------------------------

const KNOWN_CONTEXT_TYPES: [u16; 7] = [1, 2, 3, 5, 6, 7, 8];

fn negotiate_context() -> impl Strategy<Value = NegotiateContext> {
    prop_oneof![
        (vec(any::<u16>().prop_map(HashAlgorithm), 0..3), bytes(40)).prop_map(
            |(hash_algorithms, salt)| NegotiateContext::PreauthIntegrity {
                hash_algorithms,
                salt
            }
        ),
        vec(any::<u16>().prop_map(CipherId), 0..5)
            .prop_map(|ciphers| NegotiateContext::Encryption { ciphers }),
        (
            any::<u32>(),
            vec(any::<u16>().prop_map(CompressionAlgorithm), 0..4)
        )
            .prop_map(|(flags, algorithms)| NegotiateContext::Compression { flags, algorithms }),
        name().prop_map(NegotiateContext::NetName),
        any::<u32>().prop_map(|flags| NegotiateContext::Transport { flags }),
        vec(any::<u16>().prop_map(RdmaTransformId), 0..3)
            .prop_map(|transform_ids| NegotiateContext::RdmaTransform { transform_ids }),
        vec(any::<u16>().prop_map(SigningAlgorithmId), 0..3)
            .prop_map(|algorithms| NegotiateContext::Signing { algorithms }),
        (
            any::<u16>().prop_filter("unknown type", |t| !KNOWN_CONTEXT_TYPES.contains(t)),
            bytes(20)
        )
            .prop_map(|(context_type, data)| NegotiateContext::Unknown { context_type, data }),
    ]
}

fn lease() -> impl Strategy<Value = Lease> {
    prop_oneof![
        (any::<[u8; 16]>(), any::<u32>(), any::<u32>(), any::<u64>()).prop_map(
            |(key, s, flags, duration)| {
                Lease::V1 {
                    key,
                    state: LeaseState::from_bits_retain(s),
                    flags,
                    duration,
                }
            }
        ),
        (
            any::<[u8; 16]>(),
            any::<u32>(),
            any::<u32>(),
            any::<u64>(),
            any::<[u8; 16]>(),
            any::<u16>()
        )
            .prop_map(|(key, s, flags, duration, parent_key, epoch)| Lease::V2 {
                key,
                state: LeaseState::from_bits_retain(s),
                flags,
                duration,
                parent_key,
                epoch,
            }),
    ]
}

/// A raw context whose name cannot be mistaken for a known 4-byte one.
fn raw_context_name() -> impl Strategy<Value = Bytes> {
    vec(any::<u8>(), 5..17).prop_map(Bytes::from)
}

fn create_request_context() -> impl Strategy<Value = CreateRequestContext> {
    prop_oneof![
        Just(CreateRequestContext::DurableHandleRequest),
        file_id().prop_map(|file_id| CreateRequestContext::DurableHandleReconnect { file_id }),
        (any::<u32>(), any::<u32>(), guid()).prop_map(|(timeout, flags, create_guid)| {
            CreateRequestContext::DurableHandleRequestV2 {
                timeout,
                flags,
                create_guid,
            }
        }),
        (file_id(), guid(), any::<u32>()).prop_map(|(file_id, create_guid, flags)| {
            CreateRequestContext::DurableHandleReconnectV2 {
                file_id,
                create_guid,
                flags,
            }
        }),
        proptest::option::of(ft())
            .prop_map(|timestamp| CreateRequestContext::QueryMaximalAccess { timestamp }),
        Just(CreateRequestContext::QueryOnDiskId),
        lease().prop_map(CreateRequestContext::RequestLease),
        any::<u64>().prop_map(CreateRequestContext::AllocationSize),
        ft().prop_map(CreateRequestContext::TimewarpToken),
        (raw_context_name(), bytes(40))
            .prop_map(|(name, data)| CreateRequestContext::Raw { name, data }),
    ]
}

fn create_response_context() -> impl Strategy<Value = CreateResponseContext> {
    prop_oneof![
        Just(CreateResponseContext::DurableHandleResponse),
        (any::<u32>(), any::<u32>()).prop_map(|(timeout, flags)| {
            CreateResponseContext::DurableHandleResponseV2 { timeout, flags }
        }),
        (any::<u32>(), any::<u32>()).prop_map(|(s, a)| CreateResponseContext::MaximalAccess {
            query_status: NtStatus(s),
            maximal_access: AccessMask::from_bits_retain(a)
        }),
        (any::<u64>(), any::<u64>()).prop_map(|(disk_file_id, volume_id)| {
            CreateResponseContext::OnDiskId {
                disk_file_id,
                volume_id,
            }
        }),
        lease().prop_map(CreateResponseContext::Lease),
        (raw_context_name(), bytes(40))
            .prop_map(|(name, data)| CreateResponseContext::Raw { name, data }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn rt_negotiate(sm in any::<u16>(), caps in any::<u32>(), g in guid(), dialects in vec(any::<u16>().prop_map(Dialect), 0..6),
                    ctx in vec(negotiate_context(), 0..5), dialect in any::<u16>(), sizes in any::<(u32, u32, u32)>(),
                    times in (ft(), ft()), sec in bytes(60)) {
        let mut dialects = dialects;
        if !ctx.is_empty() && !dialects.contains(&Dialect::SMB_3_1_1) {
            dialects.push(Dialect::SMB_3_1_1);
        }
        round_trip(&NegotiateRequest {
            security_mode: SecurityMode::from_bits_retain(sm),
            capabilities: Capabilities::from_bits_retain(caps),
            client_guid: g,
            dialects,
            negotiate_contexts: ctx.clone(),
        })?;
        let dialect = if ctx.is_empty() { Dialect(dialect) } else { Dialect::SMB_3_1_1 };
        let ctx = if dialect == Dialect::SMB_3_1_1 { ctx } else { vec![] };
        round_trip(&NegotiateResponse {
            security_mode: SecurityMode::from_bits_retain(sm),
            dialect_revision: dialect,
            server_guid: g,
            capabilities: Capabilities::from_bits_retain(caps),
            max_transact_size: sizes.0,
            max_read_size: sizes.1,
            max_write_size: sizes.2,
            system_time: times.0,
            server_start_time: times.1,
            security_buffer: sec,
            negotiate_contexts: ctx,
        })?;
    }

    #[test]
    fn rt_session_tree(flags in any::<u8>(), sm in any::<u8>(), caps in any::<u32>(), channel in any::<u32>(), prev in any::<u64>(),
                       buf in bytes(200), sflags in any::<u16>(), path in name(), tflags in any::<u16>(),
                       st in any::<u8>(), shf in any::<u32>(), shc in any::<u32>(), acc in any::<u32>()) {
        round_trip(&SessionSetupRequest {
            flags: SessionSetupRequestFlags::from_bits_retain(flags),
            security_mode: SecurityMode::from_bits_retain(u16::from(sm)),
            capabilities: Capabilities::from_bits_retain(caps),
            channel,
            previous_session_id: prev,
            security_buffer: buf.clone(),
        })?;
        round_trip(&SessionSetupResponse { session_flags: SessionFlags::from_bits_retain(sflags), security_buffer: buf })?;
        round_trip(&TreeConnectRequest { flags: TreeConnectFlags::from_bits_retain(tflags), path })?;
        round_trip(&TreeConnectResponse {
            share_type: ShareType(st),
            share_flags: ShareFlags::from_bits_retain(shf),
            capabilities: ShareCapabilities::from_bits_retain(shc),
            maximal_access: AccessMask::from_bits_retain(acc),
        })?;
        round_trip(&LogoffRequest)?;
        round_trip(&LogoffResponse)?;
        round_trip(&TreeDisconnectRequest)?;
        round_trip(&TreeDisconnectResponse)?;
        round_trip(&EchoRequest)?;
        round_trip(&EchoResponse)?;
        round_trip(&CancelRequest)?;
    }

    #[test]
    fn rt_create(f in (any::<u8>(), any::<u8>(), any::<u32>(), any::<u64>(), any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
                 n in name(), ctx in vec(create_request_context(), 0..6),
                 r in (any::<u8>(), any::<u8>(), any::<u32>(), ft(), ft(), ft(), ft(), any::<u64>(), any::<u64>(), any::<u32>(), file_id()),
                 rctx in vec(create_response_context(), 0..6)) {
        round_trip(&CreateRequest {
            security_flags: f.0,
            requested_oplock_level: OplockLevel(f.1),
            impersonation_level: ImpersonationLevel(f.2),
            smb_create_flags: f.3,
            desired_access: AccessMask::from_bits_retain(f.4),
            file_attributes: FileAttributes::from_bits_retain(f.5),
            share_access: ShareAccess::from_bits_retain(f.6),
            create_disposition: CreateDisposition(f.7),
            create_options: CreateOptions::from_bits_retain(f.8),
            name: n,
            contexts: ctx,
        })?;
        round_trip(&CreateResponse {
            oplock_level: OplockLevel(r.0),
            flags: r.1,
            create_action: CreateAction(r.2),
            creation_time: r.3,
            last_access_time: r.4,
            last_write_time: r.5,
            change_time: r.6,
            allocation_size: r.7,
            end_of_file: r.8,
            file_attributes: FileAttributes::from_bits_retain(r.9),
            file_id: r.10,
            contexts: rctx,
        })?;
    }

    #[test]
    fn rt_close_flush_lock(id in file_id(), fl in any::<u16>(), t in (ft(), ft(), ft(), ft()), sz in any::<(u64, u64, u32)>(),
                           seq in any::<u32>(), locks in vec((any::<u64>(), any::<u64>(), any::<u32>()), 1..5)) {
        round_trip(&CloseRequest { flags: CloseFlags::from_bits_retain(fl), file_id: id })?;
        round_trip(&CloseResponse {
            flags: CloseFlags::from_bits_retain(fl),
            creation_time: t.0,
            last_access_time: t.1,
            last_write_time: t.2,
            change_time: t.3,
            allocation_size: sz.0,
            end_of_file: sz.1,
            file_attributes: FileAttributes::from_bits_retain(sz.2),
        })?;
        round_trip(&FlushRequest { file_id: id })?;
        round_trip(&FlushResponse)?;
        round_trip(&LockRequest {
            lock_sequence: seq,
            file_id: id,
            locks: locks
                .into_iter()
                .map(|(offset, length, f)| LockElement { offset, length, flags: LockFlags::from_bits_retain(f) })
                .collect(),
        })?;
        round_trip(&LockResponse)?;
    }

    #[test]
    fn rt_read_write(r in (any::<u8>(), any::<u8>(), any::<u32>(), any::<u64>(), file_id(), any::<u32>(), any::<u32>(), any::<u32>()),
                     ci in bytes(40), data in bytes(3000), w in (any::<u32>(), any::<u32>(), any::<u32>()), use_ci in any::<bool>()) {
        round_trip(&ReadRequest {
            padding: r.0,
            flags: ReadFlags::from_bits_retain(r.1),
            length: r.2,
            offset: r.3,
            file_id: r.4,
            minimum_count: r.5,
            channel: r.6,
            remaining_bytes: r.7,
            read_channel_info: ci.clone(),
        })?;
        round_trip(&ReadResponse { data_remaining: w.0, flags: w.1, data: data.clone() })?;
        let (data, ci) = if use_ci { (Bytes::new(), ci) } else { (data, Bytes::new()) };
        round_trip(&WriteRequest {
            offset: r.3,
            file_id: r.4,
            channel: w.0,
            remaining_bytes: w.1,
            flags: WriteFlags::from_bits_retain(w.2),
            write_channel_info: ci,
            data,
        })?;
        round_trip(&WriteResponse { count: w.0, remaining: w.1 })?;
    }

    #[test]
    fn rt_ioctl_query_set(io in (any::<u32>(), file_id(), bytes(100), bytes(100), any::<u32>(), any::<u32>(), any::<u32>()),
                          q in (any::<u8>(), any::<u8>(), any::<u32>(), any::<u32>(), any::<u32>(), bytes(64)),
                          qd in (any::<u8>(), any::<u8>(), any::<u32>(), name(), any::<u32>()),
                          out in bytes(300), cn in (any::<u16>(), any::<u32>())) {
        round_trip(&IoctlRequest {
            ctl_code: io.0,
            file_id: io.1,
            input: io.2.clone(),
            output: io.3.clone(),
            max_input_response: io.4,
            max_output_response: io.5,
            flags: io.6,
        })?;
        round_trip(&IoctlResponse { ctl_code: io.0, file_id: io.1, input: io.2, output: io.3, flags: io.6 })?;
        round_trip(&QueryInfoRequest {
            info_type: InfoType(q.0),
            file_info_class: q.1,
            output_buffer_length: q.2,
            additional_information: q.3,
            flags: q.4,
            file_id: io.1,
            input_buffer: q.5.clone(),
        })?;
        round_trip(&QueryInfoResponse { output_buffer: out.clone() })?;
        round_trip(&SetInfoRequest {
            info_type: InfoType(q.0),
            file_info_class: q.1,
            additional_information: q.3,
            file_id: io.1,
            buffer: q.5,
        })?;
        round_trip(&SetInfoResponse)?;
        round_trip(&QueryDirectoryRequest {
            file_information_class: FileInfoClass(qd.0),
            flags: QueryDirectoryFlags::from_bits_retain(qd.1),
            file_index: qd.2,
            file_id: io.1,
            file_name: qd.3,
            output_buffer_length: qd.4,
        })?;
        round_trip(&QueryDirectoryResponse { output_buffer: out.clone() })?;
        round_trip(&ChangeNotifyRequest {
            flags: cn.0,
            output_buffer_length: cn.1,
            file_id: io.1,
            completion_filter: CompletionFilter::from_bits_retain(cn.1),
        })?;
        round_trip(&ChangeNotifyResponse { output_buffer: out })?;
    }

    #[test]
    fn rt_breaks(lvl in any::<u8>(), id in file_id(), n in (any::<u16>(), any::<u32>(), any::<[u8; 16]>(), any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>(), any::<u32>()),
                 dur in any::<u64>()) {
        round_trip(&OplockBreakNotification { oplock_level: OplockLevel(lvl), file_id: id })?;
        round_trip(&OplockBreakAck { oplock_level: OplockLevel(lvl), file_id: id })?;
        round_trip(&OplockBreakResponse { oplock_level: OplockLevel(lvl), file_id: id })?;
        let notification = LeaseBreakNotification {
            new_epoch: n.0,
            flags: n.1,
            lease_key: n.2,
            current_lease_state: LeaseState::from_bits_retain(n.3),
            new_lease_state: LeaseState::from_bits_retain(n.4),
            break_reason: n.5,
            access_mask_hint: n.6,
            share_mask_hint: n.7,
        };
        round_trip(&notification)?;
        let ack = LeaseBreakAck { flags: n.1, lease_key: n.2, lease_state: LeaseState::from_bits_retain(n.3), lease_duration: dur };
        round_trip(&ack)?;
        round_trip(&LeaseBreakResponse { flags: n.1, lease_key: n.2, lease_state: LeaseState::from_bits_retain(n.3), lease_duration: dur })?;
        // Classification of server OPLOCK_BREAK messages.
        let mut h = header_for::<LeaseBreakNotification>();
        h.message_id = u64::MAX;
        let raw = RawMessage::parse(encode_message(&h, &notification).unwrap().into_contiguous().freeze()).unwrap();
        prop_assert_eq!(BreakMessage::decode(&raw).unwrap(), BreakMessage::LeaseNotification(notification));
        let raw = RawMessage::parse(encode_message(&h, &OplockBreakNotification { oplock_level: OplockLevel(lvl), file_id: id }).unwrap().into_contiguous().freeze()).unwrap();
        prop_assert!(matches!(BreakMessage::decode(&raw).unwrap(), BreakMessage::OplockNotification(_)));
    }

    #[test]
    fn rt_error_response(ctxs in vec((any::<u32>(), bytes(40)), 0..4), data in bytes(60), status in any::<u32>()) {
        let err = if ctxs.is_empty() {
            ErrorResponse { error_contexts: vec![], error_data: data }
        } else {
            ErrorResponse {
                error_contexts: ctxs.into_iter().map(|(error_id, data)| ErrorContext { error_id, data }).collect(),
                error_data: Bytes::new(),
            }
        };
        let mut h = Header::request(Command::CREATE);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        h.status = NtStatus(status | 0xC000_0000);
        let raw = RawMessage::parse(encode_error_message(&h, &err).unwrap().into_contiguous().freeze()).unwrap();
        prop_assert!(raw.is_error_response());
        prop_assert_eq!(raw.decode_error().unwrap(), err);
    }

    #[test]
    fn rt_header(cc in any::<u16>(), st in any::<u32>(), cmd in any::<u16>(), cr in any::<u16>(), flags in any::<u32>(),
                 next in any::<u32>(), mid in any::<u64>(), is_async in any::<bool>(), a in any::<u64>(), sid in any::<u64>(), sig in any::<[u8; 16]>()) {
        let id = if is_async { HeaderId::Async { async_id: a } } else { HeaderId::Sync { process_id: (a >> 32) as u32, tree_id: a as u32 } };
        let flags = HeaderFlags::from_bits_retain(flags & !HeaderFlags::ASYNC_COMMAND.bits());
        let h = Header { credit_charge: cc, status: NtStatus(st), command: Command(cmd), credits: cr, flags, next_command: next, message_id: mid, id, session_id: sid, signature: sig };
        let d = Header::decode(&h.to_bytes()).unwrap();
        prop_assert_eq!(d.flags, h.wire_flags());
        prop_assert_eq!(Header { flags: h.wire_flags(), ..h }, d);
    }
}

// ---------------------------------------------------------------------------
// FSCC / FSCTL / directory entries
// ---------------------------------------------------------------------------

fn idempotent<T: InfoClass + PartialEq + std::fmt::Debug>(
    data: &[u8],
) -> Result<(), TestCaseError> {
    if let Ok(v) = T::decode(data) {
        let enc = v
            .to_bytes()
            .map_err(|e| TestCaseError::fail(format!("encode: {e}")))?;
        let again = T::decode(&enc).map_err(|e| TestCaseError::fail(format!("re-decode: {e}")))?;
        prop_assert_eq!(again, v);
    }
    Ok(())
}

fn fsctl_idempotent<T: FsctlData + PartialEq + std::fmt::Debug>(
    data: &[u8],
) -> Result<(), TestCaseError> {
    if let Ok(v) = T::decode(data) {
        let enc = v
            .to_bytes()
            .map_err(|e| TestCaseError::fail(format!("encode: {e}")))?;
        prop_assert_eq!(T::decode(&enc).unwrap(), v);
    }
    Ok(())
}

fn dir_entry() -> impl Strategy<Value = DirEntry> {
    (
        (
            any::<u32>(),
            ft(),
            ft(),
            ft(),
            ft(),
            any::<u64>(),
            any::<u64>(),
            any::<u32>(),
            any::<u32>(),
        ),
        (
            proptest::option::of(vec(any::<u8>(), 0..24)),
            proptest::option::of(any::<u64>()),
            proptest::option::of(any::<[u8; 16]>()),
            proptest::option::of(any::<u32>()),
        ),
        vec(any::<u8>(), 0..40),
    )
        .prop_map(|(a, b, n)| DirEntry {
            file_index: a.0,
            creation_time: a.1,
            last_access_time: a.2,
            last_write_time: a.3,
            change_time: a.4,
            end_of_file: a.5,
            allocation_size: a.6,
            file_attributes: FileAttributes::from_bits_retain(a.7),
            ea_size: a.8,
            short_name: b.0.map(|s| Utf16Name::from_wire(Bytes::from(s))),
            file_id: b.1,
            file_id_128: b.2,
            reparse_point_tag: b.3,
            file_name: Utf16Name::from_wire(Bytes::from(n)),
        })
}

use fsfast_smb_proto::Utf16Name;

proptest! {
    #![proptest_config(ProptestConfig { cases: 512, ..ProptestConfig::default() })]

    #[test]
    fn fscc_info_round_trips(data in vec(any::<u8>(), 0..200)) {
        idempotent::<FileBasicInformation>(&data)?;
        idempotent::<FileStandardInformation>(&data)?;
        idempotent::<FileInternalInformation>(&data)?;
        idempotent::<FileEaInformation>(&data)?;
        idempotent::<FileAccessInformation>(&data)?;
        idempotent::<FilePositionInformation>(&data)?;
        idempotent::<FileModeInformation>(&data)?;
        idempotent::<FileAlignmentInformation>(&data)?;
        idempotent::<FileEndOfFileInformation>(&data)?;
        idempotent::<FileAllocationInformation>(&data)?;
        idempotent::<FileNetworkOpenInformation>(&data)?;
        idempotent::<FileAttributeTagInformation>(&data)?;
        idempotent::<FileDispositionInformation>(&data)?;
        idempotent::<FileDispositionInformationEx>(&data)?;
        idempotent::<FileIdInformation>(&data)?;
        idempotent::<FileFsSizeInformation>(&data)?;
        idempotent::<FileFsFullSizeInformation>(&data)?;
        idempotent::<FileFsDeviceInformation>(&data)?;
        idempotent::<FileFsSectorSizeInformation>(&data)?;
        fsctl_idempotent::<ValidateNegotiateInfoResponse>(&data)?;
        fsctl_idempotent::<SrvCopyChunkResponse>(&data)?;
        fsctl_idempotent::<SrvRequestResumeKeyResponse>(&data)?;
        fsctl_idempotent::<SrvCopyChunkCopy>(&data)?;
        fsctl_idempotent::<ValidateNegotiateInfoRequest>(&data)?;
    }

    #[test]
    fn fscc_named_info_round_trips(n in name(), b in any::<bool>(), root in any::<u64>(), flags in any::<u32>(),
                                   attrs in any::<u32>(), maxlen in any::<u32>(),
                                   all in (ft(), ft(), ft(), ft(), any::<u32>(), any::<u64>(), any::<u64>(), any::<u32>(), any::<bool>(), any::<bool>()),
                                   streams in vec((name(), any::<u64>(), any::<u64>()), 0..4)) {
        let r = FileRenameInformation { replace_if_exists: b, root_directory: root, file_name: n.clone() };
        prop_assert_eq!(FileRenameInformation::decode(&r.to_bytes().unwrap()).unwrap(), r);
        let l = FileLinkInformation { replace_if_exists: b, root_directory: root, file_name: n.clone() };
        prop_assert_eq!(FileLinkInformation::decode(&l.to_bytes().unwrap()).unwrap(), l);
        let rx = FileRenameInformationEx { flags: RenameFlags::from_bits_retain(flags), root_directory: root, file_name: n.clone() };
        prop_assert_eq!(FileRenameInformationEx::decode(&rx.to_bytes().unwrap()).unwrap(), rx);
        let fa = FileFsAttributeInformation {
            file_system_attributes: FsAttributes::from_bits_retain(attrs),
            maximum_component_name_length: maxlen,
            file_system_name: n.clone(),
        };
        prop_assert_eq!(FileFsAttributeInformation::decode(&fa.to_bytes().unwrap()).unwrap(), fa);
        let info = FileAllInformation {
            basic: FileBasicInformation {
                creation_time: all.0,
                last_access_time: all.1,
                last_write_time: all.2,
                change_time: all.3,
                file_attributes: FileAttributes::from_bits_retain(all.4),
            },
            standard: FileStandardInformation {
                allocation_size: all.5,
                end_of_file: all.6,
                number_of_links: all.7,
                delete_pending: all.8,
                directory: all.9,
            },
            name: FileNameInformation { file_name: n },
            ..Default::default()
        };
        prop_assert_eq!(FileAllInformation::decode(&info.to_bytes().unwrap()).unwrap(), info);
        let s = FileStreamInformation {
            entries: streams.into_iter().map(|(name, size, allocation_size)| StreamEntry { name, size, allocation_size }).collect(),
        };
        prop_assert_eq!(FileStreamInformation::decode(&s.to_bytes().unwrap()).unwrap(), s);
    }

    #[test]
    fn directory_entries_round_trip(entries in vec(dir_entry(), 0..6), class_idx in 0usize..7) {
        let class = [
            FileInfoClass::DIRECTORY, FileInfoClass::FULL_DIRECTORY, FileInfoClass::BOTH_DIRECTORY,
            FileInfoClass::ID_BOTH_DIRECTORY, FileInfoClass::ID_FULL_DIRECTORY, FileInfoClass::ID_EXTD_DIRECTORY,
            FileInfoClass::NAMES,
        ][class_idx];
        let mut buf = BytesMut::new();
        encode_directory_entries(class, &entries, &mut buf).unwrap();
        let decoded: Vec<DirEntry> = DirectoryEntries::new(class, buf.clone().freeze()).unwrap().collect::<Result<_, _>>().unwrap();
        prop_assert_eq!(decoded.len(), entries.len());
        for (d, e) in decoded.iter().zip(&entries) {
            prop_assert_eq!(&d.file_name, &e.file_name);
            prop_assert_eq!(d.file_index, e.file_index);
        }
        let mut again = BytesMut::new();
        encode_directory_entries(class, &decoded, &mut again).unwrap();
        prop_assert_eq!(again, buf);
    }

    #[test]
    fn notify_and_interfaces_round_trip(n in vec((1u32..10, name()), 0..5), ifs in vec((any::<u32>(), any::<u32>(), any::<u64>(), any::<bool>(), any::<[u8; 16]>(), any::<u16>()), 0..4)) {
        let entries: Vec<FileNotifyInformation> = n.into_iter().map(|(a, file_name)| FileNotifyInformation { action: FileAction(a), file_name }).collect();
        let mut b = BytesMut::new();
        encode_notify_information(&entries, &mut b).unwrap();
        prop_assert_eq!(decode_notify_information(&b).unwrap(), entries);
        use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
        let infos: Vec<NetworkInterfaceInfo> = ifs.into_iter().map(|(if_index, capability, link_speed, v6, ip, port)| NetworkInterfaceInfo {
            if_index,
            capability,
            link_speed,
            address: Some(if v6 {
                SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0))
            } else {
                SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]), port))
            }),
        }).collect();
        let mut b = BytesMut::new();
        encode_network_interfaces(&infos, &mut b);
        prop_assert_eq!(decode_network_interfaces(&b).unwrap(), infos);
    }
}

// ---------------------------------------------------------------------------
// NTLM, SPNEGO
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 256, ..ProptestConfig::default() })]

    #[test]
    fn ntlm_messages_round_trip(flags in any::<u32>(), ch in any::<[u8; 8]>(), target in name(),
                                pairs in vec((1u16..=10, vec(any::<u8>(), 0..30)), 0..6),
                                v in any::<(u8, u8, u16)>(), lm in vec(any::<u8>(), 0..30), nt in vec(any::<u8>(), 0..100),
                                strs in (name(), name(), name()), key in vec(any::<u8>(), 0..16), mic in any::<[u8; 16]>()) {
        let version = NtlmVersion { major: v.0, minor: v.1, build: v.2, revision: 15 };
        let flags = NegotiateFlags::from_bits_retain(flags) | NegotiateFlags::UNICODE | NegotiateFlags::VERSION;
        let neg = NegotiateMessage { flags: flags - NegotiateFlags::OEM_DOMAIN_SUPPLIED - NegotiateFlags::OEM_WORKSTATION_SUPPLIED, domain: None, workstation: None, version: Some(version) };
        prop_assert_eq!(NegotiateMessage::decode(&neg.encode().unwrap()).unwrap(), neg);
        let info = AvPairs(pairs.into_iter().map(|(id, value)| AvPair { id, value }).collect());
        let c = ChallengeMessage { flags, server_challenge: ch, target_name: target, target_info: info.clone(), version: Some(version) };
        prop_assert_eq!(ChallengeMessage::decode(&c.encode().unwrap()).unwrap(), c);
        let mut enc = Vec::new();
        info.encode(&mut enc).unwrap();
        prop_assert_eq!(AvPairs::decode(&enc).unwrap(), info);
        let a = AuthenticateMessage {
            flags, lm_response: lm, nt_response: nt, domain: strs.0, user: strs.1, workstation: strs.2,
            encrypted_random_session_key: key, version: Some(version), mic,
        };
        prop_assert_eq!(AuthenticateMessage::decode(&a.encode().unwrap()).unwrap(), a);
    }

    #[test]
    fn spnego_tokens_round_trip(mechs in vec(vec(0u8..0x7F, 1..10), 0..4), tok in proptest::option::of(vec(any::<u8>(), 0..300)),
                                hint in proptest::option::of(vec(0x20u8..0x7F, 0..40)), mic in proptest::option::of(vec(any::<u8>(), 0..20)),
                                state in proptest::option::of(0u8..4), sm in proptest::option::of(vec(0u8..0x7F, 1..10))) {
        let init = NegTokenInit { mech_types: mechs, req_flags: None, mech_token: tok.clone(), hint_name: hint, mech_list_mic: mic.clone() };
        prop_assert_eq!(NegotiationToken::decode(&init.encode()).unwrap(), NegotiationToken::Init(init));
        let neg_state = state.map(|s| [NegState::AcceptCompleted, NegState::AcceptIncomplete, NegState::Reject, NegState::RequestMic][s as usize]);
        let resp = NegTokenResp { neg_state, supported_mech: sm, response_token: tok, mech_list_mic: mic };
        prop_assert_eq!(NegotiationToken::decode(&resp.encode()).unwrap(), NegotiationToken::Resp(resp));
    }
}

// ---------------------------------------------------------------------------
// Framing, compounds, signing, encryption, compression transform
// ---------------------------------------------------------------------------

proptest! {
    #![proptest_config(ProptestConfig { cases: 128, ..ProptestConfig::default() })]

    #[test]
    fn framing_preserves_frames(frames in vec(vec(any::<u8>(), 0..2000), 1..6), chunk in 1usize..700) {
        let mut stream = Vec::new();
        for f in &frames {
            stream.extend_from_slice(&transport_header(f.len()).unwrap());
            stream.extend_from_slice(f);
        }
        let mut dec = FrameDecoder::new();
        let mut buf = BytesMut::new();
        let mut out = Vec::new();
        for c in stream.chunks(chunk) {
            buf.extend_from_slice(c);
            while let Some(f) = dec.decode(&mut buf).unwrap() {
                out.push(f.to_vec());
            }
        }
        prop_assert_eq!(out, frames);
    }

    #[test]
    fn compound_build_split(kinds in vec(0u8..4, 1..6), data in bytes(500), names in vec(name(), 6)) {
        let mut chain = CompoundBuilder::new();
        for (i, k) in kinds.iter().enumerate() {
            let mut h = Header::request(Command::CREATE);
            h.message_id = i as u64;
            let related = i > 0;
            let push = |chain: &mut CompoundBuilder, h: Header, related: bool| -> fsfast_smb_proto::Result<()> {
                macro_rules! p { ($m:expr) => { if related { chain.push_related(h, &$m).map(|_| ()) } else { chain.push(h, &$m).map(|_| ()) } } }
                match k {
                    0 => p!(CreateRequest { name: names[i].clone(), ..Default::default() }),
                    1 => p!(WriteRequest { file_id: FileId::RELATED, data: data.clone(), ..Default::default() }),
                    2 => p!(QueryInfoRequest::for_class::<FileNetworkOpenInformation>(FileId::RELATED, 56)),
                    _ => p!(CloseRequest { file_id: FileId::RELATED, ..Default::default() }),
                }
            };
            push(&mut chain, h, related).unwrap();
        }
        let msgs = chain.finish();
        let mut frame = BytesMut::new();
        for m in &msgs {
            m.write_to(&mut frame);
        }
        let parts: Vec<RawMessage> = split_compound(frame.freeze()).collect::<Result<_, _>>().unwrap();
        prop_assert_eq!(parts.len(), msgs.len());
        for (i, (p, m)) in parts.iter().zip(&msgs).enumerate() {
            prop_assert_eq!(p.header().message_id, i as u64);
            prop_assert_eq!(&p.bytes()[..], &m.clone().into_contiguous()[..]);
            prop_assert_eq!(p.header().flags.contains(HeaderFlags::RELATED_OPERATIONS), i > 0);
            if i + 1 < msgs.len() {
                prop_assert_eq!(p.bytes().len() % 8, 0);
            }
        }
    }

    #[test]
    fn signing_detects_tampering(key in any::<[u8; 16]>(), data in bytes(3000), mid in any::<u64>(), flip in any::<prop::sample::Index>(), alg in 0usize..3) {
        let alg = [SigningAlgorithm::HmacSha256, SigningAlgorithm::AesCmac, SigningAlgorithm::AesGmac][alg];
        let s = Signer::new(alg, &key).unwrap();
        let mut h = Header::request(Command::WRITE);
        h.message_id = mid;
        let mut m = encode_message(&h, &WriteRequest { data, ..Default::default() }).unwrap();
        s.sign(&mut m).unwrap();
        let mut bytes = m.into_contiguous().to_vec();
        s.verify(&bytes).unwrap();
        let i = flip.index(bytes.len());
        bytes[i] ^= 0x01;
        // A flipped bit anywhere (header, signature, body) is detected.
        prop_assert!(s.verify(&bytes).is_err());
    }

    #[test]
    fn encryption_round_trip_and_tamper(c in 0usize..4, key in any::<[u8; 32]>(), parts in vec(vec(any::<u8>(), 0..800), 1..4), sid in any::<u64>(), flip in any::<prop::sample::Index>()) {
        let cipher = [Cipher::Aes128Ccm, Cipher::Aes128Gcm, Cipher::Aes256Ccm, Cipher::Aes256Gcm][c];
        let k = SmbCipher::new(cipher, &key[..cipher.key_len()]).unwrap();
        let slices: Vec<&[u8]> = parts.iter().map(|p| &p[..]).collect();
        let plain: Vec<u8> = parts.concat();
        let frame = k.encrypt(sid, &slices).unwrap();
        let (h, p) = k.decrypt_in_place(frame.clone()).unwrap();
        prop_assert_eq!(h.session_id, sid);
        prop_assert_eq!(&p[..], &plain[..]);
        let mut bad = frame.clone();
        // Tamper anywhere after the protocol id: tag, AAD or ciphertext.
        let i = 4 + flip.index(bad.len() - 4);
        bad[i] ^= 0x10;
        prop_assert!(k.decrypt_in_place(bad).is_err());
    }

    #[test]
    fn compression_transform_round_trip(prefix in bytes(100), reps in 0u32..5000, pattern in any::<u8>(), raw in bytes(100)) {
        use fsfast_smb_proto::crypto::compression::{CompressedPayload, pattern_v1_payload};
        let total = (prefix.len() + reps as usize + raw.len()) as u32;
        let t = CompressionTransform::Chained {
            original_compressed_segment_size: total,
            payloads: vec![
                CompressedPayload { algorithm: CompressionAlgorithm::NONE, flags: 1, original_payload_size: None, data: prefix.clone() },
                CompressedPayload { algorithm: CompressionAlgorithm::PATTERN_V1, flags: 0, original_payload_size: None, data: pattern_v1_payload(pattern, reps) },
                CompressedPayload { algorithm: CompressionAlgorithm::NONE, flags: 0, original_payload_size: None, data: raw.clone() },
            ],
        };
        let mut b = BytesMut::new();
        t.encode(&mut b).unwrap();
        let parsed = CompressionTransform::parse(&b.freeze()).unwrap();
        prop_assert_eq!(&parsed, &t);
        let out = parsed.decompress().unwrap();
        let mut expected = prefix.to_vec();
        expected.extend(std::iter::repeat_n(pattern, reps as usize));
        expected.extend_from_slice(&raw);
        prop_assert_eq!(&out[..], &expected[..]);
    }
}

// ---------------------------------------------------------------------------
// Mutated valid encodings never panic
// ---------------------------------------------------------------------------

/// What a corpus entry is, so the mutated bytes go to the right decoders.
#[derive(Clone, Copy, Debug)]
enum Kind {
    Message,
    Frame,
    DirEntries(FileInfoClass),
    Dfs,
    Interfaces,
    Notify,
    Streams,
    Ntlm,
    Spnego,
}

/// Valid, structurally rich encodings (offset/length/NextEntryOffset
/// fields everywhere). Random bytes rarely get past the first length check
/// of such structures; small mutations of valid ones do.
fn corpus() -> &'static [(Kind, Vec<u8>)] {
    static CORPUS: std::sync::OnceLock<Vec<(Kind, Vec<u8>)>> = std::sync::OnceLock::new();
    CORPUS.get_or_init(|| {
        fn msg<M: Message>(m: &M) -> Vec<u8> {
            encode_message(&header_for::<M>(), m)
                .unwrap()
                .into_contiguous()
                .to_vec()
        }
        let mut out = Vec::new();
        out.push((
            Kind::Message,
            msg(&NegotiateResponse {
                dialect_revision: Dialect::SMB_3_1_1,
                security_buffer: Bytes::from_static(&[0x60, 0x03, 0x06, 0x01, 0x00]),
                negotiate_contexts: vec![
                    NegotiateContext::PreauthIntegrity {
                        hash_algorithms: vec![HashAlgorithm::SHA512],
                        salt: Bytes::from_static(&[7; 32]),
                    },
                    NegotiateContext::Encryption {
                        ciphers: vec![CipherId::AES_128_GCM],
                    },
                    NegotiateContext::NetName("srv".into()),
                    NegotiateContext::Signing {
                        algorithms: vec![SigningAlgorithmId::AES_GMAC],
                    },
                ],
                ..Default::default()
            }),
        ));
        let lease = Lease::V2 {
            key: [1; 16],
            state: LeaseState::READ_CACHING,
            flags: 0,
            duration: 0,
            parent_key: [2; 16],
            epoch: 3,
        };
        out.push((
            Kind::Message,
            msg(&CreateRequest {
                name: "dir\\file.txt".into(),
                contexts: vec![
                    CreateRequestContext::QueryMaximalAccess { timestamp: None },
                    CreateRequestContext::RequestLease(lease),
                    CreateRequestContext::DurableHandleRequestV2 {
                        timeout: 0,
                        flags: 0,
                        create_guid: Guid([9; 16]),
                    },
                    CreateRequestContext::QueryOnDiskId,
                ],
                ..Default::default()
            }),
        ));
        out.push((
            Kind::Message,
            msg(&CreateResponse {
                contexts: vec![
                    CreateResponseContext::MaximalAccess {
                        query_status: NtStatus::SUCCESS,
                        maximal_access: AccessMask::GENERIC_READ,
                    },
                    CreateResponseContext::Lease(lease),
                    CreateResponseContext::OnDiskId {
                        disk_file_id: 1,
                        volume_id: 2,
                    },
                ],
                ..Default::default()
            }),
        ));
        let entries: Vec<DirEntry> = ["a.txt", "sub", "long name with spaces.bin"]
            .iter()
            .map(|n| DirEntry {
                file_name: Utf16Name::from(*n),
                short_name: Some(Utf16Name::from("A~1.TXT")),
                file_id: Some(5),
                ..Default::default()
            })
            .collect();
        for class in [
            FileInfoClass::ID_BOTH_DIRECTORY,
            FileInfoClass::ID_EXTD_DIRECTORY,
            FileInfoClass::NAMES,
        ] {
            let mut b = BytesMut::new();
            encode_directory_entries(class, &entries, &mut b).unwrap();
            out.push((Kind::DirEntries(class), b.to_vec()));
            out.push((
                Kind::Message,
                msg(&QueryDirectoryResponse {
                    output_buffer: b.freeze(),
                }),
            ));
        }
        let dfs = DfsReferralResponse {
            path_consumed: 10,
            header_flags: 3,
            referrals: vec![
                DfsReferral {
                    version: 4,
                    server_type: 1,
                    referral_entry_flags: 0,
                    proximity: 0,
                    time_to_live: 300,
                    target: DfsReferralTarget::Target {
                        dfs_path: "\\dom\\dfs".into(),
                        dfs_alternate_path: "\\dom\\dfs".into(),
                        network_address: "\\srv\\share".into(),
                    },
                },
                DfsReferral {
                    version: 3,
                    server_type: 0,
                    referral_entry_flags: dfs_entry_flags::NAME_LIST_REFERRAL,
                    proximity: 0,
                    time_to_live: 600,
                    target: DfsReferralTarget::NameList {
                        special_name: "dom".into(),
                        expanded_names: vec!["dc1".into(), "dc2".into()],
                    },
                },
            ],
        };
        out.push((Kind::Dfs, dfs.to_bytes().unwrap().to_vec()));
        out.push((
            Kind::Message,
            msg(&IoctlResponse {
                ctl_code: fsctl::DFS_GET_REFERRALS,
                output: dfs.to_bytes().unwrap(),
                ..Default::default()
            }),
        ));
        let mut b = BytesMut::new();
        encode_network_interfaces(
            &[
                NetworkInterfaceInfo {
                    if_index: 1,
                    capability: 1,
                    link_speed: 10,
                    address: Some("10.0.0.1:0".parse().unwrap()),
                },
                NetworkInterfaceInfo {
                    if_index: 2,
                    capability: 0,
                    link_speed: 20,
                    address: Some("[fe80::1]:0".parse().unwrap()),
                },
            ],
            &mut b,
        );
        out.push((Kind::Interfaces, b.to_vec()));
        let mut b = BytesMut::new();
        encode_notify_information(
            &[
                FileNotifyInformation {
                    action: FileAction::ADDED,
                    file_name: "x".into(),
                },
                FileNotifyInformation {
                    action: FileAction::REMOVED,
                    file_name: "yy\\z".into(),
                },
            ],
            &mut b,
        )
        .unwrap();
        out.push((Kind::Notify, b.to_vec()));
        out.push((
            Kind::Streams,
            FileStreamInformation {
                entries: vec![
                    StreamEntry {
                        name: "::$DATA".into(),
                        size: 1,
                        allocation_size: 8,
                    },
                    StreamEntry {
                        name: ":ads:$DATA".into(),
                        size: 2,
                        allocation_size: 8,
                    },
                ],
            }
            .to_bytes()
            .unwrap()
            .to_vec(),
        ));
        let mut sym = BytesMut::new();
        SymlinkErrorResponse {
            unparsed_path_length: 4,
            substitute_name: "\\??\\C:\\t".into(),
            print_name: "C:\\t".into(),
            flags: 0,
        }
        .encode(&mut sym)
        .unwrap();
        let mut h = Header::request(Command::CREATE);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        h.status = NtStatus::STOPPED_ON_SYMLINK;
        let err = ErrorResponse {
            error_contexts: vec![
                ErrorContext {
                    error_id: ERROR_ID_DEFAULT,
                    data: sym.freeze(),
                },
                ErrorContext {
                    error_id: 7,
                    data: Bytes::from_static(b"abc"),
                },
            ],
            error_data: Bytes::new(),
        };
        out.push((
            Kind::Message,
            encode_error_message(&h, &err)
                .unwrap()
                .into_contiguous()
                .to_vec(),
        ));
        // A compound frame: CREATE + QUERY_INFO + READ (+ data) + CLOSE.
        let mut chain = CompoundBuilder::new();
        let h = header_for::<CreateResponse>();
        chain.push(h, &CreateResponse::default()).unwrap();
        chain
            .push_related(
                h,
                &QueryInfoResponse {
                    output_buffer: Bytes::from_static(&[1; 56]),
                },
            )
            .unwrap();
        chain
            .push_related(
                h,
                &ReadResponse {
                    data: Bytes::from_static(b"hello world"),
                    ..Default::default()
                },
            )
            .unwrap();
        chain.push_related(h, &CloseResponse::default()).unwrap();
        let mut frame = BytesMut::new();
        for m in chain.finish() {
            m.write_to(&mut frame);
        }
        out.push((Kind::Frame, frame.to_vec()));
        let mut info = AvPairs::default();
        info.set(1, "SRV".encode_utf16().flat_map(u16::to_le_bytes).collect());
        info.set(7, 133_000_000_000_000_000u64.to_le_bytes().to_vec());
        out.push((
            Kind::Ntlm,
            ChallengeMessage {
                flags: NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::TARGET_INFO,
                server_challenge: [3; 8],
                target_name: "SRV".into(),
                target_info: info,
                version: Some(NtlmVersion::DEFAULT),
            }
            .encode()
            .unwrap(),
        ));
        out.push((
            Kind::Ntlm,
            AuthenticateMessage {
                flags: NegotiateFlags::CLIENT_DEFAULT,
                lm_response: vec![0; 24],
                nt_response: vec![5; 60],
                domain: "D".into(),
                user: "u".into(),
                workstation: "W".into(),
                encrypted_random_session_key: vec![1; 16],
                version: Some(NtlmVersion::DEFAULT),
                mic: [2; 16],
            }
            .encode()
            .unwrap(),
        ));
        out.push((
            Kind::Spnego,
            NegTokenInit {
                mech_types: vec![vec![0x2A, 0x86, 0x48], vec![0x2B, 0x06, 0x01]],
                hint_name: Some(b"not_defined_in_RFC4178@please_ignore".to_vec()),
                mech_list_mic: Some(vec![4; 16]),
                ..Default::default()
            }
            .encode(),
        ));
        out.push((
            Kind::Spnego,
            NegTokenResp {
                neg_state: Some(NegState::AcceptIncomplete),
                supported_mech: Some(vec![0x2B, 0x06, 0x01]),
                response_token: Some(vec![9; 200]),
                mech_list_mic: Some(vec![1; 16]),
            }
            .encode(),
        ));
        out
    })
}

fn decode_all(kind: Kind, data: &[u8]) {
    let bytes = Bytes::copy_from_slice(data);
    match kind {
        Kind::Message | Kind::Frame => {
            for m in split_compound(bytes).take(16).flatten() {
                let _ = m.is_error_response();
                if let Ok(e) = m.decode_error() {
                    let _ = e.symlink();
                    let _ = e.share_redirect();
                    let _ = e.required_buffer_size();
                }
                let _ = m.decode::<NegotiateResponse>();
                let _ = m.decode::<CreateRequest>();
                let _ = m.decode::<CreateResponse>();
                let _ = m.decode::<QueryInfoResponse>();
                let _ = m.decode::<ReadResponse>();
                let _ = m.decode::<CloseResponse>();
                if let Ok(q) = m.decode::<QueryDirectoryResponse>() {
                    for class in [
                        FileInfoClass::ID_BOTH_DIRECTORY,
                        FileInfoClass::ID_EXTD_DIRECTORY,
                        FileInfoClass::NAMES,
                    ] {
                        let n = q.entries(class).unwrap().take(1000).count();
                        assert!(n < 1000);
                    }
                }
                if let Ok(io) = m.decode::<IoctlResponse>() {
                    let _ = DfsReferralResponse::decode(&io.output);
                }
            }
        }
        Kind::DirEntries(class) => {
            let n = DirectoryEntries::new(class, bytes)
                .unwrap()
                .take(1000)
                .count();
            assert!(n < 1000);
        }
        Kind::Dfs => {
            let _ = DfsReferralResponse::decode(data);
        }
        Kind::Interfaces => {
            let _ = decode_network_interfaces(data);
        }
        Kind::Notify => {
            let _ = decode_notify_information(data);
        }
        Kind::Streams => {
            let _ = FileStreamInformation::decode(data);
        }
        Kind::Ntlm => {
            let _ = ChallengeMessage::decode(data);
            let _ = AuthenticateMessage::decode(data);
            let mut c = NtlmClient::new(NtlmCredentials::new("u", "p"));
            c.step(&[]).unwrap();
            let _ = c.step(data);
        }
        Kind::Spnego => {
            let _ = NegotiationToken::decode(data);
            let mut sp = SpnegoClient::ntlm(NtlmCredentials::new("u", "p"));
            let _ = sp.step(data);
            let _ = sp.step(data);
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 2048, ..ProptestConfig::default() })]

    #[test]
    fn mutated_valid_encodings_never_panic(
        idx in any::<prop::sample::Index>(),
        edits in vec((any::<prop::sample::Index>(), any::<u8>()), 1..6),
        cut in proptest::option::of(any::<prop::sample::Index>()),
    ) {
        let corpus = corpus();
        let (kind, base) = &corpus[idx.index(corpus.len())];
        let mut data = base.clone();
        for (at, v) in edits {
            let i = at.index(data.len());
            // Bias towards values that make offsets/lengths point at the
            // edges: 0, small, 0xFF.., or the original byte +/- 1.
            data[i] = match v % 6 {
                0 => 0,
                1 => 0xFF,
                2 => data[i].wrapping_add(1),
                3 => data[i].wrapping_sub(1),
                _ => v,
            };
        }
        if let Some(c) = cut {
            data.truncate(c.index(data.len() + 1));
        }
        decode_all(*kind, &data);
    }
}

#[test]
fn mutation_corpus_decodes_cleanly() {
    // The unmutated corpus must decode, or the mutation property tests
    // little beyond the first error path.
    for (kind, data) in corpus() {
        match kind {
            Kind::Message => {
                let raw = RawMessage::parse(Bytes::copy_from_slice(data)).unwrap();
                let ok = match raw.command() {
                    Command::NEGOTIATE => raw.decode::<NegotiateResponse>().is_ok(),
                    Command::CREATE if raw.is_error_response() => {
                        raw.decode_error().unwrap().symlink().is_ok()
                    }
                    Command::CREATE if raw.header().is_response() => {
                        raw.decode::<CreateResponse>().is_ok()
                    }
                    Command::CREATE => raw.decode::<CreateRequest>().is_ok(),
                    Command::QUERY_DIRECTORY => raw.decode::<QueryDirectoryResponse>().is_ok(),
                    Command::IOCTL => raw
                        .decode::<IoctlResponse>()
                        .is_ok_and(|io| DfsReferralResponse::decode(&io.output).is_ok()),
                    c => panic!("unexpected corpus command {c:?}"),
                };
                assert!(ok, "{:?}", raw.command());
            }
            Kind::Frame => assert_eq!(
                split_compound(Bytes::copy_from_slice(data))
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                4
            ),
            Kind::DirEntries(class) => assert_eq!(
                DirectoryEntries::new(*class, Bytes::copy_from_slice(data))
                    .unwrap()
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap()
                    .len(),
                3
            ),
            Kind::Dfs => assert_eq!(
                DfsReferralResponse::decode(data).unwrap().referrals.len(),
                2
            ),
            Kind::Interfaces => assert_eq!(decode_network_interfaces(data).unwrap().len(), 2),
            Kind::Notify => assert_eq!(decode_notify_information(data).unwrap().len(), 2),
            Kind::Streams => {
                assert_eq!(
                    FileStreamInformation::decode(data).unwrap().entries.len(),
                    2
                )
            }
            Kind::Ntlm => assert!(
                ChallengeMessage::decode(data).is_ok() || AuthenticateMessage::decode(data).is_ok()
            ),
            Kind::Spnego => assert!(NegotiationToken::decode(data).is_ok()),
        }
    }
}

#[test]
fn header_len_is_64() {
    assert_eq!(HEADER_LEN, 64);
}
