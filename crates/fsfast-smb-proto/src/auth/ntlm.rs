//! NTLMv2 client authentication ([MS-NLMP]).
//!
//! [`NtlmClient`] produces the NEGOTIATE_MESSAGE, consumes the server's
//! CHALLENGE_MESSAGE and produces the AUTHENTICATE_MESSAGE with an NTLMv2
//! response. It follows what Windows and pyspnego (smbprotocol's
//! authentication stack) do:
//!
//! * NEGOTIATE requests 128-bit keys, key exchange, extended session
//!   security, signing and sealing, and always carries a VERSION.
//! * When the CHALLENGE carries `MsvAvTimestamp`, that timestamp is used in
//!   the NTLMv2 response, `MsvAvFlags` gets the MIC bit, the LM response is
//!   zeroed and the AUTHENTICATE carries a MIC over all three messages.
//! * With `NTLMSSP_NEGOTIATE_KEY_EXCH` the exported session key is a fresh
//!   random key sent RC4-encrypted under the key-exchange key.
//! * Anonymous authentication sends an empty NT response and a one-byte LM
//!   response.
//!
//! Only NTLMv2 is implemented: LM and NTLMv1 responses are insecure and
//! every server from the last two decades accepts NTLMv2.
//!
//! The NTLM message-integrity functions (`GSS_GetMIC`/`GSS_VerifyMIC` with
//! extended session security) are provided for the SPNEGO `mechListMIC`.
//!
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

use std::fmt;

use bitflags::bitflags;
use hmac::{Hmac, KeyInit, Mac};
use md4::Md4;
use md5::{Digest, Md5};
use rc4::{Rc4, StreamCipher};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{AuthStep, Authenticator, GssMechanism};
use crate::error::{ProtoError, Result};
use crate::fscc::FileTime;
use crate::wire::{Reader, decode_utf16le, utf16le_vec};

/// `NTLMSSP\0`.
pub const NTLMSSP_SIGNATURE: &[u8; 8] = b"NTLMSSP\0";
/// DER content octets of the NTLMSSP mechanism OID 1.3.6.1.4.1.311.2.2.10.
pub const NTLMSSP_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

const MSG_NEGOTIATE: u32 = 1;
const MSG_CHALLENGE: u32 = 2;
const MSG_AUTHENTICATE: u32 = 3;

bitflags! {
    /// NTLM `NegotiateFlags` ([MS-NLMP] §2.2.2.5).
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct NegotiateFlags: u32 {
        /// `NTLMSSP_NEGOTIATE_UNICODE`.
        const UNICODE = 0x0000_0001;
        /// `NTLM_NEGOTIATE_OEM`.
        const OEM = 0x0000_0002;
        /// `NTLMSSP_REQUEST_TARGET`.
        const REQUEST_TARGET = 0x0000_0004;
        /// `NTLMSSP_NEGOTIATE_SIGN`.
        const SIGN = 0x0000_0010;
        /// `NTLMSSP_NEGOTIATE_SEAL`.
        const SEAL = 0x0000_0020;
        /// `NTLMSSP_NEGOTIATE_DATAGRAM`.
        const DATAGRAM = 0x0000_0040;
        /// `NTLMSSP_NEGOTIATE_LM_KEY`.
        const LM_KEY = 0x0000_0080;
        /// `NTLMSSP_NEGOTIATE_NTLM`.
        const NTLM = 0x0000_0200;
        /// `NTLMSSP_ANONYMOUS` (the "J" bit).
        const ANONYMOUS = 0x0000_0800;
        /// `NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED`.
        const OEM_DOMAIN_SUPPLIED = 0x0000_1000;
        /// `NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED`.
        const OEM_WORKSTATION_SUPPLIED = 0x0000_2000;
        /// `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`.
        const ALWAYS_SIGN = 0x0000_8000;
        /// `NTLMSSP_TARGET_TYPE_DOMAIN`.
        const TARGET_TYPE_DOMAIN = 0x0001_0000;
        /// `NTLMSSP_TARGET_TYPE_SERVER`.
        const TARGET_TYPE_SERVER = 0x0002_0000;
        /// `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.
        const EXTENDED_SESSION_SECURITY = 0x0008_0000;
        /// `NTLMSSP_NEGOTIATE_IDENTIFY`.
        const IDENTIFY = 0x0010_0000;
        /// `NTLMSSP_REQUEST_NON_NT_SESSION_KEY`.
        const REQUEST_NON_NT_SESSION_KEY = 0x0040_0000;
        /// `NTLMSSP_NEGOTIATE_TARGET_INFO`.
        const TARGET_INFO = 0x0080_0000;
        /// `NTLMSSP_NEGOTIATE_VERSION`.
        const VERSION = 0x0200_0000;
        /// `NTLMSSP_NEGOTIATE_128`.
        const KEY_128 = 0x2000_0000;
        /// `NTLMSSP_NEGOTIATE_KEY_EXCH`.
        const KEY_EXCH = 0x4000_0000;
        /// `NTLMSSP_NEGOTIATE_56`.
        const KEY_56 = 0x8000_0000;
    }
}

impl NegotiateFlags {
    /// The flags [`NtlmClient`] requests by default (the same set pyspnego
    /// and Windows SSPI send): 128/56-bit keys, key exchange, version,
    /// extended session security, always-sign, NTLM, seal, sign, request
    /// target, OEM and Unicode.
    pub const CLIENT_DEFAULT: NegotiateFlags = NegotiateFlags::from_bits_retain(0xE208_8237);
}

/// `AvId` values of an `AV_PAIR` ([MS-NLMP] §2.2.2.1).
pub mod av_id {
    /// `MsvAvEOL`: end of the list.
    pub const EOL: u16 = 0x0000;
    /// `MsvAvNbComputerName`.
    pub const NB_COMPUTER_NAME: u16 = 0x0001;
    /// `MsvAvNbDomainName`.
    pub const NB_DOMAIN_NAME: u16 = 0x0002;
    /// `MsvAvDnsComputerName`.
    pub const DNS_COMPUTER_NAME: u16 = 0x0003;
    /// `MsvAvDnsDomainName`.
    pub const DNS_DOMAIN_NAME: u16 = 0x0004;
    /// `MsvAvDnsTreeName`.
    pub const DNS_TREE_NAME: u16 = 0x0005;
    /// `MsvAvFlags`.
    pub const FLAGS: u16 = 0x0006;
    /// `MsvAvTimestamp`.
    pub const TIMESTAMP: u16 = 0x0007;
    /// `MsvAvSingleHost`.
    pub const SINGLE_HOST: u16 = 0x0008;
    /// `MsvAvTargetName`.
    pub const TARGET_NAME: u16 = 0x0009;
    /// `MsvAvChannelBindings`.
    pub const CHANNEL_BINDINGS: u16 = 0x000A;
}

/// `MsvAvFlags` bits.
pub mod av_flags {
    /// The server's account authentication is constrained.
    pub const CONSTRAINED: u32 = 0x0000_0001;
    /// The AUTHENTICATE_MESSAGE carries a MIC.
    pub const MIC_PROVIDED: u32 = 0x0000_0002;
    /// The target name came from an untrusted source.
    pub const UNTRUSTED_SPN_SOURCE: u32 = 0x0000_0004;
}

/// One `AV_PAIR` with its raw value.
#[derive(Clone, PartialEq, Eq)]
pub struct AvPair {
    /// The `AvId`.
    pub id: u16,
    /// The raw value bytes.
    pub value: Vec<u8>,
}

impl fmt::Debug for AvPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.id {
            av_id::NB_COMPUTER_NAME..=av_id::DNS_TREE_NAME | av_id::TARGET_NAME => {
                write!(
                    f,
                    "AvPair({}, {:?})",
                    self.id,
                    crate::wire::decode_utf16le_lossy(&self.value)
                )
            }
            _ => write!(f, "AvPair({}, {:02x?})", self.id, self.value),
        }
    }
}

/// An ordered `AV_PAIR` list (`TargetInfo`), without the terminating
/// `MsvAvEOL`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AvPairs(pub Vec<AvPair>);

impl AvPairs {
    /// Decode a list. Stops at `MsvAvEOL`; a missing terminator is
    /// tolerated (some servers omit it), a truncated pair is not.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = Reader::new(buf, "NTLM AV_PAIR list");
        let mut out = Vec::new();
        while r.remaining() > 0 {
            let id = r.u16()?;
            let len = usize::from(r.u16()?);
            let value = r.bytes(len)?;
            if id == av_id::EOL {
                break;
            }
            out.push(AvPair {
                id,
                value: value.to_vec(),
            });
        }
        Ok(AvPairs(out))
    }

    /// Encode the list followed by `MsvAvEOL`.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        for p in &self.0 {
            let len = u16::try_from(p.value.len())
                .map_err(|_| ProtoError::InvalidInput("AV_PAIR value too long"))?;
            out.extend_from_slice(&p.id.to_le_bytes());
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(&p.value);
        }
        out.extend_from_slice(&[0, 0, 0, 0]);
        Ok(())
    }

    /// The value of the first pair with `id`.
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.0.iter().find(|p| p.id == id).map(|p| &p.value[..])
    }

    /// Replace the value of the first pair with `id`, or append a new pair.
    pub fn set(&mut self, id: u16, value: Vec<u8>) {
        match self.0.iter_mut().find(|p| p.id == id) {
            Some(p) => p.value = value,
            None => self.0.push(AvPair { id, value }),
        }
    }

    /// A text-valued pair decoded from UTF-16LE.
    pub fn get_string(&self, id: u16) -> Option<String> {
        self.get(id).map(crate::wire::decode_utf16le_lossy)
    }

    /// `MsvAvTimestamp`, if present.
    pub fn timestamp(&self) -> Option<FileTime> {
        let v: [u8; 8] = self.get(av_id::TIMESTAMP)?.try_into().ok()?;
        Some(FileTime(u64::from_le_bytes(v)))
    }

    /// `MsvAvFlags`, if present.
    pub fn flags(&self) -> Option<u32> {
        let v: [u8; 4] = self.get(av_id::FLAGS)?.try_into().ok()?;
        Some(u32::from_le_bytes(v))
    }
}

/// The NTLM `VERSION` structure ([MS-NLMP] §2.2.2.10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NtlmVersion {
    /// Product major version.
    pub major: u8,
    /// Product minor version.
    pub minor: u8,
    /// Product build number.
    pub build: u16,
    /// NTLM revision (`NTLMSSP_REVISION_W2K3` = 15).
    pub revision: u8,
}

impl NtlmVersion {
    /// `NTLMSSP_REVISION_W2K3`.
    pub const REVISION_W2K3: u8 = 0x0F;

    /// The version [`NtlmClient`] sends by default: 10.0, build 0,
    /// revision 15. The OS fields are informational only.
    pub const DEFAULT: NtlmVersion = NtlmVersion {
        major: 10,
        minor: 0,
        build: 0,
        revision: Self::REVISION_W2K3,
    };

    /// The 8 wire bytes.
    pub fn to_bytes(self) -> [u8; 8] {
        let b = self.build.to_le_bytes();
        [self.major, self.minor, b[0], b[1], 0, 0, 0, self.revision]
    }

    /// Parse 8 wire bytes.
    pub fn from_bytes(b: [u8; 8]) -> Self {
        NtlmVersion {
            major: b[0],
            minor: b[1],
            build: u16::from_le_bytes([b[2], b[3]]),
            revision: b[7],
        }
    }
}

/// Read an NTLM `(Len, MaxLen, Offset)` payload field and return the slice
/// it designates in `msg`.
fn read_field<'a>(r: &mut Reader<'_>, msg: &'a [u8], what: &'static str) -> Result<&'a [u8]> {
    let len = usize::from(r.u16()?);
    let _max = r.u16()?;
    let off = r.u32()? as usize;
    if len == 0 {
        return Ok(&[]);
    }
    crate::wire::slice_ref(msg, off, len, what)
}

/// Builds the variable payload of an NTLM message and its field
/// descriptors.
struct PayloadBuilder {
    fields: Vec<u8>,
    payload: Vec<u8>,
    next_offset: usize,
}

impl PayloadBuilder {
    fn new(payload_offset: usize) -> Self {
        PayloadBuilder {
            fields: Vec::with_capacity(48),
            payload: Vec::with_capacity(256),
            next_offset: payload_offset,
        }
    }

    fn add(&mut self, data: &[u8]) -> Result<()> {
        let len = u16::try_from(data.len())
            .map_err(|_| ProtoError::InvalidInput("NTLM field too long"))?;
        let off = u32::try_from(self.next_offset)
            .map_err(|_| ProtoError::InvalidInput("NTLM message too long"))?;
        self.fields.extend_from_slice(&len.to_le_bytes());
        self.fields.extend_from_slice(&len.to_le_bytes());
        self.fields.extend_from_slice(&off.to_le_bytes());
        self.payload.extend_from_slice(data);
        self.next_offset += data.len();
        Ok(())
    }
}

fn check_header(r: &mut Reader<'_>, expected: u32, what: &'static str) -> Result<()> {
    if &r.array::<8>()? != NTLMSSP_SIGNATURE {
        return Err(ProtoError::malformed(what, "missing NTLMSSP signature"));
    }
    if r.u32()? != expected {
        return Err(ProtoError::malformed(what, "unexpected NTLM message type"));
    }
    Ok(())
}

/// NTLM NEGOTIATE_MESSAGE ([MS-NLMP] §2.2.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NegotiateMessage {
    /// Requested flags.
    pub flags: NegotiateFlags,
    /// OEM domain name (rarely sent).
    pub domain: Option<String>,
    /// OEM workstation name (rarely sent).
    pub workstation: Option<String>,
    /// Client version (sets `NTLMSSP_NEGOTIATE_VERSION`).
    pub version: Option<NtlmVersion>,
}

impl NegotiateMessage {
    /// Encode. Payload layout matches pyspnego/Windows: version, then the
    /// (usually empty) domain and workstation.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut flags = self.flags;
        let mut b = PayloadBuilder::new(32);
        // NTLMSSP_NEGOTIATE_VERSION announces the 8-byte VERSION field, so
        // the flag follows `version` exactly.
        flags.set(NegotiateFlags::VERSION, self.version.is_some());
        if let Some(v) = self.version {
            b.payload.extend_from_slice(&v.to_bytes());
            b.next_offset += 8;
        }
        let domain = self.domain.as_deref().unwrap_or("");
        let ws = self.workstation.as_deref().unwrap_or("");
        flags.set(NegotiateFlags::OEM_DOMAIN_SUPPLIED, !domain.is_empty());
        flags.set(NegotiateFlags::OEM_WORKSTATION_SUPPLIED, !ws.is_empty());
        b.add(domain.as_bytes())?;
        b.add(ws.as_bytes())?;
        let mut out = Vec::with_capacity(32 + b.payload.len());
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&MSG_NEGOTIATE.to_le_bytes());
        out.extend_from_slice(&flags.bits().to_le_bytes());
        out.extend_from_slice(&b.fields);
        out.extend_from_slice(&b.payload);
        Ok(out)
    }

    /// Decode (used by tests and mock servers).
    pub fn decode(msg: &[u8]) -> Result<Self> {
        const W: &str = "NTLM NEGOTIATE_MESSAGE";
        let mut r = Reader::new(msg, W);
        check_header(&mut r, MSG_NEGOTIATE, W)?;
        let flags = NegotiateFlags::from_bits_retain(r.u32()?);
        let domain = read_field(&mut r, msg, W)?;
        let workstation = read_field(&mut r, msg, W)?;
        let version = if flags.contains(NegotiateFlags::VERSION) {
            Some(NtlmVersion::from_bytes(r.array()?))
        } else {
            None
        };
        let s = |b: &[u8]| (!b.is_empty()).then(|| String::from_utf8_lossy(b).into_owned());
        Ok(NegotiateMessage {
            flags,
            domain: s(domain),
            workstation: s(workstation),
            version,
        })
    }
}

/// NTLM CHALLENGE_MESSAGE ([MS-NLMP] §2.2.1.2).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ChallengeMessage {
    /// Flags selected by the server.
    pub flags: NegotiateFlags,
    /// The server challenge.
    pub server_challenge: [u8; 8],
    /// Target (server or domain) name.
    pub target_name: String,
    /// `TargetInfo` AV pairs.
    pub target_info: AvPairs,
    /// Server version, when sent.
    pub version: Option<NtlmVersion>,
}

impl ChallengeMessage {
    /// Decode a CHALLENGE_MESSAGE.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        const W: &str = "NTLM CHALLENGE_MESSAGE";
        let mut r = Reader::new(msg, W);
        check_header(&mut r, MSG_CHALLENGE, W)?;
        let target_name = read_field(&mut r, msg, W)?;
        let flags = NegotiateFlags::from_bits_retain(r.u32()?);
        let server_challenge = r.array()?;
        r.skip(8)?;
        // Very old servers end the message here (no TargetInfo fields).
        let target_info = if r.remaining() >= 8 {
            read_field(&mut r, msg, W)?
        } else {
            &[]
        };
        let version = if flags.contains(NegotiateFlags::VERSION) && r.remaining() >= 8 {
            Some(NtlmVersion::from_bytes(r.array()?))
        } else {
            None
        };
        let target_name = if flags.contains(NegotiateFlags::UNICODE) {
            crate::wire::decode_utf16le_lossy(target_name)
        } else {
            String::from_utf8_lossy(target_name).into_owned()
        };
        Ok(ChallengeMessage {
            flags,
            server_challenge,
            target_name,
            target_info: AvPairs::decode(target_info)?,
            version,
        })
    }

    /// Encode (used by tests and mock servers). Unicode target name.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut info = Vec::new();
        if !self.target_info.0.is_empty() {
            self.target_info.encode(&mut info)?;
        }
        let name = utf16le_vec(&self.target_name);
        let mut b = PayloadBuilder::new(56);
        b.add(&name)?;
        let name_field: Vec<u8> = b.fields.drain(..).collect();
        b.add(&info)?;
        let info_field: Vec<u8> = b.fields.drain(..).collect();
        let mut out = Vec::with_capacity(56 + b.payload.len());
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&MSG_CHALLENGE.to_le_bytes());
        out.extend_from_slice(&name_field);
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        out.extend_from_slice(&self.server_challenge);
        out.extend_from_slice(&[0; 8]);
        out.extend_from_slice(&info_field);
        out.extend_from_slice(&self.version.map_or([0; 8], NtlmVersion::to_bytes));
        out.extend_from_slice(&b.payload);
        Ok(out)
    }
}

/// Offset of the MIC in an AUTHENTICATE_MESSAGE (after the 8-byte VERSION).
pub const AUTHENTICATE_MIC_OFFSET: usize = 72;
const AUTHENTICATE_PAYLOAD_OFFSET: usize = 88;

/// NTLM AUTHENTICATE_MESSAGE ([MS-NLMP] §2.2.1.3).
///
/// The encoder always reserves the VERSION (zero unless
/// `NTLMSSP_NEGOTIATE_VERSION` is set) and MIC fields, as Windows does, so
/// the payload starts at offset 88.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct AuthenticateMessage {
    /// Negotiated flags.
    pub flags: NegotiateFlags,
    /// `LmChallengeResponse`.
    pub lm_response: Vec<u8>,
    /// `NtChallengeResponse`.
    pub nt_response: Vec<u8>,
    /// User's domain.
    pub domain: String,
    /// User name.
    pub user: String,
    /// Client workstation name.
    pub workstation: String,
    /// `EncryptedRandomSessionKey` (empty without key exchange).
    pub encrypted_random_session_key: Vec<u8>,
    /// Client version.
    pub version: Option<NtlmVersion>,
    /// Message integrity code (zero when not provided).
    pub mic: [u8; 16],
}

impl fmt::Debug for AuthenticateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticateMessage")
            .field("flags", &self.flags)
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("workstation", &self.workstation)
            .field("nt_response_len", &self.nt_response.len())
            .finish_non_exhaustive()
    }
}

impl AuthenticateMessage {
    /// Encode. Payload order matches pyspnego: LM, NT, domain, user,
    /// workstation, session key.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut b = PayloadBuilder::new(AUTHENTICATE_PAYLOAD_OFFSET);
        b.add(&self.lm_response)?;
        b.add(&self.nt_response)?;
        b.add(&utf16le_vec(&self.domain))?;
        b.add(&utf16le_vec(&self.user))?;
        b.add(&utf16le_vec(&self.workstation))?;
        b.add(&self.encrypted_random_session_key)?;
        let mut out = Vec::with_capacity(AUTHENTICATE_PAYLOAD_OFFSET + b.payload.len());
        out.extend_from_slice(NTLMSSP_SIGNATURE);
        out.extend_from_slice(&MSG_AUTHENTICATE.to_le_bytes());
        out.extend_from_slice(&b.fields);
        out.extend_from_slice(&self.flags.bits().to_le_bytes());
        let version = if self.flags.contains(NegotiateFlags::VERSION) {
            self.version
        } else {
            None
        };
        out.extend_from_slice(&version.map_or([0; 8], NtlmVersion::to_bytes));
        out.extend_from_slice(&self.mic);
        out.extend_from_slice(&b.payload);
        Ok(out)
    }

    /// Decode (used by tests and mock servers). The MIC is read when the
    /// payload starts at or after offset 88.
    pub fn decode(msg: &[u8]) -> Result<Self> {
        const W: &str = "NTLM AUTHENTICATE_MESSAGE";
        let mut r = Reader::new(msg, W);
        check_header(&mut r, MSG_AUTHENTICATE, W)?;
        let mut min_off = usize::MAX;
        let mut field = |r: &mut Reader<'_>| -> Result<&[u8]> {
            let save = r.clone();
            let f = read_field(r, msg, W)?;
            let mut s = save;
            let len = s.u16()?;
            s.skip(2)?;
            let off = s.u32()? as usize;
            if len > 0 {
                min_off = min_off.min(off);
            }
            Ok(f)
        };
        let lm = field(&mut r)?.to_vec();
        let nt = field(&mut r)?.to_vec();
        let domain = field(&mut r)?.to_vec();
        let user = field(&mut r)?.to_vec();
        let ws = field(&mut r)?.to_vec();
        let key = field(&mut r)?.to_vec();
        let flags = NegotiateFlags::from_bits_retain(r.u32()?);
        let unicode = flags.contains(NegotiateFlags::UNICODE);
        let text = |b: &[u8]| -> Result<String> {
            if unicode {
                decode_utf16le(b, W)
            } else {
                Ok(String::from_utf8_lossy(b).into_owned())
            }
        };
        let mut version = None;
        let mut mic = [0u8; 16];
        if min_off >= AUTHENTICATE_PAYLOAD_OFFSET && msg.len() >= AUTHENTICATE_PAYLOAD_OFFSET {
            if flags.contains(NegotiateFlags::VERSION) {
                version = Some(NtlmVersion::from_bytes(r.array()?));
            } else {
                r.skip(8)?;
            }
            mic = r.array()?;
        }
        Ok(AuthenticateMessage {
            flags,
            lm_response: lm,
            nt_response: nt,
            domain: text(&domain)?,
            user: text(&user)?,
            workstation: text(&ws)?,
            encrypted_random_session_key: key,
            version,
            mic,
        })
    }
}

// ---------------------------------------------------------------------------
// Cryptographic primitives ([MS-NLMP] §3.3.2, §3.4.4, §3.4.5).
// ---------------------------------------------------------------------------

fn hmac_md5(key: &[u8], parts: &[&[u8]]) -> [u8; 16] {
    let mut m = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC accepts any key length");
    for p in parts {
        m.update(p);
    }
    m.finalize().into_bytes().into()
}

fn md5(parts: &[&[u8]]) -> [u8; 16] {
    let mut h = Md5::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// The NT hash (NTOWFv1): `MD4(UTF-16LE(password))`.
pub fn nt_hash(password: &str) -> [u8; 16] {
    let pw = Zeroizing::new(utf16le_vec(password));
    let mut h = Md4::new();
    h.update(&pw[..]);
    h.finalize().into()
}

/// Uppercase the way Windows' `RtlUpcaseUnicodeString` does: a 1:1
/// per-character mapping (characters whose uppercase form expands, like
/// `ß`, are left unchanged).
fn windows_upper(s: &str) -> String {
    s.chars()
        .map(|c| {
            let mut up = c.to_uppercase();
            match (up.next(), up.next()) {
                (Some(u), None) => u,
                _ => c,
            }
        })
        .collect()
}

/// NTOWFv2: `HMAC_MD5(NT hash, UTF-16LE(Uppercase(user) || domain))`.
pub fn ntowfv2(nt_hash: &[u8; 16], user: &str, domain: &str) -> [u8; 16] {
    let ud = utf16le_vec(&(windows_upper(user) + domain));
    hmac_md5(nt_hash, &[&ud])
}

/// The result of the NTLMv2 response computation.
pub struct Ntlmv2Response {
    /// `NtChallengeResponse`: NTProofStr followed by the client challenge
    /// blob ("temp").
    pub nt_response: Vec<u8>,
    /// `LmChallengeResponse` (LMv2).
    pub lm_response: [u8; 24],
    /// `SessionBaseKey` (= `KeyExchangeKey` for NTLMv2).
    pub session_base_key: Zeroizing<[u8; 16]>,
}

/// Compute the NTLMv2 responses ([MS-NLMP] §3.3.2). `av_pairs` is the
/// encoded `AV_PAIR` list including `MsvAvEOL`.
pub fn ntlmv2_response(
    response_key: &[u8; 16],
    server_challenge: &[u8; 8],
    client_challenge: &[u8; 8],
    time: FileTime,
    av_pairs: &[u8],
) -> Ntlmv2Response {
    // temp = RespType, HiRespType, Z(6), Time, ClientChallenge, Z(4),
    //        ServerName (AV pairs), Z(4)
    let mut temp = Vec::with_capacity(28 + av_pairs.len() + 4);
    temp.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    temp.extend_from_slice(&time.0.to_le_bytes());
    temp.extend_from_slice(client_challenge);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(av_pairs);
    temp.extend_from_slice(&[0; 4]);
    let nt_proof = hmac_md5(response_key, &[server_challenge, &temp]);
    let mut nt_response = Vec::with_capacity(16 + temp.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&temp);
    let mut lm_response = [0u8; 24];
    lm_response[..16].copy_from_slice(&hmac_md5(
        response_key,
        &[server_challenge, client_challenge],
    ));
    lm_response[16..].copy_from_slice(client_challenge);
    Ntlmv2Response {
        nt_response,
        lm_response,
        session_base_key: Zeroizing::new(hmac_md5(response_key, &[&nt_proof])),
    }
}

/// `RC4K(key, data)`: one-shot RC4.
pub fn rc4k(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut c = Rc4::new_from_slice(key).expect("RC4 accepts 1..=256-byte keys");
    c.apply_keystream(&mut out);
    out
}

/// Which side of the exchange a key is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client-to-server.
    ClientToServer,
    /// Server-to-client.
    ServerToClient,
}

impl Direction {
    fn label(self) -> &'static str {
        match self {
            Direction::ClientToServer => "client-to-server",
            Direction::ServerToClient => "server-to-client",
        }
    }
}

/// `SIGNKEY` with extended session security.
pub fn sign_key(exported_session_key: &[u8; 16], dir: Direction) -> [u8; 16] {
    let magic = format!(
        "session key to {} signing key magic constant\0",
        dir.label()
    );
    md5(&[exported_session_key, magic.as_bytes()])
}

/// `SEALKEY` with extended session security (128-, 56- or 40-bit).
pub fn seal_key(
    flags: NegotiateFlags,
    exported_session_key: &[u8; 16],
    dir: Direction,
) -> [u8; 16] {
    let key: &[u8] = if flags.contains(NegotiateFlags::KEY_128) {
        exported_session_key
    } else if flags.contains(NegotiateFlags::KEY_56) {
        &exported_session_key[..7]
    } else {
        &exported_session_key[..5]
    };
    let magic = format!(
        "session key to {} sealing key magic constant\0",
        dir.label()
    );
    md5(&[key, magic.as_bytes()])
}

/// NTLM message integrity for one direction with extended session
/// security ([MS-NLMP] §3.4.4.2): signing key, RC4 sealing state and
/// sequence number.
pub struct NtlmMac {
    sign_key: Zeroizing<[u8; 16]>,
    seal_key: Zeroizing<[u8; 16]>,
    rc4: Rc4,
    key_exch: bool,
    seq: u32,
}

impl NtlmMac {
    /// Keys for `dir` derived from the exported session key.
    pub fn new(flags: NegotiateFlags, exported_session_key: &[u8; 16], dir: Direction) -> Self {
        let seal = Zeroizing::new(seal_key(flags, exported_session_key, dir));
        NtlmMac {
            sign_key: Zeroizing::new(sign_key(exported_session_key, dir)),
            rc4: Rc4::new_from_slice(&seal[..]).expect("16-byte RC4 key"),
            seal_key: seal,
            key_exch: flags.contains(NegotiateFlags::KEY_EXCH),
            seq: 0,
        }
    }

    /// Compute the 16-byte signature of `msg` and advance the sequence
    /// number (and the RC4 state when key exchange is negotiated).
    pub fn sign(&mut self, msg: &[u8]) -> [u8; 16] {
        let seq = self.seq.to_le_bytes();
        let mac = hmac_md5(&self.sign_key[..], &[&seq, msg]);
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&mac[..8]);
        if self.key_exch {
            self.rc4.apply_keystream(&mut checksum);
        }
        self.seq = self.seq.wrapping_add(1);
        let mut sig = [0u8; 16];
        sig[..4].copy_from_slice(&1u32.to_le_bytes());
        sig[4..12].copy_from_slice(&checksum);
        sig[12..].copy_from_slice(&seq);
        sig
    }

    /// Verify a signature (constant-time comparison). The state advances
    /// whether or not the signature matches.
    pub fn verify(&mut self, msg: &[u8], signature: &[u8]) -> Result<()> {
        let expected = self.sign(msg);
        if signature.len() == 16 && bool::from(expected.ct_eq(signature)) {
            Ok(())
        } else {
            Err(ProtoError::Auth(
                "NTLM message integrity check failed".into(),
            ))
        }
    }

    /// Re-initialize the RC4 state (Windows resets it after the SPNEGO
    /// `mechListMIC`).
    pub fn reset_rc4(&mut self) {
        self.rc4 = Rc4::new_from_slice(&self.seal_key[..]).expect("16-byte RC4 key");
    }
}

impl fmt::Debug for NtlmMac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmMac")
            .field("seq", &self.seq)
            .finish_non_exhaustive()
    }
}

// ---------------------------------------------------------------------------
// Credentials and configuration.
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Secret {
    Password(Zeroizing<String>),
    NtHash(Zeroizing<[u8; 16]>),
    Anonymous,
}

/// NTLM credentials. The secret is zeroized on drop and never printed.
#[derive(Clone)]
pub struct NtlmCredentials {
    user: String,
    domain: String,
    secret: Secret,
}

impl fmt::Debug for NtlmCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmCredentials")
            .field("domain", &self.domain)
            .field("user", &self.user)
            .field("anonymous", &self.is_anonymous())
            .finish_non_exhaustive()
    }
}

impl NtlmCredentials {
    /// Credentials from a user name and password. `DOMAIN\user` is split
    /// into domain and user; `user@domain.example` (a UPN) is kept as the
    /// user name with an empty domain, which Windows accepts.
    pub fn new(user: &str, password: &str) -> Self {
        let (domain, user) = match user.split_once('\\') {
            Some((d, u)) => (d.to_owned(), u.to_owned()),
            None => (String::new(), user.to_owned()),
        };
        NtlmCredentials {
            user,
            domain,
            secret: Secret::Password(Zeroizing::new(password.to_owned())),
        }
    }

    /// Credentials with an explicit domain.
    pub fn with_domain(domain: &str, user: &str, password: &str) -> Self {
        NtlmCredentials {
            user: user.to_owned(),
            domain: domain.to_owned(),
            secret: Secret::Password(Zeroizing::new(password.to_owned())),
        }
    }

    /// Credentials from a precomputed NT hash (pass-the-hash, credential
    /// stores).
    pub fn from_nt_hash(domain: &str, user: &str, nt_hash: [u8; 16]) -> Self {
        NtlmCredentials {
            user: user.to_owned(),
            domain: domain.to_owned(),
            secret: Secret::NtHash(Zeroizing::new(nt_hash)),
        }
    }

    /// Anonymous (null session) credentials.
    pub fn anonymous() -> Self {
        NtlmCredentials {
            user: String::new(),
            domain: String::new(),
            secret: Secret::Anonymous,
        }
    }

    /// `true` for [`NtlmCredentials::anonymous`].
    pub fn is_anonymous(&self) -> bool {
        matches!(self.secret, Secret::Anonymous)
    }

    /// The user name.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The domain.
    pub fn domain(&self) -> &str {
        &self.domain
    }

    fn nt_hash(&self) -> Option<Zeroizing<[u8; 16]>> {
        match &self.secret {
            Secret::Password(p) => Some(Zeroizing::new(nt_hash(p))),
            Secret::NtHash(h) => Some(h.clone()),
            Secret::Anonymous => None,
        }
    }
}

/// Client options.
#[derive(Debug, Clone)]
pub struct NtlmConfig {
    /// Flags requested in the NEGOTIATE_MESSAGE.
    ///
    /// Keep `SIGN` whenever `KEY_EXCH` is requested. When the server
    /// grants `KEY_EXCH` but neither `SIGN` nor `SEAL`, this client still
    /// sends a random session key wrapped with RC4. Samba accepts that.
    /// [MS-NLMP]'s server-side rule (which Windows and pyspnego follow)
    /// ignores the wrapped key in that case, so the session keys would
    /// differ from a Windows server's.
    pub flags: NegotiateFlags,
    /// VERSION sent in NEGOTIATE/AUTHENTICATE (`None` to omit it).
    pub version: Option<NtlmVersion>,
    /// Workstation name sent in the AUTHENTICATE_MESSAGE.
    pub workstation: Option<String>,
    /// Service principal name sent as `MsvAvTargetName` (e.g.
    /// `cifs/fileserver.example.com`). An empty target name is sent when
    /// `None`, like pyspnego.
    pub target_spn: Option<String>,
    /// MD5 of the GSS channel bindings, sent as `MsvAvChannelBindings`.
    pub channel_bindings_hash: Option<[u8; 16]>,
    /// Refuse servers that do not grant 128-bit keys when signing or
    /// sealing is negotiated ([MS-NLMP] `ClientRequire128bitEncryption`).
    pub require_128bit: bool,
}

impl Default for NtlmConfig {
    fn default() -> Self {
        NtlmConfig {
            flags: NegotiateFlags::CLIENT_DEFAULT,
            version: Some(NtlmVersion::DEFAULT),
            workstation: None,
            target_spn: None,
            channel_bindings_hash: None,
            require_128bit: true,
        }
    }
}

/// Inputs that are random (or clock-derived) in normal operation; tests
/// pin them to reproduce reference vectors.
#[derive(Clone, Copy)]
pub(crate) struct FixedInputs {
    pub(crate) client_challenge: [u8; 8],
    pub(crate) exported_session_key: [u8; 16],
    pub(crate) time: Option<FileTime>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    NegotiateSent,
    Complete,
    Failed,
}

/// NTLMv2 client state machine.
///
/// ```
/// use fsfast_smb_proto::auth::{AuthStep, Authenticator, NtlmClient, NtlmCredentials};
///
/// let mut ntlm = NtlmClient::new(NtlmCredentials::new("DOMAIN\\user", "secret"));
/// let AuthStep::Continue(negotiate) = ntlm.step(&[]).unwrap() else { unreachable!() };
/// assert!(negotiate.starts_with(b"NTLMSSP\0"));
/// // ... send `negotiate`, feed the server's CHALLENGE_MESSAGE to `step`,
/// // send the AUTHENTICATE_MESSAGE it returns.
/// ```
pub struct NtlmClient {
    creds: NtlmCredentials,
    config: NtlmConfig,
    state: State,
    negotiate: Vec<u8>,
    flags: NegotiateFlags,
    exported_session_key: Option<Zeroizing<[u8; 16]>>,
    mic_provided: bool,
    client_mac: Option<NtlmMac>,
    server_mac: Option<NtlmMac>,
    fixed: Option<FixedInputs>,
}

impl fmt::Debug for NtlmClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NtlmClient")
            .field("creds", &self.creds)
            .field("state", &self.state)
            .field("flags", &self.flags)
            .finish_non_exhaustive()
    }
}

impl NtlmClient {
    /// A client with the default configuration.
    pub fn new(creds: NtlmCredentials) -> Self {
        Self::with_config(creds, NtlmConfig::default())
    }

    /// A client with explicit options.
    pub fn with_config(creds: NtlmCredentials, config: NtlmConfig) -> Self {
        NtlmClient {
            creds,
            config,
            state: State::Initial,
            negotiate: Vec::new(),
            flags: NegotiateFlags::empty(),
            exported_session_key: None,
            mic_provided: false,
            client_mac: None,
            server_mac: None,
            fixed: None,
        }
    }

    /// Pin the random and clock inputs (reference-vector tests).
    #[cfg(test)]
    pub(crate) fn set_fixed_inputs(&mut self, fixed: FixedInputs) {
        self.fixed = Some(fixed);
    }

    /// The flags of the AUTHENTICATE_MESSAGE (negotiated flags), once sent.
    pub fn negotiated_flags(&self) -> NegotiateFlags {
        self.flags
    }

    /// Whether the AUTHENTICATE_MESSAGE carried a MIC (SPNEGO must then
    /// send a `mechListMIC`).
    pub fn mic_provided(&self) -> bool {
        self.mic_provided
    }

    fn negotiate_message(&self) -> Result<Vec<u8>> {
        let mut flags = self.config.flags;
        if self.creds.is_anonymous() {
            flags |= NegotiateFlags::ANONYMOUS;
        }
        NegotiateMessage {
            flags,
            domain: None,
            workstation: None,
            version: self.config.version,
        }
        .encode()
    }

    fn authenticate(&mut self, challenge_bytes: &[u8]) -> Result<Vec<u8>> {
        let challenge = ChallengeMessage::decode(challenge_bytes)?;
        let cf = challenge.flags;
        if !cf.contains(NegotiateFlags::UNICODE) {
            return Err(ProtoError::Auth(
                "the server does not support Unicode NTLM messages".into(),
            ));
        }
        let signs = cf.intersects(NegotiateFlags::SIGN | NegotiateFlags::SEAL);
        if signs && self.config.require_128bit && !cf.contains(NegotiateFlags::KEY_128) {
            return Err(ProtoError::Auth(
                "the server does not support 128-bit NTLM session keys".into(),
            ));
        }
        if signs && !cf.contains(NegotiateFlags::EXTENDED_SESSION_SECURITY) {
            return Err(ProtoError::Auth(
                "the server does not support NTLM extended session security".into(),
            ));
        }

        let fixed = self.fixed;
        let mut flags = cf;
        flags.set(
            NegotiateFlags::VERSION,
            cf.contains(NegotiateFlags::VERSION) && self.config.version.is_some(),
        );
        let mut msg = AuthenticateMessage {
            flags,
            version: self.config.version,
            workstation: self.config.workstation.clone().unwrap_or_default(),
            ..Default::default()
        };

        let key_exchange_key: Zeroizing<[u8; 16]> = match self.creds.nt_hash() {
            None => {
                // Anonymous ([MS-NLMP] §3.2.5.1.2): empty NT response, Z(1)
                // LM response, all-zero session base key.
                msg.flags |= NegotiateFlags::ANONYMOUS;
                msg.lm_response = vec![0];
                Zeroizing::new([0u8; 16])
            }
            Some(hash) => {
                msg.user = self.creds.user.clone();
                msg.domain = self.creds.domain.clone();
                let response_key =
                    Zeroizing::new(ntowfv2(&hash, &self.creds.user, &self.creds.domain));
                let mut client_challenge = [0u8; 8];
                match fixed {
                    Some(f) => client_challenge = f.client_challenge,
                    None => crate::crypto::random_bytes(&mut client_challenge),
                }
                let mut info = challenge.target_info.clone();
                let server_time = info.timestamp();
                let time = server_time
                    .or(fixed.and_then(|f| f.time))
                    .unwrap_or_else(FileTime::now);
                if let Some(cb) = self.config.channel_bindings_hash {
                    info.set(av_id::CHANNEL_BINDINGS, cb.to_vec());
                }
                info.set(
                    av_id::TARGET_NAME,
                    utf16le_vec(self.config.target_spn.as_deref().unwrap_or("")),
                );
                if server_time.is_some() {
                    let f = info.flags().unwrap_or(0) | av_flags::MIC_PROVIDED;
                    info.set(av_id::FLAGS, f.to_le_bytes().to_vec());
                    self.mic_provided = true;
                }
                let mut info_bytes = Vec::with_capacity(256);
                info.encode(&mut info_bytes)?;
                let r = ntlmv2_response(
                    &response_key,
                    &challenge.server_challenge,
                    &client_challenge,
                    time,
                    &info_bytes,
                );
                msg.nt_response = r.nt_response;
                // With a MIC, the LMv2 response is replaced by Z(24)
                // ([MS-NLMP] §3.1.5.1.2).
                msg.lm_response = if self.mic_provided {
                    vec![0; 24]
                } else {
                    r.lm_response.to_vec()
                };
                r.session_base_key
            }
        };

        let exported: Zeroizing<[u8; 16]> = if cf.contains(NegotiateFlags::KEY_EXCH) {
            let mut k = Zeroizing::new([0u8; 16]);
            match fixed {
                Some(f) => *k = f.exported_session_key,
                None => crate::crypto::random_bytes(&mut k[..]),
            }
            msg.encrypted_random_session_key = rc4k(&key_exchange_key[..], &k[..]);
            k
        } else {
            key_exchange_key
        };

        let mut out = msg.encode()?;
        if self.mic_provided {
            let mic = hmac_md5(&exported[..], &[&self.negotiate, challenge_bytes, &out]);
            out[AUTHENTICATE_MIC_OFFSET..AUTHENTICATE_MIC_OFFSET + 16].copy_from_slice(&mic);
        }
        self.flags = msg.flags;
        if msg
            .flags
            .contains(NegotiateFlags::EXTENDED_SESSION_SECURITY)
        {
            self.client_mac = Some(NtlmMac::new(
                msg.flags,
                &exported,
                Direction::ClientToServer,
            ));
            self.server_mac = Some(NtlmMac::new(
                msg.flags,
                &exported,
                Direction::ServerToClient,
            ));
        }
        self.exported_session_key = Some(exported);
        Ok(out)
    }
}

impl Authenticator for NtlmClient {
    fn step(&mut self, input: &[u8]) -> Result<AuthStep> {
        match self.state {
            State::Initial => {
                self.negotiate = self.negotiate_message()?;
                self.state = State::NegotiateSent;
                Ok(AuthStep::Continue(self.negotiate.clone()))
            }
            State::NegotiateSent => match self.authenticate(input) {
                Ok(token) => {
                    self.state = State::Complete;
                    Ok(AuthStep::Done(Some(token)))
                }
                Err(e) => {
                    self.state = State::Failed;
                    Err(e)
                }
            },
            State::Complete => {
                if input.is_empty() {
                    Ok(AuthStep::Done(None))
                } else {
                    Err(ProtoError::Auth(
                        "unexpected NTLM token after authentication completed".into(),
                    ))
                }
            }
            State::Failed => Err(ProtoError::Auth(
                "NTLM authentication already failed".into(),
            )),
        }
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.exported_session_key.as_ref().map(|k| &k[..])
    }

    fn is_anonymous(&self) -> bool {
        self.creds.is_anonymous()
    }

    fn mechanism(&self) -> &'static str {
        "NTLM"
    }
}

impl GssMechanism for NtlmClient {
    fn oid(&self) -> &'static [u8] {
        NTLMSSP_OID
    }

    fn wants_mech_list_mic(&self) -> bool {
        self.mic_provided
    }

    fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let flags = self.flags;
        let mac = self
            .client_mac
            .as_mut()
            .ok_or(ProtoError::Auth("NTLM context is not established".into()))?;
        if !flags.contains(NegotiateFlags::SIGN) {
            // SSPI's behaviour with only ALWAYS_SIGN: a fixed dummy signature.
            let mut sig = vec![0u8; 16];
            sig[0] = 1;
            return Ok(sig);
        }
        let sig = mac.sign(data).to_vec();
        // Windows resets the RC4 state after the mechListMIC ([MS-SPNG]
        // §3.3.5.1); the only MIC NTLM computes inside SMB is that one.
        mac.reset_rc4();
        Ok(sig)
    }

    fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<()> {
        let flags = self.flags;
        let mac = self
            .server_mac
            .as_mut()
            .ok_or(ProtoError::Auth("NTLM context is not established".into()))?;
        if !flags.contains(NegotiateFlags::SIGN) {
            return Ok(());
        }
        let r = mac.verify(data, mic);
        mac.reset_rc4();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // [MS-NLMP] §4.2.4 NTLMv2 Authentication example.
    const USER: &str = "User";
    const DOMAIN: &str = "Domain";
    const PASSWORD: &str = "Password";
    const SERVER_CHALLENGE: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef];
    const CLIENT_CHALLENGE: [u8; 8] = [0xaa; 8];
    const RANDOM_SESSION_KEY: [u8; 16] = [0x55; 16];

    fn spec_av_pairs() -> Vec<u8> {
        let mut info = AvPairs::default();
        info.set(av_id::NB_DOMAIN_NAME, utf16le_vec("Domain"));
        info.set(av_id::NB_COMPUTER_NAME, utf16le_vec("Server"));
        let mut b = Vec::new();
        info.encode(&mut b).unwrap();
        b
    }

    #[test]
    fn ms_nlmp_4_2_4_ntlmv2_vectors() {
        let nt = nt_hash(PASSWORD);
        let key = ntowfv2(&nt, USER, DOMAIN);
        assert_eq!(
            key.to_vec(),
            h("0c868a403bfd7a93a3001ef22ef02e3f"),
            "NTOWFv2"
        );
        let r = ntlmv2_response(
            &key,
            &SERVER_CHALLENGE,
            &CLIENT_CHALLENGE,
            FileTime(0),
            &spec_av_pairs(),
        );
        assert_eq!(
            r.session_base_key.to_vec(),
            h("8de40ccadbc14a82f15cb0ad0de95ca3"),
            "SessionBaseKey"
        );
        assert_eq!(
            r.lm_response.to_vec(),
            h("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa"),
            "LMv2"
        );
        let temp = h("0101000000000000 0000000000000000 aaaaaaaaaaaaaaaa 00000000
                      02000c0044006f006d00610069006e00 01000c00530065007200760065007200
                      0000000000000000");
        assert_eq!(
            &r.nt_response[..16],
            &h("68cd0ab851e51c96aabc927bebef6a1c")[..],
            "NTProofStr"
        );
        assert_eq!(&r.nt_response[16..], &temp[..], "temp");
        let enc = rc4k(&r.session_base_key[..], &RANDOM_SESSION_KEY);
        assert_eq!(
            enc,
            h("c5dad2544fc9799094ce1ce90bc9d03e"),
            "EncryptedRandomSessionKey"
        );
    }

    #[test]
    fn ms_nlmp_4_2_4_4_signing() {
        // Flags of the §4.2.4 CHALLENGE_MESSAGE.
        let flags = NegotiateFlags::from_bits_retain(0xe28a8233);
        let seal = seal_key(flags, &RANDOM_SESSION_KEY, Direction::ClientToServer);
        assert_eq!(
            seal.to_vec(),
            h("59f600973cc4960a25480a7c196e4c58"),
            "SealingKey"
        );
        let sign = sign_key(&RANDOM_SESSION_KEY, Direction::ClientToServer);
        assert_eq!(
            sign.to_vec(),
            h("4788dc861b4782f35d43fd98fe1a2d39"),
            "SigningKey"
        );
        // GSS_WrapEx seals before computing the checksum; reproduce that by
        // running the plaintext through RC4 first.
        let mut mac = NtlmMac::new(flags, &RANDOM_SESSION_KEY, Direction::ClientToServer);
        let plaintext = utf16le_vec("Plaintext");
        let mut sealed = plaintext.clone();
        mac.rc4.apply_keystream(&mut sealed);
        assert_eq!(
            sealed,
            h("54e50165bf1936dc996020c1811b0f06fb5f"),
            "sealed data"
        );
        let sig = mac.sign(&plaintext);
        assert_eq!(
            sig.to_vec(),
            h("010000007fb38ec5c55d497600000000"),
            "signature"
        );
        let mut server = NtlmMac::new(flags, &RANDOM_SESSION_KEY, Direction::ClientToServer);
        server.rc4.apply_keystream(&mut sealed.clone());
        server.verify(&plaintext, &sig).unwrap();
    }

    #[test]
    fn messages_round_trip() {
        let n = NegotiateMessage {
            flags: NegotiateFlags::CLIENT_DEFAULT,
            version: Some(NtlmVersion::DEFAULT),
            ..Default::default()
        };
        let b = n.encode().unwrap();
        assert_eq!(b.len(), 40);
        assert_eq!(NegotiateMessage::decode(&b).unwrap(), n);

        let mut info = AvPairs::default();
        info.set(av_id::NB_COMPUTER_NAME, utf16le_vec("SRV"));
        info.set(
            av_id::TIMESTAMP,
            133_000_000_000_000_000u64.to_le_bytes().to_vec(),
        );
        let c = ChallengeMessage {
            flags: NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::TARGET_INFO,
            server_challenge: [7; 8],
            target_name: "SRV".into(),
            target_info: info,
            version: Some(NtlmVersion::DEFAULT),
        };
        let cb = c.encode().unwrap();
        let d = ChallengeMessage::decode(&cb).unwrap();
        assert_eq!(d, c);
        assert_eq!(
            d.target_info.timestamp(),
            Some(FileTime(133_000_000_000_000_000))
        );

        let a = AuthenticateMessage {
            flags: NegotiateFlags::CLIENT_DEFAULT,
            lm_response: vec![0; 24],
            nt_response: vec![1; 50],
            domain: "D".into(),
            user: "u".into(),
            workstation: "W".into(),
            encrypted_random_session_key: vec![2; 16],
            version: Some(NtlmVersion::DEFAULT),
            mic: [3; 16],
        };
        let ab = a.encode().unwrap();
        assert_eq!(AuthenticateMessage::decode(&ab).unwrap(), a);
        for i in 0..ab.len() {
            let _ = AuthenticateMessage::decode(&ab[..i]);
            let _ = ChallengeMessage::decode(&cb[..i.min(cb.len())]);
        }
    }

    fn challenge_with_timestamp() -> Vec<u8> {
        let mut info = AvPairs::default();
        info.set(av_id::NB_DOMAIN_NAME, utf16le_vec("DOM"));
        info.set(av_id::NB_COMPUTER_NAME, utf16le_vec("SRV"));
        info.set(
            av_id::TIMESTAMP,
            133_000_000_000_000_000u64.to_le_bytes().to_vec(),
        );
        ChallengeMessage {
            flags: NegotiateFlags::CLIENT_DEFAULT
                | NegotiateFlags::TARGET_INFO
                | NegotiateFlags::TARGET_TYPE_SERVER,
            server_challenge: [9; 8],
            target_name: "SRV".into(),
            target_info: info,
            version: Some(NtlmVersion::DEFAULT),
        }
        .encode()
        .unwrap()
    }

    /// Server-side verification of an AUTHENTICATE_MESSAGE, as a mock
    /// server would do it.
    fn server_check(negotiate: &[u8], challenge: &[u8], auth: &[u8], password: &str) -> [u8; 16] {
        let c = ChallengeMessage::decode(challenge).unwrap();
        let a = AuthenticateMessage::decode(auth).unwrap();
        let key = ntowfv2(&nt_hash(password), &a.user, &a.domain);
        let temp = &a.nt_response[16..];
        let proof = hmac_md5(&key, &[&c.server_challenge, temp]);
        assert_eq!(&proof[..], &a.nt_response[..16], "NTProofStr");
        let base = hmac_md5(&key, &[&proof]);
        let exported: [u8; 16] = rc4k(&base, &a.encrypted_random_session_key)
            .try_into()
            .unwrap();
        let mut zeroed = auth.to_vec();
        zeroed[AUTHENTICATE_MIC_OFFSET..AUTHENTICATE_MIC_OFFSET + 16].fill(0);
        assert_eq!(
            hmac_md5(&exported, &[negotiate, challenge, &zeroed]),
            a.mic,
            "MIC"
        );
        exported
    }

    #[test]
    fn client_full_exchange_with_mic() {
        let cfg = NtlmConfig {
            target_spn: Some("cifs/srv".into()),
            workstation: Some("WS".into()),
            ..Default::default()
        };
        let mut c = NtlmClient::with_config(NtlmCredentials::new("DOM\\alice", "pw"), cfg);
        let AuthStep::Continue(neg) = c.step(&[]).unwrap() else {
            panic!()
        };
        assert!(!c.is_complete());
        assert!(c.session_key().is_none());
        let challenge = challenge_with_timestamp();
        let AuthStep::Done(Some(auth)) = c.step(&challenge).unwrap() else {
            panic!()
        };
        assert!(c.is_complete());
        assert!(c.mic_provided());
        let exported = server_check(&neg, &challenge, &auth, "pw");
        assert_eq!(c.session_key().unwrap(), &exported);
        let a = AuthenticateMessage::decode(&auth).unwrap();
        assert_eq!(a.user, "alice");
        assert_eq!(a.domain, "DOM");
        assert_eq!(a.workstation, "WS");
        assert_eq!(a.lm_response, vec![0; 24]);
        let blob_info = AvPairs::decode(&a.nt_response[16 + 28..]).unwrap();
        assert_eq!(
            blob_info.get_string(av_id::TARGET_NAME).unwrap(),
            "cifs/srv"
        );
        assert_eq!(
            blob_info.flags().unwrap() & av_flags::MIC_PROVIDED,
            av_flags::MIC_PROVIDED
        );
        // mechListMIC round trip between client and a server-side MAC.
        let mic = c.get_mic(b"mech list").unwrap();
        let mut server_in =
            NtlmMac::new(c.negotiated_flags(), &exported, Direction::ClientToServer);
        server_in.verify(b"mech list", &mic).unwrap();
        let mut server_out =
            NtlmMac::new(c.negotiated_flags(), &exported, Direction::ServerToClient);
        let smic = server_out.sign(b"mech list");
        c.verify_mic(b"mech list", &smic).unwrap();
        assert!(c.step(b"junk").is_err());
        assert_eq!(c.step(&[]).unwrap(), AuthStep::Done(None));
    }

    #[test]
    fn wrong_password_fails_server_check() {
        let mut c = NtlmClient::new(NtlmCredentials::new("u", "right"));
        let AuthStep::Continue(_) = c.step(&[]).unwrap() else {
            panic!()
        };
        let challenge = challenge_with_timestamp();
        let AuthStep::Done(Some(auth)) = c.step(&challenge).unwrap() else {
            panic!()
        };
        let a = AuthenticateMessage::decode(&auth).unwrap();
        let key = ntowfv2(&nt_hash("wrong"), &a.user, &a.domain);
        let proof = hmac_md5(&key, &[&[9u8; 8], &a.nt_response[16..]]);
        assert_ne!(&proof[..], &a.nt_response[..16]);
    }

    #[test]
    fn anonymous_and_no_timestamp() {
        let mut c = NtlmClient::new(NtlmCredentials::anonymous());
        let AuthStep::Continue(neg) = c.step(&[]).unwrap() else {
            panic!()
        };
        assert!(
            NegotiateMessage::decode(&neg)
                .unwrap()
                .flags
                .contains(NegotiateFlags::ANONYMOUS)
        );
        let AuthStep::Done(Some(auth)) = c.step(&challenge_with_timestamp()).unwrap() else {
            panic!()
        };
        let a = AuthenticateMessage::decode(&auth).unwrap();
        assert!(a.flags.contains(NegotiateFlags::ANONYMOUS));
        assert_eq!(a.lm_response, vec![0]);
        assert!(a.nt_response.is_empty());
        assert!(a.user.is_empty());
        assert_eq!(a.mic, [0; 16]);
        assert!(c.is_anonymous());

        // A challenge without MsvAvTimestamp: no MIC, LMv2 response sent.
        let mut ch = ChallengeMessage::decode(&challenge_with_timestamp()).unwrap();
        ch.target_info.0.retain(|p| p.id != av_id::TIMESTAMP);
        let mut c = NtlmClient::new(NtlmCredentials::with_domain("D", "u", "p"));
        c.step(&[]).unwrap();
        let AuthStep::Done(Some(auth)) = c.step(&ch.encode().unwrap()).unwrap() else {
            panic!()
        };
        let a = AuthenticateMessage::decode(&auth).unwrap();
        assert!(!c.mic_provided());
        assert_eq!(a.mic, [0; 16]);
        assert_eq!(a.lm_response.len(), 24);
        assert_ne!(a.lm_response, vec![0; 24]);
    }

    #[test]
    fn rejects_weak_or_broken_challenges() {
        let mut ch = ChallengeMessage::decode(&challenge_with_timestamp()).unwrap();
        ch.flags.remove(NegotiateFlags::KEY_128);
        let mut c = NtlmClient::new(NtlmCredentials::new("u", "p"));
        c.step(&[]).unwrap();
        assert!(matches!(
            c.step(&ch.encode().unwrap()),
            Err(ProtoError::Auth(_))
        ));
        assert!(c.step(&[]).is_err(), "a failed client stays failed");

        let mut c = NtlmClient::new(NtlmCredentials::new("u", "p"));
        c.step(&[]).unwrap();
        assert!(c.step(b"NTLMSSP\0\x02\0\0\0").is_err());
        let mut c = NtlmClient::new(NtlmCredentials::new("u", "p"));
        c.step(&[]).unwrap();
        assert!(c.step(&[]).is_err());
    }

    #[test]
    fn version_flag_matches_version_field() {
        // NtlmConfig::version = None with the default flags (which include
        // NTLMSSP_NEGOTIATE_VERSION) must not announce a VERSION field that
        // is not there: a peer would read the payload (or past the end of
        // the message) as the version.
        let cfg = NtlmConfig {
            version: None,
            ..Default::default()
        };
        assert!(cfg.flags.contains(NegotiateFlags::VERSION));
        let mut c = NtlmClient::with_config(NtlmCredentials::new("D\\u", "p"), cfg);
        let AuthStep::Continue(neg) = c.step(&[]).unwrap() else {
            panic!()
        };
        let n = NegotiateMessage::decode(&neg).unwrap();
        assert!(!n.flags.contains(NegotiateFlags::VERSION));
        assert_eq!(n.version, None);
        assert_eq!(neg.len(), 32);
        let AuthStep::Done(Some(auth)) = c.step(&challenge_with_timestamp()).unwrap() else {
            panic!()
        };
        let a = AuthenticateMessage::decode(&auth).unwrap();
        assert!(!a.flags.contains(NegotiateFlags::VERSION));
        assert_eq!(&auth[64..72], &[0; 8]);
        // A NEGOTIATE_MESSAGE built by hand with the flag but no version.
        let m = NegotiateMessage {
            flags: NegotiateFlags::CLIENT_DEFAULT,
            version: None,
            ..Default::default()
        };
        let b = m.encode().unwrap();
        assert!(
            !NegotiateMessage::decode(&b)
                .unwrap()
                .flags
                .contains(NegotiateFlags::VERSION)
        );
    }

    #[test]
    fn credentials_parsing_and_upper() {
        let c = NtlmCredentials::new("CORP\\bob", "x");
        assert_eq!((c.domain(), c.user()), ("CORP", "bob"));
        let c = NtlmCredentials::new("bob@corp.example", "Sup3rS3cret");
        assert_eq!((c.domain(), c.user()), ("", "bob@corp.example"));
        assert!(!format!("{c:?}").contains("Sup3rS3cret"));
        assert_eq!(windows_upper("straße"), "STRAßE");
        assert_eq!(windows_upper("ärger"), "ÄRGER");
        let a = NtlmCredentials::from_nt_hash("D", "u", nt_hash("p"));
        assert_eq!(a.nt_hash().unwrap().to_vec(), nt_hash("p").to_vec());
    }
}
