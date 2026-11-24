//! Authentication for SMB SESSION_SETUP: NTLMv2 ([MS-NLMP]) wrapped in
//! SPNEGO ([RFC 4178], [MS-SPNG]).
//!
//! The SMB client drives an [`Authenticator`]: it passes the security
//! buffer of the NEGOTIATE response (the server's SPNEGO hint) to the first
//! [`step`](Authenticator::step), sends each returned token in a
//! SESSION_SETUP request and feeds the token of each response back in until
//! the authenticator reports completion and the server returns
//! `STATUS_SUCCESS`:
//!
//! ```
//! use fsfast_smb_proto::auth::{AuthStep, Authenticator, NtlmCredentials, SpnegoClient};
//!
//! let mut auth = SpnegoClient::ntlm(NtlmCredentials::new("DOMAIN\\user", "secret"));
//! let negotiate_hint: &[u8] = &[]; // NegotiateResponse::security_buffer
//! match auth.step(negotiate_hint).unwrap() {
//!     AuthStep::Continue(token) => { /* SESSION_SETUP with `token` */ }
//!     AuthStep::Done(_) => unreachable!(),
//! }
//! ```
//!
//! The session key ([`Authenticator::session_key`]) becomes available as
//! soon as the client has produced its final authentication token, before
//! the server's last reply arrives: SMB 3.1.1 needs it to verify the
//! signature of that reply.
//!
//! [`GssMechanism`] is the interface SPNEGO needs from a mechanism; a
//! Kerberos mechanism (e.g. on top of the `sspi` crate or system GSSAPI)
//! plugs in by implementing it.
//!
//! [MS-NLMP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/
//! [MS-SPNG]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/
//! [RFC 4178]: https://www.rfc-editor.org/rfc/rfc4178

pub mod der;
pub mod ntlm;
pub mod spnego;

pub use ntlm::{NtlmClient, NtlmConfig, NtlmCredentials};
pub use spnego::SpnegoClient;

use crate::error::Result;

/// The outcome of one authentication step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthStep {
    /// Send this token to the server and pass the token of its reply to the
    /// next [`Authenticator::step`].
    Continue(Vec<u8>),
    /// The client side is complete. Send the token if there is one; no
    /// further server token needs to be processed.
    Done(Option<Vec<u8>>),
}

impl AuthStep {
    /// The token to send, if any.
    pub fn token(&self) -> Option<&[u8]> {
        match self {
            AuthStep::Continue(t) => Some(t),
            AuthStep::Done(t) => t.as_deref(),
        }
    }

    /// `true` for [`AuthStep::Done`].
    pub fn is_done(&self) -> bool {
        matches!(self, AuthStep::Done(_))
    }
}

/// A client-side authentication state machine (GSS-API
/// `GSS_Init_sec_context` in miniature).
pub trait Authenticator: Send {
    /// Process the server's token (empty on the first call when there is no
    /// hint, and when the server's final reply carries no token) and
    /// produce the next step.
    fn step(&mut self, input: &[u8]) -> Result<AuthStep>;

    /// `true` once authentication has completed on the client side.
    fn is_complete(&self) -> bool;

    /// The exported session key, once known. SMB uses its first 16 bytes
    /// (zero-padded) as `Session.SessionKey` and all of it as
    /// `Session.FullSessionKey` for AES-256 key derivation.
    fn session_key(&self) -> Option<&[u8]>;

    /// `true` for anonymous (null session) authentication. Such sessions
    /// are neither signed nor encrypted.
    fn is_anonymous(&self) -> bool {
        false
    }

    /// The mechanism name, for logs and errors (`"NTLM"`, `"Kerberos"`,
    /// `"SPNEGO/NTLM"`...).
    fn mechanism(&self) -> &'static str;
}

/// What SPNEGO needs from a GSS mechanism on top of [`Authenticator`].
pub trait GssMechanism: Authenticator {
    /// The mechanism OID as DER content octets (no tag/length).
    fn oid(&self) -> &'static [u8];

    /// Whether the mechanism requires a `mechListMIC` exchange (NTLM does
    /// when its AUTHENTICATE_MESSAGE carries a MIC).
    fn wants_mech_list_mic(&self) -> bool;

    /// `GSS_GetMIC` over `data` (the DER `MechTypeList`).
    fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>>;

    /// `GSS_VerifyMIC` of the peer's `mic` over `data`.
    fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<()>;
}

impl<T: Authenticator + ?Sized> Authenticator for Box<T> {
    fn step(&mut self, input: &[u8]) -> Result<AuthStep> {
        (**self).step(input)
    }
    fn is_complete(&self) -> bool {
        (**self).is_complete()
    }
    fn session_key(&self) -> Option<&[u8]> {
        (**self).session_key()
    }
    fn is_anonymous(&self) -> bool {
        (**self).is_anonymous()
    }
    fn mechanism(&self) -> &'static str {
        (**self).mechanism()
    }
}

impl<T: GssMechanism + ?Sized> GssMechanism for Box<T> {
    fn oid(&self) -> &'static [u8] {
        (**self).oid()
    }
    fn wants_mech_list_mic(&self) -> bool {
        (**self).wants_mech_list_mic()
    }
    fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        (**self).get_mic(data)
    }
    fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<()> {
        (**self).verify_mic(data, mic)
    }
}
