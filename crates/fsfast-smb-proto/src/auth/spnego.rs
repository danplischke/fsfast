//! SPNEGO ([RFC 4178], with the [MS-SPNG] `NegTokenInit2` extension).
//!
//! [`SpnegoClient`] negotiates one of its [`GssMechanism`]s with the server:
//!
//! 1. If the SMB NEGOTIATE response carried a `NegTokenInit2` hint, the
//!    offered mechanisms are narrowed to the ones the server lists.
//! 2. A `NegTokenInit` offers the mechanisms and carries the optimistic
//!    token of the preferred one.
//! 3. `NegTokenResp` tokens are exchanged until the mechanism completes.
//!    If the server picks a different mechanism, the client switches to it.
//! 4. The `mechListMIC` protects the offered list against downgrade: the
//!    client sends one when the mechanism asks for it (NTLM with a MIC), the
//!    server requests it, or the server sent one, and verifies the server's.
//!    When the server selected a mechanism other than the client's first
//!    choice, the server's MIC is mandatory (RFC 4178 §5) and completing
//!    without it fails. A server MIC that merely repeats the
//!    `responseToken` (a legacy acceptor bug) is ignored, as pyspnego does.
//!
//! [RFC 4178]: https://www.rfc-editor.org/rfc/rfc4178
//! [MS-SPNG]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-spng/

use std::fmt;

use super::der::{
    self, DerReader, Oid, TAG_APPLICATION_0, TAG_BIT_STRING, TAG_ENUMERATED, TAG_GENERAL_STRING,
    TAG_OCTET_STRING, TAG_OID, TAG_SEQUENCE, context, put_constructed, put_tlv,
};
use super::ntlm::{NTLMSSP_OID, NtlmClient, NtlmConfig, NtlmCredentials};
use super::{AuthStep, Authenticator, GssMechanism};
use crate::error::{ProtoError, Result};

/// DER content octets of the SPNEGO OID 1.3.6.1.5.5.2.
pub const SPNEGO_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// Kerberos 5 (1.2.840.113554.1.2.2).
pub const KRB5_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x12, 0x01, 0x02, 0x02];
/// Microsoft's legacy Kerberos 5 OID (1.2.840.48018.1.2.2).
pub const MS_KRB5_OID: &[u8] = &[0x2A, 0x86, 0x48, 0x82, 0xF7, 0x12, 0x01, 0x02, 0x02];
/// NegoEx (1.3.6.1.4.1.311.2.2.30).
pub const NEGOEX_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x1E];

/// Whether two mechanism OIDs name the same mechanism (the two Kerberos
/// OIDs are aliases).
pub fn same_mech(a: &[u8], b: &[u8]) -> bool {
    let krb = |o: &[u8]| o == KRB5_OID || o == MS_KRB5_OID;
    a == b || (krb(a) && krb(b))
}

const W: &str = "SPNEGO token";

/// `NegTokenInit` / `NegTokenInit2`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct NegTokenInit {
    /// Offered mechanism OIDs (DER content octets), preferred first.
    pub mech_types: Vec<Vec<u8>>,
    /// `reqFlags` BIT STRING content (deprecated; kept verbatim).
    pub req_flags: Option<Vec<u8>>,
    /// Optimistic token of the first mechanism.
    pub mech_token: Option<Vec<u8>>,
    /// `negHints.hintName` of a `NegTokenInit2` (servers send
    /// `not_defined_in_RFC4178@please_ignore`). When set, the token is
    /// encoded in the `NegTokenInit2` layout.
    pub hint_name: Option<Vec<u8>>,
    /// `mechListMIC`.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl fmt::Debug for NegTokenInit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mechs: Vec<String> = self.mech_types.iter().map(|m| Oid(m).to_string()).collect();
        f.debug_struct("NegTokenInit")
            .field("mech_types", &mechs)
            .field("mech_token_len", &self.mech_token.as_ref().map(Vec::len))
            .field(
                "hint_name",
                &self
                    .hint_name
                    .as_ref()
                    .map(|h| String::from_utf8_lossy(h).into_owned()),
            )
            .field("mech_list_mic", &self.mech_list_mic.is_some())
            .finish()
    }
}

/// The DER `MechTypeList` (`SEQUENCE OF MechType`): the input of the
/// `mechListMIC`.
pub fn encode_mech_type_list<O: AsRef<[u8]>>(mechs: &[O]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + mechs.len() * 12);
    put_constructed(&mut out, TAG_SEQUENCE, |o| {
        for m in mechs {
            put_tlv(o, TAG_OID, m.as_ref());
        }
    });
    out
}

impl NegTokenInit {
    /// Encode as a GSS-API InitialContextToken (`[APPLICATION 0]` with the
    /// SPNEGO OID), the form sent in the first SESSION_SETUP.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.mech_token.as_ref().map_or(0, Vec::len));
        put_constructed(&mut out, TAG_APPLICATION_0, |o| {
            put_tlv(o, TAG_OID, SPNEGO_OID);
            put_constructed(o, context(0), |o| {
                put_constructed(o, TAG_SEQUENCE, |o| {
                    put_constructed(o, context(0), |o| {
                        o.extend_from_slice(&encode_mech_type_list(&self.mech_types))
                    });
                    if let Some(f) = &self.req_flags {
                        put_constructed(o, context(1), |o| put_tlv(o, TAG_BIT_STRING, f));
                    }
                    if let Some(t) = &self.mech_token {
                        put_constructed(o, context(2), |o| put_tlv(o, TAG_OCTET_STRING, t));
                    }
                    let mic_tag = if let Some(h) = &self.hint_name {
                        put_constructed(o, context(3), |o| {
                            put_constructed(o, TAG_SEQUENCE, |o| {
                                put_constructed(o, context(0), |o| {
                                    put_tlv(o, TAG_GENERAL_STRING, h)
                                });
                            });
                        });
                        context(4)
                    } else {
                        context(3)
                    };
                    if let Some(m) = &self.mech_list_mic {
                        put_constructed(o, mic_tag, |o| put_tlv(o, TAG_OCTET_STRING, m));
                    }
                });
            });
        });
        out
    }

    /// Decode the `NegTokenInit` SEQUENCE content.
    fn decode_seq(content: &[u8]) -> Result<Self> {
        let mut r = DerReader::new(content);
        let mut t = NegTokenInit::default();
        while let Some(tag) = r.peek_tag() {
            let field = r.read()?;
            let mut inner = DerReader::new(field.content);
            match tag {
                0xA0 => {
                    let seq = inner.expect(TAG_SEQUENCE, W)?;
                    let mut mr = DerReader::new(seq.content);
                    while !mr.is_empty() {
                        t.mech_types.push(mr.expect(TAG_OID, W)?.content.to_vec());
                    }
                }
                0xA1 => t.req_flags = Some(inner.expect(TAG_BIT_STRING, W)?.content.to_vec()),
                0xA2 => t.mech_token = Some(inner.expect(TAG_OCTET_STRING, W)?.content.to_vec()),
                // [3] is mechListMIC in RFC 4178 and negHints in NegTokenInit2.
                0xA3 => match inner.peek_tag() {
                    Some(TAG_OCTET_STRING) => {
                        t.mech_list_mic = Some(inner.read()?.content.to_vec())
                    }
                    Some(TAG_SEQUENCE) => {
                        let hints = inner.read()?;
                        let mut hr = DerReader::new(hints.content);
                        if let Some(name) = hr.optional(context(0))? {
                            let mut nr = DerReader::new(name.content);
                            t.hint_name = Some(nr.read()?.content.to_vec());
                        }
                    }
                    _ => return Err(ProtoError::malformed(W, "unexpected NegTokenInit field 3")),
                },
                0xA4 => t.mech_list_mic = Some(inner.expect(TAG_OCTET_STRING, W)?.content.to_vec()),
                // Unknown extensions are ignored, as RFC 4178 requires.
                _ => {}
            }
        }
        Ok(t)
    }
}

/// `negState` of a `NegTokenResp`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NegState {
    /// `accept-completed` (0).
    AcceptCompleted,
    /// `accept-incomplete` (1).
    AcceptIncomplete,
    /// `reject` (2).
    Reject,
    /// `request-mic` (3).
    RequestMic,
}

impl NegState {
    fn to_u8(self) -> u8 {
        match self {
            NegState::AcceptCompleted => 0,
            NegState::AcceptIncomplete => 1,
            NegState::Reject => 2,
            NegState::RequestMic => 3,
        }
    }

    fn from_u32(v: u32) -> Result<Self> {
        Ok(match v {
            0 => NegState::AcceptCompleted,
            1 => NegState::AcceptIncomplete,
            2 => NegState::Reject,
            3 => NegState::RequestMic,
            _ => return Err(ProtoError::malformed(W, "unknown negState")),
        })
    }
}

/// `NegTokenResp`.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct NegTokenResp {
    /// `negState`.
    pub neg_state: Option<NegState>,
    /// `supportedMech` (OID content octets).
    pub supported_mech: Option<Vec<u8>>,
    /// `responseToken`.
    pub response_token: Option<Vec<u8>>,
    /// `mechListMIC`.
    pub mech_list_mic: Option<Vec<u8>>,
}

impl fmt::Debug for NegTokenResp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NegTokenResp")
            .field("neg_state", &self.neg_state)
            .field(
                "supported_mech",
                &self.supported_mech.as_deref().map(|m| Oid(m).to_string()),
            )
            .field(
                "response_token_len",
                &self.response_token.as_ref().map(Vec::len),
            )
            .field("mech_list_mic", &self.mech_list_mic.is_some())
            .finish()
    }
}

impl NegTokenResp {
    /// Encode as `[1] NegTokenResp` (no GSS framing, as on the wire).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + self.response_token.as_ref().map_or(0, Vec::len));
        put_constructed(&mut out, context(1), |o| {
            put_constructed(o, TAG_SEQUENCE, |o| {
                if let Some(s) = self.neg_state {
                    put_constructed(o, context(0), |o| put_tlv(o, TAG_ENUMERATED, &[s.to_u8()]));
                }
                if let Some(m) = &self.supported_mech {
                    put_constructed(o, context(1), |o| put_tlv(o, TAG_OID, m));
                }
                if let Some(t) = &self.response_token {
                    put_constructed(o, context(2), |o| put_tlv(o, TAG_OCTET_STRING, t));
                }
                if let Some(m) = &self.mech_list_mic {
                    put_constructed(o, context(3), |o| put_tlv(o, TAG_OCTET_STRING, m));
                }
            });
        });
        out
    }

    fn decode_seq(content: &[u8]) -> Result<Self> {
        let mut r = DerReader::new(content);
        let mut t = NegTokenResp::default();
        while let Some(tag) = r.peek_tag() {
            let field = r.read()?;
            let mut inner = DerReader::new(field.content);
            match tag {
                0xA0 => {
                    let e = inner.expect(TAG_ENUMERATED, W)?;
                    t.neg_state = Some(NegState::from_u32(der::decode_small_uint(e.content, W)?)?);
                }
                0xA1 => t.supported_mech = Some(inner.expect(TAG_OID, W)?.content.to_vec()),
                0xA2 => {
                    t.response_token = Some(inner.expect(TAG_OCTET_STRING, W)?.content.to_vec())
                }
                0xA3 => t.mech_list_mic = Some(inner.expect(TAG_OCTET_STRING, W)?.content.to_vec()),
                _ => {}
            }
        }
        Ok(t)
    }
}

/// A decoded SPNEGO `NegotiationToken`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NegotiationToken {
    /// `negTokenInit` (or `NegTokenInit2`).
    Init(NegTokenInit),
    /// `negTokenResp`.
    Resp(NegTokenResp),
}

impl NegotiationToken {
    /// Decode a token, with or without the GSS-API InitialContextToken
    /// framing. Trailing bytes after the token are rejected.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut r = DerReader::new(buf);
        let outer = r.read()?;
        if !r.is_empty() {
            return Err(ProtoError::malformed(W, "trailing bytes after the token"));
        }
        let (tag, content) = if outer.tag == TAG_APPLICATION_0 {
            let mut ir = DerReader::new(outer.content);
            let oid = ir.expect(TAG_OID, W)?;
            if oid.content != SPNEGO_OID {
                return Err(ProtoError::Auth(format!(
                    "not a SPNEGO token (mechanism {})",
                    Oid(oid.content)
                )));
            }
            let inner = ir.read()?;
            (inner.tag, inner.content)
        } else {
            (outer.tag, outer.content)
        };
        let mut cr = DerReader::new(content);
        let seq = cr.expect(TAG_SEQUENCE, W)?;
        match tag {
            0xA0 => Ok(NegotiationToken::Init(NegTokenInit::decode_seq(
                seq.content,
            )?)),
            0xA1 => Ok(NegotiationToken::Resp(NegTokenResp::decode_seq(
                seq.content,
            )?)),
            _ => Err(ProtoError::malformed(W, "unknown NegotiationToken choice")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Initial,
    InProgress,
    AwaitingFinal,
    Complete,
    Failed,
}

/// SPNEGO client over one or more [`GssMechanism`]s.
pub struct SpnegoClient {
    mechs: Vec<Box<dyn GssMechanism>>,
    /// Indices into `mechs` of the offered mechanisms, in offer order.
    offered: Vec<usize>,
    /// Index into `mechs` of the selected mechanism.
    chosen: usize,
    mech_list_der: Vec<u8>,
    state: State,
    mic_required: bool,
    mic_sent: bool,
    mic_received: bool,
}

impl fmt::Debug for SpnegoClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SpnegoClient")
            .field("mechanism", &self.mechs[self.chosen].mechanism())
            .field("state", &self.state)
            .finish_non_exhaustive()
    }
}

impl SpnegoClient {
    /// A client offering `mechs` in preference order.
    pub fn new(mechs: Vec<Box<dyn GssMechanism>>) -> Result<Self> {
        if mechs.is_empty() {
            return Err(ProtoError::InvalidInput(
                "SPNEGO needs at least one mechanism",
            ));
        }
        Ok(SpnegoClient {
            offered: (0..mechs.len()).collect(),
            mechs,
            chosen: 0,
            mech_list_der: Vec::new(),
            state: State::Initial,
            mic_required: false,
            mic_sent: false,
            mic_received: false,
        })
    }

    /// SPNEGO with NTLMv2 only, default NTLM options.
    pub fn ntlm(creds: NtlmCredentials) -> Self {
        Self::ntlm_with_config(creds, NtlmConfig::default())
    }

    /// SPNEGO with NTLMv2 only.
    pub fn ntlm_with_config(creds: NtlmCredentials, config: NtlmConfig) -> Self {
        Self::new(vec![Box::new(NtlmClient::with_config(creds, config))]).expect("one mechanism")
    }

    /// The selected mechanism.
    pub fn selected(&self) -> &dyn GssMechanism {
        &*self.mechs[self.chosen]
    }

    /// The selected mechanism, mutably.
    pub fn selected_mut(&mut self) -> &mut dyn GssMechanism {
        &mut *self.mechs[self.chosen]
    }

    /// Whether the server's `mechListMIC` was received and verified.
    pub fn mech_list_mic_verified(&self) -> bool {
        self.mic_received
    }

    fn fail<T>(&mut self, e: ProtoError) -> Result<T> {
        self.state = State::Failed;
        Err(e)
    }

    /// RFC 4178 §5: unless the acceptor selected the initiator's first
    /// choice, only the acceptor's (verified) `mechListMIC` proves that
    /// the offered mechanism list was not altered to force a weaker
    /// mechanism, so completing without it is a failure.
    fn check_downgrade_protection(&self) -> Result<()> {
        if self.chosen != self.offered[0] && !self.mic_received {
            return Err(ProtoError::Auth(format!(
                "the server selected {} instead of the preferred mechanism without \
                 sending a mechListMIC (possible downgrade)",
                self.mechs[self.chosen].mechanism()
            )));
        }
        Ok(())
    }

    fn step_initial(&mut self, hint: &[u8]) -> Result<AuthStep> {
        if !hint.is_empty() {
            match NegotiationToken::decode(hint) {
                Ok(NegotiationToken::Init(init)) if !init.mech_types.is_empty() => {
                    let supported: Vec<usize> = (0..self.mechs.len())
                        .filter(|&i| {
                            init.mech_types
                                .iter()
                                .any(|m| same_mech(m, self.mechs[i].oid()))
                        })
                        .collect();
                    if supported.is_empty() {
                        // The hint is advisory ([MS-SPNG] §3.2.5.2); some
                        // servers under-report. Offer everything.
                        tracing::debug!(
                            ?init,
                            "SPNEGO hint lists none of our mechanisms; offering all"
                        );
                    } else {
                        self.offered = supported;
                    }
                }
                Ok(other) => tracing::debug!(?other, "ignoring SPNEGO hint without mechanisms"),
                Err(e) => tracing::debug!(error = %e, "ignoring undecodable SPNEGO hint"),
            }
        }
        self.chosen = self.offered[0];
        let oids: Vec<&[u8]> = self.offered.iter().map(|&i| self.mechs[i].oid()).collect();
        self.mech_list_der = encode_mech_type_list(&oids);
        let token = match self.mechs[self.chosen].step(&[])? {
            AuthStep::Continue(t) => t,
            AuthStep::Done(Some(t)) => t,
            AuthStep::Done(None) => {
                return Err(ProtoError::Auth(
                    "mechanism produced no initial token".into(),
                ));
            }
        };
        let init = NegTokenInit {
            mech_types: oids.iter().map(|o| o.to_vec()).collect(),
            mech_token: Some(token),
            ..Default::default()
        };
        self.state = State::InProgress;
        Ok(AuthStep::Continue(init.encode()))
    }

    fn step_resp(&mut self, input: &[u8]) -> Result<AuthStep> {
        let mut out_token: Option<Vec<u8>> = None;
        let mut server_complete = false;
        if input.is_empty() {
            if self.state != State::AwaitingFinal {
                return Err(ProtoError::Auth("the server sent no SPNEGO token".into()));
            }
            // Some servers end the exchange with an empty buffer.
            server_complete = true;
        } else {
            let resp = match NegotiationToken::decode(input)? {
                NegotiationToken::Resp(r) => r,
                NegotiationToken::Init(_) => {
                    return Err(ProtoError::Auth(
                        "unexpected NegTokenInit from the server".into(),
                    ));
                }
            };
            tracing::trace!(?resp, "SPNEGO NegTokenResp");
            match resp.neg_state {
                Some(NegState::Reject) => {
                    return Err(ProtoError::Auth(format!(
                        "the server rejected {} authentication",
                        self.mechs[self.chosen].mechanism()
                    )));
                }
                Some(NegState::RequestMic) => self.mic_required = true,
                Some(NegState::AcceptCompleted) => server_complete = true,
                Some(NegState::AcceptIncomplete) | None => {}
            }
            let mut switched = false;
            if let Some(m) = &resp.supported_mech
                && !same_mech(m, self.mechs[self.chosen].oid())
            {
                // The server picked another offered mechanism: restart with
                // it. The optimistic token is discarded, so the mechList
                // must be protected by a MIC (RFC 4178 §5).
                let Some(&idx) = self
                    .offered
                    .iter()
                    .find(|&&i| same_mech(m, self.mechs[i].oid()))
                else {
                    return Err(ProtoError::Auth(format!(
                        "the server selected unoffered mechanism {}",
                        Oid(m)
                    )));
                };
                self.chosen = idx;
                self.mic_required = true;
                switched = true;
                out_token = self.mechs[idx].step(&[])?.token().map(<[u8]>::to_vec);
            }
            if let Some(tok) = &resp.response_token
                && !switched
            {
                if self.mechs[self.chosen].is_complete() {
                    return Err(ProtoError::Auth(
                        "unexpected mechanism token after completion".into(),
                    ));
                }
                out_token = self.mechs[self.chosen]
                    .step(tok)?
                    .token()
                    .map(<[u8]>::to_vec);
            }
            // Some legacy acceptors copy the responseToken into the
            // mechListMIC field; like pyspnego (smbprotocol issue #137) and
            // Heimdal, treat that as no MIC rather than failing. Downgrade
            // protection still holds: a required MIC must arrive later.
            let mech_list_mic = resp
                .mech_list_mic
                .as_ref()
                .filter(|&m| resp.response_token.as_ref() != Some(m));
            if mech_list_mic.is_none() && resp.mech_list_mic.is_some() {
                tracing::debug!("ignoring a mechListMIC that repeats the responseToken");
            }
            if let Some(mic) = mech_list_mic {
                if !self.mechs[self.chosen].is_complete() {
                    return Err(ProtoError::Auth(
                        "mechListMIC received before the mechanism completed".into(),
                    ));
                }
                self.mechs[self.chosen].verify_mic(&self.mech_list_der, mic)?;
                self.mic_received = true;
                // A peer that sends a mechListMIC expects one back.
                self.mic_required = true;
            }
        }

        let mech_complete = self.mechs[self.chosen].is_complete();
        if server_complete && !mech_complete {
            return Err(ProtoError::Auth(
                "the server completed SPNEGO before the mechanism finished".into(),
            ));
        }
        let mut out_mic = None;
        if mech_complete
            && !self.mic_sent
            && (self.mic_required || self.mechs[self.chosen].wants_mech_list_mic())
        {
            out_mic = Some(self.mechs[self.chosen].get_mic(&self.mech_list_der)?);
            self.mic_sent = true;
        }

        if out_token.is_some() || out_mic.is_some() {
            let resp = NegTokenResp {
                response_token: out_token,
                mech_list_mic: out_mic,
                ..Default::default()
            };
            if server_complete {
                self.check_downgrade_protection()?;
                self.state = State::Complete;
                return Ok(AuthStep::Done(Some(resp.encode())));
            }
            self.state = if mech_complete {
                State::AwaitingFinal
            } else {
                State::InProgress
            };
            return Ok(AuthStep::Continue(resp.encode()));
        }
        if server_complete
            || (mech_complete && self.state == State::AwaitingFinal && input.is_empty())
        {
            self.check_downgrade_protection()?;
            if self.mic_sent && !self.mic_received {
                // pyspnego and Windows accept this too; the MIC we sent
                // still protects the mechanism list towards the server.
                tracing::debug!("server completed SPNEGO without a mechListMIC");
            }
            self.state = State::Complete;
            return Ok(AuthStep::Done(None));
        }
        Err(ProtoError::Auth(
            "SPNEGO exchange stalled: the server sent nothing to continue with".into(),
        ))
    }
}

impl Authenticator for SpnegoClient {
    fn step(&mut self, input: &[u8]) -> Result<AuthStep> {
        let r = match self.state {
            State::Initial => self.step_initial(input),
            State::InProgress | State::AwaitingFinal => self.step_resp(input),
            State::Complete => {
                if input.is_empty() {
                    return Ok(AuthStep::Done(None));
                }
                return self.fail(ProtoError::Auth(
                    "unexpected SPNEGO token after completion".into(),
                ));
            }
            State::Failed => {
                return Err(ProtoError::Auth(
                    "SPNEGO authentication already failed".into(),
                ));
            }
        };
        match r {
            Ok(s) => Ok(s),
            Err(e) => self.fail(e),
        }
    }

    fn is_complete(&self) -> bool {
        self.state == State::Complete
    }

    fn session_key(&self) -> Option<&[u8]> {
        self.mechs[self.chosen].session_key()
    }

    fn is_anonymous(&self) -> bool {
        self.mechs[self.chosen].is_anonymous()
    }

    fn mechanism(&self) -> &'static str {
        self.mechs[self.chosen].mechanism()
    }
}

/// `true` if `oid` (DER content octets) is the NTLMSSP mechanism.
pub fn is_ntlm(oid: &[u8]) -> bool {
    oid == NTLMSSP_OID
}

#[cfg(test)]
mod tests {
    use super::super::ntlm::{
        AvPairs, ChallengeMessage, Direction, NegotiateFlags, NtlmMac, NtlmVersion, av_id, nt_hash,
        ntowfv2, rc4k,
    };
    use super::*;
    use crate::wire::utf16le_vec;

    fn h(s: &str) -> Vec<u8> {
        let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Samba's NegTokenInit2 hint from a NEGOTIATE response.
    fn samba_hint() -> Vec<u8> {
        NegTokenInit {
            mech_types: vec![
                MS_KRB5_OID.to_vec(),
                KRB5_OID.to_vec(),
                NTLMSSP_OID.to_vec(),
            ],
            hint_name: Some(b"not_defined_in_RFC4178@please_ignore".to_vec()),
            ..Default::default()
        }
        .encode()
    }

    #[test]
    fn init_matches_pyspnego_layout() {
        // pyspnego's NegTokenInit for NTLM (see tests/reference): GSS
        // framing, mechTypes, mechToken; no reqFlags.
        let ntlm_neg =
            h("4e544c4d5353500001000000378208e200000000280000000000000028000000000c04000000000f");
        let init = NegTokenInit {
            mech_types: vec![NTLMSSP_OID.to_vec()],
            mech_token: Some(ntlm_neg.clone()),
            ..Default::default()
        };
        let expected = h("604806062b0601050502a03e303ca00e300c060a2b06010401823702020aa22a0428")
            .into_iter()
            .chain(ntlm_neg)
            .collect::<Vec<_>>();
        assert_eq!(init.encode(), expected);
        assert_eq!(
            NegotiationToken::decode(&expected).unwrap(),
            NegotiationToken::Init(init)
        );
    }

    #[test]
    fn init2_and_resp_round_trip() {
        let hint = samba_hint();
        let NegotiationToken::Init(d) = NegotiationToken::decode(&hint).unwrap() else {
            panic!()
        };
        assert_eq!(d.mech_types.len(), 3);
        assert_eq!(
            d.hint_name.as_deref(),
            Some(&b"not_defined_in_RFC4178@please_ignore"[..])
        );
        let with_mic = NegTokenInit {
            mech_list_mic: Some(vec![1; 16]),
            ..d.clone()
        };
        assert_eq!(
            NegotiationToken::decode(&with_mic.encode()).unwrap(),
            NegotiationToken::Init(with_mic)
        );
        let rfc = NegTokenInit {
            hint_name: None,
            req_flags: Some(vec![0, 0x60]),
            mech_list_mic: Some(vec![2; 16]),
            ..d
        };
        assert_eq!(
            NegotiationToken::decode(&rfc.encode()).unwrap(),
            NegotiationToken::Init(rfc)
        );

        for state in [
            NegState::AcceptCompleted,
            NegState::AcceptIncomplete,
            NegState::Reject,
            NegState::RequestMic,
        ] {
            let r = NegTokenResp {
                neg_state: Some(state),
                supported_mech: Some(NTLMSSP_OID.to_vec()),
                response_token: Some(vec![9; 300]),
                mech_list_mic: Some(vec![3; 16]),
            };
            assert_eq!(
                NegotiationToken::decode(&r.encode()).unwrap(),
                NegotiationToken::Resp(r)
            );
        }
        assert_eq!(
            NegotiationToken::decode(&NegTokenResp::default().encode()).unwrap(),
            NegotiationToken::Resp(NegTokenResp::default())
        );
        // A known Windows accept-completed token: a1 07 30 05 a0 03 0a 01 00.
        let NegotiationToken::Resp(r) =
            NegotiationToken::decode(&h("a107300 5a0030a0100")).unwrap()
        else {
            panic!()
        };
        assert_eq!(r.neg_state, Some(NegState::AcceptCompleted));
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(NegotiationToken::decode(&[]).is_err());
        assert!(NegotiationToken::decode(b"NTLMSSP\0").is_err());
        assert!(NegotiationToken::decode(&h("600506032a0304")).is_err());
        // Kerberos raw token framing is not SPNEGO.
        let mut krb = Vec::new();
        put_constructed(&mut krb, TAG_APPLICATION_0, |o| {
            put_tlv(o, TAG_OID, KRB5_OID)
        });
        assert!(matches!(
            NegotiationToken::decode(&krb),
            Err(ProtoError::Auth(_))
        ));
        let mut extra = NegTokenResp::default().encode();
        extra.push(0);
        assert!(NegotiationToken::decode(&extra).is_err());
    }

    /// A minimal NTLM-over-SPNEGO acceptor for end-to-end tests.
    struct MockServer {
        password: &'static str,
        negotiate: Vec<u8>,
        challenge: Vec<u8>,
        mech_list: Vec<u8>,
        send_mic: bool,
    }

    impl MockServer {
        fn challenge(&mut self, token: &[u8]) -> Vec<u8> {
            let NegotiationToken::Init(init) = NegotiationToken::decode(token).unwrap() else {
                panic!()
            };
            assert_eq!(init.mech_types, vec![NTLMSSP_OID.to_vec()]);
            self.mech_list = encode_mech_type_list(&init.mech_types);
            self.negotiate = init.mech_token.unwrap();
            let mut info = AvPairs::default();
            info.set(av_id::NB_COMPUTER_NAME, utf16le_vec("SRV"));
            info.set(
                av_id::TIMESTAMP,
                133_100_000_000_000_000u64.to_le_bytes().to_vec(),
            );
            self.challenge = ChallengeMessage {
                flags: NegotiateFlags::CLIENT_DEFAULT | NegotiateFlags::TARGET_INFO,
                server_challenge: [4; 8],
                target_name: "SRV".into(),
                target_info: info,
                version: Some(NtlmVersion::DEFAULT),
            }
            .encode()
            .unwrap();
            NegTokenResp {
                neg_state: Some(NegState::AcceptIncomplete),
                supported_mech: Some(NTLMSSP_OID.to_vec()),
                response_token: Some(self.challenge.clone()),
                mech_list_mic: None,
            }
            .encode()
        }

        fn finish(&mut self, token: &[u8]) -> (Vec<u8>, [u8; 16]) {
            let NegotiationToken::Resp(r) = NegotiationToken::decode(token).unwrap() else {
                panic!()
            };
            let a = super::super::ntlm::AuthenticateMessage::decode(&r.response_token.unwrap())
                .unwrap();
            let key = ntowfv2(&nt_hash(self.password), &a.user, &a.domain);
            let base = {
                use hmac::{Hmac, KeyInit, Mac};
                let mut m = <Hmac<md5::Md5> as KeyInit>::new_from_slice(&key).unwrap();
                m.update(&[4u8; 8]);
                m.update(&a.nt_response[16..]);
                let proof = m.finalize().into_bytes();
                assert_eq!(&proof[..], &a.nt_response[..16], "bad password");
                let mut m = <Hmac<md5::Md5> as KeyInit>::new_from_slice(&key).unwrap();
                m.update(&proof);
                m.finalize().into_bytes()
            };
            let exported: [u8; 16] = rc4k(&base, &a.encrypted_random_session_key)
                .try_into()
                .unwrap();
            let flags = a.flags;
            let mut cin = NtlmMac::new(flags, &exported, Direction::ClientToServer);
            cin.verify(
                &self.mech_list,
                &r.mech_list_mic.expect("client mechListMIC"),
            )
            .unwrap();
            let mut sout = NtlmMac::new(flags, &exported, Direction::ServerToClient);
            let mic = self.send_mic.then(|| sout.sign(&self.mech_list).to_vec());
            let resp = NegTokenResp {
                neg_state: Some(NegState::AcceptCompleted),
                mech_list_mic: mic,
                ..Default::default()
            };
            (resp.encode(), exported)
        }
    }

    #[test]
    fn spnego_ntlm_end_to_end() {
        for send_mic in [true, false] {
            let mut server = MockServer {
                password: "pw",
                negotiate: vec![],
                challenge: vec![],
                mech_list: vec![],
                send_mic,
            };
            let mut c = SpnegoClient::ntlm(NtlmCredentials::new("DOM\\user", "pw"));
            let AuthStep::Continue(t1) = c.step(&samba_hint()).unwrap() else {
                panic!()
            };
            let t2 = server.challenge(&t1);
            let AuthStep::Continue(t3) = c.step(&t2).unwrap() else {
                panic!()
            };
            assert!(!c.is_complete());
            let key = c.session_key().unwrap().to_vec();
            let (t4, exported) = server.finish(&t3);
            assert_eq!(key, exported);
            assert_eq!(c.step(&t4).unwrap(), AuthStep::Done(None));
            assert!(c.is_complete());
            assert_eq!(c.mech_list_mic_verified(), send_mic);
            assert_eq!(c.mechanism(), "NTLM");
        }
    }

    #[test]
    fn spnego_bad_server_mic_and_reject() {
        let mut server = MockServer {
            password: "pw",
            negotiate: vec![],
            challenge: vec![],
            mech_list: vec![],
            send_mic: true,
        };
        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        let AuthStep::Continue(t1) = c.step(&[]).unwrap() else {
            panic!()
        };
        let t2 = server.challenge(&t1);
        let AuthStep::Continue(t3) = c.step(&t2).unwrap() else {
            panic!()
        };
        let (t4, _) = server.finish(&t3);
        let NegotiationToken::Resp(mut r) = NegotiationToken::decode(&t4).unwrap() else {
            panic!()
        };
        r.mech_list_mic.as_mut().unwrap()[5] ^= 1;
        assert!(c.step(&r.encode()).is_err());
        assert!(c.step(&[]).is_err(), "failed state is sticky");

        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        c.step(&[]).unwrap();
        let reject = NegTokenResp {
            neg_state: Some(NegState::Reject),
            ..Default::default()
        };
        assert!(matches!(c.step(&reject.encode()), Err(ProtoError::Auth(_))));
    }

    #[test]
    fn empty_final_token_and_unoffered_mech() {
        let mut server = MockServer {
            password: "pw",
            negotiate: vec![],
            challenge: vec![],
            mech_list: vec![],
            send_mic: false,
        };
        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        let AuthStep::Continue(t1) = c.step(&[]).unwrap() else {
            panic!()
        };
        let t2 = server.challenge(&t1);
        let AuthStep::Continue(_) = c.step(&t2).unwrap() else {
            panic!()
        };
        assert_eq!(c.step(&[]).unwrap(), AuthStep::Done(None));

        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        c.step(&[]).unwrap();
        let resp = NegTokenResp {
            neg_state: Some(NegState::AcceptIncomplete),
            supported_mech: Some(KRB5_OID.to_vec()),
            ..Default::default()
        };
        assert!(c.step(&resp.encode()).is_err());
        // An empty token in the middle of the exchange is an error.
        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        c.step(&[]).unwrap();
        assert!(c.step(&[]).is_err());
    }

    #[test]
    fn mech_list_mic_equal_to_response_token_is_ignored() {
        // Legacy acceptors copy the responseToken into mechListMIC
        // (smbprotocol issue #137; Heimdal has the same workaround).
        // pyspnego ignores such a MIC instead of failing authentication.
        let mut server = MockServer {
            password: "pw",
            negotiate: vec![],
            challenge: vec![],
            mech_list: vec![],
            send_mic: true,
        };
        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        let AuthStep::Continue(t1) = c.step(&[]).unwrap() else {
            panic!()
        };
        let t2 = server.challenge(&t1);
        let NegotiationToken::Resp(mut r) = NegotiationToken::decode(&t2).unwrap() else {
            panic!()
        };
        r.mech_list_mic = r.response_token.clone();
        let AuthStep::Continue(t3) = c.step(&r.encode()).unwrap() else {
            panic!("the bogus MIC must be ignored")
        };
        assert!(!c.mech_list_mic_verified());
        let (t4, _) = server.finish(&t3);
        assert_eq!(c.step(&t4).unwrap(), AuthStep::Done(None));
        assert!(c.mech_list_mic_verified());
    }

    /// A one-leg mechanism for exercising SPNEGO negotiation logic.
    struct MockMech {
        oid: &'static [u8],
        id: u8,
        done: bool,
    }

    /// MIC of `data` for direction `dir` (0 = initiator, 1 = acceptor).
    fn mock_mic(id: u8, dir: u8, data: &[u8]) -> Vec<u8> {
        [id, dir].iter().chain(data).copied().collect()
    }

    impl Authenticator for MockMech {
        fn step(&mut self, input: &[u8]) -> Result<AuthStep> {
            if self.done {
                return Err(ProtoError::Auth(format!("unexpected token {input:?}")));
            }
            self.done = true;
            Ok(AuthStep::Done(Some(vec![self.id; 4])))
        }
        fn is_complete(&self) -> bool {
            self.done
        }
        fn session_key(&self) -> Option<&[u8]> {
            self.done.then_some(&[0x5A; 16][..])
        }
        fn mechanism(&self) -> &'static str {
            "mock"
        }
    }

    impl GssMechanism for MockMech {
        fn oid(&self) -> &'static [u8] {
            self.oid
        }
        fn wants_mech_list_mic(&self) -> bool {
            false
        }
        fn get_mic(&mut self, data: &[u8]) -> Result<Vec<u8>> {
            Ok(mock_mic(self.id, 0, data))
        }
        fn verify_mic(&mut self, data: &[u8], mic: &[u8]) -> Result<()> {
            if mic == mock_mic(self.id, 1, data) {
                Ok(())
            } else {
                Err(ProtoError::Auth("bad MIC".into()))
            }
        }
    }

    fn two_mech_client() -> SpnegoClient {
        SpnegoClient::new(vec![
            Box::new(MockMech {
                oid: KRB5_OID,
                id: 1,
                done: false,
            }),
            Box::new(MockMech {
                oid: NTLMSSP_OID,
                id: 2,
                done: false,
            }),
        ])
        .unwrap()
    }

    /// Drive a two-mechanism client to the point where the acceptor has
    /// selected the client's second choice and received its token and MIC.
    fn negotiate_second_choice(c: &mut SpnegoClient) -> Vec<u8> {
        let AuthStep::Continue(t1) = c.step(&[]).unwrap() else {
            panic!()
        };
        let NegotiationToken::Init(init) = NegotiationToken::decode(&t1).unwrap() else {
            panic!()
        };
        assert_eq!(
            init.mech_types,
            vec![KRB5_OID.to_vec(), NTLMSSP_OID.to_vec()]
        );
        let mech_list = encode_mech_type_list(&init.mech_types);
        let select = NegTokenResp {
            neg_state: Some(NegState::RequestMic),
            supported_mech: Some(NTLMSSP_OID.to_vec()),
            ..Default::default()
        };
        let AuthStep::Continue(t2) = c.step(&select.encode()).unwrap() else {
            panic!()
        };
        let NegotiationToken::Resp(r) = NegotiationToken::decode(&t2).unwrap() else {
            panic!()
        };
        assert_eq!(r.response_token, Some(vec![2; 4]));
        assert_eq!(r.mech_list_mic, Some(mock_mic(2, 0, &mech_list)));
        mech_list
    }

    #[test]
    fn downgrade_requires_acceptor_mech_list_mic() {
        // RFC 4178 §5: when the acceptor selects a mechanism other than the
        // initiator's first choice, its mechListMIC is what proves the
        // mechanism list was not tampered with. Completion without it must
        // fail, whether the acceptor ends with a token or an empty buffer.
        let mut c = two_mech_client();
        negotiate_second_choice(&mut c);
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            ..Default::default()
        };
        assert!(matches!(c.step(&done.encode()), Err(ProtoError::Auth(_))));
        assert!(!c.is_complete());

        let mut c = two_mech_client();
        negotiate_second_choice(&mut c);
        assert!(matches!(c.step(&[]), Err(ProtoError::Auth(_))));

        // With a valid acceptor MIC the downgrade is legitimate.
        let mut c = two_mech_client();
        let mech_list = negotiate_second_choice(&mut c);
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            mech_list_mic: Some(mock_mic(2, 1, &mech_list)),
            ..Default::default()
        };
        assert_eq!(c.step(&done.encode()).unwrap(), AuthStep::Done(None));
        assert!(c.is_complete() && c.mech_list_mic_verified());
        assert_eq!(c.session_key(), Some(&[0x5A; 16][..]));

        // The first choice needs no acceptor MIC (MIC exchange optional).
        let mut c = two_mech_client();
        c.step(&[]).unwrap();
        let done = NegTokenResp {
            neg_state: Some(NegState::AcceptCompleted),
            supported_mech: Some(KRB5_OID.to_vec()),
            ..Default::default()
        };
        assert_eq!(c.step(&done.encode()).unwrap(), AuthStep::Done(None));
    }

    #[test]
    fn hint_without_ntlm_still_offers_ntlm() {
        let hint = NegTokenInit {
            mech_types: vec![KRB5_OID.to_vec()],
            ..Default::default()
        }
        .encode();
        let mut c = SpnegoClient::ntlm(NtlmCredentials::new("u", "pw"));
        let AuthStep::Continue(t1) = c.step(&hint).unwrap() else {
            panic!()
        };
        let NegotiationToken::Init(init) = NegotiationToken::decode(&t1).unwrap() else {
            panic!()
        };
        assert_eq!(init.mech_types, vec![NTLMSSP_OID.to_vec()]);
        assert!(same_mech(KRB5_OID, MS_KRB5_OID));
        assert!(!same_mech(KRB5_OID, NTLMSSP_OID));
        assert!(is_ntlm(NTLMSSP_OID));
        assert_eq!(Oid(NEGOEX_OID).to_string(), "1.3.6.1.4.1.311.2.2.30");
        assert_eq!(Oid(SPNEGO_OID).to_string(), "1.3.6.1.5.5.2");
    }
}
