//! SMB2 ERROR response, error contexts and the symbolic link error response
//! ([MS-SMB2] §2.2.2).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::{BufMut, Bytes, BytesMut};

use super::{EncodedMessage, body_reader};
use crate::error::{ProtoError, Result};
use crate::header::{HEADER_LEN, Header};
use crate::wire::{
    Reader, decode_utf16le, len_u16, len_u32, pad_to, padding, put_utf16le, slice_ref, utf16le_len,
};

/// `ErrorId` of the default error context.
pub const ERROR_ID_DEFAULT: u32 = 0x0000_0000;
/// `ErrorId` of the share redirect error context (`SMB2_ERROR_ID_SHARE_REDIRECT`).
pub const ERROR_ID_SHARE_REDIRECT: u32 = 0x7264_5253;
/// `SymLinkErrorTag` ("SYML").
pub const SYMLINK_ERROR_TAG: u32 = 0x4C4D_5953;
/// `SYMLINK_FLAG_RELATIVE`.
pub const SYMLINK_FLAG_RELATIVE: u32 = 0x0000_0001;

/// One SMB2_ERROR_CONTEXT (3.1.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorContext {
    /// Error id.
    pub error_id: u32,
    /// Context data.
    pub data: Bytes,
}

/// SMB2 ERROR response body.
///
/// In 3.1.1 the error data may be a list of [`ErrorContext`]s; otherwise it
/// is raw status-specific data (e.g. the symbolic link error response for
/// `STATUS_STOPPED_ON_SYMLINK`, or the required size for
/// `STATUS_BUFFER_TOO_SMALL`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorResponse {
    /// Error contexts (3.1.1; empty otherwise).
    pub error_contexts: Vec<ErrorContext>,
    /// Raw error data when there are no contexts.
    pub error_data: Bytes,
}

impl ErrorResponse {
    /// Encode the body.
    pub fn encode_body(&self, dst: &mut BytesMut) -> Result<()> {
        let n = u8::try_from(self.error_contexts.len())
            .map_err(|_| ProtoError::InvalidInput("too many error contexts"))?;
        dst.put_u16_le(9);
        dst.put_u8(n);
        dst.put_u8(0);
        let count_pos = dst.len();
        dst.put_u32_le(0);
        let start = dst.len();
        if n > 0 {
            for (i, c) in self.error_contexts.iter().enumerate() {
                if i > 0 {
                    pad_to(dst, 8);
                }
                dst.put_u32_le(len_u32(c.data.len(), "error context too long")?);
                dst.put_u32_le(c.error_id);
                dst.put_slice(&c.data);
            }
        } else {
            dst.put_slice(&self.error_data);
        }
        let byte_count = dst.len() - start;
        crate::wire::patch_u32(dst, count_pos, len_u32(byte_count, "error data too long")?);
        if byte_count == 0 {
            // ErrorData must be at least one byte.
            dst.put_u8(0);
        }
        Ok(())
    }

    /// Decode from a complete message (header first).
    pub fn decode_body(msg: &Bytes) -> Result<Self> {
        const W: &str = "ERROR response";
        let mut r = body_reader(msg, W, 9)?;
        let n = usize::from(r.u8()?);
        r.skip(1)?;
        let byte_count = r.u32()? as usize;
        let data_start = HEADER_LEN + 8;
        let data = crate::wire::slice_bytes(msg, data_start, byte_count, W)?;
        if n == 0 {
            return Ok(ErrorResponse {
                error_contexts: Vec::new(),
                error_data: data,
            });
        }
        let mut error_contexts = Vec::with_capacity(n);
        let mut pos = 0usize;
        for i in 0..n {
            if i > 0 {
                pos += padding(pos, 8);
            }
            let hdr = slice_ref(&data, pos, 8, W)?;
            let len = u32::from_le_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]) as usize;
            let error_id = u32::from_le_bytes([hdr[4], hdr[5], hdr[6], hdr[7]]);
            let cdata = crate::wire::slice_bytes(&data, pos + 8, len, W)?;
            error_contexts.push(ErrorContext {
                error_id,
                data: cdata,
            });
            pos += 8 + len;
        }
        Ok(ErrorResponse {
            error_contexts,
            error_data: Bytes::new(),
        })
    }

    /// The status-specific data: the raw error data, or the data of the
    /// first default error context.
    pub fn default_data(&self) -> &Bytes {
        if self.error_contexts.is_empty() {
            &self.error_data
        } else {
            self.error_contexts
                .iter()
                .find(|c| c.error_id == ERROR_ID_DEFAULT)
                .map_or(&self.error_data, |c| &c.data)
        }
    }

    /// Decode the symbolic link error response (`STATUS_STOPPED_ON_SYMLINK`).
    pub fn symlink(&self) -> Result<SymlinkErrorResponse> {
        SymlinkErrorResponse::decode(self.default_data())
    }

    /// The required buffer size carried by `STATUS_BUFFER_TOO_SMALL`.
    pub fn required_buffer_size(&self) -> Option<u32> {
        let d = self.default_data();
        (d.len() >= 4).then(|| u32::from_le_bytes([d[0], d[1], d[2], d[3]]))
    }

    /// Decode a share redirect error context, if present.
    pub fn share_redirect(&self) -> Option<Result<ShareRedirect>> {
        self.error_contexts
            .iter()
            .find(|c| c.error_id == ERROR_ID_SHARE_REDIRECT)
            .map(|c| ShareRedirect::decode(&c.data))
    }
}

/// Encode an ERROR response message, keeping the header's command.
pub fn encode_error_message(header: &Header, err: &ErrorResponse) -> Result<EncodedMessage> {
    let mut head = BytesMut::with_capacity(HEADER_LEN + 16);
    header.encode(&mut head);
    err.encode_body(&mut head)?;
    Ok(EncodedMessage {
        head,
        payload: None,
        padding: 0,
    })
}

/// Symbolic link error response ([MS-SMB2] §2.2.2.2.1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SymlinkErrorResponse {
    /// Bytes of the original path that were not parsed (the part after the
    /// symlink component), in UTF-16 bytes.
    pub unparsed_path_length: u16,
    /// Substitute name (the target, NT form).
    pub substitute_name: String,
    /// Print name (the target, user form).
    pub print_name: String,
    /// Flags (`SYMLINK_FLAG_RELATIVE`).
    pub flags: u32,
}

impl SymlinkErrorResponse {
    /// `true` if the target is relative to the link's directory.
    pub fn is_relative(&self) -> bool {
        self.flags & SYMLINK_FLAG_RELATIVE != 0
    }

    /// Decode from the error data.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "symbolic link error response";
        let mut r = Reader::new(buf, W);
        let _symlink_length = r.u32()?;
        if r.u32()? != SYMLINK_ERROR_TAG {
            return Err(ProtoError::malformed(W, "bad SymLinkErrorTag"));
        }
        let reparse_tag = r.u32()?;
        if reparse_tag != crate::fscc::reparse_tag::SYMLINK {
            return Err(ProtoError::malformed(
                W,
                "reparse tag is not IO_REPARSE_TAG_SYMLINK",
            ));
        }
        let _reparse_data_length = r.u16()?;
        let unparsed_path_length = r.u16()?;
        let sub_off = usize::from(r.u16()?);
        let sub_len = usize::from(r.u16()?);
        let print_off = usize::from(r.u16()?);
        let print_len = usize::from(r.u16()?);
        let flags = r.u32()?;
        let path_buffer = r.rest();
        let substitute_name = decode_utf16le(slice_ref(path_buffer, sub_off, sub_len, W)?, W)?;
        let print_name = decode_utf16le(slice_ref(path_buffer, print_off, print_len, W)?, W)?;
        Ok(SymlinkErrorResponse {
            unparsed_path_length,
            substitute_name,
            print_name,
            flags,
        })
    }

    /// Encode (mock servers, tests). The print name precedes the substitute
    /// name in the path buffer, as Windows does.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let sub_len = len_u16(
            utf16le_len(&self.substitute_name),
            "substitute name too long",
        )?;
        let print_len = len_u16(utf16le_len(&self.print_name), "print name too long")?;
        let path_len = usize::from(sub_len) + usize::from(print_len);
        let reparse_data_len = len_u16(12 + path_len, "symlink too long")?;
        // SymLinkLength counts everything after itself.
        dst.put_u32_le(len_u32(4 + 4 + 2 + 2 + 12 + path_len, "symlink too long")?);
        dst.put_u32_le(SYMLINK_ERROR_TAG);
        dst.put_u32_le(crate::fscc::reparse_tag::SYMLINK);
        dst.put_u16_le(reparse_data_len);
        dst.put_u16_le(self.unparsed_path_length);
        dst.put_u16_le(print_len); // substitute name follows the print name
        dst.put_u16_le(sub_len);
        dst.put_u16_le(0);
        dst.put_u16_le(print_len);
        dst.put_u32_le(self.flags);
        put_utf16le(dst, &self.print_name);
        put_utf16le(dst, &self.substitute_name);
        Ok(())
    }
}

/// Share redirect error context ([MS-SMB2] §2.2.2.2.2): the share moved to
/// other addresses (scale-out / cluster).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ShareRedirect {
    /// Addresses to reconnect to.
    pub ip_addresses: Vec<IpAddr>,
    /// The resource (share) name.
    pub resource_name: String,
}

impl ShareRedirect {
    /// Decode from the context data.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        const W: &str = "share redirect error context";
        let mut r = Reader::new(buf, W);
        let _structure_size = r.u32()?;
        let _notification_type = r.u32()?;
        let name_off = r.u32()? as usize;
        let name_len = r.u32()? as usize;
        r.skip(2)?;
        let _target_type = r.u16()?;
        let n = r.u32()? as usize;
        if n > r.remaining() / 24 {
            return Err(r.malformed("address count exceeds buffer"));
        }
        let mut ip_addresses = Vec::with_capacity(n);
        for _ in 0..n {
            let kind = r.u32()?;
            r.skip(4)?;
            let addr: [u8; 16] = r.array()?;
            ip_addresses.push(match kind {
                1 => IpAddr::V4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3])),
                2 => IpAddr::V6(Ipv6Addr::from(addr)),
                _ => return Err(r.malformed("unknown address type")),
            });
        }
        let resource_name = decode_utf16le(slice_ref(buf, name_off, name_len, W)?, W)?;
        Ok(ShareRedirect {
            ip_addresses,
            resource_name,
        })
    }

    /// Encode (mock servers, tests).
    pub fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        let fixed = 24 + 24 * self.ip_addresses.len();
        dst.put_u32_le(0x30);
        dst.put_u32_le(3);
        dst.put_u32_le(len_u32(fixed, "too many addresses")?);
        dst.put_u32_le(len_u32(utf16le_len(&self.resource_name), "name too long")?);
        dst.put_u16_le(0);
        dst.put_u16_le(0);
        dst.put_u32_le(len_u32(self.ip_addresses.len(), "too many addresses")?);
        for a in &self.ip_addresses {
            match a {
                IpAddr::V4(v4) => {
                    dst.put_u32_le(1);
                    dst.put_u32_le(0);
                    dst.put_slice(&v4.octets());
                    dst.put_bytes(0, 12);
                }
                IpAddr::V6(v6) => {
                    dst.put_u32_le(2);
                    dst.put_u32_le(0);
                    dst.put_slice(&v6.octets());
                }
            }
        }
        put_utf16le(dst, &self.resource_name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{Command, HeaderFlags};
    use crate::msg::RawMessage;
    use crate::status::NtStatus;

    fn rt(e: &ErrorResponse) -> ErrorResponse {
        let mut h = Header::request(Command::CREATE);
        h.flags = HeaderFlags::SERVER_TO_REDIR;
        h.status = NtStatus::STOPPED_ON_SYMLINK;
        let m = encode_error_message(&h, e)
            .unwrap()
            .into_contiguous()
            .freeze();
        let raw = RawMessage::parse(m).unwrap();
        assert!(raw.is_error_response());
        raw.decode_error().unwrap()
    }

    #[test]
    fn symlink_round_trip() {
        let s = SymlinkErrorResponse {
            unparsed_path_length: 8,
            substitute_name: "\\??\\C:\\target".into(),
            print_name: "C:\\target".into(),
            flags: 0,
        };
        let mut b = BytesMut::new();
        s.encode(&mut b).unwrap();
        let e = ErrorResponse {
            error_contexts: vec![],
            error_data: b.clone().freeze(),
        };
        let d = rt(&e);
        assert_eq!(d, e);
        assert_eq!(d.symlink().unwrap(), s);
        // 3.1.1 form with a default context.
        let e2 = ErrorResponse {
            error_contexts: vec![ErrorContext {
                error_id: ERROR_ID_DEFAULT,
                data: b.freeze(),
            }],
            error_data: Bytes::new(),
        };
        let d2 = rt(&e2);
        assert_eq!(d2, e2);
        assert_eq!(d2.symlink().unwrap(), s);
    }

    #[test]
    fn empty_and_redirect() {
        assert_eq!(rt(&ErrorResponse::default()), ErrorResponse::default());
        let sr = ShareRedirect {
            ip_addresses: vec!["10.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
            resource_name: "share".into(),
        };
        let mut b = BytesMut::new();
        sr.encode(&mut b).unwrap();
        let e = ErrorResponse {
            error_contexts: vec![
                ErrorContext {
                    error_id: ERROR_ID_DEFAULT,
                    data: Bytes::from_static(b"abc"),
                },
                ErrorContext {
                    error_id: ERROR_ID_SHARE_REDIRECT,
                    data: b.freeze(),
                },
            ],
            error_data: Bytes::new(),
        };
        let d = rt(&e);
        assert_eq!(d, e);
        assert_eq!(d.share_redirect().unwrap().unwrap(), sr);
        let small = ErrorResponse {
            error_contexts: vec![],
            error_data: Bytes::from_static(&[0x10, 0, 0, 0]),
        };
        assert_eq!(rt(&small).required_buffer_size(), Some(16));
    }
}
