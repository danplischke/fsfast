//! SMB2 COMPRESSION_TRANSFORM_HEADER parsing ([MS-SMB2] §2.2.42), unchained
//! and chained.
//!
//! Parsing is complete; decompression is implemented for the trivial
//! algorithms (`NONE`, `Pattern_V1`). LZNT1, LZ77, LZ77+Huffman and LZ4
//! ([MS-XCA]) report [`ProtoError::Unsupported`]; clients must not offer
//! them in COMPRESSION_CAPABILITIES until they are implemented.

use bytes::{BufMut, Bytes, BytesMut};

use crate::error::{ProtoError, Result};
use crate::header::COMPRESSION_PROTOCOL_ID;
use crate::msg::CompressionAlgorithm;
use crate::wire::{Reader, len_u32, slice_bytes};

/// `SMB2_COMPRESSION_FLAG_CHAINED`.
pub const COMPRESSION_FLAG_CHAINED: u16 = 0x0001;

/// One payload of a chained compression transform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressedPayload {
    /// Algorithm of this payload.
    pub algorithm: CompressionAlgorithm,
    /// Payload flags.
    pub flags: u16,
    /// Uncompressed size (present for LZNT1/LZ77/LZ77+Huffman/LZ4).
    pub original_payload_size: Option<u32>,
    /// The (compressed) payload bytes; a zero-copy slice of the frame.
    pub data: Bytes,
}

/// A parsed compression transform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompressionTransform {
    /// Unchained: an uncompressed prefix followed by one compressed blob.
    Unchained {
        /// Size of the message after decompression.
        original_compressed_segment_size: u32,
        /// Algorithm of the compressed part.
        algorithm: CompressionAlgorithm,
        /// The uncompressed prefix (`Offset` bytes).
        uncompressed: Bytes,
        /// The compressed data.
        compressed: Bytes,
    },
    /// Chained: a sequence of independently compressed payloads.
    Chained {
        /// Size of the message after decompression.
        original_compressed_segment_size: u32,
        /// Payloads in order.
        payloads: Vec<CompressedPayload>,
    },
}

fn has_original_size(alg: CompressionAlgorithm) -> bool {
    !matches!(
        alg,
        CompressionAlgorithm::NONE | CompressionAlgorithm::PATTERN_V1
    )
}

impl CompressionTransform {
    /// Parse a frame that starts with `0xFC 'SMB'`.
    pub fn parse(frame: &Bytes) -> Result<Self> {
        const W: &str = "COMPRESSION_TRANSFORM_HEADER";
        let mut r = Reader::new(frame, W);
        if r.array::<4>()? != COMPRESSION_PROTOCOL_ID {
            return Err(r.malformed("bad protocol id"));
        }
        let original_compressed_segment_size = r.u32()?;
        let algorithm = CompressionAlgorithm(r.u16()?);
        let flags = r.u16()?;
        if flags & COMPRESSION_FLAG_CHAINED == 0 {
            let offset = r.u32()? as usize;
            let start = r.pos();
            let uncompressed = slice_bytes(frame, start, offset, W)?;
            let compressed = frame.slice(start + offset..);
            return Ok(CompressionTransform::Unchained {
                original_compressed_segment_size,
                algorithm,
                uncompressed,
                compressed,
            });
        }
        // Chained: the first payload header starts at offset 8.
        let mut payloads = Vec::new();
        let mut pos = 8usize;
        while pos < frame.len() {
            let mut p = Reader::new(&frame[pos..], W);
            let algorithm = CompressionAlgorithm(p.u16()?);
            let flags = p.u16()?;
            let mut length = p.u32()? as usize;
            let mut original_payload_size = None;
            if has_original_size(algorithm) {
                // Length covers the OriginalPayloadSize field too.
                original_payload_size = Some(p.u32()?);
                length = length
                    .checked_sub(4)
                    .ok_or(ProtoError::malformed(W, "payload length too small"))?;
            }
            let data_start = pos + p.pos();
            let data = slice_bytes(frame, data_start, length, W)?;
            payloads.push(CompressedPayload {
                algorithm,
                flags,
                original_payload_size,
                data,
            });
            pos = data_start + length;
        }
        Ok(CompressionTransform::Chained {
            original_compressed_segment_size,
            payloads,
        })
    }

    /// The decompressed size announced by the header.
    pub fn original_size(&self) -> u32 {
        match self {
            CompressionTransform::Unchained {
                original_compressed_segment_size,
                ..
            }
            | CompressionTransform::Chained {
                original_compressed_segment_size,
                ..
            } => *original_compressed_segment_size,
        }
    }

    /// Decompress into a new buffer. Supports `NONE` and `Pattern_V1`;
    /// other algorithms fail with [`ProtoError::Unsupported`].
    pub fn decompress(&self) -> Result<BytesMut> {
        const W: &str = "compressed message";
        let size = self.original_size() as usize;
        // Bound the allocation by the protocol's frame limit.
        if size > crate::framing::MAX_TRANSPORT_FRAME_LEN {
            return Err(ProtoError::malformed(
                W,
                "decompressed size exceeds the frame limit",
            ));
        }
        let mut out = BytesMut::with_capacity(size);
        let append = |alg: CompressionAlgorithm, data: &[u8], out: &mut BytesMut| -> Result<()> {
            match alg {
                CompressionAlgorithm::NONE => out.put_slice(data),
                CompressionAlgorithm::PATTERN_V1 => {
                    let mut r = Reader::new(data, "Pattern_V1 payload");
                    let pattern = r.u8()?;
                    r.skip(3)?;
                    let reps = r.u32()? as usize;
                    if out.len().saturating_add(reps) > size {
                        return Err(ProtoError::malformed(
                            W,
                            "pattern exceeds the original size",
                        ));
                    }
                    out.put_bytes(pattern, reps);
                }
                _ => {
                    return Err(ProtoError::Unsupported(
                        "SMB compression algorithm (MS-XCA) not implemented",
                    ));
                }
            }
            if out.len() > size {
                return Err(ProtoError::malformed(W, "data exceeds the original size"));
            }
            Ok(())
        };
        match self {
            CompressionTransform::Unchained {
                algorithm,
                uncompressed,
                compressed,
                ..
            } => {
                append(CompressionAlgorithm::NONE, uncompressed, &mut out)?;
                append(*algorithm, compressed, &mut out)?;
            }
            CompressionTransform::Chained { payloads, .. } => {
                for p in payloads {
                    append(p.algorithm, &p.data, &mut out)?;
                }
            }
        }
        if out.len() != size {
            return Err(ProtoError::malformed(
                W,
                "decompressed size does not match the header",
            ));
        }
        Ok(out)
    }

    /// Encode (mock servers, tests). Payloads are written as given; no
    /// compression is performed.
    pub fn encode(&self, dst: &mut BytesMut) -> Result<()> {
        dst.put_slice(&COMPRESSION_PROTOCOL_ID);
        match self {
            CompressionTransform::Unchained {
                original_compressed_segment_size,
                algorithm,
                uncompressed,
                compressed,
            } => {
                dst.put_u32_le(*original_compressed_segment_size);
                dst.put_u16_le(algorithm.0);
                dst.put_u16_le(0);
                dst.put_u32_le(len_u32(uncompressed.len(), "prefix too long")?);
                dst.put_slice(uncompressed);
                dst.put_slice(compressed);
            }
            CompressionTransform::Chained {
                original_compressed_segment_size,
                payloads,
            } => {
                dst.put_u32_le(*original_compressed_segment_size);
                for (i, p) in payloads.iter().enumerate() {
                    dst.put_u16_le(p.algorithm.0);
                    let flags = if i == 0 {
                        p.flags | COMPRESSION_FLAG_CHAINED
                    } else {
                        p.flags
                    };
                    dst.put_u16_le(flags);
                    match (has_original_size(p.algorithm), p.original_payload_size) {
                        (true, Some(n)) => {
                            dst.put_u32_le(len_u32(p.data.len() + 4, "payload too long")?);
                            dst.put_u32_le(n);
                        }
                        (false, None) => dst.put_u32_le(len_u32(p.data.len(), "payload too long")?),
                        _ => {
                            return Err(ProtoError::InvalidInput(
                                "OriginalPayloadSize does not match the algorithm",
                            ));
                        }
                    }
                    dst.put_slice(&p.data);
                }
            }
        }
        Ok(())
    }
}

/// Build a Pattern_V1 payload (`Pattern`, reserved, `Repetitions`).
pub fn pattern_v1_payload(pattern: u8, repetitions: u32) -> Bytes {
    let mut b = BytesMut::with_capacity(8);
    b.put_u8(pattern);
    b.put_u8(0);
    b.put_u16_le(0);
    b.put_u32_le(repetitions);
    b.freeze()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rt(t: &CompressionTransform) -> CompressionTransform {
        let mut b = BytesMut::new();
        t.encode(&mut b).unwrap();
        CompressionTransform::parse(&b.freeze()).unwrap()
    }

    #[test]
    fn unchained_none() {
        let t = CompressionTransform::Unchained {
            original_compressed_segment_size: 8,
            algorithm: CompressionAlgorithm::NONE,
            uncompressed: Bytes::from_static(b"abc"),
            compressed: Bytes::from_static(b"defgh"),
        };
        let d = rt(&t);
        assert_eq!(d, t);
        assert_eq!(&d.decompress().unwrap()[..], b"abcdefgh");
    }

    #[test]
    fn chained_with_pattern() {
        let t = CompressionTransform::Chained {
            original_compressed_segment_size: 3 + 1000 + 2,
            payloads: vec![
                CompressedPayload {
                    algorithm: CompressionAlgorithm::NONE,
                    flags: 0,
                    original_payload_size: None,
                    data: Bytes::from_static(b"hdr"),
                },
                CompressedPayload {
                    algorithm: CompressionAlgorithm::PATTERN_V1,
                    flags: 0,
                    original_payload_size: None,
                    data: pattern_v1_payload(0, 1000),
                },
                CompressedPayload {
                    algorithm: CompressionAlgorithm::NONE,
                    flags: 0,
                    original_payload_size: None,
                    data: Bytes::from_static(b"zz"),
                },
            ],
        };
        let mut d = rt(&t);
        // The CHAINED flag is added on the first payload when encoding.
        if let CompressionTransform::Chained { payloads, .. } = &mut d {
            assert_eq!(payloads[0].flags, COMPRESSION_FLAG_CHAINED);
            payloads[0].flags = 0;
        }
        assert_eq!(d, t);
        let out = d.decompress().unwrap();
        assert_eq!(out.len(), 1005);
        assert_eq!(&out[..3], b"hdr");
        assert!(out[3..1003].iter().all(|&b| b == 0));
    }

    #[test]
    fn unsupported_and_bombs() {
        let lz = CompressionTransform::Chained {
            original_compressed_segment_size: 10,
            payloads: vec![CompressedPayload {
                algorithm: CompressionAlgorithm::LZ77,
                flags: 0,
                original_payload_size: Some(10),
                data: Bytes::from_static(b"xx"),
            }],
        };
        let d = rt(&lz);
        assert_eq!(d, {
            let mut l = lz.clone();
            if let CompressionTransform::Chained { payloads, .. } = &mut l {
                payloads[0].flags = COMPRESSION_FLAG_CHAINED;
            }
            l
        });
        assert!(matches!(d.decompress(), Err(ProtoError::Unsupported(_))));
        // A pattern larger than the announced size is rejected before allocating.
        let bomb = CompressionTransform::Chained {
            original_compressed_segment_size: 10,
            payloads: vec![CompressedPayload {
                algorithm: CompressionAlgorithm::PATTERN_V1,
                flags: 0,
                original_payload_size: None,
                data: pattern_v1_payload(1, u32::MAX),
            }],
        };
        assert!(bomb.decompress().is_err());
    }
}
