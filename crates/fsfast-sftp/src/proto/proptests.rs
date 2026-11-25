//! Property tests: decoders never panic on arbitrary or mutated input, and
//! every encodable value round-trips.

use bytes::Bytes;
use proptest::prelude::*;

use super::attrs::FileAttributes;
use super::frame::{Frame, FrameAssembler};
use super::packet::{ExtRequest, NameEntry, Payload, Reply, Request, Status, Version};
use super::wire::Cursor;
use super::{fxp, open_flags};

fn bytes_strategy(max: usize) -> impl Strategy<Value = Bytes> {
    proptest::collection::vec(any::<u8>(), 0..max).prop_map(Bytes::from)
}

fn attrs_strategy() -> impl Strategy<Value = FileAttributes> {
    (
        proptest::option::of(any::<u64>()),
        proptest::option::of((any::<u32>(), any::<u32>())),
        proptest::option::of(any::<u32>()),
        proptest::option::of((any::<u32>(), any::<u32>())),
        proptest::collection::vec((bytes_strategy(12), bytes_strategy(12)), 0..3),
    )
        .prop_map(|(size, uid_gid, permissions, times, extended)| FileAttributes {
            size,
            uid_gid,
            permissions,
            times,
            extended,
        })
}

fn request_strategy() -> impl Strategy<Value = Request> {
    let b = || bytes_strategy(40);
    prop_oneof![
        (b(), any::<u32>(), attrs_strategy()).prop_map(|(path, pflags, attrs)| Request::Open {
            path,
            pflags,
            attrs
        }),
        b().prop_map(|handle| Request::Close { handle }),
        (b(), any::<u64>(), any::<u32>()).prop_map(|(handle, offset, len)| Request::Read {
            handle,
            offset,
            len
        }),
        (b(), any::<u64>(), bytes_strategy(300)).prop_map(|(handle, offset, data)| {
            Request::Write {
                handle,
                offset,
                data,
            }
        }),
        b().prop_map(|path| Request::Stat { path }),
        b().prop_map(|path| Request::Lstat { path }),
        (b(), attrs_strategy()).prop_map(|(path, attrs)| Request::Setstat { path, attrs }),
        (b(), attrs_strategy()).prop_map(|(handle, attrs)| Request::Fsetstat { handle, attrs }),
        (b(), b()).prop_map(|(old, new)| Request::Rename { old, new }),
        (b(), b()).prop_map(|(link, target)| Request::Symlink { link, target }),
        (b(), b()).prop_map(|(old, new)| Request::Extended(ExtRequest::PosixRename { old, new })),
        (b(), any::<u64>(), any::<u64>(), b(), any::<u64>()).prop_map(
            |(read_handle, read_offset, length, write_handle, write_offset)| {
                Request::Extended(ExtRequest::CopyData {
                    read_handle,
                    read_offset,
                    length,
                    write_handle,
                    write_offset,
                })
            }
        ),
        Just(Request::Extended(ExtRequest::Limits)),
    ]
}

fn reply_strategy() -> impl Strategy<Value = Reply> {
    prop_oneof![
        (any::<u32>(), ".{0,20}", ".{0,5}").prop_map(|(code, message, lang)| Reply::Status(
            Status {
                code,
                message,
                lang
            }
        )),
        bytes_strategy(40).prop_map(Reply::Handle),
        bytes_strategy(2000).prop_map(|b| Reply::Data(Payload::from_bytes(b))),
        proptest::collection::vec((".{0,20}", ".{0,30}", attrs_strategy()), 0..5).prop_map(|v| {
            Reply::Name(
                v.into_iter()
                    .map(|(filename, longname, attrs)| NameEntry {
                        filename,
                        longname,
                        attrs,
                    })
                    .collect(),
            )
        }),
        attrs_strategy().prop_map(Reply::Attrs),
        bytes_strategy(64).prop_map(Reply::ExtendedReply),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    #[test]
    fn attrs_roundtrip(a in attrs_strategy()) {
        let mut b = bytes::BytesMut::new();
        a.encode(&mut b);
        prop_assert_eq!(b.len(), a.encoded_len());
        let mut c = Cursor::new(b.freeze());
        prop_assert_eq!(FileAttributes::decode(&mut c).unwrap(), a);
        prop_assert_eq!(c.remaining(), 0);
    }

    #[test]
    fn requests_roundtrip(r in request_strategy(), id in any::<u32>()) {
        let wire = Bytes::from(r.encode(id).to_vec());
        let len = u32::from_be_bytes([wire[0], wire[1], wire[2], wire[3]]) as usize;
        prop_assert_eq!(len + 4, wire.len());
        let (did, d) = Request::decode(wire.slice(4..)).unwrap();
        prop_assert_eq!(did, id);
        prop_assert_eq!(d, r);
    }

    #[test]
    fn replies_roundtrip_through_the_frame_splitter(
        replies in proptest::collection::vec((reply_strategy(), any::<u32>()), 1..6),
        split in proptest::collection::vec(1usize..5000, 1..20),
    ) {
        let mut wire = Vec::new();
        for (r, id) in &replies {
            wire.extend_from_slice(&r.encode(*id));
        }
        let mut a = FrameAssembler::default();
        let mut got = Vec::new();
        let mut pos = 0;
        let mut i = 0;
        while pos < wire.len() {
            let n = split[i % split.len()].min(wire.len() - pos);
            a.push(Bytes::copy_from_slice(&wire[pos..pos + n]));
            pos += n;
            i += 1;
            while let Some(f) = a.next_frame().unwrap() {
                got.push(f);
            }
        }
        prop_assert_eq!(got.len(), replies.len());
        for (f, (r, id)) in got.into_iter().zip(replies) {
            let Frame::Reply { ty, id: fid, body, data } = f else {
                return Err(TestCaseError::fail("unexpected VERSION frame"));
            };
            prop_assert_eq!(fid, id);
            let decoded = match data {
                Some(p) => Reply::Data(Payload::from_bytes(p.into_bytes())),
                None => Reply::decode(ty, body).unwrap(),
            };
            prop_assert_eq!(decoded, r);
        }
    }

    #[test]
    fn decoders_never_panic(ty in any::<u8>(), body in bytes_strategy(512)) {
        let _ = Reply::decode(ty, body.clone());
        let _ = FileAttributes::decode(&mut Cursor::new(body.clone()));
        let _ = Version::decode(body.clone());
        let _ = super::Limits::decode(body.clone());
        let _ = super::Statvfs::decode(body.clone());
        let mut req = vec![ty];
        req.extend_from_slice(&body);
        let _ = Request::decode(Bytes::from(req));
    }

    #[test]
    fn frame_splitter_never_panics(chunks in proptest::collection::vec(bytes_strategy(64), 0..16)) {
        let mut a = FrameAssembler::new(4096);
        for c in chunks {
            a.push(c);
            loop {
                match a.next_frame() {
                    Ok(Some(Frame::Reply { ty, body, data: None, .. })) => {
                        let _ = Reply::decode(ty, body);
                    }
                    Ok(Some(_)) => {}
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }

    #[test]
    fn mutated_valid_packets_never_panic(
        r in reply_strategy(),
        flips in proptest::collection::vec((any::<usize>(), any::<u8>()), 1..8),
    ) {
        let mut wire = r.encode(1).to_vec();
        for (pos, v) in flips {
            let n = wire.len();
            wire[pos % n] ^= v;
        }
        let mut a = FrameAssembler::default();
        a.push(Bytes::from(wire.clone()));
        if let Ok(Some(Frame::Reply { ty, body, data: None, .. })) = a.next_frame() {
            let _ = Reply::decode(ty, body);
        }
        if wire.len() > 4 {
            let _ = Request::decode(Bytes::from(wire[4..].to_vec()));
        }
    }
}

#[test]
fn open_flag_values_match_the_draft() {
    assert_eq!(open_flags::READ, 1);
    assert_eq!(open_flags::WRITE, 2);
    assert_eq!(open_flags::APPEND, 4);
    assert_eq!(open_flags::CREAT, 8);
    assert_eq!(open_flags::TRUNC, 0x10);
    assert_eq!(open_flags::EXCL, 0x20);
    assert_eq!(fxp::EXTENDED_REPLY, 201);
}
