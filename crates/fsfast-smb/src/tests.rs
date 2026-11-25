//! Unit tests of the connection layer against an in-process fake SMB server.
//!
//! The "server" is the test itself: a task accepts one TCP connection,
//! decodes (and, with keys, decrypts) every request frame and hands it to the
//! test through a channel; the test writes back whatever frames it wants. That
//! makes credit accounting, MessageId windows, out-of-order and interim
//! responses, cancellation, signing/encryption failures and connection loss
//! directly observable.

use std::sync::Arc;
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use fsfast_core::ErrorKind;
use fsfast_smb_proto::compound::{CompoundBuilder, split_compound};
use fsfast_smb_proto::crypto::{
    Cipher, SessionKeys, Signer, SigningAlgorithm, SmbCipher, derive_session_keys,
};
use fsfast_smb_proto::framing::FrameDecoder;
use fsfast_smb_proto::header::{Command, Header, HeaderFlags, HeaderId, TRANSFORM_PROTOCOL_ID};
use fsfast_smb_proto::msg::{
    EchoRequest, EchoResponse, EncodedMessage, ErrorResponse, Message, OutgoingFrame, RawMessage,
    ReadRequest, ReadResponse, encode_error_message, encode_message,
};
use fsfast_smb_proto::{Dialect, FileId, Guid, NtStatus, SecurityMode};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::conn::{Connection, Negotiated, Security, SessionCrypto, recv_all, was_not_sent};

/// One request frame as the server saw it.
struct Incoming {
    msgs: Vec<RawMessage>,
    encrypted: bool,
}

enum Out {
    Frame(Vec<u8>),
    Close,
}

/// The test-controlled server end of one connection.
struct Server {
    rx: mpsc::UnboundedReceiver<Incoming>,
    tx: mpsc::UnboundedSender<Out>,
    signer: Option<Signer>,
    encryptor: Option<SmbCipher>,
}

impl Server {
    /// Wait for the next request frame.
    async fn next(&mut self) -> Incoming {
        tokio::time::timeout(Duration::from_secs(10), self.rx.recv())
            .await
            .expect("timed out waiting for a request")
            .expect("client connection closed")
    }

    /// Write `msgs` as one frame (signed and/or encrypted as asked).
    fn send(&self, mut msgs: Vec<EncodedMessage>, sign: bool, encrypt: bool) {
        if sign {
            for m in &mut msgs {
                self.signer.as_ref().unwrap().sign(m).unwrap();
            }
        }
        let wire = if encrypt {
            let sid = msgs[0].header().session_id;
            let b = self
                .encryptor
                .as_ref()
                .unwrap()
                .encrypt_messages(sid, &msgs)
                .unwrap();
            OutgoingFrame::from_bytes(b.freeze()).unwrap().to_vec()
        } else {
            OutgoingFrame::from_messages(msgs).unwrap().to_vec()
        };
        let _ = self.tx.send(Out::Frame(wire));
    }

    fn close(&self) {
        let _ = self.tx.send(Out::Close);
    }
}

/// A response header for `req`.
fn resp(req: &Header, status: NtStatus, credits: u16) -> Header {
    let mut h = Header::response_to(req, status);
    h.credits = credits;
    h
}

fn echo_resp(req: &Header, credits: u16) -> EncodedMessage {
    encode_message(&resp(req, NtStatus::SUCCESS, credits), &EchoResponse).unwrap()
}

/// Start a fake server and a client connection to it.
async fn pair(
    keys: Option<&SessionKeys>,
    request_timeout: Option<Duration>,
    keepalive: Option<Duration>,
) -> (Connection, Server) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (in_tx, in_rx) = mpsc::unbounded_channel();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<Out>();
    let server_keys = keys.map(SessionKeys::server_view);
    let decryptor = server_keys.as_ref().and_then(|k| {
        k.decryption_key
            .as_ref()
            .map(|dk| SmbCipher::new(Cipher::Aes128Gcm, dk).unwrap())
    });
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (mut rd, mut wr) = sock.into_split();
        tokio::spawn(async move {
            while let Some(o) = out_rx.recv().await {
                match o {
                    Out::Frame(f) => {
                        if wr.write_all(&f).await.is_err() {
                            return;
                        }
                    }
                    Out::Close => {
                        let _ = wr.shutdown().await;
                        return;
                    }
                }
            }
        });
        let mut buf = BytesMut::new();
        let mut dec = FrameDecoder::new();
        loop {
            while let Ok(Some(frame)) = dec.decode(&mut buf) {
                let (plain, encrypted) = if frame.starts_with(&TRANSFORM_PROTOCOL_ID) {
                    let (_, p) = decryptor.as_ref().unwrap().decrypt_in_place(frame).unwrap();
                    (p.freeze(), true)
                } else {
                    (frame.freeze(), false)
                };
                let msgs = split_compound(plain).map(|m| m.unwrap()).collect();
                if in_tx.send(Incoming { msgs, encrypted }).is_err() {
                    return;
                }
            }
            match rd.read_buf(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {}
            }
        }
    });
    let stream = TcpStream::connect(addr).await.unwrap();
    let conn = Connection::start(stream, addr.to_string(), 512, request_timeout, keepalive);
    conn.set_negotiated(Negotiated {
        dialect: Dialect::SMB_3_1_1,
        max_read_size: 8 << 20,
        max_write_size: 8 << 20,
        max_transact_size: 8 << 20,
        server_guid: Guid::default(),
        server_security_mode: SecurityMode::SIGNING_ENABLED,
        server_capabilities: fsfast_smb_proto::Capabilities::LARGE_MTU,
        client_guid: Guid::default(),
        client_security_mode: SecurityMode::SIGNING_ENABLED,
        client_capabilities: fsfast_smb_proto::Capabilities::LARGE_MTU,
        offered_dialects: vec![Dialect::SMB_3_1_1],
        cipher: Some(Cipher::Aes128Gcm),
        signing_algorithm: None,
        security_buffer: Bytes::new(),
    });
    let signer = server_keys
        .as_ref()
        .map(|k| Signer::new(SigningAlgorithm::AesGmac, &k.signing_key[..]).unwrap());
    let encryptor = server_keys.as_ref().and_then(|k| {
        k.encryption_key
            .as_ref()
            .map(|ek| SmbCipher::new(Cipher::Aes128Gcm, ek).unwrap())
    });
    (
        conn,
        Server {
            rx: in_rx,
            tx: out_tx,
            signer,
            encryptor,
        },
    )
}

fn echo_msg(charge: u16) -> EncodedMessage {
    let mut h = Header::request(Command::ECHO);
    h.credit_charge = charge;
    encode_message(&h, &EchoRequest).unwrap()
}

fn read_msg(session_id: u64, offset: u64, len: u32) -> EncodedMessage {
    let r = ReadRequest {
        length: len,
        offset,
        file_id: FileId::new(1, 2),
        ..Default::default()
    };
    let h = crate::session::header_for(&r, session_id, 7, true);
    encode_message(&h, &r).unwrap()
}

/// Test keys for a 3.1.1 session with AES-128-GCM.
fn keys() -> SessionKeys {
    derive_session_keys(
        Dialect::SMB_3_1_1,
        &[0x11; 16],
        Some(&[0x22; 64]),
        Some(Cipher::Aes128Gcm),
    )
    .unwrap()
}

fn crypto(k: &SessionKeys, signing: bool, encrypt_all: bool) -> Arc<SessionCrypto> {
    Arc::new(SessionCrypto {
        session_id: 0x55,
        signer: Some(Signer::new(SigningAlgorithm::AesGmac, &k.signing_key[..]).unwrap()),
        signing,
        encryptor: Some(
            SmbCipher::new(Cipher::Aes128Gcm, k.encryption_key.as_ref().unwrap()).unwrap(),
        ),
        decryptor: Some(
            SmbCipher::new(Cipher::Aes128Gcm, k.decryption_key.as_ref().unwrap()).unwrap(),
        ),
        encrypt_all,
        peek: crate::peek::Peek::new(Cipher::Aes128Gcm, k.decryption_key.as_ref().unwrap()),
    })
}

/// Grant the initial credits: answer the first request with `credits`.
async fn handshake(conn: &Connection, server: &mut Server, credits: u16) {
    let shared = conn.shared.clone();
    let t = tokio::spawn(async move {
        let r = shared
            .send(vec![echo_msg(1)], &Security::none())
            .await
            .unwrap();
        recv_all(r).await.unwrap();
    });
    let inc = server.next().await;
    assert_eq!(inc.msgs[0].header().message_id, 0);
    server.send(vec![echo_resp(inc.msgs[0].header(), credits)], false, false);
    t.await.unwrap();
}

#[tokio::test]
async fn message_ids_stay_inside_the_granted_window() {
    let (conn, mut server) = pair(None, None, None).await;
    handshake(&conn, &mut server, 8).await;
    assert_eq!(conn.shared.credits.available(), 8);
    // 40 concurrent requests charging 1..=3 credits with only 8 credits:
    // callers must wait for returned credits, never exceeding the window.
    let mut tasks = Vec::new();
    for i in 0..40u16 {
        let shared = conn.shared.clone();
        tasks.push(tokio::spawn(async move {
            let r = shared
                .send(vec![echo_msg(i % 3 + 1)], &Security::none())
                .await
                .unwrap();
            recv_all(r).await.unwrap()
        }));
    }
    // Server: track the window like Samba's bitmap ([low, low + granted)).
    let mut granted_upto: u64 = 1 + 8; // mid 0 consumed, 8 granted
    let mut used = std::collections::BTreeSet::new();
    let mut outstanding = Vec::new();
    let mut served = 0;
    while served < 40 {
        // Collect what is in flight, then answer the oldest, granting back
        // exactly its charge (a server that keeps the window constant).
        while let Ok(Some(inc)) =
            tokio::time::timeout(Duration::from_millis(20), server.rx.recv()).await
        {
            for m in inc.msgs {
                let h = *m.header();
                let charge = u64::from(h.credit_charge.max(1));
                for id in h.message_id..h.message_id + charge {
                    assert!(
                        id < granted_upto,
                        "MessageId {id} beyond window {granted_upto}"
                    );
                    assert!(used.insert(id), "MessageId {id} reused");
                }
                assert!(
                    h.credits >= h.credit_charge,
                    "CreditRequest below the charge"
                );
                outstanding.push(h);
            }
        }
        let h = outstanding.remove(0);
        let charge = h.credit_charge.max(1);
        granted_upto += u64::from(charge);
        server.send(vec![echo_resp(&h, charge)], false, false);
        served += 1;
    }
    for t in tasks {
        t.await.unwrap();
    }
    assert_eq!(conn.shared.credits.available(), 8);
    assert_eq!(conn.shared.credits.outstanding(), 0);
}

#[tokio::test]
async fn out_of_order_and_compound_responses_reach_their_callers() {
    let (conn, mut server) = pair(None, None, None).await;
    handshake(&conn, &mut server, 64).await;
    let mut tasks = Vec::new();
    for i in 0..5u64 {
        let shared = conn.shared.clone();
        tasks.push(tokio::spawn(async move {
            let r = shared
                .send(vec![read_msg(0, i * 1000, 100_000)], &Security::none())
                .await
                .unwrap();
            let raw = recv_all(r).await.unwrap().remove(0);
            let rd: ReadResponse = raw.decode().unwrap();
            (i, rd.data)
        }));
    }
    let mut reqs = Vec::new();
    for _ in 0..5 {
        let inc = server.next().await;
        let h = *inc.msgs[0].header();
        assert_eq!(h.credit_charge, 2, "100000 bytes charge 2 credits");
        let r: ReadRequest = inc.msgs[0].decode().unwrap();
        reqs.push((h, r.offset));
    }
    // Answer in reverse order, the last two in one compound frame.
    reqs.reverse();
    let body = |off: u64| ReadResponse {
        data: Bytes::from(off.to_le_bytes().to_vec()),
        ..Default::default()
    };
    for (h, off) in &reqs[..3] {
        let m = encode_message(&resp(h, NtStatus::SUCCESS, 2), &body(*off)).unwrap();
        server.send(vec![m], false, false);
    }
    let mut chain = CompoundBuilder::new();
    for (h, off) in &reqs[3..] {
        chain.push_encoded(encode_message(&resp(h, NtStatus::SUCCESS, 2), &body(*off)).unwrap());
    }
    server.send(chain.finish(), false, false);
    for t in tasks {
        let (i, data) = t.await.unwrap();
        assert_eq!(&data[..], &(i * 1000).to_le_bytes());
    }
}

#[tokio::test]
async fn interim_responses_wait_for_the_final_one_and_return_credits_once() {
    let (conn, mut server) = pair(None, None, None).await;
    handshake(&conn, &mut server, 10).await;
    let shared = conn.shared.clone();
    let t = tokio::spawn(async move {
        let r = shared
            .send(vec![echo_msg(1)], &Security::none())
            .await
            .unwrap();
        recv_all(r).await.unwrap().remove(0)
    });
    let inc = server.next().await;
    let req = *inc.msgs[0].header();
    // Interim STATUS_PENDING with an AsyncId, granting the credit back.
    let mut ih = resp(&req, NtStatus::PENDING, 1);
    ih.id = HeaderId::Async { async_id: 77 };
    server.send(
        vec![encode_error_message(&ih, &ErrorResponse::default()).unwrap()],
        false,
        false,
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !t.is_finished(),
        "an interim response must not complete the request"
    );
    assert_eq!(conn.shared.credits.available(), 10);
    let mut fh = resp(&req, NtStatus::SUCCESS, 0);
    fh.id = HeaderId::Async { async_id: 77 };
    server.send(
        vec![encode_message(&fh, &EchoResponse).unwrap()],
        false,
        false,
    );
    let raw = t.await.unwrap();
    assert_eq!(raw.status(), NtStatus::SUCCESS);
    assert_eq!(conn.shared.credits.available(), 10);
    assert_eq!(conn.shared.credits.outstanding(), 0);
}

#[tokio::test]
async fn dropped_callers_do_not_corrupt_the_connection_and_async_ones_are_cancelled() {
    let (conn, mut server) = pair(None, None, None).await;
    handshake(&conn, &mut server, 10).await;
    // A sync request whose caller goes away before the response.
    let r = conn
        .shared
        .send(vec![echo_msg(1)], &Security::none())
        .await
        .unwrap();
    let inc = server.next().await;
    drop(r);
    server.send(vec![echo_resp(inc.msgs[0].header(), 1)], false, false);
    // An async request whose caller goes away after the interim response.
    let r = conn
        .shared
        .send(vec![echo_msg(1)], &Security::none())
        .await
        .unwrap();
    let inc = server.next().await;
    let req = *inc.msgs[0].header();
    let mut ih = resp(&req, NtStatus::PENDING, 1);
    ih.id = HeaderId::Async { async_id: 99 };
    server.send(
        vec![encode_error_message(&ih, &ErrorResponse::default()).unwrap()],
        false,
        false,
    );
    tokio::time::sleep(Duration::from_millis(50)).await;
    drop(r);
    let cancel = server.next().await;
    let ch = cancel.msgs[0].header();
    assert_eq!(ch.command, Command::CANCEL);
    assert_eq!(ch.async_id(), Some(99));
    assert_eq!(ch.message_id, req.message_id);
    assert!(ch.flags.contains(HeaderFlags::ASYNC_COMMAND));
    // The server finishes the cancelled request; nobody is waiting for it.
    let mut fh = resp(&req, NtStatus::CANCELLED, 0);
    fh.id = HeaderId::Async { async_id: 99 };
    server.send(
        vec![encode_error_message(&fh, &ErrorResponse::default()).unwrap()],
        false,
        false,
    );
    // The connection still works and no credit was lost.
    let shared = conn.shared.clone();
    let t = tokio::spawn(async move {
        let r = shared
            .send(vec![echo_msg(1)], &Security::none())
            .await
            .unwrap();
        recv_all(r).await.unwrap()
    });
    let inc = server.next().await;
    server.send(vec![echo_resp(inc.msgs[0].header(), 1)], false, false);
    t.await.unwrap();
    assert!(!conn.is_dead());
    assert_eq!(conn.shared.credits.window(), 10);
}

#[tokio::test]
async fn connection_loss_fails_everything_in_flight() {
    let (conn, mut server) = pair(None, None, None).await;
    handshake(&conn, &mut server, 10).await;
    let mut tasks = Vec::new();
    for _ in 0..3 {
        let shared = conn.shared.clone();
        tasks.push(tokio::spawn(async move {
            let r = shared
                .send(vec![echo_msg(1)], &Security::none())
                .await
                .unwrap();
            recv_all(r).await
        }));
    }
    for _ in 0..3 {
        server.next().await;
    }
    server.close();
    for t in tasks {
        let e = t.await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::ConnectionFailed, "{e}");
    }
    assert!(conn.is_dead());
    let e = conn
        .shared
        .send(vec![echo_msg(1)], &Security::none())
        .await
        .unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
    assert!(
        was_not_sent(&e),
        "a request on a dead connection is never sent"
    );
}

#[tokio::test]
async fn signed_requests_and_verified_responses() {
    let k = keys();
    let (conn, mut server) = pair(Some(&k), None, None).await;
    handshake(&conn, &mut server, 10).await;
    let c = crypto(&k, true, false);
    conn.set_crypto(Some(c.clone()));
    let sec = Security {
        session: Some(c.clone()),
        encrypt: false,
        force_sign: false,
    };
    let server_signer = server.signer.clone().unwrap();
    // Good signature both ways.
    let shared = conn.shared.clone();
    let s2 = sec.clone();
    let t = tokio::spawn(async move {
        let r = shared.send(vec![read_msg(0x55, 0, 10)], &s2).await.unwrap();
        recv_all(r).await
    });
    let inc = server.next().await;
    let m = &inc.msgs[0];
    assert!(m.header().is_signed());
    server_signer.verify(m.bytes()).expect("client signature");
    let body = ReadResponse {
        data: Bytes::from_static(b"0123456789"),
        ..Default::default()
    };
    let rm = encode_message(&resp(m.header(), NtStatus::SUCCESS, 1), &body).unwrap();
    server.send(vec![rm], true, false);
    let raw = t.await.unwrap().unwrap().remove(0);
    let rd: ReadResponse = raw.decode().unwrap();
    assert_eq!(&rd.data[..], b"0123456789");

    // An unsigned response on a signing session is rejected and kills the
    // connection.
    let shared = conn.shared.clone();
    let s2 = sec.clone();
    let t = tokio::spawn(async move {
        let r = shared.send(vec![read_msg(0x55, 0, 10)], &s2).await.unwrap();
        recv_all(r).await
    });
    let inc = server.next().await;
    let rm = encode_message(&resp(inc.msgs[0].header(), NtStatus::SUCCESS, 1), &body).unwrap();
    server.send(vec![rm], false, false);
    let e = t.await.unwrap().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol, "{e}");
    assert!(!e.is_retryable());
    assert!(conn.is_dead());
}

#[tokio::test]
async fn tampered_signature_is_detected() {
    let k = keys();
    let (conn, mut server) = pair(Some(&k), None, None).await;
    handshake(&conn, &mut server, 10).await;
    let c = crypto(&k, true, false);
    conn.set_crypto(Some(c.clone()));
    let sec = Security {
        session: Some(c),
        encrypt: false,
        force_sign: false,
    };
    let shared = conn.shared.clone();
    let t = tokio::spawn(async move {
        let r = shared.send(vec![read_msg(0x55, 0, 4)], &sec).await.unwrap();
        recv_all(r).await
    });
    let inc = server.next().await;
    let body = ReadResponse {
        data: Bytes::from_static(b"good"),
        ..Default::default()
    };
    let mut rm = encode_message(&resp(inc.msgs[0].header(), NtStatus::SUCCESS, 1), &body).unwrap();
    server.signer.as_ref().unwrap().sign(&mut rm).unwrap();
    // Flip a payload byte after signing.
    let mut wire = OutgoingFrame::from_messages([rm]).unwrap().to_vec();
    let last = wire.len() - 1;
    wire[last] ^= 1;
    let _ = server.tx.send(Out::Frame(wire));
    let e = t.await.unwrap().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Protocol);
    assert!(conn.is_dead());
}

#[tokio::test]
async fn encrypted_requests_and_responses() {
    let k = keys();
    let (conn, mut server) = pair(Some(&k), None, None).await;
    handshake(&conn, &mut server, 10).await;
    let c = crypto(&k, true, true);
    conn.set_crypto(Some(c.clone()));
    let sec = Security {
        session: Some(c),
        encrypt: true,
        force_sign: false,
    };
    for round in 0..2 {
        let shared = conn.shared.clone();
        let s2 = sec.clone();
        let t = tokio::spawn(async move {
            let r = shared
                .send(vec![read_msg(0x55, 0, 300_000)], &s2)
                .await
                .unwrap();
            recv_all(r).await
        });
        let inc = server.next().await;
        assert!(inc.encrypted, "the request must travel encrypted");
        assert!(
            !inc.msgs[0].header().is_signed(),
            "encrypted requests are not signed"
        );
        let body = ReadResponse {
            data: Bytes::from(vec![7u8; 300_000]),
            ..Default::default()
        };
        let mut h = resp(inc.msgs[0].header(), NtStatus::SUCCESS, 5);
        h.session_id = 0x55;
        let rm = encode_message(&h, &body).unwrap();
        if round == 0 {
            server.send(vec![rm], false, true);
            let raw = t.await.unwrap().unwrap().remove(0);
            let rd: ReadResponse = raw.decode().unwrap();
            assert_eq!(rd.data.len(), 300_000);
        } else {
            // A plain response to an encrypted request is refused.
            server.send(vec![rm], false, false);
            let e = t.await.unwrap().unwrap_err();
            assert_eq!(e.kind(), ErrorKind::Protocol, "{e}");
            assert!(conn.is_dead());
        }
    }
}

#[tokio::test]
async fn request_timeout_fails_and_kills_a_silent_connection() {
    let (conn, mut server) = pair(None, Some(Duration::from_millis(200)), None).await;
    let r = conn
        .shared
        .send(vec![echo_msg(1)], &Security::none())
        .await
        .unwrap();
    let _ = server.next().await;
    let e = recv_all(r).await.unwrap_err();
    assert_eq!(e.kind(), ErrorKind::Timeout);
    assert!(conn.is_dead());
}

#[tokio::test]
async fn keepalive_probes_and_detects_a_dead_peer() {
    let (conn, mut server) = pair(None, None, Some(Duration::from_millis(200))).await;
    handshake(&conn, &mut server, 10).await;
    // The first probe is answered...
    let probe = server.next().await;
    assert_eq!(probe.msgs[0].header().command, Command::ECHO);
    server.send(vec![echo_resp(probe.msgs[0].header(), 1)], false, false);
    // ...the second is not: the connection is declared dead.
    let probe = server.next().await;
    assert_eq!(probe.msgs[0].header().command, Command::ECHO);
    tokio::time::timeout(Duration::from_secs(5), async {
        while !conn.is_dead() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("connection not declared dead");
}

#[tokio::test]
async fn impossible_frames_kill_the_connection() {
    let (conn, mut server) = pair(None, None, None).await;
    let shared = conn.shared.clone();
    let t = tokio::spawn(async move {
        let r = shared
            .send(vec![echo_msg(1)], &Security::none())
            .await
            .unwrap();
        recv_all(r).await
    });
    let _ = server.next().await;
    // A request (not a response) from the server.
    let m = echo_msg(1);
    let _ = server.tx.send(Out::Frame(
        OutgoingFrame::from_messages([m]).unwrap().to_vec(),
    ));
    let e = t.await.unwrap().unwrap_err();
    assert_eq!(e.kind(), ErrorKind::ConnectionFailed);
    assert!(conn.is_dead());
}

#[test]
fn compound_chains_are_related_padded_and_charged() {
    // The fs layer's chain helper: first unrelated, the rest related with
    // FileId::RELATED, 8-byte aligned, charges from the bodies.
    let mut b = CompoundBuilder::new();
    let r = ReadRequest {
        length: 3 << 20,
        file_id: FileId::RELATED,
        ..Default::default()
    };
    let h = crate::session::header_for(&EchoRequest, 1, 2, true);
    b.push(h, &EchoRequest).unwrap();
    let h = crate::session::header_for(&r, 1, 2, true);
    assert_eq!(h.credit_charge, 48);
    b.push_related(h, &r).unwrap();
    let msgs = b.finish();
    assert_eq!(msgs[0].len() % 8, 0);
    assert!(
        !msgs[0]
            .header()
            .flags
            .contains(HeaderFlags::RELATED_OPERATIONS)
    );
    assert!(
        msgs[1]
            .header()
            .flags
            .contains(HeaderFlags::RELATED_OPERATIONS)
    );
    assert_eq!(msgs[0].header().next_command as usize, msgs[0].len());
    assert_eq!(msgs[1].header().next_command, 0);
    assert_eq!(r.credit_charge(), 48);
    // 2.0.2 sends CreditCharge 0.
    assert_eq!(crate::session::header_for(&r, 1, 2, false).credit_charge, 0);
}

/// Send a READ with a destination buffer of `cap` bytes and return the
/// task waiting for its reply.
fn spawn_read_into(
    conn: &Connection,
    sec: Security,
    len: u32,
    cap: usize,
) -> tokio::task::JoinHandle<fsfast_core::Result<(Vec<u8>, bool)>> {
    let shared = conn.shared.clone();
    tokio::spawn(async move {
        let dest = BytesMut::zeroed(cap);
        let r = shared.send_read(read_msg(0x55, 0, len), &sec, dest).await?;
        Ok(match r.recv_read().await? {
            crate::conn::ReadReply::Direct { dest, len } => (dest[..len].to_vec(), true),
            crate::conn::ReadReply::Message { msg, dest } => {
                assert!(dest.len() >= len as usize, "destination handed back");
                if msg.is_error_response() {
                    return Err(msg.status().to_error(None));
                }
                let rd: ReadResponse = msg.decode().unwrap();
                (rd.data.to_vec(), false)
            }
        })
    })
}

#[tokio::test]
async fn large_reads_land_directly_in_the_callers_buffer() {
    let k = keys();
    for (sign, encrypt) in [(true, false), (false, false), (false, true)] {
        let (conn, mut server) = pair(Some(&k), None, None).await;
        handshake(&conn, &mut server, 64).await;
        let c = crypto(&k, sign, encrypt);
        conn.set_crypto(Some(c.clone()));
        let sec = Security {
            session: Some(c),
            encrypt,
            force_sign: false,
        };
        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        // Large: received directly (plain) or decrypted directly (sealed).
        let t = spawn_read_into(&conn, sec.clone(), 300_000, 300_000);
        let inc = server.next().await;
        let mut h = resp(inc.msgs[0].header(), NtStatus::SUCCESS, 5);
        h.session_id = 0x55;
        let body = ReadResponse {
            data: Bytes::from(payload.clone()),
            ..Default::default()
        };
        server.send(vec![encode_message(&h, &body).unwrap()], sign, encrypt);
        let (data, direct) = t.await.unwrap().unwrap();
        assert!(
            direct,
            "sign={sign} encrypt={encrypt}: not received directly"
        );
        assert_eq!(data, payload);
        assert_eq!(
            conn.shared
                .direct_reads
                .load(std::sync::atomic::Ordering::Relaxed),
            1,
            "plain READs are received, sealed ones decrypted, straight into the buffer"
        );
        // Small: regular path, destination handed back untouched.
        let t = spawn_read_into(&conn, sec.clone(), 100, 4096);
        let inc = server.next().await;
        let mut h = resp(inc.msgs[0].header(), NtStatus::SUCCESS, 1);
        h.session_id = 0x55;
        let small = ReadResponse {
            data: Bytes::from_static(b"small"),
            ..Default::default()
        };
        server.send(vec![encode_message(&h, &small).unwrap()], sign, encrypt);
        let (data, direct) = t.await.unwrap().unwrap();
        assert!(!direct);
        assert_eq!(&data[..], b"small");
        // Errors take the regular path too.
        let t = spawn_read_into(&conn, sec.clone(), 300_000, 300_000);
        let inc = server.next().await;
        let mut h = resp(inc.msgs[0].header(), NtStatus::END_OF_FILE, 1);
        h.session_id = 0x55;
        server.send(
            vec![encode_error_message(&h, &ErrorResponse::default()).unwrap()],
            sign,
            encrypt,
        );
        let shared = conn.shared.clone();
        let e = t.await.unwrap().unwrap_err();
        assert_eq!(
            e.kind(),
            ErrorKind::Io,
            "END_OF_FILE arrives as a regular message"
        );
        assert!(!shared.is_dead());
        assert_eq!(shared.credits.outstanding(), 0);
    }
}

#[tokio::test]
async fn tampered_direct_reads_are_rejected() {
    let k = keys();
    for encrypt in [false, true] {
        let (conn, mut server) = pair(Some(&k), None, None).await;
        handshake(&conn, &mut server, 64).await;
        let c = crypto(&k, true, encrypt);
        conn.set_crypto(Some(c.clone()));
        let sec = Security {
            session: Some(c),
            encrypt,
            force_sign: false,
        };
        let t = spawn_read_into(&conn, sec, 200_000, 200_000);
        let inc = server.next().await;
        let mut h = resp(inc.msgs[0].header(), NtStatus::SUCCESS, 5);
        h.session_id = 0x55;
        let body = ReadResponse {
            data: Bytes::from(vec![1u8; 200_000]),
            ..Default::default()
        };
        let mut m = encode_message(&h, &body).unwrap();
        let wire = if encrypt {
            let b = server
                .encryptor
                .as_ref()
                .unwrap()
                .encrypt_messages(0x55, &[m])
                .unwrap();
            OutgoingFrame::from_bytes(b.freeze()).unwrap().to_vec()
        } else {
            server.signer.as_ref().unwrap().sign(&mut m).unwrap();
            OutgoingFrame::from_messages([m]).unwrap().to_vec()
        };
        let mut wire = wire;
        let n = wire.len();
        wire[n - 10] ^= 0x40; // inside the data
        let _ = server.tx.send(Out::Frame(wire));
        let e = t.await.unwrap().unwrap_err();
        assert_eq!(e.kind(), ErrorKind::Protocol, "encrypt={encrypt}: {e}");
        assert!(conn.is_dead());
    }
}
