//! Live tests against the local Samba (both shares). Gated on
//! `FSFAST_TEST_SMB_HOST`.

mod common;

use bytes::Bytes;
use fsfast_core::{ByteRange, FileSystem, WriteOptions};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn smoke_both_shares() {
    let Some(env) = common::env() else { return };
    for share in [env.share.clone(), env.enc_share.clone()] {
        let fs = env.fs(&[]);
        let root = format!("/{share}/{}", common::unique("smoke"));
        let i = fs.info(&format!("/{share}")).await.expect("info share root");
        assert!(i.is_dir(), "{i:?}");
        fs.mkdir(&root, false).await.expect("mkdir");
        let f = format!("{root}/hello.txt");
        fs.pipe_file(&f, Bytes::from_static(b"hello world"), &WriteOptions::default())
            .await
            .expect("pipe");
        let got = fs.cat_file(&f, ByteRange::Full).await.expect("cat");
        assert_eq!(&got[..], b"hello world");
        let ls = fs.ls(&root).await.expect("ls");
        assert_eq!(ls.len(), 1);
        assert_eq!(ls[0].name, f);
        assert_eq!(ls[0].size, 11);
        fs.rm_file(&f).await.expect("rm");
        fs.rmdir(&root).await.expect("rmdir");
        assert!(!fs.exists(&root).await.unwrap());
        fs.close().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn negotiates_3_1_1_with_gmac_and_gcm() {
    let Some(env) = common::env() else { return };
    let fs = env.fs(&[]);
    let i = fs.connection_info(&env.share).await.unwrap();
    eprintln!("{i:?}");
    assert_eq!(i.dialect, "3.1.1");
    assert!(i.signing, "signing is required by the server and by default");
    assert_eq!(i.signing_algorithm.as_deref(), Some("AES-GMAC"));
    assert_eq!(i.cipher.as_deref(), Some("AES-128-GCM"));
    assert!(!i.share_encrypted);
    let e = fs.connection_info(&env.enc_share).await.unwrap();
    assert!(e.share_encrypted && !e.encrypt_all, "{e:?}");
    assert!(i.credit_window >= 64, "credit window did not grow: {}", i.credit_window);
    fs.close().await.unwrap();
}
