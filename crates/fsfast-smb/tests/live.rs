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
