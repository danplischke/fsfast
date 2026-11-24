//! Per-check context and assertion helpers.

use std::fmt::{self, Debug, Display};
use std::sync::Arc;

use bytes::Bytes;
use fsfast_core::{
    ByteRange, Capabilities, ErrorKind, FileSystem, IoHints, Result, WriteOptions, path,
};

use crate::SuiteConfig;
use crate::pattern;

/// Why a check did not pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CheckError {
    /// An expectation was violated; the message explains which and how.
    Failed(String),
    /// The check does not apply to this backend (capability missing).
    Skipped(String),
}

pub(crate) type CheckResult = std::result::Result<(), CheckError>;

/// Attach "what was being done" to backend errors.
pub(crate) trait Context<T> {
    fn ctx(self, what: impl Display) -> std::result::Result<T, CheckError>;
}

impl<T> Context<T> for Result<T> {
    fn ctx(self, what: impl Display) -> std::result::Result<T, CheckError> {
        self.map_err(|e| CheckError::Failed(format!("{what} failed: {e} [kind: {:?}]", e.kind())))
    }
}

/// Everything a check needs. Each check runs in its own directory
/// (`dir`), created up front on hierarchical backends and removed afterwards.
pub(crate) struct Ctx {
    pub fs: Arc<dyn FileSystem>,
    pub dir: String,
    pub cfg: Arc<SuiteConfig>,
    pub caps: Capabilities,
    pub hints: IoHints,
}

impl Ctx {
    /// `dir/rel`.
    pub fn path(&self, rel: &str) -> String {
        path::join(&self.dir, rel)
    }

    /// Deterministic content for `p` (seeded by the path).
    pub fn pattern(&self, p: &str, len: usize) -> Bytes {
        pattern::generate_bytes(pattern::seed_for(p), 0, len)
    }

    /// Create directory `d` (and parents) on hierarchical backends. On
    /// emulated-directory backends directories exist implicitly, so this is a
    /// no-op.
    pub async fn ensure_dir(&self, d: &str) -> CheckResult {
        if self.caps.hierarchical {
            self.fs
                .makedirs(d, true)
                .await
                .ctx(format_args!("makedirs({d:?}, exist_ok=true)"))?;
        }
        Ok(())
    }

    /// Make sure the parent directory of `p` exists (hierarchical backends).
    pub async fn ensure_parent(&self, p: &str) -> CheckResult {
        let parent = path::parent(p);
        if parent.is_empty() || parent == self.dir {
            return Ok(());
        }
        self.ensure_dir(&parent).await
    }

    /// Write `data` to `p` with `pipe_file`, creating parents as needed.
    pub async fn put(&self, p: &str, data: impl Into<Bytes>) -> CheckResult {
        self.ensure_parent(p).await?;
        self.fs
            .pipe_file(p, data.into(), &WriteOptions::default())
            .await
            .ctx(format_args!("pipe_file({p:?})"))
    }

    /// Assert that `cat_file(p)` returns exactly `expected`.
    pub async fn expect_content(&self, p: &str, expected: &[u8]) -> CheckResult {
        let got = self
            .fs
            .cat_file(p, ByteRange::Full)
            .await
            .ctx(format_args!("cat_file({p:?})"))?;
        compare_bytes(&format!("cat_file({p:?})"), 0, expected, &got)
    }

    /// Assert that `p` does not exist (`exists` is false and `info` fails
    /// with `NotFound`).
    pub async fn expect_missing(&self, p: &str) -> CheckResult {
        let exists = self
            .fs
            .exists(p)
            .await
            .ctx(format_args!("exists({p:?})"))?;
        ensure!(!exists, "exists({p:?}) returned true, expected the path to be gone");
        expect_err(
            format!("info({p:?})"),
            self.fs.info(p).await,
            &[ErrorKind::NotFound],
        )
    }

    /// Assert that `p` exists and is a file of `size` bytes.
    pub async fn expect_file(&self, p: &str, size: u64) -> CheckResult {
        let info = self.fs.info(p).await.ctx(format_args!("info({p:?})"))?;
        ensure!(
            info.is_file(),
            "info({p:?}): expected a file, got type {:?}",
            info.file_type
        );
        ensure_eq!(info.size, size, "info({p:?}).size");
        Ok(())
    }

    /// Assert that `p` exists and is a directory.
    pub async fn expect_dir(&self, p: &str) -> CheckResult {
        let info = self.fs.info(p).await.ctx(format_args!("info({p:?})"))?;
        ensure!(
            info.is_dir(),
            "info({p:?}): expected a directory, got type {:?}",
            info.file_type
        );
        Ok(())
    }
}

/// Debug-format `v`, truncated so huge buffers do not flood the report.
pub(crate) fn short_debug(v: &impl Debug) -> String {
    const MAX: usize = 160;
    let s = format!("{v:?}");
    if s.len() <= MAX {
        return s;
    }
    let mut end = MAX;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}... ({} chars)", &s[..end], s.len())
}

/// Assert that `r` failed with one of `kinds`.
pub(crate) fn expect_err<T: Debug>(
    what: impl Display,
    r: Result<T>,
    kinds: &[ErrorKind],
) -> CheckResult {
    match r {
        Ok(v) => fail!(
            "{what}: expected an error of kind {}, but it succeeded with {}",
            KindList(kinds),
            short_debug(&v)
        ),
        Err(e) if kinds.contains(&e.kind()) => Ok(()),
        Err(e) => fail!(
            "{what}: expected an error of kind {}, got {:?}: {e}",
            KindList(kinds),
            e.kind()
        ),
    }
}

struct KindList<'a>(&'a [ErrorKind]);

impl Display for KindList<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, k) in self.0.iter().enumerate() {
            if i > 0 {
                f.write_str(" or ")?;
            }
            write!(f, "{k:?}")?;
        }
        Ok(())
    }
}

fn hex_window(data: &[u8], at: usize) -> String {
    let start = at.saturating_sub(4);
    let end = (at + 8).min(data.len());
    let mut s = String::new();
    for (i, b) in data[start..end].iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        if start + i == at {
            s.push('[');
        }
        s.push_str(&format!("{b:02x}"));
        if start + i == at {
            s.push(']');
        }
    }
    s
}

/// Compare `actual` with `expected`. `base` is the absolute file offset of
/// `expected[0]`, so mismatches are reported as file offsets.
pub(crate) fn compare_bytes(what: &str, base: u64, expected: &[u8], actual: &[u8]) -> CheckResult {
    if expected == actual {
        return Ok(());
    }
    let mut msg = format!(
        "{what}: data mismatch: expected {} bytes, got {} bytes",
        expected.len(),
        actual.len()
    );
    match pattern::first_difference(expected, actual) {
        Some(i) => msg.push_str(&format!(
            "; first mismatch at file offset {} (expected {}, got {})",
            base + i as u64,
            hex_window(expected, i),
            hex_window(actual, i)
        )),
        None => msg.push_str(&format!(
            "; the first {} bytes agree",
            expected.len().min(actual.len())
        )),
    }
    Err(CheckError::Failed(msg))
}

/// Verify `actual` against the pattern `seed` starting at file offset
/// `offset`, expecting `expected_len` bytes.
pub(crate) fn verify_pattern(
    what: &str,
    seed: u64,
    offset: u64,
    expected_len: usize,
    actual: &[u8],
) -> CheckResult {
    let common = expected_len.min(actual.len());
    let mismatch = pattern::first_mismatch(seed, offset, &actual[..common]);
    if actual.len() == expected_len && mismatch.is_none() {
        return Ok(());
    }
    let mut msg = format!(
        "{what}: data mismatch: expected {expected_len} bytes at file offset {offset}, got {} bytes",
        actual.len()
    );
    match mismatch {
        Some(at) => {
            let i = (at - offset) as usize;
            let expected = pattern::generate(seed, offset, common);
            msg.push_str(&format!(
                "; first mismatch at file offset {at} (expected {}, got {})",
                hex_window(&expected, i),
                hex_window(actual, i)
            ));
        }
        None => msg.push_str(&format!("; the first {common} bytes agree")),
    }
    Err(CheckError::Failed(msg))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compare_reports_offset_and_lengths() {
        let e = compare_bytes("x", 100, b"abcdef", b"abXdef").unwrap_err();
        let CheckError::Failed(m) = e else { panic!() };
        assert!(m.contains("file offset 102"), "{m}");
        let e = compare_bytes("x", 0, b"abc", b"ab").unwrap_err();
        let CheckError::Failed(m) = e else { panic!() };
        assert!(m.contains("expected 3 bytes, got 2 bytes"), "{m}");
        assert!(compare_bytes("x", 0, b"same", b"same").is_ok());
    }

    #[test]
    fn verify_pattern_reports_absolute_offset() {
        let seed = 9;
        let mut data = pattern::generate(seed, 5000, 10_000);
        assert!(verify_pattern("r", seed, 5000, 10_000, &data).is_ok());
        data[1234] ^= 1;
        let CheckError::Failed(m) = verify_pattern("r", seed, 5000, 10_000, &data).unwrap_err()
        else {
            panic!()
        };
        assert!(m.contains("file offset 6234"), "{m}");
        let CheckError::Failed(m) =
            verify_pattern("r", seed, 0, 10, &pattern::generate(seed, 0, 9)).unwrap_err()
        else {
            panic!()
        };
        assert!(m.contains("got 9 bytes"), "{m}");
    }

    #[test]
    fn expect_err_messages() {
        let ok: Result<u32> = Ok(5);
        let CheckError::Failed(m) = expect_err("op", ok, &[ErrorKind::NotFound]).unwrap_err()
        else {
            panic!()
        };
        assert!(m.contains("succeeded with 5"), "{m}");
        let wrong: Result<u32> = Err(fsfast_core::Error::already_exists("p"));
        let CheckError::Failed(m) = expect_err(
            "op",
            wrong,
            &[ErrorKind::NotFound, ErrorKind::IsADirectory],
        )
        .unwrap_err() else {
            panic!()
        };
        assert!(m.contains("NotFound or IsADirectory"), "{m}");
        assert!(m.contains("AlreadyExists"), "{m}");
        let right: Result<u32> = Err(fsfast_core::Error::not_found("p"));
        assert!(expect_err("op", right, &[ErrorKind::NotFound]).is_ok());
    }

    #[test]
    fn short_debug_truncates() {
        let v = vec![0u8; 10_000];
        let s = short_debug(&v);
        assert!(s.len() < 250, "{s}");
        assert!(s.contains("chars)"));
    }
}
