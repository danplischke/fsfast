//! Path rules of fsspec's `LocalFileSystem` (`_strip_protocol`,
//! `make_path_posix`, `_parent`).
//!
//! The logic is written once for both path styles as pure functions taking
//! the current directory and home directory, so the Windows rules are unit
//! tested on every platform; [`strip_protocol`] applies the host's style.

use std::borrow::Cow;

/// Which operating system's path conventions apply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathStyle {
    /// `/`-rooted paths (Linux, macOS, BSD).
    Posix,
    /// Drive letters and UNC shares, written with forward slashes.
    Windows,
}

impl PathStyle {
    /// The style of the host.
    pub const fn native() -> Self {
        if cfg!(windows) {
            PathStyle::Windows
        } else {
            PathStyle::Posix
        }
    }
}

const PREFIXES: [&str; 4] = ["file://", "file:", "local://", "local:"];

fn char_at(s: &str, i: usize) -> Option<char> {
    s.chars().nth(i)
}

/// `s[n:]` in Python (code points).
fn skip_chars(s: &str, n: usize) -> &str {
    match s.char_indices().nth(n) {
        Some((i, _)) => &s[i..],
        None => "",
    }
}

fn home_dir() -> Option<String> {
    let var = if cfg!(windows) { "USERPROFILE" } else { "HOME" };
    std::env::var(var)
        .ok()
        .or_else(|| std::env::var("HOME").ok())
        .filter(|h| !h.is_empty())
}

fn current_dir() -> String {
    // Python's os.getcwd() raises when the cwd was deleted; keep the path
    // relative then, so the operation itself reports the error.
    std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
}

/// `os.path.expanduser` for `~` and `~/...` (`~user` forms are returned
/// unchanged; resolving other users' homes needs a passwd lookup).
fn expanduser(path: &str, home: Option<&str>, sep: &[char]) -> String {
    let rest_at = path[1..].find(sep).map(|i| i + 1).unwrap_or(path.len());
    if rest_at != 1 {
        return path.to_owned();
    }
    match home {
        Some(h) => {
            let h = h.trim_end_matches(sep);
            let out = format!("{h}{}", &path[rest_at..]);
            if out.is_empty() { "/".to_owned() } else { out }
        }
        None => path.to_owned(),
    }
}

/// fsspec `make_path_posix` for a string path.
pub fn make_path_posix(
    path: &str,
    style: PathStyle,
    cwd: &dyn Fn() -> String,
    home: Option<&str>,
) -> String {
    match style {
        PathStyle::Posix => {
            if path.starts_with('/') {
                path.to_owned()
            } else if path.starts_with('~') {
                expanduser(path, home, &['/'])
            } else {
                let rel = if let Some(r) = path.strip_prefix("./") {
                    r
                } else if path == "." {
                    ""
                } else {
                    path
                };
                format!("{}/{rel}", cwd())
            }
        }
        PathStyle::Windows => {
            let mut path: Cow<'_, str> = Cow::Borrowed(path);
            if char_at(&path, 0) == Some('/') && char_at(&path, 2) == Some(':') {
                path = Cow::Owned(skip_chars(&path, 1).to_owned());
            }
            if char_at(&path, 1) == Some(':') {
                let n = path.chars().count();
                if n == 2 || (n == 3 && matches!(char_at(&path, 2), Some('/' | '\\'))) {
                    return format!("{}:/", char_at(&path, 0).unwrap_or('C'));
                }
                return path.replace('\\', "/");
            }
            if path.starts_with('~') {
                let expanded = expanduser(&path, home, &['/', '\\']);
                if expanded == path.as_ref() {
                    return expanded.replace('\\', "/");
                }
                return make_path_posix(&expanded, style, cwd, home);
            }
            if path.starts_with("\\\\") || path.starts_with("//") {
                return format!("//{}", path[2..].replace('\\', "/"));
            }
            if path.starts_with('\\') || path.starts_with('/') {
                let cwd = make_path_posix(&cwd(), style, &String::new, home);
                return format!("{}{}", windows_drive(&cwd).0, path.replace('\\', "/"));
            }
            let p = path.replace('\\', "/");
            let rel = if let Some(r) = p.strip_prefix("./") {
                r
            } else if p == "." {
                ""
            } else {
                &p
            };
            let cwd = make_path_posix(&cwd(), style, &String::new, home);
            format!("{cwd}/{rel}")
        }
    }
}

/// Split a posix-form Windows path into `(drive, rest)` like the
/// `_strip_protocol` NT branch: `C:` drives, `//server/share` UNC roots.
fn windows_drive(path: &str) -> (&str, &str) {
    if char_at(path, 1) == Some(':') {
        let split = path
            .char_indices()
            .nth(2)
            .map(|(i, _)| i)
            .unwrap_or(path.len());
        return path.split_at(split);
    }
    if let Some(rest) = path.strip_prefix("//") {
        let Some(i1) = rest.find('/').map(|i| i + 2) else {
            return (path, "");
        };
        let Some(i2) = path[i1 + 1..].find('/').map(|i| i + i1 + 1) else {
            return (path, "");
        };
        return path.split_at(i2);
    }
    ("", path)
}

/// fsspec `LocalFileSystem._strip_protocol` with explicit style and
/// environment (see [`strip_protocol`]).
pub fn strip_protocol_with(
    path: &str,
    style: PathStyle,
    cwd: &dyn Fn() -> String,
    home: Option<&str>,
) -> String {
    let mut p = path;
    for prefix in PREFIXES {
        if let Some(rest) = p.strip_prefix(prefix) {
            p = rest;
            break;
        }
    }
    let p = make_path_posix(p, style, cwd, home);
    match style {
        PathStyle::Posix => {
            let t = p.trim_end_matches('/');
            if t.is_empty() {
                "/".to_owned()
            } else {
                t.to_owned()
            }
        }
        PathStyle::Windows => {
            let (drive, rest) = windows_drive(&p);
            let rest = rest.trim_end_matches('/');
            format!("{drive}{}", if rest.is_empty() { "/" } else { rest })
        }
    }
}

/// fsspec `LocalFileSystem._strip_protocol`: remove `file://`, `file:`,
/// `local://` or `local:`, make the path absolute (relative paths resolve
/// against the current directory, `~` against the home directory), use `/`
/// separators and drop trailing slashes. Like fsspec, `.`/`..` components and
/// repeated slashes are kept as given.
pub fn strip_protocol(path: &str) -> Cow<'_, str> {
    // Fast path: an absolute posix path that is already canonical.
    if PathStyle::native() == PathStyle::Posix
        && path.starts_with('/')
        && (path.len() == 1 || !path.ends_with('/'))
    {
        return Cow::Borrowed(path);
    }
    let home = home_dir();
    Cow::Owned(strip_protocol_with(
        path,
        PathStyle::native(),
        &current_dir,
        home.as_deref(),
    ))
}

/// fsspec `LocalFileSystem._parent` of an already stripped path.
pub fn parent_with(path: &str, style: PathStyle) -> String {
    let head = path.rsplit_once('/').map_or(path, |(h, _)| h);
    match style {
        PathStyle::Posix => {
            if head.is_empty() {
                "/".to_owned()
            } else {
                head.to_owned()
            }
        }
        PathStyle::Windows => {
            if head.chars().count() <= 3 && char_at(head, 1) == Some(':') {
                format!("{}:/", char_at(head, 0).unwrap_or('C'))
            } else {
                head.to_owned()
            }
        }
    }
}

/// fsspec `LocalFileSystem._parent` with the host's style.
pub fn parent(path: &str) -> String {
    parent_with(path, PathStyle::native())
}

/// `os.path.join(dir, name)` as fsspec sees it after `_strip_protocol`.
pub(crate) fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn posix(p: &str) -> String {
        strip_protocol_with(
            p,
            PathStyle::Posix,
            &|| "/work/dir".to_owned(),
            Some("/home/me"),
        )
    }

    fn nt(p: &str) -> String {
        strip_protocol_with(
            p,
            PathStyle::Windows,
            &|| "C:\\Users\\me".to_owned(),
            Some("C:\\Users\\me"),
        )
    }

    #[test]
    fn posix_matches_fsspec() {
        // Recorded from fsspec 2026.9.0 with cwd=/work/dir, HOME=/home/me.
        let cases = [
            ("file:///a/b/", "/a/b"),
            ("local:/x", "/x"),
            ("rel", "/work/dir/rel"),
            (".", "/work/dir"),
            ("./", "/work/dir"),
            ("./x/", "/work/dir/x"),
            ("~", "/home/me"),
            ("~/data/", "/home/me/data"),
            ("~other/x", "~other/x"),
            ("/a//b/", "/a//b"),
            ("/", "/"),
            ("///", "/"),
            ("file://", "/work/dir"),
            ("local://tmp/x", "/work/dir/tmp/x"),
            ("/a/../b", "/a/../b"),
            ("", "/work/dir"),
        ];
        for (input, want) in cases {
            assert_eq!(posix(input), want, "input {input:?}");
        }
    }

    #[test]
    fn windows_matches_fsspec() {
        // Derived from fsspec's NT branches of make_path_posix/_strip_protocol.
        let cases = [
            ("C:\\Windows\\System32\\", "C:/Windows/System32"),
            ("c:/data/x.csv", "c:/data/x.csv"),
            ("/c:/local/path", "c:/local/path"),
            ("file:///C:/x/", "C:/x"),
            ("C:", "C:/"),
            ("C:\\", "C:/"),
            ("C:/", "C:/"),
            ("\\\\server\\share\\dir\\f", "//server/share/dir/f"),
            ("//server/share", "//server/share/"),
            ("//server/share/", "//server/share/"),
            ("\\\\server", "//server/"),
            ("\\rooted\\path", "C:/rooted/path"),
            ("relative\\x", "C:/Users/me/relative/x"),
            (".", "C:/Users/me"),
            ("~\\docs", "C:/Users/me/docs"),
        ];
        for (input, want) in cases {
            assert_eq!(nt(input), want, "input {input:?}");
        }
    }

    #[test]
    fn parents() {
        assert_eq!(parent_with("/a/b/c", PathStyle::Posix), "/a/b");
        assert_eq!(parent_with("/a", PathStyle::Posix), "/");
        assert_eq!(parent_with("/", PathStyle::Posix), "/");
        assert_eq!(parent_with("C:/x/y", PathStyle::Windows), "C:/x");
        assert_eq!(parent_with("C:/x", PathStyle::Windows), "C:/");
        assert_eq!(
            parent_with("//srv/share/x", PathStyle::Windows),
            "//srv/share"
        );
    }

    #[test]
    fn join_paths() {
        assert_eq!(join("/", "x"), "/x");
        assert_eq!(join("/a", "x"), "/a/x");
        assert_eq!(join("C:/", "x"), "C:/x");
    }

    #[test]
    fn native_fast_path_borrows() {
        if PathStyle::native() == PathStyle::Posix {
            assert!(matches!(
                strip_protocol("/abs/path"),
                Cow::Borrowed("/abs/path")
            ));
            assert!(matches!(strip_protocol("/"), Cow::Borrowed("/")));
            assert_eq!(strip_protocol("/abs/path/"), "/abs/path");
        }
    }

    proptest! {
        /// Stripping is idempotent and never leaves a trailing slash
        /// (except for the root), for arbitrary absolute posix inputs.
        #[test]
        fn posix_idempotent(s in "(/[a-z.~ ]{0,4}){0,5}/?") {
            let once = posix(&s);
            prop_assert_eq!(posix(&once), once.clone());
            prop_assert!(once == "/" || !once.ends_with('/'));
            prop_assert!(once.starts_with('/'));
        }

        #[test]
        fn windows_idempotent(s in "[A-Z]:(\\\\[a-z ]{1,4}){0,4}\\\\?") {
            let once = nt(&s);
            prop_assert_eq!(nt(&once), once.clone());
            prop_assert!(!once.contains('\\'));
        }
    }
}
