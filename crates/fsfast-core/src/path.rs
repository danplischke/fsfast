//! fsspec-style path helpers.
//!
//! Paths inside fsfast are protocol-stripped strings using `/` separators, the
//! same form fsspec passes to `AbstractFileSystem` methods after
//! `_strip_protocol` (e.g. `bucket/dir/key`, `/abs/path`, `/share/dir`).
//! Protocol stripping itself happens in the Python layer, which owns the
//! per-protocol URL rules.

/// Collapse repeated slashes and strip a trailing slash (but keep a lone `/`).
pub fn normalize(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    let mut prev_slash = false;
    for ch in path.chars() {
        if ch == '/' {
            if !prev_slash {
                out.push('/');
            }
            prev_slash = true;
        } else {
            out.push(ch);
            prev_slash = false;
        }
    }
    while out.len() > 1 && out.ends_with('/') {
        out.pop();
    }
    out
}

/// Parent directory, following fsspec's `_parent` (`"a/b/c" -> "a/b"`,
/// `"a" -> ""`, `"/a" -> "/"`).
pub fn parent(path: &str) -> String {
    let p = normalize(path);
    match p.rfind('/') {
        Some(0) => "/".to_owned(),
        Some(i) => p[..i].to_owned(),
        None => String::new(),
    }
}

/// Final path component.
pub fn basename(path: &str) -> &str {
    let p = path.trim_end_matches('/');
    match p.rfind('/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

/// Join `base` and `child` with exactly one `/`.
pub fn join(base: &str, child: &str) -> String {
    let child = child.trim_start_matches('/');
    if base.is_empty() {
        return child.to_owned();
    }
    if child.is_empty() {
        return base.to_owned();
    }
    if base.ends_with('/') {
        format!("{base}{child}")
    } else {
        format!("{base}/{child}")
    }
}

/// Depth of `path` below `root` in components (`root` itself is 0).
pub fn depth_below(root: &str, path: &str) -> usize {
    let root = normalize(root);
    let path = normalize(path);
    let rest = path.strip_prefix(root.as_str()).unwrap_or(&path);
    rest.split('/').filter(|s| !s.is_empty()).count()
}

/// All ancestors of `path` from the top down, excluding `path` itself and the
/// empty root (`"a/b/c" -> ["a", "a/b"]`, `"/x/y" -> ["/x"]`).
pub fn ancestors(path: &str) -> Vec<String> {
    let p = normalize(path);
    let start = usize::from(p.starts_with('/'));
    p.bytes()
        .enumerate()
        .skip(start)
        .filter(|&(_, b)| b == b'/')
        .map(|(i, _)| p[..i].to_owned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_works() {
        assert_eq!(normalize("a//b/"), "a/b");
        assert_eq!(normalize("/"), "/");
        assert_eq!(normalize("//x//"), "/x");
        assert_eq!(normalize(""), "");
    }

    #[test]
    fn parent_works() {
        assert_eq!(parent("a/b/c"), "a/b");
        assert_eq!(parent("a"), "");
        assert_eq!(parent("/a"), "/");
        assert_eq!(parent("/a/b/"), "/a");
    }

    #[test]
    fn basename_join_depth() {
        assert_eq!(basename("a/b/c/"), "c");
        assert_eq!(basename("c"), "c");
        assert_eq!(join("a/", "/b"), "a/b");
        assert_eq!(join("", "b"), "b");
        assert_eq!(depth_below("a", "a/b/c"), 2);
        assert_eq!(depth_below("/r", "/r"), 0);
    }

    #[test]
    fn ancestors_works() {
        assert_eq!(ancestors("a/b/c"), vec!["a", "a/b"]);
        assert_eq!(ancestors("/x/y"), vec!["/x"]);
        assert!(ancestors("a").is_empty());
    }
}
