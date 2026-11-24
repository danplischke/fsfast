//! The in-memory store and its operations.
//!
//! The data model mirrors fsspec's `MemoryFileSystem` exactly: a map of file
//! paths to contents (`store`) plus a set of explicitly created directories
//! (`pseudo_dirs`, always containing the root `""`). Any path that is a
//! proper prefix (at a `/` boundary) of a file or pseudo-directory is an
//! *implied* directory. All operations here take the already stripped path
//! (see [`crate::paths::strip_protocol`]) and run under the caller's lock, so
//! every operation is atomic.
//!
//! Both collections are ordered (`BTreeMap`/`BTreeSet`) so "everything below
//! `dir/`" is a range scan, and listing can skip whole sub-trees.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use bytes::{Bytes, BytesMut};
use fsfast_core::{Detail, Error, ErrorKind, FileInfo, FindOptions, Result, Value, WriteMode};

use crate::paths::{parent, strip_protocol};

/// Current time truncated to microseconds, the resolution of Python's
/// `datetime.now()`, so `created` round-trips exactly through the bindings.
fn now() -> SystemTime {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    UNIX_EPOCH + Duration::from_micros(d.as_micros() as u64)
}

/// `datetime.timestamp()` of a microsecond-resolution time.
fn timestamp(t: SystemTime) -> f64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_micros() as f64 / 1e6,
        Err(e) => -(e.duration().as_micros() as f64) / 1e6,
    }
}

fn next_generation() -> u64 {
    static GENERATION: AtomicU64 = AtomicU64::new(1);
    GENERATION.fetch_add(1, Ordering::Relaxed)
}

/// One file (fsspec `MemoryFile`).
#[derive(Debug, Clone)]
pub(crate) struct MemFile {
    pub data: Bytes,
    pub created: SystemTime,
    pub modified: SystemTime,
    /// Process-unique id of this content version; becomes `FileInfo::version`
    /// and lets write handles detect that their file was replaced.
    pub generation: u64,
}

impl MemFile {
    pub fn new(data: Bytes) -> Self {
        let t = now();
        MemFile {
            data,
            created: t,
            modified: t,
            generation: next_generation(),
        }
    }
}

/// How `created` is reported. fsspec's `info()` returns the `datetime`
/// itself, while `ls()`/`find()` return `datetime.timestamp()` (a float).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreatedAs {
    Datetime,
    Timestamp,
}

pub(crate) fn file_info(name: &str, f: &MemFile, created_as: CreatedAs) -> FileInfo {
    let mut info = FileInfo::file(name, f.data.len() as u64)
        .with_modified(Some(f.modified))
        .with_version(Some(f.generation.to_string()));
    info.created = Some(f.created);
    let created = match created_as {
        CreatedAs::Datetime => Value::Time(f.created),
        CreatedAs::Timestamp => Value::Float(timestamp(f.created)),
    };
    info.set("created", created);
    info
}

fn dir_info(name: &str) -> FileInfo {
    FileInfo::directory(name)
}

/// What an opened write handle needs to know about its slot in the store.
#[derive(Debug)]
pub(crate) struct WriteSlot {
    /// Generation of the entry the handle owns.
    pub generation: u64,
    /// Existing content the writes are appended to (append mode).
    pub base: Bytes,
    /// The entry to put back on abort (append to an existing file); `None`
    /// means the handle created the entry and abort removes it.
    pub restore: Option<MemFile>,
}

/// The two collections of fsspec's `MemoryFileSystem`.
#[derive(Debug)]
pub(crate) struct Inner {
    pub files: BTreeMap<String, MemFile>,
    pub pseudo_dirs: BTreeSet<String>,
}

impl Default for Inner {
    fn default() -> Self {
        Inner {
            files: BTreeMap::new(),
            pseudo_dirs: BTreeSet::from([String::new()]),
        }
    }
}

/// First key of `map` that is `>= from`, if it starts with `prefix`.
fn first_with_prefix<'a, V>(
    map: &'a BTreeMap<String, V>,
    from: &str,
    prefix: &str,
) -> Option<(&'a String, &'a V)> {
    map.range::<str, _>((Bound::Included(from), Bound::Unbounded))
        .next()
        .filter(|(k, _)| k.starts_with(prefix))
}

fn first_in_set_with_prefix<'a>(
    set: &'a BTreeSet<String>,
    from: &str,
    prefix: &str,
) -> Option<&'a String> {
    set.range::<str, _>((Bound::Included(from), Bound::Unbounded))
        .next()
        .filter(|k| k.starts_with(prefix))
}

/// The smallest string greater than every string starting with `dir + "/"`
/// that is still not a key below `dir`: `dir + "0"` (`'0'` follows `'/'`).
fn subtree_end(dir: &str) -> String {
    let mut s = String::with_capacity(dir.len() + 1);
    s.push_str(dir);
    s.push('0');
    s
}

fn not_empty(path: &str) -> Error {
    Error::new(ErrorKind::DirectoryNotEmpty, "Directory not empty")
        .with_path(path)
        .with_detail(Detail::Errno(39))
}

impl Inner {
    /// Reset to an empty store.
    pub fn clear(&mut self) {
        *self = Inner::default();
    }

    fn has_descendant(&self, path: &str) -> bool {
        let prefix = format!("{path}/");
        first_with_prefix(&self.files, &prefix, &prefix).is_some()
            || first_in_set_with_prefix(&self.pseudo_dirs, &prefix, &prefix).is_some()
    }

    /// fsspec `isdir`: a pseudo-directory or an implied directory.
    pub fn is_dir(&self, path: &str) -> bool {
        self.pseudo_dirs.contains(path) || self.has_descendant(path)
    }

    /// fsspec `isfile`.
    pub fn is_file(&self, path: &str) -> bool {
        self.files.contains_key(path)
    }

    /// fsspec `exists` (`info` succeeds).
    pub fn exists(&self, path: &str) -> bool {
        self.is_dir(path) || self.is_file(path)
    }

    /// fsspec `MemoryFileSystem.info`: directories win over files.
    pub fn info(&self, path: &str) -> Result<FileInfo> {
        if self.is_dir(path) {
            Ok(dir_info(path))
        } else if let Some(f) = self.files.get(path) {
            Ok(file_info(path, f, CreatedAs::Datetime))
        } else {
            Err(Error::not_found(path))
        }
    }

    /// fsspec `MemoryFileSystem.ls(detail=True)`, sorted by name.
    pub fn ls(&self, path: &str) -> Result<Vec<FileInfo>> {
        if let Some(f) = self.files.get(path) {
            return Ok(vec![file_info(path, f, CreatedAs::Timestamp)]);
        }
        let starter = format!("{path}/");
        let mut out = Vec::new();
        let mut seen_dirs: BTreeSet<String> = BTreeSet::new();

        // Files: exact children are files; deeper keys imply a child
        // directory, after which the whole sub-tree is skipped.
        let mut cursor = starter.clone();
        while let Some((name, f)) = first_with_prefix(&self.files, &cursor, &starter) {
            let rest = &name[starter.len()..];
            match rest.find('/') {
                None => {
                    out.push(file_info(name, f, CreatedAs::Timestamp));
                    // Next key strictly after `name`.
                    cursor = format!("{name}\0");
                }
                Some(i) => {
                    let dir = format!("{starter}{}", &rest[..i]);
                    cursor = subtree_end(&dir);
                    if seen_dirs.insert(dir.clone()) {
                        out.push(dir_info(&dir));
                    }
                }
            }
        }
        // Pseudo-directories: exact children, or children implied by deeper ones.
        let mut cursor = starter.clone();
        while let Some(name) = first_in_set_with_prefix(&self.pseudo_dirs, &cursor, &starter) {
            let rest = &name[starter.len()..];
            let dir = match rest.find('/') {
                // An exact child: continue right after it (siblings such as
                // `x-y` sort between `x` and `x/...`).
                None => {
                    cursor = format!("{name}\0");
                    name.clone()
                }
                // A deeper one implies a child directory: skip its sub-tree.
                Some(i) => {
                    let dir = format!("{starter}{}", &rest[..i]);
                    cursor = subtree_end(&dir);
                    dir
                }
            };
            if seen_dirs.insert(dir.clone()) {
                out.push(dir_info(&dir));
            }
        }
        if out.is_empty() {
            if self.pseudo_dirs.contains(path) {
                return Ok(out);
            }
            return Err(Error::not_found(path));
        }
        // Stable: a file and a directory of the same name keep fsspec's
        // files-first order.
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// fsspec `MemoryFileSystem.find(detail=True)`, sorted by name.
    pub fn find(&self, path: &str, opts: &FindOptions) -> Result<Vec<FileInfo>> {
        if opts.maxdepth == Some(0) {
            return Err(Error::invalid_input("maxdepth must be at least 1"));
        }
        if let Some(f) = self.files.get(path) {
            return Ok(vec![file_info(path, f, CreatedAs::Timestamp)]);
        }
        let prefix = if path.is_empty() {
            "/".to_owned()
        } else {
            format!("{path}/")
        };
        let maxdepth = opts.maxdepth;
        let within = |rel: &str| maxdepth.is_none_or(|m| rel.matches('/').count() < m);
        let mut out: BTreeMap<String, FileInfo> = BTreeMap::new();
        let mut dirs: BTreeMap<String, FileInfo> = BTreeMap::new();

        // Register every directory implied between `path` and `name` that is
        // within maxdepth (fsspec's add_ancestor_dirs).
        let add_ancestor_dirs = |name: &str, dirs: &mut BTreeMap<String, FileInfo>| {
            let mut idx = name.rfind('/');
            while let Some(i) = idx {
                if i <= path.len() {
                    break;
                }
                let parent = &name[..i];
                if dirs.contains_key(parent) {
                    break;
                }
                if within(&parent[prefix.len()..]) {
                    dirs.insert(parent.to_owned(), dir_info(parent));
                }
                idx = parent.rfind('/');
            }
        };

        for (name, f) in self
            .files
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(&prefix))
        {
            if opts.withdirs {
                add_ancestor_dirs(name, &mut dirs);
            }
            if !within(&name[prefix.len()..]) {
                continue;
            }
            out.insert(name.clone(), file_info(name, f, CreatedAs::Timestamp));
        }
        if opts.withdirs {
            for pdir in self
                .pseudo_dirs
                .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
                .take_while(|k| k.starts_with(&prefix))
            {
                add_ancestor_dirs(&format!("{pdir}/"), &mut dirs);
            }
            out.extend(dirs);
            // Like fsspec's base find(): include the root itself when it is a
            // directory.
            if !path.is_empty() && self.is_dir(path) {
                out.insert(path.to_owned(), self.info(path)?);
            }
        }
        Ok(out.into_values().collect())
    }

    /// fsspec `MemoryFileSystem.mkdir`.
    pub fn mkdir(&mut self, path: &str, create_parents: bool) -> Result<()> {
        if self.files.contains_key(path) || self.pseudo_dirs.contains(path) {
            return Err(Error::already_exists(path));
        }
        let parent_path = parent(path);
        let parent_is_root = parent_path.trim_matches('/').is_empty();
        if !parent_is_root && self.is_file(&strip_protocol(&parent_path)) {
            return Err(Error::not_a_directory(parent_path));
        }
        if create_parents && !parent_is_root {
            match self.mkdir(&strip_protocol(&parent_path), true) {
                Err(e) if e.kind() == ErrorKind::AlreadyExists => {}
                r => r?,
            }
        }
        if !path.is_empty() {
            self.pseudo_dirs.insert(path.to_owned());
        }
        Ok(())
    }

    /// fsspec `MemoryFileSystem.makedirs`.
    pub fn makedirs(&mut self, path: &str, exist_ok: bool) -> Result<()> {
        match self.mkdir(path, true) {
            Err(e) if exist_ok && e.kind() == ErrorKind::AlreadyExists => Ok(()),
            r => r,
        }
    }

    /// What fsspec's `ls(path)` would return as non-empty.
    fn has_entries(&self, path: &str) -> bool {
        self.files.contains_key(path) || self.has_descendant(path)
    }

    /// fsspec `MemoryFileSystem.rmdir`.
    pub fn rmdir(&mut self, path: &str) -> Result<()> {
        if path.is_empty() {
            // fsspec silently refuses to delete the root.
            return Ok(());
        }
        if !self.pseudo_dirs.contains(path) {
            return Err(Error::not_found(path));
        }
        if self.has_entries(path) {
            return Err(not_empty(path));
        }
        self.pseudo_dirs.remove(path);
        Ok(())
    }

    /// fsspec `MemoryFileSystem._rm` (`rm_file`).
    pub fn rm_file(&mut self, path: &str) -> Result<()> {
        match self.files.remove(path) {
            Some(_) => Ok(()),
            None => Err(Error::not_found(path)),
        }
    }

    /// fsspec `MemoryFileSystem.cp_file`: files are copied (sharing the
    /// immutable buffer), directories become pseudo-directories at `dst`.
    pub fn cp_file(&mut self, src: &str, dst: &str) -> Result<()> {
        if let Some(f) = self.files.get(src) {
            let data = f.data.clone();
            self.files.insert(dst.to_owned(), MemFile::new(data));
            Ok(())
        } else if self.is_dir(src) {
            self.pseudo_dirs.insert(dst.to_owned());
            Ok(())
        } else {
            Err(Error::not_found(src))
        }
    }

    /// Move a file, or a whole directory tree, to the final path `dst`.
    ///
    /// The result equals fsspec's `mv(src, dst, recursive=True)` (copy, then
    /// delete the source) with `dst` already resolved: moved files get a new
    /// `created` time (fsspec copies them) and every directory of a moved tree
    /// becomes a pseudo-directory at its new location.
    pub fn mv(&mut self, src: &str, dst: &str) -> Result<()> {
        if src == dst {
            return Ok(());
        }
        if self.files.contains_key(src) {
            if self.is_dir(dst) {
                return Err(Error::is_a_directory(dst));
            }
            let f = self.files.remove(src).expect("checked above");
            self.files.insert(dst.to_owned(), MemFile::new(f.data));
            return Ok(());
        }
        if !self.is_dir(src) {
            return Err(Error::not_found(src));
        }
        if src.is_empty() {
            return Err(Error::invalid_input("cannot move the filesystem root").with_path(src));
        }
        if dst.starts_with(&format!("{src}/")) {
            return Err(Error::invalid_input(format!(
                "cannot move a directory '{src}' into itself '{dst}'"
            ))
            .with_path(src));
        }
        if self.files.contains_key(dst) {
            return Err(Error::not_a_directory(dst));
        }
        if self.has_entries(dst) {
            return Err(not_empty(dst));
        }

        let prefix = format!("{src}/");
        let moved_files: Vec<String> = self
            .files
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .take_while(|(k, _)| k.starts_with(&prefix))
            .map(|(k, _)| k.clone())
            .collect();
        let mut moved_dirs: BTreeSet<String> = self
            .pseudo_dirs
            .range::<str, _>((Bound::Included(prefix.as_str()), Bound::Unbounded))
            .take_while(|k| k.starts_with(&prefix))
            .cloned()
            .collect();
        // Implied directories inside the tree: ancestors (below `src`) of
        // every moved file and pseudo-directory.
        let mut implied = BTreeSet::new();
        for name in moved_files.iter().chain(moved_dirs.iter()) {
            let mut end = name.len();
            while let Some(i) = name[..end].rfind('/') {
                if i <= src.len() {
                    break;
                }
                implied.insert(name[..i].to_owned());
                end = i;
            }
        }
        moved_dirs.extend(implied);
        let rebase = |p: &str| format!("{dst}{}", &p[src.len()..]);
        for name in moved_files {
            let f = self.files.remove(&name).expect("collected above");
            self.files.insert(rebase(&name), MemFile::new(f.data));
        }
        for d in moved_dirs {
            self.pseudo_dirs.remove(&d);
            self.pseudo_dirs.insert(rebase(&d));
        }
        self.pseudo_dirs.remove(src);
        self.pseudo_dirs.insert(dst.to_owned());
        Ok(())
    }

    /// fsspec `_open` refuses any path below a file with `FileExistsError`
    /// naming the (closest) offending ancestor.
    fn check_no_file_ancestor(&self, path: &str) -> Result<()> {
        let mut p = path.to_owned();
        while p.len() > 1 {
            p = parent(&p);
            if self.files.contains_key(strip_protocol(&p).as_ref()) {
                return Err(Error::already_exists(p));
            }
        }
        Ok(())
    }

    /// The checks of fsspec `_open(path, "rb")`.
    pub fn open_read(&self, path: &str) -> Result<&MemFile> {
        if self.pseudo_dirs.contains(path) {
            return Err(Error::is_a_directory(path));
        }
        self.check_no_file_ancestor(path)?;
        self.files.get(path).ok_or_else(|| Error::not_found(path))
    }

    /// The checks of fsspec `_open` in a write mode.
    fn check_write(&self, path: &str, mode: WriteMode) -> Result<()> {
        if mode == WriteMode::CreateNew && self.exists(path) {
            return Err(Error::already_exists(path));
        }
        if self.pseudo_dirs.contains(path) {
            return Err(Error::is_a_directory(path));
        }
        self.check_no_file_ancestor(path)
    }

    /// fsspec `_open(path, "wb" | "xb" | "ab")`: like fsspec, the file exists
    /// (empty, or with its old content for append) as soon as it is opened.
    pub fn open_write(&mut self, path: &str, mode: WriteMode) -> Result<WriteSlot> {
        self.check_write(path, mode)?;
        if mode == WriteMode::Append
            && let Some(existing) = self.files.get(path)
        {
            return Ok(WriteSlot {
                generation: existing.generation,
                base: existing.data.clone(),
                restore: Some(existing.clone()),
            });
        }
        let f = MemFile::new(Bytes::new());
        let generation = f.generation;
        self.files.insert(path.to_owned(), f);
        Ok(WriteSlot {
            generation,
            base: Bytes::new(),
            restore: None,
        })
    }

    /// `pipe_file`: store `data` without copying it.
    pub fn put(&mut self, path: &str, data: Bytes, mode: WriteMode) -> Result<()> {
        self.check_write(path, mode)?;
        if mode == WriteMode::Append
            && let Some(existing) = self.files.get_mut(path)
        {
            if !data.is_empty() {
                let mut buf = BytesMut::with_capacity(existing.data.len() + data.len());
                buf.extend_from_slice(&existing.data);
                buf.extend_from_slice(&data);
                existing.data = buf.freeze();
                existing.modified = now();
                existing.generation = next_generation();
            }
            return Ok(());
        }
        self.files.insert(path.to_owned(), MemFile::new(data));
        Ok(())
    }

    /// Publish a write handle's content if the handle still owns the entry.
    /// Returns the new generation, or `None` if the entry was replaced or
    /// deleted meanwhile (the data is then dropped, as fsspec drops writes to
    /// an orphaned `MemoryFile`).
    pub fn commit(&mut self, path: &str, generation: u64, data: Bytes) -> Option<u64> {
        let f = self.files.get_mut(path)?;
        if f.generation != generation {
            return None;
        }
        f.data = data;
        f.modified = now();
        f.generation = next_generation();
        Some(f.generation)
    }

    /// Undo a write handle: remove the entry it created, or restore the file
    /// it appended to, provided nobody replaced the entry meanwhile.
    pub fn abort(&mut self, path: &str, generation: u64, restore: Option<MemFile>) {
        if self.files.get(path).map(|f| f.generation) != Some(generation) {
            return;
        }
        match restore {
            Some(original) => {
                self.files.insert(path.to_owned(), original);
            }
            None => {
                self.files.remove(path);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn names(v: &[FileInfo]) -> Vec<&str> {
        v.iter().map(|i| i.name.as_str()).collect()
    }

    fn put(s: &mut Inner, p: &str, data: &'static [u8]) {
        s.put(p, Bytes::from_static(data), WriteMode::Overwrite).unwrap();
    }

    #[test]
    fn info_and_ls_like_fsspec() {
        let mut s = Inner::default();
        put(&mut s, "/a/b/c", b"x");
        assert!(s.info("/a").unwrap().is_dir());
        assert!(s.info("/a/b").unwrap().is_dir());
        let f = s.info("/a/b/c").unwrap();
        assert!(f.is_file());
        assert!(matches!(f.extra.get("created"), Some(Value::Time(_))));
        assert_eq!(s.info("").unwrap().name, "");
        assert!(s.info("").unwrap().is_dir());
        assert_eq!(s.info("/zz").unwrap_err().kind(), ErrorKind::NotFound);

        let l = s.ls("/a/b").unwrap();
        assert_eq!(names(&l), ["/a/b/c"]);
        assert!(matches!(l[0].extra.get("created"), Some(Value::Float(_))));
        assert_eq!(names(&s.ls("/a/b/c").unwrap()), ["/a/b/c"]);
        assert_eq!(names(&s.ls("").unwrap()), ["/a"]);
        assert_eq!(s.ls("/nope").unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn ls_order_and_dedup() {
        let mut s = Inner::default();
        put(&mut s, "/z/1", b"1");
        put(&mut s, "/z/0", b"0");
        s.mkdir("/z/a", true).unwrap();
        put(&mut s, "/z/b/c", b"c");
        put(&mut s, "/z/b/d/e", b"e");
        put(&mut s, "/z/b-x", b"bx");
        s.mkdir("/z/b/q", true).unwrap();
        s.mkdir("/z/p/q/r", true).unwrap();
        let l = s.ls("/z").unwrap();
        assert_eq!(names(&l), ["/z/0", "/z/1", "/z/a", "/z/b", "/z/b-x", "/z/p"]);
        assert!(l[3].is_dir() && l[4].is_file() && l[5].is_dir());
        // An empty pseudo-directory lists as empty.
        s.mkdir("/emp", false).unwrap();
        assert!(s.ls("/emp").unwrap().is_empty());
        // Siblings sorting between `m` and `m/...` are not skipped.
        s.mkdir("/s/m", true).unwrap();
        s.mkdir("/s/m-n", true).unwrap();
        s.mkdir("/s/m/deep", true).unwrap();
        s.mkdir("/s/m.o/deeper", false).unwrap();
        put(&mut s, "/s/f/x", b"x");
        put(&mut s, "/s/f-g", b"y");
        assert_eq!(
            names(&s.ls("/s").unwrap()),
            ["/s/f", "/s/f-g", "/s/m", "/s/m-n", "/s/m.o"]
        );
    }

    #[test]
    fn mkdir_semantics() {
        let mut s = Inner::default();
        // No parents: fsspec still records the path; the parent is implied.
        s.mkdir("/q/r", false).unwrap();
        assert!(s.pseudo_dirs.contains("/q/r") && !s.pseudo_dirs.contains("/q"));
        assert!(s.info("/q").unwrap().is_dir());
        assert_eq!(s.mkdir("/q/r", true).unwrap_err().kind(), ErrorKind::AlreadyExists);
        // An implied directory is not "existing" for mkdir/makedirs.
        put(&mut s, "/i/j", b"x");
        s.makedirs("/i", false).unwrap();
        // Below a file.
        let e = s.mkdir("/i/j/k", true).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::NotADirectory);
        assert_eq!(e.path(), Some("/i/j"));
        let e = s.mkdir("/i/j/k/l", true).unwrap_err();
        assert_eq!((e.kind(), e.path()), (ErrorKind::NotADirectory, Some("/i/j")));
        s.mkdir("/i/j/k/l", false).unwrap();
        // The root exists.
        assert_eq!(s.mkdir("", true).unwrap_err().kind(), ErrorKind::AlreadyExists);
        s.makedirs("", true).unwrap();
        // makedirs over a file with exist_ok is silently accepted by fsspec.
        s.makedirs("/i/j", true).unwrap();
        assert_eq!(s.makedirs("/i/j", false).unwrap_err().kind(), ErrorKind::AlreadyExists);
    }

    #[test]
    fn rmdir_semantics() {
        let mut s = Inner::default();
        s.mkdir("/a", true).unwrap();
        put(&mut s, "/a/f", b"x");
        let e = s.rmdir("/a").unwrap_err();
        assert_eq!(e.kind(), ErrorKind::DirectoryNotEmpty);
        assert!(e.details().contains(&Detail::Errno(39)));
        put(&mut s, "/b/c", b"x");
        assert_eq!(s.rmdir("/b").unwrap_err().kind(), ErrorKind::NotFound); // implied
        assert_eq!(s.rmdir("/b/c").unwrap_err().kind(), ErrorKind::NotFound); // a file
        s.rmdir("").unwrap();
        s.rm_file("/a/f").unwrap();
        s.rmdir("/a").unwrap();
        assert_eq!(s.info("/a").unwrap_err().kind(), ErrorKind::NotFound);
    }

    #[test]
    fn open_checks_like_fsspec() {
        let mut s = Inner::default();
        put(&mut s, "/a/b/c", b"x");
        let e = s.open_read("/a/b/c/d").unwrap_err();
        assert_eq!((e.kind(), e.path()), (ErrorKind::AlreadyExists, Some("/a/b/c")));
        s.mkdir("/pd", true).unwrap();
        assert_eq!(s.open_read("/pd").unwrap_err().kind(), ErrorKind::IsADirectory);
        assert_eq!(s.open_read("/a").unwrap_err().kind(), ErrorKind::NotFound); // implied dir
        assert_eq!(
            s.open_write("/pd", WriteMode::CreateNew).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        assert_eq!(
            s.open_write("/pd", WriteMode::Append).unwrap_err().kind(),
            ErrorKind::IsADirectory
        );
        assert_eq!(
            s.open_write("/a/b/c", WriteMode::CreateNew).unwrap_err().kind(),
            ErrorKind::AlreadyExists
        );
        // Writing over an implied directory is allowed by fsspec.
        s.open_write("/a", WriteMode::Overwrite).unwrap();
        assert!(s.is_file("/a") && s.is_dir("/a"));
    }

    #[test]
    fn write_slot_commit_and_abort() {
        let mut s = Inner::default();
        let slot = s.open_write("/w", WriteMode::Overwrite).unwrap();
        assert!(s.is_file("/w"));
        let g = s.commit("/w", slot.generation, Bytes::from_static(b"abc")).unwrap();
        assert_eq!(&s.files["/w"].data[..], b"abc");
        // A stale generation does not commit.
        assert!(s.commit("/w", slot.generation, Bytes::from_static(b"zzz")).is_none());
        s.abort("/w", g, None);
        assert!(!s.is_file("/w"));

        put(&mut s, "/ap", b"hi");
        let slot = s.open_write("/ap", WriteMode::Append).unwrap();
        assert_eq!(&slot.base[..], b"hi");
        let g = s.commit("/ap", slot.generation, Bytes::from_static(b"hi!!")).unwrap();
        s.abort("/ap", g, slot.restore);
        assert_eq!(&s.files["/ap"].data[..], b"hi");
    }

    #[test]
    fn find_like_fsspec() {
        let mut s = Inner::default();
        put(&mut s, "/a/b/c", b"x");
        s.mkdir("/q/r", false).unwrap();
        let all = FindOptions { maxdepth: None, withdirs: true };
        assert_eq!(names(&s.find("", &all).unwrap()), ["/a", "/a/b", "/a/b/c", "/q", "/q/r"]);
        assert_eq!(names(&s.find("/a", &all).unwrap()), ["/a", "/a/b", "/a/b/c"]);
        assert_eq!(names(&s.find("/a/b/c", &all).unwrap()), ["/a/b/c"]);
        assert!(s.find("/zzz", &all).unwrap().is_empty());
        let d1 = FindOptions { maxdepth: Some(1), withdirs: true };
        assert_eq!(names(&s.find("", &d1).unwrap()), ["/a", "/q"]);
        let files2 = FindOptions { maxdepth: Some(2), withdirs: false };
        assert!(s.find("", &files2).unwrap().is_empty());
        let e = s.find("", &FindOptions { maxdepth: Some(0), withdirs: false }).unwrap_err();
        assert_eq!(e.kind(), ErrorKind::InvalidInput);
    }

    #[test]
    fn cp_and_mv() {
        let mut s = Inner::default();
        put(&mut s, "/f", b"data");
        s.cp_file("/f", "/g").unwrap();
        assert_eq!(&s.files["/g"].data[..], b"data");
        assert_eq!(s.cp_file("/nope", "/x").unwrap_err().kind(), ErrorKind::NotFound);
        s.mkdir("/d", true).unwrap();
        s.cp_file("/d", "/d2").unwrap();
        assert!(s.pseudo_dirs.contains("/d2"));

        s.mv("/g", "/h").unwrap();
        assert!(!s.is_file("/g") && s.is_file("/h"));
        assert_eq!(s.mv("/h", "/d").unwrap_err().kind(), ErrorKind::IsADirectory);
        assert_eq!(s.mv("/nope", "/x").unwrap_err().kind(), ErrorKind::NotFound);

        // Directory trees move as a whole; implied directories become pseudo.
        put(&mut s, "/t/x/y/z", b"z");
        s.mkdir("/t/empty", true).unwrap();
        s.mv("/t", "/u").unwrap();
        assert!(!s.exists("/t"));
        assert!(s.is_file("/u/x/y/z"));
        for d in ["/u", "/u/x", "/u/x/y", "/u/empty"] {
            assert!(s.pseudo_dirs.contains(d), "{d}");
        }
        assert_eq!(s.mv("/u", "/u/inner").unwrap_err().kind(), ErrorKind::InvalidInput);
        assert_eq!(s.mv("/u", "/f").unwrap_err().kind(), ErrorKind::NotADirectory);
        assert_eq!(s.mv("/u", "/d").unwrap(), ()); // empty pseudo dir is replaced
        assert!(s.is_file("/d/x/y/z"));
    }

    #[test]
    fn append_put_keeps_created() {
        let mut s = Inner::default();
        put(&mut s, "/a", b"hi");
        let created = s.files["/a"].created;
        s.put("/a", Bytes::from_static(b"!!"), WriteMode::Append).unwrap();
        assert_eq!(&s.files["/a"].data[..], b"hi!!");
        assert_eq!(s.files["/a"].created, created);
        s.put("/new", Bytes::from_static(b"x"), WriteMode::Append).unwrap();
        assert_eq!(&s.files["/new"].data[..], b"x");
    }

    #[test]
    fn timestamps_have_microsecond_resolution() {
        let t = now();
        let d = t.duration_since(UNIX_EPOCH).unwrap();
        assert_eq!(d.subsec_nanos() % 1000, 0);
        let ts = timestamp(t);
        assert!((ts - d.as_secs_f64()).abs() < 1e-5);
    }

    #[derive(Debug, Clone)]
    enum Op {
        Put(usize, u8),
        Rm(usize),
        Mkdir(usize),
        Rmdir(usize),
        Cp(usize, usize),
        Mv(usize, usize),
    }

    const UNIVERSE: [&str; 8] = ["/a", "/a/b", "/a/b/c", "/a/d", "/e", "/e/f", "/g/h/i", "/a/b/j"];

    fn op() -> impl Strategy<Value = Op> {
        let i = 0..UNIVERSE.len();
        prop_oneof![
            (i.clone(), any::<u8>()).prop_map(|(p, b)| Op::Put(p, b)),
            i.clone().prop_map(Op::Rm),
            i.clone().prop_map(Op::Mkdir),
            i.clone().prop_map(Op::Rmdir),
            (i.clone(), i.clone()).prop_map(|(a, b)| Op::Cp(a, b)),
            (i.clone(), i).prop_map(|(a, b)| Op::Mv(a, b)),
        ]
    }

    proptest! {
        /// Whatever sequence of operations runs, the listings stay consistent:
        /// find("") lists exactly the stored files, every listed entry exists
        /// with a matching type, and every file's parent lists it.
        #[test]
        fn listings_stay_consistent(ops in proptest::collection::vec(op(), 0..40)) {
            let mut s = Inner::default();
            for op in ops {
                let _ = match op {
                    Op::Put(p, b) => s.put(UNIVERSE[p], Bytes::from(vec![b; usize::from(b) % 7]), WriteMode::Overwrite),
                    Op::Rm(p) => s.rm_file(UNIVERSE[p]),
                    Op::Mkdir(p) => s.mkdir(UNIVERSE[p], true),
                    Op::Rmdir(p) => s.rmdir(UNIVERSE[p]),
                    Op::Cp(a, b) => s.cp_file(UNIVERSE[a], UNIVERSE[b]),
                    Op::Mv(a, b) => s.mv(UNIVERSE[a], UNIVERSE[b]),
                };
            }
            let files = s.find("", &FindOptions::default()).unwrap();
            let mut expected: Vec<&str> = s.files.keys().map(String::as_str).collect();
            expected.sort();
            prop_assert_eq!(names(&files), expected);
            let everything = s.find("", &FindOptions { maxdepth: None, withdirs: true }).unwrap();
            for e in &everything {
                let info = s.info(&e.name).unwrap();
                if e.is_dir() {
                    prop_assert!(info.is_dir(), "{} listed as dir", e.name);
                } else {
                    prop_assert_eq!(info.size, e.size);
                }
                // fsspec's ls() of a path that is (also) a file returns just
                // the file, so only check parents that are not files.
                let parent = &e.name[..e.name.rfind('/').unwrap()];
                if !s.is_file(parent) {
                    let listing = s.ls(parent).unwrap();
                    prop_assert!(listing.iter().any(|l| l.name == e.name), "{} missing from ls({})", e.name, parent);
                }
            }
        }
    }
}
