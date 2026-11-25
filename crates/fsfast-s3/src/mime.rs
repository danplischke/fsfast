//! Content-type guessing for `put_file`, as s3fs does with Python's
//! `mimetypes.guess_type` (built-in tables only; the system's `mime.types`
//! files are not read, so results do not depend on the machine).

use std::path::Path;

#[path = "mime_table.rs"]
mod table;

/// Python's `posixpath.splitext` on a file name: `(root, ext)` with leading
/// dots not counting as an extension separator.
fn splitext(name: &str) -> (&str, &str) {
    let leading = name.len() - name.trim_start_matches('.').len();
    match name[leading..].rfind('.') {
        Some(i) => name.split_at(leading + i),
        None => (name, ""),
    }
}

/// The MIME type Python's `mimetypes.guess_type` gives `path`.
pub(crate) fn guess(path: &Path) -> Option<&'static str> {
    let mut name = path.file_name()?.to_str()?.to_owned();
    // Abbreviations such as `.tgz` expand to `.tar.gz` (case-insensitive).
    loop {
        let (base, ext) = splitext(&name);
        let lower = ext.to_ascii_lowercase();
        match table::SUFFIXES.iter().find(|(s, _)| *s == lower) {
            Some((_, full)) => name = format!("{base}{full}"),
            None => break,
        }
    }
    let (base, ext) = splitext(&name);
    // Compression suffixes (case-sensitive, as in Python) are skipped.
    let ext = if table::ENCODINGS.contains(&ext) {
        splitext(base).1
    } else {
        ext
    };
    lookup(ext)
}

fn lookup(ext: &str) -> Option<&'static str> {
    let lower = ext.to_ascii_lowercase();
    table::TYPES
        .binary_search_by(|(e, _)| (*e).cmp(lower.as_str()))
        .ok()
        .map(|i| table::TYPES[i].1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_python_mimetypes() {
        for (name, want) in [
            ("a.csv.gz", Some("text/csv")),
            ("x.tgz", Some("application/x-tar")),
            ("x.TXT", Some("text/plain")),
            ("noext", None),
            ("a.json", Some("application/json")),
            ("a.parquet", None),
            ("a.tar.gz", Some("application/x-tar")),
            ("x.gz", None),
            (".bashrc", None),
            ("dir.d/file", None),
            ("photo.JPG", Some("image/jpeg")),
        ] {
            assert_eq!(guess(Path::new(name)), want, "{name}");
        }
        assert!(table::TYPES.windows(2).all(|w| w[0].0 < w[1].0));
    }
}
