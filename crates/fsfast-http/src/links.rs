//! Directory listings scraped from HTML pages, exactly like fsspec's
//! `HTTPFileSystem._ls_real`.
//!
//! * The page is decoded like aiohttp's `text(errors="ignore")`: the
//!   `charset` of `Content-Type` (Python codec names), UTF-8 otherwise;
//!   undecodable bytes are dropped.
//! * Links are found with fsspec's two regexes. The `href` regex is always
//!   used; with `simple_links` (the default) anything that looks like an
//!   `http(s)://` URL counts too. Python's `\s` also matches U+001C..U+001F,
//!   which Rust's does not, so the class is spelled out.
//! * Links are resolved with fsspec's string rules, not RFC 3986: a link
//!   starting with `/` is made absolute on the page's server; links starting
//!   with `http` are kept only if they lie below the page URL; anything else
//!   is appended to the page URL after a `/` (`..` and `../` are ignored).
//!   `same_scheme` is implemented literally: fsspec's fallback branch also
//!   accepts the other scheme, so the option has no visible effect there
//!   either.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::LazyLock;

use regex::Regex;

/// fsspec `ex`: `<a ... href="url"`.
static HREF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<(a|A)[\s\x1C-\x1F]+(?:[^>]*?[\s\x1C-\x1F]+)?(href|HREF)=["'](?P<url>[^"']+)"#)
        .expect("valid regex")
});

/// fsfspec `ex2`: bare `http(s)://...` URLs.
static SIMPLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?P<url>http[s]?://[-a-zA-Z0-9@:%_+.~#?&/=]+)").expect("valid regex")
});

/// All link targets in `text`, in fsspec's order (bare URLs first when
/// `simple_links`, then `href` targets). Duplicates are kept.
pub fn extract_links(text: &str, simple_links: bool) -> Vec<&str> {
    let mut out = Vec::new();
    if simple_links {
        out.extend(SIMPLE.find_iter(text).map(|m| m.as_str()));
    }
    out.extend(
        HREF.captures_iter(text)
            .filter_map(|c| c.name("url").map(|m| m.as_str())),
    );
    out
}

/// Python's `urlparse(url)` scheme (lower-cased) and netloc, as fsspec uses
/// them to absolutize `/path` links.
pub fn scheme_and_netloc(url: &str) -> (String, String) {
    // urlsplit strips leading C0 controls/spaces and removes tabs/newlines.
    let cleaned: String = url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(c, '\t' | '\r' | '\n'))
        .collect();
    let mut rest = cleaned.as_str();
    let mut scheme = String::new();
    if let Some(i) = rest.find(':') {
        let cand = &rest[..i];
        let valid = cand.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
            && cand
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if valid {
            scheme = cand.to_ascii_lowercase();
            rest = &rest[i + 1..];
        }
    }
    let netloc = match rest.strip_prefix("//") {
        Some(r) => r[..r.find(['/', '?', '#']).unwrap_or(r.len())].to_owned(),
        None => String::new(),
    };
    (scheme, netloc)
}

/// Resolve scraped links against the page `url` with fsspec's rules (see
/// the module docs). Returns the set of child URLs.
pub fn resolve_links<'a>(
    url: &str,
    links: impl IntoIterator<Item = &'a str>,
    same_scheme: bool,
) -> BTreeSet<String> {
    let (scheme, netloc) = scheme_and_netloc(url);
    let base = url.trim_end_matches('/');
    let below = format!("{base}/");
    let below_http = format!("{}/", url.replace("https", "http").trim_end_matches('/'));
    let mut out = BTreeSet::new();
    for l in links {
        let l: Cow<'_, str> = if l.starts_with('/') && l.len() > 1 {
            Cow::Owned(format!("{scheme}://{netloc}{l}"))
        } else {
            Cow::Borrowed(l)
        };
        if l.starts_with("http") {
            if (same_scheme && l.starts_with(&below))
                || l.replace("https", "http").starts_with(&below_http)
            {
                out.insert(l.into_owned());
            }
        } else if l != ".." && l != "../" {
            out.insert(format!("{base}/{}", l.trim_start_matches('/')));
        }
    }
    out
}

/// Decode an HTML page like aiohttp's `ClientResponse.text(errors="ignore")`:
/// the `charset` parameter of `content_type` if Python knows it, else UTF-8;
/// invalid byte sequences are dropped.
pub fn decode_page<'a>(body: &'a [u8], content_type: Option<&str>) -> Cow<'a, str> {
    let charset = content_type.and_then(charset_param);
    match charset.as_deref().map(python_codec) {
        None | Some(Codec::Utf8) | Some(Codec::Unknown) => utf8_ignore(body),
        Some(Codec::Latin1) => Cow::Owned(body.iter().map(|&b| char::from(b)).collect()),
        Some(Codec::Ascii) => {
            if body.is_ascii() {
                utf8_ignore(body)
            } else {
                Cow::Owned(
                    body.iter()
                        .filter(|b| b.is_ascii())
                        .map(|&b| char::from(b))
                        .collect(),
                )
            }
        }
        Some(Codec::Other(enc)) => Cow::Owned(decode_ignore(enc, body)),
    }
}

/// UTF-8 with Python's `errors="ignore"`: both drop each maximal invalid
/// subsequence (Unicode's "maximal subpart" practice).
fn utf8_ignore(body: &[u8]) -> Cow<'_, str> {
    match std::str::from_utf8(body) {
        Ok(s) => Cow::Borrowed(s),
        Err(_) => {
            let mut out = String::with_capacity(body.len());
            for chunk in body.utf8_chunks() {
                out.push_str(chunk.valid());
            }
            Cow::Owned(out)
        }
    }
}

/// Decode with encoding_rs, dropping malformed sequences.
fn decode_ignore(enc: &'static encoding_rs::Encoding, body: &[u8]) -> String {
    let mut decoder = enc.new_decoder_without_bom_handling();
    let mut out = String::with_capacity(
        decoder
            .max_utf8_buffer_length_without_replacement(body.len())
            .unwrap_or(body.len() * 3),
    );
    let mut input = body;
    loop {
        let (result, read) = decoder.decode_to_string_without_replacement(input, &mut out, true);
        input = &input[read..];
        match result {
            encoding_rs::DecoderResult::InputEmpty => break,
            encoding_rs::DecoderResult::Malformed(_, _) => continue,
            encoding_rs::DecoderResult::OutputFull => {
                out.reserve(input.len() * 3 + 16);
            }
        }
    }
    out
}

/// The `charset` parameter, as aiohttp's `parse_mimetype` reads it from the
/// lower-cased header.
fn charset_param(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    lower.split(';').skip(1).find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim() == "charset").then(|| v.trim().trim_matches(|c| c == '"' || c == '\'').to_owned())
    })
}

enum Codec {
    Utf8,
    Latin1,
    Ascii,
    Other(&'static encoding_rs::Encoding),
    Unknown,
}

/// Map a charset label onto what Python's `codecs.lookup` would pick. Python
/// and WHATWG disagree on `latin-1` and `ascii` (WHATWG maps both to
/// windows-1252), so those are handled explicitly.
fn python_codec(label: &str) -> Codec {
    let norm: String = label
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c == '-' || c == ' ' { '_' } else { c })
        .collect();
    match norm.as_str() {
        "utf_8" | "utf8" | "u8" | "utf" | "cp65001" | "utf8_ucs2" | "utf8_ucs4" => Codec::Utf8,
        "latin_1" | "latin1" | "iso_8859_1" | "iso8859_1" | "8859" | "cp819" | "latin" | "l1"
        | "iso_8859_1:1987" | "iso_ir_100" | "csisolatin1" | "ibm819" => Codec::Latin1,
        "ascii" | "us_ascii" | "646" | "us" | "ansi_x3.4_1968" | "ansi_x3_4_1968"
        | "ansi_x3.4_1986" | "cp367" | "csascii" | "ibm367" | "iso646_us" | "iso_646.irv:1991"
        | "iso_ir_6" => Codec::Ascii,
        _ => match encoding_rs::Encoding::for_label(label.trim().as_bytes()) {
            Some(enc) if enc == encoding_rs::UTF_8 => Codec::Utf8,
            Some(enc) => Codec::Other(enc),
            // aiohttp falls back to UTF-8 when the codec is unknown.
            None => Codec::Unknown,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    proptest::proptest! {
        #[test]
        fn scraping_never_panics_and_stays_below_the_page(
            html in "(<a href=\"[a-z./?#:]{0,12}\">|[ -~]{0,8}|http://h/d/[a-z]{0,4}|\\PC{0,4})*",
            slash in proptest::bool::ANY,
        ) {
            let url = if slash { "http://h/d/" } else { "http://h/d" };
            for simple in [true, false] {
                let links = extract_links(&html, simple);
                for u in resolve_links(url, links.iter().copied(), true) {
                    // Every result is below the page (http/https may swap).
                    proptest::prop_assert!(
                        u.replace("https", "http").starts_with("http://h/d/"),
                        "{u}"
                    );
                }
            }
        }

        #[test]
        fn decoding_never_panics(body in proptest::collection::vec(proptest::num::u8::ANY, 0..64),
                                 cs in "(utf-8|latin-1|ascii|shift_jis|utf-16|bogus|)") {
            let ct = format!("text/html; charset={cs}");
            let _ = decode_page(&body, Some(&ct));
            let _ = decode_page(&body, None);
        }
    }

    #[test]
    fn extracts_like_fsspec() {
        let html = r#"<html><a href="a.txt">a</a> <A HREF='sub/'>s</A>
            <a class="x" href="/abs/b.bin">b</a> <a
            href="https://other.example/x">o</a> see http://h.example/p?q=1&r=2 here
            <link href="nope.css"> <a name="n">no href</a> <ahref="bad">
            <a  data-x='1'  href="c d.txt">c</a><a\x1chref="weird">w</a>"#;
        let html = html.replace("\\x1c", "\u{1c}");
        let links = extract_links(&html, true);
        assert_eq!(
            links,
            vec![
                "https://other.example/x",
                "http://h.example/p?q=1&r=2",
                "a.txt",
                "sub/",
                "/abs/b.bin",
                "https://other.example/x",
                "c d.txt",
                "weird",
            ]
        );
        let links = extract_links(&html, false);
        assert_eq!(links.len(), 6);
    }

    /// The separator class must be exactly Python's `\s` for `str`
    /// patterns: `[c for c in map(chr, range(0x110000)) if re.match(r"\s", c)]`
    /// (Python 3.13).
    #[test]
    fn href_whitespace_is_pythons_backslash_s() {
        let mut python: Vec<u32> = vec![0x85, 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f];
        python.extend(0x09..=0x0d);
        python.extend(0x1c..=0x20);
        python.extend(0x2000..=0x200a);
        python.push(0x3000);
        for cp in (0u32..0x3100).chain([0xfeff, 0xffff, 0x1_0000, 0x10_ffff]) {
            let Some(c) = char::from_u32(cp) else {
                continue;
            };
            let html = format!("<a{c}href=\"x\">");
            assert_eq!(
                extract_links(&html, false) == ["x"],
                python.contains(&cp),
                "U+{cp:04X}"
            );
        }
    }

    #[test]
    fn urlparse_scheme_and_netloc() {
        assert_eq!(
            scheme_and_netloc("HTTP://User@H:8/x?y#z"),
            ("http".into(), "User@H:8".into())
        );
        assert_eq!(scheme_and_netloc("http://h?q"), ("http".into(), "h".into()));
        assert_eq!(scheme_and_netloc("http:/x"), ("http".into(), String::new()));
        assert_eq!(
            scheme_and_netloc("https://[::1]:8/p"),
            ("https".into(), "[::1]:8".into())
        );
    }

    #[test]
    fn resolves_like_fsspec() {
        let url = "http://h.example/dir/";
        let links = [
            "a.txt",
            "sub/",
            "/dir/abs.bin",
            "/other/x",
            "/",
            "..",
            "../",
            "./",
            "http://h.example/dir/deep/f",
            "https://h.example/dir/cross",
            "http://h.example/dirt",
            "http://elsewhere/dir/x",
            "httpfoo.html",
            "?C=N;O=D",
            "//proto.relative/x",
        ];
        let out: Vec<String> = resolve_links(url, links, true).into_iter().collect();
        assert_eq!(
            out,
            vec![
                "http://h.example/dir/",
                "http://h.example/dir/./",
                "http://h.example/dir/?C=N;O=D",
                "http://h.example/dir/a.txt",
                "http://h.example/dir/abs.bin",
                "http://h.example/dir/deep/f",
                "http://h.example/dir/sub/",
                "https://h.example/dir/cross",
            ]
        );
        // same_scheme=False gives the same answer (fsspec's elif branch).
        let out2: Vec<String> = resolve_links(url, links, false).into_iter().collect();
        assert_eq!(out, out2);
        // A page without a trailing slash resolves relative links below it.
        let out: Vec<String> = resolve_links("https://h/x", ["y", "/x/z"], true)
            .into_iter()
            .collect();
        assert_eq!(out, vec!["https://h/x/y", "https://h/x/z"]);
    }

    #[test]
    fn decodes_like_aiohttp_text_ignore() {
        assert_eq!(decode_page(b"a\xffb\xe2\x82c", None), "abc");
        assert_eq!(
            decode_page(b"caf\xe9", Some("text/html; charset=ISO-8859-1")),
            "café"
        );
        // Python latin-1 maps 0x80..0x9f to C1 controls (not cp1252).
        assert_eq!(
            decode_page(b"\x80", Some("text/html; charset=latin-1")),
            "\u{80}"
        );
        assert_eq!(
            decode_page(b"\x80", Some("text/html; charset=\"windows-1252\"")),
            "\u{20ac}"
        );
        assert_eq!(
            decode_page(b"a\xe9b", Some("text/html;charset=us-ascii")),
            "ab"
        );
        assert_eq!(
            decode_page("ü".as_bytes(), Some("text/html; charset=no-such-codec")),
            "ü"
        );
        assert_eq!(
            decode_page(b"\x82\xa0", Some("text/html; charset=shift_jis")),
            "\u{3042}"
        );
    }
}
