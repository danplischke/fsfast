//! XML for the S3 and STS REST APIs.
//!
//! S3 responses use a small, regular subset of XML: no DTDs, no mixed
//! content, a default namespace on the root element. [`Element::parse`]
//! builds a tree of borrowed slices (element names and entity-free text
//! point into the response body; only text with entity references or CDATA
//! is copied), which is fast enough for listing pages of 1000 entries and
//! keeps the per-response parsers below straightforward.
//!
//! The tokenizer accepts the XML declaration, comments, processing
//! instructions, a DOCTYPE (skipped), CDATA sections, attributes (ignored),
//! namespace prefixes (stripped), the five predefined entities and numeric
//! character references. Malformed input is an error, never a panic.

use std::borrow::Cow;
use std::fmt::Write as _;
use std::time::SystemTime;

use fsfast_core::{Error, Result};

use crate::encode::{parse_iso8601, url_decode_plus};

/// A parsed XML element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element<'a> {
    /// Local name (namespace prefix removed).
    pub name: &'a str,
    /// Concatenated text content of this element (not of its children).
    pub text: Cow<'a, str>,
    /// Child elements in document order.
    pub children: Vec<Element<'a>>,
}

fn malformed(what: impl std::fmt::Display) -> Error {
    Error::protocol(format!("malformed XML response: {what}"))
}

/// Upper bound on element nesting, so hostile input cannot exhaust the stack
/// of the recursive descent (S3 documents are at most ~5 levels deep).
const MAX_DEPTH: usize = 64;

impl<'a> Element<'a> {
    /// Parse a whole document and return its root element.
    pub fn parse(src: &'a [u8]) -> Result<Element<'a>> {
        let src = std::str::from_utf8(src).map_err(|_| malformed("not UTF-8"))?;
        let src = src.strip_prefix('\u{feff}').unwrap_or(src);
        let mut p = Parser { src, pos: 0 };
        p.skip_misc()?;
        if !p.rest().starts_with('<') {
            return Err(malformed("no root element"));
        }
        let root = p.element(0)?;
        p.skip_misc()?;
        if p.pos != src.len() {
            return Err(malformed("content after the root element"));
        }
        Ok(root)
    }

    /// The first child named `name`.
    pub fn child(&self, name: &str) -> Option<&Element<'a>> {
        self.children.iter().find(|c| c.name == name)
    }

    /// All children named `name`.
    pub fn children_named<'s>(&'s self, name: &'s str) -> impl Iterator<Item = &'s Element<'a>> {
        self.children.iter().filter(move |c| c.name == name)
    }

    /// Text of the first child named `name`.
    pub fn child_text(&self, name: &str) -> Option<&str> {
        self.child(name).map(|c| c.text.as_ref())
    }

    /// Text of the first child named `name`, owned.
    pub fn child_string(&self, name: &str) -> Option<String> {
        self.child_text(name).map(str::to_owned)
    }

    /// Search depth-first for the first element named `name` (including
    /// `self`).
    pub fn find(&self, name: &str) -> Option<&Element<'a>> {
        if self.name == name {
            return Some(self);
        }
        self.children.iter().find_map(|c| c.find(name))
    }
}

struct Parser<'a> {
    src: &'a str,
    pos: usize,
}

impl<'a> Parser<'a> {
    fn rest(&self) -> &'a str {
        &self.src[self.pos..]
    }

    /// Skip whitespace, comments, processing instructions and a DOCTYPE.
    fn skip_misc(&mut self) -> Result<()> {
        loop {
            let r = self.rest();
            let trimmed = r.trim_start_matches(|c: char| c.is_ascii_whitespace());
            self.pos += r.len() - trimmed.len();
            let r = self.rest();
            if r.starts_with("<?") {
                self.skip_past("?>")?;
            } else if r.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if r.starts_with("<!DOCTYPE") || r.starts_with("<!doctype") {
                self.skip_doctype()?;
            } else {
                return Ok(());
            }
        }
    }

    fn skip_past(&mut self, end: &str) -> Result<()> {
        match self.rest().find(end) {
            Some(i) => {
                self.pos += i + end.len();
                Ok(())
            }
            None => Err(malformed(format_args!(
                "unterminated construct (missing {end:?})"
            ))),
        }
    }

    fn skip_doctype(&mut self) -> Result<()> {
        // Skip to the matching '>' (an internal subset in [...] may contain '>').
        let mut depth = 0i32;
        for (i, c) in self.rest().char_indices() {
            match c {
                '[' => depth += 1,
                ']' => depth -= 1,
                '>' if depth <= 0 => {
                    self.pos += i + 1;
                    return Ok(());
                }
                _ => {}
            }
        }
        Err(malformed("unterminated DOCTYPE"))
    }

    /// Parse an element starting at `<`.
    fn element(&mut self, depth: usize) -> Result<Element<'a>> {
        if depth > MAX_DEPTH {
            return Err(malformed("elements nested too deeply"));
        }
        debug_assert!(self.rest().starts_with('<'));
        self.pos += 1;
        let qname = self.name()?;
        let name = local(qname);
        // Attributes until '>' or '/>'.
        let self_closing = loop {
            let r = self.rest();
            let t = r.trim_start_matches(|c: char| c.is_ascii_whitespace());
            self.pos += r.len() - t.len();
            if t.starts_with("/>") {
                self.pos += 2;
                break true;
            }
            if t.starts_with('>') {
                self.pos += 1;
                break false;
            }
            if t.is_empty() {
                return Err(malformed("unterminated start tag"));
            }
            self.attribute()?;
        };
        let mut el = Element {
            name,
            text: Cow::Borrowed(""),
            children: Vec::new(),
        };
        if self_closing {
            return Ok(el);
        }
        loop {
            let r = self.rest();
            if r.is_empty() {
                return Err(malformed(format_args!("unterminated element <{qname}>")));
            }
            if let Some(after) = r.strip_prefix("</") {
                let end = after
                    .find('>')
                    .ok_or_else(|| malformed("unterminated end tag"))?;
                let close = after[..end].trim_end();
                if close != qname {
                    return Err(malformed(format_args!(
                        "mismatched end tag </{close}> for <{qname}>"
                    )));
                }
                self.pos += 2 + end + 1;
                return Ok(el);
            }
            if r.starts_with("<!--") {
                self.skip_past("-->")?;
            } else if r.starts_with("<?") {
                self.skip_past("?>")?;
            } else if let Some(after) = r.strip_prefix("<![CDATA[") {
                let end = after
                    .find("]]>")
                    .ok_or_else(|| malformed("unterminated CDATA section"))?;
                append(&mut el.text, Cow::Borrowed(&after[..end]));
                self.pos += 9 + end + 3;
            } else if r.starts_with('<') {
                let child = self.element(depth + 1)?;
                el.children.push(child);
            } else {
                let end = r.find('<').unwrap_or(r.len());
                let raw = &r[..end];
                self.pos += end;
                if !el.children.is_empty() && raw.trim().is_empty() {
                    // Indentation between child elements.
                    continue;
                }
                append(&mut el.text, unescape(raw)?);
            }
        }
    }

    fn name(&mut self) -> Result<&'a str> {
        let r = self.rest();
        let end = r
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, '>' | '/' | '='))
            .unwrap_or(r.len());
        if end == 0 {
            return Err(malformed("empty element or attribute name"));
        }
        self.pos += end;
        Ok(&r[..end])
    }

    fn attribute(&mut self) -> Result<()> {
        self.name()?;
        let r = self.rest();
        let t = r.trim_start_matches(|c: char| c.is_ascii_whitespace());
        self.pos += r.len() - t.len();
        let t = self
            .rest()
            .strip_prefix('=')
            .ok_or_else(|| malformed("attribute without value"))?;
        self.pos += 1;
        let t2 = t.trim_start_matches(|c: char| c.is_ascii_whitespace());
        self.pos += t.len() - t2.len();
        let quote = t2
            .chars()
            .next()
            .filter(|c| *c == '"' || *c == '\'')
            .ok_or_else(|| malformed("unquoted attribute value"))?;
        let end = t2[1..]
            .find(quote)
            .ok_or_else(|| malformed("unterminated attribute value"))?;
        self.pos += 1 + end + 1;
        Ok(())
    }
}

fn local(qname: &str) -> &str {
    match qname.rfind(':') {
        Some(i) => &qname[i + 1..],
        None => qname,
    }
}

fn append<'a>(text: &mut Cow<'a, str>, more: Cow<'a, str>) {
    if text.is_empty() {
        *text = more;
    } else {
        text.to_mut().push_str(&more);
    }
}

/// Decode entity and character references.
pub fn unescape(raw: &str) -> Result<Cow<'_, str>> {
    if !raw.contains('&') {
        return Ok(Cow::Borrowed(raw));
    }
    let mut out = String::with_capacity(raw.len());
    let mut rest = raw;
    while let Some(i) = rest.find('&') {
        out.push_str(&rest[..i]);
        let after = &rest[i + 1..];
        let end = after
            .find(';')
            .filter(|&e| e <= 12)
            .ok_or_else(|| malformed("unterminated entity reference"))?;
        let ent = &after[..end];
        let c = match ent {
            "amp" => '&',
            "lt" => '<',
            "gt" => '>',
            "quot" => '"',
            "apos" => '\'',
            _ => {
                let code =
                    if let Some(h) = ent.strip_prefix("#x").or_else(|| ent.strip_prefix("#X")) {
                        u32::from_str_radix(h, 16).ok()
                    } else if let Some(d) = ent.strip_prefix('#') {
                        d.parse::<u32>().ok()
                    } else {
                        None
                    };
                code.and_then(char::from_u32)
                    .ok_or_else(|| malformed(format_args!("unknown entity &{ent};")))?
            }
        };
        out.push(c);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(Cow::Owned(out))
}

/// Escape text for element content. Characters XML 1.0 cannot carry
/// (control characters other than tab/LF/CR) are written as character
/// references, which S3 accepts in object keys (as the S3 documentation on
/// XML-unsafe key characters recommends).
pub fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' => out.push(c),
            '\r' => out.push_str("&#13;"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "&#{};", c as u32);
            }
            c => out.push(c),
        }
    }
}

// ---------------------------------------------------------------------------
// Response types.

/// The owner of an object (`Owner` in listings).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Owner {
    /// `DisplayName`, if returned.
    pub display_name: Option<String>,
    /// `ID`, if returned.
    pub id: Option<String>,
}

/// `RestoreStatus` of an archived object in listings.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RestoreStatus {
    /// `IsRestoreInProgress`.
    pub in_progress: Option<bool>,
    /// `RestoreExpiryDate`.
    pub expiry: Option<SystemTime>,
}

/// One object (or object version) in a listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObjectEntry {
    /// Object key (URL-decoded if the listing was URL-encoded).
    pub key: String,
    /// `LastModified`.
    pub last_modified: Option<SystemTime>,
    /// `ETag` as sent (with quotes).
    pub etag: Option<String>,
    /// `Size`.
    pub size: u64,
    /// `StorageClass`, if returned.
    pub storage_class: Option<String>,
    /// `ChecksumAlgorithm` values (a flattened list in the XML).
    pub checksum_algorithms: Vec<String>,
    /// `ChecksumType`, if returned.
    pub checksum_type: Option<String>,
    /// `Owner`, if returned.
    pub owner: Option<Owner>,
    /// `RestoreStatus`, if returned.
    pub restore_status: Option<RestoreStatus>,
    /// `VersionId` (version listings only).
    pub version_id: Option<String>,
    /// `IsLatest` (version listings only).
    pub is_latest: Option<bool>,
}

/// A delete marker in a version listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DeleteMarker {
    /// Object key.
    pub key: String,
    /// `VersionId`.
    pub version_id: Option<String>,
    /// `IsLatest`.
    pub is_latest: bool,
    /// `LastModified`.
    pub last_modified: Option<SystemTime>,
}

/// One page of `ListObjectsV2` or `ListObjectVersions`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListPage {
    /// Objects (`Contents`) or object versions (`Version`).
    pub objects: Vec<ObjectEntry>,
    /// `DeleteMarker` entries (version listings).
    pub delete_markers: Vec<DeleteMarker>,
    /// `CommonPrefixes/Prefix` values, with the trailing delimiter.
    pub prefixes: Vec<String>,
    /// `IsTruncated`.
    pub is_truncated: bool,
    /// `NextContinuationToken` (V2).
    pub next_continuation_token: Option<String>,
    /// `NextKeyMarker` (versions).
    pub next_key_marker: Option<String>,
    /// `NextVersionIdMarker` (versions).
    pub next_version_id_marker: Option<String>,
    /// `KeyCount` (V2).
    pub key_count: Option<u64>,
}

fn parse_bool(s: &str) -> Option<bool> {
    match s.trim() {
        "true" | "True" | "TRUE" => Some(true),
        "false" | "False" | "FALSE" => Some(false),
        _ => None,
    }
}

fn parse_u64(s: &str, what: &str) -> Result<u64> {
    s.trim()
        .parse()
        .map_err(|_| malformed(format_args!("bad {what} {s:?}")))
}

fn object_entry(el: &Element<'_>, url_encoded: bool) -> Result<ObjectEntry> {
    let decode = |s: &str| -> String {
        if url_encoded {
            url_decode_plus(s).into_owned()
        } else {
            s.to_owned()
        }
    };
    let key = el
        .child_text("Key")
        .ok_or_else(|| malformed("listing entry without Key"))?;
    let mut e = ObjectEntry {
        key: decode(key),
        ..ObjectEntry::default()
    };
    for c in &el.children {
        match c.name {
            "LastModified" => e.last_modified = parse_iso8601(&c.text),
            "ETag" => e.etag = Some(c.text.to_string()),
            "Size" => e.size = parse_u64(&c.text, "Size")?,
            "StorageClass" => e.storage_class = Some(c.text.to_string()),
            "ChecksumAlgorithm" => e.checksum_algorithms.push(c.text.to_string()),
            "ChecksumType" => e.checksum_type = Some(c.text.to_string()),
            "Owner" => {
                e.owner = Some(Owner {
                    display_name: c.child_string("DisplayName"),
                    id: c.child_string("ID"),
                })
            }
            "RestoreStatus" => {
                e.restore_status = Some(RestoreStatus {
                    in_progress: c.child_text("IsRestoreInProgress").and_then(parse_bool),
                    expiry: c.child_text("RestoreExpiryDate").and_then(parse_iso8601),
                })
            }
            "VersionId" => e.version_id = Some(c.text.to_string()),
            "IsLatest" => e.is_latest = parse_bool(&c.text),
            _ => {}
        }
    }
    Ok(e)
}

impl ListPage {
    /// Parse a `ListBucketResult` (V2) or `ListVersionsResult` body.
    pub fn parse(body: &[u8]) -> Result<ListPage> {
        let root = Element::parse(body)?;
        if root.name != "ListBucketResult" && root.name != "ListVersionsResult" {
            return Err(malformed(format_args!(
                "expected a listing, got <{}>",
                root.name
            )));
        }
        // botocore decodes URL-encoded fields only when the response says
        // it used the encoding (servers may ignore `encoding-type`).
        let url_encoded = root
            .child_text("EncodingType")
            .is_some_and(|t| t.eq_ignore_ascii_case("url"));
        let decode = |s: &str| -> String {
            if url_encoded {
                url_decode_plus(s).into_owned()
            } else {
                s.to_owned()
            }
        };
        let mut page = ListPage::default();
        for c in &root.children {
            match c.name {
                "Contents" | "Version" => page.objects.push(object_entry(c, url_encoded)?),
                "DeleteMarker" => page.delete_markers.push(DeleteMarker {
                    key: decode(c.child_text("Key").unwrap_or("")),
                    version_id: c.child_string("VersionId"),
                    is_latest: c
                        .child_text("IsLatest")
                        .and_then(parse_bool)
                        .unwrap_or(false),
                    last_modified: c.child_text("LastModified").and_then(parse_iso8601),
                }),
                "CommonPrefixes" => {
                    if let Some(p) = c.child_text("Prefix") {
                        page.prefixes.push(decode(p));
                    }
                }
                "IsTruncated" => page.is_truncated = parse_bool(&c.text).unwrap_or(false),
                "NextContinuationToken" => page.next_continuation_token = Some(c.text.to_string()),
                "NextKeyMarker" => page.next_key_marker = Some(decode(&c.text)),
                "NextVersionIdMarker" => page.next_version_id_marker = Some(c.text.to_string()),
                "KeyCount" => page.key_count = c.text.trim().parse().ok(),
                _ => {}
            }
        }
        Ok(page)
    }
}

/// One bucket from `ListBuckets`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BucketEntry {
    /// `Name`.
    pub name: String,
    /// `CreationDate`.
    pub creation_date: Option<SystemTime>,
    /// `BucketRegion` (AWS, recent API versions).
    pub region: Option<String>,
}

/// `ListAllMyBucketsResult`: the buckets and the continuation token.
pub fn parse_list_buckets(body: &[u8]) -> Result<(Vec<BucketEntry>, Option<String>)> {
    let root = Element::parse(body)?;
    if root.name != "ListAllMyBucketsResult" {
        return Err(malformed(format_args!(
            "expected ListAllMyBucketsResult, got <{}>",
            root.name
        )));
    }
    let mut out = Vec::new();
    if let Some(buckets) = root.child("Buckets") {
        for b in buckets.children_named("Bucket") {
            let Some(name) = b.child_text("Name") else {
                continue;
            };
            out.push(BucketEntry {
                name: name.to_owned(),
                creation_date: b.child_text("CreationDate").and_then(parse_iso8601),
                region: b.child_string("BucketRegion"),
            });
        }
    }
    let token = root
        .child_text("ContinuationToken")
        .filter(|t| !t.is_empty())
        .map(str::to_owned);
    Ok((out, token))
}

/// An S3 (or STS) error document.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct S3ErrorDoc {
    /// `Code`.
    pub code: Option<String>,
    /// `Message`.
    pub message: Option<String>,
    /// `Region` (wrong-region errors).
    pub region: Option<String>,
    /// `Condition` (`PreconditionFailed`: which header failed).
    pub condition: Option<String>,
    /// `Endpoint` (`PermanentRedirect`).
    pub endpoint: Option<String>,
}

impl S3ErrorDoc {
    /// Parse `<Error>...</Error>` (S3) or `<ErrorResponse><Error>...` (STS).
    /// `None` if the body is not such a document.
    pub fn parse(body: &[u8]) -> Option<S3ErrorDoc> {
        let root = Element::parse(body).ok()?;
        let err = if root.name == "Error" {
            &root
        } else {
            root.find("Error")?
        };
        Some(S3ErrorDoc {
            code: err.child_string("Code").filter(|c| !c.is_empty()),
            message: err.child_string("Message"),
            region: err.child_string("Region").filter(|c| !c.is_empty()),
            condition: err.child_string("Condition"),
            endpoint: err.child_string("Endpoint"),
        })
    }
}

/// `UploadId` of an `InitiateMultipartUploadResult`.
pub fn parse_upload_id(body: &[u8]) -> Result<String> {
    let root = Element::parse(body)?;
    root.child_string("UploadId")
        .filter(|u| !u.is_empty())
        .ok_or_else(|| malformed("InitiateMultipartUploadResult without UploadId"))
}

/// The `ETag` of a `CopyObjectResult`, `CopyPartResult` or
/// `CompleteMultipartUploadResult`; `Err` with the parsed error if the
/// (HTTP 200) body is an `<Error>` document instead.
pub fn parse_result_etag(body: &[u8]) -> std::result::Result<Option<String>, S3ErrorDoc> {
    match Element::parse(body) {
        Ok(root) if root.name == "Error" => Err(S3ErrorDoc::parse(body).unwrap_or_default()),
        Ok(root) => Ok(root.child_string("ETag")),
        // Some servers send whitespace keep-alives and nothing else on
        // success; a missing body is not an error.
        Err(_) if body.iter().all(u8::is_ascii_whitespace) => Ok(None),
        Err(_) => Err(S3ErrorDoc {
            code: Some("MalformedResponse".into()),
            message: Some("unparseable result document".into()),
            ..S3ErrorDoc::default()
        }),
    }
}

/// One entry of a `DeleteResult`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeleteOutcome {
    /// The key was deleted (or did not exist).
    Deleted {
        /// Object key.
        key: String,
    },
    /// The key could not be deleted.
    Failed {
        /// Object key.
        key: String,
        /// Error code.
        code: String,
        /// Error message.
        message: String,
    },
}

/// Parse a `DeleteResult` (`DeleteObjects` response).
pub fn parse_delete_result(body: &[u8]) -> Result<Vec<DeleteOutcome>> {
    let root = Element::parse(body)?;
    if root.name == "Error" {
        let doc = S3ErrorDoc::parse(body).unwrap_or_default();
        return Err(Error::new(
            fsfast_core::ErrorKind::Io,
            format!(
                "DeleteObjects failed: {} {}",
                doc.code.unwrap_or_default(),
                doc.message.unwrap_or_default()
            ),
        ));
    }
    let mut out = Vec::new();
    for c in &root.children {
        match c.name {
            "Deleted" => out.push(DeleteOutcome::Deleted {
                key: c.child_string("Key").unwrap_or_default(),
            }),
            "Error" => out.push(DeleteOutcome::Failed {
                key: c.child_string("Key").unwrap_or_default(),
                code: c.child_string("Code").unwrap_or_default(),
                message: c.child_string("Message").unwrap_or_default(),
            }),
            _ => {}
        }
    }
    Ok(out)
}

/// `Status` of a `VersioningConfiguration` (empty if never enabled).
pub fn parse_versioning_status(body: &[u8]) -> Result<String> {
    let root = Element::parse(body)?;
    Ok(root.child_string("Status").unwrap_or_default())
}

/// Temporary credentials from an STS response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StsCredentials {
    /// `AccessKeyId`.
    pub access_key_id: String,
    /// `SecretAccessKey`.
    pub secret_access_key: String,
    /// `SessionToken`.
    pub session_token: String,
    /// `Expiration`.
    pub expiration: Option<SystemTime>,
}

/// Parse the `Credentials` element of `AssumeRole[WithWebIdentity]Response`.
pub fn parse_sts_credentials(body: &[u8]) -> Result<StsCredentials> {
    let root = Element::parse(body)?;
    let c = root
        .find("Credentials")
        .ok_or_else(|| malformed("STS response without Credentials"))?;
    let get = |n: &str| -> Result<String> {
        c.child_string(n)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| malformed(format_args!("STS credentials without {n}")))
    };
    Ok(StsCredentials {
        access_key_id: get("AccessKeyId")?,
        secret_access_key: get("SecretAccessKey")?,
        session_token: get("SessionToken")?,
        expiration: c.child_text("Expiration").and_then(parse_iso8601),
    })
}

/// One object to delete in a `DeleteObjects` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteTarget<'a> {
    /// Object key.
    pub key: &'a str,
    /// Specific version to delete.
    pub version_id: Option<&'a str>,
}

/// The `Delete` document of a `DeleteObjects` request (quiet mode: only
/// failures are reported back).
pub fn delete_objects_body(objects: &[DeleteTarget<'_>]) -> String {
    let mut out = String::with_capacity(64 + objects.len() * 64);
    out.push_str(r#"<?xml version="1.0" encoding="UTF-8"?><Delete xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Quiet>true</Quiet>"#);
    for o in objects {
        out.push_str("<Object><Key>");
        escape_into(&mut out, o.key);
        out.push_str("</Key>");
        if let Some(v) = o.version_id {
            out.push_str("<VersionId>");
            escape_into(&mut out, v);
            out.push_str("</VersionId>");
        }
        out.push_str("</Object>");
    }
    out.push_str("</Delete>");
    out
}

/// The `CompleteMultipartUpload` document.
pub fn complete_multipart_body<'a>(parts: impl IntoIterator<Item = (u32, &'a str)>) -> String {
    let mut out = String::from(
        r#"<?xml version="1.0" encoding="UTF-8"?><CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">"#,
    );
    for (n, etag) in parts {
        let _ = write!(out, "<Part><PartNumber>{n}</PartNumber><ETag>");
        escape_into(&mut out, etag);
        out.push_str("</ETag></Part>");
    }
    out.push_str("</CompleteMultipartUpload>");
    out
}

/// The `CreateBucketConfiguration` document for a location constraint.
pub fn create_bucket_body(region: &str) -> String {
    let mut out = String::from(
        r#"<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><LocationConstraint>"#,
    );
    escape_into(&mut out, region);
    out.push_str("</LocationConstraint></CreateBucketConfiguration>");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>bucket</Name><Prefix>a%2F</Prefix><KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys>
  <Delimiter>%2F</Delimiter><EncodingType>url</EncodingType><IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents>
    <Key>a%2Fb+c%26d.txt</Key><LastModified>2026-11-24T17:27:28.311Z</LastModified>
    <ETag>&quot;6057f13c496ecf7fd777ceb9e79ae285&quot;</ETag>
    <ChecksumAlgorithm>CRC32</ChecksumAlgorithm><ChecksumAlgorithm>CRC64NVME</ChecksumAlgorithm>
    <ChecksumType>FULL_OBJECT</ChecksumType>
    <Size>3</Size><Owner><ID>abc</ID><DisplayName>me</DisplayName></Owner>
    <StorageClass>STANDARD</StorageClass>
    <RestoreStatus><IsRestoreInProgress>false</IsRestoreInProgress><RestoreExpiryDate>2026-12-01T00:00:00.000Z</RestoreExpiryDate></RestoreStatus>
  </Contents>
  <Contents><Key><![CDATA[a%2Fcdata]]></Key><Size>0</Size></Contents>
  <CommonPrefixes><Prefix>a%2Fsub%2F</Prefix></CommonPrefixes>
  <!-- a comment -->
</ListBucketResult>"#;

    #[test]
    fn parses_url_encoded_listing() {
        let p = ListPage::parse(LIST.as_bytes()).unwrap();
        assert!(p.is_truncated);
        assert_eq!(
            p.next_continuation_token.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
        );
        assert_eq!(p.key_count, Some(3));
        assert_eq!(p.objects.len(), 2);
        let o = &p.objects[0];
        assert_eq!(o.key, "a/b c&d.txt");
        assert_eq!(
            o.etag.as_deref(),
            Some("\"6057f13c496ecf7fd777ceb9e79ae285\"")
        );
        assert_eq!(o.size, 3);
        assert_eq!(o.checksum_algorithms, vec!["CRC32", "CRC64NVME"]);
        assert_eq!(o.checksum_type.as_deref(), Some("FULL_OBJECT"));
        assert_eq!(
            o.owner.as_ref().unwrap().display_name.as_deref(),
            Some("me")
        );
        assert_eq!(o.restore_status.as_ref().unwrap().in_progress, Some(false));
        assert!(o.last_modified.is_some());
        assert_eq!(p.objects[1].key, "a/cdata");
        assert_eq!(p.prefixes, vec!["a/sub/"]);
    }

    #[test]
    fn plain_listing_is_not_decoded() {
        let body = r#"<ListBucketResult><Contents><Key>a+b%20c</Key><Size>1</Size></Contents></ListBucketResult>"#;
        let p = ListPage::parse(body.as_bytes()).unwrap();
        assert_eq!(p.objects[0].key, "a+b%20c");
    }

    #[test]
    fn parses_versions() {
        let body = r#"<ListVersionsResult><IsTruncated>false</IsTruncated>
<NextKeyMarker>k+1</NextKeyMarker><EncodingType>url</EncodingType>
<Version><Key>k</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><Size>2</Size></Version>
<Version><Key>k</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest><Size>1</Size></Version>
<DeleteMarker><Key>gone</Key><VersionId>d1</VersionId><IsLatest>true</IsLatest></DeleteMarker>
</ListVersionsResult>"#;
        let p = ListPage::parse(body.as_bytes()).unwrap();
        assert_eq!(p.objects.len(), 2);
        assert_eq!(p.objects[0].is_latest, Some(true));
        assert_eq!(p.objects[1].version_id.as_deref(), Some("v1"));
        assert_eq!(p.delete_markers[0].key, "gone");
        assert_eq!(p.next_key_marker.as_deref(), Some("k 1"));
    }

    #[test]
    fn parses_errors_and_results() {
        let e = S3ErrorDoc::parse(
            br#"<?xml version="1.0"?><Error><Code>AuthorizationHeaderMalformed</Code><Message>bad region</Message><Region>eu-west-1</Region></Error>"#,
        )
        .unwrap();
        assert_eq!(e.code.as_deref(), Some("AuthorizationHeaderMalformed"));
        assert_eq!(e.region.as_deref(), Some("eu-west-1"));
        let sts = S3ErrorDoc::parse(
            br#"<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><Error><Type>Sender</Type><Code>AccessDenied</Code><Message>no</Message></Error></ErrorResponse>"#,
        )
        .unwrap();
        assert_eq!(sts.code.as_deref(), Some("AccessDenied"));
        assert!(S3ErrorDoc::parse(b"not xml").is_none());
        assert_eq!(
            parse_result_etag(b"<CopyObjectResult><ETag>&quot;x&quot;</ETag></CopyObjectResult>"),
            Ok(Some("\"x\"".into()))
        );
        assert!(parse_result_etag(b"<Error><Code>InternalError</Code></Error>").is_err());
        assert_eq!(parse_result_etag(b"   \n "), Ok(None));
        let d = parse_delete_result(
            b"<DeleteResult><Deleted><Key>a</Key></Deleted><Error><Key>b</Key><Code>AccessDenied</Code><Message>m</Message></Error></DeleteResult>",
        )
        .unwrap();
        assert_eq!(d.len(), 2);
        assert_eq!(
            parse_upload_id(b"<InitiateMultipartUploadResult><UploadId>u1</UploadId></InitiateMultipartUploadResult>").unwrap(),
            "u1"
        );
    }

    #[test]
    fn builds_documents() {
        let body = delete_objects_body(&[
            DeleteTarget {
                key: "a&b<c>",
                version_id: None,
            },
            DeleteTarget {
                key: "ctl\u{1}",
                version_id: Some("v"),
            },
        ]);
        assert!(body.contains("<Key>a&amp;b&lt;c&gt;</Key>"));
        assert!(body.contains("<Key>ctl&#1;</Key><VersionId>v</VersionId>"));
        // Our own documents parse back.
        let root = Element::parse(body.as_bytes()).unwrap();
        assert_eq!(root.children_named("Object").count(), 2);
        let c = complete_multipart_body([(1, "\"e1\""), (2, "\"e2\"")]);
        assert!(c.contains("<Part><PartNumber>2</PartNumber><ETag>&quot;e2&quot;</ETag></Part>"));
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            "",
            "<a>",
            "<a></b>",
            "<a><b></a>",
            "<a x=1></a>",
            "<a>&bogus;</a>",
            "<a></a><b/>",
            "<a>&#xD800;</a>",
            "<!-- unterminated",
        ] {
            assert!(Element::parse(bad.as_bytes()).is_err(), "{bad:?}");
        }
        let deep = "<a>".repeat(100) + &"</a>".repeat(100);
        assert!(Element::parse(deep.as_bytes()).is_err());
    }

    #[test]
    fn parses_sts() {
        let body = br#"<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
<AssumeRoleResult><Credentials><AccessKeyId>ASIA</AccessKeyId><SecretAccessKey>s</SecretAccessKey>
<SessionToken>t</SessionToken><Expiration>2026-11-24T13:34:56Z</Expiration></Credentials></AssumeRoleResult>
</AssumeRoleResponse>"#;
        let c = parse_sts_credentials(body).unwrap();
        assert_eq!(c.access_key_id, "ASIA");
        assert!(c.expiration.is_some());
    }

    proptest::proptest! {
        #[test]
        fn never_panics(data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512)) {
            let _ = Element::parse(&data);
            let _ = ListPage::parse(&data);
            let _ = S3ErrorDoc::parse(&data);
        }

        #[test]
        fn escaped_text_roundtrips(s in "\\PC{0,40}") {
            let mut doc = String::from("<k>");
            escape_into(&mut doc, &s);
            doc.push_str("</k>");
            let el = Element::parse(doc.as_bytes()).unwrap();
            // Whitespace-only text next to no children is kept as is.
            proptest::prop_assert_eq!(el.text.as_ref(), s.as_str());
        }
    }
}
