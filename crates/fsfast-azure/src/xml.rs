//! XML for the Blob service REST API.
//!
//! Blob service responses use a small, regular subset of XML: no DTDs, no
//! mixed content. [`Element::parse`] builds a tree of borrowed slices
//! (element names, attribute values and entity-free text point into the
//! response body; only text with entity references or CDATA is copied),
//! which is fast enough for listing pages of 5000 entries.
//!
//! The tokenizer accepts the XML declaration, comments, processing
//! instructions, a DOCTYPE (skipped), CDATA sections, attributes (kept raw:
//! the service uses `Encoded="true"` on blob names), namespace prefixes
//! (stripped), the five predefined entities and numeric character
//! references. Malformed input is an error, never a panic.

use std::borrow::Cow;
use std::fmt::Write as _;

use fsfast_core::{Error, Result};

/// A parsed XML element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element<'a> {
    /// Local name (namespace prefix removed).
    pub name: &'a str,
    /// Attributes as `(local name, raw value)`; values are not unescaped
    /// (see [`Element::attr`]).
    pub attrs: Vec<(&'a str, &'a str)>,
    /// Concatenated text content of this element (not of its children).
    pub text: Cow<'a, str>,
    /// Child elements in document order.
    pub children: Vec<Element<'a>>,
}

fn malformed(what: impl std::fmt::Display) -> Error {
    Error::protocol(format!("malformed XML response: {what}"))
}

/// Upper bound on element nesting, so hostile input cannot exhaust the stack
/// of the recursive descent (Blob documents are at most ~6 levels deep).
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

    /// Text of the first child named `name`, `None` when absent or empty.
    pub fn child_nonempty(&self, name: &str) -> Option<&str> {
        self.child_text(name).filter(|t| !t.is_empty())
    }

    /// The unescaped value of attribute `name`.
    pub fn attr(&self, name: &str) -> Option<Cow<'a, str>> {
        self.attrs
            .iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| unescape(v).ok())
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
        self.pos += 1;
        let qname = self.name()?;
        let mut el = Element {
            name: local(qname),
            attrs: Vec::new(),
            text: Cow::Borrowed(""),
            children: Vec::new(),
        };
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
            let a = self.attribute()?;
            el.attrs.push(a);
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

    fn attribute(&mut self) -> Result<(&'a str, &'a str)> {
        let name = local(self.name()?);
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
        let value = &t2[1..1 + end];
        self.pos += 1 + end + 1;
        Ok((name, value))
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

/// Escape text for element content.
pub fn escape_into(out: &mut String, s: &str) {
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            '\t' | '\n' => out.push(c),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "&#{};", c as u32);
            }
            c => out.push(c),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_listing_shape() {
        let doc = br#"<?xml version="1.0" encoding="utf-8"?>
<EnumerationResults ServiceEndpoint="http://x/" ContainerName="c">
  <Blobs>
    <Blob><Name Encoded="true">a%01b</Name><Properties><Etag>0x1</Etag></Properties></Blob>
    <BlobPrefix><Name>d/</Name></BlobPrefix>
  </Blobs>
  <NextMarker/>
</EnumerationResults>"#;
        let root = Element::parse(doc).unwrap();
        assert_eq!(root.name, "EnumerationResults");
        assert_eq!(root.attr("ContainerName").as_deref(), Some("c"));
        let blobs = root.child("Blobs").unwrap();
        let b = blobs.child("Blob").unwrap();
        let name = b.child("Name").unwrap();
        assert_eq!(name.text, "a%01b");
        assert_eq!(name.attr("Encoded").as_deref(), Some("true"));
        assert_eq!(
            b.child("Properties").unwrap().child_text("Etag"),
            Some("0x1")
        );
        assert_eq!(root.child_nonempty("NextMarker"), None);
    }

    #[test]
    fn text_is_preserved_and_unescaped() {
        let root = Element::parse(b"<a><Name> x &amp; y </Name></a>").unwrap();
        assert_eq!(root.child_text("Name"), Some(" x & y "));
        let mut s = String::new();
        escape_into(&mut s, "<a&'\">\u{1}");
        assert_eq!(s, "&lt;a&amp;&apos;&quot;&gt;&#1;");
    }

    #[test]
    fn rejects_malformed() {
        for bad in [
            &b"<a>"[..],
            b"<a></b>",
            b"<a x></a>",
            b"<a>&bogus;</a>",
            b"",
            b"<a/><b/>",
            b"\xff",
        ] {
            assert!(Element::parse(bad).is_err(), "{bad:?}");
        }
        let deep = "<a>".repeat(100) + &"</a>".repeat(100);
        assert!(Element::parse(deep.as_bytes()).is_err());
    }
}
