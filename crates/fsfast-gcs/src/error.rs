//! Decoding GCS error responses.
//!
//! The JSON API answers errors with
//! `{"error": {"code": 404, "message": "...", "errors": [{"domain":
//! "global", "reason": "notFound", "message": "..."}]}}`; OAuth token
//! endpoints with `{"error": "invalid_grant", "error_description": "..."}`;
//! the XML API (and some emulator replies) with `<Error><Code>...</Code>
//! <Message>...</Message></Error>`. [`GcsErrorParser`] extracts the reason
//! (attached as [`fsfast_core::Detail::Code`]) and the message.
//!
//! Status → kind (the defaults of `fsfast_http_transport::status_kind`,
//! which match the exception types gcsfs raises): 404 `NotFound`
//! (`FileNotFoundError`), 401/403 `PermissionDenied` (gcsfs raises
//! `OSError("Forbidden...")`; `PermissionError` is an `OSError`), 412
//! `PreconditionFailed` (operations whose precondition is
//! `ifGenerationMatch=0` map it to `AlreadyExists`, gcsfs's
//! `FileExistsError`), 409 `AlreadyExists` (bucket deletion maps it to
//! `DirectoryNotEmpty`), 429/503 `Throttled`. Retried like gcsfs: 408,
//! 429 and 5xx; also 403 `rateLimitExceeded`/`userRateLimitExceeded`
//! (`Throttled`), which GCS documents as retryable.

use fsfast_core::ErrorKind;
use fsfast_http_transport::header::HeaderMap;
use fsfast_http_transport::{ErrorParser, ServiceError, StatusCode};
use serde_json::Value as Json;

/// The [`ErrorParser`] for GCS JSON / XML / OAuth error bodies.
#[derive(Debug, Default, Clone, Copy)]
pub struct GcsErrorParser;

impl ErrorParser for GcsErrorParser {
    fn parse(&self, status: StatusCode, _headers: &HeaderMap, body: &[u8]) -> Option<ServiceError> {
        let mut out = parse_body(body)?;
        let rate_limited = matches!(
            out.code.as_deref(),
            Some("rateLimitExceeded" | "userRateLimitExceeded")
        );
        if status.as_u16() == 403 && rate_limited {
            out.kind = Some(ErrorKind::Throttled);
            out.retryable = Some(true);
        }
        Some(out)
    }
}

/// Decode an error body (JSON API, OAuth or XML); `None` when it is none of
/// these.
pub fn parse_body(body: &[u8]) -> Option<ServiceError> {
    let text = std::str::from_utf8(body).ok()?.trim();
    if text.starts_with('{') {
        let v: Json = serde_json::from_str(text).ok()?;
        return parse_json(&v);
    }
    if text.starts_with('<') {
        return parse_xml(text);
    }
    None
}

fn parse_json(v: &Json) -> Option<ServiceError> {
    let err = v.get("error")?;
    match err {
        // OAuth: {"error": "invalid_grant", "error_description": "..."}
        Json::String(code) => Some(ServiceError {
            code: Some(code.clone()),
            message: v
                .get("error_description")
                .and_then(Json::as_str)
                .map(str::to_owned)
                .or_else(|| Some(code.clone())),
            kind: None,
            retryable: None,
        }),
        Json::Object(o) => {
            let reason = o
                .get("errors")
                .and_then(Json::as_array)
                .and_then(|a| a.first())
                .and_then(|e| e.get("reason"))
                .and_then(Json::as_str)
                .filter(|r| !r.is_empty())
                .or_else(|| o.get("status").and_then(Json::as_str))
                .map(str::to_owned);
            let message = o
                .get("message")
                .and_then(Json::as_str)
                .filter(|m| !m.is_empty())
                .map(str::to_owned);
            Some(ServiceError {
                code: reason,
                message,
                kind: None,
                retryable: None,
            })
        }
        _ => None,
    }
}

/// Text between `<tag>` and `</tag>` (no nesting, entities decoded).
fn xml_element<'a>(text: &'a str, tag: &str) -> Option<std::borrow::Cow<'a, str>> {
    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = text.find(&open)? + open.len();
    let end = start + text[start..].find(&close)?;
    let raw = &text[start..end];
    if raw.contains('&') {
        Some(std::borrow::Cow::Owned(
            raw.replace("&lt;", "<")
                .replace("&gt;", ">")
                .replace("&quot;", "\"")
                .replace("&apos;", "'")
                .replace("&amp;", "&"),
        ))
    } else {
        Some(std::borrow::Cow::Borrowed(raw))
    }
}

fn parse_xml(text: &str) -> Option<ServiceError> {
    let code = xml_element(text, "Code")?.into_owned();
    let message = xml_element(text, "Message").map(|m| m.into_owned());
    Some(ServiceError {
        code: Some(code),
        message,
        kind: None,
        retryable: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(status: u16, body: &str) -> Option<ServiceError> {
        GcsErrorParser.parse(
            StatusCode::from_u16(status).unwrap(),
            &HeaderMap::new(),
            body.as_bytes(),
        )
    }

    #[test]
    fn json_api_errors() {
        let e = parse(
            404,
            r#"{"error":{"code":404,"message":"No such object: b/k","errors":[{"domain":"global","reason":"notFound","message":"No such object: b/k"}]}}"#,
        )
        .unwrap();
        assert_eq!(e.code.as_deref(), Some("notFound"));
        assert_eq!(e.message.as_deref(), Some("No such object: b/k"));
        assert_eq!(e.kind, None);
        let e = parse(
            403,
            r#"{"error":{"code":403,"message":"slow down","errors":[{"reason":"rateLimitExceeded"}]}}"#,
        )
        .unwrap();
        assert_eq!(e.kind, Some(ErrorKind::Throttled));
        assert_eq!(e.retryable, Some(true));
        // A 403 for permissions stays as is.
        let e = parse(
            403,
            r#"{"error":{"code":403,"message":"x does not have storage.objects.get","errors":[{"reason":"forbidden"}]}}"#,
        )
        .unwrap();
        assert_eq!(e.kind, None);
        assert_eq!(e.code.as_deref(), Some("forbidden"));
        // Newer error shape with only a status.
        let e = parse(
            409,
            r#"{"error":{"code":409,"message":"exists","status":"ALREADY_EXISTS"}}"#,
        )
        .unwrap();
        assert_eq!(e.code.as_deref(), Some("ALREADY_EXISTS"));
    }

    #[test]
    fn oauth_and_xml_errors() {
        let e = parse(
            400,
            r#"{"error":"invalid_grant","error_description":"Invalid JWT Signature."}"#,
        )
        .unwrap();
        assert_eq!(e.code.as_deref(), Some("invalid_grant"));
        assert_eq!(e.message.as_deref(), Some("Invalid JWT Signature."));
        let e = parse(
            416,
            "<?xml version='1.0' encoding='UTF-8'?><Error><Code>InvalidRange</Code><Message>The requested range &amp; more.</Message></Error>",
        )
        .unwrap();
        assert_eq!(e.code.as_deref(), Some("InvalidRange"));
        assert_eq!(e.message.as_deref(), Some("The requested range & more."));
    }

    #[test]
    fn garbage_is_ignored() {
        for body in ["", "Not Found", "{", "{\"x\":1}", "<html>", "\u{ff}"] {
            assert!(parse(500, body).is_none(), "{body:?}");
        }
        assert!(parse_body(&[0xff, 0xfe]).is_none());
    }
}
