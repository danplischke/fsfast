//! Blob service errors: `x-ms-error-code` / `<Error><Code>` → [`ErrorKind`].
//!
//! The service reports a symbolic error code in the `x-ms-error-code`
//! response header (also on bodiless `HEAD` responses) and in the XML body
//! (`<Error><Code>…</Code><Message>…</Message></Error>`). The code is
//! attached as [`fsfast_core::Detail::Code`]; the kind follows the code when
//! it is known, otherwise the HTTP status (see
//! [`fsfast_http_transport::status_kind`]), except that an unknown 409 is a
//! generic conflict (`Io`), not `AlreadyExists`.

use fsfast_core::ErrorKind;
use fsfast_http_transport::header::HeaderMap;
use fsfast_http_transport::{ErrorParser, ServiceError, StatusCode};

use crate::xml::Element;

/// The kind for a Blob (or DFS) service error code, if it is one we know.
pub fn code_kind(code: &str) -> Option<ErrorKind> {
    use ErrorKind::*;
    Some(match code {
        "BlobNotFound" | "ContainerNotFound" | "ResourceNotFound" | "PathNotFound"
        | "FilesystemNotFound" | "SourcePathNotFound" | "ParentNotFound" | "CopyIdMismatch" => {
            NotFound
        }
        "AuthorizationFailure"
        | "AuthenticationFailed"
        | "AuthorizationPermissionMismatch"
        | "AuthorizationSourceIPMismatch"
        | "AuthorizationProtocolMismatch"
        | "AuthorizationResourceTypeMismatch"
        | "AuthorizationServiceMismatch"
        | "InsufficientAccountPermissions"
        | "NoAuthenticationInformation"
        | "InvalidAuthenticationInfo"
        | "KeyBasedAuthenticationNotPermitted"
        | "AccountIsDisabled"
        | "BlobImmutableDueToPolicy"
        | "BlobImmutableDueToLegalHold"
        | "LeaseIdMissing"
        | "LeaseAlreadyPresent"
        | "LeaseIdMismatchWithBlobOperation"
        | "LeaseIdMismatchWithContainerOperation"
        | "LeaseNotPresentWithBlobOperation"
        | "LeaseNotPresentWithContainerOperation"
        | "LeaseIsBrokenAndCannotBeRenewed" => PermissionDenied,
        "ConditionNotMet"
        | "TargetConditionNotMet"
        | "SourceConditionNotMet"
        | "AppendPositionConditionNotMet"
        | "MaxBlobSizeConditionNotMet"
        | "SequenceNumberConditionNotMet" => PreconditionFailed,
        "BlobAlreadyExists" | "ContainerAlreadyExists" | "PathAlreadyExists" => AlreadyExists,
        "ServerBusy" | "OperationTimedOut" => Throttled,
        "DirectoryNotEmpty" => DirectoryNotEmpty,
        "InvalidRange"
        | "InvalidBlobOrBlock"
        | "InvalidBlockId"
        | "InvalidBlockList"
        | "InvalidBlobType"
        | "InvalidHeaderValue"
        | "InvalidQueryParameterValue"
        | "InvalidResourceName"
        | "InvalidUri"
        | "InvalidInput"
        | "InvalidXmlDocument"
        | "InvalidXmlNodeValue"
        | "InvalidMetadata"
        | "MissingRequiredHeader"
        | "MissingRequiredQueryParameter"
        | "MissingRequiredXmlNode"
        | "OutOfRangeInput"
        | "OutOfRangeQueryParameterValue"
        | "RequestBodyTooLarge"
        | "BlockCountExceedsLimit"
        | "BlockListTooLong"
        | "Md5Mismatch"
        | "Crc64Mismatch"
        | "InvalidSourceBlobUrl"
        | "InvalidSourceBlobType" => InvalidInput,
        "UnsupportedHeader"
        | "UnsupportedQueryParameter"
        | "UnsupportedXmlNode"
        | "UnsupportedHttpVerb"
        | "FeatureVersionMismatch"
        | "NotImplemented"
        | "BlobOperationNotSupportedForHierarchicalNamespace"
        | "HierarchicalNamespaceNotEnabled"
        | "EndpointUnsupportedAccountFeatures" => Unsupported,
        _ => return None,
    })
}

/// Whether an error code is worth retrying regardless of its status.
fn code_retryable(code: &str) -> Option<bool> {
    match code {
        "ServerBusy" | "OperationTimedOut" | "InternalError" | "ContainerBeingDeleted" => {
            Some(true)
        }
        _ => None,
    }
}

/// Decodes Blob service error responses (header and XML body).
#[derive(Debug, Default, Clone, Copy)]
pub struct AzureErrorParser;

impl ErrorParser for AzureErrorParser {
    fn parse(&self, status: StatusCode, headers: &HeaderMap, body: &[u8]) -> Option<ServiceError> {
        let header_code = headers
            .get("x-ms-error-code")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let (body_code, message) = parse_error_body(body);
        let code = header_code.or(body_code);
        if code.is_none() && message.is_none() {
            return None;
        }
        let mut kind = code.as_deref().and_then(code_kind);
        if kind.is_none() && status.as_u16() == 409 {
            // A conflict we do not know: not necessarily "already exists".
            kind = Some(ErrorKind::Io);
        }
        let retryable = code.as_deref().and_then(code_retryable);
        Some(ServiceError {
            code,
            message,
            kind,
            retryable,
        })
    }
}

/// `(Code, first line of Message)` from an `<Error>` document (also the DFS
/// JSON shape `{"error":{"code":…,"message":…}}`).
pub fn parse_error_body(body: &[u8]) -> (Option<String>, Option<String>) {
    if body.is_empty() {
        return (None, None);
    }
    if let Ok(root) = Element::parse(body)
        && root.name == "Error"
    {
        let code = root
            .child_nonempty("Code")
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty());
        let message = root.child_text("Message").and_then(first_line);
        return (code, message);
    }
    if let Ok(serde_json::Value::Object(m)) = serde_json::from_slice::<serde_json::Value>(body)
        && let Some(serde_json::Value::Object(e)) = m.get("error")
    {
        let code = e.get("code").and_then(|v| v.as_str()).map(str::to_owned);
        let message = e
            .get("message")
            .and_then(|v| v.as_str())
            .and_then(first_line);
        return (code, message);
    }
    (None, None)
}

/// The service appends `RequestId:` and `Time:` lines to messages; keep the
/// human-readable first line.
fn first_line(s: &str) -> Option<String> {
    let l = s.lines().next()?.trim();
    (!l.is_empty()).then(|| l.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use fsfast_http_transport::header::HeaderValue;

    fn parse(status: u16, header: Option<&str>, body: &str) -> Option<ServiceError> {
        let mut h = HeaderMap::new();
        if let Some(c) = header {
            h.insert("x-ms-error-code", HeaderValue::from_str(c).unwrap());
        }
        AzureErrorParser.parse(StatusCode::from_u16(status).unwrap(), &h, body.as_bytes())
    }

    #[test]
    fn header_and_body_codes() {
        let e = parse(404, Some("BlobNotFound"), "").unwrap();
        assert_eq!(e.code.as_deref(), Some("BlobNotFound"));
        assert_eq!(e.kind, Some(ErrorKind::NotFound));

        let body = "<?xml version=\"1.0\"?><Error><Code>ContainerAlreadyExists</Code>\
                    <Message>The specified container already exists.\nRequestId:1\nTime:x</Message></Error>";
        let e = parse(409, None, body).unwrap();
        assert_eq!(e.code.as_deref(), Some("ContainerAlreadyExists"));
        assert_eq!(e.kind, Some(ErrorKind::AlreadyExists));
        assert_eq!(
            e.message.as_deref(),
            Some("The specified container already exists.")
        );
    }

    #[test]
    fn kinds() {
        for (code, kind) in [
            ("AuthorizationFailure", ErrorKind::PermissionDenied),
            ("AuthenticationFailed", ErrorKind::PermissionDenied),
            ("ConditionNotMet", ErrorKind::PreconditionFailed),
            ("BlobAlreadyExists", ErrorKind::AlreadyExists),
            ("ServerBusy", ErrorKind::Throttled),
            ("OperationTimedOut", ErrorKind::Throttled),
            ("ContainerNotFound", ErrorKind::NotFound),
            ("InvalidBlockList", ErrorKind::InvalidInput),
        ] {
            assert_eq!(code_kind(code), Some(kind), "{code}");
        }
        let e = parse(409, Some("SnapshotsPresent"), "").unwrap();
        assert_eq!(e.kind, Some(ErrorKind::Io));
        let e = parse(500, Some("OperationTimedOut"), "").unwrap();
        assert_eq!(e.retryable, Some(true));
        assert!(parse(500, None, "").is_none());
        assert!(parse(500, None, "<html>").is_none());
    }

    #[test]
    fn dfs_json_errors() {
        let e = parse(
            409,
            None,
            r#"{"error":{"code":"PathAlreadyExists","message":"The specified path already exists.\nRequestId:x"}}"#,
        )
        .unwrap();
        assert_eq!(e.kind, Some(ErrorKind::AlreadyExists));
        assert_eq!(
            e.message.as_deref(),
            Some("The specified path already exists.")
        );
    }
}
