//! S3 error mapping.
//!
//! S3 error responses carry an XML document with a `Code` (`NoSuchKey`,
//! `SlowDown`, ...). [`S3ErrorParser`] decodes it for the shared HTTP client
//! (attached as [`Detail::Code`]); [`classify`] maps code and status onto the
//! [`ErrorKind`] and errno s3fs's `translate_boto_error` produces:
//!
//! | s3fs exception | fsfast |
//! |---|---|
//! | `FileNotFoundError` (`NoSuchKey`, `NoSuchBucket`, 404, ...) | `NotFound` |
//! | `PermissionError` (`AccessDenied`, `SignatureDoesNotMatch`, 403, ...) | `PermissionDenied` |
//! | `FileExistsError` (`BucketAlreadyExists`, `BucketAlreadyOwnedByYou`, `PreconditionFailed` on `If-None-Match`) | `AlreadyExists` |
//! | `OSError(ENOTEMPTY)` (`BucketNotEmpty`) | `DirectoryNotEmpty` |
//! | `OSError(EBUSY)` (`SlowDown`, `ServiceUnavailable`, 503) | `Throttled` |
//! | `TimeoutError` (`RequestTimeout`) | `Timeout` |
//! | `OSError(EINVAL)` (`PreconditionFailed`, 412) | `PreconditionFailed` |
//! | `OSError(ENOSYS)` (`NotImplemented`, 501) | `Unsupported` |
//! | `OSError(errno)` (everything else: `InvalidArgument` EINVAL, `EntityTooLarge` EMSGSIZE, `InternalError` EREMOTEIO, `KeyTooLongError` ENAMETOOLONG, ...) | `Io` with [`Detail::Errno`] |
//!
//! Throttling, `InternalError`, `RequestTimeout` and
//! `XAmzContentSHA256Mismatch` are retried (botocore and s3fs retry them).

use fsfast_core::{Detail, Error, ErrorKind};
use fsfast_http_transport::header::HeaderMap;
use fsfast_http_transport::{ErrorParser, ServiceError, StatusCode};

use crate::xml::S3ErrorDoc;

/// POSIX errno values s3fs uses (`errno` module values of the platform,
/// with s3fs's fallbacks where a symbol does not exist).
pub mod errno {
    #![allow(missing_docs)]
    pub const EPERM: i32 = 1;
    pub const EIO: i32 = 5;
    pub const EBUSY: i32 = 16;
    pub const EINVAL: i32 = 22;
    #[cfg(target_os = "linux")]
    pub const ENAMETOOLONG: i32 = 36;
    #[cfg(target_os = "macos")]
    pub const ENAMETOOLONG: i32 = 63;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub const ENAMETOOLONG: i32 = 38;
    #[cfg(target_os = "linux")]
    pub const EMSGSIZE: i32 = 90;
    #[cfg(target_os = "macos")]
    pub const EMSGSIZE: i32 = 40;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    pub const EMSGSIZE: i32 = EINVAL;
    #[cfg(target_os = "linux")]
    pub const EREMOTEIO: i32 = 121;
    #[cfg(not(target_os = "linux"))]
    pub const EREMOTEIO: i32 = EIO;
    #[cfg(target_os = "linux")]
    pub const EREMCHG: i32 = 78;
    #[cfg(not(target_os = "linux"))]
    pub const EREMCHG: i32 = 2;
}

/// How an S3 failure maps onto fsfast.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Classified {
    /// The error kind.
    pub kind: ErrorKind,
    /// errno for `Io`-kind errors (the Python `OSError.errno`).
    pub errno: Option<i32>,
    /// Retry classification override.
    pub retryable: Option<bool>,
}

const fn c(kind: ErrorKind, errno: Option<i32>, retryable: Option<bool>) -> Classified {
    Classified {
        kind,
        errno,
        retryable,
    }
}

/// Map an S3 (or STS) error `code` with HTTP `status` (and the
/// `PreconditionFailed` condition) onto a kind, errno and retryability.
pub fn classify(status: u16, code: Option<&str>, condition: Option<&str>) -> Classified {
    use ErrorKind as K;
    use errno::*;
    if let Some(code) = code {
        let by_code = match code {
            "AccessDenied" | "AccountProblem" | "AllAccessDisabled"
            | "CrossLocationLoggingProhibited" | "ExpiredToken"
            | "IllegalLocationConstraintException" | "InvalidAccessKeyId"
            | "InvalidObjectState" | "InvalidPayer" | "InvalidSecurity" | "NotSignedUp"
            | "RequestTimeTooSkewed" | "SignatureDoesNotMatch"
            // STS.
            | "InvalidIdentityToken" | "ExpiredTokenException" | "IDPRejectedClaim"
            | "InvalidClientTokenId" | "UnrecognizedClientException" | "AccessDeniedException"
            | "RegionDisabledException" => Some(c(K::PermissionDenied, None, None)),
            "BucketAlreadyExists" | "BucketAlreadyOwnedByYou" => {
                Some(c(K::AlreadyExists, None, None))
            }
            "NoSuchBucket" | "NoSuchBucketPolicy" | "NoSuchKey" | "NoSuchLifecycleConfiguration"
            | "NoSuchUpload" | "NoSuchVersion" => Some(c(K::NotFound, None, None)),
            "BucketNotEmpty" => Some(c(K::DirectoryNotEmpty, None, None)),
            "PreconditionFailed" => {
                if condition.is_some_and(|c| c.eq_ignore_ascii_case("If-None-Match")) {
                    Some(c(K::AlreadyExists, None, None))
                } else {
                    Some(c(K::PreconditionFailed, None, None))
                }
            }
            "SlowDown" | "ServiceUnavailable" | "Throttling" | "ThrottlingException"
            | "ThrottledException" | "RequestThrottledException" | "TooManyRequestsException"
            | "RequestLimitExceeded" | "BandwidthLimitExceeded" | "RequestThrottled"
            | "IDPCommunicationError" => Some(c(K::Throttled, Some(EBUSY), Some(true))),
            "RequestTimeout" | "RequestTimeoutException" => Some(c(K::Timeout, None, Some(true))),
            "InternalError" => Some(c(K::Io, Some(EREMOTEIO), Some(true))),
            "NotImplemented" => Some(c(K::Unsupported, None, Some(false))),
            "XAmzContentSHA256Mismatch" => Some(c(K::Io, Some(EINVAL), Some(true))),
            // A conditional write raced another one on the same key and
            // was not applied: AWS documents it as safe to retry (the retry
            // then succeeds or fails with 412).
            "ConditionalRequestConflict" => Some(c(K::Io, Some(EBUSY), Some(true))),
            "OperationAborted" | "RestoreAlreadyInProgress" => Some(c(K::Io, Some(EBUSY), None)),
            "EntityTooLarge" | "InlineDataTooLarge" | "MaxMessageLengthExceeded"
            | "MaxPostPreDataLengthExceededError" | "MetadataTooLarge" => {
                Some(c(K::Io, Some(EMSGSIZE), None))
            }
            "KeyTooLongError" => Some(c(K::Io, Some(ENAMETOOLONG), None)),
            "InvalidBucketState" | "MethodNotAllowed" | "RequestTorrentOfBucketError" => {
                Some(c(K::Io, Some(EPERM), None))
            }
            "PermanentRedirect" | "Redirect" | "TemporaryRedirect" => {
                Some(c(K::Io, Some(EREMCHG), None))
            }
            "AmbiguousGrantByEmailAddress" | "AuthorizationHeaderMalformed" | "BadDigest"
            | "CredentialsNotSupported" | "EntityTooSmall"
            | "IllegalVersioningConfigurationException" | "IncompleteBody"
            | "IncorrectNumberOfFilesInPostRequest" | "InvalidAddressingHeader"
            | "InvalidArgument" | "InvalidBucketName" | "InvalidDigest"
            | "InvalidEncryptionAlgorithmError" | "InvalidLocationConstraint" | "InvalidPart"
            | "InvalidPartOrder" | "InvalidPolicyDocument" | "InvalidRange" | "InvalidRequest"
            | "InvalidSOAPRequest" | "InvalidStorageClass" | "InvalidTargetBucketForLogging"
            | "InvalidToken" | "InvalidURI" | "MalformedACLError" | "MalformedPOSTRequest"
            | "MalformedXML" | "MissingAttachment" | "MissingContentLength"
            | "MissingRequestBodyError" | "MissingSecurityElement" | "MissingSecurityHeader"
            | "NoLoggingStatusForKey" | "RequestIsNotMultiPartContent" | "TokenRefreshRequired"
            | "TooManyBuckets" | "UnexpectedContent" | "UnresolvableGrantByEmailAddress"
            | "UserKeyMustBeSpecified" | "ValidationError" | "MalformedPolicyDocument"
            | "PackedPolicyTooLarge" => Some(c(K::Io, Some(EINVAL), None)),
            _ => None,
        };
        if let Some(cl) = by_code {
            return cl;
        }
    }
    match status {
        301 | 302 | 307 => c(K::Io, Some(errno::EREMCHG), Some(false)),
        400 | 416 => c(K::Io, Some(errno::EINVAL), None),
        401 | 403 => c(K::PermissionDenied, None, None),
        404 | 410 => c(K::NotFound, None, None),
        405 => c(K::Io, Some(errno::EPERM), None),
        408 => c(K::Timeout, None, Some(true)),
        409 => c(K::Io, Some(errno::EBUSY), None),
        411 | 413 | 414 | 431 => c(K::Io, Some(errno::EINVAL), None),
        412 => c(K::PreconditionFailed, None, None),
        429 | 503 => c(K::Throttled, Some(errno::EBUSY), Some(true)),
        500 => c(K::Io, Some(errno::EREMOTEIO), Some(true)),
        501 => c(K::Unsupported, None, Some(false)),
        502 | 504 => c(
            if status == 504 { K::Timeout } else { K::Io },
            None,
            Some(true),
        ),
        _ => c(K::Io, None, None),
    }
}

/// Decodes S3 and STS error documents for the shared HTTP client.
#[derive(Debug, Default, Clone, Copy)]
pub struct S3ErrorParser;

impl ErrorParser for S3ErrorParser {
    fn parse(&self, status: StatusCode, _headers: &HeaderMap, body: &[u8]) -> Option<ServiceError> {
        let doc = S3ErrorDoc::parse(body).unwrap_or_default();
        let cl = classify(
            status.as_u16(),
            doc.code.as_deref(),
            doc.condition.as_deref(),
        );
        Some(ServiceError {
            code: doc.code,
            message: doc.message.filter(|m| !m.is_empty()),
            kind: Some(cl.kind),
            retryable: cl.retryable,
        })
    }
}

/// The service error code attached to `err`, if any.
pub fn error_code(err: &Error) -> Option<&str> {
    err.details().iter().find_map(|d| match d {
        Detail::Code(c) => Some(c.as_str()),
        _ => None,
    })
}

/// Final touches on an error from an S3 request: the errno s3fs would give
/// an `OSError` (from the code or status), and the fsfast path.
pub fn finish_error(err: Error, path: Option<&str>) -> Error {
    let has_errno = err.details().iter().any(|d| matches!(d, Detail::Errno(_)));
    let mut err = err;
    if !has_errno && let Some(status) = err.http_status() {
        let cl = classify(status, error_code(&err), None);
        if cl.kind == err.kind()
            && let Some(n) = cl.errno
        {
            err = err.with_detail(Detail::Errno(n));
        }
    }
    match path {
        Some(p) => err.with_path(p),
        None => err,
    }
}

/// Build the error for an S3 response the caller inspected itself (statuses
/// allowed through for redirect handling, and HTTP 200 responses whose body
/// is an `<Error>` document).
pub fn response_error(status: u16, doc: &S3ErrorDoc, path: &str) -> Error {
    let cl = classify(status, doc.code.as_deref(), doc.condition.as_deref());
    let reason = StatusCode::from_u16(status)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let mut message = if reason.is_empty() {
        format!("HTTP {status}")
    } else {
        format!("HTTP {status} {reason}")
    };
    if let Some(m) = doc.message.as_deref().filter(|m| !m.is_empty()) {
        message.push_str(": ");
        message.push_str(m);
    }
    let mut err = Error::new(cl.kind, message)
        .with_path(path)
        .with_detail(Detail::Http(status));
    if let Some(code) = &doc.code {
        err = err.with_detail(Detail::Code(code.clone()));
    }
    if let Some(n) = cl.errno {
        err = err.with_detail(Detail::Errno(n));
    }
    let retryable = cl
        .retryable
        .unwrap_or_else(|| fsfast_http_transport::status_retryable(status));
    err.with_retryable(retryable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapping_matches_s3fs() {
        let k = |s, code| classify(s, code, None).kind;
        assert_eq!(k(404, Some("NoSuchKey")), ErrorKind::NotFound);
        assert_eq!(k(404, None), ErrorKind::NotFound);
        assert_eq!(k(403, Some("AccessDenied")), ErrorKind::PermissionDenied);
        assert_eq!(k(403, None), ErrorKind::PermissionDenied);
        assert_eq!(
            k(409, Some("BucketAlreadyOwnedByYou")),
            ErrorKind::AlreadyExists
        );
        assert_eq!(k(409, Some("BucketNotEmpty")), ErrorKind::DirectoryNotEmpty);
        assert_eq!(k(503, Some("SlowDown")), ErrorKind::Throttled);
        assert_eq!(k(429, None), ErrorKind::Throttled);
        assert_eq!(
            k(412, Some("PreconditionFailed")),
            ErrorKind::PreconditionFailed
        );
        assert_eq!(
            classify(412, Some("PreconditionFailed"), Some("If-None-Match")).kind,
            ErrorKind::AlreadyExists
        );
        assert_eq!(k(501, Some("NotImplemented")), ErrorKind::Unsupported);
        assert_eq!(k(400, Some("RequestTimeout")), ErrorKind::Timeout);
        let inv = classify(400, Some("InvalidArgument"), None);
        assert_eq!((inv.kind, inv.errno), (ErrorKind::Io, Some(errno::EINVAL)));
        let big = classify(400, Some("EntityTooLarge"), None);
        assert_eq!(big.errno, Some(errno::EMSGSIZE));
        assert_eq!(
            classify(500, Some("InternalError"), None).retryable,
            Some(true)
        );
        assert_eq!(
            classify(400, Some("SomethingNew"), None).errno,
            Some(errno::EINVAL)
        );
    }

    #[test]
    fn response_errors_carry_details() {
        let doc = S3ErrorDoc {
            code: Some("NoSuchKey".into()),
            message: Some("The specified key does not exist.".into()),
            ..S3ErrorDoc::default()
        };
        let e = response_error(404, &doc, "b/k");
        assert_eq!(e.kind(), ErrorKind::NotFound);
        assert_eq!(e.path(), Some("b/k"));
        assert_eq!(error_code(&e), Some("NoSuchKey"));
        assert_eq!(e.http_status(), Some(404));
        assert!(!e.is_retryable());
        let e = response_error(
            200,
            &S3ErrorDoc {
                code: Some("InternalError".into()),
                ..Default::default()
            },
            "b/k",
        );
        assert!(e.is_retryable());
        assert!(e.details().contains(&Detail::Errno(errno::EREMOTEIO)));
    }

    #[test]
    fn finish_adds_errno() {
        let e = Error::new(ErrorKind::Io, "x")
            .with_detail(Detail::Http(400))
            .with_detail(Detail::Code("InvalidArgument".into()));
        let e = finish_error(e, Some("b/k"));
        assert!(e.details().contains(&Detail::Errno(errno::EINVAL)));
        assert_eq!(e.path(), Some("b/k"));
    }
}
