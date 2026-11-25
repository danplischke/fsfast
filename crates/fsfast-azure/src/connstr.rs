//! Storage connection strings, parsed as azure-storage-blob's
//! `parse_connection_str` does for the blob service.
//!
//! `Key=Value` pairs separated by `;` (keys case-insensitive, values kept
//! verbatim, a trailing `;` allowed):
//!
//! * `UseDevelopmentStorage=true`: Azurite's well-known account
//!   (`http://127.0.0.1:10000/devstoreaccount1`, its public key).
//! * `BlobEndpoint` (+ `BlobSecondaryEndpoint`): explicit endpoint.
//!   Otherwise `{DefaultEndpointsProtocol}://{AccountName}.blob.{EndpointSuffix}`
//!   when both are present, else `https://{AccountName}.blob.{EndpointSuffix
//!   or core.windows.net}`.
//! * Credentials: `AccountName` + `AccountKey` (Shared Key), else
//!   `SharedAccessSignature`.

use std::collections::HashMap;

use fsfast_core::{Error, Result};

/// The public account name of the storage emulator.
pub const DEVSTORE_ACCOUNT_NAME: &str = "devstoreaccount1";
/// The public, well-known key of the storage emulator (Azurite).
pub const DEVSTORE_ACCOUNT_KEY: &str =
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw==";
/// The emulator's blob endpoint.
pub const DEVSTORE_BLOB_ENDPOINT: &str = "http://127.0.0.1:10000/devstoreaccount1";
/// Default endpoint suffix of the public cloud.
pub const SERVICE_HOST_BASE: &str = "core.windows.net";

/// A parsed connection string (blob service view).
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionString {
    /// Primary blob endpoint URL (`scheme://host[:port][/path]`).
    pub blob_endpoint: String,
    /// Secondary endpoint, as the SDK derives it (may lack a scheme when
    /// derived from `EndpointSuffix`, exactly like the SDK).
    pub secondary_endpoint: Option<String>,
    /// `AccountName` (or the emulator's).
    pub account_name: Option<String>,
    /// `AccountKey` when given together with `AccountName`.
    pub account_key: Option<String>,
    /// `SharedAccessSignature` when no account key is given.
    pub sas_token: Option<String>,
}

impl std::fmt::Debug for ConnectionString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConnectionString")
            .field("blob_endpoint", &self.blob_endpoint)
            .field("secondary_endpoint", &self.secondary_endpoint)
            .field("account_name", &self.account_name)
            .field(
                "account_key",
                &self.account_key.as_ref().map(|_| "<redacted>"),
            )
            .field("sas_token", &self.sas_token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ConnectionString {
    /// Parse `s`.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim_end_matches(';');
        let mut settings: HashMap<String, String> = HashMap::new();
        for part in s.split(';') {
            let Some((k, v)) = part.split_once('=') else {
                return Err(Error::invalid_input(
                    "Connection string is either blank or malformed.",
                ));
            };
            settings.insert(k.trim().to_ascii_uppercase(), v.to_owned());
        }
        let get = |k: &str| settings.get(k).map(String::as_str);
        if get("USEDEVELOPMENTSTORAGE") == Some("true") {
            return Ok(ConnectionString {
                blob_endpoint: DEVSTORE_BLOB_ENDPOINT.to_owned(),
                secondary_endpoint: None,
                account_name: Some(DEVSTORE_ACCOUNT_NAME.to_owned()),
                account_key: Some(DEVSTORE_ACCOUNT_KEY.to_owned()),
                sas_token: None,
            });
        }
        let account_name = get("ACCOUNTNAME").map(str::to_owned);
        let (account_key, sas_token) = match (get("ACCOUNTNAME"), get("ACCOUNTKEY")) {
            (Some(_), Some(k)) => (Some(k.to_owned()), None),
            _ => (None, get("SHAREDACCESSSIGNATURE").map(str::to_owned)),
        };
        let (primary, secondary) = if let Some(p) = get("BLOBENDPOINT") {
            (
                Some(p.to_owned()),
                get("BLOBSECONDARYENDPOINT").map(str::to_owned),
            )
        } else {
            if get("BLOBSECONDARYENDPOINT").is_some() {
                return Err(Error::invalid_input(
                    "Connection string specifies only secondary endpoint.",
                ));
            }
            match (
                get("DEFAULTENDPOINTSPROTOCOL"),
                get("ACCOUNTNAME"),
                get("ENDPOINTSUFFIX"),
            ) {
                (Some(proto), Some(name), Some(suffix)) => (
                    Some(format!("{proto}://{name}.blob.{suffix}")),
                    Some(format!("{name}-secondary.blob.{suffix}")),
                ),
                _ => (None, None),
            }
        };
        let blob_endpoint = match primary.filter(|p| !p.is_empty()) {
            Some(p) => p,
            None => match get("ACCOUNTNAME") {
                Some(name) => format!(
                    "https://{name}.blob.{}",
                    get("ENDPOINTSUFFIX").unwrap_or(SERVICE_HOST_BASE)
                ),
                None => {
                    return Err(Error::invalid_input(
                        "Connection string missing required connection details.",
                    ));
                }
            },
        };
        Ok(ConnectionString {
            blob_endpoint,
            secondary_endpoint: secondary,
            account_name,
            account_key,
            sas_token,
        })
    }
}

/// The SAS query parameter names azure-storage-blob recognises
/// (`QueryStringConstants.to_list()`).
pub const SAS_QUERY_KEYS: &[&str] = &[
    "sig", "sp", "st", "se", "sr", "si", "sip", "spr", "sv", "rscc", "rscd", "rsce", "rscl",
    "rsct", "spk", "srk", "epk", "erk", "srt", "ss", "skoid", "sktid", "skt", "ske", "sks", "skv",
    "ses", "srh", "srq", "skdutid", "sduoid", "saoid", "suoid", "scid", "sdd",
];

/// Whether `s` looks like a SAS token: a query string whose parameters are
/// all SAS parameters (the SDK's `is_credential_sastoken`).
pub fn is_sas_token(s: &str) -> bool {
    let q = s.trim_start_matches('?');
    let mut any = false;
    for part in q.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = part.split_once('=').unwrap_or((part, ""));
        if v.is_empty() {
            // parse_qs drops blank values.
            continue;
        }
        if !SAS_QUERY_KEYS.contains(&k) {
            return false;
        }
        any = true;
    }
    any
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_endpoint_and_key() {
        let c = ConnectionString::parse(
            "DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=a2V5;BlobEndpoint=http://127.0.0.1:10000/devstoreaccount1;",
        )
        .unwrap();
        assert_eq!(c.blob_endpoint, "http://127.0.0.1:10000/devstoreaccount1");
        assert_eq!(c.account_name.as_deref(), Some("devstoreaccount1"));
        assert_eq!(c.account_key.as_deref(), Some("a2V5"));
        assert_eq!(c.sas_token, None);
        assert!(!format!("{c:?}").contains("a2V5"));
    }

    #[test]
    fn suffix_and_protocol() {
        let c = ConnectionString::parse(
            "AccountName=a;AccountKey=a2V5;EndpointSuffix=core.chinacloudapi.cn;DefaultEndpointsProtocol=http",
        )
        .unwrap();
        assert_eq!(c.blob_endpoint, "http://a.blob.core.chinacloudapi.cn");
        assert_eq!(
            c.secondary_endpoint.as_deref(),
            Some("a-secondary.blob.core.chinacloudapi.cn")
        );
        let c = ConnectionString::parse("accountname=a;accountkey=k").unwrap();
        assert_eq!(c.blob_endpoint, "https://a.blob.core.windows.net");
    }

    #[test]
    fn sas_and_devstore() {
        let c = ConnectionString::parse(
            "BlobEndpoint=https://x.example/;SharedAccessSignature=sv=1&sig=abc",
        )
        .unwrap();
        assert_eq!(c.blob_endpoint, "https://x.example/");
        assert_eq!(c.sas_token.as_deref(), Some("sv=1&sig=abc"));
        assert_eq!(c.account_name, None);

        let c = ConnectionString::parse("UseDevelopmentStorage=true").unwrap();
        assert_eq!(c.blob_endpoint, DEVSTORE_BLOB_ENDPOINT);
        assert_eq!(c.account_key.as_deref(), Some(DEVSTORE_ACCOUNT_KEY));
    }

    #[test]
    fn malformed() {
        for bad in [
            "",
            "garbage",
            "AccountKey=x",
            "BlobSecondaryEndpoint=https://x",
        ] {
            assert!(ConnectionString::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn sas_detection() {
        assert!(is_sas_token("?sv=2020&sig=abc%3D&se=x"));
        assert!(is_sas_token("sp=r&sig=x"));
        assert!(!is_sas_token(
            "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2U=="
        ));
        assert!(!is_sas_token("sig=x&foo=bar"));
        assert!(!is_sas_token(""));
    }
}
