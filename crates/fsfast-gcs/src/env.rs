//! The environment variables the filesystem consults, captured once when it
//! is built (so behaviour does not change mid-flight, and tests can inject
//! their own values without touching the process environment).

use std::collections::BTreeMap;
use std::path::PathBuf;

/// Every environment variable read by this crate.
pub const VARIABLES: &[&str] = &[
    // Endpoint selection (gcsfs `_location`).
    "STORAGE_EMULATOR_HOST",
    "GOOGLE_CLOUD_UNIVERSE_DOMAIN",
    // gcsfs default project.
    "GCSFS_DEFAULT_PROJECT",
    // Application default credentials (google-auth).
    "GOOGLE_APPLICATION_CREDENTIALS",
    "GOOGLE_CLOUD_PROJECT",
    "GCLOUD_PROJECT",
    "GOOGLE_CLOUD_QUOTA_PROJECT",
    "CLOUDSDK_CONFIG",
    "CLOUDSDK_CORE_PROJECT",
    "CLOUDSDK_ACTIVE_CONFIG_NAME",
    "HOME",
    "APPDATA",
    // GCE metadata server (google-auth `compute_engine._metadata`).
    "GCE_METADATA_HOST",
    "GCE_METADATA_ROOT",
    "GCE_METADATA_IP",
    "GCE_METADATA_TIMEOUT",
    "GCE_METADATA_DETECT_RETRIES",
    "NO_GCE_CHECK",
];

/// A snapshot of [`VARIABLES`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcsEnv {
    vars: BTreeMap<String, String>,
    /// Override of the DMI product-name file used for GCE detection
    /// (tests; `None` means `/sys/class/dmi/id/product_name`).
    pub(crate) product_name_file: Option<PathBuf>,
}

impl GcsEnv {
    /// Capture the current process environment.
    pub fn from_process() -> Self {
        let vars = VARIABLES
            .iter()
            .filter_map(|k| std::env::var(k).ok().map(|v| ((*k).to_owned(), v)))
            .collect();
        GcsEnv {
            vars,
            product_name_file: None,
        }
    }

    /// An environment with exactly these variables (nothing from the
    /// process), e.g. for tests.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        GcsEnv {
            vars: pairs
                .into_iter()
                .map(|(k, v)| (k.into(), v.into()))
                .collect(),
            product_name_file: None,
        }
    }

    /// Use `path` instead of `/sys/class/dmi/id/product_name` when
    /// detecting Google Compute Engine (tests).
    pub fn with_product_name_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.product_name_file = Some(path.into());
        self
    }

    /// The value of `key`, if set.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str)
    }

    /// The value of `key` if set and non-empty.
    pub fn non_empty(&self, key: &str) -> Option<&str> {
        self.get(key).filter(|v| !v.is_empty())
    }

    /// The user's home directory (`HOME`).
    pub fn home(&self) -> Option<PathBuf> {
        self.non_empty("HOME").map(PathBuf::from)
    }

    /// The Cloud SDK configuration directory (google-auth
    /// `_cloud_sdk.get_config_path`).
    pub fn gcloud_config_dir(&self) -> Option<PathBuf> {
        if let Some(d) = self.get("CLOUDSDK_CONFIG") {
            return Some(PathBuf::from(d));
        }
        if cfg!(windows) {
            return self
                .non_empty("APPDATA")
                .map(|a| PathBuf::from(a).join("gcloud"));
        }
        self.home().map(|h| h.join(".config").join("gcloud"))
    }

    /// The gcloud application-default-credentials file path.
    pub fn gcloud_adc_path(&self) -> Option<PathBuf> {
        self.gcloud_config_dir()
            .map(|d| d.join("application_default_credentials.json"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_dir() {
        let e = GcsEnv::from_pairs([("HOME", "/home/u")]);
        if !cfg!(windows) {
            assert_eq!(
                e.gcloud_adc_path().unwrap(),
                PathBuf::from("/home/u/.config/gcloud/application_default_credentials.json")
            );
        }
        let e = GcsEnv::from_pairs([("HOME", "/home/u"), ("CLOUDSDK_CONFIG", "/cfg")]);
        assert_eq!(e.gcloud_config_dir().unwrap(), PathBuf::from("/cfg"));
        assert_eq!(e.get("HOME"), Some("/home/u"));
        assert_eq!(e.non_empty("NOPE"), None);
        assert!(GcsEnv::from_pairs([("X", "")]).non_empty("X").is_none());
    }
}
