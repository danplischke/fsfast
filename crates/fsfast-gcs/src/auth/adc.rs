//! Credential files: service-account keys, `authorized_user` refresh
//! tokens, and the application-default-credentials lookup of google-auth
//! (`GOOGLE_APPLICATION_CREDENTIALS`, then gcloud's ADC file), plus the
//! gcloud project configuration.
//!
//! These are small local files read when the filesystem is built (gcsfs
//! reads them in its constructor too); nothing here touches the network.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use fsfast_core::{Error, Result, Value};
use serde_json::{Map, Value as Json};
use zeroize::Zeroizing;

use super::jwt::{GOOGLE_TOKEN_URI, ServiceAccountKey};
use crate::env::GcsEnv;

/// OAuth client credentials with a refresh token (`authorized_user`).
#[derive(Clone)]
pub struct AuthorizedUser {
    /// `client_id`.
    pub client_id: String,
    /// `client_secret`.
    pub client_secret: Zeroizing<String>,
    /// `refresh_token`.
    pub refresh_token: Zeroizing<String>,
    /// Token endpoint.
    pub token_uri: String,
    /// `quota_project_id` (sent as `x-goog-user-project`).
    pub quota_project_id: Option<String>,
}

impl std::fmt::Debug for AuthorizedUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorizedUser")
            .field("client_id", &self.client_id)
            .field("token_uri", &self.token_uri)
            .finish_non_exhaustive()
    }
}

impl AuthorizedUser {
    /// From a parsed `authorized_user` document. `token_uri` defaults to
    /// Google's endpoint.
    pub fn from_info(info: &Map<String, Json>) -> Result<Self> {
        let get = |k: &str| -> Result<String> {
            info.get(k)
                .and_then(Json::as_str)
                .map(str::to_owned)
                .ok_or_else(|| {
                    Error::invalid_input(format!(
                        "authorized user info was not in the expected format, missing field {k:?}"
                    ))
                })
        };
        Ok(AuthorizedUser {
            client_id: get("client_id")?,
            client_secret: Zeroizing::new(get("client_secret")?),
            refresh_token: Zeroizing::new(get("refresh_token")?),
            token_uri: info
                .get("token_uri")
                .and_then(Json::as_str)
                .unwrap_or(GOOGLE_TOKEN_URI)
                .to_owned(),
            quota_project_id: info
                .get("quota_project_id")
                .and_then(Json::as_str)
                .map(str::to_owned),
        })
    }
}

/// Credentials loaded from a file or dict.
#[derive(Debug, Clone)]
pub enum FileCredentials {
    /// A service-account key.
    ServiceAccount(Arc<ServiceAccountKey>),
    /// A user refresh token.
    AuthorizedUser(AuthorizedUser),
}

impl FileCredentials {
    /// The project the credentials name (`project_id` of a service
    /// account; user credentials name none).
    pub fn project(&self) -> Option<String> {
        match self {
            FileCredentials::ServiceAccount(k) => k.project_id.clone(),
            FileCredentials::AuthorizedUser(_) => None,
        }
    }
}

/// Read and parse a JSON object from a file.
pub fn read_json_file(path: &Path) -> Result<Map<String, Json>> {
    let text = Zeroizing::new(std::fs::read_to_string(path).map_err(|e| {
        Error::from(e).with_path(path.display().to_string())
    })?);
    match serde_json::from_str::<Json>(&text) {
        Ok(Json::Object(m)) => Ok(m),
        Ok(_) => Err(Error::invalid_input(format!(
            "credentials file {} does not contain a JSON object",
            path.display()
        ))),
        Err(e) => Err(Error::invalid_input(format!(
            "credentials file {} is not valid JSON: {e}",
            path.display()
        ))),
    }
}

/// google-auth `load_credentials_from_file` / `_load_credentials_from_info`:
/// dispatch on `"type"`. Only `authorized_user` and `service_account` are
/// supported; the other ADC types (workload identity federation,
/// impersonation, GDCH) are `Unsupported`.
pub fn credentials_from_typed_info(info: &Map<String, Json>, origin: &str) -> Result<FileCredentials> {
    match info.get("type").and_then(Json::as_str) {
        Some("service_account") => Ok(FileCredentials::ServiceAccount(Arc::new(
            ServiceAccountKey::from_info(info)?,
        ))),
        Some("authorized_user") => Ok(FileCredentials::AuthorizedUser(AuthorizedUser::from_info(info)?)),
        Some(
            t @ ("external_account"
            | "external_account_authorized_user"
            | "impersonated_service_account"
            | "gdch_service_account"),
        ) => Err(Error::unsupported(format!(
            "credentials of type {t:?} ({origin})"
        ))),
        Some(t) => Err(Error::invalid_input(format!(
            "The file {origin} does not have a valid type. Type is {t:?}, expected one of \
             authorized_user, service_account"
        ))),
        None => Err(Error::invalid_input(format!(
            "The file {origin} does not have a valid type. Type is None, expected one of \
             authorized_user, service_account"
        ))),
    }
}

/// gcsfs `_connect_token` for a token path: a service-account key file
/// first, otherwise any JSON document interpreted like a token dict.
pub fn credentials_from_token_file(path: &Path) -> Result<FileCredentials> {
    let info = read_json_file(path)?;
    if let Ok(k) = ServiceAccountKey::from_info(&info) {
        return Ok(FileCredentials::ServiceAccount(Arc::new(k)));
    }
    credentials_from_token_info(&info)
}

/// gcsfs `_dict_to_credentials`: a service-account key, else user
/// credentials (`refresh_token`, `client_secret`, `client_id`).
pub fn credentials_from_token_info(info: &Map<String, Json>) -> Result<FileCredentials> {
    match ServiceAccountKey::from_info(info) {
        Ok(k) => Ok(FileCredentials::ServiceAccount(Arc::new(k))),
        Err(sa_err) => match AuthorizedUser::from_info(info) {
            Ok(u) => Ok(FileCredentials::AuthorizedUser(u)),
            Err(_) => Err(Error::invalid_input(format!(
                "token dict is neither a service account key ({}) nor user credentials with \
                 refresh_token, client_id and client_secret",
                sa_err.message()
            ))),
        },
    }
}

/// An fsfast [`Value`] map (a Python dict) as JSON.
pub fn value_map_to_json(m: &std::collections::BTreeMap<String, Value>) -> Map<String, Json> {
    m.iter().map(|(k, v)| (k.clone(), value_to_json(v))).collect()
}

fn value_to_json(v: &Value) -> Json {
    match v {
        Value::Null => Json::Null,
        Value::Bool(b) => Json::Bool(*b),
        Value::Int(i) => Json::from(*i),
        Value::Float(f) => serde_json::Number::from_f64(*f).map_or(Json::Null, Json::Number),
        Value::Str(s) => Json::String(s.clone()),
        Value::Bytes(b) => Json::String(String::from_utf8_lossy(b).into_owned()),
        Value::Time(_) => Json::Null,
        Value::List(l) => Json::Array(l.iter().map(value_to_json).collect()),
        Value::Map(m) => Json::Object(value_map_to_json(m)),
    }
}

/// What application default credentials found in files.
#[derive(Debug, Clone)]
pub struct AdcFile {
    /// The credentials.
    pub credentials: FileCredentials,
    /// The project google-auth would report (before the
    /// `GOOGLE_CLOUD_PROJECT` override).
    pub project: Option<String>,
    /// Where they came from (for messages).
    pub origin: PathBuf,
}

/// The file-based part of google-auth's `default()`: the
/// `GOOGLE_APPLICATION_CREDENTIALS` file, else gcloud's ADC file.
/// `Ok(None)` when neither exists.
pub fn find_adc_file(env: &GcsEnv) -> Result<Option<AdcFile>> {
    let gcloud_path = env.gcloud_adc_path();
    if let Some(explicit) = env.non_empty("GOOGLE_APPLICATION_CREDENTIALS") {
        let explicit = PathBuf::from(explicit);
        // google-auth falls back to the Cloud SDK flow (which also finds
        // the gcloud project) when the variable names the gcloud file.
        if gcloud_path.as_deref() != Some(explicit.as_path()) {
            if !explicit.exists() {
                return Err(Error::invalid_input(format!(
                    "File {} was not found (GOOGLE_APPLICATION_CREDENTIALS).",
                    explicit.display()
                )));
            }
            let info = read_json_file(&explicit)?;
            let creds = credentials_from_typed_info(&info, &explicit.display().to_string())?;
            return Ok(Some(AdcFile {
                project: creds.project(),
                credentials: creds,
                origin: explicit,
            }));
        }
    }
    let Some(path) = gcloud_path.filter(|p| p.is_file()) else {
        return Ok(None);
    };
    let info = read_json_file(&path)?;
    let creds = credentials_from_typed_info(&info, &path.display().to_string())?;
    let project = creds.project().or_else(|| gcloud_project(env));
    Ok(Some(AdcFile {
        credentials: creds,
        project,
        origin: path,
    }))
}

/// The gcloud CLI's configured project (`gcloud config get project`), read
/// from its configuration files instead of running gcloud:
/// `CLOUDSDK_CORE_PROJECT`, else `[core] project` of the active
/// configuration (`CLOUDSDK_ACTIVE_CONFIG_NAME`, the `active_config` file,
/// or `default`).
pub fn gcloud_project(env: &GcsEnv) -> Option<String> {
    if let Some(p) = env.non_empty("CLOUDSDK_CORE_PROJECT") {
        return Some(p.to_owned());
    }
    let dir = env.gcloud_config_dir()?;
    let name = match env.non_empty("CLOUDSDK_ACTIVE_CONFIG_NAME") {
        Some(n) => n.to_owned(),
        None => std::fs::read_to_string(dir.join("active_config"))
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "default".to_owned()),
    };
    let text = std::fs::read_to_string(dir.join("configurations").join(format!("config_{name}"))).ok()?;
    ini_value(&text, "core", "project")
}

/// `key` in `[section]` of an INI document (gcloud's properties files).
fn ini_value(text: &str, section: &str, key: &str) -> Option<String> {
    let mut in_section = false;
    for line in text.lines() {
        let l = line.trim();
        if l.is_empty() || l.starts_with('#') || l.starts_with(';') {
            continue;
        }
        if let Some(s) = l.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            in_section = s.trim() == section;
            continue;
        }
        if in_section
            && let Some((k, v)) = l.split_once(['=', ':'])
            && k.trim() == key
        {
            let v = v.trim();
            return (!v.is_empty()).then(|| v.to_owned());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ini() {
        let t = "[core]\naccount = me@x\nproject = my-proj\n[compute]\nproject = other\n";
        assert_eq!(ini_value(t, "core", "project").as_deref(), Some("my-proj"));
        assert_eq!(ini_value(t, "compute", "project").as_deref(), Some("other"));
        assert_eq!(ini_value(t, "core", "zone"), None);
        assert_eq!(ini_value("[core]\nproject =\n", "core", "project"), None);
    }

    #[test]
    fn typed_info_dispatch() {
        let Json::Object(user) = json!({
            "type": "authorized_user",
            "client_id": "cid",
            "client_secret": "cs",
            "refresh_token": "rt",
            "quota_project_id": "qp",
        }) else {
            unreachable!()
        };
        match credentials_from_typed_info(&user, "f").unwrap() {
            FileCredentials::AuthorizedUser(u) => {
                assert_eq!(u.client_id, "cid");
                assert_eq!(u.token_uri, GOOGLE_TOKEN_URI);
                assert_eq!(u.quota_project_id.as_deref(), Some("qp"));
            }
            other => panic!("{other:?}"),
        }
        let Json::Object(ext) = json!({"type": "external_account"}) else { unreachable!() };
        assert_eq!(
            credentials_from_typed_info(&ext, "f").unwrap_err().kind(),
            fsfast_core::ErrorKind::Unsupported
        );
        let Json::Object(none) = json!({"client_id": "x"}) else { unreachable!() };
        assert!(credentials_from_typed_info(&none, "f").is_err());
        assert!(credentials_from_token_info(&none).is_err());
    }

    #[test]
    fn gcloud_files() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("gcloud");
        std::fs::create_dir_all(cfg.join("configurations")).unwrap();
        std::fs::write(cfg.join("active_config"), "work\n").unwrap();
        std::fs::write(
            cfg.join("configurations/config_work"),
            "[core]\nproject = work-proj\n",
        )
        .unwrap();
        let env = GcsEnv::from_pairs([("CLOUDSDK_CONFIG", cfg.to_str().unwrap())]);
        assert_eq!(gcloud_project(&env).as_deref(), Some("work-proj"));
        let env = GcsEnv::from_pairs([
            ("CLOUDSDK_CONFIG", cfg.to_str().unwrap()),
            ("CLOUDSDK_CORE_PROJECT", "env-proj"),
        ]);
        assert_eq!(gcloud_project(&env).as_deref(), Some("env-proj"));
        // No ADC file: nothing found.
        assert!(find_adc_file(&GcsEnv::from_pairs([("CLOUDSDK_CONFIG", cfg.to_str().unwrap())]))
            .unwrap()
            .is_none());
        // gcloud's ADC file with user credentials takes the gcloud project.
        std::fs::write(
            cfg.join("application_default_credentials.json"),
            r#"{"type":"authorized_user","client_id":"c","client_secret":"s","refresh_token":"r"}"#,
        )
        .unwrap();
        let found = find_adc_file(&GcsEnv::from_pairs([("CLOUDSDK_CONFIG", cfg.to_str().unwrap())]))
            .unwrap()
            .unwrap();
        assert_eq!(found.project.as_deref(), Some("work-proj"));
        // A missing explicit file is an error.
        let env = GcsEnv::from_pairs([("GOOGLE_APPLICATION_CREDENTIALS", "/nonexistent/x.json")]);
        assert!(find_adc_file(&env).is_err());
    }
}
