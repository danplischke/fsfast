//! STS-based providers: assume-role profiles and web identity (IRSA).

use std::collections::HashSet;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use bytes::Bytes;
use fsfast_core::{Error, ErrorKind, Result};
use fsfast_http_transport::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use fsfast_http_transport::{HttpClient, Method, Request, Url};
use tokio::sync::OnceCell;

use super::{
    ChainContext, ChainProvider, ContainerProvider, Credentials, EnvProvider, ImdsProvider,
    ProcessProvider, ProfileFile, ProfileKeysProvider, ProvideCredentials, section_keys,
};
use crate::encode::uri_encode;
use crate::error::S3ErrorParser;
use crate::profile::ProfileValue;
#[cfg(test)]
use crate::profile::{Env, ProfileFiles};
use crate::sigv4::{Signer, sha256_hex};
use crate::xml::parse_sts_credentials;

const STS_VERSION: &str = "2011-06-15";

/// A minimal STS client (`AssumeRole`, `AssumeRoleWithWebIdentity`).
#[derive(Debug)]
pub struct StsClient {
    http: HttpClient,
    endpoint: Url,
    region: String,
    signer: Signer,
}

/// Regions served by the global STS endpoint in "legacy" mode.
const LEGACY_GLOBAL_REGIONS: &[&str] = &[
    "ap-northeast-1",
    "ap-south-1",
    "ap-southeast-1",
    "ap-southeast-2",
    "aws-global",
    "ca-central-1",
    "eu-central-1",
    "eu-north-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "sa-east-1",
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
];

impl StsClient {
    /// The STS client for `ctx`: a configured endpoint, else the regional
    /// endpoint of `ctx.region`, else the global endpoint.
    pub fn new(ctx: &ChainContext) -> Result<Self> {
        let configured =
            crate::profile::configured_endpoint(&ctx.env, &ctx.profiles, &ctx.profile, "sts")?;
        let mode = ctx
            .env
            .get("AWS_STS_REGIONAL_ENDPOINTS")
            .or_else(|| {
                ctx.profiles
                    .get(&ctx.profile, "sts_regional_endpoints")
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "regional".to_owned());
        let (endpoint, region) = match (configured, ctx.region.as_deref()) {
            (Some(u), r) => (u, r.unwrap_or("us-east-1").to_owned()),
            (None, Some(r)) if mode == "legacy" && LEGACY_GLOBAL_REGIONS.contains(&r) => (
                "https://sts.amazonaws.com".to_owned(),
                "us-east-1".to_owned(),
            ),
            (None, Some(r)) => {
                let suffix = if r.starts_with("cn-") {
                    "amazonaws.com.cn"
                } else {
                    "amazonaws.com"
                };
                (format!("https://sts.{r}.{suffix}"), r.to_owned())
            }
            (None, None) => (
                "https://sts.amazonaws.com".to_owned(),
                "us-east-1".to_owned(),
            ),
        };
        let endpoint = Url::parse(&endpoint)
            .map_err(|e| Error::invalid_input(format!("invalid STS endpoint {endpoint:?}: {e}")))?;
        let mut cfg = ctx.http.clone();
        cfg.max_redirects = None;
        let http = HttpClient::builder(cfg)
            .error_parser(Arc::new(S3ErrorParser))
            .build()?;
        Ok(StsClient {
            http,
            endpoint,
            region,
            signer: Signer::new("sts"),
        })
    }

    async fn call(
        &self,
        params: &[(&str, &str)],
        creds: Option<&Credentials>,
    ) -> Result<Credentials> {
        let mut body = String::new();
        for (i, (k, v)) in params.iter().enumerate() {
            if i > 0 {
                body.push('&');
            }
            body.push_str(&uri_encode(k, false));
            body.push('=');
            body.push_str(&uri_encode(v, false));
        }
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_TYPE,
            HeaderValue::from_static("application/x-www-form-urlencoded; charset=utf-8"),
        );
        if let Some(c) = creds {
            self.signer.sign(
                "POST",
                &self.endpoint,
                &mut headers,
                &sha256_hex(body.as_bytes()),
                c,
                &self.region,
                SystemTime::now(),
            )?;
        }
        let action = params.first().map_or("", |p| p.1).to_owned();
        let mut req = Request::from_url(Method::POST, self.endpoint.clone())?
            .body(Bytes::from(body))
            .retry_safe(true)
            .path(format!("sts:{action}"));
        *req.headers_mut() = headers;
        let body = self
            .http
            .send_with(
                req,
                |resp| async move { resp.bytes_truncated(1 << 20).await },
            )
            .await
            .map_err(|e| crate::error::finish_error(e, None))?;
        let c = parse_sts_credentials(&body)?;
        Ok(Credentials::new(
            c.access_key_id,
            c.secret_access_key,
            Some(c.session_token),
            c.expiration,
        ))
    }

    /// `AssumeRole` with `source` credentials.
    pub async fn assume_role(
        &self,
        source: &Credentials,
        role: &RoleConfig,
    ) -> Result<Credentials> {
        let duration = role.duration_seconds.map(|d| d.to_string());
        let mut params = vec![
            ("Action", "AssumeRole"),
            ("Version", STS_VERSION),
            ("RoleArn", role.role_arn.as_str()),
            ("RoleSessionName", role.session_name.as_str()),
        ];
        if let Some(d) = &duration {
            params.push(("DurationSeconds", d));
        }
        if let Some(e) = &role.external_id {
            params.push(("ExternalId", e));
        }
        self.call(&params, Some(source)).await
    }

    /// `AssumeRoleWithWebIdentity` (an unsigned request).
    pub async fn assume_role_with_web_identity(
        &self,
        role_arn: &str,
        session_name: &str,
        token: &str,
    ) -> Result<Credentials> {
        self.call(
            &[
                ("Action", "AssumeRoleWithWebIdentity"),
                ("Version", STS_VERSION),
                ("RoleArn", role_arn),
                ("RoleSessionName", session_name),
                ("WebIdentityToken", token),
            ],
            None,
        )
        .await
    }
}

fn default_session_name() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format!("fsfast-session-{secs}")
}

/// The role settings of an assume-role profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoleConfig {
    /// `role_arn`.
    pub role_arn: String,
    /// `role_session_name`, or a generated name.
    pub session_name: String,
    /// `external_id`.
    pub external_id: Option<String>,
    /// `duration_seconds`.
    pub duration_seconds: Option<u32>,
}

/// Where the first role of a chain gets its credentials.
#[derive(Debug, Clone, PartialEq, Eq)]
enum RootSource {
    /// `credential_source = Environment | Ec2InstanceMetadata | EcsContainer`.
    Canonical(String),
    /// A profile resolved through the profile providers (web identity,
    /// shared credentials, process, config keys).
    Profile(String),
}

fn str_of<'a>(section: &'a crate::profile::Section, key: &str) -> Option<&'a str> {
    match section.get(key) {
        Some(ProfileValue::Str(s)) if !s.is_empty() => Some(s),
        _ => None,
    }
}

fn has_static(section: &crate::profile::Section) -> bool {
    str_of(section, "aws_access_key_id").is_some()
}

fn has_role(section: &crate::profile::Section) -> bool {
    str_of(section, "role_arn").is_some() && str_of(section, "web_identity_token_file").is_none()
}

/// Assume-role profile provider (`role_arn` + `source_profile` or
/// `credential_source`), including chains of roles.
#[derive(Debug)]
pub struct AssumeRoleProvider {
    ctx: Arc<ChainContext>,
    profile: String,
    sts: OnceCell<StsClient>,
}

impl AssumeRoleProvider {
    /// The provider for `profile`.
    pub fn new(ctx: Arc<ChainContext>, profile: String) -> Self {
        AssumeRoleProvider {
            ctx,
            profile,
            sts: OnceCell::new(),
        }
    }

    fn role_config(&self, name: &str, section: &crate::profile::Section) -> Result<RoleConfig> {
        if str_of(section, "mfa_serial").is_some() {
            return Err(Error::unsupported(format!(
                "assume-role profile {name:?} with mfa_serial (interactive MFA)"
            )));
        }
        Ok(RoleConfig {
            role_arn: str_of(section, "role_arn").unwrap_or_default().to_owned(),
            session_name: str_of(section, "role_session_name")
                .map_or_else(default_session_name, str::to_owned),
            external_id: str_of(section, "external_id").map(str::to_owned),
            duration_seconds: str_of(section, "duration_seconds").and_then(|d| d.parse().ok()),
        })
    }

    /// The roles to assume, innermost (closest to the source) last, and the
    /// source of the first credentials.
    fn plan(&self) -> Result<Option<(Vec<RoleConfig>, RootSource)>> {
        let profiles = &self.ctx.profiles;
        let Some(section) = profiles.profile(&self.profile) else {
            return Ok(None);
        };
        if !has_role(section) {
            return Ok(None);
        }
        let mut roles = Vec::new();
        let mut visited: HashSet<String> = HashSet::new();
        let mut name = self.profile.clone();
        loop {
            let section = profiles
                .profile(&name)
                .ok_or_else(|| Error::invalid_input(format!("profile {name:?} does not exist")))?;
            roles.push(self.role_config(&name, section)?);
            visited.insert(name.clone());
            let source_profile = str_of(section, "source_profile");
            let credential_source = str_of(section, "credential_source");
            match (source_profile, credential_source) {
                (Some(_), Some(_)) => {
                    return Err(Error::invalid_input(format!(
                        "The profile \"{name}\" contains both source_profile and credential_source."
                    )));
                }
                (None, None) => {
                    return Err(Error::new(
                        ErrorKind::PermissionDenied,
                        format!(
                            "Partial credentials found in assume-role, missing: source_profile or \
                             credential_source (profile {name:?})"
                        ),
                    ));
                }
                (None, Some(cs)) => {
                    if !matches!(cs, "Environment" | "Ec2InstanceMetadata" | "EcsContainer") {
                        return Err(Error::invalid_input(format!(
                            "The credential source \"{cs}\" referenced in profile \"{name}\" is not valid."
                        )));
                    }
                    return Ok(Some((roles, RootSource::Canonical(cs.to_owned()))));
                }
                (Some(src), None) => {
                    let src_section = profiles.profile(src).ok_or_else(|| {
                        Error::invalid_input(format!(
                            "The source_profile \"{src}\" referenced in the profile \"{name}\" does not exist."
                        ))
                    })?;
                    if visited.contains(src) {
                        // Only a profile sourcing its own static keys may
                        // reference itself.
                        if src == name && has_static(src_section) {
                            return Ok(Some((roles, RootSource::Profile(src.to_owned()))));
                        }
                        return Err(Error::invalid_input(format!(
                            "Infinite loop in credential configuration detected. Attempting to load \
                             from profile {src} which has already been visited."
                        )));
                    }
                    if has_static(src_section) || !has_role(src_section) {
                        return Ok(Some((roles, RootSource::Profile(src.to_owned()))));
                    }
                    name = src.to_owned();
                }
            }
        }
    }

    async fn root_credentials(&self, root: &RootSource) -> Result<Credentials> {
        let ctx = &self.ctx;
        let found = match root {
            RootSource::Canonical(cs) => match cs.as_str() {
                "Environment" => EnvProvider::new(ctx.env.clone()).provide().await?,
                "Ec2InstanceMetadata" => {
                    ImdsProvider::new(&ctx.env, &ctx.profiles, &ctx.profile)
                        .provide()
                        .await?
                }
                _ => {
                    ContainerProvider::new(ctx.env.clone(), ctx.container_base.clone())
                        .provide()
                        .await?
                }
            },
            RootSource::Profile(p) => {
                let chain = ChainProvider::new(vec![
                    Arc::new(WebIdentityProvider::new(ctx.clone(), p.clone(), true)),
                    Arc::new(ProfileKeysProvider::new(
                        ctx.profiles.clone(),
                        p.clone(),
                        ProfileFile::Credentials,
                    )),
                    Arc::new(ProcessProvider::new(ctx.profiles.clone(), p.clone())),
                    Arc::new(ProfileKeysProvider::new(
                        ctx.profiles.clone(),
                        p.clone(),
                        ProfileFile::Config,
                    )),
                ]);
                match chain.provide().await? {
                    Some(c) => Some(c),
                    // Self-referencing profile: its static keys in either file.
                    None => section_keys(ctx.profiles.profile(p), "source profile")?,
                }
            }
        };
        found.ok_or_else(|| {
            Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "no source credentials for assume-role profile {:?} ({root:?})",
                    self.profile
                ),
            )
        })
    }
}

#[async_trait]
impl ProvideCredentials for AssumeRoleProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        let Some((roles, root)) = self.plan()? else {
            return Ok(None);
        };
        let sts = self
            .sts
            .get_or_try_init(|| async { StsClient::new(&self.ctx) })
            .await?;
        let mut creds = self.root_credentials(&root).await?;
        for role in roles.iter().rev() {
            creds = sts.assume_role(&creds, role).await?;
        }
        Ok(Some(creds))
    }

    fn name(&self) -> &'static str {
        "assume-role"
    }
}

/// `AssumeRoleWithWebIdentity` from a token file (EKS IRSA and similar).
#[derive(Debug)]
pub struct WebIdentityProvider {
    ctx: Arc<ChainContext>,
    profile: String,
    disable_env: bool,
    sts: OnceCell<StsClient>,
}

impl WebIdentityProvider {
    /// The provider for `profile`; with `disable_env` only the profile's
    /// settings count (botocore when a profile is given explicitly).
    pub fn new(ctx: Arc<ChainContext>, profile: String, disable_env: bool) -> Self {
        WebIdentityProvider {
            ctx,
            profile,
            disable_env,
            sts: OnceCell::new(),
        }
    }

    fn setting(&self, env_key: &str, key: &str) -> Option<String> {
        if !self.disable_env
            && let Some(v) = self.ctx.env.get(env_key)
        {
            return Some(v);
        }
        self.ctx.profiles.get(&self.profile, key).map(str::to_owned)
    }
}

#[async_trait]
impl ProvideCredentials for WebIdentityProvider {
    async fn provide(&self) -> Result<Option<Credentials>> {
        let Some(token_file) =
            self.setting("AWS_WEB_IDENTITY_TOKEN_FILE", "web_identity_token_file")
        else {
            return Ok(None);
        };
        let role_arn = self.setting("AWS_ROLE_ARN", "role_arn").ok_or_else(|| {
            Error::invalid_input("The provided profile or the current environment is configured to assume role with web identity but has no role ARN configured. Ensure that the profile has the role_arnconfiguration set or the AWS_ROLE_ARN env var is set.")
        })?;
        let session = self
            .setting("AWS_ROLE_SESSION_NAME", "role_session_name")
            .unwrap_or_else(default_session_name);
        let path = self.ctx.env.expand(&token_file);
        let token = tokio::fs::read_to_string(&path).await.map_err(|e| {
            Error::new(
                ErrorKind::PermissionDenied,
                format!(
                    "cannot read web identity token file {}: {e}",
                    path.display()
                ),
            )
        })?;
        let sts = self
            .sts
            .get_or_try_init(|| async { StsClient::new(&self.ctx) })
            .await?;
        Ok(Some(
            sts.assume_role_with_web_identity(&role_arn, &session, token.trim())
                .await?,
        ))
    }

    fn name(&self) -> &'static str {
        "assume-role-with-web-identity"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(config: &str, creds: &str, profile: &str) -> AssumeRoleProvider {
        let ctx = ChainContext::new(
            Env::from_map::<[(&str, &str); 0], _, _>([]),
            Arc::new(ProfileFiles::from_texts(Some(config), Some(creds))),
            profile.into(),
            true,
        );
        AssumeRoleProvider::new(Arc::new(ctx), profile.into())
    }

    #[test]
    fn plans_role_chains() {
        let config = "\
[profile a]
role_arn = arn:aws:iam::1:role/a
source_profile = b
role_session_name = sess-a
external_id = ext
duration_seconds = 900
[profile b]
role_arn = arn:aws:iam::1:role/b
source_profile = base
[profile base]
region = us-east-1
[profile selfref]
role_arn = arn:aws:iam::1:role/s
source_profile = selfref
[profile loop1]
role_arn = arn:aws:iam::1:role/l1
source_profile = loop2
[profile loop2]
role_arn = arn:aws:iam::1:role/l2
source_profile = loop1
[profile ecs]
role_arn = arn:aws:iam::1:role/e
credential_source = EcsContainer
[profile both]
role_arn = arn:aws:iam::1:role/x
credential_source = Environment
source_profile = base
[profile mfa]
role_arn = arn:aws:iam::1:role/m
source_profile = base
mfa_serial = arn:aws:iam::1:mfa/me
";
        let creds = "[base]\naws_access_key_id = AK\naws_secret_access_key = SK\n[selfref]\naws_access_key_id = AK2\naws_secret_access_key = SK2\n";
        let (roles, root) = provider(config, creds, "a").plan().unwrap().unwrap();
        assert_eq!(roles.len(), 2);
        assert_eq!(roles[0].role_arn, "arn:aws:iam::1:role/a");
        assert_eq!(roles[0].session_name, "sess-a");
        assert_eq!(roles[0].external_id.as_deref(), Some("ext"));
        assert_eq!(roles[0].duration_seconds, Some(900));
        assert!(roles[1].session_name.starts_with("fsfast-session-"));
        assert_eq!(root, RootSource::Profile("base".into()));

        let (roles, root) = provider(config, creds, "selfref").plan().unwrap().unwrap();
        assert_eq!(roles.len(), 1);
        assert_eq!(root, RootSource::Profile("selfref".into()));

        assert!(provider(config, creds, "loop1").plan().is_err());
        assert_eq!(
            provider(config, creds, "ecs").plan().unwrap().unwrap().1,
            RootSource::Canonical("EcsContainer".into())
        );
        assert!(provider(config, creds, "both").plan().is_err());
        assert_eq!(
            provider(config, creds, "mfa").plan().unwrap_err().kind(),
            ErrorKind::Unsupported
        );
        assert!(provider(config, creds, "base").plan().unwrap().is_none());
        assert!(provider(config, creds, "missing").plan().unwrap().is_none());
    }

    #[test]
    fn sts_endpoints() {
        let mk = |env: Vec<(&str, &str)>, region: Option<&str>| {
            let mut ctx = ChainContext::new(
                Env::from_map(env),
                Arc::new(ProfileFiles::default()),
                "default".into(),
                false,
            );
            ctx.region = region.map(str::to_owned);
            let c = StsClient::new(&ctx).unwrap();
            (c.endpoint.to_string(), c.region)
        };
        assert_eq!(
            mk(vec![], None),
            ("https://sts.amazonaws.com/".into(), "us-east-1".into())
        );
        assert_eq!(
            mk(vec![], Some("eu-west-1")),
            (
                "https://sts.eu-west-1.amazonaws.com/".into(),
                "eu-west-1".into()
            )
        );
        assert_eq!(
            mk(
                vec![("AWS_STS_REGIONAL_ENDPOINTS", "legacy")],
                Some("eu-west-1")
            ),
            ("https://sts.amazonaws.com/".into(), "us-east-1".into())
        );
        assert_eq!(
            mk(vec![], Some("cn-north-1")).0,
            "https://sts.cn-north-1.amazonaws.com.cn/"
        );
        assert_eq!(
            mk(
                vec![("AWS_ENDPOINT_URL_STS", "http://127.0.0.1:1234")],
                Some("eu-west-1")
            ),
            ("http://127.0.0.1:1234/".into(), "eu-west-1".into())
        );
    }
}
