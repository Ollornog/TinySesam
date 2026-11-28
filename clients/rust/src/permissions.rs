//! Registering the application's permissions with TinySesam (spec §3.4, T-101).
//!
//! [`register_request`] checks a manifest and builds the request without any network; with the feature `jwks` (the
//! crate's network feature) [`register_permissions`] sends it. Registering grants nothing: an administrator assigns
//! permissions to roles, and the proxy then sends the account's permissions for this application (see
//! [`crate::Identity::has_permission`]).

use crate::error::ConfigError;
use serde_json::{Value, json};
use std::net::IpAddr;

/// The largest manifest TinySesam takes per application.
pub const MAX_PERMISSIONS: usize = 200;

/// The request [`register_permissions`] sends: `PUT <base>/auth/api/apps/<app>/permissions` with `body` as JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct PermissionRequest {
    /// Always `PUT`.
    pub method: &'static str,
    /// The address, straight at TinySesam (never through the proxy).
    pub url: String,
    /// `{"permissions": [...]}`.
    pub body: Value,
}

fn app_id_ok(app: &str) -> bool {
    let b = app.as_bytes();
    !b.is_empty()
        && b.len() <= 32
        && b[0].is_ascii_lowercase()
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'_')
}

/// `^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$` without a regex dependency.
fn permission_name_ok(name: &str) -> bool {
    let parts: Vec<&str> = name.split('.').collect();
    if !(2..=4).contains(&parts.len()) {
        return false;
    }
    let tail_ok = |p: &str| {
        p.bytes()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'_' || c == b'-')
    };
    let first = parts[0].as_bytes();
    !first.is_empty()
        && first.len() <= 32
        && first[0].is_ascii_lowercase()
        && tail_ok(parts[0])
        && parts[1..]
            .iter()
            .all(|p| !p.is_empty() && p.len() <= 32 && tail_ok(p))
}

fn base_url_ok(base: &str) -> bool {
    let (scheme, rest) = match base.split_once("://") {
        Some(x) => x,
        None => return false,
    };
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        stripped.split(']').next().unwrap_or_default()
    } else {
        authority.rsplit_once(':').map_or(authority, |(h, _)| h)
    };
    match scheme {
        "https" => !host.is_empty(),
        "http" => host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
        _ => false,
    }
}

/// Checks a manifest the way spec §3.4 asks and builds the request, without sending it. Refuses (a [`ConfigError`]) a
/// base URL that is not `https` (plain `http` only to a loopback address), an application id outside
/// `^[a-z][a-z0-9_]{0,31}$`, a manifest that is no list or has more than [`MAX_PERMISSIONS`] entries, an entry that is
/// no object or whose name breaks the rule, and a name twice. TinySesam checks labels and descriptions itself.
pub fn register_request(
    base_url: &str,
    app: &str,
    permissions: &Value,
) -> Result<PermissionRequest, ConfigError> {
    if !base_url_ok(base_url) {
        return Err(ConfigError::new(
            "the base URL must be https (plain http only to a loopback address)",
        ));
    }
    if !app_id_ok(app) {
        return Err(ConfigError::new(
            "the application id must match ^[a-z][a-z0-9_]{0,31}$",
        ));
    }
    let list = permissions
        .as_array()
        .filter(|l| l.len() <= MAX_PERMISSIONS)
        .ok_or_else(|| {
            ConfigError::new(format!(
                "the manifest is a list of at most {MAX_PERMISSIONS} permissions"
            ))
        })?;
    let mut seen: Vec<&str> = Vec::new();
    for entry in list {
        let name = entry
            .as_object()
            .and_then(|o| o.get("name"))
            .and_then(Value::as_str)
            .filter(|n| permission_name_ok(n))
            .ok_or_else(|| {
                ConfigError::new(
                    "every permission is an object whose name matches the rule of spec §3.4",
                )
            })?;
        if seen.contains(&name) {
            return Err(ConfigError::new("a permission name twice"));
        }
        seen.push(name);
    }
    Ok(PermissionRequest {
        method: "PUT",
        url: format!(
            "{}/auth/api/apps/{app}/permissions",
            base_url.trim_end_matches('/')
        ),
        body: json!({ "permissions": list }),
    })
}

/// TinySesam did not take the manifest: not reachable (`status` 0) or any answer but 200.
#[cfg(feature = "jwks")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationFailed {
    /// The HTTP status, 0 without an answer.
    pub status: u16,
}

#[cfg(feature = "jwks")]
impl std::fmt::Display for RegistrationFailed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "permission registration failed ({})", self.status)
    }
}

#[cfg(feature = "jwks")]
impl std::error::Error for RegistrationFailed {}

/// Registers the application's whole manifest with TinySesam (`PUT /auth/api/apps/{id}/permissions`) with an
/// automation key of the application's service account (scope `permissions:register`). Registering grants nothing.
/// Returns TinySesam's answer (`added`, `updated`, `returned`, `orphaned`). A manifest [`register_request`] refuses is
/// never sent (`Err(Ok(ConfigError))`); any answer but 200 is `Err(Err(RegistrationFailed))`. Deadline
/// [`crate::FETCH_DEADLINE`]; the key goes in `X-Api-Key` and never into an error.
#[cfg(feature = "jwks")]
pub async fn register_permissions(
    client: &reqwest::Client,
    base_url: &str,
    app: &str,
    permissions: &Value,
    api_key: &str,
) -> Result<serde_json::Map<String, Value>, Result<ConfigError, RegistrationFailed>> {
    let req = register_request(base_url, app, permissions).map_err(Ok)?;
    if api_key.is_empty() || crate::strict::has_control(api_key) {
        return Err(Ok(ConfigError::new("an API key is required")));
    }
    let failed = |status: u16| Err(Err(RegistrationFailed { status }));
    let resp = match client
        .put(&req.url)
        .header("X-Api-Key", api_key)
        .header("Accept", "application/json")
        .header("Content-Type", "application/json")
        .body(req.body.to_string())
        .timeout(crate::FETCH_DEADLINE)
        .send()
        .await
    {
        Ok(r) => r,
        Err(_) => return failed(0),
    };
    let status = resp.status().as_u16();
    if status != 200 {
        return failed(status);
    }
    match resp.bytes().await {
        Ok(body) if body.len() <= crate::JWKS_MAX_BODY => match crate::strict::json_object(&body) {
            Some(map) => Ok(map),
            None => failed(status),
        },
        _ => failed(status),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_and_ids() {
        for good in ["docs.read", "a.b.c.d", "docs-x.read_all", "d.x"] {
            assert!(permission_name_ok(good), "{good}");
        }
        for bad in [
            "docs",
            "Docs.read",
            "docs.",
            ".docs",
            "a.b.c.d.e",
            "docs.re ad",
            "1docs.read",
            "docs.READ",
        ] {
            assert!(!permission_name_ok(bad), "{bad}");
        }
        assert!(
            app_id_ok("docs_2")
                && !app_id_ok("Docs")
                && !app_id_ok("2docs")
                && !app_id_ok("docs/x")
        );
        assert!(base_url_ok("https://auth.example.com") && base_url_ok("http://127.0.0.1:8000"));
        assert!(base_url_ok("http://[::1]:8000") && base_url_ok("http://localhost"));
        assert!(
            !base_url_ok("http://auth.example.com")
                && !base_url_ok("ftp://x")
                && !base_url_ok("https://u@h")
        );
    }
}
