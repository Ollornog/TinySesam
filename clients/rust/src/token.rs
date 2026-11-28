//! Token mode (spec §4): the identity from a gate token whose Ed25519 signature the client verifies itself.

use crate::error::{ConfigError, TokenError};
use crate::identity::{Identity, check_account_kind};
use crate::keys::{KeySet, PublicKey};
use crate::strict::{b64url, has_control, json_object};
use ed25519_dalek::Signature;
use serde_json::{Map, Value};
use std::time::{SystemTime, UNIX_EPOCH};

/// A token larger than this many bytes is `malformed` (spec §4.4 step 1).
pub const MAX_TOKEN_BYTES: usize = 4096;
/// The largest clock leeway a client may allow, in seconds (spec §4.4).
pub const MAX_LEEWAY: u32 = 60;
/// The longest lifetime `exp − nbf` of a gate token, in seconds.
pub const MAX_LIFETIME: i64 = 3600;
/// The only algorithm: a constant of the client, never the header's value.
pub const ALGORITHM: &str = "EdDSA";
/// The `typ` of a gate token (compared ASCII case-insensitively).
pub const TOKEN_TYPE: &str = "tinysesam-gate+jwt";

pub(crate) const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;
const HEADER_MEMBERS: [&str; 3] = ["alg", "typ", "kid"];
const IDENTITY_CLAIMS: [&str; 8] = [
    "ts_user",
    "ts_name",
    "ts_email",
    "ts_groups",
    "ts_id",
    "ts_auth",
    "ts_kind",
    "ts_perms",
];

/// Seconds since the Unix epoch from the system clock (0 if the clock stands before 1970).
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// Issuer, audience and clock leeway — from configuration, never from the request (spec §4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenConfig {
    issuer: String,
    audience: String,
    leeway: u32,
}

impl TokenConfig {
    /// `issuer` is TinySesam's `base_url` without a trailing slash; `audience` is the exact string the proxy names
    /// in `audience_whitelist`, including `|roles=…` when the route requires roles. Leeway 0.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<TokenConfig, ConfigError> {
        let (issuer, audience) = (issuer.into(), audience.into());
        if issuer.is_empty() || has_control(&issuer) {
            return Err(ConfigError::new("no or an invalid issuer"));
        }
        if audience.is_empty() || has_control(&audience) {
            return Err(ConfigError::new("no or an invalid audience"));
        }
        Ok(TokenConfig {
            issuer,
            audience,
            leeway: 0,
        })
    }

    /// A clock leeway of at most 60 seconds; more is a configuration error.
    pub fn with_leeway(mut self, seconds: u32) -> Result<TokenConfig, ConfigError> {
        if seconds > MAX_LEEWAY {
            return Err(ConfigError::new(format!(
                "clock leeway above {MAX_LEEWAY} seconds"
            )));
        }
        self.leeway = seconds;
        Ok(self)
    }

    /// The configured issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The configured audience.
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// The configured clock leeway in seconds.
    pub fn leeway(&self) -> u32 {
        self.leeway
    }

    /// Steps 7–10 for a pre-checked token and the key of its `kid`: signature, payload, claims.
    pub fn finish(
        &self,
        token: Unverified<'_>,
        key: &PublicKey,
        now: i64,
    ) -> Result<Verified, TokenError> {
        key.0
            .verify_strict(token.signing_input.as_bytes(), &token.signature)
            .map_err(|_| TokenError::Signature)?;
        let claims = json_object(&token.payload).ok_or(TokenError::Malformed)?;
        self.check_claims(&claims, now)?;
        let identity = identity_from_claims(&claims)?;
        Ok(Verified {
            claims: Claims(claims),
            identity,
        })
    }

    /// The whole check against a key set: [`precheck`], the key of the `kid`, [`finish`](Self::finish).
    pub fn verify_with(&self, jws: &str, keys: &KeySet, now: i64) -> Result<Verified, TokenError> {
        let token = precheck(jws)?;
        let key = keys.get(token.kid()).ok_or(TokenError::Kid)?.clone();
        self.finish(token, &key, now)
    }

    fn check_claims(&self, c: &Map<String, Value>, now: i64) -> Result<(), TokenError> {
        use TokenError::Claims as Bad;
        let iss = c.get("iss").and_then(Value::as_str).ok_or(Bad)?;
        let sub = c.get("sub").and_then(Value::as_str).ok_or(Bad)?;
        let aud: Vec<&str> = match c.get("aud") {
            Some(Value::String(a)) => vec![a.as_str()],
            Some(Value::Array(list)) if !list.is_empty() => list
                .iter()
                .map(Value::as_str)
                .collect::<Option<Vec<_>>>()
                .ok_or(Bad)?,
            _ => return Err(Bad),
        };
        let int = |name: &str| -> Result<i64, TokenError> {
            match c.get(name).and_then(Value::as_u64) {
                Some(v) if v <= MAX_SAFE_INTEGER => Ok(v as i64),
                _ => Err(Bad),
            }
        };
        let (iat, nbf, exp) = (int("iat")?, int("nbf")?, int("exp")?);
        if c.get("jti").is_some_and(|v| !v.is_string()) {
            return Err(Bad);
        }
        for name in IDENTITY_CLAIMS {
            if let Some(v) = c.get(name)
                && has_control(v.as_str().ok_or(Bad)?)
            {
                return Err(Bad);
            }
        }
        if sub.is_empty() || has_control(sub) {
            return Err(Bad);
        }
        if c.get("ts_id").is_some_and(|v| v.as_str() != Some(sub)) {
            return Err(Bad);
        }
        if iat > nbf {
            return Err(Bad);
        }
        // Spec v2: ts_kind present and exactly user or service, never service with a session (its type was checked
        // with the identity claims above).
        let text = |name: &str| c.get(name).and_then(Value::as_str).unwrap_or_default();
        check_account_kind(text("ts_kind"), text("ts_auth")).ok_or(Bad)?;
        if iss != self.issuer {
            return Err(TokenError::Issuer);
        }
        if !aud.contains(&self.audience.as_str()) {
            return Err(TokenError::Audience);
        }
        if exp <= nbf || exp - nbf > MAX_LIFETIME {
            return Err(TokenError::Lifetime);
        }
        let leeway = i64::from(self.leeway);
        if nbf > now.saturating_add(leeway) {
            return Err(TokenError::NotYetValid);
        }
        if exp + leeway <= now {
            return Err(TokenError::Expired);
        }
        Ok(())
    }
}

/// A token that passed steps 1–5: size, structure, header JSON, header members, signature length. Its payload is not
/// parsed yet and its signature not verified — only the format-checked `kid` is readable.
pub struct Unverified<'a> {
    pub(crate) signing_input: &'a str,
    pub(crate) payload: Vec<u8>,
    pub(crate) signature: Signature,
    kid: String,
}

impl Unverified<'_> {
    /// The `kid`: exactly 16 lowercase hex digits (checked), safe to log and to look up.
    pub fn kid(&self) -> &str {
        &self.kid
    }
}

impl std::fmt::Debug for Unverified<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Unverified")
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

/// Steps 1–5 of spec §4.4: everything that is decided before a key is chosen.
pub fn precheck(jws: &str) -> Result<Unverified<'_>, TokenError> {
    precheck_typ(jws, TOKEN_TYPE)
}

/// Steps 1–5 for a JWS of the given `typ`: a gate token (spec §4.4) or an approval confirmation
/// (spec/approval-token.md §4, the same steps with its own `typ`).
pub(crate) fn precheck_typ<'a>(jws: &'a str, typ: &str) -> Result<Unverified<'a>, TokenError> {
    if jws.len() > MAX_TOKEN_BYTES {
        return Err(TokenError::Malformed);
    }
    let mut parts = jws.split('.');
    let (Some(h_seg), Some(p_seg), Some(s_seg), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TokenError::Malformed);
    };
    if h_seg.is_empty() || p_seg.is_empty() {
        return Err(TokenError::Malformed);
    }
    let head_raw = b64url(h_seg).ok_or(TokenError::Malformed)?;
    let payload = b64url(p_seg).ok_or(TokenError::Malformed)?;
    let sig = b64url(s_seg).ok_or(TokenError::Malformed)?;
    let head = json_object(&head_raw).ok_or(TokenError::Malformed)?;
    if head.keys().any(|k| !HEADER_MEMBERS.contains(&k.as_str())) {
        return Err(TokenError::Header);
    }
    if head.get("alg").and_then(Value::as_str) != Some(ALGORITHM) {
        return Err(TokenError::Header);
    }
    if !head
        .get("typ")
        .and_then(Value::as_str)
        .is_some_and(|t| t.eq_ignore_ascii_case(typ))
    {
        return Err(TokenError::Header);
    }
    let kid = match head.get("kid").and_then(Value::as_str) {
        Some(k)
            if k.len() == 16
                && k.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) =>
        {
            k
        }
        _ => return Err(TokenError::Kid),
    };
    let sig: [u8; 64] = sig.try_into().map_err(|_| TokenError::Signature)?;
    Ok(Unverified {
        signing_input: &jws[..h_seg.len() + 1 + p_seg.len()],
        payload,
        signature: Signature::from_bytes(&sig),
        kid: kid.to_owned(),
    })
}

fn identity_from_claims(c: &Map<String, Value>) -> Result<Identity, TokenError> {
    let text = |name: &str| {
        c.get(name)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    // Checked in check_claims already; refused again rather than guessed, should the order ever change.
    let account_kind =
        check_account_kind(&text("ts_kind"), &text("ts_auth")).ok_or(TokenError::Claims)?;
    Ok(Identity::new(
        text("ts_user"),
        text("ts_name"),
        text("ts_email"),
        &text("ts_groups"),
        text("sub"),
        &text("ts_auth"),
        account_kind,
    )
    .with_permissions(&text("ts_perms")))
}

/// The claims of a verified token. Unknown claims are kept but mean nothing to the client.
#[derive(Debug, Clone, PartialEq)]
pub struct Claims(Map<String, Value>);

impl Claims {
    /// All claims as a JSON object.
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    /// The issuer.
    pub fn iss(&self) -> &str {
        self.0
            .get("iss")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The account ID.
    pub fn sub(&self) -> &str {
        self.0
            .get("sub")
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The token identifier, if present.
    pub fn jti(&self) -> Option<&str> {
        self.0.get("jti").and_then(Value::as_str)
    }

    /// Not before (seconds since the epoch).
    pub fn nbf(&self) -> i64 {
        self.0
            .get("nbf")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    /// Expiry (seconds since the epoch).
    pub fn exp(&self) -> i64 {
        self.0
            .get("exp")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }
}

/// A valid token: its claims and the identity they carry.
#[derive(Debug, Clone, PartialEq)]
pub struct Verified {
    /// The claims.
    pub claims: Claims,
    /// The identity (spec §4.1).
    pub identity: Identity,
}

/// Token mode with fixed keys: configuration plus key set, checked at construction.
#[derive(Debug, Clone)]
pub struct TokenVerifier {
    config: TokenConfig,
    keys: KeySet,
}

impl TokenVerifier {
    /// A verifier; an empty key set is a configuration error.
    pub fn new(config: TokenConfig, keys: KeySet) -> Result<TokenVerifier, ConfigError> {
        if keys.is_empty() {
            return Err(ConfigError::new("no gate key"));
        }
        Ok(TokenVerifier { config, keys })
    }

    /// Checks a token against the system clock.
    pub fn verify(&self, jws: &str) -> Result<Verified, TokenError> {
        self.verify_at(jws, unix_now())
    }

    /// Checks a token at a given time (seconds since the epoch).
    pub fn verify_at(&self, jws: &str, now: i64) -> Result<Verified, TokenError> {
        self.config.verify_with(jws, &self.keys, now)
    }

    /// The configuration.
    pub fn config(&self) -> &TokenConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_errors() {
        assert!(TokenConfig::new("", "app.example.com").is_err());
        assert!(TokenConfig::new("https://auth.example.com", "").is_err());
        assert!(TokenConfig::new("https://auth.example.com", "app\n").is_err());
        let cfg = TokenConfig::new("https://auth.example.com", "app.example.com").unwrap();
        assert!(cfg.clone().with_leeway(60).is_ok());
        assert!(cfg.clone().with_leeway(61).is_err());
        assert!(TokenVerifier::new(cfg, KeySet::default()).is_err());
    }

    /// The vectors cannot tell a malformed but hex-like `kid` from an unknown one with fixed keys (both are `kid`);
    /// the format check decides whether a key set is consulted (and fetched) at all, so it is pinned here.
    #[test]
    fn kid_format_is_checked_before_any_lookup() {
        use base64::Engine;
        let b64 = |s: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(s);
        let sig = "A".repeat(86);
        let token = |kid: &str| {
            let head = format!(r#"{{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":{kid}}}"#);
            format!("{}.bm8.{sig}", b64(&head))
        };
        assert!(precheck(&token(r#""a033507ca61ad979""#)).is_ok());
        for kid in [
            r#""A033507CA61AD979""#,
            r#""a033507ca61ad97""#,
            r#""a033507ca61ad9790""#,
            r#""g033507ca61ad979""#,
            r#""a033507ca61ad97\u0000""#,
            r#""""#,
            "16",
            "null",
        ] {
            assert_eq!(precheck(&token(kid)).err(), Some(TokenError::Kid), "{kid}");
        }
    }

    #[test]
    fn precheck_never_reads_the_payload() {
        // A payload that is no JSON at all passes the pre-check: it is parsed only after the signature.
        let jws = "eyJhbGciOiJFZERTQSIsInR5cCI6InRpbnlzZXNhbS1nYXRlK2p3dCIsImtpZCI6ImEwMzM1MDdjYTYxYWQ5NzkifQ.bm8.\
                   AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert_eq!(precheck(jws).unwrap().kid(), "a033507ca61ad979");
    }
}
