//! Approval confirmations (`spec/approval-token.md`): the proof an application receives after a person confirmed one
//! of its sensitive actions in TinySesam with a fresh step-up — *this account has just confirmed exactly this action,
//! for this application, once.*
//!
//! The check runs in two parts so that any `jti` store fits, synchronous or asynchronous: [`ApprovalVerifier::check_at`]
//! runs steps 1–11 and returns a [`Checked`] whose claims stay locked until the application has written the `jti`
//! into its own store and called [`Checked::accept`] with the answer (step 12). [`ApprovalVerifier::verify_at`] does
//! both with a synchronous [`JtiStore`].
//!
//! ```
//! use tinysesam_gate::approval::{ApprovalConfig, ApprovalExpect, ApprovalVerifier};
//! use tinysesam_gate::KeySet;
//!
//! # let jwks = serde_json::json!({"keys": [{"kty": "OKP", "crv": "Ed25519",
//! #     "x": "JOXX4BdOKXI4TI3f3IRMxvEy7Dp8UFCu9yIrWAJuqOc", "kid": "e69f0aecb8602149"}]});
//! let keys = KeySet::from_jwks(&jwks).unwrap();           // /auth/approvals/jwks.json — never the gate key set
//! let verifier = ApprovalVerifier::new(ApprovalConfig::new("https://auth.example.com", "example").unwrap(), keys)
//!     .unwrap();
//! let expect = ApprovalExpect::new("example.collection.delete_permanently", "42")
//!     .field("collection", "c_81f2")
//!     .field("name", "Project Alpha");
//! // let claims = verifier.verify(&token, &expect, &|jti: &str, until: i64| insert_once(jti, until))?;
//! # let _ = (verifier, expect);
//! ```

use crate::error::{ConfigError, TokenError};
use crate::keys::{KeySet, PublicKey};
use crate::strict::{has_control, json_object};
use crate::token::{MAX_SAFE_INTEGER, Unverified, precheck_typ, unix_now};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::fmt;

/// The `typ` of a confirmation (compared ASCII case-insensitively) — never `tinysesam-gate+jwt`.
pub const APPROVAL_TOKEN_TYPE: &str = "tinysesam-approval+jwt";
/// The longest lifetime `exp − nbf` of a confirmation, in seconds.
pub const MAX_APPROVAL_LIFETIME: i64 = 300;
/// The largest clock leeway an application may allow, in seconds.
pub const MAX_APPROVAL_LEEWAY: u32 = 30;

const MAX_TEXT: usize = 128;
const MAX_SUB: usize = 1000;
const MAX_AMR: usize = 32;
const MAX_TYPE: usize = 100;
const REQUIRED: [&str; 12] = [
    "iss",
    "aud",
    "sub",
    "iat",
    "nbf",
    "exp",
    "jti",
    "auth_time",
    "amr",
    "act",
    "authorization_details",
    "ts_payload_sha256",
];

/// Why a confirmation was refused: the class of the **first** failing step of spec/approval-token.md §4. Every class
/// means the same to the application: do not carry the action out. Log the class, never the token.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ApprovalError {
    /// Steps 1–10: the classes the gate token shares (`malformed`, `header`, `kid`, `signature`, `key_unavailable`,
    /// `claims`, `issuer`, `audience`, `lifetime`, `not_yet_valid`, `expired`).
    Token(TokenError),
    /// Another action (step 11).
    ApprovalType,
    /// Other fields: a name, a JSON type or a value (step 11).
    ApprovalFields,
    /// Another account (step 11).
    Subject,
    /// Another browser session (step 11, browser entry).
    Nonce,
    /// The confirmation was used before (step 12).
    Replay,
    /// The `jti` store failed — refused, fails closed. Not a class of the specification.
    Store,
}

impl ApprovalError {
    /// The class name as the specification and the vectors spell it.
    pub fn class(&self) -> &'static str {
        match self {
            ApprovalError::Token(e) => e.class(),
            ApprovalError::ApprovalType => "approval_type",
            ApprovalError::ApprovalFields => "approval_fields",
            ApprovalError::Subject => "subject",
            ApprovalError::Nonce => "nonce",
            ApprovalError::Replay => "replay",
            ApprovalError::Store => "internal",
        }
    }
}

impl From<TokenError> for ApprovalError {
    fn from(e: TokenError) -> Self {
        ApprovalError::Token(e)
    }
}

impl fmt::Display for ApprovalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "approval confirmation refused: {}", self.class())
    }
}

impl std::error::Error for ApprovalError {}

/// The `jti` store of spec/approval-token.md §7: `remember` writes the id atomically (one `INSERT` into a table with a
/// unique key, shared by every process of the application) and answers `Ok(true)` only the first time. It may forget
/// the entry after `until` (Unix seconds). An `Err` refuses the confirmation.
pub trait JtiStore {
    /// Stores `jti` until `until`; `Ok(false)` when it was there already.
    fn remember(&self, jti: &str, until: i64) -> Result<bool, StoreFailed>;
}

/// A store that could not answer (the database is gone, …).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StoreFailed;

impl<F> JtiStore for F
where
    F: Fn(&str, i64) -> Result<bool, StoreFailed>,
{
    fn remember(&self, jti: &str, until: i64) -> Result<bool, StoreFailed> {
        self(jti, until)
    }
}

/// Issuer, the application's id and the clock leeway — from configuration, never from the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalConfig {
    issuer: String,
    app_id: String,
    leeway: u32,
}

impl ApprovalConfig {
    /// `issuer` is TinySesam's `base_url` without a trailing slash, `app_id` the application's own id. Leeway 0.
    pub fn new(
        issuer: impl Into<String>,
        app_id: impl Into<String>,
    ) -> Result<ApprovalConfig, ConfigError> {
        let (issuer, app_id) = (issuer.into(), app_id.into());
        if issuer.is_empty() || has_control(&issuer) {
            return Err(ConfigError::new("no or an invalid issuer"));
        }
        if app_id.is_empty() || has_control(&app_id) {
            return Err(ConfigError::new("no or an invalid application id"));
        }
        Ok(ApprovalConfig {
            issuer,
            app_id,
            leeway: 0,
        })
    }

    /// A clock leeway of at most 30 seconds; more is a configuration error.
    pub fn with_leeway(mut self, seconds: u32) -> Result<ApprovalConfig, ConfigError> {
        if seconds > MAX_APPROVAL_LEEWAY {
            return Err(ConfigError::new(format!(
                "clock leeway above {MAX_APPROVAL_LEEWAY} seconds for approvals"
            )));
        }
        self.leeway = seconds;
        Ok(self)
    }

    /// Steps 7–11 for a pre-checked confirmation and the key of its `kid`.
    pub fn check(
        &self,
        token: Unverified<'_>,
        key: &PublicKey,
        expect: &ApprovalExpect,
        now: i64,
    ) -> Result<Checked, ApprovalError> {
        key.0
            .verify_strict(token.signing_input.as_bytes(), &token.signature)
            .map_err(|_| TokenError::Signature)?;
        let c = json_object(&token.payload).ok_or(TokenError::Malformed)?;
        let times = check_claims(&c)?;
        if c["iss"].as_str() != Some(self.issuer.as_str()) {
            return Err(TokenError::Issuer.into());
        }
        if c["aud"].as_str() != Some(self.app_id.as_str()) {
            return Err(TokenError::Audience.into());
        }
        if times.exp <= times.nbf || times.exp - times.nbf > MAX_APPROVAL_LIFETIME {
            return Err(TokenError::Lifetime.into());
        }
        let leeway = i64::from(self.leeway);
        if times.nbf > now.saturating_add(leeway) {
            return Err(TokenError::NotYetValid.into());
        }
        if times.exp + leeway <= now {
            return Err(TokenError::Expired.into());
        }
        let entry = c["authorization_details"][0]
            .as_object()
            .cloned()
            .unwrap_or_default();
        if entry.get("type").and_then(Value::as_str) != Some(expect.kind.as_str()) {
            return Err(ApprovalError::ApprovalType);
        }
        if !same_fields(&entry, &expect.fields) {
            return Err(ApprovalError::ApprovalFields);
        }
        if c["sub"].as_str() != Some(expect.subject.as_str()) {
            return Err(ApprovalError::Subject);
        }
        if let Some(nonce) = &expect.nonce
            && c.get("nonce").and_then(Value::as_str) != Some(nonce.as_str())
        {
            return Err(ApprovalError::Nonce);
        }
        Ok(Checked {
            claims: ApprovalClaims(c),
            until: times.exp + leeway,
        })
    }
}

struct Times {
    nbf: i64,
    exp: i64,
}

fn text(v: Option<&Value>, limit: usize) -> bool {
    v.and_then(Value::as_str)
        .is_some_and(|s| !s.is_empty() && s.chars().count() <= limit && !has_control(s))
}

fn int(v: Option<&Value>) -> Option<i64> {
    v.and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
        .map(|n| n as i64)
}

/// A field value of an entry: a string, a boolean or an integer within ±(2^53 − 1) — nothing else.
fn is_field_value(v: &Value) -> bool {
    match v {
        Value::String(_) | Value::Bool(_) => true,
        Value::Number(n) => n
            .as_i64()
            .is_some_and(|i| i.unsigned_abs() <= MAX_SAFE_INTEGER),
        _ => false,
    }
}

/// Step 9: presence, types, `aud` as one string, exactly one entry, the digest, the order of the times.
fn check_claims(c: &Map<String, Value>) -> Result<Times, TokenError> {
    use TokenError::Claims as Bad;
    if REQUIRED.iter().any(|name| !c.contains_key(*name)) {
        return Err(Bad);
    }
    if !c["iss"].is_string() || !text(c.get("sub"), MAX_SUB) {
        return Err(Bad);
    }
    let (iat, nbf, exp, auth_time) = (
        int(c.get("iat")).ok_or(Bad)?,
        int(c.get("nbf")).ok_or(Bad)?,
        int(c.get("exp")).ok_or(Bad)?,
        int(c.get("auth_time")).ok_or(Bad)?,
    );
    if !text(c.get("jti"), MAX_TEXT) {
        return Err(Bad);
    }
    match c["amr"].as_array() {
        Some(amr) if !amr.is_empty() && amr.iter().all(|a| text(Some(a), MAX_AMR)) => {}
        _ => return Err(Bad),
    }
    if !c["act"].is_object() || !text(c["act"].get("sub"), MAX_TEXT) {
        return Err(Bad);
    }
    let digest = c["ts_payload_sha256"].as_str().ok_or(Bad)?;
    if c.contains_key("nonce") && !text(c.get("nonce"), MAX_TEXT) {
        return Err(Bad);
    }
    // `aud` is ONE string, the application's id — never an array, which could name several applications.
    if !c["aud"].is_string() {
        return Err(Bad);
    }
    let entry = match c["authorization_details"].as_array() {
        Some(list) if list.len() == 1 => list[0].as_object().ok_or(Bad)?,
        _ => return Err(Bad),
    };
    if !text(entry.get("type"), MAX_TYPE) || !entry.values().all(is_field_value) {
        return Err(Bad);
    }
    if digest != payload_digest(entry) {
        return Err(Bad);
    }
    if iat > nbf || auth_time > iat {
        return Err(Bad);
    }
    Ok(Times { nbf, exp })
}

/// Names, JSON types and values exactly: `1`, `"1"` and `true` are three different values.
fn same_fields(entry: &Map<String, Value>, want: &Map<String, Value>) -> bool {
    entry.len() == want.len() + 1
        && !want.contains_key("type")
        && want.iter().all(|(k, w)| {
            entry.get(k).is_some_and(|g| match (g, w) {
                (Value::Number(a), Value::Number(b)) => {
                    a.as_i64().is_some() && a.as_i64() == b.as_i64() && b.is_i64()
                }
                (Value::String(a), Value::String(b)) => a == b,
                (Value::Bool(a), Value::Bool(b)) => a == b,
                _ => false,
            })
        })
}

/// `ts_payload_sha256` of an entry: SHA-256 over its canonical form (RFC 8785 for string, integer and boolean
/// values, spec/approval-token.md §6), base64url without padding.
pub fn payload_digest(entry: &Map<String, Value>) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(canonical(entry).as_bytes()))
}

/// Members sorted by name (code point order), no whitespace, strings with only the escapes of RFC 8785, integers in
/// plain decimal, `true` and `false`.
fn canonical(entry: &Map<String, Value>) -> String {
    let mut names: Vec<&String> = entry.keys().collect();
    names.sort();
    let mut out = String::from("{");
    for (i, name) in names.into_iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        canonical_string(&mut out, name);
        out.push(':');
        match &entry[name] {
            Value::String(s) => canonical_string(&mut out, s),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => out.push_str(&n.to_string()),
            other => out.push_str(&other.to_string()),
        }
    }
    out.push('}');
    out
}

fn canonical_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\t' => out.push_str("\\t"),
            '\n' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\r' => out.push_str("\\r"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

/// The action the application stored when it asked — never taken from the confirmation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalExpect {
    kind: String,
    fields: Map<String, Value>,
    subject: String,
    nonce: Option<String>,
}

impl ApprovalExpect {
    /// The action type (`authorization_details[0].type`) and the account the application acts for (a decimal id).
    pub fn new(kind: impl Into<String>, subject: impl Into<String>) -> ApprovalExpect {
        ApprovalExpect {
            kind: kind.into(),
            fields: Map::new(),
            subject: subject.into(),
            nonce: None,
        }
    }

    /// One field exactly as sent: a string, a boolean or an integer (`serde_json::Value`, or anything that converts).
    #[must_use]
    pub fn field(mut self, name: impl Into<String>, value: impl Into<Value>) -> ApprovalExpect {
        self.fields.insert(name.into(), value.into());
        self
    }

    /// All fields at once.
    #[must_use]
    pub fn fields(mut self, fields: Map<String, Value>) -> ApprovalExpect {
        self.fields = fields;
        self
    }

    /// The `state` kept in the person's session (browser entry).
    #[must_use]
    pub fn nonce(mut self, state: impl Into<String>) -> ApprovalExpect {
        self.nonce = Some(state.into());
        self
    }
}

/// A confirmation that passed steps 1–11. Its claims stay locked until [`accept`](Self::accept) receives the answer
/// of the application's `jti` store (step 12).
#[must_use = "write the jti into the store and call accept — the action may not run before"]
#[derive(Debug)]
pub struct Checked {
    claims: ApprovalClaims,
    until: i64,
}

impl Checked {
    /// The id to write into the store.
    pub fn jti(&self) -> &str {
        self.claims.jti()
    }

    /// Until when the store must keep it (Unix seconds, `exp + leeway`).
    pub fn until(&self) -> i64 {
        self.until
    }

    /// Step 12: `first_use` is the store's answer — true only when the `jti` was written now.
    pub fn accept(self, first_use: bool) -> Result<ApprovalClaims, ApprovalError> {
        if first_use {
            Ok(self.claims)
        } else {
            Err(ApprovalError::Replay)
        }
    }
}

/// The claims of a valid confirmation. Unknown claims are kept but mean nothing to the check.
#[derive(Debug, Clone, PartialEq)]
pub struct ApprovalClaims(Map<String, Value>);

impl ApprovalClaims {
    /// All claims as a JSON object.
    pub fn as_map(&self) -> &Map<String, Value> {
        &self.0
    }

    fn str(&self, name: &str) -> &str {
        self.0.get(name).and_then(Value::as_str).unwrap_or_default()
    }

    /// The account that confirmed.
    pub fn sub(&self) -> &str {
        self.str("sub")
    }

    /// The approval id, handed out once.
    pub fn jti(&self) -> &str {
        self.str("jti")
    }

    /// Expiry (seconds since the epoch).
    pub fn exp(&self) -> i64 {
        self.0
            .get("exp")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    /// When the person stepped up for this approval.
    pub fn auth_time(&self) -> i64 {
        self.0
            .get("auth_time")
            .and_then(Value::as_i64)
            .unwrap_or_default()
    }

    /// How the person stepped up (RFC 8176 values).
    pub fn amr(&self) -> Vec<&str> {
        self.0
            .get("amr")
            .and_then(Value::as_array)
            .map(|a| a.iter().filter_map(Value::as_str).collect())
            .unwrap_or_default()
    }

    /// Who asked: `app:<application id>`.
    pub fn actor(&self) -> &str {
        self.0
            .get("act")
            .and_then(|a| a.get("sub"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    fn entry(&self) -> Option<&Map<String, Value>> {
        self.0.get("authorization_details")?.get(0)?.as_object()
    }

    /// The action type.
    pub fn kind(&self) -> &str {
        self.entry()
            .and_then(|e| e.get("type"))
            .and_then(Value::as_str)
            .unwrap_or_default()
    }

    /// The fields of the action (without `type`).
    pub fn fields(&self) -> Map<String, Value> {
        let mut out = self.entry().cloned().unwrap_or_default();
        out.remove("type");
        out
    }

    /// The browser entry's state, if any.
    pub fn nonce(&self) -> Option<&str> {
        self.0.get("nonce").and_then(Value::as_str)
    }
}

/// Steps 1–5 of spec/approval-token.md §4 (those of the gate token with the approval `typ`).
pub fn approval_precheck(jws: &str) -> Result<Unverified<'_>, TokenError> {
    precheck_typ(jws, APPROVAL_TOKEN_TYPE)
}

/// The approval check with a fixed approval key set (`/auth/approvals/jwks.json` — never the gate key set).
#[derive(Debug, Clone)]
pub struct ApprovalVerifier {
    config: ApprovalConfig,
    keys: KeySet,
}

impl ApprovalVerifier {
    /// A verifier; an empty key set is a configuration error.
    pub fn new(config: ApprovalConfig, keys: KeySet) -> Result<ApprovalVerifier, ConfigError> {
        if keys.is_empty() {
            return Err(ConfigError::new("no approval key"));
        }
        Ok(ApprovalVerifier { config, keys })
    }

    /// Steps 1–11 at a given time; write [`Checked::jti`] into the store, then [`Checked::accept`].
    pub fn check_at(
        &self,
        jws: &str,
        expect: &ApprovalExpect,
        now: i64,
    ) -> Result<Checked, ApprovalError> {
        let token = approval_precheck(jws)?;
        let key = self.keys.get(token.kid()).ok_or(TokenError::Kid)?.clone();
        self.config.check(token, &key, expect, now)
    }

    /// The whole check with a synchronous store, at a given time.
    pub fn verify_at(
        &self,
        jws: &str,
        expect: &ApprovalExpect,
        store: &dyn JtiStore,
        now: i64,
    ) -> Result<ApprovalClaims, ApprovalError> {
        let checked = self.check_at(jws, expect, now)?;
        let first = store
            .remember(checked.jti(), checked.until())
            .map_err(|_| ApprovalError::Store)?;
        checked.accept(first)
    }

    /// The whole check with a synchronous store against the system clock.
    pub fn verify(
        &self,
        jws: &str,
        expect: &ApprovalExpect,
        store: &dyn JtiStore,
    ) -> Result<ApprovalClaims, ApprovalError> {
        self.verify_at(jws, expect, store, unix_now())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configuration_errors() {
        assert!(ApprovalConfig::new("", "example").is_err());
        assert!(ApprovalConfig::new("https://auth.example.com", "").is_err());
        let cfg = ApprovalConfig::new("https://auth.example.com", "example").unwrap();
        assert!(cfg.clone().with_leeway(30).is_ok());
        assert!(cfg.clone().with_leeway(31).is_err());
        assert!(ApprovalVerifier::new(cfg, KeySet::default()).is_err());
    }

    #[test]
    fn canonical_form() {
        let entry: Map<String, Value> =
            serde_json::from_str(r#"{"type":"t","b":true,"a":-12,"s":"q\"\\é\n\u0001"}"#).unwrap();
        assert_eq!(
            canonical(&entry),
            r#"{"a":-12,"b":true,"s":"q\"\\é\n\u0001","type":"t"}"#
        );
    }

    #[test]
    fn expected_fields_compare_exactly() {
        let entry: Map<String, Value> =
            serde_json::from_str(r#"{"type":"t","n":1,"s":"1","b":true}"#).unwrap();
        let want = |n: Value| -> Map<String, Value> {
            serde_json::from_value(serde_json::json!({"n": n, "s": "1", "b": true})).unwrap()
        };
        assert!(same_fields(&entry, &want(serde_json::json!(1))));
        for other in [
            serde_json::json!(1.0),
            serde_json::json!("1"),
            serde_json::json!(true),
            serde_json::json!(null),
        ] {
            assert!(!same_fields(&entry, &want(other.clone())), "{other}");
        }
    }
}
