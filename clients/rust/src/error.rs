//! Error classes of the specification (`spec/gate-client.md` §2.4, §4.5) and configuration errors.
//!
//! Every class means the same to an application: **not authenticated**. The classes exist for logs and tests; a
//! response never names them (spec §6).

use std::fmt;

/// Why a gate token was refused. The variant is the class of the **first** failing step of spec §4.4.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TokenError {
    /// No token in the configured source. Not a class of spec §4.5 (the specification starts with a token).
    Missing,
    /// Size, structure, base64url, JSON, duplicate members, more than one gate cookie (steps 1–3, 8).
    Malformed,
    /// A forbidden or unknown header member, wrong `alg`, wrong `typ` (step 4).
    Header,
    /// `kid` missing or malformed, or not in the key set (steps 4, 6).
    Kid,
    /// Wrong signature length or failed verification (steps 5, 7).
    Signature,
    /// No key set could be obtained (step 6, spec §5).
    KeyUnavailable,
    /// A claim of the wrong type, a control character, an inconsistency (step 9).
    Claims,
    /// Wrong `iss` (step 10).
    Issuer,
    /// Wrong `aud` (step 10).
    Audience,
    /// `exp − nbf` not in (0, 3600] (step 10).
    Lifetime,
    /// Before `nbf − leeway` (step 10).
    NotYetValid,
    /// At or after `exp + leeway` (step 10).
    Expired,
}

impl TokenError {
    /// The class name as the specification and the vectors spell it (`malformed`, `not_yet_valid`, …).
    pub fn class(&self) -> &'static str {
        match self {
            TokenError::Missing => "missing",
            TokenError::Malformed => "malformed",
            TokenError::Header => "header",
            TokenError::Kid => "kid",
            TokenError::Signature => "signature",
            TokenError::KeyUnavailable => "key_unavailable",
            TokenError::Claims => "claims",
            TokenError::Issuer => "issuer",
            TokenError::Audience => "audience",
            TokenError::Lifetime => "lifetime",
            TokenError::NotYetValid => "not_yet_valid",
            TokenError::Expired => "expired",
        }
    }
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gate token refused: {}", self.class())
    }
}

impl std::error::Error for TokenError {}

/// Why header mode refused a request (spec §2.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum HeaderError {
    /// No or empty `Remote-User`.
    Unauthenticated,
    /// A repeated field, invalid UTF-8, a control character, a malformed `Remote-Id`.
    Header,
    /// The request did not come from a configured trusted peer (spec §2.1, the optional peer list).
    UntrustedPeer,
}

impl HeaderError {
    /// The class name (`unauthenticated`, `header`, `untrusted_peer`).
    pub fn class(&self) -> &'static str {
        match self {
            HeaderError::Unauthenticated => "unauthenticated",
            HeaderError::Header => "header",
            HeaderError::UntrustedPeer => "untrusted_peer",
        }
    }
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identity headers refused: {}", self.class())
    }
}

impl std::error::Error for HeaderError {}

/// A key set document that is invalid as a whole (spec §4.3): not an object, no `keys` array, more than 32 entries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct JwksInvalid;

impl JwksInvalid {
    /// The class name, `jwks_invalid`.
    pub fn class(&self) -> &'static str {
        "jwks_invalid"
    }
}

impl fmt::Display for JwksInvalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("key set refused: jwks_invalid")
    }
}

impl std::error::Error for JwksInvalid {}

/// A configuration that must stop the application at start-up instead of failing open later (spec §6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigError(pub(crate) String);

impl ConfigError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        ConfigError(message.into())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "gate client configuration: {}", self.0)
    }
}

impl std::error::Error for ConfigError {}
