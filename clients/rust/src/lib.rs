//! Gate client for applications behind TinySesam's gate.
//!
//! It answers one question per request: *who is this, and may they do this?* It never signs anyone in, holds no
//! session and issues nothing. The contract is the gate client specification (`spec/gate-client.md` in the
//! TinySesam repository); this crate passes every vector in `spec/vectors/`.
//!
//! Two modes, chosen explicitly by configuration — never a fallback from one to the other:
//!
//! - **Header mode** ([`HeaderMode`], the default deployment): the proxy checks and sets `Remote-*` headers. Safe
//!   only when the proxy duties of spec §2.1 hold (see the README).
//! - **Token mode** ([`TokenVerifier`] with fixed keys, `JwksVerifier` with a fetched key set behind the feature
//!   `jwks`): the client verifies the Ed25519 gate token itself.
//!
//! ```
//! use tinysesam_gate::{HeaderMode, Requirement, authorize};
//! use http::{HeaderMap, HeaderValue};
//!
//! let mode = HeaderMode::trust_proxy();
//! let mut headers = HeaderMap::new();
//! headers.insert("remote-user", HeaderValue::from_static("anna"));
//! headers.insert("remote-groups", HeaderValue::from_static("editors"));
//! headers.insert("remote-auth", HeaderValue::from_static("session"));
//! headers.insert("remote-kind", HeaderValue::from_static("user"));
//! let identity = mode.identify(&headers, None).ok();
//! assert!(authorize(identity.as_ref(), &[Requirement::Role("editors")]).status().is_none());
//! ```
#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod cache;
mod error;
mod guard;
mod header;
mod identity;
mod keys;
#[cfg(feature = "jwks")]
mod remote;
mod source;
mod strict;
mod token;
pub mod topbar;

/// The Rust examples of the README compile as doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub use cache::{
    FetchOutcome, JWKS_DEFAULT_FRESH, JWKS_MAX_BODY, JWKS_MAX_FRESH, JWKS_MIN_FRESH,
    JWKS_MIN_INTERVAL, JWKS_STALE_MAX, JwksCache,
};
pub use error::{ConfigError, HeaderError, JwksInvalid, TokenError};
pub use guard::{Decision, Requirement, authorize};
pub use header::{HeaderMode, HeaderNames, REMOTE_HEADERS};
pub use identity::{AccountKind, Auth, Identity, Kind, parse_groups};
pub use keys::{JWKS_MAX_KEYS, KeySet, PublicKey, key_id};
#[cfg(feature = "jwks")]
pub use remote::{
    CacheClock, FETCH_DEADLINE, Fetch, HttpFetcher, JwksVerifier, MonotonicClock, RemoteKeys,
};
pub use source::{GATE_COOKIE, TokenSource};
pub use token::{
    ALGORITHM, Claims, MAX_LEEWAY, MAX_LIFETIME, MAX_TOKEN_BYTES, TOKEN_TYPE, TokenConfig,
    TokenVerifier, Unverified, Verified, precheck, unix_now,
};
