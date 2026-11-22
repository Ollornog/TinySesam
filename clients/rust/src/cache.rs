//! The fetch-and-cache rules of spec §5 as a state machine without I/O.
//!
//! [`JwksCache`] decides when to fetch and what a fetch result means; the fetching itself is the caller's. With the
//! feature `jwks`, [`RemoteKeys`](crate::RemoteKeys) drives it over HTTPS with a deadline and shares a running fetch
//! between concurrent requests. [`JwksCache::lookup_with`] drives it synchronously — for tests and for callers that
//! bring their own (deadline-bound) fetch.

use crate::error::TokenError;
use crate::keys::{KeySet, PublicKey};
use std::sync::Arc;

/// Freshness of a set without a readable `max-age`, in seconds.
pub const JWKS_DEFAULT_FRESH: i64 = 300;
/// Lower bound of the freshness (`max-age=0` and `no-cache` do not go below it).
pub const JWKS_MIN_FRESH: i64 = 60;
/// Upper bound of the freshness: a rotation arrives within the hour.
pub const JWKS_MAX_FRESH: i64 = 3600;
/// How long past its freshness the last good set may still be used when refreshing fails.
pub const JWKS_STALE_MAX: i64 = 3600;
/// At most one fetch attempt per this many seconds, whatever the reason.
pub const JWKS_MIN_INTERVAL: i64 = 10;
/// The largest body a fetch may return.
pub const JWKS_MAX_BODY: usize = 64 * 1024;

/// What one fetch attempt brought.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// A network error, a timeout, a body above the limit.
    Failed,
    /// An HTTP answer.
    Response {
        /// The status code.
        status: u16,
        /// The `Cache-Control` header, if any.
        cache_control: Option<String>,
        /// The body (at most [`JWKS_MAX_BODY`] bytes, otherwise the fetch failed).
        body: Vec<u8>,
    },
}

/// The cached key set and the bookkeeping of spec §5. Times are seconds on one clock of the caller's choice
/// (a monotonic one in [`RemoteKeys`](crate::RemoteKeys)).
#[derive(Debug, Clone, Default)]
pub struct JwksCache {
    keys: Option<Arc<KeySet>>,
    fresh_until: i64,
    last_attempt: Option<i64>,
}

impl JwksCache {
    /// An empty cache.
    pub fn new() -> JwksCache {
        JwksCache::default()
    }

    /// The key for a `kid` at time `now`, fetching through `fetch` when spec §5 step 6 says so. `fetch` must respect
    /// the deadline of spec §5 itself.
    pub fn lookup_with<F>(
        &mut self,
        kid: &str,
        now: i64,
        mut fetch: F,
    ) -> Result<PublicKey, TokenError>
    where
        F: FnMut() -> FetchOutcome,
    {
        let mut attempt = |cache: &mut JwksCache| {
            if !cache.may_attempt(now) {
                return false;
            }
            cache.begin_attempt(now);
            cache.apply(now, fetch());
            true
        };
        let mut fetched = false;
        if self.needs_refresh(now) {
            fetched = attempt(self);
        }
        if let Some(key) = self.resolve(kid, now)? {
            return Ok(key);
        }
        if !fetched {
            attempt(self);
        }
        self.resolve(kid, now)?.ok_or(TokenError::Kid)
    }

    /// The current set, if any (regardless of its freshness).
    pub fn keys(&self) -> Option<&KeySet> {
        self.keys.as_deref()
    }

    /// No set, or it is no longer fresh.
    pub(crate) fn needs_refresh(&self, now: i64) -> bool {
        self.keys.is_none() || now >= self.fresh_until
    }

    /// The rate limit: at most one attempt per [`JWKS_MIN_INTERVAL`] seconds.
    pub(crate) fn may_attempt(&self, now: i64) -> bool {
        self.last_attempt
            .is_none_or(|last| now - last >= JWKS_MIN_INTERVAL)
    }

    pub(crate) fn begin_attempt(&mut self, now: i64) {
        self.last_attempt = Some(now);
    }

    /// Takes a fetch result. A failed fetch never replaces the cached set.
    pub(crate) fn apply(&mut self, now: i64, outcome: FetchOutcome) {
        if let Some((keys, fresh)) = interpret(outcome) {
            self.keys = Some(Arc::new(keys));
            self.fresh_until = now + fresh;
        }
    }

    /// `key_unavailable` without a set or with one more than [`JWKS_STALE_MAX`] past its freshness; otherwise the key
    /// of the `kid`, if the set has it.
    pub(crate) fn resolve(&self, kid: &str, now: i64) -> Result<Option<PublicKey>, TokenError> {
        let keys = self.keys.as_ref().ok_or(TokenError::KeyUnavailable)?;
        if now >= self.fresh_until + JWKS_STALE_MAX {
            return Err(TokenError::KeyUnavailable);
        }
        Ok(keys.get(kid).cloned())
    }
}

/// A usable set and its freshness, or `None` for a failed fetch (spec §5 step 4).
fn interpret(outcome: FetchOutcome) -> Option<(KeySet, i64)> {
    let FetchOutcome::Response {
        status: 200,
        cache_control,
        body,
    } = outcome
    else {
        return None;
    };
    if body.len() > JWKS_MAX_BODY {
        return None;
    }
    let keys = KeySet::from_jwks_json(&body).ok()?;
    if keys.is_empty() {
        return None;
    }
    let fresh = cache_control
        .as_deref()
        .and_then(max_age)
        .unwrap_or(JWKS_DEFAULT_FRESH);
    Some((keys, fresh.clamp(JWKS_MIN_FRESH, JWKS_MAX_FRESH)))
}

/// The first readable `max-age=<digits>` directive of a `Cache-Control` value.
fn max_age(value: &str) -> Option<i64> {
    value.split(',').find_map(|directive| {
        let (name, digits) = directive.split_once('=')?;
        let digits = digits.trim();
        if !name.trim().eq_ignore_ascii_case("max-age")
            || digits.is_empty()
            || !digits.bytes().all(|b| b.is_ascii_digit())
        {
            return None;
        }
        Some(digits.parse::<i64>().unwrap_or(i64::MAX))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_control() {
        assert_eq!(max_age("max-age=300"), Some(300));
        assert_eq!(max_age("public, MAX-AGE = 86400"), Some(86400));
        assert_eq!(max_age("no-cache, max-age=0"), Some(0));
        assert_eq!(max_age("max-age=\"300\""), None);
        assert_eq!(max_age("max-age=abc, max-age=200"), Some(200));
        assert_eq!(max_age("s-maxage=10"), None);
        assert_eq!(max_age("max-age=99999999999999999999999"), Some(i64::MAX));
        assert_eq!(max_age(""), None);
    }

    const GOOD: &str = r#"{"keys":[{"kty":"OKP","crv":"Ed25519","x":"ecc3yanysDDBsjOxE03UuR3bhBJmVjsRPkXuVsCwVCY","kid":"a033507ca61ad979"}]}"#;

    fn answer(status: u16, size: usize) -> FetchOutcome {
        // The good document padded with whitespace to `size` bytes: still valid JSON.
        let mut body = GOOD.as_bytes().to_vec();
        body.resize(size, b' ');
        FetchOutcome::Response {
            status,
            cache_control: None,
            body,
        }
    }

    #[test]
    fn a_body_above_the_limit_is_a_failure_even_from_a_custom_fetcher() {
        assert!(
            interpret(answer(200, JWKS_MAX_BODY)).is_some(),
            "the counterpart: exactly 64 KiB"
        );
        assert!(interpret(answer(200, JWKS_MAX_BODY + 1)).is_none());
    }

    #[test]
    fn only_status_200_counts() {
        assert!(interpret(answer(200, GOOD.len())).is_some());
        for status in [203, 206, 304, 404, 500, 503] {
            assert!(interpret(answer(status, GOOD.len())).is_none(), "{status}");
        }
    }
}
