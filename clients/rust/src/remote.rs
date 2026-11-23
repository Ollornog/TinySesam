//! Token mode with a key set fetched over HTTPS (spec §5). Feature `jwks`.
//!
//! - one fetch takes at most 5 seconds in total and its body at most 64 KiB;
//! - while a fetch is running, other requests share its result (bounded by the same deadline) instead of starting
//!   their own; with the rate limit of 10 s nothing ever fetches per request;
//! - a failed fetch never replaces the cached set, which stays usable up to 3600 s past its freshness;
//! - the URL comes from configuration only (`https`, plain `http` only to a loopback address); redirects are not
//!   followed, nothing from a token is ever fetched.

use crate::approval::{ApprovalConfig, ApprovalError, ApprovalExpect, Checked, approval_precheck};
use crate::cache::{FetchOutcome, JWKS_MAX_BODY, JwksCache};
use crate::error::{ConfigError, TokenError};
use crate::keys::PublicKey;
use crate::token::{TokenConfig, Verified, precheck, unix_now};
use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tokio::sync::watch;

/// The deadline of one fetch (connect, TLS, headers, body).
pub const FETCH_DEADLINE: Duration = Duration::from_secs(5);

/// Fetches the key set document once. Implementations must finish within [`FETCH_DEADLINE`].
pub trait Fetch: Send + Sync + 'static {
    /// One attempt.
    fn fetch(&self) -> impl Future<Output = FetchOutcome> + Send;
}

/// The clock of the cache: seconds that never go backwards.
pub trait CacheClock: Send + Sync + 'static {
    /// The current time in seconds.
    fn now(&self) -> i64;
}

/// A monotonic clock (seconds since construction): a wall clock that jumps cannot stall or flood the fetches.
#[derive(Debug, Clone, Copy)]
pub struct MonotonicClock(Instant);

impl Default for MonotonicClock {
    fn default() -> Self {
        MonotonicClock(Instant::now())
    }
}

impl CacheClock for MonotonicClock {
    fn now(&self) -> i64 {
        i64::try_from(self.0.elapsed().as_secs()).unwrap_or(i64::MAX)
    }
}

/// Fetches the key set over HTTP(S) with `reqwest` (rustls, no redirects, no decompression).
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: reqwest::Client,
    url: reqwest::Url,
    deadline: Duration,
}

impl HttpFetcher {
    /// A fetcher for the operator's key set URL, normally `https://<auth host>/auth/gate/jwks.json`. Plain `http`
    /// is accepted only to a loopback IP address.
    pub fn new(url: &str) -> Result<HttpFetcher, ConfigError> {
        let url = reqwest::Url::parse(url)
            .map_err(|_| ConfigError::new("the key set URL is not a URL"))?;
        let loopback = url
            .host_str()
            .and_then(|h| {
                h.trim_start_matches('[')
                    .trim_end_matches(']')
                    .parse::<IpAddr>()
                    .ok()
            })
            .is_some_and(|ip| ip.is_loopback());
        match url.scheme() {
            "https" if url.host().is_some() => {}
            "http" if loopback => {}
            _ => {
                return Err(ConfigError::new(
                    "the key set URL must be https (http only to a loopback address)",
                ));
            }
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(ConfigError::new(
                "the key set URL must not carry credentials",
            ));
        }
        HttpFetcher::with_client(url, FETCH_DEADLINE)
    }

    /// A shorter deadline than [`FETCH_DEADLINE`] (never a longer one).
    pub fn with_deadline(self, deadline: Duration) -> Result<HttpFetcher, ConfigError> {
        if deadline.is_zero() || deadline > FETCH_DEADLINE {
            return Err(ConfigError::new(
                "the fetch deadline must be above 0 and at most 5 seconds",
            ));
        }
        HttpFetcher::with_client(self.url, deadline)
    }

    fn with_client(url: reqwest::Url, deadline: Duration) -> Result<HttpFetcher, ConfigError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(deadline)
            .timeout(deadline)
            .build()
            .map_err(|_| ConfigError::new("the HTTP client could not be built"))?;
        Ok(HttpFetcher {
            client,
            url,
            deadline,
        })
    }

    /// One GET with the deadline and the body limit, optionally carrying a `Cookie` header (the account overview of
    /// spec §8a: only TinySesam's cookies of the request).
    pub(crate) async fn get(&self, cookie: Option<&str>) -> FetchOutcome {
        tokio::time::timeout(self.deadline, self.attempt(cookie))
            .await
            .ok()
            .flatten()
            .unwrap_or(FetchOutcome::Failed)
    }

    async fn attempt(&self, cookie: Option<&str>) -> Option<FetchOutcome> {
        let mut request = self.client.get(self.url.clone()).header(
            reqwest::header::ACCEPT,
            "application/jwk-set+json, application/json",
        );
        if let Some(cookie) = cookie {
            request = request.header(reqwest::header::COOKIE, cookie);
        }
        let mut response = request.send().await.ok()?;
        let status = response.status().as_u16();
        let cache_control = {
            let values: Option<Vec<&str>> = response
                .headers()
                .get_all(reqwest::header::CACHE_CONTROL)
                .iter()
                .map(|v| v.to_str().ok())
                .collect();
            values.filter(|v| !v.is_empty()).map(|v| v.join(", "))
        };
        if status != 200 {
            return Some(FetchOutcome::Response {
                status,
                cache_control,
                body: Vec::new(),
            });
        }
        if response
            .content_length()
            .is_some_and(|n| n > JWKS_MAX_BODY as u64)
        {
            return None;
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.ok()? {
            if body.len() + chunk.len() > JWKS_MAX_BODY {
                return None;
            }
            body.extend_from_slice(&chunk);
        }
        Some(FetchOutcome::Response {
            status,
            cache_control,
            body,
        })
    }
}

impl Fetch for HttpFetcher {
    async fn fetch(&self) -> FetchOutcome {
        self.get(None).await
    }
}

struct State {
    cache: JwksCache,
    inflight: Option<watch::Receiver<()>>,
}

struct Inner<F, C> {
    fetcher: F,
    clock: C,
    state: Mutex<State>,
}

impl<F, C> Inner<F, C> {
    fn state(&self) -> MutexGuard<'_, State> {
        // Every update of the state is a plain assignment: a poisoned lock still holds a consistent state.
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Clears the in-flight marker when the fetch ends — also when the request that runs it is dropped — and wakes the
/// requests that share it (dropping the sender closes their channel).
struct InflightGuard<'a, F, C> {
    inner: &'a Inner<F, C>,
    _done: watch::Sender<()>,
}

impl<F, C> Drop for InflightGuard<'_, F, C> {
    fn drop(&mut self) {
        self.inner.state().inflight = None;
    }
}

enum Step {
    Skip,
    Share(watch::Receiver<()>),
    Run(watch::Sender<()>),
}

/// A key set fetched and cached by the rules of spec §5. Cheap to clone (shared state).
pub struct RemoteKeys<F = HttpFetcher, C = MonotonicClock> {
    inner: Arc<Inner<F, C>>,
}

impl<F, C> Clone for RemoteKeys<F, C> {
    fn clone(&self) -> Self {
        RemoteKeys {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl RemoteKeys {
    /// Keys from the operator's key set URL (see [`HttpFetcher::new`]).
    pub fn from_url(url: &str) -> Result<RemoteKeys, ConfigError> {
        Ok(RemoteKeys::new(
            HttpFetcher::new(url)?,
            MonotonicClock::default(),
        ))
    }
}

impl<F: Fetch, C: CacheClock> RemoteKeys<F, C> {
    /// Keys from any fetcher and clock (tests, custom transports).
    pub fn new(fetcher: F, clock: C) -> RemoteKeys<F, C> {
        let state = Mutex::new(State {
            cache: JwksCache::new(),
            inflight: None,
        });
        RemoteKeys {
            inner: Arc::new(Inner {
                fetcher,
                clock,
                state,
            }),
        }
    }

    /// The key for a format-checked `kid` (spec §5 step 6).
    pub async fn lookup(&self, kid: &str) -> Result<PublicKey, TokenError> {
        let now = self.inner.clock.now();
        let mut fetched = false;
        if self.inner.state().cache.needs_refresh(now) {
            fetched = self.attempt(now).await;
        }
        let found = self.inner.state().cache.resolve(kid, now)?;
        if let Some(key) = found {
            return Ok(key);
        }
        if !fetched {
            self.attempt(now).await;
        }
        self.inner
            .state()
            .cache
            .resolve(kid, now)?
            .ok_or(TokenError::Kid)
    }

    /// One fetch attempt if the rate limit allows it, or a share of the one already running. True if this request
    /// took part in a fetch.
    async fn attempt(&self, now: i64) -> bool {
        let step = {
            let mut state = self.inner.state();
            if let Some(running) = &state.inflight {
                Step::Share(running.clone())
            } else if state.cache.may_attempt(now) {
                state.cache.begin_attempt(now);
                let (done, running) = watch::channel(());
                state.inflight = Some(running);
                Step::Run(done)
            } else {
                Step::Skip
            }
        };
        match step {
            Step::Skip => false,
            Step::Share(mut running) => {
                // Never wait longer than the deadline, even for a custom fetcher that ignores it.
                let _ = tokio::time::timeout(FETCH_DEADLINE, running.changed()).await;
                true
            }
            Step::Run(done) => {
                let guard = InflightGuard {
                    inner: &self.inner,
                    _done: done,
                };
                let outcome = self.inner.fetcher.fetch().await;
                self.inner.state().cache.apply(now, outcome);
                drop(guard);
                true
            }
        }
    }
}

/// Token mode with a fetched key set.
pub struct JwksVerifier<F = HttpFetcher, C = MonotonicClock> {
    config: TokenConfig,
    keys: RemoteKeys<F, C>,
}

impl<F, C> Clone for JwksVerifier<F, C> {
    fn clone(&self) -> Self {
        JwksVerifier {
            config: self.config.clone(),
            keys: self.keys.clone(),
        }
    }
}

impl<F: Fetch, C: CacheClock> JwksVerifier<F, C> {
    /// A verifier from configuration and remote keys.
    pub fn new(config: TokenConfig, keys: RemoteKeys<F, C>) -> JwksVerifier<F, C> {
        JwksVerifier { config, keys }
    }

    /// Checks a token against the system clock.
    pub async fn verify(&self, jws: &str) -> Result<Verified, TokenError> {
        self.verify_at(jws, unix_now()).await
    }

    /// Checks a token at a given time for its claims; the cache keeps its own clock. A `kid` that fails the format
    /// check never triggers a fetch (spec §5 step 7).
    pub async fn verify_at(&self, jws: &str, now: i64) -> Result<Verified, TokenError> {
        let token = precheck(jws)?;
        let key = self.keys.lookup(token.kid()).await?;
        self.config.finish(token, &key, now)
    }

    /// The remote keys.
    pub fn keys(&self) -> &RemoteKeys<F, C> {
        &self.keys
    }
}

/// Approval confirmations (spec/approval-token.md) with the approval key set fetched by the rules of spec §5.
pub struct ApprovalJwksVerifier<F = HttpFetcher, C = MonotonicClock> {
    config: ApprovalConfig,
    keys: RemoteKeys<F, C>,
}

impl<F, C> Clone for ApprovalJwksVerifier<F, C> {
    fn clone(&self) -> Self {
        ApprovalJwksVerifier {
            config: self.config.clone(),
            keys: self.keys.clone(),
        }
    }
}

impl ApprovalJwksVerifier {
    /// A verifier for TinySesam's approval key set, normally `https://<auth host>/auth/approvals/jwks.json`. The gate
    /// key set (a path ending in `/gate/jwks.json`) is refused: a confirmation is never checked with a gate key.
    pub fn from_url(
        config: ApprovalConfig,
        url: &str,
    ) -> Result<ApprovalJwksVerifier, ConfigError> {
        let parsed = reqwest::Url::parse(url)
            .map_err(|_| ConfigError::new("the key set URL is not a URL"))?;
        if parsed
            .path()
            .trim_end_matches('/')
            .ends_with("/gate/jwks.json")
        {
            return Err(ConfigError::new(
                "that is the GATE key set; confirmations have their own (https://<auth host>/auth/approvals/jwks.json)",
            ));
        }
        Ok(ApprovalJwksVerifier::new(
            config,
            RemoteKeys::from_url(url)?,
        ))
    }
}

impl<F: Fetch, C: CacheClock> ApprovalJwksVerifier<F, C> {
    /// A verifier from configuration and remote keys (the approval key set).
    pub fn new(config: ApprovalConfig, keys: RemoteKeys<F, C>) -> ApprovalJwksVerifier<F, C> {
        ApprovalJwksVerifier { config, keys }
    }

    /// Steps 1–11 at a given time; write [`Checked::jti`] into the store, then [`Checked::accept`]. A `kid` that
    /// fails the format check never triggers a fetch.
    pub async fn check_at(
        &self,
        jws: &str,
        expect: &ApprovalExpect,
        now: i64,
    ) -> Result<Checked, ApprovalError> {
        let token = approval_precheck(jws)?;
        let key = self.keys.lookup(token.kid()).await?;
        self.config.check(token, &key, expect, now)
    }

    /// Steps 1–11 against the system clock.
    pub async fn check(
        &self,
        jws: &str,
        expect: &ApprovalExpect,
    ) -> Result<Checked, ApprovalError> {
        self.check_at(jws, expect, unix_now()).await
    }

    /// The remote keys.
    pub fn keys(&self) -> &RemoteKeys<F, C> {
        &self.keys
    }
}
