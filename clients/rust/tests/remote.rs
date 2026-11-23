//! Feature `jwks`: the async key set client. The cache scenarios of the vectors once more through `RemoteKeys`, plus
//! what the vectors cannot carry (spec §5): a server that never answers, a body above 64 KiB, concurrent requests
//! sharing one fetch, no redirects.

mod common;

use common::*;
use serde_json::Value;
use std::future::Future;
use std::pin::pin;
use std::sync::atomic::{AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};
use tinysesam_gate::{
    CacheClock, Fetch, FetchOutcome, HttpFetcher, JwksVerifier, RemoteKeys, TokenConfig, TokenError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Runs a future that never waits (the fake fetcher answers at once).
fn ready<F: Future>(future: F) -> F::Output {
    match pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(v) => v,
        Poll::Pending => panic!("the future waited although nothing should block"),
    }
}

#[derive(Clone, Default)]
struct FakeClock(Arc<AtomicI64>);

impl CacheClock for FakeClock {
    fn now(&self) -> i64 {
        self.0.load(Ordering::SeqCst)
    }
}

/// Answers with the queued outcome and counts the calls; with nothing queued it records an unexpected fetch.
#[derive(Clone, Default)]
struct FakeFetch {
    next: Arc<Mutex<Option<FetchOutcome>>>,
    calls: Arc<AtomicUsize>,
    unexpected: Arc<AtomicUsize>,
}

impl Fetch for FakeFetch {
    async fn fetch(&self) -> FetchOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.next.lock().unwrap().take().unwrap_or_else(|| {
            self.unexpected.fetch_add(1, Ordering::SeqCst);
            FetchOutcome::Failed
        })
    }
}

fn config() -> TokenConfig {
    let d = load("jwks.json")["defaults"].clone();
    TokenConfig::new(str_of(&d, "issuer"), str_of(&d, "audience")).unwrap()
}

#[test]
fn jwks_scenarios_through_remote_keys() {
    let doc = load("jwks.json");
    let scenarios = doc["scenarios"].as_array().unwrap();
    let mut failures = Vec::new();
    for s in scenarios {
        let id = str_of(s, "id");
        let (fetch, clock) = (FakeFetch::default(), FakeClock::default());
        let verifier = JwksVerifier::new(config(), RemoteKeys::new(fetch.clone(), clock.clone()));
        for (n, step) in s["steps"].as_array().unwrap().iter().enumerate() {
            let now = step["now"].as_i64().unwrap();
            clock.0.store(now, Ordering::SeqCst);
            *fetch.next.lock().unwrap() = step.get("fetch").map(fetch_outcome);
            let before = fetch.calls.load(Ordering::SeqCst);
            let result = ready(verifier.verify_at(str_of(step, "jws"), now));
            let fetched = fetch.calls.load(Ordering::SeqCst) > before;
            let expect = &step["expect"];
            let at = format!("{id} step {n}");
            if Value::Bool(fetched) != expect["fetched"] {
                failures.push(format!(
                    "{at}: fetched = {fetched}, expected {}",
                    expect["fetched"]
                ));
            }
            match (result, expect["ok"].as_bool().unwrap()) {
                (Ok(_), true) => {}
                (Ok(_), false) => {
                    failures.push(format!("{at}: accepted, expected {}", expect["error"]))
                }
                (Err(e), true) => {
                    failures.push(format!("{at}: refused ({}), expected ok", e.class()))
                }
                (Err(e), false) if e.class() != str_of(expect, "error") => failures.push(format!(
                    "{at}: {} ≠ expected {}",
                    e.class(),
                    expect["error"]
                )),
                (Err(_), false) => {}
            }
        }
        if fetch.unexpected.load(Ordering::SeqCst) > 0 {
            failures.push(format!("{id}: fetched where a step gives no answer"));
        }
    }
    report(
        "jwks.json scenarios (RemoteKeys)",
        scenarios.len(),
        8,
        failures,
    );
}

/// The first step of the scenario `fresh-cache`: a valid token, its time and a good key set body.
fn good_case() -> (String, i64, Vec<u8>) {
    let doc = load("jwks.json");
    let s = doc["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["id"] == "fresh-cache")
        .unwrap();
    let step = &s["steps"][0];
    let body = serde_json::to_vec(&step["fetch"]["body"]).unwrap();
    (
        str_of(step, "jws").to_owned(),
        step["now"].as_i64().unwrap(),
        body,
    )
}

/// A one-shot HTTP server on a loopback port; `respond` gets the connection after the request head was read.
async fn serve<F, Fut>(respond: F) -> String
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send,
{
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "http://{}/auth/gate/jwks.json",
        listener.local_addr().unwrap()
    );
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            respond(conn).await;
        }
    });
    url
}

fn answer(status: &str, headers: &str, body: &[u8]) -> Vec<u8> {
    let mut out = format!("HTTP/1.1 {status}\r\n{headers}Connection: close\r\n\r\n").into_bytes();
    out.extend_from_slice(body);
    out
}

#[tokio::test]
async fn a_good_server_is_used() {
    let (jws, now, body) = good_case();
    let url = serve(move |mut c| {
        let body = body.clone();
        async move {
            let head = format!(
                "Content-Type: application/json\r\nContent-Length: {}\r\n",
                body.len()
            );
            let _ = c.write_all(&answer("200 OK", &head, &body)).await;
        }
    })
    .await;
    let verifier = JwksVerifier::new(config(), RemoteKeys::from_url(&url).unwrap());
    assert!(
        verifier.verify_at(&jws, now).await.is_ok(),
        "the positive control of the server tests"
    );
}

async fn never_answers(deadline: Option<Duration>) {
    let (jws, now, _) = good_case();
    let held = Arc::new(Mutex::new(Vec::new()));
    let keep = held.clone();
    let url = serve(move |c| {
        keep.lock().unwrap().push(c);
        async {}
    })
    .await;
    let mut fetcher = HttpFetcher::new(&url).unwrap();
    if let Some(d) = deadline {
        fetcher = fetcher.with_deadline(d).unwrap();
    }
    let limit = deadline.unwrap_or(tinysesam_gate::FETCH_DEADLINE);
    let verifier = JwksVerifier::new(
        config(),
        RemoteKeys::new(fetcher, tinysesam_gate::MonotonicClock::default()),
    );
    let start = Instant::now();
    let result = tokio::time::timeout(limit * 2, verifier.verify_at(&jws, now))
        .await
        .expect("the request hung");
    let took = start.elapsed();
    assert_eq!(result.err(), Some(TokenError::KeyUnavailable));
    assert!(
        took >= limit - Duration::from_millis(50) && took < limit + Duration::from_millis(900),
        "took {took:?}"
    );
    // A second request right after: the rate limit forbids a new attempt, so it fails closed at once.
    let start = Instant::now();
    assert_eq!(
        verifier.verify_at(&jws, now).await.err(),
        Some(TokenError::KeyUnavailable)
    );
    assert!(start.elapsed() < Duration::from_millis(100));
    assert!(
        !held.lock().unwrap().is_empty(),
        "the server never saw the connection"
    );
}

#[tokio::test]
async fn a_server_that_never_answers_costs_one_deadline() {
    never_answers(None).await;
}

#[tokio::test]
async fn a_shorter_deadline_is_honoured() {
    never_answers(Some(Duration::from_millis(500))).await;
}

async fn padded_body(with_length: bool, size: usize) -> Result<(), TokenError> {
    let (jws, now, body) = good_case();
    // The good document, padded with whitespace to `size` bytes: still valid JSON.
    let mut big = body.clone();
    big.extend(std::iter::repeat_n(b' ', size - body.len()));
    let url = serve(move |mut c| {
        let big = big.clone();
        async move {
            let head = if with_length {
                format!("Content-Length: {}\r\n", big.len())
            } else {
                String::new()
            };
            let _ = c.write_all(&answer("200 OK", &head, &big)).await;
        }
    })
    .await;
    let verifier = JwksVerifier::new(config(), RemoteKeys::from_url(&url).unwrap());
    verifier.verify_at(&jws, now).await.map(|_| ())
}

/// The fetcher itself stops reading above the limit (it does not hand a large body on to be refused later).
#[tokio::test]
async fn the_fetcher_stops_reading_above_64_kib() {
    let url = serve(|mut c| async move {
        let _ = c.write_all(&answer("200 OK", "", b"")).await;
        let chunk = vec![b' '; 16 * 1024];
        for _ in 0..64 {
            if c.write_all(&chunk).await.is_err() {
                break;
            }
        }
    })
    .await;
    let outcome = HttpFetcher::new(&url).unwrap().fetch().await;
    assert_eq!(outcome, FetchOutcome::Failed);
}

#[tokio::test]
async fn a_body_above_64_kib_is_a_failed_fetch() {
    let limit = tinysesam_gate::JWKS_MAX_BODY;
    for with_length in [true, false] {
        assert_eq!(
            padded_body(with_length, limit).await,
            Ok(()),
            "exactly 64 KiB, Content-Length {with_length}"
        );
        assert_eq!(
            padded_body(with_length, limit + 1).await,
            Err(TokenError::KeyUnavailable),
            "one byte above 64 KiB, Content-Length {with_length}"
        );
    }
}

#[tokio::test]
async fn redirects_are_not_followed() {
    let (jws, now, body) = good_case();
    let good = serve(move |mut c| {
        let body = body.clone();
        async move {
            let _ = c
                .write_all(&answer(
                    "200 OK",
                    &format!("Content-Length: {}\r\n", body.len()),
                    &body,
                ))
                .await;
        }
    })
    .await;
    let redirect = serve(move |mut c| {
        let location = format!("Location: {good}\r\nContent-Length: 0\r\n");
        async move {
            let _ = c.write_all(&answer("302 Found", &location, b"")).await;
        }
    })
    .await;
    let verifier = JwksVerifier::new(config(), RemoteKeys::from_url(&redirect).unwrap());
    assert_eq!(
        verifier.verify_at(&jws, now).await.err(),
        Some(TokenError::KeyUnavailable)
    );
}

/// A fetcher that takes its time, so that concurrent requests meet a running fetch.
#[derive(Clone)]
struct SlowFetch {
    body: Vec<u8>,
    calls: Arc<AtomicUsize>,
}

impl Fetch for SlowFetch {
    async fn fetch(&self) -> FetchOutcome {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(300)).await;
        FetchOutcome::Response {
            status: 200,
            cache_control: None,
            body: self.body.clone(),
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_requests_share_one_fetch() {
    let (jws, now, body) = good_case();
    let calls = Arc::new(AtomicUsize::new(0));
    let keys = RemoteKeys::new(
        SlowFetch {
            body,
            calls: calls.clone(),
        },
        tinysesam_gate::MonotonicClock::default(),
    );
    let verifier = JwksVerifier::new(config(), keys);
    let start = Instant::now();
    let tasks: Vec<_> = (0..32)
        .map(|_| {
            let (v, jws) = (verifier.clone(), jws.clone());
            tokio::spawn(async move { v.verify_at(&jws, now).await.map(|_| ()) })
        })
        .collect();
    for t in tasks {
        assert_eq!(
            t.await.unwrap(),
            Ok(()),
            "a request did not share the running fetch"
        );
    }
    assert_eq!(
        calls.load(Ordering::SeqCst),
        1,
        "one fetch for all concurrent requests"
    );
    assert!(start.elapsed() < Duration::from_secs(2));
}

#[test]
fn key_set_urls() {
    assert!(HttpFetcher::new("https://auth.example.com/auth/gate/jwks.json").is_ok());
    assert!(HttpFetcher::new("http://127.0.0.1:8080/auth/gate/jwks.json").is_ok());
    assert!(HttpFetcher::new("http://[::1]:8080/auth/gate/jwks.json").is_ok());
    assert!(
        HttpFetcher::new("http://auth.example.com/auth/gate/jwks.json").is_err(),
        "plain http to a name"
    );
    assert!(
        HttpFetcher::new("http://localhost/auth/gate/jwks.json").is_err(),
        "only loopback IP literals"
    );
    assert!(
        HttpFetcher::new("https://user:pw@auth.example.com/jwks.json").is_err(),
        "credentials"
    );
    assert!(HttpFetcher::new("file:///etc/passwd").is_err());
    assert!(HttpFetcher::new("not a url").is_err());
    let f = HttpFetcher::new("https://auth.example.com/jwks.json").unwrap();
    assert!(f.clone().with_deadline(Duration::from_secs(6)).is_err());
    assert!(f.clone().with_deadline(Duration::ZERO).is_err());
    assert!(f.with_deadline(Duration::from_secs(1)).is_ok());
}

/// A loopback HTTP server that answers every request with `status` and `body` and records the request heads.
async fn record(
    path: &str,
    status: &'static str,
    body: Vec<u8>,
) -> (String, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}{path}", listener.local_addr().unwrap());
    let heads = Arc::new(Mutex::new(Vec::new()));
    let seen = heads.clone();
    tokio::spawn(async move {
        while let Ok((mut conn, _)) = listener.accept().await {
            let mut head = Vec::new();
            let mut buf = [0u8; 1024];
            while !head.windows(4).any(|w| w == b"\r\n\r\n") {
                match conn.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => head.extend_from_slice(&buf[..n]),
                }
            }
            seen.lock()
                .unwrap()
                .push(String::from_utf8_lossy(&head).into_owned());
            let extra = format!(
                "Content-Type: application/json\r\nCache-Control: max-age=300\r\nContent-Length: {}\r\n",
                body.len()
            );
            let _ = conn.write_all(&answer(status, &extra, &body)).await;
        }
    });
    (url, heads)
}

fn approval_case() -> (Value, Value) {
    let doc = load("approval.json");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "valid-basic")
        .unwrap()
        .clone();
    (v["input"].clone(), v["expected"].clone())
}

#[test]
fn gate_verifier_never_takes_the_approval_key_set() {
    let config = TokenConfig::new("https://auth.example.com", "app.example.com").unwrap();
    for approval in [
        "https://auth.example.com/auth/approvals/jwks.json",
        "https://auth.example.com/auth/approvals/jwks.json/",
    ] {
        assert!(
            JwksVerifier::from_url(config.clone(), approval).is_err(),
            "{approval} accepted"
        );
    }
    assert!(
        JwksVerifier::from_url(
            config.clone(),
            "http://auth.example.com/auth/gate/jwks.json"
        )
        .is_err()
    );
    assert!(JwksVerifier::from_url(config, "https://auth.example.com/auth/gate/jwks.json").is_ok());
}

#[tokio::test]
async fn approval_key_set_fetched_once_never_the_gate_set() {
    use tinysesam_gate::ApprovalJwksVerifier;
    use tinysesam_gate::approval::{ApprovalConfig, ApprovalExpect};
    let (input, expected) = approval_case();
    let config = ApprovalConfig::new(str_of(&input, "issuer"), str_of(&input, "app_id")).unwrap();
    for gate in [
        "https://auth.example.com/auth/gate/jwks.json",
        "https://auth.example.com/auth/gate/jwks.json/",
    ] {
        assert!(
            ApprovalJwksVerifier::from_url(config.clone(), gate).is_err(),
            "{gate} accepted"
        );
    }
    assert!(
        ApprovalJwksVerifier::from_url(
            config.clone(),
            "http://auth.example.com/auth/approvals/jwks.json"
        )
        .is_err()
    );
    let (url, heads) = record(
        "/auth/approvals/jwks.json",
        "200 OK",
        serde_json::to_vec(&input["jwks"]).unwrap(),
    )
    .await;
    let verifier = ApprovalJwksVerifier::from_url(config, &url).unwrap();
    let e = &input["expect"];
    let expect = ApprovalExpect::new(str_of(e, "type"), str_of(e, "sub"))
        .fields(e["fields"].as_object().unwrap().clone());
    let now = input["now"].as_i64().unwrap();
    for first in [true, false] {
        let checked = verifier
            .check_at(str_of(&input, "jws"), &expect, now)
            .await
            .expect("a good confirmation");
        assert_eq!(checked.jti(), expected["claims"]["jti"]);
        assert_eq!(checked.until(), expected["claims"]["exp"].as_i64().unwrap());
        let result = checked.accept(first);
        if first {
            let claims = result.unwrap();
            assert_eq!(claims.actor(), "app:example");
            assert_eq!(claims.kind(), "example.collection.delete_permanently");
            assert_eq!(claims.fields()["collection"], "c_81f2");
        } else {
            assert_eq!(result.unwrap_err().class(), "replay");
        }
    }
    assert_eq!(heads.lock().unwrap().len(), 1, "fetched more than once");
}

#[tokio::test]
async fn account_fetch_forwards_only_tinysesam_cookies() {
    use tinysesam_gate::account::AccountFetcher;
    let full = load("account.json")["vectors"][0]["input"]["account"].clone();
    let (url, heads) = record(
        "/auth/account.json",
        "200 OK",
        serde_json::to_vec(&full).unwrap(),
    )
    .await;
    let account = AccountFetcher::new(&url)
        .unwrap()
        .fetch(Some("app=private; tinysesam_session=abc; x=1"))
        .await;
    assert!(account.signed_in);
    assert_eq!(serde_json::to_value(&account).unwrap(), full);
    let head = heads.lock().unwrap()[0].to_ascii_lowercase();
    assert!(head.contains("cookie: tinysesam_session=abc\r\n"), "{head}");
    assert!(!head.contains("private"), "{head}");
    for status in ["401 Unauthorized", "404 Not Found", "429 Too Many Requests"] {
        let (url, _) = record(
            "/auth/account.json",
            status,
            serde_json::to_vec(&full).unwrap(),
        )
        .await;
        let account = AccountFetcher::new(&url)
            .unwrap()
            .fetch(Some("tinysesam_session=abc"))
            .await;
        assert!(!account.signed_in && account.links.is_none(), "{status}");
    }
    let (url, _) = record(
        "/auth/account.json",
        "200 OK",
        vec![b' '; tinysesam_gate::JWKS_MAX_BODY + 1],
    )
    .await;
    assert!(
        !AccountFetcher::new(&url)
            .unwrap()
            .fetch(None)
            .await
            .signed_in
    );
    assert!(AccountFetcher::new("http://auth.example.com/auth/account.json").is_err());
}
