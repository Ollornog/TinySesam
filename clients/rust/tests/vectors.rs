//! The language-neutral vectors of `spec/vectors/*.json`: every vector of every file, exactly.

mod common;

use common::*;
use serde_json::Value;
use std::cell::Cell;
use std::collections::BTreeSet;
use tinysesam_gate::approval::{ApprovalConfig, ApprovalExpect, ApprovalVerifier, StoreFailed};
use tinysesam_gate::{
    FetchOutcome, HeaderMode, Identity, JwksCache, KeySet, TokenConfig, TokenError, account,
    key_id, precheck, register_request, topbar,
};

#[test]
fn every_vector_file_has_a_runner() {
    let found: BTreeSet<String> = std::fs::read_dir(vector_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.ends_with(".json"))
        .collect();
    let covered: BTreeSet<String> = [
        "account.json",
        "approval.json",
        "headers.json",
        "jwks.json",
        "keys.json",
        "permissions.json",
        "token.json",
        "topbar.json",
    ]
    .map(String::from)
    .into();
    assert_eq!(
        found, covered,
        "a vector file without a runner in this suite (or a runner without its file)"
    );
}

#[test]
fn keys() {
    let doc = load("keys.json");
    let mut failures = Vec::new();
    let keys = doc["keys"].as_object().unwrap();
    for (name, key) in keys {
        let jwk = &key["public_jwk"];
        let kid = str_of(jwk, "kid");
        let set = KeySet::from_jwks(&serde_json::json!({ "keys": [jwk] })).unwrap();
        if set.kids().collect::<Vec<_>>() != [kid] {
            failures.push(format!("{name}: public_jwk not usable"));
        }
        let fixed = KeySet::from_sign_keys([str_of(key, "sign_key_base64")]).unwrap();
        if fixed.kids().collect::<Vec<_>>() != [kid] {
            failures.push(format!("{name}: sign_key_base64 gives another kid"));
        }
        let raw: [u8; 32] = base64_url(str_of(jwk, "x")).try_into().unwrap();
        if key_id(&raw) != kid {
            failures.push(format!("{name}: key_id"));
        }
    }
    report("keys.json", keys.len(), 3, failures);
}

fn base64_url(s: &str) -> Vec<u8> {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s)
        .unwrap()
}

#[test]
fn token() {
    let doc = load("token.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in vectors {
        let (id, input, expected) = (str_of(v, "id"), &v["input"], &v["expected"]);
        let keys =
            KeySet::from_jwks(&input["jwks"]).expect("the key set of a token vector is valid");
        let leeway = u32::try_from(input["leeway"].as_u64().unwrap()).unwrap();
        let config = TokenConfig::new(str_of(input, "issuer"), str_of(input, "audience"))
            .and_then(|c| c.with_leeway(leeway))
            .unwrap();
        let result =
            config.verify_with(str_of(input, "jws"), &keys, input["now"].as_i64().unwrap());
        match (result, expected["ok"].as_bool().unwrap()) {
            (Ok(verified), true) => {
                if Value::Object(verified.claims.as_map().clone()) != expected["claims"] {
                    failures.push(format!("{id}: claims differ"));
                }
                if identity_json(&verified.identity) != expected["identity"] {
                    failures.push(format!(
                        "{id}: identity {} ≠ {}",
                        identity_json(&verified.identity),
                        expected["identity"]
                    ));
                }
                failures.extend(
                    role_mismatches(&verified.identity, expected)
                        .into_iter()
                        .map(|m| format!("{id}: {m}")),
                );
            }
            (Ok(_), false) => {
                failures.push(format!("{id}: accepted, expected {}", expected["error"]))
            }
            (Err(e), true) => failures.push(format!("{id}: refused ({}), expected ok", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!(
                        "{id}: {} ≠ expected {}",
                        e.class(),
                        expected["error"]
                    ));
                }
            }
        }
    }
    report("token.json", vectors.len(), 100, failures);
}

/// A header value of the vectors: one code point U+0000–U+00FF per octet (Latin-1).
fn octets(text: &str) -> Vec<u8> {
    text.chars()
        .map(|c| u8::try_from(u32::from(c)).expect("a header octet above U+00FF"))
        .collect()
}

#[test]
fn headers() {
    let doc = load("headers.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let mode = HeaderMode::trust_proxy();
    let (mut failures, mut via_header_map) = (Vec::new(), 0);
    for v in vectors {
        let (id, expected) = (str_of(v, "id"), &v["expected"]);
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
        for (name, value) in v["input"]["headers"].as_object().unwrap() {
            match value {
                Value::Array(list) => fields.extend(
                    list.iter()
                        .map(|x| (name.clone(), octets(x.as_str().unwrap()))),
                ),
                other => fields.push((name.clone(), octets(other.as_str().unwrap()))),
            }
        }
        let result =
            mode.identify_fields(fields.iter().map(|(n, b)| (n.as_str(), b.as_slice())), None);
        // The same request through `http::HeaderMap`, where its values are representable there (a control character
        // other than tab is not).
        let mut map = http::HeaderMap::new();
        let representable = fields.iter().all(|(n, b)| {
            match (
                http::HeaderName::from_bytes(n.as_bytes()),
                http::HeaderValue::from_bytes(b),
            ) {
                (Ok(n), Ok(b)) => {
                    map.append(n, b);
                    true
                }
                _ => false,
            }
        });
        if representable {
            via_header_map += 1;
            if mode.identify(&map, None) != result {
                failures.push(format!("{id}: HeaderMap and raw fields disagree"));
            }
        }
        match (result, expected["ok"].as_bool().unwrap()) {
            (Ok(identity), true) => {
                if identity_json(&identity) != expected["identity"] {
                    failures.push(format!(
                        "{id}: identity {} ≠ {}",
                        identity_json(&identity),
                        expected["identity"]
                    ));
                }
                failures.extend(
                    role_mismatches(&identity, expected)
                        .into_iter()
                        .map(|m| format!("{id}: {m}")),
                );
            }
            (Ok(_), false) => {
                failures.push(format!("{id}: accepted, expected {}", expected["error"]))
            }
            (Err(e), true) => failures.push(format!("{id}: refused ({}), expected ok", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!(
                        "{id}: {} ≠ expected {}",
                        e.class(),
                        expected["error"]
                    ));
                }
            }
        }
    }
    assert!(
        via_header_map >= 25,
        "only {via_header_map} vectors went through HeaderMap"
    );
    report("headers.json", vectors.len(), 30, failures);
}

#[test]
fn jwks_sets() {
    let doc = load("jwks.json");
    let sets = doc["sets"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in sets {
        let (id, expected) = (str_of(v, "id"), &v["expected"]);
        // Once parsed, once from the bytes of the document: both entry points must agree.
        let parsed = KeySet::from_jwks(&v["input"]["jwks"]);
        let bytes = KeySet::from_jwks_json(&serde_json::to_vec(&v["input"]["jwks"]).unwrap());
        if parsed != bytes {
            failures.push(format!("{id}: from_jwks and from_jwks_json disagree"));
        }
        match (parsed, expected["ok"].as_bool().unwrap()) {
            (Ok(set), true) => {
                let kids: Vec<Value> = set.kids().map(|k| Value::String(k.to_owned())).collect();
                if Value::Array(kids.clone()) != expected["kids"] {
                    failures.push(format!("{id}: kids {kids:?} ≠ {}", expected["kids"]));
                }
            }
            (Ok(_), false) => {
                failures.push(format!("{id}: accepted, expected {}", expected["error"]))
            }
            (Err(e), true) => failures.push(format!("{id}: refused ({}), expected ok", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!(
                        "{id}: {} ≠ expected {}",
                        e.class(),
                        expected["error"]
                    ));
                }
            }
        }
    }
    report("jwks.json sets", sets.len(), 15, failures);
}

#[test]
fn jwks_scenarios() {
    let doc = load("jwks.json");
    let defaults = &doc["defaults"];
    let config =
        TokenConfig::new(str_of(defaults, "issuer"), str_of(defaults, "audience")).unwrap();
    let scenarios = doc["scenarios"].as_array().unwrap();
    let mut failures = Vec::new();
    let mut steps_checked = 0;
    for s in scenarios {
        let id = str_of(s, "id");
        let mut cache = JwksCache::new();
        for (n, step) in s["steps"].as_array().unwrap().iter().enumerate() {
            steps_checked += 1;
            let now = step["now"].as_i64().unwrap();
            let fetched = Cell::new(false);
            let unexpected = Cell::new(false);
            let fetch = || {
                fetched.set(true);
                match step.get("fetch") {
                    Some(answer) => fetch_outcome(answer),
                    None => {
                        unexpected.set(true);
                        FetchOutcome::Failed
                    }
                }
            };
            let result: Result<(), TokenError> = precheck(str_of(step, "jws")).and_then(|token| {
                let key = cache.lookup_with(token.kid(), now, fetch)?;
                config.finish(token, &key, now).map(|_| ())
            });
            let expect = &step["expect"];
            let at = format!("{id} step {n}");
            if unexpected.get() {
                failures.push(format!("{at}: fetched where the step gives no answer"));
            }
            if Value::Bool(fetched.get()) != expect["fetched"] {
                failures.push(format!(
                    "{at}: fetched = {}, expected {}",
                    fetched.get(),
                    expect["fetched"]
                ));
            }
            match (result, expect["ok"].as_bool().unwrap()) {
                (Ok(()), true) => {}
                (Ok(()), false) => {
                    failures.push(format!("{at}: accepted, expected {}", expect["error"]))
                }
                (Err(e), true) => {
                    failures.push(format!("{at}: refused ({}), expected ok", e.class()))
                }
                (Err(e), false) => {
                    if e.class() != str_of(expect, "error") {
                        failures.push(format!(
                            "{at}: {} ≠ expected {}",
                            e.class(),
                            expect["error"]
                        ));
                    }
                }
            }
        }
    }
    assert!(steps_checked >= 30, "only {steps_checked} scenario steps");
    report("jwks.json scenarios", scenarios.len(), 8, failures);
}

#[test]
fn topbar() {
    let doc = load("topbar.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in vectors {
        let id = str_of(v, "id");
        let got = serde_json::to_value(topbar::normalize(&v["input"]["topbar"])).unwrap();
        if got != v["expected"]["topbar"] {
            failures.push(format!("{id}: {got} ≠ {}", v["expected"]["topbar"]));
        }
        let from_bytes =
            topbar::normalize_json(&serde_json::to_vec(&v["input"]["topbar"]).unwrap());
        if serde_json::to_value(from_bytes).unwrap() != got {
            failures.push(format!("{id}: normalize_json differs"));
        }
    }
    report("topbar.json", vectors.len(), 5, failures);
}

#[test]
fn account() {
    let doc = load("account.json");
    let vectors = doc["vectors"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in vectors {
        let id = str_of(v, "id");
        let got = serde_json::to_value(account::normalize(&v["input"]["account"])).unwrap();
        if got != v["expected"]["account"] {
            failures.push(format!("{id}: {got} ≠ {}", v["expected"]["account"]));
        }
        let from_bytes =
            account::normalize_json(&serde_json::to_vec(&v["input"]["account"]).unwrap());
        if serde_json::to_value(from_bytes).unwrap() != got {
            failures.push(format!("{id}: normalize_json differs"));
        }
    }
    report("account.json", vectors.len(), 5, failures);
    let urls = doc["action_urls"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in urls {
        let (id, input, expected) = (str_of(v, "id"), &v["input"], &v["expected"]);
        let got = match account::action_url(
            str_of(input, "href"),
            str_of(input, "return"),
            input["state"].as_str(),
        ) {
            Ok(url) => serde_json::json!({"ok": true, "url": url}),
            Err(_) => serde_json::json!({"ok": false, "error": "invalid"}),
        };
        if &got != expected {
            failures.push(format!("action_urls/{id}: {got} ≠ {expected}"));
        }
    }
    report("account.json action_urls", urls.len(), 10, failures);
    let returns = doc["action_returns"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in returns {
        let (id, input, expected) = (str_of(v, "id"), &v["input"], &v["expected"]);
        let got = match account::parse_action_return(str_of(input, "url"), input["state"].as_str())
        {
            Ok(back) => serde_json::json!({"ok": true, "return": back}),
            Err(account::ActionReturnRefused::Invalid) => {
                serde_json::json!({"ok": false, "error": "invalid"})
            }
            Err(account::ActionReturnRefused::State) => {
                serde_json::json!({"ok": false, "error": "state"})
            }
        };
        if &got != expected {
            failures.push(format!("action_returns/{id}: {got} ≠ {expected}"));
        }
    }
    report("account.json action_returns", returns.len(), 40, failures);
    let admin = doc["admin_accounts"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in admin {
        let id = str_of(v, "id");
        let got = serde_json::to_value(account::normalize_admin(&v["input"]["answer"])).unwrap();
        if got != v["expected"]["admin"] {
            failures.push(format!(
                "admin_accounts/{id}: {got} ≠ {}",
                v["expected"]["admin"]
            ));
        }
        let from_bytes =
            account::normalize_admin_json(&serde_json::to_vec(&v["input"]["answer"]).unwrap());
        if serde_json::to_value(from_bytes).unwrap() != got {
            failures.push(format!("admin_accounts/{id}: normalize_admin_json differs"));
        }
    }
    report("account.json admin_accounts", admin.len(), 8, failures);
}

#[test]
fn approval() {
    let doc = load("approval.json");
    assert_eq!(doc["spec"], "spec/approval-token.md");
    let vectors = doc["vectors"].as_array().unwrap();
    let mut failures = Vec::new();
    for v in vectors {
        let id = str_of(v, "id");
        let input = &v["input"];
        let keys = KeySet::from_jwks(&input["jwks"]).unwrap();
        let config = ApprovalConfig::new(str_of(input, "issuer"), str_of(input, "app_id"))
            .unwrap()
            .with_leeway(u32::try_from(input["leeway"].as_u64().unwrap()).unwrap())
            .unwrap();
        let verifier = ApprovalVerifier::new(config, keys).unwrap();
        let e = &input["expect"];
        let mut expect = ApprovalExpect::new(str_of(e, "type"), str_of(e, "sub"))
            .fields(e["fields"].as_object().unwrap().clone());
        if let Some(nonce) = e.get("nonce").and_then(Value::as_str) {
            expect = expect.nonce(nonce);
        }
        let seen: std::cell::RefCell<BTreeSet<String>> = std::cell::RefCell::new(
            input["seen"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| s.as_str().unwrap().to_owned())
                .collect(),
        );
        let store = |jti: &str, _until: i64| -> Result<bool, StoreFailed> {
            Ok(seen.borrow_mut().insert(jti.to_owned()))
        };
        let now = input["now"].as_i64().unwrap();
        let got = verifier.verify_at(str_of(input, "jws"), &expect, &store, now);
        let expected = &v["expected"];
        match (got, expected["ok"].as_bool().unwrap()) {
            (Ok(claims), true) => {
                if Value::Object(claims.as_map().clone()) != expected["claims"] {
                    failures.push(format!("{id}: claims differ"));
                }
            }
            (Ok(_), false) => failures.push(format!("{id}: accepted, want {}", expected["error"])),
            (Err(e), true) => failures.push(format!("{id}: refused with {}", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!("{id}: {} ≠ {}", e.class(), expected["error"]));
                }
            }
        }
    }
    report("approval.json", vectors.len(), 40, failures);
}

/// One store for two checks: the first use passes, the second is `replay`; a failing store refuses (fails closed); a
/// confirmation refused for another reason does not reach the store.
#[test]
fn approval_store() {
    let doc = load("approval.json");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "valid-basic")
        .unwrap();
    let input = &v["input"];
    let verifier = ApprovalVerifier::new(
        ApprovalConfig::new(str_of(input, "issuer"), str_of(input, "app_id")).unwrap(),
        KeySet::from_jwks(&input["jwks"]).unwrap(),
    )
    .unwrap();
    let e = &input["expect"];
    let expect = ApprovalExpect::new(str_of(e, "type"), str_of(e, "sub"))
        .fields(e["fields"].as_object().unwrap().clone());
    let now = input["now"].as_i64().unwrap();
    let jws = str_of(input, "jws");
    let seen = std::cell::RefCell::new(BTreeSet::new());
    let once = |jti: &str, _until: i64| -> Result<bool, StoreFailed> {
        Ok(seen.borrow_mut().insert(jti.to_owned()))
    };
    assert!(verifier.verify_at(jws, &expect, &once, now).is_ok());
    assert_eq!(
        verifier
            .verify_at(jws, &expect, &once, now)
            .unwrap_err()
            .class(),
        "replay"
    );
    let failing = |_: &str, _: i64| -> Result<bool, StoreFailed> { Err(StoreFailed) };
    assert_eq!(
        verifier
            .verify_at(jws, &expect, &failing, now)
            .unwrap_err()
            .class(),
        "internal"
    );
    let touched = Cell::new(false);
    let spy = |_: &str, _: i64| -> Result<bool, StoreFailed> {
        touched.set(true);
        Ok(true)
    };
    let other = ApprovalExpect::new(str_of(e, "type"), "1002")
        .fields(e["fields"].as_object().unwrap().clone());
    assert_eq!(
        verifier
            .verify_at(jws, &other, &spy, now)
            .unwrap_err()
            .class(),
        "subject"
    );
    assert!(
        !touched.get(),
        "the store was written for a refused confirmation"
    );
}

fn permission_mismatches(identity: &Identity, expected: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if serde_json::json!(identity.permissions) != expected["permissions"] {
        out.push(format!(
            "permissions {:?} ≠ {}",
            identity.permissions, expected["permissions"]
        ));
    }
    if let Some(checks) = expected.get("has_permission").and_then(Value::as_object) {
        for (p, want) in checks {
            if identity.has_permission(p) != want.as_bool().unwrap() {
                out.push(format!("has_permission({p:?}) ≠ {want}"));
            }
        }
    }
    out
}

#[test]
fn permissions() {
    let doc = load("permissions.json");
    let mut failures = Vec::new();
    let mut count = 0;
    let mode = HeaderMode::trust_proxy();
    for v in doc["headers"].as_array().unwrap() {
        count += 1;
        let (id, expected) = (str_of(v, "id"), &v["expected"]);
        let mut fields: Vec<(String, Vec<u8>)> = Vec::new();
        for (name, value) in v["input"]["headers"].as_object().unwrap() {
            match value {
                Value::Array(list) => fields.extend(
                    list.iter()
                        .map(|x| (name.clone(), octets(x.as_str().unwrap()))),
                ),
                other => fields.push((name.clone(), octets(other.as_str().unwrap()))),
            }
        }
        let result =
            mode.identify_fields(fields.iter().map(|(n, b)| (n.as_str(), b.as_slice())), None);
        match (result, expected["ok"].as_bool().unwrap()) {
            (Ok(identity), true) => failures.extend(
                permission_mismatches(&identity, expected)
                    .into_iter()
                    .map(|m| format!("headers/{id}: {m}")),
            ),
            (Ok(_), false) => failures.push(format!("headers/{id}: accepted")),
            (Err(e), true) => failures.push(format!("headers/{id}: refused ({})", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!(
                        "headers/{id}: {} ≠ {}",
                        e.class(),
                        expected["error"]
                    ));
                }
            }
        }
    }
    for v in doc["tokens"].as_array().unwrap() {
        count += 1;
        let (id, input, expected) = (str_of(v, "id"), &v["input"], &v["expected"]);
        let keys = KeySet::from_jwks(&input["jwks"]).unwrap();
        let config = TokenConfig::new(str_of(input, "issuer"), str_of(input, "audience")).unwrap();
        match (
            config.verify_with(str_of(input, "jws"), &keys, input["now"].as_i64().unwrap()),
            expected["ok"].as_bool().unwrap(),
        ) {
            (Ok(verified), true) => failures.extend(
                permission_mismatches(&verified.identity, expected)
                    .into_iter()
                    .map(|m| format!("tokens/{id}: {m}")),
            ),
            (Ok(_), false) => failures.push(format!("tokens/{id}: accepted")),
            (Err(e), true) => failures.push(format!("tokens/{id}: refused ({})", e.class())),
            (Err(e), false) => {
                if e.class() != str_of(expected, "error") {
                    failures.push(format!(
                        "tokens/{id}: {} ≠ {}",
                        e.class(),
                        expected["error"]
                    ));
                }
            }
        }
    }
    for v in doc["register"].as_array().unwrap() {
        count += 1;
        let (id, input, expected) = (str_of(v, "id"), &v["input"], &v["expected"]);
        let got = match register_request(
            str_of(input, "base_url"),
            str_of(input, "app"),
            &input["permissions"],
        ) {
            Ok(req) => serde_json::json!({"ok": true,
                "request": {"method": req.method, "url": req.url, "body": req.body}}),
            Err(_) => serde_json::json!({"ok": false, "error": "invalid"}),
        };
        if &got != expected {
            failures.push(format!("register/{id}: {got} ≠ {expected}"));
        }
    }
    report("permissions.json", count, 20, failures);
}
