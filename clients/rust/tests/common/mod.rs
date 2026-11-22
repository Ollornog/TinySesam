//! Shared helpers of the vector suites: the vectors are read from this repository (`../../spec/vectors/`), never
//! from a copy.
#![allow(dead_code)]

use serde_json::{Value, json};
use std::path::PathBuf;
use tinysesam_gate::{FetchOutcome, Identity};

pub fn vector_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../spec/vectors")
}

pub fn load(name: &str) -> Value {
    let path = vector_dir().join(name);
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let doc: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(doc["format"], 1, "{name}: unknown vector format");
    doc
}

pub fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v[key]
        .as_str()
        .unwrap_or_else(|| panic!("{key} is not a string in {v}"))
}

pub fn identity_json(id: &Identity) -> Value {
    json!({
        "user": id.user, "name": id.name, "email": id.email, "groups": id.groups, "id": id.id,
        "auth": id.auth.as_str(), "kind": id.kind.as_str(),
    })
}

/// The simulated answer of a scenario step.
pub fn fetch_outcome(fetch: &Value) -> FetchOutcome {
    if fetch.get("error").is_some() {
        return FetchOutcome::Failed;
    }
    let body = if let Some(body) = fetch.get("body") {
        serde_json::to_vec(body).unwrap()
    } else {
        fetch
            .get("body_text")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .as_bytes()
            .to_vec()
    };
    FetchOutcome::Response {
        status: u16::try_from(fetch["status"].as_u64().expect("status")).unwrap(),
        cache_control: fetch
            .get("cache_control")
            .and_then(Value::as_str)
            .map(str::to_owned),
        body,
    }
}

/// Compares the expected `has_role` answers of a vector with the identity; returns the mismatches.
pub fn role_mismatches(id: &Identity, expected: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(roles) = expected.get("has_role").and_then(Value::as_object) {
        for (role, want) in roles {
            if Value::Bool(id.has_role(role)) != *want {
                out.push(format!("has_role({role}) ≠ {want}"));
            }
        }
    }
    out
}

/// Fails with every mismatch at once, after checking that the suite saw something at all.
pub fn report(suite: &str, checked: usize, minimum: usize, failures: Vec<String>) {
    assert!(
        checked >= minimum,
        "{suite}: only {checked} vectors checked — does the runner still read the file?"
    );
    assert!(
        failures.is_empty(),
        "{suite}: {} of {checked} vectors failed:\n  {}",
        failures.len(),
        failures.join("\n  ")
    );
    println!("{suite}: {checked} vectors passed");
}
