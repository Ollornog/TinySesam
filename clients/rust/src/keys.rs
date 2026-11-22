//! Public gate keys (spec §4.3): fixed keys from configuration, or entries of a key set document (JWKS).

use crate::error::{ConfigError, JwksInvalid};
use crate::strict::{b64url, json_value};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fmt::Write as _;

/// At most this many entries in a key set document.
pub const JWKS_MAX_KEYS: usize = 32;

/// An Ed25519 public gate key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub(crate) VerifyingKey);

impl PublicKey {
    /// A key from its 32 raw bytes; `None` for bytes that are no valid Ed25519 point.
    pub fn from_bytes(raw: &[u8; 32]) -> Option<PublicKey> {
        VerifyingKey::from_bytes(raw).ok().map(PublicKey)
    }

    /// The `kid` of this key: the first 16 hex digits of SHA-256 over the 32 raw bytes (spec §4.1).
    pub fn kid(&self) -> String {
        key_id(self.0.as_bytes())
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({})", self.kid())
    }
}

/// The `kid` of 32 raw public key bytes: the first 16 hex digits of their SHA-256.
pub fn key_id(public: &[u8; 32]) -> String {
    let digest = Sha256::digest(public);
    let mut out = String::with_capacity(16);
    for b in &digest[..8] {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A key set `kid → public key`, in the order of its source.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeySet {
    keys: Vec<(String, PublicKey)>,
}

impl KeySet {
    /// Fixed keys: each the output of `tinysesam gate-key` (32 raw bytes, standard Base64 — the proxy's `sign_key`).
    /// Several keys are fine (before and after a rotation). An empty list or an unreadable key is a configuration
    /// error.
    pub fn from_sign_keys<I, S>(keys: I) -> Result<KeySet, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut out = KeySet::default();
        for text in keys {
            let raw = STANDARD
                .decode(text.as_ref().trim())
                .map_err(|_| ConfigError::new("a gate key is not standard Base64"))?;
            let raw: [u8; 32] = raw
                .try_into()
                .map_err(|_| ConfigError::new("a gate key is not 32 bytes"))?;
            let key = PublicKey::from_bytes(&raw)
                .ok_or_else(|| ConfigError::new("a gate key is no Ed25519 key"))?;
            let kid = key.kid();
            match out.get(&kid) {
                Some(existing) if *existing == key => {}
                Some(_) => return Err(ConfigError::new("two gate keys share one kid")),
                None => out.keys.push((kid, key)),
            }
        }
        if out.keys.is_empty() {
            return Err(ConfigError::new("no gate key"));
        }
        Ok(out)
    }

    /// The usable entries of a key set document given as bytes (strict JSON: no duplicate member names).
    pub fn from_jwks_json(raw: &[u8]) -> Result<KeySet, JwksInvalid> {
        KeySet::from_jwks(&json_value(raw).ok_or(JwksInvalid)?)
    }

    /// The usable entries of a parsed key set document. Unusable entries are skipped; two entries with the same
    /// `kid` make that `kid` unusable. A document that is not an object, has no `keys` array or more than 32 entries
    /// is [`JwksInvalid`].
    pub fn from_jwks(doc: &Value) -> Result<KeySet, JwksInvalid> {
        let entries = doc
            .as_object()
            .and_then(|o| o.get("keys"))
            .and_then(Value::as_array)
            .ok_or(JwksInvalid)?;
        if entries.len() > JWKS_MAX_KEYS {
            return Err(JwksInvalid);
        }
        let found: Vec<(String, PublicKey)> = entries.iter().filter_map(jwk_entry).collect();
        let keys = found
            .iter()
            .filter(|(kid, _)| found.iter().filter(|(k, _)| k == kid).count() == 1)
            .cloned()
            .collect();
        Ok(KeySet { keys })
    }

    /// The key for a `kid`.
    pub fn get(&self, kid: &str) -> Option<&PublicKey> {
        self.keys.iter().find(|(k, _)| k == kid).map(|(_, key)| key)
    }

    /// The `kid`s in order.
    pub fn kids(&self) -> impl Iterator<Item = &str> {
        self.keys.iter().map(|(k, _)| k.as_str())
    }

    /// Number of usable keys.
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// True when no key is usable.
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }
}

/// `(kid, key)` of a usable entry, `None` for one that must be skipped (spec §4.3).
fn jwk_entry(entry: &Value) -> Option<(String, PublicKey)> {
    let entry = entry.as_object()?;
    let is = |name: &str, want: &str| entry.get(name).and_then(Value::as_str) == Some(want);
    if !is("kty", "OKP") || !is("crv", "Ed25519") {
        return None;
    }
    if ["d", "x5u", "x5c", "x5t", "x5t#S256", "jku"]
        .iter()
        .any(|m| entry.contains_key(*m))
    {
        return None;
    }
    if entry.contains_key("alg") && !is("alg", "EdDSA") {
        return None;
    }
    if entry.contains_key("use") && !is("use", "sig") {
        return None;
    }
    if let Some(ops) = entry.get("key_ops")
        && !ops
            .as_array()
            .is_some_and(|ops| ops.iter().any(|o| o.as_str() == Some("verify")))
    {
        return None;
    }
    let x = entry.get("x").and_then(Value::as_str)?;
    let kid = entry.get("kid").and_then(Value::as_str)?;
    let raw: [u8; 32] = b64url(x)?.try_into().ok()?;
    if kid != key_id(&raw) {
        return None;
    }
    Some((kid.to_owned(), PublicKey::from_bytes(&raw)?))
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "ecc3yanysDDBsjOxE03UuR3bhBJmVjsRPkXuVsCwVCY=";

    #[test]
    fn fixed_keys() {
        let set = KeySet::from_sign_keys([A]).unwrap();
        assert_eq!(set.kids().collect::<Vec<_>>(), ["a033507ca61ad979"]);
        assert_eq!(KeySet::from_sign_keys([A, A]).unwrap().len(), 1);
        assert!(KeySet::from_sign_keys(Vec::<&str>::new()).is_err());
        assert!(
            KeySet::from_sign_keys(["ecc3yanysDDBsjOxE03UuR3bhBJmVjsRPkXuVsCw"]).is_err(),
            "short"
        );
        assert!(KeySet::from_sign_keys(["not base64!"]).is_err());
    }
}
