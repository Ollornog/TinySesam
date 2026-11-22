//! Tokens minted here with the public test key A of `spec/vectors/keys.json`, each with exactly ONE defect in a
//! correctly signed payload. A vector that combines two defects lets a client pass that checks only one of them
//! (`attack-payload-invalid-utf8` also repeats `ts_name`); these isolate every rule of spec §4.4 step 8.

mod common;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::*;
use ed25519_dalek::{Signer, SigningKey};
use tinysesam_gate::{KeySet, TokenConfig, TokenError};

struct Minter {
    signing: SigningKey,
    keys: KeySet,
    config: TokenConfig,
    now: i64,
}

fn minter() -> Minter {
    let keys_doc = load("keys.json");
    let a = &keys_doc["keys"]["A"];
    let seed: [u8; 32] = URL_SAFE_NO_PAD
        .decode(str_of(a, "d"))
        .unwrap()
        .try_into()
        .unwrap();
    let d = &keys_doc["defaults"];
    Minter {
        signing: SigningKey::from_bytes(&seed),
        keys: KeySet::from_sign_keys([str_of(a, "sign_key_base64")]).unwrap(),
        config: TokenConfig::new(str_of(d, "issuer"), str_of(d, "audience")).unwrap(),
        now: d["now"].as_i64().unwrap(),
    }
}

impl Minter {
    /// A correctly signed token over the raw payload bytes.
    fn mint(&self, payload: &[u8]) -> String {
        let head = URL_SAFE_NO_PAD
            .encode(br#"{"alg":"EdDSA","typ":"tinysesam-gate+jwt","kid":"a033507ca61ad979"}"#);
        let input = format!("{head}.{}", URL_SAFE_NO_PAD.encode(payload));
        let sig = self.signing.sign(input.as_bytes());
        format!("{input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn payload(&self, name: &[u8]) -> Vec<u8> {
        let (nbf, exp) = (self.now, self.now + 300);
        let mut out = format!(
            r#"{{"iss":"https://auth.example.com","aud":"app.example.com","sub":"1","iat":{nbf},"nbf":{nbf},"exp":{exp},"ts_user":"anna","ts_name":""#
        )
        .into_bytes();
        out.extend_from_slice(name);
        out.extend_from_slice(br#"","ts_auth":"session"}"#);
        out
    }

    fn check(&self, payload: &[u8]) -> Result<String, TokenError> {
        self.config
            .verify_with(&self.mint(payload), &self.keys, self.now)
            .map(|v| v.identity.name)
    }
}

#[test]
fn the_control_token_verifies() {
    let m = minter();
    assert_eq!(
        m.check(&m.payload("Jürgen".as_bytes())),
        Ok("Jürgen".to_owned())
    );
}

#[test]
fn invalid_utf8_alone_is_malformed() {
    let m = minter();
    for bad in [
        &b"J\xfcrgen"[..],
        b"\xff",
        b"\xc0\xaf",
        b"\xed\xa0\x80",
        b"a\xe2\x82",
    ] {
        assert_eq!(
            m.check(&m.payload(bad)),
            Err(TokenError::Malformed),
            "{bad:?}"
        );
    }
}

#[test]
fn a_byte_order_mark_alone_is_malformed() {
    let m = minter();
    let mut payload = b"\xef\xbb\xbf".to_vec();
    payload.extend(m.payload(b"Anna"));
    assert_eq!(m.check(&payload), Err(TokenError::Malformed));
}

#[test]
fn a_repeated_claim_alone_is_malformed() {
    let m = minter();
    let mut payload = m.payload(b"Anna");
    payload.pop();
    payload.extend_from_slice(br#","ts_user":"admin"}"#);
    assert_eq!(m.check(&payload), Err(TokenError::Malformed));
}

#[test]
fn nan_and_a_lone_surrogate_escape_are_malformed() {
    let m = minter();
    let mut nan = m.payload(b"Anna");
    nan.pop();
    nan.extend_from_slice(br#","x":NaN}"#);
    assert_eq!(m.check(&nan), Err(TokenError::Malformed));
    assert_eq!(m.check(&m.payload(br"\ud800")), Err(TokenError::Malformed));
}
