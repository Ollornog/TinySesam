//! Property tests for the parsers: no input panics, the strict rules hold for generated input, and a changed token
//! never verifies.

mod common;

use common::*;
use proptest::prelude::*;
use tinysesam_gate::{
    HeaderError, HeaderMode, KeySet, TokenConfig, TokenError, parse_groups, precheck, topbar,
};

fn valid_token() -> (String, i64, KeySet, TokenConfig) {
    let doc = load("token.json");
    let v = doc["vectors"]
        .as_array()
        .unwrap()
        .iter()
        .find(|v| v["id"] == "valid-session")
        .unwrap()
        .clone();
    let input = &v["input"];
    let keys = KeySet::from_jwks(&input["jwks"]).unwrap();
    let config = TokenConfig::new(str_of(input, "issuer"), str_of(input, "audience")).unwrap();
    (
        str_of(input, "jws").to_owned(),
        input["now"].as_i64().unwrap(),
        keys,
        config,
    )
}

const B64URL: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

proptest! {
    // No regression file: a test run must not write into the tree (a failing case is printed instead).
    #![proptest_config(ProptestConfig { cases: 512, failure_persistence: None, ..ProptestConfig::default() })]

    #[test]
    fn precheck_never_panics(s in any::<String>()) {
        let _ = precheck(&s);
    }

    #[test]
    fn precheck_never_panics_on_token_shapes(s in "[A-Za-z0-9_=+/.-]{0,300}") {
        let _ = precheck(&s);
    }

    #[test]
    fn a_changed_character_never_verifies(pos in 0usize..10_000, pick in 0usize..64) {
        let (jws, now, keys, config) = valid_token();
        let mut bytes = jws.clone().into_bytes();
        let pos = pos % bytes.len();
        let replacement = if bytes[pos] == b'.' { b'.' } else { B64URL[pick] };
        prop_assume!(replacement != bytes[pos]);
        bytes[pos] = replacement;
        let changed = String::from_utf8(bytes).unwrap();
        prop_assert!(config.verify_with(&changed, &keys, now).is_err());
    }

    #[test]
    fn appended_or_inserted_bytes_never_verify(pos in 0usize..10_000, extra in "[ =\\n\\t+/A-Za-z0-9.]{1,3}") {
        let (jws, now, keys, config) = valid_token();
        let pos = pos % (jws.len() + 1);
        let changed = format!("{}{}{}", &jws[..pos], extra, &jws[pos..]);
        prop_assert!(config.verify_with(&changed, &keys, now).is_err());
    }

    #[test]
    fn groups_invariants(s in any::<String>()) {
        let groups = parse_groups(&s);
        for (i, g) in groups.iter().enumerate() {
            prop_assert!(!g.is_empty());
            prop_assert!(!g.contains(','));
            prop_assert!(!g.starts_with(' ') && !g.ends_with(' '));
            prop_assert!(!groups[..i].contains(g), "repeated entry");
        }
        // Every non-empty trimmed entry of the input is there, in the order of its first occurrence.
        let mut expected: Vec<&str> = Vec::new();
        for part in s.split(',').map(|p| p.trim_matches(' ')).filter(|p| !p.is_empty()) {
            if !expected.contains(&part) {
                expected.push(part);
            }
        }
        prop_assert_eq!(groups, expected);
    }

    #[test]
    fn header_values_never_panic(user in proptest::collection::vec(any::<u8>(), 0..40),
                                 name in proptest::collection::vec(any::<u8>(), 0..40)) {
        let mode = HeaderMode::trust_proxy();
        let _ = mode.identify_fields([("Remote-User", user.as_slice()), ("Remote-Name", name.as_slice())], None);
    }

    #[test]
    fn a_control_character_is_refused_never_stripped(prefix in "[a-z]{0,8}", c in 0u8..0x20, suffix in "[a-z]{0,8}",
                                                    del in any::<bool>()) {
        let c = if del { 0x7f } else { c };
        let mut value = prefix.into_bytes();
        value.push(c);
        value.extend_from_slice(suffix.as_bytes());
        let mode = HeaderMode::trust_proxy();
        for slot in tinysesam_gate::REMOTE_HEADERS {
            // Every other slot well-formed (Remote-Kind included), so the control character is the only defect.
            let mut fields = vec![("Remote-User", b"anna".as_slice()), ("Remote-Kind", b"user".as_slice())];
            match slot {
                "Remote-User" => fields[0].1 = value.as_slice(),
                "Remote-Kind" => fields[1].1 = value.as_slice(),
                _ => fields.push((slot, value.as_slice())),
            }
            prop_assert_eq!(mode.identify_fields(fields, None), Err(HeaderError::Header));
        }
    }

    #[test]
    fn remote_id_is_ascii_digits_only(id in "\\PC{1,6}") {
        let mode = HeaderMode::trust_proxy();
        let r = mode.identify_fields([("Remote-User", b"anna".as_slice()), ("Remote-Id", id.as_bytes()),
                                      ("Remote-Kind", b"user".as_slice())], None);
        let digits = id.bytes().all(|b| b.is_ascii_digit());
        let control = id.chars().any(|c| c < ' ' || c == '\u{7f}');
        prop_assert_eq!(r.is_ok(), digits && !control);
    }

    #[test]
    fn topbar_never_panics_and_signed_out_has_nothing(raw in proptest::collection::vec(any::<u8>(), 0..200)) {
        let bar = topbar::normalize_json(&raw);
        if !bar.signed_in {
            prop_assert!(bar.links.is_empty() && bar.name.is_none() && bar.logout.is_none());
        }
    }

    #[test]
    fn jwks_documents_never_panic(raw in proptest::collection::vec(any::<u8>(), 0..300)) {
        let _ = KeySet::from_jwks_json(&raw);
    }
}

#[test]
fn the_valid_token_of_the_properties_verifies() {
    // Without this positive control every "never verifies" property above would hold vacuously.
    let (jws, now, keys, config) = valid_token();
    assert!(config.verify_with(&jws, &keys, now).is_ok());
    assert_eq!(
        config.verify_with(&jws, &keys, now + 300).err(),
        Some(TokenError::Expired)
    );
}
