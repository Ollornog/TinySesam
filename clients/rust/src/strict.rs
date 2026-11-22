//! Strict decoders: base64url and JSON exactly as spec §4.4 steps 2, 3 and 8 demand.
//!
//! The decoding itself comes from maintained libraries (`base64`, `serde_json`); this module adds the rules no
//! library enforces by default: the alphabet and canonical form of a segment, no byte order mark, and no member name
//! twice (every common JSON parser keeps the last of two equal names).

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;

/// Strict base64url: only `A–Z a–z 0–9 - _`, no padding, no whitespace, canonical (the unused bits are zero).
pub(crate) fn b64url(segment: &str) -> Option<Vec<u8>> {
    if !segment
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        || segment.len() % 4 == 1
    {
        return None;
    }
    // The engine refuses padding and non-zero trailing bits; the re-encoding is the explicit canonical check.
    let raw = URL_SAFE_NO_PAD.decode(segment).ok()?;
    (URL_SAFE_NO_PAD.encode(&raw) == segment).then_some(raw)
}

/// A JSON value from UTF-8 bytes: strict UTF-8, no byte order mark, no member name twice, no `NaN`/`Infinity`.
pub(crate) fn json_value(raw: &[u8]) -> Option<Value> {
    let text = std::str::from_utf8(raw).ok()?;
    if text.starts_with('\u{feff}') {
        return None;
    }
    serde_json::from_str::<Strict>(text).ok().map(|s| s.0)
}

/// A JSON object (`json_value` that must be an object).
pub(crate) fn json_object(raw: &[u8]) -> Option<Map<String, Value>> {
    match json_value(raw)? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// A `serde_json::Value` whose objects refuse a repeated member name at every depth.
struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(StrictVisitor)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Strict;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, v: bool) -> Result<Strict, E> {
        Ok(Strict(Value::Bool(v)))
    }

    fn visit_i64<E>(self, v: i64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }

    fn visit_u64<E>(self, v: u64) -> Result<Strict, E> {
        Ok(Strict(Value::Number(v.into())))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Strict, E> {
        Number::from_f64(v)
            .map(|n| Strict(Value::Number(n)))
            .ok_or_else(|| E::custom("not a finite number"))
    }

    fn visit_str<E>(self, v: &str) -> Result<Strict, E> {
        Ok(Strict(Value::String(v.to_owned())))
    }

    fn visit_string<E>(self, v: String) -> Result<Strict, E> {
        Ok(Strict(Value::String(v)))
    }

    fn visit_unit<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_none<E>(self) -> Result<Strict, E> {
        Ok(Strict(Value::Null))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Strict, A::Error> {
        let mut out = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            out.push(v);
        }
        Ok(Strict(Value::Array(out)))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut access: A) -> Result<Strict, A::Error> {
        let mut out = Map::new();
        while let Some(key) = access.next_key::<String>()? {
            if out.contains_key(&key) {
                return Err(de::Error::custom("duplicate member name"));
            }
            let Strict(v) = access.next_value()?;
            out.insert(key, v);
        }
        Ok(Strict(Value::Object(out)))
    }
}

/// C0 control characters (U+0000–U+001F, tab included) and DEL — refused, never stripped (spec §2.2, §4.4 step 9).
pub(crate) fn has_control(text: &str) -> bool {
    text.chars().any(|c| c < ' ' || c == '\u{7f}')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_is_strict() {
        assert_eq!(b64url("YQ"), Some(b"a".to_vec()));
        assert_eq!(b64url(""), Some(Vec::new()));
        assert_eq!(b64url("YQ=="), None, "padding");
        assert_eq!(b64url("YR"), None, "non-zero unused bits");
        assert_eq!(b64url("Y"), None, "impossible length");
        assert_eq!(b64url("+/8"), None, "standard alphabet");
        assert_eq!(b64url("YQ\n"), None, "line break");
        assert_eq!(b64url(" YQ"), None, "whitespace");
    }

    #[test]
    fn json_refuses_duplicates_at_every_depth() {
        assert!(json_object(br#"{"a":1,"b":{"c":2}}"#).is_some());
        assert!(json_object(br#"{"a":1,"a":1}"#).is_none());
        assert!(json_object(br#"{"a":{"c":1,"c":2}}"#).is_none());
        assert!(json_object(br#"{"a":[{"c":1,"c":2}]}"#).is_none());
    }

    #[test]
    fn json_refuses_bom_nan_and_non_objects() {
        assert!(json_object(b"\xef\xbb\xbf{}").is_none());
        assert!(json_object(br#"{"a":NaN}"#).is_none());
        assert!(json_object(br#"{"a":Infinity}"#).is_none());
        assert!(json_object(b"[1,2]").is_none());
        assert!(json_object(b"{\"a\":\"\xff\"}").is_none());
        assert!(json_object(b"{} x").is_none(), "trailing data");
    }

    #[test]
    fn control_characters() {
        assert!(has_control("a\tb"));
        assert!(has_control("a\u{0}"));
        assert!(has_control("\u{7f}"));
        assert!(!has_control("\u{202e}\u{200d}ä"));
    }
}
