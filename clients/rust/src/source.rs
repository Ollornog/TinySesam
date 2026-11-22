//! Where the gate token comes from (spec §4.2): exactly one configured source.

use crate::error::TokenError;
use http::HeaderMap;
use http::header::{COOKIE, HeaderName};

/// The default name of the gate cookie (`gate_cookie_name`).
pub const GATE_COOKIE: &str = "__Host-tinysesam_gate";

/// The one place a token is read from. Never a query parameter, a form field or `Authorization` unless configured
/// explicitly as a header source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenSource {
    /// A cookie of this name. More than one such cookie in a request is `malformed`.
    Cookie(String),
    /// A request header of this name. More than one such field is `malformed`.
    Header(HeaderName),
}

impl Default for TokenSource {
    fn default() -> Self {
        TokenSource::Cookie(GATE_COOKIE.to_owned())
    }
}

impl TokenSource {
    /// The token of a request: [`TokenError::Missing`] without one, [`TokenError::Malformed`] for a repeated or
    /// unreadable one.
    pub fn extract(&self, headers: &HeaderMap) -> Result<String, TokenError> {
        let found: Vec<&[u8]> = match self {
            TokenSource::Cookie(name) => headers
                .get_all(COOKIE)
                .iter()
                .flat_map(|field| field.as_bytes().split(|&b| b == b';'))
                .filter_map(|pair| {
                    let pair = pair.trim_ascii();
                    let eq = pair.iter().position(|&b| b == b'=')?;
                    (pair[..eq].trim_ascii() == name.as_bytes())
                        .then(|| pair[eq + 1..].trim_ascii())
                })
                .collect(),
            TokenSource::Header(name) => headers
                .get_all(name)
                .iter()
                .map(|v| v.as_bytes().trim_ascii())
                .collect(),
        };
        match found.as_slice() {
            [] | [b""] => Err(TokenError::Missing),
            [one] => std::str::from_utf8(one)
                .map(str::to_owned)
                .map_err(|_| TokenError::Malformed),
            _ => Err(TokenError::Malformed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderValue;

    fn cookies(values: &[&str]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for v in values {
            h.append(COOKIE, HeaderValue::from_str(v).unwrap());
        }
        h
    }

    #[test]
    fn cookie_source() {
        let src = TokenSource::default();
        assert_eq!(
            src.extract(&cookies(&["a=1; __Host-tinysesam_gate=abc; b=2"])),
            Ok("abc".to_owned())
        );
        assert_eq!(src.extract(&cookies(&["a=1"])), Err(TokenError::Missing));
        assert_eq!(src.extract(&cookies(&[])), Err(TokenError::Missing));
        assert_eq!(
            src.extract(&cookies(&["__Host-tinysesam_gate="])),
            Err(TokenError::Missing)
        );
        assert_eq!(
            src.extract(&cookies(&[
                "__Host-tinysesam_gate=a; __Host-tinysesam_gate=b"
            ])),
            Err(TokenError::Malformed)
        );
        assert_eq!(
            src.extract(&cookies(&[
                "__Host-tinysesam_gate=a",
                "__Host-tinysesam_gate=b"
            ])),
            Err(TokenError::Malformed),
            "two Cookie fields"
        );
        assert_eq!(
            src.extract(&cookies(&["x__Host-tinysesam_gate=a"])),
            Err(TokenError::Missing)
        );
    }

    #[test]
    fn header_source() {
        let src = TokenSource::Header(HeaderName::from_static("x-gate-token"));
        let mut h = HeaderMap::new();
        assert_eq!(src.extract(&h), Err(TokenError::Missing));
        h.append("x-gate-token", HeaderValue::from_static("abc"));
        assert_eq!(src.extract(&h), Ok("abc".to_owned()));
        h.append("x-gate-token", HeaderValue::from_static("def"));
        assert_eq!(src.extract(&h), Err(TokenError::Malformed));
        let mut auth = HeaderMap::new();
        auth.insert(
            http::header::AUTHORIZATION,
            HeaderValue::from_static("Bearer abc"),
        );
        assert_eq!(
            src.extract(&auth),
            Err(TokenError::Missing),
            "never Authorization unless configured"
        );
    }
}
