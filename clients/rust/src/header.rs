//! Header mode (spec §2): the identity from the `Remote-*` headers the proxy sets.
//!
//! The client cannot verify where a header came from. Header mode is only safe when the deployment guarantees the
//! proxy duties of spec §2.1 — see the crate README. [`HeaderMode::trust_proxy`] is the explicit opt-in.

use crate::error::{ConfigError, HeaderError};
use crate::identity::{Identity, check_account_kind};
use crate::strict::has_control;
use http::HeaderMap;
use http::header::HeaderName;
use std::net::IpAddr;

/// The eight identity headers under their default names (spec version 2 added `Remote-Kind`, T-101
/// `Remote-Permissions`, which is optional on the wire: missing or empty means none).
pub const REMOTE_HEADERS: [&str; 8] = [
    "Remote-User",
    "Remote-Name",
    "Remote-Email",
    "Remote-Groups",
    "Remote-Id",
    "Remote-Auth",
    "Remote-Kind",
    "Remote-Permissions",
];

/// Names of the seven identity headers. TinySesam's `forward_headers` can rename them; the defaults are
/// [`REMOTE_HEADERS`]. Header names are compared case-insensitively.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderNames {
    /// The account name (default `Remote-User`).
    pub user: String,
    /// The display name (default `Remote-Name`).
    pub name: String,
    /// The e-mail address (default `Remote-Email`).
    pub email: String,
    /// The roles (default `Remote-Groups`).
    pub groups: String,
    /// The account ID (default `Remote-Id`).
    pub id: String,
    /// How the request signed in (default `Remote-Auth`).
    pub auth: String,
    /// What the account is, `user` or `service` (default `Remote-Kind`).
    pub kind: String,
    /// The account's permissions for this application (default `Remote-Permissions`, spec §3.4).
    pub permissions: String,
}

impl Default for HeaderNames {
    fn default() -> Self {
        let [user, name, email, groups, id, auth, kind, permissions] =
            REMOTE_HEADERS.map(str::to_owned);
        HeaderNames {
            user,
            name,
            email,
            groups,
            id,
            auth,
            kind,
            permissions,
        }
    }
}

impl HeaderNames {
    fn slots(&self) -> [&str; 8] {
        [
            &self.user,
            &self.name,
            &self.email,
            &self.groups,
            &self.id,
            &self.auth,
            &self.kind,
            &self.permissions,
        ]
    }
}

/// An address range of trusted proxies, `192.0.2.10` or `192.0.2.0/24` or `2001:db8::/32`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct PeerNet {
    addr: IpAddr,
    prefix: u8,
}

impl PeerNet {
    fn parse(text: &str) -> Option<PeerNet> {
        let (addr, prefix) = match text.split_once('/') {
            Some((a, p)) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => {
                (a, Some(p.parse::<u8>().ok()?))
            }
            Some(_) => return None,
            None => (text, None),
        };
        let addr: IpAddr = addr.parse().ok()?;
        let addr = addr.to_canonical();
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = prefix.unwrap_or(max);
        (prefix <= max).then_some(PeerNet { addr, prefix })
    }

    fn contains(&self, peer: IpAddr) -> bool {
        match (self.addr, peer.to_canonical()) {
            (IpAddr::V4(net), IpAddr::V4(p)) => {
                let mask = u32::MAX
                    .checked_shl(32 - u32::from(self.prefix))
                    .unwrap_or(0);
                u32::from(net) & mask == u32::from(p) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(p)) => {
                let mask = u128::MAX
                    .checked_shl(128 - u32::from(self.prefix))
                    .unwrap_or(0);
                u128::from(net) & mask == u128::from(p) & mask
            }
            _ => false,
        }
    }
}

/// Header mode, configured explicitly.
#[derive(Debug, Clone)]
pub struct HeaderMode {
    names: HeaderNames,
    trusted: Option<Vec<PeerNet>>,
}

impl HeaderMode {
    /// The explicit opt-in: this application is reachable **only** through a proxy that fulfils spec §2.1.
    pub fn trust_proxy() -> HeaderMode {
        HeaderMode {
            names: HeaderNames::default(),
            trusted: None,
        }
    }

    /// Renamed headers (TinySesam's `forward_headers`). Each name must be a valid, distinct header name.
    pub fn with_names(mut self, names: HeaderNames) -> Result<HeaderMode, ConfigError> {
        let mut seen: Vec<String> = Vec::new();
        for slot in names.slots() {
            HeaderName::from_bytes(slot.as_bytes())
                .map_err(|_| ConfigError::new(format!("invalid header name {slot:?}")))?;
            let lower = slot.to_ascii_lowercase();
            if seen.contains(&lower) {
                return Err(ConfigError::new(format!("header name {slot:?} used twice")));
            }
            seen.push(lower);
        }
        self.names = names;
        Ok(self)
    }

    /// Accept header mode only from these peers (addresses or CIDR ranges); every other peer is refused with
    /// [`HeaderError::UntrustedPeer`]. Recommended by spec §2.1.
    pub fn with_trusted_peers<I, S>(mut self, peers: I) -> Result<HeaderMode, ConfigError>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut nets = Vec::new();
        for peer in peers {
            let peer = peer.as_ref();
            nets.push(
                PeerNet::parse(peer)
                    .ok_or_else(|| ConfigError::new(format!("invalid peer address {peer:?}")))?,
            );
        }
        if nets.is_empty() {
            return Err(ConfigError::new("the trusted peer list is empty"));
        }
        self.trusted = Some(nets);
        Ok(self)
    }

    /// The identity of a request from its headers. `peer` is the address of the directly connected client; it is
    /// required when a trusted peer list is configured.
    pub fn identify(
        &self,
        headers: &HeaderMap,
        peer: Option<IpAddr>,
    ) -> Result<Identity, HeaderError> {
        self.identify_fields(
            headers.iter().map(|(n, v)| (n.as_str(), v.as_bytes())),
            peer,
        )
    }

    /// Like [`identify`](Self::identify), for any list of raw header fields `(name, value octets)` — a repeated field
    /// occurs more than once.
    pub fn identify_fields<'a, I>(
        &self,
        fields: I,
        peer: Option<IpAddr>,
    ) -> Result<Identity, HeaderError>
    where
        I: IntoIterator<Item = (&'a str, &'a [u8])>,
    {
        if let Some(nets) = &self.trusted {
            match peer {
                Some(p) if nets.iter().any(|n| n.contains(p)) => {}
                _ => return Err(HeaderError::UntrustedPeer),
            }
        }
        let slots = self.names.slots();
        let mut raw: [Option<&[u8]>; 8] = [None; 8];
        for (name, value) in fields {
            if let Some(i) = slots.iter().position(|s| s.eq_ignore_ascii_case(name)) {
                if raw[i].is_some() {
                    // A field that occurs more than once, also under different spellings: never join, never pick.
                    return Err(HeaderError::Header);
                }
                raw[i] = Some(value);
            }
        }
        let mut values: [String; 8] = Default::default();
        for (slot, value) in values.iter_mut().zip(raw) {
            if let Some(octets) = value {
                let text = std::str::from_utf8(octets).map_err(|_| HeaderError::Header)?;
                if has_control(text) {
                    return Err(HeaderError::Header);
                }
                *slot = text.to_owned();
            }
        }
        let [user, name, email, groups, id, auth, kind, permissions] = values;
        if user.is_empty() {
            return Err(HeaderError::Unauthenticated);
        }
        if !id.is_empty() && !id.bytes().all(|b| b.is_ascii_digit()) {
            return Err(HeaderError::Header);
        }
        // Spec v2, rules 6–8: missing, empty, not exactly user/service, or service with a session. A missing value
        // means TinySesam or the proxy template is older than spec v2 — refused, never taken as `user`.
        let account_kind = check_account_kind(&kind, &auth).ok_or(HeaderError::Header)?;
        Ok(
            Identity::new(user, name, email, &groups, id, &auth, account_kind)
                .with_permissions(&permissions),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_ranges() {
        let net = PeerNet::parse("192.0.2.0/24").unwrap();
        assert!(net.contains("192.0.2.77".parse().unwrap()));
        assert!(
            net.contains("::ffff:192.0.2.77".parse().unwrap()),
            "IPv4-mapped"
        );
        assert!(!net.contains("192.0.3.1".parse().unwrap()));
        assert!(
            PeerNet::parse("0.0.0.0/0")
                .unwrap()
                .contains("198.51.100.1".parse().unwrap())
        );
        assert!(
            PeerNet::parse("2001:db8::/32")
                .unwrap()
                .contains("2001:db8::1".parse().unwrap())
        );
        assert!(
            !PeerNet::parse("2001:db8::1")
                .unwrap()
                .contains("2001:db8::2".parse().unwrap())
        );
        for bad in ["192.0.2.0/33", "192.0.2.0/", "x", "192.0.2.0/+1", "::/129"] {
            assert!(PeerNet::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn trusted_peers() {
        let mode = HeaderMode::trust_proxy()
            .with_trusted_peers(["127.0.0.1"])
            .unwrap();
        let fields = [
            ("Remote-User", b"anna".as_slice()),
            ("Remote-Kind", b"user".as_slice()),
        ];
        assert!(
            mode.identify_fields(fields, Some("127.0.0.1".parse().unwrap()))
                .is_ok()
        );
        assert_eq!(
            mode.identify_fields(fields, Some("192.0.2.1".parse().unwrap())),
            Err(HeaderError::UntrustedPeer)
        );
        assert_eq!(
            mode.identify_fields(fields, None),
            Err(HeaderError::UntrustedPeer)
        );
        assert!(
            HeaderMode::trust_proxy()
                .with_trusted_peers(Vec::<&str>::new())
                .is_err()
        );
    }

    #[test]
    fn renamed_headers() {
        let names = HeaderNames {
            user: "X-Gate-User".into(),
            ..HeaderNames::default()
        };
        let mode = HeaderMode::trust_proxy().with_names(names).unwrap();
        assert_eq!(
            mode.identify_fields([("Remote-User", b"anna".as_slice())], None),
            Err(HeaderError::Unauthenticated)
        );
        assert_eq!(
            mode.identify_fields(
                [
                    ("x-gate-user", b"anna".as_slice()),
                    ("Remote-Kind", b"user".as_slice())
                ],
                None
            )
            .unwrap()
            .user,
            "anna"
        );
        let kind = HeaderMode::trust_proxy()
            .with_names(HeaderNames {
                kind: "X-Account-Kind".into(),
                ..HeaderNames::default()
            })
            .unwrap();
        let bot = kind
            .identify_fields(
                [
                    ("Remote-User", b"bot".as_slice()),
                    ("Remote-Auth", b"apikey".as_slice()),
                    ("X-Account-Kind", b"service".as_slice()),
                    ("Remote-Kind", b"user".as_slice()),
                ],
                None,
            )
            .unwrap();
        assert!(bot.is_service() && !bot.is_session());
        assert_eq!(
            kind.identify_fields(
                [
                    ("Remote-User", b"anna".as_slice()),
                    ("Remote-Kind", b"user".as_slice())
                ],
                None
            ),
            Err(HeaderError::Header),
            "the default Remote-Kind no longer counts after renaming"
        );
        let twice = HeaderNames {
            name: "remote-user".into(),
            ..HeaderNames::default()
        };
        assert!(HeaderMode::trust_proxy().with_names(twice).is_err());
        let invalid = HeaderNames {
            name: "Remote Name".into(),
            ..HeaderNames::default()
        };
        assert!(HeaderMode::trust_proxy().with_names(invalid).is_err());
    }

    #[test]
    fn account_kind_rules() {
        let mode = HeaderMode::trust_proxy();
        assert_eq!(
            mode.identify_fields([("Remote-User", b"anna".as_slice())], None),
            Err(HeaderError::Header),
            "missing Remote-Kind"
        );
        assert_eq!(
            mode.identify_fields([("Remote-Groups", b"admin".as_slice())], None),
            Err(HeaderError::Unauthenticated),
            "no user comes first"
        );
        let person = mode
            .identify_fields(
                [
                    ("Remote-User", b"anna".as_slice()),
                    ("Remote-Auth", b"oauth".as_slice()),
                    ("Remote-Kind", b"user".as_slice()),
                ],
                None,
            )
            .unwrap();
        assert!(!person.is_service() && !person.is_session());
    }

    #[test]
    fn never_another_header() {
        let mode = HeaderMode::trust_proxy();
        let fields = [
            ("X-Forwarded-User", b"admin".as_slice()),
            ("X-Remote-User", b"admin".as_slice()),
        ];
        assert_eq!(
            mode.identify_fields(fields, None),
            Err(HeaderError::Unauthenticated)
        );
    }
}
