//! Top bar data (spec §8, optional): TinySesam's `topbar.json` reduced to what an application may render.
//!
//! Treat every title and name as text, never as markup, and do not cache the answer across sessions.

use crate::strict::{has_control, json_value};
use serde::Serialize;
use serde_json::Value;

/// A link of the top bar.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Link {
    /// The title (text, not markup).
    pub title: String,
    /// A safe target: an absolute `http`/`https` URL or a path starting with exactly one `/`.
    pub href: String,
}

/// The normalized top bar; signed out on any doubt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TopBar {
    /// The brand (text).
    pub brand: String,
    /// True only for `signed_in: true` (the boolean) with a string `name`.
    pub signed_in: bool,
    /// The display name when signed in.
    pub name: Option<String>,
    /// The links with a safe target.
    pub links: Vec<Link>,
    /// The links of the account menu with a safe target (spec version 2); empty when the answer has none.
    pub menu_links: Vec<Link>,
    /// The account page.
    pub account: Option<String>,
    /// The admin panel.
    pub admin_panel: Option<String>,
    /// The sign-out address.
    pub logout: Option<String>,
    /// The approvals waiting for this account, when TinySesam has approvals switched on and the answer carries a count
    /// of at least 0 and a safe link. Show the number with a word ("Approvals (2)"), never as a coloured dot alone.
    pub approvals: Option<Approvals>,
    /// What the shell draws on the application's host (spec §8d); always present.
    pub frame: Frame,
}

/// The part `frame` of the top bar (spec §8d). Without an app frame: the bar on top, nothing else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Frame {
    /// `"top"` or `"side"`.
    pub layout: String,
    /// The application's name in its app frame (text).
    pub name: Option<String>,
    /// The application's icon in its app frame: an image address (`http(s)`, a path or a `data:image/…`) — draw it as
    /// an image, never as markup.
    pub icon: Option<String>,
    /// Where "‹ name" leads back to — only for a signed-in person.
    pub home: Option<String>,
    /// The frame's links the person may see — only for a signed-in person.
    pub links: Vec<Link>,
}

/// `frame`: layout exactly `side` or else `top`, name text or `None`; home and links only signed in (a safe href, the
/// safe `{title, href}` entries). Anything that is no object reads as no frame.
fn frame(raw: Option<&Value>, signed_in: bool) -> Frame {
    let mut out = Frame {
        layout: "top".to_owned(),
        name: None,
        icon: None,
        home: None,
        links: Vec::new(),
    };
    let Some(raw) = raw.and_then(Value::as_object) else {
        return out;
    };
    if raw.get("layout").and_then(Value::as_str) == Some("side") {
        out.layout = "side".to_owned();
    }
    out.name = raw.get("name").and_then(Value::as_str).map(str::to_owned);
    out.icon = frame_icon(raw.get("icon"));
    if signed_in {
        out.home = safe_href(raw.get("home"));
        out.links = links(raw.get("links"));
    }
    out
}

/// `frame.icon`: an href of spec §8, or a `data:image/` address of the five types `apps[id].icon` takes followed by
/// `;` or `,` and printable ASCII without a quote, `<`, `>` or a backslash; anything else `None`.
fn frame_icon(raw: Option<&Value>) -> Option<String> {
    let icon = raw?.as_str()?;
    if safe_href(raw).is_some() {
        return Some(icon.to_owned());
    }
    let rest = ["png", "gif", "jpeg", "webp", "svg+xml"]
        .iter()
        .find_map(|kind| icon.strip_prefix("data:image/")?.strip_prefix(kind))?;
    let tail = rest.strip_prefix(';').or_else(|| rest.strip_prefix(','))?;
    let ok = !tail.is_empty()
        && tail.bytes().all(|b| {
            (0x21..=0x7e).contains(&b) && !matches!(b, b'"' | b'\'' | b'<' | b'>' | b'\\')
        });
    ok.then(|| icon.to_owned())
}

/// How many approvals wait for this account and where to decide them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Approvals {
    /// How many (a JSON integer from 0 to 2^53 − 1).
    pub pending: u64,
    /// Where to decide them (a safe target).
    pub href: String,
}

/// The safe `{title, href}` entries of a link list; anything that is no list counts as none.
fn links(raw: Option<&Value>) -> Vec<Link> {
    let mut out = Vec::new();
    for link in raw.and_then(Value::as_array).into_iter().flatten() {
        if let (Some(title), Some(href)) = (
            link.get("title").and_then(Value::as_str),
            safe_href(link.get("href")),
        ) {
            out.push(Link {
                title: title.to_owned(),
                href,
            });
        }
    }
    out
}

/// Normalizes the answer from bytes (strict JSON); anything unreadable is signed out.
pub fn normalize_json(raw: &[u8]) -> TopBar {
    json_value(raw).map_or_else(|| normalize(&Value::Null), |v| normalize(&v))
}

/// Normalizes a parsed answer.
pub fn normalize(data: &Value) -> TopBar {
    let mut out = TopBar {
        brand: String::new(),
        signed_in: false,
        name: None,
        links: Vec::new(),
        menu_links: Vec::new(),
        account: None,
        admin_panel: None,
        logout: None,
        approvals: None,
        frame: frame(None, false),
    };
    let Some(data) = data.as_object() else {
        return out;
    };
    if let Some(brand) = data.get("brand").and_then(Value::as_str) {
        out.brand = brand.to_owned();
    }
    let (Some(Value::Bool(true)), Some(Value::String(name))) =
        (data.get("signed_in"), data.get("name"))
    else {
        out.frame = frame(data.get("frame"), false);
        return out;
    };
    out.frame = frame(data.get("frame"), true);
    out.signed_in = true;
    out.name = Some(name.clone());
    out.links = links(data.get("links"));
    out.menu_links = links(data.get("menu_links"));
    let shown = |slot: &str| {
        let entry = data.get(slot)?;
        if entry.get("shown") == Some(&Value::Bool(true)) {
            safe_href(entry.get("href"))
        } else {
            None
        }
    };
    out.account = shown("account");
    out.admin_panel = shown("admin_panel");
    out.logout = data.get("logout").and_then(|l| safe_href(l.get("href")));
    out.approvals = data.get("approvals").and_then(|a| {
        let pending = a
            .get("pending")
            .and_then(Value::as_u64)
            .filter(|n| *n <= crate::token::MAX_SAFE_INTEGER)?;
        Some(Approvals {
            pending,
            href: safe_href(a.get("href"))?,
        })
    });
    out
}

/// The href if it is safe to render: an absolute `http`/`https` URL or a path that starts with exactly one `/`
/// (not `//`, not `/\`), without whitespace or control characters.
pub fn safe_href(href: Option<&Value>) -> Option<String> {
    let href = href?.as_str()?;
    if has_control(href) || href.chars().any(char::is_whitespace) {
        return None;
    }
    let starts = |prefix: &str| {
        href.get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    };
    let ok = starts("https://")
        || starts("http://")
        || (href.starts_with('/') && !href.starts_with("//") && !href.starts_with("/\\"));
    ok.then(|| href.to_owned())
}

/// Fetches the top bar data server-side (feature `jwks`, which brings the HTTP client): a GET to `url`
/// (`https://<auth host>/.tinysesam/topbar.json` on the application's host, or the same path on the auth host; plain
/// `http` only to a loopback address) forwarding only TinySesam's cookies, with a deadline of 5 seconds and a body
/// limit of 64 KiB. Anything but a `200` is "no bar": the signed-out answer.
///
/// The browser way stays the recommendation (spec §8): the page fetches `topbar.json` itself, with its own cookies, and
/// the application's server renders nothing that depends on the person. Use this for a server-side render only, and
/// never cache the answer across sessions.
#[cfg(feature = "jwks")]
#[derive(Debug, Clone)]
pub struct TopBarFetcher(crate::remote::HttpFetcher);

#[cfg(feature = "jwks")]
impl TopBarFetcher {
    /// A fetcher for one URL; create it once and share it.
    pub fn new(url: &str) -> Result<TopBarFetcher, crate::ConfigError> {
        crate::remote::HttpFetcher::new(url).map(TopBarFetcher)
    }

    /// The same fetcher with a shorter deadline (above 0, at most the 5 seconds of the default).
    pub fn with_deadline(
        self,
        deadline: std::time::Duration,
    ) -> Result<TopBarFetcher, crate::ConfigError> {
        self.0.with_deadline(deadline).map(TopBarFetcher)
    }

    /// The top bar for a request with this `Cookie` header — forwarding only TinySesam's cookies. Signed out on any
    /// failure: a status other than 200, a timeout, a body above 64 KiB, a body that is no strict JSON.
    pub async fn fetch(&self, cookie_header: Option<&str>) -> TopBar {
        let cookies = cookie_header.and_then(crate::account::tinysesam_cookies);
        match self.0.get(cookies.as_deref()).await {
            crate::FetchOutcome::Response {
                status: 200, body, ..
            } => normalize_json(&body),
            _ => normalize(&Value::Null),
        }
    }
}
