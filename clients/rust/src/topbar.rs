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
        return out;
    };
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
