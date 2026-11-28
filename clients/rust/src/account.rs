//! Account overview data (spec §8a, optional): the person's own security state as TinySesam's account page shows it,
//! reduced to what an application may render on its own settings page.
//!
//! Signed out (any answer but a `200` with `signed_in: true`) every group is `None`. Signed in, `account`, `sign_in`,
//! `sessions`, `programs` and `links` are always present; a `None` inside them means "missing or of the wrong type" —
//! for `totp`, `passkeys`, `oauth`, `services`, `app_passwords` "not offered by this installation". Every string is
//! text, never markup; every href passed [`crate::topbar::safe_href`]. Changes happen on TinySesam's account
//! page, which the links lead to. Do not cache the answer across sessions.

pub use crate::action_return::{ActionReturn, ActionReturnRefused, parse_action_return};
use crate::strict::json_value;
use crate::token::MAX_SAFE_INTEGER;
use crate::topbar::safe_href;
use serde::Serialize;
use serde_json::{Map, Value};

/// The normalized account overview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
pub struct Account {
    /// True only for `signed_in: true` (the boolean) in a `200` answer.
    pub signed_in: bool,
    /// The account's names.
    pub account: Option<Names>,
    /// The sign-in methods.
    pub sign_in: Option<SignIn>,
    /// The browser sessions.
    pub sessions: Option<Sessions>,
    /// The connected programs.
    pub programs: Option<Programs>,
    /// The approvals waiting; `None` when approvals are off (or the count is unusable).
    pub approvals: Option<Approvals>,
    /// On an application's host the application and the account's permissions for it (spec §8a); `None` elsewhere.
    pub permissions: Option<Permissions>,
    /// The account page and its sections.
    pub links: Option<Links>,
    /// The own action pages (spec §8c); build the address to send the person to with [`action_url`].
    pub actions: Option<Actions>,
}

/// The application of the host and the account's permissions for it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Permissions {
    /// The application id; `None` when missing or no text.
    pub app: Option<String>,
    /// The permission names; an entry that is no string is dropped.
    pub names: Vec<String>,
}

/// The account's names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Names {
    /// The sign-in name.
    pub username: Option<String>,
    /// The display name.
    pub display_name: Option<String>,
    /// Where the account comes from: `local`, `oidc`, `saml`, `ldap` (two or more = a mixed account; an unknown text
    /// is for the application to ignore); `None` when missing or no list.
    pub source: Option<Vec<String>>,
}

/// The sign-in methods.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SignIn {
    /// `set`, `unset`, `directory`; `None` when passwords are off.
    pub password: Option<String>,
    /// The authenticator app, `None` when not offered.
    pub totp: Option<Totp>,
    /// The passkeys, `None` when not offered.
    pub passkeys: Option<Passkeys>,
    /// Whether a PIN is set; `None` when PINs are off.
    pub pin: Option<bool>,
}

/// The authenticator app.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Totp {
    /// Set up and confirmed.
    pub enabled: Option<bool>,
    /// Recovery codes left.
    pub recovery_left: Option<u64>,
    /// Few recovery codes left.
    pub recovery_low: Option<bool>,
}

/// The passkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Passkeys {
    /// How many.
    pub count: Option<u64>,
    /// Each one (always a list).
    pub items: Vec<Used>,
}

/// A named thing with its creation and last use (Unix seconds; `None` = never used).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Used {
    /// The name (text).
    pub name: Option<String>,
    /// Created.
    pub created_at: Option<u64>,
    /// Last used.
    pub last_used: Option<u64>,
}

/// A live app password.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AppPassword {
    /// The name (text).
    pub name: Option<String>,
    /// Created.
    pub created_at: Option<u64>,
    /// Last used.
    pub last_used: Option<u64>,
    /// Expires; `None` = never.
    pub expires_at: Option<u64>,
}

/// The browser sessions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sessions {
    /// How many.
    pub count: Option<u64>,
    /// Each one (always a list).
    pub items: Vec<Session>,
}

/// One session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    /// Created.
    pub created_at: Option<u64>,
    /// Last seen.
    pub last_seen: Option<u64>,
    /// The sign-in method.
    pub method: Option<String>,
    /// A coarse "browser · system".
    pub device: Option<String>,
    /// True for the session of this request, false for the others, `None` when the answer does not know.
    pub current: Option<bool>,
    /// The session handle: opaque text, never the token.
    pub handle: Option<String>,
    /// The action page that ends exactly this session (`None` for the session of the request):
    /// `action_url(end, return_to, state)` is the address to send the person to.
    pub end: Option<String>,
}

/// The connected programs: `None` means "not offered here", an empty list "offered, none".
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Programs {
    /// Connected programs (OAuth).
    pub oauth: Option<Vec<Used>>,
    /// Paired services.
    pub services: Option<Vec<Used>>,
    /// Live app passwords.
    pub app_passwords: Option<Vec<AppPassword>>,
    /// Active API keys.
    pub api_keys_active: Option<u64>,
}

/// The approvals waiting for this account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Approvals {
    /// How many.
    pub pending: u64,
}

/// The account page and its sections; `None` when not offered (or not a safe link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Links {
    /// The account page.
    pub account: Option<String>,
    /// Its sessions.
    pub sessions: Option<String>,
    /// Its authenticator app.
    pub totp: Option<String>,
    /// Its passkeys.
    pub passkeys: Option<String>,
    /// Its connected programs.
    pub devices: Option<String>,
    /// Its app passwords.
    pub app_passwords: Option<String>,
    /// Its paired services.
    pub services: Option<String>,
    /// The approvals.
    pub approvals: Option<String>,
}

/// The own action pages of spec §8c; `None` when not offered to this account (or not a safe link).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Actions {
    /// Change the sign-in name.
    pub username: Option<String>,
    /// Change the e-mail address.
    pub email: Option<String>,
    /// Set or change the password.
    pub password: Option<String>,
    /// Set or change the PIN.
    pub pin: Option<String>,
    /// The authenticator app.
    pub totp: Option<String>,
    /// New recovery codes.
    pub recovery_codes: Option<String>,
    /// The passkeys.
    pub passkeys: Option<String>,
    /// The API keys.
    pub api_keys: Option<String>,
    /// The app passwords.
    pub app_passwords: Option<String>,
    /// The sessions.
    pub sessions: Option<String>,
    /// The connected programs.
    pub programs: Option<String>,
    /// The paired services.
    pub services: Option<String>,
}

/// Normalizes the body of a `200` answer (strict JSON); anything unreadable is signed out.
pub fn normalize_json(raw: &[u8]) -> Account {
    json_value(raw).map_or_else(Account::default, |v| normalize(&v))
}

static EMPTY: std::sync::LazyLock<Map<String, Value>> = std::sync::LazyLock::new(Map::new);

/// A member that is always an object in the answer: anything else reads as an empty one.
fn group<'a>(data: &'a Map<String, Value>, name: &str) -> &'a Map<String, Value> {
    data.get(name).and_then(Value::as_object).unwrap_or(&EMPTY)
}

fn text(m: &Map<String, Value>, name: &str) -> Option<String> {
    m.get(name).and_then(Value::as_str).map(str::to_owned)
}

/// The string entries of a list, in order; `None` when it is no list.
fn texts(m: &Map<String, Value>, name: &str) -> Option<Vec<String>> {
    m.get(name).and_then(Value::as_array).map(|list| {
        list.iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect()
    })
}

fn flag(m: &Map<String, Value>, name: &str) -> Option<bool> {
    m.get(name).and_then(Value::as_bool)
}

/// A count or a time: a JSON integer from 0 to 2^53 − 1.
fn count(m: &Map<String, Value>, name: &str) -> Option<u64> {
    m.get(name)
        .and_then(Value::as_u64)
        .filter(|n| *n <= MAX_SAFE_INTEGER)
}

/// The object entries of a list; anything that is no list counts as none.
fn objects(v: Option<&Value>) -> impl Iterator<Item = &Map<String, Value>> {
    v.and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
}

fn used(v: Option<&Value>) -> Vec<Used> {
    objects(v)
        .map(|e| Used {
            name: text(e, "name"),
            created_at: count(e, "created_at"),
            last_used: count(e, "last_used"),
        })
        .collect()
}

/// A list that is `None` when the answer has none (not offered).
fn offered_used(v: Option<&Value>) -> Option<Vec<Used>> {
    v.filter(|v| v.is_array()).map(|v| used(Some(v)))
}

/// Normalizes a parsed answer.
pub fn normalize(data: &Value) -> Account {
    let Some(data) = data.as_object() else {
        return Account::default();
    };
    if data.get("signed_in") != Some(&Value::Bool(true)) {
        return Account::default();
    }
    let account = group(data, "account");
    let sign_in = group(data, "sign_in");
    let sessions = group(data, "sessions");
    let programs = group(data, "programs");
    let links = group(data, "links");
    let actions = group(data, "actions");
    let href = |name: &str| safe_href(links.get(name));
    let action = |name: &str| safe_href(actions.get(name));
    Account {
        signed_in: true,
        account: Some(Names {
            username: text(account, "username"),
            display_name: text(account, "display_name"),
            source: texts(account, "source"),
        }),
        sign_in: Some(SignIn {
            password: text(sign_in, "password"),
            totp: sign_in
                .get("totp")
                .and_then(Value::as_object)
                .map(|t| Totp {
                    enabled: flag(t, "enabled"),
                    recovery_left: count(t, "recovery_left"),
                    recovery_low: flag(t, "recovery_low"),
                }),
            passkeys: sign_in
                .get("passkeys")
                .and_then(Value::as_object)
                .map(|p| Passkeys {
                    count: count(p, "count"),
                    items: used(p.get("items")),
                }),
            pin: flag(sign_in, "pin"),
        }),
        sessions: Some(Sessions {
            count: count(sessions, "count"),
            items: objects(sessions.get("items"))
                .map(|e| Session {
                    created_at: count(e, "created_at"),
                    last_seen: count(e, "last_seen"),
                    method: text(e, "method"),
                    device: text(e, "device"),
                    current: flag(e, "current"),
                    handle: text(e, "handle"),
                    end: safe_href(e.get("end")),
                })
                .collect(),
        }),
        programs: Some(Programs {
            oauth: offered_used(programs.get("oauth")),
            services: offered_used(programs.get("services")),
            app_passwords: programs
                .get("app_passwords")
                .filter(|v| v.is_array())
                .map(|v| {
                    objects(Some(v))
                        .map(|e| AppPassword {
                            name: text(e, "name"),
                            created_at: count(e, "created_at"),
                            last_used: count(e, "last_used"),
                            expires_at: count(e, "expires_at"),
                        })
                        .collect()
                }),
            api_keys_active: count(programs, "api_keys_active"),
        }),
        approvals: data
            .get("approvals")
            .and_then(Value::as_object)
            .and_then(|a| count(a, "pending"))
            .map(|pending| Approvals { pending }),
        permissions: data
            .get("permissions")
            .and_then(Value::as_object)
            .map(|p| Permissions {
                app: text(p, "app"),
                names: p
                    .get("names")
                    .and_then(Value::as_array)
                    .map(|list| {
                        list.iter()
                            .filter_map(Value::as_str)
                            .map(str::to_owned)
                            .collect()
                    })
                    .unwrap_or_default(),
            }),
        links: Some(Links {
            account: href("account"),
            sessions: href("sessions"),
            totp: href("totp"),
            passkeys: href("passkeys"),
            devices: href("devices"),
            app_passwords: href("app_passwords"),
            services: href("services"),
            approvals: href("approvals"),
        }),
        actions: Some(Actions {
            username: action("username"),
            email: action("email"),
            password: action("password"),
            pin: action("pin"),
            totp: action("totp"),
            recovery_codes: action("recovery_codes"),
            passkeys: action("passkeys"),
            api_keys: action("api_keys"),
            app_passwords: action("app_passwords"),
            sessions: action("sessions"),
            programs: action("programs"),
            services: action("services"),
        }),
    }
}

/// The longest `state` an action page carries back (spec §8c).
pub const ACTION_STATE_MAX: usize = 128;

fn printable_ascii(text: &str) -> bool {
    text.bytes().all(|b| (0x21..=0x7e).contains(&b))
}

/// Every byte but `A-Z a-z 0-9 - . _ ~` as `%XX` with upper-case hex digits.
fn query_escape(text: &str) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(b));
        } else {
            let _ = write!(out, "%{b:02X}");
        }
    }
    out
}

/// The address of an action page with the way back (spec §8c): `href` is a member of [`Account::actions`] or a
/// session's `end` (ending exactly that session), `return_to` the absolute `http(s)` URL on the application's own host
/// to come back to, `state` an optional value of the application (`None` or empty for none; printable ASCII, at most
/// [`ACTION_STATE_MAX`] characters). Send the person there by navigation; the page leads back with `ts_action`,
/// `ts_result` and `state`. Refuses (a [`crate::ConfigError`]) an href that fails the rule of spec §8 or carries a
/// fragment, a `return_to` that is no absolute `http(s)` URL of printable ASCII, and a `state` outside the rule.
pub fn action_url(
    href: &str,
    return_to: &str,
    state: Option<&str>,
) -> Result<String, crate::ConfigError> {
    if safe_href(Some(&Value::from(href))).is_none() || href.contains('#') {
        return Err(crate::ConfigError::new(
            "action_url: the href is no action page address",
        ));
    }
    let scheme_ok = ["https://", "http://"].iter().any(|prefix| {
        return_to
            .get(..prefix.len())
            .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
    });
    if !scheme_ok || !printable_ascii(return_to) {
        return Err(crate::ConfigError::new(
            "action_url: return_to must be an absolute http(s) URL in printable ASCII",
        ));
    }
    let state = state.unwrap_or_default();
    if state.len() > ACTION_STATE_MAX || !printable_ascii(state) {
        return Err(crate::ConfigError::new(
            "action_url: state is printable ASCII of at most 128 characters",
        ));
    }
    let sep = if href.contains('?') { '&' } else { '?' };
    let mut out = format!("{href}{sep}return={}", query_escape(return_to));
    if !state.is_empty() {
        out.push_str("&state=");
        out.push_str(&query_escape(state));
    }
    Ok(out)
}

/// Only TinySesam's cookies of a `Cookie` header (`tinysesam_*`, `__Host-tinysesam_*`) — what a server-side fetch of
/// the top bar or the account overview may forward. `None` when there are none.
pub fn tinysesam_cookies(cookie_header: &str) -> Option<String> {
    let kept: Vec<&str> = cookie_header
        .split(';')
        .map(str::trim)
        .filter(|part| {
            let name = part.split('=').next().unwrap_or_default().trim();
            name.starts_with("tinysesam_") || name.starts_with("__Host-tinysesam_")
        })
        .collect();
    (!kept.is_empty()).then(|| kept.join("; "))
}

/// Fetches the account overview server-side (feature `jwks`, which brings the HTTP client): a GET to `url`
/// (`https://<auth host>/auth/account.json`, or `/.tinysesam/account.json` on the application's host; plain `http`
/// only to a loopback address) with a deadline of 5 seconds and a body limit of 64 KiB.
#[cfg(feature = "jwks")]
#[derive(Debug, Clone)]
pub struct AccountFetcher(crate::remote::HttpFetcher);

#[cfg(feature = "jwks")]
impl AccountFetcher {
    /// A fetcher for one URL; create it once and share it.
    pub fn new(url: &str) -> Result<AccountFetcher, crate::ConfigError> {
        crate::remote::HttpFetcher::new(url).map(AccountFetcher)
    }

    /// The account overview for a request with this `Cookie` header — forwarding only TinySesam's cookies. Signed out
    /// on any failure: a 401 (no full browser session), a 404, a 429, a timeout, a body above 64 KiB.
    pub async fn fetch(&self, cookie_header: Option<&str>) -> Account {
        let cookies = cookie_header.and_then(tinysesam_cookies);
        match self.0.get(cookies.as_deref()).await {
            crate::FetchOutcome::Response {
                status: 200, body, ..
            } => normalize_json(&body),
            _ => Account::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_tinysesam_cookies_are_forwarded() {
        assert_eq!(
            tinysesam_cookies("other=1; tinysesam_session=abc; __Host-tinysesam_gate=t; x=2")
                .as_deref(),
            Some("tinysesam_session=abc; __Host-tinysesam_gate=t")
        );
        assert_eq!(tinysesam_cookies("app=1"), None);
    }

    #[test]
    fn signed_out_has_nothing() {
        let out = serde_json::to_value(normalize_json(b"{\"signed_in\":\"true\"}")).unwrap();
        assert_eq!(
            out,
            serde_json::json!({"signed_in": false, "account": null, "sign_in": null, "sessions": null,
                               "programs": null, "approvals": null, "permissions": null, "links": null,
                               "actions": null})
        );
    }
}
