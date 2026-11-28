//! The way back of an action page (spec §8c): the address the person comes back on carries `ts_action`, `ts_result`
//! and `state`. Re-exported from [`crate::account`].

use serde::Serialize;
use std::fmt;

/// The way back an action page gave: which action and how it ended — a hint for a message, never a proof. The
/// application reads the account overview again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ActionReturn {
    /// One of the 21 action names of the register: the own actions and the administration's (`admin_*`).
    pub action: String,
    /// `done`, `cancelled` or `unavailable`.
    pub result: String,
}

/// Why [`parse_action_return`] refused the way back. Show no message for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActionReturnRefused {
    /// Not a way back an action page gives: an unknown action or result, one of the three names twice or missing, a
    /// value outside printable ASCII, a broken escape, a `state` outside the rule.
    Invalid,
    /// The `state` that came back is not the one the application issued.
    State,
}

impl fmt::Display for ActionReturnRefused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            ActionReturnRefused::Invalid => "action page way back refused: invalid",
            ActionReturnRefused::State => "action page way back refused: state",
        })
    }
}

impl std::error::Error for ActionReturnRefused {}

/// The names an action page hands back in `ts_action`: the own actions and the administration's.
const ACTION_NAMES: [&str; 21] = [
    "username",
    "email",
    "password",
    "pin",
    "totp",
    "recovery_codes",
    "passkeys",
    "api_keys",
    "app_passwords",
    "sessions",
    "session_end",
    "programs",
    "services",
    "admin_totp_reset",
    "admin_lock",
    "admin_unlock",
    "admin_roles",
    "admin_key_revoke",
    "admin_program_revoke",
    "admin_session_end",
    "admin_signin_link",
];
/// The results an action page hands back in `ts_result`.
const ACTION_RESULTS: [&str; 3] = ["done", "cancelled", "unavailable"];

fn printable_ascii(bytes: &[u8]) -> bool {
    bytes.iter().all(|b| (0x21..=0x7e).contains(b))
}

/// A query value as written: printable ASCII only, `+` a space, `%XX` an octet (either case of hex digit).
fn form_decode(raw: &str) -> Option<Vec<u8>> {
    let raw = raw.as_bytes();
    if !printable_ascii(raw) {
        return None;
    }
    let hex = |c: u8| {
        char::from(c)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        match raw[i] {
            b'%' => {
                let high = raw.get(i + 1).copied().and_then(hex)?;
                let low = raw.get(i + 2).copied().and_then(hex)?;
                out.push(high << 4 | low);
                i += 3;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            c => {
                out.push(c);
                i += 1;
            }
        }
    }
    Some(out)
}

/// Equal octet strings, looking at every position of the longer one (the lengths count as a difference).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut diff = u8::from(a.len() != b.len());
    for i in 0..a.len().max(b.len()) {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0
}

/// Reads the way back of an action page (spec §8c) from the address the person came back on — an absolute URL, a path
/// with its query or the query alone with its `?`; the query is what lies between the first `?` and the first `#`.
/// `state` is the value the application issued with [`crate::account::action_url`] (`None` or empty for none).
///
/// `Ok(None)` when the address carries neither `ts_action` nor `ts_result` (an ordinary visit). Refuses with
/// [`ActionReturnRefused::Invalid`] a way back no action page gives and with [`ActionReturnRefused::State`] a `state` that
/// is not the one issued (compared in constant time). Only the names `ts_action`, `ts_result` and `state` exactly as
/// written count; every other parameter is the application's.
pub fn parse_action_return(
    address: &str,
    state: Option<&str>,
) -> Result<Option<ActionReturn>, ActionReturnRefused> {
    let address = address.split('#').next().unwrap_or_default();
    let query = address.split_once('?').map_or("", |(_, q)| q);
    let (mut action, mut result, mut back) = (Vec::new(), Vec::new(), Vec::new());
    for pair in query.split('&') {
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        match name {
            "ts_action" => action.push(value),
            "ts_result" => result.push(value),
            "state" => back.push(value),
            _ => {}
        }
    }
    if action.is_empty() && result.is_empty() {
        return Ok(None);
    }
    let (&[action], &[result]) = (action.as_slice(), result.as_slice()) else {
        return Err(ActionReturnRefused::Invalid);
    };
    let back = match back.as_slice() {
        [] => Vec::new(),
        [one] => form_decode(one).ok_or(ActionReturnRefused::Invalid)?,
        _ => return Err(ActionReturnRefused::Invalid),
    };
    let action = form_decode(action).and_then(|a| String::from_utf8(a).ok());
    let result = form_decode(result).and_then(|r| String::from_utf8(r).ok());
    let (Some(action), Some(result)) = (action, result) else {
        return Err(ActionReturnRefused::Invalid);
    };
    if !ACTION_NAMES.contains(&action.as_str())
        || !ACTION_RESULTS.contains(&result.as_str())
        || back.len() > crate::account::ACTION_STATE_MAX
        || !printable_ascii(&back)
    {
        return Err(ActionReturnRefused::Invalid);
    }
    if !constant_time_eq(&back, state.unwrap_or_default().as_bytes()) {
        return Err(ActionReturnRefused::State);
    }
    Ok(Some(ActionReturn { action, result }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_counts_the_length() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
        assert!(!constant_time_eq(b"", b"\0"));
        assert!(constant_time_eq(b"", b""));
    }
}
