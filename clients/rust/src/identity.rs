//! The identity both modes produce (spec §1) and the shared rules of spec §3.

/// How the request signed in: the value of `Remote-Auth` or the claim `ts_auth` (spec §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Auth {
    /// A browser session; also every gate token.
    Session,
    /// An OAuth access token.
    OAuth,
    /// An API key; never carries `admin`.
    ApiKey,
    /// An app password (WebDAV, CalDAV, Git).
    AppPassword,
    /// Empty, missing or any other value (reported as the empty string).
    Unspecified,
}

impl Auth {
    /// Reads the value exactly (case-sensitive); anything unknown is [`Auth::Unspecified`].
    pub fn parse(value: &str) -> Auth {
        match value {
            "session" => Auth::Session,
            "oauth" => Auth::OAuth,
            "apikey" => Auth::ApiKey,
            "app-password" => Auth::AppPassword,
            _ => Auth::Unspecified,
        }
    }

    /// The value as the specification spells it; empty for [`Auth::Unspecified`].
    pub fn as_str(&self) -> &'static str {
        match self {
            Auth::Session => "session",
            Auth::OAuth => "oauth",
            Auth::ApiKey => "apikey",
            Auth::AppPassword => "app-password",
            Auth::Unspecified => "",
        }
    }
}

/// The kind of a request: `Session` only when `auth` is exactly `session`, otherwise `Token` (spec §2.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A browser session (complete groups).
    Session,
    /// A token request: its groups are incomplete on purpose (never `admin` for an API key, a subset for OAuth).
    Token,
}

impl Kind {
    /// `session` or `token`.
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Session => "session",
            Kind::Token => "token",
        }
    }
}

/// Who made the request. Names may contain any character except C0 controls and DEL — bidirectional overrides and
/// zero-width characters included: escape them in HTML and isolate bidi text when rendering (spec §3.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    /// The account name (sign-in identifier).
    pub user: String,
    /// The display name, may be empty.
    pub name: String,
    /// The e-mail address, may be empty.
    pub email: String,
    /// The roles, parsed as in spec §3.3. A role missing from a token request does not mean the account lacks it.
    pub groups: Vec<String>,
    /// The account ID (decimal digits); the only value that survives a rename. Key your own records by it.
    pub id: String,
    /// How the request signed in.
    pub auth: Auth,
    /// `Session` or `Token`, derived from `auth`.
    pub kind: Kind,
}

impl Identity {
    pub(crate) fn new(
        user: String,
        name: String,
        email: String,
        groups: &str,
        id: String,
        auth: &str,
    ) -> Identity {
        let auth = Auth::parse(auth);
        let kind = if auth == Auth::Session {
            Kind::Session
        } else {
            Kind::Token
        };
        Identity {
            user,
            name,
            email,
            groups: parse_groups(groups),
            id,
            auth,
            kind,
        }
    }

    /// `role ∈ groups`, compared exactly (no case folding, no normalization). `admin` implies no other role.
    pub fn has_role(&self, role: &str) -> bool {
        self.groups.iter().any(|g| g == role)
    }

    /// True only for a browser session (`auth` exactly `session`).
    pub fn is_session(&self) -> bool {
        self.kind == Kind::Session
    }
}

/// Reads `Remote-Groups` / `ts_groups` (spec §3.3): split at every `,`, remove leading and trailing spaces (U+0020),
/// drop empty and repeated entries (the first occurrence stays, the order stays). There is no escape mechanism.
pub fn parse_groups(text: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for part in text.split(',') {
        let group = part.trim_matches(' ');
        if !group.is_empty() && !out.iter().any(|g| g == group) {
            out.push(group.to_owned());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn groups() {
        assert_eq!(parse_groups("editors, admin"), ["editors", "admin"]);
        assert_eq!(parse_groups(",,editors,,editors"), ["editors"]);
        assert_eq!(parse_groups(""), Vec::<String>::new());
        assert_eq!(parse_groups("a\\,b"), ["a\\", "b"]);
        assert_eq!(parse_groups(" team a "), ["team a"]);
        assert_eq!(
            parse_groups("\u{a0}x"),
            ["\u{a0}x"],
            "only U+0020 is trimmed"
        );
    }

    #[test]
    fn kinds() {
        let id = |auth| {
            Identity::new(
                "u".into(),
                String::new(),
                String::new(),
                "",
                "1".into(),
                auth,
            )
        };
        assert!(id("session").is_session());
        assert!(!id("Session").is_session());
        assert!(!id("").is_session());
        assert_eq!(id("oauth").auth, Auth::OAuth);
        assert_eq!(id("superuser").auth.as_str(), "");
    }
}
