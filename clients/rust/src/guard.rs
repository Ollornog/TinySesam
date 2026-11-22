//! Guards (spec §6): signed in, a role, session only, an account kind. They answer 401 or 403 and never say why.

use crate::identity::{AccountKind, Identity};
use http::StatusCode;

/// What a route requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Requirement<'a> {
    /// Any valid identity.
    SignedIn,
    /// The role is in the groups, compared exactly. `admin` implies no other role.
    Role(&'a str),
    /// A browser session (`auth` exactly `session`): the groups of a token request are incomplete on purpose.
    Session,
    /// The account is of this kind (spec version 2), e.g. `AccountKind::User` for a route only people may use.
    AccountKind(AccountKind),
}

/// The answer of a guard.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Let the request through.
    Allow,
    /// 401: not authenticated (every error class of the specification).
    Unauthorized,
    /// 403: authenticated, but a requirement is not met.
    Forbidden,
}

impl Decision {
    /// The status code to answer with, `None` for [`Decision::Allow`]. The response must not contain the token, the
    /// claims or the error detail.
    pub fn status(&self) -> Option<StatusCode> {
        match self {
            Decision::Allow => None,
            Decision::Unauthorized => Some(StatusCode::UNAUTHORIZED),
            Decision::Forbidden => Some(StatusCode::FORBIDDEN),
        }
    }
}

/// Checks every requirement. `None` (no identity, any error) is [`Decision::Unauthorized`].
pub fn authorize(identity: Option<&Identity>, requirements: &[Requirement<'_>]) -> Decision {
    let Some(identity) = identity else {
        return Decision::Unauthorized;
    };
    let met = requirements.iter().all(|r| match r {
        Requirement::SignedIn => true,
        Requirement::Role(role) => identity.has_role(role),
        Requirement::Session => identity.is_session(),
        Requirement::AccountKind(kind) => identity.account_kind == *kind,
    });
    if met {
        Decision::Allow
    } else {
        Decision::Forbidden
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decisions() {
        let token = Identity::new(
            "anna".into(),
            String::new(),
            String::new(),
            "editors",
            "1".into(),
            "apikey",
            AccountKind::User,
        );
        let session = Identity::new(
            "anna".into(),
            String::new(),
            String::new(),
            "editors",
            "1".into(),
            "session",
            AccountKind::User,
        );
        let service = Identity::new(
            "bot".into(),
            String::new(),
            String::new(),
            "editors",
            "2".into(),
            "apikey",
            AccountKind::Service,
        );
        assert_eq!(
            authorize(Some(&token), &[Requirement::AccountKind(AccountKind::User)]),
            Decision::Allow
        );
        assert_eq!(
            authorize(
                Some(&service),
                &[Requirement::AccountKind(AccountKind::User)]
            ),
            Decision::Forbidden
        );
        assert_eq!(
            authorize(
                Some(&service),
                &[Requirement::AccountKind(AccountKind::Service)]
            ),
            Decision::Allow
        );
        assert_eq!(
            authorize(None, &[Requirement::AccountKind(AccountKind::Service)]),
            Decision::Unauthorized
        );
        assert_eq!(authorize(None, &[]), Decision::Unauthorized);
        assert_eq!(
            authorize(Some(&token), &[Requirement::SignedIn]),
            Decision::Allow
        );
        assert_eq!(
            authorize(Some(&token), &[Requirement::Role("editors")]),
            Decision::Allow
        );
        assert_eq!(
            authorize(Some(&token), &[Requirement::Role("Editors")]),
            Decision::Forbidden
        );
        assert_eq!(
            authorize(Some(&token), &[Requirement::Session]),
            Decision::Forbidden
        );
        assert_eq!(
            authorize(
                Some(&session),
                &[Requirement::Session, Requirement::Role("editors")]
            ),
            Decision::Allow
        );
        assert_eq!(Decision::Forbidden.status(), Some(StatusCode::FORBIDDEN));
        assert_eq!(
            Decision::Unauthorized.status(),
            Some(StatusCode::UNAUTHORIZED)
        );
        assert_eq!(Decision::Allow.status(), None);
    }
}
