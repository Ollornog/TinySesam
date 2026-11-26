"""SQLite store for TinySesam: users, credentials (password/TOTP/WebAuthn/OIDC) and sessions.

Deliberately stdlib `sqlite3` (no ORM): lightweight, no extra dependency.
Thread-safe via a lock + `check_same_thread=False` (FastAPI workers share the instance).

What happens with a read-only, full or locked database and with a jump of the system clock
is described for operators in `docs/OPERATIONS.md` (failure behaviour).
"""
from __future__ import annotations
import contextlib, hashlib, hmac, json, logging, os, re, secrets, sqlite3, stat, threading, time, unicodedata
from typing import Any, Optional


from ._store_schema import SCHEMA  # noqa: E402  (re-exported: `store.SCHEMA`)


#: Characters where IDNA 2003 (stdlib codec) and IDNA 2008 differ: the stdlib codec
#: turns `straße.example` into `strasse.example` — a DIFFERENT domain. A domain containing one of them
#: stays in Unicode form instead of being rewritten incorrectly.
_IDNA_DEVIANTS = frozenset("ßς\u200c\u200d")


def _domain_canonical(domain: str) -> str:
    """Bring a domain into A-label form (`xn--…`) when that is unambiguous (R4-06).

    Otherwise `bücher.example` and `xn--bcher-kva.example` are stored as two different addresses
    in the database although both mean the same mailbox — two accounts, two "taken" checks
    that cannot see each other. What cannot be rewritten safely stays unchanged."""
    if domain.isascii() or any(z in _IDNA_DEVIANTS for z in domain):
        return domain
    try:
        return domain.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return domain


def _email_unicode(email: str) -> str:
    """The address with its domain in Unicode form (`xn--bcher-kva.example` → `bücher.example`).

    Only for looking up existing addresses from before R4-06 that are still stored that way — never
    for storing. What cannot be decoded is returned unchanged."""
    local, at, domain = email.rpartition("@")
    if not at or "xn--" not in domain:
        return email
    try:
        return f"{local}@{domain.encode('ascii').decode('idna').lower()}"
    except UnicodeError:
        return email


def key_kind_of(row) -> str:
    """The kind of a key row: `automation` or `human`.

    Empty or without the column means `automation`. Anything else stays as it is and, because it is not `human`,
    counts as an automation key (fail-closed, R6-6). Here and not on the manager, so that router and admin panel can
    read it without importing the manager (no import cycle)."""
    try:
        return str(row["kind"] or "automation")
    except (IndexError, KeyError, TypeError):
        return "automation"

def norm_email(email) -> Optional[str]:
    """Store an email canonically: NFKC, trimmed, lowercase, domain as A-label. `None` stays `None`.

    NFKC folds compatibility characters (R4-06): a full-width `ａｄｍｉｎ@example.com` is afterwards
    the same as `admin@example.com` — before, they were two identifiers that looked the same
    in the panel."""
    e = unicodedata.normalize("NFKC", str(email or "")).strip().lower()
    if not e:
        return None
    local, at, domain = e.rpartition("@")
    if at and domain:
        e = f"{local}@{_domain_canonical(domain)}"
    return e


def _fonts(text: str) -> set:
    """The scripts of the letters in `text` (first word of the Unicode name: LATIN,
    CYRILLIC, GREEK …). Digits and punctuation do not count."""
    return {unicodedata.name(z, "?").split(" ", 1)[0] for z in text if z.isalpha()}


#: Scripts that belong together in ONE language and may therefore be mixed (attack A6,
#: modelled on UTS #39 "Highly Restrictive"): Japanese writes kanji with hiragana and katakana
#: (`山田たろう`, `例え`), Korean hanja with hangul, Chinese han with bopomofo. Without this
#: exception the script check rejected ordinary Japanese addresses and IDN domains. Latin
#: deliberately belongs to no group — `аdmin` (Cyrillic/Latin) stays rejected.
_FONT_GROUPS = (
    frozenset({"CJK", "IDEOGRAPHIC", "HIRAGANA", "KATAKANA", "KATAKANA-HIRAGANA"}),
    frozenset({"CJK", "IDEOGRAPHIC", "HANGUL"}),
    frozenset({"CJK", "IDEOGRAPHIC", "BOPOMOFO"}),
)


def _a_font(part: str) -> bool:
    """Do the letters come from one script — or from a group that belongs together?"""
    s = _fonts(part)
    return len(s) <= 1 or any(s <= group for group in _FONT_GROUPS)


def name_invalid(name) -> bool:
    """Does a username contain control, format or separator characters (Cc/Cf/Zl/Zp)?

    Such characters separate two identifiers that look the same to a human and to an HTTP header:
    `manager\\x01` is a different name from `manager` for `identifier_taken`, but the forward-auth
    header sanitising strips the control character — the protected app received
    `Remote-User: manager` from a foreign account (attack in the third round). The same rule
    as for addresses (`valid_email`)."""
    return any(unicodedata.category(z) in ("Cc", "Cf", "Zl", "Zp") for z in str(name or ""))


def role_invalid(role) -> bool:
    """Can `role` not travel as one role (T-85)? Not a string, empty, a comma, a C0 control character or DEL, or
    surrounding spaces.

    `Remote-Groups` and the claim `ts_groups` join the roles with `,` and have no escape (`spec/gate-client.md`
    §3.3): a role `staff,admin` would reach the application as the two groups `staff` and `admin`. A control
    character was stripped on the way out (`ad\\x01min` arrived as `admin`), and every gate client trims the spaces
    around an entry (` admin` arrives as `admin`). Such a role is refused where roles are set or configured, and an
    account that still holds one is refused at the forward check rather than passed on changed."""
    if not isinstance(role, str) or not role.strip() or role != role.strip() or "," in role:
        return True
    return any(z < " " or z == "\x7f" for z in role)


def norm_identifier(identifier) -> str:
    """The login identifier as the lockout counter keeps it: NFKC, trimmed, lowercase — and an
    address as canonical as `norm_email` stores it.

    Must fold at least as coarsely as `TinySesam.find_user` (strip, `norm_email`, NOCASE):
    every spelling that hits the same account belongs in the same counting bucket. Otherwise a
    distributed attacker with `' victim'`, `'victim '`, `'\tvictim'` … sets up any number of
    fresh buckets, and the account threshold across all addresses binds nothing. `lower()`
    folds more coarsely than NOCASE (also outside ASCII) — two names that differ only in that
    then share a bucket. That is stricter, never looser.

    Until the integration of T-13 this was only strip + lower. Since R4-06, however, `norm_email` also folds
    NFKC and IDNA, and `find_user` thereby found `ｖｉｃｔｉｍ@example.com`,
    `victim＠example.com` (full-width @) and every mixed form — each with its own bucket, 2^16 for
    this one address alone. Hence NFKC first, THEN look for the `@`: the full-width @ U+FF20
    only becomes one through folding. Counting deliberately happens under the folded INPUT,
    not under the account it hits: this way the lockout behaves the same for existing and
    invented identifiers and does not reveal which address belongs to which username
    (username and address of an account are therefore two buckets; `lift_lockout`
    clears both). Namesakes from existing data (`Émile`/`émile`) share a bucket; none can be
    created anew (`TinySesam.identifier_taken` asks
    `Store.account_by_bucket`), and `delete_attempts_for` leaves a shared bucket in place."""
    k = unicodedata.normalize("NFKC", str(identifier or "")).strip().lower()
    if "@" in k:
        return norm_email(k) or ""
    return k


def _identifier_sql(value) -> Optional[str]:
    """`norm_identifier` for SQLite (`tinysesam_identifier`): NULL stays NULL, and an error becomes NULL
    instead of an exception in the middle of the query."""
    if value is None:
        return None
    try:
        return norm_identifier(value)
    except Exception:
        return None


def valid_email(email) -> bool:
    """Deliberately lenient: exactly one @, something on the left and right, a dot on the right, no spaces.
    Whether the address exists is answered only by the confirmation link (`signup_verify_email`).

    Also rejected is anything built to be confusable (R4-06): invisible characters
    (control and format characters such as zero-width joiner) and a part that mixes scripts —
    `аdmin@example.com` with a Cyrillic `а` looks like the admin mailbox in the panel. An
    address entirely in one script (`müller@…`, `иван@…`) stays allowed, as do the mixtures of one
    language from `_FONT_GROUPS` (`山田たろう@…`)."""
    e = (email or "").strip()
    if not e or " " in e or e.count("@") != 1:
        return False
    if any(unicodedata.category(z) in ("Cc", "Cf") for z in e):
        return False
    local, _, domain = e.partition("@")
    if not (bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")):
        return False
    return all(_a_font(part) for part in [local, *domain.split(".")])


class _Clock:
    """The time source for everything in the database that carries a deadline.

    Sessions, one-time tokens, step-up freshness, lockout windows and flow state compare a
    stored timestamp with "now". With the bare wall clock (`time.time()`), a backwards jump
    revived all of it: an NTP correction, a Raspberry Pi that boots with an old date
    without a backup battery, a VM snapshot — an expired session was valid again, an
    expired magic link could be redeemed, an old step-up was "fresh" again (B6-9).

    That is why this clock never runs backwards: it follows the wall clock forwards, but backwards only
    with the elapsed **monotonic** time (`time.monotonic()` knows no jumps). After a
    jump back by an hour it therefore keeps counting normally instead of standing still for an hour
    — deadlines keep expiring. Across a restart the database itself carries the state:
    `Store()` raises the clock to the most recent timestamp it finds (`at_least()`) —
    including the state that `Store` writes at most once a minute (`clock_state`, on every
    write access and on every write probe of the health check). What expired in the last minute before
    a restart, or during a time in which nothing was written at all, can therefore
    remain valid for up to that interval longer — but not for its full remaining lifetime.

    The price: if the wall clock once jumped wrongly FORWARDS, the clock stays there until the wall clock
    catches up — deadlines are then internally consistent, just dated in the future. That is the
    safe direction, and it is logged as a warning.

    `wall`/`mono` are interchangeable so that a test can set up a jump without bending the clock of
    the whole process. Without them, `time.time`/`time.monotonic` are looked up on EVERY
    call rather than bound at import: an embedding app that patches `time.time` in its tests
    (`mock.patch`, `monkeypatch`, freezegun) thereby sets this clock too.
    It cannot be turned back this way — that is exactly the protection above.

    freezegun additionally replaces `time.monotonic`, namely with the frozen time on the
    epoch scale instead of the uptime. Carried forward, that would be a jump of decades
    (and one back when leaving `freeze_time`). A monotonic step that goes backwards
    or is larger than `MONO_STEP_MAX_SEC` therefore does not count as elapsed time:
    under freezegun the clock follows the frozen wall clock forwards (including `tick()`/`move_to()`);
    after leaving, it continues from the advanced state with the real
    monotonic time — as after `mock.patch`. The lead therefore remains: for the lifetime
    of the process (real time does not catch up, both run at the same speed) and via
    `clock_state` in this database for every later opening, as long as the pause in between is shorter
    than the lead. That is the safe direction; a test that sets the clock far ahead
    therefore uses its own throwaway database. The price of the plausibility limit is paid only by
    a backwards jump of the wall clock that falls into a pause of more than a year without any call:
    then the wall clock that jumped back applies, but never less than the most recently issued
    state. The same rule applies to the monotonic stamps of the `Store` (`_fresh`): a negative
    distance is expired, not fresh.
    """

    #: Lag of the wall clock from which a warning is written (seconds). Below that
    #: it is normal NTP jitter.
    WARN_FROM_SEC = 5

    #: Largest step of monotonic time between two calls that still counts as elapsed time
    #: (seconds). A real step is the pause between two requests; freezegun instead delivers
    #: the frozen time on the epoch scale (≈1.8e9 s) — a jump of decades.
    #: One year separates the two safely without giving up the protection after a long pause.
    MONO_STEP_MAX_SEC = 365 * 86400

    def __init__(self, wall=None, mono=None):
        # Look up on EVERY call, do not bind at construction: whoever patches `time.time`
        # (`mock.patch`, `monkeypatch`, freezegun) sets this clock too (see docstring).
        def _wall():
            return time.time()

        def _mono():
            return time.monotonic()
        self.wall = wall or _wall
        self.mono = mono or _mono
        self._lock = threading.Lock()
        self._state = 0.0          # last issued time (wall-clock scale)
        self._mono = None          # monotonic time at that issue
        self._reported = False     # lag already reported? (one line per jump, not per request)

    def now(self) -> int:
        with self._lock:
            wall, mono = float(self.wall()), float(self.mono())
            step = mono - self._mono if self._mono is not None else 0.0
            if not 0.0 <= step <= self.MONO_STEP_MAX_SEC:
                # No real monotonic clock (backwards, or a jump of decades: freezegun
                # replaces `time.monotonic` with the epoch time). Do not advance — otherwise
                # the clock jumped ahead by ≈57 years and `clock_state` pinned every later opening of the
                # database there. The wall clock forwards still applies, backwards the clock stands —
                # even if the monotonic source itself jumps back (leaving freeze_time).
                step = 0.0
            self._state, self._mono = max(wall, self._state + step), mono
            self._check_backlog(wall)
            return int(self._state)

    def wall_now(self) -> int:
        """The bare wall clock (Unix seconds), WITHOUT the monotonic lead of `now()`.

        For timestamps that a foreign clock checks, not this database: the `iat`/`nbf`/`exp` of
        the gate token are compared by the proxy against ITS system clock. After a backward step
        (typical: the VM boots with a clock about a second ahead, NTP corrects it after the
        service has started) `now()` stays ahead for the whole process lifetime — that is its
        purpose. A token stamped with it carried an `iat` up to that lead in the future, and
        caddy-jwt rejected it (`"iat" not satisfied`) until the second had passed. The proxy
        never sees TinySesam's clock, so the protection of `now()` buys nothing there."""
        return int(float(self.wall()))

    def at_least(self, ts) -> None:
        """Raise the clock to at least `ts` (most recent timestamp of the database when opening)."""
        if not ts:
            return
        with self._lock:
            if float(ts) > self._state:
                self._state, self._mono = float(ts), float(self.mono())
            self._check_backlog(float(self.wall()))

    def _check_backlog(self, wall: float) -> None:
        backlog = self._state - wall
        if backlog > self.WARN_FROM_SEC and not self._reported:
            self._reported = True
            logging.getLogger("tinysesam").warning(
                "The system clock is %d s behind the last time used (backward jump "
                "or wrong date after startup). TinySesam keeps counting monotonically so that "
                "expired sessions and one-time tokens do not become valid again (after a "
                "restart from the last saved state, at most one minute old) — "
                "check the time (NTP).", int(backlog))
        elif backlog <= self.WARN_FROM_SEC:
            self._reported = False


#: One clock per process: several `Store` instances in the same process must not
#: contradict each other, and a backwards jump hits the whole process, not one database.
_CLOCK = _Clock()


def now() -> int:
    """Current time (Unix seconds) that never runs backwards — see `_Clock`."""
    return _CLOCK.now()


def wall_now() -> int:
    """The wall clock (Unix seconds) for timestamps that a foreign clock checks — see `_Clock.wall_now`."""
    return _CLOCK.wall_now()


#: Longest age after which `gc` deletes old login attempts (seconds): ten years like
#: `audit_retention_days`. The limit is not a recommendation for retention — the lockout sees
#: only its window anyway —, but keeps the number within the range SQLite can compute.
ATTEMPT_DEADLINE_MAX_SEC = 3660 * 86400


def attempt_deadline(seconds) -> int:
    """Check `attempts_older_than_sec` of `gc` — BEFORE anything is deleted.

    Without a limit, ±10**20 aborted with `OverflowError` after sessions, flows, tokens and unlocks
    were already gone; a negative value deleted every failed attempt, including those in the running
    lockout window, and thereby lifted every account lockout. 0 stays allowed: the documented way
    to clear all failed attempts. `True` is not an age (it would mean one second). `ValueError` if
    the value does not fit."""
    try:
        if isinstance(seconds, bool):
            raise ValueError
        number = int(seconds)
    except (TypeError, ValueError, OverflowError):
        raise ValueError(f"attempts_older_than_sec={seconds!r} is not a whole number of seconds.") from None
    if not 0 <= number <= ATTEMPT_DEADLINE_MAX_SEC:
        raise ValueError(f"attempts_older_than_sec={number} is outside 0…{ATTEMPT_DEADLINE_MAX_SEC} "
                         "(seconds). 0 clears all failed attempts.")
    return number


def _now() -> int:
    return _CLOCK.now()


def replacement_name(user_id) -> str:
    """Who represents a deleted account in the audit log (H-13): `deleted#<id>`.

    One place for the format — every deletion path writes its closing line under it, even
    one that no longer finds the account (otherwise the clear name would appear there again)."""
    return f"{REPLACEMENT_PREFIX}{int(user_id)}"


#: The name prefix of a deleted account in the audit log (`replacement_name`).
REPLACEMENT_PREFIX = "deleted#"


def read_payload(text) -> Optional[dict]:
    """The payload of a one-time token as a dict — `None` without a payload."""
    if not text:
        return None
    return json.loads(text)


#: Where each method of `Store` that is not in this file lives: part -> method names (T-112). A part is the module
#: `tinysesam/_store_<part>.py`, imported on the first use of one of its methods — an installation that never touches
#: OAuth never loads its queries. `tests/test_store_parts.py` pins that this index and the parts agree.
_PART_METHODS = {
    "apikeys": (
        "add_api_key", "api_key_owner", "app_password", "app_password_add", "app_password_by_digest",
        "app_password_revoke", "app_password_used", "app_passwords", "app_passwords_active",
        "app_passwords_revoke_all", "app_passwords_with_kid", "count_active_api_keys", "get_api_key",
        "get_api_key_by_hash", "list_api_keys", "open_token", "revoke_api_key", "revoke_user_api_keys",
        "source_mail_since", "touch_api_key",
    ),
    "approvals": (
        "add_approval", "approval_rejections", "approval_transition", "count_approvals_open_by",
        "count_approvals_pending", "count_approvals_since", "gc_approvals", "get_approval",
        "list_approvals_pending", "set_approval_fields",
    ),
    "audit": (
        "_earlier_identifiers", "_replace_own_values", "anonymize_audit", "audit_log", "gc_audit",
        "recent_audit",
    ),
    "factors": (
        "_check_v2_only", "add_recovery_codes", "add_webauthn", "confirm_totp", "consume_recovery_code",
        "consume_totp_step", "count_recovery_codes", "delete_pin", "delete_recovery_codes", "delete_totp",
        "delete_webauthn", "extract_secrets", "get_password_hash", "get_pin_hash", "get_totp",
        "get_webauthn_by_credid", "has_confirmed_totp", "has_pin", "list_webauthn", "old_format_count",
        "recovery_codes_before", "set_password_hash", "set_pin_hash", "set_totp", "update_webauthn_signcount",
    ),
    "federation": (
        "clear_sign_in_factors", "confirm_idp", "discard_oidc_session", "federation_since",
        "get_federated_identifier", "get_federated_user", "get_oidc_user", "has_foreign_identity",
        "idp_refused", "is_oidc_account", "link_federated", "link_oidc", "mark_first_login", "mark_login",
        "name_binding_close", "name_binding_unclosed", "oidc_session_handle", "open_name_binding",
        "password_must_change", "rebind", "set_mfa_enroll_until", "set_password_must_change",
        "unlink_federated", "without_binding",
    ),
    "gate": (
        "claim_oidc_session", "confirm_oidc_grant", "create_gate_link", "drop_oidc_grant",
        "drop_oidc_grants_for_user", "gate_is_signed_out", "gate_link_handle", "gate_resume", "gate_sign_out",
        "get_oidc_grant", "get_oidc_id_token", "get_oidc_session", "get_oidc_sessions", "list_oidc_grants",
        "move_oidc_session", "oidc_refresh_plain", "oidc_session_checked", "put_oidc_grant", "remove_gate_link",
        "set_oidc_id_token", "set_oidc_session",
    ),
    "keys": (
        "_key_insert", "_open", "_seal", "ciphertext_counts", "key_ring_create", "key_ring_retire",
        "key_ring_rotate", "key_ring_rows", "reencrypt",
    ),
    "oauth": (
        "_oauth_insert_key", "_oauth_insert_tokens", "gc_oauth", "oauth_add_client",
        "oauth_add_client_key", "oauth_add_code", "oauth_add_request", "oauth_arm_consent_pairing",
        "oauth_armed_consent_pairing", "oauth_client", "oauth_client_keys", "oauth_code", "oauth_consume_code",
        "oauth_count_idle_clients", "oauth_create_grant", "oauth_drop_successor", "oauth_evict_idle_client",
        "oauth_grant", "oauth_grants", "oauth_live_tokens_before", "oauth_mark_code_reused",
        "oauth_note_assertion", "oauth_pair_service", "oauth_release_consent_pairing",
        "oauth_replace_consent_pairing", "oauth_request", "oauth_revoke_grant", "oauth_revoke_service",
        "oauth_rotate", "oauth_service", "oauth_service_ids", "oauth_service_token", "oauth_services",
        "oauth_take_request", "oauth_token", "oauth_touch_client", "oauth_touch_grant",
        "oauth_use_consent_pairing", "oauth_user_grant_ids", "open_oauth_successor", "revoke_user_access",
        "seal_oauth_successor",
    ),
    "roles": (
        "_catalog_hook", "_role_usage_locked", "add_catalog_roles", "catalog_roles",
        "delete_catalog_roles_if_unused", "role_usage", "roles_in_use",
    ),
    "sessions": (
        "backdate_confirmation", "create_session",
        "delete_session", "delete_session_by_handle", "delete_user_sessions", "delete_user_sessions_except",
        "gc_sessions", "get_session", "get_session_by_handle", "list_sessions", "rewrite_api_key_digest",
        "rotate_session", "session_hash", "sessions_live_before", "set_session_end_others",
        "set_session_factors", "set_session_mfa", "set_session_stay", "token_digest", "token_digests",
        "tokens_live_before",
    ),
    "throttle": (
        "_fails_query", "_series_confirmed", "_series_minus", "_series_plus", "_series_sum", "cancel_attempt",
        "clear_fails", "count_fails", "delete_attempts_for", "delete_failure_series", "failure_series",
        "failure_series_confirmed", "failure_series_without", "finish_attempt", "gc_attempts",
        "gc_failure_series", "increase_failure_series", "lower_failure_series", "record_attempt",
        "reserve_attempt",
    ),
    "tokens": (
        "add_magic_token", "add_resource_unlock", "approve_qr_token", "delete_resource_secret",
        "delete_resource_unlocks", "expire_magic_token", "gc_magic_tokens", "gc_resource_unlocks",
        "gc_unconfirmed_accounts", "get_magic_token", "get_resource_secret", "is_resource_unlocked",
        "list_resource_secrets", "move_resource_unlocks", "revoke_user_magic_tokens", "set_resource_secret",
        "unconfirmed_accounts", "use_magic_token",
    ),
    "users": (
        "_remember_directory_name", "_rewrite", "_set_identifier", "account_by_bucket",
        "account_footprint", "account_with_binding_name", "account_with_directory_name", "address_proven",
        "address_switch", "adopt_account", "bucket_collisions", "bucket_of_another", "cancel_deletion",
        "confirmation_enable", "count_identifiers", "count_managed", "count_up", "counter", "create_user",
        "delete_user", "deletion_guard", "email_taken", "gc_provisioning", "get_roles", "get_user",
        "get_user_by_email", "get_user_by_name", "identifier_collisions", "identifier_limits", "list_managed",
        "list_users", "lock_by_app", "managed_counts", "merge_roles", "owner_count", "release_account",
        "release_directory_name", "remove_account", "schedule_deletion", "set_admin", "set_admin_from_idp",
        "set_binding_name", "set_disabled", "set_display_name", "set_email", "set_email_verified", "set_owner",
        "set_roles", "set_username", "setup_limit", "unlock_by_app", "user_count",
    ),
}
_PARTS = {name: part for part, names in _PART_METHODS.items() for name in names}


class _StoreParts(type):
    """Loads a part on the first access to one of its methods, on the class (`Store.token_digest`) or on a store, and
    fixes the method on the class — from then on an ordinary attribute, without this hook (T-112)."""

    def __getattr__(cls, name):
        part = _PARTS.get(name)
        if part is None:
            raise AttributeError(f"type object {cls.__name__!r} has no attribute {name!r}")
        import importlib
        setattr(cls, name, getattr(importlib.import_module(f"{__package__}._store_{part}"), name))
        return getattr(cls, name)


class Store(metaclass=_StoreParts):
    #: Permissions for a NEWLY created database. It holds password hashes, TOTP secrets
    #: and email addresses; on a shared host anyone could read it up to 0.18.0 (0644,
    #: depending on umask). Nothing is changed on an existing file — whoever deliberately
    #: released a group should keep that —, but there is a warning.
    FILE_PERMISSIONS = 0o600

    @staticmethod
    def _service_dict(r) -> dict:
        d = dict(r)
        d["roles"] = json.loads(d["roles"]) if d.get("roles") else None
        d["resources"] = json.loads(d.get("resources") or "[]")
        return d

    @staticmethod
    def _handle(value) -> str:
        """A handle is a sha256 hex digest. Whoever passes in a plaintext token by mistake
        gets an error — otherwise the UPDATE would hit nothing and the session
        would silently keep its old state (a second factor that does not arrive is noticed by nobody
        until it is missing)."""
        h = str(value or "")
        if len(h) != 64 or any(c not in "0123456789abcdef" for c in h):
            raise ValueError("Session handle expected (token_hash from the session row), "
                             f"not a plaintext token: {h[:12]!r}…")
        return h

    @staticmethod
    def _token_digest(pepper: bytes, kind: str, raw: str) -> str:
        """HMAC-SHA-256 with the pepper over label, kind and the token itself (the tokens are random, no password)."""
        return hmac.new(pepper, b"tinysesam/token/v1\x00" + kind.encode("ascii") + b"\x00" + (raw or "").encode(),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _session_digest(pepper: bytes, plain_sha256: str) -> str:
        """HMAC with the pepper over the sha256 of the token (T-71; the label names the format)."""
        return hmac.new(pepper, b"tinysesam/session-handle/v1\x00" + plain_sha256.encode("ascii"),
                        hashlib.sha256).hexdigest()

    @staticmethod
    def _slot(line, name):
        """A column of the account row — None if it does not (yet) exist (dummy, old dict)."""
        try:
            return line[name]
        except (IndexError, KeyError):
            return None

    def __getattr__(self, name):
        """A method of a store part (`_PARTS`): the class loads it, the store gets it bound (T-112)."""
        if name not in _PARTS:
            raise AttributeError(f"{type(self).__name__!r} object has no attribute {name!r}")
        getattr(type(self), name)
        return object.__getattribute__(self, name)

    def __init__(self, db_path: str):
        new = db_path not in (":memory:", "") and not os.path.exists(db_path)
        if new:
            # The file is created directly with narrow permissions. A chmod AFTER connecting would have
            # a window in which it stands open — and that is exactly when
            # SQLite writes the schema into it.
            try:
                os.close(os.open(db_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.FILE_PERMISSIONS))
            except OSError:
                new = False                      # directory missing or similar — sqlite3 reports it right away
        self.db = sqlite3.connect(db_path, check_same_thread=False,
                                  timeout=self.BUSY_TIMEOUT_MS / 1000)
        self.db.row_factory = sqlite3.Row
        # Explicitly, not as the silent default of Python's `sqlite3` (5 s): the value decides
        # whether a second writer — another worker, `tinysesam` on the command line, a
        # WAL checkpoint, a running backup — waits or aborts a login with "database is locked"
        # as a 500 (B6-11). The PRAGMA repeats the value so that it can be read off
        # the connection itself, no matter how it was opened.
        self.db.execute(f"PRAGMA busy_timeout={int(self.BUSY_TIMEOUT_MS)}")
        # Before anything writes (the journal mode is written into the file): a database below the baseline is refused
        # untouched, so that the release with the migrations still finds it as it was.
        self._refuse_below_baseline(db_path)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA foreign_keys=ON")
        # Deleted data is overwritten, not just freed: a replaced plaintext secret
        # (before encryption, H-14/H-15) or a deleted account would otherwise remain readable in free
        # pages of the file — and thereby in every backup — depending on the SQLite build.
        self.db.execute("PRAGMA secure_delete=ON")
        # The counting bucket as an SQL function — ONLY for queries of this connection (`anonymize_audit`),
        # never in schema, trigger or index: there it would break every writer without it (`_trigger_sql`).
        self.db.create_function("tinysesam_identifier", 1, _identifier_sql, deterministic=True)
        self._lock = threading.Lock()
        self._clock_secured: Optional[float] = None   # monotonic time of the last saved clock state
        self._written: Optional[float] = None     # monotonic time of the last successful commit
        self._open_schema()
        self._check_file_permissions(db_path, new)
        _CLOCK.at_least(self._youngest_timestamp())

    def close(self) -> None:
        """Close the connection under the store lock (T-67) — idempotent.

        `self.db.close()` from outside does not wait for a thread that is inside SQLite right now; `sqlite3` then
        frees the connection under it (segmentation fault, B-13). The store's reads and writes hold `_lock`, so
        closing under it waits for a running statement. Afterwards every access raises
        `sqlite3.ProgrammingError`. `TinySesam.close()` calls this after the background jobs are done."""
        with self._lock:
            self.db.close()

    #: How long a request waits for a locked database before giving up (ms).
    #: Twice Python's default: a checkpoint or a backup on slow
    #: storage (SD card, network drive) takes longer than 5 s, and an aborted login
    #: is more expensive than a slow one. No longer — the worker thread is stuck for that long.
    BUSY_TIMEOUT_MS = 10_000

    def _youngest_timestamp(self) -> int:
        """The most recent event timestamp of the database — the clock state across a restart.

        Only points in time at which something HAPPENED (created, logged), no deadlines: an
        `expires_at` is in the future by design and would set the clock ahead."""
        queries = ("SELECT MAX(created_at) AS t FROM session",
                    "SELECT MAX(created_at) AS t FROM magic_token",
                    "SELECT ts AS t FROM audit ORDER BY id DESC LIMIT 1",
                    "SELECT ts AS t FROM login_attempt ORDER BY id DESC LIMIT 1",
                    f"SELECT CAST(value AS INTEGER) AS t FROM setting WHERE key='{self.CLOCK_STATE}'")
        values = []
        for sql in queries:
            try:
                r = self._one(sql)
            except sqlite3.Error:
                continue
            if r and r["t"]:
                values.append(int(r["t"]))
        return max(values, default=0)

    def _check_file_permissions(self, db_path: str, new: bool):
        """WAL and SHM carry the same data as the database — they get the same permissions.

        The main file itself is only assessed on an existing installation, not
        rewritten: a deliberate group release is a decision of the operator, not a
        gap. It still does not stay silent."""
        if db_path in (":memory:", ""):
            return
        try:
            mode = stat.S_IMODE(os.stat(db_path).st_mode)
        except OSError:
            return
        for attachment in ("-wal", "-shm"):
            path = db_path + attachment
            try:
                if os.path.exists(path) and stat.S_IMODE(os.stat(path).st_mode) != mode:
                    os.chmod(path, mode)
            except OSError:
                pass                              # file system without permissions (Windows, some mounts)
        if not new and mode & 0o077:
            logging.getLogger("tinysesam").warning(
                "The database %s is readable by other accounts (%o). It contains password hashes "
                "and TOTP secrets. Tighten it: chmod 600 %s", db_path, mode, db_path)

    #: State of the schema (`PRAGMA user_version`). Raised by one with every change to SCHEMA after the baseline,
    #: together with ONE migration step from the state before (`_open_schema`) and a test that opens a baseline
    #: database (AGENTS.md, pitfalls).
    #:
    #: 26 — the baseline (T-111): the schema 0.30.0 reaches, created in one step by `SCHEMA`, `INDEXES` and
    #:      `_trigger_sql`. The history up to 26 lives in the CHANGELOG of 0.30.0 and before.
    SCHEMA_VERSION = 26

    #: The oldest schema this version opens: the baseline. A database below it was written by a version before
    #: `LAST_MIGRATING_RELEASE` (or never reached it) and is refused at start (`ConfigError`).
    BASELINE_SCHEMA = 26
    #: The last release that migrates older databases to the baseline — the first step of the two-step update
    #: (docs/OPERATIONS.md "Updating").
    LAST_MIGRATING_RELEASE = "0.30.0"

    #: Indexes outside the table definitions (the unique address index `ux_users_email` is created separately: data
    #: with duplicate addresses must not stop the start, see `_open_schema`).
    INDEXES = (
        # Every lookup of an identifier goes through an index, none through the whole table (R4-03): with a scan, the
        # runtime of a registration depended on whether the address is found — an oracle for taken addresses.
        # `get_user_by_name`/`get_user_by_email` compare with NOCASE, which the UNIQUE index on `username` (BINARY)
        # and `ux_users_email` (`lower(email)`) do not serve. The name in the directory (G5) counts in the identifier
        # space — the identifier triggers ask for it on every creation and every rename.
        "CREATE INDEX IF NOT EXISTS ix_users_folded_name ON users(folded_name)",
        "CREATE INDEX IF NOT EXISTS ix_users_folded_mail ON users(folded_mail)",
        "CREATE INDEX IF NOT EXISTS ix_fed_directory_name_folded ON federated_identity(directory_name_folded)",
        "CREATE INDEX IF NOT EXISTS ix_users_name_nocase ON users(username COLLATE NOCASE)",
        "CREATE INDEX IF NOT EXISTS ix_users_email_nocase ON users(email COLLATE NOCASE)",
        # The accounts of an application (account API: list, quota).
        "CREATE INDEX IF NOT EXISTS ix_users_managed_by ON users(managed_by)",
    )

    def _refuse_below_baseline(self, path: str) -> None:
        """A file with TinySesam tables below `BASELINE_SCHEMA` (or without a stamp at all, before 0.18) is refused with
        `ConfigError` — before anything is written, no partial upgrade. The way is the two-step update. Tables of
        another program in the same file (none of TinySesam's names) do not count."""
        present = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
        if present >= self.BASELINE_SCHEMA:
            return
        tables = {r[0] for r in self.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if tables & set(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA)):
            self.db.close()
            from .errors import ConfigError
            raise ConfigError(
                f"The database {path} carries schema {present}; this TinySesam version opens schema "
                f"{self.BASELINE_SCHEMA} and newer only. Update in two steps: first to TinySesam "
                f"{self.LAST_MIGRATING_RELEASE} (start it once, it migrates the database, then run `tinysesam keys "
                f"reencrypt --db {path}`), then to this version. Nothing was written. docs/OPERATIONS.md \"Updating\".")

    def _open_schema(self) -> None:
        """Create what a new database lacks — in one transaction (`_writing`); the version check ran before
        (`_refuse_below_baseline`).

        * A new file gets `SCHEMA`, `INDEXES`, the triggers and the stamp in one transaction.
        * A file at the baseline: `CREATE … IF NOT EXISTS` and `_set_trigger` find everything in place and write
          nothing (also on a read-only file).
        * A file from a newer version: a loud warning, as before — this version does not know all of its tables."""
        log = logging.getLogger("tinysesam")
        present = int(self.db.execute("PRAGMA user_version").fetchone()[0] or 0)
        with self._writing():
            # One transaction for everything: `executescript` alone commits every statement on its own, and an abort
            # in the middle of a new database left half a schema with the stamp missing.
            self.db.executescript("BEGIN IMMEDIATE;" + SCHEMA)
            for sql in self.INDEXES:
                self.db.execute(sql)
            # Email unique (login identifier) — partial, so that accounts without an email stay allowed. Data with
            # duplicates (written around TinySesam): the index cannot be created → say so loudly, do not crash.
            try:
                self.db.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_users_email "
                                "ON users(lower(email)) WHERE email IS NOT NULL AND email <> ''")
            except sqlite3.IntegrityError:
                log.warning("users.email contains duplicates — uniqueness index not created. "
                            "Clean up duplicate addresses, otherwise login by e-mail is ambiguous.")
            # The triggers over the buckets (recompute and identifier space, see `_trigger_sql`). A file on which they
            # cannot be created (read-only) must not prevent the start: no new account is created there anyway, and
            # the pre-check (`identifier_taken`) remains. It is still reported.
            try:
                self._set_trigger()
            except sqlite3.OperationalError as e:
                log.warning("Triggers over username and address not created (%s): the database only enforces the "
                            "shared identifier space after a start with write access.", e)
            self._catch_up_owner()
            if present > self.SCHEMA_VERSION:
                log.warning("The database carries schema version %d, this TinySesam version only knows %d. It comes "
                            "from a newer version — writing with this one can leave data incomplete. Install the "
                            "matching version or restore the file from a backup.", present, self.SCHEMA_VERSION)
            elif present != self.SCHEMA_VERSION:
                self.db.execute(f"PRAGMA user_version = {self.SCHEMA_VERSION}")
            self.db.commit()
        # Counting buckets of rows another writer left without one (raw SQL, the sqlite3 tool; see `folded_name`).
        # Read-only: `account_by_bucket` checks such rows itself (`_backfill_pots`), so this must not stop the start.
        left = self._backfill_pots()
        if left:
            log.warning("Counting buckets of %d account(s) not filled in: the database is not writable. The bucket "
                        "check still sees them, only more slowly.", len(left))

    #: Message of the identifier triggers (`sqlite3.IntegrityError`): name or address falls into the
    #: counting bucket of ANOTHER account. Callers recognise the case by `IntegrityError`, not by the text.
    IDENTIFIER_GRANT = "tinysesam: identifier taken"

    #: The watermarks of an identifier (G2) as an SQL expression: the highest id that exists NOW.
    #: Everything created afterwards has a larger one (`AUTOINCREMENT` never issues an id twice).
    #: Only built-in functions — same reason as for the triggers.
    WL_ATTEMPT = "(SELECT COALESCE(MAX(id), 0) FROM login_attempt)"
    WL_AUDIT = "(SELECT COALESCE(MAX(id), 0) FROM audit)"

    @classmethod
    def _trigger_sql(cls) -> list:
        """The triggers on `users` as `(name, CREATE statement)`. Only built-in SQL functions:
        the sqlite3 tool and older versions must still be able to write (a
        Python function in the trigger or in the index expression would break every writer without it with
        "no such function").

        **Recompute** (`trg_users_folded_name`/`_mail`, schema 10): another writer changes
        name or address without carrying the bucket along (an older version after a rollback,
        the manual rename that the collision guard recommends at start): then the bucket is
        stale — and NULL means "recompute". Only if the value REALLY changes: whoever sets
        the same address again keeps their bucket (until 2026-09-26 it stood at NULL afterwards until the
        next backfill, and the identifier triggers did not see the account for that long).
        The same trigger raises the watermarks of the identifier (`name_attempt_from` … , G2) to the
        current state: a foreign writer has assigned a new identifier, and what stood before under
        it did not belong to this account. That is the stricter direction — also for a
        rename that only changes the spelling. The own writers never fire it
        (`_set_identifier`); otherwise even `B1` → `b1` would shift the limit.

        **Change with bucket** (`trg_users_change_name`/`_mail`, audit round 2026-09-27): a foreign
        writer that carries the bucket ITSELF (`store.set_email` from 0.20.1 sets address and
        `folded_mail` in one statement) does not fire the recompute trigger — the bucket does
        change. Until then the watermark stayed at the state of the OLD identifier, and the first
        full sign-in cleared the failed attempts that a stranger had made under the new one before the change,
        also from the throttling of his IP. This trigger raises them when, in the same
        statement, the value AND the bucket change (to a bucket, not to NULL). The backfill
        (`_write_pots`: only the bucket) does not fire it, nor does `B1` → `b1` in `_set_identifier`
        (there the bucket is at NULL in between); on a real change in
        `_set_identifier` it sets the same state that the statement has already written.

        **Identifier space** (`trg_users_identifier_insert`/`_update`, G12c): username and address
        are ONE space (`find_user` searches both), and the counting bucket folds more coarsely than NOCASE
        (`Alice`/`alice`, `Émile`/`émile`, full-width, Unicode and A-label domain). Until then the database
        knew only `UNIQUE(username)` (BINARY) and `ux_users_email` — check
        (`identifier_taken`) and write were separate, and two simultaneous registrations
        of the same identifier (one as name, one as address) both got through. Now the
        database rejects a NEWLY assigned bucket that is already the name or address of another account
        — in the same statement as the write, under SQLite's single writer.
        Why each part:

        * `UPDATE OF username, email`, not `OF topf_*`: the backfill (`_write_pots`)
          sets only buckets and therefore does not check. Existing data with a collision does not break the start.
        * `NEW IS NOT OLD`: only a newly assigned bucket is checked. Setting one's own
          address again and a raw UPDATE (bucket stays, the trigger above then sets it
          to NULL) go through — a collision in existing data is reported, not prevented.
        * `id IS NOT NEW.id` (UPDATE only): the same row may carry name = address
          (email mode). On INSERT the row is not yet in the table.
        * Rows without a bucket (NULL: a foreign writer, not yet backfilled) count only from
          the backfill — which `identifier_taken` triggers before every creation.
        * **The name in the directory of ANOTHER account** (`federated_identity.directory_name_folded`, G5)
          counts (audit round 2026-09-27). Under one identifier the login route checks two
          secrets — the local password of the account and the LDAP password of the entry. If
          a local account took on the directory name of another person (self-service,
          registration), each of its sign-ins cleared the counters under which the other's
          LDAP password was being guessed. On UPDATE only foreign bindings (`user_id IS NOT NEW.id`):
          whoever returns to their own directory name may do so.

        The lookup runs over `ix_users_folded_name`/`ix_users_folded_mail`/`ix_fed_directory_name_folded`, no
        scan: the work does not depend on the number of accounts (step counting in
        tests/test_identifier_space.py and tests/test_audit_round2.py)."""
        def new(column, old, id_from):
            other = "id IS NOT NEW.id AND " if id_from else ""
            foreign = "user_id IS NOT NEW.id AND " if id_from else ""
            return (f"(NEW.{column} IS NOT {old} AND NEW.{column} <> '' AND (EXISTS (SELECT 1 FROM users "
                    f"WHERE {other}(folded_name = NEW.{column} OR folded_mail = NEW.{column})) "
                    f"OR EXISTS (SELECT 1 FROM federated_identity WHERE {foreign}directory_name_folded = NEW.{column})))")
        reject = f"BEGIN SELECT RAISE(ABORT, '{cls.IDENTIFIER_GRANT}'); END"
        kinds = (("username", "folded_name", "name"), ("email", "folded_mail", "mail"))
        sql = [(f"trg_users_{bucket}",
                f"CREATE TRIGGER IF NOT EXISTS trg_users_{bucket} AFTER UPDATE OF {column} ON users "
                f"WHEN NEW.{bucket} IS OLD.{bucket} AND NEW.{column} IS NOT OLD.{column} "
                f"BEGIN UPDATE users SET {bucket} = NULL, {kind}_attempt_from = {cls.WL_ATTEMPT}, "
                f"{kind}_audit_from = {cls.WL_AUDIT} WHERE id = NEW.id; END")
               for column, bucket, kind in kinds]
        sql += [(f"trg_users_change_{kind}",
                 f"CREATE TRIGGER IF NOT EXISTS trg_users_change_{kind} AFTER UPDATE OF {bucket} ON users "
                 f"WHEN NEW.{bucket} IS NOT NULL AND NEW.{bucket} IS NOT OLD.{bucket} "
                 f"AND NEW.{column} IS NOT OLD.{column} "
                 f"BEGIN UPDATE users SET {kind}_attempt_from = {cls.WL_ATTEMPT}, "
                 f"{kind}_audit_from = {cls.WL_AUDIT} WHERE id = NEW.id; END")
                for column, bucket, kind in kinds]
        sql.append(("trg_users_identifier_insert",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_identifier_insert BEFORE INSERT ON users "
                    f"WHEN {new('folded_name', 'NULL', False)} OR {new('folded_mail', 'NULL', False)} "
                    + reject))
        sql.append(("trg_users_identifier_update",
                    "CREATE TRIGGER IF NOT EXISTS trg_users_identifier_update BEFORE UPDATE OF username, email "
                    f"ON users WHEN {new('folded_name', 'OLD.folded_name', True)} "
                    f"OR {new('folded_mail', 'OLD.folded_mail', True)} " + reject))
        return sql

    def _set_trigger(self) -> None:
        """Create the triggers from `_trigger_sql` — or replace them if another version created them
        differently (without commit, under `_lock`, part of `_open_schema`).

        `CREATE TRIGGER IF NOT EXISTS` alone would leave an older definition forever
        as it was back then. The comparison is made with the text in `sqlite_master` (SQLite stores it
        without `IF NOT EXISTS`; whitespace does not count). If it matches, nothing is written — not even
        on a read-only file."""
        for name, sql in self._trigger_sql():
            should = " ".join(sql.replace(" IF NOT EXISTS", "", 1).split())
            stands = self.db.execute("SELECT sql FROM sqlite_master WHERE type='trigger' AND name=?",
                                    (name,)).fetchone()
            if stands is not None and " ".join(str(stands[0] or "").split()) == should:
                continue
            if stands is not None:
                self.db.execute(f"DROP TRIGGER IF EXISTS {name}")
            self.db.execute(sql)

    def _catch_up_owner(self) -> None:
        """If there are admins but no owner, the oldest admin becomes owner at start — one that someone set by hand
        (`is_admin=1`), active and not a service account. Admins without an owner come from own code that creates
        them with `create_user(is_admin=True)` instead of a bootstrap path, or from raw SQL. Once, with a row in the
        audit log; part of `_open_schema` (under the write lock, directly on the connection). Without an admin it
        stays with the first-admin path, which also assigns the first owner."""
        if self.db.execute("SELECT 1 FROM users WHERE is_owner=1 LIMIT 1").fetchone():
            return
        # ONLY an active, manually set admin (`is_admin=1`). A flag granted by the identity provider
        # (2) would otherwise make him a permanent owner at the next start — and thereby
        # an admin that no provider revokes anymore (attack on the second round, finding 1).
        # A locked admin would be an owner who cannot sign in (finding 2).
        u = self.db.execute(
            "SELECT id, username FROM users WHERE is_admin = 1 AND is_service = 0 AND disabled = 0 "
            "ORDER BY id LIMIT 1").fetchone()
        if u is None:
            if self.db.execute("SELECT 1 FROM users WHERE is_admin <> 0 LIMIT 1").fetchone():
                logging.getLogger("tinysesam").warning(
                    "No owner: there are admins, but none active and set by hand (only ones "
                    "granted by the identity provider, or locked). Designate an owner: "
                    "`tinysesam owner --db <file> <user>`.")
            return
        self.db.execute("UPDATE users SET is_owner=1, is_admin=1 WHERE id=?", (u["id"],))
        self.db.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
                        (_now(), "owner_grant", u["username"], None, "source=existing oldest_admin"))
        logging.getLogger("tinysesam").warning(
            "Owner model: %s is now owner (oldest admin). Further owners are granted by an owner in the "
            "admin panel.", u["username"])

    def _write_pots(self, lines) -> None:
        """Compute `folded_name`/`folded_mail` for these account rows (without commit, under `_lock`).

        Written only if name and address are still the ones read: if another
        writer changes them in between, its trigger sets the bucket to NULL, and the next call
        recomputes — instead of the bucket of the old name remaining here."""
        self.db.executemany(
            "UPDATE users SET folded_name=?, folded_mail=? WHERE id=? AND username IS ? AND email IS ?",
            [(norm_identifier(z["username"]), norm_identifier(z["email"]), z["id"], z["username"], z["email"])
             for z in lines])

    def _backfill_pots(self) -> list:
        """Backfill missing counting buckets — the rows of another writer (see `folded_name`).

        Returns the rows that could NOT be written (database read-only, locked);
        the caller checks those itself. Normally that is none, and it costs one query
        over the index — independent of which identifier is being looked up."""
        unclosed = self._all("SELECT * FROM users WHERE folded_name IS NULL OR folded_mail IS NULL")
        if not unclosed:
            return []
        try:
            with self._writing():
                self._write_pots(unclosed)
                self.db.commit()
        except sqlite3.Error:
            return unclosed
        return []

    def _one(self, sql, args=()):
        with self._lock:
            cur = self.db.execute(sql, args)
            return cur.fetchone()

    def _all(self, sql, args=()):
        with self._lock:
            return self.db.execute(sql, args).fetchall()

    def _discard(self) -> None:
        """Roll back an open transaction (under `_lock`) — after a failed write."""
        try:
            self.db.rollback()
        except sqlite3.Error:
            pass     # connection closed or similar — then nothing is left open either

    def _begin_immediate(self) -> None:
        """`BEGIN IMMEDIATE` for a self-managed transaction (under `_lock`) — counting and
        booking in one step, also across several processes (`reserve_attempt`, `finish_attempt`)."""
        if self.db.in_transaction:
            # The second lock behind `_writing`: if a transaction is lying around anyway (a
            # writer that did not roll back on failure), the BEGIN below would fail on it —
            # and with it every sign-in until someone else committed. Its content is the remainder
            # of a FAILED write; it is discarded, not booked along. Loud, because
            # it is an error elsewhere.
            logging.getLogger("tinysesam").warning(
                "Open transaction found on the database connection (remnant of a "
                "failed write) — discarded before the sign-in attempt counts.")
            self._discard()
        self.db.execute("BEGIN IMMEDIATE")

    @contextlib.contextmanager
    def _writing(self):
        """Hold `_lock`, write — and on failure DISCARD the transaction.

        Python's `sqlite3` silently opens a `BEGIN` before every INSERT/UPDATE/DELETE. If
        the write failed (a foreign writer held the lock longer than `busy_timeout`,
        volume full, file read-only), this transaction stayed open on the SHARED connection.
        Measured: `reserve_attempt` begins with an explicit `BEGIN IMMEDIATE`
        and failed with "cannot start a transaction within a transaction" — every sign-in
        ended with a 500 until some other write happened to commit. It was triggered
        by the write probe of `/healthz` alone, which is reachable without sign-in. In addition:
        that foreign commit would take along what a multi-part writer (`delete_user`) had already
        written before the failure.

        Every write path therefore runs through here (or through `_exec`, which does so too); whoever manages the
        transaction themselves (`reserve_attempt`, `rotate_session`, `_clock_record`) puts each commit in a `try` whose broad `except`
        (without type, `Exception` or `BaseException` — `sqlite3.Error` does not catch a binding error such as
        OverflowError) or `finally` rolls back. tests/test_hardening2.py checks this via the
        syntax tree for every commit in this class — not merely whether `rollback()`
        appears somewhere in the function."""
        with self._lock:
            try:
                yield
            except BaseException:
                self._discard()
                raise

    def _exec(self, sql, args=()):
        with self._writing():
            cur = self.db.execute(sql, args)
            self.db.commit()
            self._written = time.monotonic()
            self._clock_record()
            return cur

    #: Setting key of the saved clock state (see `_Clock`) and how often it is written at most
    #: (seconds).
    CLOCK_STATE = "clock_state"
    CLOCK_SECURE_SEC = 60

    def _write_clock_state(self) -> None:
        """Raise `clock_state` to `now()` — only UPWARDS (without commit, under `_lock`).

        `_open_schema()` already writes before `Store()` has raised the clock from the database;
        there `now()` is still the wrong wall clock of a boot with an old date. A blind
        overwrite would delete exactly the state that is about to raise the clock."""
        now_s = _now()
        self.db.execute("INSERT OR IGNORE INTO setting(key, value) VALUES (?, ?)",
                        (self.CLOCK_STATE, str(now_s)))
        self.db.execute("UPDATE setting SET value=? WHERE key=? AND CAST(value AS INTEGER) < ?",
                        (str(now_s), self.CLOCK_STATE, now_s))

    @staticmethod
    def _fresh(since, m, deadline) -> bool:
        """Is the monotonic stamp `seit` less than `deadline` seconds before `m`?

        A NEGATIVE distance counts as expired, not as fresh: freezegun delivers
        `time.monotonic` on the epoch scale (≈1.8e9). A write under `freeze_time`
        left the stamps there, and afterwards every distance was negative, hence always "shorter than
        the deadline" — `clock_state` was no longer saved in the whole process, the write probe
        checked only the connection (second attack round, same class as in `_Clock.now`).
        A distance above any deadline is expired anyway."""
        return since is not None and 0 <= m - since < deadline

    def _clock_record(self) -> None:
        """Save the clock state — at most once per `CLOCK_SECURE_SEC` (under `_lock`).

        Without it a restart knew only the last event in the database: what expired afterwards
        applied again for its full remaining lifetime after a boot with an old date (B6-9). Own
        commit AFTER the actual write: if it fails (volume full), it must not drag down the
        already confirmed write — the state is a bonus."""
        m = time.monotonic()
        if self._fresh(self._clock_secured, m, self.CLOCK_SECURE_SEC):
            return
        try:
            self._write_clock_state()
            self.db.commit()
            self._clock_secured = m
        except Exception as error:
            # Rolled back on EVERY failure, only the database error is swallowed (the
            # clock state is a precaution). Until the final round, `except sqlite3.Error:` caught here —
            # a binding error such as OverflowError is not one and left the transaction open;
            # only the outer `_writing` of `_exec` saved it.
            self._discard()
            if not isinstance(error, sqlite3.Error):
                raise

    #: Values of `users.disabled` besides 0 (active): the lock of a pending confirmation and
    #: the lock by the operator. Separate because `/auth/verify/…` lifts the one and never the
    #: other (H-18, second attack round): if the confirmation token arose only AFTER a
    #: lock by the operator — for instance in the outbox of an embedding app to which
    #: `send_verify_email` pushes it —, the lock found nothing to discard, and the link
    #: afterwards set `disabled` unconditionally to 0.
    LOCKED_CONFIRMATION = 1
    LOCKED_OPERATOR = 2
    #: The lock of the application that manages the account (account API, schema 23). The application lifts only
    #: this value (`unlock_by_app`), never 1 or 2, and it never downgrades another lock (`lock_by_app`).
    LOCKED_APP = 3

    # ---------- TOTP ----------
    #: Encryption/decryption of the TOTP secrets (H-14/H-15, `vault.Vault`). Set by the manager;
    #: a store without a vault (CLI tools) does not touch the secrets.
    vault: Any = None

    #: Every encrypted column: (table.column, SELECT of rowid, value and the context parts, extra WHERE).
    #: The context names the row by what does NOT change in its life — not the session handle, which rotates.
    ENCRYPTED = (
        ("totp_cred.secret", "SELECT rowid AS rid, secret AS value, user_id FROM totp_cred"),
        ("oidc_session.refresh", "SELECT rowid AS rid, refresh AS value, client, sub FROM oidc_session"),
        ("oidc_id_token.id_token", "SELECT t.rowid AS rid, t.id_token AS value, t.client, s.user_id "
                                   "FROM oidc_id_token t JOIN session s ON s.token_hash = t.token_hash"),
        ("oauth_token.successor", "SELECT rowid AS rid, successor AS value, token_hash FROM oauth_token "
                                  "WHERE successor IS NOT NULL"),
        ("key_material.material", "SELECT rowid AS rid, material AS value, purpose, kid FROM key_material"),
    )

    #: Prefix of the origin placeholders in `federated_identity.identifier` (see `TinySesam._WITHOUT_IDENTIFIER`).
    WITHOUT_IDENTIFIER = "~without-identifier:"

    # ---------- Sessions ----------
    # What is stored is a keyed digest of the token, never the token itself. Everything that comes from a
    # session row (`row["token_hash"]`) is therefore a handle: it names a session
    # and is no good for signing in. The plaintext lives between `create_session()` and the cookie.
    #
    # The digest is an HMAC with the pepper keyring (T-71, ADR-12), active key first — set by `TinySesam` right after
    # it loaded the keyring. Up to 0.26.0 it was a plain sha256: whoever could WRITE the file inserted the sha256 of a
    # token of their own choosing and held a session of any account, without any key. The pepper lives in the
    # environment, a key file or `key_material` encrypted with the vault key — never readable from this file alone.
    # The same digest serves the other tokens of a browser that are stored here: the app host's link
    # (`gate_link.link_hash`) and the area unlock (`resource_unlock.token`).
    session_peppers: tuple = ()

    # ---------- the other token digests (T-72) ----------
    # API keys, one-time tokens (sign-in links, invitations, address confirmations, reset links, the service and consent
    # pairing codes, the QR sign-in codes), the QR device secret, the recovery codes and the app-host code exchange
    # (`gatecode:` flow key and the browser binding, T-26): an HMAC with the same pepper keyring, with a label per kind. Up to 0.30.0 they were a plain sha256 — whoever could write the file inserted the
    # digest of a key, link or recovery code of their own choosing and held a working automation key, sign-in link or
    # second factor of any account.

    #: The kind of a token digest → the column it is looked up in (None: compared by the caller, not looked up).
    TOKEN_KINDS = {"apikey": ("api_key", "key_hash"), "magic": ("magic_token", "token_hash"), "qr-device": None,
                   "recovery": ("recovery_code", "code_hash"), "gatecode": None, "gatebinding": None}

    #: Inactivity limits in seconds (without / with "stay signed in"), 0 = off. Set by the
    #: manager from the configuration (F-05); the store alone knows none.
    idle_sec = (0, 0)
    #: How often `zuletzt` is written at most: writing on every request would mean that every
    #: forward-auth call locks the file. A minute of fuzziness is nothing for limits of hours.
    IDLE_STEP_SEC = 60

    @classmethod
    def secure_file(cls, source: str, destination: str) -> str:
        """Back up a database file WITHOUT touching it — the path for `tinysesam backup`.

        Why not simply `Store(quelle).backup(destination)`: the constructor sets
        `PRAGMA journal_mode=WAL` and creates missing tables. It
        **writes**, and does so before anything has been copied. Whoever does the
        only right thing before an update and makes a backup would thereby have lifted the running installation to the new
        schema while the old code is still running — the way back would be closed, and a file
        in the old schema would then exist nowhere. The safety net would have destroyed what it is meant to
        protect.

        That is why there is a separate connection in `ro` mode here: it does not migrate, creates nothing
        and needs no writable directory. The online backup API still reads
        a consistent state including WAL through it.
        """
        if not os.path.exists(source):
            raise FileNotFoundError(source)
        if not os.path.exists(destination):
            try:
                os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, cls.FILE_PERMISSIONS))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
        source_db = sqlite3.connect(f"file:{source}?mode=ro", uri=True)
        destination_db = sqlite3.connect(destination)
        try:
            source_db.backup(destination_db)
        finally:
            destination_db.close()
            source_db.close()
        for attachment in ("", "-wal", "-shm"):
            try:
                if os.path.exists(destination + attachment):
                    os.chmod(destination + attachment, cls.FILE_PERMISSIONS)
            except OSError:
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return destination

    def backup(self, destination: str) -> str:
        """Write a consistent copy of the database, during operation.

        **A file copy is no good.** The database runs in WAL mode: everything since the
        last checkpoint is in `…-wal`, not in the `.db`. Whoever copies only the `.db` (cp,
        rsync, a backup agent that knows patterns) gets a torso — measured: a fresh
        instance with five accounts yielded a copy without even the table `users`. The error
        is noticed only on restoring.

        Here SQLite's online backup runs: it takes the locks it needs, pulls in the WAL and
        delivers a file that is correct on its own. The copy gets the same narrow permissions
        as the original — a backup with password hashes deserves as much protection as the source.
        """
        if not os.path.exists(destination):
            try:
                os.close(os.open(destination, os.O_CREAT | os.O_EXCL | os.O_WRONLY, self.FILE_PERMISSIONS))
            except OSError:
                pass  # created meanwhile or cannot be created — chmod below sets the permissions
        destination_db = sqlite3.connect(destination)
        try:
            with self._lock:
                self.db.backup(destination_db)
        finally:
            destination_db.close()
        for attachment in ("", "-wal", "-shm"):
            try:
                if os.path.exists(destination + attachment):
                    os.chmod(destination + attachment, self.FILE_PERMISSIONS)
            except OSError:
                pass  # permissions cannot be set (foreign file system) — the copy itself is complete
        return destination

    def gc_flow(self) -> int:
        return self._exec("DELETE FROM flow WHERE expires_at < ?", (_now(),)).rowcount

    # ---------- Flow state (OIDC / WebAuthn, short-lived, one-shot) ----------
    #: How often writing a flow also clears the expired ones (seconds, per process). `flow` holds the OIDC `state`/`nonce`
    #: and WebAuthn challenges of every sign-in start — also of a scanner that follows the redirect and never returns —
    #: and only `TinySesam.gc()` removed expired rows; a gateway without a cron job held 159 285 of them.
    FLOW_GC_SEC = 300
    #: Monotonic time of the last clearing; None = not yet in this process (so the first write clears — a monotonic
    #: clock starts near zero on a freshly booted machine, and "0.0" would read as "just now" there).
    _flow_gc_at: Optional[float] = None

    def put_flow(self, key, data: dict, ttl=600):
        self._exec("INSERT OR REPLACE INTO flow(key, data, expires_at) VALUES (?,?,?)",
                   (key, json.dumps(data), _now() + ttl))
        if self._flow_gc_at is None or time.monotonic() - self._flow_gc_at >= self.FLOW_GC_SEC:
            self._flow_gc_at = time.monotonic()
            self.gc_flow()

    def pop_flow(self, key) -> Optional[dict]:
        """Hand out flow state exactly ONCE (WebAuthn challenge, OIDC `state`/`nonce`).

        Reading and deleting were two separate steps, each with its own lock (R3-8): two
        simultaneous callbacks with the same `state` — two threads, or two workers on
        the same file — both read the row before one deleted it, and both got the
        challenge. Now the `DELETE` decides: only whoever actually removed the row
        (`rowcount == 1`) gets the content. SQLite serialises the writers, also across
        process boundaries — `RETURNING` would be more elegant but requires SQLite ≥ 3.35."""
        with self._writing():
            r = self.db.execute("SELECT data, expires_at FROM flow WHERE key=?", (key,)).fetchone()
            if not r:
                return None
            away = self.db.execute("DELETE FROM flow WHERE key=?", (key,)).rowcount
            self.db.commit()
        if away != 1:
            return None                 # another caller consumed it first
        if r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    def claim_flow(self, key, ttl: int) -> bool:
        """Mark `key` as used for `ttl` seconds — `True` only for the FIRST caller (H1: SAML assertion IDs,
        ASVS 6.8.3). One `INSERT OR IGNORE` under the write lock decides, like the `DELETE` in `pop_flow`:
        two workers with the same assertion cannot both win. An expired row of the same key no longer counts;
        `gc_flow` removes the rest."""
        with self._writing():
            self.db.execute("DELETE FROM flow WHERE key=? AND expires_at < ?", (key, _now()))
            won = self.db.execute("INSERT OR IGNORE INTO flow(key, data, expires_at) VALUES (?, '{}', ?)",
                                  (key, _now() + max(int(ttl), 1))).rowcount
            self.db.commit()
        return won == 1

    def peek_flow(self, key) -> Optional[dict]:
        """Read flow state WITHOUT consuming it — for state that lasts several requests (the
        setup pass after a sign-in link, T-34). Expired rows count as absent."""
        r = self._one("SELECT data, expires_at FROM flow WHERE key=?", (key,))
        if not r or r["expires_at"] < _now():
            return None
        try:
            return json.loads(r["data"])
        except Exception:
            return None

    def count_argon2_hashes(self) -> int:
        """How many stored password/PIN/scope hashes are argon2? (B6-8)"""
        n = 0
        for table in ("password_cred", "pin_cred", "resource_secret"):
            r = self._one(f"SELECT COUNT(*) AS n FROM {table} WHERE hash LIKE '$argon2%'")
            n += int(r["n"] or 0) if r else 0
        return n

    #: How long a successful commit counts as proof that the database is writable
    #: (seconds). Within this period `write_probe()` only checks the connection.
    WRITE_PROBE_SEC = 5

    def write_probe(self) -> None:
        """A real write transaction — the core of the health check (B6-4).

        A `SELECT 1` also succeeds on a database that has become read-only (read-only
        mount, wrong permissions after a restore, `SQLITE_READONLY`) or whose volume is full
        (`SQLITE_FULL`) — exactly where every sign-in fails at its first `INSERT INTO
        session`. Healthy is therefore only reported once a commit goes through.
        Raises the sqlite3 exception unchanged; what of it reaches the outside is decided by the
        caller.

        What is written is the clock state (`clock_state`) — so the health check also saves it
        on the side, in times when nothing else is written. But at most every
        `WRITE_PROBE_SEC`: `/healthz` is reachable without sign-in, and one commit
        with fsync under `_lock` per call would mean that whoever floods it occupies the write lock that
        sign-ins wait for, and wears out SD cards. If the last successful commit (also
        a foreign one via `_exec`) is more recent than that, a read access suffices — a closed or
        vanished connection is still noticed immediately, a change to "read-only" at the latest
        after `WRITE_PROBE_SEC`."""
        with self._writing():
            m = time.monotonic()
            if self._fresh(self._written, m, self.WRITE_PROBE_SEC):
                self.db.execute("SELECT 1").fetchone()
                return
            self._write_clock_state()
            self.db.commit()
            self._written = self._clock_secured = m

    # ---------- Runtime settings (editable in the panel) ----------
    def get_setting(self, key) -> Optional[str]:
        r = self._one("SELECT value FROM setting WHERE key=?", (key,))
        return r["value"] if r else None

    def set_setting(self, key, value):
        self._exec("INSERT OR REPLACE INTO setting(key, value) VALUES (?,?)", (key, str(value)))

    def webauthn_handle_salt(self) -> bytes:
        """The instance's salt for passkey user handles (T-56) — created on first use, 32 random bytes.

        `INSERT OR IGNORE`: two processes racing each other agree on the first one; afterwards it never changes."""
        self._exec("INSERT OR IGNORE INTO setting(key, value) VALUES ('webauthn_handle_salt', ?)",
                   (secrets.token_hex(32),))
        return bytes.fromhex(str(self.get_setting("webauthn_handle_salt")))

    def all_settings(self) -> dict:
        return {r["key"]: r["value"] for r in self._all("SELECT key, value FROM setting")}

    #: How long a pre-booking with an open outcome (`reserve_attempt(as_pending=True)`) counts as
    #: pending, not as a failed attempt (seconds, G9). Longer than any directory query up to
    #: its timeout (`ldap_.CONNECTION_TIMEOUT`, connection setup and bind once each) including
    #: compute time. An older open row has been completed by nobody — the process has died
    #: or is hanging; it then counts as a failed attempt, when in doubt the stricter reading.
    PREBOOKING_PENDING_SEC = 30

    # ---------- Audit log ----------
    #: Truncate IPs in the audit log to their network (`TinySesamConfig.audit_ip_pseudonymize`, B5-11).
    #: Stands here and not in the manager because the login path also writes `audit_log` directly —
    #: a truncation that only some of the rows undergo protects nobody.
    audit_ip_pseudonym = False

    # ---------- Approvals (schema 22) ----------
    #: The states an approval can be in; only `pending` and `approved` are open.
    APPROVAL_OPEN = ("pending", "approved")

    #: How many audit rows `anonymize_audit` searches in the detail text per block before it
    #: releases the write lock for others (G4).
    _ANONYMOUS_BLOCK = 5000
    #: Upper bound of the span of a TODAY identifier (`anonymize_audit`): none.
    _WITHOUT_UPPER_LIMIT = 2 ** 62
    #: How many earlier names or addresses `_earlier_identifiers` traces back at most.
    _EARLIER_MAX = 100
    #: The old name in `username_changed` (`old=<name>[ by=operator][ source=cli][ actor=…]`)
    #: and the old address in `email_changed` (`old=<address> new=<address>`). A name may
    #: carry spaces, an address may not (`valid_email`).
    _OLD_NAME = re.compile(r"^old=(.*?)(?= by=| source=| actor=|$)")
    _OLD_MAIL = re.compile(r"^old=(\S*)")
    #: The values in the own rows that carry an identifier (4c): up to the next ` key=`.
    _OWN_VALUES = re.compile(r"(?<![\w@.-])(old|new|to)=(\S.*?)(?=\s[\w-]+=|$)")

    #: What settles a confirmation request from LDAP/SAML for the day (`source_mail_since`): the
    #: delivered link and the rejection of a taken or reserved address.
    SOURCE_MAIL_DONE = ("federation_email_confirm", "email_change_taken", "email_change_reserved")

    # ---------- pairing consent (ADR-14, rows in `magic_token`) ----------
    #: A code fetched by the account, not yet redeemed — and the consent it armed once the setup script redeemed it.
    CONSENT_PAIRING = "oauth_consent_pairing"
    CONSENT_ARMED = "oauth_consent_armed"
