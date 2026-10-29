"""TinySesam — central auth class. Orchestrates store, password, TOTP, (optional) OIDC & passkey.

Integration:
    from tinysesam import TinySesam, TinySesamConfig
    auth = TinySesam(TinySesamConfig(db_path="app.db", rp_id="app.example.com", origin="https://app.example.com"))
    auth.ensure_admin("admin", "startpw")          # create the first admin (only if there is none)
    app.include_router(auth.router())              # /auth/* routes + login UI
    @app.get("/geheim")
    def geheim(user = Depends(auth.require_user)):  # protected
        return {"hi": user["username"]}
"""
from __future__ import annotations
import os
import re
import sys
import json
import hashlib
import hmac
from collections import OrderedDict
import html as _html
import secrets
import sqlite3
import time
import warnings
import contextvars
from typing import Any, Callable, Literal, NoReturn, Optional, cast

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse
from starlette.responses import Response

from . import config_check
from .errors import ConfigError, StateError
from .config import TinySesamConfig
from .store import (Store, key_kind_of, name_ungueltig, norm_email, norm_kennung, jetzt as _jetzt,
                    payload_lesen, valid_email, versuchsfrist as _versuchsfrist)
from .passwords import hash_password, verify_password, needs_rehash, dummy_verify
from . import passwords as _passwords
from . import passwords as _pw
from .templates import PRAEFIX_PLATZHALTER as _PRAEFIX_PLATZHALTER, Templates, inject_nonce as _inject_nonce
from . import totp as _totp
from . import security
from .ldap_ import VERBINDUNGS_TIMEOUT as _LDAP_TIMEOUT
from ._deprecated import Deprecated
from .login_result import LoginResult
from .password_change_result import PasswordChangeResult

#: IP and signed-in account of the request currently being handled (B5-02, B5-04).
#:
#: The account methods (`totp_disable`, `create_api_key`, `create_invite`, …) get no
#: request — they can also be called without one. Their audit lines therefore had no IP and
#: no account (`detail="user=5"`), and `tinysesam audit --user X` did not find them. The value
#: is set where TinySesam resolves the request anyway (`current_user` and
#: related methods); `audit()` reads it. A ContextVar, not an instance variable: it applies per
#: request (per asyncio task or per thread-pool call) and cannot leak into a parallel one.
_ANFRAGE: contextvars.ContextVar = contextvars.ContextVar("tinysesam_anfrage", default=None)


# Sets nonce="…" in every <script>/<style> that has none yet. Central, instead of threading the
# nonce through every template function. Safe, because none of the built-in pages emits the
# string "<script"/"<style" INSIDE a JS string (checked) — only real tags.


def _host_aus(wert: str) -> str:
    """Only the host name of an address — or "" for a broken one (open IPv6 bracket etc.).

    Needed as the key for `security.einmal_melden()`: the notice belongs to the host,
    not to the individual URL — otherwise every new path lifts the suppression and the log flood
    is back.
    """
    from urllib.parse import urlsplit
    try:
        return urlsplit(str(wert or "")).hostname or ""
    except ValueError:
        return ""


class _DictKopfzeilen:
    """The three accesses that `_kopfzeilen_in` needs, on top of a plain dict.

    Lookup is case-insensitive; writes go to the key that already exists — otherwise under the
    spelling passed in. That way `exc.headers["Location"]` stays readable.
    """
    def __init__(self, d: dict):
        self.d = d

    def _schluessel(self, name: str):
        return next((k for k in self.d if k.lower() == name.lower()), None)

    def get(self, name: str, vorgabe=None):
        k = self._schluessel(name)
        return vorgabe if k is None else self.d[k]

    def setdefault(self, name: str, wert: str):
        if self._schluessel(name) is None:
            self.d[name] = wert

    def __setitem__(self, name: str, wert: str):
        self.d[self._schluessel(name) or name] = wert


def _dn_teile(wert: str) -> list[str]:
    """Split a DN at the UNescaped commas (`cn=a\\,b,ou=x` has two parts, not three)."""
    teile, aktuell, maskiert = [], [], False
    for zeichen in str(wert):
        if maskiert:
            aktuell.append(zeichen)
            maskiert = False
        elif zeichen == "\\":
            aktuell.append(zeichen)
            maskiert = True
        elif zeichen == ",":
            teile.append("".join(aktuell).strip())
            aktuell = []
        else:
            aktuell.append(zeichen)
    teile.append("".join(aktuell).strip())
    return teile


def gruppe_passt(schluessel, gruppe, teilstring: bool = False, dn: bool = False) -> bool:
    """Does the key from `*_group_role_map`/`ldap_allowed_groups` match this group?

    `teilstring=True` is the old comparison (`schluessel in gruppe`) and exists only on
    explicit request (`group_match="substring"`). Up to 0.19.x it applied to LDAP ALWAYS,
    whatever `group_match` said (F-19): `admin` then matched `cn=nicht-admin,…` and
    `staff` matched `cn=staffextern,…` — whoever may name a group in the directory got
    the role and the admin flag.

    `dn=True` (LDAP, `memberOf` delivers whole DNs) compares **exactly**, but by components:
    the whole DN, a **prefix** of whole RDNs (`cn=staff` or `cn=staff,ou=groups` — the
    partial DN without the base, as the README shows it in its example) or the value of the first RDN
    (`staff`). Case does not matter there — LDAP compares names that way, and `CN=Staff,OU=Groups`
    is the same group. This keeps the familiar spelling valid, without a name fragment
    hitting a foreign group: only whole components are compared, starting at the front.
    """
    s, g = str(schluessel), str(gruppe)
    if not s:
        return False
    if teilstring:
        return s in g
    if s == g:
        return True
    if not dn or "=" not in g:
        return False
    g_teile = [t.lower() for t in _dn_teile(g)]
    if "=" in s:
        # Whole DN or partial DN from the front (A-3): `cn=admins,ou=g` matches
        # `cn=admins,ou=g,dc=example,dc=com`. Until the first fix of this round the substring
        # covered that; without this branch a key written that way silently dropped out after the
        # update — admin mapping gone, or, as ldap_allowed_groups, every user rejected.
        s_teile = [t.lower() for t in _dn_teile(s)]
        return g_teile[:len(s_teile)] == s_teile
    _, _, wert = g_teile[0].partition("=")
    return s.strip().lower() == wert.strip()


def _teilstring_hinweis(schluessel, gruppen, feld: str) -> None:
    """Say once per key when it would only match as a substring now (A-3).

    Up to 0.19.x LDAP always compared by substring (F-19). A key that matched back then and
    no longer does costs roles after the update, silently, or — in `ldap_allowed_groups` — all
    access. It cannot be detected statically (it depends on the directory's DNs),
    so it surfaces at the first login where it happens."""
    s = str(schluessel)
    if not s or not any(s in str(g) for g in gruppen):
        return
    if any(gruppe_passt(s, g, dn=True) for g in gruppen):
        return
    if security.einmal_melden(f"ldap_teilstring:{feld}:{s}"):
        security.seclog.warning(
            "LDAP: the key %r in %s only matches as a substring (%s) and has no effect since "
            "0.20.0 — comparison is by DN components. Change the spelling "
            "(whole DN, partial DN from the front like 'cn=admins,ou=groups', or just the CN) or "
            "set group_match='substring'.", security.fuer_log(s), feld,
            security.fuer_log(next(str(g) for g in gruppen if s in str(g)))[:200])


def _auf_stderr(zeile: str) -> None:
    """One line to the operator, not to the log.

    The route is deliberately `sys.stderr` and not `seclog`: what is written here is meant for the
    human who starts the service — not for a file that fail2ban reads, logrotate
    archives and a log shipper takes along (B5-03). `sys.stderr` is looked up afresh on every
    call, so that a redirected stderr (tests, wrappers) really takes effect.
    """
    try:
        sys.stderr.write(zeile.rstrip("\n") + "\n")
        sys.stderr.flush()
    except Exception:
        pass            # no stderr (pythonw, closed descriptor) — no reason to abort


def _stderr_ist_konsole() -> bool:
    """Is a human reading along, or is someone collecting stderr (container, journal, pipe)?

    In a container stderr IS the log (`docker logs`), under systemd the journal. What is meant
    "for the operator's console only" must then not go there (finding from operations,
    2026-09-27). Like `_auf_stderr`, looked up afresh on every call.
    """
    try:
        return bool(sys.stderr is not None and sys.stderr.isatty())
    except Exception:
        return False


#: What is accepted as a CSRF token from a cookie (0.20.1). Only URL-safe characters — nothing
#: that does harm in an HTML attribute, a header or a cookie line —, at least
#: as long as what TinySesam rolls itself (`token_urlsafe(24)`: 32 characters, 192 bits),
#: at most 128. A cookie that looks different is replaced instead of written into a form.
_CSRF_FORM = re.compile(r"[A-Za-z0-9_-]{32,128}")

#: Under this key in the ASGI scope a request remembers the token it freshly rolled
#: — so that `csrf_token(request)` before rendering and `ensure_csrf(request, response)` after
#: return the same thing. The scope belongs to exactly one request; nothing leaks into another.
_CSRF_SCOPE = "tinysesam.csrf_neu"

#: How many just-signed-in sessions, not yet set in the cookie, a process remembers.
#: Between `_sitzung_anlegen()` and `set_cookie()` lies one request; the limit only catches
#: custom routes that create a session and never set a cookie.
_FRISCH_MAX = 1024


def _samesite(wert: str) -> Literal["lax", "strict", "none"]:
    """The constructor allows only these three values (see TinySesam.__init__); this states it
    once more for the type checker, which does not follow the guarantee from there."""
    return cast(Literal["lax", "strict", "none"], wert)


def _beleg_wahr(wert) -> bool:
    """Does an LDAP/SAML attribute say "this address is verified"? Only explicitly true values
    count (True, "true", "1", "yes", "ja"); anything else — also a missing attribute — does not."""
    if isinstance(wert, bool):
        return wert
    return str(wert or "").strip().lower() in ("true", "1", "yes", "ja")


def _beleg_am_konto(user) -> bool:
    """The `users.email_verified` marker of an account row.

    If the column is missing — a row from a foreign source, a test setup with a
    dictionary —, "confirmed" applies: exactly the state of every installation before this column,
    so no silent tightening for existing data. Where a sign-in path knows better,
    the evidence travels along as a parameter (`_maybe_promote_admin(user, email_bestaetigt=…)`)
    and wins."""
    try:
        return bool(user["email_verified"])
    except (IndexError, KeyError, TypeError):
        return True


#: Which switch needs which extra — switch → (module, extra).
#: Stated here, not in the test: a copy in tests/ would silently go stale with the next new
#: method. The test now checks AGAINST this table.
SCHALTER_BRAUCHT_EXTRA = {
    "passkey_enabled": ("webauthn", "passkey"),
    "oidc_enabled": ("authlib", "oidc"),
    "saml_enabled": ("onelogin", "saml"),
    "ldap_enabled": ("ldap3", "ldap"),
}



def _gueltige_regeln(regeln) -> list:
    """Only the rules whose keys are populated.

    A rule "per account" without an account would otherwise silently become one "per address"
    with the wrong boundary (`count_fails` simply drops an empty filter)."""
    return [r for r in regeln
            if all(r[2].get(k) for k in ("username", "ip") if k in r[2])]

def _messages_der_sprache(auth) -> dict:
    from .messages import MESSAGES
    return MESSAGES.get(auth.cfg.lang) or MESSAGES["en"]


class TinySesam:
    def __init__(self, config: TinySesamConfig):
        self._riegel(config, beim_aufbau=True)
        self.cfg = config
        self.store = Store(config.db_path)
        self.store.leerlauf_sek = (max(0, int(config.session_idle_minutes or 0)) * 60,
                                   max(0, int(config.session_idle_minutes_remember or 0)) * 60)
        # TOTP secrets only encrypted (H-14/H-15, mandatory). Key from the environment, the
        # configuration or next to the database; a wrong one aborts startup.
        from . import vault as _vault
        _schluessel, self._schluessel_herkunft = _vault.load_key(
            config.db_path, config.secrets_key_file)
        self.store.tresor = _vault.Vault(_schluessel)
        # Gate token (ADR-9, T-19): the signing key is derived from the same base key
        # — no second secret to back up and distribute. Always derived, even
        # when the gate is off: `tinysesam gate-key` should be able to prepare the proxy before
        # the switch is flipped.
        from . import gate as _gate
        self._gate_schluessel = _gate.schluessel_ableiten(_schluessel)
        # Separate subkey for the password fingerprints: without it a leaked memory dump would be a
        # dictionary target against the typos of the real passwords.
        self._pw_wiederholung_schluessel = hmac.new(_schluessel, b"tinysesam/passwort-wiederholung/v1",
                                                    hashlib.sha256).digest()
        self.store.geheimnisse_heben()
        # B6-8: Without the [argon2] extra every sign-in against an argon2 hash fails — until
        # now without a word, the account just looked like "wrong password" to the user.
        # At startup, count and say how many it affects; startup itself stays possible
        # (passkey, OIDC and SSO do not depend on it, and a service that no longer comes up
        # at all because of a missing package would be the bigger outage).
        if not _passwords.argon2_verfuegbar():
            betroffen = self.store.zaehle_argon2_hashes()
            if betroffen:
                security.seclog.error("%s (%d betroffene Hashes)", _passwords.ARGON2_FEHLT, betroffen)
        self.store.audit_ip_pseudonym = bool(config.audit_ip_pseudonymize)
        self._protokoll_drossel: dict = {}   # see `_einmal_je`
        # Just fully signed-in sessions (handle) whose cookie is not set yet — see
        # `_sitzung_anlegen` and `set_cookie` (CSRF rotation at sign-in, 0.20.1).
        from collections import OrderedDict
        import threading
        self._frische_anmeldungen: "OrderedDict[str, None]" = OrderedDict()
        self._frisch_lock = threading.Lock()
        self.templates = Templates()
        self._messages: dict = {}
        self._mailer_override = None
        from .mailer import Postausgang
        self._postausgang = Postausgang()
        # Own small outbox for lockout notices (ASVS 6.3.5): it is filled by whoever sends
        # failed attempts — a flood must not displace sign-in links and resets in the main outbox.
        self._hinweis_ausgang = Postausgang(arbeiter=1, max_offen=50)
        # The OIDC re-check (4a) exchanges refresh tokens in the background: a hanging provider
        # would otherwise hold every due request until the timeout — from `async` routes including the event loop
        # (attack on the second round, finding 6, same class as B6-6).
        self._oidc_ausgang = Postausgang(arbeiter=2, max_offen=200)
        #: Opt-in notification for security events on one's own account (finding B2-2,
        #: recommendation H-6) — see `SECURITY_EVENTS`. Call `hook(event, account,
        #: details)`; `account` has `id`, `username`, `email`, `display_name`. TinySesam
        #: sends nothing itself: which mail, which channel, which language is decided by
        #: the app.
        self.on_security_event: Optional[Callable[[str, dict, dict], Any]] = None
        self._blockliste = self._blockliste_laden(config.password_blocklist_file)
        # Attempt ID → (identifier, method, series state after booking) for the series
        # pre-booked in `_begin_attempt` (B2-6). In memory is enough: if the process dies
        # in between, the pre-booking remains as a failed attempt — stricter in doubt.
        self._serie_vorbuchungen: dict = {}
        # Fingerprints of wrong passwords per (account, IP) — memory only, never on disk (`_passwort_wiederholt`).
        self._pw_wiederholung: "OrderedDict[tuple, list]" = OrderedDict()
        self._pw_wiederholung_sperre = threading.Lock()
        # Waiting slots for sign-ins that would not get further only because of pending
        # pre-bookings (G9, `_begin_attempt`) — capped, so waiters do not occupy all worker threads.
        self._schwebe_plaetze = threading.BoundedSemaphore(self._SCHWEBE_WARTEPLAETZE)
        self.oidc = None
        self.webauthn = None
        self.ldap = None
        # The failure marker hangs on the manager, not on the client: it also applies to a client
        # set by hand (`auth.ldap = own_client`) — rationale at `AusfallMerker`.
        from .ldap_ import AusfallMerker
        self._ldap_ausfall = AusfallMerker()
        self.saml = None
        if config.security_log:
            security.attach_security_log(config.security_log)
        # Both limiters have the same `allow()` interface; `Any` says that without introducing
        # a Protocol for two implementations.
        self.rl: Any = security.RateLimiter()
        if config.redis_url:
            try:
                self.rl = security.RedisRateLimiter(config.redis_url)
            except Exception:
                security.seclog.warning("Redis rate limit unavailable → in-memory fallback")
        # A missing extra here is an operational error and not a subtlety: the setup
        # fails with the name of the package instead of a ModuleNotFoundError from the depths
        # or — worse — only at the first sign-in attempt as a 500.
        #
        # Checked here and not in the constructor head, on the condition "is the method
        # COMPLETELY configured": whoever sets `oidc_enabled=True` but no
        # `issuer` obviously wants to bring the client themselves (`auth.oidc = …`) — four
        # own suites work that way. A guard that triggers on the switch already forbids
        # that route. That a half-configured method gets noticed is done by config_check.
        # `find_spec` instead of an import attempt: the extras are imported LAZILY everywhere
        # (only on connect, on token exchange, when checking an assertion). A missing
        # package therefore did not show at setup but at the first sign-in attempt — as a
        # 500 from inside the library.
        # Warn, do not raise. A client can be replaced (`auth.ldap = own_client`),
        # and four own suites work exactly that way — a guard that aborts here forbids
        # that. Raising happens at the place where it can never be wrong: at the lazy import
        # in the respective module. The operator thus sees it at startup in the log and, if they
        # overlook that, at the first sign-in attempt as a readable `MissingExtra` instead of a 500.
        def _verlange(modul, schalter, extra):
            import importlib.util as _ilu
            try:
                da = _ilu.find_spec(modul) is not None
            except (ImportError, ValueError):
                da = False
            if not da:
                security.seclog.warning(
                    "%s=True, but the extra [%s] is not installed (pip install "
                    "'tinysesam[%s]') — the module '%s' is missing. Unless the client is set "
                    "separately, sign-in via this method will fail.",
                    schalter, extra, extra, modul)

        if config.ldap_enabled and config.ldap_url:
            _verlange("ldap3", "ldap_enabled", "ldap")
            from .ldap_ import LDAPClient
            self.ldap = LDAPClient(config)
        if config.saml_enabled and config.saml_idp_sso_url and config.saml_idp_x509cert:
            _verlange("onelogin", "saml_enabled", "saml")
            from .saml_ import SAMLClient
            self.saml = SAMLClient(config)
        if config.oidc_enabled and config.oidc_issuer and config.oidc_client_id:
            _verlange("authlib", "oidc_enabled", "oidc")
            from .oidc import OIDCClients, VORGABE_CLIENT
            # `self.oidc` stays the single client and with it the public surface of 0.18.0
            # (tests and foreign code access it). `self.oidc_clients` is the mapping
            # host → client; without `cfg.oidc_clients` it contains exactly this one (T-14).
            self.oidc_clients = OIDCClients(config)
            self.oidc = self.oidc_clients[VORGABE_CLIENT]
        if config.passkey_enabled:
            # Passkey has no incomplete configuration: whoever flips the switch means it.
            _verlange("webauthn", "passkey_enabled", "passkey")
            from . import webauthn_ as wa
            self.webauthn = wa
        if config.demo_mode and not self.store.get_setting("demo_users") \
                and self.store.user_count() > 0:
            # The one technical barrier a genuine demo never hits (B3-8): a demo
            # starts on an EMPTY database — there it creates its accounts and remembers them
            # (`demo_users`), every later start recognises them, even with visitors registered
            # in the meantime. Whoever switches `demo_mode` on for the first time on a database
            # that already has accounts, switches it on for existing data — i.e. in
            # production. Before, that silently created an admin account with a known password.
            raise ConfigError(
                "demo_mode=True on a database that already has accounts and was never a demo "
                f"({config.db_path!r}). The demo creates an admin account with a known password — "
                "on existing data that is a backdoor. For a demo use a separate, empty "
                "database (db_path).")
        if config.demo_mode:
            security.seclog.warning(
                "DEMO MODE active: example accounts %s with a known password. DO NOT run in production.",
                ", ".join(self._DEMO_USERS))
            self._seed_demo()
        elif self.store.get_setting("demo_users"):
            n = self._purge_demo()                       # demo mode switched off → accounts are gone
            if n:
                security.seclog.warning("Demo mode off: %d example account(s) deleted.", n)
        # Forward auth across several hosts, but without cookie_domain: the session cookie is
        # host-only, so there is NO shared SSO — every host demands its own sign-in.
        # The login URL is built per host (see forward_login_url), so that at least no silent
        # redirect loop results. This is provable in advance, without guessing about the outside
        # world: the hosts are in our own configuration.
        # With the code exchange (T-26) host-only is exactly what is wanted: the app hosts get a
        # connection, not their own sign-in — the warning would be a false alarm there.
        if (config.forward_auth_enabled and config.base_url and not config.cookie_domain
                and not getattr(config, "gate_link_enabled", False)):
            from urllib.parse import urlsplit
            own = urlsplit(config.base_url).hostname or ""
            fremd = [h for h in (config.trusted_redirect_hosts or []) if h and h != own]
            if fremd:
                security.seclog.warning(
                    "Forward auth without cookie_domain: the session cookie is host-only on %s, "
                    "not on %s. Each of these hosts demands its own sign-in (the login page "
                    "is built there). For shared SSO across subdomains set cookie_domain, "
                    "e.g. '.%s'.", own or "?", ", ".join(fremd),
                    ".".join(own.split(".")[-2:]) if own.count(".") >= 1 else "example.com")
        # Collisions in the identifier space from existing data: the database has prevented new ones
        # since 2026-09-26 (trigger over the counting buckets, `Store._trigger_sql`), but one from an
        # older version, from a raw UPDATE or from a row of a foreign writer
        # is still in there. It is not harmless: `find_user` then resolves the identifier ambiguously,
        # the rightful owner may be locked out, and two accounts share the
        # lockout threshold. Cleanup is by hand (which account keeps the name cannot be decided by
        # any library) — it is said at startup, and completely: until then the
        # message only saw "name = foreign address" via NOCASE, not `Alice`/`alice` or two
        # spellings of the same address (`topf_kollisionen`).
        kollisionen = self.store.topf_kollisionen()
        if kollisionen:
            beispiele = "; ".join(
                f"identifier '{security.fuer_log(z['kennung'])}': "
                + ", ".join(f"user_id={i}" for i in z["ids"]) for z in kollisionen[:5])
            security.seclog.warning(
                "%d identifier collision(s) in existing data: username and email are ONE "
                "identifier space (find_user searches both columns, namesakes like Alice/alice "
                "share the lockout threshold). The database prevents new ones; these date from "
                "the time before and stay until one of the identifiers is changed. Signing in "
                "with this identifier is ambiguous, the rightful owner may be locked "
                "out. Affected: %s%s. One of the identifiers has to change. The username: in the "
                "admin panel (\"Rename\", POST <admin_path>/api/users/<id>/username), with "
                "tinysesam rename --db <file> '#<user_id>' <new-name>, the owner themselves on "
                "the account page, or from the embedding service "
                "auth.change_username(user_id, new_username, by_operator=True) — all check both "
                "namespaces (in login_identifier='email' mode the name follows the address). The "
                "email from the embedding service via "
                "store.set_email(user_id, address) (raises sqlite3.IntegrityError if the new "
                "address is already the identifier of another account). Note on the email: "
                "store.set_email() stores the new address as UNCONFIRMED by default "
                "(users.email_verified=0) — the evidence for the old address does not carry over to a "
                "different one. Whoever has evidence for the new one passes verified=True.",
                len(kollisionen), beispiele,
                " (more follow)" if len(kollisionen) > 5 else "")
        # Account names with control/format characters (no longer creatable since 2026-09-24) in existing data:
        # forward auth rejects those whose characters the header sanitising would remove (otherwise
        # `Remote-User` would be a foreign name). It is said at startup, not only per request.
        auffaellig = [z for z in self.store._all("SELECT id, username FROM users")
                      if name_ungueltig(z["username"])]
        if auffaellig:
            security.seclog.warning(
                "%d account name(s) with control or format characters in existing data (user_id %s). "
                "TinySesam no longer creates new ones; names with C0 control characters get no "
                "approval at forward auth (Remote-User would be a different name). Rename: in the "
                "admin panel (\"Rename\"), with tinysesam rename --db <file> '#<user_id>' "
                "<new-name>, the owner themselves on the account page, or from the embedding "
                "service auth.change_username(user_id, new_username, by_operator=True) — all check "
                "that the new name is free among usernames AND addresses.",
                len(auffaellig), ", ".join(str(z["id"]) for z in auffaellig[:10]))
        # Binding by name (G1): the grace period starts per source at the first start at which it is
        # switched on — for existing data thus with the update — and exactly once (the marker
        # stays, see `Store.foederation_seit`). After that, one line per source for as long as there are
        # accounts that would bind via the name and the door is still open.
        for _quelle, _an in (("ldap", config.ldap_enabled), ("saml", config.saml_enabled)):
            if _an:
                self._namensbindung_bestand_melden(_quelle, self._foederation_seit(_quelle))
        tok = self.admin_claim_token()
        if tok:
            self._admin_claim_bekanntgeben(tok)
        else:
            self._claim_datei_weg()          # a leftover from a run without admin (T-17)

    # ---------- Owner ----------
    def _erster_owner(self, user_id) -> None:
        """The first admin of an instance also becomes its first owner (bootstrap paths)."""
        if self.store.owner_count() == 0:
            self.store.set_owner(user_id, True)
            u = self.store.get_user(user_id)
            self.store.audit_log("owner_grant", u["username"] if u else None, None, "quelle=erst_admin")

    def set_owner(self, user_id: int, owner: bool) -> bool:
        """Grant (`owner=True`) or give up (`False`) the owner role. False = no such account.

        Owners are admins that cannot be deleted, locked or stripped of power; there is always
        at least one, and only owners grant the role (the calling route checks that). Giving up the
        role works only if ANOTHER owner remains (`StateError`). Service accounts and
        locked accounts do not become owner (`ConfigError`) — an owner must be able to sign in."""
        u = self.store.get_user(user_id)
        if not u:
            return False
        if owner:
            if u["is_service"] or u["disabled"]:
                raise ConfigError("Only an active, interactive account can become owner.")
            if not u["is_owner"]:
                self.store.set_owner(user_id, True)
                self.audit("owner_grant", u["username"])
            return True
        if u["is_owner"]:
            if self.store.owner_count(ohne=user_id) == 0:
                raise StateError(f"Account {user_id} is the last owner. Appoint another owner "
                                 "first, then hand over the role.")
            self.store.set_owner(user_id, False)
            self.audit("owner_revoke", u["username"])
        return True

    # ---------- User management ----------
    def identifier_taken(self, identifier, exclude_id=None) -> Optional[dict]:
        """Does this login identifier already belong to an account — in EITHER of the two namespaces?

        Username and email are not separate spaces: with `login_identifier="both"` (default)
        `find_user` searches **both** columns, and for an identifier with `@` the email
        wins. Whoever checks separately allows a stranger to register the email of an
        existing account as a *username* (or vice versa) — from then on the identifier resolves
        to the foreign account and the rightful owner is locked out (finding R4-12).

        The check is **always** crosswise, also in the modes "username" and "email": the mode is
        a switch an operator flips later; a collision that sleeps today would then be
        live at once. The return value is the account the identifier belongs to, otherwise None. `exclude_id`
        leaves one account out — for checks on an existing account.

        And via the **counting bucket** of the lockout counter (`Store.konto_mit_topf`): `Émile` and
        `émile` are two names for SQLite NOCASE (ASCII only), one for `norm_kennung`. Two
        such accounts shared the account threshold against distributed guessing — and if one was
        removed (also triggerable anonymously: a registration that `gc()` sweeps away), the
        failed attempts of the other went with it. Such a namesake is therefore considered taken.

        **And via the name in the directory** (`federated_identity.name_topf`, G5; review round
        2026-09-27): under one identifier the login route checks the local password of the account AND
        the LDAP password of the entry. If a local account was named like another person in the
        directory (self-service, registration, renaming in the panel), each of its
        sign-ins cleared the counters under which that person's LDAP password was being guessed —
        the lockouts stopped working. A name that stands on the binding of ANOTHER account is
        therefore considered taken (the identifier that stands there in the directory after renaming, and
        the old name of a renamed LDAP account, see `Store._verzeichnisname_merken`).

        **A pre-check, the database decides** (since 2026-09-26): between this
        answer and the write a concurrent request can claim the identifier. The
        write then rejects it (trigger over the counting buckets, `Store._trigger_sql`), and the
        callers turn that into the same answer as here ("taken").
        """
        identifier = (identifier or "").strip()
        if not identifier:
            return None
        for treffer in (self.store.get_user_by_name(identifier), self.store.get_user_by_email(identifier),
                        self.store.konto_mit_topf(identifier, ausser=exclude_id),
                        self.store.konto_mit_verzeichnisname(identifier, ausser=exclude_id)):
            if treffer is not None and treffer["id"] != exclude_id:
                return self._als_dict(treffer)
        return None

    def create_user(self, username, password=None, is_admin=False, roles=None,
                    display_name=None, email=None, is_service=False,
                    email_verified: bool = True, *, self_chosen_name: bool = False) -> int:
        """Create an account and return its ID. `is_service=True` for machines: no
        login, API keys only. An identifier that is already taken raises `ConfigError` — **new
        also for a duplicate username**, which up to 0.18.x came as `sqlite3.IntegrityError` from the
        database (`e.field`/`e.owner_id` say what collided).

        Username and email must be free **crosswise** (`identifier_taken`) — otherwise a new account
        occupies the login identifier of an existing one. The check sits here
        so that it applies to EVERY path: self-registration, admin API, invitation, first admin
        (`ensure_admin`), service accounts (`create_service`) and the automatic creation from
        OIDC/LDAP/SAML. The CLI is deliberately not included: it cannot create accounts; its
        `rename` (G13) does not load the manager and performs the same three lookups itself.

        `email_verified=False` stores the address as **unconfirmed**: kept and
        passed along like any other, but without weight for rights (first admin/allowlist,
        see `_maybe_promote_admin`). That is the case for every sign-in path that does not vouch for
        the address: an IdP without the `email_verified` claim, **and in principle SAML and
        LDAP** — there is no attribute at all that asserts a verification.
        The default `True` applies to the paths where the operator vouches for the address
        (admin API, first admin, service accounts, invitation to this address). Self-
        registration stores the typed-in address with `False`; the evidence is only set by the
        redeemed confirmation link (`/auth/verify`), without a confirmation requirement it stays at
        `False`. Whoever registers on their own and sends `send_verify_email` also passes
        `False` — otherwise the address counts as verified before anyone has redeemed the link.

        A taken identifier raises `ConfigError` with the wording "<field> ist bereits
        vergeben" (German runtime text) and `e.field` set (`"username"`/`"email"`) plus `e.owner_id` —
        that, not the translated text, is how a caller tells the two cases apart.

        ⚠️ **Changed compared to 0.18.x:** only a duplicate *email* raised
        `ConfigError` there. A duplicate *username* went all the way to the database and came back as
        `sqlite3.IntegrityError`; it is now caught beforehand and raises the same
        `ConfigError`. Whoever catches `IntegrityError` no longer catches this case.

        **Also in a race** (since 2026-09-26): if a concurrent request claims the identifier
        between check and creation, the database rejects the INSERT — and that too comes as the
        same `ConfigError`. `e.owner_id` may then be `None`: when the other account
        is already removed again before it is looked up here.

        `self_chosen_name=True`: the person typed the name themselves (registration,
        also with an invitation). A sign-in via LDAP/SAML then never binds this account via the
        name (G2-N, `users.name_selbst_gewaehlt`). The built-in registration sets it; whoever builds
        their own passes it too. Default `False`: the operator assigns the name. Whoever
        creates accounts from their OWN foreign source (another identity provider) passes it
        too: names chosen there say nothing about who in the directory has that name."""
        return self._konto_anlegen(username, password, is_admin, roles, display_name, email,
                                   is_service, email_verified, name_selbst_gewaehlt=self_chosen_name)

    def _konto_anlegen(self, username, password=None, is_admin=False, roles=None, display_name=None,
                       email=None, is_service=False, email_verified: bool = True, *,
                       name_selbst_gewaehlt: bool = False, name_quelle: Optional[str] = None) -> int:
        """`create_user` including the origin of the name (`users.name_quelle`, attack round 2026-09-26):
        creation from OIDC, SAML and LDAP. A name that a source brings along never binds the account
        via the name to ANOTHER one (`_nachbindung_grund`) — `preferred_username`, NameID and
        `uid` are chosen by oneself at an IdP with self-registration. Reproduced: `chefin` signs
        in via OIDC, the real chefin afterwards via LDAP, and the OIDC account then carried her
        identifier and her roles. The same source may keep replacing its placeholder with the real
        identifier. Not public: whoever creates on their own uses `self_chosen_name=True` (`create_user`)."""
        username = (username or "").strip()
        email = norm_email(email)
        if name_ungueltig(username):
            # Central here, because every creation path ends here (registration, panel, CLI, OIDC,
            # SAML, LDAP): a name with control characters becomes a DIFFERENT name in `Remote-User`
            # (see `name_ungueltig`). The federated paths switch to a substitute
            # name beforehand; whoever lands here gets a rejection.
            fehler = ConfigError("Username contains control or format characters")
            fehler.field = "username"
            raise fehler
        for feld, schluessel, kennung in (("username", "username", username),
                                          ("email address", "email", email)):
            besitzer = self.identifier_taken(kennung) if kennung else None
            if besitzer:
                security.seclog.warning(
                    "Account not created: %s is already the login identifier of user_id=%s", feld, besitzer["id"])
                # The wording is that of 0.18.x ("… ist bereits vergeben"). Because a
                # `ConfigError` alone does not reveal WHAT collided, callers check the text —
                # the most brittle way to control a program, but a common one. A fix
                # must not pull the ground from under it. It does name the field that REALLY
                # collides, though: the new trigger (username = foreign email and vice versa)
                # carries the username OR the email text depending on direction, not always
                # the same. It can be told apart reliably by `field`/`owner_id`.
                fehler = ConfigError(f"{feld} is already taken")
                fehler.field = schluessel
                fehler.owner_id = int(besitzer["id"])
                raise fehler
        try:
            uid = self.store.create_user(username, display_name, email, is_admin, roles, is_service,
                                         email_verified=email_verified,
                                         name_selbst_gewaehlt=name_selbst_gewaehlt,
                                         name_quelle=name_quelle)
        except sqlite3.IntegrityError as fehler_db:
            # Race (G12c): between the check above and the INSERT a concurrent
            # request claimed the identifier, and the database rejects (identifier trigger, UNIQUE on
            # name or address). Every IntegrityError of this INSERT means "taken". Which
            # identifier, a second check says — if the other account is already gone again, it stays
            # with the username without an owner.
            treffer = [(feld, schluessel, self.identifier_taken(kennung) if kennung else None)
                       for feld, schluessel, kennung in (("username", "username", username),
                                                         ("email address", "email", email))]
            feld, schluessel, besitzer = next((t for t in treffer if t[2]), treffer[0])
            security.seclog.warning(
                "Account not created (race): %s became the login identifier of user_id=%s "
                "between check and creation", feld, besitzer["id"] if besitzer else "?")
            fehler = ConfigError(f"{feld} is already taken")
            fehler.field = schluessel
            fehler.owner_id = int(besitzer["id"]) if besitzer else None
            raise fehler from fehler_db
        if password:
            self.store.set_password_hash(uid, hash_password(password))
        return uid

    # Roles (optional). Whoever only needs "signed in or not" uses require_user.
    # Other projects differentiate users via is_admin + freely definable roles.
    def user_roles(self, user) -> list:
        """The roles of an account as a list."""
        try:
            return json.loads(user["roles"] or "[]")
        except Exception:
            return []

    def is_admin(self, user) -> bool:
        """Is this account an admin? Takes an account row, not a request."""
        return bool(user["is_admin"])

    def has_role(self, user, role, admin_implies=None) -> bool:
        """Does the user have the role? An admin satisfies EVERY role by default
        (`config.admin_implies_roles`). Whoever attaches rights solely to IdP groups switches that off —
        otherwise every local admin automatically is also "editor", "viewer", … ."""
        if admin_implies is None:
            admin_implies = self.cfg.admin_implies_roles
        if admin_implies and bool(user["is_admin"]):
            return True
        return role in self.user_roles(user)

    def set_roles(self, user_id, roles):
        """Replace the roles of an account."""
        self.store.set_roles(user_id, roles)

    def apply_idp_groups(self, user_id, groups, mapping: dict, substring: Optional[bool] = None,
                         dn: bool = False):
        """IdP groups → local roles (at login). Mapped roles are synchronised (removed when
        the group goes away), manually granted roles remain. Target '__admin__' sets the
        admin flag and takes it back again if it came from the provider (H-5).

        Target '__admin__' sets the admin flag — and, since H-5, also takes it back when the provider
        no longer delivers the group, but **only a flag it granted itself**
        (`is_admin=2`, `Store.set_admin_vom_idp`). Until then it was "grant only": whoever was thrown
        out of the admin group at the provider stayed admin here until someone noticed it in the panel. An admin
        from the panel, the CLI, `admin_identifiers` or `/auth/claim-admin` remains untouched — otherwise
        a misconfigured provider would strip the operator of their own access. A flag
        from before H-5 does not carry the marker and therefore likewise stays in place.
        If the provider thus takes the **last** admin, `admin_identifiers` promotes
        nobody afterwards (G6); the one-time token for `/auth/claim-admin` goes to the
        operator immediately (stderr or `admin_claim_token_file`).

        By default comparison is **exact** (`config.group_match`). Otherwise `admin` would also
        match `nicht-admin`: a silent privilege escalation. `dn=True` (LDAP) compares a
        group DN by its components instead of as text (`gruppe_passt`): whole DN, first
        RDN (`cn=staff`) or its value (`staff`) — never a substring."""
        if not mapping:
            return
        if substring is None:
            substring = self.cfg.group_match == "substring"
        gs = [str(g) for g in (groups or [])]
        matched = {role for key, role in mapping.items()
                   if any(gruppe_passt(key, g, substring, dn) for g in gs)}
        if dn and not substring:
            for key in mapping:
                _teilstring_hinweis(key, gs, "ldap_group_role_map")
        managed = {role for role in mapping.values() if role != "__admin__"}
        current = set(self.store.get_roles(user_id))
        new_roles = (current - managed) | {r for r in matched if r != "__admin__"}
        if new_roles != current:
            self.store.set_roles(user_id, sorted(new_roles))
        u = self.store.get_user(user_id)
        if "__admin__" in matched:
            if u and not u["is_admin"]:
                self.store.set_admin_vom_idp(user_id)
                self.audit("idp_admin_grant", u["username"], detail="quelle=idp")
        elif "__admin__" in mapping.values() and u and u["is_admin"] == 2:
            # The mapping knows an admin group, the provider no longer delivers it: the flag
            # it granted goes. Loudly, because it can also be the last admin.
            self.store.set_admin(user_id, False)
            self.audit("idp_admin_revoke", u["username"], detail="quelle=idp gruppe_entfallen=1")
            security.seclog.warning("Admin flag withdrawn: user=%s, the identity provider no longer "
                                    "delivers the admin group.", security.fuer_log(u["username"]))
            if not self.admin_exists():
                # If it was the last admin (G6), the allowlist stays closed from now on: otherwise
                # `_maybe_promote_admin` in the same login — via `apply_factor` — would promote the person again,
                # as admin "by hand" (1) and first owner, whom no provider withdraws any more and whom
                # nobody can delete or lock. And not only her: every account with an
                # allowlist entry. Only the operator's verified route remains open — the
                # one-time token, now issued immediately (until then only at startup), and the CLI.
                # The marker applies to the instance and is never reset; it only takes effect
                # as long as there is no admin. Parallel withdrawals set it idempotently.
                self.store.set_setting("allowlist_nach_idp_entzug", str(_jetzt()))
                security.seclog.warning(
                    "No admin left: the identity provider has withdrawn the instance's last admin. "
                    "admin_identifiers promotes nobody afterwards. Emergency route: "
                    "tinysesam owner --db <file> <user> or /auth/claim-admin with the "
                    "one-time token (console or admin_claim_token_file).")
                tok = self.admin_claim_token()
                if tok:
                    self._admin_claim_bekanntgeben(tok)

    # ---------- API keys / service accounts (machine access, daemons) ----------
    def create_service(self, username, roles=None, display_name=None) -> int:
        """Service/daemon account: no interactive login, API keys only. Roles = rights scope."""
        return self.create_user(username, is_service=True, roles=roles, display_name=display_name or username)

    def create_api_key(self, user_id, name=None, expires_days=None, roles=None,
                       kind: str = "automation") -> dict:
        """Create a new API key. The return value contains 'key' in PLAINTEXT — only ONCE (afterwards only the hash).

        **Two kinds** (R6-5), because a key can be two quite different things:

        * ``kind="automation"`` (default) — a service, a script, a CI. It works alone,
          but **never carries the admin flag** of its owner and satisfies no route that demands
          admin. Up to 0.18.x a key of an admin was a full admin write API,
          without a second factor and without a CSRF layer: create users, set `is_admin`,
          reset passwords. A leaked CI key was thus the whole instance.
        * ``kind="human"`` — a tool that a person operates themselves. It applies **only
          together with a valid session of the same account**; in return it carries the full
          rights. Leaked on its own, it is worthless.

        Up to 0.21.x the kinds were called `"automat"` and `"mensch"`. Since 0.22.0 only the
        English name applies (no alias, PO decision 2026-09-27) — an old one raises `ConfigError`, which
        names the new one. Stored keys were rewritten by the migration (schema 12).

        A missing `expires_days` on an automation key is not without consequence: then
        `apikey_default_days` applies (default 90). `expires_days=0` means "unlimited" and needs
        `apikey_allow_unlimited=True` — a key without expiry outlives the person who
        issued it, and the project it was meant for.

        `roles` is a **scope**, not a rights increase: the list is trimmed to the owner's roles.
        A key can thus do less than its owner, never more.

        **If nothing is left after the trim, the method raises `ConfigError` and creates no
        key** — a typo in `roles` therefore yields an exception, not a key. Why not an
        empty scope: the reason is stated at the code below; it would reverse the effect.

        Returns `{"id", "key", "prefix", "expires_at", "roles", "dropped_roles", "kind"}`.
        `key` is the plaintext and is visible only this once; `dropped_roles` names what the
        trim removed (the same information is in the audit entry, there as
        `verworfene_rollen=` — the audit line stays as it was; up to 0.21.x the key
        here was named that way too).
        Until 2026-09-21 the list was taken over unchecked, and on checking it overwrote the
        roles of the account. Every signed-in user could thereby issue themselves arbitrary roles via the self-service route
        `POST /auth/apikeys` — invisibly, because the account in the
        database stayed role-less. In forward-auth operation the invented role went on as Remote-Group
        to the downstream app.
        """
        if kind not in self._KEY_ARTEN:
            neu_name = Store.KEY_ARTEN_ALT.get(str(kind))
            raise ConfigError(
                (f"API key kind {kind!r} has been called {neu_name!r} since 0.22.0. " if neu_name else
                 f"There is no API key kind {kind!r}. ")
                + "'automation' works on its own (without admin rights), 'human' only counts "
                  "together with a session of the same account.")
        raw = "tsk_" + secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(raw.encode()).hexdigest()
        prefix = raw[:12] + "…"
        # Expiry: 0 explicitly means "unlimited" and needs permission; None means
        # "not specified" and gets the default. Telling the two apart is the point —
        # before, `None` was silently unlimited, and that was the most common case.
        if expires_days is None:
            expires_days = int(self.cfg.apikey_default_days or 0)
        expires_days = int(expires_days)
        # Exactly ZERO means unlimited. A negative value is an expiry in the past,
        # i.e. a key dead from the start — that is not nonsense but the way to create a key
        # that is invalid at once (the suite uses it to test the expiry check itself).
        if expires_days == 0:
            if not self.cfg.apikey_allow_unlimited:
                raise ConfigError(
                    "An API key without an expiry is a secret that nobody takes back — it "
                    "outlives the person who issued it and the project it was meant "
                    "for. Either set expires_days (default: "
                    f"apikey_default_days={self.cfg.apikey_default_days}) or, if there really is "
                    "no other way, apikey_allow_unlimited=True.")
            expires_at = None
        else:
            expires_at = _jetzt() + expires_days * 86400

        abgeschnitten = []
        if roles is not None:
            besitzer = self.store.get_user(user_id)
            erlaubt = set(self.user_roles(besitzer)) if besitzer else set()
            gewuenscht = [str(x) for x in roles]
            abgeschnitten = sorted(set(gewuenscht) - erlaubt)
            roles = sorted(set(gewuenscht) & erlaubt)
            # If NOTHING is left after trimming, the key must not come into being.
            #
            # The column `api_key.roles` knows only one empty value, and that means "no
            # scope, inherits the owner's roles". A scope shrunk to `[]` would thereby
            # turn into its opposite: whoever wants to scope a key to `["lagre"]` (a
            # typo) would get a key with ALL roles of the account. This trimming was
            # meant as a rights limitation and would have become a rights extension —
            # worse than before the fix.
            #
            # Hence an error instead of an assumption: only the caller knows what was meant.
            if not roles:
                raise ConfigError(
                    f"API key scope {sorted(set(gewuenscht))} contains no role that the account "
                    f"has ({sorted(erlaubt) or 'none'}). A key can only do less than "
                    "its owner, never more - and an empty scope would mean "
                    "'inherits everything' in the database. Either name an existing role or leave out `roles` "
                    "(then the key inherits the account's roles).")

        kid = self.store.add_api_key(user_id, name, prefix, key_hash, roles, expires_at, kind=kind)
        detail = f"user={user_id} key={kid} name={name} art={self._key_art_audit(kind)}"
        if expires_at is None:
            # Explicitly into the log: an unlimited key is a decision, not a
            # setting — whoever later asks "since when has this thing been lying around" finds something here.
            detail += " ablauf=unbefristet"
        if abgeschnitten:
            # Into the audit entry, not just discarded: whoever tries this should be visible.
            detail += f" verworfene_rollen={','.join(abgeschnitten)}"
        self.audit("apikey_create", self._kontoname(user_id), detail=detail)
        self._security_event("api_key_created", user_id, key_id=kid, name=name or "")
        return {"id": kid, "key": raw, "prefix": prefix, "expires_at": expires_at,
                "roles": roles, "dropped_roles": abgeschnitten, "kind": kind}

    #: The kinds of an API key (R6-5), English since 0.22.0: `automation` works alone and
    #: never carries the admin flag, `human` applies only together with a session of the same account.
    _KEY_ARTEN = ("automation", "human")
    #: The spelling in audit lines (`apikey_create … art=`, `apikey_use … art=`): that of
    #: 0.21.x. Audit and log lines do not change with the translation — operators' filters
    #: depend on them (PO decision 2026-09-27).
    _KEY_ART_AUDIT = {neu: alt for alt, neu in Store.KEY_ARTEN_ALT.items()}

    @staticmethod
    def _key_kind(row) -> str:
        """The kind of a key row with its English name (schema 12).

        A value up to 0.21.x (`automat`, `mensch`) is mapped (`Store.KEY_ARTEN_ALT`) — an
        older version that ran on the file after a downgrade writes it again. Empty
        or without the column (file before schema 7) means `automation`. Anything else stays as it
        is, and counts as an automation key because it is not `human` (fail-closed, R6-6)."""
        return key_kind_of(row)

    @classmethod
    def _key_art_audit(cls, kind) -> str:
        return cls._KEY_ART_AUDIT.get(kind, kind)

    def verify_api_key(self, key):
        """(user, key_roles|None) for a valid key, otherwise (None, None).

        The key's **kind** is afterwards in `self._letzte_key_art` — `current_user()` needs
        it, and a third return value would have broken every foreign caller (M-1 freezes the
        surface for 1.0). Whoever wants to know the kind themselves uses `api_key_kind(key)`.
        `user` is an account dict as with `get_user()` (since 0.22.0; before, the database row).
        """
        self._letzte_key_art = "automation"
        if not key or not key.startswith("tsk_"):
            return None, None
        row = self.store.get_api_key_by_hash(hashlib.sha256(key.encode()).hexdigest())
        if not row:
            self._key_protokoll(None, "unbekannt")
            return None, None
        if row["revoked"]:
            self._key_protokoll(row, "widerrufen")
            return None, None
        if row["expires_at"] and row["expires_at"] < _jetzt():
            self._key_protokoll(row, "abgelaufen")
            return None, None
        u = self.store.get_user(row["user_id"])
        if not u or u["disabled"]:
            self._key_protokoll(row, "konto_gesperrt")
            return None, None
        ruht = self._key_ruht(u)
        if ruht:
            self._key_protokoll(row, ruht)
            return None, None
        self.store.touch_api_key(row["id"])
        self._key_protokoll(row, None)
        self._letzte_key_art = self._key_kind(row)
        try:
            kr = json.loads(row["roles"] or "[]")
        except Exception:
            kr = []
        return self._als_dict(u), (kr or None)

    def _key_ruht(self, u) -> Optional[str]:
        """Are this account's API keys dormant because the identity provider does not (or no longer) back it?
        Returns: the reason (`idp_nein`, `idp_unbestaetigt`) or None (finding 8).

        Only for accounts with an OIDC binding, and only as long as OIDC is set up — without a provider
        there would be nobody who could confirm, and every key would be dead after the deadline.

        * **No from the provider** (`idp_bestaetigt_at = 0`, set by the re-check 4a): the
          session ended there already; without this check an automation key kept working for up to
          `apikey_default_days` — the same flaw PocketID itself had until 2.5.0
          (CVE-2026-43983: a locked account keeps access via an old token).
        * **No confirmation within `oidc_apikey_confirm_days`**: whoever works only by script
          has no session that 4a re-checks. This way an account locked at the provider is noticed at
          the latest after the deadline.

        Nothing is deleted: `invalid_grant` does not distinguish between "locked" and "merely
        expired" (RFC 6749 5.2) — the next sign-in via the provider wakes the keys."""
        if self.oidc is None:
            return None
        try:
            stand = u["idp_bestaetigt_at"]
        except (IndexError, KeyError):
            return None                       # row without the column: only before `_migrate`
        if not self.store.ist_oidc_konto(u["id"]):
            return None
        if int(stand if stand is not None else 1) <= 0:
            return "idp_nein"
        frist = int(self.cfg.oidc_apikey_confirm_days or 0) * 86400
        if frist and (stand is None or _jetzt() - int(stand) > frist):
            return "idp_unbestaetigt"
        return None

    def _idp_nein(self, user_id, name, ip, client, grund) -> None:
        """The provider said no (4a): the session has already ended — now the
        keys go dormant too (finding 8). One line in the audit log says how many it affects."""
        self.store.idp_verweigert(user_id)
        aktiv = [k for k in self.store.list_api_keys(user_id) if not k["revoked"]]
        if aktiv:
            self.store.audit_log("api_keys_ruhen", name, ip,
                                 f"client={client} grund={grund} anzahl={len(aktiv)}")

    #: How long the same key use (key, IP, outcome) is not written to the audit log again (B5-05).
    #: A key exists for automations that present it every second; one line per request
    #: would bury the rest of the log. One per hour and address answers the questions one asks after
    #: a leak: since when, from where, and did a NEW address join.
    _APIKEY_AUDIT_WINDOW = 3600
    _DROSSEL_MAX = 10000

    def _einmal_je(self, schluessel, fenster_sek: float) -> bool:
        """True if `schluessel` has not yet been logged within the window — and remembers it in advance.

        For events that come in bursts (key use, rejected forward auth). Per process;
        several workers therefore each write one line, which is deliberately cheaper than a reconciliation.
        """
        jetzt = _jetzt()
        if jetzt - self._protokoll_drossel.get(schluessel, 0) < fenster_sek:
            return False
        if len(self._protokoll_drossel) >= self._DROSSEL_MAX:
            self._protokoll_drossel.clear()   # cap: whoever probes addresses does not fill memory
        self._protokoll_drossel[schluessel] = jetzt
        return True

    def _key_protokoll(self, row, grund: Optional[str]) -> None:
        """Log a key use (grund=None) or rejection — throttled (B5-05).

        Until here the system knew only `last_used` of a key: no who, no from where, and
        a rejected key left nothing at all. That is exactly the signal, though — a
        revoked key that keeps knocking means: it is still lying around somewhere, or it has
        leaked. The IP comes from the running request (`_ANFRAGE`).
        """
        a = _ANFRAGE.get() or {}
        ip = a.get("ip")
        kid = row["id"] if row is not None else None
        if not self._einmal_je(("apikey", kid, ip, grund), self._APIKEY_AUDIT_WINDOW):
            return
        besitzer = self._kontoname(row["user_id"]) if row is not None else None
        art = self._key_art_audit(self._key_kind(row)) if row is not None else "?"
        if grund is None:
            self.store.audit_log("apikey_use", besitzer, ip, f"key={kid} art={art}")
            return
        detail = f"key={kid} grund={grund}" if kid is not None else f"grund={grund}"
        self.store.audit_log("apikey_denied", besitzer, ip, detail)
        security.seclog.warning("api key denied user=%s ip=%s grund=%s",
                                security.fuer_log(besitzer or "-"), security.fuer_log(ip), grund)

    def api_key_kind(self, key) -> str:
        """The kind of a key (`"automation"`/`"human"`, up to 0.21.x `"automat"`/`"mensch"`) —
        without using it. `""` for an unknown key."""
        row = self.store.get_api_key_by_hash(hashlib.sha256((key or "").encode()).hexdigest())
        return self._key_kind(row) if row else ""

    def _extract_api_key(self, request: Request):
        h = request.headers.get("x-api-key")
        if h:
            return h.strip()
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            tok = auth[7:].strip()
            if tok.startswith("tsk_"):
                return tok
        return None

    def list_api_keys(self, user_id) -> list:
        """The API keys of an account — without the secrets themselves, which exist only once at
        issuance. One dict per key (columns of `api_key`), `kind` with its English name (schema 12;
        up to 0.21.x the database row with the stored value)."""
        return [{**dict(k), "kind": self._key_kind(k)} for k in self.store.list_api_keys(user_id)]

    def revoke_api_key(self, key_id, user_id=None):
        """Revoke a key. It stays in the list — whoever issued it should see that."""
        besitzer = self.store.api_key_owner(key_id)
        vorher = self.store.count_active_api_keys(besitzer) if besitzer is not None else 0
        self.store.revoke_api_key(key_id, user_id)
        self.audit("apikey_revoke", self._kontoname(besitzer), detail=f"key={key_id}")
        if besitzer is not None and self.store.count_active_api_keys(besitzer) < vorher:
            self._security_event("api_key_revoked", besitzer, key_id=key_id)

    #: Why all keys of an account were revoked — `reason` in the event `api_keys_revoked`
    #: (`on_security_event`). Up to 0.21.x German (`sperre`, `admin_passwort`, `passwort_reset`,
    #: `sitzungen_beendet`), with the keys `anzahl`/`grund` instead of `count`/`reason`.
    _KEYS_WIDERRUFEN_GRUENDE = ("account_disabled", "admin_password_reset", "password_reset",
                                "sessions_revoked")

    def _keys_widerrufen(self, user_id, grund: str) -> int:
        """Revoke all valid keys of an account — and notify the owner (limit e).

        The one path for reset, lockout, admin password and `sessions/revoke`: before, the
        revocation was only in the audit log there, the owner learned nothing. `grund` is one of
        `_KEYS_WIDERRUFEN_GRUENDE`."""
        if grund not in self._KEYS_WIDERRUFEN_GRUENDE:
            raise ValueError(f"unknown reason {grund!r} — allowed: {self._KEYS_WIDERRUFEN_GRUENDE}")
        n = self.store.revoke_user_api_keys(user_id)
        if n:
            self._security_event("api_keys_revoked", user_id, count=n, reason=grund)
        return n

    def set_password(self, user_id, password):
        """Set an account's password (without checking the old one — that is the caller's business).

        The password rule (`password_policy_error`) does **not** check here — the setters do
        (registration, reset, account page, admin panel, CLI), because only they can give a
        readable answer. Whoever calls this method from their own code first asks `password_policy_error()`.
        Notification always happens (`password_changed`), whichever way it is reached."""
        self.store.set_password_hash(user_id, hash_password(password))
        self._security_event("password_changed", user_id)

    @staticmethod
    def _blockliste_laden(pfad) -> frozenset:
        """Read in the operator blocklist (`password_blocklist_file`) — once, at startup.

        If the file is missing, startup aborts (`ConfigError`) instead of silently continuing
        without a list: whoever specifies a list relies on it. Lines that are not
        UTF-8 are read by `blockliste_lesen` as Latin-1 — otherwise a raw
        `UnicodeDecodeError` came here instead of a usable list (A-3)."""
        if not pfad:
            return frozenset()
        try:
            return _pw.blockliste_lesen(pfad)
        except OSError as e:
            raise ConfigError(f"password_blocklist_file {pfad!r} cannot be read: {e}") from e

    def password_policy_error(self, password, *, username=None, email=None, api: bool = False) -> Optional[str]:
        """The password rule for a NEW password — `None` means "fine", otherwise the
        translated reason (`api=True`: the text for a JSON response).

        One rule for all setters: registration, password reset, account page and the
        admin panel (there every check was missing until T-13, finding B2-13). It checks minimum
        (`password_min_length`) and maximum length (R4-07), the built-in plus the custom
        blocklist and context-related words — service name (`rp_name`), username and the
        local part of the email address (B2-5/H-17). Details: `passwords.passwort_mangel`."""
        kontext = [self.cfg.rp_name, username or ""]
        if email:
            kontext.append(str(email).split("@", 1)[0])
        befund = _pw.passwort_mangel(password or "", self._passwort_mindestlaenge(),
                                     kontext=kontext, blockliste=self._blockliste)
        if befund is None:
            return None
        grund, werte = befund
        schluessel = {"short": ("api.password_short", "err.pw_short"),
                      "long": ("api.password_long", "err.pw_long"),
                      "weak": ("api.password_weak", "err.pw_weak")}[grund]
        return self.t(schluessel[0] if api else schluessel[1], **werte)

    def _passwort_allein_moeglich(self) -> bool:
        """Can the password, in this configuration, sign in COMPLETELY on its own?

        Yes in classic mode (no `login_chain`): an account without TOTP signs in with the
        password alone — and a TOTP can be removed again later. Yes also for a
        chain that demands nothing besides the password. No only when the global chain enforces a
        further factor (`["password", "totp"]`, `["oidc", "password"]`).

        Deliberately a statement about the CONFIGURATION, not about the individual account: whoever has
        TOTP today can remove it tomorrow, and the password would be left standing alone
        with the shorter length.

        And only with `mfa_enrollment="strict"`: with `"first_login"` (default) and `"grace"` an
        account sets up the demanded second factor itself the first time — whoever knows only the password
        then binds their own authenticator and is in. Exactly the initial passwords
        (panel, invitation, registration) thus sign in alone in this window (measured in the
        attack on B2-4). Only when the operator grants the enrolment is the password never
        alone. Limit: a window opened by the operator (`grant_mfa_enrollment`) — that is
        their deliberate decision for exactly one account."""
        kette = list(self.cfg.login_chain or ())
        if not kette or not (set(kette) - {"password"}):
            return True
        return self.cfg.mfa_enrollment != "strict"

    def _passwort_mindestlaenge(self) -> int:
        """The minimum length for a NEW password (B2-4, NIST SP 800-63B-4, 3.1.1.2).

        The standard demands 15 characters if the password can sign in alone, and 8 if it is only
        part of a sign-in with a further factor. Both values can be set in the panel
        (`password_min_length_single_factor`, `password_min_length`); whoever does not want the stricter
        rule sets the first to 8. Existing passwords remain valid — the rule applies
        where a password is set."""
        basis = self._sec("password_min_length")
        if self._passwort_allein_moeglich():
            return max(basis, self._sec("password_min_length_single_factor"))
        return basis

    # ---------- Notification on security events (opt-in) ----------
    #: The events for which `on_security_event` is called — everything that creates, changes,
    #: removes or consumes a sign-in factor of the account. Since T-13 (limit e) also the
    #: revocation of API keys: individually (`api_key_revoked`) and collectively on reset, lockout and
    #: `sessions/revoke` (`api_keys_revoked`, with count and reason). NIST SP 800-63B demands notifying the owner of such changes;
    #: until T-13 they learned of none (finding B2-2): an attacker with a
    #: session could switch off TOTP, add a passkey or change the password, and the
    #: owner saw it only at the next login — if at all. The details (third argument
    #: of the hook), with English keys since 0.22.0: `api_key_created` `key_id`, `name`;
    #: `api_key_revoked` `key_id`; `api_keys_revoked` `count`, `reason` (`account_disabled`,
    #: `admin_password_reset`, `password_reset`, `sessions_revoked`); `totp_disabled`
    #: `recovery_codes_deleted`; `recovery_codes_generated` `count`; `recovery_code_used`
    #: `remaining`; `passkey_added` `name`; `passkey_removed` `passkey_id`; `username_changed`
    #: and `email_changed` `old`, `new`; the rest none.
    SECURITY_EVENTS = (
        "password_changed", "pin_set", "pin_disabled", "totp_enabled", "totp_disabled",
        "recovery_codes_generated", "recovery_code_used", "passkey_added", "passkey_removed",
        "api_key_created", "api_key_revoked", "api_keys_revoked",
        "email_changed", "username_changed",
    )

    def _security_event(self, ereignis: str, user_id, **details) -> None:
        """Call `on_security_event` for an event from `SECURITY_EVENTS`, if set.

        An error in the hook does **not** abort the operation — the change has by then
        already been written, and a failed mail server must not make the password change
        fail. It does land in the security log, though: a notification that silently
        fails to appear is worse than none that nobody relies on. The hook runs
        synchronously in the request; whoever sends mail does better to put it in a queue."""
        hook = self.on_security_event
        if hook is None:
            return
        zeile = self.store.get_user(user_id)
        if zeile is None:
            return
        konto = {"id": zeile["id"], "username": zeile["username"], "email": zeile["email"],
                 "display_name": zeile["display_name"]}
        try:
            hook(ereignis, konto, dict(details))
        except Exception as e:
            security.seclog.warning("on_security_event fehlgeschlagen ereignis=%s user_id=%s: %s",
                                    ereignis, zeile["id"], security.fuer_log(repr(e)))

    def ensure_admin(self, username, password) -> bool:
        """Bootstrap: creates an admin IF no user exists yet. True on creation."""
        if self.store.user_count() == 0:
            uid = self.create_user(username, password, is_admin=True)
            self._erster_owner(uid)
            return True
        return False

    # ---------- First admin (bootstrap) ----------
    # Deliberately NOT "the first registered user becomes admin": with open registration, whoever
    # is there first wins — also a stranger who finds the fresh instance. Instead two
    # explicit paths, both effective only WHILE there is no admin — the allowlist moreover never
    # again after the identity provider has withdrawn the instance's last admin (G6).
    def delete_user(self, user_id: int) -> bool:
        """Delete an account with all its credentials (B5-08) — and take it out of the audit log (H-13).

        The audit lines stay (what happened, when, from which IP), only the name becomes
        `gelöscht#<id>` — also for sign-in attempts under the email address and where the name
        (`akteur=`) or address appears in the detail text (see `Store.audit_anonymisieren`). A
        deleted account whose name still appears in every line is not deleted; a log
        with missing lines is no longer fit for follow-up.

        The sign-in attempts disappear under every spelling under which the lockout bucket
        counts them (NFKC, IDNA, see `Store.delete_attempts_for`). Exception: a bucket that a
        remaining account shares (`ｃｌａｒａ` and `clara`) — it stays until the ordinary
        cleanup, otherwise deleting one would lift the lockout of the other.

        What arose from the creation of the account onward is replaced; a VERIFIED address also in
        older lines (for instance in the invitation that led to the account) — it demonstrably
        belongs to the account (`Store.adresse_belegt`). The address of an open account (link never
        redeemed) or of a registration without a confirmation requirement is not verified; a
        stranger may have typed it. A name belonged to nobody or to someone else before creation;
        a failed attempt under it stays as it was (see `Store.konto_entfernen`).

        The last admin cannot be deleted (`StateError`) — otherwise the instance would be left without
        administration, and the first-admin path would open up for the next best person. Returns False
        if the account does not exist.
        """
        u = self.store.get_user(user_id)
        if not u:
            return False
        if u["is_owner"]:
            raise StateError(f"Account {user_id} is an owner and cannot be deleted — hand over the "
                             "owner role first (this requires another owner to exist).")
        if u["is_admin"] and sum(1 for x in self.store.list_users() if x["is_admin"]) <= 1:
            raise StateError(f"Account {user_id} is the last admin and cannot be deleted.")
        # The one deletion path (`Store.konto_entfernen`) — the same through which `gc()`, `tinysesam gc`
        # and the withdrawal of a registration delete (integration findings 12/18). Only here, in
        # the deliberate deletion, does a verified address count as the account's own even from before creation —
        # the other paths can be triggered by a stranger (`Store.adresse_belegt`).
        entfernt = self.store.konto_entfernen(user_id, adresse_unbefristet=True)
        if entfernt is None:
            return False
        ersatz, n = entfernt
        self.audit("user_delete", ersatz, detail=f"uid={user_id} audit_anonymisiert={n}")
        return True

    def set_disabled(self, user_id: int, disabled: bool) -> bool:
        """Lock or unlock an account as operator — with the same effect as the panel
        (`POST <admin_path>/api/users/{id}/disable`, which calls exactly this method).

        **Locking** (`disabled=True`):

        * with operator marker: no confirmation link lifts the lock, not even one that
          comes into being only afterwards (H-18) — only `set_disabled(user_id, False)`;
        * all sessions of the account end, its API keys are revoked (event
          `api_keys_revoked` with `reason="account_disabled"`), open one-time tokens discarded
          (sign-in, confirmation, reset, address-change link). The revocation of the keys remains
          on unlocking — otherwise a key nobody knows about any more would come back to life;
        * an **owner** cannot be locked: `StateError`, and nothing has happened.

        **Unlocking** lifts every lock, including one from a pending confirmation.

        Audit as in the panel: `user_disable` or `user_enable` with `uid=<id>` (when locking with
        keys additionally `api_keys_revoked=<n>`) — in a request under the signed-in account (the
        admin), without a request under the affected one. What depends on the caller is checked by the route: the
        panel lets nobody lock themselves and changes an owner account only by an owner.
        Returns False if the account does not exist (then nothing happens).

        Up to 0.21.x the docs showed `auth.store.set_disabled(uid, True, durch_betreiber=True)` for this
        — that sets only the marker: sessions, keys and links stayed valid. `auth.store` is
        internals with no guarantee (PO decision 2026-09-27)."""
        u = self.store.get_user(user_id)
        if not u:
            return False
        uid = int(u["id"])
        # The marker first: with an owner the store raises before anything has happened.
        self.store.set_disabled(uid, bool(disabled), durch_betreiber=True)
        keys = 0
        if disabled:
            self.store.delete_user_sessions(uid)
            # `verify_api_key` already rejects keys of locked accounts. Revoke anyway: if
            # the account is released again later, a key nobody knows about any more would
            # otherwise come back to life.
            keys = self._keys_widerrufen(uid, "account_disabled")
            # The same for open one-time tokens: a confirmation link from registration otherwise lifted the
            # lock again (H-18, "a disabled account via no path").
            self.store.revoke_user_magic_tokens(uid)
        # From a request with a signed-in account (panel, own admin route) `audit()` names the
        # actor as the account — the same line the panel itself wrote up to 0.21.x.
        anfrage = _ANFRAGE.get() or {}
        self.audit("user_disable" if disabled else "user_enable",
                   None if anfrage.get("akteur") else str(u["username"]),
                   detail=f"uid={uid}" + (f" api_keys_revoked={keys}" if keys else ""))
        return True

    #: How the account page names an event when it is not its own name (G12b). The
    #: request for a taken or an allowlist address appears like any request — otherwise
    #: the account page would show what the response withholds. `None` hides it:
    #: `federation_email_confirm` arises only if the link went out to a FREE address, and
    #: would betray the same to an LDAP user who sets their `mail` attribute themselves. Likewise
    #: `ldap_kennung_abgewiesen` (review round 2026-09-27): the line is under the typed-in
    #: identifier and arises only if the LDAP password of the OTHER entry was right — on the
    #: local owner's account page it would be exactly the oracle that the rejection closes. The
    #: operator's audit log keeps the real names.
    _EIGENE_ANSICHT = {"email_change_taken": "email_change_requested",
                       "email_change_reserved": "email_change_requested",
                       "federation_email_confirm": None,
                       "ldap_kennung_abgewiesen": None}

    def own_events(self, user_id: int, limit: int = 20) -> list:
        """The most recent audit events of an account, for the account page (H-7).

        Only time, event and IP — the detail stays with the operator: for an admin action
        it names foreign accounts, and a display for the account owner should not show more than
        their own account. Exactly what one looks for there: "Was that me?"

        If ANOTHER person triggered the line (`akteur=` in the detail, see `audit()`), the IP there is
        theirs — the admin's. That is omitted; `by_admin` says instead that it was not
        the account owner.

        Counting starts only from the creation of the account (`Store.anlage_grenze`). The filter goes by
        the NAME, and a name may have belonged to someone else before: a deleted account
        whose lines an older version did not anonymise (integration finding 12), or
        to nobody — then the failed attempt of a stranger under the then-free name is there,
        including their IP.

        Since 2026-09-26 it is not the creation that counts but the NAME's joining (G2): whoever takes over a
        freed name (renaming) previously saw the previous owner's sign-in
        including their IP. The creation remains the fallback for existing data without a watermark.

        Likewise since 2026-09-26 it always shows an address-change request as
        `email_change_requested`, whether the address was free, taken or reserved, and
        `federation_email_confirm` not at all (`_EIGENE_ANSICHT`, G12b). A rejection ON
        CONFIRMATION (`beim_bestaetigen=1`) keeps its name: the 409 told the person clicking
        anyway, and only whoever has the link from the mailbox gets there.
        """
        u = self.store.get_user(user_id) if user_id is not None else None
        if not u:
            return []
        aus = []
        # The same boundary as `konto_entfernen`: the name's watermark, otherwise the creation.
        name = str(u["username"])
        audit_ab = self.store.kennung_grenzen(u).get(norm_kennung(name), (None, None))[1]
        seit, seit_id = self.store.anlage_grenze(u) if audit_ab is None else (None, 0)
        ausblenden = tuple(e for e, ansicht in self._EIGENE_ANSICHT.items() if ansicht is None)
        for z in self.store.recent_audit(max(1, int(limit)), username=name, seit=seit, seit_id=seit_id,
                                         ab_id=audit_ab, ohne_events=ausblenden):
            fremd = bool(re.search(r"(?:^|\s)akteur=", z["detail"] or ""))
            ereignis = z["event"]
            if not re.search(r"(?:^|\s)beim_bestaetigen=1(?:\s|$)", z["detail"] or ""):
                ereignis = self._EIGENE_ANSICHT.get(ereignis, ereignis)
            aus.append({"ts": z["ts"], "event": ereignis,
                        "ip": None if fremd else z["ip"], "by_admin": fremd})
        return aus

    def admin_exists(self) -> bool:
        """Is there at least one admin? The two bootstrap paths apply only while there is not."""
        return any(u["is_admin"] for u in self.store.list_users())

    #: Factors through which the identity comes from a FOREIGN provider. For them `_maybe_promote_admin`
    #: applies fail-closed: without explicit evidence an allowlist address there
    #: carries no first-admin decision — a new federated path that forgets to
    #: pass the evidence therefore does not promote but refuses.
    #: `ldap` is deliberately not here: LDAP writes the factor `password` (see `_check_ldap`),
    #: so it cannot be recognised by the factor name — its caller passes the evidence, which does not exist there
    #: at all, explicitly as `False`.
    _FEDERATED_FACTORS = ("oidc", "saml")

    def _maybe_promote_admin(self, user, email_bestaetigt: Optional[bool] = None,
                             faktor: Optional[str] = None) -> bool:
        """Path 1: allowlist. Whoever is in `admin_identifiers` becomes admin at login — regardless of
        the method (also OIDC/SAML/LDAP); an allowlist ADDRESS, however, only with evidence
        that it belongs to the person signing in, and via SAML/LDAP there is none. Never again afterwards —
        not even after the identity provider has withdrawn the instance's last admin (G6).

        **An entry with `@` is checked ONLY against the email, one without ONLY against the
        username.** Before, "name OR email" applied to every entry, and that made the
        constructor guard ineffective: it demands an *email address* in the allowlist for
        open registration, on the grounds that "whoever has the mailbox has the name".
        A username, however, is a free text field — whoever registers as
        `username="chef@example.com"` and confirms THEIR OWN mailbox became
        first admin. The guard checked the configuration, but the comparison here checked something
        different; the gap had merely moved.

        `email_bestaetigt` is the **evidence for the address** with which the caller arrives:
        a federated sign-in path states `True`/`False` via the claim `email_verified`,
        `None` means "this sign-in path does not know". Without evidence a matching address
        does not count: otherwise an IdP with self-registration would suffice to register the
        admin address and become first admin at the first login.

        Evidence is established in two stages, both fail-closed:

        1. **Federated path without evidence is refused.** Evidence exists only for OIDC (claim
           `email_verified`, OIDC Core 5.1). **SAML and LDAP have none** — no
           standard attribute says that a directory verified the address, and in many directories the user maintains a
           `mail` attribute themselves. So that this does not depend on the
           caller's memory: `faktor` from `_FEDERATED_FACTORS` demands
           `email_bestaetigt is True`, a forgotten argument refuses. LDAP writes the
           factor `password` and cannot be recognised by it — there the caller passes
           `email_bestaetigt=False`.
        2. **Otherwise the marker on the account decides** (`users.email_verified`, read by
           `_beleg_am_konto`). The address from an IdP without the claim is, since this version, written into the account quite
           normally (otherwise an existing installation would lose account name and
           `Remote-Email`) — it just must not carry anything. If that hung on the parameter alone, the
           protection would be a question of the sign-in path: the same record, signed in once via a local
           path (magic link, password), would come in with `None` and would have been promoted.
           The marker is in the database and therefore applies to every path.

        The username remains unaffected — the constructor guard is responsible for it,
        which forbids allowlist names as soon as accounts arise by themselves.

        **Never again after a withdrawal by the identity provider** (G6): if the provider has taken the
        instance's last admin (`apply_idp_groups`, H-5), the allowlist promotes
        nobody any more — otherwise it would make the person admin "by hand" again in the same login
        and first owner, whom no provider withdraws any more (audit `admin_bootstrap_denied
        nach_idp_entzug`). The way back into the panel is then the one-time token (`/auth/claim-admin`,
        issued immediately) and `tinysesam owner`.
        """
        ids = {str(i).strip().lower() for i in self.cfg.admin_identifiers if str(i).strip()}
        if not ids or not user or user["is_admin"] or self.admin_exists():
            return False
        adressen = {i for i in ids if "@" in i}
        namen = ids - adressen
        trifft_adresse = str(user["email"] or "").lower() in adressen
        trifft_name = str(user["username"] or "").lower() in namen
        if not (trifft_adresse or trifft_name):
            return False
        if self.store.get_setting("allowlist_nach_idp_entzug"):
            # G6: The identity provider has withdrawn the instance's last admin
            # (`apply_idp_groups`) — the allowlist does not open again afterwards, for nobody.
            security.seclog.warning(
                "First admin NOT granted: %s is in admin_identifiers, but the identity "
                "provider has withdrawn the instance's last admin — the allowlist does not open "
                "again afterwards. Emergency route: tinysesam owner --db <file> <user> or "
                "/auth/claim-admin.", security.fuer_log(user["username"]))
            self.audit("admin_bootstrap_denied", user["username"], detail="nach_idp_entzug")
            return False
        if trifft_adresse and not trifft_name:
            # Two stages, both fail-closed: explicit evidence from the sign-in path wins.
            # If the path is silent (`None`), a federated factor refuses on principle — even
            # if it simply forgot the argument —, and otherwise the marker
            # on the account decides.
            if email_bestaetigt is not None:
                belegt, grund = email_bestaetigt is True, "email_unbestaetigt"
            elif (faktor or "") in self._FEDERATED_FACTORS:
                belegt, grund = False, f"ohne_beleg:{faktor or '?'}"
            else:
                belegt, grund = _beleg_am_konto(user), "email_unbestaetigt"
            if not belegt:
                security.seclog.warning(
                    "First admin NOT granted: %s carries the allowlist address %s, but there is no "
                    "confirmation evidence for this sign-in path (%s) (OIDC: claim "
                    "email_verified; SAML and LDAP have none; otherwise the note on the account). "
                    "The address stays on the account, it just does not support this decision. "
                    "Evidenced route: /auth/claim-admin.",
                    security.fuer_log(user["username"]), security.fuer_log(user["email"]),
                    faktor or "?")
                self.audit("admin_bootstrap_denied", user["username"], detail=grund)
                return False
        self.store.set_admin(user["id"], True)
        self._erster_owner(user["id"])
        self.audit("admin_bootstrap", user["username"], detail="admin_identifiers")
        security.seclog.warning("Erst-Admin per admin_identifiers vergeben: %s",
                                security.fuer_log(user["username"]))
        return True

    def _claim_datei_auto(self) -> str:
        """`<db_path>.claim` — where the one-time token goes when stderr is not a console (T-17).

        Next to the database, because whoever operates the service may write there anyway, and because
        `<db_path>.key` also lies there. Empty without a file (`:memory:`): then only stderr remains.
        """
        db = str(self.cfg.db_path or "").strip()
        return "" if db in ("", ":memory:") else db + ".claim"

    def _claim_datei_weg(self) -> None:
        """Remove the automatically created token file — after redemption, and at startup
        when there is no token (any more). A self-chosen `admin_claim_token_file` stays
        in place (its path may be a mounted secret); its content is then invalid."""
        pfad = self._claim_datei_auto()
        if pfad:
            try:
                os.remove(pfad)
            except FileNotFoundError:
                pass  # already gone (never created or already redeemed) — exactly the target state
            except OSError as e:
                security.seclog.warning("Token file %s could not be removed (%s) — its "
                                        "content is invalid.", pfad, type(e).__name__)

    def _admin_claim_bekanntgeben(self, token: str) -> None:
        """Show the value of the first-admin one-time token to the **operator** — not to the log.

        Up to 0.18.x the token stood in plaintext in the line that `security.seclog` writes. If
        `security_log` is set, that is exactly the file the bundled fail2ban jail
        points to: it came into being without a permissions spec (measured `-rw-rw-r--`), logrotate keeps it
        for weeks and every log shipping takes it along. Whoever could read it and had any
        account on the instance called `/auth/claim-admin?token=…` and was admin (B5-03).

        The value therefore goes to **stderr** — the console of whoever starts the service, and
        the only recipient the docstring of `admin_claim_token` ever meant. Where
        stderr itself is collected (journal, container logs), the operator names a file with
        `admin_claim_token_file`; TinySesam creates it with 0600. Only **where** the token is
        goes into the log now.

        **Since 0.22.0 (T-17) also without this setting:** if stderr is not a console (container,
        journal, pipe — `sys.stderr.isatty()` false), TinySesam writes the token to
        `<db_path>.claim` (0600) and names only the path. Until then it stood there in plaintext in
        `docker logs` — directly before the line "The value is deliberately NOT in the log" (German runtime text). Without a
        database file (`:memory:`) or if the file is not created, only stderr remains, and
        the text honestly says that the value is then in the service's log. After redemption
        the file disappears (`_claim_datei_weg`).
        """
        ttl = self.cfg.admin_claim_ttl_min
        pfad = str(self.cfg.admin_claim_token_file or "").strip()
        konsole = _stderr_ist_konsole()
        automatisch = False
        if not pfad and not konsole:
            pfad = self._claim_datei_auto()
            automatisch = bool(pfad)
        # What the line in the log says must be true — also in the fallback. Up to 0.21.x it said there
        # "The value is deliberately NOT in the log" while in the container it stood two lines above.
        wohin = ("is on the console (stderr), not in this line" if konsole else
                 "is on stderr — and stderr is NOT a console here: the value is therefore in the "
                 "service's log (journal, docker logs). Remedy: set admin_claim_token_file "
                 "or use a database file instead of :memory:")
        geschrieben = False
        if pfad:
            try:
                # Open without O_TRUNC and set the permissions on the descriptor BEFORE the secret
                # goes in: with an already existing file the mode parameter of
                # os.open ignores the default, and a chmod afterwards would leave a window open.
                fd = os.open(pfad, os.O_CREAT | os.O_WRONLY, 0o600)
                try:
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, 0o600)
                    os.ftruncate(fd, 0)
                    os.write(fd, (token + "\n").encode("utf-8"))
                finally:
                    os.close(fd)
                wohin = f"is in {pfad} (mode 0600), not in the log"
                geschrieben = True
            except OSError as e:
                # No reason to refuse startup — but the operator must get the token,
                # otherwise they cannot reach their own instance.
                name = "the token file" if automatisch else "admin_claim_token_file"
                _auf_stderr(f"TinySesam: {name} {pfad} not writable "
                            f"({type(e).__name__}) — the token is here instead:")
                wohin = f"{wohin} ({pfad} was not writable: {type(e).__name__})"
        if not geschrieben:
            _auf_stderr(f"TinySesam: No admin exists. Set the first admin — sign in, then "
                        f"/auth/claim-admin?token={token} (valid {ttl} minutes, can be redeemed "
                        f"exactly once).")
        security.seclog.warning(
            "No admin exists. The one-time token for /auth/claim-admin %s — valid %d "
            "minutes, can be redeemed exactly once.", wohin, ttl)

    def admin_claim_token(self) -> Optional[str]:
        """Path 2: one-time token. As long as no admin exists, there is a token that can be redeemed
        exactly once (`/auth/claim-admin?token=…`). The value goes to stderr at startup
        or into `admin_claim_token_file` (0600) — whoever operates the server has it; whoever merely knows the
        URL or can read the log does not (B5-03). Expires."""
        # No panel, no local admins → no token. Otherwise a pure OIDC app would have a
        # path to admin that it never provided for.
        if not self.cfg.admin_enabled or self.cfg.admin_claim_ttl_min <= 0 or self.admin_exists():
            return None
        raw = self.store.get_setting("admin_claim")
        now = _jetzt()
        if raw:
            token, exp = raw.split(":", 1)
            if int(exp) > now:
                return token
        token = secrets.token_urlsafe(24)
        self.store.set_setting("admin_claim", f"{token}:{now + self.cfg.admin_claim_ttl_min * 60}")
        return token

    def _consume_admin_claim(self, token, user) -> bool:
        """Redeem the one-time token and make this account admin. Valid exactly once."""
        if not token or not user or not self.cfg.admin_enabled or self.admin_exists():
            return False
        raw = self.store.get_setting("admin_claim")
        if not raw:
            return False
        want, exp = raw.split(":", 1)
        if int(exp) <= _jetzt() or not secrets.compare_digest(token, want):
            return False
        self.store.set_setting("admin_claim", "")     # one-time
        self._claim_datei_weg()                        # the file now holds only invalid content (T-17)
        self.store.set_admin(user["id"], True)
        self._erster_owner(user["id"])
        self.audit("admin_bootstrap", user["username"], detail="claim_token")
        security.seclog.warning("Erst-Admin per Einmal-Token vergeben: %s",
                                security.fuer_log(user["username"]))
        return True

    def _admin_claim_failure(self, username, ip) -> None:
        """Record a failed first-admin claim — audit log and security log (B5-16)."""
        self.audit("admin_claim_fail", username, ip)
        security.seclog.warning("%s user=%s ip=%s method=claim_admin", security.LOG_PRUEFUNG,
                                security.fuer_log(username), security.fuer_log(ip))

    # ---------- Demo mode ----------
    _DEMO_USERS = ("demo", "demoadmin")

    def _seed_demo(self) -> None:
        """Create sample accounts (idempotent). Requires `demo_mode=True`.

        The check has been **here** since 2026-09-21 and no longer only at the caller in the constructor.
        The docstring promised it before — the body did not keep it: a direct call
        with `demo_mode=False` created `demo` and `demoadmin`, the latter with `is_admin=1` and the
        documented default password, both able to sign in at once and without a warning in the log.
        """
        if not self.cfg.demo_mode:
            raise ConfigError(
                "seed_demo() requires demo_mode=True. Without the switch two accounts able to "
                "sign in with a known password would be created — one of them admin — and the "
                "warning in the log would be missing.")
        ids = []
        for name in self._DEMO_USERS:
            u = self.store.get_user_by_name(name)
            if u:
                ids.append(str(u["id"]))
                continue
            uid = self.create_user(name, password=self.cfg.demo_password, is_admin=(name == "demoadmin"))
            if self.cfg.pin_enabled:
                self.set_pin(uid, self.cfg.demo_pin)
            ids.append(str(uid))
        self.store.set_setting("demo_users", ",".join(ids))

    def _purge_demo(self) -> int:
        """Remove the accounts created by `_seed_demo` again — exactly those, not ones of the same name."""
        raw = self.store.get_setting("demo_users") or ""
        n = 0
        for sid in filter(None, raw.split(",")):
            u = self.store.get_user(int(sid))
            if u and u["username"] in self._DEMO_USERS:
                # Via the one deletion path (H-13): if `_seed_demo` later recreates the names, the
                # new account would otherwise see the old one's events as its own (H-7).
                self.store.konto_entfernen(u["id"])
                n += 1
        self.store.set_setting("demo_users", "")
        return n

    #: What an account dict of the public surface carries (`current_user`, `session_user`,
    #: `pending_user`, `get_user`, `find_user`, `identifier_taken`, `verify_api_key`,
    #: `LoginResult.user`, the `require_*` guards) — the columns that describe the account. The
    #: store's bookkeeping stays outside: counting buckets (`topf_name`, `topf_mail`),
    #: watermarks (`name_versuch_ab` …), origin and self-choice of the name (`name_quelle`,
    #: `name_selbst_gewaehlt`), the last confirmation by the IdP (`idp_bestaetigt_at`). Up to
    #: 0.21.x the whole row went out, with German column names; since 0.22.0 the
    #: public surface is English (PO decision 2026-09-27), and internals do not belong in
    #: its guarantee. A list of the allowed rather than the forbidden columns: a new column of the
    #: store does not silently become part of the guarantee. Depending on the path, `_via` and `_key_kind` are added.
    _KONTO_FELDER = ("id", "username", "display_name", "email", "email_verified", "is_admin",
                     "is_owner", "roles", "is_service", "disabled", "first_login_at",
                     "mfa_enroll_until", "created_at")

    @classmethod
    def _als_dict(cls, zeile) -> Optional[dict]:
        """Return an account row as what the signature promises — a `dict` with the
        fields from `_KONTO_FELDER`.

        The user-facing methods have always been annotated `-> Optional[dict]` and returned
        a `sqlite3.Row`. The package carries `Typing :: Typed` and a `py.typed` — the guarantee
        was just never measured. In practice it shows as soon as someone believes the annotation:
        `u.get("email")` does not exist on a Row, and the `AttributeError` comes from a
        line that, according to the type, cannot be wrong. At the store level the Row remains — there
        it is documented and intended, with all columns.
        """
        if zeile is None:
            return None
        da = set(zeile.keys())
        return {k: zeile[k] for k in cls._KONTO_FELDER if k in da}

    def get_user(self, user_id) -> Optional[dict]:
        """Read an account by ID, or None."""
        return self._als_dict(self.store.get_user(user_id))

    # ---------- Password login ----------
    def find_user(self, identifier) -> Optional[dict]:
        """Look up an account by login identifier — depending on `config.login_identifier`.

        "username" = username only, "email" = email only, "both" = both in the same field.
        With "both" the @ decides the order; both are still searched, so that a
        username containing @ does not suddenly become unfindable."""
        ident = (identifier or "").strip()
        if not ident:
            return None
        mode = getattr(self.cfg, "login_identifier", "both")
        if mode == "username":
            gefunden = self.store.get_user_by_name(ident)
        elif mode == "email":
            gefunden = self.store.get_user_by_email(ident)
        elif "@" in ident:
            gefunden = self.store.get_user_by_email(ident) or self.store.get_user_by_name(ident)
        else:
            gefunden = self.store.get_user_by_name(ident) or self.store.get_user_by_email(ident)
        return self._als_dict(gefunden)

    def _check_password(self, username, password) -> Optional[dict]:
        """Check username/email + password. Returns the account or None — and takes equally long for both outcomes (no account probing)."""
        u = self.find_user(username)
        if not u or u["disabled"]:
            dummy_verify(password)   # equalise timing (no user enumeration)
            return None
        h = self.store.get_password_hash(u["id"])
        if not h:
            dummy_verify(password)
            return None
        if not verify_password(password, h):
            return None
        if needs_rehash(h):
            self.store.set_password_hash(u["id"], hash_password(password))
        return u

    # ---------- LDAP / lldap (password backend) ----------
    #: Sources that bind a foreign identity via a stable identifier (F-11). OIDC is not
    #: among them: with `issuer`+`sub` it has always had its own, more stable mapping.
    FEDERATED_SOURCES = ("ldap", "saml")
    #: Placeholder identifier for an account that came via a source WITHOUT a stable identifier (A-4).
    #: The row in `federated_identity` merely says "this account comes from LDAP/SAML" — otherwise
    #: it would count as local for `federated_only()` and would get a reset link whose password
    #: then wins over the directory. Unique per account (primary key source+identifier),
    #: never read for a mapping, and a real identifier replaces it at the next login —
    #: through the same door as case 4 (`_nachbindung_grund`).
    _OHNE_KENNUNG = Store.OHNE_KENNUNG

    def _fremde_identitaet_aufloesen(self, quelle: str, kennung: str, username: str,
                                     anlegen, name_zuordnen: bool = True,
                                     nur_konto: Optional[int] = None) -> Optional[dict]:
        """Find, bind or create a local account for a foreign identity (F-11).

        `kennung` is the **stable** identifier from the directory (objectGUID/entryUUID for LDAP,
        NameID for SAML), `username` the name by which mapping was done alone up to 0.19.0.
        `anlegen()` creates a new account and returns its ID or `None`.

        Four cases, and the third is the actual bolt:

        1. **The identifier is bound** → this account, even if the name has changed.
           That is exactly what the binding is for: a rename in the directory is not an account change.
        2. **Identifier unknown, name free** → create and bind.
        3. **Identifier unknown, name belongs to an account that already carries ANOTHER identifier**
           → **reject**. That is the attack: a new account arises in the directory under the name of a
           deleted person, and without this bolt it would inherit that person's local roles.
        4. **Identifier unknown, name belongs to a still unbound account** → bind afterwards. This is
           the existing-data case: accounts from before F-11 have no identifier, and at some point
           each of them has to get one. The PO explicitly approved this path for this round;
           it relies on the name once more, but only a
           single time per account, and it leaves an audit line. Since 2026-09-26 only
           through one door (`_nachbindung_grund`): not after the deadline
           (`federation_name_binding_days`, G1 — otherwise a dormant account would fall to the next
           person with that name) and never for a self-chosen name
           (`users.name_selbst_gewaehlt`, G2-N — otherwise a local account renames itself after
           someone from the directory and inherits their groups) and never for a name that
           another source brought along on creation (`users.name_quelle`, attack round
           2026-09-26 — the same attack via `preferred_username` or SAML), unless the
           operator has opened the binding for this account (`federation_unbind`). Otherwise
           it is rejected as in case 3. The same applies to the replacement of an origin placeholder.

        Without an identifier (the directory delivers none) it stays with the name — the unprotected
        state. A line per source says so, and `federation_require_stable_id=True` turns
        that into a rejection. The FIRST mapping of an existing account goes through
        the same door as case 4; an account the source already knows (placeholder) stays.

        `name_zuordnen=False`: the name says nothing about the person — an unverified
        address from a source the operator does not trust (`*_email_trusted=False`). Then
        there is neither case 4 (binding afterwards via the name) nor a mapping without an identifier: whoever
        registers the address of a local account as a name at the IdP would otherwise take over exactly
        that account (attack on the third round). Without an identifier it is rejected, with an identifier
        bound or newly created — never via the name.

        `nur_konto`: the resolution may only end at THIS account (`_check_ldap`: the account whose
        local secret is checked under the same identifier). If it leads to another one — a
        binding, a name, a creation —, it is rejected before anything is written
        (`_kennung_zweier_konten`). None: no restriction.
        """
        jetzt = _jetzt()
        roh = str(kennung or "")
        kennung = roh.strip()
        formfehler = self._kennung_formfehler(roh)
        if formfehler:
            security.seclog.warning("%s: identifier %s rejected (user=%s)", quelle,
                                    "with edge or control characters" if formfehler == "Rand-/Steuerzeichen"
                                    else "in placeholder form", security.fuer_log(username))
            self.audit(f"{quelle}_kennung_ungueltig", username, detail=formfehler)
            return None
        if not kennung and not name_zuordnen:
            security.seclog.warning(
                "%s: the name is an unverified address and there is no stable identifier (user=%s) — "
                "rejected. A mapping via this name would be a takeover. Remedy: "
                "set %s_attr_id or trust the source (%s_email_trusted).",
                quelle, security.fuer_log(username), quelle, quelle)
            self.audit(f"{quelle}_ohne_kennung", username, detail="abgewiesen: Adresse als Name")
            return None
        if not kennung:
            if self.cfg.federation_require_stable_id:
                security.seclog.warning(
                    "%s: no stable identifier in the response (user=%s) — rejected because "
                    "federation_require_stable_id=True. The attribute is named in %s_attr_id.",
                    quelle, security.fuer_log(username), quelle)
                self.audit(f"{quelle}_ohne_kennung", username, detail="abgewiesen")
                return None
            if security.einmal_melden(f"fed_ohne_kennung:{quelle}"):
                security.seclog.warning(
                    "%s delivers no stable identifier — the mapping hangs on the username, "
                    "as before 0.20.0. Whoever renames in the directory or recreates a deleted account "
                    "under the same name gets the same local account. "
                    "Remedy: set %s_attr_id (entryUUID, objectGUID) and then "
                    "federation_require_stable_id=True.", quelle, quelle)
            gebunden_uid = None
        else:
            gebunden_uid = self.store.get_federated_user(quelle, kennung)

        if gebunden_uid:
            if nur_konto is not None and int(gebunden_uid) != int(nur_konto):
                self._kennung_zweier_konten(quelle, username, nur_konto, gebunden_uid)
                return None
            u = self.store.get_user(gebunden_uid)
            return self._als_dict(u) if u else None

        u = self.store.get_user_by_name(username) if name_zuordnen else None
        if nur_konto is not None and (u is None or int(u["id"]) != int(nur_konto)):
            self._kennung_zweier_konten(quelle, username, nur_konto, u["id"] if u else None)
            return None
        if u is None:
            uid = anlegen()
            if uid is None:
                return None
            self.store.link_federated(quelle, kennung or f"{self._OHNE_KENNUNG}{uid}", uid, jetzt)
            neu = self.store.get_user(uid)
            return self._als_dict(neu) if neu else None

        vorhandene = self.store.get_federated_kennung(quelle, u["id"])
        # Only the origin placeholder, no identifier: treated as unbound (case 4). It is resolved
        # only when the door is open — a rejection leaves the account as it was.
        platzhalter = bool(vorhandene) and str(vorhandene).startswith(self._OHNE_KENNUNG)
        if not kennung:
            if not vorhandene:
                # First mapping of an existing account, via the name alone: the same door
                # as case 4 (G1, G2-N). Then record the origin (A-4) — see _OHNE_KENNUNG.
                if not self._namensbindung_erlaubt(quelle, "", u, username):
                    return None
                self.store.link_federated(quelle, f"{self._OHNE_KENNUNG}{u['id']}", u["id"], jetzt)
                self.store.namensbindung_schliessen(quelle, u["id"])
        else:
            if vorhandene and not platzhalter and vorhandene != kennung:
                # Case 3: The account belongs to someone else, even if the name is the same.
                security.seclog.warning(
                    "%s: account %s is already bound to a different identifier — signing in with "
                    "a new identifier under the same name is rejected. The directory "
                    "was probably renamed or an account recreated. The operator releases "
                    "the binding if that is intended.", quelle, security.fuer_log(username))
                self.audit(f"{quelle}_kennung_wechsel", str(u["username"]),
                           detail="rejected: account already carries a different identifier")
                return None
            if not vorhandene or platzhalter:
                # Case 4: binding afterwards — a single time per account, only through the door, and it
                # is logged.
                if not self._namensbindung_erlaubt(quelle, kennung, u, username):
                    return None
                if platzhalter:
                    self.store.unlink_federated(quelle, u["id"])
                self.store.link_federated(quelle, kennung, u["id"], jetzt)
                self.store.namensbindung_schliessen(quelle, u["id"])
                self.audit(f"{quelle}_kennung_gebunden", str(u["username"]),
                           detail="nachgebunden beim Login")
        return self._als_dict(self.store.get_user(u["id"]))

    def _kennung_zweier_konten(self, quelle: str, username: str, lokal_id, ziel_id) -> None:
        """Reject the sign-in via `quelle`: the typed-in identifier locally belongs to account
        `lokal_id`, but the directory entry to another one (`ziel_id`, None = it would be newly
        created). Log line with remedy, audit `<quelle>_kennung_abgewiesen grund=kennung_zweier_konten`.
        The caller then returns None, the route books a failed attempt (review round
        2026-09-27, p1-d)."""
        security.seclog.warning(
            "%s: sign-in under %s rejected — the identifier is the name or address of account %s, but "
            "the directory entry belongs to %s. Under one identifier TinySesam never checks the "
            "secrets of two people: the sign-in of one would otherwise clear the lockout counters under "
            "which the other is being guessed. Remedy: rename the local account (panel or "
            "`tinysesam rename`) or change the name in the directory.",
            quelle.upper(), security.fuer_log(username), lokal_id,
            f"account {ziel_id}" if ziel_id is not None else "no account (it would be newly created)")
        self.audit(f"{quelle}_kennung_abgewiesen", username,
                   detail=f"grund=kennung_zweier_konten lokal={lokal_id} "
                          f"verzeichnis={ziel_id if ziel_id is not None else 'neu'}")

    @classmethod
    def _kennung_formfehler(cls, roh) -> Optional[str]:
        """Is this value usable as a foreign identifier? None = yes, otherwise the reason (sign-in and
        existing-data binding check with the SAME function).

        * Leading/trailing whitespace or control characters: trimmed, the identifier would fall on the binding of
          ANOTHER account (`chefin\u2028` → `chefin`, counter-check). Something like that does not
          come from a real directory — reject instead of making it fit.
        * The form of the origin placeholder: via `get_federated_user` it would hit exactly the
          account whose ID it names. A directory delivers UUID/GUID — so a manipulated
          attribute."""
        roh = str(roh or "")
        if roh != roh.strip() or name_ungueltig(roh):
            return "Rand-/Steuerzeichen"
        if roh.startswith(cls._OHNE_KENNUNG):
            return "Platzhalter-Form"
        return None

    #: Why an account is not bound via the name (`_nachbindung_grund`) — short code and
    #: explanation, for the report of `federation_bind_existing` (`reason`). English since 0.22.0
    #: (PO decision 2026-09-27); the codes up to 0.21.x remain in audit and security log.
    NAME_BINDING_REFUSALS = {
        "address_as_name": "the name says nothing about the person (control characters, or the "
                           "unverified mail value of a source that is not trusted)",
        "invalid_identifier": "the identifier is unusable (leading/trailing or control characters, "
                              "or placeholder form)",
        "conflict": "the identifier already belongs to another account",
        "bound_elsewhere": "the account already carries a different identifier",
        "self_chosen_name": "the name was chosen by the person (sign-up or rename) and says nothing "
                            "about who has that name in the directory",
        "name_from_other_source": "the name comes from another source that created the account "
                                  "(OIDC, SAML or LDAP) and says nothing about who has that name "
                                  "in this one",
        "binding_window_expired": "the window for binding by name has passed "
                                  "(federation_name_binding_days)",
    }
    #: The same reasons in audit (`<quelle>_namensbindung_zu … grund=`) and security log: code
    #: and text of 0.21.x. These lines do not change with the translation — operators'
    #: filters depend on them (PO decision 2026-09-27).
    _NACHBINDUNG_PROTOKOLL = {
        "address_as_name": ("adresse_als_name", "the name says nothing about the person "
                            "(control characters, or the unverified mail value of a source that "
                            "is not trusted)"),
        "invalid_identifier": ("kennung_ungueltig", "the identifier is unusable (edge/control characters "
                               "or placeholder form)"),
        "conflict": ("konflikt", "the identifier already belongs to another account"),
        "bound_elsewhere": ("anders_gebunden", "the account already carries a different identifier"),
        "self_chosen_name": ("name_selbst_gewaehlt", "the name was chosen by the user (registration "
                             "or rename) and says nothing about who has that name in the directory"),
        "name_from_other_source": ("name_aus_quelle", "the name comes from another source that created the "
                                   "account (OIDC, SAML or LDAP) and says nothing about who has "
                                   "that name in this one"),
        "binding_window_expired": ("frist", "the window for binding by name has "
                                   "passed (federation_name_binding_days)"),
    }

    def _nachbindung_grund(self, quelle: str, kennung: str, konto, *, name_belegt: bool = True,
                           frist: bool = True) -> Optional[str]:
        """May the account `konto` be bound to the foreign identifier `kennung` via its name?
        `None` = yes, otherwise the reason (key from `NAME_BINDING_REFUSALS`; in audit
        and security log the code of 0.21.x, `_NACHBINDUNG_PROTOKOLL`).

        ONE decision for the sign-in (case 4, replacement of a placeholder, first mapping without an
        identifier — `kennung=""`) and for the existing-data binding (`federation_bind_existing`). Copied,
        the two drifted apart, and one path would bind what the other rejects (G1).

        * `name_belegt=False`: the name is the unverified `mail` value of a source that is not
          trusted (`_ldap_name_belegt`) — it says nothing about the person.
        * Identifier: form (`_kennung_formfehler`), not already bound to another account, the
          account does not already carry another one (case 3).
        * **Self-chosen name** (G2-N): an account that registered or was renamed itself
          (`users.name_selbst_gewaehlt`) is never bound via the name. Reproduced:
          `eve` renames herself to `chefin`, a name that exists only in the directory; the
          real chefin signs in via LDAP, her identifier lands on eve's account, the role from
          `ldap_group_role_map` too — and eve keeps signing in with her password.
        * **Name from another source** (`users.name_quelle`, attack round 2026-09-26): an
          account that OIDC, SAML or LDAP created carries the name the person has THERE —
          at an IdP with self-registration a self-chosen one. Reproduced: `chefin` via
          OIDC, then the real chefin via LDAP; her identifier and her roles ended up in the
          OIDC account, and the attacker kept signing in via OIDC. The same source is
          exempt: it replaces its own placeholder with the real identifier.
        * **Deadline** (`frist=True`, G1): `federation_name_binding_days` from the source's marker or
          the creation of the account, whichever is later (`_namensfrist_offen`). The existing-data binding does not check
          it — it IS the operator's explicit path.

        The last three are lifted by a binding opened by the operator (`federation_unbind`,
        table `namensbindung`)."""
        if not name_belegt or name_ungueltig(str(konto["username"] or "")):
            return "address_as_name"
        if kennung:
            if self._kennung_formfehler(kennung):
                return "invalid_identifier"
            anderes = self.store.get_federated_user(quelle, kennung)
            if anderes is not None and int(anderes) != int(konto["id"]):
                return "conflict"
            vorhandene = self.store.get_federated_kennung(quelle, konto["id"])
            if vorhandene and not vorhandene.startswith(self._OHNE_KENNUNG) and vorhandene != kennung:
                return "bound_elsewhere"
        jetzt = _jetzt()
        if self.store.namensbindung_offen(quelle, konto["id"], jetzt):
            return None
        try:
            selbst = bool(konto["name_selbst_gewaehlt"])
        except (IndexError, KeyError):
            selbst = False       # row without the column (foreign source): like existing data
        if selbst:
            return "self_chosen_name"
        try:
            herkunft = str(konto["name_quelle"] or "")
        except (IndexError, KeyError):
            herkunft = ""        # row without the column (foreign source): like existing data
        if herkunft and herkunft != quelle:
            return "name_from_other_source"
        if frist and not self._namensfrist_offen(quelle, konto, jetzt):
            return "binding_window_expired"
        return None

    def _namensbindung_erlaubt(self, quelle: str, kennung: str, konto, username: str) -> bool:
        """The door for case 4 at sign-in: `_nachbindung_grund`, and a rejection as in
        case 3 — log line with identifier and remedy, audit `<quelle>_namensbindung_zu`."""
        grund = self._nachbindung_grund(quelle, kennung, konto)
        if grund is None:
            return True
        kuerzel, text = self._NACHBINDUNG_PROTOKOLL.get(grund, (grund, grund))
        tage = int(self.cfg.federation_name_binding_days)
        security.seclog.warning(
            "%s: account %s (user_id=%s) is not bound by name to the identifier %s — %s. "
            "The sign-in is rejected. If it is the same person: "
            "auth.federation_unbind('%s', %s) opens the binding for the next sign-in "
            "(%d day(s)); existing accounts are bound by auth.federation_bind_existing('%s').",
            quelle, security.fuer_log(username), konto["id"],
            security.fuer_log(kennung) if kennung else "(none)",
            text, quelle, konto["id"], max(tage, 1), quelle)
        self.audit(f"{quelle}_namensbindung_zu", str(konto["username"]),
                   detail=f"grund={kuerzel} kennung={kennung or '-'}")
        return False

    def _foederation_seit(self, quelle: str) -> int:
        """From when does the deadline for binding via the name apply (G1)? The source's marker
        (`Store.foederation_seit`), set at the first start with the source switched on — or
        here, if it is used without the switch (a client set by hand). Exactly once:
        a marker that were set anew at every start would grant every restart a new
        deadline. Only readable: then from now on."""
        try:
            return self.store.foederation_seit(quelle, _jetzt())
        except (sqlite3.OperationalError, ValueError):
            return _jetzt()

    def _namensfrist_offen(self, quelle: str, konto, jetzt: int) -> bool:
        """Does the name still bind this account (G1)? `federation_name_binding_days` days from the
        source's marker or the creation of the account, whichever is later — a pre-creation in the panel
        thus has its own deadline. `-1` = always, `0` = never."""
        tage = int(self.cfg.federation_name_binding_days)
        if tage < 0:
            return True
        ab = max(int(konto["created_at"] or 0), self._foederation_seit(quelle))
        return jetzt < ab + tage * 86400

    def _namensbindung_bestand_melden(self, quelle: str, seit: int) -> None:
        """Startup message (G1): how many accounts still carry no identifier for this source, and until
        when does the name bind them? Only as long as the door is open for existing data — afterwards
        each rejection reports itself, and a local admin would otherwise stay in the log forever."""
        tage = int(self.cfg.federation_name_binding_days)
        if tage <= 0:
            return            # 0: explicit only; -1: the configuration check warns
        bis = seit + tage * 86400
        if _jetzt() >= bis:
            return
        try:
            konten = self.store.ohne_bindung(quelle)
        except sqlite3.OperationalError:
            return
        if not konten:
            return
        ohne_pw = sum(1 for k in konten if not k["hat_passwort"])
        weg = (f"auth.federation_bind_existing('{quelle}')" if quelle == "ldap"
               else f"auth.federation_bind_existing('{quelle}', mapping={{name: kennung}})")
        security.seclog.warning(
            "%s: %d account(s) without a binding to an identifier of the source (of which %d without a local "
            "password). Until %s (federation_name_binding_days=%d) the next sign-in binds "
            "them via the name, afterwards no longer — a dormant account would otherwise fall to the next "
            "person with the same name. Bind now: %s (dry run), then with apply=True.",
            quelle.upper(), len(konten), ohne_pw,
            time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(bis)), tage, weg)

    def federation_unbind(self, source: str, user_id: int) -> int:
        """Release an account's binding to a foreign identity (operator path) — and open the
        binding via the name for the next sign-in. Returns the number of released
        bindings (0: the account was not bound).

        Needed when the directory was really moved — then the old identifier is dead
        and the account is supposed to get the new one. That this is a deliberate step and not a
        side effect of a sign-in is the point.

        Since 2026-09-26 (G1, G2-N) the call at the same time opens the door for case 4: the next
        sign-in via this source binds the account via its name, even after the deadline
        (`federation_name_binding_days`), even with a self-chosen name and even with a name
        from another source (`users.name_quelle`) — for
        `max(federation_name_binding_days, 1)` days or until the binding is in place. On an
        unbound account the call thus means "open for the next sign-in" (pre-creation,
        returnee, an account that missed the deadline). The rejection in the log names the call."""
        weg = self.store.unlink_federated(source, user_id)
        u = self.store.get_user(user_id)
        bis = None
        if u is not None:
            bis = _jetzt() + max(int(self.cfg.federation_name_binding_days), 1) * 86400
            self.store.namensbindung_oeffnen(source, user_id, bis)
        self.audit(f"{source}_kennung_geloest", str(u["username"]) if u else None,
                   detail=f"namensbindung_offen_bis={bis}" if bis else None)
        return weg

    def federation_bind_existing(self, source: str, *, mapping: Optional[dict] = None,
                                 apply: bool = False) -> dict:
        """Bind existing accounts to their identifier in LDAP/SAML without waiting for their sign-in (G1).

        Accounts from before identifiers (F-11) bind at the next sign-in via
        their name — but only within the deadline (`federation_name_binding_days`). A dormant
        account never signs in; that is exactly what would otherwise fall to the next person with the name. This
        method binds the existing accounts explicitly. **The default is a dry run**: only with
        `apply=True` is anything written.

        * **LDAP without `mapping`**: one directory search per account without an identifier
          (`LDAPClient.eintrag_suchen`, service account or anonymous, without the user's password). It
          must be exactly ONE entry. A failure (`VerzeichnisNichtErreichbar`) aborts —
          before the first write: everything is searched first, then bound.
        * **`mapping={account name: identifier}`** — for SAML (there is no search path without sign-in;
          the NameIDs e.g. from an export of the IdP) or for individual LDAP accounts. Runs without a
          directory.

        Each account is decided with the same helper as at sign-in
        (`_nachbindung_grund`, without the deadline). Accounts with a local password are only reported
        (`local_password`): their name may belong to a different person than the entry in the
        directory — the operator opens them individually with `federation_unbind`.

        Returns (lists of entries with `user_id`, `username`, `local` = display name/address
        here, `directory` = the same in the directory, `identifier`, for rejections `reason`):

        * `bound` — bound (in the dry run: would be bound). **Read before `apply`**: if a
          name was already reused before the run, this method too binds the wrong person —
          `local` and `directory` side by side show it.
        * `conflict` — the identifier already belongs to another account (`bound_to`), or two
          accounts name the same one
        * `ambiguous` — more than one entry in the directory (`matches`: how many)
        * `not_in_directory`, `no_identifier` — no entry, or one without a stable identifier
          (`ldap_attr_id`)
        * `refused` — with `reason`: one from `NAME_BINDING_REFUSALS` or `no_account`,
          `service_account`, `disabled`, `already_bound`
        * `local_password` — account with a local password, only reported

        Plus `source` and `applied`. Up to 0.21.x the keys and reasons were German
        (`quelle`, `ausgefuehrt`, `gebunden`, `abgewiesen`/`grund` …; PO decision 2026-09-27,
        table in the CHANGELOG for 0.22.0). Each binding writes `<quelle>_kennung_gebunden` with
        `detail=migration`, the run a summary line into the security log — both as before.
        There is no CLI command: LDAP and SAML run only embedded, and the CLI does not know the
        configuration."""
        if source not in self.FEDERATED_SOURCES:
            raise ValueError(f"source must be one of {self.FEDERATED_SOURCES}, not {source!r}")
        suchen = None
        if mapping is None:
            if source != "ldap":
                raise ValueError(
                    "SAML has no lookup path without a sign-in — the identifiers come as "
                    "mapping={account name: NameID} (e.g. from an export of the IdP).")
            if not self.ldap:
                raise ConfigError("LDAP is not set up (ldap_enabled, ldap_url) — or pass "
                                  "mapping={account name: identifier}.")
            suchen = getattr(self.ldap, "eintrag_suchen", None)
            if not callable(suchen):
                raise ConfigError("The LDAP client in use cannot search (eintrag_suchen) — "
                                  "pass mapping={account name: identifier}.")
        bericht: dict = {"source": source, "applied": bool(apply), "bound": [],
                         "conflict": [], "ambiguous": [], "not_in_directory": [],
                         "no_identifier": [], "refused": [], "local_password": []}
        # Account → identifier from the mapping (None: search in the directory).
        paare: list[tuple[Any, Optional[str]]] = []
        if mapping is None:
            paare = [(k, None) for k in self.store.ohne_bindung(source)]
        else:
            for name, wert in mapping.items():
                k = self.store.get_user_by_name(str(name or "").strip())
                if k is None:
                    bericht["refused"].append({"user_id": None, "username": str(name),
                                               "reason": "no_account"})
                else:
                    paare.append((k, str(wert or "")))
        plan = []
        for konto, vorgabe in paare:
            e: dict = {"user_id": int(konto["id"]), "username": konto["username"],
                       "local": {"name": konto["display_name"], "email": konto["email"]}}
            if konto["is_service"] or konto["disabled"]:
                bericht["refused"].append(dict(e, reason="service_account" if konto["is_service"]
                                               else "disabled"))
                continue
            vorhandene = self.store.get_federated_kennung(source, konto["id"])
            if vorhandene and not vorhandene.startswith(self._OHNE_KENNUNG):
                bericht["refused"].append(dict(e, identifier=vorhandene, reason=(
                    "already_bound" if vorgabe is None or vorhandene == vorgabe else "bound_elsewhere")))
                continue
            name_belegt = True
            kennung = vorgabe or ""
            if suchen is not None:
                treffer = suchen(konto["username"])     # VerzeichnisNichtErreichbar aborts
                if not treffer:
                    bericht["not_in_directory"].append(e)
                    continue
                if len(treffer) > 1:
                    bericht["ambiguous"].append(dict(e, matches=len(treffer)))
                    continue
                info = treffer[0]
                e["directory"] = {"name": info.get("name"), "email": info.get("email")}
                kennung = str(info.get("id") or "")
                name_belegt = self._ldap_name_belegt(konto["username"], info)
            if not kennung:
                # No identifier, also an empty one in the mapping: binding would be via the name.
                bericht["no_identifier"].append(e)
                continue
            e["identifier"] = kennung
            grund = self._nachbindung_grund(source, kennung, konto, name_belegt=name_belegt,
                                            frist=False)
            if grund == "conflict":
                bericht["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, kennung)))
            elif grund:
                bericht["refused"].append(dict(e, reason=grund))
            elif self.store.get_password_hash(konto["id"]):
                bericht["local_password"].append(e)
            else:
                plan.append(e)
        # Two accounts, one identifier (mapping with a duplicate): neither.
        from collections import Counter
        doppelt = {k for k, n in Counter(e["identifier"] for e in plan).items() if n > 1}
        bericht["conflict"] += [e for e in plan if e["identifier"] in doppelt]
        plan = [e for e in plan if e["identifier"] not in doppelt]
        if not apply:
            bericht["bound"] = plan
            return bericht
        for e in plan:
            # Atomic against a sign-in that has bound since the check (`Store.nachbinden`).
            if self.store.nachbinden(source, e["identifier"], e["user_id"], _jetzt()):
                self.audit(f"{source}_kennung_gebunden", str(e["username"]), detail="migration")
                bericht["bound"].append(e)
            else:
                bericht["conflict"].append(dict(e, bound_to=self.store.get_federated_user(source, e["identifier"])))
        security.seclog.warning(
            "federation_bind_existing(%s): %d bound, %d conflict, %d ambiguous, %d not in the "
            "directory, %d without identifier, %d refused, %d with local password (reported only).",
            source, len(bericht["bound"]), len(bericht["conflict"]), len(bericht["ambiguous"]),
            len(bericht["not_in_directory"]), len(bericht["no_identifier"]),
            len(bericht["refused"]), len(bericht["local_password"]))
        return bericht

    def _ldap_vertraut(self, info) -> bool:
        """Does the operator trust the address of this entry? Blanket (`ldap_email_trusted`) or
        verified for THIS entry (evidence attribute `ldap_attr_email_verified`)."""
        return bool(self.cfg.ldap_email_trusted) or (
            bool(security.beleg_attribut(self.cfg, "ldap")) and _beleg_wahr(info.get("email_verified")))

    def _ldap_name_belegt(self, username, info) -> bool:
        """Does the name say something about the person in the directory? No for control characters — and if it
        IS the entry's unverified `mail` value (source not trusted). Sign-in and
        existing-data binding ask here; only then may an account be mapped via the name.

        What matters is whether the input IS the unverified value — not whether it looks like an
        address: `mail` is a free attribute (RFC 4524), an attacker also sets it to
        `chefin` (counter-check); a UPN with `@`, on the other hand, is the bind identifier and counts as verified."""
        if name_ungueltig(username):
            return False
        mail_wert = norm_kennung(info.get("email") or "")
        return not (not self._ldap_vertraut(info) and mail_wert
                    and norm_kennung(username) == mail_wert)

    def _check_ldap(self, username, password) -> Optional[dict]:
        """Check the password against LDAP. On success find/create the local user and return it.
        Counts like a password login (factor 'password').

        The adopted address (`info["email"]`) is a directory attribute without evidence — in
        many directories the user maintains it themselves. The operator says whether they trust it
        (`ldap_email_trusted`, default no since the PO decision 2026-09-25; or for this
        entry via `ldap_attr_email_verified`): then it counts as verified and carries rights. If
        they do not trust it, it is not used directly (confirmation link, see
        `_adresse_aus_quelle_belegen`), and a
        typed-in address does not become the account name (substitute name `ldap-…`, no mapping via the
        name). For this case — and that was the rule until then — **two**
        consequences applied and apply, both necessary:

        * A newly created account gets the address with `email_verified=False` — the marker
          on the account does not claim what nobody has verified.
        * Whoever integrates this path themselves passes `email_verified=False` on to `apply_factor`
          (the bundled login route does so). The path cannot be recognised by the factor name —
          `password` is not in `_FEDERATED_FACTORS`, because a local
          password arrives there too.

        The second alone protected only THIS login: the attacker set up a PIN or a passkey in the
        freshly signed-in session, signed in again with it
        — that factor travels without evidence —, and the marker on the account promotes them after all
        (B-umgehung-1 from T-13). Otherwise an allowlist address could determine the first admin via LDAP
        (F-14).

        **One identifier, one account** (review round 2026-09-27, p1-d): the login route asks LDAP only
        after the local password of the account for the identifier (`find_user`) did not match. If
        the directory entry leads to ANOTHER account (bound, via the name or newly
        created), it is rejected before anything is written (`_kennung_zweier_konten`) — the
        route books a failed attempt. Otherwise one identifier would check the secrets of two
        people, and the sign-in of one would clear the counters under which the other
        is being guessed (local `alice.neu` next to the directory name `alice.neu` of another person,
        or a registration with the directory address with a filter over `mail`). That also affects
        the sign-in of a directory third party under the address of a local account (until
        then secured only for the counters, G5-N1)."""
        if not self.ldap:
            return None
        from .ldap_ import AnfrageAbgebrochen, VerzeichnisNichtErreichbar, eingabe_zu_lang
        # Longer than any real sign-in: not to the directory, but treated like a wrong
        # password (failed attempt, `failed login`). Here and not only in the client, so that it also applies to
        # a client set by hand — and before the marker hands out a probe slot.
        # Before, the login route sent every length through: a password with 270,000 characters
        # made slapd close the connection (see `ldap_.AnfrageAbgebrochen`).
        if eingabe_zu_lang(username, password):
            return None
        # After an outage the directory is not even asked for a while: the route
        # has already pre-booked the attempt (R7-2) and takes it back only once the outage
        # is reported — without the marker it would hang on every attempt until the timeout and
        # meanwhile lock out bystanders (rationale at `ldap_.AusfallMerker`).
        merker = self._ldap_ausfall
        probe = merker.zugang()
        try:
            info = self.ldap.authenticate(username, password)
        except AnfrageAbgebrochen:
            # Only THIS request failed, quickly and after sending its inputs —
            # no evidence of an outage. Arming the marker would give the sender of
            # any crafted sign-in a switch that turns LDAP off for everyone. If it was the
            # probe, the next sign-in asks again.
            if probe:
                merker.freigeben()
            raise
        except VerzeichnisNichtErreichbar as e:
            merker.ausgefallen(e, war_probe=probe)
            raise
        except BaseException:
            if probe:
                merker.freigeben()
            raise
        merker.erreicht()
        if not info:
            return None
        # Group gate against memberOf — by DN components, not as a substring (F-19):
        # `staff` would otherwise also let `cn=staffextern,…` through. `group_match="substring"` brings
        # back the old comparison explicitly.
        allowed = self.cfg.ldap_allowed_groups
        teilstring = self.cfg.group_match == "substring"
        if allowed:
            groups = info.get("groups") or []
            if not teilstring:
                for a in allowed:
                    _teilstring_hinweis(a, groups, "ldap_allowed_groups")
            if not any(gruppe_passt(a, g, teilstring, dn=True) for a in allowed for g in groups):
                self.audit("ldap_group_denied", username,
                           detail=f"verlangt={sorted(str(a) for a in allowed)}")
                return None
        # Not trusted and the input is an address (a search filter over `mail`, "sign-in with
        # name or email"): then the name is the same unverified address — as account name and
        # `Remote-User` it would occupy the owner's identifier, and bound via the name
        # it would take over her account (attack on the third round). As with SAML: substitute name,
        # no mapping via the name.
        kennung_ldap = info.get("id") or ""
        quelle_vertraut = self._ldap_vertraut(info)
        ldap_name = username
        name_zuordnen = True
        if not self._ldap_name_belegt(username, info):
            ldap_name = "ldap-" + hashlib.sha256((kennung_ldap or username).encode()).hexdigest()[:8]
            name_zuordnen = False

        def _anlegen():
            if not self.cfg.ldap_auto_create:
                return None
            try:
                # Address AND evidence go into the account together: the `mail` attribute proves
                # nothing, so the marker on the account must not claim it either. If the default
                # `True` stood here, the bolt above would be shut only for THIS login — the
                # next factor the attacker sets up themselves (PIN, passkey)
                # arrives without evidence, reads the marker and promotes after all (B-umgehung-1 from T-13).
                # The operator says whether they trust the directory (`ldap_email_trusted`, default
                # no, or the evidence attribute): then with evidence, otherwise not at all (H-3).
                vertraut = quelle_vertraut
                name = ldap_name
                if name == username:
                    # The directory has just signed in this very entry under that name; if it still stands
                    # on another account's binding, it is outdated there (p1-a) — and would
                    # otherwise hold up the creation as "taken".
                    self.store.verzeichnisname_freigeben(name)
                i = 1
                while name != username and self.identifier_taken(name):
                    i += 1
                    name = f"{ldap_name}{i}"
                return self._konto_anlegen(name, display_name=info.get("name") or name,
                                           email=info.get("email") if vertraut else None,
                                           email_verified=vertraut and bool(info.get("email")),
                                           name_quelle="ldap")
            except ConfigError:
                # Name or address already belong to someone locally (finding R4-12). Fail-closed:
                # better no sign-in than an account that occupies a foreign identifier.
                self.audit("ldap_ident_taken", username)
                return None

        # Mapping is done via the directory's STABLE identifier, not via the name
        # (F-11). The name remains the fallback for accounts that have no binding yet. If the
        # identifier locally belongs to an account, the resolution may end only there (p1-d, see above).
        lokal = self.find_user(username)
        u = self._fremde_identitaet_aufloesen("ldap", kennung_ldap, username, _anlegen,
                                              name_zuordnen=name_zuordnen,
                                              nur_konto=int(lokal["id"]) if lokal else None)
        if not u or u["disabled"]:
            return None
        # Note the typed-in name on the binding if it is neither name nor address of the
        # account (G5): after a rename in the directory (local `alice`, there `alice.neu`)
        # the series (B2-6) counts under `alice.neu`, and without the note no way back would clear it —
        # neither the full sign-in nor the panel reset nor `tinysesam unlock`. Who else
        # it may belong to is checked by the reader (`Store.zaehl_kennungen`), not by this writer.
        if not name_ungueltig(username):
            self.store.bindung_name_setzen("ldap", u["id"], username)
        self._adresse_aus_quelle_belegen(u, info.get("email"), quelle_vertraut, "ldap")
        # memberOf delivers whole DNs → comparison by components (F-19). Up to 0.20.0
        # `substring=True` was hard-wired here, and `group_match` had no effect for LDAP.
        self.apply_idp_groups(u["id"], info.get("groups"), self.cfg.ldap_group_role_map, dn=True)
        return self._als_dict(self.store.get_user(u["id"]))   # fresh (mapped roles)

    # ---------- SAML (attributes → local user) ----------
    def _check_saml(self, nameid, attrs, ip: Optional[str] = None) -> Optional[dict]:
        """Find/create a local user from a verified SAML assertion. Factor 'saml'.

        The address from the attribute carries no evidence (SAML has no `email_verified`).
        Since the PO decision 2026-09-24 the operator says whether they trust it
        (`saml_email_trusted`, default no). Without trust it is not used, an
        account name with `@` yields to a substitute name, and via such a name no
        existing account is ever mapped. The factor `saml` is in `_FEDERATED_FACTORS`: an allowlist ADDRESS never becomes first admin via this path,
        even if a caller does not state the evidence — and not via a second,
        self-set-up factor at the next login either (B-umgehung-1 from T-13).

        Every substantive rejection leaves an audit line with a reason (F-22): up to 0.20.0
        group gate, missing account and locked account ended silently in a 403 — "I can't get
        in" could not be answered on the server side. `ip` is passed through by the ACS route."""
        from .saml_ import first, as_list
        cfg = self.cfg
        username = first(attrs, cfg.saml_attr_username) if cfg.saml_attr_username else None
        roh_name = str(username or nameid or "")
        # The UNTRIMMED value is checked: `strip()` also removes U+2028, U+0085 and Unicode
        # whitespace — `chefin\u2028` would otherwise become `chefin` (counter-check).
        username = roh_name.strip()
        if not username:
            self.audit("saml_denied", None, ip, "grund=kein_name")
            return None
        pauschal = bool(cfg.saml_email_trusted)
        _attr = security.beleg_attribut(cfg, "saml")
        mail = first(attrs, cfg.saml_attr_email)
        # The evidence attribute proves the ADDRESS of this login — not the name. At an IdP with
        # self-registration (exactly what it is for) the user chooses their NameID themselves:
        # `bob@example.com` as name, confirming their own address. Here the name then counted as
        # verified and was mapped via case 4 to the local account `bob@example.com` —
        # takeover (self-service attack round, finding 1). As with OIDC (`email_verified`):
        # a name with `@` is verified only if it is EXACTLY the verified address.
        beleg = bool(_attr) and _beleg_wahr(first(attrs, _attr)) and valid_email(norm_email(mail or "") or "")
        vertraut = pauschal or beleg
        # The stable identifier is the `NameID` — or an attribute if the IdP sends transient
        # NameIDs (`saml_attr_id`). The name is only the fallback (F-11).
        kennung = (first(attrs, cfg.saml_attr_id) if cfg.saml_attr_id else nameid) or ""
        # Without trust in this IdP's addresses (default) as with H-3 for OIDC: a name with `@`
        # (NameID in emailAddress format, a UPN) is the same unverified address under another
        # name — as account name and `Remote-User` it would occupy the real owner's identifier.
        # Applies only to NEW accounts; a bound one keeps its name. Checked folded
        # (`＠` U+FF20 becomes `@`, R2-1).
        neu_name = username
        name_zuordnen = True
        # The name is unverified if it is an address — or if it comes from the address attribute
        # itself (`saml_attr_username` = `saml_attr_email`): then it carries what the user
        # entered there, also `chefin` without `@` (counter-check).
        unbelegt = (not pauschal) and (
            "@" in norm_kennung(username)
            or (bool(cfg.saml_attr_username) and cfg.saml_attr_username == cfg.saml_attr_email)
        ) and not (beleg and norm_kennung(username) == norm_kennung(mail or ""))
        if name_ungueltig(roh_name) or unbelegt:
            neu_name = "saml-" + hashlib.sha256((kennung or username).encode()).hexdigest()[:8]
            name_zuordnen = False
        if cfg.saml_allowed_groups:
            groups = as_list(attrs, cfg.saml_attr_groups)
            if not (set(cfg.saml_allowed_groups) & set(str(g) for g in groups)):
                self.audit("saml_denied", username, ip,
                           f"grund=gruppe verlangt={sorted(cfg.saml_allowed_groups)}")
                return None
        def _anlegen():
            if not cfg.saml_auto_create:
                self.audit("saml_denied", username, ip, "grund=kein_konto saml_auto_create=False")
                return None
            try:
                # As with LDAP (B-umgehung-1 from T-13): the address from the assertion comes without
                # evidence, so it is stored without evidence too. Otherwise the marker on the
                # account would be a free pass for every later sign-in path that itself
                # proves nothing.
                name = neu_name
                i = 1
                while name != username and self.identifier_taken(name):
                    i += 1
                    name = f"{neu_name}{i}"
                anzeige = first(attrs, cfg.saml_attr_name) or name
                return self._konto_anlegen(name, display_name=anzeige,
                                           email=mail if vertraut else None,
                                           email_verified=vertraut and bool(mail),
                                           name_quelle="saml")
            except ConfigError:
                # As with LDAP (finding R4-12): an already taken identifier creates no account.
                self.audit("saml_ident_taken", username)
                return None

        u = self._fremde_identitaet_aufloesen("saml", kennung, username, _anlegen,
                                              name_zuordnen=name_zuordnen)
        if u and u["disabled"]:
            self.audit("saml_denied", str(u["username"]), ip, "grund=konto_gesperrt")
            return None
        if not u:
            return None     # the reason is already in the audit log (creation/identifier)
        self._adresse_aus_quelle_belegen(u, mail, vertraut, "saml")
        self.apply_idp_groups(u["id"], as_list(attrs, cfg.saml_attr_groups), cfg.saml_group_role_map)
        return self._als_dict(self.store.get_user(u["id"]))   # fresh (mapped roles)

    def _adresse_aus_quelle_belegen(self, u, mail, vertraut, quelle: str = "") -> None:
        """Bring the address from a source (LDAP/SAML) to the account.

        * **Trusted** (switch or evidence attribute of this login): verifies THE SAME address on the
          account (the source says nothing about any other one; same rule as for the OIDC claim),
          upgrade only; an account without an address gets it if it is free (as H-3 for OIDC).
        * **Not trusted** (PO decision 2026-09-25): with `federation_email_confirm`, mailer and
          `base_url`, a confirmation link goes once to the address — the same path as the
          self-service mail change (`request_email_change`). Only the click makes it the
          account's address. Only for accounts WITHOUT a verified address, at most one DELIVERED
          link per day (G12a, see below).
        Silence takes the evidence from no account that the operator set themselves.

        Deliveries are counted, attempts dampened (G12a, since 2026-09-26). Until then the
        attempt itself used up the daily allowance (per process, in memory): a throttled
        target address or a failed delivery cost the link for a whole day, and
        several workers each sent one. Now the delivery is in the database
        (`federation_email_confirm … konto=<id>`, only after sending, `Store.quellmail_seit`).
        A taken or reserved address never gets a link; its attempt (with
        audit line `konto=<id> …`) is likewise counted in the database, at most one per day. Until
        the attack round 2026-09-26 only memory dampened it — per worker and until restart:
        a free address left exactly one request on the account page, a taken one one more
        with every further worker, and an LDAP user who maintains their `mail` themselves could read from
        that whether a foreign address has an account. Memory now dampens only what
        passes — a throttle, a mail server error: after `mail_per_address_window_sec` again."""
        if not mail or not u:
            return
        adresse = norm_email(mail)
        konto_mail = norm_email(u["email"] or "")
        if vertraut:
            if konto_mail == adresse and not u["email_verified"]:
                self.store.set_email_verified(u["id"], True)
            elif not konto_mail and not self.identifier_taken(adresse, exclude_id=u["id"]):
                try:
                    self.store.set_email(u["id"], adresse, verified=True)
                except sqlite3.IntegrityError:
                    # Race: meanwhile identifier of another account — the account stays without an
                    # address, as with the pre-check (fail-closed).
                    self.audit(f"{quelle or 'quelle'}_email_taken", str(u["username"]), None,
                               "nachgetragen=0 wettlauf=1")
            return
        # An account with a verified address keeps it — also a different one from the source's: the
        # owner confirmed it themselves (self-service), and a link at every sign-in that wants to
        # replace it would be a nuisance. They can change it themselves via the account page.
        if u["email_verified"]:
            return
        if not (self.cfg.federation_email_confirm and self.cfg.base_url and self.mail_configured()):
            return
        # None while one is open, and at most one completed request per account and day —
        # delivered or rejected (taken, reserved), counted in the database, across all
        # workers. Otherwise every sign-in would write an audit line, and their count on the account page
        # would reveal whether the address is taken (attack round 2026-09-26). If a link lives longer
        # than a day (`email_change_ttl_min`), then that long: a delivered one holds up the next
        # attempt until its expiry anyway (`offener_token`), a rejection must do the same
        # — and also when the owner discards their open link (password change).
        # Every open link of the account holds things up, whichever address it goes to (p2 F2): the line
        # `federation_email_confirm` arises only after sending. With the filter on the address
        # a second worker, while the first link was still in the outbox, would send one to a
        # different `mail` — if it arrived, the first address was free (a taken one writes its
        # rejection immediately), and the account got two links in one day.
        frist = max(86400, int(self.cfg.email_change_ttl_min) * 60)
        if self.store.offener_token(u["id"], "email_change"):
            return
        if self.store.quellmail_seit(u["id"], _jetzt() - frist):
            return
        # What passes (throttle, mail server) is dampened by memory per process (G12a): after the
        # window of the mail throttle again. Identical for every target — "taken?" is asked only
        # in `_wechsel_beantragen`, with the same work for both answers (G12b).
        if not self.rl.allow(f"quellmail:{u['id']}", 1, int(self._sec("mail_per_address_window_sec"))):
            return
        try:
            senden = self._wechsel_beantragen(u["id"], adresse, self.cfg.base_url, quelle=quelle or "quelle")
        except (ValueError, ConfigError):
            return
        if senden is None:
            return
        uid, name = u["id"], u["username"]
        # Write the line in the context of the request (IP as before), but only in the outbox
        # and only if the link really went out — it is the daily allowance.
        anfrage = contextvars.copy_context()

        def _versand():
            if senden():
                anfrage.run(self.audit, "federation_email_confirm", name,
                            detail=f"konto={uid} quelle={quelle} an={adresse}")
        if not self._hinweis_ausgang.einreihen(_versand):
            # Queue full: the link never goes out. Its token expires at once — otherwise
            # it would hold up every new one as an open link (`offener_token`) until its expiry,
            # without one ever having been delivered. The next attempt is dampened by memory as
            # after a failed delivery (`quellmail:<id>`, the window of the mail throttle).
            senden.verwerfen()

    # ---------- Manage passkeys ----------
    def remove_passkey(self, user_id: int, passkey_id: int, ip: Optional[str] = None) -> bool:
        """Remove an account's passkey — deletion, audit line and `passkey_removed` in one.

        Both paths go through here: self-service (`/auth/passkey/delete`) and revocation
        by an admin in the panel. Before, each had its own lines, and after merging
        two branches only self-service reported the event — of all things the
        revocation on a FOREIGN account, performed by a taken-over admin account, stayed
        silent for the owner (integration finding 3). The audit line stands under the owner;
        if someone else acts, `audit()` adds `akteur=` from the running request.

        Returns False if the account has no passkey with this ID — then nothing is
        deleted, logged or reported (before, self-service wrote a line and an event even for
        an invented passkey)."""
        if not any(int(c["id"]) == int(passkey_id) for c in self.store.list_webauthn(user_id)):
            return False
        self.store.delete_webauthn(int(passkey_id), user_id)
        # Losing a factor is exactly what one wants to look up later (B5-01).
        self.audit("passkey_delete", self._kontoname(user_id), ip, f"id={int(passkey_id)}")
        self._security_event("passkey_removed", user_id, passkey_id=int(passkey_id))
        return True

    # ---------- PIN login (personal PIN per user) ----------
    def set_pin(self, user_id, pin):
        """Set/change the PIN. Minimum length from cfg.pin_min_length."""
        pin = str(pin or "")
        if len(pin) < self.cfg.pin_min_length:
            raise ConfigError(f"PIN too short (min. {self.cfg.pin_min_length})")
        self.store.set_pin_hash(user_id, hash_password(pin))
        self._security_event("pin_set", user_id)

    def has_pin(self, user_id) -> bool:
        """Has this account set up a PIN?"""
        return self.store.has_pin(user_id)

    def disable_pin(self, user_id):
        """Remove an account's PIN (is logged — a second factor does not vanish unnoticed)."""
        self.store.delete_pin(user_id)
        self.audit("pin_disable", self._kontoname(user_id), detail=f"user={user_id}")
        self._security_event("pin_disabled", user_id)

    def _check_pin(self, username, pin) -> Optional[dict]:
        """Like `_check_password`, only with the personal PIN."""
        u = self.find_user(username)
        if not u or u["disabled"]:
            dummy_verify(str(pin or ""))
            return None
        h = self.store.get_pin_hash(u["id"])
        if not h:
            dummy_verify(str(pin or ""))
            return None
        if not verify_password(str(pin or ""), h):
            return None
        if needs_rehash(h):
            self.store.set_pin_hash(u["id"], hash_password(str(pin)))
        return u

    # Check factors against a known identity (step-up: the user is already fixed).
    def _verify_user_password(self, user_id, password) -> bool:
        """Check the password of a KNOWN account (step-up: the identity is already fixed)."""
        h = self.store.get_password_hash(user_id)
        if not h:
            dummy_verify(password or "")
            return False
        if not verify_password(password or "", h):
            return False
        if needs_rehash(h):
            self.store.set_password_hash(user_id, hash_password(password))
        return True

    def _verify_user_pin(self, user_id, pin) -> bool:
        """Like `_verify_user_password`, only with the PIN."""
        h = self.store.get_pin_hash(user_id)
        if not h:
            dummy_verify(str(pin or ""))
            return False
        if not verify_password(str(pin or ""), h):
            return False
        if needs_rehash(h):
            self.store.set_pin_hash(user_id, hash_password(str(pin)))
        return True

    def stepup_options(self, user) -> list[str]:
        """What can THIS user confirm a step-up with? Order = suggestion.

        `config.stepup_methods` is a **wish, not a barrier**: if the user has set up none of the
        named methods, the confirmation falls back to everything they have —
        otherwise the area would be unreachable for them, without their being able to do anything about it.
        That includes the password with which they just signed in; `["totp"]` alone
        therefore does not guarantee that a second factor really stands before the sensitive area.

        Whoever wants the barrier sets `stepup_strict=True`: then the list stays empty if nothing
        wished for is set up, and the area stays closed until the user sets up the
        method."""
        cfg = self.cfg
        avail = []
        if cfg.totp_enabled and self.store.has_confirmed_totp(user["id"]):
            avail.append("totp")
        if cfg.pin_enabled and self.store.has_pin(user["id"]):
            avail.append("pin")
        if cfg.password_enabled and self.store.get_password_hash(user["id"]):
            avail.append("password")
        wanted = [m for m in (cfg.stepup_methods or []) if m in avail]
        if wanted:
            return wanted
        if cfg.stepup_methods and cfg.stepup_strict:
            return []              # wished for, but none of it set up → closed
        return avail               # the old way: the best the user has

    def _is_pin_locked(self, username, ip, login: bool = True) -> bool:
        """Own, method-scoped lockout for the PIN (short keyspace). In addition to is_locked().

        The rejection is reported here (`_abgewiesen`), as with every other lockout: until
        T-13 this was the only one to reject silently, and the security log was silent exactly when
        fail2ban was supposed to read. `login=False` for the step-up page — there the PIN is not a
        sign-in, the line then carries `failed verification`.
        """
        return self._sperre_pruefen(self._regeln_pin(username, ip), username, ip, login)

    def _is_password_change_locked(self, username, ip) -> bool:
        """Own, method-scoped lockout for the old-password prompt on the account page.

        The same design as `_is_pin_locked`, but with its own threshold
        (`password_change_max_attempts`) and **separate from the login lockout**: guessing stays
        throttled (R4-10 — the route was a silent password oracle), but a typo on the
        own account page does not lock the sign-in. The lockout applies exactly where
        the guessing happened.

        **Per account only, not per IP** (`ip` goes only into the log line). Until the
        second round an IP threshold counted here too — and behind NAT it locked
        bystanders again: three colleagues who mistyped locked the fourth out of his OWN
        password change, although he had entered nothing wrong. The rework set out to
        stop exactly that. It is not missing either: whoever guesses here already needs a
        valid session of the account whose password they are guessing — the victim is always the
        signed-in person themselves. Against knocking from outside, `_rate_ok(ip)` still stands.

        The rejection is reported here, not in the route: otherwise the
        security log would fall silent exactly when fail2ban is supposed to ban the IP (rationale at
        `_abgewiesen`).
        """
        return self._sperre_pruefen(self._regeln(username, ip, "password_change"),
                                    username, ip, login=False)

    def _is_reauth_locked(self, username, ip) -> bool:
        """Own, method-scoped lockout for the step-up confirmation (`/auth/reauth`).

        A step-up confirmation is **not a sign-in** — whoever performs it is already
        signed in. Until the second round its failed attempts nevertheless counted into the
        login bucket: five typos on the reauth page locked the user's **sign-in**
        for `lockout_window_sec`, correct password included. Now this bucket slows it
        (`reauth_max_attempts`), and **per account only**: the guessing hits exclusively
        the own account, an IP threshold would behind NAT hit only bystanders (`ip` goes only
        into the log line). The path stays throttled via `_rate_ok(ip)`.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "reauth"), username, ip, login=False)

    def _is_resource_locked(self, username, ip) -> bool:
        """Own, method-scoped lockout for the area PIN (`/auth/resource/…`).

        `username` here is the pseudo name of the area (`res:<name>`) — there is no
        account. Until the second round the counter ran into the login bucket, and because
        **any visitor** may try the area PIN, that was an amplifier: three areas
        times five misses from the same address reached the login IP threshold
        (`max_login_attempts * ip_attempt_factor`) and locked the sign-in of accounts
        that had never done anything wrong.

        Two thresholds, and their order is the point (R7-3): **per address**
        `resource_max_attempts`, **per area** the `account_attempt_factor` multiple of it. Until
        T-13 it was the other way round — the area locked after `resource_max_attempts`, no matter
        from whom. A single stranger thus locked the area for ALL with five misses,
        including those who know the secret. Now his own address stops him, long
        before the area closes; that takes several connections. The area threshold cannot be
        dropped entirely: without it a distributed attacker guesses a four-digit
        PIN in hours, because every address brings its own attempts.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "resource"), username, ip, login=False)

    def _is_totp_setup_locked(self, username, ip) -> bool:
        """Dedicated, method-scoped lockout for confirming the TOTP setup.

        Until T-13 the route `POST /auth/totp/setup` checked any number of codes, with no throttle,
        no lock and no log line (findings B2-12, R3-6) — the only OTP check
        where that was the case. Guessing gains little there (whoever sets up sees the secret), but
        a check without a brake and without a trace is exactly the one nobody looks at any more.
        Like `reauth`, **per account only** (`totp_setup_max_attempts`) and separate from the
        login lockout: five typos during setup should not lock the sign-in.

        Read-only: the route calls `_begin_attempt(…, "totp_setup")`, which checks and books in
        one step — with this method beforehand and `_record_login()` afterwards a parallel
        burst got past the limit.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "totp_setup"), username, ip, login=False)

    # ---------- The lock rules: one source for checking and atomic booking ----------
    def _regeln_pin(self, username, ip, since=None) -> list:
        """The dedicated PIN bucket: `pin_max_attempts` per account, `ip_attempt_factor` times that per address.

        Per account and not per pair of account and address: a PIN often has only four digits,
        a distributed attacker would get through it within hours with pair counting."""
        since = self._fenster_beginn() if since is None else since
        username = norm_kennung(username)
        grenze = self._sec("pin_max_attempts")
        return [("lockout_pin", grenze, dict(since=since, username=username, method="pin")),
                ("lockout_pin_ip", grenze * self._sec("ip_attempt_factor"),
                 dict(since=since, ip=ip, method="pin"))]

    @staticmethod
    def _topf(username, method) -> str:
        """Under which name an attempt counts: the identifier folded the way `find_user` reads it.

        Up to the third round, attempts were counted under the RAW typed text, but looked up
        trimmed and case-insensitively. `' victim'`, `'victim '`, `'\tvictim'` hit
        the same account and each filled a bucket of its own — the account threshold against distributed
        guessing (R7-6/H-8) thus bound nothing. The exception is the realm pseudo-name
        `res:<name>`: the server sets it from a realm that has to exist."""
        return username if method == "resource" else norm_kennung(username)

    def _fenster_beginn(self) -> int:
        return _jetzt() - self._sec("lockout_window_sec")

    def _regeln(self, username, ip, method) -> list:
        """Which counters apply to an attempt of this method? List of `(reason, limit, filter)`.

        `is_*_locked()` checks them, `_begin_attempt()` checks them AND books atomically — both read
        the same list so that the two paths are never of different strictness.

        **Sign-in** (everything except `security.NICHT_LOGIN_METHODEN`, R7-6/H-8): the first
        threshold counts per **pair of account and address** (`max_login_attempts`). Until T-13 it counted
        per account alone — then any stranger could lock out any account whose name they knew
        for a window with five requests, including the owner with the correct password. Per
        account a second, higher threshold remains (`account_attempt_factor` times) against
        guessing across many addresses; a single attacker no longer reaches it because the pair
        stops them first. Per address the NAT threshold (`ip_attempt_factor` times) remains against
        trying out many accounts.

        The account key is `_topf(username)`, not the raw text — otherwise an
        attacker could set up arbitrarily many buckets for the same account with whitespace and spellings.
        """
        since = self._fenster_beginn()
        username = self._topf(username, method)
        if method in ("password_change", "reauth", "totp_setup"):
            grenze = self._sec(f"{method}_max_attempts")
            return [(f"lockout_{method}", grenze, dict(since=since, username=username, method=method))]
        if method == "resource":
            grenze = self._sec("resource_max_attempts")
            return [("lockout_resource_ip", grenze, dict(since=since, ip=ip, method=method)),
                    ("lockout_resource", grenze * self._sec("account_attempt_factor"),
                     dict(since=since, username=username, method=method))]
        ohne = security.NICHT_LOGIN_METHODEN
        grenze = self._sec("max_login_attempts")
        regeln = []
        if username and ip:
            regeln.append(("lockout_user", grenze,
                           dict(since=since, username=username, ip=ip, exclude_methods=ohne)))
        regeln += [
            ("lockout_account", grenze * self._sec("account_attempt_factor"),
             dict(since=since, username=username, exclude_methods=ohne)),
            ("lockout_ip", grenze * self._sec("ip_attempt_factor"),
             dict(since=since, ip=ip, exclude_methods=ohne)),
        ]
        if method == "pin":
            regeln += self._regeln_pin(username, ip, since)
        return regeln

    def _serie_voll(self, username) -> bool:
        """Has this identifier reached `account_max_consecutive_failures` failed attempts IN A ROW (B2-6)?

        Unlike every window threshold, this lock does not expire: it ends with a
        complete sign-in by another route (passkey, magic link, OIDC), a
        password reset or by the operator (panel reset, `tinysesam unlock`). Counting is
        per folded identifier, whether the account exists or not — otherwise the lock would reveal which
        names exist.

        Only what is settled (`fehlserie_bestaetigt`, G9): a pending pre-booking can still
        be taken back — a deferral therefore never shows the streak-lock text."""
        return (self.store.fehlserie_bestaetigt(norm_kennung(username))
                >= self._sec("account_max_consecutive_failures"))

    def _serie_reset_hilft(self, username) -> bool:
        """Does a self-service reset lift the streak lock under this identifier?

        It clears only the shares of the first factors (`_SERIE_RESET_ARTEN`), not TOTP and not
        the PIN in the chain step (`_PIN_CHAIN_SERIES`, G7). If those alone are at the limit, the lockout
        notice and security log still named the reset as a way out until 2026-09-27 — the owner
        reset their password and stayed locked. Only for texts to the owner and operator: the
        sign-in page shows everyone the same text (`err.locked_serie`), otherwise it would reveal that
        someone is guessing the second factor under an identifier — and thus that the account exists."""
        return (self.store.fehlserie_ohne(norm_kennung(username), self._SERIE_RESET_ARTEN)
                < self._sec("account_max_consecutive_failures"))

    def _serie_ausweg(self, username) -> str:
        """What the streak lock under this identifier lifts — for the security log."""
        if self._serie_reset_hilft(username):
            return "password reset, signing in another way, or `tinysesam unlock`"
        return ("signing in another way or `tinysesam unlock` (a password reset does not clear "
                "the failed attempts after the password: TOTP, PIN in the chain step)")

    def _sperre_pruefen(self, regeln, username, ip, login: bool) -> bool:
        """Check the rules read-only; the first one that applies is reported (`_abgewiesen`).

        If a rule applies only because of pending pre-bookings (G9, `Store.reserve_attempt`), that is
        a deferral, not a lock: `True` without `failed login` and without a lockout notice
        (`_aufgeschoben`). A rule that applies as confirmed as well takes precedence."""
        schwebend = False
        if login and username:
            if self._serie_voll(username):
                self._abgewiesen(username, ip, "lockout_serie", login=True)
                return True
            schwebend = (self.store.fehlserie(norm_kennung(username))
                         >= self._sec("account_max_consecutive_failures"))
        for grund, grenze, filt in _gueltige_regeln(regeln):
            if self.store.count_fails(**filt) < grenze:
                continue
            if self.store.count_fails(**filt, nur_bestaetigt=True) >= grenze:
                self._abgewiesen(username, ip, grund, login=login)
                return True
            schwebend = True
        if schwebend:
            self._aufgeschoben(username, ip, login=login)
        return schwebend

    def _begin_attempt(self, username, ip, method, include_pin: bool = False,
                          series_kind: Optional[str] = None, schweben: bool = False) -> Optional[int]:
        """Admit a check attempt **atomically** and pre-book it as a failed attempt.

        Return: an attempt ID that goes back to `_record_login(..., versuch=id)`, or
        `None` — locked (already reported). Replaces the sequence `_is_locked()` → check →
        `_record_login()`, which let a parallel burst past the lock (R3-2, R3-7,
        R7-2; rationale at `Store.reserve_attempt`).

        `include_pin=True` also attaches the PIN bucket — for the step-up page, on which a PIN
        confirms but whose attempts land in the `reauth` bucket.

        `series_kind` books the attempt in the streak (B2-6) under a different kind than the
        method — `_PIN_CHAIN_SERIES` for a PIN that comes AFTER an already provided factor
        (chain step, route chain; G7). Window and buckets keep counting under `method`.

        `schweben=True` books the attempt with an open outcome (G9, `Store.reserve_attempt`): for
        a check that can also turn out to be "no attempt at all" — the login route with LDAP, whose
        pre-booking is taken back on an outage (F-23). If an attempt would be rejected **only** because of
        such open pre-bookings, it waits until they are decided: at most
        `_SCHWEBE_FRIST_SEK`, at most `_SCHWEBE_WARTEPLAETZE` waiters per process. If it stays
        open, the answer is `None` as with a lock — but with `deferred login` instead of
        `failed login` in the security log (fail2ban does not ban) and without a lockout notice.
        """
        regeln = self._regeln(username, ip, method)
        if include_pin:
            regeln = regeln + self._regeln_pin(username, ip)
        # The streak (B2-6) belongs in the SAME transaction as the attempt: checked and pre-booked
        # in `reserve_attempt`. Before, it was read ahead of it and counted only after the check — a
        # parallel burst at the limit could then guess for one attempt per request.
        serie = None
        if method not in security.NICHT_LOGIN_METHODEN:
            serie = (norm_kennung(username), series_kind or method, self._sec("account_max_consecutive_failures"))

        def buchen():
            return self.store.reserve_attempt(self._topf(username, method), ip, method,
                                              _gueltige_regeln(regeln), serie=serie, schweben=schweben)

        versuch, antwort = buchen()
        if versuch is None and antwort == "schwebend":
            versuch, antwort = self._schwebe_abwarten(buchen)
        if versuch is None:
            login = method not in security.NICHT_LOGIN_METHODEN
            if antwort == "schwebend":
                self._aufgeschoben(username, ip, login=login)
            else:
                self._abgewiesen(username, ip, antwort, login=login)
        elif serie is not None:
            # The kind under which it WAS booked (`serie[1]`), not the method: otherwise a
            # correct follow-up step would lower the kind `pin` and leave its pre-booking under `pin_folge`
            # standing (G7).
            self._serie_vorbuchungen[versuch] = (serie[0], serie[1], antwort)
            # Capped: an attempt that nobody ever completes (exception in the middle of the route)
            # would otherwise remain forever. Whoever drops out counts as a failed attempt — stricter,
            # never looser.
            while len(self._serie_vorbuchungen) > self._SERIE_VORBUCHUNGEN_MAX:
                self._serie_vorbuchungen.pop(next(iter(self._serie_vorbuchungen)), None)
        return versuch

    _SERIE_VORBUCHUNGEN_MAX = 10000

    #: Pending pre-bookings (G9, `_begin_attempt`): how many sign-ins per process may
    #: wait at the same time, for how long at most (one directory question up to its timeout
    #: and some headroom) and at what interval they ask again. Every re-ask takes the write lock
    #: (`BEGIN IMMEDIATE`) — at full occupancy at most about 40 short transactions per second.
    _SCHWEBE_WARTEPLAETZE = 8
    _SCHWEBE_FRIST_SEK = _LDAP_TIMEOUT + 2
    _SCHWEBE_TAKT_SEK = 0.2

    def _schwebe_abwarten(self, buchen) -> tuple:
        """Wait until the pending pre-bookings are decided, then book again (G9).

        Return as for `Store.reserve_attempt`; `(None, "schwebend")` if the deadline expires or
        no waiting slot is free. Without a cap a burst would tie up every worker thread.

        Waiting blocks the calling thread — right for the synchronous routes (they run
        in the thread pool). `POST /auth/password` has also called its check in the thread pool since 0.22.0
        (`change_password`); it never goes pending anyway: its bucket counts only its own method, and
        that one never books open."""
        if not self._schwebe_plaetze.acquire(blocking=False):
            return None, "schwebend"
        try:
            frist = time.monotonic() + self._SCHWEBE_FRIST_SEK
            while time.monotonic() < frist:
                time.sleep(self._SCHWEBE_TAKT_SEK)
                versuch, antwort = buchen()
                if versuch is not None or antwort != "schwebend":
                    return versuch, antwort
            return None, "schwebend"
        finally:
            self._schwebe_plaetze.release()

    def _aufgeschoben(self, username, ip, login: bool = True) -> None:
        """A rejection that is not a lock: only pending pre-bookings in the way (G9).

        Own event word (`deferred login`/`deferred verification`) — the bundled
        fail2ban filters do not match it, and no lockout notice goes out: there may
        afterwards not be a single failed attempt in the table. It is logged anyway so that an
        operator can attribute the 429."""
        security.seclog.warning("deferred %s user=%s ip=%s reason=pending",
                                "login" if login else "verification",
                                security.fuer_log(username) or "-", security.fuer_log(ip))

    #: Maximum number of remembered (account, IP) pairs per process — after that the oldest drops out. An attacker with many
    #: addresses can thereby only displace entries, i.e. make failed attempts COUNT again, never fewer.
    _PW_WIEDERHOLUNG_PAARE = 10000
    #: PBKDF2 rounds of the fingerprint: noticeable for someone trying out a memory dump, but only a few
    #: milliseconds per failed attempt (measured 2026-10-09 on the development machine).
    _PW_WIEDERHOLUNG_RUNDEN = 20000

    def _passwort_wiederholt(self, username, ip, password) -> bool:
        """Has the same IP already sent exactly this wrong password to this account? Remembers it otherwise.

        Call only after a FAILED ATTEMPT: a correct password is never remembered. What is remembered is an HMAC with a
        subkey derived from the master key, truncated to 64 bits, in memory only and only for
        `password_repeat_window_sec`. Per process: with several workers a repetition that another
        worker receives counts in full again — the stricter direction.

        Repeating gains an attacker nothing, because the same password tests nothing new. Every OTHER wrong
        password keeps counting in full, and the IP throttle (`_rate_ok`) applies before everything else."""
        n = self._sec("password_repeat_memory")
        if n <= 0 or not password:
            return False
        fenster = self._sec("password_repeat_window_sec")
        kennung = norm_kennung(username)
        # PBKDF2 instead of a plain HMAC: the value arises from a password, so a hash that makes guessing expensive —
        # with a secret as salt so that a memory dump yields nothing without the master key.
        fp = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8", "surrogatepass"),
                                 self._pw_wiederholung_schluessel + kennung.encode("utf-8", "surrogatepass"),
                                 self._PW_WIEDERHOLUNG_RUNDEN)[:8]
        schl = (kennung, security.ip_normiert(ip) or str(ip))
        jetzt = time.monotonic()
        with self._pw_wiederholung_sperre:
            liste = [(f, t) for f, t in self._pw_wiederholung.get(schl, ()) if jetzt - t < fenster]
            treffer = any(hmac.compare_digest(f, fp) for f, _ in liste)
            if not treffer:
                liste = (liste + [(fp, jetzt)])[-n:]
            self._pw_wiederholung[schl] = liste
            self._pw_wiederholung.move_to_end(schl)
            while len(self._pw_wiederholung) > self._PW_WIEDERHOLUNG_PAARE:
                self._pw_wiederholung.popitem(last=False)
        return treffer

    def _anmeldung_vollstaendig(self, user_id, ip, method) -> None:
        """A sign-in is through with all factors: audit `login` and the line `login ok` in the security log.

        `unban=ja|nein` (0.24.10, PO): may a guard (fail2ban) lift the lock on this IP? Only `ja` if, from
        this IP, there is NO failed attempt against ANOTHER account in the window. Otherwise an attacker with an own
        account lifts their ban by a sign-in between two bursts and guesses without limit at firewall level against
        other accounts. The question is about other accounts, not the own one: the own failed attempts have been
        cleared by the successful factor already (`_record_login`)."""
        u = self.store.get_user(user_id)
        name = u["username"] if u else None
        self.store.audit_log("login", name, ip, method)
        fremd = (self.store.count_fails(self._fenster_beginn(), ip=ip, ausser_username=norm_kennung(name),
                                        exclude_methods=security.NICHT_LOGIN_METHODEN)
                 if ip and name else 1)
        security.seclog.info("%s user=%s ip=%s method=%s unban=%s", security.LOG_ERFOLG,
                             security.fuer_log(name or "?"), security.fuer_log(ip), security.fuer_log(method),
                             "ja" if fremd == 0 else "nein")

    def _versuch_zuruecknehmen(self, versuch) -> None:
        """Take back a pre-booked attempt — it was none (directory outage, F-23).

        Together with its pre-booking in the streak (B2-6), in one transaction (G9): an outage is
        not a failed attempt, neither in the window nor in a row."""
        gebucht = self._serie_vorbuchungen.pop(versuch, None)
        self.store.cancel_attempt(versuch, serie=gebucht[:2] if gebucht else None)

    def _versuch_gescheitert(self, versuch) -> None:
        """Close a pre-booked attempt as a failed attempt, without `_record_login` (G9).

        For a route whose check ends with an unexpected exception: the attempt counts
        immediately — stricter in doubt, as with a process that dies in the middle — instead of
        staying pending for `Store.VORBUCHUNG_SCHWEBE_SEK` and making sign-ins from the same address wait.
        The streak stays booked."""
        self._serie_vorbuchungen.pop(versuch, None)
        self.store.finish_attempt(versuch, False)

    # ---------- MFA (TOTP) ----------
    def _mfa_pending(self, user_id) -> bool:
        """TOTP required? Yes, if a confirmed TOTP exists for this account.

        There is no global enforcement here (any more): the switch `totp_required`, at which
        the earlier parenthetical remark was aimed, has been rejected in the constructor with `ConfigError`
        since 0.18.0. Enforcement happens via `login_chain` — and `_session_ok` evaluates that, not
        this method."""
        return self.store.has_confirmed_totp(user_id)

    def _verify_totp(self, user_id, code) -> bool:
        """Check a TOTP code — and consume it in the process.

        A code is valid **exactly once**. Before, it was valid for 90 seconds as often as desired
        (`valid_window=1` = previous + current + next step), and two separate
        clients could sign in fully with the same code. NIST SP 800-63B is unambiguous on this point:
        "Verifiers SHALL accept a given OTP only once while it is valid."
        """
        t = self.store.get_totp(user_id)
        if not t or not t["confirmed"]:
            return False
        schritt = _totp.passender_schritt(t["secret"], code)
        if schritt is None:
            return False
        # Book before the factor counts: whoever no longer gets the step was the second one.
        return self.store.totp_step_verbrauchen(user_id, schritt)

    def totp_begin(self, user_id):
        """Start the setup: returns the secret and the `otpauth://` address for the
        authenticator — and newly raises `StateError` (not `ConfigError`, no silent success)
        if the account already has a confirmed TOTP.

        **Only as long as no confirmed TOTP exists.** Up to 0.18.0 every call overwrote the
        secret and reset `confirmed`: a confirmed second factor thereby silently disappeared,
        the recovery codes were left orphaned, and the session afterwards counted as fully valid with the
        password alone. Because `GET /auth/totp/setup` called this method unconditionally,
        a click on a foreign link was enough — a GET carries no CSRF token, and
        `SameSite=Lax` (default) sends the session cookie along with a top-level navigation
        (finding B2-1). Whoever wants to change authenticator switches TOTP off properly
        (`totp_disable` — CSRF-protected and logged) and sets it up anew.

        A running, still **unconfirmed** attempt continues to be replaced by a fresh
        one: there is nothing to lose there, and handing on a secret that was once issued
        would be worse than a new one.
        """
        if self.store.has_confirmed_totp(user_id):
            # The attempt itself is the interesting line: up to 0.18.0 this path left
            # no trace although it removed the second factor.
            self.audit("totp_setup_denied", self._kontoname(user_id),
                       detail=f"user={user_id} grund=bereits_bestaetigt")
            raise StateError(
                f"Account {user_id} already has a confirmed TOTP — disable it first "
                f"(totp_disable), then set it up again.")
        u = self.store.get_user(user_id)
        if u is None:
            raise ConfigError(f"No account with ID {user_id} — TOTP cannot be set up.")
        # Recovery codes without a confirmed TOTP belong to a secret that nobody has any more.
        # Leaving them in place would keep the second factor open via codes that do not fit
        # the new setup.
        verwaist = self.store.count_recovery_codes(user_id)
        if verwaist:
            self.store.delete_recovery_codes(user_id)
            self.audit("recovery_verwaist_geloescht", str(u["username"]),
                       detail=f"user={user_id} n={verwaist}")
        secret = _totp.new_secret()
        self.store.set_totp(user_id, secret, confirmed=False)
        self.audit("totp_setup_start", str(u["username"]), detail=f"user={user_id}")
        uri = _totp.provisioning_uri(secret, u["username"], self.cfg.rp_name)
        return {"secret": secret, "uri": uri, "qr": _totp.qr_data_uri(uri)}

    def totp_confirm(self, user_id, code) -> bool:
        """Complete the setup — only with a valid code is TOTP really on.

        The confirmation code is **consumed** like any other (finding B2-3): until T-13 this
        place only called `verify()` and did not book the time step. The same code, just typed in
        for the setup (and possibly read off while doing so), still signed in at
        `/auth/totp` for up to 90 seconds — the single-use promise from T-9 applied only to the
        sign-in, not to the setup. Whoever sets up under `login_chain=["password","totp"]`
        gets the TOTP step credited right away with this confirmation (the
        route does that, A-1) — otherwise the code just typed would be a failed attempt there.

        An **already confirmed** TOTP is not confirmed again by this method (A-4): it would
        otherwise report `totp_enabled` for something nobody set up, and would incidentally be a
        second code checker for the active factor with a bucket of its own."""
        t = self.store.get_totp(user_id)
        if not t or not code or t["confirmed"]:
            return False
        schritt = _totp.passender_schritt(t["secret"], code)
        if schritt is None or not self.store.totp_step_verbrauchen(user_id, schritt):
            return False
        self.store.confirm_totp(user_id)
        # From here on a new second factor applies — the counterpart to `totp_disable` and
        # until now the only factor change without a line (B5-07). It is precisely this that an
        # attacker with a taken-over session does in order to come back.
        self.audit("totp_enable", self._kontoname(user_id), detail=f"user={user_id}")
        self._security_event("totp_enabled", user_id)
        return True

    def totp_disable(self, user_id):
        """Remove TOTP, together with the recovery codes (both are logged)."""
        offen = self.store.count_recovery_codes(user_id)   # count before deleting
        hatte = self.store.has_confirmed_totp(user_id)
        self.store.delete_totp(user_id)
        self.store.delete_recovery_codes(user_id)   # without TOTP, recovery codes are moot
        # Switching off a second factor is what an attacker does first once they have
        # a session. Without an entry it cannot be traced afterwards — until 2026-09-21
        # it left no trace, although TOTP AND all recovery codes fall in the process.
        self.audit("totp_disable", self._kontoname(user_id), detail=f"user={user_id} recovery_codes_geloescht={offen}")
        if hatte:
            self._security_event("totp_disabled", user_id, recovery_codes_deleted=offen)

    # ---------- Recovery codes (2FA substitute for a lost authenticator) ----------
    #: Random bytes per half of a recovery code. Two halves of 7 bytes = **112 bits**.
    #: Before, it was 3 bytes (48 bits), then 4 (64). Both are too tight for a code that
    #: REPLACES the second factor and stays valid indefinitely: a TOTP code has only a
    #: million possibilities, but is valid for 30 seconds — a recovery code is valid until it is used.
    #: 112 bits is the threshold from which NIST SP 800-63B lets a simple
    #: one-way hash suffice for a "look-up secret"; below that it requires salt and a password hashing scheme. Since
    #: the codes are stored here with sha256, the threshold is the right choice.
    #: Existing codes remain valid (only the hash is stored anyway); newly generated ones
    #: are longer.
    _RECOVERY_BYTES = 7
    #: At this few remaining codes the account page shows a warning and the
    #: security log a line — whoever uses them up should generate new ones in time.
    _RECOVERY_WARN_THRESHOLD = 3

    def generate_recovery_codes(self, user_id, n=None) -> list:
        """Generate new one-time codes (replaces existing ones). Plaintext return ONLY ONCE."""
        n = int(n or self.cfg.recovery_code_count)
        codes = ["-".join(secrets.token_hex(self._RECOVERY_BYTES) for _ in range(2)) for _ in range(n)]
        self.store.delete_recovery_codes(user_id)
        self.store.add_recovery_codes(user_id, [self._rc_hash(c) for c in codes])
        self.audit("recovery_generate", self._kontoname(user_id), detail=f"user={user_id} n={n}")
        self._security_event("recovery_codes_generated", user_id, count=n)
        return codes

    @staticmethod
    def _rc_hash(code) -> str:
        norm = str(code or "").strip().lower().replace(" ", "")
        return hashlib.sha256(norm.encode()).hexdigest()

    def _verify_recovery_code(self, user_id, code) -> bool:
        """Check and consume a one-time code. A code is valid exactly once."""
        if not code:
            return False
        if not self.store.consume_recovery_code(user_id, self._rc_hash(code)):
            return False
        # Own line (B5-07/B2-7). A consumed code means: the authenticator was missing — or someone else has a
        # code. The owner should learn of either, and the operator should be able to tell it apart from a
        # TOTP sign-in (finding B2-7). Until T-13 nothing of that remained: no
        # audit line, no hint how many codes are left.
        rest = self.store.count_recovery_codes(user_id)
        self.audit("recovery_used", self._kontoname(user_id), detail=f"user={user_id} verbleibend={rest}")
        security.seclog.warning("recovery code used user_id=%s verbleibend=%s", user_id, rest)
        self._security_event("recovery_code_used", user_id, remaining=rest)
        return True

    def recovery_codes_remaining(self, user_id) -> int:
        """How many one-time codes this account still has."""
        return self.store.count_recovery_codes(user_id)

    # ---------- Password reset (forgot password) ----------
    def federated_only(self, user_id) -> bool:
        """Pure SSO account: bound to an IdP/a directory and without a local password.

        If the directory delivers no stable identifier, the login binds an origin placeholder
        (`_OHNE_KENNUNG`, A-4) — such an account also counts as federated here.

        Limit: an LDAP or SAML account that has not signed in since the update to this version
        carries no row yet and counts as local here.

        Not regulated here: the magic login link (`magiclink_enabled`) also goes to a pure
        SSO account — that is a sign-in route switched on by the operator, not a password that
        remains; whether it should be switched off for such accounts is a product decision."""
        return (self.store.has_foreign_identity(user_id)
                and not self.store.get_password_hash(user_id))

    def send_password_reset(self, email, base_url) -> bool:
        """Send a reset link to an email address IF a matching user exists. Outwardly always the
        same message (no enumeration). `base_url` is checked (`ConfigError` for a
        foreign host, see `magic_url`).

        The check comes first — before the account lookup, so that "exception instead of False" does not
        reveal whether the address exists, and before the token is issued, so that no unusable
        token is left behind.

        The mail goes to the **stored** address, not to the input (R4-11): the lookup
        is lenient (case, whitespace), the delivery must not be.
        If delivery fails, the token is invalidated immediately (B6-12) and the error is passed on
        to the caller.
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        if self.federated_only(u["id"]):
            # A pure SSO account gets no reset link (H-4). It would set a LOCAL
            # password — a second path past the IdP or directory: lock, group removal
            # and the provider's MFA requirement would then no longer apply, and with LDAP the
            # local password even wins over the directory (`_check_password` first). The response
            # to the outside stays the same (no account probing); the reason is in the audit log.
            self.audit("reset_sso_only", u["username"], detail="no local password, federated")
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "reset_password"):
            return False
        raw = self.create_magic_token("reset_password", user_id=u["id"], email=ziel)
        url = self.magic_url(raw, base_url, "reset_password")
        mins = self.cfg.magiclink_ttl_min
        self._token_mail(raw, ziel, self.t("mail.reset.subject"),
                         self.t("mail.reset.text", mins=mins, url=url),
                         html=self.t("mail.reset.html", mins=mins, url=url))
        return True

    # ---------- Factor-chain engine ----------
    _IDENTIFYING = ("password", "pin", "oidc", "passkey", "magic", "saml")  # factors that identify the user

    def _global_chain(self):
        """(factors, strict) of the global default chain, or (None, True) for classic mode."""
        return (list(self.cfg.login_chain), self.cfg.login_chain_strict) if self.cfg.login_chain else (None, True)

    def _chain_satisfied(self, required, strict, done) -> bool:
        if strict:
            pos = [done.index(f) for f in required if f in done]
            return len(pos) == len(required) and pos == sorted(pos)   # all present AND in order
        return all(f in done for f in required)

    def _next_factor(self, required, strict, done):
        for f in required:
            if f not in done:
                return f
        return None

    def _default_satisfied(self, user_id, done) -> bool:
        """Classic policy (no login_chain): one identification factor + TOTP, if set up."""
        if not any(f in done for f in self._IDENTIFYING):
            return False
        if "passkey" in done:
            return True   # passkey alone = fully valid
        if self.store.has_confirmed_totp(user_id) and "totp" not in done:
            return False
        return True

    def _session_ok(self, user_id, done) -> bool:
        """Does the factor list satisfy the ACTIVE global policy (chain or classic)?"""
        req, strict = self._global_chain()
        if req is not None:
            ok = self._chain_satisfied(req, strict, done)
        else:
            ok = self._default_satisfied(user_id, done)
        return ok and self._link_braucht(user_id, done) is None

    def _next_login_step(self, user_id, done):
        """Next open factor up to the full (global) sign-in, or None when done."""
        req, strict = self._global_chain()
        if req is not None:
            if not self._chain_satisfied(req, strict, done):
                return self._next_factor(req, strict, done)
        elif not self._default_satisfied(user_id, done):
            return "totp"
        return self._link_braucht(user_id, done)

    def _link_braucht(self, user_id, done) -> Optional[str]:
        """Which second factor is still missing because the sign-in went through the sign-in link?
        None if none (ASVS 6.3.6, PO decision 2026-09-24, `magiclink_require_second_factor`).

        The link proves only the mailbox. If the account has a second factor, the
        sign-in requires it — otherwise the mailbox alone would be the key to an account that protected itself with
        an authenticator. The classic policy always required a set-up TOTP;
        open were only accounts with passkey and chains in which the link alone
        suffices (`["magic"]`). Accounts without a second factor are still signed in by the link alone (the
        price of C versus D, deliberately decided that way). Applies to the global policy and to every
        route chain (`require(factors=[…])`, G10)."""
        if not self.cfg.magiclink_require_second_factor or "magic" not in done:
            return None
        if "totp" in done or "passkey" in done:
            return None
        if self.store.has_confirmed_totp(user_id):
            return "totp"
        if self.store.list_webauthn(user_id):
            return "passkey"
        return None

    def _factor_entry(self, step, nxt="/") -> str:
        """The address of the input page for a factor step, with `next` attached."""
        from urllib.parse import quote
        base = {"password": self.cfg.login_path, "pin": "/auth/pin", "oidc": "/auth/oidc/start",
                "passkey": self.cfg.login_path, "totp": "/auth/totp",
                "magic": "/auth/magic/request", "saml": "/auth/saml/login"}.get(step, self.cfg.login_path)
        return f"{base}?next={quote(nxt or '/', safe='/')}"

    async def json_body(self, request: Request) -> dict:
        """Read the JSON body robustly: invalid/empty body → 400 instead of 500. Enforces CSRF
        (header X-CSRF-Token) for cookie-based clients; API-key requests are exempt."""
        try:
            data = await request.json()
        except Exception:
            raise HTTPException(400, self.t("api.json_invalid"))
        if not isinstance(data, dict):
            raise HTTPException(400, self.t("api.json_object"))
        if self.cfg.csrf_enabled and not self._csrf_entbehrlich(request):
            token = request.headers.get("x-csrf-token") or data.get("_csrf")
            if not self._herkunft_ok(request) or not self._verify_csrf(request, token):
                raise HTTPException(403, self.t("api.csrf"))
        return data

    # ---------- CSRF (Double-Submit) ----------
    def issue_csrf(self, response: Response) -> str:
        """Roll a NEW CSRF token and set it as a cookie; the return value is the token. For a
        page with a form, `ensure_csrf()` is the way — this one invalidates the forms in
        all other open tabs.

        Intended for deliberate renewal (`_rotate_csrf()`). Replaces a CSRF line that the
        response already carries instead of appending a second one. If CSRF is switched off, nothing
        happens and the return value is empty."""
        if not self.cfg.csrf_enabled:
            return ""
        token = secrets.token_urlsafe(24)
        self._csrf_cookie_setzen(response, token)
        return token

    def ensure_csrf(self, request: Request, response: Response) -> str:
        """Ensure a valid CSRF cookie and return the token for the form.

        The way for own pages of an embedding app (0.20.1): an existing, valid
        token stays — the forms in other tabs remain valid, and the response gets
        no Set-Cookie line. If it is missing or the cookie value does not look like a token
        (`_CSRF_FORM`), a new one is set, with the same attributes as with `issue_csrf()`.
        If this response has already rotated the token (`set_cookie()` after a sign-in) or
        deleted it (`logout()`), that applies: after the sign-in the new one, after the sign-out a
        fresh one — never the old one from the request. If CSRF is switched off: nothing, return "".

        Two forms, depending on when the response is created:

        * FastAPI response parameter (`def page(request: Request, response: Response)`, the page
          as return value): `csrf = auth.ensure_csrf(request, response)`, then render.
        * Finished response (Jinja `TemplateResponse`): `csrf = auth.csrf_token(request)` before
          rendering, afterwards `auth.ensure_csrf(request, response)` — both deliver the same token
          in the same request. **Not in a response that signs in or out:** the page
          is rendered before `set_cookie()`/`logout()` changes the token, its form would carry
          the old one (403 on submit). Redirect there; the follow-up request renders with the new
          cookie. With the response parameter it works: first `set_cookie()`, then `ensure_csrf()`.

        Own JS does not know the cookie name by itself — `auth.csrf_cookie_name` is Python.
        The page passes it along (template variable or `<meta>`), or the JS takes the value
        from the form field `_csrf` and sends it as `X-CSRF-Token`."""
        if not self.cfg.csrf_enabled:
            return ""
        in_antwort = self._csrf_in_antwort(response)
        if in_antwort is not None and _CSRF_FORM.fullmatch(in_antwort):
            return in_antwort                       # just rotated or already set
        if in_antwort is not None:
            # Deleted in this response (sign-out) or set to something unusable — the token
            # from the request is then no longer valid, so a fresh one.
            token = self._csrf_neu(request)
        else:
            token, neu = self._csrf_der_anfrage(request)
            if not neu:
                return token
        self._csrf_cookie_setzen(response, token)
        return token

    def _csrf_der_anfrage(self, request) -> tuple:
        """(token, new): the valid token from the cookie, otherwise a new one — exactly one per
        request, so that `csrf_token()` and `ensure_csrf()` agree. Shared by
        `render_page`, `csrf_token`, `ensure_csrf` and the admin panel: where one would
        adopt a cookie that another replaces, two pages would get two tokens."""
        cur = request.cookies.get(self.csrf_cookie_name) if request is not None else None
        if cur and _CSRF_FORM.fullmatch(cur):
            return cur, False
        scope = getattr(request, "scope", None)
        gemerkt = scope.get(_CSRF_SCOPE) if isinstance(scope, dict) else None
        if gemerkt:
            return gemerkt, True
        return self._csrf_neu(request), True

    @staticmethod
    def _csrf_neu(request) -> str:
        token = secrets.token_urlsafe(24)
        scope = getattr(request, "scope", None)
        if isinstance(scope, dict):
            scope[_CSRF_SCOPE] = token
        return token

    def _csrf_cookie_setzen(self, response, token: str) -> None:
        """THE place that writes the CSRF cookie — replaces a line that this response
        already carries for it instead of appending a second one. NOT httponly: the built-in
        JS calls read the cookie and send `X-CSRF-Token`."""
        self._set_cookie_entfernen(response, self.csrf_cookie_name)
        response.set_cookie(self.csrf_cookie_name, token, secure=self.cfg.cookie_secure,
                            samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)

    def _csrf_cookie_loeschen(self, response) -> None:
        """Delete the CSRF cookie in the browser — with Secure and path as when setting it, otherwise
        the browser silently discards the deletion of a `__Host-` cookie."""
        self._set_cookie_entfernen(response, self.csrf_cookie_name)
        response.delete_cookie(self.csrf_cookie_name, path=self.cfg.cookie_path,
                               secure=self.cfg.cookie_secure,
                               samesite=_samesite(self.cfg.cookie_samesite))

    def _csrf_in_antwort(self, response) -> Optional[str]:
        """The value this response already sets for the CSRF cookie: None = no line,
        "" = deleted."""
        praefix = self.csrf_cookie_name.encode("latin-1") + b"="
        wert = None
        for schluessel, zeile in getattr(response, "raw_headers", None) or []:
            if schluessel.lower() == b"set-cookie" and zeile.startswith(praefix):
                wert = zeile[len(praefix):].split(b";", 1)[0].strip().decode("latin-1")
        if wert is None:
            return None
        return "" if wert in ("", '""') else wert

    @staticmethod
    def _set_cookie_entfernen(response, name: str) -> None:
        """Take the Set-Cookie lines for exactly this name out of the response. The list is changed
        in place: `response.headers` holds a reference to the same list."""
        roh = getattr(response, "raw_headers", None)
        if roh is None:
            return
        praefix = name.encode("latin-1") + b"="
        roh[:] = [(k, v) for k, v in roh if not (k.lower() == b"set-cookie" and v.startswith(praefix))]

    def _verify_csrf(self, request: Request, submitted) -> bool:
        """Does the submitted CSRF token match the cookie? Comparison in constant time."""
        if not self.cfg.csrf_enabled:
            return True
        import hmac
        cookie = request.cookies.get(self.csrf_cookie_name)
        return bool(cookie) and bool(submitted) and hmac.compare_digest(str(cookie), str(submitted))

    def _csrf_entbehrlich(self, request: Request) -> bool:
        """May this request skip the CSRF check?

        Only if it is signed in **actually via API key**. Until the second audit
        it sufficed that `_extract_api_key()` returned anything — the value was not
        checked, and whether a key was used at all was not either. An arbitrary header
        `X-API-Key: made-up` thus switched the check off, the sign-in then continued via the
        **session cookie** (`current_user` asks the session first), even with
        `apikey_enabled=False`. The mechanism on which the CSRF protection rests could thereby be
        switched off by the caller.

        The reason for the exception remains right: a foreign page cannot set
        a custom header without CORS approval, and a daemon has no cookie. But the key has to be
        genuine — and where a session is present, the session counts.
        """
        if not self.cfg.apikey_enabled:
            return False
        key = self._extract_api_key(request)
        if not key:
            return False
        if self.store.get_session(request.cookies.get(self.session_cookie_name) or ""):
            return False        # cookie in play → CSRF applies, whatever the header says
        # Record the IP before the key check: this check runs BEFORE `current_user`, and
        # `verify_api_key` logs use and rejection (B5-05). Without the call, a
        # revoked key at a POST route stood in the log without an address, and a valid one twice —
        # once without, once with IP, because the IP is part of the throttle key.
        self._anfrage_merken(request)
        return self.verify_api_key(key)[0] is not None

    def require_csrf(self, request: Request, submitted):
        """For form POSTs: raises 403 if the CSRF token is missing/does not match.

        Exempt are only requests that are really signed in via API key — see
        `_csrf_entbehrlich`."""
        if self.cfg.csrf_enabled and not self._csrf_entbehrlich(request) \
                and not (self._herkunft_ok(request) and self._verify_csrf(request, submitted)):
            raise HTTPException(403, self.t("api.csrf"))

    def _eigene_hosts(self, request: Request) -> set:
        """The hostnames under which this instance is reachable in the browser.

        A foreign script in the victim's browser cannot set the Host header and X-Forwarded-Host —
        so they say where the browser WANTED to go. Plus `base_url`, so that a proxy
        that rewrites the host does not lock anyone out.

        `trusted_redirect_hosts` do NOT belong here. They are permitted targets for `?next=`, and
        in the forward-auth setup those are the protected apps — foreign code from TinySesam's
        point of view. Counted as an own origin, a form POST from a compromised
        app would pass the origin check (login CSRF, session actions in the victim's name)."""
        from urllib.parse import urlsplit

        def name(netloc):
            try:
                return (urlsplit("//" + netloc.strip()).hostname or "") if netloc else ""
            except ValueError:
                return ""
        h = request.headers
        hosts = {name(h.get("host", "")), name((h.get("x-forwarded-host") or "").split(",")[0]),
                 name(request.url.netloc)}
        if self.cfg.base_url:
            hosts.add(urlsplit(self.cfg.base_url).hostname or "")
        hosts.discard("")
        return hosts

    def _herkunft_ok(self, request: Request) -> bool:
        """Pre-check before the double-submit comparison (H-2, F-02).

        The token alone proves only that cookie and form field match each other. Whoever can set a cookie
        via a neighbouring subdomain (cookie tossing) sets the matching pair along with it
        and sends the victim by form into THEIR account (login CSRF). But the browser reveals
        where the request comes from: `Origin` on every POST, `Sec-Fetch-Site` on every
        request to a secure address (HTTPS or `localhost`; over HTTP no browser sends
        `Sec-Fetch-*`, that is how the Fetch Metadata specification wants it). A foreign page cannot
        forge these.

        * `Sec-Fetch-Site: same-origin` → yes. The browser says so itself, measured against the
          address THEY see — so an app stays usable behind a proxy that rewrites the
          host without setting X-Forwarded-Host (nginx default), even without
          `base_url` (A-3). A neighbouring subdomain gets `same-site` here, never `same-origin`.
        * `Origin` set → it must be an own host, otherwise no. `same-site` from a
          neighbouring subdomain with its own origin drops out here.
        * no usable `Origin` (missing or `null`), but `Sec-Fetch-Site: same-site` or
          `cross-site` → no. A neighbouring subdomain does get `null` if it serves its page
          with `Referrer-Policy: no-referrer`; the browser says `same-site` regardless.
          Until the rework only `cross-site` dropped out here, and where the CSRF cookie cannot carry
          `__Host-`, the token alone decided again for the neighbouring subdomain.
          This rule closes that only over HTTPS (see the last point).
        * `Origin` missing or `null`, and `Sec-Fetch-Site` says `none` (initiated by the user
          themselves, no page can trigger that) → the token alone decides.
        * `Origin` missing or `null`, and `Sec-Fetch-Site` missing → the token likewise decides
          alone. That is not only the old browser, the script or the TestClient,
          but **every browser over HTTP** (`cookie_secure=False`, except `localhost`). There
          a neighbouring subdomain with `Origin: null` (page with
          `Referrer-Policy: no-referrer`) gets as far as the token, and without `Secure` the
          CSRF cookie carries no `__Host-`, so it can be planted. Over HTTP this
          check therefore does not protect against login CSRF from the neighbourhood. Rejecting would gain little there:
          in the same configuration the session cookie itself can already be planted
          (known limit, SECURITY.md).
        """
        if not self.cfg.csrf_origin_check:
            return True
        from urllib.parse import urlsplit
        if (request.headers.get("sec-fetch-site") or "").strip().lower() == "same-origin":
            return True
        origin = (request.headers.get("origin") or "").strip()
        if origin and origin != "null":
            try:
                host = (urlsplit(origin).hostname or "").lower()
            except ValueError:
                host = ""
            if host and host in self._eigene_hosts(request):
                return True
            security.seclog.warning(
                "csrf origin rejected origin=%s ip=%s — foreign origin. If the app sits behind "
                "a proxy that rewrites the host: set base_url.",
                security.fuer_log(origin[:200]), security.fuer_log(self.client_ip(request)))
            return False
        seite = (request.headers.get("sec-fetch-site") or "").strip().lower()
        if seite in ("same-site", "cross-site"):
            security.seclog.warning("csrf origin rejected sec-fetch-site=%s origin=%s ip=%s",
                                    seite, "null" if origin else "-",
                                    security.fuer_log(self.client_ip(request)))
            return False
        return True

    # ---------- Email sending ----------
    def set_mailer(self, fn):
        """Attach a custom mail sender: fn(to, subject, text, html=None). Overrides SMTP."""
        self._mailer_override = fn

    def mail_configured(self) -> bool:
        """Can a mail go out at all — via SMTP or via `set_mailer`?"""
        return bool(self._mailer_override or self.cfg.smtp_host)

    def send_mail(self, to, subject, text, html=None):
        """Send a mail — via SMTP or the route set with `set_mailer`."""
        from .mailer import SMTPMailer
        fn = self._mailer_override or SMTPMailer(self.cfg)
        fn(to, subject, text, html)

    def _mail_ziel_ok(self, adresse, zweck, topf="mail") -> bool:
        """May another mail go to this address? Throttled per **target**, not per sender (R4-04).

        The routes' IP throttle protects the server, not the mailbox: whoever triggers "forgot password"
        for a foreign account via changing addresses would fill its mailbox
        without limit. The rejection is invisible to the outside (same response as otherwise) and
        appears in the audit log so that the operator sees the flood.

        `topf` separates quotas: sign-in link and reset share one (both bring the
        owner into the account — whoever triggers them for them sends them usable links). The notice
        of the registration has one of its own (attack A2): any stranger triggers it, it carries
        no token, and in the shared bucket three foreign registrations used up the
        quota with which the owner sends themselves a link — with operation using only the
        sign-in link, a repeatable lockout.
        """
        schluessel = f"{topf}:" + (norm_email(adresse) or "")
        if self.rl.allow(schluessel, self._sec("mail_per_address_max"),
                         self._sec("mail_per_address_window_sec")):
            return True
        self.audit("mail_ratelimit", detail=f"{zweck} an={adresse}")
        return False

    @staticmethod
    def _token_hash(raw) -> str:
        return hashlib.sha256(str(raw).encode()).hexdigest()

    def _token_mail(self, raw, to, subject, text, html=None) -> bool:
        """Send a mail with a one-time token. If delivery fails, the token is consumed
        immediately (B6-12): otherwise a valid, never delivered link lay in the database until expiry
        — a piece of evidence without a recipient, and with a relay that does deliver the mail after all,
        a link which the sender believes does not exist.

        If the token has already been discarded or redeemed before sending, no mail goes out:
        if the outbox lies between creation and sending, the operator may have locked the account in the
        meantime (H-18) — the mail would then carry only a dead link.

        True if the mail went out; False if the token was already gone (G12a counts only
        delivered links); a delivery error comes as an exception."""
        zeile = self.store.get_magic_token(self._token_hash(raw))
        if not zeile or zeile["used_at"]:
            return False
        try:
            self.send_mail(to, subject, text, html)
        except Exception:
            self.store.expire_magic_token(self._token_hash(raw))
            raise
        return True

    def after_response(self, resp, task, on_overflow=None):
        """Run `task()` only AFTER the response has been sent, in the own mail worker
        (`mailer.Postausgang`, R4-05/B6-6). Returns `resp`."""
        from starlette.background import BackgroundTask
        resp.background = BackgroundTask(self._postausgang.nachher(task, on_overflow))
        return resp

    #: Cap for `token_invalid` lines in the audit log: at most this many per window (global).
    _TOKEN_AUDIT_MAX = 20
    _TOKEN_AUDIT_FENSTER_SEC = 60

    def _token_rejected(self, zweck, request: Optional[Request] = None, grund="ungueltig"):
        """An invalid/expired/consumed one-time token was presented (B5-18).

        Until now that left no trace: whoever tried out reset or sign-in tokens was seen by the
        operator nowhere. Audit line for the operator, security log with the word of the
        non-login checks (`failed verification`) — a stale link in one's own
        mailbox is not a sign-in attempt and must not lock anyone out via fail2ban.
        """
        ip = self.client_ip(request) if request is not None else None
        # The security log gets every line: it rotates, and fail2ban's verify jail
        # bans from it exactly the one who tries out links.
        self._abgewiesen(None, ip, f"token_{zweck}", login=False)
        # The audit log, by contrast, is never cleaned up by `gc()`, and the routes are anonymous and unthrottled
        # (attack A3): every GET on /auth/magic/<nonsense> wrote a database row permanently —
        # a disk could be filled that way. The cap is therefore global per time window,
        # not per IP (an attacker changes that), and when the cap applies, exactly
        # ONE line about it appears in the audit — otherwise the operator would not see the flood.
        fenster = self._TOKEN_AUDIT_FENSTER_SEC
        if self.rl.allow("audit:token_invalid", self._TOKEN_AUDIT_MAX, fenster):
            self.audit("token_invalid", ip=ip, detail=f"zweck={zweck} grund={grund}")
        elif self.rl.allow("audit:token_invalid_gedrosselt", 1, fenster):
            self.audit("token_invalid_throttled", ip=ip,
                       detail=f"mehr als {self._TOKEN_AUDIT_MAX} in {fenster}s — weitere nur im Sicherheits-Log")

    # ---------- Magic / one-time tokens ----------
    def create_magic_token(self, purpose, user_id=None, email=None, ttl_min=None, payload=None) -> str:
        """Create a one-time token (plaintext return). Only the sha256 hash is in the DB."""
        raw = secrets.token_urlsafe(32)
        h = hashlib.sha256(raw.encode()).hexdigest()
        ttl = int(ttl_min if ttl_min is not None else self.cfg.magiclink_ttl_min) * 60
        self.store.add_magic_token(h, purpose, _jetzt() + ttl, user_id, email, payload)
        return raw

    #: Where a token is redeemed — a separate endpoint per purpose. Up to 0.15 all four ran
    #: via /auth/magic/{token}: whoever switched off the magic link thereby also lost email
    #: confirmation and invitation, which have nothing to do with it.
    TOKEN_PATHS = {
        "login": "/auth/magic/{t}",
        "verify_email": "/auth/verify/{t}",
        "invite": "/auth/invite/{t}",
        "reset_password": "/auth/reset?token={t}",
        "email_change": "/auth/email/{t}",
    }

    def magic_url(self, raw, base_url, purpose="login") -> str:
        """The link the recipient clicks — path depending on purpose (`TOKEN_PATHS`). `base_url`
        is checked: a foreign host raises `ConfigError` — in a route
        `public_base(request)` supplies the checked base.

        The check sits here because all four mail routes converge here: reset,
        sign-in link, confirmation and invitation. So the protection applies regardless of who builds the
        route — also for an app with its own form. Permitted are `base_url`, a host
        from `trusted_redirect_hosts` and loopback.
        """
        from urllib.parse import quote
        pfad = self.TOKEN_PATHS[purpose].format(t=quote(str(raw), safe=""))
        return f"{self._gepruefte_basis(base_url)}{pfad}"

    def redeem_magic(self, raw, purpose=None) -> Optional[dict]:
        """Redeem a token (one-shot). Returns {purpose,user_id,email,payload} or None (invalid/expired/used).

        `payload` with English keys (schema 12): an address-change link carries `old`, the
        previous address — up to 0.21.x `alt`, which is mapped on reading (`payload_lesen`)."""
        if not raw:
            return None
        h = hashlib.sha256(raw.encode()).hexdigest()
        row = self.store.get_magic_token(h)
        if not row or (purpose and row["purpose"] != purpose):
            return None
        if not self.store.use_magic_token(h):
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": payload_lesen(row["purpose"], row["payload"])}

    def peek_magic(self, raw, purpose=None) -> Optional[dict]:
        """Check a token WITHOUT consuming it (for the invite flow: redeem only at registration).
        Return as for `redeem_magic`."""
        if not raw:
            return None
        row = self.store.get_magic_token(hashlib.sha256(raw.encode()).hexdigest())
        if not row or row["used_at"] or row["expires_at"] < _jetzt():
            return None
        if purpose and row["purpose"] != purpose:
            return None
        return {"purpose": row["purpose"], "user_id": row["user_id"], "email": row["email"],
                "payload": payload_lesen(row["purpose"], row["payload"])}

    def create_invite(self, email, base_url, roles=None, is_admin=False, ttl_min=None) -> dict:
        """Create an invitation (+ optionally send it). Return {url, token}. The token carries the
        intended roles/admin rights; it is redeemed only at registration. `base_url`
        is checked (`ConfigError` for a foreign host, see `magic_url`).

        The check happens before the token is issued, so that a rejected call leaves no
        invitation token behind. If sending fails, the token is invalidated (B6-12).
        """
        base_url = self._gepruefte_basis(base_url)
        raw = self.create_magic_token("invite", email=email, ttl_min=ttl_min,
                                      payload={"roles": list(roles or []), "is_admin": bool(is_admin)})
        url = self.magic_url(raw, base_url, "invite")
        if email and self.mail_configured():
            self._token_mail(raw, email, self.t("mail.invite.subject"),
                             self.t("mail.invite.text", url=url),
                             html=self.t("mail.invite.html", url=url))
        self.audit("invite_create", detail=email)
        return {"url": url, "token": raw}

    def send_verify_email(self, user_id, email, base_url) -> bool:
        """Send the confirmation link for an address. False if there is no mailer.
        `base_url` is checked (`ConfigError` for a foreign host, see `magic_url`).
        If sending fails, the token is invalidated (B6-12) and the error is passed on.
        The link unlocks an account whose confirmation is pending (registration), never one
        that the operator has locked (admin panel, `set_disabled(user_id, True)`) — even if
        the link comes into being only after this lock, e.g. because the call waits via
        `after_response` (H-18).
        When redeemed it sets the evidence for the address (`email_verified`), as long as it is still the
        account's.
        """
        senden = self._verify_mail(user_id, email, base_url)
        if senden is None:
            return False
        senden()
        return True

    def _verify_mail(self, user_id, email, base_url):
        """Create the confirmation token NOW and return the sending as a function — or
        None if there is no mailer. `base_url` is checked as with `send_verify_email`.

        Separate, because registration only pushes the sending into the outbox (R4-05/B6-6),
        not the token issuing: the operator's lock discards open tokens (H-18).
        If the token only came into being in the mail worker, a lock in the waiting window found nothing, and
        the delayed link lifted it again afterwards (T-13 attack, mail × operation)."""
        base_url = self._gepruefte_basis(base_url)
        if not (email and self.mail_configured()):
            return None
        raw = self.create_magic_token("verify_email", user_id=user_id, email=email)
        url = self.magic_url(raw, base_url, "verify_email")

        def senden():
            self._token_mail(raw, email, self.t("mail.verify.subject"),
                             self.t("mail.verify.text", url=url),
                             html=self.t("mail.verify.html", url=url))
        return senden

    # ---------- Self-service: username and address (PO decision 2026-09-25) ----------
    #: Longer is no longer a name but a payload (header, log lines, panel).
    NAME_MAX = 150

    def change_username(self, user_id, new_username, ip: Optional[str] = None, *,
                        by_operator: bool = False) -> str:
        """Change one's own username. Returns the new name, `ValueError` with the
        reason if it is not possible.

        **A self-chosen name does not bind via LDAP/SAML** (G2-N): the account afterwards carries
        `users.name_selbst_gewaehlt`, and a sign-in via a federated source never binds it
        via the name — otherwise a local account renames itself after someone from the directory
        and inherits identifier and groups at their next sign-in. Whoever renames as **operator**
        (from the embedding service, e.g. to resolve a collision) passes
        `by_operator=True`: then the name stands for the operator, the marker is dropped, and the
        audit line says `durch=betreiber`.

        Everything attached to the account — sessions, keys, factors, roles, bindings to LDAP/SAML/OIDC —
        hangs on the ID, not on the name, and stays. Outwardly `Remote-User` changes; `Remote-Id`
        is stable. The same rules as on creation (free in BOTH namespaces, no
        control characters) and three of its own:

        * **No name with `@`**, except the own taken address: otherwise someone would occupy the
          address of a person who does not yet exist here, and that person would get
          "taken" at registration (the same rule as registration with confirmation, attack A1).
        * **No name from `admin_identifiers`**: whoever calls themselves that would become
          first admin at the next login. The response is the same as for "taken" — the allowlist stays hidden.
        * **Not in mode `login_identifier="email"`**: there the name is the address and follows it.
        * **Alongside LDAP only as operator** (`by_operator=True`, since 2026-09-27): there the
          names come from the directory; an account that renames itself could adopt the name of a
          person who has never signed in, and lock them out."""
        konto = self.store.get_user(user_id)
        if not konto:
            raise ValueError(self.t("api.not_found"))
        if self.cfg.login_identifier == "email":
            raise ValueError(self.t("api.username_follows_email"))
        # Alongside LDAP nobody renames themselves (PO decision 2026-09-27): a local account
        # could adopt the directory name of a person who has never signed in, and
        # thereby lock them out — the same gap as open registration. The operator may.
        if self.cfg.ldap_enabled and not by_operator:
            raise ValueError(self.t("api.username_from_directory"))
        name = str(new_username or "").strip()
        if not name:
            raise ValueError(self.t("err.username_required"))
        if len(name) > self.NAME_MAX or name_ungueltig(name):
            raise ValueError(self.t("err.username_invalid"))
        eigene = norm_email(konto["email"]) if konto["email"] and konto["email_verified"] else None
        if "@" in norm_kennung(name) and norm_email(name) != eigene:
            raise ValueError(self.t("api.username_is_address"))
        if name == konto["username"]:
            return name
        erlaubt = {norm_kennung(i) for i in (self.cfg.admin_identifiers or []) if str(i).strip()}
        if self.identifier_taken(name, exclude_id=user_id) or norm_kennung(name) in erlaubt:
            raise ValueError(self.t("api.user_exists"))
        alt = konto["username"]
        try:
            # Marker and name in one transaction (G2-N) — in between, a sign-in via
            # LDAP/SAML could otherwise still bind the account via the new name.
            self.store.set_username(user_id, name, selbst_gewaehlt=not by_operator)
        except sqlite3.IntegrityError:
            # Race: taken between check and write — the database decides.
            raise ValueError(self.t("api.user_exists")) from None
        self.audit("username_changed", name, ip,
                   f"alt={alt} durch=betreiber" if by_operator else f"alt={alt}")
        self._security_event("username_changed", user_id, old=alt, new=name)
        return name

    def request_email_change(self, user_id, new_email, base_url):
        """Request the change to a new address: confirmation link to the NEW one. Returns the
        sending function (for `after_response`) — even when the address is taken
        or reserved and no link goes out; `senden()` says so with True/False. None only
        for a throttle and for the own, already taken address. `ValueError` for an
        invalid address or without a mailer. If sending fails before it begins (full
        queue), `senden.verwerfen()` lets the token expire — as `on_overflow` for
        `after_response` (since 2026-09-27).

        The response to the requester is the same in every case: if the address is already the identifier
        of another account (or is in `admin_identifiers`), no link goes out, and
        that appears only in the audit log — otherwise the account page would be an oracle for taken
        addresses. The new address is valid only with the click (`confirm_email_change`), before that
        nothing changes.

        **One branch for every target** (G12b, since 2026-09-26). Until then the request for
        a taken address returned early, and that was visible in three places although the
        response read the same: the notice to the own address came only for a free one, the
        request used up the account's quota only for a free one, and the account page
        named `email_change_taken`. Plus the runtime: one row fewer in the database and
        no sending after the response. Now: first the throttles (for every target), then in every
        case a token and an audit line — for "no" a throwaway token, expired from the start
        (nobody knows the plaintext, `offener_token` and redeeming do not see it,
        `gc()` clears it; the pattern of R4-03 for registration) —, then always a sender
        that sends the notice to the own address in every case. The account page shows every
        request as `email_change_requested` (`own_events`)."""
        return self._wechsel_beantragen(user_id, new_email, base_url)

    def _wechsel_beantragen(self, user_id, neu, base_url, quelle: str = ""):
        """`request_email_change`, with the source for the path via LDAP/SAML
        (`_adresse_aus_quelle_belegen`). With `quelle` the detail of the audit line begins with
        `konto=<id> quelle=<quelle>` — the same for every result, free like taken. From that the
        database also counts the rejections (`Store.quellmail_seit`, attack round 2026-09-26)."""
        konto = self.store.get_user(user_id)
        if not konto:
            raise ValueError(self.t("api.not_found"))
        # Fold first, then check (like registration and admin API): `x＠evil.test@example.com`
        # is valid raw and, folded, an address with two `@` — it would be the token target, recipient
        # and, after the click, the account's taken address (attack round, finding 3).
        mail = norm_email(neu or "") or ""
        if not valid_email(mail):
            raise ValueError(self.t("api.email_invalid"))
        if not self.mail_configured():
            raise ValueError(self.t("api.no_mail"))
        base_url = self._gepruefte_basis(base_url)
        if mail == norm_email(konto["email"] or "") and konto["email_verified"]:
            return None
        # Throttled per ACCOUNT (attack round, finding 3 of self-service): the bucket per target address
        # protects a mailbox, not against scattering — otherwise an account would send mails to arbitrarily
        # many foreign addresses until only the IP throttle brakes (reputation of the sender domain, and
        # every mail is a pretext to click). The same quota as per target address.
        # BEFORE the question "taken?" (G12b): otherwise an account probed taken addresses without
        # quota, and after three probes the link to the own check address revealed whether they
        # were taken.
        if not self.rl.allow(f"wechsel-konto:{user_id}", self._sec("mail_per_address_max"),
                             self._sec("mail_per_address_window_sec")):
            self.audit("mail_ratelimit", konto["username"], detail=f"email_change konto={user_id}")
            return None
        # Bucket of its own (like the registration notice, attack A2): anyone with an account requests the change to a
        # FOREIGN address — in the `mail` bucket it would use up the quota with which
        # the owner of that address sends themselves a sign-in link.
        if not self._mail_ziel_ok(mail, "email_change", topf="wechsel"):
            return None
        # An address from `admin_identifiers` gets no change link (like the name): on an
        # instance without an admin, the owner could easily click "confirm your new address" for their
        # own setup — and the FOREIGN account would afterwards carry the taken allowlist address and
        # be first admin at the next sign-in. The same response as "taken".
        nein = ("email_change_taken" if self.identifier_taken(mail, exclude_id=user_id)
                else "email_change_reserved" if self._allowlist_adresse(mail) else None)
        # The same database work in both cases (G12b): for "no" a token that has already
        # expired when it is created.
        raw = self.create_magic_token("email_change", user_id=user_id, email=mail,
                                      ttl_min=(-1 if nein else int(self.cfg.email_change_ttl_min)),
                                      payload={"old": konto["email"] or ""})
        url = self.magic_url(raw, base_url, "email_change")
        herkunft = f"konto={int(user_id)} quelle={quelle} " if quelle else ""
        self.audit(nein or "email_change_requested", konto["username"], detail=f"{herkunft}neu={mail}")
        # The mail names the account: whoever confirms an address should see for WHICH one — otherwise
        # a good-faith click confirms the own address for a foreign account (suspicion from
        # the attack round; mainly concerns the path via LDAP/SAML, where the request does not come from the
        # owner of the address).
        name = str(konto["username"])
        alt = norm_email(konto["email"] or "") if konto["email_verified"] else None

        def senden() -> bool:
            try:
                return (not nein) and self._token_mail(
                    raw, mail, self.t("mail.email_change.subject"),
                    self.t("mail.email_change.text", name=name, url=url),
                    html=self.t("mail.email_change.html", name_html=_html.escape(name), url=url))
            finally:
                # In EVERY case (G12b) — even if no link went out, and even if sending
                # the link failed: the text ("applies only once the link is clicked") is correct
                # always, and its absence would reveal "taken".
                if alt and alt != mail:
                    self._wechsel_antrag_hinweis(alt, name, mail)

        def verwerfen() -> None:
            """Sending fails before it begins (queue full): the token expires
            immediately, as after a failed sending (B6-12) — a never delivered link would
            otherwise, as an open one, hold up the next until its expiry (`offener_token`)."""
            self.store.expire_magic_token(self._token_hash(raw))
        senden.verwerfen = verwerfen   # type: ignore[attr-defined]
        return senden

    def _wechsel_antrag_hinweis(self, alt, name, neu) -> None:
        """Even the REQUEST for an address change goes to the previous, taken address
        (attack round, finding 1): if it comes from a taken-over session, the owner learns of it
        before the link is redeemed — and a password change or "end sessions"
        discards it. **Without a link** (nothing whose base would have to be checked; test_self_service)."""
        if self._mail_ziel_ok(alt, "email_change_notice", topf="hinweis"):
            self.send_mail(alt, self.t("mail.email_change_notice.subject"),
                           self.t("mail.email_change_notice.text", name=name, new=neu))

    def _allowlist_adresse(self, mail) -> bool:
        """Steht diese Adresse in `admin_identifiers`?"""
        return norm_email(mail or "") in {norm_email(i) for i in (self.cfg.admin_identifiers or [])
                                          if "@" in str(i)}

    def confirm_email_change(self, raw, ip: Optional[str] = None) -> Optional[str]:
        """Redeem the confirmation link. Return: "ok", "taken" (meanwhile the identifier of
        another account; until 0.21.x "vergeben") or None (invalid, expired, used, account
        locked/gone).

        Afterwards the new address is the account's, **with evidence** (the click proved
        the mailbox). In mode `login_identifier="email"` the username moves along if it was the
        old address. Open links to the old address (reset, sign-in link) no longer
        apply — they belonged to a mailbox that no longer belongs to the account. The old address
        gets a notice (ASVS 6.3.7)."""
        data = self.redeem_magic(raw, purpose="email_change")
        if not data or not data.get("user_id"):
            return None
        uid = data["user_id"]
        konto = self.store.get_user(uid)
        if not konto or konto["disabled"]:
            return None
        mail = norm_email(data.get("email") or "")
        if not mail:
            return None
        if self.identifier_taken(mail, exclude_id=uid):
            self.audit("email_change_taken", konto["username"], ip, f"neu={mail} beim_bestaetigen=1")
            return "taken"
        if self._allowlist_adresse(mail):     # only got onto the list after the request
            self.audit("email_change_reserved", konto["username"], ip, f"neu={mail} beim_bestaetigen=1")
            return "taken"
        alt = konto["email"] or ""
        # Address and (in email mode) the name in ONE transaction: written separately,
        # the new address would stand next to the old name after a failure of the second.
        name_folgt = (self.cfg.login_identifier == "email" and bool(alt)
                      and norm_email(konto["username"]) == norm_email(alt))
        try:
            self.store.adresse_wechseln(uid, mail, name_folgt=name_folgt)
        except sqlite3.IntegrityError:
            # Race (G12c): the address has become the identifier of another account between check
            # and write. The same response as above; nothing is changed.
            self.audit("email_change_taken", konto["username"], ip,
                       f"neu={mail} beim_bestaetigen=1 wettlauf=1")
            return "taken"
        self.store.revoke_user_magic_tokens(uid)
        name = self._kontoname(uid)
        self.audit("email_changed", name, ip, f"alt={alt} neu={mail}")
        self._security_event("email_changed", uid, old=alt, new=mail)
        if alt and self.mail_configured():
            def hinweis():
                self.send_mail(alt, self.t("mail.email_changed.subject"),
                               self.t("mail.email_changed.text", mail=mail))
            self._hinweis_ausgang.einreihen(hinweis)
        return "ok"

    def _send_signup_notice(self, email, base_url) -> bool:
        """Notice to the owner of an address with which someone wanted to register again (R4-03).

        With confirmation switched on, registration answers for a taken address
        exactly as for a free one ("confirmation mail is on its way") — otherwise it revealed via
        409 and text which addresses have an account. The real owner gets instead
        this mail: no token, only the way to sign in. Throttled like any mail (R4-04), but
        in a bucket of its own — otherwise it would lock the owner out of their own links (A2).
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["is_service"] or not self.mail_configured():
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "signup_notice", topf="hinweis"):
            return False
        login = f"{base_url}{self.cfg.login_path}"
        self.send_mail(ziel, self.t("mail.signup_notice.subject"),
                       self.t("mail.signup_notice.text", login=login),
                       html=self.t("mail.signup_notice.html", login=login))
        return True

    def send_login_link(self, email, base_url, next="/") -> bool:
        """Send a login link to an email address IF a matching interactive user exists.
        Return only internal — outwardly always the same message (no user enumeration).
        `base_url` is checked (`ConfigError` for a foreign host, see `magic_url`).

        The check comes first — before the account lookup, so that the exception reveals no address.
        Sending goes to the stored address (R4-11), throttled per target (R4-04); a
        failed sending invalidates the token (B6-12).
        """
        base_url = self._gepruefte_basis(base_url)
        u = self.store.get_user_by_email(email)
        if not u or u["disabled"] or u["is_service"]:
            return False
        ziel = u["email"]
        if not self._mail_ziel_ok(ziel, "login"):
            return False
        raw = self.create_magic_token("login", user_id=u["id"], email=ziel, payload={"next": next})
        url = self.magic_url(raw, base_url)
        mins = self.cfg.magiclink_ttl_min
        self._token_mail(raw, ziel, self.t("mail.login_link.subject"),
                         self.t("mail.login_link.text", mins=mins, url=url),
                         html=self.t("mail.login_link.html", mins=mins, url=url))
        return True

    # ---------- Sessions ----------
    def _ttl(self, remember: bool = True) -> int:
        """Server-Session-Lebensdauer. remember=False → kurze Transient-TTL (Session-Cookie)."""
        hours = self.cfg.session_ttl_hours if remember else self.cfg.session_ttl_transient_hours
        return hours * 3600

    def start_session(self, user_id, method, ip=None, ua=None, remember: bool = True) -> tuple[str, bool]:
        """New session with the first factor. Returns (token, session_ok). session_ok=False → further steps needed."""
        done = [method]
        mfa_ok = self._session_ok(user_id, done)
        token = self._sitzung_anlegen(user_id, self._ttl(remember), mfa_ok, method, ip, ua, remember,
                                      factors=done)
        if mfa_ok:   # full login completed → audit
            self._anmeldung_vollstaendig(user_id, ip, method)
            self._vermerke_erstlogin(user_id)
            self.lift_lockout(user_id)
        return token, mfa_ok

    def _sitzung_anlegen(self, user_id, ttl, mfa_ok, method, ip=None, ua=None, remember=True,
                         factors=None) -> str:
        """THE place where a session row comes into being — and the full one is noted.

        A session that comes into being here already fully valid is a sign-in: first factor without
        chain, the last step of a chain (`apply_factor`, `complete_totp`), an
        identity switch. Setting its cookie (`set_cookie()`) then rotates the CSRF token
        in the same response (0.20.1) — no matter which route the sign-in came through, including an
        own one of the app (`start_session` + `set_cookie`). A step-up creates no row
        (`store.rotate_session`) and therefore rotates nothing. A guard in `tests/test_csrf.py`
        (E3) ensures that `store.create_session` is called only here."""
        token = self.store.create_session(user_id, ttl, mfa_ok, method, ip, ua, remember,
                                          factors=factors)
        if mfa_ok:
            self._anmeldung_vormerken(token)
        return token

    def _anmeldung_vormerken(self, token: str) -> None:
        h = self.store.session_hash(token)
        with self._frisch_lock:
            self._frische_anmeldungen[h] = None
            while len(self._frische_anmeldungen) > _FRISCH_MAX:
                self._frische_anmeldungen.popitem(last=False)

    def _anmeldung_einloesen(self, token) -> bool:
        """Was this token a sign-in just now? Once yes, afterwards no."""
        if not token:
            return False
        h = self.store.session_hash(token)
        with self._frisch_lock:
            if h in self._frische_anmeldungen:
                del self._frische_anmeldungen[h]
                return True
        return False

    def _vermerke_erstlogin(self, user_id: int) -> None:
        """Record the first complete login (R3-1).

        The self-enrollment in the default operating mode hangs on this: an account may set up the factor required
        by the chain itself as long as it has never been used. The note
        closes this window — at the FIRST complete login, no matter by which
        route it came about. An open setup window is closed in the process: it was meant for
        exactly this one process."""
        if not self.store.mark_first_login(user_id, _jetzt()):
            return
        u = self.store.get_user(user_id)
        try:
            offen = u["mfa_enroll_until"] if u else None
        except (IndexError, KeyError):
            offen = None
        if offen:
            self.store.set_mfa_enroll_until(user_id, None)

    def apply_factor(self, request, user_id, factor, ip=None, ua=None, remember=True,
                     email_verified: Optional[bool] = None) -> tuple[str, bool, bool]:
        """Apply a confirmed factor: attach to the running session of the same user
        (chain step) OR start a new session (first factor/identity switch).
        Returns (token, session_ok, is_new). With is_new the caller must call set_cookie(resp, token).

        `email_verified` passes a federated route through (OIDC: claim `email_verified`;
        SAML and LDAP know no evidence and pass `False` through) — this is where
        the first admin is decided, and an unverified address must not carry it. The factor goes
        along to `_maybe_promote_admin`: for a federated factor it applies fail-closed there,
        a forgotten argument therefore does not promote.

        A locked account never gets a session here (403) — no matter which route verified
        the factor. Every sign-in route ends in this method; the check in the individual
        routes remains, but the class no longer depends on every new route knowing it
        (H-18: sign-in link and passkey created a session for a locked account, which only
        `current_user()` discarded again)."""
        konto = self.store.get_user(user_id)
        if not konto or konto["disabled"]:
            self.audit("login_disabled", str(konto["username"]) if konto else None, ip, factor)
            raise HTTPException(403, self.t("api.account_disabled"))
        s = self._session_from_request(request)
        if s and s["user_id"] == user_id:
            # same identity → attach the factor to the running session (chain/route step).
            # An identity switch (another user) falls through → new session.
            done = json.loads(s["factors_done"] or "[]")
            was_ok = bool(s["mfa_ok"])
            if factor not in done:
                done.append(factor)
            ok = self._session_ok(user_id, done)
            self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
            self._maybe_promote_admin(self.store.get_user(user_id), email_verified,
                                      faktor=factor)
            if ok and not was_ok:
                self._anmeldung_vollstaendig(user_id, s["ip"], factor)
                self._vermerke_erstlogin(user_id)
                self.lift_lockout(user_id)
                # **New token on privilege change.** Here the session turns from a half login
                # into a fully valid one — OWASP Session Management Cheat Sheet: "The session ID must
                # be renewed or regenerated by the web application after any privilege level
                # change." Before, it kept its token: whoever could set a cookie on the victim before the login
                # (subdomain, plaintext HTTP) held a fully authenticated session
                # after the victim's second factor.
                neu_token = self._sitzung_anlegen(
                    user_id, self._ttl(bool(s["remember"])), True, s["method"],
                    s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
                self._nachfolger(s, neu_token)
                self.store.delete_session_by_handle(s["token_hash"])
                self._andere_nach_abschluss(s, neu_token)
                return neu_token, ok, True      # is_new → the caller sets the cookie anew
            if ok and was_ok:
                # The session was already fully valid, the factor only refreshes it — that is a
                # step-up (mfa_at has just been set anew). That one also gets a new token
                # (F-06, ASVS 5.0 7.2.4); lifetime and sign-in time remain.
                gedreht = self.store.rotate_session(s["token_hash"], self._gnade())
                if gedreht:
                    return gedreht, ok, True
            # The plaintext token from the cookie is returned — the caller builds
            # redirects and cookies from it. The session row holds only the handle.
            return request.cookies.get(self.session_cookie_name), ok, False
        token, ok = self.start_session(user_id, factor, ip, ua, remember)
        self._maybe_promote_admin(self.store.get_user(user_id), email_verified, faktor=factor)
        return token, ok, True

    def _nachfolger(self, alte_zeile, neu_token) -> None:
        """What hangs on the half session passes to the full one that replaces it — BEFORE
        deleting the old one: the OIDC rows (4a, otherwise the foreign key would take them along) and the
        explicit choice "stay signed in" (F-05).

        `alte_zeile` is a whole row from `get_session` (`SELECT *`); the column has always existed since
        the migration to schema 11. If it is missing after all, that should fail loudly — a
        silent skip would lose the choice and with it the long idle period, without anyone
        noticing."""
        neu = self.store.session_hash(neu_token)
        self.store.oidc_sitzung_umhaengen(alte_zeile["token_hash"], neu)
        if alte_zeile["bleiben_gewaehlt"]:
            self.store.set_session_bleiben(neu)

    def _andere_nach_abschluss(self, alte_zeile, neu_token) -> None:
        """If the half session recorded that the remaining ones are to be ended (limit d), then now — with
        the full session that has just come into being as the only one that stays.

        Occasion: the mandatory setup of TOTP in the middle of a chain (`password → totp → pin`)
        ends with a HALF session, and a half one must not end the remaining ones. The offer
        under ASVS 7.4.3 was previously omitted there entirely. Now the page asks as usual, and the
        consent is redeemed here as soon as the sign-in is complete. The column has existed
        since schema 11 (as with `_nachfolger`: if missing, it fails loudly)."""
        if not alte_zeile["andere_beenden"]:
            return
        self.store.delete_user_sessions_except(alte_zeile["user_id"], self.store.session_hash(neu_token))
        u = self.store.get_user(alte_zeile["user_id"])
        self.store.audit_log("sessions_revoke", u["username"] if u else None, alte_zeile["ip"],
                             "scope=others nach_einschreibung=1")

    def _login_redirect_after(self, request, token, user_id, nxt):
        """Target redirect after a factor: nxt if the session is complete, otherwise the input page of the next factor."""
        return self._nach_dem_faktor(request, token, user_id, nxt)[0]

    def _nach_dem_faktor(self, request, token, user_id, nxt) -> tuple:
        """(onward, next, done) after a provided factor — the one source for the
        redirect of every sign-in route and for `LoginResult.next_url`/`next_factor`/`done`."""
        s = self.store.get_session(token)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if s and s["mfa_ok"]:
            # Whoever explicitly signs in (again) wants to go to the application it returns to —
            # an earlier sign-out "here only" (T-22) no longer applies to that.
            if "://" in str(nxt or ""):
                from urllib.parse import urlsplit
                ziel = (urlsplit(str(nxt)).hostname or "").lower()
                if ziel:
                    self.store.gate_fortsetzen(s["token_hash"], ziel)
            return nxt, None, True
        step = self._next_login_step(user_id, done)
        return (self.browser_path(request, self._factor_entry(step, nxt)) if step else nxt), step, False

    def complete_totp(self, token) -> Optional[str]:
        """Complete the TOTP step: attach factor `totp` to the running session. Returns a
        new session token that belongs in the cookie (`new = auth.complete_totp(token)`,
        `if new: auth.set_cookie(resp, new)`) — the old one is dead afterwards, also in a step-up.

        A new token is issued if the session thereby becomes fully valid or, already fully valid,
        is freshly confirmed (step-up, F-06). Otherwise `None` (nothing to do). Since F-06 this applies
        to the step-up as well: an own UI that ignores the return value there keeps
        a dead session in the cookie afterwards. At login (half → full) this was always so.

        Called this since 0.18.0 because the old name `complete_mfa` promised more than the method
        does — MFA is the whole chain, here it is about exactly one factor. `complete_mfa` remains
        as an alias and is not removed; a rename that breaks existing calls
        would not be worth the gain.
        """
        s = self.store.get_session(token)
        if not s:
            return None
        konto = self.store.get_user(s["user_id"])
        if not konto or konto["disabled"]:
            # Locked between the first factor and TOTP: the half session ends here instead of
            # becoming a fully valid one (H-18, the same rule as in `apply_factor`).
            self.store.delete_session_by_handle(s["token_hash"])
            return None
        war_ok = bool(s["mfa_ok"])
        done = json.loads(s["factors_done"] or "[]")
        if "totp" not in done:
            done.append("totp")
        ok = self._session_ok(s["user_id"], done)
        self.store.set_session_factors(s["token_hash"], done, mfa_ok=ok)
        if ok:
            self._anmeldung_vollstaendig(s["user_id"], s["ip"], "totp")
        if ok and not war_ok:
            self.lift_lockout(s["user_id"])
            # Privilege change → new token (OWASP Session Management). Returns it so that the
            # caller can set the cookie — the old token belongs to a deleted row.
            neu_token = self._sitzung_anlegen(
                s["user_id"], self._ttl(bool(s["remember"])), True, s["method"],
                s["ip"], s["user_agent"], bool(s["remember"]), factors=done)
            self._nachfolger(s, neu_token)
            self.store.delete_session_by_handle(s["token_hash"])
            self._andere_nach_abschluss(s, neu_token)
            return neu_token
        if ok and war_ok:
            # The session was already fully valid; `set_session_factors` has just set `mfa_at` anew
            # — that is a step-up, and it rotates the token like `/auth/reauth` and
            # `apply_factor` (F-06, ASVS 5.0 7.2.4). Before, it stayed: a cookie that was read along
            # thus got fresh sudo rights. Lifetime and sign-in time remain.
            return self.store.rotate_session(s["token_hash"], self._gnade())
        return None

    # ---------- Signing in for own pages (stage A, 0.22.0) ----------
    # PO finding 2026-09-26: the README showed `check_password` + `start_session` as building blocks
    # of an own login page. The inner checkers do not throttle — lock, counter, streak and
    # the fail2ban lines existed only in the routes. These three methods ARE now the routes:
    # `POST /auth/login`, `/auth/pin` and `/auth/totp` call them and only render the
    # result. One source, no drift — `tests/test_sign_in.py` ensures via AST that none
    # of the three routes calls an inner checker itself, and checks own pages against the
    # built-in ones (the same audit and log lines).

    @staticmethod
    def _csrf_mitgeschickt(request, csrf: Optional[str]) -> Optional[str]:
        """The submitted CSRF token: the argument, otherwise the header `X-CSRF-Token`."""
        return request.headers.get("x-csrf-token") if csrf is None else csrf

    def _bleiben_gewaehlt(self, remember: Optional[bool]) -> bool:
        """Is "stay signed in" chosen? Without a tick in the form (`remember_me_enabled=False`) every
        session counts as persistent, as before; otherwise only an explicit True (F-05)."""
        return True if not self.cfg.remember_me_enabled else remember is True

    def _anmeldung_nein(self, grund: str, status: int, text: str, weiter: str,
                        naechster: Optional[str] = None) -> LoginResult:
        """A failure: no session, no cookie — only reason, status and text."""
        return LoginResult(ok=False, reason=grund, status=status, message=self.t(text) if text else "",
                           next_url=weiter, next_factor=naechster)

    def _anmeldung_gesperrt(self, kennung: str, weiter: str, naechster: Optional[str] = None,
                            text: str = "err.locked", grund: str = "locked") -> LoginResult:
        """The pre-booking was rejected. A streak lock (B2-6) does not expire —
        "temporary" would be a lie, and the user needs the way out. The message reveals
        nothing about the existence of the account: counting is per identifier, whether it exists or not.
        A deferral (G9) gets the same 429 and the same reason as a lock — otherwise
        the response would reveal that someone else is currently signing in under this identifier or address."""
        if self._serie_voll(kennung):
            return self._anmeldung_nein("locked_series", 429, "err.locked_serie", weiter, naechster)
        return self._anmeldung_nein(grund, 429, text, weiter, naechster)

    def _angemeldet(self, request, token, neu: bool, user_id: int, nxt: str) -> LoginResult:
        """A success: target and open factor from the same source as every redirect."""
        weiter, naechster, fertig = self._nach_dem_faktor(request, token, user_id, nxt)
        return LoginResult._with_session(self, token if neu else None, ok=True, reason="ok",
                                         status=303, next_url=weiter, next_factor=naechster,
                                         done=fertig, user=self.get_user(user_id))

    def login_password(self, request: Request, username: str, password: str, *, next: str = "",
                       remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
        """Sign in with identifier and password — throttled, counted and locked like `POST /auth/login`, which calls exactly this method.

        The building block for an own login route (SPA, JSON, other fields). It checks the
        CSRF token (`csrf`, otherwise header `X-CSRF-Token`), throttles per IP, pre-books the attempt atomically
        (failed attempts per identifier, IP and pair, streak), asks with `ldap_enabled` the
        directory as a fallback (one identifier, one account; an outage is not a failed attempt),
        writes audit and security log (the lines for fail2ban) and creates the session —
        or attaches the factor to the running one. A `LoginResult` comes back:

            result = auth.login_password(request, username, password, next=next, csrf=csrf)
            if not result:
                return mein_formular(fehler=result.message, status=result.status)
            return result.redirect()     # to the open factor (result.next_factor) or to next

        `remember=True` is the ticked "stay signed in" box. Raises only what the route
        raises too: `HTTPException(403)` for a wrong CSRF token (and from `apply_factor` for an
        account that has just been locked) as well as the unexpected — the attempt then counts as a
        failed attempt. Synchronous: call from a `def` route (FastAPI uses the thread pool for it),
        in an `async def` route via `run_in_threadpool`."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        if not cfg.password_enabled:
            return self._anmeldung_nein("method_disabled", 404, "api.password_off", nxt)
        if not username or not password:
            return self._anmeldung_nein("missing", 400, "err.required", nxt)
        bleiben = self._bleiben_gewaehlt(remember)
        ip = self.client_ip(request)
        if not self._rate_ok(ip):
            return self._anmeldung_nein("ratelimit", 429, "err.rate", nxt)
        # Check and book in ONE step (R7-2): with `_is_locked()` beforehand and
        # `_record_login()` afterwards the whole password check lay in between, and a parallel
        # burst read "not yet locked" N times. From here on the attempt already stands as a
        # failed attempt in the table; `_record_login(..., versuch=…)` turns it into a success.
        # With LDAP it stays pending until the directory has answered (G9): on an outage it is
        # taken back (F-23), and until then it must lock nobody, only make them wait.
        versuch = self._begin_attempt(username, ip, "password", schweben=cfg.ldap_enabled)
        if versuch is None:
            return self._anmeldung_gesperrt(username, nxt)
        # The unexpected (programming error in the client, database gone, an HTTPException from the
        # check) turns the attempt into a failed attempt immediately — stricter in doubt, as before.
        # Without that it would stay pending for `Store.VORBUCHUNG_SCHWEBE_SEK` and make sign-ins
        # from the same address wait (G9). From `_record_login` on it is closed.
        try:
            u = self._check_password(username, password)
            aus_verzeichnis = False
            if not u and cfg.ldap_enabled:
                from .ldap_ import VerzeichnisNichtErreichbar
                try:
                    u = self._check_ldap(username, password)   # LDAP/lldap backend (factor 'password')
                except VerzeichnisNichtErreichbar as e:
                    # An outage is not a failed attempt (F-23): book nothing against account or IP
                    # and no `failed login` in the security log — otherwise a few minutes of
                    # directory outage would lock the users out, and fail2ban would ban them on top. The
                    # response is the same 503 for every account, so it reveals nothing about its
                    # existence (local wrong password and unknown name both end up here).
                    self.audit("ldap_unavailable", username, ip, security.fuer_log(str(e))[:300])
                    security.seclog.error("LDAP unreachable user=%s ip=%s reason=%s",
                                          security.fuer_log(username), security.fuer_log(ip),
                                          security.fuer_log(str(e)))
                    # …but only the DIRECTORY's share is excused (A-1). If the account has
                    # a local password and it was wrong, that is a failed attempt as always —
                    # otherwise every outage would be a rate pause without account lock against precisely the
                    # emergency account (local admin) that one needs at that moment; spread over many
                    # IPs, only the IP rate limit would still apply. The response stays 503. A local account
                    # WITH a password can thus be recognised during an outage by the later 429 —
                    # the same lock that also hits it in normal operation; that is the smaller price.
                    # The attempt has stood in the table since `_begin_attempt` (R7-2), as a
                    # pending pre-booking (G9) — without a local password it is therefore
                    # taken back, not merely not booked additionally. Until then it lets
                    # sign-ins that would fail because of it wait instead of locking them; so that
                    # this does not take until the timeout on every attempt, `_check_ldap` does not ask at all for
                    # a pause after an outage (`ldap_.AusfallMerker`) and
                    # raises immediately.
                    lokal = self.find_user(username)
                    if lokal and self.store.get_password_hash(lokal["id"]):
                        self._record_login(username, ip, False, "password", versuch=versuch, quelle="lokal")
                    else:
                        self._versuch_zuruecknehmen(versuch)
                    return self._anmeldung_nein("directory_down", 503, "err.directory_down", nxt)
                aus_verzeichnis = u is not None
        except BaseException:
            self._versuch_gescheitert(versuch)
            raise
        # The same wrong password once more (0.24.9): no new failed attempt — neither in the window nor in the streak,
        # and no `failed login` for fail2ban. The response is the same 401 as for every failed attempt.
        if not u and self._passwort_wiederholt(username, ip, password):
            self._versuch_zuruecknehmen(versuch)
            # In the audit a `login_fail` like any other (account page and panel show it the same, no oracle), only the
            # reason says "repeated".
            self.store.audit_log("login_fail", username, ip, "password grund=wiederholt")
            security.seclog.info("%s user=%s ip=%s method=password", security.LOG_WIEDERHOLT,
                                 security.fuer_log(username), security.fuer_log(ip))
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt)
        # Which route decided is recorded in the audit log (F-29): before, a
        # directory sign-in could not be told apart from a local one — both wrote
        # factor `password`, and on a failed attempt it said `grund=kein_konto`, although the
        # directory had been asked and had refused.
        # From the directory: pass along the account to which the identifier was resolved (G5-N1) —
        # a filter via `mail` also matches an identifier that locally belongs to ANOTHER account.
        # `_check_ldap` has rejected this case since 2026-09-27 (one identifier, one account); the
        # guard in `_raeumgrenze` remains the second safeguard.
        self._record_login(username, ip, bool(u), "password", versuch=versuch,
                           quelle=("" if not cfg.ldap_enabled else "ldap" if aus_verzeichnis
                                   else "lokal" if u else "lokal+ldap"),
                           konto=u["id"] if aus_verzeichnis and u else None)
        if not u:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt)
        # If the account came from the directory, the email is an LDAP attribute — in many
        # directories maintained by whoever it belongs to, and confirmed by nobody. If the
        # operator trusts the directory (`ldap_email_trusted`) or names an evidence attribute
        # (`ldap_attr_email_verified`), the evidence on the account decides (None) — `_check_ldap`
        # sets it only if the source is trusted; otherwise "no
        # evidence" explicitly travels along here: an allowlist ADDRESS must not lead to first admin via LDAP (F-14).
        # The route cannot be recognised from the factor name — LDAP deliberately counts as `password`.
        token, _ok, neu = self.apply_factor(request, u["id"], "password", ip,
                                            request.headers.get("user-agent"), bleiben,
                                            email_verified=(None if (cfg.ldap_email_trusted
                                                                       or security.beleg_attribut(cfg, "ldap"))
                                                              else False)
                                            if aus_verzeichnis else None)
        if cfg.remember_me_enabled and bleiben:
            self.store.set_session_bleiben(self.store.session_hash(token))     # F-05: explicitly chosen
        return self._angemeldet(request, token, neu, u["id"], nxt)

    def login_pin(self, request: Request, pin: str, username: str = "", *, next: str = "",
                  remember: Optional[bool] = None, csrf: Optional[str] = None) -> LoginResult:
        """Sign in with the personal PIN or provide the PIN step — throttled and locked like `POST /auth/pin`, which calls exactly this method.

        Three situations, like the route: on a full session (PIN as the factor of a route) and in the
        chain step after the first factor (`login_chain` with `pin`) the PIN belongs to the account of the
        session, `username` stays empty — wrong guesses there are booked under a dedicated streak kind
        that a self-service reset does not clear (G7). Without a session the PIN is a first factor
        with `username`, only with `pin_login` (`TinySesamConfig.pin_as_first_factor()`), otherwise
        `reason="method_disabled"` (404). A four-digit PIN is the most grateful target of a
        burst: login and PIN buckets are pre-booked in one step (R3-7). Result, CSRF,
        `remember` and exceptions as with `login_password`; `result.next_factor == "pin"` after a
        failure means: the same PIN page once more, without a name field."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        bleiben = self._bleiben_gewaehlt(remember)
        ip = self.client_ip(request)
        # Already signed in → the PIN belongs to the running session, no user field needed.
        # "Signed in" here means: a full SESSION (0.20.1, `session_user`). With
        # `current_user()` a pure API-key request counted as signed in — the bolt
        # `pin_login=False` below did not apply, the PIN of the key's account was checked, and
        # `apply_factor` created a new, full session for lack of one: machine key + PIN
        # yielded an interactive session including the admin flag, which the key alone never carries.
        # A key arrives here only as a guest, and for that `pin_as_first_factor()` applies.
        me = self.session_user(request)
        # The chain step: first factor provided, the session is still pending (`pending_user`,
        # like `/auth/totp`). Until 2026-09-26 it went through the guest route — with `pin_login=False`
        # a chain `password → pin` was therefore a dead end (404), and its wrong guesses
        # booked like those of a first factor, which a self-service reset clears (G7).
        # If the form names ANOTHER account, it remains an identity switch via the
        # guest route; own PIN pages that send the name along remain in the chain step.
        # The half session counts only if the PIN is now its chain step (p2 F1): otherwise it
        # would check PINs in classic mode (oracle with only the password) or before the TOTP
        # of a strict chain, whose order could then never be fulfilled.
        halb = None if me else self._pin_kettenschritt(request)
        if halb and username:
            gemeint = self.find_user(username)
            if not gemeint or gemeint["id"] != halb["id"]:
                halb = None
        folge = me or halb      # the PIN comes AFTER an already provided factor
        offen = "pin" if folge else None
        if not cfg.pin_enabled or (not folge and not cfg.pin_as_first_factor()):
            # PIN is not a first factor — switched off or, in a strict chain behind
            # another factor, never fulfillable (G7: otherwise an oracle without a password).
            return self._anmeldung_nein("method_disabled", 404, "api.not_found", nxt)
        if not pin or (not folge and not username):
            return self._anmeldung_nein("missing", 400, "err.required", nxt, offen)
        if not self._rate_ok(ip):
            return self._anmeldung_nein("ratelimit", 429, "err.rate", nxt, offen)
        ident = folge["username"] if folge else username
        if not ident:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt, offen)
        # Login and PIN buckets in one atomic step (R3-7): a four-digit PIN
        # is the most grateful target of a parallel burst. Behind a provided factor
        # the streak books under its own kind: these wrong guesses arise only for whoever has the first
        # factor, and a self-service reset does not clear them (like TOTP, G7).
        versuch = self._begin_attempt(ident, ip, "pin",
                                         series_kind=self._PIN_CHAIN_SERIES if folge else None)
        if versuch is None:
            return self._anmeldung_gesperrt(ident, nxt, offen)
        try:
            if folge:
                u = self.get_user(folge["id"]) if self._verify_user_pin(folge["id"], pin) else None
            else:
                u = self._check_pin(ident, pin)
        except BaseException:
            self._versuch_gescheitert(versuch)       # the unexpected counts immediately (as with the password)
            raise
        self._record_login(ident, ip, bool(u), "pin", versuch=versuch)
        if not u:
            return self._anmeldung_nein("invalid", 401, "err.credentials", nxt, offen)
        token, _ok, neu = self.apply_factor(request, u["id"], "pin", ip,
                                            request.headers.get("user-agent"), bleiben)
        if cfg.remember_me_enabled and bleiben:
            self.store.set_session_bleiben(self.store.session_hash(token))  # F-05: explicitly chosen
        return self._angemeldet(request, token, neu, u["id"], nxt)

    def login_totp(self, request: Request, code: str, *, next: str = "",
                   csrf: Optional[str] = None) -> LoginResult:
        """Provide the TOTP step — with a TOTP code or a one-time code, throttled and locked like `POST /auth/totp`, which calls exactly this method.

        For the half session after the first factor (`result.next_factor == "totp"`
        of a previous `LoginResult`) and as a step-up of a full one. Both come from the cookie
        (`pending_user`/`session_user`, never from an API key); without a session the result is
        `reason="no_session"` with the login page as `next_url`. If the session thereby becomes full
        or freshly confirmed, it gets a new token — `redirect()`/`set_cookie()`
        set it; whoever ignores it has a dead session in the cookie. Result, CSRF and
        exceptions as with `login_password`."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        s = self._session_from_request(request)
        # The code of the account is checked whose session then proceeds — both from the
        # cookie (0.20.1, `session_user`). `current_user()` fell back to an API key here
        # if the session's account was locked; then the key account's code would have counted.
        pu = self.pending_user(request) or self.session_user(request)
        offen = "totp" if s and pu else None
        if not code:
            return self._anmeldung_nein("missing", 400, "err.required", nxt, offen)
        if not s or not pu:
            return self._anmeldung_nein("no_session", 401, "api.not_signed_in",
                                        self.browser_path(request, cfg.login_path))
        ip = self.client_ip(request)
        # Atomic as at login (R3-2): otherwise the check lies between lock and counting.
        drossel_ok = self._rate_ok(ip)
        versuch = self._begin_attempt(pu["username"], ip, "totp") if drossel_ok else None
        if versuch is None:
            return self._anmeldung_gesperrt(pu["username"], nxt, offen, text="err.retry",
                                            grund="locked" if drossel_ok else "ratelimit")
        try:
            # accept a TOTP code OR a one-time recovery code
            richtig = self._verify_totp(pu["id"], code) or self._verify_recovery_code(pu["id"], code)
        except BaseException:
            self._versuch_gescheitert(versuch)       # the unexpected counts immediately (as with the password)
            raise
        if not richtig:
            self._record_login(pu["username"], ip, False, "totp", versuch=versuch)
            return self._anmeldung_nein("invalid", 401, "err.code", nxt, offen)
        self._record_login(pu["username"], ip, True, "totp", versuch=versuch)
        sitzungs_token = request.cookies.get(self.session_cookie_name)   # plaintext only here, in the cookie
        # If the session becomes fully valid through this factor, it gets a new token — the
        # privilege change. Likewise in a step-up on an already full session (F-06). In both
        # cases the cookie has to come along; if the session becomes full here (login), `set_cookie` also
        # rotates the CSRF token, in a step-up it does not — it would only invalidate the forms of the
        # other open tabs.
        erneuert = self.complete_totp(sitzungs_token)
        return self._angemeldet(request, erneuert or sitzungs_token, bool(erneuert), pu["id"], nxt)

    # ---------- Step-up and password change for own pages (stage A, 0.22.0) ----------
    # PO decision 2026-09-27: the same pattern as `login_*` for confirmation before sensitive
    # actions (until then only the built-in page `/auth/reauth`) and for the own
    # password change (until then only `POST /auth/password`). The inner checkers
    # (`_verify_user_password`, `_verify_user_pin`, `_verify_totp`) do not throttle; these methods
    # do what the routes do — because the routes call them. `tests/test_confirm.py` ensures via AST
    # that neither of the two routes calls an inner checker itself, and measures own pages
    # against the built-in ones (the same status, audit, log and counter lines).

    #: Whoever attempts a confirmation or a password change without a session gets `no_session`.
    #: If the request shows an API key instead of a session, that means 403 with this text — the
    #: key is not checked in the process, it simply does not count here (0.20.1).
    _OHNE_SITZUNG_KEY = {"reauth": "api.stepup_session", "password_change": "api.password_needs_session"}

    def _nur_mit_sitzung(self, request, zweck: str) -> tuple:
        """(account of the full session, None) — or (None, (status, text key)) for `no_session`.

        The account comes from `session_user()`, never from an API key (0.20.1): `/auth/reauth`
        until then checked the factor of the account from `current_user()` and afterwards refreshed the
        session from the cookie — with a HALF session `current_user()` fell back to the key,
        and machine key plus password replaced the second factor. For the password change
        (since 0.22.0): a machine key does not change a human's password, and without an own
        session the change ended ALL sessions of the account."""
        u = self.session_user(request)
        if u is not None:
            return u, None
        if self.cfg.apikey_enabled and self._extract_api_key(request):
            return None, (403, self._OHNE_SITZUNG_KEY[zweck])
        return None, (401, "api.not_signed_in")

    def _bestaetigen(self, request: Request, verfahren: str, geheimnis, next: str,
                     csrf: Optional[str]) -> LoginResult:
        """The one source of `confirm_password`, `confirm_pin` and `confirm_totp` — and thus of
        `POST /auth/reauth`, which calls one of them depending on the field filled in."""
        cfg = self.cfg
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))
        nxt = self.safe_next(next, request)
        u, ohne = self._nur_mit_sitzung(request, "reauth")
        if u is None:
            return self._anmeldung_nein("no_session", ohne[0], ohne[1],
                                        self.browser_path(request, cfg.login_path))
        methods = self.stepup_options(u)
        if not methods:
            # This account has no method with which it could confirm here
            # (`stepup_strict`, or no factor set up at all yet). The attempt CANNOT
            # succeed — it is therefore not logged as a failed attempt, otherwise the
            # hopeless page feeds the lock of the same account.
            return self._anmeldung_nein("method_disabled", 403, "err.stepup_none", nxt)
        if not geheimnis:
            # Empty is not a guess (0.22.0): until then a form submitted empty at
            # `/auth/reauth` counted as a failed attempt — as at login, `missing` now applies, without booking.
            return self._anmeldung_nein("missing", 400, "err.required", nxt)
        if verfahren not in methods:
            # Only an offered method counts (`stepup_options`: `stepup_methods`,
            # `stepup_strict`). Otherwise an own page with a password field would bypass the default
            # `stepup_methods=["totp"]`. Nothing is checked here — so nothing is counted either.
            return self._anmeldung_nein("method_disabled", 403, "err.reauth", nxt)
        ip = self.client_ip(request)
        # Own bucket (`_is_reauth_locked`), not that of the login: a step-up confirmation
        # is not a sign-in — whoever is here is already signed in. With the shared
        # counter, five typos on this page locked the **sign-in** of the same
        # account for `lockout_window_sec`, correct password included. The path
        # remains throttled and logged, just in its own bucket. If the page offers the PIN,
        # its bucket applies too (C-3): a PIN locked at login cannot be guessed
        # on here.
        drossel_ok = self._rate_ok(ip, login=False)
        versuch = (self._begin_attempt(u["username"], ip, "reauth", include_pin="pin" in methods)
                   if drossel_ok else None)
        if versuch is None:
            return self._anmeldung_nein("locked" if drossel_ok else "ratelimit", 429, "err.retry", nxt)
        pruefer = {"totp": self._verify_totp, "pin": self._verify_user_pin,
                   "password": self._verify_user_password}[verfahren]
        richtig = pruefer(u["id"], geheimnis)
        self._record_login(u["username"], ip, richtig, "reauth", versuch=versuch)
        if not richtig:
            return self._anmeldung_nein("invalid", 401, "err.reauth", nxt)
        s = self._session_from_request(request)
        neu = None
        if s:
            self.store.set_session_mfa(s["token_hash"], True)   # sets mfa_at=now → fresh again
            # Freshly confirmed means a new token (F-06): an old cookie that was read along would otherwise
            # hold exactly the session that has just received sudo rights. The old one still applies for
            # `session_rotation_grace_sec`, without freshness (A-6). The CSRF token stays.
            neu = self.store.rotate_session(s["token_hash"], self._gnade())
        self.audit("stepup", u["username"], ip)
        return LoginResult._with_session(self, neu, ok=True, reason="ok", status=303, next_url=nxt,
                                         done=True, user=self.get_user(u["id"]))

    def confirm_password(self, request: Request, password: str, *, next: str = "",
                         csrf: Optional[str] = None) -> LoginResult:
        """Freshly confirm the session with the password of the own account (step-up) — throttled and locked like `POST /auth/reauth`, which calls exactly this method.

        The building block for an own step-up page (dialog of a single-page app, own
        form before a sensitive action). It checks the CSRF token (`csrf`, otherwise header
        `X-CSRF-Token`), requires a full session (an API key does not count: `no_session`, 403),
        admits only a method that `stepup_options()` offers this account, throttles per IP,
        pre-books the attempt atomically in the own bucket (`reauth_max_attempts`, not that of the
        login), writes audit and security log and, on success, makes the session fresh
        (`stepup_fresh`, `require(mfa=True)`) — with a new token, which `redirect()`/`set_cookie()`
        set. A `LoginResult` comes back:

            result = auth.confirm_password(request, password, next=next, csrf=csrf)
            if not result:
                return mein_dialog(fehler=result.message, status=result.status)
            return result.redirect()     # to next, with the renewed session cookie

        An empty password is `missing` (400) and does not count. Raises only what the route
        raises too: `HTTPException(403)` for a wrong CSRF token, plus the unexpected. Synchronous: call from
        a `def` route, in an `async def` route via `run_in_threadpool`."""
        return self._bestaetigen(request, "password", password, next, csrf)

    def confirm_pin(self, request: Request, pin: str, *, next: str = "",
                    csrf: Optional[str] = None) -> LoginResult:
        """Freshly confirm the session with the PIN of the own account (step-up) — like `confirm_password`, throttled and locked like `POST /auth/reauth`.

        Like `confirm_password`, only with the PIN (`pin_enabled`, the account has one). If the
        page offers the PIN, the PIN bucket applies in addition (C-3): a PIN locked at the PIN sign-in
        cannot be guessed on here. The failed attempts themselves count in the `reauth` bucket."""
        return self._bestaetigen(request, "pin", pin, next, csrf)

    def confirm_totp(self, request: Request, code: str, *, next: str = "",
                     csrf: Optional[str] = None) -> LoginResult:
        """Freshly confirm the session with a TOTP code of the own account (step-up) — like `confirm_password`, throttled and locked like `POST /auth/reauth`.

        Like `confirm_password`, only with a TOTP code (each is valid once); a one-time code
        (recovery) does not count here — as on the built-in page. Not to be confused with
        `totp_confirm(user_id, code)`, which completes the setup of TOTP."""
        return self._bestaetigen(request, "totp", code, next, csrf)

    def change_password(self, request: Request, current: str, new: str, *,
                        csrf: Optional[str] = None) -> PasswordChangeResult:
        """Change the password of the own account — the old one checked throttled and locked like `POST /auth/password`, which calls exactly this method.

        The building block for an own password-change page. It checks the CSRF token (`csrf`, otherwise
        header `X-CSRF-Token`), requires a full session (an API key does not count:
        `no_session`, 403), throttles per IP, pre-books the attempt atomically in the own bucket
        (`password_change_max_attempts`, per account only; a typo here does not lock the
        sign-in), checks the old password against the session's account (never against a
        resolved identifier, R4-12), then the new one against the password rule. On success: new
        password, all OTHER sessions ended (the own one stays), open address-change links
        discarded, audit `password_change`. A `PasswordChangeResult` comes back:

            result = auth.change_password(request, current, new, csrf=csrf)
            if not result:
                return mein_formular(fehler=result.message, status=result.status)
            # result.api_keys_active: this many API keys remain valid — say so, do not conceal

        An empty old password is `missing` (400) and does not count. Raises only what the route
        raises too: `HTTPException(403)` for a wrong CSRF token, plus the unexpected. Synchronous:
        call from a `def` route, in an `async def` route via `run_in_threadpool`."""
        self.require_csrf(request, self._csrf_mitgeschickt(request, csrf))

        def nein(grund, status, text, **werte) -> PasswordChangeResult:
            return PasswordChangeResult(ok=False, reason=grund, status=status,
                                        message=self.t(text, **werte) if text else "")

        u, ohne = self._nur_mit_sitzung(request, "password_change")
        if u is None:
            return nein("no_session", *ohne)
        if not current:
            return nein("missing", 400, "err.required")
        ip = self.client_ip(request)
        # The old password is a secret as at login — so the same triad of
        # throttle, lock and log. Without it `/auth/password` was a silent, unlimited
        # password oracle: any number of attempts, never a 429, no line in the security
        # log, no failed attempt in `login_attempt` — while the same failed attempt at login
        # locks after a few tries (R4-10; the login threshold is `max_login_attempts`,
        # default 5 and adjustable in the panel).
        #
        # The lock is a bucket of its OWN (`_is_password_change_locked`, own threshold
        # `password_change_max_attempts`), not that of the login: with the shared counter
        # five typos here locked the sign-in for 15 minutes — including this route, via
        # which the user could have worked off the lock. Behind NAT it even hit uninvolved colleagues via
        # `ip_attempt_factor`. It remains throttled (`_rate_ok`),
        # and logged too.
        drossel_ok = self._rate_ok(ip, login=False)
        versuch = self._begin_attempt(u["username"], ip, "password_change") if drossel_ok else None
        if versuch is None:
            return nein("locked" if drossel_ok else "ratelimit", 429, "api.too_many")
        # Checked against the **ID** of the own session, not against the login identifier:
        # `_check_password(u["username"], …)` went through `find_user()` and could thereby resolve to a
        # FOREIGN account (attacker's username = victim's email, R4-12).
        # Then one would guess here not one's own password but the victim's — and the hit
        # silently set one's own password, so it stayed invisible.
        richtig = self._verify_user_password(u["id"], current)
        # Own method: a hit here does NOT clear the login path's failed attempts
        # (`_record_login` deletes only those of the same method) — the lock stays where it applies.
        self._record_login(u["username"], ip, richtig, "password_change", versuch=versuch)
        if not richtig:
            return nein("invalid", 403, "api.password_wrong")
        mangel = self.password_policy_error(new or "", username=u["username"], email=u.get("email"), api=True)
        if mangel:
            return PasswordChangeResult(ok=False, reason="policy", status=400, message=mangel)
        self.set_password(u["id"], new)
        # end the user's other sessions (keep the current one) — default after a credential change
        s = self._session_from_request(request)
        self.store.delete_user_sessions_except(u["id"], s["token_hash"] if s else None)
        # An open address change may stem from one of the sessions just ended — it
        # falls with them (finding 1). Other links (sign-in link, reset) go to the own address.
        self.store.revoke_user_magic_tokens(u["id"], purposes=("email_change",))
        # API keys survive the own password change on purpose: they are meant for automations,
        # and a routine change should not shut those down wholesale (one account = often one
        # key = several integrations). It is still not concealed — whoever changes the password after a
        # break-in must know that a door is still open.
        aktiv = self.store.count_active_api_keys(u["id"])
        self.audit("password_change", u["username"], ip, f"api_keys_active={aktiv}" if aktiv else None)
        return PasswordChangeResult(ok=True, reason="ok", status=200, api_keys_active=aktiv)

    def _session_from_request(self, request):
        """The session row for this request, or None. `row["token_hash"]` is its handle.

        An OIDC session is re-verified with the provider here every `oidc_session_refresh_minutes`
        (4a): if it refuses, the session is gone, and this request counts as not signed in."""
        s = self.store.get_session(request.cookies.get(self.session_cookie_name))
        if s is not None and not self._oidc_nachpruefen(s):
            return None
        return s

    def _oidc_sitzung_merken(self, token, client, sub, refresh_token) -> None:
        """Store the refresh token for the (just created) session (4a) — with the client_id to
        which it went."""
        if not int(self.cfg.oidc_session_refresh_minutes or 0) or not token:
            return
        self.store.set_oidc_sitzung(self.store.session_hash(token), client, sub, refresh_token,
                                    client_id=self.oidc_clients[client].client_id)

    def _gnade(self) -> int:
        """Grace period of the old token after rotation, in seconds (A-6)."""
        return max(0, int(self.cfg.session_rotation_grace_sec or 0))

    def _oidc_nachpruefen(self, s) -> bool:
        """Does the session still follow the provider? False = the session has ended (4a).

        Every `oidc_session_refresh_minutes` the refresh token is exchanged — per client of the
        session, in the background (`_oidc_tausch`). This request merely claims the due exchange
        (`oidc_sitzung_beanspruchen`, exactly one of many parallel ones) and carries on; the
        result applies from the next request. So a hanging provider blocks nothing, and two
        requests never exchange the same token (rotation at the provider). Nobody asks the provider about locked
        accounts — they do not get in anyway (F-17)."""
        frist = int(self.cfg.oidc_session_refresh_minutes or 0) * 60
        if not frist or self.oidc is None:
            return True
        zeilen = self.store.get_oidc_sitzungen(s["token_hash"])
        if not zeilen:
            return True
        konto = self.store.get_user(s["user_id"])
        if not konto or konto["disabled"]:
            return True
        jetzt = _jetzt()
        grenze = int(self.cfg.oidc_session_max_unverified_hours or 0) * 3600
        for z in zeilen:
            try:
                erfolg = z["erfolg_at"]
            except (IndexError, KeyError):
                erfolg = None
            # Since when has the provider not said yes? Without a value (row from the time before
            # the column) the last exchange counts.
            seit = int(erfolg if erfolg is not None else z["geprueft_at"])
            if grenze and jetzt - seit > grenze:
                # Upper limit without a successful re-check: the session ends. That is NOT a no
                # from the provider — the API keys therefore do not go dormant (finding 8 stays with the real no).
                self.store.delete_session_by_handle(s["token_hash"])
                konto_name = konto["username"] if konto else None
                self.store.audit_log("oidc_unbestaetigt", konto_name, s["ip"],
                                     f"client={z['client']} stunden={grenze // 3600}")
                security.seclog.warning(
                    "OIDC re-check without result for over %d hours — session ended. Check: "
                    "client secret/client at the provider, reachability. user=%s",
                    grenze // 3600, security.fuer_log(konto_name))
                return False
            if jetzt - int(z["geprueft_at"]) < frist:
                continue
            if not self.store.oidc_sitzung_beanspruchen(s["token_hash"], z["client"], z["geprueft_at"], jetzt):
                continue          # another request is exchanging right now
            if not self._oidc_ausgang.einreihen(lambda z=z: self._oidc_tausch(s, z, frist)):
                # Queue full: give the claim back, the next request tries again.
                self.store.oidc_sitzung_geprueft(s["token_hash"], z["client"], z["geprueft_at"])
        return True

    def _oidc_tausch(self, s, z, frist) -> None:
        """Exchange a refresh token at the provider and apply the result (4a, in the background).

        * if the provider refuses (locked, deleted, removed from the group, withdrawn from the application) → the
          session ends, with a line in the audit log;
        * if it delivers fresh data → groups, allowed groups and the admin flag assigned by the provider
          are re-evaluated (H-5 thus takes effect within minutes) — but only if the
          group claim is present at all: if it is missing, "no groups" would otherwise mean revoking every mapped
          role;
        * if it is unreachable → nothing changes, new attempt in a minute. An outage
          of the provider should sign nobody out."""
        handle, client = s["token_hash"], z["client"]
        konto = self.store.get_user(s["user_id"])
        name = konto["username"] if konto else None
        try:
            ausgestellt_fuer = z["client_id"]
        except (IndexError, KeyError):
            ausgestellt_fuer = None
        if not self.oidc_clients.bekannt(client) or (
                ausgestellt_fuer and ausgestellt_fuer != self.oidc_clients[client].client_id):
            # The application was removed from `oidc_clients`, or the client was recreated
            # at the provider (different client_id). The exchange would run with wrong credentials, the
            # provider would say no, and that would hit the account (attack on the third round and
            # counter-check). The row goes, the session stays until its expiry.
            self.store.oidc_sitzung_verwerfen(handle, client)
            security.seclog.warning("OIDC re-check: client %s is no longer set up (like this) — "
                                    "row discarded, not counted as a no. user=%s",
                                    security.fuer_log(client), security.fuer_log(name))
            return
        try:
            refresh = self.store.tresor.decrypt(z["refresh"])
        except Exception:   # noqa: BLE001 — wrong key: the start checks that; do not burn anything here
            self.store.oidc_sitzung_geprueft(handle, client, _jetzt() - frist + 60,
                                             alt_verschluesselt=z["refresh"])
            return
        gefragt = _jetzt()
        status, info, tok = self.oidc_clients[client].refresh(refresh, z["sub"])
        jetzt = _jetzt()
        # During the exchange the session may have received a new token (step-up, completion
        # of a factor) — its current handle stands at the row, found via the token.
        handle = self.store.oidc_sitzung_handle(client, z["refresh"]) or handle
        if status == "fehler":
            self.store.oidc_sitzung_geprueft(handle, client, jetzt - frist + 60, alt_verschluesselt=z["refresh"])
            security.seclog.warning("OIDC re-check without result (%s): provider unreachable or "
                                    "a client error (credentials, grant) — session stays, "
                                    "new attempt in one minute. user=%s",
                                    security.fuer_log(str(tok.get("error", "?"))), security.fuer_log(name))
            return
        if status == "abgelehnt":
            self.store.delete_session_by_handle(handle)
            fehler = security.fuer_log(str(tok.get('error', '?')))
            self.store.audit_log("oidc_widerruf", name, s["ip"], f"client={client} grund={fehler}")
            self._idp_nein(s["user_id"], name, s["ip"], client, fehler)
            return
        lebt = self.store.oidc_sitzung_geprueft(handle, client, jetzt, tok.get("refresh_token"),
                                                alt_verschluesselt=z["refresh"], erfolg=True)
        eintrag = self.oidc_clients.eintrag(client)
        if self.cfg.oidc_group_claim in info:
            roh = info.get(self.cfg.oidc_group_claim) or []
            gruppen = roh if isinstance(roh, list) else [roh]
            erlaubte = eintrag["allowed_groups"]
            if erlaubte and not (set(erlaubte) & set(map(str, gruppen))):
                self.store.delete_session_by_handle(handle)
                self.store.audit_log("oidc_widerruf", name, s["ip"], f"client={client} grund=gruppe")
                self._idp_nein(s["user_id"], name, s["ip"], client, "gruppe")
                return
            self.apply_idp_groups(s["user_id"], gruppen, eintrag["group_role_map"])
        if lebt:
            # Only if the session is still there: a parallel no via another client
            # may have ended it in the meantime — then this yes confirms nothing any more.
            self.store.idp_bestaetigen(s["user_id"], gefragt)

    def current_user(self, request) -> Optional[dict]:
        """The signed-in account for this request — from the session OR an API key. None if nobody is signed in.

        Not the source for a route that applies a factor to the running session, refreshes it
        or ends it — there the account belongs from `session_user()` (0.20.1)."""
        # Remember the IP first, then resolve: even a rejected API key (B5-05) should appear in the log
        # with the address it came from.
        self._anfrage_merken(request)
        u = self._current_user_ermitteln(request)
        if u:
            self._anfrage_merken(request, u)
        return u

    def session_user(self, request) -> Optional[dict]:
        """The account of this request's full session — like `current_user()`, only never from an API key.

        **The source for every route with session effect** (0.20.1): whoever checks a factor and
        then applies it to the session (`apply_factor`, `complete_totp`), refreshes it
        (step-up) or ends it takes the account from here. Without a full session
        `current_user()` falls back to the API key. In such a route the factor then checked the
        key's account, and the effect hit the cookie: `/auth/reauth` made someone else's half session
        full, `/auth/pin` with `pin_login=False` lifted the bolt "PIN is not a first factor"
        and created a full session from machine key and PIN — including the admin flag, which
        the key alone never carries (R6-5). For these routes a key is "not signed in".

        A half session (first factor yes, chain open) yields None; `pending_user()` reads it.
        A guard in `tests/test_stepup.py` ensures that no place in the package with session effect
        takes its account from a source that accepts a key.
        The same rule applies to own routes of the app that call `apply_factor()` for "the
        signed-in account"."""
        self._anfrage_merken(request)
        u = self._konto_der_sitzung(self._session_from_request(request))
        if u:
            self._anfrage_merken(request, u)
        return u

    def _konto_der_sitzung(self, s) -> Optional[dict]:
        """The account of a FULL session row, locked accounts excluded — or None."""
        if s and s["mfa_ok"]:
            u = self.store.get_user(s["user_id"])
            if u and not u["disabled"]:
                d: dict = self._als_dict(u) or {}
                d["_via"] = "session"
                return d
        return None

    def _current_user_ermitteln(self, request) -> Optional[dict]:
        # 1) Session (human, incl. MFA) — the same resolution as `session_user()`
        s = self._session_from_request(request)
        d = self._konto_der_sitzung(s)
        if d:
            return d
        # 2) API key (machine / daemon) — the key IS the factor, no MFA
        if self.cfg.apikey_enabled:
            key = self._extract_api_key(request)
            if key:
                u, key_roles = self.verify_api_key(key)
                art = getattr(self, "_letzte_key_art", "automation")
                if u and art == "human":
                    # A human key counts ONLY together with a session of the same account
                    # (R6-5). Leaked on its own it is worthless — that is the whole difference
                    # from the machine key, and for that it may carry the full rights.
                    if not (s and s["mfa_ok"] and s["user_id"] == u["id"]):
                        security.seclog.warning(
                            "API key of kind 'human' presented without a matching session "
                            "(user=%s ip=%s) — rejected.",
                            security.fuer_log(str(u["username"])),
                            security.fuer_log(self.client_ip(request)))
                        return None
                if u:
                    d = dict(u)
                    d["_via"] = "apikey"
                    d["_key_kind"] = art
                    # `!= "human"` instead of `== "automation"`: fail-closed for every kind that does not
                    # exist (a typo in the column, a value from a foreign version).
                    # Before, a key with `kind="Automat"` kept the admin flag (R6-6). The
                    # values up to 0.21.x (`mensch`) arrive already mapped (`_key_kind`).
                    if art != "human" and d.get("is_admin"):
                        # The core of R6-5: a machine key does NOT carry its owner's
                        # admin flag. Before, every key of an admin was a complete
                        # admin write API — without a second factor, without a CSRF layer. The roles
                        # remain (that is what the scope is for), the flag does not.
                        d["is_admin"] = 0
                    if key_roles is not None:
                        # INTERSECTION, not override: the scope narrows, it never widens.
                        # Second layer beside the limit in create_api_key — it also applies
                        # to keys that were created before the fix or that sit directly in the database.
                        # `is_admin` is left untouched, that comes from the user row.
                        d["roles"] = json.dumps(sorted(set(key_roles) & set(self.user_roles(u))))
                    return d
        return None

    def pending_user(self, request) -> Optional[dict]:
        """User of a session that is still stuck in the MFA step (mfa_ok=0)."""
        s = self._session_from_request(request)
        if not s or s["mfa_ok"]:
            return None
        u = self._als_dict(self.store.get_user(s["user_id"]))
        if u:
            self._anfrage_merken(request, u)
        return u

    def _pin_kettenschritt(self, request) -> Optional[dict]:
        """The account of the half session if the PIN is now its chain step — otherwise None.

        Yes only if the global `login_chain` requires the PIN, it is still missing in this session
        and, in a strict chain, it is the next step. Until 2026-09-27 any
        half session sufficed (G7-N1): in classic mode with `pin_login=False`, `/auth/pin` then checked
        the PIN for anyone who had only the password (wrong 401, right 303 — an oracle there
        that did not exist before), and in a strict chain `password → totp → pin` the PIN stood
        in the session before the TOTP. Its order could then never be fulfilled again, and every
        further sign-in in the same browser stuck to it until sign-out (p2 F1)."""
        u = self.pending_user(request)
        req, strict = self._global_chain()
        if not u or not req or "pin" not in req:
            return None
        s = self._session_from_request(request)
        done = json.loads(s["factors_done"] or "[]") if s else []
        if "pin" in done or (strict and self._next_factor(req, strict, done) != "pin"):
            return None
        return u

    def totp_enrollment_user(self, request) -> Optional[dict]:
        """Who may set up TOTP **without** already being fully signed in? Otherwise None.

        Exactly one situation: the global `login_chain` requires `totp`, the user has provided their
        first factor (the session is stuck in the MFA step) and has no confirmed TOTP yet.

        Without this path, `login_chain=["password","totp"]` is a **dead end** for every account without a set-up
        TOTP: the correct password leads to `/auth/totp`, which for lack of a
        secret leads back to the login page — and the setup page required a
        fully signed-in user, which can never exist under this chain. The account got neither
        in nor to the setup; the operator had to go to the database.

        Security-wise this is no concession: whoever is here has already provided the first factor,
        and without the chain (classic mode) the same password would have signed them in completely
        anyway. The setup alone signs nobody in — the factor counts only once a
        code from the fresh secret matches. That is the confirmation code itself: the route
        `POST /auth/totp/setup` completes the TOTP step with it (A-1), because the code is
        consumed and at `/auth/totp` only a failed attempt.
        """
        u = self.pending_user(request)
        if not u or self.store.has_confirmed_totp(u["id"]):
            return None
        req, _ = self._global_chain()
        if not (req and "totp" in req):
            return None
        if self.store.list_webauthn(u["id"]):
            # If the account already has a strong second factor (passkey), it sets up a
            # further one only if it presented it in THIS session — or in a window
            # that the operator has explicitly opened (lost device; the window wins
            # as in `mfa_enrollment_allowed`). Otherwise the mailbox would set up a second
            # factor for itself and bypass the passkey: via the sign-in link (ASVS 6.3.6, attack on the
            # third round) or via "forgot password" and then the new password (counter-check).
            # Accounts WITHOUT a second factor may continue to — that is the deliberate price of option C.
            s = self._session_from_request(request)
            done = json.loads(s["factors_done"] or "[]") if s else []
            konto = self.store.get_user(u["id"])
            fenster = konto["mfa_enroll_until"] if konto else None
            if "passkey" not in done and not (fenster and int(fenster) > _jetzt()):
                self.audit("mfa_enrollment_denied", str(konto["username"]) if konto else None,
                           detail="account has a passkey that is missing in this session")
                return None
        if not self.mfa_enrollment_allowed(u["id"]):
            # No silent no: whoever fails here has the correct password and stands before
            # a door that does not open. The line tells the operator which route remains.
            #
            # **Without `log_ereignis`**, i.e. without the word the fail2ban jail matches on: this
            # is not a failed attempt. Whoever gets this far has entered their correct password
            # — having them locked out for that as well would be exactly backwards. The
            # name comes from the freshly fetched account row, not from the request.
            konto = self.store.get_user(u["id"])
            security.seclog.warning(
                "mfa enrollment denied user=%s art=%s — the second factor is missing and may not "
                "be set up here any more. Route: auth.grant_mfa_enrollment(uid) or the "
                "admin panel.",
                security.fuer_log(str(konto["username"]) if konto else "?"),
                self.cfg.mfa_enrollment)
            self.audit("mfa_enrollment_denied", str(konto["username"]) if konto else None,
                       detail=f"art={self.cfg.mfa_enrollment}")
            return None
        return u

    #: The permitted values of `cfg.mfa_enrollment` — as a list so that a typo during
    #: construction is noticed and not only when someone is standing at the door.
    MFA_ENROLLMENT_MODES = ("first_login", "grace", "strict")

    def mfa_enrollment_allowed(self, user_id: int, now: Optional[int] = None) -> bool:
        """May this account set up the factor required by the chain **itself**? (R3-1)

        Three operating modes (`cfg.mfa_enrollment`), plus a window opened by the operator
        that always wins — that is the way for every account to which the operating mode would otherwise
        deny it (admin panel, invitation, `grant_mfa_enrollment`).

        The danger at stake: whoever had the password of an **existing** account used to bind
        their own authenticator. For an account that has never been used, the
        risk is a different one — there the first person to sign in is the rightful one, just as with an
        invitation link.
        """
        now = _jetzt() if now is None else int(now)
        u = self.store.get_user(user_id)
        if not u:
            return False
        fenster = None
        try:
            fenster = u["mfa_enroll_until"]
        except (IndexError, KeyError):
            fenster = None            # file from before schema 8
        if fenster and int(fenster) > now:
            return True
        art = str(self.cfg.mfa_enrollment or "first_login")
        if art == "strict":
            return False
        if art == "grace":
            tage = max(0, int(self.cfg.mfa_enrollment_grace_days or 0))
            return (now - int(u["created_at"])) <= tage * 86400
        # "first_login": allowed as long as this account has never been fully signed in.
        try:
            return u["first_login_at"] is None
        except (IndexError, KeyError):
            return True               # file from before schema 8: the chance remains

    def grant_mfa_enrollment(self, user_id: int, minutes: int = 60) -> int:
        """Open a setup window and return its expiry.

        The operator's way if someone has lost their device or `mfa_enrollment="strict"`
        applies. Deliberately time-limited: a permanently open window would be the old gap under a
        new name."""
        bis = _jetzt() + max(1, int(minutes)) * 60
        self.store.set_mfa_enroll_until(user_id, bis)
        u = self.store.get_user(user_id)
        self.audit("mfa_enrollment_granted", str(u["username"]) if u else None,
                   detail=f"minuten={minutes}")
        return bis

    def revoke_mfa_enrollment(self, user_id: int) -> None:
        """Ein offenes Einrichtungsfenster sofort schliessen."""
        self.store.set_mfa_enroll_until(user_id, None)
        u = self.store.get_user(user_id)
        self.audit("mfa_enrollment_revoked", str(u["username"]) if u else None)

    def _rotate_csrf(self, response) -> str:
        """Set a fresh CSRF token — at login.

        The naive double-submit is considered vulnerable to *cookie injection*: whoever can set a cookie via a
        subdomain sets a matching CSRF pair along with it. The OWASP
        CSRF Prevention Cheat Sheet therefore recommends binding to "a session-dependent value
        that changes with each login". Renewing the token at sign-in is the cheap
        part of that and costs nothing.

        Since 0.20.1 `set_cookie()` calls the method itself as soon as the token belongs to a just
        signed-in session — every sign-in route, including an own route of the app with
        `start_session` + `set_cookie`. Up to 0.20.0 this happened only at the end of a TOTP step,
        although this docstring promised it for every login. Only whoever builds a
        sign-in without `set_cookie()` has to call it directly. Replaces a CSRF line that the response already carries.
        """
        return self.issue_csrf(response)

    # ---------- Cookie names (H-1) ----------
    def _cookie_name(self, basis: str, host_only: bool = False) -> str:
        """`__Host-` in front, where the browser allows it (Secure, no Domain, path `/`).

        A `__Host-` cookie can be set only by the own host over HTTPS — a neighbouring subdomain
        can neither create it nor shadow it with a `Domain=.example.com` cookie of the same name.
        Exactly this is what planting a session, CSRF or
        unlock token builds on (F-01, F-02). Computed at request time because `cfg` may be
        changed after construction.

        `host_only=True` for cookies that are never set with `cookie_domain` (the
        CSRF cookie and the flow cookies of OIDC, SAML and passkey) — those may carry the prefix
        even then.

        The path must be literally `/`: with `cookie_path=""` `set_cookie` sends no
        `Path` attribute at all, and a `__Host-` cookie without `Path=/` is silently discarded by the browser —
        then, for example, the CSRF cookie would never arrive and every POST would fail (A-7).

        `cookie_prefix` replaces a leading `tinysesam_` (app with its own TinySesam behind a
        gateway whose templates remove every `tinysesam_*` cookie). Names with `__` remain."""
        c = self.cfg
        praefix = getattr(c, "cookie_prefix", "tinysesam_") or "tinysesam_"
        if praefix != "tinysesam_" and basis.startswith("tinysesam_"):
            basis = praefix + basis[len("tinysesam_"):]
        if (getattr(c, "cookie_host_prefix", True) and c.cookie_secure
                and (host_only or not c.cookie_domain)
                and c.cookie_path == "/" and not basis.startswith("__")):
            return "__Host-" + basis
        return basis

    def flow_cookie_name(self, base: str) -> str:
        """Name of a flow cookie (OIDC, SAML, passkey) — with `__Host-` where possible (A-1).

        The flow cookie binds a sign-in process to the browser that started it. If
        a neighbouring subdomain can set it via `Domain=.example.com`, it plants the attacker's
        flow on the victim and lures them to the callback URL — login CSRF, although the
        session cookie itself is already prefixed."""
        return self._cookie_name(base, host_only=True)

    def _flow_cookie_setzen(self, response, basis: str, wert: str, max_age: int,
                           samesite: Optional[str] = None) -> None:
        """Ein Flow-Cookie setzen: httponly, host-only, kurzlebig."""
        response.set_cookie(self.flow_cookie_name(basis), wert, max_age=max_age, httponly=True,
                            secure=self.cfg.cookie_secure,
                            samesite=_samesite(samesite or self.cfg.cookie_samesite),
                            path=self.cfg.cookie_path)

    def _flow_cookie_loeschen(self, response, basis: str,
                             samesite: Optional[str] = None) -> None:
        # With Secure: the browser does not accept a `__Host-` Set-Cookie without Secure, not
        # even the deleting one.
        response.delete_cookie(self.flow_cookie_name(basis), path=self.cfg.cookie_path,
                               secure=self.cfg.cookie_secure, httponly=True,
                               samesite=_samesite(samesite or self.cfg.cookie_samesite))

    @property
    def session_cookie_name(self) -> str:
        """The actual name of the session cookie (with `__Host-` where possible)."""
        return self._cookie_name(self.cfg.session_cookie)

    @property
    def csrf_cookie_name(self) -> str:
        """The actual name of the CSRF cookie — own JS gets it from the page.

        JS cannot read this property: the page passes the name along (template variable
        or `<meta>`), or the JS takes the token from the form field `_csrf`, which
        `ensure_csrf()` supplies.

        With `__Host-` even when `cookie_domain` is set: TinySesam never sets the CSRF cookie
        with a domain (`issue_csrf`, `render_page`, admin panel), it is always host-only. Without a
        prefix, in the forward-auth setup every protected app could set a `tinysesam_csrf` for the
        whole domain and pass the double-submit with its own value."""
        return self._cookie_name(self.cfg.csrf_cookie, host_only=True)

    @property
    def resource_cookie_name(self) -> str:
        """The actual name of the unlock cookie of the realm PIN."""
        return self._cookie_name(self.cfg.resource_cookie)

    def set_cookie(self, response, token, remember: Optional[bool] = None):
        """Set the session cookie. remember=True → persistent cookie (max_age = long TTL);
        remember=False → pure session cookie (max_age=None, ends when the browser closes).

        Without `remember` the kind follows the session the token belongs to (A-2):
        a step-up or a chain step rotates the token of a RUNNING session, and its
        kind was chosen by the user at the first factor. Before, a blunt `True` applied here — a
        session without "stay signed in" got a cookie for seven days after redeeming a magic link,
        which survived closing the browser on a shared computer.
        If there is no session for the token, the persistent cookie remains as before.

        If the token is a just-created sign-in (`start_session`, the last step of a
        chain), the same response also sets a new CSRF token (0.20.1). Whoever renders a form in this
        response afterwards fetches the token with `ensure_csrf(request, response)` — via
        the FastAPI response parameter. A finished response is then already rendered and its
        form would carry the old token: redirect there instead of delivering a form."""
        if remember is None:
            s = self.store.get_session(token)
            remember = bool(s["remember"]) if s else True
        kw = dict(httponly=True, secure=self.cfg.cookie_secure,
                  samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        if remember:
            kw["max_age"] = self._ttl(True)   # type: ignore[assignment]  # kw carries mixed types
        response.set_cookie(self.session_cookie_name, token, **kw)
        # A sign-in rotates the CSRF token (OWASP: "changes with each login"). Centrally here,
        # not per route: every sign-in sets this cookie, and every full session is noted
        # at its creation (`_sitzung_anlegen`). A step-up does not rotate.
        if self._anmeldung_einloesen(token):
            self._rotate_csrf(response)

    def rotate_session(self, request, response) -> Optional[str]:
        """Give the running session a new token and set the cookie (F-06).

        For every privilege change that creates NO new session — the step-up. OWASP Session
        Management: "The session ID must be renewed … after any privilege level change";
        ASVS 5.0 7.2.4 explicitly requires this for re-authentication too. Whoever read along the old
        token holds a dead session afterwards instead of a freshly confirmed one.
        Lifetime and sign-in time remain; the cookie keeps its kind (persistent or
        not). Returns the new token, or None without a session.

        In the process clears the cookies under the names from before the `__Host-` prefix (H-1) — like
        `logout()`, even when an own route of the app calls the method."""
        s = self._session_from_request(request)
        if not s:
            return None
        neu = self.store.rotate_session(s["token_hash"], self._gnade())
        if neu:
            self.set_cookie(response, neu, remember=bool(s["remember"]))
            self._altnamen_loeschen(request, response)
        return neu

    def count_other_sessions(self, request, user, token: Optional[str] = None) -> int:
        """How many sessions of this account are running EXCEPT the current one? (B1-7)

        The response to every factor change carries the number as `other_sessions`: ASVS 5.0 7.4.3
        requires, after adding or removing a factor, the offer to end the remaining sessions. The account page
        then asks; whoever builds an own UI reads the field.

        The mandatory setup of TOTP in the middle of a chain (`password → totp → pin`) reports
        0 here, because the session is still half afterwards and a half one must not end the others
        — it reports the number as `other_sessions_after`, and the consent is redeemed at the
        completion of the chain (`_andere_nach_abschluss`, limit d).

        `token`: the plaintext token of the own session if it has changed in THIS response
        (the mandatory setup of TOTP completes the sign-in and rotates the
        token in the process). The request's cookie then names a session that no longer exists — counted
        against it, the new own session would count as "other"."""
        s = self.store.get_session(token) if token else self._session_from_request(request)
        eigen = s["token_hash"] if s else None
        return sum(1 for z in self.store.list_sessions(user["id"]) if z["token_hash"] != eigen)

    def _cookie_loeschen(self, response, name):
        # Secure must come along: a browser does not accept a `__Host-` Set-Cookie without Secure —
        # not even the one meant to delete it.
        kw = dict(path=self.cfg.cookie_path, secure=self.cfg.cookie_secure, httponly=True,
                  samesite=_samesite(self.cfg.cookie_samesite))
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.delete_cookie(name, **kw)

    def _altnamen(self) -> list:
        """The names of session, CSRF and unlock cookie from the time before the
        `__Host-` prefix (H-1) — only those for which the prefix now actually applies. Where it
        does not apply, the old name IS the current one. The flow cookies are deliberately missing: they
        live only minutes."""
        paare = ((self.session_cookie_name, self.cfg.session_cookie),
                 (self.csrf_cookie_name, self.cfg.csrf_cookie),
                 (self.resource_cookie_name, self.cfg.resource_cookie))
        return [basis for name, basis in paare if name != basis]

    def _altnamen_loeschen(self, request, response) -> None:
        """Delete cookies under the old names in the browser when this response
        writes the session (sign-in, sign-out, step-up).

        Called by the route class (every built-in route), by `logout()` and
        by `rotate_session()` — the two public methods have the request. `set_cookie()`
        does not have it: an own sign-in route of the app (`start_session` + `set_cookie`) leaves
        the old names standing until the browser next passes through one of these places or
        they expire. TinySesam no longer reads them anyway.

        After the switch to `__Host-` TinySesam no longer reads them, but the browser kept
        sending them along until their expiry (session up to seven days) — to TinySesam and to
        every app behind it. Together with the new names that was more tinysesam cookies than
        the nginx templates could filter out (B-20). Only what the browser
        sent along is deleted, and host-only: that is how they were set, because the prefix applies only without
        `cookie_domain` (the CSRF cookie never carried a domain). If a
        second instance with the same base name and without a prefix runs on the same host, it loses its cookie — two
        instances on one host need their own names anyway (`session_cookie`).

        The session and the unlocks behind the old cookies end with them: the token in them was
        otherwise valid for up to seven days longer — presented under the new name, it signed
        in, and it was precisely the cookie that slipped through to the apps. Whoever presents it may
        also end it; that is the same rule as with sign-out."""
        alt = [n for n in self._altnamen() if n in request.cookies]
        if not alt:
            return
        gesetzt = {wert.split(b"=", 1)[0].strip().decode("latin-1")
                   for schluessel, wert in getattr(response, "raw_headers", [])
                   if schluessel.lower() == b"set-cookie"}
        if self.session_cookie_name not in gesetzt:
            return
        for name in alt:
            if name in gesetzt:
                continue
            wert = request.cookies.get(name) or ""
            if wert and name == self.cfg.session_cookie:
                self.store.delete_session(wert)
            elif wert and name == self.cfg.resource_cookie:
                self.store.delete_resource_unlocks(wert)
            response.delete_cookie(name, path=self.cfg.cookie_path,
                                   secure=self.cfg.cookie_secure, httponly=True,
                                   samesite=_samesite(self.cfg.cookie_samesite))

    def logout(self, request, response):
        """End this request's session, the realm unlocks of this browser along with it, and
        delete the cookies — session, unlock and since 0.20.1 also the CSRF cookie, plus the
        cookies under the names from before the `__Host-` prefix.

        The unlocks belong to it (F-08): up to 0.20 they survived the sign-out by up to
        `resource_unlock_ttl_hours`. Whoever signs out on a shared computer expects that
        nothing is open afterwards — not even the realm locked with a PIN."""
        s = self._session_from_request(request)
        if s:
            self.store.delete_session_by_handle(s["token_hash"])
        self._cookie_loeschen(response, self.session_cookie_name)
        freigabe = request.cookies.get(self.resource_cookie_name)
        if freigabe:
            self.store.delete_resource_unlocks(freigabe)
            self._cookie_loeschen(response, self.resource_cookie_name)
        # The CSRF token ends with the session (0.20.1): up to 0.20.0 it survived sign-out and
        # signing in again until the browser was closed. The next page sets a fresh one;
        # `ensure_csrf()` in the same response likewise.
        if self.cfg.csrf_enabled or request.cookies.get(self.csrf_cookie_name):
            self._csrf_cookie_loeschen(response)
        # Here too, not only in the route class: `logout()` is public and is called from
        # own routes of the app that the class does not cover.
        self._altnamen_loeschen(request, response)

    # ---------- Hardening (regulation / rate limit / audit) ----------
    def client_ip(self, request: Request) -> str:
        """The real client IP. Behind a proxy only from `X-Forwarded-For` if the peer is in `trusted_proxies` — otherwise the header would be forgeable."""
        return security.client_ip(request, self.cfg.trusted_proxies)

    def _sec(self, key) -> int:
        """Hardening value: store setting (panel) OR default, always within `security.SECURITY_GRENZEN`.

        Read via `security.haertung_lesen` — the CLI (`tinysesam passwd`) takes the same route;
        an existing value beyond the limits counts there as here as the nearest limit."""
        return security.haertung_lesen(self.store, key)

    def all_security(self) -> dict:
        """All hardening thresholds as a dict (defaults, overridden by what is set in the panel)."""
        return {k: self._sec(k) for k in security.SECURITY_DEFAULTS}

    def set_security(self, key, value):
        """Set a hardening threshold at runtime; it survives the restart in the database.

        Unknown key or value outside `security.SECURITY_GRENZEN` → `ConfigError`,
        and nothing is written. Up to 0.19.x an unknown key silently dropped out and every
        value was accepted — `rate_limit_max=0` then locked every sign-in, including the one with which
        the value could have been turned back (R6-4)."""
        try:
            zahl = security.pruefe_haertung(key, value)
        except ValueError as e:
            raise ConfigError(str(e)) from None
        self.store.set_setting(key, zahl)

    def set_rate_limiter(self, limiter):
        """Attach a custom rate-limit backend — any object with allow(key, max, window)->bool."""
        self.rl = limiter

    # Rejection happens at eleven places in the router; reporting happens HERE, in the check itself.
    # Reason: as long as the app lockout applied, nobody called `_record_login()` any more — the app
    # answered 429 and wrote no line. The security log thus fell silent at exactly the
    # moment when fail2ban should have banned the IP: the app lockout blinded the guard
    # that is supposed to take over from it. Patching the eleven call sites one by one would mean that the
    # next new route is silent again.
    #
    # The format is deliberately the same as for a real failed attempt — the bundled
    # fail2ban filter (`failed login user=… ip=<HOST> method=.*`) thereby applies immediately, even
    # in installations that never touch their filter file. `reason=` says why.
    #
    # `login=False` for the rejections of the non-login buckets: they carry the other
    # event word (`security.LOG_PRUEFUNG`) and thus pass by the bundled jail
    # — otherwise a signed-in user would ban themselves at firewall level with a few typos on their
    # own account page, and every further click after the
    # app lock would speed up the ban (rationale at `security.LOG_ANMELDUNG`).
    #: Lock reasons that concern an ACCOUNT (not an address or the rate limit): only they trigger
    #: the notice to the owner (ASVS 6.3.5).
    _KONTO_SPERREN = ("lockout_user", "lockout_account", "lockout_serie", "lockout_pin")

    def _abgewiesen(self, username, ip, grund: str, login: bool = True):
        wort = security.LOG_ANMELDUNG if login else security.LOG_PRUEFUNG
        security.seclog.warning("%s user=%s ip=%s method=blocked reason=%s", wort,
                                security.fuer_log(username) or "-", security.fuer_log(ip), grund)
        if login and grund in self._KONTO_SPERREN and username:
            self._sperrhinweis(username, ip, grund)

    def _sperrhinweis(self, username, ip, grund) -> None:
        """Notify the owner that their account has been locked (ASVS 6.3.5, B1-12).

        In the request the same thing happens for EVERY name — one throttle per name, one job into
        the own outbox —, whether the account exists or not. Lookup and sending
        happen only in the background: otherwise the response time would reveal which names have an account
        (the same consideration as R4-05). Only to a taken address (H-3), never to a
        service account; at most one notice per name and lock window."""
        if not self.cfg.notify_login_failures or not self.mail_configured():
            return
        schluessel = "sperrhinweis:" + norm_kennung(username)
        if not self.rl.allow(schluessel, 1, self._sec("lockout_window_sec")):
            return
        zeit = _jetzt()

        def _senden():
            u = self.find_user(username)
            if not u or u.get("is_service") or not u.get("email") or not _beleg_am_konto(u):
                return
            # The actual throttle is in the database, not in memory: the key above
            # lies in the shared, capped limiter and can be displaced with enough foreign keys;
            # with several workers each has its own (finding 11). The audit log applies to
            # all processes and forgets nothing before the deadline.
            seit = _jetzt() - self._sec("lockout_window_sec")
            if self.store._one("SELECT 1 FROM audit WHERE event='sperrhinweis' AND lower(username)=lower(?) "
                               "AND ts >= ? LIMIT 1", (u["username"], seit)):
                return
            betreff = self.t("mail.lockout.subject")
            # Name the reset only if it also clears the streak (it does not clear TOTP and the PIN in the chain step,
            # `_serie_reset_hilft`).
            bis = ""
            if grund == "lockout_serie":
                bis = (self.t("mail.lockout.until_reset") if self._serie_reset_hilft(username)
                       else self.t("mail.lockout.until_operator"))
            text = self.t("mail.lockout.text", name=u["username"], until=bis,
                          time=time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(zeit)),
                          ip=security.fuer_log(ip) or self.t("mail.unknown"))
            self.send_mail(u["email"], betreff, text)
            self.store.audit_log("sperrhinweis", u["username"], ip, f"grund={grund}")

        self._hinweis_ausgang.einreihen(_senden)

    def _rate_ok(self, ip, login: bool = True) -> bool:
        """May this IP still? A no writes a line into the security log (fail2ban reads along).

        `login=False` for routes that are not a sign-in (password change, step-up, realm PIN):
        their line then carries `failed verification` instead of `failed login` — otherwise the
        bundled jail banned a signed-in user who keeps clicking on their own
        account page (final attack C-1)."""
        erlaubt = self.rl.allow(ip or "?", self._sec("rate_limit_max"), self._sec("rate_limit_window_sec"))
        if not erlaubt:
            self._abgewiesen(None, ip, "ratelimit", login=login)
        return erlaubt

    def _is_locked(self, username, ip) -> bool:
        """Too many failed attempts in the window — per pair of account and IP, per account, per IP.

        The thresholds are in `_regeln` (rationale there): the pair at `max_login_attempts`,
        the account alone at `account_attempt_factor` times that, the address alone at
        `ip_attempt_factor` times that (NAT). Without `ip` only the account threshold applies.

        Everything in `login_attempt` that was a **sign-in attempt** is counted; the methods from
        `security.NICHT_LOGIN_METHODEN` stay out. Otherwise a wrong guess that was not
        a sign-in at all would lock the sign-in too. The counter of these methods is not lost,
        it just has its own bucket (e.g. `_is_password_change_locked`).

        Read-only: the routes take `_begin_attempt()`, which checks and books in one step.
        """
        return self._sperre_pruefen(self._regeln(username, ip, "password"), username, ip, login=True)

    def _record_login(self, username, ip, success, method, versuch: Optional[int] = None,
                      quelle: str = "", konto: Optional[int] = None):
        """Book a sign-in attempt. A success clears only the failed attempts of the SAME method.

        `versuch` is the ID from `_begin_attempt()`: then the attempt already stands as a
        failed attempt in the table and is only closed here instead of being counted a second time.

        `quelle` tells the audit log WHO checked the secret where the method does not
        reveal it (F-29): LDAP deliberately writes the factor `password` — lock and chain should
        treat both routes the same —, but in the log the operator must be able to separate them.
        A success with `quelle` writes a line of its own `login_<quelle>` (`login_ldap`,
        `login_lokal`), a failed attempt appends `quelle=…` to `login_fail` (`lokal+ldap`: both
        were asked, both refused). Empty = as before, no additional information.

        `konto` is the ID of the account to which the identifier was resolved if that did not happen via
        name or address — with a directory sign-in (G5-N1). Then a success clears
        the failed attempts under the typed identifier only if it does not belong to ANOTHER account:
        a directory filter via `mail` also resolves `boss@example.com` to a third party
        whose `mail` attribute reads that — and every one of their sign-ins reset the local owner's
        account window until 2026-09-26 (distributed guessing without limit apart from streak and
        IP limit).

        If the identifier is the name or address of a local account, clearing starts from its joining that
        account (limit a, G2): failed attempts that a stranger made under the then free identifier
        before the rename or address change remain — they count in the
        throttling of THEIR IP. Details in `_raeumgrenze`."""
        topf = self._topf(username, method)   # the same key as when counting
        vorgebucht = self._serie_vorbuchungen.pop(versuch, None) if versuch is not None else None
        uebergang = None
        if versuch is None:
            self.store.record_attempt(topf, ip, success, method)
        else:
            # On a success the pre-booking in the streak does not apply — taken back in the same
            # transaction as the closing (G9). The streak before it remains: a correct first
            # factor is not yet a complete sign-in (`lift_lockout`). On a
            # failed attempt the closing says how the streak stood before and after (p2 F3).
            uebergang = self.store.finish_attempt(versuch, bool(success),
                                                  serie=vorgebucht[:2] if vorgebucht else None)
        if success and quelle:
            self.store.audit_log(f"login_{quelle}", username, ip, f"{method} quelle={quelle}")
        if success:
            # ONLY the failed attempts of the same method: a password success says nothing about
            # whether someone is currently trying out TOTP codes. Before, it cleared them too and made
            # the second factor guessable. Everything else is cleared only by the COMPLETE sign-in
            # (`lift_lockout`).
            grenze = self._raeumgrenze(topf, method, konto)
            if grenze is not None:     # 'login' audit only at full completion
                self.store.clear_fails(username=topf, method=method, **grenze)
        else:
            # The REASON belongs in the server-side log. The HTTP response deliberately stays
            # the same (no account probing) — but in the audit log only the operator reads along,
            # and "wrong password", "account deactivated" and "username
            # mistyped" all said the same to them so far: `login_fail … password`. That is the most frequent
            # support case, and it could not be answered with built-in means.
            self.store.audit_log("login_fail", username, ip,
                                 f"{method} grund={self._fehl_grund(username, method)}"
                                 + (f" quelle={quelle}" if quelle else ""))
            # fail2ban parses this line (ip=…)
            # `fuer_log`: the username comes from a form field. Unfiltered, it could be used
            # to create a second log line with a foreign IP and point fail2ban at third parties
            # (verified against real fail2ban 1.1.1).
            # The event word separates sign-in attempts from everything else: only `failed login`
            # matches the bundled failregex. A wrong guess at the password change, at the
            # step-up page or at a realm PIN is not a sign-in and must not lock out a
            # legitimate, signed-in user at firewall level (see
            # `security.log_ereignis`).
            security.seclog.warning("%s user=%s ip=%s method=%s", security.log_ereignis(method),
                                    security.fuer_log(username), security.fuer_log(ip), method)
            if method not in security.NICHT_LOGIN_METHODEN:
                # The streak counts per folded identifier, like the account bucket (`_topf`). Pre-booked
                # by `_begin_attempt`; only a route without pre-booking counts here. Exactly at the
                # crossing of the limit one line: from there the sign-in is permanently closed, and
                # the operator must know why someone can no longer sign in.
                #
                # The crossing is that of the SETTLED state (p2 F3). An immediately settled
                # booking (without pending) crosses the limit at the booking itself
                # (`vorgebucht[2]`, the settled state afterwards) — it is reported if the
                # streak still stands at closing. A pending one crosses it only with its
                # closing (`vorher < max_serie <= nachher`, in one transaction). Until 2026-09-27
                # the state at booking applied, pending pre-bookings included: if a
                # parallel full sign-in ended the streak, `lockout_serie` stood in the log although
                # nothing was locked.
                max_serie = self._sec("account_max_consecutive_failures")
                if vorgebucht and uebergang:
                    vorher, nachher = uebergang
                    stand = nachher
                    gesperrt = vorher < max_serie <= nachher or max_serie <= min(vorgebucht[2], nachher)
                else:
                    stand = self.store.fehlserie_erhoehen(norm_kennung(username), method)
                    gesperrt = stand == max_serie
                if gesperrt:
                    self.store.audit_log("lockout_serie", username, ip, f"fehlversuche_in_folge={stand}")
                    security.seclog.warning(
                        "Sign-in for user=%s locked: %d failed attempts in a row. Lift: %s.",
                        security.fuer_log(username), stand, self._serie_ausweg(username))

    def _raeumgrenze(self, topf, method, konto: Optional[int] = None) -> Optional[dict]:
        """From where does a success clear the failed attempts under `topf`? Keywords for
        `Store.clear_fails` — or None: not at all (`_record_login`).

        * `konto` given (directory sign-in): if the identifier belongs to ANOTHER account → None
          (G5-N1, `Store.topf_eines_anderen`). Otherwise without limit, as until then: the identifier
          belongs to the entry in the directory, not only from the local creation — that often arises
          only with exactly this sign-in, and the typos before it were made by the same person.
        * The identifier is the name or address of a local account → from its watermark (`ab_id`,
          G2), for existing data without a watermark from the creation (`seit`).
        * Otherwise (a realm `res:<name>`, no identifier of an account) → without limit, as until
          then: there is no account to which the identifier belongs only from a point in time."""
        if method == "resource" or not topf:
            return {}
        if konto is not None:
            return None if self.store.topf_eines_anderen(topf, konto) else {}
        u = self.store.konto_mit_topf(topf)
        if u is None:
            return {}
        grenze = self.store.kennung_grenzen(u).get(topf)
        if grenze is None:
            return {}
        return {"ab_id": grenze[0]} if grenze[0] is not None else {"seit": int(u["created_at"] or 0)}

    #: Which shares of the streak (B2-6) a self-service reset clears: those of the FIRST factors.
    #: Anyone can produce them without knowing a secret — a stranger locks, with wrong PINs,
    #: an account whose owner does not even have a PIN. If they stayed, the reset the message
    #: advises would no longer help (attack on the fixes, R2-2). TOTP wrong guesses, by contrast,
    #: arise only for whoever already has the password; only a complete sign-in or the
    #: operator clears those (R4-13). Likewise a PIN AFTER an already provided factor (chain step of the
    #: half session, route chain of the full one): it books under `_PIN_CHAIN_SERIES` and stays
    #: like TOTP (G7). Until 2026-09-26 the kind did not know the position — in a chain
    #: `password → pin` the reset cleared the second factor's wrong guesses too.
    _SERIE_RESET_ARTEN = ("password", "pin")
    #: The kind of the streak for a PIN behind an already provided factor (G7). `login_attempt`
    #: and the PIN bucket keep counting it as `pin`; only the self-service reset distinguishes.
    _PIN_CHAIN_SERIES = "pin_folge"

    def lift_lockout(self, user_id, methods=None) -> int:
        """Clear the sign-in failed attempts of an account; returns how many there were.

        Without `methods`: after a **complete** sign-in (R7-1). The login lockout counts
        method-blind — password, PIN and TOTP fill the same bucket —, but a success cleared
        only its own method. Whoever signed in by PIN after three mistyped TOTP codes
        carried the three along, and the account was never "fresh" again. A complete
        sign-in has passed every required factor; afterwards there is nothing left against which
        the old failed attempts protect. The own buckets (`NICHT_LOGIN_METHODEN`) remain:
        they belong to processes AFTER the sign-in.

        With `methods`: only these. The self-service reset (R4-13) clears `("password",)`:
        it proves access to the mailbox and replaces the password — about PIN and TOTP it says
        nothing. If it also cleared their failed attempts, anyone with access to the mailbox would get, at
        every reset, fresh guesses against the second factor.

        Counting happened under the identifier someone typed — username OR email,
        with a directory sign-in also the name there (G5). Clearing therefore happens under all of them
        (`Store.zaehl_kennungen`).
        """
        u = self.store.get_user(user_id)
        if not u:
            return 0
        weg = 0
        # The streak (B2-6): a complete sign-in ends it entirely. A password reset
        # clears the shares of the first factors (`_SERIE_RESET_ARTEN`), not the second — the same
        # reason as below (R4-13): the self-service reset proves the mailbox, not the
        # second factor. If it cleared the TOTP wrong guesses too, anyone with a mailbox and
        # password would get a fresh streak against TOTP per reset (measured in the attack on B2-6). The
        # operator clears entirely (`_serie_beenden`, panel reset, `tinysesam unlock`).
        #
        # The streak is deliberately cleared WITHOUT limit a, even if it began before the identifier
        # joined (G2, option A): it has no IP and protects only whoever owns the identifier
        # NOW — before the joining it protected no account, so clearing takes protection from nobody
        # and launders no throttling of an IP. A limit in time would not work either:
        # the streak knows no individual times, and a streak begun before the joining
        # could otherwise no longer be ended by the new owner with any sign-in (permanent lock).
        arten = None if methods is None else tuple(
            set(methods) | (set(self._SERIE_RESET_ARTEN) if "password" in methods else set()))
        for kennung in self.store.zaehl_kennungen(user_id):
            self.store.fehlserie_loeschen(kennung, arten=arten)
        # The window from the joining of the identifier (limit a, G2): otherwise the first
        # complete sign-in would also clear the failed attempts that a stranger had made BEFORE the creation, the
        # rename or the address change under the same identifier — also from the
        # throttling of their IP. Until 2026-09-26 the limit was the creation of the account for every
        # identifier; it is now only the fallback for existing data without a watermark.
        # The directory name (G5) has no watermark: its window is cleared by the sign-in itself
        # (`_record_login`), here only the streak.
        since = int(u["created_at"] or 0)
        for kennung, (ab_id, _) in self.store.kennung_grenzen(u).items():
            grenze = {"seit": since} if ab_id is None else {"ab_id": ab_id}
            ab = since if ab_id is None else 0
            if methods is None:
                ohne = security.NICHT_LOGIN_METHODEN
                weg += self.store.count_fails(ab, username=kennung, exclude_methods=ohne, ab_id=ab_id)
                self.store.clear_fails(username=kennung, exclude_methods=ohne, **grenze)
            else:
                for m in methods:
                    weg += self.store.count_fails(ab, username=kennung, method=m, ab_id=ab_id)
                    self.store.clear_fails(username=kennung, method=m, **grenze)
        return weg

    def _serie_beenden(self, user_id) -> int:
        """End the streak of an account entirely (B2-6) — the operator's way (panel reset).

        Under name, address and the name in the directory (G5, `Store.zaehl_kennungen`): counting
        happens under what someone typed."""
        return sum(self.store.fehlserie_loeschen(k) for k in self.store.zaehl_kennungen(user_id))

    def _fehl_grund(self, username, method=None) -> str:
        """Why did the sign-in fail — for the log, not for the response."""
        if method == "resource":
            # The pseudo-name `res:<name>` is never an account. `kein_konto` therefore stood at
            # EVERY wrong guess at a realm PIN — a line that nobody can evaluate.
            return "falsches_bereichsgeheimnis"
        u = self.find_user(username)
        if not u:
            return "kein_konto"
        if u["disabled"]:
            return "konto_gesperrt"
        if not self.store.get_password_hash(u["id"]) and not self.store.has_pin(u["id"]):
            return "kein_passwort_gesetzt"
        return "falsches_geheimnis"

    def audit(self, event, username=None, ip=None, detail=None):
        """Write an event into the audit log. `detail` takes everything that later answers the question "why".

        What the caller does not name, `audit()` supplements from the running request (B5-02): the
        IP, the signed-in account as `username` if none is named, and `akteur=<name>` in the
        detail if the signed-in account is ANOTHER one than the affected — the admin who
        issues a key to a foreign account. `username` is thus always the account at issue;
        `tinysesam audit --user X` also finds what others did to X.
        """
        a = _ANFRAGE.get()
        if a:
            if ip is None:
                ip = a.get("ip")
            akteur = a.get("akteur")
            if akteur:
                if username is None:
                    username = akteur
                elif str(username).lower() != str(akteur).lower():
                    detail = f"{detail} akteur={akteur}" if detail else f"akteur={akteur}"
        self.store.audit_log(event, username, ip, detail)

    def _kontoname(self, user_id) -> Optional[str]:
        """The username for an ID — for audit lines that would otherwise carry only `user=<id>`."""
        u = self.store.get_user(user_id) if user_id is not None else None
        return str(u["username"]) if u else None

    def _anfrage_merken(self, request, u=None) -> None:
        """Record the IP and signed-in account of the running request for `audit()` (`_ANFRAGE`)."""
        try:
            ip = self.client_ip(request)
        except Exception:        # dummy without header/client — then just without IP
            ip = None
        _ANFRAGE.set({"ip": ip, "akteur": str(u["username"]) if u else None})

    def gc(self, attempts_older_than_sec: int = 86400) -> dict:
        """Clean up: expired sessions/flows/magic tokens/realm unlocks + old
        login attempts. Call regularly (cron/startup/scheduler) — otherwise the tables grow.
        The audit log only if `audit_retention_days` sets a deadline (B5-11) — then the number
        appears under `audit`. Returns the number of deleted rows per area: `unverified_accounts`,
        `sessions`, `flow`, `magic_tokens`, `resource_unlocks`, `login_attempts`,
        `failure_series` (until 0.21.x `fehlserien`), possibly `audit`.
        `attempts_older_than_sec` lies between 0 (all failed attempts) and ten years in
        seconds, otherwise `ValueError`, before anything is deleted."""
        older = _jetzt() - _versuchsfrist(attempts_older_than_sec)
        # BEFORE the tokens: the characteristic "never confirmed" is the expired confirmation token —
        # if `gc_magic_tokens` clears it first, the account can no longer be recognised (R4-09).
        # Without this step an address that someone foreign had registered and never
        # confirmed remained taken forever: the real owner got "email taken".
        # The same loop as `tinysesam gc` — it is in the store so that both go through the one
        # deletion route (H-13, integration findings 12/18). Before, `gc()` had its own copy
        # that deleted the account past the anonymisation.
        zahlen = {
            "unverified_accounts": self.store.gc_unbestaetigte_konten(),
            "sessions": self.store.gc_sessions(),
            "flow": self.store.gc_flow(),
            "magic_tokens": self.store.gc_magic_tokens(),
            "resource_unlocks": self.store.gc_resource_unlocks(),
            "login_attempts": self.store.gc_attempts(older),
            # Streaks not triggered after 90 days of rest; triggered ones remain (B2-6).
            "failure_series": self.store.gc_fehlserien(
                _jetzt() - 90 * 86400, self._sec("account_max_consecutive_failures")),
        }
        tage = int(self.cfg.audit_retention_days or 0)
        if tage > 0:
            zahlen["audit"] = self.store.gc_audit(_jetzt() - tage * 86400)
        return zahlen

    def version(self) -> str:
        """The running version — for the panel. TinySesam does not update itself;
        whoever installed it does that (pinned tag / wheel of a release)."""
        from . import current_version
        return current_version()

    # ---------- Forward auth (reverse proxy) ----------
    #: Default: the set that Authelia/Traefik setups expect.
    #: `Remote-Id` is the account ID — the only value that survives a rename and an email
    #: change (PO decision 2026-09-25: "hang everything on the ID"). An app that assigns users by it
    #: confuses nobody after a change.
    FORWARD_HEADERS_DEFAULT = {"user": "Remote-User", "name": "Remote-Name",
                               "email": "Remote-Email", "groups": "Remote-Groups", "id": "Remote-Id"}

    def _forward_response_headers(self, user) -> dict:
        """The headers the proxy passes on to the app on a successful check.

        `config.forward_headers` is the **complete** list, not an addition: whoever sets only
        `{"user": "X-WEBAUTH-USER"}` also sends only that one header — so "I do not want to
        give out the email address" is an omission and not a second switch. A field may
        point to several names if an app reads one and an intermediary the other.
        """
        if any(z < " " or z == "\x7f" for z in str(user["username"] or "")):
            # The cleaning below would remove the character and send the name of ANOTHER
            # account (`boss\x01` → `boss`). Fail-closed: better no approval than a
            # foreign identity. Exactly the characters that `_header_wert` removes (C0, DEL) — a
            # ZWNJ in a Persian existing name passes through losslessly and does not collide
            # (counter-check). `create_user` no longer permits new names like that at all.
            security.seclog.warning("forward-auth rejected: account name with control characters (user_id=%s)",
                                    user["id"])
            raise HTTPException(403, self.t("api.name_invalid"))
        werte = self._forward_werte(user)
        out = {}
        for feld, namen in (self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT).items():
            for name in ([namen] if isinstance(namen, str) else namen):
                out[name] = self._header_wert(werte[feld])
        return out

    def _forward_werte(self, user) -> dict:
        """The values behind the forward-auth headers and the claims of the gate token — ONE source,
        so that the proxy passes on the same identity on both routes."""
        return {
            "id": str(user["id"]),
            "user": str(user["username"] or ""),
            "name": str(user["display_name"] or user["username"] or ""),
            "email": str(user["email"] or ""),
            "groups": ",".join(self.user_roles(user) + (["admin"] if user["is_admin"] else [])),
        }

    def gate_public_key(self) -> str:
        """The public key of the gate tokens (ADR-9): 32 raw bytes, Base64 — the value for
        `sign_key` in Caddy's `jwtauth` (with `sign_alg EdDSA`). Public, no secret.

        It follows the installation's master key (`TINYSESAM_SECRETS_KEY`, `secrets_key_file`
        resp. `<db>.key`). If that is changed, the proxy needs this value anew."""
        from . import gate as _gate
        return _gate.oeffentlich_b64(self._gate_schluessel)

    def gate_issuer(self) -> str:
        """`iss` of the gate tokens: `base_url` without a trailing slash, without it `"tinysesam"`.
        Fixed rather than derived from the request — the proxy compares it with its configuration."""
        return (security.normalisiere_basis(str(self.cfg.base_url or "").strip()) or "").rstrip("/") or "tinysesam"

    def _gate_hosts(self) -> set:
        """Hosts for which a gate token is issued: the protected ones (`trusted_redirect_hosts`,
        `oidc_clients`) and the own one from `base_url`. Not for any other — `X-Forwarded-Host`
        comes from the caller, and a token for a host that this installation does not protect at all
        would have no purpose except an attacker's."""
        from urllib.parse import urlsplit
        hosts = {str(h).strip().lower().rstrip(".") for h in (self.cfg.trusted_redirect_hosts or []) if h}
        hosts |= {str(h).strip().lower().rstrip(".") for h in (self.cfg.oidc_clients or {}) if h}
        eigen = urlsplit(self.gate_issuer()).hostname
        if eigen:
            hosts.add(eigen.lower())
        return hosts

    _GATE_LINK_COOKIE = "__Host-tinysesam_link"
    _GATE_LINKFLOW_COOKIE = "__Host-tinysesam_linkflow"

    def _gate_link_sitzung(self, request, host: str):
        """The session row behind the connection cookie of this app host (T-26) — or None.

        The cookie applies only to the host for which it was issued: the row in `gate_link` carries
        it, and a cookie that turns up at another host finds nothing. The session itself is checked
        with the same rules as via the own cookie (expiry, inactivity, OIDC re-check)."""
        if not self.cfg.gate_link_enabled or not host:
            return None
        roh = request.cookies.get(self._GATE_LINK_COOKIE) or ""
        if not roh:
            return None
        handle = self.store.gate_link_handle(self.store.session_hash(roh), host)
        if not handle:
            return None
        s = self.store.get_session_by_handle(handle)
        if s is not None and not self._oidc_nachpruefen(s):
            return None
        return s

    def _gate_sitzung(self, request, host: str = ""):
        """The session of this request for the gate: the own cookie, otherwise the host's connection."""
        return self._session_from_request(request) or self._gate_link_sitzung(request, host)

    def _gate_set_cookie(self, response, name: str, wert: str, max_age: int) -> None:
        """A host-only cookie under `__Host-` — Secure, Path=/, without Domain (otherwise the
        browser discards it). With `max_age=0` it deletes."""
        response.headers.append("set-cookie", f"{name}={wert}; Path=/; Max-Age={int(max_age)}; "
                                              "Secure; HttpOnly; SameSite=Lax")

    def _gate_link_url(self, host: str, orig_url: str, request=None) -> str:
        """Where an app host without a connection is sent: to ITS `/.tinysesam/start` (T-26)."""
        from urllib.parse import quote, urlsplit
        o = urlsplit(orig_url or "")
        schema = o.scheme if o.scheme in ("http", "https") else "https"
        netloc = o.netloc or host
        rest = (o.path or "/") + (("?" + o.query) if o.query else "")
        return f"{schema}://{netloc}/.tinysesam/start?rd={quote(rest, safe='')}"

    def _gate_cookie(self, request, user, orig_url: str, rollen_gruppen, sitzung=None) -> Optional[str]:
        """The `Set-Cookie` value with a fresh gate token — or None.

        Only for a full SESSION of the same account, never for an API key: a machine holds
        no cookie, and a token from a key would live on in the browser after the key
        is revoked. Only for a protected host (`_gate_hosts`). The required roles
        are in the audience (`gate.zielgruppe`) so that a token from a check without
        roles does not apply at a path with roles."""
        if not self.cfg.gate_token_enabled:
            return None
        from urllib.parse import urlsplit
        from . import gate as _gate
        host = (urlsplit(orig_url or "").hostname or "").lower().rstrip(".")
        if not host or host not in self._gate_hosts():
            return None
        s = sitzung if sitzung is not None else self._session_from_request(request)
        if not s or not s["mfa_ok"] or s["user_id"] != user["id"]:
            return None
        felder = self.cfg.forward_headers or self.FORWARD_HEADERS_DEFAULT
        werte = self._forward_werte(user)
        claims = {feld: "".join(z for z in werte[feld] if z >= " " and z != "\x7f") for feld in felder}
        ttl = int(self.cfg.gate_token_ttl_sec)
        token = _gate.ausstellen(self._gate_schluessel, iss=self.gate_issuer(),
                                 aud=_gate.zielgruppe(host, rollen_gruppen), sub=str(user["id"]),
                                 claims=claims, ttl=ttl, jetzt=_jetzt())
        return _gate.set_cookie(self.cfg.gate_cookie_name, token, ttl)

    @staticmethod
    def _header_wert(wert: str) -> str:
        """Prepare a value so that it passes as an HTTP header.

        Up to 0.18.0 it went out raw, and two things broke on it:

        1. **Line breaks.** A display name like `"Bose\r\nX-Remote-Groups: admin"` — with OIDC
           or SAML the name comes from the foreign IdP — would be header injection. `h11` does
           catch it, but with `LocalProtocolError`: the response aborts, and the person
           affected no longer gets through the forward auth at all. An injection thus becomes
           a self-lockout with a cryptic message.
        2. **Names beyond Latin-1.** HTTP headers are Latin-1; `"Иван"` or `"测试"` are
           not encodable, and the ASGI server answers with 500. That is no attack, that is
           a Tuesday in an international company — the user simply cannot use the protected
           app.

        Control characters are dropped. The rest goes **always as UTF-8 over the wire** (the bytes
        are passed through Latin-1-transparently) — lossless, and the downstream app reads
        the header as UTF-8.

        Deliberately *always*, not only in an emergency: switching depending on content would be the worse
        solution. "Müller" would then arrive as Latin-1 and "Иван" as UTF-8, and no app could
        know what it has. For pure ASCII — the normal case — nothing changes, because
        ASCII has the same bytes in both encodings.
        """
        sauber = "".join(z for z in str(wert or "") if z >= " " and z != "\x7f")
        return sauber.encode("utf-8").decode("latin-1")

    def _forwarded_url(self, request: Request) -> str:
        """Reconstruct the original URL requested by the proxy (Caddy/Traefik: X-Forwarded-*,
        nginx: X-Original-URL). Fallback: Referer resp. '/'."""
        h = request.headers
        orig = h.get("x-original-url")           # nginx auth_request
        if orig and "://" in orig:
            return orig
        proto = (h.get("x-forwarded-proto") or "https").split(",")[0].strip()
        host = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
        uri = h.get("x-forwarded-uri") or orig or h.get("x-original-uri") or "/"
        if host:
            return f"{proto}://{host}{uri}"
        return h.get("referer") or "/"

    def _forward_app(self, url_or_host: str) -> dict:
        """The gate's settings for an application (T-21): `name` and `login`, from
        `forward_apps[host]` with `forward_login` as fallback. The host without port, lowercase."""
        from urllib.parse import urlsplit
        roh = str(url_or_host or "")
        host = ((urlsplit(roh).hostname if "://" in roh else roh.split(":", 1)[0]) or "").lower().rstrip(".")
        e = {}
        for h, werte in (self.cfg.forward_apps or {}).items():
            if str(h).strip().lower().rstrip(".") == host:
                e = dict(werte or {})
                break
        return {"name": str(e.get("name") or ""), "login": str(e.get("login") or self.cfg.forward_login),
                "logout": str(e.get("logout") or self.cfg.forward_logout)}

    def _gate_host(self, request) -> str:
        """The protected host to which this request went (via the proxy: X-Forwarded-Host, otherwise
        Host) — or "" if this installation does not protect it. For the sign-out routes under
        `/.tinysesam/`: they act on the gate cookie of EXACTLY this host."""
        h = request.headers
        roh = (h.get("x-forwarded-host") or h.get("host") or "").split(",")[0].strip()
        host = roh.rsplit(":", 1)[0] if roh.count(":") == 1 else roh
        host = host.lower().rstrip(".")
        return host if host and host in self._gate_hosts() else ""

    def _gate_cookie_loeschen(self, response) -> None:
        """Delete this host's gate cookie (attributes as when setting it, otherwise it does not apply)."""
        response.headers.append("set-cookie", f"{self.cfg.gate_cookie_name}=; Path=/; Max-Age=0; "
                                              "Secure; HttpOnly; SameSite=Lax")

    @staticmethod
    def _ist_seitenaufruf(request: Optional[Request]) -> bool:
        """Is the browser loading a PAGE here (and not a script, an image, an XHR)?

        `Sec-Fetch-Mode: navigate` says so explicitly; the proxy passes the request's headers on to
        `/auth/forward`. Without the header (older browsers, tools) `Accept: text/html` counts.
        Why: only a page load may go directly to the provider. A background fetch that is
        redirected there can do nothing with the provider's sign-in page — and each one
        would start an OIDC flow of its own (database row, rate limit)."""
        if request is None:
            return False
        h = request.headers
        modus = (h.get("sec-fetch-mode") or "").strip().lower()
        if modus:
            return modus == "navigate"
        return "text/html" in (h.get("accept") or "").lower()

    def _forward_login_url(self, orig_url: str, request: Optional[Request] = None,
                           direkt: bool = False) -> str:
        """Central login URL (on base_url resp. derived) with next=<orig_url>.

        Exception against a silent endless loop: **without `cookie_domain` the session cookie applies
        host-only.** If the login URL then points to a different host than the requested one,
        TinySesam sets the cookie on host A and sends the browser to host B, where it is not
        sent along — the proxy asks again, it goes to the login again, without an error message
        and without a log line. If the requested host is in `trusted_redirect_hosts`, we therefore build the
        login URL there: the same host on which the cookie applies.

        `base_url` remains unaffected — OIDC/SAML callbacks continue to need the one fixed
        address registered at the IdP. Only the own login page is affected.
        The real fix for SSO across several subdomains remains `cookie_domain=".example.com"`.

        The base comes from `public_base()`, i.e. from the same one rule as everywhere:
        `base_url` wins (the headers are then not even read), otherwise a
        derived host counts only from `trusted_redirect_hosts` or loopback, otherwise "" remains.
        **The one exception is the paragraph above** and it is deliberate: without `cookie_domain`
        the requested — co-trusted — host may claim the login page, otherwise the sign-in
        goes round in circles. `config_check` announces this case at startup.
        """
        from urllib.parse import quote, urlsplit
        kandidat = ""
        if not self.cfg.base_url and request is not None:
            h = request.headers
            proto = (h.get("x-forwarded-proto") or request.url.scheme or "https").split(",")[0].strip()
            host = (h.get("x-forwarded-host") or h.get("host") or request.url.netloc).split(",")[0].strip()
            # R4-01 applies here too: Host and X-Forwarded-Host come from the requester. If the
            # derived base does not withstand the check, the login URL stays relative — the
            # browser resolves it against the called host, so a foreign name does
            # not get into the redirect.
            kandidat = f"{self._login_schema(proto, host)}://{host}" if host else ""
        base = self.public_base(candidate=kandidat)
        if base and not self.cfg.cookie_domain:
            # Host from orig_url, not again from the headers: forwarded_url() has already evaluated
            # X-Original-URL and X-Forwarded-*. The whitelist trusted_redirect_hosts is
            # at the same time the protection — a forged X-Forwarded-Host cannot bend the login URL
            # to a foreign host.
            o = urlsplit(orig_url or "")
            if (o.scheme in ("http", "https") and o.hostname
                    and o.hostname != (urlsplit(base).hostname or "")
                    and o.hostname in (self.cfg.trusted_redirect_hosts or [])):
                # Through the same form check as every other base (R5-1): `o.netloc` is raw and
                # carried a user part (`https://foreign.example@app.example.com`) unchanged
                # into the login URL; the scheme came unchecked from X-Forwarded-Proto/X-Original-URL.
                base = security.normalisiere_basis(
                    f"{self._login_schema(o.scheme, o.hostname)}://{o.netloc}") or base
        # Origin of the base + path of the login page WITH prefix (T-15): the base may already
        # carry the prefix (base_url) or not at all (derived, rebuilt for the requested host) —
        # `browser_path()` sets it from the one source, so only scheme and host count from the base.
        ursprung = ""
        if base:
            teile = urlsplit(str(base))
            ursprung = f"{teile.scheme}://{teile.netloc}"
        # `direkt` (T-21, and every re-check at the provider, B-2): straight into the OIDC round instead of
        # onto the login page.
        pfad = "/auth/oidc/start" if direkt else self.cfg.login_path
        ziel = f"{ursprung}{self.browser_path(request, pfad)}?next={quote(orig_url or '/', safe='')}"
        # If this installation protects several applications, the target host belongs in the login URL:
        # only then does `/auth/oidc/start` know for which client it has to begin the round (T-14).
        # Without that every sign-in would run via the default client, and the approval that the
        # provider grants per client would be ineffective.
        anwendung = self._oidc_application(orig_url)
        if anwendung:
            ziel += f"&app={quote(anwendung, safe='')}"
        return ziel

    def _login_schema(self, schema: str, host: str) -> str:
        """The scheme of the login URL if it comes from the request (R5-1).

        Without `base_url` it comes from `X-Forwarded-Proto` resp. `X-Original-URL` — inputs that
        not only the proxy sets. With `cookie_secure=True`, `http` is never right there: the
        session cookie would not arrive at all over http, but the password would go in plaintext over the
        network. So https, except for loopback (local setup without a certificate)."""
        schema = (schema or "").strip().lower()
        if schema not in ("http", "https"):
            schema = "https"
        if schema == "http" and self.cfg.cookie_secure:
            from urllib.parse import urlsplit
            try:
                name = urlsplit("//" + (host or "")).hostname or ""
            except ValueError:
                name = ""
            if not security.eigener_host(name):      # without a list: only loopback counts
                schema = "https"
        return schema

    # ---------- Approvals per application (T-14) ----------
    def _oidc_application(self, url_or_host: str) -> str:
        """The client key for this address — "" if this installation protects only one
        application. The empty return value is intentional: it keeps every call site
        word-for-word at the behaviour of 0.18.0 as long as `oidc_clients` is empty."""
        from urllib.parse import urlsplit
        registry = getattr(self, "oidc_clients", None)
        if not registry or not registry.mehrere:
            return ""
        roh = str(url_or_host or "")
        host = urlsplit(roh).hostname if "://" in roh else roh
        return registry.schluessel_fuer_host(host or "")

    def _record_oidc_approval(self, token: str, client: str, rollen=None) -> None:
        """The provider has approved for this application — note it on the session."""
        self.store.put_oidc_grant(self.store.session_hash(token), client or "*",
                                  _jetzt(), rollen)

    def _oidc_approval_valid(self, token_hash: str, client: str) -> tuple:
        """May this session enter this application? Return `(yes, reason)`.

        `reason` is "" for yes, otherwise "fehlt" (the provider has never approved
        for this application) or "veraltet" (the approval is older than `oidc_revalidate_minutes`).
        The difference matters: in the first case the person has never been here, in the second
        only the deadline expires — and the hop via the provider is then usually
        invisible because its session continues to exist.

        Without several clients the answer is always yes. An installation with one client
        thus behaves exactly like 0.18.0, even if `oidc_revalidate_minutes` is set:
        there is no per-application approval there that could expire.
        """
        registry = getattr(self, "oidc_clients", None)
        if not registry or not registry.mehrere:
            return True, ""
        grant = self.store.get_oidc_grant(token_hash, client or "*")
        if not grant:
            return False, "fehlt"
        frist = int(self.cfg.oidc_revalidate_minutes or 0) * 60
        if frist and (_jetzt() - int(grant["checked_at"])) > frist:
            return False, "veraltet"
        return True, ""

    # ---------- i18n ----------
    def t(self, key, **fmt) -> str:
        """Translated text for key in config.lang (fallback en → key). Placeholders via {name}."""
        from .messages import translate
        return translate(self.cfg.lang, key, self._messages, **fmt)

    def add_messages(self, lang, mapping: dict):
        """Add/override own translations (they take precedence over the built-in ones)."""
        self._messages.setdefault(lang, {}).update(mapping)

    # ---------- Views / redirect safety ----------
    #: The pages that can be replaced — the same list that `render_page()` serves.
    #: The docstring used to name 'magic_sent' and 'resource_pin', neither of which ever existed, and
    #: left out seven real ones. A typo thereby remained silently without consequence: the own page
    #: was registered and never called.
    PAGES = ("account", "error", "forgot", "gate_logged_out", "gate_logout", "gateway_home", "login", "logout",
             "magic_confirm", "magic_invalid",
              "magic_request", "pin", "reauth", "register", "reset", "resource_unlock", "totp",
              "totp_setup")

    def set_template(self, name, fn):
        """Replace a built-in page with an own renderer: fn(auth, ctx) -> str | Response.

        Names: see `TinySesam.PAGES` (depending on the enabled features not all appear).
        String → HTML with status; Response → 1:1. An unknown name is an error, not a
        silent nothing.

        Under a subpath (T-15): `ctx["prefix"]` is the prefix that a TinySesam path
        needs in the browser (`f"{ctx['prefix']}/auth/logout"`; up to 0.21.x `ctx["praefix"]`).
        `ctx["next"]` and `ctx["action"]` are already paths of the browser; `ctx["admin_path"]` is
        a path of the app (prefix in front). The page `magic_confirm` gets `ctx["purpose"]`
        (`login`, `verify_email`, `email_change`; up to 0.21.x `ctx["zweck"]`). Which keys
        a page gets is stated in the docstring of its built-in renderer
        (`tinysesam/templates.py`) — all English since 0.22.0.
        """
        if name not in self.PAGES:
            raise ConfigError(f"Unknown page {name!r} — available: {', '.join(self.PAGES)}")
        self.templates.set(name, fn)

    def csrf_token(self, request: Optional[Request] = None) -> str:
        """The CSRF token of this browser — reuse an existing cookie, otherwise roll a new one.

        Sets NO cookie. A newly rolled token is remembered by the request: a later
        `ensure_csrf(request, response)` sets exactly this one (the way for finished responses such as
        Jinja's `TemplateResponse` — not for one that signs in or out, see `ensure_csrf`). A
        cookie that does not look like a token does not count."""
        if request is not None and self.cfg.csrf_enabled:
            return self._csrf_der_anfrage(request)[0]
        return secrets.token_urlsafe(24)

    def render_page(self, template, status=200, request: Optional[Request] = None, **ctx) -> Response:
        """Pass `request` wherever there is one: then an already set CSRF token remains valid.
        Without `request` a new one is created — that overwrites the cookie and invalidates *other* open
        forms (the classic "form expired" trap)."""
        tok, fresh = None, False
        if request is not None:
            self._pruefe_secure_flag(request)
        if self.cfg.csrf_enabled:
            tok, fresh = self._csrf_der_anfrage(request)
            ctx.setdefault("csrf", tok)      # templates embed <input name=_csrf> / JS reads the cookie
        # One nonce per response. The built-in pages manage without inline handlers/style=;
        # the nonce travels centrally into every <script>/<style> (no threading through the templates)
        # and into the CSP header. An override that returns a response stays untouched —
        # it sets its CSP itself; ctx['nonce'] is available to it.
        nonce = secrets.token_urlsafe(16)
        ctx.setdefault("nonce", nonce)
        # For own templates (set_template): the prefix that app paths need in the browser (T-15).
        ctx.setdefault("prefix", self._praefix(request))
        eingebaut = not self.templates.ueberschrieben(template)
        out = self.templates.render(template, self, ctx)
        if isinstance(out, Response):
            resp = out
        else:
            # The built-in pages write `__TS_P__` in front of every app path (forms, links,
            # fetch calls) — here it becomes the mount prefix (T-15). ONLY for them: the output
            # of an own template stays byte-identical (counter-check: a placeholder in data
            # would there have altered a checked target after the fact).
            if eingebaut:
                out = str(out).replace(_PRAEFIX_PLATZHALTER, ctx["prefix"])
            resp = HTMLResponse(_inject_nonce(out, nonce), status_code=status)
            policy = self._csp_header(nonce)
            if policy:
                resp.headers.setdefault("Content-Security-Policy", policy)
        if tok is not None and fresh:
            self._csrf_cookie_setzen(resp, tok)
        # Here too, not only in the route: error pages from `install_error_pages` pass
        # by no TinySesam route and otherwise carry not a single hardening header.
        return self._kopfzeilen(resp)

    def _kopfzeilen(self, resp: Response) -> Response:
        """The hardening headers of every TinySesam response (R8-1, R8-5, R4-08, R5-2).

        Up to 0.19.0 only the rendered page carried a CSP; everything else — admin panel, JSON API,
        redirects with a token in the address — came without any header. `setdefault`, so that a
        route (or an override) that deliberately sets something else wins.

        * `nosniff` — a JSON response with user input in it is never interpreted as HTML.
        * `Referrer-Policy: same-origin` — reset, sign-in and invitation pages carry the token
          in the address; an image or link to the outside would otherwise take it along as `Referer`.
          Deliberately not `no-referrer`: with that the browser sets `Origin: null` on every
          same-origin POST, and an origin check in the proxy in front would reject the login form.
        * `Cache-Control: no-store` + `Vary: Cookie` — the responses depend on the session
          (account, session list, `/auth/me`); a shared cache in front must neither keep them
          nor hand them to the next visitor.
        * `X-Frame-Options: SAMEORIGIN` — only with `csp='strict'`, whose `frame-ancestors 'self'`
          it repeats for older browsers. An own policy or `off` (the proxy sets the
          CSP) itself decides who may embed; a fixed XFO would override that.
        """
        self._kopfzeilen_in(resp.headers)
        return resp

    _secure_flag_gemeldet = False

    def _pruefe_secure_flag(self, request: Request) -> None:
        """`cookie_secure=False` although the browser comes over HTTPS? Say so loudly once (F-04).

        The most common production form is a TLS proxy in front of an app that itself sees only HTTP.
        Whoever leaves `cookie_secure=False` there (because it was needed locally without a certificate)
        sends the session cookie without the Secure flag — and nothing reported it: the
        configuration check deliberately stays silent (`base_url` is no statement about the
        transport), and the panel warns only about missing HTTPS. The request itself knows,
        though: scheme `https` or `X-Forwarded-Proto: https`. Loopback does NOT count here as
        secure (unlike in `_is_secure`) — local without a certificate is exactly the permitted case.
        One line per instance so that the log does not fill up."""
        if self.cfg.cookie_secure or self._secure_flag_gemeldet:
            return
        proto = (request.headers.get("x-forwarded-proto") or "").split(",")[0].strip().lower()
        if request.url.scheme != "https" and proto != "https":
            return
        self._secure_flag_gemeldet = True
        security.seclog.warning(
            "Configuration: cookie_secure=False, but the browser comes in over HTTPS — session and "
            "CSRF cookie go out without the Secure flag and thus also over any plaintext connection "
            "to the same host. Set cookie_secure=True (that is the default).")

    def _kopfzeilen_fehler(self, exc) -> None:
        """The same headers for an `HTTPException` from a TinySesam route.

        The response there is built by the host's exception handler (or Starlette's default) —
        the route class never gets to see it. Both do take over `exc.headers`, though; so
        the headers travel into it there. The 401 from `/auth/admin` without a session is exactly such
        a response.

        `exc.headers` remains an ordinary dict with the keys as the route wrote them.
        A detour via `MutableHeaders` wrote them in lowercase — a host handler with
        `exc.headers["Location"]` then no longer found the redirect and delivered a 307 without
        a target (A1). Hence: ignore case only when looking up, never when writing.
        """
        exc.headers = dict(exc.headers or {})
        self._kopfzeilen_in(_DictKopfzeilen(exc.headers))

    def _kopfzeilen_in(self, h) -> None:
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("Cache-Control", "no-store")
        vary = h.get("vary", "")
        if "cookie" not in [v.strip().lower() for v in vary.split(",")]:
            h["Vary"] = f"{vary}, Cookie" if vary.strip() else "Cookie"
        if ((self.cfg.csp or "").strip() == "strict"
                and h.get("content-type", "").startswith("text/html")):
            h.setdefault("X-Frame-Options", "SAMEORIGIN")

    def _csp_header(self, nonce: str) -> str:
        """The CSP for the own pages. 'strict' = everything same-origin, script/style only via
        nonce (no 'unsafe-inline'); 'off' = no header; otherwise the own string with {nonce}."""
        csp = (self.cfg.csp or "").strip()
        if not csp or csp == "off":
            return ""
        if csp == "strict":
            # Background images from https addresses (brand_backgrounds) — exactly their origin, nothing beyond.
            fremd = sorted({"https://" + b[len("https://"):].split("/", 1)[0].split("?", 1)[0]
                            for b in (getattr(self.cfg, "brand_backgrounds", None) or []) if b.startswith("https://")})
            return ("default-src 'self'; "
                    f"script-src 'nonce-{nonce}'; style-src 'nonce-{nonce}'; "
                    f"img-src 'self' data:{''.join(' ' + h for h in fremd)}; base-uri 'none'; "
                    f"form-action 'self'{''.join(' ' + h for h in self._form_ziele())}; "
                    "frame-ancestors 'self'; object-src 'none'")
        return csp.replace("{nonce}", nonce)

    def _form_ziele(self) -> list:
        """Where a form of the own pages may lead, beyond `'self'` (0.24.13, `form-action`).

        `form-action` does not fall back to `default-src` (DAST 2026-10-11, ZAP 10055-13): without the directive an
        injected `<form action=https://foreign>` may send anywhere. Chrome also checks it on the redirect
        AFTER submitting (Firefox does not) — therefore the targets to which TinySesam itself redirects are listed here:
        the own `base_url` (sign-out on the app host goes to the gateway), the protected hosts from
        `trusted_redirect_hosts` and the client entries (sign-in, "Continue as …", return after sign-out),
        the OIDC provider including its sign-out endpoint (sign-out "everywhere") and the SAML IdP. Only hosts from the own
        configuration, no wildcard; a host without a scheme counts in the CSP for the page with its scheme (and
        http→https)."""
        from urllib.parse import urlsplit

        def host(url):
            try:
                n = urlsplit(url if "://" in url else "https://" + url).netloc
            except ValueError:
                return ""
            return n if n and re.fullmatch(r"[A-Za-z0-9.\-\[\]:]+", n) else ""

        c = self.cfg
        urls = [c.base_url or "", c.oidc_issuer or "", getattr(c, "saml_idp_sso_url", "") or ""]
        oidc = getattr(self, "oidc", None)
        meta = getattr(oidc, "_meta", None) if oidc is not None else None
        if isinstance(meta, dict):
            # Only what is already loaded — the head of a response triggers no network access.
            urls.append(str(meta.get("end_session_endpoint") or ""))
        ziele = {host(u) for u in urls if u and "://" in u}
        # Hosts from trusted_redirect_hosts (and the client hosts): `safe_next` compares only the name, any port
        # is allowed. In the CSP a host without a port counts only for the default port — hence `name:*`, otherwise
        # a redirect would get stuck that `next` has just allowed.
        for h in list(c.trusted_redirect_hosts or []) + list(getattr(c, "oidc_clients", None) or {}):
            n = host(str(h)).rsplit("]", 1)
            name = (n[0] + "]") if len(n) == 2 else n[0].split(":", 1)[0]
            if name:
                ziele.add(name + ":*")
        return sorted(z for z in ziele if z)

    def public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
        """The public base URL for everything that leaves the house — mail links,
        redirect URIs, SAML metadata. Empty means: there is none, the caller aborts.

        Up to 0.18.0 ten places derived this address from the request themselves — six times as
        `cfg.base_url or str(request.base_url)` (magic link, reset, confirmation, OIDC post-logout,
        OIDC redirect URI, admin invitation), three times for SAML and once in the forward-auth
        redirect. The derived part is the raw `Host` header and thus an input of the
        attacker: whoever triggers "forgot password" for a
        foreign mailbox and sets `Host: attacker.example` in the process, made TinySesam send a real mail with a real reset token whose
        link pointed to the attacker's server (R4-01/R8-4, CWE-644). `trusted_redirect_hosts`
        protected only `?next=`, not this route.

        Now: `base_url` always wins — if it is set, nothing at all comes from the request.
        Otherwise the derived host is checked (`security.eigener_host`), and only a
        host from `trusted_redirect_hosts` or a loopback address counts as the own.

        **This is the only place where this question is decided.**
        `require_public_base()` and `_gepruefte_basis()` both call it and only turn the
        empty result into an error — with the text that fits their caller.
        `_forward_login_url()` also asks here (with its one exception, justified in the docstring
        there). Two versions of the same rule diverged as soon as several
        own names were in play: the routes held `base_url`, the route via the methods
        let the `Host` header choose — and the gap sat exactly in the difference.

        `candidate` allows a route to have a differently derived base checked (SAML
        evaluates `X-Forwarded-Proto/Host` itself) — it is checked by the same rule.

        **The path part belongs to it**, from both sources: `base_url="https://example.com/sso"`
        keeps its prefix, and a derived base takes over the server's `root_path`
        (`security.sichere_basis`). Without that, an app mounted under a subpath got
        mail links without the prefix — and whoever appends it once more afterwards, links with it four times.
        The result is the **finished** base: nothing is appended to it any more.

        The links sent carry the subpath via this base; the built-in pages and
        redirects since T-15 via `_praefix()`/`browser_path()` — from the same `base_url`.

        Whoever needs a base and must not continue without one takes
        `require_public_base()` — this method here returns "" and leaves the
        decision to the caller. Exactly two places may do that, because both have a viable
        way back: the OIDC post-logout (without a base the provider detour is dropped, the local
        logout runs anyway) and `_forward_login_url()` (without a base the redirect stays
        relative, the browser resolves it against the called host).
        """
        if self.cfg.base_url:
            # The CONFIGURED base also goes through the same form check as the derived one
            # (C-7). Before, it saw only `strip().rstrip("/")`: `https://who:what@auth.example`
            # thus stood in every reset link and every redirect URI, a fragment cut off
            # the appended token. `config_check` already rejects both at construction —
            # this line is the floor beneath it, because a config can still be changed after the
            # constructor.
            basis = security.normalisiere_basis(str(self.cfg.base_url))
            if not basis:
                raise StateError(
                    "base_url is set, but is not a usable base address: "
                    f"{str(self.cfg.base_url)!r}. Expected is scheme http/https and a host, "
                    "without user info, query or fragment (a subpath is allowed, e.g. "
                    "\"https://example.com/sso\"). Nothing is guessed here.")
            return basis
        roh = str(candidate or (str(request.base_url) if request is not None else "")).strip()
        basis = security.sichere_basis(roh, self.cfg.trusted_redirect_hosts)
        if not basis and roh and security.einmal_melden("public_base:" + _host_aus(roh)):
            # Say loudly once why nothing happens — otherwise the operator looks for the error
            # at the mailer. fail2ban reads this logger along, and the forward auth asks here on
            # EVERY anonymous request (one page load is twenty subresources): a
            # storm of identical lines would itself be a finding, so `einmal_melden()` says it
            # once per process and host — the hint about base_url is in the line.
            security.seclog.warning(
                "No trustworthy public host: %s comes from the Host header and "
                "is neither in trusted_redirect_hosts nor loopback. The operation aborts "
                "(otherwise a link to a foreign host would go out). Remedy: set "
                "base_url. This line appears once per host, not per request.",
                security.fuer_log(roh))
        return basis

    def require_public_base(self, request: Optional[Request] = None, candidate: str = "") -> str:
        """Like `public_base()`, only without a way back: no checked base → `ConfigError`.

        For every route that puts an absolute address **into foreign hands**: link in a mail,
        redirect URI at the IdP, entity ID in SAML metadata.

        Up to 0.18.x this was solved differently at every place, and two places solved it wrongly:
        `/auth/forgot` and `/auth/magic/request` with a missing base wrote only an
        audit line and **still rendered the success page** — HTTP 200, "mail is on its way",
        no mail. The same response prevents user enumeration, and precisely because of that
        it concealed the total failure here: password reset and magic link were
        broken for all users, visible only in the log. The other places threw `HTTPException(500)` — right
        in the result, but a server error in the middle of the sign-in attempt, although it was already clear at construction
        that it could not work.

        Both are gone. `config_check` makes `base_url` mandatory as soon as one of these routes
        is on — so construction fails before a user clicks "forgot password".
        This method is the second lock for the rest: a config that was changed
        after the constructor (it is read at request time). Then the process aborts with a
        message that says what to enter — not with silent success.
        """
        basis = self.public_base(request, candidate)
        if not basis:
            raise ConfigError(
                "No trustworthy public address: base_url is empty, and the host "
                "from the request is not established as our own (it is not in "
                "trusted_redirect_hosts and is not a loopback address). Nothing is guessed "
                "from the Host header — it is an input of the requester, and with a "
                "mail to a foreign mailbox that is the attacker (R4-01). Remedy: set base_url "
                "to the public address of this app, e.g. "
                "base_url=\"https://auth.example.com\"; mounted under a subpath, with "
                "prefix (\"https://example.com/sso\").")
        return basis

    def _gepruefte_basis(self, base_url) -> str:
        """Check a base address passed in from OUTSIDE before it goes into a link.

        `public_base()` sits in the routes — but whoever embeds TinySesam often builds their own "forgot
        password" form and then calls `send_password_reset(mail, base)`.
        If this app followed the obvious pattern `str(request.base_url)`, it was fully exposed to R4-01,
        although the built-in route had long been sealed: the check was only
        in the route, not in the method. Therefore every route that sends a link now
        checks its base itself — `magic_url()` and the four senders above it.

        It is **the same one rule** — this method calls `public_base()` and turns the
        empty result into an error, just as `require_public_base()` does for the routes.
        The difference lies only in the text of the exception, which speaks of the passed value:

        * If `cfg.base_url` is set, **it wins unconditionally** — with scheme and path part. The
          passed base does not come into play at all. This also catches the case in which, behind a
          TLS-terminating proxy, `str(request.base_url)` yields an `http://` (the link would
          otherwise silently remain unencrypted) **and** the case of several co-trusted names: until the
          second rework `base_url` won here only if the passed host happened to be
          the same; otherwise `trusted_redirect_hosts` decided. The `Host` header could thus
          still *choose* which of the own names goes into the reset link — exactly the core
          of R4-01, only one level deeper.
        * Without `base_url` the host must come from `trusted_redirect_hosts` or be loopback
          (`security.sichere_basis`). A path in the base is preserved (app mounted under a
          subpath), a user part in the host is not.
        * Everything else is a foreign name → `ConfigError`. No token, no mail, an error
          that the developer sees on the first attempt — instead of a link that the victim
          clicks.

        **Idempotent**, and that is no subtlety: the four senders check their base before the
        token is issued, `magic_url()` checks it once more, because an app also lands there that
        calls only this one method. The first version appended the path part each time anew
        to a base that already carried it (`sichere_basis()` has returned it as well since N1) — from
        `https://example.com/portal` became, over four stations,
        `https://example.com/portal/portal/portal/portal/auth/reset?token=…`. The mail went
        out, the recipient clicked, the link was 404: no error, no log line. Therefore
        nothing is appended here any more, and a test sends a base WITH a path through all
        five routes and **counts** the occurrences of the prefix.
        """
        roh = str(base_url or "").strip()
        basis = self.public_base(candidate=roh)
        # It is replaced silently — but not noiselessly: whoever passes a different address than the one that
        # ends up in the link has either passed the request through (then that is exactly the
        # protection) or made a mistake (then they would otherwise search for a long time). Once per address, not per
        # request: with this pattern the value comes from the `Host` header.
        #
        # The **whole** base is compared, not just the host (C-5): an app under a
        # subpath that passes `https://auth.example/falsch` while `base_url` is
        # `https://auth.example/sso` previously got no line — same host, so
        # the place stayed silent. Exactly this case (wrong prefix → 404 at the recipient) is the one
        # the CHANGELOG promises to report.
        _vergleich = security.normalisiere_basis(roh) or roh.rstrip("/")
        if basis and roh and _vergleich != basis \
                and security.einmal_melden("gepruefte_basis:" + _vergleich):
            security.seclog.warning(
                "Passed base address %s is replaced by base_url (%s) — base_url is the "
                "operator's commitment and always wins. If the value comes from str(request.base_url), "
                "it is the requester's Host header; that is exactly how a reset link pointed to "
                "a foreign server (R4-01). This line appears once per host, not per request.",
                security.fuer_log(roh), security.fuer_log(basis))
        if not basis:
            # `public_base()` has already logged (once per host). In the text of the exception is
            # the shortened version freed of control characters: the value comes from the requester,
            # and an exception travels into logs and error pages.
            raise ConfigError(
                f"This base address does not go into a sent link: "
                f"{security.fuer_log(roh)!r}. Allowed "
                "are base_url, a host from trusted_redirect_hosts, and loopback. Whoever takes the base "
                "from the request takes the requester's Host header — with a mail to "
                "a foreign mailbox, that is the attacker's. In a route "
                "auth.public_base(request) returns the checked base (empty = abort).")
        return basis

    #: What may serve as a mount prefix (`root_path`) in pages and redirects (T-15). The value comes
    #: from the ASGI server (`--root-path`) or from a Starlette mount, not from the browser — but it
    #: lands unmasked in attributes and scripts, hence only these characters.
    _PRAEFIX_FORM = re.compile(r"(?:/[A-Za-z0-9._~-]+)*")

    def _praefix(self, request: Optional[Request]) -> str:
        """The prefix under which TinySesam's pages lie in the browser, without a trailing slash.

        One source for all built-in pages and redirects (T-15): under `uvicorn --root-path
        /sso` behind a proxy that strips `/sso`, or as `Mount("/sso", app)`, they pointed
        until then out of the mount (`/auth/login` instead of `/sso/auth/login` → 404).

        **First the path of `base_url`** — it is TinySesam's public address and carries
        the prefix according to the docs anyway. Only so is the prefix right where the running request
        does not know it: in a guard of the host app outside the TinySesam mount (`root_path`
        is empty there) and behind a proxy that strips without `--root-path` (counter-check).
        Without `base_url` the request's `root_path`. A value of unexpected shape is not
        used (loudly, once) — better a 404 than a prefix that carries markup into a page."""
        if self.cfg.base_url:
            from urllib.parse import urlsplit
            roh = urlsplit(self.cfg.base_url).path.rstrip("/")
        elif request is None:
            return ""
        else:
            roh = str(request.scope.get("root_path") or "").rstrip("/")
        if not roh:
            return ""
        if not self._PRAEFIX_FORM.fullmatch(roh):
            if security.einmal_melden("praefix_form"):
                security.seclog.warning("root_path %s has an unexpected form and is not used for pages and "
                                        "redirects (allowed: /part/part of A–Z a–z 0–9 . _ ~ -).",
                                        security.fuer_log(roh))
            return ""
        return roh

    def browser_path(self, request: Optional[Request], path: str) -> str:
        """Convert an app path (`/auth/login`, `login_path`, `admin_path`, …) into the path
        the browser needs — with the mount prefix in front (T-15).

        Only for paths meant relative to the app. A `next` target is already a path of the
        browser (it comes from `request.url.path`, and the prefix is already there) and gets
        no second one. Absolute URLs and protocol-relative values remain as they are."""
        p = str(path or "")
        if not p.startswith("/") or p.startswith("//"):
            return p
        return self._praefix(request) + p

    def safe_next(self, next_: str, request: Optional[Request] = None) -> str:
        """Secure the ?next= target against open redirect (only relative paths resp. trusted_redirect_hosts).

        With `request` the fallback `login_redirect` gets the mount prefix (T-15); the
        passed target itself remains as it is — it is already a path of the browser.

        The host of the own `base_url` always counts: a redirect to the own public
        address is by definition not an open redirect. Otherwise, with forward auth on
        ONE host (app and TinySesam under the same name), one would have to repeat the own host in
        `trusted_redirect_hosts` — if one forgets, the absolute `next=` is
        silently discarded and one lands on `login_redirect` after the login.
        """
        hosts = list(self.cfg.trusted_redirect_hosts or [])
        if self.cfg.base_url:
            from urllib.parse import urlsplit
            own = urlsplit(self.cfg.base_url).hostname or ""
            if own and own not in hosts:
                hosts.append(own)
        rueckfall = self.browser_path(request, self.cfg.login_redirect)
        if _PRAEFIX_PLATZHALTER in str(next_ or ""):
            # The placeholder of the built-in pages has no business in a target: on replacing,
            # `/__TS_P__/evil.example` would become `//evil.example` (counter-check T-15).
            return rueckfall
        return security.safe_next(next_, rueckfall, hosts or None)

    # ---------- FastAPI-Integration ----------
    def _riegel(self, config: TinySesamConfig, *, beim_aufbau: bool) -> None:
        """All checks that make construction fail — in the constructor and once more before
        `router()`/`admin_router()` (A2).

        Until then they stood only in the constructor; `_nachpruefen` knew only `config_check` and
        the cookie fields. Whoever set `auth.cfg.allow_signup = True` afterwards built, alongside
        `admin_identifiers=["boss"]`, a router in which the first visitor registered as "boss"
        and became first admin. `beim_aufbau=False` leaves out only `config_check` —
        `_nachpruefen` has already run it via `TinySesamConfig._befunde()`, warnings included."""
        if config.login_identifier not in ("username", "email", "both"):
            raise ConfigError("login_identifier must be 'username', 'email' or 'both'")
        if config.login_identifier == "email" and config.allow_signup and not config.signup_require_email:
            raise ConfigError("login_identifier='email' needs signup_require_email=True — "
                             "otherwise accounts arise that cannot sign in")
        # All remaining contradictions at once — at construction, not at the first login. The
        # checks above raise individually because each tells its own story;
        # what comes after is collected by config_check.py and reported together. Whoever has three things
        # wrong should read them once and not start three times.
        if beim_aufbau:
            befunde, hinweise = config_check.check_config(config)
            for hinweis in hinweise:
                security.seclog.warning("configuration: %s", hinweis)
            if befunde:
                raise ConfigError("The configuration does not work like this:\n  - " + "\n  - ".join(befunde))

        if config.cookie_samesite not in ("lax", "strict", "none"):
            raise ConfigError(
                "cookie_samesite must be 'lax', 'strict' or 'none' (lower case). "
                "Starlette only checks the value at the first cookie — and under `python -O` not at "
                "all, so the typo would end up in the Set-Cookie header.")
        if config.cookie_samesite == "none" and not config.cookie_secure:
            raise ConfigError(
                "cookie_samesite='none' requires cookie_secure=True — a browser discards a "
                "SameSite=None cookie without the Secure flag, the sign-in would never arrive.")
        if not isinstance(config.csp, str):
            raise ConfigError("csp must be a string ('strict', 'off' or a custom policy)")
        if config.https_mode not in ("off", "warn", "force"):
            raise ConfigError("https_mode must be 'off', 'warn' or 'force' — anything else "
                             "counts as 'no redirect', so a typo silently switches the "
                             "HTTPS enforcement off")
        # cookie_secure=False is right for local setups without a certificate and remains
        # allowed. Together with https_mode='force' it contradicts itself, though: the app then redirects
        # every request to HTTPS and still hands out the session cookie without the
        # Secure flag.
        #
        # Only what the app says about its OWN behaviour is checked — not what it claims about
        # the outside world. An earlier version also fired on
        # `base_url='https://…' + cookie_secure=False`; that sounded plausible but was wrong:
        # `base_url` is a commitment about the public address (SAML/OIDC build callbacks from it),
        # not about the transport between browser and app. Four suites of our own
        # need exactly this combination (public HTTPS URL, TestClient on http://) —
        # a guard that fires wrongly four times in the own house does so all the more with users.
        # `totp_required` was always a switch without a wire: it stood in the config, in
        # both READMEs ("enforce 2FA") and on the website — and was read nowhere in the
        # code. Whoever set it believed the second factor was enforced and it was
        # not. An ineffective security switch is more dangerous than none at all, because
        # it ends the search for the right way. The library therefore now says so loudly
        # instead of continuing to ignore it silently — and names the route that really applies.
        if getattr(config, "totp_required", False):
            raise ConfigError(
                "totp_required has never had any effect — the switch was not read anywhere. "
                "Whoever wants to make TOTP mandatory uses the factor chain: "
                "login_chain=['password', 'totp'] (with login_chain_strict=True). Without a chain "
                "the classic policy applies: TOTP is required as soon as it is set up.")
        if not config.cookie_secure and config.https_mode == "force":
            raise ConfigError(
                "https_mode='force' and cookie_secure=False contradict each other: the app "
                "redirects every request to HTTPS but hands out the session cookie without the "
                "Secure flag. Either cookie_secure=True, or https_mode='warn' "
                "(local/without certificate).")

        # First admin via allowlist + open self-registration: the allowlist vouches only for
        # WHICH name becomes admin — not WHO gets that name. If `admin_identifiers` stands
        # on a fresh instance with `allow_signup=True`, the first person to guess
        # the address registers exactly under it and is admin at the first login. That is the same
        # error the bootstrap is actually meant to avoid ("first one wins") — only one
        # stage later.
        #
        # The combination is viable only if the identity from the registration itself
        # is proven: an email address (not a pure username that nobody confirms),
        # mandatory at registration AND verified via confirmation link. Then whoever has the mailbox
        # has the name.
        #
        # This door is open not only with `allow_signup`. Every method that creates an account
        # itself at the first login creates it under a name that the foreign IdP
        # supplies: `oidc.py` takes `preferred_username`, SAML the NameID/attribute field, LDAP
        # the sign-in name. That is the same situation as with open registration — only
        # there the visitor determines the name and here the IdP, and with an IdP
        # with self-registration that is the same person.
        offene_tueren = []
        if config.allow_signup:
            offene_tueren.append("allow_signup=True")
        for an, anlegen, name in (("oidc_enabled", "oidc_auto_create", "OIDC"),
                                  ("saml_enabled", "saml_auto_create", "SAML"),
                                  ("ldap_enabled", "ldap_auto_create", "LDAP")):
            if getattr(config, an, False) and getattr(config, anlegen, False):
                offene_tueren.append(f"{anlegen}=True ({name})")
        if config.admin_identifiers and offene_tueren:
            ids = [str(i).strip() for i in config.admin_identifiers if str(i).strip()]
            namen = [i for i in ids if "@" not in i]
            if namen:
                raise ConfigError(
                    f"admin_identifiers={namen} are usernames, and accounts arise here "
                    f"on their own ({', '.join(offene_tueren)}): nobody confirms a "
                    "username — whoever signs in first like that becomes first admin. With open "
                    "registration enter an email address instead (with "
                    "signup_require_email=True and signup_verify_email=True); with an IdP "
                    "use the one-time-token route (/auth/claim-admin, see admin_claim_ttl_min) "
                    "or switch off auto-creation and assign the account yourself beforehand "
                    "(with OIDC, oidc_allowed_groups narrows the circle further).")
        if config.admin_identifiers and config.allow_signup:
            if not (config.signup_require_email and config.signup_verify_email):
                raise ConfigError(
                    "admin_identifiers together with allow_signup=True requires "
                    "signup_require_email=True AND signup_verify_email=True — otherwise "
                    "anyone simply enters the admin address at registration and becomes admin at the "
                    "first login. Alternatively allow_signup=False or the one-time-token route "
                    "(/auth/claim-admin, see admin_claim_ttl_min).")
        # A typo in the field name ("mail" instead of "email") would otherwise simply omit the
        # header — silently, and visible only when debugging the foreign app. Header names are checked
        # against the permitted character set: a value with a line break would be header injection.
        if config.forward_headers:
            erlaubt = set(self.FORWARD_HEADERS_DEFAULT)
            # First the shape, then the names. `{"user": None}` slipped through (`namen or []`
            # turned it into an empty list) and later tipped EVERY forward-auth request into
            # a 500; `{"user": 123}` killed the constructor with a raw `TypeError` that
            # an `except ConfigError` does not catch.
            for feld, wert in config.forward_headers.items():
                if isinstance(wert, str):
                    continue
                if isinstance(wert, (list, tuple)) and all(isinstance(x, str) for x in wert):
                    continue
                raise ConfigError(
                    f"forward_headers[{feld!r}] must be a header name or a list of them "
                    f"— but is {type(wert).__name__}. Example: "
                    '{"user": "Remote-User"} or {"user": ["Remote-User", "X-Auth-User"]}')
            unbekannt = [k for k in config.forward_headers if k not in erlaubt]
            if unbekannt:
                raise ConfigError(f"forward_headers: unknown field {unbekannt} — allowed are "
                                 f"{sorted(erlaubt)}")
            for feld, namen in config.forward_headers.items():
                for name in ([namen] if isinstance(namen, str) else namen or []):
                    if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9!#$%&'*+.^_`|~-]+", name):
                        raise ConfigError(f"forward_headers[{feld!r}]: {name!r} is not a valid "
                                         "header name")

    def _nachpruefen(self) -> None:
        """Check the config once more before routes arise from it (B3-14).

        The constructor checks and afterwards holds a **reference** to the config object. Whoever
        changes something in between (`auth.cfg.cookie_samesite = "Strict"`, `auth.cfg.base_url = ""`)
        used to bypass every guard — `TinySesamConfig.validate()` existed for that, nobody
        called it. Here is the last point at which an error is still noticed at startup instead of at the
        first click. The constructor has already issued warnings; here only what would have made
        construction fail counts — and ALL of it: `config_check` including the cookie fields and
        the constructor's bolts (`_riegel`, A2)."""
        fehler, _ = self.cfg._befunde()
        if not fehler:
            try:
                self._riegel(self.cfg, beim_aufbau=False)
            except ConfigError as e:
                fehler = [str(e)]
        if fehler:
            raise ConfigError("The configuration was changed after construction and does not "
                              "work like this:\n  - " + "\n  - ".join(fehler))

    def router(self):
        """The FastAPI router with all enabled routes. Mount once, done.

        Checks the config once more beforehand (`_nachpruefen`) — a config broken
        after the constructor fails here with `ConfigError`, not only in operation."""
        self._nachpruefen()
        from .router import build_router
        return build_router(self)

    def admin_router(self):
        """Standalone admin router (relative paths) — mountable at any prefix / sub-app / port,
        or (admin_ui_enabled=False) only the JSON API for the own panel."""
        self._nachpruefen()
        from .admin import build_admin_router
        return build_admin_router(self)

    def _is_secure(self, request: Request) -> bool:
        """HTTPS aktiv? (direkt, via X-Forwarded-Proto hinter Proxy, oder localhost)."""
        if request.url.scheme == "https":
            return True
        if request.headers.get("x-forwarded-proto", "").split(",")[0].strip() == "https":
            return True
        host = request.client.host if request.client else ""
        return host in ("127.0.0.1", "::1", "localhost")

    def install_error_pages(self, app):
        """Register themed error pages (opt-in). Browsers get the 'error' page (in the branding),
        API clients JSON; redirects (login/reauth/factor, via Location header) remain redirects."""
        from starlette.exceptions import HTTPException as _HTTPExc
        from starlette.responses import RedirectResponse, JSONResponse

        def _wants_html(request):
            return "text/html" in request.headers.get("accept", "")

        @app.exception_handler(_HTTPExc)
        async def _handle_http(request, exc):
            headers = exc.headers or {}
            loc = headers.get("Location") or headers.get("location")
            if loc:   # our _deny/_deny_stepup/_redirect_factor → pass the redirect through unchanged
                return RedirectResponse(loc, status_code=exc.status_code, headers=headers)
            if _wants_html(request):
                # Starlette's default text ("Not Found") is English — on the page in the language of the
                # installation, where there is a text for it. Own messages remain as they are.
                nachricht = exc.detail
                from http import HTTPStatus as _HS
                try:
                    standard = _HS(exc.status_code).phrase
                except ValueError:
                    standard = None
                if nachricht == standard and f"error.{exc.status_code}" in _messages_der_sprache(self):
                    nachricht = self.t(f"error.{exc.status_code}")
                return self.render_page("error", status=exc.status_code, request=request,
                                       code=exc.status_code, message=nachricht)
            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code, headers=headers or None)

        @app.exception_handler(Exception)
        async def _handle_500(request, exc):
            if _wants_html(request):
                return self.render_page("error", status=500, request=request, code=500,
                                       message=self.t("error.oops"))
            # The JSON branch bypassed `render_page` and came without any hardening header (A2).
            return self._kopfzeilen(JSONResponse({"detail": "internal server error"}, status_code=500))

    def install_https(self, app):
        """HTTPS according to config.https_mode: 'force' → HTTP→HTTPS redirect middleware; 'warn'/'off' →
        also runs WITHOUT a certificate (with 'warn' a panel notice). Returns the mode."""
        if self.cfg.https_mode == "force":
            from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
            app.add_middleware(HTTPSRedirectMiddleware)
        return self.cfg.https_mode

    def _deny(self, request: Request) -> NoReturn:
        # HTML browser → redirect to login; otherwise (API/JSON) → 401
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, self.cfg.login_path)}?next={nxt}"})
        raise HTTPException(401, self.t("api.not_signed_in"))

    def _deny_stepup(self, request: Request) -> NoReturn:
        # signed in, but factor not fresh. Browser → redirect to /auth/reauth; otherwise 403 + hint header.
        if "text/html" in request.headers.get("accept", ""):
            from urllib.parse import quote
            nxt = quote(request.url.path, safe="/")
            raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/reauth')}?next={nxt}"})
        raise HTTPException(403, self.t("api.stepup"),
                            headers={"X-TinySesam-Reauth": self.browser_path(request, "/auth/reauth")})

    # ---------- Step-up freshness ----------
    def stepup_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
        """True if the current session has freshly confirmed a factor (sudo freshness)."""
        user = user or self.current_user(request)
        if not user or user.get("_via") == "apikey":
            return False   # machine access cannot freshly confirm an interactive factor
        s = self._session_from_request(request)
        if not s or not s["mfa_ok"]:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if not s["mfa_at"] or (_jetzt() - s["mfa_at"]) > self.cfg.stepup_max_age_sec:
                return False
        return True

    def login_fresh(self, request: Request, user: Optional[dict] = None) -> bool:
        """True if the **sign-in** is at most `stepup_max_age_sec` ago.

        The weaker sister of `stepup_fresh()`: what is measured is not the last
        factor confirmation but the age of the session (`created_at`, i.e. the login).

        Intended for exactly one situation — an account that has **no** factor with which it could
        confirm (`stepup_options()` empty, purely federated account without password, PIN
        and TOTP). For creating the FIRST factor the barrier there cannot hang on
        confirmation, otherwise the setup is a dead end: after the window expired,
        `/auth/pin/set` answered with 403, and the reauth page offered a password field that
        this account does not have. An API key is worth nothing here either.
        """
        user = user or self.current_user(request)
        if not user or user.get("_via") == "apikey":
            return False
        s = self._session_from_request(request)
        if not s:
            return False
        if self.cfg.stepup_max_age_sec > 0:
            if (_jetzt() - (s["created_at"] or 0)) > self.cfg.stepup_max_age_sec:
                return False
        return True

    def _redirect_factor(self, request: Request, step) -> NoReturn:
        # Browser → redirect to the input page of the next factor; JSON → 401 + X-TinySesam-Factor.
        if step is None:
            self._deny(request)
        if "text/html" in request.headers.get("accept", ""):
            raise HTTPException(307, headers={"Location": self.browser_path(request, self._factor_entry(step, request.url.path))})
        raise HTTPException(401, self.t("api.factor"), headers={"X-TinySesam-Factor": step})

    def _enforce_route_chain(self, request: Request, factors, strict) -> dict:
        """Enforce a route chain (`require(factors=[…])`) — **in addition** to the global rule.

        A route chain tightens, it never undercuts (PO decision 2026-09-27, "align"):
        First the session must be full for the GLOBAL rule (`mfa_ok`, as with `current_user`) —
        a half session goes first to the missing step of the global sign-in
        (`_next_login_step`). Until then the route's list alone sufficed: `factors=["password"]`
        opened the route to a half session whose account still owed TOTP, and
        `["pin", "password"]` that of an account with TOTP that had provided only PIN and password.
        After that the route's own list (`_chain_satisfied`) and the second factor after the
        sign-in link (`_link_braucht`, G10). An API key does not satisfy a route chain."""
        strict = self.cfg.login_chain_strict if strict is None else strict
        s = self._session_from_request(request)
        usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
        if usr and usr["disabled"]:
            usr = None
        done = json.loads(s["factors_done"] or "[]") if s else []
        if usr is None or s is None:
            self._redirect_factor(request, factors[0] if factors else "password")
        if not s["mfa_ok"]:
            # The global sign-in is still open: first its next step. `None` (nothing
            # open any more, but not full either — e.g. a factor removed in the meantime) → login.
            self._redirect_factor(request, self._next_login_step(usr["id"], done))
        if not self._chain_satisfied(factors, strict, done):
            self._redirect_factor(request, self._next_factor(factors, strict, done))
        # The same rule as for the global policy (G10): if the sign-in went through the link and
        # the account has a second factor, a route chain like `["magic"]` demands it too — otherwise
        # the mailbox alone would open the route of an account that protected itself with TOTP/passkey.
        # If the chain itself contains `totp`/`passkey`, it is already provided (no double step).
        fehlt = self._link_braucht(usr["id"], done)
        if fehlt is not None:
            self._redirect_factor(request, fehlt)
        d = dict(usr)
        d["_via"] = "session"
        return d

    def _enforce(self, request: Request, mfa=False, admin=False, role=None, factors=None,
                 strict: Optional[bool] = None, admin_implies: Optional[bool] = None) -> dict:
        gchain, _ = self._global_chain()
        # The first branch always yields a dict, the other two can yield None and then
        # abort via `_deny`/`_redirect_factor`. Without this declaration a type checker
        # assumes the type of the first branch for the whole rest.
        u: Optional[dict]
        if factors is not None:
            # explicit route chain: never satisfiable via API key, drives own factor steps
            u = self._enforce_route_chain(request, factors, strict)
        elif gchain is None:
            # classic (fast path, unchanged)
            u = self.current_user(request)
            if not u:
                self._deny(request)
        else:
            # global chain: current_user mirrors it (mfa_ok); partial session → next step
            u = self.current_user(request)
            if not u:
                s = self._session_from_request(request)
                usr = self._als_dict(self.store.get_user(s["user_id"])) if s else None
                if not usr or usr["disabled"]:
                    self._deny(request)   # no identity → login (first factor)
                done = json.loads(s["factors_done"] or "[]")
                self._redirect_factor(request, self._next_login_step(usr["id"], done))
        if admin and not self.is_admin(u):
            raise HTTPException(403, self.t("api.admin"))
        if role:
            # One role or several (then ONE of them suffices — the same OR meaning as
            # ?roles=a,b in forward auth). Whoever requires ALL stacks two guards.
            noetig = [role] if isinstance(role, str) else list(role)
            if not any(self.has_role(u, r, admin_implies) for r in noetig):
                raise HTTPException(403, self.t("api.role", rollen=", ".join(f"'{r}'" for r in noetig)))
        if mfa and not self.stepup_fresh(request, u):
            if u.get("_via") == "apikey":
                raise HTTPException(403, self.t("api.stepup_session"))
            self._deny_stepup(request)
        return u

    def require_user(self, request: Request) -> dict:
        """FastAPI dependency (direct): enforces a signed-in (incl. MFA) user.
        Whoever needs no roles: `Depends(auth.require_user)` suffices."""
        return self._enforce(request)

    def require_admin(self, request: Request) -> dict:
        """FastAPI-Dependency (direkt): eingeloggt + Admin (+ Step-up, wenn admin_require_mfa)."""
        return self._enforce(request, admin=True, mfa=self.cfg.admin_require_mfa)

    def require_role(self, *roles, mfa: bool = False, admin_implies: Optional[bool] = None):
        """FastAPI dependency factory: signed in + role. `Depends(auth.require_role('editor'))`.

        **Several roles: one of them suffices** — `auth.require_role('editorial', 'proofreading')`.
        That is the same OR meaning as `?roles=a,b` in forward auth; otherwise the same
        question would mean something different depending on the operating mode. A list works as well
        (`require_role(['editorial', 'proofreading'])`), handy for roles from the configuration.

        Whoever requires **all** stacks two guards — `Depends` dependencies all run:
        `@app.get(..., dependencies=[Depends(auth.require_role('a')), Depends(auth.require_role('b'))])`.

        An admin satisfies the role by default — `admin_implies=False` really requires it.
        mfa=True additionally requires step-up freshness.
        """
        flach = []
        for r in roles:
            if isinstance(r, str):
                flach.append(r)
                continue
            try:
                flach.extend(r)
            except TypeError:
                # Catches the one call that changes through the variadic signature:
                # require_role("editor", True) used to mean mfa=True. mfa and admin_implies
                # are now keyword-only — loud instead of silently wrong.
                raise TypeError(f"require_role(): {r!r} is not a role. "
                                "Pass mfa/admin_implies as keyword arguments only.") from None
        if not flach:
            raise ConfigError("require_role() needs at least one role")

        def dep(request: Request) -> dict:
            return self._enforce(request, role=flach, mfa=mfa, admin_implies=admin_implies)
        return dep

    def require(self, mfa: bool = False, admin: bool = False, role=None,
                factors: Optional[list] = None, strict: Optional[bool] = None,
                admin_implies: Optional[bool] = None):
        """General guard factory for arbitrary combinations — the "flag on the guard" route:
        `Depends(auth.require(mfa=True))`, `Depends(auth.require(admin=True, mfa=True))`.
        `role=` takes one role or several (`role=["editorial", "proofreading"]` → one suffices).
        factors=[...] additionally requires a specific factor chain for this route,
        strict=True/False controls the order: `Depends(auth.require(factors=['oidc','password']))`.
        The route chain tightens the global rule, it does not replace it: a session that is not yet full for the
        global sign-in (second factor open, chain incomplete) goes first
        to its missing step — also with `factors=["password"]` (since 2026-09-27; until then
        the route chain overrode the global one). If the sign-in went through the sign-in link and the
        account has TOTP or a passkey, a route chain demands it too
        (`magiclink_require_second_factor`, as in the global policy)."""
        def dep(request: Request) -> dict:
            return self._enforce(request, mfa=mfa, admin=admin, role=role, factors=factors,
                                 strict=strict, admin_implies=admin_implies)
        return dep

    def require_mfa(self, request: Request) -> dict:
        """FastAPI dependency (direct): signed in + fresh step-up confirmation."""
        return self._enforce(request, mfa=True)

    def require_session(self, request: Request, user: Optional[dict] = None) -> dict:
        """Signed in — and **interactively** at that: a session yes, an API key no (403).

        The bolt for **creating** a factor (set up TOTP, register passkey,
        first PIN). `require_mfa()` covered only the removal; creation still hung on
        `current_user()`, and that accepts an API key. A leaked CI key
        thereby set up a factor that **it** controls: the TOTP secret is in the response
        of `GET /auth/totp/setup`, and a self-registered passkey is a full
        login — through it the key got a fresh interactive session and thus after all to the
        `require_mfa()` routes. The enrollment route was the lever that broke the lock.

        The check is for `_via == "apikey"`, not for `_via == "session"`: with
        TOTP setup under `login_chain=["password","totp"]` a user from
        `totp_enrollment_user()` is there — a session that has provided its first factor but is not yet
        fully signed in. It may set up, a machine credential may not.
        (The key management checks the other way round for `"session"` — it knows no such
        intermediate state and prefers to stay fail-closed.)
        """
        u = user or self.current_user(request)
        if not u:
            self._deny(request)
        if u.get("_via") == "apikey":
            raise HTTPException(403, self.t("api.needs_session"))
        return u

    # ---------- Shared resource secrets (PIN or passphrase, without a user account) ----------
    def set_resource_secret(self, name, secret, kind="pin", label=None):
        """Set/change the secret for a realm. kind='pin' (numeric) | 'password' (passphrase)."""
        if not secret:
            raise ConfigError("empty secret")
        if kind not in ("pin", "password"):
            raise ConfigError("kind must be 'pin' or 'password'")
        self.store.set_resource_secret(name, hash_password(str(secret)), kind, label)

    def remove_resource_secret(self, name):
        """Release a locked resource again (remove the lock, not unlock it)."""
        self.store.delete_resource_secret(name)

    def list_resource_secrets(self):
        """All locked resources (names and descriptions, no secrets)."""
        return self.store.list_resource_secrets()

    def _check_resource(self, name, secret) -> bool:
        """Check the secret of a locked resource (without unlocking it — `_unlock_resource` does that)."""
        row = self.store.get_resource_secret(name)
        return bool(row and verify_password(str(secret or ""), row["hash"]))

    def resource_unlocked(self, request: Request, name) -> bool:
        """Is this resource currently unlocked for this browser?"""
        return self.store.is_resource_unlocked(request.cookies.get(self.resource_cookie_name), name)

    def _unlock_resource(self, request: Request, response, name):
        """Unlock a resource for this browser and set the cookie.

        Every unlock gets a **new** token (F-01). Before, it took over the token from the
        browser's cookie: whoever had planted their own on the victim beforehand
        (neighbouring subdomain, plaintext HTTP) knew afterwards the token of an unlocked
        browser — session fixation, only for the realm PIN. What this browser already had
        open moves over to the new token."""
        alt = request.cookies.get(self.resource_cookie_name)
        token = secrets.token_urlsafe(32)
        if alt:
            self.store.move_resource_unlocks(alt, token)
        ttl = self.cfg.resource_unlock_ttl_hours * 3600
        self.store.add_resource_unlock(token, name, _jetzt() + ttl)
        kw = dict(httponly=True, secure=self.cfg.cookie_secure, samesite=_samesite(self.cfg.cookie_samesite),
                  path=self.cfg.cookie_path, max_age=ttl)
        if self.cfg.cookie_domain:
            kw["domain"] = self.cfg.cookie_domain
        response.set_cookie(self.resource_cookie_name, token, **kw)

    def require_resource(self, name: str):
        """FastAPI dependency factory: realm accessible only after entering the resource secret.
        Independent of the user login. `Depends(auth.require_resource('photos'))`."""
        def dep(request: Request):
            if not self.resource_unlocked(request, name):
                if "text/html" in request.headers.get("accept", ""):
                    from urllib.parse import quote
                    nxt = quote(request.url.path, safe="/")
                    raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/resource/' + name)}?next={nxt}"})
                raise HTTPException(401, self.t("api.resource_locked"))
            return True
        return dep

    # ---------- Stage C: deprecated names, dropped with 1.0 ----------
    # PO decision 2026-09-26: these names are wiring of the built-in routes and do not belong
    # to the commitment (stage C). Up to 0.21.x they carried no underscore and looked like any other
    # method — `check_password` even stood as a building block in the README, although it does not throttle.
    # Since 0.22.0 the implementation is called `_name`, and TinySesam calls only that. The old
    # name remains until 1.0 as an alias that triggers exactly one
    # `DeprecationWarning` with the replacement on call (constants: on read). `tests/test_api_surface.py` holds the list against
    # `tests/api_surface.json` (stage C), checks warning and target of each alias and forbids
    # code in the package from using an old name; `tests/run_all.py` turns such a warning from the
    # package itself into an error.

    def __init_subclass__(cls, **kwargs):
        """A subclass that overrides an old name gets a `RuntimeWarning`.

        Up to 0.21.x an overridden `check_password` took effect on the built-in routes; since
        0.22.0 they call `_check_password`, and the override silently runs into nothing. For
        a checking method that is exactly the kind of change nobody notices until it matters —
        hence a warning that is visible without a filter (not a `DeprecationWarning`)."""
        super().__init_subclass__(**kwargs)
        for name, wert in vars(cls).items():
            alias = next((vars(b)[name] for b in cls.__mro__[1:] if name in vars(b)), None)
            if isinstance(alias, Deprecated) and not isinstance(wert, Deprecated):
                warnings.warn(
                    f"{cls.__name__}.{name} overrides a deprecated name and has had no effect since "
                    f"0.22.0: TinySesam internally calls `{alias.ziel}`. {alias.meldung}",
                    RuntimeWarning, stacklevel=2)

    check_ldap = Deprecated(
        "_check_ldap", "use `login_password` instead (asks the directory as a fallback, "
        "throttles and locks like `POST /auth/login`)")
    check_password = Deprecated(
        "_check_password", "use `login_password` instead (throttles, counts and locks like "
        "`POST /auth/login`), for a custom look use `set_template(\"login\", …)` alone; "
        "`check_password` itself does not throttle")
    check_pin = Deprecated(
        "_check_pin", "use `login_pin` instead (throttles, counts and locks like `POST /auth/pin`), "
        "for a custom look use `set_template(\"pin\", …)` alone; `check_pin` itself does not "
        "throttle")
    check_resource = Deprecated(
        "_check_resource", "use `POST /auth/resource/{name}` (throttles and locks) or "
        "`require_resource` instead")
    check_saml = Deprecated(
        "_check_saml", "use `POST /auth/saml/acs` instead, which checks the assertion's signature; "
        "`check_saml` trusts its arguments")
    complete_mfa = Deprecated("complete_totp", "use `complete_totp` instead (same behaviour)")
    consume_admin_claim = Deprecated(
        "_consume_admin_claim", "use the route `/auth/claim-admin`, `ensure_admin` or "
        "`admin_identifiers` instead")
    factor_entry = Deprecated(
        "_factor_entry", "no replacement; `require_user`/`require` redirect to the open factor themselves")
    forward_login_url = Deprecated(
        "_forward_login_url", "no replacement; the route `/auth/forward` builds the login address itself")
    forward_response_headers = Deprecated(
        "_forward_response_headers", "no replacement; which headers `/auth/forward` sets is controlled by "
        "`forward_headers`")
    forwarded_url = Deprecated(
        "_forwarded_url", "no replacement; the route `/auth/forward` reads the proxy headers itself")
    is_locked = Deprecated(
        "_is_locked", "use `login_password`, `login_pin` or `login_totp` instead, which "
        "check and book atomically; `is_locked` only reads and lets parallel bursts through")
    is_password_change_locked = Deprecated(
        "_is_password_change_locked", "use `change_password` instead (checks and books atomically like "
        "`POST /auth/password`)")
    is_pin_locked = Deprecated(
        "_is_pin_locked", "use `login_pin` instead (checks and books atomically like `POST /auth/pin`)")
    is_reauth_locked = Deprecated(
        "_is_reauth_locked", "use `confirm_password`, `confirm_pin` or `confirm_totp` instead "
        "(check and book atomically like `/auth/reauth`, where `require(mfa=True)` redirects to)")
    is_resource_locked = Deprecated(
        "_is_resource_locked", "use `POST /auth/resource/{name}` instead (checks and books atomically)")
    is_secure = Deprecated(
        "_is_secure", "no replacement; the warning without HTTPS is controlled by `https_mode`")
    is_totp_setup_locked = Deprecated(
        "_is_totp_setup_locked", "use `POST /auth/totp/setup` instead (checks and books atomically)")
    login_redirect_after = Deprecated(
        "_login_redirect_after", "use `next_url` or `redirect()` on the result of "
        "`login_password`, `login_pin` or `login_totp` instead (next factor or `next`)")
    maybe_promote_admin = Deprecated(
        "_maybe_promote_admin", "use `admin_identifiers` or `ensure_admin` instead; called "
        "directly it bypasses the address evidence")
    mfa_pending = Deprecated(
        "_mfa_pending", "no replacement (the name means “has a confirmed TOTP”); the same is "
        "returned by `auth.store.has_confirmed_totp(user_id)` — internals, no promise")
    next_login_step = Deprecated(
        "_next_login_step", "no replacement; `require_user`/`require` redirect to the open "
        "factor themselves")
    purge_demo = Deprecated(
        "_purge_demo", "use `demo_mode=False` instead (clears the demo accounts at startup)")
    rate_ok = Deprecated(
        "_rate_ok", "use `login_password`, `login_pin` or `login_totp` instead (they throttle "
        "per IP), or your own limiter via `set_rate_limiter`")
    record_login = Deprecated(
        "_record_login", "use `login_password`, `login_pin` or `login_totp` instead, which "
        "book every attempt; called wrongly it clears other accounts' failed-attempt counters")
    sec = Deprecated("_sec", "use `all_security()` instead")
    seed_demo = Deprecated(
        "_seed_demo", "use `demo_mode=True` instead (creates the demo accounts at startup)")
    send_signup_notice = Deprecated(
        "_send_signup_notice", "no replacement; `POST /auth/register` sends the notice itself")
    session_from_request = Deprecated(
        "_session_from_request", "use `current_user` or `session_user` instead")
    unlock_resource = Deprecated(
        "_unlock_resource", "use `POST /auth/resource/{name}` instead (checks the secret first)")
    verify_csrf = Deprecated("_verify_csrf", "use `require_csrf` instead")
    verify_recovery_code = Deprecated(
        "_verify_recovery_code", "use `login_totp` instead (also accepts one-time codes, throttles "
        "and locks like `POST /auth/totp`); `verify_recovery_code` itself does not throttle")
    verify_totp = Deprecated(
        "_verify_totp", "use `login_totp` instead (throttles and locks like `POST /auth/totp`), "
        "for the step-up `confirm_totp`; `verify_totp` itself does not throttle")
    verify_user_password = Deprecated(
        "_verify_user_password", "use `confirm_password` instead (step-up, throttles and locks like "
        "`/auth/reauth`) or `change_password` (like `POST /auth/password`); "
        "`verify_user_password` itself does not throttle")
    verify_user_pin = Deprecated(
        "_verify_user_pin", "use `confirm_pin` instead (step-up, throttles and locks like "
        "`/auth/reauth`); `verify_user_pin` itself does not throttle")

    DEMO_USERS = Deprecated(
        "_DEMO_USERS", "no replacement; the demo accounts are called `demo` and `demoadmin` (README)")
    IDENTIFYING = Deprecated(
        "_IDENTIFYING", "no replacement; which factors identify is documented in docs/OPERATIONS.md")
    RECOVERY_BYTES = Deprecated("_RECOVERY_BYTES", "no replacement, an internal value")
