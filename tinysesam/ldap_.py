"""LDAP/lldap backend: verify a password against a directory bind (extra `[ldap]`, ldap3).

Two modes:
- **Direct bind** (`ldap_user_dn_template`, e.g. lldap `uid={username},ou=people,dc=…`): binds directly
  with the user DN + password and then reads attributes.
- **Search-then-bind** (`ldap_bind_dn`/`ldap_bind_password` + `ldap_user_base`/`ldap_user_filter`):
  a service account looks up the user, then a re-bind with that DN + password.

On success returns {username, email, name, groups}; on a wrong password/unknown account
None. If the directory is unreachable or unusable (network, TLS, service account), it raises
`DirectoryNotReachable` — an outage is not a failed attempt by the person signing in (F-23).
Usernames are escaped for filter/DN (LDAP injection protection). **This module never follows
referrals** — otherwise ldap3 would bind on the referred host with the same credentials
(see `_WITHOUT_REFERRALS`). A discarded referral is written to the security log
(`_report_reference`) so that operations can see the reason for the rejection and not just
"wrong password" for every user.
"""
from __future__ import annotations

import threading
import time

from . import errors
from .security import proof_attribute, for_log, seclog


def _missing_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Turn a bare import error into a message that says what to do.

    The extras are deliberately imported LAZILY here (only on use). The price for that was,
    up to 0.18.0, a `ModuleNotFoundError: ldap3` in the middle of the sign-in — for the operator
    a defect, although only one line was missing from the install command."""
    return errors.MissingExtra(
        "The extra [ldap] is not installed (pip install 'tinysesam[ldap]') — "
        f"missing: {e.name or 'ldap3'}.", extra="ldap")


#: Do NOT follow referrals — on EVERY connection this module opens.
#:
#: ldap3 follows a referral (`SearchResultDone resultCode=10`) on its own and opens a
#: new connection to the host that the RESPONSE names — with the same credentials
#: (`create_referral_connection` passes the connection's `user`/`password` on). So a
#: referral injected, or set by a compromised directory, is enough to send the service account's DN and
#: password to a foreign server; on the user connection
#: it would be the password of the person signing in. Reproduced with two LDAP servers on loopback: the
#: foreign host received the complete BindRequest including the plaintext password (audit T-13, F-28).
#:
#: Deliberately hard and without a switch: a referral followed with credentials is not an
#: operating mode that a configuration field should bring back. Anyone who has to search across several AD domains
#: queries the Global Catalog (port 3268/3269) instead of following referrals.
#: Without following, the search ends without a result → `authenticate()` returns `None` (fail-closed).
#: So that this does not happen silently, `_report_reference()` reports the case in the security log.
_WITHOUT_REFERRALS = {"auto_referrals": False}


def _report_reference(conn, was: str, username: str) -> None:
    """Write a search that the directory answered with a REFERRAL to the security log
    — otherwise the login ends silently as "wrong password".

    Without this line the price of the F-28 fix was invisible: anyone searching across several AD domains
    got a rejection for **every** user after the update and nothing pointing
    to the cause (the Global Catalog hint existed only in the source). Only the
    referral case is reported; an ordinary empty search (the account does not exist) is not noteworthy
    and would flood the log.

    The referral address comes from a FOREIGN response and therefore goes through `for_log` —
    a line break in it would be an additional, freely invented line in exactly the log that
    fail2ban reads (the same trap as with the username).
    """
    try:
        result = getattr(conn, "result", None) or {}
        references = result.get("referrals") or []
        code = result.get("result")
    except Exception:            # foreign/unexpected connection object — never disturb the login
        return
    if not references and code != 10:
        return
    seclog.warning(
        "LDAP: %s for user=%s ended with a REFERRAL to %s — TinySesam deliberately does not "
        "follow it (otherwise the password would go to the referred host, finding F-28). The "
        "sign-in therefore fails although the account may exist. Whoever searches across several "
        "AD domains queries the Global Catalog (port 3268/3269) and sets "
        "ldap_user_base to the root.",
        was, for_log(username),
        ", ".join(for_log(v) for v in references[:3]) or "(host not named)")


class DirectoryNotReachable(errors.TinySesamError, RuntimeError):
    """The directory did not answer the question — network, TLS, service account (F-23).

    Up to 0.20.0 every error in `authenticate()` ended as `None`, i.e. as "wrong password":
    the login booked a failed attempt, fail2ban read `failed login`, and after a few
    minutes of outage the users who had done nothing wrong were locked out. In the log
    the outage was indistinguishable from a wrong password. This exception separates the
    two cases; the login route then answers 503 and books nothing against the account."""


class RequestAborted(DirectoryNotReachable):
    """The directory aborted THIS request — not proof that it is gone.

    Raised when a step that carried input from the person signing in (user search, user bind,
    attribute search) ends quickly with a communication error: connection terminated by the
    server, sending or receiving failed. A person signing in can trigger exactly that with the content
    of their own request — OpenLDAP terminates the session as soon as a PDU on the still
    anonymous session is larger than `sockbuf_max_incoming` (default 262143 bytes).

    For the login route it is the same as an outage (subclass: 503, no failed attempt).
    But `TinySesam._check_ldap` does NOT arm the `FailureMarker` for it: until the
    refinement of the T-13 integration it did, and ONE crafted sign-in without an account gave
    every LDAP user 503 for 30 s — repeated every few seconds, indefinitely, without it costing
    the sender a failed attempt. The marker is for failures that HANG (without
    it every pre-booked attempt would hang until the timeout); a quick abort does not hang.
    """


#: How long a connection setup and a response may take. Without a limit a login hung
#: on a directory that drops packets instead of rejecting them for as long as the TCP timeout
#: of the operating system (minutes) — with one worker thread per waiting user.
CONNECTION_TIMEOUT = 10

#: How long a sign-in may query the directory IN TOTAL, across all steps (seconds).
#: Below `Store.PREBOOKING_PENDING_SEC` (30), with headroom for the rest of the route: that is how long the
#: pre-booking of the login route stays pending (G9); an older open row counts as a failed attempt of a process
#: that has died. Until 2026-09-27 there was only the limit per response (`CONNECTION_TIMEOUT`), and
#: a search-then-bind waits up to ten times (per connection setup, TLS handshake, StartTLS,
#: bind, search): a slow but responding directory let a still-running sign-in
#: count as a confirmed failed attempt — a real lockout, lockout mail and `failed login` for third parties
#: (review round 2026-09-27, p2 V1). The limit is distributed across the wait points (`_Deadline`).
TOTAL_DEADLINE_SEC = 25

#: From what duration a failed step that carried input from the person signing in counts as "the
#: directory hangs" (seconds) — then it arms the `FailureMarker` like any
#: outage. Below that it is an abort of THIS request (`RequestAborted`). The threshold separates
#: the two cases the marker is and is not for: a hanging directory responds
#: only after `CONNECTION_TIMEOUT`, an abort because of the content comes within milliseconds.
HANGER_SEC = 1.0

#: Upper limits for what a sign-in may send to the directory (characters). Anything longer
#: is not a sign-in: usernames, UPNs and addresses stay far below 256 characters, and
#: `passwords.PASSWORD_MAX_LENGTH` allows 256 when setting — 1024 leaves directories with
#: their own password rule plenty of room. Even fully used (UTF-8, escaped DN characters)
#: a bind PDU stays under 16 KiB, far below slapd's 256 KiB for anonymous sessions.
#: TinySesam does not even ask about anything above that and treats it like a wrong password.
LDAP_NAME_MAX = 256
LDAP_PASSWORD_MAX = 1024


def input_too_long(username, password) -> bool:
    """Is the username or password longer than any real sign-in (`LDAP_NAME_MAX`,
    `LDAP_PASSWORD_MAX`)? Then do not send it to the directory — see `RequestAborted`."""
    return (len(str(username or "")) > LDAP_NAME_MAX
            or len(str(password or "")) > LDAP_PASSWORD_MAX)

#: How long after an outage the directory is not queried at all (seconds, see
#: `FailureMarker`). As long as the Redis pause: shorter would mean more hanging probes, longer
#: would mean that a directory that has come back is accepted again noticeably later.
FAILURE_PAUSE_SEC = 30


class FailureMarker:
    """Remembers a directory outage so that not every sign-in hangs until the timeout.

    Modelled on the Redis pause (`security.RedisRateLimiter`). Here it is more than convenience: the
    login route books every attempt IN ADVANCE as a failed attempt (`_begin_attempt`, R7-2) and takes it
    back on an outage only when `DirectoryNotReachable` arrives (F-23). With a
    directory that drops packets, that is after `CONNECTION_TIMEOUT`. Until then every
    hanging sign-in counted for account, pair and address — and during the WHOLE outage,
    since every new attempt hung again for ten seconds: 15 colleagues behind one NAT address, and
    the local emergency admin got 429 with the correct password; every further rejection wrote
    `failed login … reason=lockout_ip`, and fail2ban banned the address. That is exactly what F-23 was
    meant to prevent.

    It is armed only by a failure that affects the directory as a whole —
    connection setup, TLS, service account, or a question that HUNG until the timeout. If the
    directory instead aborts only a single request quickly (`RequestAborted`, e.g. slapd on
    an oversized PDU), that affects only this one: otherwise a crafted sign-in without an
    account would silence LDAP sign-in for everyone for 30 s, repeated as often as desired.

    Sequence: after an outage the directory rests for `pause_sec` — every question immediately gets
    `DirectoryNotReachable`, the pre-booked attempt is taken back milliseconds later.
    After that **exactly one** sign-in asks again (probe); all others keep getting the
    outage immediately until it is back. So even when asking again at most one attempt is pending. If
    the directory answers — even with "wrong password" — it is free again; otherwise the next
    pause begins. The transition is reported (once on the outage, once on the return), not every
    request.

    **The first window** (G9): before the first question fails, nobody knows that the
    directory is gone; sign-ins that begin within those at most `CONNECTION_TIMEOUT` seconds
    hang until the timeout — once per outage and per process (the marker lives in the
    process, so with `--workers N` N times, simultaneously). Their pre-bookings no longer block anybody,
    though: the login route books them as pending (`Store.reserve_attempt(as_pending=True)`), and
    anyone who would fail only because of them waits until they are decided (`_begin_attempt`) —
    at most `CONNECTION_TIMEOUT + 2` seconds, without `failed login` and without a lockout notice. Until
    2026-09-26 this window remained a known gap: 429 for bystanders, including the
    emergency admin, plus a ban by fail2ban.

    `clock` is replaceable so that a test can let the pause expire without waiting.
    """

    def __init__(self, pause_sec: float = FAILURE_PAUSE_SEC, clock=None):
        self.pause_sec = pause_sec
        self._clock = clock or time.monotonic
        self._lock = threading.Lock()
        self._disturbed = False
        self._pause_until = 0.0
        self._probe = False
        self._reason = ""

    def access(self) -> bool:
        """May this sign-in query the directory? Raises `DirectoryNotReachable` if not.

        Return `True`: this sign-in is the probe after a pause — it MUST end with
        `failed()`, `reached()` or `release()`, otherwise nobody asks again."""
        with self._lock:
            if not self._disturbed:
                return False
            rest = self._pause_until - self._clock()
            if rest > 0 or self._probe:
                reason = self._reason
                why = (f"next attempt in {rest:.0f} s" if rest > 0
                         else "another sign-in is asking right now")
            else:
                self._probe = True
                return True
        raise DirectoryNotReachable(
            f"LDAP directory is considered unreachable after a failure ({why}): {reason}")

    def failed(self, error, was_probe: bool = False) -> None:
        """The question failed: start the pause (again), report the transition once.

        Only the probe itself releases the probe's slot — a straggler from the first
        window that only now runs into its timeout would otherwise allow a second probe."""
        with self._lock:
            self._pause_until = self._clock() + self.pause_sec
            if was_probe:
                self._probe = False
            self._reason = str(error)[:300]
            new = not self._disturbed
            self._disturbed = True
        if new:
            seclog.warning("LDAP directory unreachable (%s) — sign-ins via the "
                           "directory get 503 immediately for %d s, afterwards a single "
                           "sign-in asks again.", for_log(str(error)), int(self.pause_sec))

    def reached(self) -> None:
        """The directory has answered (even with "wrong password"): free again."""
        if not self._disturbed:
            return
        with self._lock:
            was = self._disturbed
            self._disturbed = False
            self._probe = False
        if was:
            seclog.warning("LDAP directory reachable again — sign-ins ask it again.")

    def release(self) -> None:
        """A probe ended without an answer and without an outage (other error): release the slot."""
        with self._lock:
            self._probe = False


def _wait_points(cfg) -> int:
    """How many times a connection waits at most for a directory response: setup, with
    `ldaps://` the TLS handshake, with StartTLS its response and handshake, bind, search. Each
    point has its own limit (`connect_timeout` resp. `receive_timeout` of ldap3)."""
    return (3 + (1 if str(cfg.ldap_url or "").lower().startswith("ldaps://") else 0)
            + (2 if cfg.ldap_start_tls else 0))


class _Deadline:
    """The total limit of a sign-in (`TOTAL_DEADLINE_SEC`), distributed across the wait points.

    ldap3 knows only one limit per response, set when a connection is set up. An upper bound
    for the whole sign-in therefore arises only if each connection gets its share: the
    service account at most half of the rest (the user connection is still to come), the
    user connection the whole rest — per wait point at most `CONNECTION_TIMEOUT`. A
    fast directory notices none of this: each response takes milliseconds, the limit is
    only the ceiling. If the rest no longer suffices for one second per wait point, the directory counts
    as unreachable (`DirectoryNotReachable`, 503, no failed attempt) — before it is
    queried. Whole seconds: ldap3 packs `receive_timeout` as an integer into the socket option."""

    def __init__(self):
        self.end = time.monotonic() + TOTAL_DEADLINE_SEC

    def per_wait_point(self, wait_points: int) -> int:
        rest = self.end - time.monotonic()
        deadline = min(int(CONNECTION_TIMEOUT), int(rest // max(1, wait_points)))
        if deadline < 1:
            raise DirectoryNotReachable(
                f"LDAP: total deadline of {TOTAL_DEADLINE_SEC} s for one sign-in used up "
                f"({max(0.0, rest):.1f} s left for {wait_points} responses)")
        return deadline


def _failure_kinds() -> tuple:
    """The ldap3 errors that mean "directory unreachable/unusable" — not "wrong
    password". A wrong user password raises none of them: `bind()` then returns False.
    `LDAPBindError` comes only from the service account's `auto_bind` — its credentials are
    operator configuration, not the error of the person signing in."""
    try:
        from ldap3.core import exceptions as lx
    except ImportError:          # substituted ldap3 without an exceptions module (test dummy)
        return ()
    return (lx.LDAPCommunicationError, lx.LDAPStartTLSError, lx.LDAPBindError,
            lx.LDAPMaximumRetriesError, lx.LDAPSSLConfigurationError)


def _content_free_kinds() -> tuple:
    """The kinds of outage that the CONTENT of a request cannot trigger: the connection was not
    established (TCP, with `ldaps://` also the TLS handshake), StartTLS failed, the
    TLS configuration is unusable, or the service account did not get in. Up to that point nothing
    from the person signing in has gone over the wire."""
    try:
        from ldap3.core import exceptions as lx
    except ImportError:
        return ()
    return (lx.LDAPSocketOpenError, lx.LDAPStartTLSError, lx.LDAPBindError,
            lx.LDAPSSLConfigurationError)


class LDAPClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _server(self, deadline=None):
        """`deadline`: the limit for connection setup (seconds); without it `CONNECTION_TIMEOUT`."""
        try:
            import ldap3
        except ModuleNotFoundError as e:
            raise _missing_extra(e) from e
        # `allowed_referral_hosts=[]` is the second lock against the referral trap (see
        # `_WITHOUT_REFERRALS`): ldap3 assigns `[('*', True)]` here by default — "any host, and
        # with credentials at that". Even if someone ever creates a connection without
        # `auto_referrals=False`, ldap3 then finds no permitted referral host any more.
        return ldap3.Server(self.cfg.ldap_url, get_info=ldap3.NONE, allowed_referral_hosts=[],
                            tls=self._tls(ldap3), connect_timeout=deadline or CONNECTION_TIMEOUT)

    def _tls(self, ldap3):
        """The TLS settings for `ldaps://` and StartTLS (F-12).

        Up to 0.19.0 there were none: `ldap3.Server(...)` without `tls=` does **not** check
        the certificate (`validate=CERT_NONE` is ldap3's default). Encrypted thus meant only "not
        readable by anyone who is not sitting in between". Anyone who redirects the traffic presents their
        own certificate, obtains the service account's password and every
        user password, and passes the response on to the real directory — for both
        sides the process looks normal.

        `ldap_tls_verify=False` remains possible (a directory with a self-signed certificate
        and no CA file of its own), but announces itself when the connection is set up.
        """
        import ssl
        if not self.cfg.ldap_tls_verify:
            return ldap3.Tls(validate=ssl.CERT_NONE)
        return ldap3.Tls(validate=ssl.CERT_REQUIRED,
                         ca_certs_file=(self.cfg.ldap_tls_ca_file or None))

    def authenticate(self, username: str, password: str):
        if not username or not password:
            return None
        if input_too_long(username, password):
            return None      # not a sign-in, but the lever from `RequestAborted`
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
            from ldap3.utils.dn import escape_rdn
        except ModuleNotFoundError as e:
            # Do NOT swallow this. This spot is the path a login takes: without `ldap3`
            # `authenticate()` simply returned `None`, the app answered 401, and that looked
            # like a wrong password. The operator then searches for days in the wrong place
            # — while elsewhere (`_server()`) a `MissingExtra` was correctly raised.
            raise _missing_extra(e) from e
        except Exception:
            return None
        cfg = self.cfg
        # Outside the `try`, as before: an invalid URL or TLS setting is a configuration
        # error and must not end as "wrong password". The connections each get a server below
        # with their share of the total limit (`TOTAL_DEADLINE_SEC`, p2 V1),
        # the service account at most half of the rest.
        self._server()
        deadline, places = _Deadline(), _wait_points(cfg)
        # Which step is running, since when, and does it carry input from the person signing in? On that depends
        # whether a failure affects the directory as a whole or only this request (see
        # `RequestAborted`, `HANGER_SEC`).
        input_text, since = False, time.monotonic()
        try:
            if cfg.ldap_user_dn_template:
                user_dn = cfg.ldap_user_dn_template.format(username=escape_rdn(username))
            else:
                # Search-then-bind: first search with the service account
                # **TLS BEFORE the bind** (F-12). Before, `auto_bind=True` stood here and
                # `start_tls()` one line later: the service account's password was thus already
                # on the wire before it was encrypted. An eavesdropper did not even need
                # an attack — only patience. `AUTO_BIND_TLS_BEFORE_BIND` exists precisely for this;
                # the user connection below did it right from the start.
                per = deadline.per_wait_point(2 * places)
                svc = ldap3.Connection(
                    self._server(per), user=cfg.ldap_bind_dn or None,
                    password=cfg.ldap_bind_password or None,
                    auto_bind=(ldap3.AUTO_BIND_TLS_BEFORE_BIND if cfg.ldap_start_tls
                               else ldap3.AUTO_BIND_NO_TLS),
                    receive_timeout=per, **_WITHOUT_REFERRALS)
                flt = cfg.ldap_user_filter.format(username=escape_filter_chars(username))
                attrs = _attribute_list(cfg)
                input_text, since = True, time.monotonic()        # the filter carries the username
                svc.search(cfg.ldap_user_base, flt, attributes=attrs)
                if not svc.entries:
                    _report_reference(svc, "the user search", username)
                    svc.unbind()
                    return None
                user_dn = svc.entries[0].entry_dn
                svc.unbind()
            # Re-bind with the user DN + password → verifies the password
            per = deadline.per_wait_point(places)
            conn = ldap3.Connection(self._server(per), user=user_dn, password=password,
                                    receive_timeout=per, **_WITHOUT_REFERRALS)
            # Connection and TLS explicitly BEFORE the bind: if they fail, nothing from the person signing in
            # has been sent yet — an outage of the directory, no matter how long it took.
            input_text, since = False, time.monotonic()
            conn.open()
            if cfg.ldap_start_tls:
                conn.start_tls()
            input_text, since = True, time.monotonic()            # bind: user DN and password
            if not conn.bind():
                return None
            attrs = _attribute_list(cfg)
            conn.search(user_dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            entry = conn.entries[0] if conn.entries else None
            if entry is None:
                # Here too: a referral on the attribute search leaves email, name and groups
                # missing — with ldap_allowed_groups that is a rejection for no recognisable reason.
                _report_reference(conn, "the attribute search", username)
            info = _info_from_entry(entry, username, cfg)
            conn.unbind()
            return info
        except _failure_kinds() as e:
            # No `None`: that would mean "wrong password" and cost the user a failed attempt
            # for an outage they did not cause (F-23).
            #
            # Only this request, if all three apply: the step carried input from the
            # person signing in, the error is not one of those that arise before sending, and it
            # was QUICK. A directory that hangs responds only after the timeout — that is
            # an outage, even if it hangs only at the user bind (backend blocked).
            duration = time.monotonic() - since
            only_this = (input_text and duration < HANGER_SEC
                         and not isinstance(e, _content_free_kinds()))
            # The tag comes FIRST: route and audit truncate the reason (`for_log`, 64 characters).
            if only_this:
                raise RequestAborted(
                    f"LDAP: only this request aborted — {type(e).__name__}: {e} "
                    f"({cfg.ldap_url})") from e
            raise DirectoryNotReachable(
                f"LDAP directory {cfg.ldap_url} unusable: {type(e).__name__}: {e}") from e
        except DirectoryNotReachable:
            raise                # the total limit (`_Deadline`) — not "wrong password"
        except Exception:
            return None


    def entry_search(self, username: str) -> list:
        """Look up the directory entry for a username — without its password (G1).

        For binding existing accounts (`TinySesam.federation_bind_existing`): an account from the time before
        the identifiers otherwise binds only at the next sign-in — a dormant one never. The search
        works as at sign-in, only without the user bind:

        * **Search-then-bind** (`ldap_user_base` + `ldap_user_filter`): the same filter, with the
          service account (`ldap_bind_dn`) or anonymously.
        * **Direct bind** (`ldap_user_dn_template`): a BASE search on the constructed DN, with the
          service account if set, otherwise anonymously — the directory must allow reading.

        Return: one entry per hit in the same form as `authenticate` (`id`, `email`,
        `name`, `groups`), at most two. **The caller requires exactly one** —
        `authenticate`, by contrast, silently takes the first, which suffices for a sign-in with password
        (the password decides), but not for a binding without a password. Empty: no entry,
        or the directory answered with a referral (it is in the log).

        An outage — network, TLS, a rejected service account, a rejected search (e.g.
        missing read permissions) — raises `DirectoryNotReachable`. That is not "not in the
        directory": the binding of existing accounts then aborts instead of delivering a wrong picture."""
        if not username or len(str(username)) > LDAP_NAME_MAX:
            return []
        try:
            import ldap3
            from ldap3.core import exceptions as lx
            from ldap3.utils.conv import escape_filter_chars
            from ldap3.utils.dn import escape_rdn
        except ModuleNotFoundError as e:
            raise _missing_extra(e) from e
        cfg = self.cfg
        server = self._server()
        try:
            conn = ldap3.Connection(server, user=cfg.ldap_bind_dn or None,
                                    password=cfg.ldap_bind_password or None,
                                    receive_timeout=CONNECTION_TIMEOUT, **_WITHOUT_REFERRALS)
            # TLS BEFORE the bind — as with the service account of the sign-in (F-12).
            conn.open()
            if cfg.ldap_start_tls:
                conn.start_tls()
            if not conn.bind():
                raise DirectoryNotReachable(
                    f"LDAP {cfg.ldap_url}: service account or anonymous search rejected "
                    f"({(conn.result or {}).get('description') or '?'})")
            attrs = _attribute_list(cfg)
            if cfg.ldap_user_dn_template:
                dn = cfg.ldap_user_dn_template.format(username=escape_rdn(username))
                conn.search(dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            else:
                flt = cfg.ldap_user_filter.format(username=escape_filter_chars(username))
                conn.search(cfg.ldap_user_base, flt, attributes=attrs, size_limit=2)
            code = (conn.result or {}).get("result")
            entries = list(conn.entries)[:2]
            if not entries and code == 10:
                _report_reference(conn, "the existing-account search", username)
            elif code not in (0, 4, 32):
                # 0 hits or end, 4 more than two hits (size_limit), 32 no such DN.
                raise DirectoryNotReachable(
                    f"LDAP {cfg.ldap_url}: search rejected "
                    f"({(conn.result or {}).get('description') or code})")
            conn.unbind()
            return [_info_from_entry(e, username, cfg) for e in entries]
        except DirectoryNotReachable:
            raise
        except (lx.LDAPException, OSError) as e:
            raise DirectoryNotReachable(
                f"LDAP directory {cfg.ldap_url} unusable: {type(e).__name__}: {e}") from e


def _info_from_entry(entry, username: str, cfg) -> dict:
    """From a directory entry, what `authenticate` and `entry_search` return.
    `entry=None` (the attribute search came back empty): only the name, no identifier."""
    info: dict = {"username": username, "email": None, "name": username, "groups": [],
                  "id": None}
    if entry is not None:
        info["email"] = _first(entry, cfg.ldap_attr_email)
        info["name"] = _first(entry, cfg.ldap_attr_name) or username
        info["groups"] = _list(entry, cfg.ldap_group_attr)
        info["id"] = _stable_identifier(entry, cfg)
        if proof_attribute(cfg, "ldap"):
            info["email_verified"] = _first(entry, proof_attribute(cfg, "ldap"))
    return info


#: Attributes in which directories keep their stable identifier — tried in this order
#: if `ldap_attr_id` is empty. `entryUUID` is the standard (RFC 4530, OpenLDAP,
#: lldap), `objectGUID` the Active Directory variant. A username is NOT part of it:
#: it is the value that this identifier is meant to replace (F-11).
STABLE_IDENTIFIER_ATTRIBUTE = ("entryUUID", "objectGUID")


def _attribute_list(cfg) -> list:
    """All attributes that have to be fetched — including the stable identifier.

    It was missing here up to 0.19.0 because nobody read it. If it is not requested, the
    server does not deliver it either: the binding would then silently be without an identifier, i.e. again via the name.
    """
    names = [cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr]
    if proof_attribute(cfg, "ldap"):
        names.append(proof_attribute(cfg, "ldap"))
    names += [cfg.ldap_attr_id] if cfg.ldap_attr_id else list(STABLE_IDENTIFIER_ATTRIBUTE)
    seen, out = set(), []
    for a in names:
        if a and a.lower() not in seen:
            seen.add(a.lower())
            out.append(a)
    return out


def _stable_identifier(entry, cfg):
    """The stable identifier from the entry — as text so that it fits into the database.

    With Active Directory `objectGUID` arrives as bytes; stored raw it would, depending on the ldap3 version,
    be read one way or another. Hence a fixed representation here: hex of the RAW bytes.

    Not from `value` alone: without a schema (`get_info=NONE`) ldap3 decodes every value that
    happens to be valid UTF-8 to text — for a GUID made of bytes below 0x80, for example, a `str` with
    control characters. The form check of the sign-in rejected that as tampered (the person never got in via
    LDAP again), a printable one ended up as text instead of hex (found with ldap3
    MOCK_SYNC, G1). `objectGUID` is therefore always read raw, another attribute
    (`ldap_attr_id`) if its text carries control characters — an identifier in text form never has any.
    """
    candidates = [cfg.ldap_attr_id] if cfg.ldap_attr_id else list(STABLE_IDENTIFIER_ATTRIBUTE)
    for attr in candidates:
        value = _first(entry, attr)
        if value in (None, ""):
            continue
        if isinstance(value, str) and (attr.lower() == "objectguid" or _has_control_chars(value)):
            value = _raw(entry, attr) or value
        if isinstance(value, (bytes, bytearray)):
            return value.hex()
        return str(value)
    return None


def _has_control_chars(text: str) -> bool:
    return any(ord(z) < 0x20 or 0x7F <= ord(z) <= 0x9F for z in text)


def _raw(entry, attr):
    """The first value of an attribute as the bytes the directory sent — or None."""
    try:
        raw = entry[attr].raw_values if attr in entry else None
    except Exception:
        return None
    return raw[0] if raw and isinstance(raw[0], (bytes, bytearray)) else None


def _first(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return None
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def _list(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return []
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]
