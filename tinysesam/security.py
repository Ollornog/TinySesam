"""Hardening: real client IP (trusted proxy), rate limiting, fail2ban logger.
Brute-force regulation itself lives in the manager (DB-based, configurable in the panel)."""
from __future__ import annotations
import os
import stat
import time
import logging
import logging.handlers
import ipaddress
import re
from urllib.parse import urlsplit
from collections import OrderedDict, deque

# fail2ban parses this logger. Failed-login lines contain "ip=<IP>" → the filter matches on it.
seclog = logging.getLogger("tinysesam.security")

#: Unicode format characters that flip the reading direction (bidi overrides/isolates). They do not
#: break a line, but make a terminal show something other than what is stored (A-7).
_BIDI = frozenset("؜‎‏‪‫‬‭‮"
                  "⁦⁧⁨⁩")


def _line_breaker(z: str) -> bool:
    """A character that has no business in a log line.

    Not only ASCII < 0x20 and DEL: also the C1 control characters (U+0080–U+009F, including NEL as
    a line break and CSI as a terminal command), the line and paragraph separators U+2028/U+2029 —
    `str.splitlines()` and some viewers break on them — and the bidi control characters.
    """
    o = ord(z)
    return o < 0x20 or 0x7f <= o <= 0x9f or o in (0x2028, 0x2029) or z in _BIDI


def proof_attribute(cfg, source: str) -> str:
    """The evidence attribute of a source (`ldap`/`saml`), trimmed — `""` means: none.

    The ONE read site for runtime, router and configuration check: if the check reads it trimmed
    and the runtime raw, `" "` there means "never first admin" and here "there is evidence"
    (self-service attack round, finding 2)."""
    return str(getattr(cfg, f"{source}_attr_email_verified", "") or "").strip()


def for_log(value) -> str:
    """Prepare a foreign value so that it cannot blow up a log line.

    The username comes raw from a form field and used to land unfiltered in the line that
    fail2ban reads. A `\n` in it creates an **additional line** — and whoever puts a line break at
    the start and the end pushes the real `ip=` entry onto a following line that the filter no
    longer matches, and leaves a freely invented one in between. fail2ban then counts the failed
    attempts of an IP **chosen by the attacker**, while the real one produces zero hits. With
    `maxretry = 6`, six requests suffice to lock out any address — that of the admin, a partner,
    a monitoring probe.

    So control characters are removed, and the length is capped (a 4 kB username is not a
    login but an attempt to flood the log).
    """
    text = "".join(z for z in str(value if value is not None else "") if not _line_breaker(z))
    # Without effect — `_line_breaker` has already removed every line break —, but this is the form CodeQL
    # recognises as a filter against log injection (`ReplaceLineBreaksSanitizer`: `.replace("\n", …)`).
    # Without it `py/log-injection` flags every line whose values pass through this function, and
    # every alert had to be closed by hand as a false positive (most recently #266).
    text = text.replace("\n", "")
    return (text[:64] + "…") if len(text) > 64 else text


def line_fixed(value) -> str:
    """Like `for_log`, but without the length cap — for displays that need the whole value.

    A line break becomes visible (`\\n`) instead of being silently removed: in the forensic view it
    should be noticeable THAT someone wrote a line break into a username (B5-06).
    """
    text = str(value if value is not None else "")
    return "".join(z if not _line_breaker(z) else
                   {"\n": "\\n", "\r": "\\r", "\t": "\\t"}.get(z, "?") for z in text)


def url_for_log(url) -> str:
    """A URL without query and fragment, line-safe and capped — for the audit log.

    Behind the `?` there are often secrets in protected applications: approval links
    (`?token=…`), OAuth codes, signed download parameters. In the audit log they would stay
    readable permanently, also in the panel. For the question "where did the request want to go"
    host and path suffice; a `?…` shows that there was a query.
    """
    text = str(url or "")
    parts = urlsplit(text) if "://" in text else None
    if parts is not None and parts.netloc:
        rest = "?…" if (parts.query or parts.fragment) else ""
        text = f"{parts.scheme}://{parts.netloc}{parts.path}{rest}"
    else:
        head, separator, _ = text.partition("?")
        head, separator2, _ = head.partition("#")
        text = head + ("?…" if (separator or separator2) else "")
    return line_fixed(text)[:200]


class _LinesProtection(logging.Filter):
    """Neutralizes control characters in the ARGUMENTS of every `seclog` line (B5-14).

    `for_log` at every call site is a convention — and two sites did not have it
    (the `X-Forwarded-For` warning and the OIDC address without evidence). The next new line
    forgets it again. The filter hangs on the logger itself and therefore applies to every line,
    including future ones. The format string stays untouched: it is code, not input.
    """

    def filter(self, record: logging.LogRecord) -> bool:
        args = record.args
        if isinstance(args, tuple):
            record.args = tuple(self._clean(a) for a in args)
        elif isinstance(args, dict):
            record.args = {k: self._clean(v) for k, v in args.items()}
        return True

    @staticmethod
    def _clean(a):
        if isinstance(a, (int, float)) or a is None:
            return a            # %d/%.1f need the number, and a number does not break a line
        return line_fixed(a)


seclog.addFilter(_LinesProtection())


def ip_normalized(value) -> str | None:
    """The canonical notation of an IP address, or None if it is not one (B5-15).

    Canonical means: `2001:DB8::1` and `2001:db8:0::1` are the same address and end up as
    one in the log, in the rate limit and in the lockout — otherwise every notation would count
    as its own client. A port specification (`1.2.3.4:5678`, `[2001:db8::1]:443`), as some
    proxies write it into `X-Forwarded-For`, is stripped off.
    """
    raw = str(value or "").strip()
    if not raw:
        return None
    if raw.startswith("[") and "]" in raw:
        raw = raw[1:raw.index("]")]
    elif raw.count(":") == 1:
        raw = raw.split(":", 1)[0]
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return None
    if getattr(addr, "scope_id", None) is not None:
        # The zone specification (`fe80::1%eth0`) is dropped. `ipaddress` accepts any text after
        # the `%` — even a line break —, and every zone would be its own key: via a proxy that
        # passes the client header through, an attacker rotates it per request and thereby
        # evades rate limit, IP lockout and log throttle. The zone only names the sender's
        # interface, not the client.
        addr = ipaddress.IPv6Address(addr.packed)
    return str(addr)


def ip_pseudonym(ip: str) -> str:
    """Shorten an IP to its network: IPv4 to /24, IPv6 to /48 (`audit_ip_pseudonymize`).

    This is the truncation that web analytics tools also apply for "no longer relatable to a
    person". For forensics the network remains — enough to recognize a provider or a wave,
    not enough to name a connection. No IP → value unchanged.
    """
    norm = ip_normalized(ip)
    if norm is None:
        return ip
    addr = ipaddress.ip_address(norm)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped             # ::ffff:1.2.3.4 is an IPv4 address
    network = ipaddress.ip_network(f"{addr}/{24 if addr.version == 4 else 48}", strict=False)
    return str(network)


#: Permissions with which the security log file is created — on the first line and after every
#: rotation. Before, it was created with the process umask, in practice `-rw-rw-r--`: world-readable.
#: The lines contain usernames and IP addresses; up to 0.18.x even the first-admin one-time
#: token was in there (B5-03). fail2ban reads the file as root, log shipping via the group
#: suffices — nobody else needs it. Counterpart to `Store.FILE_PERMISSIONS` (0600).
LOG_FILE_PERMISSIONS = 0o640


class _SecurityLogHandler(logging.handlers.WatchedFileHandler):
    """WatchedFileHandler that creates the file with `LOG_FILE_PERMISSIONS` instead of the umask.

    The `mode` argument of `os.open` can only **remove** permissions (the umask is still
    subtracted), never add any — setups configured narrower than 0640 therefore stay narrow.
    The detour via `opener` instead of a `chmod` afterwards avoids the window in which the file
    stands open, and also applies when logrotate removes the file and the handler creates it
    **anew** on the next record — exactly there a one-off chmod at startup would be ineffective.
    """

    def _open(self):
        def opener(path, flags):
            return os.open(path, flags, LOG_FILE_PERMISSIONS)
        return open(self.baseFilename, self.mode, encoding=self.encoding,
                    errors=self.errors, opener=opener)


def attach_security_log(path: str) -> bool:
    """Also write the security logger to a file — what the fail2ban jail reads
    (`deploy/fail2ban/`). Without this handler the shipped jail points to a file that never
    comes into existence: it would be silently ineffective.

    Idempotent (the same path is not attached twice — several TinySesam instances in the same
    process are allowed) and not startup-preventing: an unwritable path is a reason to warn,
    but none to shut down sign-in. The format carries the timestamp up front, which fail2ban
    needs to date the hits.

    The file is newly created with `LOG_FILE_PERMISSIONS` (0640), no longer with the umask; an
    already existing, world-readable file is reported but not rewritten.
    """
    path = str(path)
    for h in seclog.handlers:
        if getattr(h, "_tinysesam_path", None) == path:
            return True
    already_da = os.path.exists(path)
    try:
        # WatchedFileHandler, not FileHandler: logrotate renames the file and creates a new one
        # — a FileHandler keeps the old inode open and from then on keeps writing into the
        # renamed file. The new one would stay empty, and the fail2ban jail would read nothing
        # from the FIRST rotation on: no error, no message, just a guard that no longer
        # guards. The watched handler checks inode and device before every line and reopens.
        # (No effect on Windows — an open file cannot be renamed there anyway, and
        # `copytruncate` is the way.)
        h = _SecurityLogHandler(path, encoding="utf-8")
    except OSError as e:
        seclog.warning("security_log %s not writable (%s) — fail2ban gets nothing to read.",
                       path, e)
        return False
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    # Own marker on the handler, so that the same path is not attached twice. `setattr`
    # instead of direct assignment: the attribute is ours, not the class's — a type checker
    # would otherwise rightly report an error here.
    setattr(h, "_tinysesam_path", path)
    seclog.addHandler(h)
    # Without its own level the logger inherits the root's; if that is ERROR, exactly the
    # WARNING lines with the failed attempts are missing.
    # INFO, not WARNING (0.24.9): `repeated login` and `login ok` are INFO lines and belong in the same file.
    if seclog.level == logging.NOTSET or seclog.level > logging.INFO:
        seclog.setLevel(logging.INFO)
    # Only here, after the level: a warning that the logger discards is none. An EXISTING file
    # is not rewritten — a deliberate release to a group (log shipping, `adm`) is a decision of
    # the operator, not a hole. It does not stay silent anyway: the lines contain usernames and
    # IP addresses.
    if already_da:
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            mode = 0
        if mode & 0o007:
            seclog.warning(
                "security_log %s is world-readable (%o). It contains usernames and "
                "IP addresses. Tighten it: chmod 640 %s", path, mode, path)
    return True


# Hardening defaults — overridable in the admin panel (store.setting). Only these keys are configurable.
SECURITY_DEFAULTS = {
    # The order is that of the panel: what is configured together is listed together.
    "max_login_attempts": 5,        # failed attempts per account AND IP (pair) in the window → lockout
    "lockout_window_sec": 900,      # observation/lockout window (15 min)
    "ip_attempt_factor": 3,         # IP lockout threshold = max_login_attempts * factor (several users behind NAT)
    "account_attempt_factor": 3,    # account threshold across all IPs = max_login_attempts * factor (distributed guessing)
    "account_max_consecutive_failures": 100,  # consecutive failed attempts per account, without window (B2-6, NIST)
    "pin_max_attempts": 5,          # own, method-scoped failed-attempt counter for PIN (short keyspace)
    "rate_limit_max": 30,           # max requests per IP …
    "rate_limit_window_sec": 60,    # … per window on auth endpoints
    "password_min_length": 8,       # minimum length when the password is part of a chain with a 2nd factor
    "password_min_length_single_factor": 15,  # … when it can sign in on its own (B2-4, NIST 800-63B)
    "password_change_max_attempts": 5,  # own counter for the old-password prompt on the account page
    "reauth_max_attempts": 5,       # own counter for the step-up confirmation (/auth/reauth)
    "resource_max_attempts": 5,     # own counter for the area PIN (/auth/resource/…, without account)
    "mail_per_address_max": 3,      # mails per target address in the window (sign-in link, reset, notice) — R4-04
    "mail_per_address_window_sec": 900,  # … window for it; the IP throttle alone does not protect a third party's mailbox
    "totp_setup_max_attempts": 5,   # own counter for the confirmation of the TOTP setup
    # The same wrong password, from the same IP, to the same account counts only ONCE (0.24.9, PO: "typing the same password
    # 10 times is hardly a hacking attempt"): a phone with an old password should lock neither the account nor the
    # home IP. The last N fingerprints per (account, IP) are remembered; 0 switches this off.
    "password_repeat_memory": 5,
    "password_repeat_window_sec": 86400,  # … how long a remembered fingerprint counts as "already tried"
}

#: Permitted range per hardening threshold, both bounds inclusive (R6-4, B2-9).
#:
#: Without bounds a typo in the panel would shut the instance down silently and permanently: with
#: `rate_limit_max=0`, `_rate_ok` rejects every sign-in — including that of the administrator
#: who would have to turn the value back. The value is in the database and survives every
#: restart. Likewise `max_login_attempts=0` (every account counts as locked at once) or a
#: `lockout_window_sec` of years. The lower bounds keep operation alive, the upper bounds the
#: protection: `password_min_length` below 8 is not tuning but switching off the password rule.
#:
#: The bounds forbid shutting down, not tightening: a single attempt
#: (`count >= 1` locks after the first failure) or a lockout of weeks is a hard but
#: legitimate choice — only `0` or years turn it into an outage. `rate_limit_max` stays at
#: 3, because a sign-in with a second factor needs several requests; below that nobody
#: gets through any more.
SECURITY_LIMITS = {
    "max_login_attempts": (1, 1000),
    "lockout_window_sec": (60, 30 * 86400),
    "ip_attempt_factor": (1, 100),
    "rate_limit_max": (3, 100000),
    "rate_limit_window_sec": (1, 86400),
    "password_min_length": (8, 128),
    "password_min_length_single_factor": (8, 128),
    # Lower bound 10: a series lockout is hard (it does not expire), a few typos must not
    # trigger it — the window thresholds exist for that. Upper bound 100000 practically means "off".
    "account_max_consecutive_failures": (10, 100000),
    "pin_max_attempts": (1, 100),
    "password_change_max_attempts": (1, 100),
    "reauth_max_attempts": (1, 100),
    "resource_max_attempts": (1, 100),
    "account_attempt_factor": (1, 100),
    "totp_setup_max_attempts": (1, 100),
    "password_repeat_memory": (0, 50),
    "password_repeat_window_sec": (60, 7 * 86400),
    "mail_per_address_max": (1, 1000),
    "mail_per_address_window_sec": (60, 86400),
}


def check_hardening(key: str, value) -> int:
    """Check a hardening value and return it as int — or `ValueError` with readable text.

    One place for panel, `set_security()` and reading from the database: two versions of the
    bounds would otherwise drift apart, and the weaker one would decide."""
    if key not in SECURITY_DEFAULTS:
        raise ValueError(f"{key!r} is not a hardening threshold. Known ones are: "
                         f"{', '.join(sorted(SECURITY_DEFAULTS))}")
    # bool is an int in Python — `True` as "1 attempt" would be a silent typo.
    if isinstance(value, bool):
        raise ValueError(f"{key}: {value!r} is not a number")
    try:
        number = int(value)
    except (TypeError, ValueError, OverflowError):
        # OverflowError: `int(float("inf"))` — Starlette's JSON accepts the literal `Infinity`,
        # and without this case it became a 500 instead of a 400 (A4).
        raise ValueError(f"{key}: {value!r} is not an integer") from None
    if isinstance(value, float) and value != number:
        raise ValueError(f"{key}: {value!r} is not an integer")
    below, above = SECURITY_LIMITS[key]
    if not below <= number <= above:
        raise ValueError(f"{key}={number} is outside {below}…{above}")
    return number


def clamp_hardening(key: str, value) -> int:
    """Pull a legacy value from the database that `check_hardening` rejects to the nearest bound.

    Not reset to the default: an existing value beyond the bound is almost always on the
    STRICT side (2 attempts, one week lockout), and the default would then be the weaker
    setting — an upgrade must not silently loosen the hardening (A1). The bound is the
    strictest value that does not shut operation down, and the panel accepts it. Only what is
    not a number at all falls back to the default."""
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError, OverflowError):
        return SECURITY_DEFAULTS[key]
    below, above = SECURITY_LIMITS[key]
    return min(max(number, below), above)


def read_hardening(store, key: str) -> int:
    """Read a hardening threshold from the database as it applies: the value from the panel or
    the default, always within `SECURITY_LIMITS`.

    The ONE read path for `TinySesam._sec()` and the CLI (`tinysesam passwd`). The CLI read
    `password_min_length` raw until T-13: a legacy value from a version without bounds (4, 0)
    counted as 8 on the web, offline still as 4 — and `passwd` set a password that every web
    setting site rejects. Two read paths drift apart, and the weaker one decides.

    A value outside the bounds that is already in the database (from a version without
    bounds, or written directly) is pulled to the nearest bound (`clamp_hardening`):
    continuing to apply it would mean leaving a shut-down instance shut down (R6-4); setting it
    to the default would silently loosen every stricter existing setting (A1)."""
    v = store.get_setting(key)
    if v is None:
        return SECURITY_DEFAULTS[key]
    try:
        return check_hardening(key, v)
    except ValueError as e:
        value = clamp_hardening(key, v)
        if report_once("sec:" + key):
            seclog.warning(
                "Hardening value in the database invalid (%s) — %s applies. The value can "
                "be confirmed or changed in the admin panel.", e, value)
        return value

# Methods from `login_attempt` that are NOT a sign-in attempt and therefore must not count into
# the login lockout (`_is_locked`) — and next to it the latch that throttles each of them
# INSTEAD.
#
# Why at all: the old-password prompt of the account page, the step-up confirmation and the
# area PIN record their failed attempts in the same table as the login (R4-10 — otherwise they
# would be silent oracles). But `_is_locked` counted method-blind, and so five typos on one's
# OWN account page locked sign-in for 15 minutes — the user could not work them off by
# anything, because a success only clears the failed attempts of the same method.
# Behind NAT, three colleagues with five typos each sufficed to lock the login of a completely
# uninvolved fourth (`ip_attempt_factor`); for the area PIN, foreign visitors who have no
# account at all sufficed.
#
# The mapping is deliberate and not a convenience: whoever enters a method here takes it out of
# the login lockout — without its own bucket it would thereby be guessable without limit. That
# is why the replacement stands next to it, `NOT_LOGIN_METHODS` is derived from it (a method
# without a latch cannot even be entered), and a test holds the table against the methods with
# which the router really calls `_record_login()`.
#
# Deliberately an **exception list**, not a positive list of the login methods: a new
# sign-in method thereby counts on its own. A forgotten line costs convenience here
# (a lockout counts stricter than necessary), a forgotten line in a positive list would have
# cost a hole in the lockout.
OWN_LOCK = {
    "password_change": "_is_password_change_locked",
    "reauth": "_is_reauth_locked",
    "resource": "_is_resource_locked",
    "totp_setup": "_is_totp_setup_locked",
}

NOT_LOGIN_METHODS = tuple(OWN_LOCK)

#: The event word of the line in the security log. **Only `failed login` hits the shipped
#: fail2ban failregex** (`deploy/fail2ban/tinysesam-filter.conf`) — and that is the point: a
#: miss from `NOT_LOGIN_METHODS` comes from someone who is already signed in (account page,
#: step-up) or who needs no account at all (area PIN). With the same word, the shipped jail
#: (`maxretry = 6`) banned a legitimate user at firewall level after a few typos — and for the
#: whole instance, not for the route. Aggravating: from the app lockout on, every further click
#: produces a further line. So it is logged unchanged, only under its own name; whoever also
#: wants to ban these lines takes the second, milder jail from `deploy/fail2ban/`.
LOG_SIGN_IN = "failed login"
LOG_CHECK = "failed verification"
#: A wrong password that the same IP has already sent to the same account (`password_repeat_memory`). Deliberately
#: its own word and INFO: the shipped failregex requires `WARNING failed login`, so this line does not count.
LOG_REPEATED = "repeated login"
#: A COMPLETE sign-in (all factors) — for evaluation and filters that want to reset a lockout ladder.
LOG_SUCCESS = "login ok"


def log_event(method) -> str:
    """Which event word belongs in the security log line of this method?

    `failed login` only for real sign-in attempts — everything from `NOT_LOGIN_METHODS` gets
    `failed verification` and thereby bypasses the shipped fail2ban jail."""
    return LOG_CHECK if method in NOT_LOGIN_METHODS else LOG_SIGN_IN


def safe_next(next_: str, default: str = "/", allowed_hosts=None) -> str:
    """Open-redirect protection for ?next= targets.

    Allows only *relative* paths on the same host (starting with exactly one '/', no
    protocol-relative '//', no scheme, no backslash). Absolute URLs are only allowed
    if their host is in allowed_hosts (for the forward-auth/SSO case). Everything else → default.
    """
    if not next_:
        return default
    n = next_.strip()
    # relative path: exactly one leading slash, no scheme/backslash/protocol-relative
    if n.startswith("/") and not n.startswith("//") and "\\" not in n and "://" not in n:
        return n
    if allowed_hosts:
        try:
            parts = urlsplit(n)
        except Exception:
            return default
        host = parts.hostname or ""
        if parts.scheme in ("http", "https") and host and host in allowed_hosts:
            return n
    return default


def own_host(host: str, allowed_hosts=None) -> bool:
    """May this host go into an address that leaves the house (mail link, redirect URI)?

    The host from `request.base_url` is the raw `Host` header, i.e. an **input of the
    client** — no proxy and no ASGI server checks it. Whoever triggers a reset mail for a foreign
    mailbox and sets `Host: attacker.example` while doing so got exactly this host into the link
    that the victim receives by mail until 0.18.0 (R4-01/R8-4). Therefore a derived host only
    counts if it is provably our own:

    * it is in `trusted_redirect_hosts` — the same circle that `?next=` may already trust, or
    * it is a loopback address. A link to `localhost` is of no use to an attacker: it ends up
      at the recipient itself. This keeps the local setup usable without `base_url`.

    Everything else is a foreign name. The caller then aborts — a mail that does not go out
    at all is better than one with a link to the attacker's server.
    """
    h = (host or "").strip().strip("[]").lower()
    if not h:
        return False
    if allowed_hosts and h in {str(a).strip().lower() for a in allowed_hosts if a}:
        return True
    if h == "localhost":
        return True
    try:
        return ipaddress.ip_address(h).is_loopback
    except ValueError:
        return False


#: Which path part from a derived base may go out with it. Narrowly drawn and
#: fail-closed: here stands a mount prefix (`/sso`, `/auth/v2`), nothing else. Anything with a
#: double slash, percent sign or whitespace falls through, and `.`/`..` as a segment
#: likewise (`/../etc` is normalized nowhere and otherwise stood exactly so in the mail) — then
#: there is no base, instead of a half-guessed one.
_PATH_OK = re.compile(r"(?:/(?!\.{1,2}(?:/|$))[A-Za-z0-9._~-]+)+")


def normalize_base(candidate: str) -> str:
    """Check a base URL for its **form** and assemble it canonically — or "" (fail closed).

    Does **not** answer the question whether the host is our own; `secure_base()` does that.
    Separated since 0.18.0, because both branches of `TinySesam.public_base()` need the same form:
    until then only the **derived** branch went through here, while a configured `base_url`
    saw merely `strip().rstrip("/")` and the configuration check accepted it with a coarse
    scheme-and-host pattern. That let through what fails here: a user part in the host
    (`https://wer:was@auth.example` — it would stand in every reset link and every redirect URI),
    a fragment or a query, an invalid port, a path with `..` or `//`. One rule,
    two callers — not two rule sets, one of which is weaker.

    The **path part comes along**: `request.base_url` carries the `root_path` of the ASGI server
    (uvicorn `--root-path`, a `Mount`), and until 0.18.x this function threw it away. Whoever had
    mounted the app under a subpath got mail links without the prefix — thus
    404 instead of the reset form. The `root_path` is server configuration, not client input
    (neither uvicorn nor Starlette derives it from a header), but it is checked against
    `_PATH_OK` anyway: a base that we cannot assemble cleanly does not exist.
    """
    raw = str(candidate or "").strip()
    if not raw:
        return ""
    try:
        parts = urlsplit(raw)
    except Exception:
        return ""
    if parts.scheme not in ("http", "https") or not parts.netloc:
        return ""
    # Query and fragment do not belong in a base: what is appended at the end (token, path)
    # would otherwise stand BEHIND the `#` and never reach the server — the link would look valid
    # and lead nowhere.
    if parts.query or parts.fragment:
        return ""
    host = parts.hostname or ""
    if not host:
        return ""
    # Assembled anew instead of taking over `netloc`: a user part in the host
    # (`https://trusted.example@…`) would otherwise be part of every outgoing link. Only
    # `hostname` is checked anyway, so only that may go out.
    try:
        port = parts.port
    except ValueError:
        return ""
    if ":" in host:
        host = f"[{host}]"
    path = (parts.path or "").rstrip("/")
    if path and not _PATH_OK.fullmatch(path):
        return ""
    return f"{parts.scheme}://{host}" + (f":{port}" if port else "") + path


def secure_base(candidate: str, allowed_hosts=None) -> str:
    """Check a **derived** base URL: form (`normalize_base`) **and** own host.

    Empty means: there is no trustworthy public address. Do not guess — abort.
    The difference to `normalize_base()` is the origin: what comes from the `Host` header
    must additionally prove that it is a name of our own (R4-01/CWE-644).
    """
    raw = str(candidate or "").strip()
    if not raw:
        return ""
    try:
        host = urlsplit(raw).hostname or ""
    except Exception:
        return ""
    if not own_host(host, allowed_hosts):
        return ""
    return normalize_base(raw)


def invalid_networks(trusted_nets) -> list:
    """The entries of a `trusted_proxies` list that are not an IP network (B3-3)."""
    bad = []
    for n in trusted_nets or []:
        try:
            ipaddress.ip_network(str(n).strip(), strict=False)
        except ValueError:
            bad.append(n)
    return bad


def is_trusted(ip: str, trusted_nets) -> bool:
    # Check per entry, not the whole list in one `try` (B3-3): a single invalid
    # entry (a hostname, a typo) used to raise in the middle of `any()` and thereby invalidate
    # ALL the others — the proxy counted as foreign, every user appeared under its IP. The
    # warning about it then advised entering the proxy network, which was there all along.
    # `config_check` rejects such a list at setup; here is the floor for a list
    # that was changed afterwards.
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for n in trusted_nets or []:
        try:
            if addr in ipaddress.ip_network(str(n).strip(), strict=False):
                return True
        except (ValueError, TypeError):
            continue
    return False


# Peers that have already been complained about — a misconfiguration reports once, not per
# request. A log storm is filtered away and helps nobody.
_REPORTED_PEERS: set = set()

#: Keys for which a notice line already stands in the security log (`report_once`).
#: Capped: the key comes from the request, and whoever probes the `Host` header
#: should fill neither the file nor the memory.
#:
#: The cap applies **per time window**, not for the lifetime of the process (C-4, 0.18.0):
#: before, 512 invented `Host` values sufficed to disable the site until restart —
#: afterwards the notice about the **real** operational error also stayed away. An attacker
#: could thus not only make noise but deliberately switch off a warning. Now a new window
#: begins after `_REPORTED_WINDOW_SEC`, and reaching the cap says once, loudly,
#: that silence starts from here — an invisible suppression would be the same hole.
_REPORTED_MAX = 512
_REPORTED_WINDOW_SEC = 3600
_REPORTED: set = set()

#: Start of the current window and whether the cap has already been reported in it. Deliberately a dict
#: and not two module variables: those would have to be declared `global` in every writing function,
#: and a variable set via `global` is read by CodeQL as unused (py/unused-global-variable)
#: — a false alarm that would otherwise have to be rejected anew in every version.
_REPORTED_WINDOW = {"beginn": 0.0, "ueberlauf": False}


def report_once(key_name: str, now: float | None = None) -> bool:
    """True exactly on the first call with this key, False afterwards — against log storms.

    The same idea as `_REPORTED_PEERS` in `client_ip()`, only general: a notice about a
    **misconfiguration** says everything the first time; if it repeats per request, it fills
    the file the fail2ban jail points to and that logrotate keeps for weeks. A
    page view with twenty sub-resources thus wrote twenty identical lines, a crawler
    arbitrarily many — the message does not become more correct by that, only louder.

    The key belongs to the cause, not to the single request (so the host, not the
    full URL) — otherwise every new path lifts the lock again.

    The state is process-wide: a test that wants to see the line empties `_REPORTED` beforehand
    (tests must stay repeatable) — `once_report_reset()` exists for that.

    `now` exists only for tests: this way the window change can be checked without waiting
    an hour (a test that sleeps is not a test).
    """
    t = time.time() if now is None else float(now)
    if t - _REPORTED_WINDOW["beginn"] >= _REPORTED_WINDOW_SEC:
        _REPORTED.clear()
        _REPORTED_WINDOW["beginn"] = t
        _REPORTED_WINDOW["ueberlauf"] = False
    if key_name in _REPORTED:
        return False
    if len(_REPORTED) >= _REPORTED_MAX:
        if not _REPORTED_WINDOW["ueberlauf"]:
            _REPORTED_WINDOW["ueberlauf"] = True
            # Directly and not via `report_once()` — otherwise the message about the
            # cap would run into the same cap. Exactly one line per window.
            seclog.warning(
                "Notice cap reached: %d distinct keys in this window (%d s). "
                "Further notices of this kind are suppressed until the window changes. Whoever "
                "probes the Host header produces exactly this picture — if base_url is set, "
                "the Host header has no effect anyway.",
                _REPORTED_MAX, _REPORTED_WINDOW_SEC)
        return False
    _REPORTED.add(key_name)
    return True


def once_report_reset() -> None:
    """Empty the notice store (tests, and an operation that deliberately wants to listen anew)."""
    _REPORTED.clear()
    _REPORTED_WINDOW["beginn"] = 0.0
    _REPORTED_WINDOW["ueberlauf"] = False


def client_ip(request, trusted_nets) -> str:
    """Real client IP. X-Forwarded-For is only evaluated if the direct peer is trusted
    (rightmost NON-trusted address) — otherwise XFF is forgeable.

    **The most common misoperation is silent**: in a container the proxy is another container,
    hence not `127.0.0.1`. The default then does not fit, XFF is discarded, and EVERY user
    appears under the proxy IP — rate limit and IP lockout apply collectively from then on, and
    fail2ban in the worst case bans the proxy, i.e. everyone. None of this looks like an error.
    That is why this function speaks up once per peer.
    """
    peer = request.client.host if request.client else "?"
    xff = request.headers.get("x-forwarded-for")
    if xff and is_trusted(peer, trusted_nets):
        for ip in reversed([p.strip() for p in xff.split(",") if p.strip()]):
            if not is_trusted(ip, trusted_nets):
                # Only a REAL address becomes the client IP (B5-15). Before, the first
                # non-trusted entry went through unchecked — also `evil`, a line break
                # or 4 kB of text, and that as a key for rate limit, lockout and audit log.
                # A proxy that merely passes the client header through instead of appending makes
                # exactly this entry client-controllable. Then rather the peer IP (collective, but real).
                norm = ip_normalized(ip)
                if norm is not None:
                    return norm
                if report_once("xff-ungueltig:" + peer):
                    seclog.warning(
                        "X-Forwarded-For from %s names no valid address (%s) — the peer IP "
                        "is kept. Does the proxy only pass the client's header through instead of "
                        "appending?", peer, for_log(ip))
                return peer
    if xff and peer not in _REPORTED_PEERS:
        _REPORTED_PEERS.add(peer)
        if not is_trusted(peer, trusted_nets):
            seclog.warning(
                "X-Forwarded-For from %s is ignored: the peer is not in trusted_proxies "
                "(%s). All users now appear under this one IP — rate limit and "
                "IP lockout act collectively. In a container the proxy is NOT 127.0.0.1: "
                "enter the proxy's network, e.g. trusted_proxies=['172.28.0.0/16'].",
                peer, list(trusted_nets or []))
        else:
            # Peer trusted, but NO non-trusted address found in XFF — that
            # is the case `trusted_proxies=['0.0.0.0/0']`: if every address counts as a proxy,
            # none remains as client, and XFF is ineffective instead of generous.
            seclog.warning(
                "X-Forwarded-For (%s) contains no address outside trusted_proxies (%s) "
                "— the peer IP %s is kept. An entry like 0.0.0.0/0 devalues XFF instead of "
                "trusting it: enter only the network of your own proxy.",
                for_log(xff), list(trusted_nets or []), peer)
    return peer


class RateLimiter:
    """In-memory token bucket per key (IP), per process. For single-worker deployments;
    with several workers the DB-based regulation (lockout) applies in addition. For a
    cross-process limit use RedisRateLimiter (config.redis_url).

    **Capped** (R7-5): until T-13 the dictionary grew with every new address and never
    shrank — an empty bucket stayed behind as a key. Whoever changes the source address (IPv6
    supplies a /64 per connection) thereby filled the process's memory. Now
    `max_keys` applies, and beyond it the longest-dormant key goes first — every request, even
    a rejected one, moves its key to the front. Whoever is currently being throttled thus
    keeps asking and stays; displaced is whoever's last attempt lies furthest back.
    """
    def __init__(self, max_keys: int = 100_000):
        self._hits: OrderedDict = OrderedDict()
        self.max_keys = max(1, int(max_keys))

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        now = time.time()
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
        self._hits.move_to_end(key)
        while dq and dq[0] < now - window_sec:
            dq.popleft()
        if len(dq) >= max_requests:
            return False
        dq.append(now)
        while len(self._hits) > self.max_keys:
            self._hits.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._hits)


class RedisRateLimiter:
    """Cross-process rate limit via Redis (fixed-window counter) — for multi-worker/
    multi-instance. Same allow() interface.

    **On a Redis outage it does not open up, but keeps counting per process** (B6-1).
    Until T-13 it said "fail-open (allow)" here, with the reasoning that the DB lockout keeps
    applying. But that exists only on the sign-in routes; magic-link request, forgotten
    password, registration and the start of federation hang on this limit alone — without
    Redis they were open, and the first two send mails to arbitrary addresses. Now
    a built-in `RateLimiter` takes over: per process instead of across all, so up to N times as
    generous — but a limit. Nobody is locked out by the outage.

    **And it is noticed** (B6-2): the constructor asks Redis once (`ping`) instead of discovering
    the outage only at the first visitor. The **change** is reported — once on
    the outage, once on the return —, not every request: before, every request wrote a
    warning line into exactly the file that fail2ban reads. After an error Redis rests
    `pause_sec`, after which it is tried again; this way not every request hangs in the timeout
    of a dead server. Plus short socket timeouts: a Redis that does not answer (instead of
    refusing) would otherwise hold every request indefinitely.
    """
    def __init__(self, url: str, prefix: str = "tsrl", pause_sec: float = 30.0, timeout_sec: float = 1.0):
        import redis   # extra [redis]
        self.client = redis.from_url(url, socket_connect_timeout=timeout_sec, socket_timeout=timeout_sec)
        self.prefix = prefix
        self._set_up(pause_sec)
        try:
            self.client.ping()
        except Exception as e:
            self._failed(e)

    def _set_up(self, pause_sec: float = 30.0) -> None:
        """Create the fallback state (also for tests that bypass `__init__`)."""
        self.replacement = RateLimiter()
        self.pause_sec = pause_sec
        self._pause_until = 0.0
        self._disturbed = False

    def _failed(self, error) -> None:
        self._pause_until = time.time() + self.pause_sec
        if not self._disturbed:
            self._disturbed = True
            seclog.warning("Redis rate limit unreachable (%s) — every process now counts "
                           "on its own until Redis answers again.", error)

    def allow(self, key: str, max_requests: int, window_sec: int) -> bool:
        if not hasattr(self, "replacement"):
            self._set_up()
        if self._disturbed and time.time() < self._pause_until:
            return self.replacement.allow(key, max_requests, window_sec)
        try:
            bucket = int(time.time() // max(1, window_sec))
            rk = f"{self.prefix}:{key}:{window_sec}:{bucket}"
            pipe = self.client.pipeline()
            pipe.incr(rk)
            pipe.expire(rk, window_sec)
            count = pipe.execute()[0]
        except Exception as e:
            self._failed(e)
            return self.replacement.allow(key, max_requests, window_sec)
        if self._disturbed:
            self._disturbed = False
            seclog.warning("Redis rate limit reachable again — counting across all processes again.")
        return int(count) <= max_requests
