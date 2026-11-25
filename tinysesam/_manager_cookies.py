"""The building block `cookies` of `TinySesam`: the double-submit CSRF token and the cookie names.

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import secrets
from . import security
from fastapi import HTTPException
from fastapi import Request
from starlette.responses import Response
from typing import Optional
from .manager import (
    _CSRF_FORM,
    _CSRF_SCOPE,
    _samesite,
)


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
    self._set_csrf_cookie(response, token)
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
    in_response = self._csrf_in_response(response)
    if in_response is not None and _CSRF_FORM.fullmatch(in_response):
        return in_response                       # just rotated or already set
    if in_response is not None:
        # Deleted in this response (sign-out) or set to something unusable — the token
        # from the request is then no longer valid, so a fresh one.
        token = self._csrf_new(request)
    else:
        token, new = self._csrf_of_request(request)
        if not new:
            return token
    self._set_csrf_cookie(response, token)
    return token


def _csrf_of_request(self, request) -> tuple:
    """(token, new): the valid token from the cookie, otherwise a new one — exactly one per
    request, so that `csrf_token()` and `ensure_csrf()` agree. Shared by
    `render_page`, `csrf_token`, `ensure_csrf` and the admin panel: where one would
    adopt a cookie that another replaces, two pages would get two tokens."""
    cur = request.cookies.get(self.csrf_cookie_name) if request is not None else None
    if cur and _CSRF_FORM.fullmatch(cur):
        return cur, False
    scope = getattr(request, "scope", None)
    remembered = scope.get(_CSRF_SCOPE) if isinstance(scope, dict) else None
    if remembered:
        return remembered, True
    return self._csrf_new(request), True


def _set_csrf_cookie(self, response, token: str) -> None:
    """THE place that writes the CSRF cookie — replaces a line that this response
    already carries for it instead of appending a second one. NOT httponly: the built-in
    JS calls read the cookie and send `X-CSRF-Token`."""
    self._remove_set_cookie(response, self.csrf_cookie_name)
    response.set_cookie(self.csrf_cookie_name, token, secure=self.cfg.cookie_secure,
                        samesite=_samesite(self.cfg.cookie_samesite), path=self.cfg.cookie_path)


def _delete_csrf_cookie(self, response) -> None:
    """Delete the CSRF cookie in the browser — with Secure and path as when setting it, otherwise
    the browser silently discards the deletion of a `__Host-` cookie."""
    self._remove_set_cookie(response, self.csrf_cookie_name)
    response.delete_cookie(self.csrf_cookie_name, path=self.cfg.cookie_path,
                           secure=self.cfg.cookie_secure,
                           samesite=_samesite(self.cfg.cookie_samesite))


def _csrf_in_response(self, response) -> Optional[str]:
    """The value this response already sets for the CSRF cookie: None = no line,
    "" = deleted."""
    prefix = self.csrf_cookie_name.encode("latin-1") + b"="
    value = None
    for key_name, line in getattr(response, "raw_headers", None) or []:
        if key_name.lower() == b"set-cookie" and line.startswith(prefix):
            value = line[len(prefix):].split(b";", 1)[0].strip().decode("latin-1")
    if value is None:
        return None
    return "" if value in ("", '""') else value


def _verify_csrf(self, request: Request, submitted) -> bool:
    """Does the submitted CSRF token match the cookie? Comparison in constant time."""
    if not self.cfg.csrf_enabled:
        return True
    import hmac
    cookie = request.cookies.get(self.csrf_cookie_name)
    return bool(cookie) and bool(submitted) and hmac.compare_digest(str(cookie), str(submitted))


def _csrf_dispensable(self, request: Request) -> bool:
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
    self._remember_request(request)
    return self.verify_api_key(key)[0] is not None


def require_csrf(self, request: Request, submitted):
    """For form POSTs: raises 403 if the CSRF token is missing/does not match.

    Exempt are only requests that are really signed in via API key — see
    `_csrf_dispensable`."""
    if self.cfg.csrf_enabled and not self._csrf_dispensable(request) \
            and not (self._origin_ok(request) and self._verify_csrf(request, submitted)):
        raise HTTPException(403, self.t("api.csrf"))


def _own_hosts(self, request: Request) -> set:
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


def _origin_ok(self, request: Request) -> bool:
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
        if host and host in self._own_hosts(request):
            return True
        security.seclog.warning(
            "csrf origin rejected origin=%s ip=%s — foreign origin. If the app sits behind "
            "a proxy that rewrites the host: set base_url.",
            security.for_log(origin[:200]), security.for_log(self.client_ip(request)))
        return False
    page_html = (request.headers.get("sec-fetch-site") or "").strip().lower()
    if page_html in ("same-site", "cross-site"):
        security.seclog.warning("csrf origin rejected sec-fetch-site=%s origin=%s ip=%s",
                                page_html, "null" if origin else "-",
                                security.for_log(self.client_ip(request)))
        return False
    return True


# ---------- Cookie names (H-1) ----------
def _cookie_name(self, base: str, host_only: bool = False) -> str:
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
    prefix = getattr(c, "cookie_prefix", "tinysesam_") or "tinysesam_"
    if prefix != "tinysesam_" and base.startswith("tinysesam_"):
        base = prefix + base[len("tinysesam_"):]
    if (getattr(c, "cookie_host_prefix", True) and c.cookie_secure
            and (host_only or not c.cookie_domain)
            and c.cookie_path == "/" and not base.startswith("__")):
        return "__Host-" + base
    return base


def flow_cookie_name(self, base: str) -> str:
    """Name of a flow cookie (OIDC, SAML, passkey) — with `__Host-` where possible (A-1).

    The flow cookie binds a sign-in process to the browser that started it. If
    a neighbouring subdomain can set it via `Domain=.example.com`, it plants the attacker's
    flow on the victim and lures them to the callback URL — login CSRF, although the
    session cookie itself is already prefixed."""
    return self._cookie_name(base, host_only=True)


def _set_flow_cookie(self, response, base: str, value: str, max_age: int,
                       samesite: Optional[str] = None) -> None:
    """Set a flow cookie: httponly, host-only, short-lived."""
    response.set_cookie(self.flow_cookie_name(base), value, max_age=max_age, httponly=True,
                        secure=self.cfg.cookie_secure,
                        samesite=_samesite(samesite or self.cfg.cookie_samesite),
                        path=self.cfg.cookie_path)


def _delete_flow_cookie(self, response, base: str,
                         samesite: Optional[str] = None) -> None:
    # With Secure: the browser does not accept a `__Host-` Set-Cookie without Secure, not
    # even the deleting one.
    response.delete_cookie(self.flow_cookie_name(base), path=self.cfg.cookie_path,
                           secure=self.cfg.cookie_secure, httponly=True,
                           samesite=_samesite(samesite or self.cfg.cookie_samesite))


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
    # at its creation (`_create_session`). A step-up does not rotate.
    if self._redeem_sign_in(token):
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
    new = self.store.rotate_session(s["token_hash"], self._mercy())
    if new:
        self.set_cookie(response, new, remember=bool(s["remember"]))
        self._delete_old_names(request, response)
    return new


def count_other_sessions(self, request, user, token: Optional[str] = None) -> int:
    """How many sessions of this account are running EXCEPT the current one? (B1-7)

    The response to every factor change carries the number as `other_sessions`: ASVS 5.0 7.4.3
    requires, after adding or removing a factor, the offer to end the remaining sessions. The account page
    then asks; whoever builds an own UI reads the field.

    The mandatory setup of TOTP in the middle of a chain (`password → totp → pin`) reports
    0 here, because the session is still half afterwards and a half one must not end the others
    — it reports the number as `other_sessions_after`, and the consent is redeemed at the
    completion of the chain (`_other_after_completion`, limit d).

    `token`: the plaintext token of the own session if it has changed in THIS response
    (the mandatory setup of TOTP completes the sign-in and rotates the
    token in the process). The request's cookie then names a session that no longer exists — counted
    against it, the new own session would count as "other"."""
    s = self.store.get_session(token) if token else self._session_from_request(request)
    own = s["token_hash"] if s else None
    return sum(1 for z in self.store.list_sessions(user["id"]) if z["token_hash"] != own)


def _delete_cookie(self, response, name):
    # Secure must come along: a browser does not accept a `__Host-` Set-Cookie without Secure —
    # not even the one meant to delete it.
    kw = dict(path=self.cfg.cookie_path, secure=self.cfg.cookie_secure, httponly=True,
              samesite=_samesite(self.cfg.cookie_samesite))
    if self.cfg.cookie_domain:
        kw["domain"] = self.cfg.cookie_domain
    response.delete_cookie(name, **kw)


def _old_names(self) -> list:
    """The names of session, CSRF and unlock cookie from the time before the
    `__Host-` prefix (H-1) — only those for which the prefix now actually applies. Where it
    does not apply, the old name IS the current one. The flow cookies are deliberately missing: they
    live only minutes."""
    pairs = ((self.session_cookie_name, self.cfg.session_cookie),
             (self.csrf_cookie_name, self.cfg.csrf_cookie),
             (self.resource_cookie_name, self.cfg.resource_cookie))
    return [base for name, base in pairs if name != base]


def _delete_old_names(self, request, response) -> None:
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
    old = [n for n in self._old_names() if n in request.cookies]
    if not old:
        return
    assigned = {value.split(b"=", 1)[0].strip().decode("latin-1")
               for key_name, value in getattr(response, "raw_headers", [])
               if key_name.lower() == b"set-cookie"}
    if self.session_cookie_name not in assigned:
        return
    for name in old:
        if name in assigned:
            continue
        value = request.cookies.get(name) or ""
        if value and name == self.cfg.session_cookie:
            self.store.delete_session(value)
        elif value and name == self.cfg.resource_cookie:
            self.store.delete_resource_unlocks(value)
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
    self._delete_cookie(response, self.session_cookie_name)
    release = request.cookies.get(self.resource_cookie_name)
    if release:
        self.store.delete_resource_unlocks(release)
        self._delete_cookie(response, self.resource_cookie_name)
    # The CSRF token ends with the session (0.20.1): up to 0.20.0 it survived sign-out and
    # signing in again until the browser was closed. The next page sets a fresh one;
    # `ensure_csrf()` in the same response likewise.
    if self.cfg.csrf_enabled or request.cookies.get(self.csrf_cookie_name):
        self._delete_csrf_cookie(response)
    # Here too, not only in the route class: `logout()` is public and is called from
    # own routes of the app that the class does not cover.
    self._delete_old_names(request, response)
    # T-52 (ASVS 14.3.1): the browser drops what it cached from this origin — pages of the app that a shared
    # computer could otherwise show again with the back button. Only "cache": TinySesam keeps nothing in
    # browser storage, "storage" would wipe the app's own data (and the light/dark choice), and "cookies"
    # would sign out every app under the same registrable domain. The browser honours it over HTTPS only.
    response.headers.setdefault("Clear-Site-Data", '"cache"')
