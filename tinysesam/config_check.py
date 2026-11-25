"""All contradictions of a configuration at once — at construction, not at the first login.

Up to 0.18.0 the constructor checked half a dozen combinations and raised at the first finding.
The rest only showed up in operation, and exactly where you look for it least: an app without
a single active login method started without complaint; a `login_chain` that names a disabled
method is unsatisfiable — the user ends up in a loop; OIDC without `issuer`
only fails at the click on "Sign in".

Two ranks, and the line between them is not severity but **repairability**:

* **Error** — the situation is unsatisfiable by itself and will not become satisfiable. Nobody
  gets in, or a protection is silently off. This aborts construction.
* **Warning** — something is missing that may still arrive later. A mailer is typically
  set after the constructor (`auth.set_mailer(...)`); turning that into an error would mean
  forbidding a perfectly common order. It is logged anyway, because "silent" is exactly
  the problem solved here.

All findings come out **together**. Whoever has three things wrong should read them once
and not start three times.
"""
from __future__ import annotations

import os
import re

from . import _chain
from . import _role_levels
from . import security
from .store import role_invalid

#: Method → which config field switches it on. The same list serves the chain check.
PROCEDURE = {
    "password": "password_enabled",
    "pin": "pin_enabled",
    "passkey": "passkey_enabled",
    "oidc": "oidc_enabled",
    "saml": "saml_enabled",
    "ldap": "ldap_enabled",
    "magic": "magiclink_enabled",
    "apikey": "apikey_enabled",
}

#: What may appear in a `login_chain`: the factors a session can really get
#: (`TinySesam._IDENTIFYING`) plus `totp`. Deliberately NOT `PROCEDURE` — that also holds
#: `ldap` (writes the factor `password`) and `apikey` (never becomes a factor).
CHAIN_STEPS = frozenset({"password", "pin", "oidc", "passkey", "magic", "saml", "totp"})

#: Methods with which a human can SIGN IN. `apikey` does not count: a key is issued
#: by an account, which has to exist first.
SIGNING_IN = ("password", "pin", "passkey", "oidc", "saml", "ldap", "magic")

#: Method → fields without which it cannot work.
REQUIRED_FIELDS = {
    "oidc": ("oidc_issuer", "oidc_client_id"),
    "saml": ("saml_idp_sso_url", "saml_idp_x509cert"),
    "ldap": ("ldap_url",),
}

#: What needs a mailer. Not an error — `set_mailer` often comes later.
REQUIRES_MAILER = {
    "magiclink_enabled": "Magic-link sign-in",
    "password_reset_enabled": "\"Forgot password\"",
    "signup_verify_email": "Email confirmation at registration",
}

#: What hands an **absolute** address to third parties — the link in a mail to a mailbox,
#: the redirect URI at the IdP, the entity ID in SAML metadata. Without `base_url` only
#: the `Host` header would remain for it, and the requester sets that (R4-01). These switches make `base_url`
#: **mandatory**: without it construction fails, not only the first sign-in attempt.
REQUIRES_BASE_URL = {
    "magiclink_enabled": "Magic link and invitation (link in the email)",
    "password_reset_enabled": "\"Forgot password\" (reset link in the email)",
    "signup_verify_email": "Email confirmation (confirmation link in the email)",
    "oidc_enabled": "OIDC (redirect URI to the IdP)",
    "saml_enabled": "SAML (entity ID and ACS URL)",
}

#: The same thought, but only a warning: the forward-auth redirect sends the **same**
#: browser to its own login page. Without a checked base it stays relative (`/auth/login?…`)
#: and the browser resolves it against the requested host — that works as long as app and
#: TinySesam live under one name. A foreign name does not get into the redirect this way, nothing
#: goes out to third parties, and therefore this is no reason to refuse to start.
BASE_URL_RECOMMENDED = {
    "forward_auth_enabled": "Forward auth (redirect of the proxy to the login page)",
}


def _is_ip(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _is_loopback(value: str) -> bool:
    import ipaddress
    try:
        return ipaddress.ip_address(value).is_loopback
    except ValueError:
        return False


def _urlsplit_host(url: str) -> str:
    """The host of an address, without port and without the brackets of an IPv6 literal."""
    from urllib.parse import urlsplit
    return (urlsplit(url).hostname or "").lower()


def _topbar_link_findings(config, f: str, links, hosts: set, roles_known: set, error: list, warnings: list,
                          frame: bool = False) -> None:
    """The checks of one top bar link field (`topbar_links`, `topbar_menu_links`, `forward_apps[host]['links']` —
    named by `f` in the findings): shape, visibility, target. `frame`: the links of an app frame (T-91), whose
    targets lie on exactly the application's host (`hosts` = that one host)."""
    links = links or []
    if not isinstance(links, (list, tuple)):
        links = [links]
    for link in links:
        if (not isinstance(link, (list, tuple)) or len(link) not in (2, 3) or not isinstance(link[0], str)
                or not 1 <= len(link[0].strip()) <= 60 or not isinstance(link[1], str)
                or any(z < " " or z == "\x7f" for z in link[0])):
            error.append(_t(
                config,
                "{f}: {v!r} — each entry is a (title, target) pair with a title of 1–60 characters",
                f=f, v=link))
            continue
        # Visibility (T-76): a third element {"admin": True} or {"role": "…"} — exactly one of them. Anything else
        # would hide the link from everyone (topbar.link_visible is fail-closed) without saying why.
        if len(link) == 3:
            rule = link[2]
            admin_rule = isinstance(rule, dict) and set(rule) == {"admin"} and rule["admin"] is True
            role_rule = (isinstance(rule, dict) and set(rule) == {"role"} and isinstance(rule["role"], str)
                         and bool(rule["role"].strip()))
            if not (admin_rule or role_rule):
                error.append(_t(
                    config,
                    "{f}: {v!r} — the visibility is {{\"admin\": True}} or {{\"role\": \"name\"}}",
                    f=f, v=link))
                continue
            if role_rule and rule["role"] not in roles_known:
                warnings.append(_t(
                    config,
                    "{f}: the link {title!r} is shown only to the role {role!r}, which is not in "
                    "available_roles — a typo hides it from everyone. List the role in available_roles.",
                    f=f, title=link[0], role=rule["role"]))
        href = link[1]
        if not _frame_target_ok(href, hosts):
            if frame:
                error.append(_t(
                    config,
                    "{f}: {h!r} — a target of the app frame is a path (\"/spaces\", on this host) or an https "
                    "address on exactly this host, without quotation marks, angle brackets, backslash and spaces",
                    f=f, h=href))
                continue
            error.append(_t(
                config,
                "{f}: {h!r} — a target is a path on the own origin (\"/wiki\") or an https address on "
                "the host of base_url or of trusted_redirect_hosts, without quotation marks, angle brackets, "
                "backslash and spaces",
                f=f, h=href))


def _frame_target_ok(href, hosts: set) -> bool:
    """A link target of the top bar or the app frame: a path (not `//`) or an https address on one of `hosts`, without
    quotation marks, angle brackets, backslash and white space (the bar writes it into a single-quoted attribute)."""
    if not isinstance(href, str):
        return False
    bad = not href or any(z in href for z in "'\"<>\\ \t\n\r")
    if bad:
        return False
    if href.startswith("/") and not href.startswith("//"):
        return True
    if href.startswith("https://"):
        try:
            return _urlsplit_host(href) in hosts and "@" not in href.split("/", 3)[2]
        except ValueError:
            return False
    return False


def _t(config, template: str, **values) -> str:
    """Finding text in the language of `config.lang`: English (default) or German.

    `template` is the English text with named placeholders (`str.format`); for `lang == "de"` the
    German template with the same key is taken from `_DE` (fallback: English if the key is missing).
    Literal braces in a template are written doubled (`{{` / `}}`)."""
    if getattr(config, "lang", "en") == "de":
        template = _DE.get(template, template)
    return template.format(**values)


def _an(config, slot: str) -> bool:
    return bool(getattr(config, slot, False))


def _integer(config, slot: str, missing: int | None = 0):
    """Read a number field for a combination check — or None if it is not an integer.

    Type and range are reported by `_number_limits` (including `True`, text, `inf`, `nan`); the combination
    is then not evaluated. An `int()` on the raw value crashed the whole check
    before the type message came, and `TinySesam(cfg)` raised ValueError/OverflowError instead of a
    collected ConfigError (second attack round, config)."""
    value = getattr(config, slot, missing)
    if value is None:
        return missing
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value


#: The directives a Content-Security-Policy knows (CSP Level 3 plus the common
#: legacy ones). A custom policy needs at least one of them; every other one gives a warning.
CSP_DIRECTIVES = frozenset({
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src",
    "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
    "fenced-frame-src", "base-uri", "form-action", "frame-ancestors", "navigate-to", "sandbox",
    "upgrade-insecure-requests", "block-all-mixed-content", "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types", "webrtc", "plugin-types", "referrer",
})


def _csp_names(value) -> list[str] | None:
    """The directive names of a custom policy, lower-cased — None for 'strict'/'off'/empty."""
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if raw in ("", "strict", "off"):
        return None
    return [part.split()[0].lower() for part in raw.split(";") if part.strip()]


def csp_error(value, config=None) -> str:
    """The finding for `csp`, empty if fine (B3-2).

    Everything except 'strict' and 'off' went unchecked 1:1 into the header up to 0.19.0. A typo
    like 'Strict' or 'stirct' thus was a "custom policy" without a single directive — the
    browser discards such a header, and the pages ran **without any CSP**, without anyone
    noticing. An error is therefore only the policy without a **single** known
    directive. If an unknown one stands next to known ones, the browser skips only it and applies
    the rest — that is `csp_warning` (A3: `require-sri-for`, `disown-opener` otherwise kept a
    previously working policy from starting).
    """
    names = _csp_names(value)
    if names is None:
        return ""                  # the constructor reports a non-string separately
    raw = value.strip()
    if raw.lower() in ("strict", "off"):
        return _t(
            config,
            "csp={value!r} — probably {intended!r} (lower case) is meant. As written it would be a "
            "custom policy without a directive, and the browser would run without any CSP.",
            value=value, intended=raw.lower())
    if not any(n in CSP_DIRECTIVES for n in names):
        return _t(
            config,
            "csp={value!r} is neither 'strict' nor 'off' nor a policy with a known directive. The "
            "browser discards such a header, and the pages would run without any CSP.",
            value=value)
    return ""


def csp_warning(value, config=None) -> str:
    """Unknown directives next to known ones: not an error, but probably a typo.

    The browser applies the policy without them. With 'scirpt-src', `default-src` then applies instead of
    the intended rule — that should be in the log. A real directive that is merely not listed here
    passes just the same.
    """
    names = _csp_names(value)
    if not names or csp_error(value, config):
        return ""
    unknown = [n for n in names if n not in CSP_DIRECTIVES]
    if not unknown:
        return ""
    return _t(
        config,
        "csp={value!r} contains directives that TinySesam does not know: {unknown}. The browser "
        "skips what it does not know and applies the rest — with a typo, the intended rule "
        "therefore does not apply.",
        value=value, unknown=", ".join(unknown))


def check_config(config) -> tuple[list[str], list[str]]:
    """(errors, warnings) — both complete, not aborted at the first finding."""
    error: list[str] = []
    warnings: list[str] = []

    # Background images (0.24.8): an address lands in a CSS url() — a quote or a parenthesis would be
    # a breakout from the stylesheet. Here and not only at the router, so render_page() is protected without a router too.
    for b in getattr(config, "brand_backgrounds", None) or []:
        if not isinstance(b, str) or not b or any(z in b for z in "'\"()\\<> \t\n"):
            error.append(_t(
                config,
                "brand_backgrounds: {b!r} — an address without quotation marks, parentheses, "
                "backslash and spaces (it ends up in a CSS url())",
                b=b))
        elif not (b.startswith("/") and not b.startswith("//")) and not b.startswith(("https://", "data:image/")):
            error.append(_t(
                config,
                "brand_backgrounds: {b!r} — allowed are /path, data:image/… and https://…",
                b=b))
    # C22 adapter: the app's stylesheet from its own origin — a path, never a foreign address (nothing from
    # third parties), and nothing that could leave the href attribute.
    _sheet = getattr(config, "c22_stylesheet", "") or ""
    if _sheet and (not isinstance(_sheet, str) or not _sheet.startswith("/") or _sheet.startswith("//")
                   or any(z in _sheet for z in "'\"<>\\ \t\n")):
        error.append(_t(
            config,
            "c22_stylesheet: {s!r} — a path on the app's own origin (\"/static/c22.css\"), "
            "without quotation marks, angle brackets, backslash and spaces",
            s=_sheet))
    # Top bar links (T-64) and account menu links: a link of the operator's own pages — a path on the own origin, or
    # an https address on a host a `next=` may reach (base_url, trusted_redirect_hosts). Never an arbitrary foreign
    # origin, nothing that could leave the href attribute, no javascript:/data: target. One check for both fields.
    _hosts = {str(h).lower() for h in (getattr(config, "trusted_redirect_hosts", None) or [])}
    if getattr(config, "base_url", ""):
        _hosts.add(_urlsplit_host(config.base_url))
    _roles_known = set(getattr(config, "available_roles", None) or [])
    _topbar_link_findings(config, "topbar_links", getattr(config, "topbar_links", None), _hosts, _roles_known, error,
                          warnings)
    _topbar_link_findings(config, "topbar_menu_links", getattr(config, "topbar_menu_links", None), _hosts, _roles_known,
                          error, warnings)
    _menu = getattr(config, "topbar_menu_links", None) or []
    if isinstance(_menu, (list, tuple)) and len(_menu) > 10:
        warnings.append(_t(
            config,
            "topbar_menu_links: {n} entries — more than 10 run off the screen of the account menu",
            n=len(_menu)))
    # The logo's tooltip: text in an attribute (escaped on output), bounded, without control characters.
    _icon_title = getattr(config, "brand_icon_title", "")
    if _icon_title:
        if (not isinstance(_icon_title, str) or len(_icon_title) > 200
                or any(z < " " or z == "\x7f" for z in _icon_title)):
            error.append(_t(
                config,
                "brand_icon_title: at most 200 characters of text without control characters"))
        else:
            _icon = getattr(config, "brand_icon", "") or ""
            if not ((_icon.startswith("/") and not _icon.startswith("//")) or _icon.startswith("data:image/")):
                warnings.append(_t(
                    config,
                    "brand_icon_title works only with an image in brand_icon (a path or data:image/…) — the "
                    "built-in mark and \"none\" carry no title"))
    _destination = getattr(config, "brand_background_credit_url", "")
    if _destination and not str(_destination).startswith(("https://", "http://")):
        error.append(_t(
            config,
            "brand_background_credit_url: only http(s) addresses"))

    # Cookie prefix (0.24.12): the start of a cookie name, no `__` (`__Host-`/`__Secure-` reserve that), and a gateway
    # stays at `tinysesam_` — the proxy templates strip its session in front of the app only under that name.
    _prefix = getattr(config, "cookie_prefix", "tinysesam_")
    if not isinstance(_prefix, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", _prefix):
        error.append(_t(
            config,
            "cookie_prefix={p!r}: 1–32 characters of letters, digits, _ and -, starting with a "
            "letter or a digit (e.g. \"myapp_\")",
            p=_prefix))
    elif _an(config, "forward_auth_enabled") and not _prefix.startswith("tinysesam_"):
        error.append(_t(
            config,
            "cookie_prefix={p!r} with forward_auth_enabled=True: the proxy templates strip "
            "only tinysesam_* cookies in front of the app — the session of this gateway would "
            "then reach every protected app. A gateway stays at cookie_prefix=\"tinysesam_\"; "
            "the prefix is for the app behind it.",
            p=_prefix))


    # `enabled_methods()` is asked — the same list from which the login page
    # builds its fields. A second list of its own here had exactly the error it is meant to catch: it saw
    # `pin_enabled=True` and overlooked `pin_login=False`, and thereby let an empty login page
    # through (PIN only as step-up is the documented way, not an exotic value).
    try:
        active = list(config.enabled_methods())
    except Exception:
        active = [name for name in SIGNING_IN if _an(config, PROCEDURE[name])]
    if not active:
        # `ldap_enabled=True` is NOT in the remedy (F-30): LDAP is not a field of its own on
        # the login page, but checks the password form against the directory. The message
        # named it anyway — and whoever followed it got the same message again.
        error.append(_t(
            config,
            "Not a single login method is enabled — the login page would have no field at all, "
            "nobody can sign in. At least one of: {fields} (for PIN also pin_login=True, "
            "otherwise it is only step-up). LDAP alone is not enough: ldap_enabled=True checks "
            "the password form against the directory and therefore needs password_enabled=True.",
            fields=", ".join(f"{PROCEDURE[n]}=True" for n in SIGNING_IN if n != "ldap")))
    if _an(config, "ldap_enabled") and not _an(config, "password_enabled"):
        # Warning, not error: with a second method (OIDC, passkey) construction starts
        # sensibly — only the LDAP path is dead then, and the operator should know.
        warnings.append(_t(
            config,
            "ldap_enabled=True, but password_enabled=False. LDAP has no form of its own, it "
            "checks the password field of the login page against the directory — without "
            "password_enabled=True nobody signs in via LDAP."))

    # Warning, not error: the clients for OIDC, SAML and LDAP can be replaced
    # (`auth.ldap = own_client`), and the own suites work exactly that way. A hard
    # guard would thereby forbid a legitimate setup. It does not stay silent anyway — the
    # normal case "switched on and forgotten to configure" would otherwise only fail at the
    # first click on "Sign in".
    # A field name that does not exist at all would be the worst kind of false alarm: it fires on
    # EVERY configuration of the method and at the same time never checks what was meant. Exactly
    # that happened (`ldap_server` instead of `ldap_url`, and the field appeared in the whole repo only in
    # this line). Hence an assertion here instead of trust.
    unknown = sorted({f for fields in REQUIRED_FIELDS.values() for f in fields
                        if not hasattr(config, f)}
                       | {v for v in PROCEDURE.values() if not hasattr(config, v)}
                       | {f for f in REQUIRES_MAILER if not hasattr(config, f)}
                       | {f for f in REQUIRES_BASE_URL if not hasattr(config, f)}
                       | {f for f in BASE_URL_RECOMMENDED if not hasattr(config, f)}
                       | {f for f in ("base_url", "trusted_redirect_hosts")
                          if not hasattr(config, f)})
    if unknown:
        error.append(_t(
            config,
            "The configuration check names fields that do not exist in TinySesamConfig: "
            "{fields}. This is a bug in TinySesam itself — please report it.",
            fields=unknown))

    for name, fields in REQUIRED_FIELDS.items():
        if not _an(config, PROCEDURE[name]):
            continue
        empty = [f for f in fields if not str(getattr(config, f, "") or "").strip()]
        if empty:
            warnings.append(_t(
                config,
                "{method}=True, but {empty} is empty. The method cannot work that way and "
                "fails at the first sign-in attempt — unless the client is replaced at runtime.",
                method=PROCEDURE[name], empty=', '.join(empty)))

    # Side finding from the same audit (F-28): a service-account DN without password is not an
    # anonymous search, but a combination that ldap3 rejects on its own
    # (`LDAPPasswordIsMandatoryError`). The error is raised in the middle of the login and swallowed there
    # — the operator sees "wrong password" for EVERY user and looks at the
    # wrong end. Warning instead of error, because the client is replaceable at runtime.
    if _an(config, "ldap_enabled") and str(getattr(config, "ldap_bind_dn", "") or "").strip() \
            and not str(getattr(config, "ldap_bind_password", "") or "").strip():
        warnings.append(_t(
            config,
            "ldap_bind_dn is set, ldap_bind_password is empty. This is not an anonymous "
            "search: ldap3 rejects a DN without a password, the error only occurs at login and "
            "looks there like a wrong password for every user. Either set the password of the "
            "service account or empty ldap_bind_dn (then the search really is anonymous)."))

    # A chain step must be a factor that a session can actually get. `ldap` is
    # none (it writes the factor `password`), neither is `apikey` — both were in the
    # whitelist anyway, and `login_chain=["ldap","totp"]` is the most obvious spelling for an
    # LDAP operator. It led into exactly the loop this module warns about.
    raw_chain = list(getattr(config, "login_chain", None) or [])
    # Alternatives per step (T-34): "password|passkey". Every name is checked on its own; an empty
    # alternative ("password|", "|totp", "") is a typo, not a wildcard.
    hollow = [entry for entry in raw_chain
              if not isinstance(entry, str) or any(not part.strip() for part in entry.split("|"))]
    if hollow:
        error.append(_t(
            config,
            "login_chain has empty steps or alternatives: {steps}. A step names one factor or "
            "several separated by '|', e.g. 'password|passkey'.",
            steps=hollow))
    # Every factor named, alternatives included, in the order of the chain.
    chain = list(dict.fromkeys(f for step in _chain.steps(e for e in raw_chain if isinstance(e, str))
                               for f in step))
    unknown = [s for s in chain if s not in CHAIN_STEPS]
    if unknown:
        notice = ""
        if "ldap" in unknown:
            notice = _t(config, " — LDAP satisfies the step 'password', not 'ldap'")
        error.append(_t(
            config,
            "login_chain names steps that are not a factor: {steps}{hint}. Allowed are "
            "{allowed}.",
            steps=unknown, hint=notice, allowed=sorted(CHAIN_STEPS)))
    from_ = [s for s in chain if s in PROCEDURE and not _an(config, PROCEDURE[s])]
    if from_:
        error.append(_t(
            config,
            "login_chain requires {steps}, but {switches} — the chain is unsatisfiable, nobody "
            "gets past this step.",
            steps=from_, switches=", ".join(f"{PROCEDURE[s]}=False" for s in from_)))
    if "totp" in chain and not _an(config, "totp_enabled"):
        error.append(_t(
            config,
            "login_chain requires 'totp', but totp_enabled=False — unsatisfiable."))
    # A PIN behind another factor is, in a NON-strict chain with `pin_login`,
    # at the same time a first factor (`pin_as_first_factor`): whoever starts with it then satisfies the chain
    # with the password. Then anyone guesses the PIN without the password, and a self-service reset
    # clears these wrong guesses from the series (R2-2) — the configuration says "follow-up factor", the
    # behaviour "first factor" (G7). In a strict chain TinySesam closes the guest path itself.
    if not hollow and raw_chain and not _chain.assignable(raw_chain):
        error.append(_t(
            config,
            "login_chain={chain} cannot be satisfied: one factor satisfies at most one step, and "
            "the steps name too few different factors.",
            chain=raw_chain))
    if ("pin" in chain and "pin" not in _chain.first_step(raw_chain) and _an(config, "pin_enabled")
            and _an(config, "pin_login") and not getattr(config, "login_chain_strict", True)):
        warnings.append(_t(
            config,
            "login_chain={chain} with login_chain_strict=False names 'pin' behind another "
            "factor, and pin_login=True offers the PIN as a first factor at the same time: "
            "whoever starts with it guesses it without the password, and a self-service reset "
            "clears these failed attempts from the series (account_max_consecutive_failures). "
            "If the PIN is meant to be only a follow-up factor: pin_login=False — the PIN step "
            "after the first factor stays reachable.",
            chain=raw_chain))

    # Here once stood "resource_locks_enabled needs pin_enabled". That was wrong and
    # a suite of its own refuted it immediately: a locked resource is released with its OWN
    # secret (`store.get_resource_secret`), not with the login PIN. A
    # false alarm costs the same trust as an overlooked finding — hence the note stands
    # here instead of the check.

    # Cross-device sign-in (T-33): the QR code carries the approval address to the second device.
    # It is built only from `base_url`, never from the Host header (R4-01) — without it the page
    # shows the short code alone. Works, but the operator should know why there is no QR code.
    if _an(config, "qr_login_enabled") and not str(getattr(config, "base_url", "") or "").strip():
        warnings.append(_t(
            config,
            "qr_login_enabled=True, but base_url is empty. The QR code needs the public address "
            "and is never built from the Host header — the login page then shows only the short "
            "code, which the user types on the signed-in device. Set base_url for the QR code."))
    # Links without the mail self-request (T-33): a chain step `magic` sends the user to
    # `/auth/magic/request` — the route that this switch removes. The step can then only be
    # satisfied with a link the admin hands out.
    if (_an(config, "magiclink_enabled") and not getattr(config, "magiclink_self_request", True)
            and "magic" in chain):
        warnings.append(_t(
            config,
            "login_chain contains 'magic', but magiclink_self_request=False: the chain step "
            "leads to /auth/magic/request, which does not exist then (404). The step can only "
            "be satisfied with a link issued by the admin or by app code."))
    # "Link only for the first sign-in" (T-34) is a rule about redeeming links — without links it
    # guards nothing, and the operator may believe a protection is in place that is not.
    if getattr(config, "magiclink_first_login_only", False) and not _an(config, "magiclink_enabled"):
        warnings.append(_t(
            config,
            "magiclink_first_login_only=True, but magiclink_enabled=False: there are no sign-in "
            "links whose use the switch could limit."))
    if _an(config, "password_reset_enabled") and not _an(config, "magiclink_enabled"):
        warnings.append(_t(
            config,
            "password_reset_enabled=True, but magiclink_enabled=False. The routes are mounted, "
            "but the link \"Forgot password?\" does not appear on the login page — the feature "
            "is on and reachable for nobody."))
    if _an(config, "allow_signup") and not _an(config, "password_enabled"):
        error.append(_t(
            config,
            "allow_signup=True with password_enabled=False creates accounts that can never "
            "sign in — registration assigns a password, and password login is off."))
    # Open registration next to LDAP (PO decision 2026-09-27): an identifier belongs to exactly one
    # account — if the directory returns another person under a locally assigned identifier,
    # TinySesam rejects the sign-in (review round p1-d). Whoever registers in advance with the name or the
    # directory address of a person who has never signed in would lock them
    # out. TinySesam does not know these names before the directory names them — so
    # the combination does not exist. There the operator creates accounts (panel, `create_user`).
    if _an(config, "allow_signup") and _an(config, "ldap_enabled"):
        error.append(_t(
            config,
            "allow_signup=True next to ldap_enabled=True: whoever registers with the name or "
            "the address of a person from the directory before that person has signed in locks "
            "them out under this identifier (an identifier belongs to exactly one account). "
            "Turn registration off and create accounts in the admin panel or with "
            "auth.create_user(...)."))

    # `base_url` was missing entirely from this module — and with it the only hint at
    # the path that R4-01/R8-4 exploits: without it TinySesam builds absolute addresses from the
    # `Host` header, that is, from an input of the requester.
    #
    # Here once stood a **warning**, with two reasons — the local setup (loopback counts as its
    # own host) and a `base_url` that is only set after the constructor. Neither
    # held up, the follow-up measured it:
    #
    # * A warning starts anyway. Whoever updated without `base_url` lost "forgot
    #   password" and magic link for ALL users — and silently: the route kept rendering the
    #   success page ("mail is on its way", HTTP 200), because the same reply prevents
    #   user enumeration. It was visible in one log line.
    # * If several hosts are in `trusted_redirect_hosts` — the normal case with forward auth/SSO —
    #   the runtime check was satisfied by ANY of them. The attacker triggered "forgot password" for
    #   a foreign mailbox and set `Host:` to another co-trusted host; the
    #   reset link went out there. `base_url` closes exactly this freedom of choice: when it is set,
    #   nothing at all comes from the request.
    #
    # Therefore now an **error**: construction fails with `ConfigError` instead of allowing
    # an operation that silently does the wrong thing. The local setup simply enters its address
    # (`base_url="http://127.0.0.1:8000"`), and whoever learns it late writes it on the
    # config object BEFORE `TinySesam(config)` runs — unlike `set_mailer()` there is
    # no way to supply it later, because without a base the first click on "forgot password"
    # ends in nothing.
    # The check uses the **same** function that `public_base()` applies later
    # (`security.normalize_base`), not a weaker pattern of its own: a coarse
    # scheme-and-host pattern accepted `https://wer:was@auth.example` and `https://auth.example/x#y`
    # — both would then stand in every reset link, and the part behind `#` does not even
    # reach the server. Two rule sets for the same question are one too many (C-7).
    _base = str(getattr(config, "base_url", "") or "").strip()
    _canonical = security.normalize_base(_base)
    if _base and _canonical and _canonical != _base.rstrip("/"):
        # The address is usable, but it is altered on the way — we say so here
        # instead of doing it silently. Most common case: user info in the host
        # (`https://wer:was@auth.example`), which is removed from every outgoing link.
        error.append(_t(
            config,
            "base_url={base!r} is used as {canon!r} — the address is not in the form in which "
            "it appears in links. Please enter exactly the second value, so that configuration "
            "and reality say the same.",
            base=_base, canon=_canonical))
    if _base and not _canonical:
        error.append(_t(
            config,
            "base_url={base!r} is not a usable base address (expected e.g. "
            "\"https://auth.example.com\", with a subpath \"https://example.com/sso\"). "
            "Required are scheme http/https and a host; not allowed are user info in the host, "
            "a query (?) or fragment (#), an invalid port and a path with \"..\" or \"//\". "
            "Every link built from it would be broken — without an error, without a log line, "
            "only at the recipient.",
            base=_base))
    if not _base:
        affected = [_t(config, for_what) for slot, for_what in REQUIRES_BASE_URL.items() if _an(config, slot)]
        if affected:
            error.append(_t(
                config,
                "base_url is empty, but these functions hand an absolute address to third "
                "parties: {functions}. The only source left would be the Host header of the "
                "respective request — and that is set by the requester (with a mail to a "
                "foreign mailbox, therefore the attacker). Remedy: set base_url to the public "
                "address of this app, e.g. base_url=\"https://auth.example.com\" (locally "
                "base_url=\"http://127.0.0.1:8000\"). Mounted under a subpath, the prefix "
                "belongs in it (\"https://example.com/sso\"). trusted_redirect_hosts is NOT a "
                "substitute for this: if more than one host is listed there, the requester "
                "decides via the Host header which of them ends up in the link.",
                functions="; ".join(affected)))
        soft = [_t(config, for_what) for slot, for_what in BASE_URL_RECOMMENDED.items() if _an(config, slot)]
        if soft and not affected:
            warnings.append(_t(
                config,
                "base_url is empty, but this function builds absolute addresses: {functions}. "
                "Without a checked base the redirect stays relative — that holds as long as "
                "app and login page live under the same host. For SSO across several hosts set "
                "base_url (and cookie_domain).",
                functions="; ".join(soft)))
    # A bare IP address as base_url (T-37): it works, but only with a CA of your own that every
    # device has to trust — the cookies are `Secure`, OAuth clients refuse a token endpoint over
    # plain HTTP — and WebAuthn refuses passkeys outright when the origin's host is an IP address
    # (Web Authentication Level 3, §5.1.3: "Only the domain format of host is allowed here").
    # A domain gets a publicly trusted certificate instead (DNS-01 also for names that resolve
    # only at home). Loopback stays silent: browsers treat
    # `http://127.0.0.1`/`[::1]` as a secure context and OAuth clients accept it (RFC 8252) —
    # that is local development, not a home network, and needs no CA at all.
    _base_host = _urlsplit_host(_canonical) if _canonical else ""
    if _base_host and _is_ip(_base_host) and not _is_loopback(_base_host):
        warnings.append(_t(
            config,
            "base_url={base!r} is an IP address. HTTPS on it needs a CA of your own that every "
            "device trusts once (Secure cookies and OAuth clients require HTTPS), and passkeys do "
            "not work on an IP address at all (WebAuthn accepts only domain names). Recommended: "
            "a domain — a publicly trusted certificate via DNS-01 works even for names that "
            "resolve only inside your network. "
            "If it has to be the IP: docs/HOME-NETWORK.md.",
            base=_base))
    # First-admin token: the value must not land where strangers can read it. That was exactly
    # B5-03 — it stood in the file that the fail2ban jail reads and logrotate archives.
    token_file = str(getattr(config, "admin_claim_token_file", "") or "").strip()
    seclog_file = str(getattr(config, "security_log", "") or "").strip()
    if token_file and seclog_file and os.path.abspath(token_file) == os.path.abspath(seclog_file):
        error.append(_t(
            config,
            "admin_claim_token_file and security_log point to the same file. The first-admin "
            "one-time token would then end up again in the log that fail2ban reads, logrotate "
            "archives and a log shipper takes along — whoever reads it becomes admin. Use a "
            "file of its own for the token (e.g. /run/<service>/admin-claim.token) or leave "
            "the field empty, then the value goes to stderr."))
    _claim_ttl = _integer(config, "admin_claim_ttl_min")
    if token_file and ((_claim_ttl is not None and _claim_ttl <= 0)
                        or not _an(config, "admin_enabled")):
        warnings.append(_t(
            config,
            "admin_claim_token_file is set, but the token path is off (admin_claim_ttl_min=0 "
            "or admin_enabled=False) — the file is never written. The first admin then only "
            "comes about via admin_identifiers or an own call of auth.ensure_admin(…) — the "
            "CLI cannot create accounts."))

    # First admin via allowlist ADDRESS while SAML or LDAP create accounts themselves: the
    # constructor forbids allowlist *names* here (nobody confirms them). An
    # address stays allowed — but it carries the decision only with proof. SAML and LDAP
    # deliver none; since the PO decisions 2026-09-24/25 the operator says per source whether they trust
    # its addresses (`*_email_trusted`, default no) or which attribute vouches for them
    # (`*_attr_email_verified`). Not trusted: the runtime never promotes (fail-closed, F-14) —
    # and the confirmation link goes to no allowlist address. Trusted or provable
    # by attribute: the address promotes — correct only if nobody can enter it or the attribute
    # themselves.
    allowlist_addresses = sorted({str(i).strip() for i in
                                 (getattr(config, "admin_identifiers", None) or [])
                                 if "@" in str(i)})
    sources = [(name, _an(config, trust) or bool(security.proof_attribute(config, source)))
               for an, create, trust, source, name in (
        ("saml_enabled", "saml_auto_create", "saml_email_trusted", "saml", "SAML"),
        ("ldap_enabled", "ldap_auto_create", "ldap_email_trusted", "ldap", "LDAP"))
        if _an(config, an) and _an(config, create)]
    without_proof = [name for name, trusted in sources if not trusted]
    with_proof = [name for name, trusted in sources if trusted]
    if allowlist_addresses and without_proof:
        warnings.append(_t(
            config,
            "admin_identifiers names the address(es) {addrs}, and accounts are created at the "
            "first login by {sources} itself, without the operator trusting the addresses of "
            "this source (*_email_trusted=False, no *_attr_email_verified). Through these "
            "paths the address NEVER becomes the first admin — the address is not used there "
            "at all. The proven way is the one-time token: sign in, then /auth/claim-admin "
            "(see admin_claim_ttl_min); after that the first admin assigns the rights "
            "themselves.",
            addrs=allowlist_addresses, sources=_t(config, " and ").join(without_proof)))
    if allowlist_addresses and with_proof:
        warnings.append(_t(
            config,
            "admin_identifiers names the address(es) {addrs}, and {sources} counts as a "
            "trusted source (*_email_trusted=True or a proof attribute *_attr_email_verified): "
            "whoever holds one of these addresses as proven there becomes first admin at the "
            "first login. That is only right if nobody can change their address (or the proof "
            "attribute) in this source themselves (no self-service for the mail attribute, no "
            "IdP with self-registration) — otherwise turn both off and use /auth/claim-admin.",
            addrs=allowlist_addresses, sources=_t(config, " and ").join(with_proof)))
    # LDAP not trusted, but the search filter finds accounts via the address: then the
    # input at login is an address that nobody vouches for. TinySesam does not take it as an
    # account name (substitute name `ldap-…`), but needs a stable identifier for that.
    _filter = str(getattr(config, "ldap_user_filter", "") or "")
    _mail_attr = str(getattr(config, "ldap_attr_email", "") or "mail")
    if _an(config, "ldap_enabled") and not _an(config, "ldap_email_trusted") \
            and f"({_mail_attr.lower()}=" in _filter.lower():
        warnings.append(_t(
            config,
            "ldap_user_filter searches via {attr}, but ldap_email_trusted=False: whoever signs "
            "in with their {attr} value gets a substitute name (ldap-…) instead of this value "
            "as the account name and is never matched to an existing account by name; without "
            "a stable identifier (ldap_attr_id) the sign-in is rejected.",
            attr=_mail_attr))
    # G1: binding indefinitely via the name is the state up to 0.20.x — and exactly the gap that the
    # deadline closes. Allowed (way back), but not silently.
    _federated = [name for an, name in (("ldap_enabled", "LDAP"), ("saml_enabled", "SAML"))
                   if _an(config, an)]
    _days = _integer(config, "federation_name_binding_days", 30)
    if _federated and _days is not None and _days < 0:
        warnings.append(_t(
            config,
            "federation_name_binding_days={days}: for {sources}, an unbound account is bound "
            "indefinitely via its name. A dormant account (someone has left) then falls to the "
            "next person who gets the same name in the directory — together with roles and "
            "admin right. Better: bind the existing accounts once "
            "(auth.federation_bind_existing(source), first as a dry run) and keep the default "
            "(30).",
            days=_days, sources=_t(config, " and ").join(_federated)))

    # Paths of the app have carried no mount prefix since T-15 — TinySesam puts it in front from the path
    # of the base_url. Whoever entered it by hand for the old version (`/sso/auth/login`)
    # would now get `/sso/sso/auth/login` (404). A warning, not an error: a path of the app can
    # by pure chance be named like the prefix.
    from urllib.parse import urlsplit as _urlsplit
    _prefix = _urlsplit(str(getattr(config, "base_url", "") or "")).path.rstrip("/")
    if _prefix:
        _paths = {"login_path": str(getattr(config, "login_path", "") or ""),
                  "login_redirect": str(getattr(config, "login_redirect", "") or ""),
                  "logout_redirect": str(getattr(config, "logout_redirect", "") or ""),
                  "admin_path": str(getattr(config, "admin_path", "") or "")}
        double = [f"{slot}={value!r}" for slot, value in _paths.items() if value.startswith(_prefix + "/")]
        if double:
            warnings.append(_t(
                config,
                "{fields} begins with the prefix of base_url ({prefix}). These fields are app "
                "paths without the prefix — TinySesam puts it in front itself since 0.21, "
                "otherwise {prefix}{prefix}/… results. Remove the prefix from the value.",
                fields=', '.join(double), prefix=_prefix))

    # --- Several applications behind one installation (T-14) ---
    _clients = getattr(config, "oidc_clients", None) or {}
    # Type and range are checked by NUMBER_LIMITS (below, including negative values); here only the
    # combination. An `int()` on a text crashed the whole check.
    _revalidate = _integer(config, "oidc_revalidate_minutes") or 0
    if _clients and not _an(config, "oidc_enabled"):
        error.append(_t(
            config,
            "oidc_clients names {hosts}, but oidc_enabled is False. The host→client mapping "
            "would have no effect: there would be no OIDC path through which an approval could "
            "arise.",
            hosts=", ".join(sorted(str(h) for h in _clients))))
    if _revalidate > 0 and not _clients:
        warnings.append(_t(
            config,
            "oidc_revalidate_minutes={n}, but oidc_clients is empty. The re-check concerns the "
            "approval per application — without several clients there is none, and the value "
            "stays without effect. Probably session_ttl_hours (lifetime of the session) or "
            "stepup_max_age_sec (freshness for sensitive routes) was meant.",
            n=_revalidate))
    # The upper bound in NUMBER_LIMITS (30 days) catches a period in seconds only from one day
    # (86400). The preset's default, one hour, written in seconds (3600) passed
    # silently — re-check every 60 hours, a revocation at the provider arrived 60 times later. A
    # period above one day is unusual enough to ask about the unit; 300 or 900
    # (five or 15 minutes in seconds) are caught by no bound.
    if _revalidate > 24 * 60:
        warnings.append(_t(
            config,
            "oidc_revalidate_minutes={n} means: re-check at the provider every {hours} hours. "
            "The field counts minutes — was the period meant in seconds (one hour = 60, not "
            "3600)? If the long period is intended, it stays at this warning.",
            n=_revalidate, hours=format(_revalidate / 60, "g")))
    # By host name, as the runtime compares them (a port in either entry is not a different host, RFC 6265 8.5).
    _trusted = [security.host_name(h) for h in (getattr(config, "trusted_redirect_hosts", None) or [])]
    for host, entry in _clients.items():
        _hn = security.host_name(host)
        e = dict(entry or {})
        where = f"oidc_clients[{host!r}]"
        if not str(e.get("client_id") or "").strip():
            error.append(_t(
                config,
                "{where} has no client_id. Without it there is no client at the provider for this "
                "application — and thus no approval of its own.",
                where=where))
        if not str(e.get("client_secret") or "").strip():
            error.append(_t(
                config,
                "{where} has no client_secret. The exchange of the authorization code then fails "
                "at the provider, and only after the sign-in — that is, at the point where "
                "nobody suspects a configuration gap any more.",
                where=where))
        if e.get("issuer"):
            error.append(_t(
                config,
                "{where} names an issuer of its own. Several providers in one installation are "
                "not intended: discovery document, JWKS and the mapping issuer+sub→account "
                "hang on the one oidc_issuer. A second provider needs a second instance.",
                where=where))
        if _trusted and _hn not in _trusted:
            warnings.append(_t(
                config,
                "{where} is not in trusted_redirect_hosts. The login URL for this application is "
                "then built on base_url instead of on the requested host — without "
                "cookie_domain the session cookie is host-only, and the sign-in goes round in "
                "circles.",
                where=where))
    if _clients and not _an(config, "forward_auth_enabled"):
        warnings.append(_t(
            config,
            "oidc_clients is set, but forward_auth_enabled is False. The approval per "
            "application is checked in /auth/forward — without forward auth it arises at "
            "login, but is afterwards queried by nothing."))

    # --- Self-enrollment of the second factor (R3-1) ---
    _kinds = ("first_login", "grace", "strict")
    _kind = str(getattr(config, "mfa_enrollment", "") or "first_login")
    if _kind not in _kinds:
        error.append(_t(
            config,
            "mfa_enrollment={kind!r} does not exist. Allowed are {allowed}: 'first_login' "
            "(default, allowed until the first complete login), 'grace' (allowed "
            "mfa_enrollment_grace_days after account creation), 'strict' (never — the setup "
            "then comes from the operator).",
            kind=_kind, allowed=list(_kinds)))
    _mercy = _integer(config, "mfa_enrollment_grace_days")
    if _kind == "grace" and _mercy is not None and _mercy <= 0:
        error.append(_t(
            config,
            "mfa_enrollment='grace', but mfa_enrollment_grace_days is 0 or less. 'grace' then "
            "behaves like 'strict', only less conspicuously — either set a period or write "
            "mfa_enrollment='strict' right away."))

    # --- CSRF protection fully off (F-03) ---
    # Individually each value is defensible: `csrf_enabled=False`, because SameSite=Lax already
    # stops cross-site POSTs; `cookie_samesite='none'` for an embedded app, because
    # the CSRF token then protects. Together NOTHING remains: the session cookie rides along with every
    # foreign form, and nobody checks a token. That is not a compromise, that is a hole.
    if (not _an(config, "csrf_enabled")
            and str(getattr(config, "cookie_samesite", "lax") or "").lower() == "none"):
        error.append(_t(
            config,
            "csrf_enabled=False together with cookie_samesite='none': the browser then sends "
            "the session cookie along with every form of a foreign site, and no token holds "
            "against it — every state-changing route can be triggered via CSRF. Either "
            "csrf_enabled=True (needed as soon as SameSite=None is used) or "
            "cookie_samesite='lax'."))

    # --- User verification for passkeys (B2-10) ---
    _uv = str(getattr(config, "passkey_user_verification", "required") or "required")
    if _uv not in ("required", "preferred"):
        error.append(_t(
            config,
            "passkey_user_verification={uv!r} does not exist. Allowed are 'required' (default: "
            "the authenticator must verify the person) and 'preferred' (it is asked to). A "
            "passkey signs in on its own — without verification it only proves possession of "
            "the key.",
            uv=_uv))
    elif _uv == "preferred" and _an(config, "passkey_enabled"):
        warnings.append(_t(
            config,
            "passkey_user_verification='preferred': a passkey without user verification signs "
            "in on its own and then proves only possession of the key — an unlocked computer "
            "or a plugged-in stick is enough. That is a deliberate decision for a stock of old "
            "authenticators; for a new one the value belongs at 'required'."))

    # --- Sign-in link bound (T-51) ---
    _link_max = _integer(config, "signin_link_max_ttl_min", 24 * 60)
    _link_default = _integer(config, "magiclink_ttl_min", 10)
    if (_an(config, "magiclink_enabled") and _link_max is not None and _link_default is not None
            and _link_max < _link_default):
        error.append(_t(
            config,
            "signin_link_max_ttl_min={most} is below magiclink_ttl_min={default}: a sign-in link issued without "
            "its own validity takes magiclink_ttl_min and would always be refused. Raise the bound or lower "
            "magiclink_ttl_min.",
            most=_link_max, default=_link_default))
    # An invitation is a hand-over link under the same bound; its own default (24 h) must fit under it.
    _invite_default = _integer(config, "invite_ttl_min", 24 * 60)
    if (_an(config, "allow_signup") and _link_max is not None and _invite_default is not None
            and _link_max < _invite_default):
        error.append(_t(
            config,
            "signin_link_max_ttl_min={most} is below invite_ttl_min={default}: an invitation issued without its "
            "own validity takes invite_ttl_min and would always be refused. Raise the bound or lower "
            "invite_ttl_min.",
            most=_link_max, default=_invite_default))

    # --- TOTP time window (T-57) ---
    _window = str(getattr(config, "totp_window", "previous"))
    if _window not in ("current", "previous", "previous_and_next"):
        error.append(_t(
            config,
            "totp_window={window!r} does not exist. Allowed are 'previous' (default: the current and the "
            "previous 30-second step), 'current' (only the running step) and 'previous_and_next' (also the "
            "next step, the behaviour up to 0.25.x).",
            window=_window))

    # --- LDAP transport (F-12) ---
    if _an(config, "ldap_enabled"):
        _url = str(getattr(config, "ldap_url", "") or "").strip().lower()
        _tls_an = _url.startswith("ldaps://") or _an(config, "ldap_start_tls")
        if _url and not _tls_an and not _an(config, "ldap_allow_plaintext"):
            error.append(_t(
                config,
                "ldap_url={url!r} speaks plain text and ldap_start_tls is False. Then the "
                "password of the service account AND every user password travel unencrypted "
                "over the network — at every sign-in. Remedy: ldaps:// in the URL (port 636) "
                "or ldap_start_tls=True (port 389). If the directory is on the same host and "
                "the traffic never leaves it, ldap_allow_plaintext=True says so explicitly.",
                url=_url))
        if _an(config, "ldap_allow_plaintext") and not _tls_an:
            warnings.append(_t(
                config,
                "ldap_allow_plaintext=True: the LDAP traffic is unencrypted. The password of "
                "the service account and every user password can thus be read by anyone "
                "sitting on the path. Only justifiable if this path does not leave the machine."))
        if _tls_an and not _an(config, "ldap_tls_verify"):
            warnings.append(_t(
                config,
                "ldap_tls_verify=False: the certificate of the directory is not checked. "
                "Encrypted then only means: not readable by someone who does not sit in "
                "between. Whoever redirects the traffic presents a certificate of their own "
                "and gets both passwords. With a CA of your own, it belongs in "
                "ldap_tls_ca_file."))
        _ca = str(getattr(config, "ldap_tls_ca_file", "") or "").strip()
        if _ca and not os.path.exists(_ca):
            error.append(_t(
                config,
                "ldap_tls_ca_file={ca!r} does not exist. The connection to the directory then "
                "fails at every sign-in — and only in operation.",
                ca=_ca))

    _csp_hit = csp_error(getattr(config, "csp", "strict"), config)
    if _csp_hit:
        error.append(_csp_hit)
    _csp_notice = csp_warning(getattr(config, "csp", "strict"), config)
    if _csp_notice:
        warnings.append(_csp_notice)
    _number_limits(config, error)
    _proxies_and_passkey(config, error, warnings)
    _stepup(config, error, warnings)
    _open_gates(config, warnings)
    _groups_scope(config, warnings)
    _combinations(config, error, warnings)
    _gate(config, error, warnings)
    _oauth(config, error, warnings)
    _oauth_services_without_oauth(config, error)
    _oauth_pairing_consent_without_oauth(config, error)
    _approvals(config, error)
    _apps(config, error, warnings)
    _app_approvals(config, error)
    _keys(config, warnings)
    _forward_apps(config, error, warnings)
    _first_sign_in(config, error, warnings)

    has_mailer = bool(str(getattr(config, "smtp_host", "") or "").strip())
    # --- SMTP TLS (B3-1, attack A4): since the certificate is checked, a wrong
    # CA path or a relay by IP address fails on EVERY mail — and silently, only as
    # *_send_error in the audit log. Both can be detected at construction.
    _smtp_ca = str(getattr(config, "smtp_ca_file", "") or "").strip()
    if _smtp_ca and not os.path.isfile(_smtp_ca):
        error.append(_t(
            config,
            "smtp_ca_file={ca!r} does not exist. The TLS check of the mail server then fails "
            "on every mail — sign-in links, resets and confirmations would never go out, and "
            "only in operation.",
            ca=_smtp_ca))
    _smtp_host = str(getattr(config, "smtp_host", "") or "").strip().strip("[]")
    if has_mailer and _is_ip(_smtp_host):
        warnings.append(_t(
            config,
            "smtp_host={host!r} is an IP address. The certificate of the mail server is "
            "checked against the hostname; if it does not carry the IP as a Subject "
            "Alternative Name, every send fails. Remedy: enter the name the certificate is "
            "issued for (with a CA of your own additionally smtp_ca_file).",
            host=_smtp_host))
    for slot, for_what in REQUIRES_MAILER.items():
        # Links on without the mail self-request (T-33): sign-in links come only from the admin
        # panel or app code — nothing goes out by mail, so nothing is missing without a mailer.
        if slot == "magiclink_enabled" and not getattr(config, "magiclink_self_request", True):
            continue
        if _an(config, slot) and not has_mailer:
            warnings.append(_t(
                config,
                "{field}=True ({what}), but smtp_host is empty. Without a mailer no mail goes "
                "out and the method ends silently. Either set smtp_host or call "
                "auth.set_mailer(...) at runtime — then this message is moot.",
                field=slot, what=_t(config, for_what)))

    _role_names(config, error)
    _roles_without_list(config, warnings)
    _admin_delegates(config, error, warnings)
    _delegates_and_app_allowlists(config, warnings)
    _role_level_ladders(config, error, warnings)

    # `audit_retention_days` is checked by NUMBER_LIMITS (below): a negative period would be in `gc()` a
    # point in time in the future — the whole audit log would vanish on the next run. The own
    # check that stood here knew only `< 0` and let `True`, seconds instead of days and
    # huge values (OverflowError in gc()) through.

    return error, warnings


#: Number fields of the config → allowed range, both bounds inclusive (B3-12).
#:
#: Before, not a single one had a bound, and the failure modes are all silent: `session_ttl_hours=0`
#: lets every session expire the moment it is created (sign-in "works", the next click
#: is the login page again), `magiclink_ttl_min=0` sends dead links, `recovery_code_count=0`
#: issues no codes and still reports success, a negative `stepup_max_age_sec` makes
#: every step-up confirmation instantly old. The upper bounds catch the unit error (minutes instead of
#: hours, seconds instead of minutes), which silently multiplies a period by sixty.
NUMBER_LIMITS = {
    "brand_background_seconds": (4, 600),   # dwell time per background image (0.24.8)
    "pin_min_length": (4, 64),
    "apikey_default_days": (0, 3650),
    "app_password_default_days": (1, 3650),   # T-66; "no expiry" is a choice at creation, not a default
    "admin_claim_ttl_min": (0, 7 * 24 * 60),
    "resource_unlock_ttl_hours": (1, 24 * 30),
    "magiclink_ttl_min": (1, 24 * 60),
    # T-51: a week is the most a hand-over link may live; longer is no hand-over but a second password.
    "signin_link_max_ttl_min": (1, 7 * 24 * 60),
    "invite_ttl_min": (1, 7 * 24 * 60),      # bounded further by signin_link_max_ttl_min (check above)
    # A cross-device request is approved within moments; longer than a quarter of an hour is a
    # code lying around on a screen, not a hand-over.
    "qr_login_ttl_sec": (30, 15 * 60),
    "smtp_port": (1, 65535),
    "smtp_timeout": (1, 300),
    "recovery_code_count": (1, 100),
    "mfa_enrollment_grace_days": (0, 365),
    "stepup_max_age_sec": (0, 7 * 86400),
    "session_ttl_hours": (1, 24 * 400),
    "session_ttl_transient_hours": (1, 24 * 400),
    # 0 = no deadline. Ten years (including leap days) suffice for any retention duty;
    # above that is almost always the period in seconds (2592000 for 30 days), which would never apply.
    # `True` counted as one day here, and gc() deleted the audit log except for the last day.
    "audit_retention_days": (0, 3660),
    # 0 = no re-check. A revocation at the provider that arrives only after more than 30 days
    # is no longer a re-check; `86400` (one day in seconds instead of minutes) stands out this way.
    # Shorter periods in seconds (3600 for one hour) do not — for that `check_config` warns above 1440.
    "oidc_revalidate_minutes": (0, 30 * 24 * 60),
    "oidc_session_refresh_minutes": (0, 24 * 60),
    # One year is the utmost that is still a bound; 0 = off.
    "oidc_session_max_unverified_hours": (0, 365 * 24),
    # Longer than a minute is no longer a grace period but a second token.
    "session_rotation_grace_sec": (0, 60),
    # A confirmation link is a key to the account — longer than a week is no longer a deadline.
    "email_change_ttl_min": (5, 7 * 24 * 60),
    # 0 = no deadline. Ten years is the utmost that is still a deadline.
    "oidc_apikey_confirm_days": (0, 3660),
    "session_idle_minutes": (0, 365 * 24 * 60),
    "session_idle_minutes_remember": (0, 365 * 24 * 60),
    # -1 = unlimited (behaviour up to 0.20.x), 0 = only explicitly. Below that no value is meant;
    # ten years is the utmost that is still a deadline.
    "federation_name_binding_days": (-1, 3660),
    # Lifetime of the gate token (ADR-9) = revocation delay at the proxy. Below 30 s the proxy asks almost
    # as often as without a token; above an hour a revocation comes too late to be one.
    "gate_token_ttl_sec": (30, 3600),
    # OAuth (T-36): an access token is checked per request anyway; a day is the most that makes sense.
    "oauth_access_token_ttl_sec": (60, 86400),
    "oauth_refresh_idle_days": (1, 3650),
    "oauth_refresh_max_days": (0, 3650),
    "oauth_refresh_grace_sec": (0, 60),
    # Services (T-60): they ask again for a token at no cost, so an hour is the most; a pairing code is typed
    # in right after issuing it.
    "oauth_service_token_ttl_sec": (60, 3600),
    "oauth_service_key_days": (0, 3650),
    "oauth_pairing_minutes": (1, 60),
    # Pairing consent (ADR-14): the window in which a local process could take the armed consent first — an hour at
    # most; below a minute nobody runs the setup script.
    "oauth_pairing_consent_minutes": (1, 60),
    # Approvals (stage A): a request waits minutes, not hours — a link that stays valid for a day is one more link
    # lying around; below two minutes nobody can open it, step up and decide.
    "approval_pending_sec": (120, 1800),
    "approval_open_per_account": (1, 50),
    "approval_open_per_token": (1, 50),
    "approval_requests_per_hour": (1, 500),
    "approval_reject_limit": (1, 20),
    # Stage B (application actions): a confirmed action waits minutes for its pickup; the confirmation itself lives at
    # most five minutes — it carries one action, once (`approval_token.MAX_LIFETIME`).
    "approval_pickup_sec": (60, 900),
    "approval_token_ttl_sec": (30, 300),
    "approval_app_requests_per_hour": (1, 10000),
    # Waiting time on the "Signed out" page before it leads back to the application. Above five minutes
    # nobody waits any more, for that there is 0 (leave standing).
    "forward_logged_out_sec": (0, 300),
}


def _number_limits(config, error: list) -> None:
    for slot, (below, above) in NUMBER_LIMITS.items():
        if not hasattr(config, slot):
            error.append(_t(
                config,
                "The configuration check names the field {field!r}, which does not exist in "
                "TinySesamConfig — a bug in TinySesam itself.",
                field=slot))
            continue
        value = getattr(config, slot)
        # bool is an int: `session_ttl_hours=True` would mean one hour, which was never intended.
        if isinstance(value, bool) or not isinstance(value, int):
            error.append(_t(
                config,
                "{field}={value!r} is not an integer.",
                field=slot, value=value))
            continue
        if not below <= value <= above:
            error.append(_t(
                config,
                "{field}={value} is outside {lo}…{hi}. The most common reason is a mixed-up "
                "unit (the field name states it).",
                field=slot, value=value, lo=below, hi=above))


def _proxies_and_passkey(config, error: list, warnings: list) -> None:
    # --- trusted_proxies (B3-3) ---
    # An invalid entry raised at runtime in the middle of the check and invalidated the WHOLE
    # list; the warning afterwards advised entering the proxy network that was long there. A
    # hostname is the most common case — proxies are given here as a network, not as a name.
    bad = security.invalid_networks(getattr(config, "trusted_proxies", None) or [])
    if bad:
        error.append(_t(
            config,
            "trusted_proxies contains entries that are not an IP network: {bad}. Expected are "
            "addresses or networks like '203.0.113.5' or '198.51.100.0/24' — no hostnames. An "
            "invalid entry must not be read along: it would otherwise decide whether the proxy "
            "counts as trustworthy.",
            bad=bad))

    # --- WebAuthn: rp_id and origin (B3-10) ---
    # Both fields carry developer values as default (`localhost`, `http://localhost:8000`).
    # Forgotten in production, EVERY passkey ceremony fails — only in the browser, with a message
    # that looks like a problem of the authenticator. What is checked is what can be proven without the
    # outside world: form, matching, and the comparison with `base_url`.
    if not _an(config, "passkey_enabled"):
        return
    from urllib.parse import urlsplit
    rp_id = str(getattr(config, "rp_id", "") or "").strip().lower()
    raw = getattr(config, "origin", "")
    raw = "" if raw is None else raw
    # py_webauthn also accepts a list as `expected_origin` (A5): whoever serves the sign-in page under
    # several names enters them all. Each entry is then checked individually —
    # `str(list)` is never an origin, and so a working config became an error.
    origins = [str(o).strip() for o in raw] if isinstance(raw, (list, tuple)) else [str(raw).strip()]
    if not origins:
        error.append(_t(
            config,
            "origin is an empty list — at least one origin like \"https://auth.example.com\" "
            "must be there, otherwise every passkey fails."))
        return
    hosts = []
    for origin in origins:
        parts = urlsplit(origin)
        host = (parts.hostname or "").lower()
        if parts.scheme not in ("http", "https") or not host or parts.path not in ("", "/") \
                or parts.query or parts.fragment or origin.endswith("/"):
            error.append(_t(
                config,
                "origin={origin!r} is not an origin. Required is exactly scheme, host and "
                "optionally port (\"https://auth.example.com\"), without a path and without a "
                "trailing slash — the browser compares character by character.",
                origin=origin))
            return
        hosts.append(host)
    if not rp_id or "://" in rp_id or ":" in rp_id or "/" in rp_id:
        error.append(_t(
            config,
            "rp_id={rp!r} must be a hostname without scheme and port, e.g. "
            "\"auth.example.com\" or the domain above it (\"example.com\").",
            rp=rp_id))
    else:
        for origin, host in zip(origins, hosts):
            if not (host == rp_id or host.endswith("." + rp_id)):
                error.append(_t(
                    config,
                    "rp_id={rp!r} does not match origin={origin!r}: the rp_id must be the host "
                    "of the origin or a domain above it. Every browser rejects the passkey "
                    "ceremony that way.",
                    rp=rp_id, origin=origin))
    base = security.normalize_base(str(getattr(config, "base_url", "") or "").strip())
    if base:
        b = urlsplit(base)
        should = f"{b.scheme}://{b.netloc}"
        if should.lower() not in [o.lower() for o in origins]:
            # Warning, not error: whoever serves the sign-in page under a second name of their own
            # (base_url only for the mail links) may want it that way.
            display = origins[0] if len(origins) == 1 else origins
            warnings.append(_t(
                config,
                "origin={shown!r} differs from base_url ({base}). The login page runs under "
                "base_url, and the browser reports exactly this origin — with the value here "
                "every passkey fails. Usually the development default is still in place here.",
                shown=display, base=should))
    elif all(h in ("localhost", "127.0.0.1", "::1") for h in hosts) and rp_id == "localhost":
        warnings.append(_t(
            config,
            "passkey_enabled=True with the developer values rp_id={rp!r}, origin={origin!r}. "
            "Outside your own machine every passkey fails with them — in production set both "
            "to the public address (and base_url as well).",
            rp=rp_id, origin=raw))


#: What may appear in `stepup_methods`, and which switch turns the method on.
STEPUP_PROCEDURE = {"totp": "totp_enabled", "pin": "pin_enabled", "password": "password_enabled"}


def _stepup(config, error: list, warnings: list) -> None:
    # B3-6: `stepup_methods` is a wish, and a wish that does not exist is silently
    # passed over — `["topt"]` fell back to "everything the user has", that is, to the password
    # with which they had just signed in. The second factor before the sensitive area was gone,
    # and nothing said so. With `stepup_strict=True` it was the other way round: nobody ever got in.
    wished = [str(m) for m in (getattr(config, "stepup_methods", None) or [])]
    unknown = [m for m in wished if m not in STEPUP_PROCEDURE]
    if unknown:
        error.append(_t(
            config,
            "stepup_methods names {names} — those are not step-up methods. Allowed are "
            "{allowed}. An unknown name is not skipped but rejected: skipped, the confirmation "
            "would fall back to the password.",
            names=unknown, allowed=sorted(STEPUP_PROCEDURE)))
    from_ = [m for m in wished if m in STEPUP_PROCEDURE and not _an(config, STEPUP_PROCEDURE[m])]
    if from_:
        error.append(_t(
            config,
            "stepup_methods requires {names}, but {switches}. This wish can never be fulfilled "
            "— without stepup_strict the confirmation silently falls back to another method, "
            "with stepup_strict the area stays closed.",
            names=from_, switches=", ".join(f"{STEPUP_PROCEDURE[m]}=False" for m in from_)))
    # T-45 (ASVS 7.5.3/8.4.2): the panel can set passwords, issue sign-in links for any account and
    # grant admin rights. Since H2 it asks for a fresh confirmation by default; whoever turns that off
    # should know what an old admin session can then do.
    if _an(config, "admin_enabled") and getattr(config, "admin_require_mfa", True) is False:
        warnings.append(_t(
            config,
            "admin_require_mfa=False: the admin panel (and require_admin) work from any old admin "
            "session without a fresh confirmation — such a session sets passwords, issues sign-in "
            "links for any account and grants admin rights. Leave it on (the default) unless another "
            "layer asks again."))
    if _an(config, "stepup_strict") and not wished:
        warnings.append(_t(
            config,
            "stepup_strict=True without stepup_methods has no effect: the barrier applies only "
            "to named methods. Probably e.g. stepup_methods=['totp'] was meant."))


def _open_gates(config, warnings: list) -> None:
    """Deny-by-default for the gate in front of foreign applications (H-11, B3-9).

    Forward auth answers "through" for every signed-in session — without `?roles=` at the proxy
    it is therefore enough to HAVE an account. Where accounts come from thus decides the circle:
    if an IdP path creates accounts itself and no group limits it, every account at the provider is
    a key to every protected application; with open registration, every visitor.

    Warning, not error: this is exactly how a gateway in front of a provider with its own, closed
    user circle is meant, and the approval per application may also lie with the provider
    (`oidc_clients`, T-14). An error would mean forbidding this setup — deciding that
    would be a new switch (a deliberate "all"), not a check.
    """
    if not _an(config, "forward_auth_enabled"):
        return
    unclosed = []
    for an, create, groups, name in (("oidc_enabled", "oidc_auto_create", "oidc_allowed_groups", "OIDC"),
                                       ("saml_enabled", "saml_auto_create", "saml_allowed_groups", "SAML"),
                                       ("ldap_enabled", "ldap_auto_create", "ldap_allowed_groups", "LDAP")):
        if not (_an(config, an) and _an(config, create)) or getattr(config, groups, None):
            continue
        if name == "OIDC" and getattr(config, "oidc_clients", None):
            # One client of its own per application (T-14): the approval lies with the provider, and
            # `/auth/forward` checks it per host. That is a closed gate — just one
            # whose key the provider manages.
            continue
        unclosed.append(f"{name} ({create}=True, {groups} empty)")
    if unclosed:
        warnings.append(_t(
            config,
            "Forward auth with an open gate: {items}. Every account at the provider is created "
            "at the first login and then gets through EVERY protected application that does "
            "not require ?roles= at the proxy. Limit the circle: set *_allowed_groups (for the "
            "gateway TINYSESAM_ALLOWED_GROUPS), require ?roles= at the proxy, or regulate the "
            "approval per application at the provider (oidc_clients).",
            items="; ".join(unclosed)))
    if _an(config, "allow_signup") and not _an(config, "signup_invite_only"):
        warnings.append(_t(
            config,
            "Forward auth with open self-registration: every visitor creates an account and "
            "thereby gets through every protected application that does not require ?roles= at "
            "the proxy. signup_invite_only=True, allow_signup=False or require roles at the "
            "proxy."))


#: Providers that deliver the group claim without a scope of their own and
#: REJECT an unknown scope: Entra ID takes `groups` as a Graph API permission and aborts the sign-in
#: (AADSTS650053 "scope 'groups' that doesn't exist"; the groups come there via "optional
#: claims" of the app registration). The advice "add `groups` to
#: oidc_scopes" would be wrong there, the warning a permanent false alarm for the `entra_id` preset.
_GROUPS_WITHOUT_SCOPE = ("login.microsoftonline.com",)


def _groups_scope(config, warnings: list) -> None:
    """Group rule via the claim `groups`, but the scope `groups` is not requested.

    Finding from operation (2026-09-27): PocketID — and other providers that tie claims to
    scopes — sends the claim `groups` only if the client asks for the scope `groups`. Without
    it `oidc_allowed_groups` rejects everyone ("no matching group", in the audit
    `oidc_group_denied`), and `oidc_group_role_map` silently assigns no role. The default
    `oidc_scopes="openid profile email"` does not request it.

    Warning, not error, and no silent re-requesting: other providers (Keycloak, Authentik)
    deliver the claim via a mapper without a scope of their own, and some reject a scope
    they do not know — TinySesam cannot read that from the configuration. The check is done
    per client: the single client with `oidc_scopes`, each application from `oidc_clients` with its
    own `scopes` (otherwise `oidc_scopes`) and its group rule (otherwise the global one), exactly
    as `OIDCClients` composes them. SAML and LDAP have no counterpart: there are no
    scopes there, whether the IdP releases the group attribute is in ITS configuration.
    """
    if not _an(config, "oidc_enabled"):
        return
    if str(getattr(config, "oidc_group_claim", "") or "").strip() != "groups":
        return
    from urllib.parse import urlsplit
    try:
        idp = (urlsplit(str(getattr(config, "oidc_issuer", "") or "").strip()).hostname or "").lower()
    except ValueError:
        idp = ""
    if idp in _GROUPS_WITHOUT_SCOPE:
        return
    global_groups = list(getattr(config, "oidc_allowed_groups", None) or [])
    global_map = dict(getattr(config, "oidc_group_role_map", None) or {})
    global_scopes = str(getattr(config, "oidc_scopes", "") or "")

    def without_scope(scopes) -> bool:
        return "groups" not in str(scopes or "").split()

    affected = []
    if (global_groups or global_map) and without_scope(global_scopes):
        affected.append(f"oidc_scopes={global_scopes!r}")
    for host, entry in (getattr(config, "oidc_clients", None) or {}).items():
        e = dict(entry or {})
        rule = e.get("allowed_groups") or global_groups or e.get("group_role_map") or global_map
        scopes = e.get("scopes") or global_scopes
        if rule and without_scope(scopes):
            affected.append(f"oidc_clients[{host!r}] (scopes={str(scopes)!r})")
    if affected:
        warnings.append(_t(
            config,
            "Group rule via the claim 'groups' (oidc_allowed_groups or oidc_group_role_map), "
            "but the scope 'groups' is not requested: {affected}. PocketID and other providers "
            "send the claim only with this scope — then oidc_allowed_groups rejects EVERYONE, "
            "and oidc_group_role_map assigns no role. Add 'groups' to oidc_scopes (gateway: "
            "TINYSESAM_OIDC_SCOPES; per application `scopes` in the oidc_clients entry). If "
            "the provider delivers the claim without a scope of its own (mapper, e.g. with "
            "Keycloak), this warning is moot.",
            affected="; ".join(affected)))


def _oauth(config, error: list, warnings: list) -> None:
    """OAuth 2.1 authorization server (T-36, ADR-11): the resource side is forward auth, the issuer is base_url."""
    if not _an(config, "oauth_enabled"):
        return
    from urllib.parse import urlsplit
    from . import oauth as _oauth_mod
    if not _an(config, "forward_auth_enabled"):
        error.append(_t(
            config,
            "oauth_enabled=True without forward_auth_enabled=True: the access token is checked in "
            "/auth/forward — without it no application accepts the tokens."))
    base = security.normalize_base(str(getattr(config, "base_url", "") or "").strip())
    if not base:
        error.append(_t(
            config,
            "oauth_enabled=True without base_url: base_url is the issuer of the tokens (RFC 8414) and the "
            "address of the sign-in — it must be fixed, never taken from a request."))
    if not _an(config, "csrf_enabled"):
        error.append(_t(
            config,
            "oauth_enabled=True with csrf_enabled=False: the consent page needs the CSRF protection — "
            "otherwise a foreign page could allow a device in the name of the signed-in person."))
    resources = list(getattr(config, "oauth_resources", None) or [])
    if not resources:
        error.append(_t(
            config,
            "oauth_enabled=True, but oauth_resources is empty: tokens are issued only for a known "
            "resource (e.g. [\"https://app.example.com/mcp\"]) — without one every request is refused."))
    own = _oauth_mod.normalize_resource(base) if base else None
    own_origin = "/".join(own.split("/", 3)[:3]) if own else ""
    for r in resources:
        n = _oauth_mod.normalize_resource(r)
        if n is None:
            error.append(_t(
                config,
                "oauth_resources: {value!r} is no absolute http(s) URL without query and fragment.",
                value=r))
            continue
        host = (urlsplit(n).hostname or "").lower()
        if n.startswith("http://") and not _is_loopback(host):
            error.append(_t(
                config,
                "oauth_resources: {value!r} uses http — tokens would travel in clear text. Use https "
                "(a certificate with an IP SAN works without a domain).",
                value=r))
        if own_origin and "/".join(n.split("/", 3)[:3]) == own_origin:
            error.append(_t(
                config,
                "oauth_resources: {value!r} lies on the address of TinySesam itself — a resource is an "
                "application behind forward auth, not the authorization server.",
                value=r))
    max_days = _integer(config, "oauth_refresh_max_days", None)
    if max_days == 0:
        warnings.append(_t(
            config,
            "oauth_refresh_max_days=0: a connected device stays connected as long as it is used, without "
            "an absolute maximum. ASVS 5.0 V10.4.8 (level 2) asks for one; the default is 180 days."))
    if _an(config, "oauth_service_clients") and _integer(config, "oauth_service_key_days", None) == 0:
        warnings.append(_t(
            config,
            "oauth_service_key_days=0: a service key never expires — a copied key file stays usable until someone "
            "revokes the service. With a lifetime the reference client rotates the key on its own."))


def _oauth_services_without_oauth(config, error: list) -> None:
    """Services (T-60) are a grant type of the OAuth server — without it there is no token endpoint."""
    if _an(config, "oauth_service_clients") and not _an(config, "oauth_enabled"):
        error.append(_t(
            config,
            "oauth_service_clients=True without oauth_enabled=True: services get their tokens from the OAuth "
            "server — switch it on (with base_url, forward_auth_enabled and oauth_resources)."))


def _oauth_pairing_consent_without_oauth(config, error: list) -> None:
    """The pairing consent (ADR-14) arms a consent of the OAuth server — without it there is nothing to arm."""
    if _an(config, "oauth_pairing_consent_enabled") and not _an(config, "oauth_enabled"):
        error.append(_t(
            config,
            "oauth_pairing_consent_enabled=True without oauth_enabled=True: the pairing code arms one consent of the "
            "OAuth server — switch it on (with base_url, forward_auth_enabled and oauth_resources)."))


#: Where container and service managers put secrets — mode and directory are theirs, not the operator's choice
#: (Docker/Podman `secrets:`, systemd `LoadCredential=`).
_SECRET_MOUNTS = ("/run/secrets/", "/run/credentials/")


def _keys(config, warnings: list) -> None:
    """Key files (T-48, ADR-12): not readable by others, not beside the database, and no gate key that the data
    directory alone gives away. Only what the configuration and the file system show — the keyring in the
    database (a key still derived from the vault key) is reported by the start itself."""
    from . import keys as _keys_mod
    db = str(getattr(config, "db_path", "") or "")
    db_dir = os.path.dirname(os.path.abspath(db)) if db and db != ":memory:" else ""
    in_use = []
    for purpose, field in _keys_mod.FILE_FIELD.items():
        if os.environ.get(_keys_mod.ENV[purpose], "").strip():
            continue
        path = str(getattr(config, field, "") or "").strip()
        if path:
            in_use.append((field, path, True))
        elif purpose == _keys_mod.VAULT and db_dir:
            in_use.append(("vault key", db + ".key", False))
    for field, path, configured in in_use:
        absolute = os.path.abspath(path)
        if absolute.startswith(_SECRET_MOUNTS):
            continue
        try:
            mode = os.stat(path).st_mode & 0o777
        except OSError:
            mode = None          # missing: the start says so (a configured one), or creates it (beside the db)
        if mode is not None and mode & 0o077:
            warnings.append(_t(
                config,
                "{field}={path!r} is readable or writable by group or others (mode {mode}). It holds key material: "
                "chmod 600, owned by the service's user.",
                field=field, path=path, mode=f"{mode:04o}"))
        if configured and db_dir and os.path.dirname(absolute) == db_dir:
            warnings.append(_t(
                config,
                "{field}={path!r} lies in the database's directory — a backup or copy of that directory carries the "
                "key together with the data it protects. Keep it elsewhere (docs/OPERATIONS.md \"Keys\").",
                field=field, path=path))
    vault_beside = any(not configured for _f, _p, configured in in_use)
    gate_own = bool(os.environ.get(_keys_mod.ENV[_keys_mod.GATE], "").strip()
                    or str(getattr(config, "gate_key_file", "") or "").strip())
    if _an(config, "gate_token_enabled") and vault_beside and not gate_own:
        warnings.append(_t(
            config,
            "gate_token_enabled=True, the vault key is {path!r} next to the database, and the gate key is kept in the "
            "database encrypted with it: whoever can read the data directory can mint gate tokens for every account. "
            "Put TINYSESAM_SECRETS_KEY or secrets_key_file elsewhere, or give the gate key a place of its own "
            "(TINYSESAM_GATE_KEY, gate_key_file).",
            path=db + ".key"))


def _combinations(config, error: list, warnings: list) -> None:
    """Combinations that are allowed individually and together do not do what they say (B3-16)."""
    # E-mail confirmation without a mandatory address: whoever leaves the field empty gets an IMMEDIATELY
    # active account — the confirmation applies only to those who give an address. The barrier
    # thus has a door next to it.
    if _an(config, "allow_signup") and _an(config, "signup_verify_email") \
            and not _an(config, "signup_require_email"):
        error.append(_t(
            config,
            "signup_verify_email=True, but signup_require_email=False: whoever gives no "
            "address at registration is active immediately without any confirmation. Either "
            "signup_require_email=True or do without the confirmation."))
    # ASVS 6.3.8 (B1-12): without confirmation a free registration signs in immediately, a
    # taken address answers with 409 — the difference cannot be hidden, and
    # everyone learns which addresses have an account here. With confirmation both answer
    # the same (R4-03), at runtime too.
    if _an(config, "allow_signup") and not _an(config, "signup_invite_only") \
            and not _an(config, "signup_verify_email") \
            and (_an(config, "signup_require_email") or getattr(config, "login_identifier", "") == "email"):
        warnings.append(_t(
            config,
            "Open registration without signup_verify_email: a taken address answers with 409, "
            "a free one signs in immediately — every visitor thus learns which addresses have "
            "an account here (ASVS 6.3.8). With signup_verify_email=True both answer the same."))
    if _an(config, "signup_invite_only") and not _an(config, "allow_signup"):
        warnings.append(_t(
            config,
            "signup_invite_only=True without allow_signup=True has no effect — registration is "
            "off anyway."))
    # Via `_integer` like every combination (tests/test_security_findings.py checks that): text,
    # inf, nan and True are reported by `_number_limits`; here the combination then stays unevaluated.
    lang = _integer(config, "session_ttl_hours", None)
    short = _integer(config, "session_ttl_transient_hours", None)
    if lang is not None and short is not None and short > lang:
        warnings.append(_t(
            config,
            "session_ttl_transient_hours={short} is longer than session_ttl_hours={long}: "
            "without \"Stay signed in\" one would stay signed in longer than with it.",
            short=short, long=lang))
    for slot in ("admin_path", "login_path", "oidc_callback_path"):
        value = str(getattr(config, slot, "") or "")
        if value and not value.startswith("/"):
            error.append(_t(
                config,
                "{field}={value!r} must begin with '/' — otherwise it is no path, and routes "
                "as well as links point nowhere.",
                field=slot, value=value))
    # cookie_domain that does not cover the own host: the browser discards the cookie, every
    # sign-in "works" and the next click is the login page again.
    dom = str(getattr(config, "cookie_domain", "") or "").strip().lower().lstrip(".")
    base = security.normalize_base(str(getattr(config, "base_url", "") or "").strip())
    if dom and base:
        from urllib.parse import urlsplit
        host = (urlsplit(base).hostname or "").lower()
        if host and not (host == dom or host.endswith("." + dom)):
            error.append(_t(
                config,
                "cookie_domain={domain!r} does not cover the host of base_url ({host}). The "
                "browser discards a cookie for a foreign domain — nobody would stay signed in.",
                domain=getattr(config, 'cookie_domain'), host=host))
    # Demo mode next to a real sign-in path (B3-8): the demo accounts have a known
    # password, one is admin. Next to OIDC/SAML/LDAP that is no demo any more, but a
    # production instance with a back door.
    if _an(config, "demo_mode"):
        real = [slot for slot in ("oidc_enabled", "saml_enabled", "ldap_enabled", "forward_auth_enabled")
                if _an(config, slot)]
        if real:
            error.append(_t(
                config,
                "demo_mode=True together with {real}: the demo creates an admin account with a "
                "known password. Next to a real login path or in front of foreign applications "
                "that is a back door, not a demonstration.",
                real=', '.join(real)))


# The rules by feature (T-112): split into parts, every name re-exported here.
from ._config_check_roles import (  # noqa: E402
    DELEGATE_ACTIONS,
    _DELEGATE_KEYS,
    _admin_delegates,
    _mapped_roles,
    _role_level_ladders,
    _role_names,
    _roles_without_list,
    _strings,
    app_visible,
    configured_roles,
    delegate_may_manage,
    delegate_scopes,
    delegation_graph,
    ladder_coverage,
    may_manage,
)
from ._config_check_apps import (  # noqa: E402
    APPROVAL_FIELD,
    APPROVAL_FIELDS_MAX,
    APPROVAL_FIELD_KEYS,
    APPROVAL_FINDINGS,
    APPROVAL_INT_LIMIT,
    APPROVAL_KEYS,
    APPROVAL_PATTERN_MAX,
    APPROVAL_RETURN_URLS_MAX,
    APPROVAL_STRING_MAX,
    APPROVAL_SUMMARY_MAX,
    APPROVAL_TITLE_MAX,
    APPROVAL_TYPE,
    APPROVAL_TYPES_MAX,
    APPROVAL_TYPE_KEYS,
    APPROVAL_TYPE_MAX,
    APPROVAL_URL_MAX,
    APP_ID,
    APP_KEYS,
    FORWARD_APP_KEY_NAME,
    FORWARD_FRAME_KEYS,
    FORWARD_FRAME_LINKS_MAX,
    FORWARD_LOGIN,
    FORWARD_LOGOUT,
    LINK_NEXT_MAX,
    PROVISIONING_DEFAULTS,
    PROVISIONING_GRACE_MAX,
    PROVISIONING_KEYS,
    PROVISIONING_LIMITS,
    PROVISIONING_LIMIT_MAX,
    PROVISIONING_MAX_ACCOUNTS,
    PROVISIONING_SCOPES,
    TOTP_APP_HINT_LANGS,
    TOTP_APP_HINT_MAX,
    _LANG,
    _LANG_TAG,
    _PREFIX_MARK,
    _app_approvals,
    _approvals,
    _approver_roles,
    _apps,
    _bad_text,
    _delegates_and_app_allowlists,
    _first_sign_in,
    _forward_apps,
    _forward_frame,
    _forward_frame_default,
    _gate,
    _placeholders,
    _plain_int,
    approval_return_url_ok,
    approval_type_findings,
    link_next_ok,
    read_approval_types_file,
    totp_app_hint_ok,
)
from ._config_check_de import (  # noqa: E402
    _DE,
)
