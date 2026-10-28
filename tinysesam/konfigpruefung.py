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

from . import security

#: Method → which config field switches it on. The same list serves the chain check.
VERFAHREN = {
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
#: (`TinySesam._IDENTIFYING`) plus `totp`. Deliberately NOT `VERFAHREN` — that also holds
#: `ldap` (writes the factor `password`) and `apikey` (never becomes a factor).
KETTENSCHRITTE = frozenset({"password", "pin", "oidc", "passkey", "magic", "saml", "totp"})

#: Methods with which a human can SIGN IN. `apikey` does not count: a key is issued
#: by an account, which has to exist first.
ANMELDEND = ("password", "pin", "passkey", "oidc", "saml", "ldap", "magic")

#: Method → fields without which it cannot work.
PFLICHTFELDER = {
    "oidc": ("oidc_issuer", "oidc_client_id"),
    "saml": ("saml_idp_sso_url", "saml_idp_x509cert"),
    "ldap": ("ldap_url",),
}

#: What needs a mailer. Not an error — `set_mailer` often comes later.
BRAUCHT_MAILER = {
    "magiclink_enabled": "Magic-Link-Anmeldung",
    "password_reset_enabled": "„Passwort vergessen\"",
    "signup_verify_email": "E-Mail-Bestätigung bei der Registrierung",
}

#: What hands an **absolute** address to third parties — the link in a mail to a mailbox,
#: the redirect URI at the IdP, the entity ID in SAML metadata. Without `base_url` only
#: the `Host` header would remain for it, and the requester sets that (R4-01). These switches make `base_url`
#: **mandatory**: without it construction fails, not only the first sign-in attempt.
BRAUCHT_BASE_URL = {
    "magiclink_enabled": "Magic-Link und Einladung (Link in der Mail)",
    "password_reset_enabled": "„Passwort vergessen\" (Reset-Link in der Mail)",
    "signup_verify_email": "E-Mail-Bestätigung (Bestätigungslink in der Mail)",
    "oidc_enabled": "OIDC (Redirect-URI zum IdP)",
    "saml_enabled": "SAML (Entity-ID und ACS-URL)",
}

#: The same thought, but only a warning: the forward-auth redirect sends the **same**
#: browser to its own login page. Without a checked base it stays relative (`/auth/login?…`)
#: and the browser resolves it against the requested host — that works as long as app and
#: TinySesam live under one name. A foreign name does not get into the redirect this way, nothing
#: goes out to third parties, and therefore this is no reason to refuse to start.
BASE_URL_EMPFOHLEN = {
    "forward_auth_enabled": "Forward-Auth (Umleitung des Proxys auf die Login-Seite)",
}


def _ist_ip(wert: str) -> bool:
    import ipaddress
    try:
        ipaddress.ip_address(wert)
        return True
    except ValueError:
        return False


def _an(config, feld: str) -> bool:
    return bool(getattr(config, feld, False))


def _ganzzahl(config, feld: str, fehlt: int | None = 0):
    """Read a number field for a combination check — or None if it is not an integer.

    Type and range are reported by `_zahlengrenzen` (including `True`, text, `inf`, `nan`); the combination
    is then not evaluated. An `int()` on the raw value crashed the whole check
    before the type message came, and `TinySesam(cfg)` raised ValueError/OverflowError instead of a
    collected ConfigError (second attack round, config)."""
    wert = getattr(config, feld, fehlt)
    if wert is None:
        return fehlt
    if isinstance(wert, bool) or not isinstance(wert, int):
        return None
    return wert


#: The directives a Content-Security-Policy knows (CSP Level 3 plus the common
#: legacy ones). A custom policy needs at least one of them; every other one gives a warning.
CSP_DIREKTIVEN = frozenset({
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src",
    "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
    "fenced-frame-src", "base-uri", "form-action", "frame-ancestors", "navigate-to", "sandbox",
    "upgrade-insecure-requests", "block-all-mixed-content", "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types", "webrtc", "plugin-types", "referrer",
})


def _csp_namen(wert) -> list[str] | None:
    """The directive names of a custom policy, lower-cased — None for 'strict'/'off'/empty."""
    if not isinstance(wert, str):
        return None
    roh = wert.strip()
    if roh in ("", "strict", "off"):
        return None
    return [teil.split()[0].lower() for teil in roh.split(";") if teil.strip()]


def csp_fehler(wert) -> str:
    """The finding for `csp`, empty if fine (B3-2).

    Everything except 'strict' and 'off' went unchecked 1:1 into the header up to 0.19.0. A typo
    like 'Strict' or 'stirct' thus was a "custom policy" without a single directive — the
    browser discards such a header, and the pages ran **without any CSP**, without anyone
    noticing. An error is therefore only the policy without a **single** known
    directive. If an unknown one stands next to known ones, the browser skips only it and applies
    the rest — that is `csp_warnung` (A3: `require-sri-for`, `disown-opener` otherwise kept a
    previously working policy from starting).
    """
    namen = _csp_namen(wert)
    if namen is None:
        return ""                  # the constructor reports a non-string separately
    roh = wert.strip()
    if roh.lower() in ("strict", "off"):
        return (f"csp={wert!r} — gemeint ist wohl {roh.lower()!r} (klein geschrieben). So wäre es "
                "eine eigene Policy ohne Direktive, und der Browser liefe ohne jede CSP.")
    if not any(n in CSP_DIREKTIVEN for n in namen):
        return (f"csp={wert!r} ist weder 'strict' noch 'off' noch eine Policy mit einer bekannten "
                "Direktive. Der Browser verwirft so einen Header, und die Seiten liefen ohne jede "
                "CSP.")
    return ""


def csp_warnung(wert) -> str:
    """Unknown directives next to known ones: not an error, but probably a typo.

    The browser applies the policy without them. With 'scirpt-src', `default-src` then applies instead of
    the intended rule — that should be in the log. A real directive that is merely not listed here
    passes just the same.
    """
    namen = _csp_namen(wert)
    if not namen or csp_fehler(wert):
        return ""
    unbekannt = [n for n in namen if n not in CSP_DIREKTIVEN]
    if not unbekannt:
        return ""
    return (f"csp={wert!r} enthält Direktiven, die TinySesam nicht kennt: {', '.join(unbekannt)}. "
            "Der Browser überspringt, was er nicht kennt, und wendet den Rest an — bei einem "
            "Tippfehler gilt die gemeinte Regel also nicht.")


def pruefe(config) -> tuple[list[str], list[str]]:
    """(errors, warnings) — both complete, not aborted at the first finding."""
    fehler: list[str] = []
    warnungen: list[str] = []

    # Background images (0.24.8): an address lands in a CSS url() — a quote or a parenthesis would be
    # a breakout from the stylesheet. Here and not only at the router, so render_page() is protected without a router too.
    for b in getattr(config, "brand_backgrounds", None) or []:
        if not isinstance(b, str) or not b or any(z in b for z in "'\"()\\<> \t\n"):
            fehler.append(f"brand_backgrounds: {b!r} — eine Adresse ohne Anführungszeichen, Klammern, Backslash "
                          f"und Leerzeichen (sie landet in einer CSS-url())")
        elif not (b.startswith("/") and not b.startswith("//")) and not b.startswith(("https://", "data:image/")):
            fehler.append(f"brand_backgrounds: {b!r} — erlaubt sind /pfad, data:image/… und https://…")
    _ziel = getattr(config, "brand_background_credit_url", "")
    if _ziel and not str(_ziel).startswith(("https://", "http://")):
        fehler.append("brand_background_credit_url: nur http(s)-Adressen")

    # Cookie prefix (0.24.12): the start of a cookie name, no `__` (`__Host-`/`__Secure-` reserve that), and a gateway
    # stays at `tinysesam_` — the proxy templates strip its session in front of the app only under that name.
    _praefix = getattr(config, "cookie_prefix", "tinysesam_")
    if not isinstance(_praefix, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,31}", _praefix):
        fehler.append(f"cookie_prefix={_praefix!r}: 1–32 Zeichen aus Buchstaben, Ziffern, _ und -, am Anfang ein "
                      f"Buchstabe oder eine Ziffer (z. B. \"meineapp_\")")
    elif _an(config, "forward_auth_enabled") and not _praefix.startswith("tinysesam_"):
        fehler.append(f"cookie_prefix={_praefix!r} mit forward_auth_enabled=True: Die Proxy-Vorlagen entfernen nur "
                      f"tinysesam_*-Cookies vor der App — die Sitzung dieses Gateways käme dann bei jeder geschützten "
                      f"App an. Ein Gateway bleibt bei cookie_prefix=\"tinysesam_\"; das Präfix ist für die App dahinter.")


    # `enabled_methods()` is asked — the same list from which the login page
    # builds its fields. A second list of its own here had exactly the error it is meant to catch: it saw
    # `pin_enabled=True` and overlooked `pin_login=False`, and thereby let an empty login page
    # through (PIN only as step-up is the documented way, not an exotic value).
    try:
        aktive = list(config.enabled_methods())
    except Exception:
        aktive = [name for name in ANMELDEND if _an(config, VERFAHREN[name])]
    if not aktive:
        # `ldap_enabled=True` is NOT in the remedy (F-30): LDAP is not a field of its own on
        # the login page, but checks the password form against the directory. The message
        # named it anyway — and whoever followed it got the same message again.
        fehler.append(
            "Keine einzige Anmelde-Methode ist eingeschaltet — die Login-Seite hätte kein "
            "einziges Feld, niemand kann sich anmelden. Mindestens eines von: "
            + ", ".join(f"{VERFAHREN[n]}=True" for n in ANMELDEND if n != "ldap")
            + " (bei PIN zusätzlich pin_login=True, sonst ist sie nur Step-up). LDAP allein "
            "genügt nicht: ldap_enabled=True prüft das Passwortformular gegen das Verzeichnis "
            "und braucht deshalb password_enabled=True.")
    if _an(config, "ldap_enabled") and not _an(config, "password_enabled"):
        # Warning, not error: with a second method (OIDC, passkey) construction starts
        # sensibly — only the LDAP path is dead then, and the operator should know.
        warnungen.append(
            "ldap_enabled=True, aber password_enabled=False. LDAP hat kein eigenes Formular, es "
            "prüft das Passwortfeld der Login-Seite gegen das Verzeichnis — ohne "
            "password_enabled=True meldet sich niemand über LDAP an.")

    # Warning, not error: the clients for OIDC, SAML and LDAP can be replaced
    # (`auth.ldap = own_client`), and the own suites work exactly that way. A hard
    # guard would thereby forbid a legitimate setup. It does not stay silent anyway — the
    # normal case "switched on and forgotten to configure" would otherwise only fail at the
    # first click on "Sign in".
    # A field name that does not exist at all would be the worst kind of false alarm: it fires on
    # EVERY configuration of the method and at the same time never checks what was meant. Exactly
    # that happened (`ldap_server` instead of `ldap_url`, and the field appeared in the whole repo only in
    # this line). Hence an assertion here instead of trust.
    unbekannt = sorted({f for felder in PFLICHTFELDER.values() for f in felder
                        if not hasattr(config, f)}
                       | {v for v in VERFAHREN.values() if not hasattr(config, v)}
                       | {f for f in BRAUCHT_MAILER if not hasattr(config, f)}
                       | {f for f in BRAUCHT_BASE_URL if not hasattr(config, f)}
                       | {f for f in BASE_URL_EMPFOHLEN if not hasattr(config, f)}
                       | {f for f in ("base_url", "trusted_redirect_hosts")
                          if not hasattr(config, f)})
    if unbekannt:
        fehler.append(
            f"Die Konfigurationsprüfung nennt Felder, die es in TinySesamConfig nicht gibt: "
            f"{unbekannt}. Das ist ein Fehler in TinySesam selbst — bitte melden.")

    for name, felder in PFLICHTFELDER.items():
        if not _an(config, VERFAHREN[name]):
            continue
        leer = [f for f in felder if not str(getattr(config, f, "") or "").strip()]
        if leer:
            warnungen.append(
                f"{VERFAHREN[name]}=True, aber {', '.join(leer)} ist leer. So kann das Verfahren "
                "nicht arbeiten und scheitert beim ersten Anmeldeversuch — es sei denn, der "
                "Client wird zur Laufzeit ersetzt.")

    # Side finding from the same audit (F-28): a service-account DN without password is not an
    # anonymous search, but a combination that ldap3 rejects on its own
    # (`LDAPPasswordIsMandatoryError`). The error is raised in the middle of the login and swallowed there
    # — the operator sees "wrong password" for EVERY user and looks at the
    # wrong end. Warning instead of error, because the client is replaceable at runtime.
    if _an(config, "ldap_enabled") and str(getattr(config, "ldap_bind_dn", "") or "").strip() \
            and not str(getattr(config, "ldap_bind_password", "") or "").strip():
        warnungen.append(
            "ldap_bind_dn ist gesetzt, ldap_bind_password ist leer. Das ist keine anonyme Suche: "
            "ldap3 lehnt DN ohne Passwort ab, der Fehler fällt erst beim Login an und sieht dort "
            "für jeden Nutzer wie ein falsches Passwort aus. Entweder das Passwort des "
            "Dienstkontos setzen oder ldap_bind_dn leeren (dann wird wirklich anonym gesucht).")

    # A chain step must be a factor that a session can actually get. `ldap` is
    # none (it writes the factor `password`), neither is `apikey` — both were in the
    # whitelist anyway, and `login_chain=["ldap","totp"]` is the most obvious spelling for an
    # LDAP operator. It led into exactly the loop this module warns about.
    kette = list(getattr(config, "login_chain", None) or [])
    unbekannt = [s for s in kette if s not in KETTENSCHRITTE]
    if unbekannt:
        hinweis = ""
        if "ldap" in unbekannt:
            hinweis = " — LDAP erfüllt den Schritt 'password', nicht 'ldap'"
        fehler.append(f"login_chain nennt Schritte, die kein Faktor sind: {unbekannt}{hinweis}. "
                      f"Erlaubt sind {sorted(KETTENSCHRITTE)}.")
    aus = [s for s in kette if s in VERFAHREN and not _an(config, VERFAHREN[s])]
    if aus:
        fehler.append(
            f"login_chain verlangt {aus}, aber " +
            ", ".join(f"{VERFAHREN[s]}=False" for s in aus) +
            " — die Kette ist unerfüllbar, niemand kommt über diesen Schritt hinaus.")
    if "totp" in kette and not _an(config, "totp_enabled"):
        fehler.append("login_chain verlangt 'totp', aber totp_enabled=False — unerfüllbar.")
    # A PIN behind another factor is, in a NON-strict chain with `pin_login`,
    # at the same time a first factor (`pin_as_first_factor`): whoever starts with it then satisfies the chain
    # with the password. Then anyone guesses the PIN without the password, and a self-service reset
    # clears these wrong guesses from the series (R2-2) — the configuration says "follow-up factor", the
    # behaviour "first factor" (G7). In a strict chain TinySesam closes the guest path itself.
    if ("pin" in kette and kette[0] != "pin" and _an(config, "pin_enabled")
            and _an(config, "pin_login") and not getattr(config, "login_chain_strict", True)):
        warnungen.append(
            f"login_chain={kette} mit login_chain_strict=False nennt 'pin' hinter einem anderen "
            "Faktor, und pin_login=True bietet die PIN zugleich als Erstfaktor an: Wer mit ihr "
            "beginnt, rät sie ohne das Passwort, und ein Selbstbedienungs-Reset räumt diese "
            "Fehlversuche aus der Serie (account_max_consecutive_failures). Soll die PIN nur "
            "Folgefaktor sein: pin_login=False — der PIN-Schritt nach dem ersten Faktor bleibt "
            "erreichbar.")

    # Here once stood "resource_locks_enabled needs pin_enabled". That was wrong and
    # a suite of its own refuted it immediately: a locked resource is released with its OWN
    # secret (`store.get_resource_secret`), not with the login PIN. A
    # false alarm costs the same trust as an overlooked finding — hence the note stands
    # here instead of the check.

    if _an(config, "password_reset_enabled") and not _an(config, "magiclink_enabled"):
        warnungen.append(
            "password_reset_enabled=True, aber magiclink_enabled=False. Die Routen sind montiert, "
            "der Link „Passwort vergessen?\" erscheint auf der Login-Seite aber nicht — die "
            "Funktion ist an und für niemanden erreichbar.")
    if _an(config, "allow_signup") and not _an(config, "password_enabled"):
        fehler.append(
            "allow_signup=True mit password_enabled=False legt Konten an, die sich nie anmelden "
            "können — die Registrierung vergibt ein Passwort, und der Passwort-Login ist aus.")
    # Open registration next to LDAP (PO decision 2026-09-27): an identifier belongs to exactly one
    # account — if the directory returns another person under a locally assigned identifier,
    # TinySesam rejects the sign-in (review round p1-d). Whoever registers in advance with the name or the
    # directory address of a person who has never signed in would lock them
    # out. TinySesam does not know these names before the directory names them — so
    # the combination does not exist. There the operator creates accounts (panel, `create_user`).
    if _an(config, "allow_signup") and _an(config, "ldap_enabled"):
        fehler.append(
            "allow_signup=True neben ldap_enabled=True: Wer sich mit dem Namen oder der Adresse "
            "einer Person aus dem Verzeichnis registriert, bevor sie sich angemeldet hat, sperrt sie "
            "unter dieser Kennung aus (eine Kennung gehört genau einem Konto). Registrierung "
            "ausschalten und Konten im Admin-Panel bzw. mit auth.create_user(...) anlegen.")

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
    # (`security.normalisiere_basis`), not a weaker pattern of its own: a coarse
    # scheme-and-host pattern accepted `https://wer:was@auth.example` and `https://auth.example/x#y`
    # — both would then stand in every reset link, and the part behind `#` does not even
    # reach the server. Two rule sets for the same question are one too many (C-7).
    _basis = str(getattr(config, "base_url", "") or "").strip()
    _kanonisch = security.normalisiere_basis(_basis)
    if _basis and _kanonisch and _kanonisch != _basis.rstrip("/"):
        # The address is usable, but it is altered on the way — we say so here
        # instead of doing it silently. Most common case: user info in the host
        # (`https://wer:was@auth.example`), which is removed from every outgoing link.
        fehler.append(
            f"base_url={_basis!r} wird als {_kanonisch!r} verwendet — die Adresse ist nicht in "
            "der Form, in der sie in Links steht. Bitte genau den zweiten Wert eintragen, damit "
            "Konfiguration und Wirklichkeit dasselbe sagen.")
    if _basis and not _kanonisch:
        fehler.append(
            f"base_url={_basis!r} ist keine brauchbare Basis-Adresse (erwartet z.B. "
            "\"https://auth.example.com\", mit Unterpfad \"https://example.com/sso\"). Verlangt "
            "sind Schema http/https und ein Host; nicht erlaubt sind Benutzerangabe im Host, "
            "Abfrage (?) oder Fragment (#), ein unzulässiger Port und ein Pfad mit \"..\" oder "
            "\"//\". Jeder daraus gebaute Link wäre kaputt — ohne Fehler, ohne Logzeile, erst "
            "beim Empfänger.")
    if not _basis:
        betroffen = [wofuer for feld, wofuer in BRAUCHT_BASE_URL.items() if _an(config, feld)]
        if betroffen:
            fehler.append(
                "base_url ist leer, aber diese Funktionen geben eine absolute Adresse in fremde "
                "Hand: " + "; ".join(betroffen)
                + ". Als Quelle bliebe der Host-Header der jeweiligen Anfrage — den setzt der "
                "Anfragende (bei einer Mail an ein fremdes Postfach also der Angreifer). "
                "Abhilfe: base_url auf die öffentliche Adresse dieser App setzen, z.B. "
                "base_url=\"https://auth.example.com\" (lokal "
                "base_url=\"http://127.0.0.1:8000\"). Unter einem Unterpfad montiert gehört "
                "das Präfix mit hinein (\"https://example.com/sso\"). "
                "trusted_redirect_hosts ist dafür KEIN Ersatz: Steht dort mehr als ein Host, "
                "bestimmt der Anfragende per Host-Header, welcher davon in den Link kommt.")
        weich = [wofuer for feld, wofuer in BASE_URL_EMPFOHLEN.items() if _an(config, feld)]
        if weich and not betroffen:
            warnungen.append(
                "base_url ist leer, aber diese Funktion baut absolute Adressen: "
                + "; ".join(weich)
                + ". Ohne geprüfte Basis bleibt die Umleitung relativ — das trägt, solange App "
                "und Login-Seite unter demselben Host liegen. Für SSO über mehrere Hosts "
                "base_url (und cookie_domain) setzen.")
    # First-admin token: the value must not land where strangers can read it. That was exactly
    # B5-03 — it stood in the file that the fail2ban jail reads and logrotate archives.
    token_datei = str(getattr(config, "admin_claim_token_file", "") or "").strip()
    seclog_datei = str(getattr(config, "security_log", "") or "").strip()
    if token_datei and seclog_datei and os.path.abspath(token_datei) == os.path.abspath(seclog_datei):
        fehler.append(
            "admin_claim_token_file und security_log zeigen auf dieselbe Datei. Damit stünde das "
            "Erst-Admin-Einmal-Token wieder in dem Log, das fail2ban liest, logrotate archiviert "
            "und ein Log-Versand mitnimmt — wer es liest, wird Admin. Für den Token eine eigene "
            "Datei nehmen (z.B. /run/<dienst>/admin-claim.token) oder das Feld leer lassen, dann "
            "geht der Wert auf stderr.")
    _claim_ttl = _ganzzahl(config, "admin_claim_ttl_min")
    if token_datei and ((_claim_ttl is not None and _claim_ttl <= 0)
                        or not _an(config, "admin_enabled")):
        warnungen.append(
            "admin_claim_token_file ist gesetzt, aber der Token-Weg ist aus "
            "(admin_claim_ttl_min=0 oder admin_enabled=False) — die Datei wird nie geschrieben. "
            "Der Erst-Admin kommt dann nur über admin_identifiers oder einen eigenen Aufruf "
            "von auth.ensure_admin(…) zustande — das CLI kann keine Konten anlegen.")

    # First admin via allowlist ADDRESS while SAML or LDAP create accounts themselves: the
    # constructor forbids allowlist *names* here (nobody confirms them). An
    # address stays allowed — but it carries the decision only with proof. SAML and LDAP
    # deliver none; since the PO decisions 2026-09-24/25 the operator says per source whether they trust
    # its addresses (`*_email_trusted`, default no) or which attribute vouches for them
    # (`*_attr_email_verified`). Not trusted: the runtime never promotes (fail-closed, F-14) —
    # and the confirmation link goes to no allowlist address. Trusted or provable
    # by attribute: the address promotes — correct only if nobody can enter it or the attribute
    # themselves.
    allowlist_adressen = sorted({str(i).strip() for i in
                                 (getattr(config, "admin_identifiers", None) or [])
                                 if "@" in str(i)})
    quellen = [(name, _an(config, vertrauen) or bool(security.beleg_attribut(config, quelle)))
               for an, anlegen, vertrauen, quelle, name in (
        ("saml_enabled", "saml_auto_create", "saml_email_trusted", "saml", "SAML"),
        ("ldap_enabled", "ldap_auto_create", "ldap_email_trusted", "ldap", "LDAP"))
        if _an(config, an) and _an(config, anlegen)]
    ohne_beleg = [name for name, vertraut in quellen if not vertraut]
    mit_beleg = [name for name, vertraut in quellen if vertraut]
    if allowlist_adressen and ohne_beleg:
        warnungen.append(
            f"admin_identifiers nennt die Adresse(n) {allowlist_adressen}, und "
            + " und ".join(ohne_beleg) +
            " legt Konten beim ersten Login selbst an, ohne dass der Betreiber den Adressen "
            "dieser Quelle traut (*_email_trusted=False, kein *_attr_email_verified). Über diese "
            "Wege wird die Adresse NIE "
            "zum Erst-Admin — die Adresse wird dort gar nicht verwendet. Der belegte Weg ist das "
            "Einmal-Token: anmelden, dann /auth/claim-admin (s. admin_claim_ttl_min); danach "
            "vergibt der Erst-Admin die Rechte selbst.")
    if allowlist_adressen and mit_beleg:
        warnungen.append(
            f"admin_identifiers nennt die Adresse(n) {allowlist_adressen}, und "
            + " und ".join(mit_beleg) +
            " gilt als vertraute Quelle (*_email_trusted=True oder ein Beleg-Attribut "
            "*_attr_email_verified): Wer dort eine dieser Adressen belegt trägt, wird beim ersten "
            "Login Erst-Admin. Das ist nur richtig, wenn niemand seine Adresse (bzw. das "
            "Beleg-Attribut) in dieser Quelle selbst ändern kann (kein Self-Service für das "
            "mail-Attribut, kein IdP mit Selbstregistrierung) — sonst beides aus und /auth/claim-admin.")
    # LDAP not trusted, but the search filter finds accounts via the address: then the
    # input at login is an address that nobody vouches for. TinySesam does not take it as an
    # account name (substitute name `ldap-…`), but needs a stable identifier for that.
    _filter = str(getattr(config, "ldap_user_filter", "") or "")
    _mail_attr = str(getattr(config, "ldap_attr_email", "") or "mail")
    if _an(config, "ldap_enabled") and not _an(config, "ldap_email_trusted") \
            and f"({_mail_attr.lower()}=" in _filter.lower():
        warnungen.append(
            f"ldap_user_filter sucht über {_mail_attr}, aber ldap_email_trusted=False: Wer sich mit "
            f"seinem {_mail_attr}-Wert anmeldet, bekommt einen Ersatznamen (ldap-…) statt dieses "
            "Werts als Kontonamen und wird nie über den Namen einem vorhandenen Konto zugeordnet; "
            "ohne stabile Kennung (ldap_attr_id) wird die Anmeldung abgewiesen.")
    # G1: binding indefinitely via the name is the state up to 0.20.x — and exactly the gap that the
    # deadline closes. Allowed (way back), but not silently.
    _foederiert = [name for an, name in (("ldap_enabled", "LDAP"), ("saml_enabled", "SAML"))
                   if _an(config, an)]
    _tage = _ganzzahl(config, "federation_name_binding_days", 30)
    if _foederiert and _tage is not None and _tage < 0:
        warnungen.append(
            f"federation_name_binding_days={_tage}: {' und '.join(_foederiert)} binden ein "
            "ungebundenes Konto unbegrenzt über seinen Namen. Ein ruhendes Konto (jemand ist "
            "ausgeschieden) fällt dann an die nächste Person, die im Verzeichnis denselben Namen "
            "bekommt — samt Rollen und Admin-Recht. Besser: den Bestand einmal binden "
            "(auth.federation_bind_existing(source), erst als Trockenlauf) und die Vorgabe (30) lassen.")

    # Paths of the app have carried no mount prefix since T-15 — TinySesam puts it in front from the path
    # of the base_url. Whoever entered it by hand for the old version (`/sso/auth/login`)
    # would now get `/sso/sso/auth/login` (404). A warning, not an error: a path of the app can
    # by pure chance be named like the prefix.
    from urllib.parse import urlsplit as _urlsplit
    _praefix = _urlsplit(str(getattr(config, "base_url", "") or "")).path.rstrip("/")
    if _praefix:
        _pfade = {"login_path": str(getattr(config, "login_path", "") or ""),
                  "login_redirect": str(getattr(config, "login_redirect", "") or ""),
                  "logout_redirect": str(getattr(config, "logout_redirect", "") or ""),
                  "admin_path": str(getattr(config, "admin_path", "") or "")}
        doppelt = [f"{feld}={wert!r}" for feld, wert in _pfade.items() if wert.startswith(_praefix + "/")]
        if doppelt:
            warnungen.append(
                f"{', '.join(doppelt)} beginnt mit dem Präfix der base_url ({_praefix}). Diese Felder "
                "sind Pfade der App ohne Präfix — TinySesam setzt ihn seit 0.21 selbst davor, sonst "
                f"entsteht {_praefix}{_praefix}/…. Den Präfix aus dem Wert nehmen.")

    # --- Several applications behind one installation (T-14) ---
    _clients = getattr(config, "oidc_clients", None) or {}
    # Type and range are checked by ZAHLENGRENZEN (below, including negative values); here only the
    # combination. An `int()` on a text crashed the whole check.
    _revalidate = _ganzzahl(config, "oidc_revalidate_minutes") or 0
    if _clients and not _an(config, "oidc_enabled"):
        fehler.append(
            "oidc_clients nennt " + ", ".join(sorted(str(h) for h in _clients)) + ", aber "
            "oidc_enabled ist False. Die Zuordnung Host→Client wäre wirkungslos: Es gäbe keinen "
            "OIDC-Weg, über den eine Freigabe entstehen könnte.")
    if _revalidate > 0 and not _clients:
        warnungen.append(
            f"oidc_revalidate_minutes={_revalidate}, aber oidc_clients ist leer. Die Nachprüfung "
            "betrifft die Freigabe je Anwendung — ohne mehrere Clients gibt es keine, und der "
            "Wert bleibt folgenlos. Gemeint war vermutlich session_ttl_hours (Lebensdauer der "
            "Sitzung) oder stepup_max_age_sec (Frische für heikle Routen).")
    # The upper bound in ZAHLENGRENZEN (30 days) catches a period in seconds only from one day
    # (86400). The preset's default, one hour, written in seconds (3600) passed
    # silently — re-check every 60 hours, a revocation at the provider arrived 60 times later. A
    # period above one day is unusual enough to ask about the unit; 300 or 900
    # (five or 15 minutes in seconds) are caught by no bound.
    if _revalidate > 24 * 60:
        warnungen.append(
            f"oidc_revalidate_minutes={_revalidate} heisst: Nachprüfung beim Provider alle "
            f"{_revalidate / 60:g} Stunden. Das Feld zählt Minuten — war die Frist in Sekunden "
            "gemeint (eine Stunde = 60, nicht 3600)? Ist die lange Frist gewollt, bleibt es bei "
            "dieser Warnung.")
    _vertraute = [str(h).strip().lower() for h in (getattr(config, "trusted_redirect_hosts", None) or [])]
    for host, eintrag in _clients.items():
        h = str(host).strip().lower()
        e = dict(eintrag or {})
        wo = f"oidc_clients[{host!r}]"
        if not str(e.get("client_id") or "").strip():
            fehler.append(f"{wo} hat keine client_id. Ohne sie gibt es für diese Anwendung keinen "
                          "Client beim Provider — und damit auch keine eigene Freigabe.")
        if not str(e.get("client_secret") or "").strip():
            fehler.append(f"{wo} hat kein client_secret. Der Tausch des Autorisierungs-Codes "
                          "scheitert dann beim Provider, und zwar erst nach der Anmeldung — also "
                          "an der Stelle, an der niemand mehr eine Konfigurationslücke vermutet.")
        if e.get("issuer"):
            fehler.append(f"{wo} nennt einen eigenen issuer. Mehrere Provider in einer Installation "
                          "sind nicht vorgesehen: Discovery-Dokument, JWKS und die Zuordnung "
                          "issuer+sub→Konto hängen am einen oidc_issuer. Für einen zweiten Provider "
                          "braucht es eine zweite Instanz.")
        if _vertraute and h not in _vertraute:
            warnungen.append(
                f"{wo} ist nicht in trusted_redirect_hosts. Die Login-URL für diese Anwendung wird "
                "dann auf base_url gebaut statt auf den angefragten Host — ohne cookie_domain "
                "gilt das Sitzungs-Cookie host-only, und die Anmeldung dreht sich im Kreis.")
    if _clients and not _an(config, "forward_auth_enabled"):
        warnungen.append(
            "oidc_clients ist gesetzt, forward_auth_enabled aber False. Die Freigabe je Anwendung "
            "wird in /auth/forward geprüft — ohne Forward-Auth entsteht sie beim Login, wird "
            "danach aber von nichts abgefragt.")

    # --- Self-enrollment of the second factor (R3-1) ---
    _arten = ("first_login", "grace", "strict")
    _art = str(getattr(config, "mfa_enrollment", "") or "first_login")
    if _art not in _arten:
        fehler.append(
            f"mfa_enrollment={_art!r} gibt es nicht. Erlaubt sind {list(_arten)}: 'first_login' "
            "(Vorgabe, erlaubt bis zum ersten vollständigen Login), 'grace' (erlaubt "
            "mfa_enrollment_grace_days ab Kontoanlage), 'strict' (nie — die Einrichtung kommt "
            "dann vom Betreiber).")
    _gnade = _ganzzahl(config, "mfa_enrollment_grace_days")
    if _art == "grace" and _gnade is not None and _gnade <= 0:
        fehler.append(
            "mfa_enrollment='grace', aber mfa_enrollment_grace_days ist 0 oder kleiner. Damit "
            "verhält sich 'grace' wie 'strict', nur unauffälliger — entweder eine Frist setzen "
            "oder gleich mfa_enrollment='strict' schreiben.")

    # --- CSRF protection fully off (F-03) ---
    # Individually each value is defensible: `csrf_enabled=False`, because SameSite=Lax already
    # stops cross-site POSTs; `cookie_samesite='none'` for an embedded app, because
    # the CSRF token then protects. Together NOTHING remains: the session cookie rides along with every
    # foreign form, and nobody checks a token. That is not a compromise, that is a hole.
    if (not _an(config, "csrf_enabled")
            and str(getattr(config, "cookie_samesite", "lax") or "").lower() == "none"):
        fehler.append(
            "csrf_enabled=False zusammen mit cookie_samesite='none': Dann schickt der Browser "
            "das Sitzungs-Cookie bei jedem Formular einer fremden Seite mit, und kein Token "
            "hält dagegen — jede zustandsändernde Route ist per CSRF auslösbar. Entweder "
            "csrf_enabled=True (nötig, sobald SameSite=None gebraucht wird) oder "
            "cookie_samesite='lax'.")

    # --- User verification for passkeys (B2-10) ---
    _uv = str(getattr(config, "passkey_user_verification", "required") or "required")
    if _uv not in ("required", "preferred"):
        fehler.append(
            f"passkey_user_verification={_uv!r} gibt es nicht. Erlaubt sind 'required' (Vorgabe: "
            "der Authenticator muss den Menschen prüfen) und 'preferred' (er wird gebeten). "
            "Ein Passkey meldet allein an — ohne Prüfung belegt er nur den Besitz des Schlüssels.")
    elif _uv == "preferred" and _an(config, "passkey_enabled"):
        warnungen.append(
            "passkey_user_verification='preferred': Ein Passkey ohne Nutzerprüfung meldet allein "
            "an und belegt dann nur den Besitz des Schlüssels — ein entsperrter Rechner oder ein "
            "eingesteckter Stick genügt. Das ist eine bewusste Entscheidung für einen Bestand "
            "alter Authentikatoren; für einen neuen gehört der Wert auf 'required'.")

    # --- LDAP transport (F-12) ---
    if _an(config, "ldap_enabled"):
        _url = str(getattr(config, "ldap_url", "") or "").strip().lower()
        _tls_an = _url.startswith("ldaps://") or _an(config, "ldap_start_tls")
        if _url and not _tls_an and not _an(config, "ldap_allow_plaintext"):
            fehler.append(
                f"ldap_url={_url!r} spricht im Klartext und ldap_start_tls ist False. Dann gehen "
                "das Passwort des Dienstkontos UND jedes Benutzerpasswort unverschlüsselt über "
                "das Netz — bei jeder Anmeldung. Abhilfe: ldaps:// in der URL (Port 636) oder "
                "ldap_start_tls=True (Port 389). Ist das Verzeichnis auf demselben Host und der "
                "Verkehr verlässt ihn nie, sagt ldap_allow_plaintext=True das ausdrücklich.")
        if _an(config, "ldap_allow_plaintext") and not _tls_an:
            warnungen.append(
                "ldap_allow_plaintext=True: Der LDAP-Verkehr ist unverschlüsselt. Das Passwort "
                "des Dienstkontos und jedes Benutzerpasswort sind damit für jeden mitlesbar, der "
                "auf dem Weg sitzt. Nur vertretbar, wenn dieser Weg die Maschine nicht verlässt.")
        if _tls_an and not _an(config, "ldap_tls_verify"):
            warnungen.append(
                "ldap_tls_verify=False: Das Zertifikat des Verzeichnisses wird nicht geprüft. "
                "Verschlüsselt heisst dann nur: nicht mitlesbar von jemandem, der nicht "
                "dazwischensitzt. Wer den Verkehr umlenkt, hält ein eigenes Zertifikat hin und "
                "bekommt beide Passwörter. Bei eigener CA gehört sie in ldap_tls_ca_file.")
        _ca = str(getattr(config, "ldap_tls_ca_file", "") or "").strip()
        if _ca and not os.path.exists(_ca):
            fehler.append(
                f"ldap_tls_ca_file={_ca!r} gibt es nicht. Die Verbindung zum Verzeichnis "
                "scheitert dann bei jeder Anmeldung — und zwar erst im Betrieb.")

    _csp_fund = csp_fehler(getattr(config, "csp", "strict"))
    if _csp_fund:
        fehler.append(_csp_fund)
    _csp_hinweis = csp_warnung(getattr(config, "csp", "strict"))
    if _csp_hinweis:
        warnungen.append(_csp_hinweis)
    _zahlengrenzen(config, fehler)
    _proxies_und_passkey(config, fehler, warnungen)
    _stepup(config, fehler, warnungen)
    _offene_tore(config, warnungen)
    _gruppen_scope(config, warnungen)
    _kombinationen(config, fehler, warnungen)
    _gate(config, fehler, warnungen)
    _forward_apps(config, fehler, warnungen)

    hat_mailer = bool(str(getattr(config, "smtp_host", "") or "").strip())
    # --- SMTP TLS (B3-1, attack A4): since the certificate is checked, a wrong
    # CA path or a relay by IP address fails on EVERY mail — and silently, only as
    # *_send_error in the audit log. Both can be detected at construction.
    _smtp_ca = str(getattr(config, "smtp_ca_file", "") or "").strip()
    if _smtp_ca and not os.path.isfile(_smtp_ca):
        fehler.append(
            f"smtp_ca_file={_smtp_ca!r} gibt es nicht. Die TLS-Prüfung des Mailservers scheitert "
            "dann bei jeder Mail — Anmelde-Links, Resets und Bestätigungen gingen nie hinaus, "
            "und das erst im Betrieb.")
    _smtp_host = str(getattr(config, "smtp_host", "") or "").strip().strip("[]")
    if hat_mailer and _ist_ip(_smtp_host):
        warnungen.append(
            f"smtp_host={_smtp_host!r} ist eine IP-Adresse. Das Zertifikat des Mailservers wird "
            "gegen den Hostnamen geprüft; trägt es die IP nicht als Subject Alternative Name, "
            "scheitert jeder Versand. Abhilfe: den Namen eintragen, auf den das Zertifikat "
            "ausgestellt ist (bei eigener CA zusätzlich smtp_ca_file).")
    for feld, wofuer in BRAUCHT_MAILER.items():
        if _an(config, feld) and not hat_mailer:
            warnungen.append(
                f"{feld}=True ({wofuer}), aber smtp_host ist leer. Ohne Mailer geht keine Mail "
                "hinaus und das Verfahren endet still. Entweder smtp_host setzen oder zur "
                "Laufzeit auth.set_mailer(...) aufrufen — dann ist diese Meldung gegenstandslos.")

    # `audit_retention_days` is checked by ZAHLENGRENZEN (below): a negative period would be in `gc()` a
    # point in time in the future — the whole audit log would vanish on the next run. The own
    # check that stood here knew only `< 0` and let `True`, seconds instead of days and
    # huge values (OverflowError in gc()) through.

    return fehler, warnungen


#: Number fields of the config → allowed range, both bounds inclusive (B3-12).
#:
#: Before, not a single one had a bound, and the failure modes are all silent: `session_ttl_hours=0`
#: lets every session expire the moment it is created (sign-in "works", the next click
#: is the login page again), `magiclink_ttl_min=0` sends dead links, `recovery_code_count=0`
#: issues no codes and still reports success, a negative `stepup_max_age_sec` makes
#: every step-up confirmation instantly old. The upper bounds catch the unit error (minutes instead of
#: hours, seconds instead of minutes), which silently multiplies a period by sixty.
ZAHLENGRENZEN = {
    "brand_background_seconds": (4, 600),   # dwell time per background image (0.24.8)
    "pin_min_length": (4, 64),
    "apikey_default_days": (0, 3650),
    "admin_claim_ttl_min": (0, 7 * 24 * 60),
    "resource_unlock_ttl_hours": (1, 24 * 30),
    "magiclink_ttl_min": (1, 24 * 60),
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
    # Shorter periods in seconds (3600 for one hour) do not — for that `pruefe` warns above 1440.
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
    # Waiting time on the "Signed out" page before it leads back to the application. Above five minutes
    # nobody waits any more, for that there is 0 (leave standing).
    "forward_logged_out_sec": (0, 300),
}


def _zahlengrenzen(config, fehler: list) -> None:
    for feld, (unten, oben) in ZAHLENGRENZEN.items():
        if not hasattr(config, feld):
            fehler.append(f"Die Konfigurationsprüfung nennt das Feld {feld!r}, das es in "
                          "TinySesamConfig nicht gibt — ein Fehler in TinySesam selbst.")
            continue
        wert = getattr(config, feld)
        # bool is an int: `session_ttl_hours=True` would mean one hour, which was never intended.
        if isinstance(wert, bool) or not isinstance(wert, int):
            fehler.append(f"{feld}={wert!r} ist keine ganze Zahl.")
            continue
        if not unten <= wert <= oben:
            fehler.append(f"{feld}={wert} liegt ausserhalb von {unten}…{oben}. Häufigster Grund "
                          "ist eine verwechselte Einheit (der Feldname nennt sie).")


def _proxies_und_passkey(config, fehler: list, warnungen: list) -> None:
    # --- trusted_proxies (B3-3) ---
    # An invalid entry raised at runtime in the middle of the check and invalidated the WHOLE
    # list; the warning afterwards advised entering the proxy network that was long there. A
    # hostname is the most common case — proxies are given here as a network, not as a name.
    schlecht = security.ungueltige_netze(getattr(config, "trusted_proxies", None) or [])
    if schlecht:
        fehler.append(
            f"trusted_proxies enthält Einträge, die kein IP-Netz sind: {schlecht}. Erwartet "
            "werden Adressen oder Netze wie '203.0.113.5' oder '198.51.100.0/24' — keine Hostnamen. "
            "Ein ungültiger Eintrag darf nicht mitgelesen werden: Er entschiede sonst, ob der "
            "Proxy als vertrauenswürdig gilt.")

    # --- WebAuthn: rp_id and origin (B3-10) ---
    # Both fields carry developer values as default (`localhost`, `http://localhost:8000`).
    # Forgotten in production, EVERY passkey ceremony fails — only in the browser, with a message
    # that looks like a problem of the authenticator. What is checked is what can be proven without the
    # outside world: form, matching, and the comparison with `base_url`.
    if not _an(config, "passkey_enabled"):
        return
    from urllib.parse import urlsplit
    rp_id = str(getattr(config, "rp_id", "") or "").strip().lower()
    roh = getattr(config, "origin", "")
    roh = "" if roh is None else roh
    # py_webauthn also accepts a list as `expected_origin` (A5): whoever serves the sign-in page under
    # several names enters them all. Each entry is then checked individually —
    # `str(list)` is never an origin, and so a working config became an error.
    origins = [str(o).strip() for o in roh] if isinstance(roh, (list, tuple)) else [str(roh).strip()]
    if not origins:
        fehler.append("origin ist eine leere Liste — mindestens ein Origin wie "
                      "\"https://auth.example.com\" muss dastehen, sonst scheitert jeder Passkey.")
        return
    hosts = []
    for origin in origins:
        teile = urlsplit(origin)
        host = (teile.hostname or "").lower()
        if teile.scheme not in ("http", "https") or not host or teile.path not in ("", "/") \
                or teile.query or teile.fragment or origin.endswith("/"):
            fehler.append(
                f"origin={origin!r} ist kein Origin. Verlangt ist genau Schema, Host und ggf. Port "
                "(\"https://auth.example.com\"), ohne Pfad und ohne Schrägstrich am Ende — der "
                "Browser vergleicht Zeichen für Zeichen.")
            return
        hosts.append(host)
    if not rp_id or "://" in rp_id or ":" in rp_id or "/" in rp_id:
        fehler.append(f"rp_id={rp_id!r} muss ein Hostname ohne Schema und Port sein, z.B. "
                      "\"auth.example.com\" oder die Domain darüber (\"example.com\").")
    else:
        for origin, host in zip(origins, hosts):
            if not (host == rp_id or host.endswith("." + rp_id)):
                fehler.append(
                    f"rp_id={rp_id!r} passt nicht zu origin={origin!r}: Die rp_id muss der Host "
                    "des Origins sein oder eine Domain darüber. So lehnt jeder Browser die "
                    "Passkey-Zeremonie ab.")
    basis = security.normalisiere_basis(str(getattr(config, "base_url", "") or "").strip())
    if basis:
        b = urlsplit(basis)
        soll = f"{b.scheme}://{b.netloc}"
        if soll.lower() not in [o.lower() for o in origins]:
            # Warning, not error: whoever serves the sign-in page under a second name of their own
            # (base_url only for the mail links) may want it that way.
            anzeige = origins[0] if len(origins) == 1 else origins
            warnungen.append(
                f"origin={anzeige!r} weicht von base_url ab ({soll}). Die Anmeldeseite läuft unter "
                "base_url, und der Browser meldet genau diesen Origin — mit dem Wert hier "
                "scheitert jeder Passkey. Meist steht hier noch die Vorgabe für die Entwicklung.")
    elif all(h in ("localhost", "127.0.0.1", "::1") for h in hosts) and rp_id == "localhost":
        warnungen.append(
            f"passkey_enabled=True mit den Entwicklerwerten rp_id={rp_id!r}, origin={roh!r}. "
            "Ausserhalb der eigenen Maschine scheitert damit jeder Passkey — produktiv beide auf "
            "die öffentliche Adresse setzen (und base_url dazu).")


#: What may appear in `stepup_methods`, and which switch turns the method on.
STEPUP_VERFAHREN = {"totp": "totp_enabled", "pin": "pin_enabled", "password": "password_enabled"}


def _stepup(config, fehler: list, warnungen: list) -> None:
    # B3-6: `stepup_methods` is a wish, and a wish that does not exist is silently
    # passed over — `["topt"]` fell back to "everything the user has", that is, to the password
    # with which they had just signed in. The second factor before the sensitive area was gone,
    # and nothing said so. With `stepup_strict=True` it was the other way round: nobody ever got in.
    gewuenscht = [str(m) for m in (getattr(config, "stepup_methods", None) or [])]
    unbekannt = [m for m in gewuenscht if m not in STEPUP_VERFAHREN]
    if unbekannt:
        fehler.append(
            f"stepup_methods nennt {unbekannt} — das sind keine Step-up-Verfahren. Erlaubt sind "
            f"{sorted(STEPUP_VERFAHREN)}. Ein unbekannter Name wird nicht übersprungen, sondern "
            "abgewiesen: Übersprungen fiele die Bestätigung auf das Passwort zurück.")
    aus = [m for m in gewuenscht if m in STEPUP_VERFAHREN and not _an(config, STEPUP_VERFAHREN[m])]
    if aus:
        fehler.append(
            f"stepup_methods verlangt {aus}, aber "
            + ", ".join(f"{STEPUP_VERFAHREN[m]}=False" for m in aus)
            + ". Dieser Wunsch kann nie erfüllt werden — ohne stepup_strict fällt die Bestätigung "
            "still auf ein anderes Verfahren zurück, mit stepup_strict bleibt der Bereich zu.")
    if _an(config, "stepup_strict") and not gewuenscht:
        warnungen.append(
            "stepup_strict=True ohne stepup_methods ist wirkungslos: Die Schranke gilt nur für "
            "genannte Verfahren. Gemeint war vermutlich z.B. stepup_methods=['totp'].")


def _offene_tore(config, warnungen: list) -> None:
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
    offen = []
    for an, anlegen, gruppen, name in (("oidc_enabled", "oidc_auto_create", "oidc_allowed_groups", "OIDC"),
                                       ("saml_enabled", "saml_auto_create", "saml_allowed_groups", "SAML"),
                                       ("ldap_enabled", "ldap_auto_create", "ldap_allowed_groups", "LDAP")):
        if not (_an(config, an) and _an(config, anlegen)) or getattr(config, gruppen, None):
            continue
        if name == "OIDC" and getattr(config, "oidc_clients", None):
            # One client of its own per application (T-14): the approval lies with the provider, and
            # `/auth/forward` checks it per host. That is a closed gate — just one
            # whose key the provider manages.
            continue
        offen.append(f"{name} ({anlegen}=True, {gruppen} leer)")
    if offen:
        warnungen.append(
            "Forward-Auth mit offenem Tor: " + "; ".join(offen) + ". Jedes Konto beim Anbieter "
            "wird beim ersten Login angelegt und kommt danach durch JEDE geschützte Anwendung, "
            "die am Proxy kein ?roles= verlangt. Den Kreis begrenzen: *_allowed_groups setzen "
            "(beim Gateway TINYSESAM_ALLOWED_GROUPS), am Proxy ?roles= verlangen, oder die "
            "Freigabe je Anwendung beim Provider regeln (oidc_clients).")
    if _an(config, "allow_signup") and not _an(config, "signup_invite_only"):
        warnungen.append(
            "Forward-Auth mit offener Selbst-Registrierung: Jeder Besucher legt sich ein Konto an "
            "und kommt damit durch jede geschützte Anwendung, die am Proxy kein ?roles= verlangt. "
            "signup_invite_only=True, allow_signup=False oder Rollen am Proxy verlangen.")


#: Providers that deliver the group claim without a scope of their own and
#: REJECT an unknown scope: Entra ID takes `groups` as a Graph API permission and aborts the sign-in
#: (AADSTS650053 "scope 'groups' that doesn't exist"; the groups come there via "optional
#: claims" of the app registration). The advice "add `groups` to
#: oidc_scopes" would be wrong there, the warning a permanent false alarm for the `entra_id` preset.
_GRUPPEN_OHNE_SCOPE = ("login.microsoftonline.com",)


def _gruppen_scope(config, warnungen: list) -> None:
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
    if idp in _GRUPPEN_OHNE_SCOPE:
        return
    global_gruppen = list(getattr(config, "oidc_allowed_groups", None) or [])
    global_map = dict(getattr(config, "oidc_group_role_map", None) or {})
    global_scopes = str(getattr(config, "oidc_scopes", "") or "")

    def ohne_scope(scopes) -> bool:
        return "groups" not in str(scopes or "").split()

    betroffen = []
    if (global_gruppen or global_map) and ohne_scope(global_scopes):
        betroffen.append(f"oidc_scopes={global_scopes!r}")
    for host, eintrag in (getattr(config, "oidc_clients", None) or {}).items():
        e = dict(eintrag or {})
        regel = e.get("allowed_groups") or global_gruppen or e.get("group_role_map") or global_map
        scopes = e.get("scopes") or global_scopes
        if regel and ohne_scope(scopes):
            betroffen.append(f"oidc_clients[{host!r}] (scopes={str(scopes)!r})")
    if betroffen:
        warnungen.append(
            "Gruppenregel über den Claim 'groups' (oidc_allowed_groups bzw. oidc_group_role_map), "
            "aber der Scope 'groups' wird nicht angefordert: " + "; ".join(betroffen) + ". "
            "PocketID und andere Provider schicken den Claim nur mit diesem Scope — dann weist "
            "oidc_allowed_groups JEDEN ab, und oidc_group_role_map vergibt keine Rolle. 'groups' "
            "in oidc_scopes aufnehmen (Gateway: TINYSESAM_OIDC_SCOPES; je Anwendung `scopes` im "
            "Eintrag von oidc_clients). Liefert der Provider den Claim ohne eigenen Scope (Mapper, "
            "etwa bei Keycloak), ist diese Warnung gegenstandslos.")


FORWARD_APP_SCHLUESSEL = ("name", "login", "logout")
FORWARD_LOGIN = ("page", "direct")
FORWARD_LOGOUT = ("all", "app", "ask")


def _forward_apps(config, fehler: list, warnungen: list) -> None:
    """Login mode and settings per application in front of the gate (T-21)."""
    modus = getattr(config, "forward_login", "page")
    if modus not in FORWARD_LOGIN:
        fehler.append(f"forward_login={modus!r}: erlaubt sind {', '.join(FORWARD_LOGIN)}.")
    abmelden = getattr(config, "forward_logout", "all")
    if abmelden not in FORWARD_LOGOUT:
        fehler.append(f"forward_logout={abmelden!r}: erlaubt sind {', '.join(FORWARD_LOGOUT)}.")
    apps = getattr(config, "forward_apps", None) or {}
    if not isinstance(apps, dict):
        fehler.append("forward_apps muss ein Dict sein: {\"app.example.com\": {\"name\": …, \"login\": …}}.")
        return
    direkt = [("forward_login", modus)] if modus == "direct" else []
    vertraut = {str(h).strip().lower() for h in (getattr(config, "trusted_redirect_hosts", None) or [])}
    for host, e in apps.items():
        wo = f"forward_apps[{host!r}]"
        if not isinstance(e, dict):
            fehler.append(f"{wo} muss ein Dict sein.")
            continue
        fremd = sorted(set(e) - set(FORWARD_APP_SCHLUESSEL))
        if fremd:
            # A mistyped key (`logn`) would otherwise silently not apply — the application would get
            # the global mode, and nobody would know why.
            fehler.append(f"{wo} kennt {', '.join(fremd)} nicht (erlaubt: {', '.join(FORWARD_APP_SCHLUESSEL)}).")
        if "login" in e and e["login"] not in FORWARD_LOGIN:
            fehler.append(f"{wo}['login']={e['login']!r}: erlaubt sind {', '.join(FORWARD_LOGIN)}.")
        if "logout" in e and e["logout"] not in FORWARD_LOGOUT:
            fehler.append(f"{wo}['logout']={e['logout']!r}: erlaubt sind {', '.join(FORWARD_LOGOUT)}.")
        if e.get("login") == "direct":
            direkt.append((wo, "direct"))
        if vertraut and str(host).strip().lower() not in vertraut:
            warnungen.append(f"{wo} steht nicht in trusted_redirect_hosts — für diesen Host gibt es "
                             "keine Rückleitung, die Einstellung greift nie.")
    if apps and not _an(config, "forward_auth_enabled"):
        warnungen.append("forward_apps ist gesetzt, forward_auth_enabled aber False — die Einstellungen "
                         "je Anwendung liest nur die Forward-Auth.")
    # "Sign out everywhere" without the provider, in front of a gate that sends directly to the provider: the
    # next page request silently signs in again — signing out looks like a reload.
    abmeldungen = [abmelden] + [str(e.get("logout")) for e in apps.values() if isinstance(e, dict) and e.get("logout")]
    if (direkt and _an(config, "oidc_enabled") and not _an(config, "oidc_rp_logout")
            and any(a in ("all", "ask") for a in abmeldungen)):
        warnungen.append(
            "forward_login='direct' und Abmelden („all“/„ask“), aber oidc_rp_logout=False: Die Sitzung "
            "beim Provider bleibt, und der nächste Seitenaufruf meldet ohne Zutun wieder an. "
            "oidc_rp_logout=True setzen (oidc_gateway() tut das).")
    if direkt and _an(config, "forward_auth_enabled"):
        try:
            methoden = list(config.enabled_methods())
        except Exception:
            methoden = []
        if methoden != ["oidc"]:
            fehler.append(
                f"{direkt[0][0]}='direct' leitet direkt zum Identity Provider — das geht nur, wenn OIDC "
                f"die einzige Anmeldemethode ist (eingeschaltet: {', '.join(methoden) or 'keine'}). Sonst "
                "gäbe es für die übrigen Methoden keinen Weg auf die Login-Seite.")


def _gate(config, fehler: list, warnungen: list) -> None:
    """Gate token (ADR-9, T-19): only as part of forward auth, only with a cookie that the
    browser returns exclusively to the application's host."""
    if _an(config, "gate_link_enabled"):
        # Code exchange (T-26): it replaces the session cookie on the parent domain. Both at once
        # would mean sending the session to every app after all — and the exchange would be only a detour.
        if not _an(config, "gate_token_enabled"):
            fehler.append("gate_link_enabled=True ohne gate_token_enabled=True: Der Code-Austausch gibt dem "
                          "App-Host eine Verbindung, mit der er Gate-Token bekommt — ohne Gate-Token hat sie "
                          "keinen Zweck.")
        if str(getattr(config, "cookie_domain", "") or "").strip():
            fehler.append("gate_link_enabled=True zusammen mit cookie_domain: Der Code-Austausch soll das "
                          "Sitzungs-Cookie gerade NICHT auf der Elterndomain haben — sonst erreicht es jede "
                          "App darunter. cookie_domain leer lassen.")
        if not str(getattr(config, "base_url", "") or "").strip():
            fehler.append("gate_link_enabled=True ohne base_url: Die App-Hosts schicken zur Anmeldung an "
                          "die Adresse des Gateways — die steht in base_url.")
    if not _an(config, "gate_token_enabled"):
        return
    if not _an(config, "forward_auth_enabled"):
        fehler.append(
            "gate_token_enabled=True ohne forward_auth_enabled=True: Das Gate-Token entsteht in der "
            "Antwort von /auth/forward — ohne die Route gibt es keins, und der Proxy fiele bei jeder "
            "Anfrage auf eine Prüfung zurück, die nicht existiert.")
    name = str(getattr(config, "gate_cookie_name", "") or "")
    # `__Host-`: the browser accepts the cookie only with Secure, Path=/ and WITHOUT Domain — it then applies
    # to exactly the host that set it. Without the prefix only our own
    # Set-Cookie line prevents a domain cookie; with it, the browser prevents it.
    # `tinysesam_` after it: the templates strip every `tinysesam_*` cookie before the request
    # reaches the application (B-20). A differently named gate cookie would be read along by the application.
    if not re.fullmatch(r"__Host-tinysesam_[A-Za-z0-9_]+", name):
        fehler.append(
            f"gate_cookie_name={name!r} muss die Form __Host-tinysesam_<name> haben: __Host- bindet "
            "das Cookie an den Host der Anwendung (der Browser nimmt es nur ohne Domain-Angabe an), "
            "und tinysesam_ sorgt dafür, dass die Proxy-Vorlagen es vor der Anwendung "
            "entfernen.")
    ttl = _ganzzahl(config, "gate_token_ttl_sec", None)
    if ttl is not None and 900 < ttl <= 3600:
        warnungen.append(
            f"gate_token_ttl_sec={ttl}: So lange wirkt am Proxy weder ein Abmelden in einer anderen "
            "Anwendung noch eine Sperre oder eine beim Provider entzogene Freigabe. Bis 300 s ist "
            "der Unterschied zur Prüfung je Anfrage kaum zu spüren; über 15 Minuten ist es ein "
            "Widerrufsverzug, den man bewusst wollen sollte.")
    hosts = [h for h in (getattr(config, "trusted_redirect_hosts", None) or []) if h] + \
            [h for h in (getattr(config, "oidc_clients", None) or {}) if h]
    if not hosts and not str(getattr(config, "base_url", "") or "").strip():
        warnungen.append(
            "gate_token_enabled=True, aber kein geschützter Host: weder trusted_redirect_hosts noch "
            "oidc_clients noch base_url. Ein Gate-Token entsteht nur für diese Hosts — so für keinen, "
            "und der Proxy fragt weiter bei jeder Anfrage.")


def _kombinationen(config, fehler: list, warnungen: list) -> None:
    """Combinations that are allowed individually and together do not do what they say (B3-16)."""
    # E-mail confirmation without a mandatory address: whoever leaves the field empty gets an IMMEDIATELY
    # active account — the confirmation applies only to those who give an address. The barrier
    # thus has a door next to it.
    if _an(config, "allow_signup") and _an(config, "signup_verify_email") \
            and not _an(config, "signup_require_email"):
        fehler.append(
            "signup_verify_email=True, aber signup_require_email=False: Wer bei der Registrierung "
            "keine Adresse angibt, ist ohne jede Bestätigung sofort aktiv. Entweder "
            "signup_require_email=True oder auf die Bestätigung verzichten.")
    # ASVS 6.3.8 (B1-12): without confirmation a free registration signs in immediately, a
    # taken address answers with 409 — the difference cannot be hidden, and
    # everyone learns which addresses have an account here. With confirmation both answer
    # the same (R4-03), at runtime too.
    if _an(config, "allow_signup") and not _an(config, "signup_invite_only") \
            and not _an(config, "signup_verify_email") \
            and (_an(config, "signup_require_email") or getattr(config, "login_identifier", "") == "email"):
        warnungen.append(
            "Offene Registrierung ohne signup_verify_email: Eine vergebene Adresse antwortet mit "
            "409, eine freie meldet sofort an — jeder Besucher erfährt so, welche Adressen hier ein "
            "Konto haben (ASVS 6.3.8). Mit signup_verify_email=True antworten beide gleich.")
    if _an(config, "signup_invite_only") and not _an(config, "allow_signup"):
        warnungen.append("signup_invite_only=True ohne allow_signup=True ist wirkungslos — die "
                         "Registrierung ist ohnehin aus.")
    # Via `_ganzzahl` like every combination (tests/test_sicherheit_befunde.py checks that): text,
    # inf, nan and True are reported by `_zahlengrenzen`; here the combination then stays unevaluated.
    lang = _ganzzahl(config, "session_ttl_hours", None)
    kurz = _ganzzahl(config, "session_ttl_transient_hours", None)
    if lang is not None and kurz is not None and kurz > lang:
        warnungen.append(
            f"session_ttl_transient_hours={kurz} ist länger als session_ttl_hours={lang}: Ohne "
            "„Angemeldet bleiben\" bliebe man länger angemeldet als mit.")
    for feld in ("admin_path", "login_path", "oidc_callback_path"):
        wert = str(getattr(config, feld, "") or "")
        if wert and not wert.startswith("/"):
            fehler.append(f"{feld}={wert!r} muss mit '/' beginnen — sonst ist es kein Pfad, und "
                          "Routen wie Links zeigen ins Leere.")
    # cookie_domain that does not cover the own host: the browser discards the cookie, every
    # sign-in "works" and the next click is the login page again.
    dom = str(getattr(config, "cookie_domain", "") or "").strip().lower().lstrip(".")
    basis = security.normalisiere_basis(str(getattr(config, "base_url", "") or "").strip())
    if dom and basis:
        from urllib.parse import urlsplit
        host = (urlsplit(basis).hostname or "").lower()
        if host and not (host == dom or host.endswith("." + dom)):
            fehler.append(
                f"cookie_domain={getattr(config, 'cookie_domain')!r} umfasst den Host von base_url "
                f"({host}) nicht. Der Browser verwirft ein Cookie für eine fremde Domain — "
                "niemand bliebe angemeldet.")
    # Demo mode next to a real sign-in path (B3-8): the demo accounts have a known
    # password, one is admin. Next to OIDC/SAML/LDAP that is no demo any more, but a
    # production instance with a back door.
    if _an(config, "demo_mode"):
        echt = [feld for feld in ("oidc_enabled", "saml_enabled", "ldap_enabled", "forward_auth_enabled")
                if _an(config, feld)]
        if echt:
            fehler.append(
                f"demo_mode=True zusammen mit {', '.join(echt)}: Die Demo legt ein Admin-Konto mit "
                "bekanntem Passwort an. Neben einem echten Anmeldeweg oder vor fremden Anwendungen "
                "ist das eine Hintertür, keine Vorführung.")
