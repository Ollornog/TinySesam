"""Alle Widersprüche einer Konfiguration auf einmal — beim Aufbau, nicht beim ersten Login.

Bis 0.18.0 prüfte der Konstruktor ein halbes Dutzend Kombinationen und warf beim ersten Fund.
Der Rest fiel erst im Betrieb auf, und zwar dort, wo man ihn am wenigsten sucht: Eine App ohne
eine einzige aktive Login-Methode startete klaglos; eine `login_chain`, die ein abgeschaltetes
Verfahren nennt, ist unerfüllbar — der Nutzer landet in einer Schleife; OIDC ohne `issuer`
scheitert erst beim Klick auf „Anmelden".

Zwei Ränge, und die Grenze ist nicht Strenge, sondern **Reparierbarkeit**:

* **Fehler** — die Lage ist aus sich heraus unerfüllbar und wird es auch nicht mehr. Niemand
  kommt herein, oder ein Schutz ist stillschweigend aus. Das bricht den Aufbau ab.
* **Warnung** — es fehlt etwas, das später noch kommen kann. Ein Mailer wird typischerweise
  nach dem Konstruktor gesetzt (`auth.set_mailer(...)`); daraus einen Fehler zu machen hiesse,
  eine völlig übliche Reihenfolge zu verbieten. Geloggt wird trotzdem, denn „still" ist genau
  das Problem, das hier behoben wird.

Alle Funde kommen **gemeinsam** heraus. Wer drei Dinge falsch hat, soll sie einmal lesen und
nicht dreimal starten.
"""
from __future__ import annotations

import os
import re

from . import security

#: Verfahren → welches Config-Feld es einschaltet. Dieselbe Liste bedient die Ketten-Prüfung.
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

#: Was in einer `login_chain` stehen darf: die Faktoren, die eine Sitzung wirklich bekommen
#: kann (`TinySesam.IDENTIFYING`) plus `totp`. Bewusst NICHT `VERFAHREN` — dort stehen auch
#: `ldap` (schreibt den Faktor `password`) und `apikey` (wird nie zum Faktor).
KETTENSCHRITTE = frozenset({"password", "pin", "oidc", "passkey", "magic", "saml", "totp"})

#: Verfahren, mit dem sich ein Mensch ANMELDEN kann. `apikey` zählt nicht: Ein Schlüssel wird
#: von einem Konto ausgestellt, das es erst geben muss.
ANMELDEND = ("password", "pin", "passkey", "oidc", "saml", "ldap", "magic")

#: Verfahren → Felder, ohne die es nicht funktionieren kann.
PFLICHTFELDER = {
    "oidc": ("oidc_issuer", "oidc_client_id"),
    "saml": ("saml_idp_sso_url", "saml_idp_x509cert"),
    "ldap": ("ldap_url",),
}

#: Was einen Mailer braucht. Kein Fehler — `set_mailer` kommt oft später.
BRAUCHT_MAILER = {
    "magiclink_enabled": "Magic-Link-Anmeldung",
    "password_reset_enabled": "„Passwort vergessen\"",
    "signup_verify_email": "E-Mail-Bestätigung bei der Registrierung",
}

#: Was eine **absolute** Adresse in fremde Hand gibt — den Link in einer Mail an ein Postfach,
#: die Redirect-URI beim IdP, die Entity-ID in SAML-Metadaten. Fehlt `base_url`, bliebe dafür
#: nur der `Host`-Header, und den setzt der Anfragende (R4-01). Diese Schalter machen `base_url`
#: zur **Pflicht**: ohne sie scheitert der Aufbau, nicht erst der erste Anmeldeversuch.
BRAUCHT_BASE_URL = {
    "magiclink_enabled": "Magic-Link und Einladung (Link in der Mail)",
    "password_reset_enabled": "„Passwort vergessen\" (Reset-Link in der Mail)",
    "signup_verify_email": "E-Mail-Bestätigung (Bestätigungslink in der Mail)",
    "oidc_enabled": "OIDC (Redirect-URI zum IdP)",
    "saml_enabled": "SAML (Entity-ID und ACS-URL)",
}

#: Derselbe Gedanke, aber nur eine Warnung: Die Forward-Auth-Umleitung schickt **denselben**
#: Browser auf die eigene Login-Seite. Ohne geprüfte Basis bleibt sie relativ (`/auth/login?…`)
#: und der Browser löst sie gegen den aufgerufenen Host auf — das funktioniert, solange App und
#: TinySesam unter einem Namen liegen. Ein fremder Name kommt so nicht in die Umleitung, es geht
#: nichts an Dritte hinaus, und deshalb ist das kein Grund, den Start zu verweigern.
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


#: Die Direktiven, die eine Content-Security-Policy kennt (CSP Level 3 plus die verbreiteten
#: Altlasten). Eine eigene Policy braucht mindestens eine davon; jede andere gibt eine Warnung.
CSP_DIREKTIVEN = frozenset({
    "default-src", "script-src", "script-src-elem", "script-src-attr", "style-src",
    "style-src-elem", "style-src-attr", "img-src", "font-src", "connect-src", "media-src",
    "object-src", "frame-src", "child-src", "worker-src", "manifest-src", "prefetch-src",
    "fenced-frame-src", "base-uri", "form-action", "frame-ancestors", "navigate-to", "sandbox",
    "upgrade-insecure-requests", "block-all-mixed-content", "report-uri", "report-to",
    "require-trusted-types-for", "trusted-types", "webrtc", "plugin-types", "referrer",
})


def _csp_namen(wert) -> list[str] | None:
    """Die Direktivnamen einer eigenen Policy, klein geschrieben — None für 'strict'/'off'/leer."""
    if not isinstance(wert, str):
        return None
    roh = wert.strip()
    if roh in ("", "strict", "off"):
        return None
    return [teil.split()[0].lower() for teil in roh.split(";") if teil.strip()]


def csp_fehler(wert) -> str:
    """Der Befund zu `csp`, leer wenn in Ordnung (B3-2).

    Alles ausser 'strict' und 'off' ging bis 0.19.0 ungeprüft 1:1 in den Header. Ein Tippfehler
    wie 'Strict' oder 'stirct' war damit eine „eigene Policy" ohne eine einzige Direktive — der
    Browser verwirft so einen Header, und die Seiten liefen **ohne jede CSP**, ohne dass es
    irgendwo auffiel. Ein Fehler ist deshalb nur die Policy ohne eine **einzige** bekannte
    Direktive. Steht eine unbekannte neben bekannten, überspringt der Browser nur sie und wendet
    den Rest an — das ist `csp_warnung` (A3: `require-sri-for`, `disown-opener` hielten eine
    bisher wirksame Policy sonst vom Start ab).
    """
    namen = _csp_namen(wert)
    if namen is None:
        return ""                  # kein String meldet der Konstruktor eigens
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
    """Unbekannte Direktiven neben bekannten: kein Fehler, aber wohl ein Tippfehler.

    Der Browser wendet die Policy ohne sie an. Bei 'scirpt-src' greift dann `default-src` statt
    der gemeinten Regel — das soll im Log stehen. Eine echte, nur hier nicht gelistete Direktive
    geht ebenso durch.
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
    """(Fehler, Warnungen) — beide vollständig, nicht beim ersten Fund abgebrochen."""
    fehler: list[str] = []
    warnungen: list[str] = []

    # Gefragt wird `enabled_methods()` — dieselbe Liste, aus der die Login-Seite ihre Felder
    # baut. Eine zweite, eigene Liste hier hatte genau den Fehler, den sie fangen soll: Sie sah
    # `pin_enabled=True` und übersah `pin_login=False`, und liess damit eine leere Login-Seite
    # durchgehen (PIN nur als Step-up ist der dokumentierte Weg, kein exotischer Wert).
    try:
        aktive = list(config.enabled_methods())
    except Exception:
        aktive = [name for name in ANMELDEND if _an(config, VERFAHREN[name])]
    if not aktive:
        # `ldap_enabled=True` steht NICHT in der Abhilfe (F-30): LDAP ist kein eigenes Feld auf
        # der Login-Seite, sondern prüft das Passwortformular gegen das Verzeichnis. Die Meldung
        # nannte es trotzdem — und wer es befolgte, bekam dieselbe Meldung wieder.
        fehler.append(
            "Keine einzige Anmelde-Methode ist eingeschaltet — die Login-Seite hätte kein "
            "einziges Feld, niemand kann sich anmelden. Mindestens eines von: "
            + ", ".join(f"{VERFAHREN[n]}=True" for n in ANMELDEND if n != "ldap")
            + " (bei PIN zusätzlich pin_login=True, sonst ist sie nur Step-up). LDAP allein "
            "genügt nicht: ldap_enabled=True prüft das Passwortformular gegen das Verzeichnis "
            "und braucht deshalb password_enabled=True.")
    if _an(config, "ldap_enabled") and not _an(config, "password_enabled"):
        # Warnung, kein Fehler: Mit einem zweiten Verfahren (OIDC, Passkey) startet der Aufbau
        # sinnvoll — nur der LDAP-Weg ist dann tot, und das soll der Betreiber wissen.
        warnungen.append(
            "ldap_enabled=True, aber password_enabled=False. LDAP hat kein eigenes Formular, es "
            "prüft das Passwortfeld der Login-Seite gegen das Verzeichnis — ohne "
            "password_enabled=True meldet sich niemand über LDAP an.")

    # Warnung, nicht Fehler: Die Clients für OIDC, SAML und LDAP lassen sich ersetzen
    # (`auth.ldap = eigener_client`), und genau so arbeiten auch die eigenen Suiten. Ein harter
    # Wächter verböte damit einen legitimen Aufbau. Still bleibt es trotzdem nicht — der
    # Normalfall „eingeschaltet und vergessen zu konfigurieren" scheiterte sonst erst beim
    # ersten Klick auf „Anmelden".
    # Ein Feldname, den es gar nicht gibt, wäre die schlimmste Sorte Fehlalarm: Er feuert bei
    # JEDER Konfiguration des Verfahrens und prüft gleichzeitig nie das, was gemeint war. Genau
    # das ist passiert (`ldap_server` statt `ldap_url`, und das Feld kam im ganzen Repo nur in
    # dieser Zeile vor). Deshalb hier eine Zusicherung statt Vertrauen.
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

    # Nebenbefund aus demselben Audit (F-28): Ein Dienstkonto-DN ohne Passwort ist keine
    # anonyme Suche, sondern eine Kombination, die ldap3 von sich aus ablehnt
    # (`LDAPPasswordIsMandatoryError`). Der Fehler fliegt mitten im Login und wird dort
    # verschluckt — der Betreiber sieht für JEDEN Nutzer „Passwort falsch" und sucht am
    # falschen Ende. Warnung statt Fehler, weil der Client zur Laufzeit ersetzbar ist.
    if _an(config, "ldap_enabled") and str(getattr(config, "ldap_bind_dn", "") or "").strip() \
            and not str(getattr(config, "ldap_bind_password", "") or "").strip():
        warnungen.append(
            "ldap_bind_dn ist gesetzt, ldap_bind_password ist leer. Das ist keine anonyme Suche: "
            "ldap3 lehnt DN ohne Passwort ab, der Fehler fällt erst beim Login an und sieht dort "
            "für jeden Nutzer wie ein falsches Passwort aus. Entweder das Passwort des "
            "Dienstkontos setzen oder ldap_bind_dn leeren (dann wird wirklich anonym gesucht).")

    # Ein Kettenschritt muss ein Faktor sein, den eine Sitzung auch bekommen kann. `ldap` ist
    # keiner (es schreibt den Faktor `password`), `apikey` ebenso wenig — beide standen trotzdem
    # in der Whitelist, und `login_chain=["ldap","totp"]` ist für einen LDAP-Betreiber die
    # naheliegendste Schreibweise. Sie führte in genau die Schleife, vor der dieses Modul warnt.
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

    # Hier stand kurzzeitig „resource_locks_enabled braucht pin_enabled". Das war falsch und
    # eine eigene Suite hat es sofort widerlegt: Eine gesperrte Ressource wird mit ihrem EIGENEN
    # Geheimnis freigegeben (`store.get_resource_secret`), nicht mit der Login-PIN. Ein
    # Fehlalarm kostet dasselbe Vertrauen wie ein übersehener Fund — deshalb steht die Notiz
    # hier statt der Prüfung.

    if _an(config, "password_reset_enabled") and not _an(config, "magiclink_enabled"):
        warnungen.append(
            "password_reset_enabled=True, aber magiclink_enabled=False. Die Routen sind montiert, "
            "der Link „Passwort vergessen?\" erscheint auf der Login-Seite aber nicht — die "
            "Funktion ist an und für niemanden erreichbar.")
    if _an(config, "allow_signup") and not _an(config, "password_enabled"):
        fehler.append(
            "allow_signup=True mit password_enabled=False legt Konten an, die sich nie anmelden "
            "können — die Registrierung vergibt ein Passwort, und der Passwort-Login ist aus.")

    # `base_url` fehlte in diesem Modul komplett — und damit fehlte der einzige Hinweis auf
    # den Weg, den R4-01/R8-4 ausnutzt: Ohne sie baut TinySesam absolute Adressen aus dem
    # `Host`-Header, also aus einer Eingabe des Anfragenden.
    #
    # Hier stand eine **Warnung**, mit zwei Begründungen — der lokale Aufbau (Loopback zählt als
    # eigener Host) und ein `base_url`, das erst nach dem Konstruktor gesetzt wird. Beide haben
    # nicht getragen, die Nacharbeit hat es gemessen:
    #
    # * Eine Warnung startet durch. Wer ohne `base_url` aktualisierte, verlor „Passwort
    #   vergessen" und Magic-Link für ALLE Nutzer — und zwar still: Die Route rendete weiter die
    #   Erfolgsseite („Mail ist unterwegs", HTTP 200), weil dieselbe Antwort die
    #   Benutzer-Enumeration verhindert. Sichtbar war es in einer Logzeile.
    # * Stehen mehrere Hosts in `trusted_redirect_hosts` — beim Forward-Auth/SSO der Normalfall —
    #   genügte der Laufzeit-Prüfung JEDER davon. Der Angreifer stieß „Passwort vergessen" für
    #   ein fremdes Postfach an und setzte `Host:` auf einen anderen mitvertrauten Host; der
    #   Reset-Link ging dorthin hinaus. `base_url` schließt genau diese Wahlfreiheit: Steht sie,
    #   kommt gar nichts aus dem Request.
    #
    # Deshalb jetzt ein **Fehler**: Der Aufbau scheitert mit `ConfigError`, statt einen Betrieb
    # zu erlauben, der still das Falsche tut. Der lokale Aufbau trägt seine Adresse einfach ein
    # (`base_url="http://127.0.0.1:8000"`), und wer sie erst spät kennt, schreibt sie ans
    # Config-Objekt, BEVOR `TinySesam(config)` läuft — anders als `set_mailer()` gibt es dafür
    # keinen Nachreich-Weg, denn ohne Basis endet der erste Klick auf „Passwort vergessen"
    # bereits im Nichts.
    # Geprüft wird mit **derselben** Funktion, die `public_base()` später anwendet
    # (`security.normalisiere_basis`), nicht mit einem eigenen, schwächeren Muster: Ein grobes
    # Schema-und-Host-Muster nahm `https://wer:was@auth.example` und `https://auth.example/x#y`
    # ab — beides stünde danach in jedem Reset-Link, und der Teil hinter `#` erreicht nicht
    # einmal den Server. Zwei Regelwerke für dieselbe Frage sind eines zu viel (C-7).
    _basis = str(getattr(config, "base_url", "") or "").strip()
    _kanonisch = security.normalisiere_basis(_basis)
    if _basis and _kanonisch and _kanonisch != _basis.rstrip("/"):
        # Die Adresse ist brauchbar, aber sie wird unterwegs verändert — das sagen wir hier,
        # statt es still zu tun. Häufigster Fall: eine Benutzerangabe im Host
        # (`https://wer:was@auth.example`), die aus jedem ausgehenden Link entfernt wird.
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
    # Erst-Admin-Token: Der Wert darf nicht dort landen, wo ihn Fremde lesen. Genau das war
    # B5-03 — er stand in der Datei, die die fail2ban-Jail liest und logrotate archiviert.
    token_datei = str(getattr(config, "admin_claim_token_file", "") or "").strip()
    seclog_datei = str(getattr(config, "security_log", "") or "").strip()
    if token_datei and seclog_datei and os.path.abspath(token_datei) == os.path.abspath(seclog_datei):
        fehler.append(
            "admin_claim_token_file und security_log zeigen auf dieselbe Datei. Damit stünde das "
            "Erst-Admin-Einmal-Token wieder in dem Log, das fail2ban liest, logrotate archiviert "
            "und ein Log-Versand mitnimmt — wer es liest, wird Admin. Für den Token eine eigene "
            "Datei nehmen (z.B. /run/<dienst>/admin-claim.token) oder das Feld leer lassen, dann "
            "geht der Wert auf stderr.")
    if token_datei and (int(getattr(config, "admin_claim_ttl_min", 0) or 0) <= 0
                        or not _an(config, "admin_enabled")):
        warnungen.append(
            "admin_claim_token_file ist gesetzt, aber der Token-Weg ist aus "
            "(admin_claim_ttl_min=0 oder admin_enabled=False) — die Datei wird nie geschrieben. "
            "Der Erst-Admin kommt dann nur über admin_identifiers oder einen eigenen Aufruf "
            "von auth.ensure_admin(…) zustande — das CLI kann keine Konten anlegen.")

    # Erst-Admin per Allowlist-ADRESSE, während SAML oder LDAP Konten selbst anlegt: Der
    # Konstruktor verbietet an dieser Stelle Allowlist-*Namen* (die bestätigt niemand). Eine
    # Adresse bleibt erlaubt — aber sie trägt die Entscheidung nur mit Beleg, und einen Beleg
    # gibt es allein bei OIDC (`email_verified`). SAML und LDAP kennen keinen: Kein
    # Standardattribut sagt, dass die Adresse geprüft wurde, und ein `mail`-Attribut pflegt
    # der Nutzer in vielen Verzeichnissen selbst. Die Laufzeit befördert dort deshalb nie
    # (fail-closed, F-14) — wer den ersten Admin über diesen Weg erwartet, wartet umsonst.
    # Warnung, nicht Fehler: Derselbe Aufbau ist mit einem lokalen Passwort-Login (bestätigte
    # Adresse) völlig tragfähig, und der Betreiber soll nur wissen, welcher Weg zählt.
    allowlist_adressen = sorted({str(i).strip() for i in
                                 (getattr(config, "admin_identifiers", None) or [])
                                 if "@" in str(i)})
    ohne_beleg = [name for an, anlegen, name in (("saml_enabled", "saml_auto_create", "SAML"),
                                                 ("ldap_enabled", "ldap_auto_create", "LDAP"))
                  if _an(config, an) and _an(config, anlegen)]
    if allowlist_adressen and ohne_beleg:
        warnungen.append(
            f"admin_identifiers nennt die Adresse(n) {allowlist_adressen}, und "
            + " und ".join(ohne_beleg) +
            " legt Konten beim ersten Login selbst an. Über diese Wege wird die Adresse NIE "
            "zum Erst-Admin: Weder SAML noch LDAP liefern einen Bestätigungsbeleg für eine "
            "Adresse (bei OIDC ist es der Claim email_verified), und ohne Beleg befördert "
            "TinySesam nicht — sonst genügte ein IdP mit Selbstregistrierung oder ein "
            "Verzeichnis, in dem der Nutzer sein mail-Attribut selbst pflegt. Der belegte "
            "Weg ist das Einmal-Token: anmelden, dann /auth/claim-admin (s. "
            "admin_claim_ttl_min); danach vergibt der Erst-Admin die Rechte selbst. Ein "
            "lokaler Passwort-Login mit bestätigter Adresse befördert weiterhin.")

    # --- Mehrere Anwendungen hinter einer Installation (T-14) ---
    _clients = getattr(config, "oidc_clients", None) or {}
    # Typ und Bereich prüft ZAHLENGRENZEN (unten, samt negativer Werte); hier nur die
    # Kombination. Ein `int()` auf einen Text liess die ganze Prüfung abstürzen.
    _revalidate = getattr(config, "oidc_revalidate_minutes", 0)
    if isinstance(_revalidate, bool) or not isinstance(_revalidate, int):
        _revalidate = 0
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

    # --- Selbst-Enrollment des zweiten Faktors (R3-1) ---
    _arten = ("first_login", "grace", "strict")
    _art = str(getattr(config, "mfa_enrollment", "") or "first_login")
    if _art not in _arten:
        fehler.append(
            f"mfa_enrollment={_art!r} gibt es nicht. Erlaubt sind {list(_arten)}: 'first_login' "
            "(Vorgabe, erlaubt bis zum ersten vollständigen Login), 'grace' (erlaubt "
            "mfa_enrollment_grace_days ab Kontoanlage), 'strict' (nie — die Einrichtung kommt "
            "dann vom Betreiber).")
    if _art == "grace" and int(getattr(config, "mfa_enrollment_grace_days", 0) or 0) <= 0:
        fehler.append(
            "mfa_enrollment='grace', aber mfa_enrollment_grace_days ist 0 oder kleiner. Damit "
            "verhält sich 'grace' wie 'strict', nur unauffälliger — entweder eine Frist setzen "
            "oder gleich mfa_enrollment='strict' schreiben.")

    # --- CSRF-Schutz ganz aus (F-03) ---
    # Einzeln ist jeder Wert vertretbar: `csrf_enabled=False`, weil SameSite=Lax die
    # Cross-Site-POSTs schon abfängt; `cookie_samesite='none'` für eine eingebettete App, weil
    # das CSRF-Token dann schützt. Zusammen bleibt NICHTS: Das Sitzungs-Cookie fährt bei jedem
    # fremden Formular mit, und niemand prüft ein Token. Das ist kein Kompromiss, das ist ein Loch.
    if (not _an(config, "csrf_enabled")
            and str(getattr(config, "cookie_samesite", "lax") or "").lower() == "none"):
        fehler.append(
            "csrf_enabled=False zusammen mit cookie_samesite='none': Dann schickt der Browser "
            "das Sitzungs-Cookie bei jedem Formular einer fremden Seite mit, und kein Token "
            "hält dagegen — jede zustandsändernde Route ist per CSRF auslösbar. Entweder "
            "csrf_enabled=True (nötig, sobald SameSite=None gebraucht wird) oder "
            "cookie_samesite='lax'.")

    # --- Nutzerprüfung bei Passkeys (B2-10) ---
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

    # --- LDAP-Transport (F-12) ---
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
    _kombinationen(config, fehler, warnungen)

    hat_mailer = bool(str(getattr(config, "smtp_host", "") or "").strip())
    # --- SMTP-TLS (B3-1, Angriff A4): Seit das Zertifikat geprüft wird, scheitert ein falscher
    # CA-Pfad oder ein Relay per IP-Adresse bei JEDER Mail — und zwar still, nur als
    # *_send_error im Audit-Log. Beides lässt sich schon beim Aufbau erkennen.
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

    # `audit_retention_days` prüft ZAHLENGRENZEN (unten): Eine negative Frist wäre in `gc()` ein
    # Zeitpunkt in der Zukunft — das ganze Audit-Log fiele beim nächsten Lauf weg. Die eigene
    # Prüfung, die hier stand, kannte nur `< 0` und liess `True`, Sekunden statt Tagen und
    # Riesenwerte (OverflowError in gc()) durch.

    return fehler, warnungen


#: Zahlenfelder der Config → erlaubter Bereich, beide Grenzen eingeschlossen (B3-12).
#:
#: Vorher hatte kein einziges eine Grenze, und die Fehlbilder sind alle still: `session_ttl_hours=0`
#: lässt jede Sitzung im Moment ihrer Entstehung ablaufen (Anmeldung „klappt", der nächste Klick
#: ist wieder die Login-Seite), `magiclink_ttl_min=0` verschickt tote Links, `recovery_code_count=0`
#: stellt keine Codes aus und meldet trotzdem Erfolg, ein negatives `stepup_max_age_sec` macht
#: jede Step-up-Bestätigung sofort alt. Die Obergrenzen fangen den Einheitenfehler (Minuten statt
#: Stunden, Sekunden statt Minuten), der eine Frist unbemerkt ver-sechzigfacht.
ZAHLENGRENZEN = {
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
    # 0 = keine Frist. Zehn Jahre (samt Schalttagen) reichen für jede Aufbewahrungspflicht;
    # darüber liegt fast immer die Frist in Sekunden (2592000 für 30 Tage), die nie griffe.
    # `True` galt hier als ein Tag, und gc() löschte das Audit-Log bis auf den letzten Tag.
    "audit_retention_days": (0, 3660),
    # 0 = keine Nachprüfung. Ein Entzug beim Provider, der erst nach mehr als 30 Tagen ankommt,
    # ist keine Nachprüfung mehr; `86400` (ein Tag in Sekunden statt Minuten) fällt so auf.
    "oidc_revalidate_minutes": (0, 30 * 24 * 60),
}


def _zahlengrenzen(config, fehler: list) -> None:
    for feld, (unten, oben) in ZAHLENGRENZEN.items():
        if not hasattr(config, feld):
            fehler.append(f"Die Konfigurationsprüfung nennt das Feld {feld!r}, das es in "
                          "TinySesamConfig nicht gibt — ein Fehler in TinySesam selbst.")
            continue
        wert = getattr(config, feld)
        # bool ist ein int: `session_ttl_hours=True` hiesse eine Stunde, gemeint war es nie.
        if isinstance(wert, bool) or not isinstance(wert, int):
            fehler.append(f"{feld}={wert!r} ist keine ganze Zahl.")
            continue
        if not unten <= wert <= oben:
            fehler.append(f"{feld}={wert} liegt ausserhalb von {unten}…{oben}. Häufigster Grund "
                          "ist eine verwechselte Einheit (der Feldname nennt sie).")


def _proxies_und_passkey(config, fehler: list, warnungen: list) -> None:
    # --- trusted_proxies (B3-3) ---
    # Ein ungültiger Eintrag warf zur Laufzeit mitten in der Prüfung und entwertete die GANZE
    # Liste; die Warnung danach riet, das Proxy-Netz einzutragen, das längst dastand. Ein
    # Hostname ist der häufigste Fall — Proxys werden hier als Netz angegeben, nicht als Name.
    schlecht = security.ungueltige_netze(getattr(config, "trusted_proxies", None) or [])
    if schlecht:
        fehler.append(
            f"trusted_proxies enthält Einträge, die kein IP-Netz sind: {schlecht}. Erwartet "
            "werden Adressen oder Netze wie '203.0.113.5' oder '198.51.100.0/24' — keine Hostnamen. "
            "Ein ungültiger Eintrag darf nicht mitgelesen werden: Er entschiede sonst, ob der "
            "Proxy als vertrauenswürdig gilt.")

    # --- WebAuthn: rp_id und origin (B3-10) ---
    # Beide Felder tragen Entwicklerwerte als Vorgabe (`localhost`, `http://localhost:8000`).
    # Produktiv vergessen scheitert JEDE Passkey-Zeremonie — erst im Browser, mit einer Meldung,
    # die nach einem Problem des Authenticators aussieht. Geprüft wird, was sich ohne die
    # Aussenwelt beweisen lässt: Form, Zusammenpassen, und der Abgleich mit `base_url`.
    if not _an(config, "passkey_enabled"):
        return
    from urllib.parse import urlsplit
    rp_id = str(getattr(config, "rp_id", "") or "").strip().lower()
    roh = getattr(config, "origin", "")
    roh = "" if roh is None else roh
    # py_webauthn nimmt als `expected_origin` auch eine Liste (A5): Wer die Anmeldeseite unter
    # mehreren Namen ausliefert, trägt sie alle ein. Geprüft wird dann jeder Eintrag einzeln —
    # `str(liste)` ist nie ein Origin, und so wurde aus einer funktionierenden Config ein Fehler.
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
            # Warnung, kein Fehler: Wer die Anmeldeseite unter einem zweiten eigenen Namen
            # ausliefert (base_url nur für die Mail-Links), kann es so wollen.
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


#: Was in `stepup_methods` stehen darf, und welcher Schalter das Verfahren einschaltet.
STEPUP_VERFAHREN = {"totp": "totp_enabled", "pin": "pin_enabled", "password": "password_enabled"}


def _stepup(config, fehler: list, warnungen: list) -> None:
    # B3-6: `stepup_methods` ist ein Wunsch, und ein Wunsch, den es nicht gibt, wird still
    # übergangen — `["topt"]` fiel auf „alles, was der Nutzer hat" zurück, also auf das Passwort,
    # mit dem er sich gerade angemeldet hat. Der zweite Faktor vor dem sensiblen Bereich war weg,
    # und nichts hat es gesagt. Mit `stepup_strict=True` war es umgekehrt: niemand kam je hinein.
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
    """Deny-by-default für das Tor vor fremden Anwendungen (H-11, B3-9).

    Forward-Auth beantwortet für jede angemeldete Sitzung „durch" — ohne `?roles=` am Proxy
    reicht es also, ein Konto zu HABEN. Woher Konten kommen, entscheidet damit über den Kreis:
    Legt ein IdP-Weg Konten selbst an und begrenzt keine Gruppe, ist jedes Konto beim Provider
    ein Schlüssel für jede geschützte Anwendung; bei offener Registrierung jeder Besucher.

    Warnung, kein Fehler: Genau so ist ein Gateway vor einem Provider mit eigenem, geschlossenem
    Nutzerkreis gedacht, und die Freigabe je Anwendung kann auch beim Provider liegen
    (`oidc_clients`, T-14). Ein Fehler hiesse, diesen Aufbau zu verbieten — das zu entscheiden
    wäre ein neuer Schalter (bewusstes „alle"), nicht eine Prüfung.
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
            # Je Anwendung ein eigener Client (T-14): Die Freigabe liegt beim Provider, und
            # `/auth/forward` prüft sie je Host. Das ist ein geschlossenes Tor — nur eben eines,
            # dessen Schlüssel der Provider verwaltet.
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


def _kombinationen(config, fehler: list, warnungen: list) -> None:
    """Kombinationen, die einzeln erlaubt sind und zusammen nicht tun, was sie sagen (B3-16)."""
    # E-Mail-Bestätigung ohne Pflicht-Adresse: Wer das Feld leer lässt, bekommt ein SOFORT
    # aktives Konto — die Bestätigung gilt nur für die, die eine Adresse angeben. Die Schranke
    # hat also eine Tür daneben.
    if _an(config, "allow_signup") and _an(config, "signup_verify_email") \
            and not _an(config, "signup_require_email"):
        fehler.append(
            "signup_verify_email=True, aber signup_require_email=False: Wer bei der Registrierung "
            "keine Adresse angibt, ist ohne jede Bestätigung sofort aktiv. Entweder "
            "signup_require_email=True oder auf die Bestätigung verzichten.")
    if _an(config, "signup_invite_only") and not _an(config, "allow_signup"):
        warnungen.append("signup_invite_only=True ohne allow_signup=True ist wirkungslos — die "
                         "Registrierung ist ohnehin aus.")
    lang, kurz = getattr(config, "session_ttl_hours", 0), getattr(config, "session_ttl_transient_hours", 0)
    if isinstance(lang, int) and isinstance(kurz, int) and kurz > lang:
        warnungen.append(
            f"session_ttl_transient_hours={kurz} ist länger als session_ttl_hours={lang}: Ohne "
            "„Angemeldet bleiben\" bliebe man länger angemeldet als mit.")
    for feld in ("admin_path", "login_path", "oidc_callback_path"):
        wert = str(getattr(config, feld, "") or "")
        if wert and not wert.startswith("/"):
            fehler.append(f"{feld}={wert!r} muss mit '/' beginnen — sonst ist es kein Pfad, und "
                          "Routen wie Links zeigen ins Leere.")
    # cookie_domain, die den eigenen Host nicht umfasst: Der Browser verwirft das Cookie, jede
    # Anmeldung „klappt" und der nächste Klick ist wieder die Login-Seite.
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
    # Demo-Modus neben einem echten Anmeldeweg (B3-8): Die Demo-Konten haben ein bekanntes
    # Passwort, eines ist Admin. Neben OIDC/SAML/LDAP ist das keine Demo mehr, sondern eine
    # Produktivinstanz mit einer Hintertür.
    if _an(config, "demo_mode"):
        echt = [feld for feld in ("oidc_enabled", "saml_enabled", "ldap_enabled", "forward_auth_enabled")
                if _an(config, feld)]
        if echt:
            fehler.append(
                f"demo_mode=True zusammen mit {', '.join(echt)}: Die Demo legt ein Admin-Konto mit "
                "bekanntem Passwort an. Neben einem echten Anmeldeweg oder vor fremden Anwendungen "
                "ist das eine Hintertür, keine Vorführung.")
