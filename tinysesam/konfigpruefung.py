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

#: Was eine **absolute** Adresse nach draußen baut: Mail-Links, Redirect-URIs, SAML-Metadaten.
#: Fehlt `base_url`, bliebe dafür nur der `Host`-Header — und den setzt der Anfragende (R4-01).
BRAUCHT_BASE_URL = {
    "magiclink_enabled": "Magic-Link und Einladung (Link in der Mail)",
    "password_reset_enabled": "„Passwort vergessen\" (Reset-Link in der Mail)",
    "signup_verify_email": "E-Mail-Bestätigung (Bestätigungslink in der Mail)",
    "oidc_enabled": "OIDC (Redirect-URI zum IdP)",
    "saml_enabled": "SAML (Entity-ID und ACS-URL)",
    "forward_auth_enabled": "Forward-Auth (Umleitung des Proxys auf die Login-Seite)",
}


def _an(config, feld: str) -> bool:
    return bool(getattr(config, feld, False))


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
        fehler.append(
            "Keine einzige Anmelde-Methode ist eingeschaltet — die Login-Seite hätte kein "
            "einziges Feld, niemand kann sich anmelden. Mindestens eines von: "
            + ", ".join(f"{VERFAHREN[n]}=True" for n in ANMELDEND)
            + " (bei PIN zusätzlich pin_login=True, sonst ist sie nur Step-up).")

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
    # `Host`-Header, also aus einer Eingabe des Anfragenden. Seit dieser Fassung lehnt die
    # Laufzeit einen fremden Host ab (`TinySesam.public_base`) — die Funktion ist damit nicht
    # unsicher, sondern schlicht aus. Warnung statt Fehler, weil zweierlei legitim bleibt: der
    # lokale Aufbau (Loopback zählt als eigener Host) und ein `base_url`, das erst nach dem
    # Konstruktor gesetzt wird (die Config wird zur Request-Zeit gelesen).
    if not str(getattr(config, "base_url", "") or "").strip():
        betroffen = [wofuer for feld, wofuer in BRAUCHT_BASE_URL.items() if _an(config, feld)]
        if betroffen:
            warnungen.append(
                "base_url ist leer, aber diese Funktionen bauen absolute Adressen: "
                + "; ".join(betroffen)
                + ". Als Quelle bliebe der Host-Header der jeweiligen Anfrage — den setzt der "
                "Anfragende, und bei einer Mail an ein fremdes Postfach ist das der Angreifer. "
                "TinySesam lässt deshalb nur Hosts aus trusted_redirect_hosts und Loopback "
                "durch und bricht sonst ab (es geht keine Mail hinaus, der Flow endet mit "
                "einem Fehler). Abhilfe: base_url auf die öffentliche Adresse setzen.")

    hat_mailer = bool(str(getattr(config, "smtp_host", "") or "").strip())
    for feld, wofuer in BRAUCHT_MAILER.items():
        if _an(config, feld) and not hat_mailer:
            warnungen.append(
                f"{feld}=True ({wofuer}), aber smtp_host ist leer. Ohne Mailer geht keine Mail "
                "hinaus und das Verfahren endet still. Entweder smtp_host setzen oder zur "
                "Laufzeit auth.set_mailer(...) aufrufen — dann ist diese Meldung gegenstandslos.")

    return fehler, warnungen
