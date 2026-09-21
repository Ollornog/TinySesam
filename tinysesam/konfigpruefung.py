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

#: Verfahren, mit dem sich ein Mensch ANMELDEN kann. `apikey` zählt nicht: Ein Schlüssel wird
#: von einem Konto ausgestellt, das es erst geben muss.
ANMELDEND = ("password", "pin", "passkey", "oidc", "saml", "ldap", "magic")

#: Verfahren → Felder, ohne die es nicht funktionieren kann.
PFLICHTFELDER = {
    "oidc": ("oidc_issuer", "oidc_client_id"),
    "saml": ("saml_idp_sso_url", "saml_idp_x509cert"),
    "ldap": ("ldap_server",),
}

#: Was einen Mailer braucht. Kein Fehler — `set_mailer` kommt oft später.
BRAUCHT_MAILER = {
    "magiclink_enabled": "Magic-Link-Anmeldung",
    "password_reset_enabled": "„Passwort vergessen\"",
    "signup_verify_email": "E-Mail-Bestätigung bei der Registrierung",
}


def _an(config, feld: str) -> bool:
    return bool(getattr(config, feld, False))


def pruefe(config) -> tuple[list[str], list[str]]:
    """(Fehler, Warnungen) — beide vollständig, nicht beim ersten Fund abgebrochen."""
    fehler: list[str] = []
    warnungen: list[str] = []

    aktive = [name for name in ANMELDEND if _an(config, VERFAHREN[name])]
    if not aktive:
        fehler.append(
            "Keine einzige Anmelde-Methode ist eingeschaltet — niemand kann sich anmelden. "
            "Mindestens eines von: " + ", ".join(f"{VERFAHREN[n]}=True" for n in ANMELDEND))

    # Warnung, nicht Fehler: Die Clients für OIDC, SAML und LDAP lassen sich ersetzen
    # (`auth.ldap = eigener_client`), und genau so arbeiten auch die eigenen Suiten. Ein harter
    # Wächter verböte damit einen legitimen Aufbau. Still bleibt es trotzdem nicht — der
    # Normalfall „eingeschaltet und vergessen zu konfigurieren" scheiterte sonst erst beim
    # ersten Klick auf „Anmelden".
    for name, felder in PFLICHTFELDER.items():
        if not _an(config, VERFAHREN[name]):
            continue
        leer = [f for f in felder if not str(getattr(config, f, "") or "").strip()]
        if leer:
            warnungen.append(
                f"{VERFAHREN[name]}=True, aber {', '.join(leer)} ist leer. So kann das Verfahren "
                "nicht arbeiten und scheitert beim ersten Anmeldeversuch — es sei denn, der "
                "Client wird zur Laufzeit ersetzt.")

    kette = list(getattr(config, "login_chain", None) or [])
    unbekannt = [s for s in kette if s not in VERFAHREN and s != "totp"]
    if unbekannt:
        fehler.append(f"login_chain nennt unbekannte Schritte {unbekannt} — erlaubt sind "
                      f"{sorted(VERFAHREN)} und 'totp'.")
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

    hat_mailer = bool(str(getattr(config, "smtp_host", "") or "").strip())
    for feld, wofuer in BRAUCHT_MAILER.items():
        if _an(config, feld) and not hat_mailer:
            warnungen.append(
                f"{feld}=True ({wofuer}), aber smtp_host ist leer. Ohne Mailer geht keine Mail "
                "hinaus und das Verfahren endet still. Entweder smtp_host setzen oder zur "
                "Laufzeit auth.set_mailer(...) aufrufen — dann ist diese Meldung gegenstandslos.")

    return fehler, warnungen
