"""Nachgestellte Befunde des zweiten Audits (2026-09-21).

Der erste Durchgang reparierte sechs Lücken. Dieser hier prüft die **Reparaturen** — und drei
davon hatten ihr eigenes Loch aufgerissen: Der Erst-Admin-Wächter verschob die Lücke nur, die
API-Key-Beschneidung machte einen Key mächtiger statt schwächer, und `tinysesam backup`
migrierte die Datei, die es sichern sollte.

Wie in `test_sicherheit_befunde.py`: benannt nach dem ANGRIFF bzw. dem Betriebsfall, nicht nach
der Funktion. Wer eine Zeile hier rot sieht, weiss sofort, was wieder möglich ist.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import security as _sec  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Audit Runde 2 — die Reparaturen der Reparaturen")


def _app(**cfg):
    tmp = tempfile.mkdtemp()
    # `base_url` gehört in die Grundausstattung, seit sie bei Mail-Wegen/OIDC/SAML Pflicht ist:
    # ohne sie scheiterte hier jeder Aufbau — und zwar aus einem Grund, der mit dem geprüften
    # Befund nichts zu tun hat. Ein einzelner Aufruf überschreibt sie weiterhin.
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False,
                 base_url="http://testserver")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── Erst-Admin über den BENUTZERNAMEN ─────────────────────────────────────────
# Der Wächter aus Runde 1 verlangt bei offener Registrierung eine E-MAIL in `admin_identifiers`
# („den Namen hat, wer das Postfach hat"). `maybe_promote_admin` verglich aber weiter Name ODER
# E-Mail — und der Benutzername ist ein freies Textfeld. Die Lücke war nur verschoben.
auth_a, _ = _app(admin_identifiers=["chef@example.com"], allow_signup=True,
                 signup_require_email=True, signup_verify_email=True,
                 magiclink_enabled=True, smtp_host="mail.example.com")
angreifer = auth_a.create_user("chef@example.com", password="geheim12345",
                               email="angreifer@evil.example")
r.check("wer sich unter der Admin-ADRESSE als Benutzername registriert, wird nicht Admin",
        not auth_a.maybe_promote_admin(auth_a.get_user(angreifer)),
        "er ist Admin — der Wächter prüft die Konfiguration, der Vergleich etwas anderes")

# Eigene Instanz: seit R4-12 kann dieselbe Zeichenfolge nicht Benutzername des einen und
# E-Mail des anderen sein. Der rechtmäßige Inhaber wird deshalb in einem sauberen Bestand
# geprüft — die Frage hier ist die Beförderung, nicht die Eindeutigkeit.
auth_a2, _ = _app(admin_identifiers=["chef@example.com"], allow_signup=True,
                  signup_require_email=True, signup_verify_email=True,
                  magiclink_enabled=True, smtp_host="mail.example.com")
inhaber = auth_a2.create_user("chefin", password="geheim12345", email="chef@example.com")
r.check("wer die Adresse wirklich hat, wird es weiterhin",
        auth_a2.maybe_promote_admin(auth_a2.get_user(inhaber)),
        "der vorgesehene Weg ist zu")

# Und umgekehrt: Ein Eintrag OHNE @ gilt nur für den Benutzernamen.
auth_b, _ = _app(admin_identifiers=["chef"])
mit_mail = auth_b.create_user("jemand", password="geheim12345", email="chef")
r.check("ein Allowlist-Name ohne @ wird nicht gegen die E-Mail geprüft",
        not auth_b.maybe_promote_admin(auth_b.get_user(mit_mail)),
        "eine E-Mail, die zufällig wie der Name aussieht, befördert")


# ── Erst-Admin über eine IdP-Adresse, die niemand bestätigt hat (Runde 3, F-14) ──
# Der T-9-Fix oben reparierte den VERGLEICH (Adresse gegen Adresse) — der BELEG fehlte weiter.
# `oidc.py` las `email` bedingungslos und übersah den Standard-Claim `email_verified` (OIDC
# Core 5.1): Wer sich bei einem IdP mit Selbstregistrierung oder in einem zweiten Mandanten
# die Admin-Adresse einträgt, war beim ersten Login Erst-Admin. Und der Wächter, der
# Allowlist-BENUTZERNAMEN verbietet, hing allein an `allow_signup` — beim Auto-Anlegen durch
# einen IdP griff er gar nicht, obwohl auch dort der Name aus fremder Hand kommt.
from urllib.parse import parse_qs, urlparse  # noqa: E402

IDP = "https://idp.example.invalid"


class _Claims(dict):
    """Was `exchange()` zurückgibt. Die Signaturprüfung selbst prüft test_oidc_jwks.py —
    hier geht es um das, was TinySesam MIT den Claims macht."""

    def validate(self, *a, **k):
        pass


def _oidc_app(claims, nutzerinfo=None, **cfg):
    """Eine App mit OIDC, aber ohne Netz: Discovery vorbefüllt, Token-Tausch als Attrappe.

    `nutzerinfo` ist das, was der /userinfo-Endpunkt zurückgibt — getrennt vom ID-Token,
    weil genau diese Trennung geprüft wird."""
    auth, app = _app(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                     oidc_client_secret="geheim", base_url="http://testserver",
                     csrf_enabled=False, **cfg)
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
    # Ersetzt wird nur der HTTP-Abruf; der `sub`-Abgleich aus F-18 läuft über die ECHTE
    # Funktion. Eine Attrappe, die ihn nachbaut, prüft sonst den Nachbau statt den Code —
    # eine entfernte Prüfung fiele dann hier nicht auf.
    def _userinfo(at, erwartetes_sub=""):
        from tinysesam.oidc import OIDCClient
        return OIDCClient.userinfo_pruefen(dict(nutzerinfo or {}) or {}, erwartetes_sub)

    auth.oidc.userinfo = _userinfo
    return auth, app


def _oidc_login(app):
    """Einmal durch den echten Flow — Start, state, Callback aus demselben Browser."""
    c = TestClient(app)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


ANGRIFF = {"sub": "angreifer-123", "preferred_username": "angreifer", "name": "Angreifer",
           "email": "chef@example.com", "email_verified": False}

auth_f, app_f = _oidc_app(ANGRIFF, admin_identifiers=["chef@example.com"])
antwort = _oidc_login(app_f)
konto = auth_f.store.get_user_by_name("angreifer")
r.check("der Angreifer kommt herein (die Anmeldung selbst bleibt erlaubt)",
        antwort.status_code == 303 and konto is not None,
        f"HTTP {antwort.status_code} — dann misst der Rest nichts")
r.check("wer eine UNBESTÄTIGTE IdP-Adresse mitbringt, wird nicht Erst-Admin",
        konto is not None and not konto["is_admin"],
        "er ist Admin — email_verified wird wieder ignoriert")
r.check("die Instanz hat danach immer noch keinen Admin", not auth_f.admin_exists(),
        "irgendein Weg hat doch befördert")
# Die Adresse wird NICHT verwendet (H-3, PO-Entscheid 2026-09-24). Bis dahin wurde sie geführt
# und als `Remote-Email` weitergereicht, nur ohne Rechte in TinySesam — eine geschützte App, die
# Nutzer über die Adresse zuordnet, sah den Vermerk aber nie. Für einen Provider, der den Claim
# nie schickt, sagt der Betreiber es ausdrücklich (`oidc_email_verified_default=True`).
r.check("die unbestätigte Adresse wird nicht übernommen und geht nicht als Remote-Email weiter",
        konto is not None and not konto["email"]
        and not auth_f.forward_response_headers(konto).get("Remote-Email"),
        f"gespeichert: {konto['email'] if konto else '—'} — die fremde Adresse erreicht die App")
r.check("… ist aber als unbestätigt vermerkt", konto is not None and not konto["email_verified"],
        "der Vermerk fehlt — dann trägt sie beim nächsten Login wieder Rechte")
# Der Vermerk steht in der Datenbank, nicht im Anmeldeweg: Genau hier wäre der Schutz sonst
# offen. Derselbe Datensatz über einen lokalen Weg (Magic-Link, Passwort) angemeldet reist mit
# `email_bestaetigt=None` an — vor dem Vermerk hätte das befördert.
r.check("auch ein Login OHNE Beleg im Gepäck befördert dieses Konto nicht",
        not auth_f.maybe_promote_admin(auth_f.get_user(konto["id"])),
        "über einen lokalen Weg ist die unbestätigte Adresse doch Erst-Admin-fähig")

# Gegenprobe — ohne sie wäre die Prüfung oben auch dann grün, wenn OIDC gar nichts täte.
auth_g, app_g = _oidc_app({**ANGRIFF, "sub": "chefin-1", "preferred_username": "chefin",
                           "email_verified": True},
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_g)
chefin = auth_g.store.get_user_by_name("chefin")
r.check("mit email_verified=true wird der vorgesehene Erst-Admin weiterhin vergeben",
        chefin is not None and chefin["is_admin"] == 1,
        "der dokumentierte Bootstrap-Weg ist zu")
r.check("und die bestätigte Adresse steht im Konto",
        chefin is not None and chefin["email"] == "chef@example.com"
        and bool(chefin["email_verified"]),
        f"gespeichert: {chefin['email'] if chefin else '—'}")

# Der Claim ist in OIDC Core 5.1 OPTIONAL, und manche IdPs schicken ihn nie (Entra ID nennt der
# Code selbst). Wer seine Adressen selbst verantwortet, dreht das Nein für den FEHLENDEN Claim
# um — sonst wäre `admin_identifiers` für diese IdPs dauerhaft zu.
auth_v, app_v = _oidc_app({"sub": "entra-1", "preferred_username": "chefin",
                           "email": "chef@example.com"},        # Claim fehlt ganz
                          admin_identifiers=["chef@example.com"],
                          oidc_email_verified_default=True)
_oidc_login(app_v)
entra = auth_v.store.get_user_by_name("chefin")
r.check("mit oidc_email_verified_default=True zählt eine Adresse ohne Claim als belegt",
        entra is not None and entra["is_admin"] == 1 and bool(entra["email_verified"]),
        f"Konto: {dict(entra) if entra else None} — für Entra-IdPs bliebe der Weg zu")
# Der Schalter gilt nur für das SCHWEIGEN des Providers. Sagt er ausdrücklich „nicht bestätigt",
# wäre ein Ja daraus eine Umgehung seiner Aussage.
auth_v2, app_v2 = _oidc_app({"sub": "entra-2", "preferred_username": "luegner",
                             "email": "chef@example.com", "email_verified": False},
                            admin_identifiers=["chef@example.com"],
                            oidc_email_verified_default=True)
_oidc_login(app_v2)
luegner = auth_v2.store.get_user_by_name("luegner")
r.check("der Schalter überschreibt aber kein ausdrückliches email_verified=false",
        luegner is not None and not luegner["is_admin"] and not luegner["email_verified"],
        "die Vorgabe schlägt die Aussage des Providers")

# Bestandskonto: Die Adresse steht schon in der Datenbank (vor dem Fix angelegt). Auch dann darf
# ein Login ohne Beleg nicht befördern — sonst hinge der Schutz allein an der Adresse im Konto.
auth_b3, app_b3 = _oidc_app({"sub": "alt-1", "preferred_username": "altkonto",
                             "email": "chef@example.com"},   # Claim fehlt ganz
                            admin_identifiers=["chef@example.com"])
alt_uid = auth_b3.create_user("altkonto", email="chef@example.com")
auth_b3.store.link_oidc(IDP, "alt-1", alt_uid)
_oidc_login(app_b3)
r.check("ein Bestandskonto mit der Adresse wird ohne Beleg nicht nachträglich befördert",
        not auth_b3.get_user(alt_uid)["is_admin"],
        "der fehlende Claim gilt wieder als bestätigt")
# Dieselbe Entscheidung direkt an der Quelle — zeigt, dass der Beleg sie trägt und nicht
# irgendein Nebeneffekt des Flows: dieselbe Zeile, einmal ohne und einmal mit Beleg.
r.check("maybe_promote_admin verweigert bei email_bestaetigt=False",
        not auth_b3.maybe_promote_admin(auth_b3.get_user(alt_uid), email_bestaetigt=False))
r.check("und befördert bei einem lokalen Login (kein IdP im Spiel) weiterhin",
        auth_b3.maybe_promote_admin(auth_b3.get_user(alt_uid)),
        "der lokale Weg ist zu — dort verbürgt der Konstruktor-Wächter die Bestätigungsmail")
# Dass der Beleg dieses Bestandskontos den OIDC-Login mit FEHLENDEM Claim überlebt hat, ist die
# zweite Hälfte derselben Regel: Schweigen ist keine Aussage. Wäre es eine, hätte der Login
# gerade die Bestätigung gelöscht, die der Betreiber beim Anlegen verbürgt hat.
r.check("ein fehlender Claim löscht den Vermerk eines Bestandskontos nicht",
        bool(auth_b3.get_user(alt_uid)["email_verified"]),
        "das Schweigen des Providers hat den lokalen Beleg überschrieben")

# Umgekehrt zählt eine ausdrückliche Aussage — in beide Richtungen, sonst wäre der Vermerk ein
# Einwegventil: Ein nachgeliefertes `email_verified=true` müsste ewig ohne Wirkung bleiben, und
# ein zurückgenommener Beleg bliebe für immer stehen.
def _claims_setzen(auth, claims):
    auth.oidc.exchange = lambda code, ru, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


NACH = {"sub": "nach-1", "preferred_username": "nachtrag", "email": "nach@example.com"}
auth_s, app_s = _oidc_app(NACH)                      # erster Login: Claim fehlt → unbestätigt
_oidc_login(app_s)
nach = auth_s.store.get_user_by_name("nachtrag")
vorher = bool(nach["email_verified"])
_claims_setzen(auth_s, {**NACH, "email_verified": True})
_oidc_login(app_s)
nachher = bool(auth_s.get_user(nach["id"])["email_verified"])
# Seit H-3 legt der erste Login das Konto OHNE Adresse an; der nachgelieferte Beleg trägt sie ein.
r.check("liefert der Provider den Beleg nach, kommt die Adresse belegt ins Konto",
        not vorher and nachher and auth_s.get_user(nach["id"])["email"] == "nach@example.com",
        f"vorher={vorher} nachher={nachher} adresse={auth_s.get_user(nach['id'])['email']}")
_claims_setzen(auth_s, {**NACH, "email_verified": False})
_oidc_login(app_s)
r.check("und nimmt er ihn zurück, fällt der Vermerk wieder",
        not bool(auth_s.get_user(nach["id"])["email_verified"]),
        "ein einmal erteilter Beleg bleibt für immer stehen")

# `_flag_wahr` ist der einzige Ort, der aus dem Claim ein Ja/Nein macht. Die Formen stammen aus
# dem, was echte Provider senden. Entscheidend ist die Zeile `"false"` → Nein: Sie ist der
# Unterschied zu jeder Wahrheitsprüfung auf dem rohen Wert (`bool("false")` ist wahr), und mit
# so einer Mutation blieb die Suite vorher grün — eine als „false" gemeldete Adresse wäre
# wieder Erst-Admin-fähig gewesen.
from tinysesam.oidc import _flag_wahr  # noqa: E402

for wert, erwartet in [(True, True), ("true", True), ("True", True), (" TRUE ", True),
                       (1, True), ("1", True),
                       (False, False), ("false", False), ("False", False), (0, False),
                       ("0", False), ("", False), (None, False), ("ja", False), ([], False)]:
    r.check(f"_flag_wahr({wert!r}) → {erwartet}", _flag_wahr(wert) is erwartet,
            f"ergibt {_flag_wahr(wert)!r}")


# Der Beleg gehört zu SEINER Adresse — nicht zu der aus dem anderen Dokument.
# Der Callback legt userinfo-Dokument und ID-Token zusammen (`{**nutzerinfo, **claims}`), und
# beim Mischen gewann bis hierher die Adresse aus dem ID-Token, der Beleg aber konnte aus dem
# userinfo-Dokument stammen: `email_verified=true` für eine ANDERE Adresse hätte die ungeprüfte
# mit durchgetragen. OIDC Core 5.1 meint mit `email_verified` immer die `email` DERSELBEN Antwort.
auth_m, app_m = _oidc_app({"sub": "misch-1", "preferred_username": "mischer",
                           "email": "chef@example.com"},              # ID-Token: ohne Beleg
                          nutzerinfo={"sub": "misch-1",            # Pflicht seit F-18
                                      "email": "mischer@fremd.example",
                                      "email_verified": True},        # Beleg gehört HIERHIN
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_m)
mischer = auth_m.store.get_user_by_name("mischer")
r.check("ein Beleg aus dem userinfo-Dokument trägt nicht die Adresse aus dem ID-Token",
        mischer is not None and not mischer["is_admin"],
        "Admin — der fremde email_verified wurde auf die ungeprüfte Adresse gemünzt")
r.check("… und sie wird gar nicht übernommen (H-3)",
        mischer is not None and not mischer["email"] and not mischer["email_verified"],
        f"Konto: {dict(mischer) if mischer else None}")

# Gegenprobe: Liefert der IdP die Adresse NUR im userinfo-Dokument (verbreiteter Aufbau),
# muss der dortige Beleg ganz normal zählen — sonst wäre der Schutz eine Sperre für alle.
# Seit F-18 trägt die Antwort ihr `sub`: Ohne passendes wird sie verworfen (OIDC Core 5.3.2),
# was der Abschnitt unten gesondert misst.
auth_n, app_n = _oidc_app({"sub": "nur-ui-1", "preferred_username": "nurui"},
                          nutzerinfo={"sub": "nur-ui-1",           # Pflicht seit F-18
                                      "email": "chef@example.com", "email_verified": True},
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_n)
nurui = auth_n.store.get_user_by_name("nurui")
r.check("eine bestätigte Adresse aus dem userinfo-Dokument zählt weiterhin",
        nurui is not None and nurui["is_admin"] == 1 and nurui["email"] == "chef@example.com",
        f"Konto: {dict(nurui) if nurui else None}")


# Der Beleg gibt es aber NUR bei OIDC. SAML kennt kein `email_verified`, und ein LDAP-`mail`
# pflegt in vielen Verzeichnissen der Nutzer selbst — über diese Wege darf eine
# Allowlist-ADRESSE deshalb NIE befördern. Bis zur Nacharbeit N4 hing der Riegel allein am
# OIDC-Callback: SAML und LDAP riefen `apply_factor` ohne das Argument, und `None` hiess
# „kein IdP im Spiel" — es lief am Riegel vorbei. Jetzt entscheidet der FAKTOR mit: ein
# föderierter Weg ohne ausdrücklichen Beleg befördert nicht (fail-closed), das Vergessen des
# Arguments ist also kein Loch mehr.
def _bootstrap_probe():
    """Frische Instanz mit Allowlist-ADRESSE und einem Konto, das sie trägt.

    Jede Probe braucht ihre eigene: `maybe_promote_admin` ist nicht folgenlos — ein Erfolg
    setzt das Admin-Flag, und danach messen alle weiteren Aufrufe nur noch `admin_exists`."""
    a, _ = _app(admin_identifiers=["chef@example.com"])
    return a, a.create_user("chefin", email="chef@example.com")


for faktor, beleg, soll, was in (("saml", None, False, "SAML ohne Beleg (Argument vergessen)"),
                                 ("oidc", None, False, "OIDC ohne Beleg (Argument vergessen)"),
                                 ("saml", False, False, "SAML mit ausdrücklichem „kein Beleg\""),
                                 ("password", None, True, "lokaler Passwort-Login"),
                                 ("oidc", True, True, "OIDC mit email_verified=true")):
    a_p, uid_p = _bootstrap_probe()
    ergebnis = a_p.maybe_promote_admin(a_p.get_user(uid_p), beleg, faktor=faktor)
    r.check(f"{was} → Erst-Admin {'JA' if soll else 'NEIN'}", ergebnis is soll,
            f"maybe_promote_admin gab {ergebnis!r} zurück")


# Der Riegel muss auch den ZWEITEN Login halten — sonst ist er nur eine Verzögerung.
# `maybe_promote_admin` fragt ohne ausdrücklichen Beleg den Vermerk am Konto
# (`users.email_verified`), und genau den legten `check_ldap`/`check_saml` mit der Vorgabe
# `True` an, obwohl über diese Wege per Definition nichts belegt ist. Der Angreifer meldete
# sich einmal an (die Beförderung wurde korrekt verweigert), richtete sich in seiner frisch
# angemeldeten Sitzung eine PIN oder einen Passkey ein — Selbstbedienung — und war beim
# zweiten Login Erst-Admin, mit einem Faktor, der selbst nichts behauptet (B-umgehung-1 aus T-13).
# Die vollständigen Wege über die Routen stehen in `test_ldap.py`/`test_saml.py`; hier die
# Quelle des Fehlers: das frisch angelegte Konto.
class _FakeLDAP:
    """Verzeichnis, in dem der Nutzer sein `mail`-Attribut selbst pflegt — der F-14-Fall."""

    @staticmethod
    def authenticate(username, password):
        return {"username": username, "email": "chef@example.com", "name": username,
                "groups": []}


for weg, anlegen in (
        ("LDAP", lambda a: (setattr(a, "ldap", _FakeLDAP()), a.check_ldap("mallory", "x"))[1]),
        ("SAML", lambda a: a.check_saml("mallory", {"email": ["chef@example.com"]}))):
    a_v, _ = _app(admin_identifiers=["chef@example.com"], ldap_enabled=True,
                  ldap_url="ldaps://dir.example.invalid")
    konto = anlegen(a_v)
    r.check(f"ein über {weg} angelegtes Konto trägt die Adresse OHNE Beleg",
            konto is not None and not konto["email_verified"],
            f"Konto: {konto} — der Vermerk behauptet, was {weg} nie belegt")
    # Der zweite Sprung: ein Faktor, den sich der Angreifer selbst einrichtet (PIN, Passkey).
    # Er ist nicht föderiert und reicht keinen Beleg — es entscheidet allein der Vermerk.
    r.check(f"… und ein zweiter, selbst eingerichteter Faktor befördert sie nach dem {weg}-Login nicht",
            a_v.maybe_promote_admin(a_v.get_user(konto["id"]), faktor="pin") is False,
            "Erst-Admin über einen Umweg — der Riegel hielt nur den ersten Login")
    # Gegenprobe auf derselben Instanz: Trägt die Adresse einen Beleg (Bestätigungsmail,
    # Betreiber), befördert genau derselbe Aufruf. Ohne sie wäre oben auch eine kaputte
    # Beförderung grün.
    a_v.store.set_email_verified(konto["id"], True)
    r.check(f"… Gegenprobe: mit Beleg am Konto befördert derselbe Aufruf ({weg})",
            a_v.maybe_promote_admin(a_v.get_user(konto["id"]), faktor="pin") is True,
            "der Bootstrap-Weg ist ganz zu — dann misst die Prüfung darüber nichts")


# Ein Adresswechsel überträgt den Beleg der ALTEN Adresse nicht auf die NEUE. Seit der Vermerk
# über Rechte entscheidet, ist `store.set_email` sonst ein Bootstrap-Weg: Konto mit belegter
# `eve@example.com` → Adresse auf die Allowlist-Adresse ändern → der alte Beleg trägt sie
# (B-umgehung-8 aus T-13). Der Docstring nannte das „fail-closed" und meinte nur die andere Richtung.
a_se, _ = _app(admin_identifiers=["chef@example.com"])
uid_se = a_se.create_user("eve", email="eve@example.com")          # belegt (Betreiber)
a_se.store.set_email(uid_se, "chef@example.com")
r.check("ein Adresswechsel per set_email nimmt den Beleg mit weg",
        not a_se.get_user(uid_se)["email_verified"],
        "die neue Adresse trägt den Beleg der alten")
r.check("… und trägt deshalb auch die Erst-Admin-Entscheidung nicht",
        a_se.maybe_promote_admin(a_se.get_user(uid_se), faktor="password") is False,
        "Erst-Admin allein durch das Umschreiben einer Adresse")
# Gegenprobe: Wer einen Beleg für die NEUE Adresse hat, sagt es — dann zählt sie wie immer.
a_se2, _ = _app(admin_identifiers=["chef@example.com"])
uid_se2 = a_se2.create_user("eve", email="eve@example.com")
a_se2.store.set_email(uid_se2, "chef@example.com", verified=True)
r.check("… mit ausdrücklichem verified=True bleibt der Beleg an der neuen Adresse",
        a_se2.get_user(uid_se2)["email_verified"] == 1
        and a_se2.maybe_promote_admin(a_se2.get_user(uid_se2), faktor="password") is True,
        "der belegte Weg ist zu")


# Der Betreiber soll das beim Aufbau erfahren und nicht beim vergeblichen Warten auf den
# ersten Admin: Die Konfigurationsprüfung nennt die Kombination und den belegten Weg. Warnung,
# nicht Fehler — mit einem lokalen Passwort-Login (bestätigte Adresse) ist derselbe Aufbau
# tragfähig, nur eben nicht über SAML/LDAP.
from tinysesam import konfigpruefung as _kp_f14  # noqa: E402

OIDC_AN = dict(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="c", oidc_client_secret="s")
SAML_AN = dict(saml_enabled=True, saml_idp_sso_url=IDP + "/sso", saml_idp_x509cert="PEM")
LDAP_AN = dict(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid")
for kurz, an in (("SAML", SAML_AN), ("LDAP", LDAP_AN)):
    _f14, _w14 = _kp_f14.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                                admin_identifiers=["chef@example.com"], **an))
    treffer = [w for w in _w14 if "/auth/claim-admin" in w and kurz in w]
    r.check(f"konfigpruefung nennt bei admin_identifiers + {kurz} den Weg über /auth/claim-admin",
            len(treffer) == 1, f"Warnungen: {_w14!r}")
    r.check(f"...und macht aus dem {kurz}-Aufbau keinen Fehler", not _f14, f"Fehler: {_f14!r}")

# Gegenproben: OIDC hat den Beleg (dort trägt die Adresse weiterhin), und ohne IdP ist gar
# nichts zu melden. Eine Warnung, die immer feuert, liest am Ende niemand mehr.
_f14b, _w14b = _kp_f14.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                              admin_identifiers=["chef@example.com"], **OIDC_AN))
r.check("bei OIDC schweigt sie (der Claim email_verified ist der Beleg)",
        not any("/auth/claim-admin" in w for w in _w14b), f"{_w14b!r}")
_f14c, _w14c = _kp_f14.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                              admin_identifiers=["chef@example.com"]))
r.check("und ohne föderierten Weg ebenfalls",
        not any("/auth/claim-admin" in w for w in _w14c), f"{_w14c!r}")


# ── R4-12 über die föderierten Wege: die Login-Kennung ist EIN Raum ──────────
# Die Kreuzprüfung sitzt in `create_user` und gilt damit auch für das Auto-Anlegen aus
# OIDC/LDAP/SAML. Gemessen war diese Hälfte nie: Vier Mutationen (Ausweichname → harte 409,
# saubere Abweisung → roher 500) liessen die volle Suite grün.
auth_k9, app_k9 = _oidc_app({"sub": "k9", "preferred_username": "chef@example.com",
                             "email": "neu@example.com", "email_verified": True})
lokal9 = auth_k9.create_user("chef", password="geheim12345", email="chef@example.com")
antw9 = _oidc_login(app_k9)
r.check("ein OIDC-Name, der die E-Mail eines Kontos ist, weicht auf einen freien Namen aus",
        antw9.status_code == 303, f"HTTP {antw9.status_code} — der Nutzer kommt nicht mehr herein")
# Seit dem Angriff auf H-3 (2026-09-24) gilt ein `preferred_username` mit `@` nur, wenn er die
# belegte Adresse ist — hier ist er eine FREMDE Adresse, das Konto heisst also nach der belegten
# (`neu@example.com`), nicht mehr `chef@example.com2`. Die Zusage bleibt dieselbe: eine eigene,
# freie Kennung, keine besetzte.
_k9_uid = auth_k9.store.get_oidc_user(IDP, "k9")
_k9_name = auth_k9.store.get_user(_k9_uid)["username"] if _k9_uid else None
r.check("...das neue Konto heisst anders", _k9_name not in (None, "chef@example.com", "chef"),
        f"Name {_k9_name!r} — dann wurde entweder abgewiesen oder eine Kennung besetzt")
r.check("...und die Kennung zeigt weiter auf das lokale Konto",
        (auth_k9.find_user("chef@example.com") or {}).get("id") == lokal9,
        "die fremde Anmeldung hat die Kennung übernommen")

# Was sich NICHT ausweichen lässt: die E-Mail der Identität. Dann bleibt nur fail-closed —
# und zwar als saubere Abweisung, nicht als 500 mitten im Anmeldevorgang.
auth_k11, app_k11 = _oidc_app({"sub": "k11", "preferred_username": "fremd",
                               "email": "kollision@example.com", "email_verified": True})
lokal11 = auth_k11.create_user("kollision@example.com", password="geheim12345")
antw11 = _oidc_login(app_k11)
r.check("eine OIDC-Adresse, die lokal schon Login-Kennung ist, wird mit 409 abgewiesen",
        antw11.status_code == 409, f"HTTP {antw11.status_code} — 500 wäre ein Defekt, 303 ein Loch")
r.check("...und legt kein Konto an", auth_k11.store.get_user_by_name("fremd") is None,
        "das Konto steht trotz Abweisung in der Datenbank")
r.check("...der Inhaber behält seine Kennung",
        (auth_k11.find_user("kollision@example.com") or {}).get("id") == lokal11,
        "die Kennung wurde besetzt")


# ── Allowlist-BENUTZERNAME, während ein IdP Konten von selbst anlegt (F-14 b) ──
# Der Name eines auto-angelegten Kontos kommt aus `preferred_username` bzw. dem
# SAML-/LDAP-Feld — von niemandem bestätigt, genau wie bei der offenen Registrierung.
def _baut_f14(**cfg):
    tmp = tempfile.mkdtemp()
    # `base_url` ist hier nicht Beiwerk, sondern nötig, damit die Probe überhaupt etwas
    # aussagt: Ohne sie wirft der Konstruktor bei OIDC/SAML wegen der fehlenden Basis —
    # `gebaut=False` sähe dann aus wie ein Treffer des F-14-Wächters.
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False,
                 base_url="http://testserver")
    grund.update(cfg)
    try:
        TinySesam(TinySesamConfig(**grund))
        return True, ""
    except ConfigError as e:
        return False, str(e)


gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False, **OIDC_AN)
r.check("Allowlist-BENUTZERNAME + oidc_auto_create wird abgewiesen", not gebaut,
        "die Instanz baut — wer beim IdP 'chef' heisst, wird Erst-Admin")
r.check("die Abweisung nennt die offene Tür", "oidc_auto_create" in text,
        f"Meldung nennt sie nicht: {text[:110]!r}")
for feld, an in (("saml_auto_create", dict(saml_enabled=True,
                                           saml_idp_sso_url=IDP + "/sso",
                                           saml_idp_x509cert="PEM")),
                 ("ldap_auto_create", dict(ldap_enabled=True,
                                           ldap_url="ldaps://dir.example.invalid"))):
    gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False, **an)
    r.check(f"dasselbe für {feld}", not gebaut and feld in text,
            f"gebaut={gebaut}, Meldung: {text[:110]!r}")

# Gegenproben — der Wächter darf die tragfähigen Aufbauten nicht mitnehmen.
gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False,
                         oidc_auto_create=False, **OIDC_AN)
r.check("ohne Auto-Anlegen bleibt der Allowlist-Name erlaubt", gebaut,
        f"zu streng: {text[:120]}")
gebaut, text = _baut_f14(admin_identifiers=["chef@example.com"], allow_signup=False, **OIDC_AN)
r.check("eine Allowlist-ADRESSE bleibt mit OIDC erlaubt (sie braucht den Claim, nicht ein Verbot)",
        gebaut, f"zu streng, der dokumentierte Bootstrap ist zu: {text[:120]}")


# ── Ein API-Key-Scope, der zu nichts zusammenschrumpft ───────────────────────
# `["tippfehler"]` wurde zu `[]`, und `[]` heisst in der Datenbank „kein Scope, erbt alles".
# Die Beschneidung, die begrenzen sollte, machte den Key mächtiger.
auth_k, _ = _app(apikey_enabled=True)
uid_k = auth_k.create_user("bob", password="geheim12345", roles=["kasse", "lager"])

for wunsch, was in ((["lagre"], "Tippfehler"), ([], "ausdrücklich leer")):
    try:
        auth_k.create_api_key(uid_k, "k", roles=list(wunsch))
        entstanden = True
    except ConfigError:
        entstanden = False
    r.check(f"ein Scope, der zu nichts wird ({was}), erzeugt keinen Key", not entstanden,
            "der Key entsteht — und erbt in der Datenbank ALLE Rollen des Kontos")

schluessel = auth_k.create_api_key(uid_k, "echt", roles=["lager"])
_, rollen = auth_k.verify_api_key(schluessel["key"])
r.check("eine gültige Teilmenge geht weiterhin", rollen == ["lager"], f"{rollen}")
ohne = auth_k.create_api_key(uid_k, "ohne")
_, rollen2 = auth_k.verify_api_key(ohne["key"])
r.check("ohne `roles` erbt der Key wie bisher", rollen2 is None, f"{rollen2}")


# ── Der CSRF-Ausschalter im Header ───────────────────────────────────────────
# `require_csrf` übersprang, sobald irgendein `X-API-Key` dastand — ungeprüft, und danach lief
# die Anmeldung über das Sitzungs-Cookie weiter. Auch bei apikey_enabled=False.
for apikey_an in (False, True):
    auth_c, _ = _app(apikey_enabled=apikey_an)
    chef = auth_c.create_user("chefin", password="geheim12345", is_admin=True)
    app_c = FastAPI()
    app_c.include_router(auth_c.router())
    cc = TestClient(app_c)
    cc.cookies.set(auth_c.cfg.session_cookie,
                   auth_c.store.create_session(chef, 3600, True, "password"))
    mit = cc.post("/auth/admin/api/security", json={"max_login_attempts": 7},
                  headers={"X-API-Key": "voellig-erfunden"})
    r.check(f"ein erfundener X-API-Key schaltet CSRF nicht ab (apikey_enabled={apikey_an})",
            mit.status_code == 403, f"HTTP {mit.status_code} — die Prüfung ist abschaltbar")

# Gegenprobe: ein ECHTER Key ohne Cookie darf weiterhin ohne CSRF-Token arbeiten.
auth_d, app_d = _app(apikey_enabled=True)
uid_d = auth_d.create_user("daemon", password="geheim12345")
echt = auth_d.create_api_key(uid_d, "bot")["key"]
cd = TestClient(app_d)
r.check("ein echter Key kommt ohne CSRF-Token durch",
        cd.get("/auth/apikeys", headers={"X-API-Key": echt}).status_code == 200,
        "der Daemon-Weg ist zu")


# ── Ein Schlüssel stellt sich selbst einen mächtigeren aus ───────────────────
auth_e, app_e = _app(apikey_enabled=True)
uid_e = auth_e.create_user("bob", password="geheim12345", roles=["kasse", "lager"])
eng = auth_e.create_api_key(uid_e, "eng", roles=["lager"])["key"]
ce = TestClient(app_e)
antwort = ce.post("/auth/apikeys", json={"name": "selbst"}, headers={"X-API-Key": eng})
r.check("ein API-Key kann keinen API-Key ausstellen", antwort.status_code == 403,
        f"HTTP {antwort.status_code} — er hebt damit seine eigene Begrenzung auf")


# ── Ein TOTP-Code, der mehrfach gilt ─────────────────────────────────────────
auth_t, _ = _app()
uid_t = auth_t.create_user("bob", password="geheim12345")
auth_t.totp_begin(uid_t)
geheim = auth_t.store.get_totp(uid_t)["secret"]
auth_t.store.set_totp(uid_t, geheim, confirmed=True)
code = pyotp.TOTP(geheim).now()
r.check("ein TOTP-Code gilt beim ersten Mal", auth_t.verify_totp(uid_t, code))
r.check("derselbe Code gilt kein zweites Mal", not auth_t.verify_totp(uid_t, code),
        "NIST SP 800-63B: „SHALL accept a given OTP only once while it is valid\"")
import time as _t  # noqa: E402

r.check("der nächste Zeitschritt geht weiterhin",
        auth_t.verify_totp(uid_t, pyotp.TOTP(geheim).at(int(_t.time()) + 30)),
        "die Einmal-Buchung sperrt zu viel")


# ── Freigeschaltete Ressourcen im Klartext ───────────────────────────────────
auth_r2, app_r2 = _app(csrf_enabled=False, resource_locks_enabled=True, pin_enabled=True)
uid_r = auth_r2.create_user("bob", password="geheim12345")
auth_r2.set_resource_secret("tresor", "geheimwort", kind="password", label="Tresor")
cr = TestClient(app_r2)
cr.cookies.set(auth_r2.cfg.session_cookie, auth_r2.store.create_session(uid_r, 3600, True, "password"))
cr.post("/auth/resource/tresor", data={"secret": "geheimwort", "next": "/"}, follow_redirects=False)
keks = cr.cookies.get(auth_r2.cfg.resource_cookie)
in_db = [z["token"] for z in auth_r2.store._all("SELECT token FROM resource_unlock")]
r.check("der Freigabe-Token steht nicht im Klartext in der Datenbank",
        keks not in in_db and in_db and len(in_db[0]) == 64,
        f"DB: {in_db[:1]} — wer die Datei liest, öffnet jede freigeschaltete Ressource")
r.check("die Freigabe gilt trotzdem",
        auth_r2.store.is_resource_unlocked(keks, "tresor"),
        "das Hashen hat die Funktion gebrochen")


# ── Eine Logzeile, die fail2ban gegen Dritte richtet ─────────────────────────
puffer = io.StringIO()
haken = logging.StreamHandler(puffer)
haken.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_sec.seclog.addHandler(haken)
try:
    auth_f, _ = _app()
    auth_f.create_user("opfer", password="geheim12345")
    auth_f.record_login("opfer\nWARNING failed login user=x ip=198.51.100.5 method=password\nx",
                        "203.0.113.11", success=False, method="password")
finally:
    _sec.seclog.removeHandler(haken)
zeilen = [z for z in puffer.getvalue().splitlines() if "failed login" in z]
r.check("ein Benutzername mit Zeilenumbruch erzeugt genau EINE Logzeile", len(zeilen) == 1,
        f"{len(zeilen)} Zeilen — fail2ban zählt dann eine fremde IP")
muster = re.compile(r"^\S+ \S+ WARNING failed login user=.* ip=(\S+) method=\S+(?: reason=\S+)?$")
gesehen = [m.group(1) for m in (muster.match(z) for z in zeilen) if m]
r.check("und der mitgelieferte Filter sieht nur die echte IP", gesehen == ["203.0.113.11"],
        f"{gesehen}")
filter_datei = (ROOT / "deploy" / "fail2ban" / "tinysesam-filter.conf").read_text(encoding="utf-8")
r.check("der Filter ist auf die ganze Zeile verankert",
        "^" in filter_datei.split("failregex =")[1].split("\n")[0],
        "ohne Verankerung zählt eine eingeschobene Zeile mit")


# ── Die Anmeldung scheitert — und das Protokoll sagt nicht, warum ────────────
auth_g, _ = _app()
auth_g.create_user("anna", password="geheim12345")
gesperrt = auth_g.create_user("bert", password="geheim12345")
auth_g.store.set_disabled(gesperrt, True)
for name in ("anna", "bert", "carla"):
    auth_g.record_login(name, "203.0.113.9", success=False, method="password")
gruende = {z["username"]: (z["detail"] or "") for z in auth_g.store.recent_audit(20)
           if z["event"] == "login_fail"}
r.check("das Protokoll unterscheidet falsches Geheimnis, gesperrtes und fehlendes Konto",
        "falsches_geheimnis" in gruende.get("anna", "")
        and "konto_gesperrt" in gruende.get("bert", "")
        and "kein_konto" in gruende.get("carla", ""),
        f"{gruende}")


# ── Die Sicherung, die ihre Quelle verändert ─────────────────────────────────
ordner = Path(tempfile.mkdtemp())
alt_pfad = ordner / "alt.db"
roh = sqlite3.connect(str(alt_pfad))
roh.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, display_name TEXT,
    is_admin INT DEFAULT 0, disabled INT DEFAULT 0, roles TEXT DEFAULT '[]',
    created_at INT DEFAULT 0, is_service INT DEFAULT 0);
CREATE TABLE session (token TEXT PRIMARY KEY, user_id INT, created_at INT, expires_at INT,
    mfa_ok INT DEFAULT 0, method TEXT);
INSERT INTO users(id, username) VALUES (1, 'admin');
INSERT INTO session VALUES ('KLARTEXT', 1, 0, 99999999999, 1, 'password');""")
roh.commit()
roh.close()
vorher = ([z[1] for z in sqlite3.connect(str(alt_pfad)).execute("PRAGMA table_info(session)")],
          sqlite3.connect(str(alt_pfad)).execute("PRAGMA user_version").fetchone()[0])

lauf = subprocess.run([sys.executable, "-m", "tinysesam", "backup", "--db", str(alt_pfad),
                       str(ordner / "kopie.db")], cwd=ROOT, capture_output=True, text=True)
nachher = ([z[1] for z in sqlite3.connect(str(alt_pfad)).execute("PRAGMA table_info(session)")],
           sqlite3.connect(str(alt_pfad)).execute("PRAGMA user_version").fetchone()[0])
r.check("`tinysesam backup` läuft durch", lauf.returncode == 0, lauf.stderr[:120])
r.check("...und lässt die QUELLE unverändert", vorher == nachher,
        f"vorher {vorher} → nachher {nachher}. Wer vor einem Update sichert, hätte damit die "
        "laufende Installation migriert — und den Rückweg zugemacht.")
kopie = sqlite3.connect(str(ordner / "kopie.db"))
r.check("die Kopie ist vollständig und im alten Schema",
        kopie.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        and "token" in [z[1] for z in kopie.execute("PRAGMA table_info(session)")],
        "die Sicherung taugt nicht zum Zurückspielen")


# ── Die Rücksicherung, die stillschweigend nichts tut ────────────────────────
# Nach einem Absturz liegen -wal/-shm daneben; ein blosses `cp` wird davon überschrieben.
ordner2 = Path(tempfile.mkdtemp())
ziel = ordner2 / "auth.db"
auth_s = TinySesam(TinySesamConfig(db_path=str(ziel), cookie_secure=False))
for n in ("alt0", "alt1"):
    auth_s.create_user(n, password="geheim12345")
subprocess.run([sys.executable, "-m", "tinysesam", "backup", "--db", str(ziel),
                str(ordner2 / "sicherung.db")], cwd=ROOT, capture_output=True)
auth_s.store.db.close()
# Ein echter Absturz, kein sauberes Schliessen: Letzteres checkt die WAL ein und löscht sie —
# dann misst der Test den entscheidenden Fall gar nicht. Also ein Unterprozess, der mitten im
# Betrieb per SIGKILL endet.
absturz = (
    "import os, signal\n"
    "from tinysesam import TinySesam, TinySesamConfig\n"
    f"a = TinySesam(TinySesamConfig(db_path={str(ziel)!r}, cookie_secure=False))\n"
    "a.create_user('neu0', password='geheim12345')\n"
    "os.kill(os.getpid(), signal.SIGKILL)\n")
subprocess.run([sys.executable, "-c", absturz], cwd=ROOT, capture_output=True)
r.check("die Ausgangslage hat eine liegengebliebene WAL",
        (ordner2 / "auth.db-wal").exists(),
        "ohne WAL misst der Test den entscheidenden Fall nicht")

# Gegenprobe: Ein blosses `cp` holt hier den alten Stand zurück — genau der Befund.
import shutil as _sh  # noqa: E402

probe = ordner2 / "probe.db"
for teil in ("", "-wal", "-shm"):
    if (ordner2 / f"auth.db{teil}").exists():
        _sh.copyfile(ordner2 / f"auth.db{teil}", ordner2 / f"probe.db{teil}")
_sh.copyfile(ordner2 / "sicherung.db", probe)
naiv = [z[0] for z in sqlite3.connect(str(probe)).execute("SELECT username FROM users")]
r.check("ein blosses `cp` der Sicherung wirkt NICHT (die WAL überschreibt es)",
        "neu0" in naiv,
        f"{naiv} — dann misst der Test den Unterschied nicht, den `restore` ausmacht")

lauf2 = subprocess.run([sys.executable, "-m", "tinysesam", "restore", "--db", str(ziel),
                        str(ordner2 / "sicherung.db"), "--ja"],
                       cwd=ROOT, capture_output=True, text=True)
r.check("`tinysesam restore` läuft durch", lauf2.returncode == 0, lauf2.stderr[:140])
namen = [z[0] for z in sqlite3.connect(str(ziel)).execute("SELECT username FROM users")]
r.check("nach dem Zurückspielen steht der gesicherte Stand da", namen == ["alt0", "alt1"],
        f"{namen} — die WAL hat den alten Stand wieder eingespielt")


# ── Eine Migration, die auf halbem Weg abbricht ──────────────────────────────
ordner3 = Path(tempfile.mkdtemp())
halb = ordner3 / "halb.db"
roh3 = sqlite3.connect(str(halb))
roh3.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, display_name TEXT,
    is_admin INT DEFAULT 0, disabled INT DEFAULT 0, roles TEXT DEFAULT '[]',
    created_at INT DEFAULT 0, is_service INT DEFAULT 0);
CREATE TABLE session (token_hash TEXT PRIMARY KEY, user_id INT, created_at INT, expires_at INT,
    mfa_ok INT DEFAULT 0, method TEXT);
INSERT INTO users(id, username) VALUES (1, 'admin');
INSERT INTO session VALUES ('IMMER-NOCH-KLARTEXT', 1, 0, 99999999999, 1, 'password');
PRAGMA user_version = 2;""")
roh3.commit()
roh3.close()
st3 = Store(str(halb))
werte = [z["token_hash"] for z in st3._all("SELECT token_hash FROM session")]
r.check("eine halb migrierte Datei wird beim nächsten Start geheilt",
        all(len(w) == 64 for w in werte),
        f"{werte} — Klartext bleibt für immer, weil die Erkennung nie wieder greift")
r.check("und das alte Cookie gilt danach weiter",
        st3.get_session("IMMER-NOCH-KLARTEXT") is not None,
        "die Heilung hat die Sitzung verworfen")
st3.db.close()


# ── Der Healthcheck, der einen Datenbankschaden nicht sieht ──────────────────
umgebung = dict(os.environ, TINYSESAM_OIDC_ISSUER="https://id.example.com",
                TINYSESAM_OIDC_CLIENT_ID="x", TINYSESAM_OIDC_CLIENT_SECRET="y",
                TINYSESAM_BASE_URL="https://a.example.com",
                TINYSESAM_DB=str(Path(tempfile.mkdtemp()) / "g.db"))
skript = (
    "from fastapi.testclient import TestClient\n"
    "from tinysesam.gateway import build_app\n"
    "app = build_app(); c = TestClient(app)\n"
    "print('gesund', c.get('/healthz').status_code)\n"
    "app.state.auth.store.db.close()\n"
    "print('kaputt', c.get('/healthz').status_code)\n")
lauf3 = subprocess.run([sys.executable, "-c", skript], cwd=ROOT, capture_output=True,
                       text=True, env=umgebung)
ausgabe = lauf3.stdout
r.check("der Healthcheck meldet eine gesunde Instanz mit 200", "gesund 200" in ausgabe,
        ausgabe[:120] + lauf3.stderr[-120:])
r.check("...und eine kaputte Datenbank mit 503", "kaputt 503" in ausgabe,
        f"{ausgabe[:160]} — Docker führte den Container dauerhaft als healthy, "
        "während jede angemeldete Anfrage 500 lieferte")


# ── Das Sitzungs-Token beim Rechtewechsel ───────────────────────────────────
auth_w, app_w = _app(csrf_enabled=False)
uid_w = auth_w.create_user("bob", password="geheim12345")
auth_w.totp_begin(uid_w)
geheim_w = auth_w.store.get_totp(uid_w)["secret"]
auth_w.store.set_totp(uid_w, geheim_w, confirmed=True)
cw = TestClient(app_w)
cw.post("/auth/login", data={"username": "bob", "password": "geheim12345", "next": "/"},
        follow_redirects=False)
vor = cw.cookies.get(auth_w.cfg.session_cookie)
cw.post("/auth/totp", data={"code": pyotp.TOTP(geheim_w).now(), "next": "/"},
        follow_redirects=False)
nach = cw.cookies.get(auth_w.cfg.session_cookie)
r.check("das Sitzungs-Token wird beim Rechtewechsel erneuert", vor != nach,
        "OWASP: „must be renewed after any privilege level change\"")
r.check("die neue Sitzung ist vollwertig",
        bool(auth_w.store.get_session(nach) and auth_w.store.get_session(nach)["mfa_ok"]),
        "der zweite Faktor ist verloren gegangen")
r.check("und die alte ist weg", auth_w.store.get_session(vor) is None,
        "beide Token gelten — dann war die Erneuerung nur Kosmetik")


# ── Der Konfigurations-Prüfer, der ein Feld nennt, das es nicht gibt ─────────
from tinysesam.konfigpruefung import BRAUCHT_MAILER, PFLICHTFELDER, VERFAHREN  # noqa: E402

felder = TinySesamConfig(db_path=":memory:")
unbekannt = sorted({f for fs in PFLICHTFELDER.values() for f in fs if not hasattr(felder, f)}
                   | {v for v in VERFAHREN.values() if not hasattr(felder, v)}
                   | {f for f in BRAUCHT_MAILER if not hasattr(felder, f)})
r.check("jeder Feldname der Konfigurationsprüfung existiert wirklich", not unbekannt,
        f"{unbekannt} — die Warnung feuert dann immer und prüft nie, was gemeint war")

preset = TinySesamConfig.active_directory(ldap_url="ldaps://dc.example.com:636",
                                          upn_suffix="corp.example.com", db_path=":memory:")
from tinysesam.konfigpruefung import pruefe  # noqa: E402

f_p, w_p = pruefe(preset)
r.check("das eigene active_directory-Preset löst keine Warnung aus", not f_p and not w_p,
        f"Fehler={f_p} Warnungen={w_p}")


# ── Gespeichertes XSS im Admin-Panel über den Benutzernamen ──────────────────
# Das Panel-JS baute Daten in `onclick`-Attribute, und `esc()` ersetzte nur `<`. HTML-Escaping
# genügt dort ohnehin nicht: Der Browser dekodiert das Attribut ZUERST und lässt den JS-Parser
# danach über das Ergebnis laufen — aus `&#39;` wird wieder ein Apostroph, der den String
# schliesst. Ein Nutzer, der sich passend registriert, führte damit Code im Browser der
# angemeldeten Administratorin aus. (CodeQL fand das nicht: Es sieht Python, nicht das
# JavaScript in einem Python-String.)
panel_js = (ROOT / "tinysesam" / "admin.py").read_text(encoding="utf-8")

r.check("esc() ersetzt alle HTML-Sonderzeichen, nicht nur '<'",
        all(z in panel_js for z in ('"&":"&amp;"', "'\"':\"&quot;\"", '"\'":"&#39;"')),
        "esc() deckt nicht alle Zeichen ab — in einem Attribut reicht `<` nicht")

# Seit R8-1 steht gar kein Datum mehr in einem Inline-Handler: Die CSP des Panels liesse ihn
# nicht laufen, und ein onclick ist Code. Die Knöpfe tragen `data-on` (Aktionsname) und
# `data-a` (Argumente als JSON), ein delegierter Listener liest sie mit JSON.parse.
r.check("kein onclick mehr im Panel", not re.search(r"\bon[a-z]+=", panel_js.split("_PAGE = ")[1]),
        "ein Inline-Handler ist zurück — unter der CSP läuft er nicht, und Daten darin sind Code")
r.check("Knöpfe laufen über on() (JSON in data-a, Attribut-escaped)",
        'const on=(f,...a)=>`data-on="${f}" data-a="${esc(JSON.stringify(a))}"`;' in panel_js
        and panel_js.count("${on(") >= 10, f"{panel_js.count('${on(')} Verwendungen")
r.check("der Listener ruft nur Aktionen aus ACT auf und liest data-a mit JSON.parse",
        "const ACT={" in panel_js and 'JSON.parse(el.dataset.a||"[]")' in panel_js)

# Die Wirkung messen, nicht im Quelltext raten.
#
# Der Kern ist prüfbar ohne JS-Laufzeit: `on` = JSON-Liste + HTML-Escaping in einem
# doppelt-gequoteten Attribut. Darin darf KEIN rohes `"` stehen (sonst endet das Attribut), und
# nach der Dekodierung durch den Browser muss JSON.parse genau den Namen zurückgeben.
ZEICHEN = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _esc(w):
    return "".join(ZEICHEN.get(z, z) for z in str(w))


def _on(f, *a):
    import json as _j
    return f'data-on="{f}" data-a="{_esc(_j.dumps(list(a), separators=(",", ":")))}"'


angriff = "bob\");alert(document.cookie);//'\"><img src=x onerror=alert(1)>"
attribut = _on("keys", 1, angriff)
_wert = attribut.split('data-a="', 1)[1]
r.check("ein präparierter Benutzername lässt kein rohes Anführungszeichen im Attribut",
        '"' not in _wert[:-1] and "<" not in _wert and "'" not in _wert, attribut)
import html as _html  # noqa: E402
import json as _json_a  # noqa: E402

r.check("nach der HTML-Dekodierung liefert JSON.parse genau die Argumente zurück",
        _json_a.loads(_html.unescape(_wert[:-1])) == [1, angriff], _wert)

# Wenn node da ist, dasselbe gegen die ECHTEN Helfer aus dem Panel — die stärkere Messung.
from voraussetzung import pflicht_werkzeug  # noqa: E402

# Fehlt node, ist das rot statt still weniger geprüft (s. `pflicht_werkzeug`).
node = pflicht_werkzeug("node", "Panel-Helfer esc/on gegen präparierte Namen")
if node:
    import json as _json2

    defs = re.search(r"const esc=.*?\);\n", panel_js, re.S)
    ondef = re.search(r"const on=.*?;\n", panel_js)
    r.check("die JS-Helfer sind im Panel auffindbar", defs is not None and ondef is not None,
            "esc/on nicht gefunden")
    if defs and ondef:
        probe = defs.group(0) + ondef.group(0) + (
            f"\nprocess.stdout.write(`<button ${{on('keys',1,{_json2.dumps(angriff)})}}>x</button>`);")
        aus = subprocess.run([node, "-e", probe], capture_output=True, text=True).stdout
        r.check("auch das echte Panel-JS bricht nicht aus dem Attribut aus",
                "<img" not in aus and "&quot;" in aus, f"erzeugt: {aus[:110]}")
        r.check("und der Nachbau oben stimmt mit dem echten JS überein",
                _on("keys", 1, angriff) in aus,
                f"Nachbau: {_on('keys', 1, angriff)!r} — dann misst die Prüfung ohne node etwas anderes")

# ---------- F-17: ein gesperrtes Konto bekommt beim SSO-Login gar nichts mehr ----------
# Bis 0.18.x lief der Callback für ein `disabled=1`-Konto vollständig durch: Gruppen wurden
# übernommen, das Admin-Flag konnte gesetzt werden, ein Login-Eintrag entstand — nur die Sitzung
# blieb aus. Sperren heisst aber „diese Person soll nichts mehr können"; dass ihre Rollen sich
# dabei noch ändern, ist das Gegenteil. Im Protokoll sah es zudem aus wie eine Anmeldung.
auth_d, app_d = _oidc_app({"sub": "gesperrt-1", "preferred_username": "gesperrt",
                           "email": "gesperrt@example.com", "email_verified": True,
                           "groups": ["admins"]},
                          oidc_group_role_map={"admins": "chef"})
_oidc_login(app_d)                                   # erster Login legt das Konto an
_uid_d = auth_d.store.get_user_by_name("gesperrt")["id"]
auth_d.store.set_disabled(_uid_d, True)
auth_d.store._exec("UPDATE users SET roles='[]' WHERE id=?", (_uid_d,))

_antwort_d = _oidc_login(app_d)
_konto_d = auth_d.store.get_user(_uid_d)
r.check("gesperrtes Konto: der SSO-Callback weist ab (403, keine Sitzung)",
        _antwort_d.status_code == 403, f"HTTP {_antwort_d.status_code}")
r.check("… und die Rollen aus dem IdP werden NICHT mehr übernommen",
        _konto_d["roles"] == "[]", f"roles={_konto_d['roles']!r}")
r.check("… das Konto bleibt gesperrt", bool(_konto_d["disabled"]))
_ereignisse_d = [e["event"] for e in auth_d.store.recent_audit(limit=20)]
r.check("… und es gibt eine Audit-Zeile mit dem Grund",
        "oidc_disabled" in _ereignisse_d, f"Ereignisse: {_ereignisse_d}")

# Gegenprobe: entsperrt läuft derselbe Weg wieder durch — sonst wäre der Riegel eine Sackgasse.
auth_d.store.set_disabled(_uid_d, False)
r.check("entsperrt: derselbe Login geht wieder durch",
        _oidc_login(app_d).status_code == 303)

# ---------- F-18: die UserInfo-Antwort muss zum ID-Token passen ----------
# Die Antwort ist nicht signiert und wird über die Claims gelegt — sie liefert Gruppen, E-Mail
# und damit mittelbar Rollen und das Admin-Flag. Passt ihr `sub` nicht, gilt sie gar nicht
# (OIDC Core 5.3.2). Geprüft wird hier der Weg durch den echten Callback.
auth_x, app_x = _oidc_app({"sub": "echt-1", "preferred_username": "echt"},
                          nutzerinfo={"sub": "JEMAND-ANDERS", "email": "chef@example.com",
                                      "email_verified": True, "groups": ["admins"]},
                          admin_identifiers=["chef@example.com"],
                          oidc_group_role_map={"admins": "chef"})
_oidc_login(app_x)
_echt = auth_x.store.get_user_by_name("echt")
r.check("fremdes sub im userinfo-Dokument: weder Adresse noch Rollen wandern ins Konto",
        _echt is not None and not _echt["is_admin"] and _echt["roles"] == "[]"
        and (_echt["email"] or "") != "chef@example.com",
        f"Konto: {dict(_echt) if _echt else None}")


# ══════════════════════════════════════════════════════════════════════════════════════════
# T-13, Bereich „Audit und Forensik": Wer, von wo, was genau — und was das Log verfälscht.
# ══════════════════════════════════════════════════════════════════════════════════════════
import contextlib as _ctxlib  # noqa: E402
from tinysesam.__main__ import _audit as _cli_audit, _gc as _cli_gc  # noqa: E402

auth_t, app_t = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                     forward_auth_enabled=True)
auth_t.set_mailer(lambda *a, **k: None)
_chef_t = auth_t.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_anna_t = auth_t.create_user("anna", password="Geheim12345!-lang", email="anna@example.com")


def _sitzung_t(uid):
    c = TestClient(app_t)
    c.cookies.set(auth_t.cfg.session_cookie, auth_t.store.create_session(uid, 3600, True, "password"))
    return c


def _zeilen_t(event, n=500):
    return [dict(z) for z in auth_t.store.recent_audit(n) if z["event"] == event]


c_anna, c_chef = _sitzung_t(_anna_t), _sitzung_t(_chef_t)

# ── B5-02: Konto-Ereignisse tragen Konto und IP ──────────────────────────────────────────
_start = c_anna.post("/auth/totp/setup/start")
_geheim = auth_t.store.get_totp(_anna_t)["secret"]
_best = c_anna.post("/auth/totp/setup", data={"code": pyotp.TOTP(_geheim).now()})
_rc = c_anna.post("/auth/totp/recovery")
r.check("Aufbau: TOTP eingerichtet, Recovery-Codes ausgestellt",
        _start.status_code == 200 and _best.json().get("ok") and _rc.status_code == 200,
        f"{_start.status_code} {_best.text[:80]} {_rc.status_code} {_rc.text[:80]}")
_konto_ev = ("totp_setup_start", "totp_enable", "recovery_generate")
_ohne = [(e, z["username"], z["ip"]) for e in _konto_ev for z in _zeilen_t(e)
         if z["username"] != "anna" or not z["ip"]]
r.check("B5-02: jede Konto-Zeile nennt das Konto UND die IP", not _ohne and all(
    _zeilen_t(e) for e in _konto_ev), f"ohne Konto/IP: {_ohne}")
r.check("B5-02: `tinysesam audit --user anna` findet sie (Filter in SQL auf username)",
        {"totp_setup_start", "totp_enable", "recovery_generate"}
        <= {z["event"] for z in auth_t.store.recent_audit(50, username="anna")})

# ── B5-07: TOTP-Einrichtung protokolliert, Recovery-Code ≠ TOTP ────────────────────────────
r.check("B5-07: das Bestätigen der TOTP-Einrichtung hinterlässt `totp_enable`",
        len(_zeilen_t("totp_enable")) == 1)
_login_rc = TestClient(app_t)
_login_rc.post("/auth/login", data={"username": "anna", "password": "Geheim12345!-lang"})
_rc_antwort = _login_rc.post("/auth/totp", data={"code": _rc.json()["codes"][0]},
                             follow_redirects=False)
_rc_zeilen = _zeilen_t("recovery_used")
r.check("B5-07: ein Recovery-Code im TOTP-Schritt steht als `recovery_used` im Log",
        _rc_antwort.status_code == 303 and len(_rc_zeilen) == 1
        and _rc_zeilen[0]["username"] == "anna" and _rc_zeilen[0]["ip"]
        and "verbleibend=9" in (_rc_zeilen[0]["detail"] or ""),
        f"HTTP {_rc_antwort.status_code}, Zeilen {_rc_zeilen}")

# ── B5-04 / R6-3: die drei Panel-Routen ohne Akteur ───────────────────────────────────────
_key_t = c_chef.post(f"/auth/admin/api/users/{_anna_t}/keys", json={"name": "ci"}).json()
c_chef.post(f"/auth/admin/api/keys/{_key_t['id']}/revoke")
c_chef.post("/auth/admin/api/invite", json={"email": "gast@example.com"})
_panel = {e: (_zeilen_t(e) or [{}])[0] for e in ("apikey_create", "apikey_revoke", "invite_create")}
r.check("B5-04/R6-3: Key anlegen/widerrufen nennt Besitzer, IP und den Admin als akteur=",
        all(_panel[e].get("username") == "anna" and _panel[e].get("ip")
            and "akteur=chef" in (_panel[e].get("detail") or "")
            for e in ("apikey_create", "apikey_revoke")), f"{_panel}")
r.check("B5-04: die Einladung nennt den einladenden Admin und seine IP",
        _panel["invite_create"].get("username") == "chef" and _panel["invite_create"].get("ip"),
        f"{_panel['invite_create']}")

# ── B5-05: Key-Nutzung und -Abweisung ─────────────────────────────────────────────────────
_key2 = auth_t.create_api_key(_anna_t, name="sync")
for _ in range(3):
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": _key2["key"]})
_nutzung = [z for z in _zeilen_t("apikey_use") if f"key={_key2['id']} " in z["detail"] + " "]
r.check("B5-05: die Nutzung eines Keys steht mit Besitzer und IP im Log — gedrosselt, 1× statt 3×",
        len(_nutzung) == 1 and _nutzung[0]["username"] == "anna" and _nutzung[0]["ip"],
        f"{_nutzung}")
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": _key_t["key"]})     # widerrufen
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": "tsk_" + "x" * 40})  # unbekannt
finally:
    _sec.seclog.removeHandler(_sl_h)
_abgewiesen = {z["detail"].split("grund=")[-1]: z for z in _zeilen_t("apikey_denied")}
r.check("B5-05: ein WIDERRUFENER Key, der weiter anklopft, steht im Log (Konto, IP, Grund)",
        _abgewiesen.get("widerrufen", {}).get("username") == "anna"
        and _abgewiesen["widerrufen"].get("ip"), f"{_abgewiesen}")
r.check("B5-05: ein unbekannter Key ebenfalls — und beide im Sicherheits-Log",
        "unbekannt" in _abgewiesen and _sl_puffer.getvalue().count("api key denied") == 2,
        _sl_puffer.getvalue())

# ── R6-7: Vorher/Nachher ──────────────────────────────────────────────────────────────────
c_chef.post(f"/auth/admin/api/users/{_anna_t}/roles", json={"roles": ["redaktion"], "is_admin": True})
_rollen_z = _zeilen_t("user_roles")[0]["detail"] or ""
r.check("R6-7: die Rollenänderung nennt vorher → nachher, samt Admin-Flag",
        "rollen=-->redaktion" in _rollen_z and "admin=0->1" in _rollen_z, _rollen_z)
c_chef.post(f"/auth/admin/api/users/{_anna_t}/roles", json={"roles": [], "is_admin": False})
_vorher_ma = auth_t.sec("max_login_attempts")
c_chef.post("/auth/admin/api/security", json={"max_login_attempts": _vorher_ma + 995})
_sec_z = _zeilen_t("security_update")[0]["detail"] or ""
r.check("R6-7: die Härtungsänderung nennt den alten und den neuen Wert",
        f"max_login_attempts={_vorher_ma}->{_vorher_ma + 995}" in _sec_z, _sec_z)
auth_t.set_security("max_login_attempts", _vorher_ma)

# ── B5-12: Lesen wird protokolliert ───────────────────────────────────────────────────────
c_chef.get("/auth/admin/api/sessions")
c_chef.get("/auth/admin/api/audit")
r.check("B5-12: Sitzungsliste und Audit-Log lesen hinterlässt eine Zeile mit dem Leser",
        (_zeilen_t("sessions_read") or [{}])[0].get("username") == "chef"
        and (_zeilen_t("audit_read") or [{}])[0].get("username") == "chef")

# ── H-7: eigene Ereignisse auf der Kontoseite ─────────────────────────────────────────────
_konto_seite = c_anna.get("/auth/account").text
r.check("H-7: die Kontoseite zeigt die eigenen Ereignisse",
        "Recent activity" in _konto_seite and "totp_enable" in _konto_seite
        and "recovery_used" in _konto_seite)
r.check("H-7: … ohne Detailtext (dort stehen bei Admin-Aktionen fremde Konten)",
        "akteur=" not in _konto_seite and "verbleibend=" not in _konto_seite)

# ── B5-17: abgewiesene Forward-Auth ───────────────────────────────────────────────────────
_vorher_fw = len(_zeilen_t("forward_denied"))
TestClient(app_t).get("/auth/forward")                                   # ohne Nachweis
_ohne_nachweis = len(_zeilen_t("forward_denied")) - _vorher_fw
_fw = TestClient(app_t)
_fw.cookies.set(auth_t.cfg.session_cookie, "abgelaufen-oder-geraten")
_fw_status = [_fw.get("/auth/forward").status_code for _ in range(3)]
_fw_z = _zeilen_t("forward_denied")
r.check("B5-17: eine 401 mit ungültigem Sitzungscookie steht im Log (gedrosselt: 1× für 3 Anfragen)",
        _fw_status == [401] * 3 and len(_fw_z) - _vorher_fw == 1
        and "grund=sitzung_ungueltig" in _fw_z[0]["detail"] and _fw_z[0]["ip"],
        f"{_fw_status} {_fw_z}")
r.check("B5-17: … ein Aufruf ganz ohne Nachweis (der erste Besuch) dagegen nicht", _ohne_nachweis == 0)

# ── B5-08 / H-13: Passkey widerrufen, Konto löschen, Log anonymisieren ────────────────────
auth_t.store.add_webauthn(_anna_t, "credid-b5-08", "pubkey", 0, ["usb"], "Stick")
_pk = c_chef.get(f"/auth/admin/api/users/{_anna_t}/passkeys").json()
_pk_weg = c_chef.post(f"/auth/admin/api/users/{_anna_t}/passkeys/{_pk[0]['id']}/delete")
_pk_z = _zeilen_t("passkey_delete")[0]
r.check("B5-08: der Admin widerruft einen fremden Passkey — protokolliert beim Inhaber",
        len(_pk) == 1 and _pk_weg.status_code == 200 and not auth_t.store.list_webauthn(_anna_t)
        and _pk_z["username"] == "anna" and "akteur=chef" in _pk_z["detail"], f"{_pk} {_pk_z}")
r.check("B5-08: fremder Passkey über die falsche Konto-ID → 404, nichts gelöscht",
        c_chef.post(f"/auth/admin/api/users/{_chef_t}/passkeys/999/delete").status_code == 404)
r.check("B5-08: das eigene Konto lässt sich im Panel nicht löschen",
        c_chef.post(f"/auth/admin/api/users/{_chef_t}/delete").status_code == 400)
_try_last = None
try:
    auth_t.delete_user(_chef_t)
except Exception as e:        # noqa: BLE001
    _try_last = type(e).__name__
r.check("B5-08: der letzte Admin lässt sich nicht löschen (StateError)", _try_last == "StateError",
        str(_try_last))
auth_t.store.audit_log("invite_create", "chef", None, "an anna@example.com und annabell")
_weg = c_chef.post(f"/auth/admin/api/users/{_anna_t}/delete")
_rest = [dict(z) for z in auth_t.store.recent_audit(1000)]
r.check("B5-08: Konto gelöscht", _weg.status_code == 200 and auth_t.store.get_user(_anna_t) is None,
        f"HTTP {_weg.status_code} {_weg.text[:80]}")
r.check("H-13: im Audit-Log steht der Name nirgends mehr, weder als Konto noch im Detail",
        not any("anna" == (z["username"] or "") or "anna@example.com" in (z["detail"] or "")
                for z in _rest),
        f"{[z for z in _rest if 'anna' in str(z)][:3]}")
r.check("H-13: … die Zeilen selbst bleiben stehen (Forensik), unter `gelöscht#<id>`",
        len(auth_t.store.recent_audit(1000, username=f"gelöscht#{_anna_t}")) >= 10)
r.check("H-13: … und nur ganze Wörter werden ersetzt („annabell“ bleibt)",
        any("annabell" in (z["detail"] or "") for z in _rest))

# ── B5-11: Aufbewahrungsfrist und IP-Kürzung ──────────────────────────────────────────────
auth_f, _ = _app(audit_retention_days=30, audit_ip_pseudonymize=True)
auth_f.store.audit_log("alt", "x", "203.0.113.77")
auth_f.store.audit_log("neu", "x", "2001:DB8:1234:5678::1")
auth_f.store._exec("UPDATE audit SET ts = ts - 31*86400 WHERE event='alt'")
_ips_f = {z["event"]: z["ip"] for z in auth_f.store.recent_audit(10)}
r.check("B5-11: audit_ip_pseudonymize kürzt IPv4 auf /24 und IPv6 auf /48",
        _ips_f == {"alt": "203.0.113.0/24", "neu": "2001:db8:1234::/48"}, f"{_ips_f}")
_gc_f = auth_f.gc()
r.check("B5-11: gc() löscht Audit-Zeilen jenseits der Frist, die jüngeren bleiben",
        _gc_f.get("audit") == 1 and [z["event"] for z in auth_f.store.recent_audit(10)] == ["neu"],
        f"{_gc_f}")
auth_g, _ = _app()
auth_g.store.audit_log("alt", "x", "203.0.113.77")
auth_g.store._exec("UPDATE audit SET ts = ts - 3650*86400")
r.check("B5-11: ohne Frist (Vorgabe) bleibt das Log unangetastet, und die IP voll",
        "audit" not in auth_g.gc() and auth_g.store.recent_audit(5)[0]["ip"] == "203.0.113.77")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_gc(["--db", auth_g.cfg.db_path, "--audit-days", "30"])
r.check("B5-11: `tinysesam gc --audit-days N` räumt dasselbe von der Kommandozeile",
        "audit=1" in _cli_out.getvalue() and not auth_g.store.recent_audit(5), _cli_out.getvalue())
try:
    _app(audit_retention_days=-1)
    _neg = "angenommen"
except ConfigError:
    _neg = "abgewiesen"
r.check("B5-11: eine negative Frist (löschte ALLES) wird beim Aufbau abgewiesen", _neg == "abgewiesen")

# ── B5-06: Log-Injection in `tinysesam audit` ─────────────────────────────────────────────
auth_i, _ = _app()
auth_i.store.audit_log("login_fail", "x\n2026-01-01 00:00:00  login  admin  198.51.100.1  ok\x1b[2J",
                       "198.51.100.9", "password\nzweite")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_audit(["--db", auth_i.cfg.db_path])
_cli_zeilen = _cli_out.getvalue().splitlines()
r.check("B5-06: ein Umbruch im Benutzernamen erzeugt in `tinysesam audit` KEINE zweite Zeile",
        len(_cli_zeilen) == 1 and "\\n" in _cli_zeilen[0] and "\x1b" not in _cli_out.getvalue(),
        repr(_cli_out.getvalue()))

# ── B5-14: Steuerzeichen in JEDER seclog-Zeile, auch ohne fuer_log an der Aufrufstelle ────
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    _sec.seclog.warning("probe user=%s ip=%s", "x\nfailed login user=y ip=192.0.2.66", "192.0.2.1")
finally:
    _sec.seclog.removeHandler(_sl_h)
r.check("B5-14: der Logger selbst neutralisiert Umbrüche in den Argumenten (eine Zeile, nicht zwei)",
        _sl_puffer.getvalue().count("\n") == 1 and "192.0.2.66" in _sl_puffer.getvalue(),
        repr(_sl_puffer.getvalue()))


# ── B5-15: das Feld `ip` enthält eine IP ─────────────────────────────────────────────────
class _Anfr:
    def __init__(self, peer, xff):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff}


_sec.einmal_melden_zuruecksetzen()
_proxy = ["127.0.0.1/32"]
r.check("B5-15: ein X-Forwarded-For ohne gültige Adresse wird nicht zur Client-IP",
        _sec.client_ip(_Anfr("127.0.0.1", "evil\nfailed login"), _proxy) == "127.0.0.1")
r.check("B5-15: gültige Adressen kommen kanonisch an (Schreibweise ≠ neuer Client)",
        _sec.client_ip(_Anfr("127.0.0.1", "2001:DB8:0::1"), _proxy) == "2001:db8::1"
        and _sec.client_ip(_Anfr("127.0.0.1", "198.51.100.7:4711"), _proxy) == "198.51.100.7")
auth_i.store.audit_log("probe", "x", "kein\nip")
r.check("B5-15: das Audit-Log nimmt in der ip-Spalte nichts mit Zeilenumbruch an",
        "\n" not in auth_i.store.recent_audit(1)[0]["ip"])


# ══════════════════════════════════════════════════════════════════════════════════════════
# T-13, Angriff auf die Audit-Fixes (A-1 … A-7): was die Reparaturen selbst aufrissen.
# ══════════════════════════════════════════════════════════════════════════════════════════

# ── A-1: IPv6-Zonenangabe als frei drehbarer Schlüssel ────────────────────────────────────
# `ipaddress` nimmt hinter dem `%` jeden Text. Über einen Proxy, der XFF nur durchreicht, wäre
# jede Zone ein neuer Client — für Rate-Limit, Sperre und Log-Drossel.
_sec.einmal_melden_zuruecksetzen()
_zonen = {_sec.client_ip(_Anfr("127.0.0.1", f"2001:db8::2%z{i}"), _proxy) for i in range(20)}
r.check("A-1: wechselnde IPv6-Zonen ergeben EINE Client-IP (ohne Zone)",
        _zonen == {"2001:db8::2"}, f"{_zonen}")
auth_z, _ = _app(trusted_proxies=["127.0.0.1/32"])
_erlaubt = sum(auth_z.rate_ok(_sec.client_ip(_Anfr("127.0.0.1", f"2001:db8::3%q{i}"), _proxy))
               for i in range(60))
_fest = sum(auth_z.rate_ok("2001:db8::4") for _ in range(60))
r.check("A-1: das Rate-Limit greift bei Zonen-Rotation genauso wie bei fester Adresse",
        _erlaubt == _fest < 60, f"Rotation {_erlaubt}/60, fest {_fest}/60")
auth_i.store.audit_log("probe_zone", "x", "fe80::1%a\nFAKE 2026-01-01 login admin")
r.check("A-1: eine Zone mit Zeilenumbruch landet nicht in der ip-Spalte",
        auth_i.store.recent_audit(1)[0]["ip"] == "fe80::1", repr(auth_i.store.recent_audit(1)[0]["ip"]))

# ── A-2 / A-3: Konto löschen trifft fremde Zeilen nicht, dafür die Anmeldeversuche per Mail ──
auth_d, app_d2 = _app(csrf_enabled=False)
auth_d.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_adm = auth_d.create_user("admin", password="Geheim12345!-lang", email="Anna.Admin@example.com",
                          is_admin=True)
_bob = auth_d.create_user("bob", password="Geheim12345!-lang")
_kd = TestClient(app_d2)
_kd.cookies.set(auth_d.cfg.session_cookie, auth_d.store.create_session(_adm, 3600, True, "password"))
_kd.post(f"/auth/admin/api/users/{_bob}/roles", json={"roles": ["ops"], "is_admin": True})
auth_d.record_login("bob", "198.51.100.3", False, "password")
auth_d.record_login("anna.admin@example.com", "198.51.100.4", False, "password")
auth_d.record_login("Anna.Admin@example.com", "198.51.100.4", False, "password")
auth_d.delete_user(_adm)
_zd = [dict(z) for z in auth_d.store.recent_audit(200)]
_rollen_d = next(z for z in _zd if z["event"] == "user_roles")
r.check("A-2: ein gelöschtes Konto `admin` verstümmelt `admin=0->1` einer FREMDEN Zeile nicht",
        "admin=0->1" in _rollen_d["detail"] and "gelöscht" not in _rollen_d["detail"],
        _rollen_d["detail"])
r.check("A-2: … dieselbe Zeile nennt den gelöschten Admin als Täter nicht mehr",
        _rollen_d["username"] == f"gelöscht#{_adm}", f"{_rollen_d}")
_bob_fail = next(z for z in _zd if z["event"] == "login_fail" and z["username"] == "bob")
r.check("A-2: die Methode im Detail fremder Fehlversuche bleibt unberührt",
        _bob_fail["detail"].startswith("password "), _bob_fail["detail"])
_mail_rest = [z for z in _zd if "anna.admin@example.com" in str(z).lower()]
r.check("A-3: Anmeldeversuche unter der E-Mail-Adresse sind im Audit-Log anonymisiert",
        not _mail_rest and sum(1 for z in _zd if z["event"] == "login_fail"
                               and z["username"] == f"gelöscht#{_adm}") == 2, f"{_mail_rest}")
_versuche = auth_d.store._all("SELECT username FROM login_attempt", ())
r.check("A-3: … und ihre login_attempt-Zeilen sind gelöscht (nur bob bleibt)",
        [v["username"] for v in _versuche] == ["bob"], f"{[dict(v) for v in _versuche]}")
auth_d.store.audit_log("apikey_create", "bob", None, "key=9 akteur=Admin")
auth_d.store.audit_log("user_create", "chef", None, "admin service=False")
auth_d.store.audit_anonymisieren("admin", "gelöscht#99")
_nach = {z["event"]: z["detail"] for z in auth_d.store.recent_audit(2)}
r.check("A-2: dort, wo ein Name steht (akteur=, Kopf von user_create), wird er weiter ersetzt",
        _nach == {"apikey_create": "key=9 akteur=gelöscht#99",
                  "user_create": "gelöscht#99 service=False"}, f"{_nach}")

# ── A-4: die CSRF-Ausnahme prüft den Key VOR current_user — die IP muss schon da sein ─────
auth_k, app_k = _app()
_kchef = auth_k.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_k_weg = auth_k.create_api_key(_kchef, name="alt")
auth_k.revoke_api_key(_k_weg["id"])
_k_ok = auth_k.create_api_key(_kchef, name="ok")
_kc = TestClient(app_k, client=("198.51.100.50", 1))
for _k in (_k_weg["key"], _k_ok["key"]):
    _kc.post(f"/auth/admin/api/users/{_kchef}/roles", json={"roles": []}, headers={"X-API-Key": _k})
_kz = [dict(z) for z in auth_k.store.recent_audit(50) if z["event"].startswith("apikey_")
       and z["event"] != "apikey_create" and z["event"] != "apikey_revoke"]
r.check("A-4: widerrufener Key an einer POST-Route: apikey_denied MIT IP",
        [(z["event"], z["ip"]) for z in _kz if z["event"] == "apikey_denied"]
        == [("apikey_denied", "198.51.100.50")], f"{_kz}")
r.check("A-4: gültiger Key an einer POST-Route: EINE apikey_use-Zeile, mit IP",
        [(z["event"], z["ip"]) for z in _kz if z["event"] == "apikey_use"]
        == [("apikey_use", "198.51.100.50")], f"{_kz}")

# ── A-5: die Kontoseite zeigt nicht die IP des Admins ─────────────────────────────────────
auth_e, app_e = _app(csrf_enabled=False)
_echef = auth_e.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_eanna = auth_e.create_user("anna", password="Geheim12345!-lang")
_ec = TestClient(app_e, client=("198.51.100.50", 1))
_ec.cookies.set(auth_e.cfg.session_cookie, auth_e.store.create_session(_echef, 3600, True, "password"))
_ea = TestClient(app_e, client=("203.0.113.9", 1))
_ea.cookies.set(auth_e.cfg.session_cookie, auth_e.store.create_session(_eanna, 3600, True, "password"))
_ec.post(f"/auth/admin/api/users/{_eanna}/keys", json={"name": "ci"})
auth_e.audit("password_change", "anna", "203.0.113.9")
_eigene = auth_e.own_events(_eanna)
_seite_e = _ea.get("/auth/account").text
r.check("A-5: eine Admin-Aktion am eigenen Konto zeigt die Admin-IP nicht, nur „durch einen Admin“",
        ("apikey_create", None, True) in [(e["event"], e["ip"], e["by_admin"]) for e in _eigene]
        and "198.51.100.50" not in _seite_e and "by an administrator" in _seite_e, f"{_eigene}")
r.check("A-5: … die eigenen Zeilen behalten ihre IP",
        ("password_change", "203.0.113.9", False) in
        [(e["event"], e["ip"], e["by_admin"]) for e in _eigene] and "203.0.113.9" in _seite_e)

# ── A-6: kein Query-String (Freigabe-Token) im Audit-Log ─────────────────────────────────
_fw6 = TestClient(app_t, client=("198.51.100.66", 1))
_fw6.cookies.set(auth_t.cfg.session_cookie, "abgelaufen")
_fw6.get("/auth/forward", headers={"x-forwarded-proto": "https", "x-forwarded-host": "app.example.com",
                                   "x-forwarded-uri": "/share?t=GEHEIM#frag"})
_fw6_z = [z["detail"] for z in auth_t.store.recent_audit(50) if z["event"] == "forward_denied"
          and z["ip"] == "198.51.100.66"]
r.check("A-6: forward_denied nennt Host und Pfad, aber nicht den Query-String",
        len(_fw6_z) == 1 and "GEHEIM" not in _fw6_z[0] and "/share?…" in _fw6_z[0], f"{_fw6_z}")
r.check("A-6: url_fuer_log auch für relative Ziele und ohne Query",
        _sec.url_fuer_log("/a/b?code=x") == "/a/b?…" and _sec.url_fuer_log("https://h.example/p")
        == "https://h.example/p" and _sec.url_fuer_log("/x#t") == "/x?…")

# ── A-7: C1-Steuerzeichen, Zeilentrenner und Bidi-Overrides ──────────────────────────────
auth_c, _ = _app()
auth_c.store.audit_log("login_fail", "x\x852026-01-01 login admin zeile\x9b2J‮evil",
                       "198.51.100.9", "d ")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_audit(["--db", auth_c.cfg.db_path])
_c7 = _cli_out.getvalue()
r.check("A-7: NEL/U+2028/U+2029 erzeugen in `tinysesam audit` keine weitere Zeile, CSI und "
        "U+202E kommen nicht roh an",
        len(_c7.splitlines()) == 1 and not any(z in _c7 for z in "\x85\x9b  ‮"),
        repr(_c7))
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    _sec.seclog.warning("probe user=%s ip=%s", "x\x85failed login user=y ip=192.0.2.66‮",
                        "192.0.2.1")
finally:
    _sec.seclog.removeHandler(_sl_h)
r.check("A-7: auch im Sicherheits-Log (Filter am Logger) und in fuer_log",
        len(_sl_puffer.getvalue().splitlines()) == 1 and "\x85" not in _sl_puffer.getvalue()
        and "‮" not in _sl_puffer.getvalue()
        and _sec.fuer_log("a\x9bb c‮d") == "abcd", repr(_sl_puffer.getvalue()))

# ── F-20/H-12: PKCE über den echten Flow ──────────────────────────────────────
# `oidc.py` misst die Mechanik (Challenge, Verifier im POST). Hier der Draht dazwischen: Die
# Challenge in der Umleitung zum Provider muss zu dem Verifier passen, den der Callback beim
# Tausch mitgibt — und der Verifier darf nie in der Adresszeile stehen.
import base64 as _b64p  # noqa: E402
import hashlib as _hlp  # noqa: E402

auth_p, app_p = _oidc_app({"sub": "pkce-1", "preferred_username": "pkce"})
_gesehen_p = {}


def _tausch_p(code, ru, nonce, t=None, code_verifier=""):
    _gesehen_p["verifier"] = code_verifier
    return _Claims({"sub": "pkce-1", "preferred_username": "pkce", "nonce": nonce}), {"access_token": "at"}


auth_p.oidc.exchange = _tausch_p
_cp = TestClient(app_p)
_start_p = _cp.get("/auth/oidc/start", follow_redirects=False)
_q_p = parse_qs(urlparse(_start_p.headers["location"]).query)
_antwort_p = _cp.get(f"/auth/oidc/callback?code=x&state={_q_p['state'][0]}", follow_redirects=False)
_v_p = _gesehen_p.get("verifier") or ""
_passend = _b64p.urlsafe_b64encode(_hlp.sha256(_v_p.encode()).digest()).rstrip(b"=").decode()
r.check("PKCE: die Umleitung zum Provider verlangt S256",
        _q_p.get("code_challenge_method") == ["S256"] and bool(_q_p.get("code_challenge")), _q_p)
r.check("PKCE: der Callback tauscht mit DEM Verifier, der zur Challenge gehört",
        _antwort_p.status_code == 303 and _v_p and _q_p.get("code_challenge") == [_passend],
        f"HTTP {_antwort_p.status_code}, Verifier={_v_p!r}")
r.check("PKCE: der Verifier steht nie in der Adresszeile",
        _v_p and _v_p not in _start_p.headers["location"])

# ══ Angriff auf die T-13-Integration: Lücken an den Nähten der Zweige ══════════════════════════
# Jeder Zweig war für sich stimmig; die Lücken entstanden, weil ein Zweig einen Weg einführte und
# ein anderer eine Zusage, die diesen Weg nicht kannte. Die Blöcke hier prüfen deshalb die ZUSAGE
# über alle Wege, die es heute gibt — und je ein Wächter hält fest, dass es nur EINEN Weg gibt,
# damit der nächste Zweig nicht still einen zweiten dazubaut.
import ast as _ast  # noqa: E402
import importlib.util as _ilu  # noqa: E402


def _aufrufe_ausserhalb(methode: str, empfaenger, erlaubt: set, quellen=None) -> list:
    """Wo in `tinysesam/` steht ein Aufruf `<empfaenger>.<methode>(…)` ausserhalb von `erlaubt`?

    `erlaubt` sind Paare (innerste Klasse, innerste Funktion). Per AST und nicht per Textsuche:
    Docstrings und Kommentare nennen die Methode ebenfalls, und eine verschachtelte Funktion wie
    `_zuruecknehmen` muss als sie selbst erkannt werden, nicht als die Route um sie herum.
    `quellen` (Liste aus (Dateiname, Text)) ersetzt `tinysesam/*.py` — für die Selbsttests."""
    funde = []
    if quellen is None:
        quellen = [(p.name, p.read_text(encoding="utf-8"))
                   for p in sorted((ROOT / "tinysesam").glob("*.py"))]
    for pfadname, text in quellen:
        baum = _ast.parse(text)

        def gehe(knoten, klasse=None, funktion=None):
            for kind in _ast.iter_child_nodes(knoten):
                k, f = klasse, funktion
                if isinstance(kind, _ast.ClassDef):
                    k = kind.name
                elif isinstance(kind, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    f = kind.name
                if (isinstance(kind, _ast.Call) and isinstance(kind.func, _ast.Attribute)
                        and kind.func.attr == methode and empfaenger(kind.func.value, k)
                        and (k, f) not in erlaubt):
                    funde.append(f"{pfadname}:{kind.lineno} ({k}.{f})")
                gehe(kind, k, f)
        gehe(baum)
    return funde


def _ist_store(knoten, klasse) -> bool:
    """`auth.store.x`, `self.store.x`, `store.x` — und im Store selbst `self.x`."""
    return ((isinstance(knoten, _ast.Attribute) and knoten.attr == "store")
            or (isinstance(knoten, _ast.Name) and knoten.id == "store")
            or (isinstance(knoten, _ast.Name) and knoten.id == "self" and klasse == "Store"))


# Der Wächter muss selbst anschlagen können — sonst misst er nichts (Negativtest).
r.check("Wächter-Selbsttest: ein Aufruf ausserhalb der Erlaubnis wird gefunden",
        any("admin.py" in f for f in _aufrufe_ausserhalb("delete_user_sessions", _ist_store, set()))
        and not _aufrufe_ausserhalb("gibt_es_nicht", _ist_store, set()))

# ── Fund 3: der Admin-Widerruf eines Passkeys meldet sich beim Inhaber ────────────────────────
# Der Zweig audit brachte die Panel-Route, der Zweig faktoren hängte `passkey_removed` nur an die
# Selbstbedienung. Nach dem Merge war der einzige Faktor-Wechsel ohne Benachrichtigung genau der,
# den ein übernommenes Admin-Konto an einem FREMDEN Konto vornimmt.
# (Mutationsproben: in `remove_passkey` den `sicherheitsereignis`-Aufruf streichen → rot; die
#  Panel-Route wieder direkt `store.delete_webauthn` + `audit` rufen lassen → rot, Hook UND Wächter.)
auth_f3, app_f3 = _app(csrf_enabled=False)
_f3_chef = auth_f3.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_f3_anna = auth_f3.create_user("anna", password="Geheim12345!-lang")
_f3_ereig = []
auth_f3.on_security_event = lambda e, k, d: _f3_ereig.append((e, k["username"], dict(d)))
auth_f3.store.add_webauthn(_f3_anna, b"cred-f3-a", b"pk", 0, [], "Laptop")
auth_f3.store.add_webauthn(_f3_anna, b"cred-f3-b", b"pk", 0, [], "Telefon")
_f3_pk, _f3_pk2 = [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)]
_f3_c = TestClient(app_f3, client=("198.51.100.70", 1))
_f3_c.cookies.set(auth_f3.cfg.session_cookie,
                  auth_f3.store.create_session(_f3_chef, 3600, True, "password"))
_f3_r = _f3_c.post(f"/auth/admin/api/users/{_f3_anna}/passkeys/{_f3_pk}/delete")
r.check("Fund 3: der Admin-Widerruf entfernt den Passkey und meldet passkey_removed an den Inhaber",
        _f3_r.status_code == 200
        and [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)] == [_f3_pk2]
        and [(e, u) for e, u, _ in _f3_ereig] == [("passkey_removed", "anna")]
        and _f3_ereig[0][2].get("passkey_id") == _f3_pk,
        f"HTTP {_f3_r.status_code}, Hook {_f3_ereig}")
_f3_audit = [(z["username"], z["detail"]) for z in auth_f3.store.recent_audit(20)
             if z["event"] == "passkey_delete"]
r.check("Fund 3: … die Audit-Zeile steht unter dem Inhaber, der Admin als akteur=",
        _f3_audit == [("anna", f"id={_f3_pk} akteur=chef")], f"{_f3_audit}")
_f3_ereig.clear()
_f3_r2 = _f3_c.post(f"/auth/admin/api/users/{_f3_anna}/passkeys/{_f3_pk}/delete")
r.check("Fund 3: ein Passkey, den das Konto nicht (mehr) hat → 404, keine Meldung, keine Zeile",
        _f3_r2.status_code == 404 and _f3_ereig == []
        and len([z for z in auth_f3.store.recent_audit(20) if z["event"] == "passkey_delete"]) == 1,
        f"HTTP {_f3_r2.status_code}, Hook {_f3_ereig}")
# Derselbe Weg ohne HTTP — und für ein fremdes Konto greift er nicht.
r.check("Fund 3: remove_passkey trifft nur Passkeys DIESES Kontos",
        auth_f3.remove_passkey(_f3_chef, _f3_pk2) is False
        and [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)] == [_f3_pk2] and _f3_ereig == [])
if _ilu.find_spec("webauthn") is not None:
    # Die Selbstbedienung läuft über dieselbe Methode (vorher: eigene Zeilen in webauthn_.py —
    # und ein fremder oder erfundener Passkey schrieb trotzdem Zeile UND Ereignis).
    auth_f3s, app_f3s = _app(csrf_enabled=False, passkey_enabled=True, rp_id="localhost",
                             origin="http://localhost")
    _f3s_anna = auth_f3s.create_user("anna", password="Geheim12345!-lang")
    _f3s_ereig = []
    auth_f3s.on_security_event = lambda e, k, d: _f3s_ereig.append((e, k["username"], dict(d)))
    auth_f3s.store.add_webauthn(_f3s_anna, b"cred-f3s", b"pk", 0, [], "Laptop")
    _f3s_pk = auth_f3s.store.list_webauthn(_f3s_anna)[0]["id"]
    _f3s_c = TestClient(app_f3s, client=("203.0.113.70", 1))
    _f3s_c.cookies.set(auth_f3s.cfg.session_cookie,
                       auth_f3s.store.create_session(_f3s_anna, 3600, True, "password"))
    _f3s_fremd = _f3s_c.post("/auth/passkey/delete", json={"id": _f3s_pk + 99})
    _f3s_r = _f3s_c.post("/auth/passkey/delete", json={"id": _f3s_pk})
    r.check("Fund 3: Selbstbedienung — unbekannter Passkey 404 ohne Ereignis, eigener 200 mit Ereignis",
            _f3s_fremd.status_code == 404 and _f3s_r.status_code == 200
            and _f3s_ereig == [("passkey_removed", "anna", {"passkey_id": _f3s_pk})]
            and [(z["username"], z["detail"]) for z in auth_f3s.store.recent_audit(20)
                 if z["event"] == "passkey_delete"] == [("anna", f"id={_f3s_pk}")],
            f"{_f3s_fremd.status_code}/{_f3s_r.status_code}, Hook {_f3s_ereig}")
_f3_weg = _aufrufe_ausserhalb("delete_webauthn", _ist_store, {("TinySesam", "remove_passkey")})
r.check("Fund 3 (Wächter): einen Passkey löscht nur TinySesam.remove_passkey — jede Route geht darüber",
        not _f3_weg, f"direkte Aufrufe: {_f3_weg}")

# ── Funde 12/18: EIN Löschweg für Konten (H-13 × R4-09/B6-5) ──────────────────────────────────
# H-13 (Zweig audit) nahm ein gelöschtes Konto nur in `TinySesam.delete_user` aus dem Audit-Log.
# Der Zweig mailwege brachte weitere Löschwege — `gc()`, `tinysesam gc` (Store) und die Rücknahme
# bei gescheitertem Bestätigungsversand (B6-5) —, die direkt `store.delete_user` riefen. Name,
# fremde IP und die Adresse des Opfers blieben im Log, und die Kontoseite eines späteren
# Namensvetters zeigte die Registrierung des Fremden samt IP als eigenes Ereignis (H-7).
# (Mutationsproben: in `Store.konto_entfernen` `audit_anonymisieren` streichen → rot für alle
#  Wege; `gc_unbestaetigte_konten` wieder `self.delete_user` rufen lassen → rot, Spuren UND
#  Wächter; `signup_expired` wieder mit dem Klarnamen schreiben → rot; `_zuruecknehmen` wieder
#  `store.delete_user` rufen lassen → rot, Spuren UND Wächter.)
_F12_NAME, _F12_MAIL = "squatter", "opfer@example.com"


def _f12_spuren(a) -> tuple:
    """Was vom gelöschten Konto noch unter Name oder Adresse im Log und in den Versuchen steht."""
    kennungen = (_F12_NAME, _F12_MAIL)
    zeilen = [(z["event"], z["username"], z["detail"]) for z in a.store._all("SELECT * FROM audit")
              if (z["username"] or "").lower() in kennungen
              or any(k in (z["detail"] or "").lower() for k in kennungen)]
    versuche = [z["username"] for z in a.store._all("SELECT username FROM login_attempt")
                if (z["username"] or "").lower() in kennungen]
    return zeilen, versuche


def _f12_unbestaetigt():
    """Ein Konto, wie es die Registrierung mit Bestätigungspflicht hinterlässt, samt Spuren: die
    Registrierung des Fremden (mit seiner IP) und ein Fehlversuch des echten Adressinhabers."""
    a, app_ = _app(csrf_enabled=False)
    uid = a.create_user(_F12_NAME, password="Geheim12345!-lang", email=_F12_MAIL)
    a.store.set_disabled(uid, True)
    a.create_magic_token("verify_email", user_id=uid)
    # Die Spuren entstehen NACH der Sekunde der Anlage (das Konto ist eine Minute alt): Ein
    # Anmeldeversuch aus der Anlage-Sekunde selbst lässt `delete_attempts_for` bewusst stehen —
    # ob er davor oder danach kam, ist nicht zu entscheiden (Nachbesserung N-1).
    a.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (uid,))
    a.audit("signup", _F12_NAME, "203.0.113.66")
    TestClient(app_, client=("198.51.100.7", 1)).post(
        "/auth/login", data={"username": _F12_MAIL, "password": "falsch-falsch"})
    a.store._exec("UPDATE magic_token SET expires_at=0 WHERE user_id=?", (uid,))
    vorher = _f12_spuren(a)
    assert vorher[0] and vorher[1], f"Vorbedingung: Spuren müssen da sein, sonst misst das nichts: {vorher}"
    return a, app_, uid


for _f12_weg, _f12_lauf in (("gc()", lambda a: a.gc()["unverified_accounts"]),
                            ("tinysesam gc (Store)", lambda a: a.store.gc_unbestaetigte_konten())):
    _f12_a, _, _f12_uid = _f12_unbestaetigt()
    _f12_n = _f12_lauf(_f12_a)
    _f12_rest = _f12_spuren(_f12_a)
    r.check(f"Funde 12/18: {_f12_weg} entfernt das Konto und nimmt es aus Audit-Log und Versuchen",
            _f12_n == 1 and _f12_a.store.get_user(_f12_uid) is None and _f12_rest == ([], []),
            f"n={_f12_n}, übrig: {_f12_rest}")
    _f12_ablauf = [z["username"] for z in _f12_a.store.recent_audit(20) if z["event"] == "signup_expired"]
    r.check(f"Funde 12/18: {_f12_weg} schreibt signup_expired unter dem Ersatznamen",
            _f12_ablauf == [f"gelöscht#{_f12_uid}"], f"{_f12_ablauf}")

# Und die Kontoseite der echten Carol danach (Fund 12 im Wortlaut): nur ihre eigenen Zeilen.
_f12_a, _f12_app, _ = _f12_unbestaetigt()
_f12_a.gc()
_f12_neu = _f12_a.create_user(_F12_NAME, password="Geheim12345!-lang", email="echt@example.com")
_f12_a.audit("signup", _F12_NAME, "198.51.100.8")
_f12_eigene = [(e["event"], e["ip"]) for e in _f12_a.own_events(_f12_neu)]
r.check("Fund 12: ein späterer Namensvetter sieht die Registrierung des Fremden nicht",
        _f12_eigene == [("signup", "198.51.100.8")], f"{_f12_eigene}")

# B6-5: der Bestätigungsversand scheitert → das Konto wird zurückgenommen, ebenfalls über den Weg.
_f12_b, _f12_bapp = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                         csrf_enabled=False)


def _f12_kaputt(*a, **k):
    raise OSError("Mailserver weg")


_f12_b.set_mailer(_f12_kaputt)
_f12_bc = TestClient(_f12_bapp, client=("203.0.113.66", 1), raise_server_exceptions=False)
_f12_br = _f12_bc.post("/auth/register", data={"username": _F12_NAME, "password": "Geheim12345!-lang",
                                                "email": _F12_MAIL, "next": "/"})
_f12_brest = _f12_spuren(_f12_b)
_f12_bzeile = [z["username"] for z in _f12_b.store.recent_audit(20) if z["event"] == "verify_send_error"]
r.check("Funde 12/18: die B6-5-Rücknahme nimmt das Konto aus dem Log, verify_send_error unter Ersatznamen",
        _f12_br.status_code == 200 and _f12_b.store.get_user_by_name(_F12_NAME) is None
        and _f12_brest == ([], []) and len(_f12_bzeile) == 1
        and _f12_bzeile[0].startswith("gelöscht#"), f"HTTP {_f12_br.status_code}, übrig {_f12_brest}, {_f12_bzeile}")

# purge_demo (Demo-Modus aus) — derselbe Weg, auch wenn der Fund ihn nicht nannte.
_f12_d, _ = _app(demo_mode=True)
_f12_d.audit("login", "demo", "198.51.100.9")
_f12_d.purge_demo()
r.check("Funde 12/18: purge_demo nimmt die Demo-Konten ebenso aus dem Log",
        not [z for z in _f12_d.store._all("SELECT * FROM audit") if z["username"] in _f12_d.DEMO_USERS],
        f"{[dict(z) for z in _f12_d.store._all('SELECT * FROM audit')]}")

_f12_weg = _aufrufe_ausserhalb("delete_user", _ist_store, {("Store", "konto_entfernen")})
r.check("Funde 12/18 (Wächter): ein Konto löscht nur Store.konto_entfernen — kein Weg an H-13 vorbei",
        not _f12_weg, f"direkte Aufrufe: {_f12_weg}")

# Zeilen, die VOR dem Konto entstanden, gehören nicht ihm — auch aus Beständen, die ein älterer
# Stand an H-13 vorbei gelöscht hat, und ein Fehlversuch unter einem damals freien Namen.
# (Mutationsprobe: in `own_events` `seit=` nicht übergeben → rot.)
_f12_c, _ = _app()
_f12_c.store.audit_log("login_fail", "berta", "203.0.113.66", "password")
_f12_c.store._exec("UPDATE audit SET ts=ts-3600 WHERE username='berta'")
_f12_berta = _f12_c.create_user("berta", password="Geheim12345!-lang")
_f12_c.audit("signup", "berta", "198.51.100.10")
_f12_bev = [(e["event"], e["ip"]) for e in _f12_c.own_events(_f12_berta)]
r.check("Fund 12: die Kontoseite zeigt keine Zeilen von vor der Anlage des Kontos",
        _f12_bev == [("signup", "198.51.100.10")], f"{_f12_bev}")

# ══════════════════════════════════════════════════════════════════════════════════════════
# Nachbesserung: Angriff auf die Integrationsfixes (Löschweg, Einladung, Passkey-ID, Wächter)
# ══════════════════════════════════════════════════════════════════════════════════════════

# ── N-1/N-6: der eine Löschweg rührt nur an, was ab der Anlage des Kontos entstand ─────────
# Seit `gc()`, `tinysesam gc` und die B6-5-Rücknahme über `Store.konto_entfernen` löschen, löst
# diesen Weg ein Fremder ohne Konto aus: registrieren, nie bestätigen. Ohne Grenze schrieb er
# dabei Zeilen um, die VOR seinem Konto entstanden und anderen gehören — die Einladung des
# Admins (Adresse im Detail), den Fehlversuch eines Sprayers unter dem damals freien Namen, den
# der echten Adressinhaberin — und ihre login_attempt-Zeilen (Drosselung je IP) verschwanden.
# Geprüft in zwei Lagen: die fremden Zeilen eine Minute vor der Registrierung (der Normalfall)
# und in DERSELBEN Sekunde (angehaltene Uhr — so lief der Nachweis des Angreifers). Eine nur
# sekundengenaue Grenze hält die zweite Lage nicht; dort entscheidet die Registrierungszeile
# (`Store.anlage_grenze`).
# (Mutationsproben: in `konto_entfernen` `seit=`/`nach=` nicht weitergeben → rot in beiden
#  Lagen; `seit_id` nicht weitergeben → rot nur in „dieselbe Sekunde"; in `delete_attempts_for`
#  `ts > ?` zu `ts >= ?` → rot in „dieselbe Sekunde"; in `TinySesam.delete_user`
#  `adresse_unbefristet=True` streichen → rot bei N-6.)
from tinysesam import store as _store_mod  # noqa: E402

_N1_NAME, _N1_MAIL = "root", "carol@example.com"
_N1_IPS = ("203.0.113.9", "198.51.100.50")


@_ctxlib.contextmanager
def _uhr_steht():
    """Die Store-Uhr anhalten: Alles darin trägt denselben Zeitstempel (dieselbe Sekunde).
    Danach läuft sie ab dort weiter — ohne Vorlauf gegenüber der Wanduhr."""
    uhr = _store_mod._UHR
    alt = (uhr.wand, uhr.mono)
    wand, mono = float(uhr.wand()), float(uhr.mono())
    uhr.wand, uhr.mono = (lambda: wand), (lambda: mono)
    try:
        yield
    finally:
        uhr.wand, uhr.mono = alt


def _n1_fremde(a) -> tuple:
    """Die Zeilen, die vor dem Konto entstanden: Einladung, zwei Fehlversuche, zwei Versuche."""
    audit = [(z["event"], z["username"], z["ip"], z["detail"]) for z in a.store._all(
        "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail') AND ip IN (?, ?, ?) "
        "ORDER BY id", ("198.51.100.1", *_N1_IPS))]
    versuche = [(z["username"], z["ip"], z["success"]) for z in a.store._all(
        "SELECT * FROM login_attempt WHERE ip IN (?, ?) ORDER BY id", _N1_IPS)]
    return audit, versuche


def _n1_kaputt(*a, **k):
    raise OSError("550 recipient rejected")


def _n1_lauf(mailer, gleiche_sekunde: bool):
    """Einladung, Sprayer, echte Inhaberin — dann registriert ein Fremder Name und Adresse."""
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   magiclink_enabled=True, csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)   # die Einladung geht hinaus; `mailer` gilt danach
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    vor_id = a.store._one("SELECT COALESCE(MAX(id), 0) AS m FROM audit")["m"]
    with (_uhr_steht() if gleiche_sekunde else _ctxlib.nullcontext()):
        assert ca.post("/auth/admin/api/invite", json={"email": _N1_MAIL}).status_code == 200
        TestClient(app_, client=(_N1_IPS[0], 1)).post(                # Sprayer, Name noch frei
            "/auth/login", data={"username": _N1_NAME, "password": "Passwort1!"})
        TestClient(app_, client=(_N1_IPS[1], 1)).post(                # die echte Carol, ohne Konto
            "/auth/login", data={"username": _N1_MAIL, "password": "irgendwas-langes"})
        if not gleiche_sekunde:
            a.store._exec("UPDATE audit SET ts=ts-60")                # eine Minute davor
            a.store._exec("UPDATE login_attempt SET ts=ts-60")
        vorher = _n1_fremde(a)
        assert len(vorher[0]) == 3 and len(vorher[1]) == 2, f"Vorbedingung: {vorher}"
        a.set_mailer(mailer)
        reg = TestClient(app_, client=("192.0.2.66", 1), raise_server_exceptions=False).post(
            "/auth/register", data={"username": _N1_NAME, "password": "Fremder-Langes-77",
                                    "email": _N1_MAIL, "next": "/"})
        if gleiche_sekunde:
            _konto = a.store.get_user_by_name(_N1_NAME)
            _ts = {z["ts"] for z in a.store._all("SELECT ts FROM audit WHERE id > ?", (vor_id,))}
            assert len(_ts) == 1 and (_konto is None or {_konto["created_at"]} == _ts), \
                f"Vorbedingung: alles in einer Sekunde ({_ts})"
    return a, app_, reg, vorher


for _n1_lage, _n1_gleich in (("eine Minute davor", False), ("dieselbe Sekunde", True)):
    _n1_a, _n1_app, _n1_reg, _n1_vorher = _n1_lauf(lambda *x, **k: True, _n1_gleich)
    _n1_uid = _n1_a.store.get_user_by_name(_N1_NAME)["id"]
    # Dieselbe Grenze auf der Kontoseite (H-7): Der Fehlversuch des Sprayers unter dem damals
    # freien Namen ist nicht das Ereignis dieses Kontos — auch nicht aus derselben Sekunde.
    # (Mutationsprobe: in `own_events` `seit_id` nicht weitergeben → rot in „dieselbe Sekunde".)
    _n1_eigen = [(e["event"], e["ip"]) for e in _n1_a.own_events(_n1_uid)]
    r.check(f"N-1 ({_n1_lage}): die Kontoseite zeigt nur die eigene Registrierung, nicht den Sprayer",
            _n1_eigen == [("signup", "192.0.2.66")], f"{_n1_eigen}")
    # Nach der Anlage: ein Fehlversuch unter dem Namen — der trifft DIESES Konto und geht mit.
    # Er kommt Sekunden später (die Sekunde der Anlage selbst lässt `delete_attempts_for` stehen).
    TestClient(_n1_app, client=("203.0.113.77", 1)).post(
        "/auth/login", data={"username": _N1_NAME, "password": "falsch-falsch"})
    _n1_a.store._exec("UPDATE audit SET ts=ts+5 WHERE ip='203.0.113.77'")
    _n1_a.store._exec("UPDATE login_attempt SET ts=ts+5 WHERE ip='203.0.113.77'")
    _n1_a.store._exec("UPDATE magic_token SET expires_at=0 WHERE user_id=? AND purpose='verify_email'",
                      (_n1_uid,))
    _n1_gc = _n1_a.gc()["unverified_accounts"]
    _n1_nach = _n1_fremde(_n1_a)
    r.check(f"N-1 ({_n1_lage}): gc() eines nie bestätigten Kontos lässt Zeilen von VOR seiner Anlage "
            "stehen (Einladung des Admins, Sprayer, echte Adressinhaberin — samt Versuchszeilen)",
            _n1_reg.status_code == 200 and _n1_gc == 1 and _n1_nach == _n1_vorher,
            f"HTTP {_n1_reg.status_code}, gc={_n1_gc}\nvorher {_n1_vorher}\nnachher {_n1_nach}")
    _n1_danach = [(z["event"], z["username"]) for z in _n1_a.store._all(
        "SELECT * FROM audit WHERE ip IN ('192.0.2.66', '203.0.113.77') ORDER BY id")]
    _n1_versuch77 = _n1_a.store._all("SELECT * FROM login_attempt WHERE ip='203.0.113.77'")
    r.check(f"N-1 ({_n1_lage}): … was ab der Anlage entstand, geht weiter mit (Registrierung, "
            "späterer Fehlversuch)",
            _n1_danach == [("signup", f"gelöscht#{_n1_uid}"), ("login_fail", f"gelöscht#{_n1_uid}")]
            and not _n1_versuch77, f"{_n1_danach}, Versuche {[dict(v) for v in _n1_versuch77]}")

    _n1_b, _, _n1_breg, _n1_bvorher = _n1_lauf(_n1_kaputt, _n1_gleich)
    _n1_bnach = _n1_fremde(_n1_b)
    _n1_bsignup = [z["username"] for z in _n1_b.store._all("SELECT * FROM audit WHERE event='signup'")]
    r.check(f"N-1 ({_n1_lage}): die B6-5-Rücknahme (Versand scheitert) lässt dieselben fremden "
            "Zeilen stehen — und nimmt die eigene Registrierung aus dem Log",
            _n1_breg.status_code == 200 and _n1_b.store.get_user_by_name(_N1_NAME) is None
            and _n1_bnach == _n1_bvorher and len(_n1_bsignup) == 1
            and _n1_bsignup[0].startswith("gelöscht#"),
            f"HTTP {_n1_breg.status_code}, signup {_n1_bsignup}\nvorher {_n1_bvorher}\n"
            f"nachher {_n1_bnach}")

# Der Anker ist die Registrierungszeile aus der Sekunde der Anlage (oder der nächsten) — nicht
# irgendeine spätere. Eine Registrierung mit der Adresse als Name, die schon einem Konto als
# Benutzername gehört, schreibt `signup_taken` unter genau diesem Namen; als Anker genommen, fiele
# die Zeile des Admins aus der Anlage-Sekunde aus der Anonymisierung.
# S-3 (Schlussrunde): Die erste Fassung prüfte das nur mit +5 s. In der Anlage-Sekunde selbst und
# in der nächsten nahm `anlage_grenze` die fremde Zeile doch als Anker — der Docstring sagte das
# Gegenteil. Jetzt zählt `signup_taken` nur als Anlage eines Platzhalters (keine Adresse am Konto,
# Detail ≠ Name); geprüft mit +0, +1 und +5 s.
# (Mutationsproben: die Platzhalter-Bedingung streichen, also jede `signup_taken`-Zeile als Anker
#  nehmen → rot bei +0 und +1; nur die Bedingung „Konto ohne Adresse“ behalten → ebenso rot. Die
#  Zeilen-Bedingung trägt allein: Die Bedingung „Konto ohne Adresse“ ist ein zweiter Riegel, den
#  heute kein Weg erreicht — gestrichen bleibt die Suite grün (gemessen). Das Zeitfenster misst der
#  Fall mit einer späteren `signup`-Zeile: `ts BETWEEN ? AND ?` zu `ts >= ?` → rot nur dort.)
def _n7_lauf(versatz: int, ereignis: str = "signup_taken"):
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    with _uhr_steht():                 # Anlage und `user_create` in einer Sekunde
        assert ca.post("/auth/admin/api/users", json={"username": "kasse@example.com"}).status_code == 200
    konto = a.store.get_user_by_name("kasse@example.com")
    if ereignis == "signup_taken":
        antwort = TestClient(app_, client=("203.0.113.66", 1)).post(
            "/auth/register", data={"username": "kasse@example.com", "password": "Anderes-77!-lang-genug",
                                    "email": "kasse@example.com", "next": "/"})
        status = antwort.status_code
    else:                              # eine einbettende App protokolliert ihre eigene Anmeldung
        a.audit(ereignis, "kasse@example.com", "203.0.113.66")
        status = 200
    a.store._exec("UPDATE audit SET ts=? WHERE event=?", (konto["created_at"] + versatz, ereignis))
    anker = a.store.anlage_grenze(a.store.get_user(konto["id"]))
    a.delete_user(konto["id"])
    zeilen = [z["detail"] for z in a.store._all("SELECT * FROM audit WHERE event='user_create'")]
    return status, konto["id"], anker, zeilen


for _n7_ereignis, _n7_versatz in (("signup_taken", 0), ("signup_taken", 1), ("signup_taken", 5),
                                  ("signup", 5)):
    _n7_status, _n7_uid, _n7_anker, _n7_z = _n7_lauf(_n7_versatz, _n7_ereignis)
    r.check(f"N-1/S-3: eine fremde {_n7_ereignis}-Zeile (+{_n7_versatz} s nach der Anlage) unter dem "
            "Namen verschiebt die Grenze nicht (user_create aus der Anlage-Sekunde wird anonymisiert)",
            _n7_status == 200 and _n7_anker[1] == 0 and _n7_z == [f"gelöscht#{_n7_uid} service=False"],
            f"HTTP {_n7_status}, anlage_grenze {_n7_anker}, {_n7_z}")

# Gegenprobe: Die signup_taken-Zeile EINES PLATZHALTERS ist seine Anlage und bleibt der Anker —
# sonst zählte die ganze Sekunde, und `gc()` schriebe den Fehlversuch eines Sprayers, der in
# derselben Sekunde den damals freien Namen probierte, dem Platzhalter zu (wie N-1, nur über den
# Zweig „Adresse vergeben“, R4-03).
_s3_a, _s3_app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                      csrf_enabled=False)
_s3_a.set_mailer(lambda *x, **k: True)
_s3_a.create_user("inhaberin", password="Geheim12345!-lang", email="belegt@example.com")
with _uhr_steht():
    TestClient(_s3_app, client=("203.0.113.9", 1)).post(          # Sprayer, Name noch frei
        "/auth/login", data={"username": "platz", "password": "Passwort1!"})
    _s3_reg = TestClient(_s3_app, client=("192.0.2.66", 1)).post(
        "/auth/register", data={"username": "platz", "password": "Fremder-Langes-77",
                                "email": "belegt@example.com", "next": "/"})
_s3_platz = _s3_a.store.get_user_by_name("platz")
_s3_anker = _s3_a.store.anlage_grenze(_s3_platz) if _s3_platz else None
_s3_a.store._exec("UPDATE magic_token SET expires_at=0 WHERE purpose='verify_email'")
_s3_gc = _s3_a.gc()["unverified_accounts"]
_s3_zeilen = [(z["event"], z["username"]) for z in _s3_a.store._all(
    "SELECT * FROM audit WHERE event IN ('login_fail', 'signup_taken') ORDER BY id")]
r.check("S-3: … die signup_taken-Zeile eines Platzhalters bleibt sein Anker — gc() lässt den Sprayer "
        "aus derselben Sekunde stehen und nimmt nur die eigene Zeile",
        _s3_reg.status_code == 200 and _s3_platz is not None and not _s3_platz["email"]
        and _s3_anker[1] > 0 and _s3_gc == 1
        and _s3_zeilen == [("login_fail", "platz"), ("signup_taken", f"gelöscht#{_s3_platz['id']}")],
        f"HTTP {_s3_reg.status_code}, Anker {_s3_anker}, gc={_s3_gc}, {_s3_zeilen}")

# Die bewusste Löschung eines Kontos, dessen Adresse BESTÄTIGT ist, bleibt so gründlich wie
# H-13 sie zusagt: Die Adresse gehört nachweislich dem Konto, also verschwindet sie auch aus
# älteren Zeilen (die Einladung, die zu dem Konto führte). Der NAME dagegen gehörte vor der
# Anlage niemandem — der Fehlversuch darunter bleibt, wie er war.
_n6_a, _ = _app(csrf_enabled=False)
_n6_a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_n6_a.store.audit_log("invite_create", "chef", "198.51.100.1", "dora@example.com")
_n6_a.store.audit_log("login_fail", "dora", "203.0.113.9", "password grund=kein_konto")
_n6_a.store.record_attempt("dora", "203.0.113.9", False, "password")
_n6_a.store._exec("UPDATE audit SET ts=ts-60")
_n6_a.store._exec("UPDATE login_attempt SET ts=ts-60")
_n6_dora = _n6_a.create_user("dora", password="Geheim12345!-lang", email="dora@example.com")
_n6_a.delete_user(_n6_dora)
_n6_zeilen = {z["event"]: (z["username"], z["detail"]) for z in _n6_a.store._all(
    "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail')")}
r.check("N-6: die Löschung durch einen Admin nimmt eine bestätigte Adresse auch aus älteren Zeilen (H-13)",
        _n6_zeilen.get("invite_create") == ("chef", f"gelöscht#{_n6_dora}"), f"{_n6_zeilen}")
r.check("N-6: … den Namen aber erst ab der Anlage — der Fehlversuch unter dem freien Namen bleibt samt Versuch",
        _n6_zeilen.get("login_fail") == ("dora", "password grund=kein_konto")
        and len(_n6_a.store._all("SELECT id FROM login_attempt WHERE username='dora'")) == 1,
        f"{_n6_zeilen}")

# ── S-2: unbefristet ersetzt wird nur eine BELEGTE Adresse ─────────────────────────────────────
# N-6 prüfte nur ein Konto, dessen Adresse der Admin angelegt hatte. Die Registrierung legte die
# eingetippte Adresse aber als „bestätigt“ an, solange der Link ausstand — ohne
# Bestätigungspflicht sogar für immer. Löschte ein Admin ein solches Konto (Aufräumen, Löschwunsch
# des Fremden), gingen die Einladung des Admins und der Fehlversuch der echten Inhaberin von VOR der
# Anlage auf `gelöscht#<id>` über — der Schaden aus N-1, nur über den bewussten Löschweg.
# Jetzt setzt erst der eingelöste Link den Beleg, und `Store.adresse_belegt` sieht ein offenes Konto
# (gesperrt, Token offen) auch dann, wenn eine App es mit der Vorgabe `email_verified=True` anlegt.
# (Mutationsproben: in `register_submit` wieder ohne `email_verified=` anlegen → rot bei „ohne
#  Bestätigungspflicht“ und „offen“; in `adresse_belegt` die Token-Prüfung streichen → rot bei
#  „App-Weg“; in `konto_entfernen` wieder nur den Vermerk fragen → rot bei „App-Weg“; in
#  `/auth/verify` `set_email_verified` streichen → rot bei „nach dem Link“.)
_S2_MAIL = "carol@example.com"


def _s2_lauf(verify: bool):
    a, app_ = _app(allow_signup=True, signup_verify_email=verify, signup_require_email=True,
                   magiclink_enabled=True, csrf_enabled=False)
    post = []
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, text)))
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    assert ca.post("/auth/admin/api/invite", json={"email": _S2_MAIL}).status_code == 200
    TestClient(app_, client=("198.51.100.50", 1)).post(          # die echte Carol, ohne Konto
        "/auth/login", data={"username": _S2_MAIL, "password": "irgendwas-langes"})
    a.store._exec("UPDATE audit SET ts=ts-60")                    # eine Minute vor der Anlage
    a.store._exec("UPDATE login_attempt SET ts=ts-60")
    return a, app_, ca, post


def _s2_fremde(a) -> list:
    return [(z["event"], z["username"], z["detail"]) for z in a.store._all(
        "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail') ORDER BY id")]


def _s2_registrieren(app_):
    return TestClient(app_, client=("192.0.2.66", 1)).post(
        "/auth/register", data={"username": "fremder", "password": "Fremder-Langes-77",
                                "email": _S2_MAIL, "next": "/"}, follow_redirects=False)


# (a) Bestätigung verlangt, Link nie eingelöst — der Admin löscht das offene Konto im Panel.
_s2_a, _s2_app, _s2_ca, _ = _s2_lauf(True)
_s2_vorher = _s2_fremde(_s2_a)
_s2_reg = _s2_registrieren(_s2_app)
_s2_u = _s2_a.store.get_user_by_name("fremder")
_s2_del = _s2_ca.post(f"/auth/admin/api/users/{_s2_u['id']}/delete")
_s2_nach = _s2_fremde(_s2_a)
_s2_versuch = _s2_a.store._all("SELECT * FROM login_attempt WHERE ip='198.51.100.50'")
r.check("S-2 (offen): die Registrierung legt die eingetippte Adresse ohne Beleg an, und die "
        "Löschung im Panel lässt Einladung und Fehlversuch der Inhaberin von vor der Anlage stehen",
        _s2_reg.status_code == 200 and _s2_u["email_verified"] == 0 and _s2_del.status_code == 200
        and _s2_nach == _s2_vorher and len(_s2_versuch) == 1,
        f"HTTP {_s2_reg.status_code}/{_s2_del.status_code}, email_verified={_s2_u['email_verified']}\n"
        f"vorher {_s2_vorher}\nnachher {_s2_nach}, Versuche {len(_s2_versuch)}")

# (b) Ohne Bestätigungspflicht: angemeldet, aber die Adresse ist nie belegt.
_s2_b, _s2_bapp, _, _ = _s2_lauf(False)
_s2_bvorher = _s2_fremde(_s2_b)
_s2_breg = _s2_registrieren(_s2_bapp)
_s2_bu = _s2_b.store.get_user_by_name("fremder")
_s2_b.delete_user(_s2_bu["id"])
_s2_bnach = _s2_fremde(_s2_b)
r.check("S-2 (ohne Bestätigungspflicht): unbelegt — delete_user lässt die Zeilen von vor der Anlage stehen",
        _s2_breg.status_code == 303 and _s2_bu["email_verified"] == 0 and _s2_bnach == _s2_bvorher,
        f"HTTP {_s2_breg.status_code}, email_verified={_s2_bu['email_verified']}\n"
        f"vorher {_s2_bvorher}\nnachher {_s2_bnach}")

# (c) Gegenprobe: Nach dem eingelösten Link ist die Adresse belegt — H-13 bleibt so gründlich wie
# bisher und nimmt sie auch aus der Einladung, die zu dem Konto führte.
_s2_c, _s2_capp, _, _s2_post = _s2_lauf(True)
_s2_creg = _s2_registrieren(_s2_capp)
_s2_link = [m.group(1) for zu, text in _s2_post if zu == _S2_MAIL
            for m in [re.search(r"/auth/verify/([\w\-]+)", text)] if m]
_s2_cver = TestClient(_s2_capp, client=("192.0.2.66", 1)).post(
    f"/auth/verify/{_s2_link[-1]}", follow_redirects=False) if _s2_link else None
_s2_cu = _s2_c.store.get_user_by_name("fremder")
_s2_c.delete_user(_s2_cu["id"])
_s2_cnach = dict((e, (u, d)) for e, u, d in _s2_fremde(_s2_c))
r.check("S-2 (nach dem Link): der eingelöste Link setzt den Beleg, und die Löschung nimmt die "
        "Adresse auch aus der älteren Einladung (H-13)",
        _s2_creg.status_code == 200 and _s2_cver is not None and _s2_cver.status_code == 303
        and _s2_cu["email_verified"] == 1
        and _s2_cnach.get("invite_create") == ("chef", f"gelöscht#{_s2_cu['id']}"),
        f"HTTP {_s2_creg.status_code}/{getattr(_s2_cver, 'status_code', None)}, "
        f"email_verified={_s2_cu['email_verified']}, {_s2_cnach}")

# (d) Der App-Weg: `create_user` mit der Vorgabe `email_verified=True`, gesperrt, eigener
# Bestätigungslink ausstehend. Der Vermerk sagt „belegt“, der offene Token widerspricht.
_s2_d, _, _, _ = _s2_lauf(True)
_s2_dvorher = _s2_fremde(_s2_d)
_s2_duid = _s2_d.create_user("fremder", password="Geheim12345!-lang", email=_S2_MAIL)
_s2_d.store.set_disabled(_s2_duid, True)
_s2_d.create_magic_token("verify_email", user_id=_s2_duid, email=_S2_MAIL)
_s2_offen_belegt = _s2_d.store.adresse_belegt(_s2_d.store.get_user(_s2_duid))
_s2_d.delete_user(_s2_duid)
r.check("S-2 (App-Weg): ein offenes Konto mit dem Vermerk „bestätigt“ gilt nicht als belegt",
        _s2_offen_belegt is False and _s2_fremde(_s2_d) == _s2_dvorher,
        f"belegt={_s2_offen_belegt}\nvorher {_s2_dvorher}\nnachher {_s2_fremde(_s2_d)}")

# ── S-1: die Topf-Prüfung darf die Registrierung nicht zum Adress-Orakel machen ─────────────────
# `Store.konto_mit_topf` (N-5) faltete bei JEDEM Aufruf alle Konten in Python. Die Registrierung
# mit einer FREIEN Adresse ruft sie öfter als die mit einer vergebenen (dort trifft
# `get_user_by_email` vorher) — gemessen bei 20 000 Konten: 118 ms gegen 151 ms, die Bereiche
# überlappten nicht, eine Anfrage reichte (R4-03 gekippt). `gc()` wuchs mit offenen × allen
# Konten. Jetzt stehen die Töpfe als indizierte Spalten in `users` (Schema 10), und auch die
# NOCASE-Suche nach Name und Adresse läuft über einen Index (vorher las SQLite dort jede Zeile,
# bei einem Treffer bis zu ihm — derselbe Unterschied, nur kleiner).
# Gemessen wird nicht die Wanduhr, sondern die Arbeit der Datenbank: die Zahl der SQLite-Schritte
# (`set_progress_handler(…, 1)`) bei 100 und bei 3000 Konten. Ein Scan über die Konten kostet
# mindestens einen Schritt je Zeile, also Tausende; ein Index-Zugriff ist ein Schritt, egal wie
# tief der Baum ist. Die Konten kommen per rohem INSERT ohne Topf — wie von einem anderen
# Schreiber —, der erste Aufruf trägt die Töpfe nach (`_toepfe_nachtragen`).
# (Mutationsproben: `konto_mit_topf` wieder als Python-Schleife über alle Konten → rot, „frei“
#  1 662 → 48 062 Schritte bei 100 → 3000 Konten; die Indizes `ix_users_name_nocase`/
#  `ix_users_email_nocase` nicht anlegen → rot, „vergeben (erstes Konto)“ 430 gegen „letztes
#  Konto“ 33 122 — genau das Orakel; `_toepfe_nachtragen` schreibt nichts → rot, 3000 Zeilen
#  ohne Topf und wieder die Schleife über alle.)
def _s1_app(n: int):
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)
    a.store.db.executemany(
        "INSERT INTO users(username, display_name, email, is_admin, roles, is_service, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        [(f"konto{i}", None, f"konto{i}@example.com", 0, "[]", 0, 1) for i in range(n)])
    a.store.db.commit()
    a.kennung_vergeben("aufwaermen")          # trägt die Töpfe der rohen Zeilen nach
    return a, app_


def _s1_schritte(a, fn) -> int:
    zaehler = [0]

    def schritt():
        zaehler[0] += 1
        return 0
    a.store.db.set_progress_handler(schritt, 1)
    try:
        fn()
    finally:
        a.store.db.set_progress_handler(None, 1)
    return zaehler[0]


def _s1_messen(n: int) -> dict:
    a, app_ = _s1_app(n)
    ohne_topf = a.store._one("SELECT COUNT(*) AS n FROM users WHERE topf_name IS NULL "
                             "OR topf_mail IS NULL")["n"]
    letzte, erste = f"konto{n - 1}@example.com", "konto0@example.com"
    m = {"ohne_topf": ohne_topf,
         "frei": _s1_schritte(a, lambda: a.kennung_vergeben("niemand@example.org")),
         "vergeben (erstes Konto)": _s1_schritte(a, lambda: a.kennung_vergeben(erste)),
         "vergeben (letztes Konto)": _s1_schritte(a, lambda: a.kennung_vergeben(letzte)),
         "Namensvetter": _s1_schritte(a, lambda: a.kennung_vergeben("KONTO7")),
         "Registrierung frei": _s1_schritte(a, lambda: TestClient(app_, client=("192.0.2.31", 1)).post(
             "/auth/register", data={"username": "probefrei", "password": "Sehr-Langes-Passwort-77",
                                     "email": "neu@example.org", "next": "/"})),
         "Registrierung vergeben": _s1_schritte(a, lambda: TestClient(app_, client=("192.0.2.32", 1)).post(
             "/auth/register", data={"username": "probevergeben", "password": "Sehr-Langes-Passwort-77",
                                     "email": letzte, "next": "/"}))}
    for i in range(5):                        # fünf offene Konten, Link abgelaufen
        uid = a.store.create_user(f"offen{i}", None, f"offen{i}@example.org", False, [], False)
        a.store.set_disabled(uid, True)
        a.create_magic_token("verify_email", user_id=uid)
    a.store._exec("UPDATE magic_token SET expires_at=1 WHERE purpose='verify_email'")
    m["gc (5 offene Konten)"] = _s1_schritte(a, a.store.gc_unbestaetigte_konten)
    return m


_s1_klein, _s1_gross = _s1_messen(100), _s1_messen(3000)
# Spielraum 100 Schritte: ein Mitschreiben des Uhrstands (`_uhr_mitschreiben`) mehr oder weniger.
# Ein Scan über 2900 zusätzliche Konten liegt weit darüber.
_s1_wachsen = {k: (_s1_klein[k], _s1_gross[k]) for k in _s1_klein
               if k != "ohne_topf" and abs(_s1_gross[k] - _s1_klein[k]) > 100}
r.check("S-1: die Datenbankarbeit von kennung_vergeben, der Registrierung (frei und vergeben) und "
        "gc() hängt nicht von der Zahl der Konten ab (100 vs. 3000, SQLite-Schritte)",
        not _s1_wachsen and _s1_gross["ohne_topf"] == 0,
        f"wächst: {_s1_wachsen}\n100: {_s1_klein}\n3000: {_s1_gross}")
r.check("S-1: … frei und vergeben unterscheiden sich bei 3000 Konten nur um einen festen, kleinen Betrag",
        abs(_s1_gross["Registrierung frei"] - _s1_gross["Registrierung vergeben"]) <= 200
        and abs(_s1_gross["frei"] - _s1_gross["vergeben (letztes Konto)"]) <= 200,
        f"{_s1_gross}")
# Die Topf-Prüfung selbst muss weiter greifen, auch für eine Zeile eines anderen Schreibers, die
# jemand umbenennt: Der Trigger setzt den Topf auf NULL, der nächste Aufruf rechnet ihn neu.
# (Mutationsprobe: der Trigger setzt nichts → rot, „ärmel“ bleibt unerkannt, „konto3“ trifft.)
_s1_a, _ = _s1_app(10)
_s1_a.store.db.execute("UPDATE users SET username='Ärmel' WHERE username='konto3'")
_s1_a.store.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Özlem', NULL, 1)")
_s1_a.store.db.commit()
_s1_treffer = {k: (_s1_a.store.konto_mit_topf(k) or {"username": None})["username"]
               for k in ("ärmel", "özlem", "konto3", "KONTO4@EXAMPLE.COM")}
r.check("S-1: … und findet Namensvetter weiter — auch nach Umbenennung und INSERT am Store vorbei",
        _s1_treffer == {"ärmel": "Ärmel", "özlem": "Özlem", "konto3": None,
                        "KONTO4@EXAMPLE.COM": "konto4"}, f"{_s1_treffer}")
# Nur lesbar (Volume schreibgeschützt): Ein Topf, der sich nicht nachtragen lässt, darf weder den
# Start verhindern (der ging vorher auch) noch einen Namensvetter übersehen lassen. Zur Laufzeit
# echt über `PRAGMA query_only`, beim Start über einen Nachtrag, der wie auf einer nur lesbaren
# Datei scheitert (eine Datei per chmod zu sperren hält einen Test unter root nicht auf).
# (Mutationsproben: in `_migrate` das Abfangen streichen → rot, der Start scheitert; in
#  `_toepfe_nachtragen` bei einem Fehler `[]` statt der Zeilen zurückgeben → rot bei „Özlem“.)
_s1_a.store.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Ündine', NULL, 1)")
_s1_a.store.db.commit()
_s1_a.store.db.execute("PRAGMA query_only = ON")
try:
    _s1_nur_lesend = (_s1_a.store.konto_mit_topf("ündine") or {"username": None})["username"]
finally:
    _s1_a.store.db.execute("PRAGMA query_only = OFF")
_s1_ro_db = os.path.join(tempfile.mkdtemp(), "ro.db")
_s1_ro = Store(_s1_ro_db)
_s1_ro.create_user("anna", None, "anna@example.com")
_s1_ro.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Özlem', NULL, 1)")
_s1_ro.db.commit()
_s1_ro.db.close()
_s1_schreiben = Store._toepfe_schreiben


def _s1_nicht_schreibbar(self, zeilen):
    if zeilen:
        raise sqlite3.OperationalError("attempt to write a readonly database")


Store._toepfe_schreiben = _s1_nicht_schreibbar
try:
    _s1_ro2 = Store(_s1_ro_db)
    _s1_start = [(_s1_ro2.konto_mit_topf(k) or {"username": None})["username"] for k in ("özlem", "ANNA")]
    _s1_ro2.db.close()
except Exception as _e:        # der Start selbst scheitert
    _s1_start = f"{type(_e).__name__}: {_e}"
finally:
    Store._toepfe_schreiben = _s1_schreiben
r.check("S-1: … auch ohne Schreibrecht: der Start gelingt, und Zeilen ohne Topf prüft Python selbst",
        _s1_nur_lesend == "Ündine" and _s1_start == ["Özlem", "anna"],
        f"Laufzeit {_s1_nur_lesend}, Start {_s1_start}")
# Die Schreiber im Store führen den Topf selbst mit, in derselben Anweisung — der Nachtrag ist
# für fremde Schreiber da, nicht für die eigenen.
# (Mutationsproben: in `Store.create_user` bzw. `Store.set_email` den Topf weglassen → rot.)
_s1_uid = _s1_a.store.create_user("Ärger", None, "X@Bücher.example")
_s1_nach_anlage = tuple(_s1_a.store._one("SELECT topf_name, topf_mail FROM users WHERE id=?", (_s1_uid,)))
_s1_a.store.set_email(_s1_uid, "Neu@Example.com")
_s1_nach_wechsel = _s1_a.store._one("SELECT topf_mail FROM users WHERE id=?", (_s1_uid,))["topf_mail"]
r.check("S-1: … create_user und set_email schreiben den Topf gleich mit",
        _s1_nach_anlage == ("ärger", "x@xn--bcher-kva.example") and _s1_nach_wechsel == "neu@example.com",
        f"nach Anlage {_s1_nach_anlage}, nach Adresswechsel {_s1_nach_wechsel}")

# ── N-5: Nicht-ASCII-Namensvetter teilen einen Zähl-Topf ──────────────────────────────────────
# Der Sperrzähler faltet mit Python-`lower()` (`norm_kennung`), `kennung_vergeben` und
# `get_user_by_name` mit SQLite-NOCASE — das faltet nur ASCII. Neben `Émile` liess sich deshalb
# `émile` anlegen, beide zählten im Topf `émile`. Über `konto_entfernen` (gc, B6-5 — anonym
# auslösbar) löschte das Entfernen von `émile` die Fehlversuche von `Émile`: Die Konto-Schwelle
# gegen verteiltes Raten (R7-6/H-8) liess sich für jedes Konto mit Ö/Ü/Ä/É … beliebig oft leeren.
# (Mutationsproben: in `kennung_vergeben` die Topf-Prüfung streichen → rot bei der Registrierung;
#  in `delete_attempts_for` die Prüfung auf ein verbleibendes Konto im Topf streichen → rot beim
#  Bestand; `delete_attempts_for` wieder nur mit SQLite-`lower()` vergleichen → rot beim Admin.)
_n5_a, _n5_app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                      csrf_enabled=False)
_n5_a.set_mailer(_n1_kaputt)          # scheiterte die Registrierung doch, griffe B6-5 sofort
_n5_a.create_user("Émile", password="Geheim12345!-lang", email="emile@example.com")
_n5_reg = TestClient(_n5_app, client=("203.0.113.99", 1), raise_server_exceptions=False).post(
    "/auth/register", data={"username": "émile", "password": "Irgendwas-Langes-77",
                            "email": "gibtsnicht@example.org", "next": "/"})
_n5_kein = None
try:
    # Klein-é: SQLite-NOCASE sieht darin einen anderen Namen (anders als bei „ÉMILE“, das
    # schon an ASCII-Faltung scheitert) — der Weg, den die Registrierung oben nimmt.
    _n5_a.create_user("émile", password="Anderes-77!-lang-genug")
except ConfigError as _e:
    _n5_kein = getattr(_e, "feld", "?")
r.check("N-5: „émile“ neben „Émile“ ist vergeben (derselbe Zähl-Topf) — 409, kein zweites Konto",
        _n5_reg.status_code == 409 and _n5_kein == "username"
        and len(_n5_a.store._all("SELECT id FROM users")) == 1,
        f"HTTP {_n5_reg.status_code}, create_user: {_n5_kein}")
r.check("N-5: … ein anderer Topf bleibt frei („Emile“ ohne Akzent)",
        bool(_n5_a.create_user("Emile", password="Anderes-77!-lang-genug")))


def _n5_rate(a, app_, name):
    for _i in range(4):
        _cl = TestClient(app_, client=(f"203.0.113.{_i + 1}", 1))
        for _ in range(4):
            _cl.post("/auth/login", data={"username": name, "password": "falsch-falsch"})


# Bestand aus einem Stand vor dieser Prüfung: der Namensvetter liegt schon in der Datenbank.
_n5_b, _n5_bapp = _app(csrf_enabled=False)
_n5_b.create_user("Özlem", password="Geheim12345!-lang", email="oezlem@example.com")
_n5_platz = _n5_b.store.create_user("özlem")
# Eine Minute vor den Rateversuchen angelegt — sonst blieben sie schon als Versuche aus der
# Anlage-Sekunde stehen, und die Probe mässe die Topf-Prüfung nicht.
_n5_b.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (_n5_platz,))
_n5_b.store.set_disabled(_n5_platz, True)
_n5_b.create_magic_token("verify_email", user_id=_n5_platz)
_n5_rate(_n5_b, _n5_bapp, "Özlem")


def _n5_topf(a, topf):
    return a.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE username=? AND success=0",
                        (topf,))["n"]


_n5_vor = _n5_topf(_n5_b, "özlem")
_n5_b.store._exec("UPDATE magic_token SET expires_at=1 WHERE purpose='verify_email'")
_n5_gc = _n5_b.gc()["unverified_accounts"]
_n5_frisch = TestClient(_n5_bapp, client=("198.51.100.200", 1)).post(
    "/auth/login", data={"username": "Özlem", "password": "falsch"})
r.check("N-5: gc() eines Namensvetters aus dem Bestand leert den Topf des verbleibenden Kontos nicht",
        _n5_vor >= 15 and _n5_gc == 1 and _n5_topf(_n5_b, "özlem") == _n5_vor
        and _n5_frisch.status_code == 429,
        f"vorher {_n5_vor}, gc={_n5_gc}, nachher {_n5_topf(_n5_b, 'özlem')}, "
        f"nächster Versuch HTTP {_n5_frisch.status_code}")

# Und in die andere Richtung: Der Topf von `Émile` heisst `émile`, SQLite-`lower('Émile')`
# ist `Émile`. Eine Löschung durch den Admin liess die Versuchszeilen deshalb liegen — die
# Zusage von H-13 („deren Versuchszeilen werden gelöscht") galt nur für ASCII-Namen.
_n5_c, _n5_capp = _app(csrf_enabled=False)
_n5_c.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_n5_ae = _n5_c.create_user("Ärmel", password="Geheim12345!-lang")
_n5_c.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (_n5_ae,))
_n5_rate(_n5_c, _n5_capp, "Ärmel")
_n5_cvor = _n5_topf(_n5_c, "ärmel")
_n5_c.delete_user(_n5_ae)
r.check("N-5: die Löschung eines Kontos mit Nicht-ASCII-Grossbuchstaben räumt auch seinen Zähl-Topf",
        _n5_cvor >= 15 and _n5_topf(_n5_c, "ärmel") == 0,
        f"vorher {_n5_cvor}, nachher {_n5_topf(_n5_c, 'ärmel')}")

# ── N-2: auch der GET mit Einladungs-Token hinterlässt eine Spur (B5-18) ──────────────────────
# `/auth/register?invite=<t>` prüft den Token per peek und antwortet unterschiedlich (403/200
# samt vorausgefüllter Adresse) — ohne Audit- und fail2ban-Zeile. /auth/invite/<t> und der POST
# protokollieren; wer Einladungs-Token durchprobieren wollte, nahm den stillen Weg.
# (Mutationsprobe: den `token_abgewiesen`-Aufruf in `register_page` streichen → rot.)
_n2_a, _n2_app = _app(allow_signup=True, signup_invite_only=True, magiclink_enabled=True,
                      csrf_enabled=False)
_n2_a.set_mailer(lambda *x, **k: True)
_n2_inv = _n2_a.create_invite("gast@example.com", "http://testserver")
_n2_tok = _n2_inv.get("token") or _n2_inv["url"].rsplit("/", 1)[-1]
_n2_puffer = io.StringIO()
_n2_haken = logging.StreamHandler(_n2_puffer)
_sec.seclog.addHandler(_n2_haken)
_n2_erg = {}
try:
    _n2_c = TestClient(_n2_app, client=("203.0.113.5", 1))
    for _n2_name, _n2_pfad in (("geraten", "/auth/register?invite=geraten-123"),
                               ("echt", f"/auth/register?invite={_n2_tok}"),
                               ("ohne", "/auth/register")):
        _n2_a0 = len(_n2_a.store._all("SELECT id FROM audit WHERE event='token_invalid'"))
        _n2_l0 = len([z for z in _n2_puffer.getvalue().splitlines()
                      if z.startswith(_sec.LOG_PRUEFUNG) and "token_invite" in z])
        _n2_st = _n2_c.get(_n2_pfad).status_code
        _n2_erg[_n2_name] = (
            _n2_st,
            len(_n2_a.store._all("SELECT id FROM audit WHERE event='token_invalid'")) - _n2_a0,
            len([z for z in _n2_puffer.getvalue().splitlines()
                 if z.startswith(_sec.LOG_PRUEFUNG) and "token_invite" in z]) - _n2_l0)
finally:
    _sec.seclog.removeHandler(_n2_haken)
r.check("N-2: GET /auth/register mit erfundenem Einladungs-Token → token_invalid + „failed verification“",
        _n2_erg.get("geraten") == (403, 1, 1), f"{_n2_erg}")
r.check("N-2: … mit gültigem Token und ganz ohne Token dagegen keine Zeile",
        _n2_erg.get("echt") == (200, 0, 0) and _n2_erg.get("ohne") == (403, 0, 0), f"{_n2_erg}")

# ── N-3: die Passkey-ID der Selbstbedienung ist eine ganze Zahl — sonst 400 ──────────────────
# Gefangen wurden nur TypeError/ValueError. `1e400`, `Infinity` und `-Infinity` macht json.loads
# zu float('inf'), `int()` wirft OverflowError → HTTP 500. `true` las `int()` als Passkey 1 und
# löschte ihn, `1.9` als Passkey 1.
# (Mutationsprobe: in `passkey_delete` wieder `int(b.get("id"))` mit TypeError/ValueError → rot.)
if _ilu.find_spec("webauthn") is not None:
    _n3_a, _n3_app = _app(csrf_enabled=False, passkey_enabled=True, rp_id="localhost",
                          origin="http://localhost")
    _n3_anna = _n3_a.create_user("anna", password="Geheim12345!-lang")
    _n3_ereig = []
    _n3_a.on_security_event = lambda e, k, d: _n3_ereig.append(e)
    _n3_a.store.add_webauthn(_n3_anna, b"cred-n3", b"pk", 0, [], "Laptop")
    _n3_pk = _n3_a.store.list_webauthn(_n3_anna)[0]["id"]
    _n3_c = TestClient(_n3_app, client=("203.0.113.70", 1), raise_server_exceptions=False)
    _n3_c.cookies.set(_n3_a.cfg.session_cookie,
                      _n3_a.store.create_session(_n3_anna, 3600, True, "password"))
    _n3_status = {}
    for _n3_body in ('{"id": 1e400}', '{"id": Infinity}', '{"id": -Infinity}', '{"id": NaN}',
                     '{"id": true}', f'{{"id": {_n3_pk}.9}}', '{"id": "¹"}', '{"id": " 1"}',
                     '{"id": 99999999999999999999999999}'):
        _n3_status[_n3_body] = _n3_c.post("/auth/passkey/delete", content=_n3_body,
                                          headers={"content-type": "application/json"}).status_code
    r.check("N-3: id aus 1e400/Infinity/true/Kommazahl/Hochzahl → 400, nichts gelöscht, kein Ereignis",
            all(s in (400, 404) for s in _n3_status.values())
            and all(_n3_status[b] == 400 for b in list(_n3_status)[:8])
            and len(_n3_a.store.list_webauthn(_n3_anna)) == 1 and _n3_ereig == [],
            f"{_n3_status}, übrig {len(_n3_a.store.list_webauthn(_n3_anna))}, Hook {_n3_ereig}")
    _n3_ok = _n3_c.post("/auth/passkey/delete", json={"id": str(_n3_pk)})
    r.check("N-3: … eine ganze Zahl (auch als Ziffernfolge) löscht wie bisher",
            _n3_ok.status_code == 200 and not _n3_a.store.list_webauthn(_n3_anna)
            and _n3_ereig == ["passkey_removed"], f"HTTP {_n3_ok.status_code}, Hook {_n3_ereig}")

# ── N-8: der Löschweg-Wächter sieht auch Alias, getattr und rohes SQL ──────────────────────
# `_ist_store` erkannte nur die wörtlichen Formen `auth.store.x`, `self.store.x`, `store.x`.
# `st = self.store; st.delete_user(uid)` oder ein `DELETE FROM users` am Store vorbei blieben
# grün — genau der „nächste neue Weg", gegen den der Wächter stehen soll. Jetzt umgekehrt: Ein
# Aufruf von `delete_user` gilt als Store-Aufruf, solange sein Empfänger nicht nachweislich der
# Manager ist (`auth`, `self` in TinySesam), und rohes SQL, das Konten oder Passkeys löscht
# (auch mit einem Tabellennamen aus einer Variable), steht nur in den Store-Bausteinen.
# Grenze, die der Wächter nicht sieht: ein Methodenname, der erst zur Laufzeit entsteht, und
# SQL, dessen Schlüsselwort erst zur Laufzeit aus Bruchstücken entsteht (`"DEL" + "ETE FROM …"`).
# (Mutationsproben: die Empfänger-Prüfung wieder auf `_ist_store` stellen → rot beim Alias;
#  `_sql_ausserhalb` leer zurückgeben → rot beim SQL-Selbsttest.)
#
# S-4 (Schlussrunde): Die erste Fassung suchte nach `DELETE FROM` direkt den Tabellennamen oder
# das String-Ende — das String-Ende passt nur beim Konstantenteil eines f-Strings. `'DELETE FROM
# %s' % t`, `'DELETE FROM {}'.format('users')` und `DELETE FROM main.users` blieben grün.
# Jetzt umgedreht: JEDES löschende SQL (`DELETE FROM`, `DROP TABLE`, `REPLACE INTO`) meldet sich,
# es sei denn, danach steht der Name einer Tabelle, die kein Konto und keinen Passkey trägt
# (aus `store.SCHEMA` gelesen, ohne `users`/`webauthn_cred`). Ein Platzhalter (`%s`, `{}`,
# `{t}`, String-Ende), ein Schema-Präfix (`main.`), Anführungszeichen, ein SQL-Kommentar
# dazwischen und ein unbekannter Name gelten als Konten-Tabelle bzw. als Name aus einer Variable.
# (Mutationsproben: `_sql_loeschziele` wieder nur `users|webauthn_cred|$` erkennen lassen → rot
#  beim Selbsttest „%-Format, .format(), Schema-Präfix“; ein zweiter Löschweg in `manager.py` mit
#  genau diesen drei Schreibweisen → rot beim Wächter, drei Funde.)
from tinysesam import store as _store_s4  # noqa: E402

_SQL_KOMMENTAR = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)
_SQL_BEZEICHNER = r"(?:\"[^\"]*\"|`[^`]*`|\[[^\]]*\]|\w+)"
_SQL_LOESCHT = re.compile(
    r"\b(?:DELETE\s+FROM|DROP\s+TABLE(?:\s+IF\s+EXISTS)?|(?:INSERT\s+OR\s+)?REPLACE\s+INTO)\s*"
    rf"(?P<ziel>(?:{_SQL_BEZEICHNER}\s*\.\s*)?{_SQL_BEZEICHNER})?", re.IGNORECASE)
_SQL_HARMLOS = frozenset(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _store_s4.SCHEMA)) - {
    "users", "webauthn_cred"}


def _sql_loeschziele(text: str) -> list:
    """Die Tabellen, aus denen `text` löscht und die NICHT bekannt harmlos sind: `users`,
    `webauthn_cred`, oder `""` für einen Namen, der erst zur Laufzeit feststeht (Platzhalter,
    unbekannter Name)."""
    aus = []
    for treffer in _SQL_LOESCHT.finditer(_SQL_KOMMENTAR.sub(" ", text)):
        ziel = treffer.group("ziel") or ""
        name = re.split(r"\s*\.\s*", ziel)[-1].strip("\"`[]").lower() if ziel else ""
        if name in _SQL_HARMLOS:
            continue
        aus.append(name if name in ("users", "webauthn_cred") else "")
    return aus


def _ist_manager(knoten, klasse) -> bool:
    """`auth.x`, `self.auth.x` und in TinySesam `self.x` — der Manager, nicht der Store."""
    return ((isinstance(knoten, _ast.Name) and knoten.id == "auth")
            or (isinstance(knoten, _ast.Attribute) and knoten.attr == "auth")
            or (isinstance(knoten, _ast.Name) and knoten.id == "self" and klasse == "TinySesam"))


def _getattr_ausserhalb(methode, erlaubt, quellen=None) -> list:
    """`getattr(x, "<methode>")` ausserhalb von `erlaubt` — der Umweg um jede Empfänger-Prüfung."""
    funde = []
    for name, text in (quellen if quellen is not None else _quelltexte()):
        for pfad, knoten, k, f in _knoten_mit_ort(name, text):
            if (isinstance(knoten, _ast.Call) and isinstance(knoten.func, _ast.Name)
                    and knoten.func.id == "getattr" and len(knoten.args) >= 2
                    and isinstance(knoten.args[1], _ast.Constant) and knoten.args[1].value == methode
                    and (k, f) not in erlaubt):
                funde.append(f"{pfad}:{knoten.lineno} ({k}.{f})")
    return funde


def _sql_ausserhalb(erlaubt: dict, quellen=None) -> list:
    """Rohes SQL, das Konten/Passkeys löschen kann (`_sql_loeschziele`: jede löschende
    Anweisung, deren Tabelle nicht bekannt harmlos ist), ausserhalb der erlaubten Stellen.
    `erlaubt` ordnet der Tabelle (`""` = Name aus einer Variable) die Paare (Klasse, Funktion)
    zu. Docstrings zählen nicht."""
    funde = []
    for name, text in (quellen if quellen is not None else _quelltexte()):
        for pfad, knoten, k, f in _knoten_mit_ort(name, text):
            if not (isinstance(knoten, _ast.Constant) and isinstance(knoten.value, str)):
                continue
            if getattr(knoten, "_ist_docstring", False):
                continue
            for tabelle in _sql_loeschziele(knoten.value):
                if (k, f) not in erlaubt.get(tabelle, set()):
                    funde.append(f"{pfad}:{knoten.lineno} ({k}.{f}) DELETE FROM {tabelle or '{…}'}")
    return funde


def _quelltexte():
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((ROOT / "tinysesam").glob("*.py"))]


def _knoten_mit_ort(name, text):
    """Jeder AST-Knoten mit (Datei, Knoten, innerste Klasse, innerste Funktion); Docstrings markiert."""
    baum = _ast.parse(text)
    for traeger in _ast.walk(baum):
        if isinstance(traeger, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            koerper = traeger.body
            if (koerper and isinstance(koerper[0], _ast.Expr)
                    and isinstance(koerper[0].value, _ast.Constant)
                    and isinstance(koerper[0].value.value, str)):
                koerper[0].value._ist_docstring = True
    aus = []

    def gehe(knoten, klasse=None, funktion=None):
        for kind in _ast.iter_child_nodes(knoten):
            k, f = klasse, funktion
            if isinstance(kind, _ast.ClassDef):
                k = kind.name
            elif isinstance(kind, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                f = kind.name
            aus.append((name, kind, k, f))
            gehe(kind, k, f)
    gehe(baum)
    return aus


def _nicht_manager(knoten, klasse) -> bool:
    return not _ist_manager(knoten, klasse)


_N8_ERLAUBT_SQL = {"users": {("Store", "delete_user")},
                   "webauthn_cred": {("Store", "delete_user"), ("Store", "delete_webauthn")},
                   "": {("Store", "delete_user")}}
_N8_PROBEN = {
    "Alias": "class TinySesam:\n    def weg(self, uid):\n        st = self.store\n        st.delete_user(uid)\n",
    "Attribut": "class Hilfe:\n    def weg(self, uid):\n        self._s.delete_user(uid)\n",
    "getattr": "def weg(s, uid):\n    getattr(s, 'delete_user')(uid)\n",
    "SQL": "class TinySesam:\n    def weg(self, uid):\n        self.store._exec('DELETE FROM users WHERE id=?', (uid,))\n",
    "SQL-Passkey": "def weg(db):\n    db.execute(\"DELETE  FROM webauthn_cred WHERE id=1\")\n",
    "SQL-Variable": "def weg(db, t):\n    db.execute(f'DELETE FROM {t} WHERE id=1')\n",
}
_n8_selbst = {}
for _n8_art, _n8_text in _N8_PROBEN.items():
    _n8_q = [("probe.py", _n8_text)]
    _n8_selbst[_n8_art] = bool(
        _aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")}, _n8_q)
        or _getattr_ausserhalb("delete_user", set(), _n8_q)
        or _sql_ausserhalb(_N8_ERLAUBT_SQL, _n8_q))
_n8_harmlos = [("probe.py", "def route(auth, uid):\n    '''DELETE FROM users steht nur im Docstring'''\n"
                            "    auth.delete_user(uid)\n")]
r.check("N-8 (Wächter-Selbsttest): Alias, fremdes Attribut, getattr und rohes SQL schlagen an",
        all(_n8_selbst.values()), f"{_n8_selbst}")
r.check("N-8 (Wächter-Selbsttest): … der Manager-Aufruf und ein Docstring nicht",
        not (_aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")}, _n8_harmlos)
             or _sql_ausserhalb(_N8_ERLAUBT_SQL, _n8_harmlos)))

# S-4: die Schreibweisen, an denen die erste Fassung vorbeisah — jede allein gegen die SQL-Prüfung
# (die Aufruf-Prüfungen sähen `_exec`/`execute` ohnehin nicht). Dazu Gegenproben: löschendes SQL
# auf einer harmlosen Tabelle, auch mit Schema-Präfix, bleibt still — sonst meldet der Wächter
# jede Sitzungsbereinigung, und am Ende liest ihn niemand mehr.
_S4_PROBEN = {
    "%-Format": "class TinySesam:\n    def w(self, t, uid):\n        self.store._exec('DELETE FROM %s WHERE id=?' % t, (uid,))\n",
    ".format()": "class TinySesam:\n    def w(self, uid):\n        self.store._exec('DELETE FROM {} WHERE id=?'.format('users'), (uid,))\n",
    "Schema-Präfix": "class TinySesam:\n    def w(self, uid):\n        self.store._exec('DELETE FROM main.users WHERE id=?', (uid,))\n",
    "Schema-Präfix Passkey": "def w(db):\n    db.execute('DELETE FROM main.webauthn_cred WHERE id=1')\n",
    "Präfix in Anführungszeichen": "def w(db):\n    db.execute('DELETE FROM \"main\".\"users\" WHERE id=1')\n",
    "Kommentar dazwischen": "def w(db):\n    db.execute('DELETE /* x */ FROM users WHERE id=1')\n",
    "Verkettung": "def w(db, t):\n    db.execute('DELETE FROM ' + t + ' WHERE id=1')\n",
    "DROP TABLE": "def w(db):\n    db.execute('DROP TABLE IF EXISTS users')\n",
    "REPLACE INTO": "def w(db):\n    db.execute('INSERT OR REPLACE INTO users(id, username) VALUES (1, ?)', ('x',))\n",
}
_s4_selbst = {art: bool(_sql_ausserhalb(_N8_ERLAUBT_SQL, [("probe.py", text)]))
              for art, text in _S4_PROBEN.items()}
r.check("S-4 (Wächter-Selbsttest): %-Format, .format(), Schema-Präfix, Kommentar, Verkettung, "
        "DROP TABLE und REPLACE INTO schlagen an",
        all(_s4_selbst.values()), f"{_s4_selbst}")
_s4_harmlos = [("probe.py", "def w(db):\n    db.execute('DELETE FROM session WHERE user_id=?', (1,))\n"
                            "    db.execute('DELETE FROM main.login_attempt WHERE ts < 1')\n"
                            "    db.execute('DELETE FROM \"magic_token\" WHERE used_at IS NOT NULL')\n")]
r.check("S-4 (Wächter-Selbsttest): … löschendes SQL auf Sitzungen, Versuchen und Token nicht",
        not _sql_ausserhalb(_N8_ERLAUBT_SQL, _s4_harmlos) and len(_SQL_HARMLOS) >= 10,
        f"{_sql_ausserhalb(_N8_ERLAUBT_SQL, _s4_harmlos)}, harmlos: {sorted(_SQL_HARMLOS)}")
_n8_funde = (_aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")})
             + _aufrufe_ausserhalb("delete_webauthn", lambda k, c: True, {("TinySesam", "remove_passkey")})
             + _getattr_ausserhalb("delete_user", set()) + _getattr_ausserhalb("delete_webauthn", set())
             + _sql_ausserhalb(_N8_ERLAUBT_SQL))
r.check("N-8 (Wächter): Konten und Passkeys löschen nur die Bausteine — auch nicht per Alias oder SQL",
        not _n8_funde, f"{_n8_funde}")

sys.exit(r.done())
