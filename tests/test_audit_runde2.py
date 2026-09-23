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
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None: (
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
# Die Adresse WIRD geführt — sie zu verwerfen war die erste Fassung des Fixes und kostete den
# Kontonamen und `Remote-Email` (dieselbe Person landete in einem anderen Konto der geschützten
# App). Getrennt gemerkt wird nur der Beleg; er ist es, der die Rechte trägt.
r.check("die unbestätigte Adresse bleibt im Konto und geht als Remote-Email weiter",
        konto is not None and konto["email"] == "chef@example.com"
        and auth_f.forward_response_headers(konto)["Remote-Email"] == "chef@example.com",
        f"gespeichert: {konto['email'] if konto else '—'} — ein Gateway verliert die Adresse")
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
    auth.oidc.exchange = lambda code, ru, nonce, t=None: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


NACH = {"sub": "nach-1", "preferred_username": "nachtrag", "email": "nach@example.com"}
auth_s, app_s = _oidc_app(NACH)                      # erster Login: Claim fehlt → unbestätigt
_oidc_login(app_s)
nach = auth_s.store.get_user_by_name("nachtrag")
vorher = bool(nach["email_verified"])
_claims_setzen(auth_s, {**NACH, "email_verified": True})
_oidc_login(app_s)
nachher = bool(auth_s.get_user(nach["id"])["email_verified"])
r.check("liefert der Provider den Beleg nach, zieht der Vermerk am Konto nach",
        not vorher and nachher, f"vorher={vorher} nachher={nachher}")
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
r.check("… und sie steht im Konto als unbestätigt, nicht als belegt",
        mischer is not None and mischer["email"] == "chef@example.com"
        and not mischer["email_verified"],
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
r.check("...das neue Konto heisst anders", auth_k9.store.get_user_by_name("chef@example.com2") is not None,
        "kein Ausweichname — dann wurde entweder abgewiesen oder eine Kennung besetzt")
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
import shutil as _sh2  # noqa: E402

node = _sh2.which("node")
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
_chef_t = auth_t.create_user("chef", password="Geheim12345!", is_admin=True)
_anna_t = auth_t.create_user("anna", password="Geheim12345!", email="anna@example.com")


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
_login_rc.post("/auth/login", data={"username": "anna", "password": "Geheim12345!"})
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
_ch = auth_d.create_user("chef", password="Geheim12345!", is_admin=True)
_adm = auth_d.create_user("admin", password="Geheim12345!", email="Anna.Admin@example.com",
                          is_admin=True)
_bob = auth_d.create_user("bob", password="Geheim12345!")
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
_kchef = auth_k.create_user("chef", password="Geheim12345!", is_admin=True)
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
_echef = auth_e.create_user("chef", password="Geheim12345!", is_admin=True)
_eanna = auth_e.create_user("anna", password="Geheim12345!")
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

sys.exit(r.done())
