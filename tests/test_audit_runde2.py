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
    auth.oidc.userinfo = lambda at: dict(nutzerinfo or {})
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
r.check("und die unbestätigte Adresse landet gar nicht erst im Konto",
        konto is not None and not konto["email"],
        f"gespeichert: {konto['email'] if konto else '—'} — sie ginge als Remote-Email weiter")
r.check("die Instanz hat danach immer noch keinen Admin", not auth_f.admin_exists(),
        "irgendein Weg hat doch befördert")

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
        chefin is not None and chefin["email"] == "chef@example.com",
        f"gespeichert: {chefin['email'] if chefin else '—'}")

# Bestandskonto: Die Adresse steht schon in der Datenbank (vor dem Fix angelegt, oder
# `oidc_require_verified_email=False`). Auch dann darf ein Login ohne Beleg nicht befördern —
# sonst hinge der Schutz allein am Nicht-Übernehmen der Adresse.
auth_b3, app_b3 = _oidc_app({"sub": "alt-1", "preferred_username": "altkonto",
                             "email": "chef@example.com"},   # Claim fehlt ganz
                            admin_identifiers=["chef@example.com"],
                            oidc_require_verified_email=False)
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


# Der Beleg gehört zu SEINER Adresse — nicht zu der aus dem anderen Dokument.
# Der Callback legt userinfo-Dokument und ID-Token zusammen (`{**nutzerinfo, **claims}`), und
# beim Mischen gewann bis hierher die Adresse aus dem ID-Token, der Beleg aber konnte aus dem
# userinfo-Dokument stammen: `email_verified=true` für eine ANDERE Adresse hätte die ungeprüfte
# mit durchgetragen. OIDC Core 5.1 meint mit `email_verified` immer die `email` DERSELBEN Antwort.
auth_m, app_m = _oidc_app({"sub": "misch-1", "preferred_username": "mischer",
                           "email": "chef@example.com"},              # ID-Token: ohne Beleg
                          nutzerinfo={"email": "mischer@fremd.example",
                                      "email_verified": True},        # Beleg gehört HIERHIN
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_m)
mischer = auth_m.store.get_user_by_name("mischer")
r.check("ein Beleg aus dem userinfo-Dokument trägt nicht die Adresse aus dem ID-Token",
        mischer is not None and not mischer["is_admin"],
        "Admin — der fremde email_verified wurde auf die ungeprüfte Adresse gemünzt")
r.check("und diese Adresse landet auch nicht im Konto",
        mischer is not None and not mischer["email"],
        f"gespeichert: {mischer['email'] if mischer else '—'}")

# Gegenprobe: Liefert der IdP die Adresse NUR im userinfo-Dokument (verbreiteter Aufbau),
# muss der dortige Beleg ganz normal zählen — sonst wäre der Schutz eine Sperre für alle.
auth_n, app_n = _oidc_app({"sub": "nur-ui-1", "preferred_username": "nurui"},
                          nutzerinfo={"email": "chef@example.com", "email_verified": True},
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_n)
nurui = auth_n.store.get_user_by_name("nurui")
r.check("eine bestätigte Adresse aus dem userinfo-Dokument zählt weiterhin",
        nurui is not None and nurui["is_admin"] == 1 and nurui["email"] == "chef@example.com",
        f"Konto: {dict(nurui) if nurui else None}")


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


OIDC_AN = dict(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="c", oidc_client_secret="s")
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

# Kein `'${esc(...)}'` mehr: ein JS-String, den ein HTML-escapter Wert füllt, ist ausbrechbar.
ausbrechbar = re.findall(r"onclick=\"[^\"]*'\$\{esc\([^\"]*\"", panel_js)
r.check("kein JS-String-Argument mehr, das nur HTML-escaped ist", not ausbrechbar,
        f"{ausbrechbar[:2]} — dort bricht ein Apostroph aus")

r.check("Daten in onclick laufen über jsarg() (JSON.stringify + Attribut-Escaping)",
        "const jsarg=" in panel_js and panel_js.count("${jsarg(") >= 4,
        f"{panel_js.count('${jsarg(')} Verwendungen")

# Die Wirkung messen, nicht im Quelltext raten.
#
# Der Kern ist prüfbar ohne JS-Laufzeit: `jsarg` = JSON-Literal + HTML-Escaping. Ein Wert, der
# so behandelt wird, darf im erzeugten Attribut KEIN rohes Anführungszeichen mehr enthalten —
# sonst schliesst er den JS-String, sobald der Browser das Attribut dekodiert hat.
ZEICHEN = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _esc(w):
    return "".join(ZEICHEN.get(z, z) for z in str(w))


def _jsarg(w):
    import json as _j
    return _esc(_j.dumps(str(w)))


angriff = "bob');alert(document.cookie);//"
attribut = f'onclick="keys(1,{_jsarg(angriff)})"'
r.check("ein präparierter Benutzername lässt kein rohes Anführungszeichen im Attribut",
        "'" not in attribut.split("keys(1,")[1] and '"' not in attribut.split("keys(1,")[1][:-2],
        f"{attribut}")
# Und nach der Attribut-Dekodierung durch den Browser muss ein gültiges JS-Literal dastehen,
# nicht ein geschlossener String plus Code.
import html as _html  # noqa: E402

dekodiert = _html.unescape(attribut.split("keys(1,")[1].rsplit(")", 1)[0])
r.check("nach der HTML-Dekodierung steht ein einzelnes JS-String-Literal da",
        dekodiert.startswith('"') and dekodiert.endswith('"')
        and dekodiert.count('"') == 2 + dekodiert.count('\\"'),
        f"{dekodiert!r} — hier bricht der String auf")

# Wenn node da ist, dasselbe gegen die ECHTEN Helfer aus dem Panel — die stärkere Messung.
import shutil as _sh2  # noqa: E402

node = _sh2.which("node")
if node:
    import json as _json2

    defs = re.search(r"const esc=.*?const jsarg=v=>esc\(JSON\.stringify\(v\?\?\"\"\)\);",
                     panel_js, re.S)
    r.check("die JS-Helfer sind im Panel auffindbar", defs is not None, "esc/jsarg nicht gefunden")
    if defs:
        probe = defs.group(0) + (
            f"\nprocess.stdout.write(`<button onclick=\"keys(1,${{jsarg({_json2.dumps(angriff)})}})\">x</button>`);")
        aus = subprocess.run([node, "-e", probe], capture_output=True, text=True).stdout
        r.check("auch das echte Panel-JS bricht nicht aus dem onclick aus",
                "');alert" not in aus and "&#39;" in aus, f"erzeugt: {aus[:110]}")
        r.check("und der Nachbau oben stimmt mit dem echten JS überein",
                _jsarg(angriff) in aus,
                f"Nachbau: {_jsarg(angriff)!r} — dann misst die Prüfung ohne node etwas anderes")

sys.exit(r.done())
