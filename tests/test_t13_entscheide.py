"""Die sechs PO-Entscheidungen zu den offenen T-13-Punkten (2026-09-24), jede am Verhalten gemessen.

Einstellbar (Vorgabe = die strenge Wahl, im Panel änderbar):
  B2-4  Passwort-Mindestlänge 15, wenn das Passwort allein anmelden kann (NIST SP 800-63B)
  B2-6  Anmeldung gesperrt nach N Fehlversuchen IN FOLGE (Vorgabe 100), zurück erst mit Erfolg/Reset
  B2-8  PIN als Erstfaktor bleibt erlaubt — ausdrücklich, mit eigener Versuchsgrenze neben den Sperren

Fest verankert:
  F-27  E-Mail-Kollision beim OIDC-Login → saubere Abweisung, keine Übernahme, kein 500
  H-3   Eine IdP-Adresse ohne Beleg wird nicht verwendet (kein Konto-Feld, kein Remote-Email, kein Name)
  H-5   Ein vom IdP vergebenes Admin-Flag geht wieder, wenn der IdP die Gruppe nicht mehr liefert
"""
from __future__ import annotations

import io
import os
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import Depends, FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("T-13-Entscheidungen (B2-4, B2-6, B2-8, F-27, H-3, H-5)")
IDP = "https://idp.example.invalid"


def _app(**cfg):
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── B2-4: Mindestlänge je nach Faktor-Lage ────────────────────────────────────────────────
VIERZEHN, FUENFZEHN, ELF = "Kiefer-Spur-47", "Kiefer-Spur-478", "Kiefer-Spur"
auth, app = _app()
r.check("B2-4: Vorgabe (keine Kette, das Passwort meldet allein an): 14 Zeichen zu kurz",
        "min. 15" in (auth.passwort_mangel(VIERZEHN) or ""), str(auth.passwort_mangel(VIERZEHN)))
r.check("… 15 Zeichen gehen durch", auth.passwort_mangel(FUENFZEHN) is None,
        str(auth.passwort_mangel(FUENFZEHN)))
with TestClient(_app(allow_signup=True)[1]) as c:
    antwort = c.post("/auth/register", data={"username": "neuling", "password": VIERZEHN})
r.check("… und die Registrierung hält sich daran", antwort.status_code == 400 and "min. 15" in antwort.text,
        f"HTTP {antwort.status_code}")
# Eine Kette mit zweitem Faktor schützt das Passwort nur, wenn niemand ihn selbst einrichten darf:
# Bei `mfa_enrollment="first_login"` (Vorgabe) bindet, wer nur das Erstpasswort kennt, beim
# ersten Login seinen eigenen Authenticator — das Passwort meldet dann allein an (Angriff auf B2-4).
for kette, einschreiben, erwartet in ((["password", "totp"], "first_login", "min. 15"),
                                      (["password", "totp"], "grace", "min. 15"),
                                      (["password", "totp"], "strict", None),
                                      (["pin", "password"], "strict", None),
                                      (["password"], "strict", "min. 15")):
    a_k, _ = _app(login_chain=kette, pin_enabled="pin" in kette, mfa_enrollment=einschreiben)
    befund = a_k.passwort_mangel(ELF)
    r.check(f"B2-4: Kette {kette}, Einrichtung {einschreiben}: 11 Zeichen "
            f"{'gehen durch' if erwartet is None else 'zu kurz'}",
            (befund is None) if erwartet is None else (erwartet in (befund or "")), str(befund))
auth.set_security("password_min_length_single_factor", 8)
r.check("B2-4 einstellbar: auf 8 gestellt, gilt wieder die Grundlänge",
        auth.passwort_mangel(ELF) is None, str(auth.passwort_mangel(ELF)))
try:
    auth.set_security("password_min_length_single_factor", 7)
    _unter = False
except ConfigError:
    _unter = True
r.check("… aber nie unter 8 (die Grenze der Passwortregel)", _unter)
# (Mutationsprobe: in `_passwort_mindestlaenge` immer `basis` zurückgeben → die ersten drei rot;
#  `_passwort_allein_moeglich` immer True → die beiden Ketten mit zweitem Faktor rot.)

# ── B2-6: Fehlversuche in Folge, ohne Zeitfenster ────────────────────────────────────────
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
PW = "Serien-Passwort-2026"
uid = auth.create_user("serie", password=PW, email="serie@example.com")
c = TestClient(app)


def _login(client, name, pw):
    return client.post("/auth/login", data={"username": name, "password": pw}, follow_redirects=False)


for _ in range(10):
    _login(c, "serie", "falsch-falsch-falsch")
gesperrt = _login(c, "serie", PW)
r.check("B2-6: nach 10 Fehlversuchen in Folge sperrt die Anmeldung — auch mit dem richtigen Passwort",
        gesperrt.status_code == 429 and "in Folge" in gesperrt.text, f"HTTP {gesperrt.status_code}")
r.check("… die Sperre steht genau einmal im Audit-Log",
        sum(1 for z in auth.store.recent_audit(200) if z["event"] == "lockout_serie") == 1)
for _ in range(10):
    _login(c, "gibt-es-nicht", "falsch-falsch-falsch")
fremd = _login(c, "gibt-es-nicht", "falsch-falsch-falsch")
r.check("… ein unbekannter Name bekommt dieselbe Antwort (kein Orakel für vorhandene Konten)",
        fremd.status_code == 429 and "in Folge" in fremd.text, f"HTTP {fremd.status_code}")

# Gealtert, sonst prüfte das nur die 90 Tage und nicht die Grenze (so gemessen: die Mutation
# „gc räumt auch ausgelöste“ blieb grün, solange die Serie frisch war).
auth.store._exec("UPDATE fehlserie SET zuletzt = zuletzt - 91 * 86400 WHERE topf='serie'")
auth.gc()
r.check("B2-6: gc() räumt eine ausgelöste Serie nicht, auch nach 90 Tagen (sie läuft nicht ab)",
        auth.store.fehlserie("serie") == 10, str(auth.store.fehlserie("serie")))
auth.store.fehlserie_erhoehen("alt-und-halb")
auth.store._exec("UPDATE fehlserie SET zuletzt = zuletzt - 91 * 86400 WHERE topf='alt-und-halb'")
auth.gc()
r.check("… wohl aber eine nicht ausgelöste nach 90 Tagen Ruhe", auth.store.fehlserie("alt-und-halb") == 0)

auth.sperre_aufheben(uid, methoden=("password",))           # der Weg des Selbstbedienungs-Resets
r.check("B2-6: ein Reset beendet die Serie (neu binden)", _login(c, "serie", PW).status_code == 303,
        "nach dem Reset weiter gesperrt")

uid2 = auth.create_user("wechsel", password=PW)
for _ in range(9):
    _login(TestClient(app), "wechsel", "falsch-falsch-falsch")
_login(TestClient(app), "wechsel", PW)                        # erfolgreicher Zugang
for _ in range(9):
    _login(TestClient(app), "wechsel", "falsch-falsch-falsch")
r.check("B2-6: ein erfolgreicher Zugang setzt die Serie zurück (9 + Erfolg + 9 sperrt nicht)",
        _login(TestClient(app), "wechsel", PW).status_code == 303, str(auth.store.fehlserie("wechsel")))

auth.record_login("wechsel", "198.51.100.1", False, "password_change")
r.check("B2-6: ein Fehlgriff, der keine Anmeldung ist (Passwortwechsel), zählt nicht",
        auth.store.fehlserie("wechsel") == 0, str(auth.store.fehlserie("wechsel")))

for _ in range(10):
    _login(TestClient(app), "wechsel", "falsch-falsch-falsch")
admin_id = auth.create_user("chefin", password=PW, is_admin=True)
ca = TestClient(app)
_login(ca, "chefin", PW)
neu = ca.post(f"/auth/admin/api/users/{uid2}/password", json={"password": "Ganz-Neues-Passwort-1"})
r.check("B2-6: der Passwort-Reset im Panel beendet die Serie",
        neu.status_code == 200 and _login(TestClient(app), "wechsel", "Ganz-Neues-Passwort-1").status_code == 303,
        f"HTTP {neu.status_code}, Serie {auth.store.fehlserie('wechsel')}")

for _ in range(10):
    _login(TestClient(app), "wechsel", "falsch-falsch-falsch")
from tinysesam.__main__ import main as _cli  # noqa: E402
# Das CLI endet über `sys.exit` — ungefangen beendete das diesen Test mit Exit 0, mitten im Lauf
# und grün (Skip ist kein Grün).
_code = 0
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        _cli(["unlock", "--db", auth.cfg.db_path, "wechsel"])
    except SystemExit as e:
        _code = e.code or 0
r.check("B2-6: `tinysesam unlock` beendet die Serie", _code == 0 and auth.store.fehlserie("wechsel") == 0,
        f"exit {_code}, Serie {auth.store.fehlserie('wechsel')}")

for wert, gilt in ((9, False), (10, True), (100000, True), (100001, False)):
    try:
        auth.set_security("account_max_consecutive_failures", wert)
        ok_ = True
    except ConfigError:
        ok_ = False
    r.check(f"B2-6 einstellbar: {wert} {'erlaubt' if gilt else 'abgewiesen'}", ok_ is gilt)
# (Mutationsproben: die Serien-Prüfung in `versuch_beginnen` streichen → erste Prüfung rot;
#  `fehlserie_loeschen` in `sperre_aufheben` streichen → Reset/Panel rot; in `gc_fehlserien` die
#  Bedingung `anzahl < ?` streichen → „läuft nicht ab" rot.)

# Befunde aus dem Angriff auf B2-6 — je einer ein eigener Test.
auth, app = _app()
for k, v in (("max_login_attempts", 1000), ("rate_limit_max", 100000),
             ("account_max_consecutive_failures", 10)):
    auth.set_security(k, v)
uid_a = auth.create_user("atom", password=PW)
for _ in range(9):
    auth.record_login("atom", "198.51.100.2", False, "password",
                      versuch=auth.versuch_beginnen("atom", "198.51.100.2", "password"))
offen = [auth.versuch_beginnen("atom", f"198.51.100.{10 + i}", "password") for i in range(5)]
r.check("B2-6 atomar: an der Grenze kommt genau EIN laufender Versuch durch, nicht jeder",
        sum(1 for v in offen if v is not None) == 1, str(offen))
auth.record_login("atom", "198.51.100.10", True, "password", versuch=next(v for v in offen if v))
r.check("… und ein richtiger Versuch nimmt seine Vorbuchung zurück, räumt aber nicht die Serie",
        auth.store.fehlserie("atom") == 9, str(auth.store.fehlserie("atom")))
v = auth.versuch_beginnen("atom", "198.51.100.3", "password")
auth._versuch_zuruecknehmen(v)
r.check("B2-6: ein zurückgenommener Versuch (Verzeichnis-Ausfall) zählt nicht",
        auth.store.fehlserie("atom") == 9, str(auth.store.fehlserie("atom")))

uid_t = auth.create_user("zweit", password=PW)
for _ in range(10):
    auth.record_login("zweit", "198.51.100.4", False, "totp",
                      versuch=auth.versuch_beginnen("zweit", "198.51.100.4", "totp"))
auth.sperre_aufheben(uid_t, methoden=("password",))            # Selbstbedienungs-Reset
r.check("B2-6 + R4-13: der Selbstbedienungs-Reset räumt TOTP-Fehlgriffe der Serie NICHT",
        auth.store.fehlserie("zweit") == 10 and auth.versuch_beginnen("zweit", "198.51.100.5", "password") is None,
        str(auth.store.fehlserie("zweit")))
# Umgekehrt die ERSTEN Faktoren: Falsche PINs kann jeder schicken, auch ohne ein Geheimnis zu kennen.
# Blieben sie nach dem Reset stehen, hülfe der Reset nicht mehr, zu dem die Meldung rät (R2-2).
uid_pin = auth.create_user("pinopfer", password=PW)
for _ in range(10):
    auth.record_login("pinopfer", "198.51.100.8", False, "pin",
                      versuch=auth.versuch_beginnen("pinopfer", "198.51.100.8", "pin"))
auth.sperre_aufheben(uid_pin, methoden=("password",))          # Selbstbedienungs-Reset
r.check("B2-6: eine Serie aus falschen PINs (Erstfaktor, von jedem erzeugbar) räumt der Reset",
        auth.store.fehlserie("pinopfer") == 0, str(auth.store.fehlserie("pinopfer")))

chefin_t = auth.create_user("chefin-t", password=PW, is_admin=True)
cpt = TestClient(app)
cpt.post("/auth/login", data={"username": "chefin-t", "password": PW}, follow_redirects=False)
neu_t = cpt.post(f"/auth/admin/api/users/{uid_t}/password", json={"password": "Vom-Betreiber-Gesetzt-1"})
r.check("… der Betreiber räumt sie ganz (Passwort-Reset im Panel, auch den TOTP-Anteil)",
        neu_t.status_code == 200 and auth.store.fehlserie("zweit") == 0, str(auth.store.fehlserie("zweit")))
# Und über den Weg, den die Routen nehmen: ein Nicht-Login-Versuch bucht nichts vor.
v_pc = auth.versuch_beginnen("zweit", "198.51.100.6", "password_change")
auth.record_login("zweit", "198.51.100.6", False, "password_change", versuch=v_pc)
r.check("B2-6: ein Fehlgriff am Passwortwechsel (über versuch_beginnen) bucht keine Serie",
        auth.store.fehlserie("zweit") == 0, str(auth.store.fehlserie("zweit")))

# ── B2-8: PIN als Erstfaktor — ausdrücklich erlaubt, mit eigener Grenze ─────────────────
auth, app = _app(pin_enabled=True)


@app.get("/allgemein")
def _allgemein(user=Depends(auth.require())):
    return {"ok": True}


@app.get("/detail")
def _detail(user=Depends(auth.require(factors=["pin", "password"]))):
    return {"ok": True}


pin_uid = auth.create_user("pinnutzer", password=PW)
auth.set_pin(pin_uid, "4711")
cp = TestClient(app)
seite = cp.get("/auth/login")
r.check("B2-8: die Login-Seite bietet die PIN als Erstfaktor an (pin_login, Vorgabe)",
        "/auth/pin" in seite.text, "kein PIN-Weg auf der Login-Seite")
cp.post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"}, follow_redirects=False)
r.check("… mit der PIN allein kommt man auf die allgemeine Seite",
        cp.get("/allgemein", follow_redirects=False).status_code == 200)
r.check("… die Detailseite verlangt mehr (Kette pin → password je Route)",
        cp.get("/detail", follow_redirects=False).status_code != 200)
_login(cp, "pinnutzer", PW)
r.check("… und öffnet sich nach dem Passwort", cp.get("/detail", follow_redirects=False).status_code == 200)
a_aus, _ = _app(pin_enabled=True, pin_login=False)
r.check("B2-8 einstellbar: pin_login=False nimmt die PIN von der Login-Seite",
        "/auth/pin" not in TestClient(_).get("/auth/login").text)
reihe = list(auth.all_security())
r.check("B2-8: die PIN-Versuche stehen im Panel bei den Sperr-Einstellungen",
        reihe.index("pin_max_attempts") == reihe.index("account_max_consecutive_failures") + 1
        and reihe.index("account_max_consecutive_failures") == reihe.index("account_attempt_factor") + 1,
        str(reihe[:8]))
for _ in range(auth.sec("pin_max_attempts")):
    TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "0000"})
gesperrt = TestClient(app).post("/auth/pin", data={"username": "pinnutzer", "pin": "4711"})
r.check("B2-8: nach pin_max_attempts Fehlgriffen ist der PIN-Weg zu", gesperrt.status_code == 429,
        f"HTTP {gesperrt.status_code}")
r.check("… und die PIN-Fehlgriffe zählen in die Serie (B2-6)", auth.store.fehlserie("pinnutzer") >= 5)


# ── OIDC-Hilfen: Netz-frei, echter Callback ───────────────────────────────────────────────
class _Claims(dict):
    def validate(self, *a, **k):
        pass


def _oidc(claims, **cfg):
    auth, app = _app(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                     oidc_client_secret="geheim", **cfg)
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    _setze(auth, claims)
    from tinysesam.oidc import OIDCClient
    auth.oidc.userinfo = lambda at, erwartetes_sub="": OIDCClient.userinfo_pruefen({}, erwartetes_sub)
    return auth, app


def _setze(auth, claims):
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


def _oidc_login(app):
    c = TestClient(app, raise_server_exceptions=False)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


# ── F-27: E-Mail-Kollision mit einem lokalen Konto ───────────────────────────────────────
a27, app27 = _oidc({"sub": "k-1", "preferred_username": "neu", "email": "lokal@example.com",
                    "email_verified": True})
lokal = a27.create_user("lokal", password=PW, email="lokal@example.com")
antwort = _oidc_login(app27)
r.check("F-27: belegte Adresse eines lokalen Kontos → 409, kein 500", antwort.status_code == 409,
        f"HTTP {antwort.status_code}")
r.check("… kein zweites Konto, keine Verknüpfung, eine Zeile für den Betreiber",
        a27.store.get_user_by_name("neu") is None and not a27.store.get_oidc_user(IDP, "k-1")
        and any(z["event"] == "oidc_ident_taken" for z in a27.store.recent_audit(50)))
a27b, app27b = _oidc({"sub": "k-2", "preferred_username": "neu2", "email": "lokal@example.com",
                      "email_verified": False})
lokal_b = a27b.create_user("lokal", password=PW, email="lokal@example.com")
antwort = _oidc_login(app27b)
neu2 = a27b.store.get_user_by_name("neu2")
r.check("F-27 + H-3: eine UNBELEGTE fremde Adresse kollidiert nicht und übernimmt nichts",
        antwort.status_code == 303 and neu2 is not None and not neu2["email"]
        and a27b.store.get_user(lokal_b)["email"] == "lokal@example.com",
        f"HTTP {antwort.status_code}")

# ── H-3: eine Adresse ohne Beleg wird nicht verwendet ────────────────────────────────────
a3, app3 = _oidc({"sub": "h3-1", "email": "fremd@example.com", "email_verified": False})
_oidc_login(app3)
konten = [dict(u) for u in a3.store.list_users()]
k3 = konten[0] if konten else None
r.check("H-3: ohne Beleg kein Name aus der Adresse, keine Adresse im Konto, kein Remote-Email",
        k3 is not None and k3["username"].startswith("oidc-") and not k3["email"]
        and not a3.forward_response_headers(k3).get("Remote-Email"), str(k3))
a3b, app3b = _oidc({"sub": "h3-2", "email": "belegt@example.com", "email_verified": True})
_oidc_login(app3b)
k3b = a3b.store.get_user_by_name("belegt@example.com")
r.check("… mit Beleg wird sie verwendet (Name, Konto, Remote-Email)",
        k3b is not None and k3b["email"] == "belegt@example.com" and k3b["email_verified"]
        and a3b.forward_response_headers(k3b).get("Remote-Email") == "belegt@example.com")
a3c, app3c = _oidc({"sub": "h3-3", "email": "entra@example.com"}, oidc_email_verified_default=True)
_oidc_login(app3c)
r.check("… ein Provider ohne Claim zählt nur mit der ausdrücklichen Aussage des Betreibers",
        a3c.store.get_user_by_name("entra@example.com") is not None)
a3d, app3d = _oidc({"sub": "h3-4", "email": "nein@example.com", "email_verified": False},
                   oidc_email_verified_default=True)
_oidc_login(app3d)
r.check("… ein ausdrückliches false bleibt false, auch mit dieser Aussage",
        all(not u["email"] for u in a3d.store.list_users()))
a3e, app3e = _oidc({"sub": "h3-5", "preferred_username": "spaet", "email": "spaet@example.com"})
_oidc_login(app3e)
_setze(a3e, {"sub": "h3-5", "preferred_username": "spaet", "email": "spaet@example.com",
             "email_verified": True})
_oidc_login(app3e)
r.check("H-3: liefert der Provider den Beleg nach, kommt die Adresse belegt ins Konto",
        a3e.store.get_user_by_name("spaet")["email"] == "spaet@example.com"
        and a3e.store.get_user_by_name("spaet")["email_verified"])
a3f, app3f = _oidc({"sub": "h3-6", "preferred_username": "spaet2", "email": "vergeben@example.com"})
_oidc_login(app3f)
a3f.create_user("inhaber", password=PW, email="vergeben@example.com")
_setze(a3f, {"sub": "h3-6", "preferred_username": "spaet2", "email": "vergeben@example.com",
             "email_verified": True})
_oidc_login(app3f)
r.check("… es sei denn, sie gehört inzwischen einem anderen Konto (dann bleibt es ohne)",
        not a3f.store.get_user_by_name("spaet2")["email"]
        and any(z["event"] == "oidc_email_taken" for z in a3f.store.recent_audit(50)))
for wunsch, belegt, erwartet in (("opfer@example.com", False, "oidc-"), ("opfer@example.com", True, "opfer@example.com"),
                                 ("opfer\uff20example.com", False, "oidc-"), ("opfer\ufe6bexample.com", False, "oidc-"),
                                 ("anderer@example.com", True, "opfer@example.com"), ("klarname", False, "klarname")):
    a3g, app3g = _oidc({"sub": f"h3-pu-{wunsch}-{belegt}", "preferred_username": wunsch,
                        "email": "opfer@example.com", "email_verified": belegt})
    _oidc_login(app3g)
    namen = [u["username"] for u in a3g.store.list_users()]
    r.check(f"H-3: preferred_username={wunsch!r} bei {'belegter' if belegt else 'unbelegter'} Adresse → {erwartet}…",
            len(namen) == 1 and namen[0].startswith(erwartet), str(namen))
# (Mutationsproben: in oidc.py `belegte_mail = mail` → die erste H-3-Prüfung rot; die Prüfung auf
#  `@` in `preferred_username` streichen → die Fälle mit Adresse als Namen rot.)

# ── H-5: der IdP nimmt, was er gegeben hat ───────────────────────────────────────────────
KARTE = {"admins": "__admin__", "redaktion": "editor"}
a5, app5 = _oidc({"sub": "h5-1", "preferred_username": "idpchef", "groups": ["admins", "redaktion"]},
                 oidc_group_role_map=KARTE)
_oidc_login(app5)
chef = a5.store.get_user_by_name("idpchef")
r.check("H-5: Admin-Gruppe beim IdP → Admin-Flag, vermerkt als „vom IdP“ (2)", chef["is_admin"] == 2,
        str(chef["is_admin"]))
_setze(a5, {"sub": "h5-1", "preferred_username": "idpchef", "groups": ["redaktion"]})
_oidc_login(app5)
chef = a5.store.get_user_by_name("idpchef")
r.check("… liefert der IdP die Gruppe nicht mehr, ist das Flag beim nächsten Login weg",
        not chef["is_admin"] and "editor" in a5.user_roles(chef), str(dict(chef)))
r.check("… mit Zeile im Audit-Log", any(z["event"] == "idp_admin_revoke" for z in a5.store.recent_audit(50)))
hand = a5.create_user("handadmin", password=PW, is_admin=True)
a5.apply_idp_groups(hand, [], KARTE)
r.check("H-5: ein von Hand vergebenes Admin-Flag nimmt der IdP nie", a5.store.get_user(hand)["is_admin"] == 1)
idp_admin = a5.create_user("idpzwei", password=PW)
a5.apply_idp_groups(idp_admin, ["admins"], KARTE)
a5.apply_idp_groups(idp_admin, [], {"redaktion": "editor"})
r.check("… und ein Mapping ohne Admin-Ziel entzieht nichts (es verwaltet kein Admin-Recht)",
        a5.store.get_user(idp_admin)["is_admin"] == 2)
a5.apply_idp_groups(idp_admin, ["cn=admins,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
a5.apply_idp_groups(idp_admin, ["cn=andere,ou=g,dc=x"], {"cn=admins": "__admin__"}, dn=True)
r.check("H-5 gilt auch für LDAP-DNs (derselbe Weg)", not a5.store.get_user(idp_admin)["is_admin"])
# Befund aus dem Angriff auf H-5: Das Panel schickt den Admin-Haken bei jedem Speichern der Rollen
# mit — `set_admin(True)` machte aus der 2 still eine 1, und der Entzug griff nie mehr.
a5p, app5p = _oidc({"sub": "h5-p", "preferred_username": "panelfall", "groups": ["admins"]},
                   oidc_group_role_map=KARTE)
_oidc_login(app5p)
_pf = a5p.store.get_user_by_name("panelfall")
a5p.create_user("chefin", password=PW, is_admin=True)
cpan = TestClient(app5p)
cpan.post("/auth/login", data={"username": "chefin", "password": PW}, follow_redirects=False)
gespeichert = cpan.post(f"/auth/admin/api/users/{_pf['id']}/roles", json={"roles": ["editor"], "is_admin": True})
r.check("H-5: Rollen im Panel speichern lässt ein IdP-Admin-Flag, wie es ist (2)",
        gespeichert.status_code == 200 and a5p.store.get_user(_pf["id"])["is_admin"] == 2,
        f"HTTP {gespeichert.status_code}, is_admin={a5p.store.get_user(_pf['id'])['is_admin']}")
_setze(a5p, {"sub": "h5-p", "preferred_username": "panelfall", "groups": []})
_oidc_login(app5p)
r.check("… und der nächste Login ohne Admin-Gruppe nimmt es", not a5p.store.get_user(_pf["id"])["is_admin"])
_normal = a5p.create_user("normalo", password=PW)
cpan.post(f"/auth/admin/api/users/{_normal}/roles", json={"roles": [], "is_admin": True})
r.check("… ein Haken, den der Betreiber neu setzt, bleibt eine 1 (von Hand)",
        a5p.store.get_user(_normal)["is_admin"] == 1)
# (Mutationsproben: den `elif`-Zweig in apply_idp_groups streichen → „ist das Flag weg" rot;
#  `u["is_admin"] == 2` → `u["is_admin"]` → „von Hand … nie" rot; in admin.py die Bedingung
#  „nur bei echter Änderung" streichen → „lässt ein IdP-Admin-Flag, wie es ist" rot.)

# ── Schema 11, Zwischenstand: `fehlserie` ohne Spalte `art` wird neu angelegt (R2-3) ─────────
_pfad_z = str(Path(tempfile.mkdtemp()) / "zwischen.db")
Store(_pfad_z).db.close()
_roh = sqlite3.connect(_pfad_z)
_roh.execute("DROP TABLE fehlserie")
_roh.execute("CREATE TABLE fehlserie (topf TEXT PRIMARY KEY, anzahl INTEGER NOT NULL, "
             "seit INTEGER NOT NULL, zuletzt INTEGER NOT NULL)")
_roh.commit()
_roh.close()
_z = Store(_pfad_z)
_spalten = {z["name"] for z in _z._all("PRAGMA table_info(fehlserie)")}
r.check("Zwischenstand: eine `fehlserie` ohne `art` wird neu angelegt, statt jede Anmeldung zu brechen",
        "art" in _spalten and _z.fehlserie_erhoehen("x", "password") == 1, str(_spalten))
_z.db.close()

# ── Schema 11: eine Datei von 0.20.x bekommt die Tabelle beim Start ───────────────────────
_pfad = str(Path(tempfile.mkdtemp()) / "alt.db")
Store(_pfad).db.close()
_roh = sqlite3.connect(_pfad)
_roh.execute("DROP TABLE fehlserie")
_roh.execute("PRAGMA user_version = 10")
_roh.commit()
_roh.close()
_neu = Store(_pfad)
_tabellen = {z["name"] for z in _neu._all("SELECT name FROM sqlite_master WHERE type='table'")}
r.check("Schema 10 → 11: `fehlserie` entsteht beim Start, der Stempel zieht nach",
        "fehlserie" in _tabellen and int(_neu.db.execute("PRAGMA user_version").fetchone()[0]) == 11
        and Store.SCHEMA_VERSION == 11)
_neu.db.close()
os.remove(_pfad)

sys.exit(r.done())
