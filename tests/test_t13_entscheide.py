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

# ── F-05: Inaktivitäts-Timeout ────────────────────────────────────────────────────────────
auth_i, app_i = _app()


@app_i.get("/drin")
def _drin(user=Depends(auth_i.require())):
    return {"ok": True}


r.check("F-05: Vorgabe 8 h Inaktivität ohne „Angemeldet bleiben“, mit: aus",
        auth_i.store.leerlauf_sek == (8 * 3600, 0), str(auth_i.store.leerlauf_sek))
auth_i.create_user("ruhig", password=PW)
ci = TestClient(app_i)
ci.post("/auth/login", data={"username": "ruhig", "password": PW}, follow_redirects=False)   # ohne remember
r.check("… frisch angemeldet kommt man hinein", ci.get("/drin", follow_redirects=False).status_code == 200)
auth_i.store._exec("UPDATE session SET zuletzt = zuletzt - 8 * 3600 - 5")
r.check("… nach 8 h ohne Anfrage ist die Sitzung weg (nicht nur abgewiesen, gelöscht)",
        ci.get("/drin", follow_redirects=False).status_code != 200
        and auth_i.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0)
ci2 = TestClient(app_i)
ci2.post("/auth/login", data={"username": "ruhig", "password": PW, "remember": "1"}, follow_redirects=False)
auth_i.store._exec("UPDATE session SET zuletzt = zuletzt - 30 * 86400")
r.check("… mit „Angemeldet bleiben“ zählt nur die absolute Laufzeit (Vorgabe)",
        ci2.get("/drin", follow_redirects=False).status_code == 200)
auth_j, app_j = _app(session_idle_minutes_remember=60)


@app_j.get("/drin")
def _drin_j(user=Depends(auth_j.require())):
    return {"ok": True}


auth_j.create_user("ruhig", password=PW)
cj = TestClient(app_j)
cj.post("/auth/login", data={"username": "ruhig", "password": PW, "remember": "1"}, follow_redirects=False)
cj.get("/drin")
_vorher = auth_j.store._one("SELECT zuletzt FROM session")["zuletzt"]
cj.get("/drin")
r.check("F-05: eine zweite Anfrage in derselben Minute schreibt nicht (keine Sperre je Abruf)",
        auth_j.store._one("SELECT zuletzt FROM session")["zuletzt"] == _vorher)
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 61 * 60")
r.check("F-05 einstellbar: auch für „Angemeldet bleiben“ (hier 60 min)",
        cj.get("/drin", follow_redirects=False).status_code != 200)
auth_j.create_user("aktiv", password=PW)
ck = TestClient(app_j)
ck.post("/auth/login", data={"username": "aktiv", "password": PW, "remember": "1"}, follow_redirects=False)
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 50 * 60, created_at = created_at - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='aktiv')")
ck.get("/drin")                                              # Aktivität setzt die Uhr neu
auth_j.store._exec("UPDATE session SET zuletzt = zuletzt - 50 * 60 "
                   "WHERE user_id = (SELECT id FROM users WHERE username='aktiv')")
r.check("F-05: wer aktiv ist, bleibt drin (50 + 50 min, aber nie 60 am Stück)",
        ck.get("/drin", follow_redirects=False).status_code == 200)
# (Mutationsproben: die Leerlauf-Prüfung in `get_session` streichen → „nach 8 h … weg" rot; das
#  Nachschreiben von `zuletzt` streichen → „wer aktiv ist, bleibt drin" rot.)

# ── Grenzen a–e aus dem Integrationsangriff (PO: bauen) ─────────────────────────────────
import re as _re  # noqa: E402
import pyotp  # noqa: E402

# (a) Eine vollständige Anmeldung räumt nur Fehlversuche ab der Anlage des Kontos.
auth_a8, app_a8 = _app()
for _ in range(3):
    auth_a8.record_login("vorher@example.com", "198.51.100.20", False, "password")
auth_a8.store._exec("UPDATE login_attempt SET ts = ts - 3600")
uid_a8 = auth_a8.create_user("neukonto", password=PW, email="vorher@example.com")
_login(TestClient(app_a8), "neukonto", PW)
r.check("Grenze a: Fehlversuche unter der Adresse von VOR der Anlage bleiben nach dem ersten Login stehen",
        auth_a8.store.count_fails(0, username="vorher@example.com") == 3,
        str(auth_a8.store.count_fails(0, username="vorher@example.com")))
auth_a8.record_login("neukonto", "198.51.100.21", False, "password")
_login(TestClient(app_a8), "neukonto", PW)
r.check("… die eigenen (nach der Anlage) räumt er wie bisher",
        auth_a8.store.count_fails(0, username="neukonto") == 0)

# (b) Das Panel unterscheidet die beiden Sperren.
auth_b8, app_b8 = _app()
auth_b8.create_user("panelchef", password=PW, is_admin=True)
wartet = auth_b8.create_user("wartet", password=PW)
betr = auth_b8.create_user("betreiber-gesperrt", password=PW)
auth_b8.store.set_disabled(wartet, True)
auth_b8.store.set_disabled(betr, True, durch_betreiber=True)
cb8 = TestClient(app_b8)
_login(cb8, "panelchef", PW)
liste = {u["username"]: u for u in cb8.get("/auth/admin/api/users").json()}
r.check("Grenze b: das Panel nennt den Grund der Sperre (Bestätigung/App vs. Betreiber)",
        liste["wartet"]["disabled_by"] == "confirmation" and liste["betreiber-gesperrt"]["disabled_by"] == "operator"
        and liste["panelchef"]["disabled_by"] is None, str({k: v["disabled_by"] for k, v in liste.items()}))

# (c) Die Audit-Suchen laufen über einen Index.
_plan = auth_b8.store.db.execute(
    "EXPLAIN QUERY PLAN SELECT id FROM audit WHERE event IN ('signup','signup_taken') "
    "AND lower(username) = lower(?) AND ts BETWEEN ? AND ?", ("x", 1, 2)).fetchall()
r.check("Grenze c: `anlage_grenze` sucht über den Index statt durch das ganze Audit-Log",
        any("idx_audit_name_ts" in str(tuple(z)) for z in _plan), str([tuple(z) for z in _plan]))

# (d) Kette password → totp → pin mit Pflicht-Einrichtung: das Angebot, die übrigen Sitzungen zu
#     beenden, wird eingelöst, sobald die Kette voll ist.
auth_d8, app_d8 = _app(login_chain=["password", "totp", "pin"], pin_enabled=True)
uid_d8 = auth_d8.create_user("kette", password=PW)
auth_d8.set_pin(uid_d8, "4812")
alt_token = auth_d8.store.create_session(uid_d8, 3600, True, "password")   # das verlorene Gerät
cd8 = TestClient(app_d8)
_login(cd8, "kette", PW)
_seite = cd8.post("/auth/totp/setup/start", data={"next": "/"})
_geheim = _re.search(r"secret=([A-Z2-7]+)", _seite.text) or _re.search(r"\b([A-Z2-7]{32})\b", _seite.text)
_bestaetigt = cd8.post("/auth/totp/setup", data={"code": pyotp.TOTP(_geheim.group(1)).now(), "next": "/"}).json()
r.check("Grenze d: die Einschreibung mitten in der Kette meldet die übrigen Sitzungen (other_sessions_after)",
        _bestaetigt.get("ok") and _bestaetigt.get("other_sessions_after") == 1, str(_bestaetigt))
_vermerk = cd8.post("/auth/sessions/revoke-after-login", json={})
r.check("… die Zustimmung wird vermerkt, aber noch nichts beendet",
        _vermerk.status_code == 200 and auth_d8.store.get_session(alt_token) is not None)
cd8.post("/auth/pin", data={"username": "kette", "pin": "4812"}, follow_redirects=False)   # halbe Sitzung: mit Namen
r.check("… und mit dem letzten Faktor (PIN) enden die übrigen Sitzungen",
        auth_d8.store.get_session(alt_token) is None and cd8.get("/auth/me").status_code == 200)
auth_v8, app_v8 = _app()                                      # ohne Kette: Passwort = volle Sitzung
auth_v8.create_user("voll", password=PW)
cvoll = TestClient(app_v8)
_login(cvoll, "voll", PW)
r.check("… eine volle Sitzung kann den Vermerk nicht setzen (dafür gibt es /auth/sessions/revoke)",
        cvoll.post("/auth/sessions/revoke-after-login", json={}).status_code in (400, 401))

# (e) Der Widerruf von API-Keys benachrichtigt den Inhaber.
auth_e8, app_e8 = _app()
ereignisse = []
auth_e8.on_security_event = lambda ereignis, konto, details: ereignisse.append((ereignis, details))
uid_e8 = auth_e8.create_user("keyhalter", password=PW)
k1 = auth_e8.create_api_key(uid_e8, name="ci")
auth_e8.revoke_api_key(k1["id"])
auth_e8.revoke_api_key(k1["id"])                              # zweimal: nur ein Ereignis
auth_e8.create_api_key(uid_e8, name="a")
auth_e8.create_api_key(uid_e8, name="b")
auth_e8._keys_widerrufen(uid_e8, "test")
namen = [e for e, _ in ereignisse]
r.check("Grenze e: ein einzelner Widerruf meldet api_key_revoked (genau einmal)",
        namen.count("api_key_revoked") == 1, str(namen))
r.check("… ein gesammelter meldet api_keys_revoked mit Anzahl",
        ("api_keys_revoked", {"anzahl": 2, "grund": "test"}) in ereignisse, str(ereignisse))
chef_e8 = auth_e8.create_user("chef-e8", password=PW, is_admin=True)
auth_e8.create_api_key(uid_e8, name="c")
ce8 = TestClient(app_e8)
_login(ce8, "chef-e8", PW)
ce8.post(f"/auth/admin/api/users/{uid_e8}/disable", json={"disabled": True})
r.check("… auch beim Sperren im Panel", ("api_keys_revoked", {"anzahl": 1, "grund": "sperre"}) in ereignisse,
        str(ereignisse[-2:]))
# (Mutationsproben: `seit=since` in `sperre_aufheben` streichen → (a) rot; `disabled_by` fest auf
#  None → (b) rot; Index streichen → (c) rot; `_andere_nach_abschluss` leer → (d) rot;
#  `sicherheitsereignis` in `_keys_widerrufen` streichen → (e) rot.)

# ── B1-12 / ASVS 6.3.8: die Registrierung verrät keine Adressen (auch nicht in der Laufzeit) ─
def _reg_app():
    a, app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                  login_identifier="email")
    a.set_mailer(lambda to, betreff, text, html=None: None)
    return a, app


a638, app638 = _reg_app()
a638.create_user("vergeben@example.com", password=PW, email="vergeben@example.com")
_zaehler = {"n": 0}
_orig_exec = a638.store._exec


def _zaehlend(sql, args=()):
    _zaehler["n"] += 1
    return _orig_exec(sql, args)


a638.store._exec = _zaehlend
c638 = TestClient(app638)
_zaehler["n"] = 0
frei = c638.post("/auth/register", data={"email": "frei@example.com", "password": FUENFZEHN + "x"})
_n_frei = _zaehler["n"]
_zaehler["n"] = 0
vergeben = c638.post("/auth/register", data={"email": "vergeben@example.com", "password": FUENFZEHN + "x"})
_n_vergeben = _zaehler["n"]
a638.store._exec = _orig_exec
r.check("ASVS 6.3.8: freie und vergebene Adresse antworten gleich (Status und Seite)",
        frei.status_code == vergeben.status_code == 200
        and _re.sub(r"nonce=\"[^\"]+\"", "", frei.text) == _re.sub(r"nonce=\"[^\"]+\"", "", vergeben.text),
        f"{frei.status_code}/{vergeben.status_code}")
r.check("… und machen dieselbe Arbeit in der Anfrage (gleich viele Schreibzugriffe — kein Laufzeit-Orakel)",
        _n_frei == _n_vergeben, f"frei {_n_frei}, vergeben {_n_vergeben}")
_platz = [u for u in a638.store.list_users() if str(u["username"]).startswith("reserviert-")]
r.check("… der Platzhalter ist gesperrt, trägt keine Adresse und verschwindet mit gc()",
        len(_platz) == 1 and _platz[0]["disabled"] and not _platz[0]["email"])
from tinysesam import konfigpruefung as _kp  # noqa: E402
_, _w638 = _kp.pruefe(TinySesamConfig(db_path=":memory:", base_url="https://app.example", allow_signup=True,
                                      signup_require_email=True))
r.check("… ohne Bestätigung geht das nicht — die Konfigurationsprüfung sagt es (6.3.8)",
        any("6.3.8" in w for w in _w638), str(_w638)[:200])
# (Mutationsprobe: im Vergeben-Zweig wieder nur `hash_password` statt Platzhalter → Schreibzugriffe rot.)

# ── B1-12 / ASVS 6.3.5: Hinweis an den Inhaber, wenn sein Konto gesperrt wird ─────────────
def _hinweis_app(**cfg):
    a, app = _app(**cfg)
    post = []
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff, text)))
    return a, app, post


a635, app635, post635 = _hinweis_app()
a635.create_user("inhaberin", password=PW, email="inhaberin@example.com")
for _ in range(a635.sec("max_login_attempts") + 2):
    _login(TestClient(app635), "inhaberin", "falsch-falsch-falsch")
a635._hinweis_ausgang.abwarten()
r.check("ASVS 6.3.5: bei konfiguriertem Versand bekommt die Inhaberin einen Hinweis (Vorgabe an, opt-out)",
        len(post635) == 1 and post635[0][0] == "inhaberin@example.com", str(post635))
r.check("… genau einen je Sperrfenster, nicht einen je abgewiesenem Versuch",
        len(post635) == 1 and any(z["event"] == "sperrhinweis" for z in a635.store.recent_audit(50)))
for _ in range(a635.sec("max_login_attempts") + 2):
    _login(TestClient(app635), "niemand", "falsch-falsch-falsch")
a635._hinweis_ausgang.abwarten()
r.check("… ein unbekannter Name löst nichts aus (und in der Anfrage geschieht dasselbe)", len(post635) == 1)
a635u, app635u, post635u = _hinweis_app()
_u = a635u.create_user("unbelegt", password=PW, email="unbelegt@example.com")
a635u.store.set_email_verified(_u, False)
for _ in range(a635u.sec("max_login_attempts") + 2):
    _login(TestClient(app635u), "unbelegt", "falsch-falsch-falsch")
a635u._hinweis_ausgang.abwarten()
r.check("… an eine UNBELEGTE Adresse geht nichts (H-3)", post635u == [], str(post635u))
a635o, app635o, post635o = _hinweis_app(notify_login_failures=False)
a635o.create_user("still", password=PW, email="still@example.com")
for _ in range(a635o.sec("max_login_attempts") + 2):
    _login(TestClient(app635o), "still", "falsch-falsch-falsch")
a635o._hinweis_ausgang.abwarten()
r.check("… opt-out: notify_login_failures=False schickt nichts", post635o == [], str(post635o))
# (Mutationsproben: `_sperrhinweis` in `_abgewiesen` nicht rufen → erste Prüfung rot; die Drossel
#  streichen → „genau einen" rot; `_beleg_am_konto` streichen → „UNBELEGTE" rot.)

# ── H-14/H-15: TOTP-Geheimnisse ruhend verschlüsselt (Pflicht) ───────────────────────────
import base64 as _b64  # noqa: E402
import os as _os  # noqa: E402
import stat as _stat  # noqa: E402

a14, app14 = _app()
u14 = a14.create_user("totpnutzer", password=PW)
geheim14 = a14.totp_begin(u14)["secret"]
roh14 = a14.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: in der Datenbank steht das TOTP-Geheimnis verschlüsselt, nicht im Klartext",
        roh14.startswith("v1:") and geheim14 not in roh14, roh14[:20])
r.check("… und die Anmeldung damit funktioniert (Einrichtung mit echtem Code)",
        a14.totp_confirm(u14, pyotp.TOTP(geheim14).now()))
_keydatei = a14.cfg.db_path + ".key"
r.check("… ohne Angabe liegt der Schlüssel neben der Datenbank, nur für den Besitzer lesbar (0600)",
        _os.path.isfile(_keydatei) and _stat.S_IMODE(_os.stat(_keydatei).st_mode) == 0o600)

# Bestand: ein Klartext-Geheimnis wird beim Start verschlüsselt (stilles Heben).
_pfad14 = a14.cfg.db_path
a14.store._exec("UPDATE totp_cred SET secret=? WHERE user_id=?", (geheim14, u14))   # wie vor 0.21
a14.store.db.close()
a14b, _ = _app(db_path=_pfad14)
roh14b = a14b.store._one("SELECT secret FROM totp_cred WHERE user_id=?", (u14,))["secret"]
r.check("H-14/15: ein Klartext-Geheimnis aus der Zeit davor wird beim Start verschlüsselt",
        roh14b.startswith("v1:") and a14b.store.get_totp(u14)["secret"] == geheim14)
a14b.store.db.close()

# Falscher Schlüssel → der Start bricht ab, statt still jede TOTP-Anmeldung scheitern zu lassen.
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _app(db_path=_pfad14)
    _falsch = False
except ConfigError:
    _falsch = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("H-14/15: ein Schlüssel, der nicht passt, bricht den Start ab (ConfigError)", _falsch)

# Vorrang: Umgebung vor Datei vor „neben der Datenbank"; eine kaputte Angabe ist ein Fehler.
_datei14 = str(Path(tempfile.mkdtemp()) / "schluessel")
with open(_datei14, "w") as _f:
    _f.write(_b64.b64encode(_os.urandom(32)).decode())
a14c, _ = _app(secrets_key_file=_datei14)
r.check("… secrets_key_file wird genommen, dann entsteht keine Datei neben der Datenbank",
        a14c._schluessel_herkunft == "datei" and not _os.path.exists(a14c.cfg.db_path + ".key"))
with open(_datei14, "w") as _f:
    _f.write("zu-kurz")
try:
    _app(secrets_key_file=_datei14)
    _kaputt = False
except ConfigError:
    _kaputt = True
r.check("… ein kaputter Schlüssel (kein Base64 von 32 Byte) ist ein Fehler, kein stiller Ersatz", _kaputt)
# (Mutationsproben: in `set_totp` unverschlüsselt speichern → erste Prüfung rot; die Schlüsselprobe
#  in `geheimnisse_heben` streichen → „bricht den Start ab" rot; das Heben streichen → „Klartext …
#  wird beim Start verschlüsselt" rot.)

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
