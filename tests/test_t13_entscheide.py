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

# Die Wahl übersteht den Abschluss einer Kette: Passwort (mit Haken) → TOTP legt eine NEUE volle
# Sitzung an (Rechtewechsel, neues Token); `_nachfolger` trägt die Wahl hinüber. Ohne das fiele
# jede „Angemeldet bleiben"-Sitzung mit zweitem Faktor still auf die 8-h-Grenze zurück.
import time as _uhr_k  # noqa: E402

import pyotp as _pyotp  # noqa: E402
auth_k, app_k = _app(login_chain=["password", "totp"])


@app_k.get("/drin")
def _drin_k(user=Depends(auth_k.require())):
    return {"ok": True}


uid_k = auth_k.create_user("zweifach", password=PW)
_geheim_k = auth_k.totp_begin(uid_k)["secret"]
auth_k.totp_confirm(uid_k, _pyotp.TOTP(_geheim_k).at(_uhr_k.time() - 30))
ckk = TestClient(app_k)
ckk.post("/auth/login", data={"username": "zweifach", "password": PW, "remember": "1"}, follow_redirects=False)
_halb_k = auth_k.store._one("SELECT token_hash, bleiben_gewaehlt FROM session")
ckk.post("/auth/totp", data={"code": _pyotp.TOTP(_geheim_k).now(), "next": "/"}, follow_redirects=False)
_voll_k = auth_k.store._all("SELECT token_hash, bleiben_gewaehlt, mfa_ok FROM session")
r.check("F-05: „Angemeldet bleiben“ übersteht den zweiten Faktor (neue volle Sitzung trägt die Wahl)",
        _halb_k["bleiben_gewaehlt"] == 1 and len(_voll_k) == 1
        and _voll_k[0]["token_hash"] != _halb_k["token_hash"] and _voll_k[0]["bleiben_gewaehlt"] == 1,
        str([dict(z) for z in _voll_k]))
auth_k.store._exec("UPDATE session SET zuletzt = zuletzt - 30 * 86400")
r.check("… und damit gilt nach Passwort + TOTP weiter nur die absolute Laufzeit",
        ckk.get("/drin", follow_redirects=False).status_code == 200)
# (Mutationsprobe: die Übertragung in `_nachfolger` streichen → beide rot.)

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
r.check("… der Hinweis trägt keinen Link (es gibt keine Basis, die ein Angreifer biegen könnte)",
        post635 and "://" not in post635[0][2], post635[0][2][:120] if post635 else "")
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



def _jetzt_minus(auth):
    """Sekunden bis zur nächsten Nachprüfung der (einzigen) OIDC-Sitzung."""
    import time as _t
    z = auth.store._one("SELECT geprueft_at FROM oidc_sitzung")
    return int(z["geprueft_at"]) + int(auth.cfg.oidc_session_refresh_minutes) * 60 - int(_t.time())


# ── 4a: Widerruf folgt dem Provider (Refresh-Token alle N Minuten) ─────────────────────────
a4a, app4a = _oidc({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"]},
                   oidc_group_role_map=KARTE)
a4a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-1", "preferred_username": "refresher", "groups": ["admins"], "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-1"})
_antworten = []
_gerufen = []


def _refresh(rt, sub):
    _gerufen.append((rt, sub))
    return _antworten.pop(0)


a4a.oidc.refresh = _refresh
c4a = TestClient(app4a, raise_server_exceptions=False)
_start = c4a.get("/auth/oidc/start", follow_redirects=False)
_st = parse_qs(urlparse(_start.headers["location"]).query)["state"][0]
c4a.get(f"/auth/oidc/callback?code=x&state={_st}", follow_redirects=False)
_roh4a = a4a.store._one("SELECT refresh FROM oidc_sitzung")
r.check("4a: das Refresh-Token liegt zur Sitzung, verschlüsselt",
        _roh4a is not None and _roh4a["refresh"].startswith("v1:") and "rt-1" not in _roh4a["refresh"])
r.check("… innerhalb der Frist fragt TinySesam den Provider nicht",
        c4a.get("/auth/me").status_code == 200 and _gerufen == [])


def _altern():
    a4a.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")


_uid4a = a4a.store.get_user_by_name("refresher")["id"]
_altern()
_antworten.append(("ok", {"sub": "r-1", "groups": ["admins"]}, {"refresh_token": "rt-2"}))
_erste = c4a.get("/auth/me").status_code
a4a._oidc_ausgang.abwarten()                                  # getauscht wird im Hintergrund (Fund 6)
r.check("4a: nach der Frist wird getauscht; der Provider sagt ja → die Sitzung bleibt",
        _erste == 200 and c4a.get("/auth/me").status_code == 200 and _gerufen == [("rt-1", "r-1")])
r.check("… ein neu ausgegebenes Refresh-Token ersetzt das alte (Rotation)",
        a4a.store.get_oidc_sitzung(a4a.store._one("SELECT token_hash FROM oidc_sitzung")["token_hash"])["refresh"] == "rt-2")
_altern()
_antworten.append(("ok", {"sub": "r-1", "groups": []}, {}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a + H-5: nimmt der Provider die Admin-Gruppe, ist das Flag binnen der Frist weg — nicht erst beim Login",
        not a4a.store.get_user(_uid4a)["is_admin"])
_altern()
_antworten.append(("ok", {"sub": "r-1"}, {}))                   # kein Gruppen-Claim
a4a.set_roles(_uid4a, ["editor"])
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("… fehlt der Gruppen-Claim ganz, bleiben die Rollen (fehlend ≠ keine Gruppen)",
        "editor" in a4a.user_roles(a4a.store.get_user(_uid4a)))
_altern()
_antworten.append(("fehler", {}, {"error": "ConnectError"}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a: ist der Provider nicht erreichbar, bleibt die Sitzung (ein Ausfall meldet niemanden ab)",
        c4a.get("/auth/me").status_code == 200)
r.check("… und es wird in einer Minute neu versucht, nicht erst nach der vollen Frist",
        _jetzt_minus(a4a) <= 15 * 60 - 60 + 5)
_altern()
_antworten.append(("abgelehnt", {}, {"error": "invalid_grant"}))
c4a.get("/auth/me")
a4a._oidc_ausgang.abwarten()
r.check("4a: verweigert der Provider (gesperrt, gelöscht, entzogen), ist die Sitzung weg",
        c4a.get("/auth/me").status_code == 401
        and a4a.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and any(z["event"] == "oidc_widerruf" for z in a4a.store.recent_audit(20)))
a4b, app4b = _oidc({"sub": "r-2", "preferred_username": "ohne"}, oidc_session_refresh_minutes=0)
a4b.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
    _Claims({"sub": "r-2", "preferred_username": "ohne", "nonce": nonce}),
    {"access_token": "at", "refresh_token": "rt-x"})
_oidc_login(app4b)
r.check("4a einstellbar: oidc_session_refresh_minutes=0 legt nichts ab",
        a4b.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung")["n"] == 0)
# (Mutationsproben: `_oidc_nachpruefen` immer True → „Sitzung weg" rot; die Gruppen-Neubewertung
#  streichen → „Flag … weg" rot; `in info` streichen → „fehlend ≠ keine Gruppen" rot; die
#  Wiederholung in einer Minute streichen → „in einer Minute" rot.)

# ── Befunde aus dem Angriff auf die zweite Runde (4a, Schlüssel, Leerlauf, Hinweis) ─────────
import threading as _th  # noqa: E402
import time as _zeit  # noqa: E402


def _oidc_mit_refresh(sub, claims=None, **cfg):
    extra = dict(claims or {})
    a, app = _oidc({"sub": sub, "preferred_username": sub, **extra}, **cfg)
    a.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({"sub": sub, "preferred_username": sub, **extra, "nonce": nonce}),
        {"access_token": "at", "refresh_token": "rt-" + sub})
    c = TestClient(app, raise_server_exceptions=False)
    st = parse_qs(urlparse(c.get("/auth/oidc/start", follow_redirects=False).headers["location"]).query)["state"][0]
    c.get(f"/auth/oidc/callback?code=x&state={st}", follow_redirects=False)
    return a, app, c


# Fund 5: parallele Anfragen nach der Frist → genau EIN Tausch (Rotation beim Provider).
a5r, _, c5r = _oidc_mit_refresh("parallel")
_tausche = []
a5r.oidc.refresh = lambda rt, sub: (_tausche.append(rt) or ("ok", {"sub": sub}, {}))
a5r.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
_s5 = a5r.store._one("SELECT * FROM session")
for _ in range(4):
    a5r._oidc_nachpruefen(_s5)
a5r._oidc_ausgang.abwarten()
r.check("Fund 5: vier Anfragen nach der Frist tauschen das Refresh-Token genau einmal", len(_tausche) == 1,
        str(_tausche))

# Fund 6: ein hängender Provider hält die Anfrage nicht fest.
a6r, _, c6r = _oidc_mit_refresh("haengt")
a6r.oidc.refresh = lambda rt, sub: (_zeit.sleep(1.5), ("ok", {"sub": sub}, {}))[1]
a6r.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
_t0 = _zeit.monotonic()
_st6 = c6r.get("/auth/me").status_code
_dauer = _zeit.monotonic() - _t0
a6r._oidc_ausgang.abwarten()
r.check("Fund 6: die Anfrage wartet nicht auf den Provider (Tausch im Hintergrund)",
        _st6 == 200 and _dauer < 1.0, f"{_dauer:.2f}s")

# Fund 7: je Client eine Zeile — ein Login über einen zweiten Client überschreibt die erste nicht.
_h7 = a6r.store._one("SELECT token_hash FROM oidc_sitzung")["token_hash"]
a6r.store.set_oidc_sitzung(_h7, "app-b", "haengt", "rt-b")
r.check("Fund 7: mehrere Clients einer Sitzung — jede Zeile bleibt und wird nachgeprüft",
        {z["client"] for z in a6r.store.get_oidc_sitzungen(_h7)} == {"*", "app-b"})

# Fund 13: ein gesperrtes Konto fragt niemand beim Provider nach.
a13, _, c13 = _oidc_mit_refresh("gesperrt13")
_t13 = []
a13.oidc.refresh = lambda rt, sub: (_t13.append(rt) or ("ok", {"sub": sub, "groups": ["admins"]}, {}))
a13.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a13.store._exec("UPDATE users SET disabled = 2")
c13.get("/auth/me")
a13._oidc_ausgang.abwarten()
r.check("Fund 13: für ein gesperrtes Konto wird nicht getauscht (F-17)", _t13 == [], str(_t13))

# Fund 4: ein falscher Schlüssel bricht den Start auch ab, wenn es nur Refresh-Tokens gibt.
_pfad4 = a5r.cfg.db_path
a5r.store.db.close()
_os.environ["TINYSESAM_SECRETS_KEY"] = _b64.b64encode(_os.urandom(32)).decode()
try:
    _oidc({"sub": "x"}, db_path=_pfad4)
    _f4 = False
except ConfigError:
    _f4 = True
finally:
    del _os.environ["TINYSESAM_SECRETS_KEY"]
r.check("Fund 4: falscher Schlüssel + nur OIDC-Refresh-Tokens → der Start bricht ab", _f4)

# Fund 9: das 8-h-Limit gilt für jede Sitzung ohne AUSDRÜCKLICHES „Angemeldet bleiben".
a9, app9, c9 = _oidc_mit_refresh("leerlauf9")
a9.store._exec("UPDATE session SET zuletzt = zuletzt - 9 * 3600")
r.check("Fund 9: eine OIDC-Sitzung (dauerhaft, aber ohne Wahl) endet nach 8 h Inaktivität",
        c9.get("/auth/me").status_code == 401)

# Fund 10: mehrere Worker legen den Schlüssel gleichzeitig an — alle bekommen denselben.
from tinysesam import geheimnis as _gh  # noqa: E402
_db10 = str(Path(tempfile.mkdtemp()) / "race.db")
_erg10, _fehler10 = [], []


def _laden10():
    try:
        _erg10.append(_gh.schluessel_laden(_db10)[0])
    except Exception as e:   # noqa: BLE001
        _fehler10.append(repr(e))


_faeden = [_th.Thread(target=_laden10) for _ in range(24)]
for _f in _faeden:
    _f.start()
for _f in _faeden:
    _f.join()
r.check("Fund 10: 24 gleichzeitige Erststarts — kein Fehler, ein einziger Schlüssel",
        not _fehler10 and len(set(_erg10)) == 1 and len(_erg10) == 24, f"{_fehler10[:2]} / {len(set(_erg10))}")

# Fund 11: die Drossel des Sperr-Hinweises steht in der Datenbank — ein verdrängter Speicher-Schlüssel
# (oder ein zweiter Worker) schickt keinen zweiten.
a11, app11, post11 = _hinweis_app()
a11.create_user("gedrosselt", password=PW, email="gedrosselt@example.com")
a11._sperrhinweis("gedrosselt", "198.51.100.30", "lockout_user")
a11._hinweis_ausgang.abwarten()
a11.rl.allow = lambda *a, **k: True                             # wie nach der Verdrängung
a11._sperrhinweis("gedrosselt", "198.51.100.31", "lockout_user")
a11._hinweis_ausgang.abwarten()
r.check("Fund 11: auch ohne Speicher-Drossel höchstens ein Hinweis je Sperrfenster", len(post11) == 1,
        str(len(post11)))
# (Mutationsproben: den Anspruch in `_oidc_nachpruefen` streichen → Fund 5 rot; den Tausch
#  synchron statt über `_oidc_ausgang` → Fund 6 rot; die Audit-Drossel in `_senden` streichen →
#  Fund 11 rot; `bleiben_gewaehlt` in `get_session` streichen → Fund 9 rot.)

# ── Fund 8: API-Keys folgen dem Identity Provider (PO-Entscheid 2026-09-24) ────────────────
# Sagt der Provider Nein (4a), ruhen die Keys des OIDC-Kontos; ohne Bestätigung binnen
# `oidc_apikey_confirm_days` ebenso. Gelöscht wird nichts — die nächste Anmeldung weckt sie.
def _erneut_ueber_idp(c):
    st = parse_qs(urlparse(c.get("/auth/oidc/start", follow_redirects=False).headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={st}", follow_redirects=False)


a8, app8, c8 = _oidc_mit_refresh("keyhalter")
uid8 = a8.store.get_user_by_name("keyhalter")["id"]
key8 = a8.create_api_key(uid8, name="backup")["key"]
r.check("Fund 8: der Key eines frisch über den Provider angemeldeten Kontos gilt",
        a8.verify_api_key(key8)[0] is not None)
a8.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})
a8.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8._oidc_nachpruefen(a8.store._one("SELECT * FROM session"))
a8._oidc_ausgang.abwarten()
r.check("Fund 8: nach dem Nein des Providers ruht der Key (Sitzung weg, Key abgewiesen)",
        a8.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0 and a8.verify_api_key(key8)[0] is None)
_zeile8 = a8.store._one("SELECT detail FROM audit WHERE event='api_keys_ruhen'")
r.check("… mit Zeile im Audit-Log (wie viele Keys es betrifft)",
        _zeile8 is not None and "anzahl=1" in _zeile8["detail"], str(_zeile8 and dict(_zeile8)))
r.check("… gelöscht oder widerrufen ist nichts",
        not a8.store._one("SELECT revoked FROM api_key")["revoked"])
# Das Nein liegt als NEGATIVER Zeitpunkt; ein Ja weckt nur, wenn seine Frage danach abging. Hier
# liegt das Nein fünf Sekunden zurück, die Anmeldung beginnt jetzt.
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (-(int(_zeit.time()) - 5), uid8))
r.check("… und die nächste Anmeldung über den Provider weckt ihn wieder",
        _erneut_ueber_idp(c8).status_code == 303 and a8.verify_api_key(key8)[0] is not None)
# Der Wettlauf: Die Frage ging VOR dem Nein ab (zwei Sitzungen, zwei Arbeiter), das Ja wird
# aber danach angewandt. Es darf das Nein nicht überschreiben.
a8.store.idp_verweigert(uid8)
_frage_vorher = int(_zeit.time()) - 10
r.check("Fund 8: ein Ja, dessen Frage VOR dem Nein abging, weckt die Keys nicht (Wettlauf)",
        not a8.store.idp_bestaetigen(uid8, _frage_vorher) and a8.verify_api_key(key8)[0] is None)
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (-(int(_zeit.time()) - 5), uid8))
r.check("… eines, dessen Frage danach abging, schon",
        a8.store.idp_bestaetigen(uid8, int(_zeit.time())) and a8.verify_api_key(key8)[0] is not None)

# Frist ohne Sitzung (Skript-only): 30 Tage Vorgabe.
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (int(_zeit.time()) - 29 * 86400, uid8))
_innen8 = a8.verify_api_key(key8)[0] is not None
a8.store._exec("UPDATE users SET idp_bestaetigt_at = ? WHERE id=?", (int(_zeit.time()) - 31 * 86400, uid8))
r.check("Fund 8: ohne Bestätigung binnen 30 Tagen ruht der Key (29 Tage: gilt, 31: ruht)",
        _innen8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 0
_ohne_frist8 = a8.verify_api_key(key8)[0] is not None
a8.store.idp_verweigert(uid8)
r.check("… `oidc_apikey_confirm_days=0` schaltet nur die Frist ab — das Nein zählt weiter",
        _ohne_frist8 and a8.verify_api_key(key8)[0] is None)
a8.cfg.oidc_apikey_confirm_days = 30

# Ein Ja beim Tausch bestätigt; ein Gruppen-Entzug ist ein Nein.
a8b, app8b, c8b = _oidc_mit_refresh("gruppe8", claims={"groups": ["team"]}, oidc_allowed_groups=["team"])
uid8b = a8b.store.get_user_by_name("gruppe8")["id"]
key8b = a8b.create_api_key(uid8b, name="ci")["key"]
a8b.store._exec("UPDATE users SET idp_bestaetigt_at = 1000 WHERE id=?", (uid8b,))
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["team"]}, {})
a8b.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8b._oidc_nachpruefen(a8b.store._one("SELECT * FROM session"))
a8b._oidc_ausgang.abwarten()
r.check("Fund 8: ein Ja beim Refresh-Tausch bestätigt das Konto (der alte Stand wird frisch)",
        a8b.store.get_user(uid8b)["idp_bestaetigt_at"] > 1000 and a8b.verify_api_key(key8b)[0] is not None)
a8b.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub, "groups": ["andere"]}, {})
a8b.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a8b._oidc_nachpruefen(a8b.store._one("SELECT * FROM session"))
a8b._oidc_ausgang.abwarten()
r.check("… ein Entzug der erlaubten Gruppe ist ein Nein: der Key ruht",
        a8b.verify_api_key(key8b)[0] is None and a8b.store.get_user(uid8b)["idp_bestaetigt_at"] < 0)

# Konten ohne OIDC-Bindung betrifft das nicht — auch nicht mit einem Stand, der „Nein" hiesse.
lokal8 = a8.create_user("lokal8", password=PW)
key8l = a8.create_api_key(lokal8, name="lokal")["key"]
a8.store._exec("UPDATE users SET idp_bestaetigt_at = 0 WHERE id=?", (lokal8,))
r.check("Fund 8: ein Konto ohne OIDC-Bindung behält seinen Key (auch mit idp_bestaetigt_at=0)",
        a8.verify_api_key(key8l)[0] is not None)

# Bestand: Die Frist beginnt mit dem Update, genau einmal.
_pfad8 = str(Path(tempfile.mkdtemp()) / "bestand8.db")
_alt8 = Store(_pfad8)
_alt8.create_user("bestand-oidc", None, None, False, [], False)
_alt8.link_oidc("https://idp.example", "sub-b", 1)
_alt8.db.execute("ALTER TABLE users DROP COLUMN idp_bestaetigt_at")
_alt8.db.execute("DELETE FROM setting WHERE key='idp_bestand_gesetzt'")   # eine 0.20-Datei kennt ihn nicht
_alt8.db.commit()
_alt8.db.close()
_neu8 = Store(_pfad8)
_stand8 = _neu8.get_user(1)["idp_bestaetigt_at"]
# Danach ohne Stand (ein Konto, das auf einem Weg ohne Bestätigung gebunden wurde): Ein Neustart
# darf ihm KEINE frische Frist schenken.
_neu8.db.execute("UPDATE users SET idp_bestaetigt_at = NULL WHERE id=1")
_neu8.db.commit()
_neu8.db.close()
r.check("Fund 8, Bestand: Die Frist eines OIDC-Kontos beginnt mit dem Update — und nur einmal",
        _stand8 is not None and abs(_stand8 - int(_zeit.time())) < 60
        and Store(_pfad8).get_user(1)["idp_bestaetigt_at"] is None, f"{_stand8}")
# Abbruch mitten im Update: Die Spalte ist schon da (das ALTER ist sofort dauerhaft), Stand und
# Merker nicht. Der nächste Start holt es nach.
_pfad8c = str(Path(tempfile.mkdtemp()) / "abbruch8.db")
_ab8 = Store(_pfad8c)
_ab8.create_user("abbruch-oidc", None, None, False, [], False)
_ab8.link_oidc("https://idp.example", "sub-c", 1)
_ab8.db.execute("DELETE FROM setting WHERE key='idp_bestand_gesetzt'")
_ab8.db.commit()
_ab8.db.close()
r.check("Fund 8, Bestand: nach einem Abbruch (Spalte da, Merker nicht) setzt der nächste Start den Stand",
        Store(_pfad8c).get_user(1)["idp_bestaetigt_at"] is not None)
# (Mutationsproben: `_key_ruht` in `verify_api_key` streichen → „ruht" rot; `idp_bestaetigen` im
#  Callback streichen → „weckt ihn wieder" rot; die Frist-Prüfung streichen → „31: ruht" rot;
#  `_idp_nein` im Gruppen-Zweig streichen → Gruppen-Entzug rot; die Bindungs-Prüfung streichen →
#  „ohne OIDC-Bindung" rot; die Bestands-Zeile bei jedem Start → „nur einmal" rot.)


# ── 3c · ASVS 6.3.6: der Anmelde-Link braucht den zweiten Faktor, wenn es einen gibt ─────────
def _link_app(**cfg):
    a, ap = _app(magiclink_enabled=True, **cfg)
    a.set_mailer(lambda *x, **k: True)

    @ap.get("/drin")
    def _drin(user=Depends(a.require())):
        return {"u": user["username"]}
    return a, ap


def _link_login(a, ap, name):
    c = TestClient(ap)
    uid = a.store.get_user_by_name(name)["id"]
    tok = a.create_magic_token("login", user_id=uid, payload={"next": "/drin"})
    return c, c.post(f"/auth/magic/{tok}", follow_redirects=False)


# Klassisch (keine Kette), Konto nur mit Passkey: bis hierhin meldete der Link allein voll an.
a3c, ap3c = _link_app()
u3c = a3c.create_user("passkey-konto", password=PW, email="pk@example.com")
a3c.store.add_webauthn(u3c, b"cred-3c", b"pub", 0, "[]", "Laptop")
c3c, antw3c = _link_login(a3c, ap3c, "passkey-konto")
r.check("3c: Konto mit Passkey — der Link allein meldet nicht voll an (weiter zum Passkey)",
        antw3c.status_code == 303 and antw3c.headers["location"].startswith(a3c.cfg.login_path)
        and c3c.get("/drin", follow_redirects=False).status_code != 200,
        f"{antw3c.status_code} {antw3c.headers.get('location')}")
# Kette ["magic"] mit TOTP: der Link genügte der Kette, der Authenticator zählte nicht.
a3k, ap3k = _link_app(login_chain=["magic"])
u3k = a3k.create_user("totp-konto", password=PW, email="tk@example.com")
_g3k = a3k.totp_begin(u3k)["secret"]
a3k.totp_confirm(u3k, pyotp.TOTP(_g3k).at(_zeit.time() - 30))
c3k, antw3k = _link_login(a3k, ap3k, "totp-konto")
r.check("3c: Kette [\"magic\"], Konto mit TOTP — nach dem Link folgt der TOTP-Schritt",
        antw3k.status_code == 303 and antw3k.headers["location"].startswith("/auth/totp")
        and c3k.get("/drin", follow_redirects=False).status_code != 200,
        f"{antw3k.status_code} {antw3k.headers.get('location')}")
_fertig3k = c3k.post("/auth/totp", data={"code": pyotp.TOTP(_g3k).now(), "next": "/drin"},
                     follow_redirects=False)
r.check("… mit dem Code ist die Anmeldung vollständig",
        _fertig3k.status_code == 303 and c3k.get("/drin").json() == {"u": "totp-konto"})
a3o, ap3o = _link_app(login_chain=["magic"])
a3o.create_user("ohne-faktor", password=PW, email="of@example.com")
c3o, _ = _link_login(a3o, ap3o, "ohne-faktor")
r.check("3c: ein Konto ohne zweiten Faktor meldet der Link weiter allein an (C, nicht D)",
        c3o.get("/drin").json() == {"u": "ohne-faktor"})
a3a, ap3a = _link_app(login_chain=["magic"], magiclink_require_second_factor=False)
u3a = a3a.create_user("totp-a", password=PW, email="ta@example.com")
_g3a = a3a.totp_begin(u3a)["secret"]
a3a.totp_confirm(u3a, pyotp.TOTP(_g3a).at(_zeit.time() - 30))
c3a, _ = _link_login(a3a, ap3a, "totp-a")
r.check("3c einstellbar: magiclink_require_second_factor=False — der Link genügt wieder (A)",
        c3a.get("/drin").json() == {"u": "totp-a"})
_pw3 = TestClient(ap3k)
_pw3.post("/auth/login", data={"username": "totp-konto", "password": PW, "next": "/drin"},
          follow_redirects=False)
r.check("… andere Wege bleiben, wie sie waren (Passwort in der Kette [\"magic\"] allein: kein Login)",
        _pw3.get("/drin", follow_redirects=False).status_code != 200)
# (Mutationsproben: `_link_braucht` in `_session_ok` streichen → die ersten zwei rot; die
#  Passkey-Zeile streichen → Passkey-Konto rot; den Schalter nicht lesen → „einstellbar" rot.)

# ── Angriff auf die dritte Runde: Funde und ihre Riegel ────────────────────────────────────
from fastapi import HTTPException as _HTTPEx  # noqa: E402
from tinysesam import konfigpruefung as _kp3  # noqa: E402
from tinysesam.oidc import OIDCClient as _OC3  # noqa: E402


class _LDAP3:
    def __init__(self, eintraege):
        self.e = eintraege

    def authenticate(self, username, password):
        z = self.e.get(username)
        return dict(z, username=username, groups=[]) if z and password == "x" else None


# S1 (hoch): SAML nicht vertraut — ein Name, der die Adresse eines lokalen Kontos ist, bindet es nicht.
a_s1, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", login_identifier="email")
opfer_s1 = a_s1.create_user("bob@example.com", password=PW, email="bob@example.com", is_admin=True)
neu_s1 = a_s1.check_saml("bob@example.com", {"email": ["bob@example.com"]})
r.check("Angriff R3/S1: SAML (nicht vertraut) mit der Adresse eines lokalen Kontos als NameID übernimmt es nicht",
        neu_s1 is not None and neu_s1["id"] != opfer_s1 and neu_s1["username"].startswith("saml-")
        and not neu_s1["is_admin"] and a_s1.store.get_federated_kennung("saml", opfer_s1) is None,
        str(neu_s1))
a_s1.check_saml("BOB@EXAMPLE.COM", {"email": ["bob@example.com"]})
r.check("… auch nicht in anderer Schreibweise", a_s1.store.get_federated_kennung("saml", opfer_s1) is None)

# S3: ohne stabile Kennung wird ein Adress-Name abgewiesen — nicht bei jedem Login ein neues Konto.
a_s3, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_id="objectGUID")
_vorher_s3 = len(a_s3.store.list_users())
_e1 = a_s3.check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
_e2 = a_s3.check_saml("anna@corp.example", {"email": ["anna@corp.example"]})
r.check("Angriff R3/S3: SAML nicht vertraut, Adress-Name ohne Kennung → abgewiesen, kein Konto je Login",
        _e1 is None and _e2 is None and len(a_s3.store.list_users()) == _vorher_s3)

# S2 (mittel): LDAP nicht vertraut, Anmeldung mit einer Adresse (Filter über mail).
a_s2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False,
               login_identifier="both")
chefin_s2 = a_s2.create_user("chefin@example.com", password=PW, email="chefin@example.com")
a_s2.ldap = _LDAP3({"chefin@example.com": {"id": "uuid-mallory", "email": "chefin@example.com", "name": "M"}})
neu_s2 = a_s2.check_ldap("chefin@example.com", "x")
r.check("Angriff R3/S2: LDAP nicht vertraut — die eingetippte Adresse wird weder Kontoname noch bindet sie ein Konto",
        neu_s2 is not None and neu_s2["id"] != chefin_s2 and neu_s2["username"].startswith("ldap-")
        and not neu_s2["email"] and a_s2.store.get_federated_kennung("ldap", chefin_s2) is None, str(neu_s2))

# S4 (hoch, vorbestehend): Steuerzeichen im Kontonamen.
a_s4, app_s4 = _app(allow_signup=True)
try:
    a_s4.create_user("chefin\x01", password=PW)
    _s4_create = False
except ConfigError:
    _s4_create = True
_s4_reg = TestClient(app_s4).post("/auth/register", data={"username": "chefin​", "password": PW + "xyz",
                                                         "next": "/"}, follow_redirects=False)
r.check("Angriff R3/S4: kein Konto mit Steuer-/Formatzeichen im Namen (create_user, Registrierung)",
        _s4_create and _s4_reg.status_code == 400 and a_s4.store.get_user_by_name("chefin​") is None,
        f"create={_s4_create} reg={_s4_reg.status_code}")
a_s4.create_user("chefin", password=PW)
_alt_s4 = a_s4.store.create_user("chefin\x01", None, None, False, [], False)       # Bestand am Riegel vorbei
try:
    a_s4.forward_response_headers(a_s4.get_user(_alt_s4))
    _s4_fwd = False
except _HTTPEx as e:
    _s4_fwd = e.status_code == 403
r.check("… und ein solcher Bestand bekommt keinen Remote-User (fail-closed statt `chefin`)", _s4_fwd)
a_s4o, app_s4o = _oidc({"sub": "s4-sub", "preferred_username": "chefin\x01", "email": "c4@example.com",
                        "email_verified": True})
_oidc_login(app_s4o)
_s4o = [u["username"] for u in a_s4o.store.list_users()]
r.check("… ein IdP-Name mit Steuerzeichen wird verworfen (hier gilt die belegte Adresse)",
        _s4o == ["c4@example.com"], str(_s4o))
a_s4s, app_s4s = _oidc({"sub": "\x01s4", "preferred_username": ""})
_s4s_antwort = _oidc_login(app_s4s)
_s4s = [u["username"] for u in a_s4s.store.list_users()]
r.check("… und eine `sub` mit Steuerzeichen ergibt einen gehashten Ersatznamen, keine Abweisung",
        _s4s_antwort.status_code == 303 and len(_s4s) == 1 and _s4s[0].startswith("oidc-")
        and "\x01" not in _s4s[0], f"{_s4s_antwort.status_code} {_s4s}")

# F8-2: Fehler des Clients sind kein Nein zum Konto.
import httpx as _httpx3  # noqa: E402


class _Antwort3:
    def __init__(self, code, body):
        self.status_code, self._b = code, body

    def json(self):
        return self._b


_post3 = _httpx3.post
_oc3 = _OC3.__new__(_OC3)
_oc3.client_id, _oc3.client_secret = "c", "s"
_oc3.meta = lambda: {"token_endpoint": "https://idp.example/token", "issuer": "https://idp.example"}
_erg3 = {}
try:
    for code, body in ((401, {"error": "invalid_client"}), (400, {"error": "unauthorized_client"}),
                       (400, {"error": "unsupported_grant_type"}), (401, {}), (503, {}),
                       (400, {}), (400, {"error": "invalid_request"}), (400, {"error": "invalid_grant"}),
                       (400, {"error": "access_denied"})):
        _httpx3.post = lambda *a, _c=code, _b=body, **k: _Antwort3(_c, _b)
        _erg3[(code, body.get("error", "-"))] = _oc3.refresh("rt", "sub")[0]
finally:
    _httpx3.post = _post3
_soll3 = {(401, "invalid_client"): "fehler", (400, "unauthorized_client"): "fehler",
          (400, "unsupported_grant_type"): "fehler", (401, "-"): "fehler", (503, "-"): "fehler",
          (400, "-"): "abgelehnt", (400, "invalid_request"): "abgelehnt",      # Dex: widerrufenes Token
          (400, "invalid_grant"): "abgelehnt", (400, "access_denied"): "abgelehnt"}
r.check("Angriff R3/F8-2: Client-Fehler, 401 und 5xx → „fehler\"; jede andere 4xx (auch Dex' invalid_request) → Nein",
        _erg3 == _soll3, str({k: v for k, v in _erg3.items() if _soll3.get(k) != v}))
# … und eine Zeile eines nicht mehr eingerichteten Clients wird verworfen, nicht als Nein getauscht.
a_f2, _, _ = _oidc_mit_refresh("f2-konto")
_uid_f2 = a_f2.store.get_user_by_name("f2-konto")["id"]
_h_f2 = a_f2.store._one("SELECT token_hash FROM session")["token_hash"]
a_f2.store.set_oidc_sitzung(_h_f2, "app-weg", "f2-konto", "rt-weg")
a_f2.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})     # der Rückfall sagte Nein
a_f2.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60 WHERE client='app-weg'")
a_f2._oidc_nachpruefen(a_f2.store._one("SELECT * FROM session"))
a_f2._oidc_ausgang.abwarten()
r.check("… eine Zeile eines entfernten Clients geht, die Sitzung bleibt, das Konto bekommt kein Nein",
        a_f2.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung WHERE client='app-weg'")["n"] == 0
        and a_f2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_f2.store.get_user(_uid_f2)["idp_bestaetigt_at"] or 0) > 0)

# 3c/M1: Kette ["magic","totp"], Konto mit Passkey ohne TOTP — das Postfach richtet sich kein TOTP ein.
a_m1, ap_m1 = _link_app(login_chain=["magic", "totp"])
u_m1 = a_m1.create_user("pk-kette", password=PW, email="pkk@example.com")
a_m1.store.add_webauthn(u_m1, b"cred-m1", b"pub", 0, "[]", "Laptop")
c_m1, _ = _link_login(a_m1, ap_m1, "pk-kette")
_setup_m1 = c_m1.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False)
r.check("Angriff R3/M1: nur Anmelde-Link + Konto mit Passkey → keine TOTP-Selbsteinrichtung",
        _setup_m1.status_code != 200 and not a_m1.store.has_confirmed_totp(u_m1)
        and any(z["event"] == "mfa_enrollment_denied" for z in a_m1.store.recent_audit(20)),
        f"HTTP {_setup_m1.status_code}")
a_m2, ap_m2 = _link_app(login_chain=["magic", "totp"])
a_m2.create_user("frisch-kette", password=PW, email="fk@example.com")
c_m2, _ = _link_login(a_m2, ap_m2, "frisch-kette")
r.check("… ein Konto ohne zweiten Faktor darf es weiter (der Preis von C)",
        c_m2.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)

# S5: Die Konfigurationsprüfung sagt, was die Laufzeit tut.
_w_v = " ".join(_kp3.pruefe(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                             ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                             ldap_email_trusted=True))[1])
_w_n = " ".join(_kp3.pruefe(TinySesamConfig(db_path=":memory:", admin_identifiers=["chef@example.com"],
                                             ldap_enabled=True, ldap_url="ldaps://d.example", ldap_auto_create=True,
                                             ldap_email_trusted=False))[1])
r.check("Angriff R3/S5: Konfig-Prüfung — vertraute Quelle: „wird Erst-Admin\"; nicht vertraut: „NIE\"",
        "vertraute Quelle" in _w_v and "NIE" not in _w_v and "NIE" in _w_n, _w_v[:200])
# (Mutationsproben stehen im Commit: name_zuordnen ignoriert → S1 rot; Abweisung ohne Kennung weg →
#  S3 rot; LDAP-Ersatzname weg → S2 rot; name_ungueltig in create_user weg → S4 rot; Header-Riegel
#  weg → „fail-closed" rot; Client-Fehler wieder als Nein → F8-2 rot; `bekannt` weg → „entfernter
#  Client" rot; Passkey-Prüfung in totp_enrollment_user weg → M1 rot.)

# ── Gegenprüfung der Fixes (dritte Runde): Umwege und Regressionen ──────────────────────────
import logging as _log3  # noqa: E402

# V1: LDAP nicht vertraut — ein mail-Wert OHNE „@" ist genauso unbelegt.
a_v1, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
chefin_v1 = a_v1.create_user("chefin", password=PW, is_admin=True)
a_v1.ldap = _LDAP3({"chefin": {"id": "uuid-mallory", "email": "chefin", "name": "M"}})
neu_v1 = a_v1.check_ldap("chefin", "x")
r.check("Gegenprüfung R3/V1: LDAP nicht vertraut, Eingabe = eigener mail-Wert ohne „@\" → keine Übernahme",
        neu_v1 is not None and neu_v1["id"] != chefin_v1 and neu_v1["username"].startswith("ldap-")
        and a_v1.store.get_federated_kennung("ldap", chefin_v1) is None, str(neu_v1))
# V2: … und ein UPN (Bind-Kennung, nicht der mail-Wert) bleibt Kontoname, auch ohne Kennung.
a_v2, _ = _app(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
a_v2.ldap = _LDAP3({"bob@corp.example": {"id": "", "email": "b.mail@corp.example", "name": "Bob"}})
neu_v2 = a_v2.check_ldap("bob@corp.example", "x")
r.check("… ein UPN, der nicht der mail-Wert ist, meldet wie vor dem Fix an (keine Regression)",
        neu_v2 is not None and neu_v2["username"] == "bob@corp.example" and not neu_v2["email"], str(neu_v2))

# V3: Forward-Auth sperrt nur, was die Säuberung wirklich entfernt; Startbefund für den Bestand.
a_v3, _ = _app()
_zwnj = a_v3.store.create_user("علی‌رضا", None, None, False, [], False)
_c0 = a_v3.store.create_user("chefin\x01", None, None, False, [], False)
try:
    _kopf_v3 = a_v3.forward_response_headers(a_v3.get_user(_zwnj))
except _HTTPEx:
    _kopf_v3 = None
r.check("Gegenprüfung R3/V3: ein Bestandsname mit ZWNJ bekommt seinen Remote-User (kollidiert nicht)",
        _kopf_v3 is not None and "‌".encode("utf-8").decode("latin-1") in _kopf_v3["Remote-User"])
_fang_v3 = []
_h_v3 = _log3.Handler()
_h_v3.emit = lambda rec: _fang_v3.append(rec.getMessage())
_log3.getLogger("tinysesam.security").addHandler(_h_v3)
try:
    TinySesam(TinySesamConfig(db_path=a_v3.cfg.db_path, cookie_secure=False, base_url="http://testserver"))
finally:
    _log3.getLogger("tinysesam.security").removeHandler(_h_v3)
r.check("… und der Start nennt Bestandsnamen mit Steuer-/Formatzeichen",
        any("Kontoname(n) mit Steuer- oder Formatzeichen" in m and str(_c0) in m for m in _fang_v3))
# Der genannte Weg (seit der Selbstbedienung) wirkt: umbenannt, danach Remote-User wieder da.
_neu_v3 = a_v3.change_username(_c0, "chefin-neu")
r.check("… und der Weg, den er nennt (auth.change_username), räumt den Namen auf",
        any("auth.change_username" in m for m in _fang_v3) and _neu_v3 == "chefin-neu"
        and a_v3.forward_response_headers(a_v3.get_user(_c0))["Remote-User"] == "chefin-neu")

# V4: SAML-Kennung mit Rand-Steuerzeichen trifft keine fremde Bindung.
a_v4, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_email_trusted=True)
echt_v4 = a_v4.check_saml("chefin", {})
fremd_v4 = a_v4.check_saml("chefin ", {})
r.check("Gegenprüfung R3/V4: NameID `chefin` + U+2028 landet nicht im Konto der gebundenen `chefin`",
        echt_v4 is not None and fremd_v4 is None, f"{echt_v4 and echt_v4['id']} / {fremd_v4}")

# V5: SAML nicht vertraut, der Name kommt aus dem Adress-Attribut selbst (auch ohne „@").
a_v5, _ = _app(saml_enabled=True, saml_idp_entity_id="https://idp.example", saml_idp_sso_url="https://idp.example/sso",
               saml_idp_x509cert="MII", saml_attr_username="email")
chefin_v5 = a_v5.create_user("chefin", password=PW, is_admin=True)
neu_v5 = a_v5.check_saml("opaque-mallory", {"email": ["chefin"]})
r.check("Gegenprüfung R3/V5: SAML-Name aus dem Adress-Attribut (`chefin`) bindet das lokale Konto nicht",
        neu_v5 is not None and neu_v5["id"] != chefin_v5 and neu_v5["username"].startswith("saml-")
        and a_v5.store.get_federated_kennung("saml", chefin_v5) is None, str(neu_v5))

# I2: Client beim Provider neu angelegt (andere client_id) — kein Nein, die Zeile geht.
a_i2, _, _ = _oidc_mit_refresh("i2-konto")
_uid_i2 = a_i2.store.get_user_by_name("i2-konto")["id"]
a_i2.store._exec("UPDATE oidc_sitzung SET client_id='alte-client-id', geprueft_at = geprueft_at - 16 * 60")
a_i2.oidc.refresh = lambda rt, sub: ("abgelehnt", {}, {"error": "invalid_grant"})
a_i2._oidc_nachpruefen(a_i2.store._one("SELECT * FROM session"))
a_i2._oidc_ausgang.abwarten()
r.check("Gegenprüfung R3/I2: Token einer alten client_id → Zeile verworfen, Sitzung bleibt, kein Nein",
        a_i2.store._one("SELECT COUNT(*) AS n FROM oidc_sitzung")["n"] == 0
        and a_i2.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 1
        and (a_i2.store.get_user(_uid_i2)["idp_bestaetigt_at"] or 0) > 0)

# I3 + I4: Passkey-Konto richtet sich TOTP nur mit Passkey in der Sitzung oder im Betreiber-Fenster ein.
a_i3, ap_i3 = _link_app(login_chain=["password", "totp"])
u_i3 = a_i3.create_user("pk-reset", password=PW, email="pkr@example.com")
a_i3.store.add_webauthn(u_i3, b"cred-i3", b"pub", 0, "[]", "Laptop")
c_i3 = TestClient(ap_i3)
c_i3.post("/auth/login", data={"username": "pk-reset", "password": PW, "next": "/"}, follow_redirects=False)
r.check("Gegenprüfung R3/I3: Passkey-Konto, nur Passwort in der Sitzung (z. B. nach „Passwort vergessen\") → keine Einrichtung",
        c_i3.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code != 200)
_h_i3 = a_i3.store._one("SELECT token_hash FROM session")["token_hash"]
a_i3.store.set_session_factors(_h_i3, ["password", "passkey"], mfa_ok=False)
r.check("… mit dem Passkey in derselben Sitzung darf der Inhaber",
        c_i3.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)
a_i4, ap_i4 = _link_app(login_chain=["magic", "totp"])
u_i4 = a_i4.create_user("pk-verloren", password=PW, email="pkv@example.com")
a_i4.store.add_webauthn(u_i4, b"cred-i4", b"pub", 0, "[]", "Altes Handy")
a_i4.grant_mfa_enrollment(u_i4, 60)
c_i4, _ = _link_login(a_i4, ap_i4, "pk-verloren")
r.check("Gegenprüfung R3/I4: ein vom Betreiber geöffnetes Fenster gewinnt (verlorenes Gerät, nur Link)",
        c_i4.post("/auth/totp/setup/start", data={"next": "/"}, follow_redirects=False).status_code == 200)

# I5: Bekommt die Sitzung während des Tauschs ein neues Token, geht das rotierte Refresh-Token nicht verloren.
a_i5, _, _ = _oidc_mit_refresh("i5-konto")
_alt_i5 = a_i5.store._one("SELECT token_hash FROM session")["token_hash"]


def _tausch_mit_rotation(rt, sub):
    # Mitten im Tausch: Step-up o. ä. gibt der Sitzung ein neues Token, die OIDC-Zeile zieht mit.
    a_i5.store._exec("UPDATE session SET token_hash='neu-i5' WHERE token_hash=?", (_alt_i5,))
    a_i5.store._exec("UPDATE oidc_sitzung SET token_hash='neu-i5' WHERE token_hash=?", (_alt_i5,))
    return "ok", {"sub": sub}, {"refresh_token": "rt-rotiert"}


a_i5.oidc.refresh = _tausch_mit_rotation
a_i5.store._exec("PRAGMA foreign_keys=OFF")
a_i5.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60")
a_i5._oidc_nachpruefen(a_i5.store._one("SELECT * FROM session"))
a_i5._oidc_ausgang.abwarten()
_z_i5 = a_i5.store._one("SELECT refresh FROM oidc_sitzung WHERE token_hash='neu-i5'")
r.check("Gegenprüfung R3/I5: Rotation während des Tauschs — das neue Refresh-Token landet an der Zeile",
        _z_i5 is not None and a_i5.store.tresor.entschluesseln(_z_i5["refresh"]) == "rt-rotiert")
# (Mutationsproben: LDAP wieder an „@" statt am mail-Wert → V1 rot, V2 rot; Forward-Riegel wieder
#  name_ungueltig → V3 rot; Startbefund weg → V3b rot; Kennung trimmen → V4 rot; client_id-Vergleich
#  weg → I2 rot; „nicht magic" statt „passkey" → I3 rot; Fenster-Prüfung weg → I4 rot;
#  alt_verschluesselt weg → I5 rot.)

# ── Obergrenze ohne erfolgreiche Nachprüfung (PO-Entscheid 2026-09-25: 25 Stunden) ──────────
a_ob, _, c_ob = _oidc_mit_refresh("ob-konto")
_uid_ob = a_ob.store.get_user_by_name("ob-konto")["id"]
r.check("Obergrenze: Vorgabe 25 Stunden, Stand der Zeile beim Login gesetzt",
        a_ob.cfg.oidc_session_max_unverified_hours == 25
        and a_ob.store._one("SELECT erfolg_at FROM oidc_sitzung")["erfolg_at"] is not None)
a_ob.oidc.refresh = lambda rt, sub: ("ok", {"sub": sub}, {})
_vor_ob = int(_zeit.time()) - 2 * 3600
a_ob.store._exec("UPDATE oidc_sitzung SET geprueft_at = geprueft_at - 16 * 60, erfolg_at = ?", (_vor_ob,))
c_ob.get("/auth/me")
a_ob._oidc_ausgang.abwarten()
r.check("… ein Ja beim Tausch setzt den Stand neu",
        (a_ob.store._one("SELECT erfolg_at FROM oidc_sitzung")["erfolg_at"] or 0) > _vor_ob)
a_ob.oidc.refresh = lambda rt, sub: ("fehler", {}, {"error": "invalid_client"})
a_ob.store._exec("UPDATE oidc_sitzung SET erfolg_at = ?", (int(_zeit.time()) - 24 * 3600,))
r.check("… 24 Stunden ohne Ja: die Sitzung bleibt", c_ob.get("/auth/me").status_code == 200)
a_ob.store._exec("UPDATE oidc_sitzung SET erfolg_at = ?", (int(_zeit.time()) - 26 * 3600,))
_antw_ob = c_ob.get("/auth/me").status_code
r.check("… 26 Stunden ohne Ja: die Sitzung endet, mit Audit-Zeile — und das ist KEIN Nein für die Keys",
        _antw_ob == 401 and a_ob.store._one("SELECT COUNT(*) AS n FROM session")["n"] == 0
        and a_ob.store._one("SELECT 1 FROM audit WHERE event='oidc_unbestaetigt'") is not None
        and (a_ob.store.get_user(_uid_ob)["idp_bestaetigt_at"] or 0) > 0, f"HTTP {_antw_ob}")
a_ob0, _, c_ob0 = _oidc_mit_refresh("ob-aus", oidc_session_max_unverified_hours=0)
a_ob0.store._exec("UPDATE oidc_sitzung SET erfolg_at = 1000")
r.check("… oidc_session_max_unverified_hours=0 schaltet die Grenze ab", c_ob0.get("/auth/me").status_code == 200)
# (Mutationsproben: die Prüfung in `_oidc_nachpruefen` streichen → „26 Stunden" rot; `erfolg=True`
#  beim Tausch weg → „ein Ja setzt den Stand neu" rot; `_idp_nein` statt nur Löschen → Keys-Prüfung
#  rot.)

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
