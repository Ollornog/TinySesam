"""Härtung: Brute-Force-Lockout (pro User), Attempt-Tracking, Audit-Log, Panel-Settings."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, trusted_proxies=["127.0.0.1/32"]))
auth.ensure_admin("admin", "geheim123")

# Härtung schärfer stellen (wie im Admin-Panel) und persistent prüfen
auth.set_security("max_login_attempts", 3)
assert auth.sec("max_login_attempts") == 3

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)

# 3 Fehlversuche → danach gesperrt, auch mit RICHTIGEM Passwort
for i in range(3):
    assert c.post("/auth/login", data={"username": "admin", "password": "falsch"}).status_code == 401, i
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123"})
assert r.status_code == 429, f"nach Lockout erwartet 429, war {r.status_code}"
print("  ✓ Lockout nach 3 Fehlversuchen (blockt auch korrektes Passwort)")

fails = [a for a in auth.store.recent_audit(20) if a["event"] == "login_fail"]
assert len(fails) >= 3
print(f"  ✓ Audit-Log: {len(fails)}× login_fail")

# Entsperren (Admin) → Login wieder möglich + login-Audit
auth.store.clear_fails(username="admin")
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123"}, follow_redirects=False)
assert r.status_code == 303
assert any(a["event"] == "login" for a in auth.store.recent_audit(5))
print("  ✓ nach Entsperren Login OK + login-Audit")

# Settings-Roundtrip (Panel-editierbar)
auth.set_security("rate_limit_max", 99)
assert auth.sec("rate_limit_max") == 99 and auth.all_security()["rate_limit_max"] == 99
print("  ✓ Härtungs-Settings persistent + über all_security() lesbar")

# Trusted-Proxy: XFF nur von vertrauenswürdigem Peer
from tinysesam import security
class Req:  # Minimal-Fake
    def __init__(self, host, xff=None):
        self.client = type("C", (), {"host": host})()
        self.headers = {"x-forwarded-for": xff} if xff else {}
assert security.client_ip(Req("127.0.0.1", "9.9.9.9"), ["127.0.0.1/32"]) == "9.9.9.9"      # trusted Proxy → XFF gilt
assert security.client_ip(Req("8.8.8.8", "9.9.9.9"), ["127.0.0.1/32"]) == "8.8.8.8"        # untrusted Peer → XFF ignoriert
print("  ✓ echte Client-IP: XFF nur hinter vertrauenswürdigem Proxy")

# ---------- R4-10: /auth/password ist kein Passwort-Orakel ----------
# Angriff: Die Alt-Passwort-Prüfung dieser Route lief ohne rate_ok/is_locked/record_login UND
# löste das Konto über die Login-Kennung auf (`check_password(u["username"], …)` → find_user)
# statt über die ID der eigenen Sitzung. Wer ein Konto namens "chef@example.com" besitzt,
# während das Konto "chef" genau diese E-Mail trägt, riet darüber unbegrenzt und lautlos das
# Passwort des FREMDEN Kontos — kein 429, kein Fehlversuch, kein Protokolleintrag, und der
# Treffer setzte still das eigene Passwort (der Angriff blieb also auch im Erfolg unsichtbar).
AT = chr(64)          # keine Adresse im Klartext im Quelltext
def _mail(lokal): return lokal + AT + "example.com"

db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False))
auth2.set_security("max_login_attempts", 3)
# Der Passwortwechsel hat seinen EIGENEN Zähler mit eigener Schwelle — hier ebenfalls scharf
# gestellt, damit der Test beide Töpfe auseinanderhält (und die Vorgabe 5 nicht mitmisst).
auth2.set_security("password_change_max_attempts", 3)
# Die Drossel ist weiter oben gemessen; in diesem Block soll eine 429 BEWEISBAR aus der Sperre
# kommen und nicht aus dem Token-Bucket, sonst bewiese (d) unten das Gegenteil von dem, was
# dasteht (alle Anfragen kommen von derselben Test-IP).
auth2.set_security("rate_limit_max", 500)
app2 = FastAPI()
app2.include_router(auth2.router())
OPFER_PW = "Opfer-Passwort-2026"
ANG_PW = "Angreifer-Passwort-1"
uid_opfer = auth2.create_user("chef", OPFER_PW, email=_mail("chef"), is_admin=True)
# Die Kollision entsteht über den Store, also am Wächter vorbei — sie stellt damit eine
# Datenbank von VOR R4-12 dar (Altbestand). Seit R4-12 sperrt `create_user` die beiden
# Namensräume kreuzweise, eine neue Kollision kann über die API nicht mehr entstehen; eine
# bestehende wird aber nicht rückwirkend aufgelöst — genau dagegen schützt die ID-Prüfung hier.
uid_ang = auth2.store.create_user(_mail("chef"), email=_mail("eve"))
auth2.set_password(uid_ang, ANG_PW)

# Vorbedingung: Die Kennung des Angreifers zeigt tatsächlich auf das fremde Konto. Ohne sie
# liefe der Angriff ins Leere und der Test bewiese nichts.
assert auth2.find_user(_mail("chef"))["id"] == uid_opfer != uid_ang, "Angriffslage nicht hergestellt"

ang = TestClient(app2)
tok, _ = auth2.start_session(uid_ang, "password", remember=True)
ang.cookies.set(auth2.cfg.session_cookie, tok)

# (a) Das RICHTIGE Passwort des Opfers ist für diese Sitzung kein Treffer mehr.
r = ang.post("/auth/password", json={"current": OPFER_PW, "new": "neues-langes-passwort"})
assert r.status_code == 403, f"fremdes Passwort wurde akzeptiert: {r.status_code}"
assert auth2.check_password("chef", OPFER_PW) is not None, "Passwort des Opfers wurde verändert"
print("  ✓ /auth/password prüft die eigene Konto-ID, nicht die aufgelöste Login-Kennung")

# (b) Raten wird gedrosselt: spätestens nach password_change_max_attempts kommt 429 statt 403.
auth2.store.clear_fails(username=_mail("chef"))
GRENZE = auth2.sec("password_change_max_attempts")
codes = [ang.post("/auth/password", json={"current": f"falsch{i}", "new": "neues-langes-passwort"}).status_code
         for i in range(GRENZE + 2)]
assert 429 in codes, f"kein Lockout auf /auth/password: {codes}"
# Die Schwelle ist verdrahtet, nicht nur vorhanden: die erste 429 sitzt GENAU hinter ihr.
# (Mutationsprobe: `limit = self.sec("password_change_max_attempts") - 1` in
# `is_password_change_locked` → [403, 403, 429, 429, 429]. `429 in codes` hält dabei, diese
# Zeile fällt — deshalb steht sie hier.)
assert codes.index(429) == GRENZE, f"429 nicht nach {GRENZE} Fehlversuchen: {codes}"
assert auth2.store.count_fails(0, username=_mail("chef"), method="password_change") >= GRENZE, \
    "Fehlversuche wurden nicht verbucht"
assert any(a["event"] == "login_fail" and "password_change" in (a["detail"] or "")
           for a in auth2.store.recent_audit(20)), "kein Protokolleintrag zum Fehlversuch"
print("  ✓ Alt-Passwort-Raten läuft in Sperre + Protokoll (429, login_attempt, Audit-Log)")

# (c) Der legitime Weg funktioniert weiter — mit dem EIGENEN Passwort.
auth2.store.clear_fails(username=_mail("chef"))
r = ang.post("/auth/password", json={"current": ANG_PW, "new": "neues-langes-passwort"})
assert r.status_code == 200, f"eigener Passwortwechsel scheitert: {r.status_code} {r.text[:120]}"
assert auth2.verify_user_password(uid_ang, "neues-langes-passwort"), "neues Passwort nicht gesetzt"
assert auth2.check_password("chef", OPFER_PW) is not None, "fremdes Konto angefasst"
print("  ✓ eigener Passwortwechsel unverändert möglich")

# (d) Regression: Der Zähler ist METHODENGEBUNDEN. Fehlversuche beim Passwortwechsel sind kein
# Anmeldeversuch und dürfen den Login nicht sperren. Mit dem geteilten Topf sperrten drei
# Tippfehler auf der eigenen Kontoseite die Anmeldung für `lockout_window_sec` — und zwar ohne
# Ausweg: Auch der Passwortwechsel war dann zu, und ein Erfolg räumt nur die Fehlversuche
# DERSELBEN Methode weg. (Mutationsprobe: `exclude_methods` in `is_locked` entfernen → beide
# folgenden Zeilen fallen, `is_locked` True und Login 429.)
ANNA_PW = "Anna-Passwort-2026"
uid_anna = auth2.create_user("anna", ANNA_PW)
anna = TestClient(app2)
tok_anna, _ = auth2.start_session(uid_anna, "password", remember=True)
anna.cookies.set(auth2.cfg.session_cookie, tok_anna)
for i in range(GRENZE + 1):
    anna.post("/auth/password", json={"current": f"vertippt{i}", "new": "neues-langes-passwort"})
assert auth2.store.count_fails(0, username="anna", method="password_change") >= GRENZE, \
    "Tippfehler wurden nicht verbucht — der Test messe nichts"
assert not auth2.is_locked("anna", "testclient"), "Tippfehler am Passwortwechsel sperren den Login"
frisch = TestClient(app2)
r = frisch.post("/auth/login", data={"username": "anna", "password": ANNA_PW}, follow_redirects=False)
assert r.status_code == 303, f"Login nach Tippfehlern am Passwortwechsel gesperrt: {r.status_code}"
assert auth2.cfg.session_cookie in frisch.cookies, "keine Sitzung nach dem Login"
print("  ✓ Tippfehler beim Passwortwechsel sperren die Anmeldung nicht (eigener Zähler)")

# (e) Die Sperre gilt trotzdem — dort, wo geraten wurde: Annas Passwortwechsel bleibt zu, auch
# mit dem RICHTIGEN alten Passwort. Sie ist abtragbar (Admin-Weg, wie `python -m tinysesam unlock`).
r = anna.post("/auth/password", json={"current": ANNA_PW, "new": "neues-langes-passwort"})
assert r.status_code == 429, f"Sperre am Passwortwechsel greift nicht: {r.status_code}"
auth2.store.clear_fails(username="anna")
r = anna.post("/auth/password", json={"current": ANNA_PW, "new": "neues-langes-passwort"})
assert r.status_code == 200, f"Passwortwechsel nach Entsperren scheitert: {r.status_code} {r.text[:120]}"
print("  ✓ Sperre greift am Passwortwechsel selbst und ist entsperrbar")

# (f) Regression, NAT-Verstärkung: Die IP-Schwelle des Logins
# (`max_login_attempts * ip_attempt_factor`) zählte ebenfalls methodenblind. Damit genügten
# mehrere vertippte Kollegen hinter demselben Anschluss, um einem völlig UNBETEILIGTEN Vierten
# den Login zu verriegeln. Die Fehlversuche kommen hier alle von derselben Test-IP — genau die
# Lage eines Büros hinter NAT. (Mutationsprobe: `exclude_methods` im IP-Zweig von `is_locked`
# entfernen → `is_locked("unbeteiligt", …)` wird True und der Login des Dritten 429.)
IP_GRENZE = auth2.sec("max_login_attempts") * auth2.sec("ip_attempt_factor")
assert auth2.store.count_fails(0, ip="testclient", method="password_change") == 0, \
    "Vorbedingung: die Test-IP startet ohne Fehlversuche am Passwortwechsel"
for n in range(1, 9):
    if auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_GRENZE:
        break
    uid = auth2.create_user(f"kollege{n}", "Kollegen-Passwort-1")
    kollege = TestClient(app2)
    t, _ = auth2.start_session(uid, "password", remember=True)
    kollege.cookies.set(auth2.cfg.session_cookie, t)
    for _ in range(GRENZE):
        kollege.post("/auth/password", json={"current": "vertippt", "new": "neues-langes-passwort"})
# Die IP-Schwelle des LOGINS ist erreicht — mit dem methodenblinden Zähler wäre ab hier jeder
# Login von dieser IP gesperrt, auch der eines Kontos, das nie etwas falsch gemacht hat.
assert auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_GRENZE, \
    "Angriffslage nicht hergestellt: die Test-IP hat die Login-IP-Schwelle nicht erreicht"
auth2.create_user("unbeteiligt", "Dritte-Passwort-1")
assert not auth2.is_locked("unbeteiligt", "testclient"), \
    "vertippte Kollegen hinter NAT sperren einen Unbeteiligten aus"
dritter = TestClient(app2)
r = dritter.post("/auth/login", data={"username": "unbeteiligt", "password": "Dritte-Passwort-1"},
                 follow_redirects=False)
assert r.status_code == 303, f"Login des Unbeteiligten gesperrt: {r.status_code}"
print("  ✓ keine NAT-Verstärkung: vertippte Kollegen sperren Unbeteiligte nicht aus")

# (g) Nacharbeit zur zweiten Runde: Der eigene Topf trug die IP-Dimension zunächst mit
# (`limit * ip_attempt_factor`). Damit verriegelten drei vertippte Kollegen dem vierten seinen
# EIGENEN Passwortwechsel — dieselbe Kollateralsperre, nur eine Ebene tiefer, und gegen einen,
# der nichts falsch eingegeben hat. Auf `main` gab es diese Sperre gar nicht. Sie fehlt auch
# nicht: Wer hier rät, braucht bereits eine gültige Sitzung DIESES Kontos.
# (Mutationsprobe: `ip_faktor=self.sec("ip_attempt_factor")` an `is_password_change_locked`
# zurückgeben → diese drei Zeilen fallen, der Vierte bekommt 429.)
assert auth2.store.count_fails(0, ip="testclient", method="password_change") >= IP_GRENZE, \
    "Vorbedingung: die Test-IP hat die IP-Schwelle des Logins längst überschritten"
uid_vierter = auth2.create_user("vierter", "Vierte-Passwort-1")
vierter = TestClient(app2)
t4, _ = auth2.start_session(uid_vierter, "password", remember=True)
vierter.cookies.set(auth2.cfg.session_cookie, t4)
assert not auth2.is_password_change_locked("vierter", "testclient"), \
    "vertippte Kollegen sperren dem Unbeteiligten den eigenen Passwortwechsel"
r = vierter.post("/auth/password", json={"current": "Vierte-Passwort-1", "new": "neues-langes-passwort"})
assert r.status_code == 200, f"Passwortwechsel des Unbeteiligten gesperrt: {r.status_code} {r.text[:120]}"
print("  ✓ der eigene Topf sperrt pro Konto, nicht pro Anschluss (kein NAT-Kollateral)")

# ---------- R4-10/Runde 2: Die Ausnahmeliste ist vollständig — und jede Ausnahme hat eine Bremse ----------
# Der erste Anlauf nahm nur `password_change` aus dem Login-Lockout. `record_login()` wird im
# Router aber auch mit `reauth` (Step-up-Bestätigung) und `resource` (Bereichs-PIN ohne Konto)
# gerufen: Fünf Tippfehler an der Reauth-Seite sperrten die Anmeldung desselben Kontos, und
# drei Bereiche à fünf Fehlgriffe erreichten über `ip_attempt_factor` die Login-IP-Schwelle und
# verriegelten die Anmeldung wildfremder Konten. Niemand merkte es, weil kein Test den INHALT
# der Liste gegen die Wirklichkeit hielt. Genau das tun die folgenden drei Prüfungen.
import ast                                                                      # noqa: E402
from pathlib import Path                                                        # noqa: E402
from tinysesam import security as _sec                                          # noqa: E402

QUELLEN = sorted((Path(__file__).resolve().parent.parent / "tinysesam").glob("*.py"))
ECHTE_ANMELDUNG = {"password", "pin", "totp"}     # bewusst hier gepflegt, nicht abgeleitet


def _record_login_methoden(pfad: Path) -> set:
    """Mit welchen Methoden ruft dieser Modul-Quelltext `record_login()`? (AST, nicht grep:
    ein Docstring, der die Zeile zitiert, ist kein Aufruf.)"""
    baum = ast.parse(pfad.read_text(encoding="utf-8"))
    gefunden = set()
    for knoten in ast.walk(baum):
        if not (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Attribute)):
            continue
        if knoten.func.attr != "record_login":
            continue
        arg = knoten.args[3] if len(knoten.args) > 3 else None
        for kw in knoten.keywords:
            if kw.arg == "method":
                arg = kw.value
        if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
            gefunden.add(arg.value)
        else:
            gefunden.add(f"<nicht-konstant in {pfad.name}:{knoten.lineno}>")
    return gefunden


benutzt = set().union(*(_record_login_methoden(q) for q in QUELLEN))
assert "password" in benutzt and "reauth" in benutzt and "resource" in benutzt, \
    f"der Sammler findet die bekannten Aufrufstellen nicht mehr: {sorted(benutzt)}"
unbekannt = benutzt - ECHTE_ANMELDUNG - set(_sec.NICHT_LOGIN_METHODEN)
assert not unbekannt, (f"neue record_login-Methode(n) {sorted(unbekannt)}: entweder ein echter "
                       "Anmeldeversuch (dann oben in ECHTE_ANMELDUNG eintragen) oder keiner "
                       "(dann in security.EIGENE_SPERRE — mit eigenem Topf)")
print(f"  ✓ jede record_login-Methode ist eingeordnet ({len(benutzt)} gefunden, AST über tinysesam/)")

# Kein Eintrag ohne Bremse: Eine Methode aus dem Login-Lockout zu nehmen, ohne ihr einen
# eigenen Topf zu geben, hiesse, sie unbegrenzt ratbar zu machen.
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
auth3 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db3, cookie_secure=False,
                                  passkey_enabled=False, oidc_enabled=False))
for _m in _sec.NICHT_LOGIN_METHODEN:
    riegel = getattr(auth3, _sec.EIGENE_SPERRE[_m], None)
    assert callable(riegel), f"{_m} steht in NICHT_LOGIN_METHODEN, hat aber keinen eigenen Topf"
    name = f"probant-{_m}"
    for _ in range(20):
        auth3.record_login(name, "198.51.100.4", False, _m)
    assert not auth3.is_locked(name, "198.51.100.4"), \
        f"Fehlversuche mit method={_m} sperren die Anmeldung (weder Anmeldung noch Ausnahme?)"
    assert riegel(name, "198.51.100.4"), \
        f"method={_m} ist aus dem Login-Lockout genommen, aber {_sec.EIGENE_SPERRE[_m]} bremst nicht"
print(f"  ✓ jede Nicht-Login-Methode hat eine eigene Bremse ({', '.join(_sec.NICHT_LOGIN_METHODEN)})")

# Und die Töpfe sind getrennt: Der eine füllt den anderen nicht.
for _m in _sec.NICHT_LOGIN_METHODEN:
    for _anderer in _sec.NICHT_LOGIN_METHODEN:
        if _anderer == _m:
            continue
        assert not getattr(auth3, _sec.EIGENE_SPERRE[_anderer])(f"probant-{_m}", None), \
            f"Fehlversuche mit method={_m} sperren auch {_anderer}"
print("  ✓ die Töpfe sind gegeneinander dicht (Fehlgriff der einen Methode sperrt die andere nicht)")
os.remove(db3)


# ---------- T-13: Sperren atomar (R7-2, R3-2, R3-7) ----------
# Zwischen `is_locked()` und `record_login()` lag die ganze Prüfung. Eine parallele Salve las
# N-mal „noch nicht gesperrt" und durfte N-mal raten. Die Probe verlangsamt die Prüfung künstlich
# (sonst gewinnt der Zufall) und schickt zwölf Anfragen gleichzeitig: Mehr als die Grenze darf
# nicht bis zur Prüfung durchkommen. (Mutationsprobe: in `login_submit` wieder
# `is_locked()` + `record_login()` ohne `versuch` → alle zwölf kommen durch.)
import threading                                                                # noqa: E402
import time as _time                                                            # noqa: E402
from concurrent.futures import ThreadPoolExecutor                               # noqa: E402
import pyotp                                                                    # noqa: E402


def _salve(anzahl, aufruf):
    """`anzahl` Aufrufe gleichzeitig loslassen (Barriere), Statuscodes zurück."""
    start = threading.Barrier(anzahl)

    def eins(i):
        start.wait(timeout=10)
        return aufruf(i)
    with ThreadPoolExecutor(max_workers=anzahl) as pool:
        return sorted(pool.map(eins, range(anzahl)))


def _langsam(obj, name, sek=0.25):
    echt = getattr(obj, name)

    def bremse(*a, **k):
        _time.sleep(sek)
        return echt(*a, **k)
    setattr(obj, name, bremse)


db_t = os.path.join(tempfile.mkdtemp(), "t.db")
auth_t = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_t, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                   pin_login=True))
auth_t.set_security("max_login_attempts", 3)
auth_t.set_security("pin_max_attempts", 3)
auth_t.set_security("rate_limit_max", 1000)
uid_t = auth_t.create_user("toni", "Toni-Passwort-2026")
auth_t.set_pin(uid_t, "13579")
app_t = FastAPI()
app_t.include_router(auth_t.router())

# (1) Passwort-Login (R7-2)
_langsam(auth_t, "check_password")
codes = _salve(12, lambda i: TestClient(app_t).post(
    "/auth/login", data={"username": "toni", "password": f"falsch{i}"}).status_code)
assert codes.count(401) <= 3, f"R7-2: {codes.count(401)} von 12 parallelen Versuchen durften raten: {codes}"
assert codes.count(429) >= 9, codes
print(f"  ✓ R7-2: parallele Salve am Login — {codes.count(401)} geprüft, {codes.count(429)} gesperrt")
auth_t.store.clear_fails(username="toni")

# (1b) Zählen und Buchen sind EIN Schritt, nicht bloss dicht hintereinander: Hier wird das
# Zählen selbst verlangsamt. Wer zählt und danach getrennt bucht, lässt die Salve wieder durch.
# (Mutationsprobe: `versuch_beginnen` zählt per `count_fails` und bucht danach mit eigenem
# INSERT → rot.)
del auth_t.check_password                         # wieder die echte Prüfung
_langsam(auth_t.store, "_fails_abfrage", 0.05)
codes = _salve(12, lambda i: TestClient(app_t).post(
    "/auth/login", data={"username": "toni", "password": f"falsch{i}"}).status_code)
assert codes.count(401) <= 3, f"Zählen und Buchen sind getrennte Schritte: {codes.count(401)} von 12 durch"
del auth_t.store._fails_abfrage
print(f"  ✓ …Zählen und Buchen in einer Transaktion ({codes.count(401)} geprüft, {codes.count(429)} gesperrt)")
auth_t.store.clear_fails(username="toni")

# (2) PIN-Login (R3-7) — der kurze Schlüsselraum ist das eigentliche Ziel
_langsam(auth_t, "check_pin")
codes = _salve(12, lambda i: TestClient(app_t).post(
    "/auth/pin", data={"username": "toni", "pin": f"{i:04d}"}).status_code)
assert codes.count(401) <= 3, f"R3-7: {codes.count(401)} von 12 parallelen PIN-Versuchen durften raten: {codes}"
print(f"  ✓ R3-7: parallele Salve an der PIN — {codes.count(401)} geprüft, {codes.count(429)} gesperrt")
auth_t.store.clear_fails(username="toni")

# (3) TOTP-Schritt (R3-2) — mit bekanntem Passwort, gleiche halbe Sitzung für alle
geheim_t = auth_t.totp_begin(uid_t)["secret"]
auth_t.totp_confirm(uid_t, pyotp.TOTP(geheim_t).now())
c_t = TestClient(app_t)
assert c_t.post("/auth/login", data={"username": "toni", "password": "Toni-Passwort-2026"},
                follow_redirects=False).status_code == 303
halb = c_t.cookies.get(auth_t.cfg.session_cookie)
_langsam(auth_t, "verify_totp")


def _totp(i):
    ci = TestClient(app_t)
    ci.cookies.set(auth_t.cfg.session_cookie, halb)
    return ci.post("/auth/totp", data={"code": "000000"}).status_code


codes = _salve(12, _totp)
assert codes.count(401) <= 3, f"R3-2: {codes.count(401)} von 12 parallelen TOTP-Versuchen durften raten: {codes}"
print(f"  ✓ R3-2: parallele Salve am TOTP-Schritt — {codes.count(401)} geprüft, {codes.count(429)} gesperrt")
os.remove(db_t)

# ---------- R7-6 / H-8: Konto UND Adresse, nicht Konto allein ----------
# Bis T-13 sperrten fünf Fehlversuche von IRGENDWO das Konto für alle — jeder, der einen
# Benutzernamen kannte, verriegelte dessen Inhaber für ein Fenster, samt richtigem Passwort.
# Jetzt stoppt die erste Schwelle das Paar aus Konto und Adresse; das Konto allein geht erst beim
# `account_attempt_factor`-fachen zu, also erst, wenn mehrere Anschlüsse raten.
# (Mutationsprobe: in `_regeln` die Paar-Regel streichen und `lockout_account` auf
# `max_login_attempts` setzen → der Inhaber bekommt 429.)
db_f = os.path.join(tempfile.mkdtemp(), "t.db")
auth_f = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_f, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False))
auth_f.create_user("inhaber", "Inhaber-Passwort-1")
app_f = FastAPI()
app_f.include_router(auth_f.router())
G = auth_f.sec("max_login_attempts")
fremd = TestClient(app_f, client=("198.51.100.20", 40000))
codes = [fremd.post("/auth/login", data={"username": "inhaber", "password": "rate"}).status_code
         for _ in range(G + 1)]
assert codes == [401] * G + [429], codes
assert fremd.post("/auth/login", data={"username": "inhaber", "password": "Inhaber-Passwort-1"}
                  ).status_code == 429, "die Adresse des Fremden ist für dieses Konto nicht gesperrt"
inhaber = TestClient(app_f, client=("203.0.113.21", 40000))
r = inhaber.post("/auth/login", data={"username": "inhaber", "password": "Inhaber-Passwort-1"},
                 follow_redirects=False)
assert r.status_code == 303, f"R7-6: ein Fremder sperrt den Inhaber aus: {r.status_code}"
print("  ✓ R7-6/H-8: ein Fremder sperrt nur das Paar Konto+Adresse, nicht den Inhaber")
inhaber.get("/auth/logout")
# Die Konto-Schwelle bleibt gegen verteiltes Raten: Viele Anschlüsse zusammen sperren das Konto.
# (Der Login oben war vollständig und hat die Fehlversuche geräumt — R7-1 —, also neu zählen.)
for i in range(auth_f.sec("account_attempt_factor")):
    ci = TestClient(app_f, client=(f"198.51.100.{30 + i}", 40000))
    for _ in range(G):
        ci.post("/auth/login", data={"username": "inhaber", "password": "rate"})
r = inhaber.post("/auth/login", data={"username": "inhaber", "password": "Inhaber-Passwort-1"})
assert r.status_code == 429, f"verteiltes Raten über viele Adressen bleibt unbegrenzt: {r.status_code}"
print("  ✓ …die Konto-Schwelle greift weiter, wenn viele Adressen zusammen raten")
os.remove(db_f)

# ---------- R7-1: Der Lockout zählt methodenblind — also räumt eine volle Anmeldung auch so ----------
# Passwort, PIN und TOTP füllen denselben Topf; ein Erfolg räumte bis T-13 nur die eigene
# Methode. Wer nach zwei vertippten Passwörtern per PIN VOLLSTÄNDIG hineinkam, trug die zwei
# weiter mit sich. Ein Teil-Erfolg (Passwort vor einem TOTP-Schritt) räumt weiter NUR sich
# selbst — sonst wäre der zweite Faktor wieder ratbar. (Mutationsprobe: `sperre_aufheben` in
# `start_session` streichen → die erste Zusage fällt.)
db_m = os.path.join(tempfile.mkdtemp(), "t.db")
auth_m = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db_m, cookie_secure=False,
                                   passkey_enabled=False, oidc_enabled=False, pin_enabled=True,
                                   pin_login=True))
uid_m = auth_m.create_user("mia", "Mia-Passwort-2026")
auth_m.set_pin(uid_m, "24680")
app_m = FastAPI()
app_m.include_router(auth_m.router())
c_m = TestClient(app_m)
for _ in range(2):
    c_m.post("/auth/login", data={"username": "mia", "password": "vertippt"})
auth_m.record_login("mia", "testclient", False, "password_change")   # eigener Topf, bleibt
assert c_m.post("/auth/pin", data={"username": "mia", "pin": "24680"},
                follow_redirects=False).status_code == 303
assert auth_m.store.count_fails(0, username="mia", method="password") == 0, \
    "R7-1: eine vollständige Anmeldung lässt die Fehlversuche der anderen Methoden stehen"
assert auth_m.store.count_fails(0, username="mia", method="password_change") == 1, \
    "die volle Anmeldung räumt auch die eigenen Töpfe (Kontoseite) — das gehört nicht dazu"
print("  ✓ R7-1: eine vollständige Anmeldung räumt alle Anmelde-Töpfe, nicht die eigenen")
c_m.get("/auth/logout")
# Teil-Erfolg: Passwort gelingt, TOTP steht noch aus → die TOTP-Fehlversuche bleiben.
geheim_m = auth_m.totp_begin(uid_m)["secret"]
auth_m.totp_confirm(uid_m, pyotp.TOTP(geheim_m).now())
auth_m.record_login("mia", "testclient", False, "totp")
assert c_m.post("/auth/login", data={"username": "mia", "password": "Mia-Passwort-2026"},
                follow_redirects=False).status_code == 303
assert auth_m.store.count_fails(0, username="mia", method="totp") == 1, \
    "ein halber Login räumt die Fehlversuche des zweiten Faktors — TOTP wird wieder ratbar"
print("  ✓ …ein halber Login (TOTP ausstehend) räumt den zweiten Faktor nicht")
os.remove(db_m)

os.remove(db2)

os.remove(db)
print("\nHÄRTUNG OK ✅")
