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

os.remove(db2)

os.remove(db)
print("\nHÄRTUNG OK ✅")
