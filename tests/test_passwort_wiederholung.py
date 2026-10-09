"""Dasselbe falsche Passwort zählt nur einmal (0.24.9, `password_repeat_memory`).

PO 2026-10-09: „gleiches passwort 10 mal eintippen ist wohl weniger ein hack versuch.“ Ein Handy mit altem Passwort
fragt im Takt immer wieder mit demselben Wert an — bisher sperrte es nach fünf Anläufen Konto und Heim-IP, und fail2ban
bannte die IP obendrein. Jetzt:

  (a) zehnmal dasselbe falsche Passwort von derselben IP: ein Fehlversuch, neunmal `repeated login`, keine Sperre,
      das richtige Passwort kommt danach durch, die Antwort bleibt jedes Mal dieselbe 401
  (b) sechs VERSCHIEDENE falsche Passwörter sperren wie bisher (Gegenprobe)
  (c) dieselbe Wiederholung von einer anderen IP zählt dort einmal neu
  (d) `password_repeat_memory=0` schaltet es ab — dann sperrt die Wiederholung wie früher
  (e) gemerkt werden nur N Fingerabdrücke: wer N+1 Passwörter im Kreis schickt, zählt jedes Mal
  (f) Sicherheits-Log: `WARNING failed login` nur für den ersten, `INFO repeated login` danach, `INFO login ok` beim
      Erfolg — und nur die erste Zeile trifft die mitgelieferte failregex
  (g) im Speicher steht kein Passwort, nur 8-Byte-Fingerabdrücke
"""
from __future__ import annotations

import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

PW = "Richtiges-Pw-2026"
ALT = "altes-passwort-2025"
IP_A = ("203.0.113.9", 50000)
IP_B = ("198.51.100.4", 50000)


def ok(text):
    print(f"  ok   {text}")


def _app(**haertung):
    d = tempfile.mkdtemp()
    log = os.path.join(d, "security.log")
    auth = TinySesam(TinySesamConfig(db_path=os.path.join(d, "t.db"), cookie_secure=False, csrf_enabled=False,
                                     base_url="http://testserver", lang="de", passkey_enabled=False,
                                     security_log=log))
    for k, v in {"rate_limit_max": 100000, **haertung}.items():
        auth.set_security(k, v)
    auth.create_user("anna", PW)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, log


def _login(app, pw, ip=IP_A):
    return TestClient(app, client=ip).post("/auth/login", data={"username": "anna", "password": pw, "next": "/"},
                                           follow_redirects=False)


def _zeilen(log, wort):
    with open(log, encoding="utf-8") as fh:
        return [z for z in fh.read().splitlines() if f" {wort} " in z]


def _audit(auth, ereignis):
    """`login_fail` = gezählte Fehlversuche, `login_repeat` = Wiederholungen (Audit `login_fail … grund=wiederholt`)."""
    alle = [e for e in auth.store.recent_audit(limit=500) if e["event"] == "login_fail"]
    wdh = [e for e in alle if "grund=wiederholt" in (e["detail"] or "")]
    return wdh if ereignis == "login_repeat" else [e for e in alle if e not in wdh]


print("Passwort-Wiederholung")

# (a) + (f)
auth, app, log = _app()
antworten = [_login(app, ALT) for _ in range(10)]
assert all(r.status_code == antworten[0].status_code for r in antworten), [r.status_code for r in antworten]
assert antworten[0].status_code in (200, 401), antworten[0].status_code
assert len({re.sub(r"[A-Za-z0-9_-]{20,}", "", r.text) for r in antworten}) == 1, "die Antwort auf eine Wiederholung unterscheidet sich vom ersten Fehlversuch"
ok("zehnmal dasselbe falsche Passwort: jedes Mal dieselbe Antwort (bis auf Nonce)")
assert len(_audit(auth, "login_fail")) == 1 and len(_audit(auth, "login_repeat")) == 9
ok("Audit: zehnmal login_fail, davon neun mit grund=wiederholt")
r = _login(app, PW)
assert r.status_code in (302, 303) and "set-cookie" in r.headers, (r.status_code, r.text[:200])
ok("danach kommt das richtige Passwort durch — keine Sperre (Fenster 5)")
assert len(_zeilen(log, "failed login")) == 1 and len(_zeilen(log, "repeated login")) == 9
assert len(_zeilen(log, "login ok")) == 1, _zeilen(log, "login ok")
FAILREGEX = re.compile(r"^\s*WARNING failed login user=.* ip=(?P<host>\S+) method=\S+(?: reason=\S+)?$")
with open(ROOT / "deploy" / "fail2ban" / "tinysesam-filter.conf", encoding="utf-8") as fh:
    assert "WARNING failed login user=.* ip=<HOST>" in fh.read()
with open(log, encoding="utf-8") as fh:
    treffer = [z for z in fh.read().splitlines() if FAILREGEX.match(z.split(" ", 2)[2])]
assert len(treffer) == 1, treffer
ok("Sicherheits-Log: 1× failed login, 9× repeated login, 1× login ok — nur der erste trifft die failregex")

# (g)
roh = repr(auth._pw_wiederholung)
assert ALT not in roh and PW not in roh
assert all(len(f) == 8 for liste in auth._pw_wiederholung.values() for f, _ in liste)
ok("im Speicher stehen 8-Byte-Fingerabdrücke, kein Passwort")

# (b) Gegenprobe
auth, app, log = _app()
for i in range(6):
    _login(app, f"falsch-{i}-xxxxxxxx")
r = _login(app, PW)
assert not (r.status_code in (302, 303) and "set-cookie" in r.headers), r.status_code
ok("sechs verschiedene falsche Passwörter sperren wie bisher")

# (c) andere IP zählt neu, aber auch dort nur einmal
auth, app, log = _app()
for _ in range(3):
    _login(app, ALT, IP_A)
    _login(app, ALT, IP_B)
assert len(_audit(auth, "login_fail")) == 2 and len(_audit(auth, "login_repeat")) == 4
ok("je IP einmal: zwei Fehlversuche, vier Wiederholungen")

# (d) abgeschaltet
auth, app, log = _app(password_repeat_memory=0)
for _ in range(6):
    _login(app, ALT)
assert len(_audit(auth, "login_fail")) >= 5 and not _audit(auth, "login_repeat")
r = _login(app, PW)
assert not (r.status_code in (302, 303) and "set-cookie" in r.headers), r.status_code
ok("password_repeat_memory=0: jede Wiederholung zählt, die Sperre greift")

# (e) Kreis aus N+1 Passwörtern
auth, app, log = _app(password_repeat_memory=2, max_login_attempts=20)
for _runde in range(2):
    for i in range(3):
        _login(app, f"kreis-{i}-xxxxxxxx")
assert len(_audit(auth, "login_fail")) == 6 and not _audit(auth, "login_repeat"), (
    len(_audit(auth, "login_fail")), len(_audit(auth, "login_repeat")))
ok("drei Passwörter im Kreis bei Gedächtnis 2: jedes zählt")

print("Passwort-Wiederholung OK")
