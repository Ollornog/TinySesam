"""security_log: der fail2ban-Logger schreibt in die Datei, auf die die mitgelieferte Jail zeigt.

Ohne dieses Feld musste man den Handler von Hand verdrahten — die Jail in deploy/fail2ban/ zeigte
auf eine Datei, die nie entstand, und lief still ins Leere.
"""
import contextlib
import io
import logging
import os
import re
import stat
import tempfile

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, security
from tinysesam.errors import ConfigError


def ok(name):
    print(f"  ✓ {name}")


def _abraeumen():
    for h in list(security.seclog.handlers):
        if getattr(h, "_tinysesam_path", None):
            security.seclog.removeHandler(h)
            h.close()


_abraeumen()
tmp = tempfile.mkdtemp()
logdatei = os.path.join(tmp, "security.log")
db = os.path.join(tempfile.mkdtemp(), "t.db")

auth = TinySesam(TinySesamConfig(db_path=db, security_log=logdatei, cookie_secure=False,
                                 passkey_enabled=False, csrf_enabled=False))
auth.create_user("anna", "geheim123")
assert os.path.exists(logdatei)
ok("security_log gesetzt → Datei wird angelegt")

# ein Fehlversuch — genau die Zeile, die deploy/fail2ban/tinysesam-filter.conf matcht
auth.check_password("anna", "falsch")
auth.record_login("anna", "203.0.113.7", False, "password")
with open(logdatei, encoding="utf-8") as fh:
    inhalt = fh.read()
assert "failed login user=anna ip=203.0.113.7" in inhalt, inhalt
ok("Fehlversuch landet in der Datei")

muster = re.compile(r"failed login user=.* ip=(?P<host>\S+) method=.*")   # = failregex der Jail
zeile = [z for z in inhalt.splitlines() if "failed login" in z][0]
assert muster.search(zeile).group("host") == "203.0.113.7"
assert re.match(r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}", zeile), zeile
ok("Zeile passt zum failregex der Jail und trägt den Zeitstempel vorn (fail2ban datiert danach)")

# zweite Instanz auf denselben Pfad darf nicht doppelt schreiben
vorher = len([h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None) == logdatei])
security.attach_security_log(logdatei)
nachher = len([h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None) == logdatei])
assert vorher == nachher == 1
ok("idempotent: derselbe Pfad wird nicht zweimal angehängt")

# nicht schreibbarer Pfad: warnen, aber weiterlaufen — eine Logdatei legt keine Anmeldung still
assert security.attach_security_log(os.path.join(tmp, "gibtsnicht", "x.log")) is False
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
TinySesam(TinySesamConfig(db_path=db2, security_log="/proc/darf/ich/nicht.log",
                          cookie_secure=False, passkey_enabled=False))
ok("nicht schreibbarer Pfad → False + Warnung, Start läuft weiter")

# ohne security_log bleibt alles wie bisher: kein Datei-Handler
_abraeumen()
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
TinySesam(TinySesamConfig(db_path=db3, cookie_secure=False, passkey_enabled=False))
assert not [h for h in security.seclog.handlers if getattr(h, "_tinysesam_path", None)]
ok("ohne security_log kein Handler (wer sein Logging selbst einrichtet, behält es)")

# ---------------------------------------------------------------------------
# B5-03: Das Erst-Admin-Einmal-Token darf NICHT in dieser Datei stehen.
#
# Bis 0.18.x schrieb der Konstruktor "…/auth/claim-admin?token=<wert>…" über seclog — also
# genau in die Datei, auf die die mitgelieferte fail2ban-Jail zeigt, die logrotate archiviert
# und die (gemessen) mit -rw-rw-r-- entstand. Wer sie lesen konnte und irgendein Konto auf der
# Instanz hatte, wurde damit Admin.
# ---------------------------------------------------------------------------
_abraeumen()
alte_maske = os.umask(0o000)          # der Fall, in dem die Datei vorher welt-lesbar entstand
try:
    tmp2 = tempfile.mkdtemp()
    log2 = os.path.join(tmp2, "security.log")
    db4 = os.path.join(tmp2, "t.db")
    stderr = io.StringIO()
    with contextlib.redirect_stderr(stderr):
        auth2 = TinySesam(TinySesamConfig(db_path=db4, security_log=log2, cookie_secure=False,
                                          passkey_enabled=False, allow_signup=True,
                                          signup_require_email=False))
    inhalt2 = open(log2, encoding="utf-8").read()

    # Vorbedingung: Es GIBT ein Token zu verraten. Ohne diese Prüfung wäre alles Folgende auch
    # dann grün, wenn der Bootstrap-Weg schlicht abgeschaltet wäre — der Test misst dann nichts.
    token = auth2.admin_claim_token()
    assert token and len(token) >= 20, token
    assert "Kein Admin vorhanden" in inhalt2, inhalt2      # die Zeile wird weiterhin geschrieben
    ok("Vorbedingung: ohne Admin entsteht ein Einmal-Token und das Log meldet die Lage")

    # Der Angriff: der PoC las den Wert mit genau diesem Muster aus der Logdatei.
    assert not re.search(r"claim-admin\?token=(\S+)", inhalt2), inhalt2
    assert token not in inhalt2, inhalt2
    ok("B5-03: der Tokenwert steht NICHT in der Datei, die fail2ban liest")

    assert "stderr" in inhalt2 and "NICHT im Log" in inhalt2, inhalt2
    ok("das Log nennt nur den Abrufweg, nicht den Wert")

    modus = stat.S_IMODE(os.stat(log2).st_mode)
    assert modus == 0o640, oct(modus)
    ok("die Logdatei entsteht mit 0640 statt mit der umask (nicht welt-lesbar)")

    # … und nach einer Rotation wieder: logrotate nimmt die Datei weg, der Handler legt sie neu an.
    os.remove(log2)
    security.seclog.warning("failed login user=b5 ip=203.0.113.9 method=password")
    assert stat.S_IMODE(os.stat(log2).st_mode) == 0o640, oct(stat.S_IMODE(os.stat(log2).st_mode))
    ok("auch die nach einer Rotation neu angelegte Datei trägt 0640")

    # Der legitime Weg 1: Wer den Dienst startet, sieht den Token auf der Konsole.
    assert f"/auth/claim-admin?token={token}" in stderr.getvalue(), stderr.getvalue()
    ok("legitimer Weg: der Betreiber bekommt den Token auf stderr")

    # Der legitime Weg 2: eine eigene Datei mit 0600 — und das Token wirkt dort weiterhin.
    _abraeumen()
    tmp3 = tempfile.mkdtemp()
    log3 = os.path.join(tmp3, "security.log")
    tokdatei = os.path.join(tmp3, "admin-claim.token")
    open(tokdatei, "w").close()                    # schon vorhanden und offen: Rechte müssen ziehen
    os.chmod(tokdatei, 0o666)
    db5 = os.path.join(tmp3, "t.db")
    with contextlib.redirect_stderr(io.StringIO()):
        auth3 = TinySesam(TinySesamConfig(db_path=db5, security_log=log3, cookie_secure=False,
                                          passkey_enabled=False, csrf_enabled=False,
                                          allow_signup=True, signup_require_email=False,
                                          admin_claim_token_file=tokdatei))
    tok3 = open(tokdatei, encoding="utf-8").read().strip()
    assert tok3 == auth3.admin_claim_token(), tok3
    assert stat.S_IMODE(os.stat(tokdatei).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(tokdatei).st_mode))
    assert tok3 not in open(log3, encoding="utf-8").read()
    assert tokdatei in open(log3, encoding="utf-8").read()      # der Pfad darf genannt werden
    ok("admin_claim_token_file: Wert in einer eigenen Datei mit 0600, Log nennt nur den Pfad")

    app = FastAPI()
    app.include_router(auth3.router())
    c = TestClient(app)
    r = c.post("/auth/register", data={"username": "betreiber", "password": "geheim123"},
               follow_redirects=False)
    assert r.status_code == 303, r.status_code
    r = c.get(f"/auth/claim-admin?token={tok3}", follow_redirects=False)
    assert r.status_code == 303, r.status_code
    assert auth3.store.get_user_by_name("betreiber")["is_admin"]
    ok("legitimer Weg bleibt heil: der Token aus der 0600-Datei macht den Erst-Admin")

    # Und die Datei darf nicht wieder das Log sein — sonst stünde der Wert genau dort.
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log3, admin_claim_token_file=log3,
                                  cookie_secure=False, passkey_enabled=False))
        raise AssertionError("admin_claim_token_file == security_log wurde angenommen")
    except ConfigError as e:
        assert "dieselbe Datei" in str(e), str(e)
    ok("Konfigurationsprüfung: admin_claim_token_file darf nicht das security_log sein")
finally:
    os.umask(alte_maske)

# ---------------------------------------------------------------------------
# Drei Zusagen aus demselben Fix, die bisher niemand gemessen hat (Nacharbeit zu B5-03):
# eine schon vorhandene welt-lesbare Datei wird GEMELDET, die Token-Datei wird vor dem
# Schreiben ABGESCHNITTEN, und eine Token-Datei ohne Token-Weg fällt der Konfigurationsprüfung
# auf. Jede dieser Zeilen liess sich zurückbauen, ohne dass eine Suite rot wurde.
# ---------------------------------------------------------------------------

# (1) Vorhandene Datei: nicht umschreiben (das wäre eine Entscheidung des Betreibers), aber sagen.
_abraeumen()
tmp5 = tempfile.mkdtemp()
log5 = os.path.join(tmp5, "security.log")
open(log5, "w").close()
os.chmod(log5, 0o666)                       # so entstand sie vor dem Fix: umask-abhängig, welt-lesbar
puffer5 = io.StringIO()
haken5 = logging.StreamHandler(puffer5)
security.seclog.addHandler(haken5)
try:
    assert security.attach_security_log(log5) is True
finally:
    security.seclog.removeHandler(haken5)
text5 = puffer5.getvalue()
assert "welt-lesbar" in text5, f"keine Meldung: {text5[:160]!r}"
assert log5 in text5 and "chmod 640" in text5, text5[:200]
assert stat.S_IMODE(os.stat(log5).st_mode) == 0o666, "die bestehende Datei wurde umgeschrieben"
ok("eine schon vorhandene welt-lesbare Logdatei wird gemeldet (und nicht umgeschrieben)")

# Gegenprobe: eine bereits enge Datei schweigt — sonst wäre die Warnung Rauschen, das niemand liest.
_abraeumen()
log5b = os.path.join(tmp5, "eng.log")
open(log5b, "w").close()
os.chmod(log5b, 0o640)
puffer5b = io.StringIO()
haken5b = logging.StreamHandler(puffer5b)
security.seclog.addHandler(haken5b)
try:
    security.attach_security_log(log5b)
finally:
    security.seclog.removeHandler(haken5b)
assert "welt-lesbar" not in puffer5b.getvalue(), puffer5b.getvalue()[:160]
ok("...eine bereits enge Datei meldet sich nicht")

# (2) Die Token-Datei wird vor dem Schreiben abgeschnitten. Ohne `os.ftruncate` bliebe der
#     Schwanz einer längeren Vorgängerdatei stehen — ein abgelaufenes Token, das noch aussieht
#     wie eines, und eine Datei, aus der nicht hervorgeht, welche Zeile gilt.
_abraeumen()
tmp6 = tempfile.mkdtemp()
tokdatei6 = os.path.join(tmp6, "admin-claim.token")
with open(tokdatei6, "w", encoding="utf-8") as fh:
    fh.write("ALTES-TOKEN-AUS-EINEM-FRUEHEREN-LAUF-VIEL-LAENGER-ALS-DAS-NEUE-0123456789\n")
os.chmod(tokdatei6, 0o600)
with contextlib.redirect_stderr(io.StringIO()):
    auth6 = TinySesam(TinySesamConfig(db_path=os.path.join(tmp6, "t.db"), cookie_secure=False,
                                      passkey_enabled=False, csrf_enabled=False,
                                      admin_claim_token_file=tokdatei6))
inhalt6 = open(tokdatei6, encoding="utf-8").read()
assert inhalt6 == auth6.admin_claim_token() + "\n", repr(inhalt6)
assert "ALTES-TOKEN" not in inhalt6, f"Rest der Vorgängerdatei: {inhalt6!r}"
ok("die Token-Datei wird abgeschnitten — kein Rest eines längeren Vorgängers")

# (3) Token-Datei gesetzt, Token-Weg aus: Die Datei entsteht nie. Ohne Warnung wartet der
#     Betreiber auf einen Token, der nicht kommt.
from tinysesam.konfigpruefung import pruefe                                    # noqa: E402

_gemeinsam7 = dict(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                   admin_claim_token_file=os.path.join(tmp6, "claim.token"))
for _lage, _cfg in (("admin_claim_ttl_min=0", TinySesamConfig(admin_claim_ttl_min=0, **_gemeinsam7)),
                    ("admin_enabled=False", TinySesamConfig(admin_enabled=False, **_gemeinsam7))):
    _f7, _w7 = pruefe(_cfg)
    assert any("admin_claim_token_file ist gesetzt" in w and "nie geschrieben" in w for w in _w7), \
        f"{_lage}: keine Warnung — {_w7!r}"
    assert not _f7, _f7
_f7, _w7 = pruefe(TinySesamConfig(**_gemeinsam7))          # Weg an → still
assert not any("admin_claim_token_file ist gesetzt" in w for w in _w7), _w7
ok("admin_claim_token_file ohne Token-Weg wird beim Aufbau gemeldet (mit Weg: still)")

_abraeumen()
for f in (db, db2, db3):
    if os.path.exists(f):
        os.remove(f)
os.remove(logdatei)
os.rmdir(tmp)
print("\nSECURITY-LOG OK ✅")
