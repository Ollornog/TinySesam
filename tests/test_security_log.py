"""security_log: der fail2ban-Logger schreibt in die Datei, auf die die mitgelieferte Jail zeigt.

Ohne dieses Feld musste man den Handler von Hand verdrahten — die Jail in deploy/fail2ban/ zeigte
auf eine Datei, die nie entstand, und lief still ins Leere.
"""
import os
import re
import tempfile

from tinysesam import TinySesam, TinySesamConfig, security


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

_abraeumen()
for f in (db, db2, db3):
    if os.path.exists(f):
        os.remove(f)
os.remove(logdatei)
os.rmdir(tmp)
print("\nSECURITY-LOG OK ✅")
