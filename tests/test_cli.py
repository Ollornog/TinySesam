"""CLI: `version` und das Wartungskommando `passwd` (Passwort offline neu setzen).

Hintergrund: Mit einem Preset ohne Mailer (local_accounts) sind „Passwort vergessen" und
Magic-Link aus, und die Erst-Admin-Wege greifen nur, solange kein Admin existiert. Wer sein
Admin-Passwort verliert, hatte damit keinen dokumentierten Weg zurück.
"""
import io
import os
import sys
import tempfile
import contextlib

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.__main__ import main


def ok(name):
    print(f"  ✓ {name}")


def cli(*argv, stdin=None):
    """main() aufrufen, Ausgabe und Exit-Code einsammeln."""
    alt = sys.stdin
    if stdin is not None:
        sys.stdin = io.StringIO(stdin)
    aus, code = io.StringIO(), 0
    try:
        with contextlib.redirect_stdout(aus), contextlib.redirect_stderr(aus):
            main(list(argv))
    except SystemExit as e:
        code = e.code or 0
    finally:
        sys.stdin = alt
    return code, aus.getvalue()


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, passkey_enabled=False))
auth.create_user("admin", "altes-geheim", is_admin=True)
uid = auth.store.get_user_by_name("admin")["id"]

code, aus = cli("version")
assert code == 0 and aus.strip()
ok("version gibt die installierte Version aus")

code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin="neues-geheim\n")
assert code == 0, aus
assert auth.check_password("admin", "neues-geheim")
assert not auth.check_password("admin", "altes-geheim")
ok("passwd setzt das Passwort (der Weg zurück ohne Mailer und ohne zweiten Admin)")

# offene Sitzungen gelten nach einem Credential-Wechsel nicht weiter
tok = auth.store.create_session(uid, 3600, True, "password")
cli("passwd", "--db", db, "--stdin", "admin", stdin="noch-eins-geheim\n")
assert auth.store.get_session(tok) is None
ok("offene Sitzungen werden beendet (--keep-sessions lässt sie stehen)")

tok = auth.store.create_session(uid, 3600, True, "password")
cli("passwd", "--db", db, "--stdin", "--keep-sessions", "admin", stdin="und-noch-eins\n")
assert auth.store.get_session(tok) is not None
ok("--keep-sessions behält sie")

assert any(a["event"] == "password_reset_cli" for a in auth.store.recent_audit(50))
ok("der Eingriff steht im Audit-Log")

code, aus = cli("passwd", "--db", db, "--stdin", "gibtsnicht", stdin="egal-egal-egal\n")
assert code == 1 and "gibtsnicht" in aus
ok("unbekanntes Konto → Fehlermeldung, Exit 1")

code, aus = cli("passwd", "--db", db + ".fehlt", "--stdin", "admin", stdin="egal-egal-egal\n")
assert code == 1 and "Keine Datenbank" in aus
assert not os.path.exists(db + ".fehlt")     # sqlite legt sonst still eine leere Datei an
ok("falscher DB-Pfad → klare Meldung, keine leere Datenbank als Nebenwirkung")

code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin="kurz\n")
assert code == 1 and "zu kurz" in aus
assert auth.check_password("admin", "und-noch-eins")
ok("password_min_length gilt auch hier")

# Dieselbe Regel wie im Web (B2-5/B2-13): Blockliste, Benutzername, Höchstlänge.
for _schwach, _text in (("Passwort2026!", "leicht zu erraten"), ("admin-admin", "leicht zu erraten"),
                        ("y" * 257, "zu lang")):
    code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin=_schwach + "\n")
    assert code == 1 and _text in aus, (_schwach[:20], aus)
assert auth.check_password("admin", "und-noch-eins")
ok("passwd: Blockliste, Kontowort und Höchstlänge gelten auch offline")

# A-7: Die Betreiber-Blockliste und der Dienstname galten offline nicht — ein Passwort von der
# eigenen Liste liess sich per CLI setzen. Jetzt über dieselben Werte wie in der Config.
_liste = os.path.join(tempfile.mkdtemp(), "block.txt")
with open(_liste, "wb") as _f:
    _f.write(b"# Kommentar\nfirmengeheimnis\nsch\xf6nwetter99\n")   # zweite Zeile ist Latin-1
for _args, _pw in ((("--blocklist-file", _liste), "Firmengeheimnis2026!"),
                   (("--blocklist-file", _liste), "Schönwetter99"),
                   (("--rp-name", "Beispielportal"), "Beispielportal1!")):
    code, aus = cli("passwd", "--db", db, "--stdin", *_args, "admin", stdin=_pw + "\n")
    assert code == 1 and "leicht zu erraten" in aus, (_args, _pw, aus)
_von_der_liste = "Firmengeheimnis2026!"
code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin=_von_der_liste + "\n")
assert code == 0, aus    # Gegenprobe: ohne Schalter kennt das CLI die Liste nicht
code, aus = cli("passwd", "--db", db, "--stdin", "--blocklist-file", _liste + ".fehlt", "admin",
                stdin="noch-ein-anderes\n")
assert code == 1 and "lässt sich nicht lesen" in aus, aus
assert auth.check_password("admin", _von_der_liste)
ok("passwd liest --blocklist-file (auch Latin-1-Zeilen) und --rp-name wie die Config")

code, aus = cli("quatsch")
assert code == 2 and "usage" in aus
ok("unbekanntes Kommando → usage, Exit 2")

# `--help` ist eine Frage, kein Fehler: Exit 0, damit ein Skript den Unterschied zum Tippfehler
# sieht. (Der Prüfbericht hatte das für das Gateway gemeldet — hier ist die Gegenprobe.)
code, aus = cli("--help")
assert code == 0 and "usage" in aus, (code, aus)
ok("--help → usage, Exit 0 (nicht 2 wie ein Tippfehler)")

# ---------- backup: eine Datei-Kopie taugt im WAL-Modus nicht ----------
import sqlite3

nackt = os.path.join(tempfile.mkdtemp(), "t.db")
code, aus = cli("backup", "--db", db, nackt)
assert code == 0 and "Sicherung geschrieben" in aus, (code, aus)
namen = {z[0] for z in sqlite3.connect(nackt).execute("SELECT username FROM users")}
assert namen, "Sicherung ohne Konten"
ok(f"backup zieht eine Kopie, die für sich allein stimmt ({len(namen)} Konten)")

import stat as _stat

assert _stat.S_IMODE(os.stat(nackt).st_mode) == 0o600, oct(_stat.S_IMODE(os.stat(nackt).st_mode))
ok("die Sicherung trägt dieselben engen Rechte wie die Quelle")

# Das naive Backup zur Gegenprobe — es ist genau der Fehler, den das Kommando abnimmt.
import shutil

roh = os.path.join(tempfile.mkdtemp(), "t.db")
shutil.copy(db, roh)
try:
    sqlite3.connect(roh).execute("SELECT COUNT(*) FROM users").fetchone()
    naiv_ok = True
except sqlite3.DatabaseError:
    naiv_ok = False
assert not naiv_ok, "die blosse Datei-Kopie war brauchbar — dann misst der Test nichts"
ok("eine blosse Datei-Kopie ist unbrauchbar (WAL) — deshalb gibt es das Kommando")

code, aus = cli("backup", "--db", db, nackt)
assert code == 1 and "gibt es schon" in aus, (code, aus)
ok("backup überschreibt keine bestehende Datei")

code, aus = cli("backup", "--db", os.path.join(tempfile.mkdtemp(), "t.db"), os.path.join(tempfile.mkdtemp(), "datei"))
assert code == 1 and "Keine Datenbank" in aus, (code, aus)
ok("backup auf eine fehlende Datenbank → Exit 1, keine leere Datei angelegt")

# ---------- gc: das Aufräumen braucht einen Weg von aussen ----------
# R4-09: ein nie bestätigtes Konto (gesperrt, abgelaufener unbenutzter Bestätigungstoken) räumt
# auch der CLI-Weg weg — und zwar VOR den Tokens, sonst verschwände das Merkmal zuerst.
_sq = auth.create_user("squatter", password="geheim12345", email="opfer@example.com")
auth.store.set_disabled(_sq, True)
auth.store.add_magic_token("abgelaufen-verify", "verify_email", 1, user_id=_sq, email="opfer@example.com")
code, aus = cli("gc", "--db", db)
assert code == 0 and "sessions=" in aus and "login_attempts=" in aus, (code, aus)
assert "unverified_accounts=1" in aus and auth.store.get_user(_sq) is None, aus
ok("gc räumt auf und nennt je Bereich die Zahl (für Cron/Timer), nie bestätigte Konten zuerst")

os.remove(nackt)
os.remove(roh)
os.remove(db)
print("\nCLI OK ✅")
