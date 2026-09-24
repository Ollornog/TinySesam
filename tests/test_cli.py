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

# Die Mindestlänge liest das CLI wie das Web (T-13-Angriff, faktoren × konfiguration): Ein
# Altwert aus einer Fassung ohne Grenzen (`password_min_length` = 4 oder 0) gilt im Web als 8
# (`sec()` zieht ihn an die Grenze), das CLI las ihn roh und setzte Passwörter, die jede
# Web-Setzstelle ablehnt.
from tinysesam import security as _security

for _altwert in ("4", "0"):
    auth.store.set_setting("password_min_length", _altwert)
    code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin="k9T#q7\n")   # 6 Zeichen
    assert code == 1 and "zu kurz (min. 8)" in aus, (_altwert, code, aus)
    assert auth.sec("password_min_length") == 8 == _security.haertung_lesen(auth.store, "password_min_length")
    assert auth.check_password("admin", _von_der_liste)
auth.store.set_setting("password_min_length", "12")                 # gültiger Wert: gilt wie im Web
code, aus = cli("passwd", "--db", db, "--stdin", "admin", stdin="Elf-Zeichen\n")   # 11 Zeichen
assert code == 1 and "zu kurz (min. 12)" in aus, (code, aus)
auth.store._exec("DELETE FROM setting WHERE key='password_min_length'")   # zurück zur Vorgabe
ok("passwd liest die Mindestlänge wie das Web (Altwert jenseits der Grenze gilt als Grenze)")
# (Mutationsprobe: in `_passwd` wieder `int(store.get_setting("password_min_length") or …)` statt
# `haertung_lesen` → rot.)

# Die Klasse dahinter: Jede Härtungs-Schwelle wird über `security.haertung_lesen` gelesen — ein
# zweiter, roher Leseweg entschiede sonst mit dem schwächeren Wert. Geprüft wird jeder Lesezugriff
# auf die Settings-Tabelle im Paket, nicht nur die Schreibweise, die der erste Fund benutzte
# (zweite Angriffsrunde, konfig: `get_setting(key="…")`, ein Schlüssel über eine Variable und
# `all_settings()[…]` kamen durch, und ein falscher Pfad hätte null Dateien geprüft — grün).
import ast as _ast
import pathlib as _pl
import re as _re

#: Wo ein NICHT-literaler Schlüssel erlaubt ist (Datei, Funktion) — der gemeinsame Leseweg selbst.
_SETTING_FREIER_SCHLUESSEL = {("security.py", "haertung_lesen")}
#: Wo `all_settings()` gerufen werden darf. Heute nirgends; wer es braucht, trägt die Stelle
#: hier ein und begründet, warum dort keine Härtungs-Schwelle roh gelesen wird.
_SETTING_ALLE = set()
_SETTING_METHODEN = ("get_setting", "all_settings")
# Die Klassen statt der Schreibweisen (Schlussfund konfig-2: der Wächter suchte case-sensitiv nach
# `FROM setting` und sah `get_setting` nur als Attribut-Aufruf — kleingeschriebenes SQL, `main.`,
# Anführungszeichen, ein f-String mit dem Tabellennamen, `getattr(store, "get_setting")` und ein
# Alias `lesen = store.get_setting` blieben grün):
# 1. Rohes SQL auf die Tabelle `setting` ausserhalb von store.py: ein String, in dem `setting` als
#    Tabelle hinter FROM/JOIN/UPDATE/INTO steht — gleich in welcher Schreibung (SQLite unterscheidet
#    dort nicht), mit Schema-Präfix (`main.`), in Quotes oder Klammern, mit Kommentar statt
#    Leerzeichen. Auch ein Schreibzugriff fällt darunter: Er ginge ebenso am Store vorbei.
# 2. SQL, dessen Tabellenname erst zur Laufzeit dazukommt (f-String, `+`, `%`, `.format`): Der Text
#    beginnt mit einem SQL-Verb, und hinter FROM/JOIN/UPDATE/INTO steht eine Lücke. Welche Tabelle
#    es wird, sieht kein Syntaxbaum.
#    Geprüft wird je Ausdruck der ganze Text: f-Strings und `+`-Ketten werden zusammengesetzt
#    (eine Lücke steht als `{}`), `"… FROM sett" + "ing"` fällt also unter 1. Docstrings zählen
#    nicht — sie laufen nie gegen die Datenbank.
# 3. Jede Erwähnung von `get_setting`/`all_settings`, die kein direkter Aufruf ist (Alias,
#    `functools.partial`, Übergabe als Argument) und jeder String, der genau so heisst (`getattr`,
#    `operator.methodcaller`). Ein Aufruf über einen Namen (`get_setting(...)` als Parameter)
#    wird geprüft wie ein Methodenaufruf.
# Grenze: Ein Name, der erst zur Laufzeit ENTSTEHT (`getattr(store, name)`), SQL, das über mehrere
# Anweisungen wächst (`sql += …`), SQL aus einer Datei und eine eigene sqlite3-Verbindung mit so
# gebautem SQL sieht dieser Wächter nicht; vollständig erkennen liesse sich das nur zur Laufzeit.
# Umgekehrt meldete er englischen Fliesstext der Form „… from setting …“ (heute keiner im Paket):
# Dann nennt er Datei und Zeile, und die Formulierung wird geändert.
_SQL_SETTING = _re.compile(
    r"(?i)(?<![\w$])(?:from|join|update|into)(?:\s|/\*.*?\*/)*"
    r"(?:(?:\"[^\"]*\"|`[^`]*`|\[[^\]]*\]|\w+)\s*\.\s*)?[\"'`\[]?setting(?![\w$])", _re.S)
_SQL_ANFANG = _re.compile(r"(?is)^(?:\s|--[^\n]*\n|/\*.*?\*/)*(?:select|with|update|insert|replace|delete|explain)\b")
_SQL_TABELLE_OFFEN = _re.compile(r"(?i)(?<![\w$])(?:from|join|update|into)(?:\s|/\*.*?\*/)+[\"'`\[]?\s*(?:\{|%)", _re.S)


def _sql_text(k):
    """Der Text eines String-Ausdrucks: Konstante, f-String oder `+`-Kette (Lücken als `{}`)."""
    if isinstance(k, _ast.Constant) and isinstance(k.value, str):
        return k.value
    if isinstance(k, _ast.JoinedStr):
        return "".join(t.value if isinstance(t, _ast.Constant) else "{}" for t in k.values)
    if isinstance(k, _ast.BinOp) and isinstance(k.op, _ast.Add):
        links, rechts = _sql_text(k.left), _sql_text(k.right)
        if links is None and rechts is None:
            return None
        return (links if links is not None else "{}") + (rechts if rechts is not None else "{}")
    if isinstance(k, _ast.BinOp) and isinstance(k.op, _ast.Mod):
        return _sql_text(k.left)
    return None


def _setting_lesewege(quellen):
    """(Verstöße, gesehene erlaubte Stellen) für [(Dateiname, Quelltext), …]."""
    verstoesse, gesehen = [], set()
    for name, text in quellen:
        baum = _ast.parse(text)
        eltern = {}
        for knoten in _ast.walk(baum):
            for kind in _ast.iter_child_nodes(knoten):
                eltern[kind] = knoten

        def funktion(k):
            while k in eltern:
                k = eltern[k]
                if isinstance(k, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    return k.name
            return "<modul>"
        for k in _ast.walk(baum):
            text = _sql_text(k)
            if text is not None:
                p = eltern.get(k)
                ganz = not (isinstance(p, _ast.JoinedStr) or _sql_text(p) is not None
                            and isinstance(p, _ast.BinOp))
                if name != "store.py" and ganz and not isinstance(p, _ast.Expr):
                    if _SQL_SETTING.search(text):
                        verstoesse.append(f"{name}:{k.lineno} rohes SQL auf die Settings-Tabelle")
                    elif _SQL_ANFANG.search(text) and _SQL_TABELLE_OFFEN.search(text):
                        verstoesse.append(f"{name}:{k.lineno} SQL mit Tabellennamen zur Laufzeit")
                if isinstance(k, _ast.Constant) and k.value in _SETTING_METHODEN:
                    verstoesse.append(f"{name}:{k.lineno} {k.value!r} als Text (getattr o. ä.)")
                continue
            if isinstance(k, _ast.Attribute):
                methode = k.attr
            elif isinstance(k, _ast.Name):
                methode = k.id
            else:
                continue
            if methode not in _SETTING_METHODEN:
                continue
            aufruf = eltern.get(k)
            stelle = (name, funktion(k))
            if not (isinstance(aufruf, _ast.Call) and aufruf.func is k):
                verstoesse.append(f"{name}:{k.lineno} {methode} als Wert weitergereicht in {stelle[1]}")
                continue
            if methode == "all_settings":
                if stelle in _SETTING_ALLE:
                    gesehen.add(stelle)
                else:
                    verstoesse.append(f"{name}:{k.lineno} all_settings() in {stelle[1]}")
                continue
            schluessel = aufruf.args[0] if aufruf.args else next(
                (w.value for w in aufruf.keywords if w.arg == "key"), None)
            if isinstance(schluessel, _ast.Constant) and isinstance(schluessel.value, str):
                if schluessel.value in _security.SECURITY_DEFAULTS:
                    verstoesse.append(f"{name}:{k.lineno} Härtungs-Schwelle {schluessel.value!r} roh gelesen")
            elif stelle in _SETTING_FREIER_SCHLUESSEL:
                gesehen.add(stelle)
            else:
                verstoesse.append(f"{name}:{k.lineno} get_setting ohne literalen Schlüssel in {stelle[1]}")
    return verstoesse, gesehen


# Selbsttest des Wächters: jede Schreibweise eines rohen Lesewegs fällt auf.
for _schreibweise in ('n = int(store.get_setting("password_min_length") or 8)',
                      'n = int(store.get_setting(key="password_min_length") or 8)',
                      'k = "max_login_attempts"\nn = int(store.get_setting(k) or 5)',
                      'n = int(store.all_settings().get("max_login_attempts", 5))',
                      'n = db.execute("SELECT value FROM setting WHERE key=?", (k,))',
                      # Schlussfund konfig-2: kamen durch, solange der Wächter eine Schreibweise sah.
                      'n = db.execute("select value from setting where key=?", (k,))',
                      'n = db.execute("SELECT value FROM main.setting WHERE key=?", (k,))',
                      'n = db.execute(\'SELECT value FROM "setting" WHERE key=?\', (k,))',
                      't = "setting"\nn = db.execute(f"SELECT value FROM {t} WHERE key=?", (k,))',
                      'n = getattr(store, "get_setting")("password_min_length")',
                      'lesen = store.get_setting\nn = lesen("password_min_length")',
                      # Dieselben Klassen in weiteren Schreibweisen:
                      'n = db.execute("SELECT value FROM [setting] WHERE key=?", (k,))',
                      'n = db.execute("SELECT value FROM/**/Setting WHERE key=?", (k,))',
                      'n = db.execute("SELECT value FROM %s WHERE key=?" % t, (k,))',
                      'n = db.execute("SELECT value FROM {} WHERE key=?".format(t), (k,))',
                      'n = db.execute("SELECT value FROM " + t + " WHERE key=?", (k,))',
                      'n = functools.partial(store.get_setting, "password_min_length")()',
                      'n = operator.methodcaller("get_setting", "password_min_length")(store)',
                      'alle = getattr(store, "all_settings")()',
                      'def f(get_setting):\n    return get_setting("password_min_length")',
                      'n = Store.get_setting(store, "password_min_length")',
                      'n = db.execute("SELECT value FROM sett" + "ing WHERE key=?", (k,))',
                      'n = db.execute("SELECT value " + "FROM " + t + " WHERE key=?", (k,))',
                      'n = db.execute(\'SELECT value FROM "main"."setting"\')',
                      'n = db.execute("UPDATE setting SET value=value WHERE key=? RETURNING value", (k,))'):
    assert _setting_lesewege([("fremd.py", _schreibweise)])[0], f"Wächter übersieht: {_schreibweise}"
# Gegenprobe: Ein literaler Schlüssel ohne Härtungs-Schwelle, der Mail-Kopf `From`, Fliesstext über
# „settings“/„setting“ und ein Docstring bleiben ohne Befund — sonst prüfte der Selbsttest nur, dass
# alles anschlägt.
for _harmlos in ('x = store.get_setting("demo_users")', 'msg["From"] = absender',
                 'hinweis = "Die settings from the panel gelten sofort."',
                 'hinweis = "Select whether this setting applies."',
                 'hinweis = f"Login from {ip}"',
                 'def f():\n    """Liest nie SELECT value FROM setting — nur ein Docstring."""'):
    assert not _setting_lesewege([("fremd.py", _harmlos)])[0], f"Fehlalarm: {_harmlos}"

_paket = sorted((_pl.Path(__file__).resolve().parent.parent / "tinysesam").rglob("*.py"))
assert len(_paket) >= 10 and any(d.name == "security.py" for d in _paket), \
    f"Wächter findet das Paket nicht: {len(_paket)} Datei(en)"
_verstoesse, _gesehen = _setting_lesewege([(d.name, d.read_text(encoding="utf-8")) for d in _paket])
assert not _verstoesse, f"Settings am gemeinsamen Leseweg vorbei gelesen: {_verstoesse}"
assert _gesehen == _SETTING_FREIER_SCHLUESSEL | _SETTING_ALLE, \
    f"Ausnahmeliste veraltet oder Wächter blind: gesehen {_gesehen}"
ok("jeder Lesezugriff auf die Settings läuft über literale Schlüssel oder security.haertung_lesen")
# (Mutationsproben: im Wächter nur `aufruf.args[0]` lesen, Schlüsselwörter übergehen → der
# Selbsttest wird rot; den Zweig für nicht-literale Schlüssel streichen → rot; in `_passwd` wieder
# `int(store.get_setting("password_min_length") or …)` → der Wächter nennt `__main__.py:<Zeile>`,
# einzeln nachgeprüft, weil in der Suite das assert weiter oben zuerst anschlägt. Schlussrunde,
# je einzeln → rot: `(?i)` streichen; den Schema-Präfix nicht zulassen; die Prüfung auf den
# Tabellennamen zur Laufzeit streichen; das Zusammensetzen von `+`-Ketten abschalten; die Meldung
# „als Wert weitergereicht“ streichen; den Methodennamen als Text übergehen; Aufrufe über einen
# Namen übergehen → der Selbsttest wird rot. Das SQL-Verb am Anfang nicht verlangen → die
# Gegenprobe `f"Login from {ip}"` wird rot; Docstrings mitprüfen → die Docstring-Gegenprobe wird
# rot. Am Paket: die Fund-Mutation (kleines SQL und Alias) in security.py → rot mit
# `security.py:<Zeile>`; `getattr(self.store, "get_setting")` in manager.py → rot mit
# `manager.py:<Zeile>`; ein f-String `select value from {_T}` in admin.py → rot mit `admin.py:<Zeile>`.)

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

# `--audit-days` ist das Gegenstück zu `audit_retention_days` und hält dieselbe Grenze
# (T-13-Angriff, audit × konfiguration): 10**20 brach mit OverflowError ab, NACHDEM Sitzungen und
# Tokens schon gelöscht waren; Sekunden statt Tagen (2592000) liessen die Frist still ins Leere laufen.
auth.store.audit_log("bleibt", "x", None)
for _tage in (str(10 ** 20), "2592000", "-1"):
    try:
        code, aus = cli("gc", "--db", db, "--audit-days", _tage)
    except Exception as e:   # noqa: BLE001 — ein Traceback ist hier der Befund
        code, aus = f"{type(e).__name__}", str(e)
    assert code == 2 and "--audit-days" in aus, (_tage, code, aus[-200:])
assert any(z["event"] == "bleibt" for z in auth.store.recent_audit(20))
ok("gc --audit-days hält dieselbe Grenze wie audit_retention_days (kein Absturz, nichts gelöscht)")
# (Mutationsprobe: die Bereichsprüfung in `_gc` auf `a.audit_days < 0` zurückstellen → rot.)

# Dieselbe Klasse am Nachbarparameter (zweite Angriffsrunde, konfig): `--attempts-older-than` und
# `TinySesam.gc(attempts_older_than_sec=)` hatten keine Grenze. ±10**20 brach mit OverflowError ab,
# NACHDEM Sitzungen, Flows, Tokens und Unlocks schon gelöscht waren; ein negativer Wert räumte
# jeden Fehlversuch weg — auch die im laufenden Sperrfenster — und hob damit jede Kontosperre auf.
# 0 bleibt erlaubt: der dokumentierte Weg, alle Fehlversuche zu räumen (s. `unlock`).
_gc_uid = auth.create_user("gc-probe", password="Gc-Probe#lang-12345")
auth.store.create_session(_gc_uid, 3600, True, "password")
auth.store._exec("UPDATE session SET expires_at=1 WHERE user_id=?", (_gc_uid,))   # abgelaufen


def _abgelaufene_sitzungen():
    return auth.store._one("SELECT COUNT(*) AS n FROM session WHERE user_id=?", (_gc_uid,))["n"]


for _ in range(auth.sec("max_login_attempts") + 1):
    auth.record_login("gc-probe", "198.51.100.7", False, "password")
assert auth.is_locked("gc-probe", "198.51.100.7")
for _sek in (str(10 ** 20), str(-10 ** 20), "-1"):
    try:
        code, aus = cli("gc", "--db", db, "--attempts-older-than", _sek)
    except Exception as e:   # noqa: BLE001 — ein Traceback ist hier der Befund
        code, aus = f"{type(e).__name__}", str(e)
    assert code == 2 and "--attempts-older-than" in aus, (_sek, code, aus[-200:])
assert _abgelaufene_sitzungen() == 1, "gc hat gelöscht, obwohl das Argument abgewiesen wurde"
assert auth.is_locked("gc-probe", "198.51.100.7"), "ein abgewiesener gc-Lauf hat die Sperre aufgehoben"
for _sek in (10 ** 20, -10 ** 20, -1, True, float("inf"), "viel"):
    try:
        auth.gc(attempts_older_than_sec=_sek)
        _gc_fund = "angenommen"
    except ValueError:
        _gc_fund = None
    except Exception as e:   # noqa: BLE001 — ein anderer Absturz ist hier der Befund
        _gc_fund = f"{type(e).__name__}: {e}"
    assert _gc_fund is None, (_sek, _gc_fund)
assert _abgelaufene_sitzungen() == 1 and auth.is_locked("gc-probe", "198.51.100.7")
assert auth.gc(attempts_older_than_sec=86400)["sessions"] >= 1 and _abgelaufene_sitzungen() == 0
code, aus = cli("gc", "--db", db, "--attempts-older-than", "0")
assert code == 0 and "login_attempts=" in aus, (code, aus)
ok("gc --attempts-older-than und auth.gc() prüfen die Frist, bevor irgendetwas gelöscht wird")
# (Mutationsprobe: `store.versuchsfrist(...)` in `_gc` durch den rohen Wert ersetzen → rot
# (OverflowError bzw. Exit 0); dasselbe in `TinySesam.gc` → rot.)

os.remove(nackt)
os.remove(roh)
os.remove(db)
print("\nCLI OK ✅")
