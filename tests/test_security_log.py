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


def _lies(pfad):
    """Eine Datei ganz lesen und den Griff wieder schließen.

    `open(...).read()` lässt den Griff bis zur nächsten Sammlung offen; CodeQL meldet das
    (py/file-not-closed) zu Recht, und in einem `assert` wäre das Lesen zudem eine
    Nebenwirkung, die unter `python -O` mitsamt der Prüfung verschwindet.
    """
    with open(pfad, encoding="utf-8") as fh:
        return fh.read()



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
    inhalt2 = _lies(log2)

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
    tok3 = _lies(tokdatei).strip()
    assert tok3 == auth3.admin_claim_token(), tok3
    assert stat.S_IMODE(os.stat(tokdatei).st_mode) == 0o600, oct(stat.S_IMODE(os.stat(tokdatei).st_mode))
    _log3 = _lies(log3)
    assert tok3 not in _log3
    assert tokdatei in _log3                                   # der Pfad darf genannt werden
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
inhalt6 = _lies(tokdatei6)
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

# (3b) …und diese Warnung muss einen Weg nennen, den es GIBT. Sie riet „Der Erst-Admin kommt
#      dann nur über admin_identifiers oder die CLI zustande" — dieselbe falsche CLI-Zusage, die
#      der CHANGELOG an anderer Stelle ausdrücklich zurückgenommen hat („Das CLI stand hier
#      zunächst mit in der Liste — es kann gar keine Konten anlegen"), diesmal in einem Text, den
#      der Betreiber zu lesen bekommt. Wer ihr folgte, suchte ein Kommando, das nicht existiert.
_f8, _w8 = pruefe(TinySesamConfig(admin_claim_ttl_min=0, **_gemeinsam7))
_zeile8 = next(w for w in _w8 if "admin_claim_token_file ist gesetzt" in w)
assert "ensure_admin" in _zeile8 and hasattr(TinySesam, "ensure_admin"), \
    f"die Warnung nennt keinen Weg, den es gibt: {_zeile8!r}"
assert "oder die CLI zustande" not in _zeile8, \
    f"das CLI legt keine Konten an — es darf hier nicht als Weg stehen: {_zeile8!r}"
# Gegenprobe: Das CLI kann es wirklich nicht. `main()` kennt genau diese sieben Kommandos;
# käme eines dazu, das Konten anlegt, wäre die Zeile oben zu ändern statt zu behalten.
import inspect as _inspect  # noqa: E402
from tinysesam.__main__ import main as _cli_main  # noqa: E402

_kommandos = set(re.findall(r'cmd == "([a-z]+)"', _inspect.getsource(_cli_main)))
assert _kommandos == {"version", "passwd", "backup", "restore", "gc", "audit", "unlock"}, \
    (f"CLI-Kommandos geändert: {sorted(_kommandos)} — kann eines davon jetzt Konten anlegen "
     "oder Kennungen ändern, gehören die Betreiber-Meldungen mitgeändert")
ok("Erst-Admin-Warnung nennt ensure_admin statt des CLI (das keine Konten anlegt)")

# (4) Befund B-regression-6: Der Hinweis „Kein vertrauenswürdiger öffentlicher Host" kam bei
#     JEDER anonymen Forward-Auth-Anfrage. `forward_login_url()` fragt seit N1 `public_base()`,
#     und ohne `base_url` (erlaubt: forward_auth_enabled ist nur eine Warnung) hält die
#     abgeleitete Basis der Prüfung nicht stand. Ein Seitenaufruf mit zwanzig Unterressourcen
#     schrieb zwanzig gleiche Zeilen — in die Datei, auf die die fail2ban-Jail zeigt und die
#     logrotate wochenlang aufhebt. Die Zeile bleibt, der Sturm geht.
_abraeumen()
security._GEMELDET.clear()            # prozessweiter Zustand: der Lauf muss wiederholbar sein
tmp8 = tempfile.mkdtemp()
log8 = os.path.join(tmp8, "security.log")
auth8 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log8, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, forward_auth_enabled=True))
app8 = FastAPI()
app8.include_router(auth8.router())
c8 = TestClient(app8)


def _hinweiszeilen(pfad, host=None) -> int:
    with open(pfad, encoding="utf-8") as fh:
        return len([z for z in fh if "Kein vertrauenswürdiger öffentlicher Host" in z
                    and (host is None or host in z)])


for _i in range(20):
    c8.get("/auth/forward", headers={"x-forwarded-proto": "https",
                                     "x-forwarded-host": "app.example.com",
                                     "x-forwarded-uri": f"/asset{_i}.css"})
assert _hinweiszeilen(log8) == 1, \
    f"{_hinweiszeilen(log8)} Zeilen nach 20 Anfragen — ein Crawler bläst die fail2ban-Datei auf"
ok("der Hinweis auf die fehlende Basis kommt einmal, nicht je Anfrage")

c8.get("/auth/forward", headers={"x-forwarded-proto": "https",
                                 "x-forwarded-host": "zweiter.example.com",
                                 "x-forwarded-uri": "/"})
assert _hinweiszeilen(log8, "zweiter.example.com") == 1, \
    "ein ANDERER Host bekommt keine eigene Zeile mehr — dann schweigt die Stelle zu neuen Fällen"
ok("...ein anderer Host wird trotzdem gemeldet (still ist nicht dasselbe wie stumm)")

# Der Deckel: Der Schlüssel kommt aus der Anfrage. Wer den Host-Header durchprobiert, darf weder
# die Datei noch den Speicher füllen — ab `_GEMELDET_MAX` schweigt die Stelle.
security.einmal_melden_zuruecksetzen()
T0 = 1_000_000.0
assert all(security.einmal_melden(f"probe:{i}", jetzt=T0) for i in range(security._GEMELDET_MAX))
assert not security.einmal_melden("probe:noch einer", jetzt=T0), "ohne Deckel füllt ein Angreifer den Speicher"
assert not security.einmal_melden("probe:0", jetzt=T0), "derselbe Schlüssel meldet sich nicht zweimal"
ok("einmal_melden() ist gedeckelt (der Schlüssel stammt aus der Anfrage)")

# C-4: Der Deckel darf nicht für immer gelten. Vorher genügten 512 erfundene Host-Werte, um die
# Stelle bis zum Neustart stillzulegen — danach blieb auch der Hinweis auf den ECHTEN
# Betriebsfehler aus. Ein Angreifer konnte damit gezielt eine Warnung abschalten, nicht nur Lärm
# machen. (Mutationsprobe: den Fensterwechsel in `einmal_melden` entfernen → die nächste Zeile
# wird rot, der Rest der Suite bleibt grün.)
assert security.einmal_melden("probe:nach dem Fenster", jetzt=T0 + security._GEMELDET_FENSTER_SEK), \
    "nach dem Fenster muss die Stelle wieder sprechen"
assert security.einmal_melden("probe:0", jetzt=T0 + security._GEMELDET_FENSTER_SEK), \
    "der Speicher des alten Fensters ist geleert"
assert len(security._GEMELDET) == 2, "das neue Fenster fängt bei null an, nicht bei 512"
ok("...und der Deckel gilt je Zeitfenster, nicht für die Lebensdauer des Prozesses")

# Und die Unterdrückung selbst ist sichtbar: genau eine Zeile je Fenster, sonst wäre „ab hier
# schweige ich" ein zweites stilles Loch.
security.einmal_melden_zuruecksetzen()
_puffer_deckel = io.StringIO()
_haken_deckel = logging.StreamHandler(_puffer_deckel)
security.seclog.addHandler(_haken_deckel)
try:
    for i in range(security._GEMELDET_MAX):
        security.einmal_melden(f"voll:{i}", jetzt=T0)
    for i in range(3):
        security.einmal_melden(f"zuviel:{i}", jetzt=T0)
finally:
    security.seclog.removeHandler(_haken_deckel)
_text_deckel = _puffer_deckel.getvalue()
assert _text_deckel.count("Hinweis-Deckel erreicht") == 1, \
    f"genau eine Zeile je Fenster, nicht {_text_deckel.count('Hinweis-Deckel erreicht')}: {_text_deckel[:200]!r}"
assert str(security._GEMELDET_MAX) in _text_deckel, _text_deckel[:200]
security.einmal_melden_zuruecksetzen()
ok("...und das Erreichen des Deckels wird einmal gemeldet (keine unsichtbare Unterdrückung)")

# (5) Dieselbe Bremse für den umgekehrten Fall: Steht `base_url`, GEWINNT sie — auch gegen eine
#     übergebene Basis auf einem zweiten eigenen Host. Ganz still wäre das eine Falle für den
#     Entwickler (sein Wert verschwindet), je Anfrage wäre es der nächste Sturm (der Wert kommt
#     bei diesem Muster aus dem Host-Header). Also einmal je Host.
_abraeumen()
tmp9 = tempfile.mkdtemp()
log9 = os.path.join(tmp9, "security.log")
auth9 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  security_log=log9, cookie_secure=False, passkey_enabled=False,
                                  base_url="https://auth.example.com",
                                  trusted_redirect_hosts=["app-b.example.com"]))
for _ in range(5):
    assert auth9.magic_url("tok", "https://app-b.example.com", "reset_password").startswith(
        "https://auth.example.com/"), "base_url muss auch gegen einen zweiten eigenen Namen gewinnen"
with open(log9, encoding="utf-8") as fh:
    _ersetzt = [z for z in fh if "wird durch base_url" in z]
assert len(_ersetzt) == 1, f"{len(_ersetzt)} Zeilen nach 5 Aufrufen — einmal je Adresse, nicht je Anfrage"
security.einmal_melden_zuruecksetzen()
ok("eine ersetzte Basis meldet sich einmal je Adresse (nicht still, nicht im Sturm)")

# C-5: Derselbe Fall mit GLEICHEM Host, aber anderem Pfad. Der CHANGELOG verspricht eine Zeile,
# wenn base_url eine abweichende Angabe ersetzt — geprüft wurde vorher nur der Host, also schwieg
# genau der Fall, der beim Empfänger als 404 ankommt: eine unter `/sso` montierte App, deren
# eigenes Formular `https://auth.example.com/falsch` durchreicht.
# (Mutationsprobe: den Vergleich wieder auf `_host_aus(...)` zurückdrehen → die nächste
# Zusicherung wird rot.)
_abraeumen()
tmp10 = tempfile.mkdtemp()
log10 = os.path.join(tmp10, "security.log")
auth10 = TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                   security_log=log10, cookie_secure=False, passkey_enabled=False,
                                   base_url="https://auth.example.com/sso"))
security.einmal_melden_zuruecksetzen()
for _ in range(4):
    _link = auth10.magic_url("tok", "https://auth.example.com/falsch", "reset_password")
    assert _link.startswith("https://auth.example.com/sso/"), _link
_zeilen10 = [z for z in _lies(log10).splitlines() if "wird durch base_url" in z]
assert len(_zeilen10) == 1, \
    f"gleicher Host, anderer Pfad: {len(_zeilen10)} Zeilen — erwartet genau eine"
assert "/falsch" in _zeilen10[0] and "/sso" in _zeilen10[0], _zeilen10[0][:200]

# Gegenprobe: dieselbe Adresse wie base_url (nur mit Schrägstrich am Ende) ist keine Abweichung
# und darf nicht melden — sonst wäre die Zeile Rauschen.
security.einmal_melden_zuruecksetzen()
_vorher10 = len(_lies(log10).splitlines())
auth10.magic_url("tok", "https://auth.example.com/sso/", "reset_password")
assert len(_lies(log10).splitlines()) == _vorher10, "eine identische Angabe ist keine Ersetzung"
security.einmal_melden_zuruecksetzen()
ok("...auch bei gleichem Host mit abweichendem Pfad (und Schweigen bei identischer Angabe)")

# C-7: Die KONFIGURIERTE Basis läuft durch dieselbe Formprüfung wie die abgeleitete. Vorher sah
# sie nur strip()/rstrip("/") — eine Benutzerangabe im Host stand damit in jedem Link, ein
# Fragment hätte den angehängten Token abgeschnitten.
for _kaputt in ("https://auth.example.com/x#y", "https://auth.example.com/x?y=1",
                "https://auth.example.com/a/../b", "https://auth.example.com:99999", "auth.example.com"):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                  cookie_secure=False, passkey_enabled=False,
                                  base_url=_kaputt, oidc_enabled=False))
        raise AssertionError(f"base_url={_kaputt!r} kam durch die Konfigurationsprüfung")
    except ConfigError:
        pass
# Eine Benutzerangabe ist brauchbar, wird aber entfernt — das sagt die Prüfung, statt es still zu tun.
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"), cookie_secure=False,
                              passkey_enabled=False, base_url="https://wer:was@auth.example.com"))
    raise AssertionError("die veränderte Adresse wurde nicht gemeldet")
except ConfigError as _e:
    # Auf den kanonischen Wert in seiner Zitierform geprüft, nicht per Teilzeichenkette: sonst
    # genügte "https://auth.example.com.angreifer.test" irgendwo im Text (CodeQL
    # py/incomplete-url-substring-sanitization).
    assert "wird als" in str(_e) and repr("https://auth.example.com") in str(_e), str(_e)[:200]
ok("base_url wird nach derselben Regel geprüft wie eine abgeleitete Basis (C-7)")

# ---------------------------------------------------------------------------
# Runde 2: Ein Fehlgriff, der KEINE Anmeldung war, darf die mitgelieferte Jail nicht treffen.
#
# Seit R4-10 protokolliert auch die Alt-Passwort-Abfrage der Kontoseite — richtig so, vorher
# war sie ein stilles Orakel. Sie schrieb aber `failed login`, Zeichen für Zeichen die Zeile,
# auf die `deploy/fail2ban/tinysesam-jail.conf` mit `maxretry = 6` bannt. Gemessen: acht
# Fehlgriffe eines ANGEMELDETEN Nutzers am eigenen alten Passwort erzeugten acht passende
# Zeilen — der legitime Nutzer sperrte sich auf Firewall-Ebene aus, für die ganze Instanz.
# Verschärfend erzeugte ab der App-Sperre jeder weitere Klick eine weitere passende Zeile.
# Jetzt tragen diese Zeilen ein eigenes Ereigniswort (`security.LOG_PRUEFUNG`).
#
# Geprüft wird gegen die AUSGELIEFERTEN Filterdateien, nicht gegen ein Muster im Test: Sonst
# misst der Test seine eigene Kopie und merkt nicht, wenn die Vorlage auseinanderläuft.
# ---------------------------------------------------------------------------
_abraeumen()
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _failregex(datei):
    text = _lies(os.path.join(ROOT, "deploy", "fail2ban", datei))
    zeile = [z for z in text.splitlines() if z.startswith("failregex =")][0]
    muster = zeile.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)")
    return re.compile(muster)


JAIL = _failregex("tinysesam-filter.conf")                 # bannt: echte Anmeldeversuche
JAIL_PRUEFUNG = _failregex("tinysesam-verify-filter.conf")  # die zweite, mildere Jail


def _ohne_datum(zeile):
    """Wie fail2ban die Zeile sieht: Den Zeitstempel datiert es selbst ab, der Rest wird gematcht."""
    return re.sub(r"^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d(?:,\d+)? ", "", zeile)


class _Mitschnitt:
    """Fängt die Zeilen des Sicherheits-Logs im Format der ausgelieferten Datei ab."""

    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = logging.StreamHandler(self.puffer)
        self.haken.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        security.seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        security.seclog.removeHandler(self.haken)

    def zeilen(self):
        return [_ohne_datum(z) for z in self.puffer.getvalue().splitlines() if z.strip()]


dbf = os.path.join(tempfile.mkdtemp(), "t.db")
authf = TinySesam(TinySesamConfig(db_path=dbf, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
uid_f = authf.create_user("anna", "Anna-Passwort-2026")

# (1) Jede Methode einzeln: Anmeldeversuche treffen die Jail, alles andere nicht.
for methode in ("password", "pin", "totp"):
    with _Mitschnitt() as m:
        authf.record_login("anna", "203.0.113.4", False, methode)
    zeile = m.zeilen()[-1]
    assert JAIL.search(zeile), f"{methode}: die Jail sieht den Anmeldeversuch nicht — {zeile!r}"
    assert JAIL.search(zeile).group("host") == "203.0.113.4", zeile
    assert not JAIL_PRUEFUNG.search(zeile), f"{methode} landet in der milderen Jail: {zeile!r}"
for methode in security.NICHT_LOGIN_METHODEN:
    with _Mitschnitt() as m:
        authf.record_login("anna", "203.0.113.4", False, methode)
    zeile = m.zeilen()[-1]
    assert not JAIL.search(zeile), f"{methode} trifft die mitgelieferte Login-Jail: {zeile!r}"
    assert JAIL_PRUEFUNG.search(zeile), f"{methode} trifft auch die zweite Jail nicht: {zeile!r}"
    assert f"method={methode}" in zeile, zeile
ok("Ereigniswort trennt: nur echte Anmeldeversuche treffen die failregex der Jail")

# (2) Auch die ABWEISUNG (App-Lockout greift schon) hält sich daran — sonst verschöbe sich das
# Problem nur um eine Zeile: ab der Sperre erzeugt jeder Klick eine weitere.
authf.store.clear_fails(username="anna")
for _ in range(authf.sec("max_login_attempts")):
    authf.record_login("anna", "203.0.113.4", False, "password")
with _Mitschnitt() as m:
    assert authf.is_locked("anna", "203.0.113.4"), "Vorbedingung: der Login-Lockout greift"
assert JAIL.search(m.zeilen()[-1]), f"die Login-Abweisung ist für die Jail unsichtbar: {m.zeilen()[-1]!r}"
authf.store.clear_fails(username="anna")
for _ in range(authf.sec("password_change_max_attempts")):
    authf.record_login("anna", "203.0.113.4", False, "password_change")
with _Mitschnitt() as m:
    assert authf.is_password_change_locked("anna", "203.0.113.4"), "Vorbedingung: der eigene Topf greift"
zeile = m.zeilen()[-1]
assert "reason=lockout_password_change" in zeile, zeile
assert not JAIL.search(zeile), f"die Abweisung des eigenen Topfes trifft die Login-Jail: {zeile!r}"
assert JAIL_PRUEFUNG.search(zeile), zeile
ok("auch die Abweisungen tragen das Wort ihres Topfes (Grund bleibt im Log)")

# (3) Der gemessene Fall aus der Runde: acht Fehlgriffe eines ANGEMELDETEN Nutzers am eigenen
# alten Passwort — mit `maxretry = 6` war das ein Selbst-Bann auf Firewall-Ebene.
authf.store.clear_fails(username="anna")
appf = FastAPI()
appf.include_router(authf.router())
cf = TestClient(appf)
tok_f, _ = authf.start_session(uid_f, "password", remember=True)
cf.cookies.set(authf.cfg.session_cookie, tok_f)
with _Mitschnitt() as m:
    codes = [cf.post("/auth/password", json={"current": f"vertippt{i}", "new": "neues-langes-passwort"}).status_code
             for i in range(8)]
assert 403 in codes and 429 in codes, codes          # geraten wurde, und die App-Sperre griff
zeilen_f = [z for z in m.zeilen() if "user=anna" in z]
assert len(zeilen_f) == 8, f"{len(zeilen_f)} Zeilen — der Vorgang wird nicht mehr protokolliert"
treffer = [z for z in zeilen_f if JAIL.search(z)]
assert not treffer, f"{len(treffer)} von 8 Zeilen bannen den legitimen Nutzer: {treffer[:1]}"
assert all(JAIL_PRUEFUNG.search(z) for z in zeilen_f), zeilen_f[:1]
ok("acht Tippfehler am eigenen Passwortwechsel: protokolliert, aber kein Treffer der Login-Jail")

# (4) Und die Gegenprobe, damit (3) nicht bloss misst, dass nichts mehr greift: Derselbe
# Angriff von aussen — Fehlanmeldungen am Login — füllt die Jail unverändert.
with _Mitschnitt() as m:
    for i in range(6):
        cf.post("/auth/login", data={"username": "anna", "password": f"falsch{i}"})
treffer = [z for z in m.zeilen() if JAIL.search(z)]
assert len(treffer) >= 6, f"nur {len(treffer)} bannbare Zeilen — die Jail bekommt zu wenig zu lesen"
ok("Gegenprobe: Fehlanmeldungen am Login treffen die Jail weiterhin")
os.remove(dbf)

# (5) `is_pin_locked` meldet seine Abweisung wie jede andere Sperre. Bis T-13 wies sie als
# einzige stumm ab — fail2ban bekam genau dann nichts zu lesen, wenn es bannen sollte. Am Login
# ist die PIN ein Anmeldeversuch (`failed login`), auf der Step-up-Seite nicht.
# (Mutationsprobe: in `is_pin_locked` wieder nur zählen, ohne `_sperre_pruefen` → rot.)
dbp = os.path.join(tempfile.mkdtemp(), "t.db")
authp = TinySesam(TinySesamConfig(db_path=dbp, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de", pin_enabled=True, pin_login=True))
authp.create_user("paul", "Paul-Passwort-2026")
for _ in range(authp.sec("pin_max_attempts")):
    authp.record_login("paul", "203.0.113.5", False, "pin")
with _Mitschnitt() as m:
    assert authp.is_pin_locked("paul", "203.0.113.5"), "Vorbedingung: der PIN-Topf greift"
zeilen_p = [z for z in m.zeilen() if "reason=lockout_pin" in z]
assert zeilen_p and JAIL.search(zeilen_p[-1]), f"die PIN-Sperre weist stumm ab: {m.zeilen()!r}"
with _Mitschnitt() as m:
    assert authp.is_pin_locked("paul", "203.0.113.5", login=False)
assert m.zeilen() and not JAIL.search(m.zeilen()[-1]) and JAIL_PRUEFUNG.search(m.zeilen()[-1]), \
    f"auf der Step-up-Seite ist die PIN-Sperre keine Anmeldung: {m.zeilen()!r}"
ok("is_pin_locked meldet die Abweisung (Login: failed login, Step-up: failed verification)")
os.remove(dbp)

# (6) B5-16: Fehlgriffe an /auth/claim-admin — gedrosselt und protokolliert. Bis T-13 durfte
# ein angemeldetes Konto hier beliebig oft raten, spurlos. (Mutationsprobe:
# `admin_claim_fehlgriff` im Router streichen → keine Zeile, kein Audit.)
dbc = os.path.join(tempfile.mkdtemp(), "t.db")
authc = TinySesam(TinySesamConfig(db_path=dbc, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
authc.admin_claim_token()
authc.create_user("clara", "Clara-Passwort-2026")
authc.set_security("rate_limit_max", 5)
appc = FastAPI()
appc.include_router(authc.router())
cc = TestClient(appc, headers={"Accept": "text/html"})
cc.post("/auth/login", data={"username": "clara", "password": "Clara-Passwort-2026"})
with _Mitschnitt() as m:
    codes = [cc.get(f"/auth/claim-admin?token=rate{i}").status_code for i in range(8)]
assert 403 in codes and codes[-1] == 429, f"B5-16: /auth/claim-admin ist nicht gedrosselt: {codes}"
zeilen_c = [z for z in m.zeilen() if "method=claim_admin" in z]
assert len(zeilen_c) == codes.count(403), f"B5-16: {len(zeilen_c)} Zeilen für {codes.count(403)} Fehlgriffe"
assert all(JAIL_PRUEFUNG.search(z) and not JAIL.search(z) for z in zeilen_c), zeilen_c[:1]
fehl = [z for z in authc.store.recent_audit(50) if z["event"] == "admin_claim_fail"]
assert len(fehl) == codes.count(403) and fehl[0]["username"] == "clara" and fehl[0]["ip"], fehl[:1]
ok("B5-16: Fehlgriffe am Erst-Admin-Claim sind gedrosselt, im Audit- und im Sicherheits-Log")
os.remove(dbc)

# (7) Die Bereichs-PIN schreibt einen Grund, den man auswerten kann. `res:<name>` ist nie ein
# Konto — bis T-13 stand bei JEDEM Fehlgriff `grund=kein_konto`.
dbr = os.path.join(tempfile.mkdtemp(), "t.db")
authr = TinySesam(TinySesamConfig(db_path=dbr, cookie_secure=False, passkey_enabled=False,
                                  csrf_enabled=False, lang="de"))
authr.record_login("res:lager", "203.0.113.6", False, "resource")
detail = [z["detail"] for z in authr.store.recent_audit(5) if z["event"] == "login_fail"][0]
assert "grund=falsches_bereichsgeheimnis" in detail and "kein_konto" not in detail, detail
ok("Bereichs-PIN: grund=falsches_bereichsgeheimnis statt des irreführenden kein_konto")
os.remove(dbr)

_abraeumen()
for f in (db, db2, db3):
    if os.path.exists(f):
        os.remove(f)
os.remove(logdatei)
os.rmdir(tmp)
print("\nSECURITY-LOG OK ✅")
