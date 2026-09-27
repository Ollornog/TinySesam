"""Schwebende Vorbuchungen (G9): Das erste Fenster eines LDAP-Ausfalls sperrt niemanden mehr.

Die Login-Route bucht jeden Versuch VORAB als Fehlversuch (R7-2) und nimmt ihn bei einem Ausfall
des Verzeichnisses zurück (F-23) — aber erst, wenn der Ausfall gemeldet ist. Bei einem Verzeichnis,
das Pakete verwirft, ist das nach dem Timeout. Nach dem ersten Ausfall hält der `AusfallMerker`
das kurz; das ERSTE Fenster blieb: Wer in diesen Sekunden anklopfte, sah die hängenden
Vorbuchungen als Fehlversuche — 429 für die Kollegen hinter derselben NAT-Adresse und für den
Notfall-Admin mit richtigem Passwort, dazu `failed login … reason=lockout_ip` für fail2ban und eine
Mail „Gesperrte Anmeldung“ an Unbeteiligte. Danach stand kein einziger Fehlversuch in der Tabelle.

Jetzt schwebt die Vorbuchung in der Datenbank (`login_attempt.offen`). Wer nur an schwebenden
Vorbuchungen scheitern würde, wartet, bis sie entschieden sind — begrenzt in Zeit und Zahl. Die
Salve (R7-2) bleibt gebremst: Sie wartet mit und bekommt dann die echte Sperre.

Die Fristen sind im Test verkürzt (`_SCHWEBE_FRIST_SEK`); das Verzeichnis hängt `HAENGT` Sekunden.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.ldap_ import VerzeichnisNichtErreichbar  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from tinysesam.store import Store, jetzt  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Schwebende Vorbuchungen — das erste Fenster eines LDAP-Ausfalls (G9)")
HAENGT = 1.5
FRIST = 4.0
PW = "Notfall-Pw-15!"
NAT = ("198.51.100.7", 40000)


class Verzeichnis:
    """Ein Verzeichnis mit Launen: hängt bis zum „Timeout“, lehnt schnell ab, oder wirft."""

    def __init__(self, modus="haengt", dauer=HAENGT):
        self.modus = modus
        self.dauer = dauer
        self.fragen = 0
        self._zaehler = threading.Lock()

    def authenticate(self, username, password):
        with self._zaehler:
            self.fragen += 1
        if self.modus == "haengt":
            time.sleep(self.dauer)
            raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: timed out")
        if self.modus == "weg":
            raise VerzeichnisNichtErreichbar("LDAP-Verzeichnis ldap://dummy nicht benutzbar: Test")
        if self.modus == "kaputt":
            raise RuntimeError("unerwarteter Fehler im Client")
        time.sleep(self.dauer)
        if self.modus == "richtig":
            return {"username": username, "email": None, "name": username, "groups": [], "id": f"l-{username}"}
        return None                                    # „falsch“: Passwort abgelehnt


def _aufbau(verzeichnis, **haertung):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, csrf_enabled=False,
                                     passkey_enabled=False, oidc_enabled=False, lang="de",
                                     ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                                     base_url="http://testserver"))
    post: list = []
    auth.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff)))
    auth.set_security("rate_limit_max", 1000)          # eine 429 muss aus der Sperre kommen
    for k, v in haertung.items():
        auth.set_security(k, v)
    auth._SCHWEBE_FRIST_SEK = FRIST
    auth.create_user("admin", password=PW, email="admin@example.com")
    auth.create_user("alice", email="alice@example.com")     # Verzeichnis-Konto ohne lokales Passwort
    auth.ldap = verzeichnis
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post, db


def _anmelden(app, name, pw="x", client=NAT, zeit=None):
    t0 = time.monotonic()
    antwort = TestClient(app, client=client, raise_server_exceptions=False).post(
        "/auth/login", data={"username": name, "password": pw}, follow_redirects=False)
    if zeit is not None:
        zeit.append(time.monotonic() - t0)
    return antwort.status_code


def _failregex(datei):
    text = (ROOT / "deploy" / "fail2ban" / datei).read_text(encoding="utf-8")
    zeile = [z for z in text.splitlines() if z.startswith("failregex =")][0]
    return re.compile(zeile.split("=", 1)[1].strip().replace("<HOST>", r"(?P<host>\S+)"))


class Mitschnitt:
    """Das Sicherheits-Log im Format der ausgelieferten Datei, ohne Zeitstempel (wie fail2ban)."""

    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = logging.StreamHandler(self.puffer)
        self.haken.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        seclog.removeHandler(self.haken)

    def zeilen(self, wort=""):
        return [z for z in self.puffer.getvalue().splitlines() if wort in z]


def _alt_offen(auth, name, ip, anzahl):
    """Offene Vorbuchungen, die niemand abgeschlossen hat (Prozess gestorben) — älter als die Frist."""
    alt = jetzt() - Store.VORBUCHUNG_SCHWEBE_SEK - 1
    for _ in range(anzahl):
        auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                         "VALUES (?,?,?,0,'password',1)", (alt, name, ip))


# ── (a) Das erste Fenster: niemand wird gesperrt, der Notfall-Admin kommt hinein ─────────────
auth, app, post, db = _aufbau(Verzeichnis("haengt"))
paar = auth.sec("max_login_attempts")
schwelle_ip = paar * auth.sec("ip_attempt_factor")
with Mitschnitt() as log_a, ThreadPoolExecutor(max_workers=schwelle_ip + 4) as pool:
    # Die ungeduldige Alice klickt fünfmal, das Büro hinter derselben NAT-Adresse meldet sich an.
    laufend = [pool.submit(_anmelden, app, "alice") for _ in range(paar)]
    laufend += [pool.submit(_anmelden, app, f"kollege{i}") for i in range(schwelle_ip - paar)]
    time.sleep(HAENGT * 0.4)
    schwebend = auth.store.count_fails(0, ip=NAT[0])
    bestaetigt = auth.store.count_fails(0, ip=NAT[0], nur_bestaetigt=True)
    zeit_admin: list = []
    alice6 = pool.submit(_anmelden, app, "alice")
    admin = pool.submit(_anmelden, app, "admin", PW, NAT, zeit_admin)
    alice6, admin = alice6.result(timeout=30), admin.result(timeout=30)
    haengende = [f.result(timeout=30) for f in laufend]
auth._hinweis_ausgang.abwarten()
r.check("Vorbedingung: im ersten Fenster schweben so viele Vorbuchungen wie die IP-Schwelle",
        schwebend == schwelle_ip and bestaetigt == 0, f"{schwebend} gezählt, {bestaetigt} bestätigt")
r.check("Vorbedingung: der Admin hat gewartet (die Sperre hätte gegriffen)",
        zeit_admin and zeit_admin[0] >= HAENGT * 0.3, f"{zeit_admin}")
r.check("der Notfall-Admin kommt mit richtigem Passwort hinein (303, nicht 429)", admin == 303, f"{admin}")
r.check("Alices sechster Klick bekommt den Ausfall (503), keine Sperre", alice6 == 503, f"{alice6}")
r.check("die hängenden Anläufe enden mit 503", set(haengende) == {503}, f"{sorted(set(haengende))}")
r.check("kein `failed login` im Sicherheits-Log (fail2ban bannt die NAT-Adresse nicht)",
        not log_a.zeilen("failed login"), "; ".join(log_a.zeilen("failed login"))[:300])
r.check("keine Mail „Gesperrte Anmeldung“ an Unbeteiligte", post == [], f"{post}")
r.check("danach steht kein Fehlversuch der Adresse in der Tabelle",
        auth.store.count_fails(0, ip=NAT[0]) == 0, f"{auth.store.count_fails(0, ip=NAT[0])}")
os.remove(db)

# ── (b) R7-2 bleibt: eine Salve wartet mit und bekommt dann die echte Sperre ───────────────
# Das Verzeichnis lehnt schnell ab. Genau `max_login_attempts` Versuche erreichen es; der Rest wartet
# auf deren Ausgang (oder bekommt ohne Warteplatz sofort den Aufschub) und läuft dann in die Sperre.
verz_b = Verzeichnis("falsch", dauer=0.3)
auth, app, post, db = _aufbau(verz_b)
paar = auth.sec("max_login_attempts")
with Mitschnitt() as log_b, ThreadPoolExecutor(max_workers=3 * paar) as pool:
    salve = list(pool.map(lambda i: _anmelden(app, "alice", f"falsch{i}"), range(3 * paar)))
auth._hinweis_ausgang.abwarten()
r.check("R7-2: genau max_login_attempts Versuche erreichen das Verzeichnis",
        verz_b.fragen == paar, f"{verz_b.fragen} von {3 * paar}")
r.check("R7-2: die übrigen bekommen 429", sorted(salve) == [401] * paar + [429] * (2 * paar), f"{sorted(salve)}")
r.check("R7-2: die Sperre steht mit `reason=lockout_user` im Sicherheits-Log",
        any("failed login user=alice" in z and "reason=lockout_user" in z for z in log_b.zeilen()),
        "; ".join(log_b.zeilen())[:400])
r.check("R7-2: die echten Fehlversuche stehen als `failed login … method=password` darin",
        len([z for z in log_b.zeilen("failed login user=alice") if "method=password" in z]) == paar)
r.check("R7-2: nach der Salve ist nichts mehr offen",
        auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE offen=1")["n"] == 0)
os.remove(db)

# ── (c) Eine offene Vorbuchung, die niemand abschliesst, wird nach der Frist ein Fehlversuch ──
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0))
_alt_offen(auth, "alice", NAT[0], auth.sec("max_login_attempts"))
zeit_c: list = []
with Mitschnitt() as log_c:
    status_c = _anmelden(app, "alice", zeit=zeit_c)
r.check("verwaiste Vorbuchungen: sofortige Sperre (429), kein Warten",
        status_c == 429 and zeit_c[0] < FRIST / 2, f"{status_c} nach {zeit_c[0]:.1f} s")
r.check("verwaiste Vorbuchungen: `reason=lockout_user` im Log, kein Aufschub",
        any("reason=lockout_user" in z for z in log_c.zeilen("failed login"))
        and not log_c.zeilen("deferred"), "; ".join(log_c.zeilen())[:300])
os.remove(db)

# Dasselbe für die Serie (B2-6): Eine alte offene Vorbuchung zählt dort mit.
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0), max_login_attempts=100)
grenze_s = auth.sec("account_max_consecutive_failures")
_alt_offen(auth, "alice", "192.0.2.50", grenze_s)
for _ in range(grenze_s):
    auth.store.fehlserie_erhoehen("alice")
zeit_c2: list = []
with Mitschnitt() as log_c2:
    status_c2 = _anmelden(app, "alice", zeit=zeit_c2)
r.check("verwaiste Vorbuchungen in der Serie: sofort `lockout_serie`, kein Aufschub",
        status_c2 == 429 and zeit_c2[0] < FRIST / 2
        and any("reason=lockout_serie" in z for z in log_c2.zeilen("failed login"))
        and not log_c2.zeilen("deferred"), f"{status_c2} nach {zeit_c2[0]:.1f} s; {log_c2.zeilen()}"[:400])
os.remove(db)

# Greift eine Regel schon mit den bestätigten Zeilen, geht sie vor — kein Warten auf eine andere,
# die nur schwebend greift. Hier schweben fünf Vorbuchungen von Alice (ein anderer Prozess prüft
# sie gerade), und die Adresse hat ihre Schwelle mit bestätigten Fehlversuchen schon erreicht.
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0))
for _ in range(auth.sec("max_login_attempts")):
    auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                     "VALUES (?,'alice',?,0,'password',1)", (jetzt(), NAT[0]))
for i in range(auth.sec("max_login_attempts") * auth.sec("ip_attempt_factor")):
    auth.store.record_attempt(f"kollege{i}", NAT[0], False, "password")
zeit_c3: list = []
with Mitschnitt() as log_c3:
    status_c3 = _anmelden(app, "alice", zeit=zeit_c3)
r.check("eine bestätigt greifende Regel geht der schwebenden vor: sofort `lockout_ip`",
        status_c3 == 429 and zeit_c3[0] < FRIST / 2
        and any("reason=lockout_ip" in z for z in log_c3.zeilen("failed login"))
        and not log_c3.zeilen("deferred"), f"{status_c3} nach {zeit_c3[0]:.1f} s; {log_c3.zeilen()}"[:400])
os.remove(db)

# ── (d) Die Serie: Eine hängende Vorbuchung an der Grenze löst keine Serien-Sperre aus ─────────
verz_d = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_d, max_login_attempts=100)
grenze_s = auth.sec("account_max_consecutive_failures")
for _ in range(grenze_s - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_d, ThreadPoolExecutor(max_workers=2) as pool:
    haengend_d = pool.submit(_anmelden, app, "alice", "x", ("192.0.2.60", 40000))
    time.sleep(HAENGT * 0.4)
    stand_d = (auth.store.fehlserie("alice"), auth.store.fehlserie_bestaetigt("alice"))
    parallel_d = pool.submit(_anmelden, app, "alice", "y", ("192.0.2.61", 40000)).result(timeout=30)
    haengend_d = haengend_d.result(timeout=30)
auth._hinweis_ausgang.abwarten()
r.check("Vorbedingung: die Serie steht mit der hängenden Vorbuchung an der Grenze",
        stand_d == (grenze_s, grenze_s - 1), f"{stand_d}")
r.check("paralleler Login an der Grenze: Ausfall (503), keine Serien-Sperre",
        parallel_d == 503 and haengend_d == 503, f"{parallel_d}, {haengend_d}")
r.check("paralleler Login an der Grenze: kein `lockout_serie`, keine Sperrmail",
        not any("lockout_serie" in z for z in log_d.zeilen()) and post == [], f"{log_d.zeilen()} {post}"[:300])
r.check("…und die Serie steht danach wieder bei grenze−1", auth.store.fehlserie("alice") == grenze_s - 1,
        f"{auth.store.fehlserie('alice')}")
os.remove(db)

# Ohne Warteplatz an derselben Stelle: Der Aufschub zeigt nicht den Text der Serien-Sperre („bis du
# dein Passwort zurücksetzt“), und `is_locked` meldet ihn als Aufschub — ohne `lockout_serie`, ohne Mail.
verz_d3 = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_d3, max_login_attempts=100)
auth._schwebe_plaetze = threading.BoundedSemaphore(1)
auth._schwebe_plaetze.acquire()                          # alle Warteplätze belegt
for _ in range(grenze_s - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_d3, ThreadPoolExecutor(max_workers=1) as pool:
    haengend_d3 = pool.submit(_anmelden, app, "alice", "x", ("192.0.2.60", 40000))
    time.sleep(HAENGT * 0.4)
    seite_d3 = TestClient(app, client=("192.0.2.61", 40000)).post(
        "/auth/login", data={"username": "alice", "password": "y"}, follow_redirects=False)
    gesperrt_d3 = auth.is_locked("alice", "192.0.2.62")
    haengend_d3.result(timeout=30)
auth._hinweis_ausgang.abwarten()
r.check("Aufschub an der Serien-Grenze: 429 mit dem Text der Fenster-Sperre, nicht der Serien-Sperre",
        seite_d3.status_code == 429 and auth.t("err.locked") in seite_d3.text
        and "in Folge" not in seite_d3.text and "in Folge" in auth.t("err.locked_serie"),
        f"{seite_d3.status_code}")
r.check("is_locked an der Serien-Grenze mit schwebender Vorbuchung: True, als Aufschub",
        gesperrt_d3 and len(log_d3.zeilen("deferred login")) == 2
        and not any("lockout_serie" in z for z in log_d3.zeilen()) and post == [],
        f"{gesperrt_d3} {log_d3.zeilen()} {post}"[:400])
os.remove(db)

# Rücknahme und Abschluss senken die Serie in DERSELBEN Transaktion wie die Zeile. Getrennt stand
# die Vorbuchung dazwischen weder als offen noch als zurückgenommen da, und wer gerade wartet, las
# die Serie um eins zu hoch — an der Grenze eine Sperre samt Sperrmail für nichts.
verz_t = Verzeichnis("weg")
auth, app, post, db = _aufbau(verz_t)
aufrufe: list = []
_echt = auth.store._serie_minus


def _spion(topf, art):
    aufrufe.append((topf, art, auth.store.db.in_transaction))
    return _echt(topf, art)


auth.store._serie_minus = _spion
_anmelden(app, "alice")                                  # Ausfall → Rücknahme
verz_t.modus, verz_t.dauer = "richtig", 0
auth._ldap_ausfall = type(auth._ldap_ausfall)()          # der Merker ist nach dem Ausfall scharf
status_t = _anmelden(app, "alice")                       # Erfolg → Abschluss
r.check("Rücknahme und Erfolg senken die Serie in der Transaktion der Zeile",
        aufrufe == [("alice", "password", True), ("alice", "password", True)] and status_t == 303,
        f"{aufrufe}, {status_t}")
r.check("…und die Serie steht danach bei 0", auth.store.fehlserie("alice") == 0, f"{auth.store.fehlserie('alice')}")
os.remove(db)

# ── (e) Warteplätze: Wer keinen bekommt, bekommt sofort den Aufschub — ohne Sperre ────────────
auth, app, post, db = _aufbau(Verzeichnis("haengt"), max_login_attempts=1)
auth._schwebe_plaetze = threading.BoundedSemaphore(1)
zeiten_e: list = []
with Mitschnitt() as log_e, ThreadPoolExecutor(max_workers=3) as pool:
    haengend_e = pool.submit(_anmelden, app, "alice")
    time.sleep(HAENGT * 0.3)
    wartende = [pool.submit(_anmelden, app, "alice", "x", NAT, zeiten_e) for _ in range(2)]
    status_e = sorted(f.result(timeout=30) for f in wartende)
    haengend_e = haengend_e.result(timeout=30)
auth._hinweis_ausgang.abwarten()
zeiten_e.sort()
r.check("ohne Warteplatz: sofort 429, der andere wartet und bekommt den Ausfall (503)",
        status_e == [429, 503] and zeiten_e[0] < HAENGT * 0.4 <= zeiten_e[1],
        f"{status_e}, Zeiten {[round(z, 2) for z in zeiten_e]}")
deferred = log_e.zeilen("deferred login")
r.check("ohne Warteplatz: `deferred login … reason=pending` im Log, kein `failed login`, keine Mail",
        len(deferred) == 1 and "user=alice" in deferred[0] and "reason=pending" in deferred[0]
        and not log_e.zeilen("failed login") and post == [], f"{log_e.zeilen()} {post}"[:400])

# ── (g) Die mitgelieferten fail2ban-Filter treffen den Aufschub nicht ──────────────────────
jail, jail_pruefung = _failregex("tinysesam-filter.conf"), _failregex("tinysesam-verify-filter.conf")
r.check("die failregex beider Jails trifft `deferred login` nicht",
        deferred and not any(j.search(z) for z in deferred for j in (jail, jail_pruefung)), f"{deferred}")
r.check("Gegenprobe: dieselbe Zeile als `failed login` träfe die Jail",
        deferred and bool(jail.search(deferred[0].replace("deferred login", "failed login")
                                      .replace(" reason=", " method=blocked reason="))))
os.remove(db)

# ── (h) is_locked: ein Aufschub ist True, aber ohne Sperrmail und ohne `failed login` ─────────
auth, app, post, db = _aufbau(Verzeichnis("haengt"))
with Mitschnitt() as log_h, ThreadPoolExecutor(max_workers=auth.sec("max_login_attempts")) as pool:
    laufend = [pool.submit(_anmelden, app, "alice") for _ in range(auth.sec("max_login_attempts"))]
    time.sleep(HAENGT * 0.4)
    gesperrt_h = auth.is_locked("alice", NAT[0])
    [f.result(timeout=30) for f in laufend]
    frei_h = not auth.is_locked("alice", NAT[0])
auth._hinweis_ausgang.abwarten()
r.check("is_locked während schwebender Vorbuchungen: True, danach False", gesperrt_h and frei_h,
        f"{gesperrt_h}, {frei_h}")
r.check("is_locked beim Aufschub: `deferred login`, kein `failed login`, keine Mail",
        log_h.zeilen("deferred login") and not log_h.zeilen("failed login") and post == [],
        f"{log_h.zeilen()} {post}"[:300])
os.remove(db)

# ── (f) Eine unerwartete Ausnahme lässt keine schwebende Zeile zurück ───────────────────────
auth, app, post, db = _aufbau(Verzeichnis("kaputt"))
status_f = _anmelden(app, "alice")
zeilen_f = [(z["offen"], z["success"]) for z in auth.store._all("SELECT offen, success FROM login_attempt")]
r.check("Ausnahme im Verzeichnis-Client: 500, der Versuch ist ein bestätigter Fehlversuch",
        status_f == 500 and zeilen_f == [(0, 0)], f"{status_f}, {zeilen_f}")
os.remove(db)

# ── (i) p2 F3: `lockout_serie` genau beim Übergang des feststehenden Stands ────────────────────
# Bis 2026-09-27 protokollierte ein Fehlversuch den Serienstand bei SEINER Buchung, samt schwebender
# Vorbuchungen. Die Inhaberin (richtiges Passwort) und ein Angreifer (falsch) schweben gleichzeitig,
# die Serie steht bei grenze−2: Die Inhaberin wird voll angemeldet und beendet die Serie, der
# Angreifer scheitert mit dem gebuchten Stand = grenze — `lockout_serie` im Audit-Log und „gesperrt“
# im Sicherheits-Log, obwohl nichts gesperrt war.
RICHTIG_I = "richtig-im-verz"


class Pruefendes(Verzeichnis):
    """Nimmt genau ein Passwort an, nach `dauer` Sekunden."""

    def authenticate(self, username, password):
        with self._zaehler:
            self.fragen += 1
        time.sleep(self.dauer)
        if password == RICHTIG_I:
            return {"username": username, "email": None, "name": username, "groups": [], "id": f"l-{username}"}
        return None


def _serien_zeilen(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM audit WHERE event='lockout_serie'")["n"]


auth, app, post, db = _aufbau(Pruefendes(dauer=0.6), max_login_attempts=1000,
                              account_max_consecutive_failures=10)
grenze_i = auth.sec("account_max_consecutive_failures")
for _ in range(grenze_i - 2):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_i, ThreadPoolExecutor(max_workers=2) as pool:
    inhaberin = pool.submit(_anmelden, app, "alice", RICHTIG_I, ("198.51.100.1", 40000))
    time.sleep(0.15)
    angreifer = pool.submit(_anmelden, app, "alice", "falsch", ("203.0.113.66", 40000))
    inhaberin, angreifer = inhaberin.result(timeout=30), angreifer.result(timeout=30)
auth._hinweis_ausgang.abwarten()
# (Mutationsprobe: in `record_login` wieder `stand = vorgebucht[2]` und `stand == grenze`, dazu in
#  `reserve_attempt` die Summe statt des feststehenden Stands → eine Zeile → rot.)
r.check("p2 F3: Inhaberin und Angreifer schweben an grenze−2, die Inhaberin beendet die Serie — "
        "kein `lockout_serie` im Audit-Log, kein „gesperrt“ im Sicherheits-Log",
        inhaberin == 303 and angreifer == 401 and auth.store.fehlserie("alice") == 0
        and _serien_zeilen(auth) == 0 and not log_i.zeilen("gesperrt") and post == [],
        f"{inhaberin}/{angreifer}, Serie {auth.store.fehlserie('alice')}, Zeilen {_serien_zeilen(auth)}, "
        f"{log_i.zeilen('gesperrt')} {post}"[:400])
os.remove(db)

# Gegenprobe: die echte Sperre per Salve — genau eine Zeile, mit Schweben (LDAP) und ohne.
verz_i2 = Verzeichnis("falsch", dauer=0.3)
auth, app, post, db = _aufbau(verz_i2, max_login_attempts=1000, account_max_consecutive_failures=10)
for _ in range(grenze_i - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_i2, ThreadPoolExecutor(max_workers=6) as pool:
    salve_i2 = sorted(pool.map(lambda i: _anmelden(app, "alice", f"falsch{i}", (f"192.0.2.{20 + i}", 40000)),
                               range(6)))
auth._hinweis_ausgang.abwarten()
r.check("p2 F3 Gegenprobe mit LDAP (schwebend): Salve an grenze−1 → eine Frage ans Verzeichnis, Serie "
        "steht, genau eine Zeile `lockout_serie`",
        verz_i2.fragen == 1 and salve_i2 == [401] + [429] * 5
        and auth.store.fehlserie_bestaetigt("alice") == grenze_i and _serien_zeilen(auth) == 1
        and len(log_i2.zeilen("gesperrt: ")) == 1,
        f"{verz_i2.fragen} {salve_i2} {auth.store.fehlserie_bestaetigt('alice')} {_serien_zeilen(auth)}")
os.remove(db)

db_i3 = str(Path(tempfile.mkdtemp()) / "t.db")
auth_i3 = TinySesam(TinySesamConfig(db_path=db_i3, cookie_secure=False, csrf_enabled=False,
                                    passkey_enabled=False, oidc_enabled=False, lang="de"))
for k, v in (("rate_limit_max", 1000), ("max_login_attempts", 1000), ("account_max_consecutive_failures", 10)):
    auth_i3.set_security(k, v)
auth_i3.create_user("bert", password=PW)
app_i3 = FastAPI()
app_i3.include_router(auth_i3.router())
for _ in range(grenze_i - 1):
    auth_i3.store.fehlserie_erhoehen("bert")
with ThreadPoolExecutor(max_workers=6) as pool:
    salve_i3 = sorted(pool.map(lambda i: _anmelden(app_i3, "bert", f"falsch{i}", (f"192.0.2.{40 + i}", 40000)),
                               range(6)))
r.check("p2 F3 Gegenprobe ohne LDAP (sofort feststehend): Salve an grenze−1 → genau eine Zeile `lockout_serie`",
        salve_i3 == [401] + [429] * 5 and _serien_zeilen(auth_i3) == 1, f"{salve_i3} {_serien_zeilen(auth_i3)}")
# Sofort feststehende Buchung über die Grenze, die Serie wird vor ihrem Abschluss beendet (eine volle
# Anmeldung auf einem anderen Weg): keine Zeile. Und gemischt — eine schwebende und eine sofort
# feststehende an der Grenze, in beiden Reihenfolgen abgeschlossen: genau eine.
auth_i3.store.fehlserie_loeschen("bert")
for _ in range(grenze_i - 1):
    auth_i3.store.fehlserie_erhoehen("bert")
_vor_i3 = _serien_zeilen(auth_i3)
_v = auth_i3.versuch_beginnen("bert", "192.0.2.60", "pin")
auth_i3.sperre_aufheben(auth_i3.store.get_user_by_name("bert")["id"])
auth_i3.record_login("bert", "192.0.2.60", False, "pin", versuch=_v)
# (Mutationsprobe: in `record_login` `min(vorgebucht[2], nachher)` durch `vorgebucht[2]` ersetzen → rot.)
r.check("p2 F3: Buchung über die Grenze, Serie vor dem Abschluss beendet → keine Zeile",
        _v is not None and _serien_zeilen(auth_i3) == _vor_i3, f"{_v} {_serien_zeilen(auth_i3) - _vor_i3}")
_gemischt = []
for reihenfolge in ("schwebend zuerst", "feststehend zuerst"):
    auth_i3.store.fehlserie_loeschen("bert")
    for _ in range(grenze_i - 2):
        auth_i3.store.fehlserie_erhoehen("bert")
    _vor = _serien_zeilen(auth_i3)
    _s = auth_i3.versuch_beginnen("bert", "192.0.2.61", "password", schweben=True)
    _f = auth_i3.versuch_beginnen("bert", "192.0.2.62", "pin")
    for v, m in ((_s, "password"), (_f, "pin"))[::1 if reihenfolge == "schwebend zuerst" else -1]:
        auth_i3.record_login("bert", "192.0.2.61", False, m, versuch=v)
    _gemischt.append((reihenfolge, _s is not None and _f is not None, _serien_zeilen(auth_i3) - _vor))
# (Mutationsprobe: `vorher < max_serie <= nachher` streichen → „schwebend zuerst" 0 Zeilen → rot.)
r.check("p2 F3: schwebende und sofort feststehende Buchung an der Grenze — in beiden Reihenfolgen genau eine Zeile",
        all(ok_ and n == 1 for _, ok_, n in _gemischt), str(_gemischt))
auth_i3.store.db.close()
os.remove(db_i3)

# ── (j) p2 V1: eine Gesamtfrist für die Frage ans Verzeichnis ──────────────────────────────────
# Die Vorbuchung schwebt höchstens `Store.VORBUCHUNG_SCHWEBE_SEK`; danach gilt sie als Fehlversuch
# eines gestorbenen Prozesses. ldap3 kennt nur eine Frist je Antwort (10 s), und ein Search-then-Bind
# mit StartTLS wartet bis zu zehnmal: Ein langsames, aber antwortendes Verzeichnis liess eine noch
# laufende Anmeldung als bestätigten Fehlversuch zählen. Gemessen mit einem untergeschobenen ldap3 und
# einer Uhr, die nur die Attrappe vorstellt — ohne echte Wartezeit.
import types as _types  # noqa: E402

from tinysesam import ldap_ as _ldap_mod  # noqa: E402


class _Uhr:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


def _ldap3_langsam(uhr, antwort_sek, mitschrift):
    """ldap3-Attrappe: Jede Antwort braucht `antwort_sek`; ist die Frist der Wartestelle kürzer,
    endet sie nach der Frist mit dem Fehler, den ldap3 dort wirft."""
    mod = _types.ModuleType("ldap3")
    mod.NONE, mod.BASE = "NONE", "BASE"
    mod.AUTO_BIND_NO_TLS, mod.AUTO_BIND_TLS_BEFORE_BIND = "NO_TLS", "TLS_BEFORE_BIND"
    kern = _types.ModuleType("ldap3.core")
    lx = _types.ModuleType("ldap3.core.exceptions")
    for name in ("LDAPException", "LDAPCommunicationError", "LDAPStartTLSError", "LDAPBindError",
                 "LDAPMaximumRetriesError", "LDAPSSLConfigurationError"):
        setattr(lx, name, type(name, (Exception,), {}))
    lx.LDAPSocketOpenError = type("LDAPSocketOpenError", (lx.LDAPCommunicationError,), {})
    lx.LDAPSocketReceiveError = type("LDAPSocketReceiveError", (lx.LDAPCommunicationError,), {})

    def warten(frist, fehler):
        if antwort_sek >= frist:
            uhr.t += frist
            raise fehler("timed out")
        uhr.t += antwort_sek

    class Tls:
        def __init__(self, **kw):
            pass

    class Server:
        def __init__(self, url, **kw):
            self.url, self.connect_timeout = url, kw.get("connect_timeout")

    class Eintrag:
        entry_dn = "uid=alice,ou=people,dc=example,dc=com"

        def __contains__(self, name):
            return False

    class Connection:
        def __init__(self, server, **kw):
            self.server, self.frist, self.entries = server, kw.get("receive_timeout"), []
            mitschrift.append((server.connect_timeout, self.frist))
            if kw.get("auto_bind"):
                self.open()
                if kw["auto_bind"] == "TLS_BEFORE_BIND":
                    self.start_tls()
                self.bind()

        def open(self):
            warten(self.server.connect_timeout, lx.LDAPSocketOpenError)
            if self.server.url.startswith("ldaps://"):
                warten(self.frist, lx.LDAPSocketReceiveError)       # TLS-Handschlag

        def start_tls(self):
            warten(self.frist, lx.LDAPSocketReceiveError)           # Antwort auf StartTLS
            warten(self.frist, lx.LDAPSocketReceiveError)           # TLS-Handschlag

        def bind(self):
            warten(self.frist, lx.LDAPSocketReceiveError)
            return True

        def search(self, *a, **kw):
            warten(self.frist, lx.LDAPSocketReceiveError)
            self.entries = [Eintrag()]
            return True

        def unbind(self):
            pass

    mod.Tls, mod.Server, mod.Connection = Tls, Server, Connection
    conv = _types.ModuleType("ldap3.utils.conv")
    conv.escape_filter_chars = lambda v, encoding=None: v
    dn = _types.ModuleType("ldap3.utils.dn")
    dn.escape_rdn = lambda v: v
    return {"ldap3": mod, "ldap3.core": kern, "ldap3.core.exceptions": lx,
            "ldap3.utils": _types.ModuleType("ldap3.utils"), "ldap3.utils.conv": conv, "ldap3.utils.dn": dn}


_LDAP3_NAMEN = ("ldap3", "ldap3.core", "ldap3.core.exceptions", "ldap3.utils", "ldap3.utils.conv",
                "ldap3.utils.dn")


def _langsam_fragen(antwort_sek, **cfg):
    """(Ausgang, verstrichene Sekunden, Fristen je Verbindung) einer Anmeldung gegen die Attrappe."""
    uhr, mitschrift = _Uhr(), []
    vorher = {n: sys.modules.get(n) for n in _LDAP3_NAMEN}
    zeit_vorher = _ldap_mod.time
    grund = dict(db_path=":memory:", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
                 ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="svc",
                 ldap_user_base="ou=people,dc=example,dc=com")
    grund.update(cfg)
    try:
        sys.modules.update(_ldap3_langsam(uhr, antwort_sek, mitschrift))
        _ldap_mod.time = uhr
        start = uhr.t
        try:
            ausgang = "angemeldet" if _ldap_mod.LDAPClient(TinySesamConfig(**grund)).authenticate("alice", "pw") \
                else "abgewiesen"
        except _ldap_mod.VerzeichnisNichtErreichbar:
            ausgang = "nicht erreichbar"
        return ausgang, uhr.t - start, mitschrift
    finally:
        _ldap_mod.time = zeit_vorher
        for n, m in vorher.items():
            if m is None:
                sys.modules.pop(n, None)
            else:
                sys.modules[n] = m


_faelle_j = {"Search-then-Bind + StartTLS": dict(ldap_start_tls=True),
             "Search-then-Bind, ldaps://": dict(ldap_url="ldaps://verzeichnis.example.com"),
             "Search-then-Bind, ohne TLS": dict(),
             "Direkt-Bind + StartTLS": dict(ldap_start_tls=True, ldap_bind_dn="", ldap_bind_password="",
                                            ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com")}
_messung_j = {(name, sek): _langsam_fragen(sek, **cfg)[:2]
              for name, cfg in _faelle_j.items() for sek in (0.01, 1.2, 1.9, 2.9, 4.5, 9.5)}
_zu_lang_j = {k: v for k, v in _messung_j.items() if v[1] > _ldap_mod.GESAMT_FRIST_SEK}
# (Mutationsprobe: in `_Frist.je_wartestelle` wieder immer `VERBINDUNGS_TIMEOUT` → bis zu 95 s → rot.)
r.check("p2 V1: jede Anmeldung gegen ein langsames, aber antwortendes Verzeichnis endet innerhalb der "
        f"Gesamtfrist ({_ldap_mod.GESAMT_FRIST_SEK} s) — angemeldet oder „nicht erreichbar“, nie „abgewiesen“",
        not _zu_lang_j and all(a in ("angemeldet", "nicht erreichbar") for a, _ in _messung_j.values()),
        f"zu lang: {_zu_lang_j}; {[(k, v) for k, v in _messung_j.items() if v[0] == 'abgewiesen']}")
r.check("… ein schnelles Verzeichnis merkt nichts: angemeldet, das Dienstkonto mit der halben, die "
        "Benutzer-Verbindung mit der ganzen Restfrist je Antwort (höchstens 10 s)",
        all(_messung_j[(n, 0.01)][0] == "angemeldet" for n in _faelle_j)
        and _langsam_fragen(0.01)[2] == [(4, 4), (8, 8)], str(_langsam_fragen(0.01)[2]))
r.check("… und die Gesamtfrist liegt mit Luft unter der Schwebezeit der Vorbuchung",
        _ldap_mod.GESAMT_FRIST_SEK + 5 <= Store.VORBUCHUNG_SCHWEBE_SEK,
        f"{_ldap_mod.GESAMT_FRIST_SEK} / {Store.VORBUCHUNG_SCHWEBE_SEK}")
_frist_vorher = _ldap_mod.GESAMT_FRIST_SEK
try:
    _ldap_mod.GESAMT_FRIST_SEK = 5                    # reicht für keine Sekunde je Wartestelle
    _knapp_j = _langsam_fragen(0.01, ldap_start_tls=True)
finally:
    _ldap_mod.GESAMT_FRIST_SEK = _frist_vorher
# (Mutationsprobe: `except VerzeichnisNichtErreichbar: raise` in `authenticate` streichen → „abgewiesen“,
#  ein Fehlversuch für die Langsamkeit des Verzeichnisses → rot.)
r.check("p2 V1: reicht die Frist nicht, gilt das Verzeichnis als nicht erreichbar, bevor es gefragt wird "
        "(kein Fehlversuch)", _knapp_j[0] == "nicht erreichbar" and _knapp_j[2] == [], str(_knapp_j))

# ── Ohne LDAP schwebt nichts, und die Spalte kommt auch in eine Datei, die schon Schema 11 trägt ─
db_o = str(Path(tempfile.mkdtemp()) / "t.db")
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, csrf_enabled=False,
                                   passkey_enabled=False, oidc_enabled=False, lang="de"))
auth_o.create_user("bert", password=PW)
app_o = FastAPI()
app_o.include_router(auth_o.router())
_anmelden(app_o, "bert", "falsch")
r.check("ohne LDAP: der Fehlversuch ist sofort bestätigt (offen=0)",
        [z["offen"] for z in auth_o.store._all("SELECT offen FROM login_attempt")] == [0])
auth_o.store.db.close()
roh = sqlite3.connect(db_o)
roh.execute("ALTER TABLE login_attempt DROP COLUMN offen")
stempel = roh.execute("PRAGMA user_version").fetchone()[0]
roh.close()
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, passkey_enabled=False, oidc_enabled=False))
spalten = {z["name"] for z in auth_o.store._all("PRAGMA table_info(login_attempt)")}
r.check("eine Datei auf Schema 11 ohne die Spalte bekommt sie beim Start (idempotent)",
        stempel == Store.SCHEMA_VERSION == 11 and "offen" in spalten
        and auth_o.store.count_fails(0, username="bert", nur_bestaetigt=True) == 1, f"{stempel} {spalten}")
auth_o.store.db.close()
os.remove(db_o)

sys.exit(r.done())
