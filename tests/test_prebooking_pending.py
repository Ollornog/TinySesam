"""Pending pre-bookings (G9): the first window of an LDAP outage no longer locks anyone out.

The login route books every attempt IN ADVANCE as a failed attempt (R7-2) and withdraws it when the
directory is down (F-23) — but only once the outage has been reported. For a directory
that drops packets, that is after the timeout. After the first outage the `AusfallMerker`
keeps it short; the FIRST window remained: whoever knocked during those seconds saw the hanging
pre-bookings as failed attempts — 429 for the colleagues behind the same NAT address and for the
emergency admin with the correct password, plus `failed login … reason=lockout_ip` for fail2ban and a
"Locked sign-in" mail to bystanders. Afterwards not a single failed attempt was in the table.

Now the pre-booking is pending in the database (`login_attempt.offen`). Whoever would fail only on pending
pre-bookings waits until they are decided — bounded in time and number. The
burst (R7-2) stays throttled: it waits along and then gets the real lockout.

The deadlines are shortened in the test (`_SCHWEBE_FRIST_SEK`); the directory hangs for `HAENGT` seconds.
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
    """A moody directory: hangs until the "timeout", rejects quickly, or raises."""

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


def warte_bis(bedingung, was, frist=20.0):
    """Wait until `bedingung()` is true — instead of a fixed time (T-18).

    Until 2026-10-07 these places had `time.sleep(HAENGT * 0.4)` in the hope that the
    parallel sign-ins had arrived in the hanging directory by then. Under load that once was not
    enough (CI job repeat, PR #108): the precondition was read before all were there. Now
    it is read as soon as they are there; if the state does not come, that is a named error."""
    ende = time.monotonic() + frist
    while not bedingung():
        if time.monotonic() > ende:
            raise AssertionError(f"Zeitüberschreitung ({frist} s): {was}")
        time.sleep(0.01)


def _aufbau(verzeichnis, **haertung):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    auth = TinySesam(TinySesamConfig(db_path=db, cookie_secure=False, csrf_enabled=False,
                                     passkey_enabled=False, oidc_enabled=False, lang="de",
                                     ldap_enabled=True, ldap_url="ldap://dummy", ldap_allow_plaintext=True,
                                     base_url="http://testserver"))
    post: list = []
    auth.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff)))
    auth.set_security("rate_limit_max", 1000)          # a 429 must come from the lockout
    for k, v in haertung.items():
        auth.set_security(k, v)
    auth._SCHWEBE_FRIST_SEK = FRIST
    auth.create_user("admin", password=PW, email="admin@example.com")
    auth.create_user("alice", email="alice@example.com")     # directory account without a local password
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
    """The security log in the format of the shipped file, without timestamp (like fail2ban)."""

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
    """Open pre-bookings that nobody completed (process died) — older than the deadline."""
    alt = jetzt() - Store.VORBUCHUNG_SCHWEBE_SEK - 1
    for _ in range(anzahl):
        auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                         "VALUES (?,?,?,0,'password',1)", (alt, name, ip))


# ── (a) The first window: nobody gets locked out, the emergency admin gets in ─────────────────
verz_a = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_a)
paar = auth._sec("max_login_attempts")
schwelle_ip = paar * auth._sec("ip_attempt_factor")
with Mitschnitt() as log_a, ThreadPoolExecutor(max_workers=schwelle_ip + 4) as pool:
    # Impatient Alice clicks five times, the office behind the same NAT address signs in.
    laufend = [pool.submit(_anmelden, app, "alice") for _ in range(paar)]
    laufend += [pool.submit(_anmelden, app, f"kollege{i}") for i in range(schwelle_ip - paar)]
    warte_bis(lambda: verz_a.fragen >= schwelle_ip, f"{schwelle_ip} Anläufe im hängenden Verzeichnis")
    schwebend = auth.store.count_fails(0, ip=NAT[0])
    bestaetigt = auth.store.count_fails(0, ip=NAT[0], nur_bestaetigt=True)
    zeit_admin: list = []
    alice6 = pool.submit(_anmelden, app, "alice")
    admin = pool.submit(_anmelden, app, "admin", PW, NAT, zeit_admin)
    alice6, admin = alice6.result(timeout=30), admin.result(timeout=30)
    haengende = [f.result(timeout=30) for f in laufend]
auth._hinweis_ausgang.abwarten()
r.check("precondition: in the first window as many pre-bookings are pending as the IP threshold",
        schwebend == schwelle_ip and bestaetigt == 0, f"{schwebend} counted, {bestaetigt} confirmed")
r.check("precondition: the admin waited (the lockout would have applied)",
        zeit_admin and zeit_admin[0] >= HAENGT * 0.3, f"{zeit_admin}")
r.check("the emergency admin gets in with the correct password (303, not 429)", admin == 303, f"{admin}")
r.check("Alice's sixth click gets the outage (503), no lockout", alice6 == 503, f"{alice6}")
r.check("the hanging attempts end with 503", set(haengende) == {503}, f"{sorted(set(haengende))}")
r.check("no `failed login` in the security log (fail2ban does not ban the NAT address)",
        not log_a.zeilen("failed login"), "; ".join(log_a.zeilen("failed login"))[:300])
r.check("no “Gesperrte Anmeldung” mail to bystanders", post == [], f"{post}")
r.check("afterwards no failed attempt of the address is in the table",
        auth.store.count_fails(0, ip=NAT[0]) == 0, f"{auth.store.count_fails(0, ip=NAT[0])}")
os.remove(db)

# ── (b) R7-2 stays: a burst waits along and then gets the real lockout ─────────────────────────
# The directory rejects quickly. Exactly `max_login_attempts` attempts reach it; the rest waits
# for their outcome (or, with no waiting slot, immediately gets the deferral) and then runs into the lockout.
verz_b = Verzeichnis("falsch", dauer=0.3)
auth, app, post, db = _aufbau(verz_b)
paar = auth._sec("max_login_attempts")
with Mitschnitt() as log_b, ThreadPoolExecutor(max_workers=3 * paar) as pool:
    salve = list(pool.map(lambda i: _anmelden(app, "alice", f"falsch{i}"), range(3 * paar)))
auth._hinweis_ausgang.abwarten()
r.check("R7-2: exactly max_login_attempts attempts reach the directory",
        verz_b.fragen == paar, f"{verz_b.fragen} of {3 * paar}")
r.check("R7-2: the rest get 429", sorted(salve) == [401] * paar + [429] * (2 * paar), f"{sorted(salve)}")
r.check("R7-2: the lockout appears with `reason=lockout_user` in the security log",
        any("failed login user=alice" in z and "reason=lockout_user" in z for z in log_b.zeilen()),
        "; ".join(log_b.zeilen())[:400])
r.check("R7-2: the real failed attempts appear in it as `failed login … method=password`",
        len([z for z in log_b.zeilen("failed login user=alice") if "method=password" in z]) == paar)
r.check("R7-2: after the burst nothing is open any more",
        auth.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE offen=1")["n"] == 0)
os.remove(db)

# ── (c) An open pre-booking that nobody completes becomes a failed attempt after the deadline ──
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0))
_alt_offen(auth, "alice", NAT[0], auth._sec("max_login_attempts"))
zeit_c: list = []
with Mitschnitt() as log_c:
    status_c = _anmelden(app, "alice", zeit=zeit_c)
r.check("orphaned pre-bookings: immediate lockout (429), no waiting",
        status_c == 429 and zeit_c[0] < FRIST / 2, f"{status_c} after {zeit_c[0]:.1f} s")
r.check("orphaned pre-bookings: `reason=lockout_user` in the log, no deferral",
        any("reason=lockout_user" in z for z in log_c.zeilen("failed login"))
        and not log_c.zeilen("deferred"), "; ".join(log_c.zeilen())[:300])
os.remove(db)

# The same for the series (B2-6): an old open pre-booking counts there too.
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0), max_login_attempts=100)
grenze_s = auth._sec("account_max_consecutive_failures")
_alt_offen(auth, "alice", "192.0.2.50", grenze_s)
for _ in range(grenze_s):
    auth.store.fehlserie_erhoehen("alice")
zeit_c2: list = []
with Mitschnitt() as log_c2:
    status_c2 = _anmelden(app, "alice", zeit=zeit_c2)
r.check("orphaned pre-bookings in the series: immediate `lockout_serie`, no deferral",
        status_c2 == 429 and zeit_c2[0] < FRIST / 2
        and any("reason=lockout_serie" in z for z in log_c2.zeilen("failed login"))
        and not log_c2.zeilen("deferred"), f"{status_c2} after {zeit_c2[0]:.1f} s; {log_c2.zeilen()}"[:400])
os.remove(db)

# If a rule already applies with the confirmed rows, it takes precedence — no waiting for another one
# that only applies while pending. Here five pre-bookings of Alice are pending (another process is checking
# them right now), and the address has already reached its threshold with confirmed failed attempts.
auth, app, post, db = _aufbau(Verzeichnis("falsch", dauer=0))
for _ in range(auth._sec("max_login_attempts")):
    auth.store._exec("INSERT INTO login_attempt(ts, username, ip, success, method, offen) "
                     "VALUES (?,'alice',?,0,'password',1)", (jetzt(), NAT[0]))
for i in range(auth._sec("max_login_attempts") * auth._sec("ip_attempt_factor")):
    auth.store.record_attempt(f"kollege{i}", NAT[0], False, "password")
zeit_c3: list = []
with Mitschnitt() as log_c3:
    status_c3 = _anmelden(app, "alice", zeit=zeit_c3)
r.check("a rule that applies with confirmed rows takes precedence over the pending one: `lockout_ip` immediately",
        status_c3 == 429 and zeit_c3[0] < FRIST / 2
        and any("reason=lockout_ip" in z for z in log_c3.zeilen("failed login"))
        and not log_c3.zeilen("deferred"), f"{status_c3} after {zeit_c3[0]:.1f} s; {log_c3.zeilen()}"[:400])
os.remove(db)

# ── (d) The series: a hanging pre-booking at the limit does not trigger a series lockout ──────
verz_d = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_d, max_login_attempts=100)
grenze_s = auth._sec("account_max_consecutive_failures")
for _ in range(grenze_s - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_d, ThreadPoolExecutor(max_workers=2) as pool:
    haengend_d = pool.submit(_anmelden, app, "alice", "x", ("192.0.2.60", 40000))
    warte_bis(lambda: verz_d.fragen >= 1, "der hängende Anlauf im Verzeichnis")
    stand_d = (auth.store.fehlserie("alice"), auth.store.fehlserie_bestaetigt("alice"))
    parallel_d = pool.submit(_anmelden, app, "alice", "y", ("192.0.2.61", 40000)).result(timeout=30)
    haengend_d = haengend_d.result(timeout=30)
auth._hinweis_ausgang.abwarten()
r.check("precondition: the series is at the limit with the hanging pre-booking",
        stand_d == (grenze_s, grenze_s - 1), f"{stand_d}")
r.check("parallel login at the limit: outage (503), no series lockout",
        parallel_d == 503 and haengend_d == 503, f"{parallel_d}, {haengend_d}")
r.check("parallel login at the limit: no `lockout_serie`, no lockout mail",
        not any("lockout_serie" in z for z in log_d.zeilen()) and post == [], f"{log_d.zeilen()} {post}"[:300])
r.check("…and the series is afterwards back at limit−1", auth.store.fehlserie("alice") == grenze_s - 1,
        f"{auth.store.fehlserie('alice')}")
os.remove(db)

# Without a waiting slot at the same spot: the deferral does not show the text of the series lockout ("until you
# reset your password"), and `is_locked` reports it as a deferral — without `lockout_serie`, without mail.
verz_d3 = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_d3, max_login_attempts=100)
auth._schwebe_plaetze = threading.BoundedSemaphore(1)
auth._schwebe_plaetze.acquire()                          # all waiting slots taken
for _ in range(grenze_s - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_d3, ThreadPoolExecutor(max_workers=1) as pool:
    haengend_d3 = pool.submit(_anmelden, app, "alice", "x", ("192.0.2.60", 40000))
    warte_bis(lambda: verz_d3.fragen >= 1, "der hängende Anlauf im Verzeichnis")
    seite_d3 = TestClient(app, client=("192.0.2.61", 40000)).post(
        "/auth/login", data={"username": "alice", "password": "y"}, follow_redirects=False)
    gesperrt_d3 = auth._is_locked("alice", "192.0.2.62")
    haengend_d3.result(timeout=30)
auth._hinweis_ausgang.abwarten()
r.check("deferral at the series limit: 429 with the text of the window lockout, not of the series lockout",
        seite_d3.status_code == 429 and auth.t("err.locked") in seite_d3.text
        and "in Folge" not in seite_d3.text and "in Folge" in auth.t("err.locked_serie"),
        f"{seite_d3.status_code}")
r.check("is_locked at the series limit with pending pre-booking: True, as deferral",
        gesperrt_d3 and len(log_d3.zeilen("deferred login")) == 2
        and not any("lockout_serie" in z for z in log_d3.zeilen()) and post == [],
        f"{gesperrt_d3} {log_d3.zeilen()} {post}"[:400])
os.remove(db)

# Withdrawal and completion lower the series in the SAME transaction as the row. Separately, the
# pre-booking stood in between as neither open nor withdrawn, and whoever was waiting read
# the series one too high — at the limit a lockout including a lockout mail for nothing.
verz_t = Verzeichnis("weg")
auth, app, post, db = _aufbau(verz_t)
aufrufe: list = []
_echt = auth.store._serie_minus


def _spion(topf, art):
    aufrufe.append((topf, art, auth.store.db.in_transaction))
    return _echt(topf, art)


auth.store._serie_minus = _spion
_anmelden(app, "alice")                                  # failure → withdrawal
verz_t.modus, verz_t.dauer = "richtig", 0
auth._ldap_ausfall = type(auth._ldap_ausfall)()          # the marker is armed after the failure
status_t = _anmelden(app, "alice")                       # Erfolg → Abschluss
r.check("withdrawal and success lower the series in the row's transaction",
        aufrufe == [("alice", "password", True), ("alice", "password", True)] and status_t == 303,
        f"{aufrufe}, {status_t}")
r.check("…and the series is afterwards at 0", auth.store.fehlserie("alice") == 0, f"{auth.store.fehlserie('alice')}")
os.remove(db)

# ── (e) Waiting slots: whoever gets none immediately gets the deferral — without a lockout ────
verz_e = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_e, max_login_attempts=1)
auth._schwebe_plaetze = threading.BoundedSemaphore(1)
zeiten_e: list = []
with Mitschnitt() as log_e, ThreadPoolExecutor(max_workers=3) as pool:
    haengend_e = pool.submit(_anmelden, app, "alice")
    warte_bis(lambda: verz_e.fragen >= 1, "der hängende Anlauf hält den einen Warteplatz")
    wartende = [pool.submit(_anmelden, app, "alice", "x", NAT, zeiten_e) for _ in range(2)]
    status_e = sorted(f.result(timeout=30) for f in wartende)
    haengend_e.result(timeout=30)
auth._hinweis_ausgang.abwarten()
zeiten_e.sort()
r.check("without waiting slot: immediately 429, the other waits and gets the outage (503)",
        status_e == [429, 503] and zeiten_e[0] < HAENGT * 0.4 <= zeiten_e[1],
        f"{status_e}, Zeiten {[round(z, 2) for z in zeiten_e]}")
deferred = log_e.zeilen("deferred login")
r.check("without waiting slot: `deferred login … reason=pending` in the log, no `failed login`, no mail",
        len(deferred) == 1 and "user=alice" in deferred[0] and "reason=pending" in deferred[0]
        and not log_e.zeilen("failed login") and post == [], f"{log_e.zeilen()} {post}"[:400])
# Name and address come raw from the request: a line break in them must not produce a second line, otherwise
# an attacker writes a forged `failed login` line with a foreign IP that fail2ban counts (CodeQL #266).
with Mitschnitt() as log_e2:
    auth._aufgeschoben("alice\nWARNING failed login user=x ip=198.51.100.7", "203.0.113.9\r\nip=198.51.100.8")
r.check("deferral with a line break in name and address: exactly one line, no forged `failed login`",
        len(log_e2.zeilen()) == 1 and not log_e2.zeilen("failed login\n")
        and log_e2.zeilen()[0].startswith("WARNING deferred login user=alice"), f"{log_e2.zeilen()}")

# ── (g) The shipped fail2ban filters do not match the deferral ─────────────────────────────────
jail, jail_pruefung = _failregex("tinysesam-filter.conf"), _failregex("tinysesam-verify-filter.conf")
r.check("the failregex of both jails does not match `deferred login`",
        deferred and not any(j.search(z) for z in deferred for j in (jail, jail_pruefung)), f"{deferred}")
r.check("counter-check: the same line as `failed login` would hit the jail",
        deferred and bool(jail.search(deferred[0].replace("deferred login", "failed login")
                                      .replace(" reason=", " method=blocked reason="))))
os.remove(db)

# ── (h) is_locked: a deferral is True, but without a lockout mail and without `failed login` ──
verz_h = Verzeichnis("haengt")
auth, app, post, db = _aufbau(verz_h)
with Mitschnitt() as log_h, ThreadPoolExecutor(max_workers=auth._sec("max_login_attempts")) as pool:
    laufend = [pool.submit(_anmelden, app, "alice") for _ in range(auth._sec("max_login_attempts"))]
    warte_bis(lambda: verz_h.fragen >= auth._sec("max_login_attempts"), "alle Anläufe im hängenden Verzeichnis")
    gesperrt_h = auth._is_locked("alice", NAT[0])
    [f.result(timeout=30) for f in laufend]
    frei_h = not auth._is_locked("alice", NAT[0])
auth._hinweis_ausgang.abwarten()
r.check("is_locked during pending pre-bookings: True, afterwards False", gesperrt_h and frei_h,
        f"{gesperrt_h}, {frei_h}")
r.check("is_locked on deferral: `deferred login`, no `failed login`, no mail",
        log_h.zeilen("deferred login") and not log_h.zeilen("failed login") and post == [],
        f"{log_h.zeilen()} {post}"[:300])
os.remove(db)

# ── (f) An unexpected exception leaves no pending row behind ───────────────────────────────────
auth, app, post, db = _aufbau(Verzeichnis("kaputt"))
status_f = _anmelden(app, "alice")
zeilen_f = [(z["offen"], z["success"]) for z in auth.store._all("SELECT offen, success FROM login_attempt")]
r.check("exception in the directory client: 500, the attempt is a confirmed failed attempt",
        status_f == 500 and zeilen_f == [(0, 0)], f"{status_f}, {zeilen_f}")
os.remove(db)

# ── (i) p2 F3: `lockout_serie` exactly at the transition of the settled state ──────────────────
# Until 2026-09-27 a failed attempt logged the series state at ITS booking, including pending
# pre-bookings. The owner (correct password) and an attacker (wrong) are pending at the same time,
# the series is at limit−2: the owner is fully signed in and ends the series, the
# attacker fails with the booked state = limit — `lockout_serie` in the audit log and "locked"
# im Sicherheits-Log, obwohl nichts gesperrt war.
RICHTIG_I = "richtig-im-verz"


class Pruefendes(Verzeichnis):
    """Accepts exactly one password, after `dauer` seconds."""

    def authenticate(self, username, password):
        with self._zaehler:
            self.fragen += 1
        time.sleep(self.dauer)
        if password == RICHTIG_I:
            return {"username": username, "email": None, "name": username, "groups": [], "id": f"l-{username}"}
        return None


def _serien_zeilen(auth):
    return auth.store._one("SELECT COUNT(*) AS n FROM audit WHERE event='lockout_serie'")["n"]


verz_i = Pruefendes(dauer=0.6)
auth, app, post, db = _aufbau(verz_i, max_login_attempts=1000, account_max_consecutive_failures=10)
grenze_i = auth._sec("account_max_consecutive_failures")
for _ in range(grenze_i - 2):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_i, ThreadPoolExecutor(max_workers=2) as pool:
    inhaberin = pool.submit(_anmelden, app, "alice", RICHTIG_I, ("198.51.100.1", 40000))
    warte_bis(lambda: verz_i.fragen >= 1, "die Inhaberin im Verzeichnis")
    angreifer = pool.submit(_anmelden, app, "alice", "falsch", ("203.0.113.66", 40000))
    inhaberin, angreifer = inhaberin.result(timeout=30), angreifer.result(timeout=30)
auth._hinweis_ausgang.abwarten()
# (Mutation probe: in `record_login` restore `stand = vorgebucht[2]` and `stand == grenze`, plus in
#  `reserve_attempt` the sum instead of the settled state → one row → red.)
r.check("p2 F3: owner and attacker are pending at limit−2, the owner ends the series — "
        "no `lockout_serie` in the audit log, no “gesperrt” in the security log",
        inhaberin == 303 and angreifer == 401 and auth.store.fehlserie("alice") == 0
        and _serien_zeilen(auth) == 0 and not log_i.zeilen("gesperrt") and post == [],
        f"{inhaberin}/{angreifer}, Serie {auth.store.fehlserie('alice')}, Zeilen {_serien_zeilen(auth)}, "
        f"{log_i.zeilen('gesperrt')} {post}"[:400])
os.remove(db)

# Counter-check: the real lockout by burst — exactly one row, with pending (LDAP) and without.
verz_i2 = Verzeichnis("falsch", dauer=0.3)
auth, app, post, db = _aufbau(verz_i2, max_login_attempts=1000, account_max_consecutive_failures=10)
for _ in range(grenze_i - 1):
    auth.store.fehlserie_erhoehen("alice")
with Mitschnitt() as log_i2, ThreadPoolExecutor(max_workers=6) as pool:
    salve_i2 = sorted(pool.map(lambda i: _anmelden(app, "alice", f"falsch{i}", (f"192.0.2.{20 + i}", 40000)),
                               range(6)))
auth._hinweis_ausgang.abwarten()
r.check("p2 F3 counter-check with LDAP (pending): burst at limit−1 → one question to the directory, series "
        "stands, exactly one `lockout_serie` row",
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
r.check("p2 F3 counter-check without LDAP (settled immediately): burst at limit−1 → exactly one `lockout_serie` row",
        salve_i3 == [401] + [429] * 5 and _serien_zeilen(auth_i3) == 1, f"{salve_i3} {_serien_zeilen(auth_i3)}")
# Immediately settled booking over the limit, the series is ended before its completion (a full
# sign-in by another route): no row. And mixed — one pending and one immediately
# settled at the limit, completed in both orders: exactly one.
auth_i3.store.fehlserie_loeschen("bert")
for _ in range(grenze_i - 1):
    auth_i3.store.fehlserie_erhoehen("bert")
_vor_i3 = _serien_zeilen(auth_i3)
_v = auth_i3._begin_attempt("bert", "192.0.2.60", "pin")
auth_i3.lift_lockout(auth_i3.store.get_user_by_name("bert")["id"])
auth_i3._record_login("bert", "192.0.2.60", False, "pin", versuch=_v)
# (Mutation probe: replace `min(vorgebucht[2], nachher)` with `vorgebucht[2]` in `record_login` → red.)
r.check("p2 F3: booking over the limit, series ended before completion → no row",
        _v is not None and _serien_zeilen(auth_i3) == _vor_i3, f"{_v} {_serien_zeilen(auth_i3) - _vor_i3}")
_gemischt = []
for reihenfolge in ("schwebend zuerst", "feststehend zuerst"):
    auth_i3.store.fehlserie_loeschen("bert")
    for _ in range(grenze_i - 2):
        auth_i3.store.fehlserie_erhoehen("bert")
    _vor = _serien_zeilen(auth_i3)
    _s = auth_i3._begin_attempt("bert", "192.0.2.61", "password", schweben=True)
    _f = auth_i3._begin_attempt("bert", "192.0.2.62", "pin")
    for v, m in ((_s, "password"), (_f, "pin"))[::1 if reihenfolge == "schwebend zuerst" else -1]:
        auth_i3._record_login("bert", "192.0.2.61", False, m, versuch=v)
    _gemischt.append((reihenfolge, _s is not None and _f is not None, _serien_zeilen(auth_i3) - _vor))
# (Mutationsprobe: `vorher < max_serie <= nachher` streichen → „schwebend zuerst" 0 Zeilen → rot.)
r.check("p2 F3: pending and immediately settled booking at the limit — exactly one row in both orders",
        all(ok_ and n == 1 for _, ok_, n in _gemischt), str(_gemischt))
auth_i3.store.db.close()
os.remove(db_i3)

# ── (j) p2 V1: an overall deadline for the question to the directory ───────────────────────────
# The pre-booking is pending for at most `Store.VORBUCHUNG_SCHWEBE_SEK`; after that it counts as a failed attempt
# of a dead process. ldap3 only knows one deadline per response (10 s), and a search-then-bind
# with StartTLS waits up to ten times: a slow but responding directory let a still
# running sign-in count as a confirmed failed attempt. Measured with a substituted ldap3 and
# a clock that only the dummy presents — without real waiting time.
import types as _types  # noqa: E402

from tinysesam import ldap_ as _ldap_mod  # noqa: E402


class _Uhr:
    def __init__(self):
        self.t = 1000.0

    def monotonic(self):
        return self.t


def _ldap3_langsam(uhr, antwort_sek, mitschrift):
    """ldap3 dummy: every response needs `antwort_sek`; if the deadline of the waiting point is shorter,
    it ends after the deadline with the error that ldap3 raises there."""
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
            warten(self.frist, lx.LDAPSocketReceiveError)           # response to StartTLS
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
    """(outcome, elapsed seconds, deadlines per connection) of a sign-in against the dummy."""
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
r.check("p2 V1: every sign-in against a slow but responding directory ends within the "
        f"overall deadline ({_ldap_mod.GESAMT_FRIST_SEK} s) — signed in or “nicht erreichbar”, never “abgewiesen”",
        not _zu_lang_j and all(a in ("angemeldet", "nicht erreichbar") for a, _ in _messung_j.values()),
        f"zu lang: {_zu_lang_j}; {[(k, v) for k, v in _messung_j.items() if v[0] == 'abgewiesen']}")
r.check("… a fast directory notices nothing: signed in, the service account with the half, the "
        "user connection with the whole remaining deadline per response (at most 10 s)",
        all(_messung_j[(n, 0.01)][0] == "angemeldet" for n in _faelle_j)
        and _langsam_fragen(0.01)[2] == [(4, 4), (8, 8)], str(_langsam_fragen(0.01)[2]))
r.check("… and the overall deadline lies with room below the pending time of the pre-booking",
        _ldap_mod.GESAMT_FRIST_SEK + 5 <= Store.VORBUCHUNG_SCHWEBE_SEK,
        f"{_ldap_mod.GESAMT_FRIST_SEK} / {Store.VORBUCHUNG_SCHWEBE_SEK}")
_frist_vorher = _ldap_mod.GESAMT_FRIST_SEK
try:
    _ldap_mod.GESAMT_FRIST_SEK = 5                    # not enough for one second per waiting point
    _knapp_j = _langsam_fragen(0.01, ldap_start_tls=True)
finally:
    _ldap_mod.GESAMT_FRIST_SEK = _frist_vorher
# (Mutationsprobe: `except VerzeichnisNichtErreichbar: raise` in `authenticate` streichen → „abgewiesen“,
#  a failed attempt for the slowness of the directory → red.)
r.check("p2 V1: if the deadline is not enough, the directory counts as unreachable before it is asked "
        "(no failed attempt)", _knapp_j[0] == "nicht erreichbar" and _knapp_j[2] == [], str(_knapp_j))

# ── Without LDAP nothing is pending, and the column also lands in a file that already carries schema 11 ─
db_o = str(Path(tempfile.mkdtemp()) / "t.db")
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, csrf_enabled=False,
                                   passkey_enabled=False, oidc_enabled=False, lang="de"))
auth_o.create_user("bert", password=PW)
app_o = FastAPI()
app_o.include_router(auth_o.router())
_anmelden(app_o, "bert", "falsch")
r.check("without LDAP: the failed attempt is confirmed immediately (offen=0)",
        [z["offen"] for z in auth_o.store._all("SELECT offen FROM login_attempt")] == [0])
auth_o.store.db.close()
roh = sqlite3.connect(db_o)
roh.execute("ALTER TABLE login_attempt DROP COLUMN offen")
stempel = roh.execute("PRAGMA user_version").fetchone()[0]
roh.close()
auth_o = TinySesam(TinySesamConfig(db_path=db_o, cookie_secure=False, passkey_enabled=False, oidc_enabled=False))
spalten = {z["name"] for z in auth_o.store._all("PRAGMA table_info(login_attempt)")}
r.check("a file from schema 11 without the column gets it at start (idempotent)",
        stempel == Store.SCHEMA_VERSION >= 11 and "offen" in spalten
        and auth_o.store.count_fails(0, username="bert", nur_bestaetigt=True) == 1, f"{stempel} {spalten}")
auth_o.store.db.close()
os.remove(db_o)

sys.exit(r.done())
