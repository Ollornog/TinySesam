"""Phase 5: Mailer-Hook + Magic-Link (Einmal-Login per E-Mail)."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


sent = []   # abgefangene Mails

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, magiclink_enabled=True, magiclink_ttl_min=15,
                                 # Seit R4-01 baut TinySesam Mail-Links nur aus einer zugesagten
                                 # öffentlichen Adresse, nicht mehr aus dem Host-Header.
                                 base_url="https://auth.example.com"))
auth.set_mailer(lambda to, subject, text, html=None: sent.append({"to": to, "subject": subject, "text": text}))
auth.ensure_admin("admin", "geheim123")
uid = auth.store.get_user_by_name("admin")["id"]
auth.store._exec("UPDATE users SET email=? WHERE id=?", ("admin@example.com", uid))

app = FastAPI()
app.include_router(auth.router())


@app.get("/geheim")
def geheim(u=Depends(auth.require_user)):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# Login-Seite zeigt Magic-Option
assert "Login-Link per E-Mail" in c.get("/auth/login").text
ok("Login-Seite zeigt Magic-Link-Option")

# Request-Seite
assert "E-Mail" in c.get("/auth/magic/request").text

# unbekannte Adresse → gleiche Antwort, KEINE Mail (keine Enumeration)
r = c.post("/auth/magic/request", data={"email": "fremd@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert sent == []
ok("unbekannte Adresse: generische Antwort, keine Mail (keine Enumeration)")

# bekannte Adresse → Mail mit Link
r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert len(sent) == 1 and sent[0]["to"] == "admin@example.com"
import re
m = re.search(r"/auth/magic/([\w\-]+)", sent[0]["text"])
assert m, sent[0]["text"]
token = m.group(1)
ok("bekannte Adresse: Anmelde-Link per Mail verschickt")

# noch nicht eingeloggt
assert c.get("/geheim", headers=JSON).status_code == 401

# R4-02: Der GET aus der Mail (oder vom Mail-Scanner) meldet NICHT an und verbraucht nichts —
# er zeigt nur einen Knopf, dessen POST einlöst.
scanner = TestClient(app)
for _ in range(3):
    r = scanner.get(f"/auth/magic/{token}", follow_redirects=False)
    assert r.status_code == 200 and f"action='/auth/magic/{token}'" in r.text and "method=post" in r.text, r.text[:300]
assert scanner.get("/geheim", headers=JSON).status_code == 401, "ein GET darf niemanden anmelden"
assert auth.peek_magic(token, purpose="login"), "ein GET darf den Token nicht verbrauchen"
ok("R4-02: GET auf den Anmelde-Link verbraucht nichts und meldet nicht an")

# Link einlösen (POST) → eingeloggt, Redirect auf next
r = c.post(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim", r.headers.get("location")
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("Magic-Link einlösen → eingeloggt (Faktor 'magic')")

# one-shot: zweite Einlösung schlägt fehl
c2 = TestClient(app)
r = c2.post(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 400 and "ungültig" in r.text.lower()
assert c2.get(f"/auth/magic/{token}", follow_redirects=False).status_code == 400
ok("Token ist one-shot (zweite Einlösung ungültig)")

# abgelaufener Token
raw = auth.create_magic_token("login", user_id=uid, email="admin@example.com", ttl_min=15, payload={"next": "/"})
h = __import__("hashlib").sha256(raw.encode()).hexdigest()
auth.store._exec("UPDATE magic_token SET expires_at=0 WHERE token_hash=?", (h,))
assert auth.redeem_magic(raw) is None
ok("abgelaufener Token → ungültig")

# mail_configured / MailNotConfigured
assert auth.mail_configured() is True
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
a2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, magiclink_enabled=True,
                               # Pflicht seit der base_url-Nacharbeit; geprüft wird hier der
                               # fehlende MAILER, nicht die fehlende Basis.
                               base_url="https://auth.example.com"))   # kein smtp_host, kein Mailer
assert a2.mail_configured() is False
from tinysesam.mailer import MailNotConfigured
try:
    a2.send_mail("x@y.z", "s", "t"); assert False
except MailNotConfigured:
    ok("ohne SMTP/Mailer: send_mail wirft MailNotConfigured")
os.remove(db2)

# ---------- /auth/magic/{token} ist seit 0.16 NUR der Anmelde-Link ----------
# Vorher war es der Eingang für vier Zwecke; wer den Magic-Link abschaltete, verlor Bestätigung
# und Einladung gleich mit. Ein Token anderen Zwecks wird hier jetzt abgewiesen.
fremd = auth.create_magic_token("verify_email", user_id=uid, email="admin@example.com")
r = c.get(f"/auth/magic/{fremd}", follow_redirects=False)
assert r.status_code == 400, r.status_code
assert auth.peek_magic(fremd, purpose="verify_email"), "und bleibt dabei unverbraucht"
ok("/auth/magic/{token} nimmt nur noch login-Token (eigene Endpunkte für den Rest)")

# ---------- R4-11: die Mail geht an die GESPEICHERTE Adresse, nicht an die Eingabe ----------
sent.clear()
c.post("/auth/magic/request", data={"email": "  ADMIN@Example.COM ", "next": "/"})
assert len(sent) == 1 and sent[0]["to"] == "admin@example.com", sent
ok("R4-11: Anmelde-Link geht an die gespeicherte Adresse, nicht an die rohe Eingabe")

# ---------- R4-04: gedrosselt je ZIELADRESSE (die IP-Drossel schützt kein fremdes Postfach) ----------
sent.clear()
auth.rl = type(auth.rl)()   # frischer Limiter: die Zählung oben soll hier nicht mitspielen
_grenze = auth.sec("mail_per_address_max")
_antworten = set()
for _ in range(_grenze + 3):
    _r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/"})
    _antworten.add((_r.status_code, "unterwegs" in _r.text))
assert len(sent) == _grenze, (len(sent), _grenze)
assert _antworten == {(200, True)}, _antworten   # nach aussen unsichtbar (keine Enumeration)
assert auth.store._all("SELECT * FROM audit WHERE event='mail_ratelimit'"), "Flut steht im Audit-Log"
# … auch über den direkten API-Weg (eigene Formulare einer App)
assert auth.send_password_reset("admin@example.com", auth.cfg.base_url) is False
assert len(sent) == _grenze
ok(f"R4-04: höchstens {_grenze} Mails je Adresse und Fenster, Rest verworfen + protokolliert")
auth.rl = type(auth.rl)()

# ---------- B6-12: scheitert der Versand, ist der Token sofort entwertet ----------
def _kaputt(*a, **k):
    raise OSError("Relay weg")
auth.set_mailer(_kaputt)
_vorher = {z["token_hash"] for z in auth.store._all("SELECT token_hash FROM magic_token")}
for _ruf in (lambda: auth.send_login_link("admin@example.com", auth.cfg.base_url),
             lambda: auth.send_password_reset("admin@example.com", auth.cfg.base_url),
             lambda: auth.send_verify_email(uid, "admin@example.com", auth.cfg.base_url),
             lambda: auth.create_invite("gast@example.com", auth.cfg.base_url)):
    try:
        _ruf(); assert False, "Versandfehler muss beim Aufrufer ankommen"
    except OSError:
        pass
_neu = [z for z in auth.store._all("SELECT * FROM magic_token") if z["token_hash"] not in _vorher]
assert len(_neu) == 4, _neu
_jetzt = int(__import__("time").time())
assert all(z["expires_at"] < _jetzt and z["used_at"] is None for z in _neu), [dict(z) for z in _neu]
ok("B6-12: gescheiterter Versand → Token sofort abgelaufen (Login, Reset, Bestätigung, Einladung)")
# Über die Route: generische Antwort, Fehler im Audit-Log, kein gültiger Token
_r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/"})
assert _r.status_code == 200 and "unterwegs" in _r.text
assert auth.store._all("SELECT * FROM audit WHERE event='magic_send_error'")
auth.set_mailer(lambda to, subject, text, html=None: sent.append({"to": to, "subject": subject, "text": text}))

# ---------- B5-18: ein ungültiger Anmelde-Token hinterlässt eine Spur ----------
auth.store._exec("DELETE FROM audit")
c.get("/auth/magic/gibtsnicht", follow_redirects=False)
c.post("/auth/magic/gibtsnicht", follow_redirects=False)
_spur = auth.store._all("SELECT * FROM audit WHERE event='token_invalid'")
assert len(_spur) == 2 and all("zweck=login" in z["detail"] for z in _spur), [dict(z) for z in _spur]
ok("B5-18: ungültiger Anmelde-Token (GET und POST) steht im Audit-Log")

# ---------- R4-05 + B6-6: die Antwort wartet nicht auf den Mailserver ----------
# Gemessen am rohen ASGI-Protokoll, nicht mit TestClient: Der wartet auf Hintergrundaufgaben und
# sähe den Unterschied nicht. Ein Mailer, der hängt, bis wir ihn loslassen, und fünfzig
# gleichzeitige Anfragen — mehr, als der Threadpool von AnyIO Plätze hat (40).
import asyncio, threading
import anyio.to_thread
_los = threading.Event()
_mailfaeden = []
def _haengt(to, subject, text, html=None):
    _mailfaeden.append(threading.current_thread().name)
    _los.wait(10)
auth.set_mailer(_haengt)
auth.set_security("rate_limit_max", 1000)
auth.set_security("mail_per_address_max", 1000)
auth.rl = type(auth.rl)()


async def _asgi(methode, pfad, body=b""):
    fertig = asyncio.get_running_loop().create_future()
    status = {}
    geschickt = False
    haengen = asyncio.Event()

    async def receive():
        nonlocal geschickt
        if not geschickt:
            geschickt = True
            return {"type": "http.request", "body": body, "more_body": False}
        await haengen.wait()
        return {"type": "http.disconnect"}

    async def send(msg):
        if msg["type"] == "http.response.start":
            status["code"] = msg["status"]
        elif msg["type"] == "http.response.body" and not msg.get("more_body") and not fertig.done():
            fertig.set_result(status.get("code"))

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "method": methode,
             "scheme": "http", "path": pfad, "raw_path": pfad.encode(), "query_string": b"",
             "root_path": "", "client": ("127.0.0.1", 50000), "server": ("testserver", 80),
             "headers": [(b"host", b"testserver"), (b"accept", b"text/html"),
                         (b"content-type", b"application/x-www-form-urlencoded"),
                         (b"content-length", str(len(body)).encode())]}
    lauf = asyncio.ensure_future(app(scope, receive, send))
    return fertig, lauf


async def _messung():
    posten = [await _asgi("POST", "/auth/magic/request", b"email=admin%40example.com&next=%2F")
              for _ in range(50)]
    # Alle fünfzig Antworten sind DA, obwohl kein einziger Versand fertig ist (R4-05) …
    codes = await asyncio.wait_for(asyncio.gather(*(f for f, _ in posten)), 5)
    assert codes == [200] * 50, codes
    await asyncio.sleep(0.2)
    assert _mailfaeden and not _los.is_set()
    # … der Threadpool ist frei, eine synchrone Route antwortet sofort (B6-6) …
    belegt = anyio.to_thread.current_default_thread_limiter().borrowed_tokens
    f_login, _ = await _asgi("GET", "/auth/login")
    assert await asyncio.wait_for(f_login, 3) == 200
    _los.set()
    await asyncio.wait_for(asyncio.gather(*(l for _, l in posten)), 20)
    return belegt

_belegt = asyncio.run(_messung())
assert _belegt == 0, f"{_belegt} Threadpool-Plätze hielt der Versand fest"
assert set(n.split("_")[0] for n in _mailfaeden) == {"tinysesam-mail"}, set(_mailfaeden)
assert len(_mailfaeden) == 50, len(_mailfaeden)
ok("R4-05/B6-6: 50 Antworten vor dem ersten Versand, Threadpool frei, Versand im eigenen Arbeiter")

os.remove(db)

# ---------- B3-1: SMTP-TLS prüft Zertifikat UND Hostnamen ----------
import ssl
from tinysesam import mailer as _mailer_mod
_kontexte = []


class _FalschSMTP:
    def __init__(self, *a, **k):
        if "context" in k:
            _kontexte.append(k["context"])
    def __enter__(self): return self
    def __exit__(self, *a): return False
    def starttls(self, context=None):
        _kontexte.append(context)
    def login(self, *a): pass
    def send_message(self, *a): pass


_echt = (_mailer_mod.smtplib.SMTP, _mailer_mod.smtplib.SMTP_SSL)
_mailer_mod.smtplib.SMTP = _mailer_mod.smtplib.SMTP_SSL = _FalschSMTP
try:
    for _ssl in (False, True):
        _cfg = TinySesamConfig(smtp_host="mail.example.com", smtp_ssl=_ssl, smtp_user="u", smtp_password="p")
        _mailer_mod.SMTPMailer(_cfg)("x@example.com", "s", "t")
    assert len(_kontexte) == 2, _kontexte
    for _k in _kontexte:
        assert isinstance(_k, ssl.SSLContext) and _k.verify_mode == ssl.CERT_REQUIRED and _k.check_hostname, _k
    # `smtp_ca_file` wird wirklich benutzt (ein fehlender Pfad fällt auf, statt still ignoriert zu werden)
    try:
        _mailer_mod.SMTPMailer(TinySesamConfig(smtp_host="mail.example.com", smtp_ssl=True,
                                               smtp_ca_file="/gibt/es/nicht.pem"))("x@example.com", "s", "t")
        assert False, "smtp_ca_file wurde ignoriert"
    except (FileNotFoundError, ssl.SSLError):
        pass
finally:
    _mailer_mod.smtplib.SMTP, _mailer_mod.smtplib.SMTP_SSL = _echt
ok("B3-1: STARTTLS und SMTPS mit Zertifikats- und Hostnamenprüfung; smtp_ca_file greift")

# ---------- Angriff A4: die Folgen von B3-1 fallen beim Aufbau bzw. mit einem Hinweis auf ----------
from tinysesam.konfigpruefung import pruefe as _pruefe
def _smtp_befunde(**kw):
    f, w = _pruefe(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                   passkey_enabled=False, **kw))
    return ([x for x in f if "smtp" in x.lower()], [x for x in w if "smtp_host=" in x])
assert len(_smtp_befunde(smtp_host="mail.example.com", smtp_ca_file="/gibt/es/nicht.pem")[0]) == 1
with tempfile.NamedTemporaryFile(suffix=".pem") as _ca:
    assert _smtp_befunde(smtp_host="mail.example.com", smtp_ca_file=_ca.name) == ([], [])
assert len(_smtp_befunde(smtp_host="192.0.2.10")[1]) == 1, "Relay per IP: Hostnamenprüfung scheitert"
assert len(_smtp_befunde(smtp_host="[2001:db8::1]")[1]) == 1
assert _smtp_befunde(smtp_host="mail.example.com") == ([], [])
# Scheitert die Zertifikatsprüfung, sagt das Log, was zu tun ist (nicht nur *_send_error im Audit)
import logging as _logging, io as _io


class _ZertSMTP(_FalschSMTP):
    def starttls(self, context=None):
        raise ssl.SSLCertVerificationError(1, "certificate verify failed: self-signed certificate")


_puffer = _io.StringIO()
_h = _logging.StreamHandler(_puffer)
_mailer_mod.log.addHandler(_h)
_mailer_mod.smtplib.SMTP = _ZertSMTP
try:
    try:
        _mailer_mod.SMTPMailer(TinySesamConfig(smtp_host="mail.example.com"))("x@example.com", "s", "t")
        assert False, "Zertifikatsfehler verschluckt"
    except ssl.SSLCertVerificationError:
        pass
finally:
    _mailer_mod.smtplib.SMTP, _mailer_mod.smtplib.SMTP_SSL = _echt
    _mailer_mod.log.removeHandler(_h)
assert "smtp_ca_file" in _puffer.getvalue() and re.search(r"\bmail\.example\.com\b", _puffer.getvalue()), \
    _puffer.getvalue()
ok("A4: fehlender smtp_ca_file ist Aufbaufehler, Relay per IP warnt, Zertifikatsfehler nennt die Abhilfe")

print("\nMAGIC-LINK OK ✅")
