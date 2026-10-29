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
                                 # Since R4-01 TinySesam builds mail links only from a promised
                                 # public address, no longer from the Host header.
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

# unknown address → same response, NO mail (no enumeration)
r = c.post("/auth/magic/request", data={"email": "fremd@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert sent == []
ok("unknown address: generic response, no mail (no enumeration)")

# known address → mail with link
r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/geheim"})
assert r.status_code == 200 and "unterwegs" in r.text
assert len(sent) == 1 and sent[0]["to"] == "admin@example.com"
import re
m = re.search(r"/auth/magic/([\w\-]+)", sent[0]["text"])
assert m, sent[0]["text"]
token = m.group(1)
ok("bekannte Adresse: Anmelde-Link per Mail verschickt")

# not logged in yet
assert c.get("/geheim", headers=JSON).status_code == 401

# R4-02: The GET from the mail (or from the mail scanner) does NOT sign in and consumes nothing —
# it only shows a button whose POST redeems.
scanner = TestClient(app)
for _ in range(3):
    r = scanner.get(f"/auth/magic/{token}", follow_redirects=False)
    assert r.status_code == 200 and f"action='/auth/magic/{token}'" in r.text and "method=post" in r.text, r.text[:300]
assert scanner.get("/geheim", headers=JSON).status_code == 401, "a GET must not sign anyone in"
assert auth.peek_magic(token, purpose="login"), "a GET must not consume the token"
ok("R4-02: GET on the sign-in link consumes nothing and does not sign in")

# redeem link (POST) → logged in, redirect to next
r = c.post(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim", r.headers.get("location")
assert c.get("/geheim", headers=JSON).json() == {"u": "admin"}
ok("redeem magic link → logged in (factor 'magic')")

# one-shot: second redemption fails
c2 = TestClient(app)
r = c2.post(f"/auth/magic/{token}", follow_redirects=False)
assert r.status_code == 400 and "ungültig" in r.text.lower()
assert c2.get(f"/auth/magic/{token}", follow_redirects=False).status_code == 400
ok("token is one-shot (second redemption invalid)")

# abgelaufener Token
raw = auth.create_magic_token("login", user_id=uid, email="admin@example.com", ttl_min=15, payload={"next": "/"})
h = __import__("hashlib").sha256(raw.encode()).hexdigest()
auth.store._exec("UPDATE magic_token SET expires_at=0 WHERE token_hash=?", (h,))
assert auth.redeem_magic(raw) is None
ok("expired token → invalid")

# mail_configured / MailNotConfigured
assert auth.mail_configured() is True
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
a2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, magiclink_enabled=True,
                               # Required since the base_url follow-up; what is checked here is the
                               # missing MAILER, not the missing base.
                               base_url="https://auth.example.com"))   # no smtp_host, no mailer
assert a2.mail_configured() is False
from tinysesam.mailer import MailNotConfigured
try:
    a2.send_mail("x@y.z", "s", "t"); assert False
except MailNotConfigured:
    ok("without SMTP/mailer: send_mail raises MailNotConfigured")
os.remove(db2)

# ---------- /auth/magic/{token} has been ONLY the sign-in link since 0.16 ----------
# Before, it was the entry for four purposes; whoever switched the magic link off also lost confirmation
# and invitation. A token of another purpose is now rejected here.
fremd = auth.create_magic_token("verify_email", user_id=uid, email="admin@example.com")
r = c.get(f"/auth/magic/{fremd}", follow_redirects=False)
assert r.status_code == 400, r.status_code
assert auth.peek_magic(fremd, purpose="verify_email"), "and stays unconsumed"
ok("/auth/magic/{token} takes only login tokens now (own endpoints for the rest)")

# ---------- R4-11: the mail goes to the STORED address, not to the input ----------
sent.clear()
c.post("/auth/magic/request", data={"email": "  ADMIN@Example.COM ", "next": "/"})
assert len(sent) == 1 and sent[0]["to"] == "admin@example.com", sent
ok("R4-11: sign-in link goes to the stored address, not to the raw input")

# ---------- R4-04: throttled per TARGET address (the IP throttle protects no foreign mailbox) ----------
sent.clear()
auth.rl = type(auth.rl)()   # fresh limiter: the count above should not play along here
_grenze = auth._sec("mail_per_address_max")
_antworten = set()
for _ in range(_grenze + 3):
    _r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/"})
    _antworten.add((_r.status_code, "unterwegs" in _r.text))
assert len(sent) == _grenze, (len(sent), _grenze)
assert _antworten == {(200, True)}, _antworten   # invisible to the outside (no enumeration)
assert auth.store._all("SELECT * FROM audit WHERE event='mail_ratelimit'"), "Flut steht im Audit-Log"
# … also via the direct API path (own forms of an app)
assert auth.send_password_reset("admin@example.com", auth.cfg.base_url) is False
assert len(sent) == _grenze
ok(f"R4-04: at most {_grenze} mails per address and window, rest discarded + logged")
auth.rl = type(auth.rl)()

# ---------- B6-12: if sending fails, the token is invalidated immediately ----------
def _kaputt(*a, **k):
    raise OSError("Relay weg")
auth.set_mailer(_kaputt)
_vorher = {z["token_hash"] for z in auth.store._all("SELECT token_hash FROM magic_token")}
for _ruf in (lambda: auth.send_login_link("admin@example.com", auth.cfg.base_url),
             lambda: auth.send_password_reset("admin@example.com", auth.cfg.base_url),
             lambda: auth.send_verify_email(uid, "admin@example.com", auth.cfg.base_url),
             lambda: auth.create_invite("gast@example.com", auth.cfg.base_url)):
    try:
        _ruf(); assert False, "sending error must reach the caller"
    except OSError:
        pass
_neu = [z for z in auth.store._all("SELECT * FROM magic_token") if z["token_hash"] not in _vorher]
assert len(_neu) == 4, _neu
_jetzt = int(__import__("time").time())
assert all(z["expires_at"] < _jetzt and z["used_at"] is None for z in _neu), [dict(z) for z in _neu]
ok("B6-12: failed sending → token expired immediately (login, reset, confirmation, invitation)")
# Via the route: generic response, error in the audit log, no valid token
_r = c.post("/auth/magic/request", data={"email": "admin@example.com", "next": "/"})
assert _r.status_code == 200 and "unterwegs" in _r.text
assert auth.store._all("SELECT * FROM audit WHERE event='magic_send_error'")
auth.set_mailer(lambda to, subject, text, html=None: sent.append({"to": to, "subject": subject, "text": text}))

# ---------- B5-18: an invalid sign-in token leaves a trace ----------
auth.store._exec("DELETE FROM audit")
c.get("/auth/magic/gibtsnicht", follow_redirects=False)
c.post("/auth/magic/gibtsnicht", follow_redirects=False)
_spur = auth.store._all("SELECT * FROM audit WHERE event='token_invalid'")
assert len(_spur) == 2 and all("zweck=login" in z["detail"] for z in _spur), [dict(z) for z in _spur]
ok("B5-18: invalid sign-in token (GET and POST) is in the audit log")

# ---------- R4-05 + B6-6: the response does not wait for the mail server ----------
# Measured on the raw ASGI protocol, not with TestClient: it waits for background tasks and
# would not see the difference. A mailer that hangs until we let go, and fifty
# simultaneous requests — more than the AnyIO threadpool has slots (40).
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
    # All fifty responses are THERE, although not a single send has finished (R4-05) …
    codes = await asyncio.wait_for(asyncio.gather(*(f for f, _ in posten)), 5)
    assert codes == [200] * 50, codes
    await asyncio.sleep(0.2)
    assert _mailfaeden and not _los.is_set()
    # … the threadpool is free, a synchronous route responds immediately (B6-6) …
    belegt = anyio.to_thread.current_default_thread_limiter().borrowed_tokens
    f_login, _ = await _asgi("GET", "/auth/login")
    assert await asyncio.wait_for(f_login, 3) == 200
    _los.set()
    await asyncio.wait_for(asyncio.gather(*(l for _, l in posten)), 20)
    return belegt

_belegt = asyncio.run(_messung())
assert _belegt == 0, f"{_belegt} threadpool slots were held by the sending"
assert set(n.split("_")[0] for n in _mailfaeden) == {"tinysesam-mail"}, set(_mailfaeden)
assert len(_mailfaeden) == 50, len(_mailfaeden)
ok("R4-05/B6-6: 50 responses before the first send, threadpool free, sending in its own worker")

os.remove(db)

# ---------- B3-1: SMTP-TLS checks certificate AND hostname ----------
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
    # `smtp_ca_file` is really used (a missing path is noticed instead of being silently ignored)
    try:
        _mailer_mod.SMTPMailer(TinySesamConfig(smtp_host="mail.example.com", smtp_ssl=True,
                                               smtp_ca_file="/gibt/es/nicht.pem"))("x@example.com", "s", "t")
        assert False, "smtp_ca_file was ignored"
    except (FileNotFoundError, ssl.SSLError):
        pass
finally:
    _mailer_mod.smtplib.SMTP, _mailer_mod.smtplib.SMTP_SSL = _echt
ok("B3-1: STARTTLS and SMTPS with certificate and hostname check; smtp_ca_file takes effect")

# ---------- Attack A4: the consequences of B3-1 show up at build time or with a hint ----------
from tinysesam.config_check import check_config as _check_config
def _smtp_befunde(**kw):
    f, w = _check_config(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "t.db"),
                                   passkey_enabled=False, **kw))
    return ([x for x in f if "smtp" in x.lower()], [x for x in w if "smtp_host=" in x])
assert len(_smtp_befunde(smtp_host="mail.example.com", smtp_ca_file="/gibt/es/nicht.pem")[0]) == 1
with tempfile.NamedTemporaryFile(suffix=".pem") as _ca:
    assert _smtp_befunde(smtp_host="mail.example.com", smtp_ca_file=_ca.name) == ([], [])
assert len(_smtp_befunde(smtp_host="192.0.2.10")[1]) == 1, "relay by IP: hostname check fails"
assert len(_smtp_befunde(smtp_host="[2001:db8::1]")[1]) == 1
assert _smtp_befunde(smtp_host="mail.example.com") == ([], [])
# If the certificate check fails, the log says what to do (not only *_send_error in the audit)
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
ok("A4: missing smtp_ca_file is a build error, relay by IP warns, certificate error names the remedy")

# Mail wording follows `lang`: English for "en", the old German wording for "de" (messages.py `mail.*`).
_sprachmails = {}
for _sprache in ("en", "de"):
    _gesendet: list = []
    _am = TinySesam(TinySesamConfig(csrf_enabled=False, lang=_sprache, db_path=os.path.join(tempfile.mkdtemp(), "l.db"),
                                    passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                    magiclink_enabled=True, base_url="https://auth.example.com"))
    _am.set_mailer(lambda to, subject, text, html=None, _g=_gesendet: _g.append((subject, text)))
    _am.ensure_admin("admin", "geheim123")
    _uid = _am.store.get_user_by_name("admin")["id"]
    _am.store._exec("UPDATE users SET email=? WHERE id=?", ("admin@example.com", _uid))
    _app = FastAPI()
    _app.include_router(_am.router())
    TestClient(_app).post("/auth/magic/request", data={"email": "admin@example.com", "next": "/"})
    _am.request_email_change(_uid, "neu@example.com", "https://auth.example.com")()
    _sprachmails[_sprache] = _gesendet
for _sprache, _betreffe in (("en", ["Your sign-in link", "Confirm your new email address"]),
                            ("de", ["Dein Anmelde-Link", "Neue E-Mail-Adresse bestätigen"])):
    assert [s for s, _t in _sprachmails[_sprache]][:2] == _betreffe, (_sprache, _sprachmails[_sprache])
assert "Open this link to sign in" in _sprachmails["en"][0][1] and "Zum Anmelden" not in _sprachmails["en"][0][1]
assert "Zum Anmelden" in _sprachmails["de"][0][1] and "Open this link" not in _sprachmails["de"][0][1]
ok("mail wording follows lang: sign-in link and email-change confirmation in English (en) and German (de)")

print("\nMAGIC-LINK OK ✅")
