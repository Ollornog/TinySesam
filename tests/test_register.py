"""Phase 6: Registrierung (deaktivierbar) + E-Mail-Verifikation + Einladung (invite-only)."""
import os
import tempfile, os, re
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


def build(**cfgkw):
    sent = []
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                     cookie_secure=False,
                                     # Der Bestätigungslink kommt seit R4-01 aus base_url,
                                     # nicht mehr aus dem Host-Header (überschreibbar).
                                     **{"base_url": "https://auth.example.com", **cfgkw}))
    auth.set_mailer(lambda to, s, t, html=None: sent.append({"to": to, "text": t}))
    auth.ensure_admin("admin", "geheim123-lang-genug")
    app = FastAPI()
    app.include_router(auth.router())

    @app.get("/geheim")
    def geheim(u=Depends(auth.require_user)):
        return {"u": u["username"]}

    return db, auth, app, sent, TestClient(app)


JSON = {"Accept": "application/json"}

# ---------- Registrierung deaktiviert (Default) → keine Route ----------
db, auth, app, sent, c = build(allow_signup=False)
assert c.get("/auth/register").status_code == 404
os.remove(db)
ok("allow_signup=False → /auth/register existiert nicht (404)")

# ---------- Einfache Registrierung → sofort eingeloggt ----------
db, auth, app, sent, c = build(allow_signup=True)
assert "Konto erstellen" in c.get("/auth/register").text
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug", "email": "neu@example.com", "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
assert c.get("/geheim", headers=JSON).json() == {"u": "neu"}
# zu kurzes Passwort abgelehnt
r = c.post("/auth/register", data={"username": "x", "password": "1", "next": "/"})
assert r.status_code == 400
# E-Mail ist Pflicht (signup_require_email, Default an)
r = c.post("/auth/register", data={"username": "y", "password": "supergeheim-lang-genug", "next": "/"})
assert r.status_code == 400
# vergebener Name (mit eigener, freier E-Mail → scheitert wirklich am Namen)
r = c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug",
                                   "email": "anders@example.com", "next": "/"})
assert r.status_code == 409
os.remove(db)
ok("allow_signup=True: Konto anlegen → eingeloggt; Validierung greift")

# ---------- E-Mail-Verifikation: Konto erst nach Link aktiv ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True)
r = c.post("/auth/register", data={"username": "verify", "password": "supergeheim-lang-genug", "email": "v@example.com", "next": "/"})
assert "Bestätigung" in r.text or "bestätig" in r.text.lower()
uid = auth.store.get_user_by_name("verify")["id"]
assert auth.store.get_user(uid)["disabled"] == 1     # noch gesperrt
assert len(sent) == 1
# Der Bestätigungslink zeigt auf den EIGENEN Endpunkt, nicht mehr auf /auth/magic/ —
# sonst nimmt magiclink_enabled=False die E-Mail-Bestätigung mit (siehe unten).
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert "/auth/magic/" not in sent[0]["text"]
# R4-02: Der GET (Mail-Scanner, Vorschau) zeigt nur eine Bestätigungsseite und verbraucht NICHTS.
for _ in range(3):
    r = c.get(f"/auth/verify/{token}", follow_redirects=False)
    assert r.status_code == 200 and "action='/auth/verify/" in r.text, (r.status_code, r.text[:200])
assert auth.store.get_user(uid)["disabled"] == 1, "ein GET darf das Konto nicht freischalten"
assert auth.peek_magic(token, purpose="verify_email"), "ein GET darf den Token nicht verbrauchen"
ok("R4-02: GET auf den Bestätigungslink verbraucht nichts (Mail-Scanner)")
r = c.post(f"/auth/verify/{token}", follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0     # aktiviert
assert c.post(f"/auth/verify/{token}", follow_redirects=False).status_code == 400   # one-shot
assert c.get(f"/auth/verify/{token}", follow_redirects=False).status_code == 400    # auch die Seite sagt es
ok("signup_verify_email: eigener Endpunkt /auth/verify/{token}, einmal einlösbar")

# B5-18: Ein ungültiger Token hinterlässt eine Spur (Audit + Sicherheits-Log, NICHT die Login-Jail)
import logging, io
from tinysesam import security as _sec
_puffer = io.StringIO()
_h = logging.StreamHandler(_puffer)
_sec.seclog.addHandler(_h)
try:
    c.get("/auth/verify/erfunden-123", follow_redirects=False)
finally:
    _sec.seclog.removeHandler(_h)
_zeilen = auth.store._all("SELECT * FROM audit WHERE event='token_invalid'")
assert _zeilen and "verify_email" in (_zeilen[0]["detail"] or ""), _zeilen
assert "failed verification" in _puffer.getvalue() and "failed login" not in _puffer.getvalue(), _puffer.getvalue()
ok("B5-18: ungültiger Einmal-Token → Audit token_invalid + `failed verification` (keine Login-Jail)")
os.remove(db)

# ---------- R4-03: eine vergebene Adresse antwortet wie eine freie (mit Bestätigung) ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
auth.create_user("inhaber", password="supergeheim-lang-genug", email="da@example.com")
frei = c.post("/auth/register", data={"username": "neu1", "password": "supergeheim-lang-genug",
                                      "email": "frei@example.com", "next": "/"})
vergeben = c.post("/auth/register", data={"username": "neu2", "password": "supergeheim-lang-genug",
                                          "email": "Da@Example.com", "next": "/"})
assert frei.status_code == vergeben.status_code == 200, (frei.status_code, vergeben.status_code)
_rumpf = lambda t: re.sub(r"(nonce|value)=['\"][^'\"]*['\"]", "", t)
assert _rumpf(frei.text) == _rumpf(vergeben.text), "Antwort unterscheidet sich — Enumeration"
assert auth.store.get_user_by_email("da@example.com")["username"] == "inhaber", "kein zweites Konto für die Adresse"
_ph = auth.store.get_user_by_name("neu2")   # A1: Name belegt wie bei echtem Anlegen, aber gesperrt und ohne Adresse
assert _ph is not None and _ph["disabled"] == 1 and not _ph["email"], dict(_ph) if _ph else None
_an_inhaber = [m for m in sent if m["to"] == "da@example.com"]
assert len(_an_inhaber) == 1 and "/auth/verify/" not in _an_inhaber[0]["text"] \
    and "https://auth.example.com/auth/login" in _an_inhaber[0]["text"], _an_inhaber
ok("R4-03: vergebene Adresse → gleiche Antwort, Inhaber bekommt einen Hinweis (ohne Token)")
# Ohne Bestätigung meldet der Erfolgsfall sofort an — dort bleibt 409 (Grenze, im Code benannt)
db2, auth2, app2, sent2, c2 = build(allow_signup=True)
auth2.create_user("inhaber", password="supergeheim-lang-genug", email="da@example.com")
assert c2.post("/auth/register", data={"username": "neu2", "password": "supergeheim-lang-genug",
                                       "email": "da@example.com", "next": "/"}).status_code == 409
os.remove(db2)
ok("R4-03: ohne Bestätigung bleibt es bei 409 (Erfolg meldet sofort an — nicht zu verbergen)")
os.remove(db)

# ---------- B6-5: scheitert der Bestätigungsversand, bleibt keine Kontoleiche und kein 500 ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
def _kaputt(*a, **k):
    raise OSError("Mailserver weg")
auth.set_mailer(_kaputt)
cx = TestClient(app, raise_server_exceptions=False)
r = cx.post("/auth/register", data={"username": "pech", "password": "supergeheim-lang-genug",
                                    "email": "pech@example.com", "next": "/"})
assert r.status_code == 200, r.status_code
assert auth.store.get_user_by_name("pech") is None, "Konto muss zurückgenommen sein"
_ev = [z["event"] for z in auth.store._all("SELECT event FROM audit")]
assert "verify_send_error" in _ev, _ev
# … und die Registrierung lässt sich wiederholen, sobald der Mailer wieder geht
auth.set_mailer(lambda to, s_, t, html=None: sent.append({"to": to, "text": t}))
r = cx.post("/auth/register", data={"username": "pech", "password": "supergeheim-lang-genug",
                                    "email": "pech@example.com", "next": "/"})
assert r.status_code == 200 and auth.store.get_user_by_name("pech") is not None
ok("B6-5: Mailer-Fehler bei der Registrierung → kein 500, Konto zurückgenommen, erneut möglich")
os.remove(db)

# ---------- R4-09: nie bestätigte Konten räumt gc() weg — und NUR die ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
c.post("/auth/register", data={"username": "squatter", "password": "supergeheim-lang-genug",
                               "email": "opfer@example.com", "next": "/"})
sq = auth.store.get_user_by_name("squatter")["id"]
# Gegenprobe 1: ein vom Admin gesperrtes Bestandskonto ohne Bestätigungstoken
alt = auth.create_user("gesperrt", password="supergeheim-lang-genug", email="g@example.com")
auth.store.set_disabled(alt, True)
# Gegenprobe 2: ein bestätigtes und später gesperrtes Konto (eingelöster Token daneben)
c.post("/auth/register", data={"username": "echt", "password": "supergeheim-lang-genug",
                               "email": "echt@example.com", "next": "/"})
echt = auth.store.get_user_by_name("echt")["id"]
_tok = re.search(r"/auth/verify/([\w\-]+)", sent[-1]["text"]).group(1)
assert auth.redeem_magic(_tok, purpose="verify_email")
auth.store._exec("UPDATE magic_token SET expires_at=0")
auth.store.set_disabled(echt, True)
assert auth.gc()["unverified_accounts"] == 1
assert auth.store.get_user(sq) is None, "nie bestätigtes Konto nach Ablauf entfernt"
assert auth.store.get_user(alt) is not None, "gesperrtes Bestandskonto bleibt"
assert auth.store.get_user(echt) is not None, "bestätigtes Konto bleibt"
assert c.post("/auth/register", data={"username": "richtig", "password": "supergeheim-lang-genug",
                                      "email": "opfer@example.com", "next": "/"}).status_code == 200
assert auth.store.get_user_by_name("richtig") is not None, "die Adresse ist wieder frei"
ok("R4-09: gc() entfernt nie bestätigte Konten nach Ablauf des Links — nur diese")
os.remove(db)

# ---------- Angriff A1: Benutzername als Orakel für die Adresse (R4-03 umgangen) ----------
# Vorher prüfte die Registrierung die Adresse VOR dem Namen: vergebener Name + vergebene Adresse
# → 200, vergebener Name + freie Adresse → 409. Und ein Wegwerfname verriet beim zweiten Versuch
# per 409, ob der erste ein Konto angelegt hatte.
for _modus in ("both", "username"):
    db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, login_identifier=_modus)
    auth.create_user("opfer", password="supergeheim-lang-genug", email="vergeben@example.com")
    _reg = lambda n, e: c.post("/auth/register", data={"username": n, "password": "supergeheim-lang-genug",
                                                       "email": e, "next": "/"}).status_code
    assert _reg("admin", "vergeben@example.com") == _reg("admin", "frei@example.com") == 409, _modus
    assert _reg("zz1", "vergeben@example.com") == _reg("zz2", "frei2@example.com") == 200, _modus
    assert _reg("zz1", "zz1@probe.example") == _reg("zz2", "zz2@probe.example") == 409, _modus
    # Die Adresse im Namensfeld (fremde Adresse) verriet über die Kreuzprüfung dasselbe
    assert _reg("vergeben@example.com", "x1@probe.example") == _reg("frei3@example.com", "x2@probe.example") == 400
    assert auth.store._exec("SELECT COUNT(*) FROM users WHERE email='vergeben@example.com'").fetchone()[0] == 1
    # Der Platzhalter räumt gc() nach Ablauf weg — wie ein nie bestätigtes echtes Konto
    auth.store._exec("UPDATE magic_token SET expires_at=0")
    auth.gc()
    assert auth.store.get_user_by_name("zz1") is None and auth.store.get_user_by_name("zz2") is None
    assert auth.store.get_user_by_name("opfer") is not None
    os.remove(db)
# Name = eigene Adresse bleibt erlaubt und läuft über die Adress-Prüfung (gleiche Antwort)
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True)
auth.create_user("opfer", password="supergeheim-lang-genug", email="vergeben@example.com")
_reg = lambda n, e: c.post("/auth/register", data={"username": n, "password": "supergeheim-lang-genug",
                                                   "email": e, "next": "/"}).status_code
assert _reg("vergeben@example.com", "vergeben@example.com") == _reg("frei@example.com", "frei@example.com") == 200
os.remove(db)
ok("A1: vergebener Name, Wegwerfname und Adresse im Namensfeld verraten die Adresse nicht mehr")

# ---------- Angriff A2: Hinweismails verbrauchen nicht das Kontingent des Inhabers ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                               password_reset_enabled=True)
auth.create_user("opfer", password="supergeheim-lang-genug", email="opfer@example.com")
for _i in range(5):
    c.post("/auth/register", data={"username": f"angr{_i}", "password": "supergeheim-lang-genug",
                                   "email": "opfer@example.com", "next": "/"})
_hinweise = [m for m in sent if m["to"] == "opfer@example.com"]
assert len(_hinweise) == 3, len(_hinweise)          # die Hinweise selbst bleiben gedrosselt
_n = len(sent)
assert c.post("/auth/forgot", data={"email": "opfer@example.com"}).status_code == 200
assert c.post("/auth/magic/request", data={"email": "opfer@example.com", "next": "/"}).status_code == 200
_neu = sent[_n:]
assert len(_neu) == 2 and "/auth/reset" in _neu[0]["text"] and "/auth/magic/" in _neu[1]["text"], _neu
os.remove(db)
ok("A2: fremd ausgelöste Hinweise sperren Reset und Anmelde-Link des Inhabers nicht")

# ---------- Angriff A3: ungültige Token füllen das Audit-Log nicht ----------
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                               password_reset_enabled=True)
import logging as _logging, io as _io
from tinysesam import security as _sec2
_puffer = _io.StringIO()
_h = _logging.StreamHandler(_puffer)
_sec2.seclog.addHandler(_h)
try:
    for _i in range(200):
        assert c.get(f"/auth/magic/x{_i}").status_code == 400
finally:
    _sec2.seclog.removeHandler(_h)
_z = lambda ev: auth.store._exec("SELECT COUNT(*) FROM audit WHERE event=?", (ev,)).fetchone()[0]
assert _z("token_invalid") == auth._TOKEN_AUDIT_MAX, _z("token_invalid")
assert _z("token_invalid_throttled") == 1, "genau eine Zeile, wenn der Deckel greift"
assert _puffer.getvalue().count("failed verification") == 200, "das Sicherheits-Log (fail2ban) sieht alles"
# GET /auth/reset ohne Token ist kein vorgelegter Link — kein Eintrag, keine Log-Zeile
db2, auth2, app2, sent2, c2 = build(password_reset_enabled=True)
_puffer = _io.StringIO()
_h = _logging.StreamHandler(_puffer)
_sec2.seclog.addHandler(_h)
try:
    assert c2.get("/auth/reset").status_code == 400
finally:
    _sec2.seclog.removeHandler(_h)
assert auth2.store._exec("SELECT COUNT(*) FROM audit WHERE event='token_invalid'").fetchone()[0] == 0
assert "failed verification" not in _puffer.getvalue()
os.remove(db); os.remove(db2)
ok("A3: token_invalid im Audit-Log global gedeckelt (+1 Hinweiszeile), /auth/reset ohne Token kein Fehlalarm")

# ---------- Angriff A5: Bestandsadresse in Unicode-Form, Eingabe als A-Label ----------
db, auth, app, sent, c = build(allow_signup=True)
auth.store._exec("INSERT INTO users(username, email, created_at) VALUES ('alt', 'user@bücher.example', 0)")
assert auth.store.get_user_by_email("user@xn--bcher-kva.example")["username"] == "alt"
assert auth.store.get_user_by_email("USER@XN--BCHER-KVA.example")["username"] == "alt"
assert c.post("/auth/register", data={"username": "neu", "password": "supergeheim-lang-genug",
                                      "email": "user@xn--bcher-kva.example", "next": "/"}).status_code == 409
assert auth.store._exec("SELECT COUNT(*) FROM users WHERE username IN ('alt','neu')").fetchone()[0] == 1
os.remove(db)
ok("A5: A-Label-Eingabe findet die Bestandsadresse in Unicode-Form — kein zweites Konto")

# … und der funktioniert OHNE Magic-Link. Das war der eigentliche Fehler: beides hing am selben
# Endpunkt, also verlor man mit dem Anmelde-Link auch die Bestätigung.
db, auth, app, sent, c = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=False)
c.post("/auth/register", data={"username": "ohne", "password": "supergeheim-lang-genug",
                               "email": "o@example.com", "next": "/"})
uid = auth.store.get_user_by_name("ohne")["id"]
token = re.search(r"/auth/verify/([\w\-]+)", sent[0]["text"]).group(1)
assert c.post(f"/auth/verify/{token}", follow_redirects=False).status_code == 303
assert auth.store.get_user(uid)["disabled"] == 0
assert c.get("/auth/magic/request").status_code == 404     # Magic-Link ist wirklich aus
ok("E-Mail-Bestätigung funktioniert ohne Magic-Link")
os.remove(db)

# ---------- Invite-only: ohne Einladung kein Zugang, mit Einladung ok ----------
db, auth, app, sent, c = build(allow_signup=True, signup_invite_only=True, magiclink_enabled=True)
assert c.get("/auth/register").status_code == 403        # ohne Einladung
# Die Basis kommt aus base_url, nicht aus dem Host des TestClients: `create_invite` prueft sie
# seit R4-01 selbst und weist einen fremden Host mit ConfigError ab (kein Token, keine Mail).
inv = auth.create_invite("gast@example.com", auth.cfg.base_url, roles=["editor"])
token = inv["token"]
# Link öffnen → Weiterleitung zur Registrierung (Token NICHT verbraucht)
assert "/auth/invite/" in inv["url"] and "/auth/magic/" not in inv["url"]
r = c.get(f"/auth/invite/{token}", follow_redirects=False)
assert r.status_code == 303 and "/auth/register?invite=" in r.headers["location"]
# Registrierungsseite mit Einladung erreichbar, E-Mail vorbefüllt
page = c.get(f"/auth/register?invite={token}").text
assert "gast@example.com" in page
# Registrieren → Konto mit Rollen aus der Einladung, eingeloggt
r = c.post("/auth/register", data={"username": "gast", "password": "supergeheim-lang-genug", "invite": token, "next": "/geheim"},
           follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/geheim"
u = auth.store.get_user_by_name("gast")
assert u and auth.has_role(u, "editor")
# Einladung ist verbraucht → erneut nutzen scheitert
assert auth.peek_magic(token, purpose="invite") is None
r2 = TestClient(app).get(f"/auth/register?invite={token}")
assert r2.status_code == 403
ok("invite-only: nur mit gültiger Einladung; Rollen übernommen; Einladung one-shot")
os.remove(db)

print("\nREGISTER + INVITE OK ✅")
