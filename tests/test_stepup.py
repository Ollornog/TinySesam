"""Phase 2: Step-up / per-Route-MFA (Flag am Guard), Reauth-Frische, admin_require_mfa."""
import os
import re
import tempfile, os, time
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
import pyotp
import importlib.util
from tinysesam import TinySesam, TinySesamConfig

#: Ohne das Extra [passkey] gibt es keine Passkey-Routen — `build_router` wirft dann
#: `MissingExtra`. Die Suite prüft hier Step-up und Faktor-Abbau, nicht WebAuthn selbst:
#: Sie läuft deshalb auch im Kern-Betrieb und lässt nur die Passkey-Route aus.
HAT_PASSKEY = importlib.util.find_spec("webauthn") is not None


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, stepup_max_age_sec=900))
auth.ensure_admin("admin", "geheim123")
app = FastAPI()
app.include_router(auth.router())


@app.get("/normal")
def normal(u=Depends(auth.require_user)):
    return {"u": u["username"]}


@app.get("/sudo")
def sudo(u=Depends(auth.require(mfa=True))):
    return {"u": u["username"]}


c = TestClient(app)
JSON = {"Accept": "application/json"}
uid = auth.store.get_user_by_name("admin")["id"]


def stale():
    """mfa_at der aktuellen Sitzung künstlich altern lassen."""
    tok = c.cookies.get("tinysesam_session")
    auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(tok)))


# ---------- frisch nach Login → sudo erreichbar ----------
c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
assert c.get("/normal", headers=JSON).status_code == 200
assert c.get("/sudo", headers=JSON).status_code == 200
ok("frische Sitzung: require_user UND require(mfa=True) erreichbar")

# ---------- Frische abgelaufen → normal ok, sudo blockt (403 + Reauth-Header) ----------
stale()
assert c.get("/normal", headers=JSON).status_code == 200, "normale Route bleibt erreichbar"
r = c.get("/sudo", headers=JSON)
assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth") == "/auth/reauth", (r.status_code, dict(r.headers))
ok("abgelaufene Frische: JSON-Client → 403 + X-TinySesam-Reauth")

# Browser (Accept: text/html) → Redirect auf /auth/reauth
r = c.get("/sudo", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"] == "/auth/reauth?next=/sudo", r.headers.get("location")
ok("abgelaufene Frische: Browser → 307 /auth/reauth?next=/sudo")

# ---------- Reauth per Passwort (User ohne TOTP) → wieder frisch ----------
r = c.get("/auth/reauth", follow_redirects=False)
assert r.status_code == 200 and "Passwort" in r.text
assert c.post("/auth/reauth", data={"password": "falsch", "next": "/sudo"}).status_code == 401
r = c.post("/auth/reauth", data={"password": "geheim123", "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/sudo"
assert c.get("/sudo", headers=JSON).status_code == 200
ok("Reauth per Passwort → sudo wieder erreichbar")

# ---------- F-06: der Step-up erneuert das Sitzungs-Token ----------
# Wer das alte Cookie mitgelesen hat, darf nach der Bestätigung keine Sudo-Sitzung halten.
# Laufzeit und Anmeldezeitpunkt bleiben — ein Step-up verlängert die Sitzung nicht.
stale()
vorher = c.cookies.get("tinysesam_session")
zeile_vorher = auth.store.get_session(vorher)
r = c.post("/auth/reauth", data={"password": "geheim123", "next": "/sudo"}, follow_redirects=False)
assert r.status_code == 303 and "tinysesam_session=" in r.headers.get("set-cookie", ""), r.headers
nachher = c.cookies.get("tinysesam_session")
assert nachher and nachher != vorher, "Reauth muss ein neues Token ausgeben"
assert auth.store.get_session(vorher) is None, "das alte Token muss tot sein"
zeile = auth.store.get_session(nachher)
assert zeile["created_at"] == zeile_vorher["created_at"] and zeile["expires_at"] == zeile_vorher["expires_at"]
assert zeile["remember"] == zeile_vorher["remember"] and zeile["mfa_ok"] == 1
assert c.get("/sudo", headers=JSON).status_code == 200
dieb = TestClient(app)
dieb.cookies.set("tinysesam_session", vorher)
assert dieb.get("/normal", headers=JSON).status_code == 401, "altes Cookie trägt nicht mehr"
ok("F-06: Reauth rotiert das Token (altes tot, Laufzeit und created_at unverändert)")

# Dasselbe, wenn der Step-up über einen erneuten Login mit einem Faktor läuft (apply_factor auf
# einer schon vollwertigen Sitzung): neues Token, alte Sitzung weg, keine zweite daneben.
vorher = c.cookies.get("tinysesam_session")
anzahl = len(auth.store.list_sessions(uid))
r = c.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303 and c.cookies.get("tinysesam_session") != vorher
assert auth.store.get_session(vorher) is None and len(auth.store.list_sessions(uid)) == anzahl
ok("F-06: erneuter Faktor auf vollwertiger Sitzung → Token rotiert, Sitzungszahl gleich")

# ---------- API-Key erfüllt Step-up NICHT ----------
key = auth.create_api_key(uid, name="k")["key"]
assert c.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
# frische Session-Cookies raus, nur Key
c2 = TestClient(app)
assert c2.get("/normal", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 200
assert c2.get("/sudo", headers={**JSON, "Authorization": f"Bearer {key}"}).status_code == 403
ok("API-Key: require_user ok, require(mfa=True) → 403 (kein interaktiver Faktor)")

# ---------- admin_require_mfa mit TOTP-User ----------
secret = auth.totp_begin(uid)["secret"]
auth.totp_confirm(uid, pyotp.TOTP(secret).at(time.time() - 30))
auth.cfg.admin_require_mfa = True
c3 = TestClient(app)
# Login → TOTP-Schritt → voll eingeloggt (frisch)
c3.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/"}, follow_redirects=False)
c3.post("/auth/totp", data={"code": pyotp.TOTP(secret).now(), "next": "/"}, follow_redirects=False)
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 200, r.status_code
# altern → Admin-Panel verlangt Reauth
tok = c3.cookies.get("tinysesam_session")
auth.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                     (int(time.time()) - 100000, auth.store.session_hash(tok)))
r = c3.get("/auth/admin", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and "/auth/reauth" in r.headers["location"], r.headers.get("location")
# Reauth verlangt jetzt TOTP (nicht Passwort)
assert "Authenticator" in c3.get("/auth/reauth").text
# Frischer Zeitschritt: Der Code vom Login ist verbraucht (ein TOTP-Code gilt genau einmal).
r = c3.post("/auth/reauth", data={"code": pyotp.TOTP(secret).at(int(time.time()) + 30),
                                  "next": "/auth/admin"}, follow_redirects=False)
assert r.status_code == 303
assert c3.get("/auth/admin", headers={"Accept": "text/html"}).status_code == 200
ok("admin_require_mfa: Panel altert → Reauth per TOTP → wieder frei")

# ---------- R3-3: Faktor-Verwaltung verlangt Frische — und scheitert am API-Key ----------
# Angriff (Befund R3-3, Runde 3): Eine übernommene oder lange offene Sitzung bekam auf jedem
# `require(mfa=True)`-Guard 403, durfte aber weiterhin TOTP löschen, sich zehn frische
# Recovery-Codes ausstellen, die PIN setzen/entfernen und Passkeys löschen. Dieselben Routen
# hingen an `current_user()` — und das akzeptiert auch einen **API-Key**: ein abgeflossenes
# Maschinen-Credential, das nie einen interaktiven Faktor erbracht hat, baute den zweiten
# Faktor seines Besitzers lautlos ab.
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, rp_name="Test",
                                  cookie_secure=False, oidc_enabled=False, pin_enabled=True,
                                  apikey_enabled=True, passkey_enabled=HAT_PASSKEY,
                                  stepup_max_age_sec=900))
uid2 = auth2.create_user("opfer", password="geheim123")
sec2 = auth2.totp_begin(uid2)["secret"]
assert auth2.totp_confirm(uid2, pyotp.TOTP(sec2).at(time.time() - 30))
auth2.set_pin(uid2, "2468")
auth2.store.add_webauthn(uid2, "credid-r3-3", "pubkey", 0, ["internal"], "Testschlüssel")
pk2 = auth2.store.list_webauthn(uid2)[0]["id"]
app2 = FastAPI()
app2.include_router(auth2.router())


@app2.get("/normal2")
def normal2(u=Depends(auth2.require_user)):
    return {"u": u["username"]}


@app2.get("/sudo2")
def sudo2(u=Depends(auth2.require(mfa=True))):
    return {"u": u["username"]}


def koerper(pfad, pin="9876", pk=None):
    """Was die jeweilige Route als Body erwartet (die anderen ignorieren ihn)."""
    if pfad == "/auth/pin/set":
        return {"pin": pin}
    if pfad == "/auth/passkey/delete":
        return {"id": pk}
    return {}


#: Die fünf Routen, die einen Anmeldefaktor abbauen oder ersetzen.
VERWALTUNG = ("/auth/totp/recovery", "/auth/totp/disable", "/auth/pin/set",
              "/auth/pin/disable") + (("/auth/passkey/delete",) if HAT_PASSKEY else ())


def faktoren(a, uid):
    """Womit kann sich dieses Konto gerade anmelden? (TOTP, PIN, Anzahl Passkeys)"""
    return (a.store.has_confirmed_totp(uid), a.has_pin(uid), len(a.store.list_webauthn(uid)))


c4 = TestClient(app2)
c4.post("/auth/login", data={"username": "opfer", "password": "geheim123", "next": "/"},
        follow_redirects=False)
c4.post("/auth/totp", data={"code": pyotp.TOTP(sec2).now(), "next": "/"}, follow_redirects=False)
assert c4.get("/sudo2", headers=JSON).status_code == 200
assert c4.post("/auth/totp/recovery", json={}, headers=JSON).status_code == 200
assert c4.post("/auth/pin/set", json={"pin": "9876"}, headers=JSON).status_code == 200
assert auth2.verify_user_pin(uid2, "9876")
ok("frische Sitzung: Recovery-Codes und PIN-Änderung gehen weiter durch (legitimer Weg)")

tok2 = c4.cookies.get("tinysesam_session")
auth2.store._exec("UPDATE session SET mfa_at=? WHERE token_hash=?",
                  (int(time.time()) - 100000, auth2.store.session_hash(tok2)))
# Vorbedingung — ohne sie prüfte der Block nichts: Die Sitzung LEBT weiter, `current_user()`
# liefert sie, nur die Frische fehlt. Genau darauf stützten sich die fünf Routen vorher; mit
# den alten `current_user()`-Zeilen wäre jede der folgenden Zusicherungen rot.
assert c4.get("/normal2", headers=JSON).status_code == 200, "die Sitzung muss gültig bleiben"
assert c4.get("/sudo2", headers=JSON).status_code == 403, "die Frische muss wirklich weg sein"
vorher2 = faktoren(auth2, uid2)
for pfad in VERWALTUNG:
    antwort = c4.post(pfad, json=koerper(pfad, pk=pk2), headers=JSON)
    assert antwort.status_code == 403, (pfad, antwort.status_code, antwort.text[:90])
    assert antwort.headers.get("X-TinySesam-Reauth") == "/auth/reauth", (pfad, dict(antwort.headers))
assert faktoren(auth2, uid2) == vorher2, "aus einer veralteten Sitzung darf sich kein Faktor ändern"
ok(f"veraltete Sitzung: alle {len(VERWALTUNG)} Faktor-Routen → 403 + Reauth-Hinweis, nichts geändert")

# Frischer Zeitschritt: der Code vom Login ist verbraucht (ein TOTP-Code gilt genau einmal).
r = c4.post("/auth/reauth", data={"code": pyotp.TOTP(sec2).at(int(time.time()) + 30), "next": "/"},
            follow_redirects=False)
assert r.status_code == 303, r.status_code
if HAT_PASSKEY:
    assert c4.post("/auth/passkey/delete", json={"id": pk2}, headers=JSON).status_code == 200
    assert auth2.store.list_webauthn(uid2) == [], "nach dem Step-up muss der legitime Weg offen sein"
else:
    assert c4.post("/auth/pin/disable", json={}, headers=JSON).status_code == 200
    assert not auth2.has_pin(uid2), "nach dem Step-up muss der legitime Weg offen sein"
ok("nach Reauth: derselbe Aufruf geht wieder durch (Faktor abgebaut)")

# ---------- Derselbe Angriff per API-Key, mit eingeschaltetem CSRF ----------
# CSRF bleibt hier AN (Vorgabe): Für einen echten API-Key greift `_csrf_entbehrlich`, die
# CSRF-Schicht hält ihn also nicht auf. Was ihn aufhält, muss die Frische-Schranke sein.
db3 = os.path.join(tempfile.mkdtemp(), "t.db")
auth3 = TinySesam(TinySesamConfig(lang="de", db_path=db3, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, pin_enabled=True, apikey_enabled=True,
                                  passkey_enabled=HAT_PASSKEY))
uid3 = auth3.create_user("opfer", password="geheim123")
sec3 = auth3.totp_begin(uid3)["secret"]
assert auth3.totp_confirm(uid3, pyotp.TOTP(sec3).at(time.time() - 30))
auth3.set_pin(uid3, "1357")
auth3.store.add_webauthn(uid3, "credid-r3-3-api", "pubkey", 0, ["internal"], "Testschlüssel")
pk3 = auth3.store.list_webauthn(uid3)[0]["id"]
schluessel = auth3.create_api_key(uid3, name="ci")["key"]
app3 = FastAPI()
app3.include_router(auth3.router())


@app3.get("/normal3")
def normal3(u=Depends(auth3.require_user)):
    return {"u": u["username"]}


c5 = TestClient(app3)
KEY = {"X-API-Key": schluessel, "Accept": "application/json"}
# Vorbedingung: Der Key ist gültig und `current_user()` liefert damit das Konto — genau die
# Grundlage, auf der die fünf Routen den Faktor-Abbau vorher zuliessen.
assert c5.get("/normal3", headers=KEY).status_code == 200, "der API-Key muss gültig sein"
vorher3 = faktoren(auth3, uid3)
#: Welche Meldung die Abweisung tragen MUSS. `/auth/pin/set` läuft in den Sitzungs-Riegel
#: (er steht dort vor der Fallunterscheidung erste/weitere PIN), die vier reinen Abbau-Routen
#: in die Frische-Schranke. Beides ist 403 — geprüft wird der Grund, nicht nur die Zahl,
#: sonst hielte auch ein zufälliges CSRF-403 den Test grün.
GRUND = {"/auth/pin/set": "api.needs_session"}
for pfad in VERWALTUNG:
    antwort = c5.post(pfad, json=koerper(pfad, pin="1111", pk=pk3), headers=KEY)
    assert antwort.status_code == 403, (pfad, antwort.status_code, antwort.text[:90])
    erwartet = auth3.t(GRUND.get(pfad, "api.stepup_session"))
    assert antwort.json().get("detail") == erwartet, (pfad, antwort.text[:90])
assert faktoren(auth3, uid3) == vorher3, "ein API-Key darf keinen Faktor abbauen"
assert auth3.verify_user_pin(uid3, "1357"), "die PIN darf sich per API-Key nicht ändern lassen"
ok(f"API-Key (CSRF an): alle {len(VERWALTUNG)} Faktor-Routen → 403, jede mit ihrem Grund")

# ---------- A-umgehung-2: derselbe Riegel gilt für die ANLAGE eines Faktors ----------
# Der R3-3-Fix deckte nur den ABBAU. Die Anlage hing weiter an `current_user()`, und das
# akzeptiert einen API-Key; die CSRF-Prüfung entfällt für einen echten Key ohnehin
# (`_csrf_entbehrlich`). Zwei Wege standen damit offen:
#   (1) `GET /auth/totp/setup` gibt das Geheimnis im Klartext zurück, `POST` bestätigt es →
#       das Konto trug danach ein TOTP, dessen Geheimnis der KEY-Inhaber kennt.
#   (2) Ein selbst registrierter Passkey ist ein vollwertiger Login → frische interaktive
#       Sitzung → und damit stand der Key doch vor den fünf Abbau-Routen.
# Nachgestellt in `A2b_r3-3_apikey_totp.py` / `A2_r3-3_apikey_passkey.py` (Runde 3, Angriff
# gegen die Fixes). Mutationsprobe: `auth.require_session(...)` in `totp_setup` oder
# `reg_begin` wieder durch `auth.current_user(request)` ersetzt → dieser Block wird rot
# (GET 200 mit Geheimnis bzw. begin 200), der Rest der Suite bleibt grün.
db4 = os.path.join(tempfile.mkdtemp(), "t.db")
auth4 = TinySesam(TinySesamConfig(lang="de", db_path=db4, rp_name="Test", cookie_secure=False,
                                  oidc_enabled=False, pin_enabled=True, apikey_enabled=True,
                                  passkey_enabled=HAT_PASSKEY))
uid4 = auth4.create_user("opfer", password="geheim123")      # KEIN TOTP, KEINE PIN
app4 = FastAPI()
app4.include_router(auth4.router())
c6 = TestClient(app4)
KEY4 = {"X-API-Key": auth4.create_api_key(uid4, name="ci")["key"], "Accept": "application/json"}

r = c6.get("/auth/totp/setup", headers=KEY4)
assert r.status_code == 403, (r.status_code, r.text[:90])
assert r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert auth4.store.get_totp(uid4) is None, "der Aufruf darf nicht einmal ein Geheimnis anlegen"
# Ohne Geheimnis kann der Key auch nichts bestätigen — geprüft wird trotzdem die Route selbst.
r = c6.post("/auth/totp/setup", data={"code": "000000"}, headers=KEY4)
assert r.status_code == 403 and r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert not auth4.store.has_confirmed_totp(uid4), "per API-Key darf kein TOTP scharf werden"
# Seit N7 entsteht das Geheimnis in einer EIGENEN Route. Sie ist der Weg, den der Riegel oben
# eigentlich meint — ohne diese Zeile wäre er nach dem Umbau umgehbar geblieben.
r = c6.post("/auth/totp/setup/start", data={}, headers=KEY4)
assert r.status_code == 403 and r.json().get("detail") == auth4.t("api.needs_session"), r.text[:120]
assert auth4.store.get_totp(uid4) is None, "auch der neue Start darf per Key kein Geheimnis anlegen"
for pfad in (("/auth/passkey/register/begin", "/auth/passkey/register/finish")
             if HAT_PASSKEY else ()):
    r = c6.post(pfad, json={}, headers=KEY4)
    assert r.status_code == 403, (pfad, r.status_code, r.text[:90])
    assert r.json().get("detail") == auth4.t("api.needs_session"), (pfad, r.text[:120])
    assert "tinysesam_waflow" not in r.cookies, pfad
assert auth4.store.list_webauthn(uid4) == [], "per API-Key darf kein Passkey dazukommen"
assert auth4.list_api_keys(uid4), "Vorbedingung: der Key ist ausgestellt und gültig"
ok("API-Key: auch die ANLAGE (totp/setup" + (", passkey/register" if HAT_PASSKEY else "")
   + ") → 403 'nur mit Sitzung'")

# Und der legitime Weg desselben Kontos läuft weiter — sonst wäre der Riegel eine Sackgasse.
c7 = TestClient(app4)
c7.get("/auth/login", headers={"Accept": "text/html"})     # holt das CSRF-Cookie
assert c7.post("/auth/login", data={"username": "opfer", "password": "geheim123", "next": "/",
                                    "_csrf": c7.cookies.get("tinysesam_csrf") or ""},
               follow_redirects=False).status_code == 303
seite = c7.get("/auth/totp/setup", headers={"Accept": "text/html"})
assert seite.status_code == 200, seite.status_code
# Seit N7 zeigt der GET nur den Knopf; das Geheimnis entsteht erst im CSRF-geschützten POST.
assert "/auth/totp/setup/start" in seite.text, seite.text[:200]
seite = c7.post("/auth/totp/setup/start",
                data={"_csrf": c7.cookies.get("tinysesam_csrf") or ""},
                headers={"Accept": "text/html"})
assert seite.status_code == 200, seite.status_code
geheim = re.search(r"<div class=mono>([A-Z2-7]+)</div>", seite.text)
assert geheim, seite.text[:200]
r = c7.post("/auth/totp/setup", data={"code": pyotp.TOTP(geheim.group(1)).now()},
            headers={"X-CSRF-Token": c7.cookies.get("tinysesam_csrf") or "", "Accept": "application/json"})
assert r.status_code == 200 and r.json() == {"ok": True, "other_sessions": 0}, r.text[:120]
assert auth4.store.has_confirmed_totp(uid4), "die Einrichtung aus der Sitzung muss durchgehen"
ok("Sitzung desselben Kontos: TOTP einrichten geht unverändert (Geheimnis, Bestätigung)")

# ---------- Runde 2: Fehlversuche an der Reauth-Seite sperren die ANMELDUNG nicht ----------
# `/auth/reauth` verbuchte seine Fehlgriffe als `record_login(…, "reauth")`, und `is_locked`
# zählte sie mit: Fünf Tippfehler bei der Step-up-Bestätigung sperrten dem Nutzer die
# Anmeldung für `lockout_window_sec` — auch mit dem richtigen Passwort. Eine Bestätigung ist
# aber keine Anmeldung; wer sie leistet, ist bereits angemeldet. Jetzt hat sie ihren eigenen
# Topf (`is_reauth_locked`, `reauth_max_attempts`), und der kennt keine IP-Dimension: Das
# Raten trifft nur das eigene Konto. (Mutationsprobe: in `reauth_submit` wieder `is_locked`
# prüfen und "reauth" aus `security.EIGENE_SPERRE` nehmen → (a) wird rot.)
db5 = os.path.join(tempfile.mkdtemp(), "t.db")
auth5 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db5, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False, stepup_max_age_sec=900))
PW_ANNA, PW_BEA = "Anna-Passwort-2026", "Bea-Passwort-2026"      # Literale: nicht neben `password=`
auth5.create_user("anna", PW_ANNA)
auth5.create_user("bea", PW_BEA)
app5 = FastAPI()
app5.include_router(auth5.router())
c8 = TestClient(app5)
assert c8.post("/auth/login", data={"username": "anna", "password": PW_ANNA, "next": "/"},
               follow_redirects=False).status_code == 303
GRENZE_R = auth5.sec("reauth_max_attempts")
for i in range(GRENZE_R):
    r = c8.post("/auth/reauth", data={"password": f"tippfehler{i}", "next": "/"})
    assert r.status_code == 401, (i, r.status_code)
assert auth5.store.count_fails(0, username="anna", method="reauth") >= GRENZE_R, \
    "die Fehlversuche wurden gar nicht verbucht — der Test misst dann nichts"

# (a) Der Angriff: Die Anmeldung desselben Kontos bleibt offen.
assert not auth5.is_locked("anna", "testclient"), "Step-up-Tippfehler sperren den Login"
frisch5 = TestClient(app5)
r = frisch5.post("/auth/login", data={"username": "anna", "password": PW_ANNA, "next": "/"},
                 follow_redirects=False)
assert r.status_code == 303, f"Login nach Step-up-Tippfehlern gesperrt: {r.status_code}"
ok("Fehlversuche an der Reauth-Seite sperren die Anmeldung nicht (eigener Topf)")

# (b) Gebremst wird trotzdem — dort, wo geraten wurde: Der nächste Versuch läuft in die Sperre,
# auch mit dem richtigen Passwort. Die Schwelle ist verdrahtet, nicht nur vorhanden.
assert auth5.is_reauth_locked("anna", "testclient"), "kein eigener Lockout für die Bestätigung"
r = c8.post("/auth/reauth", data={"password": PW_ANNA, "next": "/"})
assert r.status_code == 429, f"Step-up-Raten läuft nicht in die Sperre: {r.status_code}"
ok("…die Bestätigung selbst ist nach reauth_max_attempts gesperrt (429)")

# (c) Keine IP-Dimension: Ein zweiter Nutzer hinter derselben Adresse bestätigt weiter.
c9 = TestClient(app5)
assert c9.post("/auth/login", data={"username": "bea", "password": PW_BEA, "next": "/"},
               follow_redirects=False).status_code == 303
assert not auth5.is_reauth_locked("bea", "testclient"), \
    "die Fehlversuche eines Kollegen sperren hinter NAT die Bestätigung eines Unbeteiligten"
r = c9.post("/auth/reauth", data={"password": PW_BEA, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"Bestätigung des Unbeteiligten gesperrt: {r.status_code}"
ok("…und sie sperrt pro Konto, nicht pro Anschluss")

# (d) Der legitime Weg von anna ist nach dem Abtragen wieder offen (Admin-Weg wie beim Login).
auth5.store.clear_fails(username="anna", method="reauth")
r = c8.post("/auth/reauth", data={"password": PW_ANNA, "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"Bestätigung nach Entsperren scheitert: {r.status_code}"
ok("…entsperrbar, danach bestätigt dasselbe Konto wieder")
os.remove(db5)


# ---------- H-18 (b): jede Selbstverwaltungsroute ist eingeordnet und hält ihre Klasse ----------
# R3-3 hat fünf Routen an die Step-up-Frische gebunden — einzeln. Eine sechste Route, die einen
# Faktor anlegt oder abbaut, fiele keinem Test auf. Deshalb: Jede POST-Route des Routers, die
# nicht zum Anmeldefluss gehört, steht in genau einer Klasse, und jede Klasse wird gemessen.
# Eine neue Route ohne Einordnung macht diese Prüfung rot — das ist der Zweck.
db6 = os.path.join(tempfile.mkdtemp(), "t.db")
auth6 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db6, rp_name="Test",
                                  passkey_enabled=HAT_PASSKEY, oidc_enabled=False,
                                  cookie_secure=False, stepup_max_age_sec=900, pin_enabled=True,
                                  apikey_enabled=True, account_enabled=True,
                                  resource_locks_enabled=True))
app6 = FastAPI()
router6 = auth6.router()
app6.include_router(router6)
uid6 = auth6.create_user("selbst", password="Geheim12345!")
auth6.set_pin(uid6, "471193")
_sec6 = auth6.totp_begin(uid6)["secret"]
assert auth6.totp_confirm(uid6, pyotp.TOTP(_sec6).now())
key6 = auth6.create_api_key(uid6, "bot")["key"]

#: Anmeldefluss: Diese Routen SIND die Bestätigung, sie verwalten nichts.
ANMELDEFLUSS = {"/auth/login", "/auth/totp", "/auth/pin", "/auth/magic/request", "/auth/reauth",
                "/auth/forgot", "/auth/reset", "/auth/register", "/auth/resource/{name}",
                "/auth/saml/acs", "/auth/passkey/login/begin", "/auth/passkey/login/finish"}
#: Verlangen frische Bestätigung (require_mfa): abgelaufene Sitzung → 403 + X-TinySesam-Reauth.
STEPUP = {"/auth/totp/disable", "/auth/totp/recovery", "/auth/pin/set", "/auth/pin/disable",
          "/auth/passkey/delete"}
#: Das alte Passwort ist die Bestätigung (gedrosselt, gesperrt, protokolliert — R4-10).
PASSWORT = {"/auth/password"}
#: Einrichtung eines Faktors: nur mit interaktiver Sitzung, nie mit API-Key (R3-1/R3-3).
NUR_SITZUNG = {"/auth/totp/setup/start", "/auth/totp/setup", "/auth/passkey/register/begin",
               "/auth/passkey/register/finish"}
#: Bekannt offen — mit Begründung. Wird eine davon gebunden, gehört sie nach STEPUP.
OFFEN = {"/auth/sessions/revoke": "F-09 (Sitzungen beenden ohne erneute Authentisierung)",
         "/auth/apikeys": "Key-Ausgabe ohne Step-up (gemeldet mit H-18)",
         "/auth/apikeys/{key_id}/revoke": "Key-Widerruf ohne Step-up (gemeldet mit H-18)"}

# Aus dem Router selbst, nicht aus `app6.routes`: Neuere FastAPI-Fassungen legen eingebundene
# Router dort als ein Objekt ohne Pfad ab — die Liste wäre leer und die Prüfung still grün.
_post6 = {rt.path for rt in router6.routes
          if "POST" in (getattr(rt, "methods", None) or ())
          and not str(getattr(rt, "path", "")).startswith(auth6.cfg.admin_path)}
_klassen = [ANMELDEFLUSS, STEPUP, PASSWORT, NUR_SITZUNG, set(OFFEN)]
_uneingeordnet = sorted(p for p in _post6 if not any(p in k for k in _klassen))
assert not _uneingeordnet, f"Selbstverwaltungsroute ohne Einordnung: {_uneingeordnet}"
_doppelt = [p for p in _post6 if sum(p in k for k in _klassen) > 1]
assert not _doppelt, _doppelt
assert STEPUP & _post6 and NUR_SITZUNG & _post6, f"Wächter ohne Treffer: Router-Aufbau geändert? {sorted(_post6)}"
ok(f"H-18: alle {len(_post6)} POST-Routen eingeordnet (Anmeldefluss, Step-up, Passwort, Sitzung, offen)")


def _abgestanden_client():
    """Voll angemeldet, aber Anmeldung UND letzte Bestätigung liegen lange zurück."""
    cl = TestClient(app6)
    tok = auth6.store.create_session(uid6, 3600, True, "password")
    alt = int(time.time()) - 100000
    auth6.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                      (alt, alt, auth6.store.session_hash(tok)))
    cl.cookies.set(auth6.cfg.session_cookie, tok)
    return cl


_nutzlast = {"/auth/pin/set": {"json": {"pin": "999999"}}, "/auth/totp/setup": {"data": {"code": "000000"}},
             "/auth/password": {"json": {"current": "falsch-falsch", "new": "Neu1234567890!"}},
             "/auth/sessions/revoke": {"json": {"scope": "others"}},
             "/auth/apikeys": {"json": {"name": "neu"}}}
for pfad in sorted(STEPUP & _post6):
    r = _abgestanden_client().post(pfad, headers=JSON, **_nutzlast.get(pfad, {}))
    assert r.status_code == 403 and r.headers.get("X-TinySesam-Reauth"), \
        f"{pfad}: abgelaufene Bestätigung kam durch ({r.status_code}) — Step-up fehlt"
for pfad in sorted(NUR_SITZUNG & _post6):
    r = TestClient(app6).post(pfad, headers={**JSON, "X-API-Key": key6}, **_nutzlast.get(pfad, {}))
    assert r.status_code in (401, 403), f"{pfad}: API-Key richtet einen Faktor ein ({r.status_code})"
r = _abgestanden_client().post("/auth/password", headers=JSON, **_nutzlast["/auth/password"])
assert r.status_code == 403 and auth6.check_password("selbst", "Geheim12345!"), \
    f"/auth/password ohne das alte Passwort: {r.status_code}"
for pfad in sorted(set(OFFEN) & _post6):
    ziel = pfad.replace("{key_id}", str(auth6.list_api_keys(uid6)[0]["id"]))
    r = _abgestanden_client().post(ziel, headers=JSON, **_nutzlast.get(pfad, {}))
    assert r.status_code == 200, (
        f"{pfad} verlangt jetzt eine Bestätigung ({r.status_code}) — aus OFFEN nach STEPUP "
        f"verschieben ({OFFEN[pfad]})")
ok(f"H-18: {len(STEPUP & _post6)} Routen verlangen Step-up, {len(NUR_SITZUNG & _post6)} nur eine "
   f"Sitzung, {len(set(OFFEN) & _post6)} bekannt offen ({', '.join(sorted(set(OFFEN.values())))})")
os.remove(db6)

# ---------- A-2: der Step-up behält die Art des Sitzungs-Cookies ----------
# Seit F-06 dreht ein Step-up das Token, und der Aufrufer setzt das Cookie neu. Mit der
# Vorgabe `remember=True` bekam eine Sitzung OHNE „Angemeldet bleiben" dabei ein Cookie für
# sieben Tage, das das Schließen des Browsers am geteilten Rechner überlebte; umgekehrt machte
# die PIN-Route mit leerem Formularfeld aus einer gemerkten Sitzung ein Session-Cookie.
db6 = os.path.join(tempfile.mkdtemp(), "t.db")
auth6 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db6, passkey_enabled=False,
                                  oidc_enabled=False, cookie_secure=False, magiclink_enabled=True,
                                  pin_enabled=True, base_url="https://auth.example.com"))
auth6.set_mailer(lambda *a, **k: None)
auth6.ensure_admin("admin", "geheim123")
uid6 = auth6.store.get_user_by_name("admin")["id"]
auth6.set_pin(uid6, "24680")
app6 = FastAPI()
app6.include_router(auth6.router())


def _sitzungs_cookie(antwort):
    zeilen = [z for z in antwort.headers.get_list("set-cookie") if z.startswith("tinysesam_session=")]
    assert len(zeilen) == 1, antwort.headers.get_list("set-cookie")
    return zeilen[0].lower()


for merken in ("", "on"):
    c6 = TestClient(app6)
    r = c6.post("/auth/login", data={"username": "admin", "password": "geheim123", "next": "/",
                                     "remember": merken}, follow_redirects=False)
    assert ("max-age" in _sitzungs_cookie(r)) == bool(merken), _sitzungs_cookie(r)
    vorher = c6.cookies.get("tinysesam_session")
    roh = auth6.create_magic_token("login", user_id=uid6, email="x@example.com", ttl_min=15,
                                   payload={"next": "/"})
    r = c6.get(f"/auth/magic/{roh}", follow_redirects=False)
    assert c6.cookies.get("tinysesam_session") != vorher, "Step-up muss rotieren (F-06)"
    assert ("max-age" in _sitzungs_cookie(r)) == bool(merken), \
        f"Magic-Step-up (remember={merken!r}) ändert die Cookie-Art: {_sitzungs_cookie(r)}"
    # PIN mit dem GEGENTEIL im Formular — die Sitzung hat ihre Art beim ersten Faktor bekommen.
    r = c6.post("/auth/pin", data={"username": "admin", "pin": "24680", "next": "/",
                                   "remember": "" if merken else "on"}, follow_redirects=False)
    assert r.status_code == 303, r.status_code
    assert ("max-age" in _sitzungs_cookie(r)) == bool(merken), \
        f"PIN-Step-up (Sitzung remember={merken!r}) ändert die Cookie-Art: {_sitzungs_cookie(r)}"
    zeile = auth6.store.get_session(c6.cookies.get("tinysesam_session"))
    assert bool(zeile["remember"]) == bool(merken)
ok("A-2: Step-up per Magic-Link und PIN behält die Cookie-Art der Sitzung (merken ja/nein)")
os.remove(db6)

os.remove(db)
os.remove(db2)
os.remove(db3)
os.remove(db4)
print("\nSTEP-UP OK ✅")
