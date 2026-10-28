"""Phase 4: shared resource secret (PIN OR passphrase) — without a user account."""
import os
import tempfile, os
from fastapi import FastAPI, Depends
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False, oidc_enabled=False,
                                 cookie_secure=False, resource_locks_enabled=True))
# two areas: one PIN, one passphrase
auth.set_resource_secret("fotos", "2468", kind="pin", label="Familienfotos")
auth.set_resource_secret("wiki", "geheime passphrase", kind="password", label="Team-Wiki")

app = FastAPI()
app.include_router(auth.router())


@app.get("/fotos")
def fotos(_=Depends(auth.require_resource("fotos"))):
    return {"area": "fotos"}


@app.get("/wiki")
def wiki(_=Depends(auth.require_resource("wiki"))):
    return {"area": "wiki"}


c = TestClient(app)
JSON = {"Accept": "application/json"}

# locked without unlock → 401 (JSON) or 307 to the unlock page (browser)
assert c.get("/fotos", headers=JSON).status_code == 401
r = c.get("/fotos", headers={"Accept": "text/html"}, follow_redirects=False)
assert r.status_code == 307 and r.headers["location"] == "/auth/resource/fotos?next=/fotos"
ok("locked area: JSON→401, browser→307 to the unlock page")

# unlock page shows PIN or password field depending on kind
assert "Familienfotos" in c.get("/auth/resource/fotos").text
assert "Zugangswort" in c.get("/auth/resource/wiki").text
ok("unlock page: PIN field or passphrase field depending on kind")

# falsches Geheimnis → 401
assert c.post("/auth/resource/fotos", data={"secret": "0000", "next": "/fotos"}).status_code == 401
ok("falsches Geheimnis → 401")

# correct PIN unlocks → access, without any user login
r = c.post("/auth/resource/fotos", data={"secret": "2468", "next": "/fotos"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/fotos"
assert c.get("/fotos", headers=JSON).json() == {"area": "fotos"}
ok("PIN correct → area open (no user account needed)")

# unlocking is per area: wiki still locked
assert c.get("/wiki", headers=JSON).status_code == 401
r = c.post("/auth/resource/wiki", data={"secret": "geheime passphrase", "next": "/wiki"}, follow_redirects=False)
assert r.status_code == 303
assert c.get("/wiki", headers=JSON).json() == {"area": "wiki"}
# fotos stays open in parallel
assert c.get("/fotos", headers=JSON).status_code == 200
ok("Freischaltung pro Bereich getrennt (Passphrase-Bereich separat)")

# lockout after too many failed attempts (pseudo user res:name)
c2 = TestClient(app)
GRENZE = auth._sec("resource_max_attempts")
codes = [c2.post("/auth/resource/fotos", data={"secret": "0000", "next": "/"}).status_code
         for _ in range(GRENZE)]
assert codes == [401] * GRENZE, codes
assert c2.post("/auth/resource/fotos", data={"secret": "2468", "next": "/"}).status_code == 429
ok("Ressourcen-Lockout greift")

# ---------- Round 2: area slips do not lock any SIGN-IN ----------
# EVERY visitor may try the area PIN — an account is not needed for it. Their
# slips nevertheless ran into the login bucket (`record_login(pseudo, …, "resource")` +
# `is_locked`), and because the IP threshold `max_login_attempts * ip_attempt_factor` applies there,
# three areas with five slips each from the same address were enough to lock the sign-in of accounts
# that had nothing to do with it. Now the own bucket locks what it
# protects: areas. (Mutation probe: check `is_locked` again in `resource_submit` and
# remove "resource" from `security.EIGENE_SPERRE` → (a) turns red.)
db2 = os.path.join(tempfile.mkdtemp(), "t.db")
auth2 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db2, rp_name="Test",
                                  passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                  resource_locks_enabled=True))
auth2.create_user("unbeteiligt", "Unbeteiligt-Passwort-1")
app2 = FastAPI()
app2.include_router(auth2.router())
c3 = TestClient(app2)
bereiche = ["lager", "archiv", "keller"]
for n in bereiche:
    auth2.set_resource_secret(n, "1234", kind="pin", label=n)
# Since R7-3 the ADDRESS locks already at `resource_max_attempts` — the attack situation (the address
# reaches the login IP threshold) can therefore no longer be produced with the default.
# For this probe the area threshold is therefore raised to the login IP threshold.
JE_BEREICH = auth2._sec("resource_max_attempts")     # as before: five per area, 15 together
auth2.set_security("resource_max_attempts",
                   auth2._sec("max_login_attempts") * auth2._sec("ip_attempt_factor"))
for n in bereiche:
    for _ in range(JE_BEREICH):
        c3.post(f"/auth/resource/{n}", data={"secret": "0000", "next": "/"})
IP_GRENZE = auth2._sec("max_login_attempts") * auth2._sec("ip_attempt_factor")
assert auth2.store.count_fails(0, ip="testclient", method="resource") >= IP_GRENZE, \
    "attack situation not produced: the test IP has not reached the login IP threshold"

# (a) The attack: the sign-in of an uninvolved person from the same address stays open.
assert not auth2._is_locked("unbeteiligt", "testclient"), \
    "slips on the area PIN lock the sign-in of uninvolved persons"
r = c3.post("/auth/login", data={"username": "unbeteiligt", "password": "Unbeteiligt-Passwort-1"},
            follow_redirects=False)
assert r.status_code == 303, f"Login des Unbeteiligten gesperrt: {r.status_code}"
ok("area slips lock no sign-in (own bucket)")

# (b) The IP dimension is nevertheless retained here — unlike with the signed-in paths:
# Here a stranger guesses, the victim is no particular user, and without it he could keep guessing endlessly via
# new area names. A FOURTH, never touched area is therefore closed from
# the same address.
auth2.set_resource_secret("tresor", "9876", kind="pin", label="Tresor")
assert auth2.store.count_fails(0, username="res:tresor", method="resource") == 0, \
    "precondition: this area itself has seen no slip"
r = c3.post("/auth/resource/tresor", data={"secret": "9876", "next": "/"})
assert r.status_code == 429, f"the IP threshold of the area bucket does not apply: {r.status_code}"
# …and another connection is unaffected (the lockout sticks to the address, not to the area).
c4 = TestClient(app2, client=("203.0.113.30", 50000))
r = c4.post("/auth/resource/tresor", data={"secret": "9876", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"fremder Anschluss mitgesperrt: {r.status_code}"
ok("…the IP threshold of the area bucket remains (locks areas, no sign-ins)")
os.remove(db2)

# ---------- R7-3: a single stranger does not lock the area for everyone ----------
# Until T-13 the area threshold (`res:<name>`) applied already at `resource_max_attempts` — no matter
# who the slips came from. Five requests from a stranger locked the area for everyone,
# even for those who know the secret. Now the address stops the stranger first; the
# area itself only closes at `account_attempt_factor` times that, i.e. only if several
# connections guess. (Mutation probe: swap the two resource limits in `_regeln` → red.)
db5 = os.path.join(tempfile.mkdtemp(), "t.db")
auth5 = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db5, rp_name="Test",
                                  passkey_enabled=False, oidc_enabled=False, cookie_secure=False,
                                  resource_locks_enabled=True))
auth5.set_resource_secret("garten", "4711", kind="pin", label="Garten")
app5 = FastAPI()
app5.include_router(auth5.router())
G5 = auth5._sec("resource_max_attempts")
fremd = TestClient(app5, client=("198.51.100.66", 40000))
codes = [fremd.post("/auth/resource/garten", data={"secret": "0000", "next": "/"}).status_code
         for _ in range(G5 + 2)]
assert codes[:G5] == [401] * G5 and codes[G5:] == [429, 429], codes
kenner = TestClient(app5, client=("203.0.113.77", 40000))
r = kenner.post("/auth/resource/garten", data={"secret": "4711", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, f"a single stranger locks the area for everyone: {r.status_code}"
ok("R7-3: a stranger locks only his address, not the area")

# …but distributed guessing stays limited: from `account_attempt_factor` connections the
# area closes, also for a further, uninvolved one.
kenner.cookies.clear()
auth5.store.clear_fails(username="res:garten")
for i in range(auth5._sec("account_attempt_factor")):
    ci = TestClient(app5, client=(f"198.51.100.{10 + i}", 40000))
    for _ in range(G5):
        ci.post("/auth/resource/garten", data={"secret": "0000", "next": "/"})
spaet = TestClient(app5, client=("203.0.113.78", 40000))
r = spaet.post("/auth/resource/garten", data={"secret": "4711", "next": "/"}, follow_redirects=False)
assert r.status_code == 429, f"distributed guessing is unlimited: {r.status_code}"
ok("…distributed guessing over many addresses still locks the area")
os.remove(db5)

# Admin-API verwaltet Geheimnisse
admin = auth.store.get_user_by_name("admin")
# (no admin created in this test → check via manager)
auth.set_resource_secret("neu", "1234", kind="pin", label="Neu")
names = {r["name"] for r in auth.list_resource_secrets()}
assert {"fotos", "wiki", "neu"} <= names
auth.remove_resource_secret("neu")
assert "neu" not in {r["name"] for r in auth.list_resource_secrets()}
ok("manager/admin: create + delete secrets")

# F-01: session fixation of the unlock. The attacker plants a token on the victim that he
# knows (neighbour subdomain, plain-text HTTP); the victim unlocks the area. Before, the
# unlock afterwards hung on EXACTLY this token — the attacker was in too.
for _b in ("fotos", "wiki"):     # the lockout checks above locked the areas
    auth.store.clear_fails(username=f"res:{_b}", method="resource")
RC = auth.resource_cookie_name
cf = TestClient(app, client=("198.51.100.41", 50000))   # own address: the lockouts above stick to "testclient"


def mit(tok):
    """Cookie explicitly in the header — the client's jar would otherwise stay at the old value."""
    cf.cookies.clear()
    return {**JSON, "Cookie": f"{RC}={tok}"} if tok else dict(JSON)


def gesetzt(r):
    import re as _re
    m = _re.search(RC + r"=([^;]*)", ";".join(r.headers.get_list("set-cookie")))
    return m.group(1) if m else None


untergeschoben = "vom-angreifer-gewaehlt-0123456789abcdef"
r = cf.post("/auth/resource/fotos", data={"secret": "2468", "next": "/fotos"},
            headers=mit(untergeschoben), follow_redirects=False)
assert r.status_code == 303, (r.status_code, r.text[:200])
neu_tok = gesetzt(r)
assert neu_tok and neu_tok != untergeschoben, "the unlock must get a NEW token"
assert cf.get("/fotos", headers=mit(neu_tok)).status_code == 200, "the victim itself is in"
assert cf.get("/fotos", headers=mit(untergeschoben)).status_code == 401, \
    "the planted token is worthless"
ok("F-01: unlock issues a new token — a planted one is not unlocked")

# What the same browser already had open moves along — and does not stay on the old token.
r = cf.post("/auth/resource/wiki", data={"secret": "geheime passphrase", "next": "/wiki"},
            headers=mit(neu_tok), follow_redirects=False)
drittes = gesetzt(r)
assert drittes and drittes != neu_tok
assert cf.get("/fotos", headers=mit(drittes)).status_code == 200
assert cf.get("/wiki", headers=mit(drittes)).status_code == 200
assert cf.get("/fotos", headers=mit(neu_tok)).status_code == 401, "the previous token must be empty"
ok("…already open areas move to the new token, the old one holds nothing any more")

# F-08: logout also ends the unlocks of this browser — signing out on a shared machine
# so far left the locked area open for up to resource_unlock_ttl_hours.
r = cf.get("/auth/logout", headers=mit(drittes), follow_redirects=False)
assert r.status_code == 303
assert gesetzt(r) in ("", '""'), f"unlock cookie must be cleared: {gesetzt(r)!r}"
assert cf.get("/fotos", headers=mit(drittes)).status_code == 401, "unlock survives the logout"
assert cf.get("/wiki", headers=mit(drittes)).status_code == 401
ok("F-08: logout deletes the unlocks server-side and the unlock cookie in the browser")

os.remove(db)
print("\nRESOURCE-LOCK OK ✅")
