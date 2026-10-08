"""Zentrales Gateway mit Code-Austausch (T-26): Die Sitzung verlässt den Host des Gateways nie.

Ein App-Host bekommt über /.tinysesam/start → /auth/gate/authorize → /.tinysesam/callback nur ein
eigenes Verbindungs-Cookie (`__Host-tinysesam_link`), das ausschliesslich für ihn gilt. Geprüft mit zwei
TestClients auf zwei Hosts — wie zwei Herkünfte im Browser: Ein Cookie des einen erreicht den anderen nicht.
"""
import os
import tempfile
from urllib.parse import parse_qs, urlsplit

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import konfigpruefung


def ok(name):
    print(f"  ✓ {name}")


GW = "https://auth.example.com"
APP = "https://app.example.com"
WIKI = "https://wiki.example.com"
PW = "Gate-Link-Probe-17!"

auth = TinySesam(TinySesamConfig(
    csrf_enabled=False, lang="de", db_path=os.path.join(tempfile.mkdtemp(), "t.db"), rp_name="Gate",
    passkey_enabled=False, oidc_enabled=False, forward_auth_enabled=True, base_url=GW,
    trusted_redirect_hosts=["app.example.com", "wiki.example.com"], gate_token_enabled=True,
    gate_link_enabled=True, forward_apps={"app.example.com": {"name": "App", "login": "page"},
                                          "wiki.example.com": {"name": "Wiki"}}))

_fa_orig = auth._forward_app


def _wiki_direct():
    """Der Zweig „direct“ für wiki: Die Konfigurationsprüfung verlangt dafür OIDC als einzige Methode, diese Probe
    meldet sich aber per Passwort an — deshalb nur für die betreffenden Prüfungen umgebogen."""
    auth._forward_app = lambda h: {**_fa_orig(h), "login": "direct"} if "wiki" in str(h) else _fa_orig(h)
uid = auth.create_user("anna", PW)
fa = FastAPI()
fa.include_router(auth.router())


def browser():
    """Ein Browser: je Herkunft ein eigener Client (eigener Cookie-Speicher)."""
    return {"gw": TestClient(fa, base_url=GW), "app": TestClient(fa, base_url=APP),
            "wiki": TestClient(fa, base_url=WIKI)}


def forward(c, host="app.example.com", uri="/seite"):
    return c.get("/auth/forward", headers={"X-Forwarded-Proto": "https", "X-Forwarded-Host": host,
                                           "X-Forwarded-Uri": uri, "Sec-Fetch-Mode": "navigate"})


def ort(r):
    return r.headers.get("location") or r.headers.get("X-TinySesam-Location") or ""


def koppeln(b, rd="/seite", anmelden=True, gast="app"):
    """Der ganze Austausch für einen Browser. Rückgabe: (callback-Antwort, Code)."""
    s = b[gast].get(f"/.tinysesam/start?rd={rd}", follow_redirects=False)
    assert s.status_code == 303 and ort(s).startswith(GW + "/auth/gate/authorize?flow="), ort(s)
    a = b["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
    if a.status_code == 303 and urlsplit(ort(a)).path == "/auth/login" and anmelden:
        nxt = parse_qs(urlsplit(ort(a)).query)["next"][0]
        b["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": nxt}, follow_redirects=False)
        a = b["gw"].get(nxt, follow_redirects=False)
    assert a.status_code == 303 and "/.tinysesam/callback?code=" in ort(a), (a.status_code, ort(a))
    code = parse_qs(urlsplit(ort(a)).query)["code"][0]
    koppeln.bindung = b[gast].cookies.get("__Host-tinysesam_linkflow")
    return b[gast].get(f"/.tinysesam/callback?code={code}", follow_redirects=False), code


# ---------- der Weg ----------
b = browser()
r = forward(b["app"])
assert r.status_code == 401 and ort(r) == APP + "/.tinysesam/start?rd=%2Fseite", ort(r)
ok("App-Host ohne Verbindung → 401 auf SEINEN /.tinysesam/start (nicht auf die Login-Seite)")

s = b["app"].get("/.tinysesam/start?rd=/seite", follow_redirects=False)
assert any(v.startswith("__Host-tinysesam_linkflow=") for v in s.headers.get_list("set-cookie"))
a = b["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
assert a.status_code == 303 and urlsplit(ort(a)).path == "/auth/login", ort(a)
seite = b["gw"].get(urlsplit(ort(a)).path + "?" + urlsplit(ort(a)).query)
assert "Anmelden bei App" in seite.text, seite.text[:300]
assert "Anmelden bei" not in b["gw"].get("/auth/login?next=/&gate_host=evil.example.net").text
ok("Gateway ohne Sitzung → Login „Anmelden bei App“, der Ablauf wartet (fremder gate_host → kein Name)")

cb, code = koppeln(b)
assert cb.status_code == 303 and ort(cb) == "/seite", (cb.status_code, ort(cb))
link = [v for v in cb.headers.get_list("set-cookie") if v.startswith("__Host-tinysesam_link=")]
assert link and "Secure" in link[0] and "HttpOnly" in link[0] and "Domain" not in link[0], link
ok("Callback → zurück zu rd, Verbindungs-Cookie __Host- (Secure, HttpOnly, ohne Domain)")

r = forward(b["app"])
assert r.status_code == 200 and r.headers["Remote-User"] == "anna", (r.status_code, dict(r.headers))
assert "X-TinySesam-Gate-Cookie" in r.headers
ok("mit Verbindung → 200, Remote-User, Gate-Token")

assert auth.session_cookie_name not in b["app"].cookies and auth.session_cookie_name in b["gw"].cookies
ok("die Sitzung liegt nur beim Gateway — der App-Host hat sie nie gesehen")

# ---------- Angriffe ----------
roh = b["app"].cookies.get("__Host-tinysesam_link")
fremd = TestClient(fa, base_url=WIKI)
fremd.cookies.set("__Host-tinysesam_link", roh)
assert forward(fremd, host="wiki.example.com").status_code == 401
ok("die Verbindung von app gilt nicht für wiki (an den Host gebunden)")

# Mit derselben Bindung wie beim ersten Mal — sonst schiede der zweite Versuch schon an der fehlenden
# Bindung und nicht am verbrauchten Code (Mutationsprobe: Code nach dem Einlösen zurücklegen → rot).
nochmal = TestClient(fa, base_url=APP)
nochmal.cookies.set("__Host-tinysesam_linkflow", koppeln.bindung)
assert nochmal.get(f"/.tinysesam/callback?code={code}", follow_redirects=False).status_code == 400
ok("ein Code gilt genau einmal (auch mit der passenden Bindung)")

b2 = browser()
b2["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": "/"}, follow_redirects=False)
s = b2["app"].get("/.tinysesam/start?rd=/x", follow_redirects=False)
a = b2["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
code2 = parse_qs(urlsplit(ort(a)).query)["code"][0]
opfer = TestClient(fa, base_url=APP)       # ein anderer Browser, ohne Bindungs-Cookie
assert opfer.get(f"/.tinysesam/callback?code={code2}", follow_redirects=False).status_code == 400
ok("ein fremder Code im Browser eines anderen (ohne Bindung) → 400, keine Verbindung")

b3 = browser()
b3["gw"].post("/auth/login", data={"username": "anna", "password": PW, "next": "/"}, follow_redirects=False)
s = b3["app"].get("/.tinysesam/start?rd=/x", follow_redirects=False)
a = b3["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
code3 = parse_qs(urlsplit(ort(a)).query)["code"][0]
b3["wiki"].cookies.set("__Host-tinysesam_linkflow", b3["app"].cookies.get("__Host-tinysesam_linkflow"))
assert b3["wiki"].get(f"/.tinysesam/callback?code={code3}", follow_redirects=False).status_code == 400
ok("ein Code für app, eingelöst an wiki → 400")

for boese in ("//evil.example/x", "https://evil.example/", "\\\\evil", "evil"):
    s = browser()["app"].get("/.tinysesam/start", params={"rd": boese}, follow_redirects=False)
    flow = parse_qs(urlsplit(ort(s)).query)["flow"][0]
    assert auth.store.pop_flow("gatelink:" + flow)["rd"] == "/", boese
ok("rd nimmt nur Pfade dieses Hosts (//, fremde Adresse, Backslash → /)")

assert TestClient(fa, base_url=GW).get("/auth/gate/authorize?flow=erfunden").status_code == 400
assert TestClient(fa, base_url="https://fremd.example.net").get("/.tinysesam/start").status_code == 404
ok("unbekannter Ablauf → 400, ungeschützter Host → 404")

# ---------- die Sitzung wird gedreht, die Verbindung zieht mit ----------
h = auth.store.session_hash(b["gw"].cookies.get(auth.session_cookie_name))
neu = auth.store.rotate_session(h)
b["gw"].cookies.set(auth.session_cookie_name, neu)
assert forward(b["app"]).status_code == 200
ok("Sitzung gedreht (Step-up) — die Verbindung des App-Hosts gilt weiter")

# ---------- nur hier abmelden ----------
r = b["app"].get("/.tinysesam/logout?scope=app", follow_redirects=False)
assert r.status_code == 303
assert any(v.startswith("__Host-tinysesam_link=;") or v.startswith("__Host-tinysesam_link=; ")
           for v in r.headers.get_list("set-cookie")), r.headers.get_list("set-cookie")
b["app"].cookies.delete("__Host-tinysesam_link")
assert forward(b["app"]).status_code == 401
s = b["app"].get("/.tinysesam/start?rd=/seite", follow_redirects=False)
a = b["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
assert a.status_code == 200 and "Weiter als anna" in a.text and "name=gate_host value='app.example.com'" in a.text, a.status_code
ok("nur hier abgemeldet: Verbindung weg; der neue Austausch zeigt „Weiter als anna“ statt still zu koppeln")

nxt = "/auth/gate/authorize?flow=" + parse_qs(urlsplit(ort(s)).query)["flow"][0]
r = b["gw"].post("/auth/gate/resume", data={"next": nxt, "gate_host": "app.example.com"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == nxt
a = b["gw"].get(nxt, follow_redirects=False)
assert "/.tinysesam/callback?code=" in ort(a)
ok("„Weiter als …“ hebt die Abmeldung für app auf, der Austausch läuft weiter")

# ---------- überall abmelden vom App-Host ----------
b4 = browser()
koppeln(b4)
assert forward(b4["app"]).status_code == 200
r = b4["app"].get("/.tinysesam/logout?scope=all", follow_redirects=False)
assert r.status_code == 303
assert b4["gw"].get("/auth/me").status_code == 401, "die Sitzung beim Gateway muss enden"
assert forward(b4["app"]).status_code == 401
ok("überall abmelden am App-Host beendet die Sitzung beim Gateway — und damit jede Verbindung")

# ---------- erst nur hier, dann überall abmelden: die Sitzung beim Gateway darf nicht übrig bleiben ----------
b5 = browser()
koppeln(b5)
b5["app"].get("/.tinysesam/logout?scope=app", follow_redirects=False)
b5["app"].cookies.delete("__Host-tinysesam_link")
r = b5["app"].get("/.tinysesam/logout?scope=all", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == GW + "/auth/gate/logout?host=app.example.com", r.headers.get("location")
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", headers={"Sec-Fetch-Site": "cross-site"}, follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == APP + "/.tinysesam/logout", r.headers.get("location")
assert b5["gw"].get("/auth/me").status_code == 200, "cross-site darf die Sitzung nicht beenden (Logout-CSRF)"
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", headers={"Sec-Fetch-Site": "same-site"}, follow_redirects=False)
assert r.status_code == 303 and b5["gw"].get("/auth/me").status_code == 401, (r.status_code, r.headers.get("location"))
r = b5["gw"].get("/auth/gate/logout?host=app.example.com", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/auth/gate/logged-out?host=app.example.com", r.headers.get("location")
r = b5["gw"].get("/auth/gate/logged-out?host=app.example.com", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == APP + "/.tinysesam/start?rd=%2F&abgemeldet=1", r.headers.get("location")
_wiki_direct()
r = b5["gw"].get("/auth/gate/logged-out?host=wiki.example.com")
auth._forward_app = _fa_orig
assert r.status_code == 200 and "href='https://wiki.example.com/'" in r.text, r.text[-400:]
assert b5["gw"].get("/auth/gate/logged-out?host=evil.example.net").status_code == 400
assert b5["gw"].get("/auth/gate/logout?host=evil.example.net").status_code == 400
ok("überall abmelden ohne Verbindung → ans Gateway, dort endet die Sitzung (cross-site erst Rückfrage, keine Schleife); ohne Sitzung „Abgemeldet“ beim Gateway mit Weg zur App")

# ---------- nach dem Abmelden: Anmeldeseite mit Hinweis statt Zwischenseite (Modus page, PO 2026-10-08) ----------
b6 = browser()
r = b6["app"].get("/.tinysesam/after-logout", follow_redirects=False)
assert r.status_code == 303 and r.headers["location"] == "/.tinysesam/start?rd=%2F&abgemeldet=1", (r.status_code, r.headers.get("location"))
s = b6["app"].get("/.tinysesam/start?rd=%2F&abgemeldet=1", follow_redirects=False)
a = b6["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
assert a.status_code == 303 and "abgemeldet=1" in ort(a), ort(a)
seite = b6["gw"].get(urlsplit(ort(a)).path + "?" + urlsplit(ort(a)).query)
assert "Du wurdest abgemeldet." in seite.text and "Anmelden bei App" in seite.text, seite.text[:400]
s = b6["app"].get("/.tinysesam/start?rd=%2F", follow_redirects=False)
a = b6["gw"].get(urlsplit(ort(s)).path + "?" + urlsplit(ort(s)).query, follow_redirects=False)
assert "abgemeldet" not in ort(a) and "abgemeldet" not in b6["gw"].get(urlsplit(ort(a)).path + "?" + urlsplit(ort(a)).query).text.lower()
assert "abgemeldet" not in b6["gw"].get("/auth/login?next=/&abgemeldet=0").text.lower()
_wiki_direct()
w = TestClient(fa, base_url=WIKI).get("/.tinysesam/after-logout")
auth._forward_app = _fa_orig
assert w.status_code == 200 and "Abgemeldet" in w.text, w.status_code
ok("nach dem Abmelden: Anmeldeseite „Anmelden bei App“ mit „Du wurdest abgemeldet.“ (page); Modus direct behält die Seite")

# ---------- Konfigurationsprüfung ----------
try:
    TinySesam(TinySesamConfig(db_path=":memory:", forward_auth_enabled=True, gate_token_enabled=True,
                              gate_link_enabled=True, base_url=GW, cookie_domain=".example.com"))
except ConfigError as e:
    assert "cookie_domain" in str(e)
else:
    raise AssertionError("Link-Modus mit cookie_domain startet")
assert any("gate_token_enabled" in f for f in konfigpruefung.pruefe(TinySesamConfig(
    db_path=":memory:", forward_auth_enabled=True, gate_link_enabled=True, base_url=GW))[0])
ok("Konfigurationsprüfung: Link-Modus nicht mit cookie_domain, nicht ohne Gate-Token")

print("Gate-Link OK")
