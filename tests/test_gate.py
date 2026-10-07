"""Gate-Token (ADR-9, T-19): Ausstellen in /auth/forward, Zielgruppe, Claims, Schlüssel, Prüfung.

Der Weg durch einen echten Caddy mit caddy-jwt steht in `tests/test_gate_caddy.py`. Hier geht es
um die Seite von TinySesam: wann ein Token entsteht, was darin steht, und dass ein Prüfer, der es
so prüft wie der Proxy, jede Verfälschung ablehnt.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import time

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig, ConfigError
from tinysesam import gate, konfigpruefung


def ok(name):
    print(f"  ✓ {name}")


ISS = "https://auth.example.com"
PROXY = {"X-Forwarded-Proto": "https", "X-Forwarded-Host": "app.example.com", "X-Forwarded-Uri": "/x"}


def instanz(**extra):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    werte = dict(csrf_enabled=False, lang="de", db_path=db, rp_name="Test", passkey_enabled=False,
                 oidc_enabled=False, cookie_secure=False, forward_auth_enabled=True, base_url=ISS,
                 trusted_redirect_hosts=["app.example.com"], gate_token_enabled=True)
    werte.update(extra)
    auth = TinySesam(TinySesamConfig(**werte))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def token_aus(r):
    kopf = r.headers.get("X-TinySesam-Gate-Cookie")
    if not kopf:
        return None, None
    name, rest = kopf.split("=", 1)
    return name, rest.split(";", 1)[0]


def anmelden(app, name="anna", pw="geheim123"):
    c = TestClient(app)
    r = c.post("/auth/login", data={"username": name, "password": pw, "next": "/"}, follow_redirects=False)
    assert r.status_code in (302, 303), r.status_code
    return c


auth, app = instanz()
auth.ensure_admin("admin", "geheim123")
uid = auth.create_user("anna", "geheim123", roles=["redaktion"])
auth.store._exec("UPDATE users SET email=?, display_name=? WHERE id=?",
                 ("anna@example.com", "Anna Berg", uid))
PUB = base64.b64decode(auth.gate_public_key())
assert len(PUB) == 32


def pruefe(tok, aud="app.example.com", jetzt=None):
    return gate.pruefen(PUB, tok, aud=aud, iss=ISS, jetzt=int(time.time()) if jetzt is None else jetzt)


# ---------- Ausstellen ----------
c = anmelden(app)
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200
name, tok = token_aus(r)
assert name == "__Host-tinysesam_gate", name
kopf = r.headers["X-TinySesam-Gate-Cookie"]
for teil in ("Path=/", "Max-Age=300", "Secure", "HttpOnly", "SameSite=Lax"):
    assert teil in kopf, (teil, kopf)
assert "domain" not in kopf.lower(), kopf
inhalt = pruefe(tok)
assert inhalt, "das frische Token besteht die Prüfung nicht"
assert inhalt["sub"] == str(uid) and inhalt["ts_user"] == "anna" and inhalt["ts_id"] == str(uid)
assert inhalt["ts_name"] == "Anna Berg" and inhalt["ts_email"] == "anna@example.com"
assert inhalt["ts_groups"] == "redaktion"
assert inhalt["exp"] - inhalt["iat"] == 300 and inhalt["nbf"] == inhalt["iat"]
ok("Sitzung → 200 mit Gate-Cookie (__Host-, Secure, HttpOnly, ohne Domain); Claims = Forward-Header")

# Dieselbe Identität auf beiden Wegen: was die Header sagen, sagen die Claims.
assert r.headers["Remote-User"] == inhalt["ts_user"]
assert r.headers["Remote-Id"] == inhalt["ts_id"]
ok("Header und Claims nennen dieselbe Identität")

# Kein Token für einen Host, den diese Installation nicht schützt.
r = c.get("/auth/forward", headers={**PROXY, "X-Forwarded-Host": "fremd.example.net"})
assert token_aus(r) == (None, None)
ok("fremder Host → kein Gate-Token")

# Kein Token ohne Anmeldung.
r = TestClient(app).get("/auth/forward", headers=PROXY)
assert r.status_code == 401 and token_aus(r) == (None, None)
ok("ohne Anmeldung → 401, kein Gate-Token")

# Kein Token für einen API-Key: Ein Automat hält kein Cookie, und eines aus einem Key überlebte
# im Browser dessen Widerruf.
key = auth.create_api_key(uid, name="k")["key"]
r = TestClient(app).get("/auth/forward", headers={**PROXY, "Authorization": f"Bearer {key}"})
assert r.status_code == 200 and token_aus(r) == (None, None)
ok("API-Key → 200, aber kein Gate-Token")

# Fehlende Rolle → 403, kein Token.
r = c.get("/auth/forward?roles=chef", headers=PROXY)
assert r.status_code == 403 and token_aus(r) == (None, None)
ok("Rolle fehlt → 403, kein Gate-Token")

# ---------- Zielgruppe mit Rollen ----------
r = c.get("/auth/forward?roles=redaktion,chef", headers=PROXY)
_, tok_r = token_aus(r)
assert pruefe(tok_r) is None, "ein Token aus einer Prüfung MIT Rollen gilt am Pfad ohne Rollen"
assert pruefe(tok_r, aud="app.example.com|roles=chef,redaktion")
ok("Rollen stehen in der Zielgruppe (kanonisch sortiert)")

# Umgekehrt der eigentliche Angriff: Ein Token ohne Rollenangabe darf an einem Pfad mit Rollen
# nicht gelten — der Proxy sieht nur die Zielgruppe.
assert pruefe(tok, aud="app.example.com|roles=redaktion") is None
ok("Token ohne Rollenangabe gilt nicht an einem Pfad mit Rollen")

assert gate.zielgruppe("App.Example.com.", [["b", "a", "a"], ["c"], []]) == "app.example.com|roles=a,b;c"
assert gate.zielgruppe("app.example.com", [["c"], ["a", "b"]]) == gate.zielgruppe("app.example.com", [["b", "a"], ["c"]])
ok("zielgruppe(): gross/klein, Punkt am Ende, Dubletten und Reihenfolge ändern nichts")

# ---------- Prüfung wie am Proxy: jede Verfälschung fällt ----------
k, i, s = tok.split(".")
jetzt = int(time.time())


def neu_signiert(inhalt_neu, kopf_neu=None, schluessel=None):
    kk = gate._b64u(json.dumps(kopf_neu or {"alg": "EdDSA", "typ": "JWT"}).encode())
    ii = gate._b64u(json.dumps(inhalt_neu).encode())
    sig = (schluessel or auth._gate_schluessel).sign(f"{kk}.{ii}".encode())
    return f"{kk}.{ii}.{gate._b64u(sig)}"


basis = json.loads(gate._b64u_lesen(i))
fremd = gate.schluessel_ableiten(b"\x00" * 32)
faelle = {
    # Ein BYTE der Signatur kippen, nicht die letzten Zeichen ersetzen: Die letzten Base64-Zeichen
    # tragen Füllbits, und `…AA` statt `…AB` ist mitunter dieselbe Signatur (1 in 256 Läufen).
    "Signatur verändert": f"{k}.{i}." + gate._b64u(bytes([gate._b64u_lesen(s)[0] ^ 1]) + gate._b64u_lesen(s)[1:]),
    "Inhalt verändert (anderes Konto)": f"{k}.{gate._b64u(json.dumps({**basis, 'sub': '1'}).encode())}.{s}",
    "alg none": f"{gate._b64u(json.dumps({'alg': 'none'}).encode())}.{i}.",
    "alg HS256": f"{gate._b64u(json.dumps({'alg': 'HS256'}).encode())}.{i}.{s}",
    # Gültig signiert, aber der Kopf nennt einen anderen Algorithmus: Nur der Vergleich mit
    # `EdDSA` fängt das — die Signatur selbst stimmt.
    "alg HS256, gültig signiert": neu_signiert(basis, kopf_neu={"alg": "HS256", "typ": "JWT"}),
    "fremder Schlüssel": neu_signiert(basis, schluessel=fremd),
    "abgelaufen": neu_signiert({**basis, "exp": jetzt - 1}),
    "noch nicht gültig": neu_signiert({**basis, "nbf": jetzt + 60}),
    "anderer Aussteller": neu_signiert({**basis, "iss": "https://evil.example"}),
    "andere Zielgruppe": neu_signiert({**basis, "aud": "wiki.example.com"}),
    "kein Token": "",
    "Unsinn": "a.b.c",
}
for was, falsch in faelle.items():
    assert pruefe(falsch) is None, was
assert pruefe(neu_signiert(basis)), "die Gegenprobe (unverändert neu signiert) muss bestehen"
ok(f"Prüfung lehnt {len(faelle)} Verfälschungen ab, die unveränderte Gegenprobe besteht")

# Unabhängige Gegenprobe: eine fremde JOSE-Implementierung (authlib, Extra [oidc]) liest das Token
# genauso. Fehlt sie, entfällt nur dieser Teil — die Suite prüft das Format sonst selbst.
try:
    from authlib.jose import JsonWebToken, OKPKey
except ImportError:
    print("  – authlib fehlt: Gegenprobe mit fremder JOSE-Implementierung entfällt")
else:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    claims = JsonWebToken(["EdDSA"]).decode(tok, OKPKey.import_key(Ed25519PublicKey.from_public_bytes(PUB)))
    claims.validate()
    assert claims["ts_user"] == "anna" and claims["aud"] == "app.example.com"
    ok("authlib (fremde JOSE-Implementierung) prüft das Token und liest dieselben Claims")

# ---------- Claims folgen forward_headers ----------
auth2, app2 = instanz(forward_headers={"user": "X-WEBAUTH-USER"})
auth2.create_user("bea", "geheim123")
r = anmelden(app2, "bea").get("/auth/forward", headers=PROXY)
_, t2 = token_aus(r)
inh2 = gate.pruefen(base64.b64decode(auth2.gate_public_key()), t2, aud="app.example.com", iss=ISS,
                    jetzt=int(time.time()))
assert {k for k in inh2 if k.startswith("ts_")} == {"ts_user"}, inh2
ok("forward_headers ist die vollständige Liste — auch für die Claims (keine Adresse, wenn sie fehlt)")

# Namen jenseits von ASCII und mit Steuerzeichen (kommen bei OIDC/SAML vom fremden IdP). Direkt
# an `_gate_cookie`: Der TestClient (httpx) lehnt Header ausserhalb von ASCII ab und könnte die
# Antwort mit `Remote-Name` gar nicht lesen — der Weg über die Leitung steht in test_gate_caddy.py.
from starlette.requests import Request  # noqa: E402


def gate_direkt():
    sitzung = c.cookies.get(auth.session_cookie_name)
    scope = {"type": "http", "method": "GET", "path": "/auth/forward", "query_string": b"",
             "headers": [(b"cookie", f"{auth.session_cookie_name}={sitzung}".encode())],
             "client": ("127.0.0.1", 1), "server": ("testserver", 80), "scheme": "http"}
    kopf = auth._gate_cookie(Request(scope), auth._als_dict(auth.store.get_user(uid)),
                             "https://app.example.com/x", [])
    return pruefe(kopf.split(";", 1)[0].split("=", 1)[1])


for roh, soll in (("Anna Ärger", "Anna Ärger"), ("Иван", "Иван"),
                  ("Anna\r\nRemote-User: admin", "AnnaRemote-User: admin"), ("A\x7fB\x01", "AB")):
    auth.store._exec("UPDATE users SET display_name=? WHERE id=?", (roh, uid))
    assert gate_direkt()["ts_name"] == soll, (roh, gate_direkt()["ts_name"])
auth.store._exec("UPDATE users SET display_name=? WHERE id=?", ("Anna Berg", uid))
ok("Claims: Umlaute und Kyrillisch unverändert (UTF-8), Steuerzeichen fallen heraus")

# ---------- Ausgeschaltet ----------
auth.cfg.gate_token_enabled = False
r = c.get("/auth/forward", headers=PROXY)
assert r.status_code == 200 and token_aus(r) == (None, None)
auth.cfg.gate_token_enabled = True
ok("gate_token_enabled=False → /auth/forward wie bisher, ohne Gate-Token")

# ---------- Schlüssel ----------
# Derselbe Grundschlüssel → derselbe Signaturschlüssel (alle Worker, jeder Neustart); ein anderer
# → ein anderer. Der Proxy-Schlüssel ändert sich also genau dann, wenn der Grundschlüssel wechselt.
alt = os.environ.get("TINYSESAM_SECRETS_KEY")
try:
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x07" * 32).decode()
    a1, _ = instanz()
    a2, _ = instanz()
    os.environ["TINYSESAM_SECRETS_KEY"] = base64.b64encode(b"\x08" * 32).decode()
    a3, _ = instanz()
finally:
    if alt is None:
        os.environ.pop("TINYSESAM_SECRETS_KEY", None)
    else:
        os.environ["TINYSESAM_SECRETS_KEY"] = alt
assert a1.gate_public_key() == a2.gate_public_key() != a3.gate_public_key()
ok("Signaturschlüssel folgt dem Grundschlüssel: gleich bei gleichem, anders bei anderem")

# Der Signaturschlüssel ist abgeleitet, nicht der Grundschlüssel selbst: Wer ihn kennt (etwa aus
# einem Speicherabzug des Signierens), kennt damit nicht den Schlüssel der TOTP-Geheimnisse.
g = b"\x07" * 32
from cryptography.hazmat.primitives import serialization  # noqa: E402
saat = gate.schluessel_ableiten(g).private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                                 serialization.NoEncryption())
assert saat != g and len(saat) == 32
ok("Signaturschlüssel ist abgeleitet (HKDF mit eigenem Kontext), nicht der Grundschlüssel")

# ---------- CLI: tinysesam gate-key ----------
db = auth.cfg.db_path
umg = {**os.environ, "PYTHONPATH": os.pathsep.join(sys.path)}
umg.pop("TINYSESAM_SECRETS_KEY", None)
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", db],
                   capture_output=True, text=True, env=umg, timeout=60)
assert r.returncode == 0, r.stderr
assert r.stdout.strip() == auth.gate_public_key()
ok("`tinysesam gate-key` gibt denselben öffentlichen Schlüssel aus wie der Dienst")

leer = os.path.join(tempfile.mkdtemp(), "x.db")
r = subprocess.run([sys.executable, "-m", "tinysesam", "gate-key", "--db", leer],
                   capture_output=True, text=True, env=umg, timeout=60)
assert r.returncode == 1 and not os.path.exists(leer + ".key"), (r.returncode, r.stderr)
ok("`gate-key` ohne Grundschlüssel: Fehler, und es legt KEINEN neuen an")

# ---------- Konfigurationsprüfung ----------
def befunde(**extra):
    werte = dict(db_path=":memory:", forward_auth_enabled=True, gate_token_enabled=True)
    werte.update(extra)
    return konfigpruefung.pruefe(TinySesamConfig(**werte))[0]


assert not [b for b in befunde() if "gate" in b]
assert any("forward_auth_enabled" in b for b in befunde(forward_auth_enabled=False))
for name in ("tinysesam_gate", "__Secure-tinysesam_gate", "__Host-gate", "__Host-tinysesam_", "__Host-tinysesam_a;b"):
    assert any("gate_cookie_name" in b for b in befunde(gate_cookie_name=name)), name
for ttl in (29, 3601, True):
    assert any("gate_token_ttl_sec" in b for b in befunde(gate_token_ttl_sec=ttl)), ttl
assert not [b for b in befunde(gate_token_ttl_sec=30) + befunde(gate_token_ttl_sec=3600) if "gate" in b]
try:
    TinySesamConfig(db_path=":memory:", gate_token_enabled=True)
    TinySesam(TinySesamConfig(db_path=":memory:", gate_token_enabled=True))
except ConfigError as e:
    assert "forward_auth_enabled" in str(e)
else:
    raise AssertionError("gate_token_enabled ohne forward_auth_enabled startet")
ok("Konfigurationsprüfung: ohne forward_auth, falscher Cookie-Name, Laufzeit ausserhalb 30–3600")

# ---------- Vorlage: der Proxy setzt die Identität, nicht der Browser ----------
# Jeder Header, den TinySesam als Identität schickt, wird in der Vorlage zuerst aus der Anfrage
# entfernt. Im Verhalten ist das unsichtbar, solange beide Wege ihn danach setzen — es ist die
# Absicherung für den Tag, an dem jemand eine `header_up`-Zeile streicht oder ein Feld aus
# forward_headers nimmt. Deshalb hier als Wächter über die Datei, nicht als Probe.
import pathlib  # noqa: E402
import re  # noqa: E402
vorlage = (pathlib.Path(__file__).resolve().parent.parent / "deploy/forward-auth/Caddyfile.gate").read_text(encoding="utf-8")
code = "\n".join(z.split("#", 1)[0] for z in vorlage.splitlines())
site = code[code.index("app.example.com {"):]
for kopfname in TinySesam.FORWARD_HEADERS_DEFAULT.values():
    assert re.search(rf"^\trequest_header -{kopfname}\s*$", site, re.M), f"Vorlage entfernt {kopfname} nicht"
    assert re.search(rf"header_up {kopfname} \{{http\.auth\.user\.ts_", site), f"schneller Weg setzt {kopfname} nicht"
    assert f"request_header {kopfname} {{rp.header.{kopfname}}}" in site, f"Rückweg setzt {kopfname} nicht"
assert site.index("request_header -Remote-User") < site.index("route {"), "Entfernen erst nach dem Weiterleiten"
assert re.search(r"^\t\t\tsign_alg EdDSA\s*$", site, re.M), "jwtauth ohne festen Algorithmus"
assert "from_cookies __Host-tinysesam_gate" in site
ok("Vorlage: jeder Remote-*-Header wird erst entfernt, dann auf beiden Wegen gesetzt; sign_alg fest")

print("Gate-Token OK")
