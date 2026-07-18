"""CSP: nonce-basierte Content-Security-Policy für die eingebauten Seiten.

Beweist die Zusage der Bibliothek: jede eingebaute Seite (Login/Account/TOTP/Fehler)
läuft unter einer strengen, nonce-basierten CSP — kein 'unsafe-inline'. Der zugehörige
Browser-Beweis (Chrome blockt bei falschem Nonce) steht in test_browser.py.
"""
import re
import tempfile
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


_TAG = re.compile(r'<(script|style)\b')


def _cfg(**kw):
    return TinySesamConfig(db_path=tempfile.mktemp(suffix=".db"), csrf_enabled=False,
                           cookie_secure=False, pin_enabled=True, apikey_enabled=True, **kw)


def _pages(auth):
    return {
        "login": auth.render_page("login", request=None, next="/"),
        "account": auth.render_page("account", request=None,
                                    user={"username": "u", "display_name": "U", "id": 1},
                                    methods=["password", "pin", "passkey"]),
        "totp": auth.render_page("totp", request=None, next="/"),
        "error": auth.render_page("error", request=None, code=404, message="x"),
    }


def _nonce(resp):
    m = re.search(r"'nonce-([\w-]+)'", resp.headers.get("content-security-policy", ""))
    return m.group(1) if m else None


# 1) Default 'strict': Header da, jedes <script>/<style> genonced, kein Inline-Handler/style=
auth = TinySesam(_cfg())
for name, resp in _pages(auth).items():
    csp = resp.headers.get("content-security-policy", "")
    assert csp.startswith("default-src 'self'"), f"{name}: keine strenge CSP: {csp!r}"
    assert "'unsafe-inline'" not in csp, f"{name}: CSP enthält unsafe-inline"
    n = _nonce(resp)
    assert n, f"{name}: kein Nonce in der CSP"
    body = resp.body.decode()
    tags = len(_TAG.findall(body))
    nonced = len(re.findall(rf'<(?:script|style) nonce="{re.escape(n)}"', body))
    assert tags and tags == nonced, f"{name}: {nonced}/{tags} script/style genonced"
    assert not re.search(r'\son(click|submit)=', body), f"{name}: Inline-Handler geblieben"
    assert not re.search(r'\sstyle=', body), f"{name}: style=-Attribut geblieben"
ok("strict: Header + Nonce auf jedem <script>/<style>, keine Inline-Handler/style=")

# 2) Pro Antwort ein frischer Nonce
n1, n2 = _nonce(auth.render_page("login", request=None)), _nonce(auth.render_page("login", request=None))
assert n1 and n2 and n1 != n2, "Nonce nicht pro Antwort frisch"
ok("Nonce pro Antwort frisch")

# 3) csp='off' → kein Header (z.B. wenn ein Proxy die CSP zentral setzt)
assert not TinySesam(_cfg(csp="off")).render_page("login", request=None) \
    .headers.get("content-security-policy")
ok("csp='off' → kein Header")

# 4) Eigene Policy: {nonce} wird ersetzt, der Rest 1:1
cust = TinySesam(_cfg(csp="default-src 'self'; script-src 'nonce-{nonce}' https://cdn.example"))
csp = cust.render_page("login", request=None).headers["content-security-policy"]
assert "{nonce}" not in csp and "https://cdn.example" in csp and "nonce-" in csp, csp
ok("eigene Policy: {nonce} ersetzt, Rest 1:1")

# 5) Ungültige csp (kein String) → klare Ablehnung beim Bau
try:
    TinySesam(_cfg(csp=123))
    assert False, "csp=123 haette scheitern muessen"
except ValueError:
    ok("csp muss ein String sein (Bau lehnt ab)")

# 6) Echter HTTP-Pfad: der Header steht auf der GET /auth/login-Antwort
app = FastAPI()
app.include_router(auth.router())
r = TestClient(app).get("/auth/login")
assert r.headers.get("content-security-policy", "").startswith("default-src 'self'")
ok("HTTP GET /auth/login trägt den CSP-Header")

print("\ntest_csp: alle Checks grün")
