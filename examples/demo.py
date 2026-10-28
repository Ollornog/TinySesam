"""Minimal example: put TinySesam in front of a FastAPI app.

    pip install -e '.[all]'          # or without extras: password + TOTP only
    uvicorn examples.demo:app --reload
    # → http://127.0.0.1:8000  (leitet zum Login; admin / geheim123)
"""
from html import escape

from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="/tmp/tinysesam-demo.db",
    rp_name="Demo",
    password_enabled=True,
    passkey_enabled=False,     # off for a local HTTP test; enable over HTTPS / a real domain
    oidc_enabled=False,
    cookie_secure=False,       # local, without HTTPS
))
auth.ensure_admin("admin", "geheim123")   # only on first start

app = FastAPI()
app.include_router(auth.router())


@app.get("/", response_class=HTMLResponse)
def home(user=Depends(auth.require_user)):
    # `escape()`: a username is a free text field — TinySesam deliberately does not filter it,
    # but expects the app to escape on OUTPUT. Without that, an account named
    # `<script>…</script>` is stored XSS, and this example gets copied.
    return (f"<h1>Hallo {escape(user['username'])}</h1>"
            f"<p><a href='/auth/totp/setup'>2FA einrichten</a> · <a href='/auth/logout'>Logout</a></p>")
