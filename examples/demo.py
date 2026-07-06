"""Minimal-Beispiel: TinySesam vor eine FastAPI-App hängen.

    pip install -e '.[all]'          # oder ohne extras: nur Passwort+TOTP
    uvicorn examples.demo:app --reload
    # → http://127.0.0.1:8000  (leitet zum Login; admin / geheim123)
"""
from fastapi import FastAPI, Depends
from fastapi.responses import HTMLResponse

from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="/tmp/tinysesam-demo.db",
    rp_name="Demo",
    password_enabled=True,
    passkey_enabled=False,     # für lokalen HTTP-Test aus; über HTTPS/echte Domain einschalten
    oidc_enabled=False,
    cookie_secure=False,       # lokal ohne HTTPS
))
auth.ensure_admin("admin", "geheim123")   # nur beim ersten Start

app = FastAPI()
app.include_router(auth.router())


@app.get("/", response_class=HTMLResponse)
def home(user=Depends(auth.require_user)):
    return (f"<h1>Hallo {user['username']}</h1>"
            f"<p><a href='/auth/totp/setup'>2FA einrichten</a> · <a href='/auth/logout'>Logout</a></p>")
