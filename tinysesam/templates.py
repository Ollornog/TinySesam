"""Minimale, eigenständige Login-Views (dark/light). Überschreibbar: eigene Seiten rendern
und TinySesam nur als Backend (check_password/start_session/…) nutzen."""
from __future__ import annotations
import html
from fastapi.responses import HTMLResponse

_CSS = """
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;
     background:#0f1115;color:#e6e6e6}
.card{width:340px;max-width:92vw;background:#161a22;border:1px solid #262b36;border-radius:14px;padding:26px}
h1{font-size:20px;margin:0 0 18px;text-align:center}
label{display:block;font-size:12px;color:#9aa4b2;margin:12px 0 4px}
input{width:100%;background:#0f1115;color:#e6e6e6;border:1px solid #303643;border-radius:8px;padding:10px 12px;font-size:15px}
button,.btn2{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;font-size:15px;cursor:pointer;
     background:#2563eb;color:#fff;display:block;text-align:center;text-decoration:none}
.btn2{background:#374151;margin-top:10px}
.err{background:#3a1520;color:#f87171;padding:9px 12px;border-radius:8px;font-size:13px;margin-bottom:6px}
.or{text-align:center;color:#6b7280;font-size:12px;margin:16px 0 4px}
.hint{color:#9aa4b2;font-size:12px;text-align:center;margin-top:14px}
.code{width:100%;text-align:center;letter-spacing:.4em;font-size:22px}
img.qr{display:block;margin:14px auto;width:190px;height:190px;background:#fff;border-radius:8px;padding:6px}
.mono{font-family:ui-monospace,monospace;background:#0f1115;border:1px solid #303643;border-radius:6px;padding:6px 8px;
      font-size:13px;text-align:center;word-break:break-all}
"""


def _shell(title, body):
    return (f"<!doctype html><html lang=de><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body><div class=card>{body}</div></body></html>")


def login_page(auth, next_, error="", status=200):
    cfg = auth.cfg
    methods = cfg.enabled_methods()
    err = f"<div class=err>{html.escape(error)}</div>" if error else ""
    pw = ""
    if "password" in methods:
        pw = (f"<form method=post action='/auth/login'>"
              f"<input type=hidden name=next value='{html.escape(next_)}'>"
              f"<label>Benutzer</label><input name=username autofocus autocomplete=username>"
              f"<label>Passwort</label><input name=password type=password autocomplete=current-password>"
              f"<button type=submit>Anmelden</button></form>")
    oidc = (f"<a class=btn2 href='/auth/oidc/start?next={html.escape(next_)}'>{html.escape(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    passkey = "<button class=btn2 type=button id=pkbtn>🔑 Mit Passkey anmelden</button>" if "passkey" in methods else ""
    sep = "<div class=or>oder</div>" if (oidc or passkey) and pw else ""
    js = _PASSKEY_LOGIN_JS.replace("__NEXT__", html.escape(next_)) if "passkey" in methods else ""
    body = f"<h1>{html.escape(cfg.rp_name)}</h1>{err}{pw}{sep}{oidc}{passkey}{js}"
    return HTMLResponse(_shell("Anmelden", body), status_code=status)


def totp_page(auth, next_, error="", status=200):
    err = f"<div class=err>{html.escape(error)}</div>" if error else ""
    body = (f"<h1>Bestätigung</h1>{err}"
            f"<form method=post action='/auth/totp'>"
            f"<input type=hidden name=next value='{html.escape(next_)}'>"
            f"<label>6-stelliger Code aus deiner Authenticator-App</label>"
            f"<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>"
            f"<button type=submit>Weiter</button></form>"
            f"<div class=hint><a href='/auth/logout' style='color:#9aa4b2'>Abbrechen</a></div>")
    return HTMLResponse(_shell("Bestätigung", body), status_code=status)


def totp_setup_page(auth, data):
    qr = f"<img class=qr src='{data['qr']}'>" if data.get("qr") else ""
    body = (f"<h1>2FA einrichten</h1>"
            f"<div class=hint>Scanne den QR-Code mit deiner Authenticator-App und gib dann einen Code ein.</div>"
            f"{qr}"
            f"<div class=hint>oder Schlüssel manuell:</div><div class=mono>{html.escape(data['secret'])}</div>"
            f"<form onsubmit='return conf(event)'>"
            f"<label>Bestätigungs-Code</label>"
            f"<input name=code class=code inputmode=numeric maxlength=6 autofocus>"
            f"<button type=submit>Aktivieren</button></form>"
            f"<div class=hint id=msg></div>"
            "<script>async function conf(e){e.preventDefault();const c=e.target.code.value;"
            "const r=await fetch('/auth/totp/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'code='+encodeURIComponent(c)});const j=await r.json();"
            "document.getElementById('msg').textContent=j.ok?'✓ 2FA aktiv':'Code falsch';return false}</script>")
    return HTMLResponse(_shell("2FA einrichten", body))


# Passkey-Login-JS (WebAuthn) — nur eingebunden, wenn passkey aktiv. Wird beim WebAuthn-Modul befüllt.
_PASSKEY_LOGIN_JS = """
<script>
document.getElementById('pkbtn')?.addEventListener('click', async () => {
  try {
    const o = await (await fetch('/auth/passkey/login/begin', {method:'POST'})).json();
    o.challenge = Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
    (o.allowCredentials||[]).forEach(c => c.id = Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')), x=>x.charCodeAt(0)));
    const cred = await navigator.credentials.get({publicKey:o});
    const enc = a => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload = {id:cred.id, rawId:enc(cred.rawId), type:cred.type, response:{
      clientDataJSON:enc(cred.response.clientDataJSON), authenticatorData:enc(cred.response.authenticatorData),
      signature:enc(cred.response.signature), userHandle:cred.response.userHandle?enc(cred.response.userHandle):null}};
    const r = await fetch('/auth/passkey/login/finish?next=__NEXT__', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    if (r.ok) location.href = (await r.json()).redirect || '/'; else alert('Passkey-Login fehlgeschlagen');
  } catch(e){ alert('Passkey abgebrochen: '+e); }
});
</script>
"""
