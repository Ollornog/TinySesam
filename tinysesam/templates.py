"""Eingebaute Login-/Auth-Views (dark/light) — und die Template-Registry, über die sich
JEDE Seite ersetzen lässt.

Frontend komplett austauschbar:
    auth.set_template("login", meine_login_funktion)   # fn(auth, ctx) -> str | Response
Die eingebauten Renderer bleiben als Fallback. `ctx` ist ein dict mit allen Variablen der Seite
(dokumentiert je Renderer). Gibt ein Override eine Starlette-`Response` zurück, wird sie unverändert
ausgeliefert; ein String wird als HTML mit dem jeweiligen Status verpackt.
"""
from __future__ import annotations
import html


class Templates:
    """Registry benannter Seiten-Renderer. `render(name, auth, ctx)` nimmt einen Override
    (falls gesetzt) oder den eingebauten Default."""
    def __init__(self):
        self._overrides: dict = {}

    def set(self, name: str, fn):
        """Einen Renderer überschreiben. fn(auth, ctx) -> str | Response."""
        self._overrides[name] = fn

    def has(self, name: str) -> bool:
        return name in self._overrides or name in DEFAULTS

    def render(self, name: str, auth, ctx: dict):
        fn = self._overrides.get(name) or DEFAULTS.get(name)
        if fn is None:
            raise KeyError(f"kein Template '{name}'")
        return fn(auth, ctx)


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
.ok{background:#12331f;color:#4ade80;padding:9px 12px;border-radius:8px;font-size:13px;margin-bottom:6px}
.or{text-align:center;color:#6b7280;font-size:12px;margin:16px 0 4px}
.hint{color:#9aa4b2;font-size:12px;text-align:center;margin-top:14px}
.remember{display:flex;align-items:center;gap:7px;margin-top:14px;font-size:13px;color:#9aa4b2}
.remember input{width:auto;margin:0}
.code{width:100%;text-align:center;letter-spacing:.4em;font-size:22px}
img.qr{display:block;margin:14px auto;width:190px;height:190px;background:#fff;border-radius:8px;padding:6px}
.mono{font-family:ui-monospace,monospace;background:#0f1115;border:1px solid #303643;border-radius:6px;padding:6px 8px;
      font-size:13px;text-align:center;word-break:break-all}
.warnbar{background:#442006;color:#fdba74;padding:9px 12px;border-radius:8px;font-size:12px;margin-bottom:10px}
"""


def _shell(title, body):
    return (f"<!doctype html><html lang=de><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body><div class=card>{body}</div></body></html>")


def _e(s) -> str:
    return html.escape(str(s or ""))


# ---------- Default-Renderer  (fn(auth, ctx) -> str) ----------

def _login(auth, ctx) -> str:
    """ctx: next, error, warn(optional). Zeigt alle aktiven Login-Methoden."""
    cfg = auth.cfg
    next_ = ctx.get("next", "/")
    error = ctx.get("error", "")
    methods = cfg.enabled_methods()
    warn = f"<div class=warnbar>{_e(ctx['warn'])}</div>" if ctx.get("warn") else ""
    err = f"<div class=err>{_e(error)}</div>" if error else ""
    remember = ""
    if cfg.remember_me_enabled:
        remember = ("<label class=remember><input type=checkbox name=remember value=1 checked> "
                    "Angemeldet bleiben</label>")
    pw = ""
    if "password" in methods:
        pw = (f"<form method=post action='{_e(cfg.login_path)}'>"
              f"<input type=hidden name=next value='{_e(next_)}'>"
              f"<label>Benutzer</label><input name=username autofocus autocomplete=username>"
              f"<label>Passwort</label><input name=password type=password autocomplete=current-password>"
              f"{remember}"
              f"<button type=submit>Anmelden</button></form>")
    pin = ""
    if "pin" in methods:
        pin = (f"<form method=post action='/auth/pin'>"
               f"<input type=hidden name=next value='{_e(next_)}'>"
               f"<label>Benutzer</label><input name=username autocomplete=username>"
               f"<label>PIN</label><input name=pin type=password inputmode=numeric autocomplete=off class=code>"
               f"{remember if not pw else ''}"
               f"<button type=submit>Mit PIN anmelden</button></form>")
    magic = ""
    if "magic" in methods:
        magic = f"<a class=btn2 href='/auth/magic/request?next={_e(next_)}'>✉️ Login-Link per E-Mail</a>"
    oidc = (f"<a class=btn2 href='/auth/oidc/start?next={_e(next_)}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    passkey = "<button class=btn2 type=button id=pkbtn>🔑 Mit Passkey anmelden</button>" if "passkey" in methods else ""
    others = oidc + passkey + magic
    sep = "<div class=or>oder</div>" if others and (pw or pin) else ""
    signup = (f"<div class=hint><a href='/auth/register?next={_e(next_)}' style='color:#9aa4b2'>Konto erstellen</a></div>"
              if cfg.allow_signup else "")
    js = _PASSKEY_LOGIN_JS.replace("__NEXT__", _e(next_)) if "passkey" in methods else ""
    body = f"<h1>{_e(cfg.rp_name)}</h1>{warn}{err}{pw}{pin}{sep}{others}{signup}{js}"
    return _shell("Anmelden", body)


def _totp(auth, ctx) -> str:
    """ctx: next, error."""
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>Bestätigung</h1>{err}"
            f"<form method=post action='/auth/totp'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<label>6-stelliger Code aus deiner Authenticator-App</label>"
            f"<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>"
            f"<button type=submit>Weiter</button></form>"
            f"<div class=hint><a href='/auth/logout' style='color:#9aa4b2'>Abbrechen</a></div>")
    return _shell("Bestätigung", body)


def _totp_setup(auth, ctx) -> str:
    """ctx: data = {secret, uri, qr}."""
    data = ctx["data"]
    qr = f"<img class=qr src='{data['qr']}'>" if data.get("qr") else ""
    body = (f"<h1>2FA einrichten</h1>"
            f"<div class=hint>Scanne den QR-Code mit deiner Authenticator-App und gib dann einen Code ein.</div>"
            f"{qr}"
            f"<div class=hint>oder Schlüssel manuell:</div><div class=mono>{_e(data['secret'])}</div>"
            f"<form onsubmit='return conf(event)'>"
            f"<label>Bestätigungs-Code</label>"
            f"<input name=code class=code inputmode=numeric maxlength=6 autofocus>"
            f"<button type=submit>Aktivieren</button></form>"
            f"<div class=hint id=msg></div>"
            "<script>async function conf(e){e.preventDefault();const c=e.target.code.value;"
            "const r=await fetch('/auth/totp/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},"
            "body:'code='+encodeURIComponent(c)});const j=await r.json();"
            "document.getElementById('msg').textContent=j.ok?'✓ 2FA aktiv':'Code falsch';return false}</script>")
    return _shell("2FA einrichten", body)


# Passkey-Login-JS (WebAuthn) — nur eingebunden, wenn passkey aktiv.
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


DEFAULTS = {
    "login": _login,
    "totp": _totp,
    "totp_setup": _totp_setup,
}
