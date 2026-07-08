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
        sep_pin = "<div class=or>oder</div>" if pw else ""
        pin = (f"{sep_pin}<form method=post action='/auth/pin'>"
               f"<input type=hidden name=next value='{_e(next_)}'>"
               f"<label>Benutzer</label><input name=username autocomplete=username{'' if pw else ' autofocus'}>"
               f"<label>PIN</label><input name=pin type=password inputmode=numeric autocomplete=off class=code>"
               f"{remember}"
               f"<button type=submit>Mit PIN anmelden</button></form>")
    magic = ""
    if "magic" in methods:
        magic = f"<a class=btn2 href='/auth/magic/request?next={_e(next_)}'>✉️ Login-Link per E-Mail</a>"
    oidc = (f"<a class=btn2 href='/auth/oidc/start?next={_e(next_)}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    passkey = "<button class=btn2 type=button id=pkbtn>🔑 Mit Passkey anmelden</button>" if "passkey" in methods else ""
    others = oidc + passkey + magic
    sep = "<div class=or>oder</div>" if others and (pw or pin) else ""
    links = []
    if cfg.allow_signup:
        links.append(f"<a href='/auth/register?next={_e(next_)}' style='color:#9aa4b2'>Konto erstellen</a>")
    if getattr(cfg, "password_reset_enabled", False) and cfg.magiclink_enabled:
        links.append("<a href='/auth/forgot' style='color:#9aa4b2'>Passwort vergessen?</a>")
    signup = f"<div class=hint>{' · '.join(links)}</div>" if links else ""
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


def _account(auth, ctx) -> str:
    """ctx: user, methods, has_totp, has_pin, is_admin, admin_path. Selbstverwaltung + Logout.
    Über auth.set_template('account', fn) komplett ersetzbar."""
    u = ctx["user"]
    methods = ctx.get("methods", [])
    name = _e(u["display_name"] or u["username"])
    sections = []

    # Passwort ändern
    if "password" in methods:
        sections.append(
            "<div class=sec><h2>Passwort</h2>"
            "<input id=pw_cur type=password placeholder='Aktuelles Passwort'>"
            "<input id=pw_new type=password placeholder='Neues Passwort'>"
            "<button onclick=changepw()>Passwort ändern</button><span id=pw_msg class=msg></span></div>")

    # PIN
    if "pin" in methods:
        state = "gesetzt" if ctx.get("has_pin") else "nicht gesetzt"
        sections.append(
            f"<div class=sec><h2>PIN <small>({state})</small></h2>"
            "<input id=pin_new type=password inputmode=numeric placeholder='Neue PIN'>"
            "<button onclick=setpin()>PIN setzen</button> "
            "<button class=warn onclick=delpin()>PIN entfernen</button><span id=pin_msg class=msg></span></div>")

    # TOTP / 2FA
    if auth.cfg.totp_enabled:
        if ctx.get("has_totp"):
            totp = ("<span class=ok>✓ aktiv</span> "
                    "<button class=warn onclick=deltotp()>2FA deaktivieren</button> "
                    "<button onclick=recovery()>Recovery-Codes erzeugen</button>")
        else:
            totp = "<a class=btnlink href='/auth/totp/setup'>2FA einrichten</a>"
        sections.append(f"<div class=sec><h2>Zwei-Faktor (TOTP)</h2>{totp}<span id=totp_msg class=msg></span>"
                        "<pre id=rc_out style='white-space:pre-wrap;margin-top:10px'></pre></div>")

    # Passkeys
    if "passkey" in methods:
        sections.append(
            "<div class=sec><h2>Passkeys</h2><ul id=pklist></ul>"
            "<button onclick=addpk()>Passkey hinzufügen</button><span id=pk_msg class=msg></span></div>")

    # API-Keys
    if auth.cfg.apikey_enabled:
        sections.append(
            "<div class=sec><h2>API-Keys</h2><ul id=keylist></ul>"
            "<input id=key_name placeholder='Name (optional)'>"
            "<button onclick=mkkey()>Key erzeugen</button><span id=key_msg class=msg></span></div>")

    admin_link = (f"<a href='{_e(ctx.get('admin_path', '/auth/admin'))}'>Admin-Panel</a>"
                  if ctx.get("is_admin") else "")

    css = """
    body{max-width:640px;margin:0 auto;padding:24px;display:block}
    header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
    header h1{font-size:20px;margin:0}
    .sec{background:#161a22;border:1px solid #262b36;border-radius:12px;padding:16px;margin-bottom:14px}
    .sec h2{font-size:13px;color:#9aa4b2;text-transform:uppercase;letter-spacing:.05em;margin:0 0 12px}
    .sec small{text-transform:none;letter-spacing:0}
    .sec input{margin:4px 0}
    .sec button,.btnlink{width:auto;display:inline-block;margin:8px 6px 0 0;padding:9px 14px}
    button.warn{background:#b91c1c}
    .btnlink{background:#374151;color:#fff;border-radius:8px;text-decoration:none;padding:9px 14px}
    .msg{margin-left:8px;font-size:12px;color:#9aa4b2}
    .ok{color:#4ade80} ul{list-style:none;padding:0;margin:0 0 8px} li{padding:4px 0;font-size:13px;border-bottom:1px solid #20252f}
    a{color:#7dd3fc}
    """
    pkjs = _PASSKEY_REGISTER_JS if "passkey" in methods else ""
    body = (f"<header><h1>Konto · {name}</h1><div>{admin_link} <a href='/auth/logout'>Abmelden</a></div></header>"
            + "".join(sections) + _ACCOUNT_JS + pkjs)
    return (f"<!doctype html><html lang=de><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>Mein Konto</title><style>{_CSS}{css}</style></head><body>{body}</body></html>")


_ACCOUNT_JS = """
<script>
const J=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b||{})});
const say=(id,t,good)=>{const e=document.getElementById(id);if(e){e.textContent=t;e.style.color=good?'#4ade80':'#f87171'}};
async function changepw(){const r=await J('/auth/password',{current:pw_cur.value,new:pw_new.value});
  say('pw_msg',r.ok?'✓ geändert':(await r.json()).detail||'Fehler',r.ok);if(r.ok){pw_cur.value='';pw_new.value=''}}
async function setpin(){const r=await J('/auth/pin/set',{pin:pin_new.value});
  say('pin_msg',r.ok?'✓ gesetzt':(await r.json()).detail||'Fehler',r.ok);if(r.ok)setTimeout(()=>location.reload(),600)}
async function delpin(){const r=await J('/auth/pin/disable');say('pin_msg','✓ entfernt',true);setTimeout(()=>location.reload(),600)}
async function deltotp(){if(!confirm('2FA wirklich deaktivieren?'))return;await J('/auth/totp/disable');location.reload()}
async function recovery(){if(!confirm('Neue Recovery-Codes erzeugen? Alte werden ung\\u00fcltig.'))return;
  const r=await (await J('/auth/totp/recovery')).json();
  if(r.codes){document.getElementById('rc_out').textContent='Jetzt sicher notieren (einmalig sichtbar):\\n'+r.codes.join('\\n')}else say('totp_msg',r.detail||'Fehler',false)}
async function loadkeys(){const el=document.getElementById('keylist');if(!el)return;
  const ks=await (await fetch('/auth/apikeys')).json();
  el.innerHTML=ks.map(k=>`<li>${k.prefix} ${k.name||''} ${k.revoked?'<span style=color:#f87171>(widerrufen)</span>':`<button class=warn onclick=revk(${k.id})>widerrufen</button>`}</li>`).join('')||'<li>keine</li>'}
async function mkkey(){const r=await (await J('/auth/apikeys',{name:key_name.value})).json();
  if(r.key)prompt('API-Key — JETZT kopieren:',r.key);loadkeys()}
async function revk(id){await J('/auth/apikeys/'+id+'/revoke');loadkeys()}
async function loadpk(){const el=document.getElementById('pklist');if(!el)return;
  const ps=await (await fetch('/auth/passkey/list')).json();
  el.innerHTML=ps.map(p=>`<li>${p.name||'Passkey'} <button class=warn onclick=delpk(${p.id})>löschen</button></li>`).join('')||'<li>keine</li>'}
async function delpk(id){await J('/auth/passkey/delete',{id});loadpk()}
loadkeys();loadpk();
</script>
"""

_PASSKEY_REGISTER_JS = """
<script>
async function addpk(){
  try{
    const o=await (await fetch('/auth/passkey/register/begin',{method:'POST'})).json();
    o.challenge=Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    o.user.id=Uint8Array.from(atob(o.user.id.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    (o.excludeCredentials||[]).forEach(c=>c.id=Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0)));
    const cred=await navigator.credentials.create({publicKey:o});
    const enc=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload={id:cred.id,rawId:enc(cred.rawId),type:cred.type,response:{
      clientDataJSON:enc(cred.response.clientDataJSON),attestationObject:enc(cred.response.attestationObject),
      transports:(cred.response.getTransports&&cred.response.getTransports())||[]}};
    const r=await fetch('/auth/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)});
    say('pk_msg',r.ok?'✓ hinzugefügt':'fehlgeschlagen',r.ok);loadpk();
  }catch(e){say('pk_msg','abgebrochen: '+e,false)}
}
</script>
"""


def _register(auth, ctx) -> str:
    """ctx: next, invite, email, error, invite_only, sent_verify(optional)."""
    if ctx.get("sent_verify"):
        body = ("<h1>Fast fertig</h1>"
                "<div class=ok>Wir haben dir eine E-Mail zur Bestätigung geschickt.</div>"
                "<div class=hint>Öffne den Link darin, um dein Konto zu aktivieren.</div>"
                "<a class=btn2 href='/auth/login'>Zur Anmeldung</a>")
        return _shell("Bestätigung nötig", body)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    emailro = " readonly" if ctx.get("invite") and ctx.get("email") else ""
    body = (f"<h1>Konto erstellen</h1>{err}"
            f"<form method=post action='/auth/register'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<input type=hidden name=invite value='{_e(ctx.get('invite', ''))}'>"
            f"<label>Benutzername</label><input name=username autofocus autocomplete=username>"
            f"<label>E-Mail</label><input name=email type=email value='{_e(ctx.get('email', ''))}'{emailro} autocomplete=email>"
            f"<label>Passwort</label><input name=password type=password autocomplete=new-password>"
            f"<button type=submit>Registrieren</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>Schon ein Konto? Anmelden</a></div>")
    return _shell("Konto erstellen", body)


def _magic_request(auth, ctx) -> str:
    """ctx: next, sent (bool), error. E-Mail-Adresse für den Login-Link."""
    if ctx.get("sent"):
        body = ("<h1>E-Mail unterwegs</h1>"
                "<div class=ok>Wenn ein Konto zu dieser Adresse existiert, ist ein Anmelde-Link unterwegs.</div>"
                "<div class=hint>Prüfe dein Postfach. Der Link ist einige Minuten gültig.</div>"
                "<a class=btn2 href='/auth/login'>Zurück zur Anmeldung</a>")
        return _shell("E-Mail unterwegs", body)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>Login-Link per E-Mail</h1>{err}"
            f"<div class=hint>Wir schicken dir einen einmaligen Anmelde-Link.</div>"
            f"<form method=post action='/auth/magic/request'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<label>E-Mail-Adresse</label>"
            f"<input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>Link senden</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>Zurück</a></div>")
    return _shell("Login-Link", body)


def _forgot(auth, ctx) -> str:
    """ctx: sent (bool), error. E-Mail für den Reset-Link."""
    if ctx.get("sent"):
        return _shell("E-Mail unterwegs",
                      "<h1>E-Mail unterwegs</h1>"
                      "<div class=ok>Wenn ein Konto zu dieser Adresse existiert, ist ein Reset-Link unterwegs.</div>"
                      "<a class=btn2 href='/auth/login'>Zur Anmeldung</a>")
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>Passwort vergessen</h1>{err}"
            f"<div class=hint>Wir schicken dir einen Link zum Zurücksetzen.</div>"
            f"<form method=post action='/auth/forgot'>"
            f"<label>E-Mail-Adresse</label><input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>Reset-Link senden</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>Zurück</a></div>")
    return _shell("Passwort vergessen", body)


def _reset(auth, ctx) -> str:
    """ctx: token, error. Neues Passwort setzen."""
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>Neues Passwort</h1>{err}"
            f"<form method=post action='/auth/reset'>"
            f"<input type=hidden name=token value='{_e(ctx.get('token', ''))}'>"
            f"<label>Neues Passwort</label>"
            f"<input name=password type=password autocomplete=new-password autofocus>"
            f"<button type=submit>Passwort setzen</button></form>")
    return _shell("Neues Passwort", body)


def _magic_invalid(auth, ctx) -> str:
    body = ("<h1>Link ungültig</h1>"
            "<div class=err>Dieser Link ist ungültig, abgelaufen oder wurde bereits benutzt.</div>"
            "<a class=btn2 href='/auth/login'>Zur Anmeldung</a>")
    return _shell("Link ungültig", body)


def _resource_unlock(auth, ctx) -> str:
    """ctx: name, kind ('pin'|'password'), label, next, error. Geteiltes Ressourcen-Geheimnis."""
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    if ctx.get("kind") == "pin":
        field = "<input name=secret type=password inputmode=numeric autocomplete=off class=code autofocus>"
        lbl = "PIN"
    else:
        field = "<input name=secret type=password autocomplete=off autofocus>"
        lbl = "Zugangswort"
    body = (f"<h1>{_e(ctx.get('label'))}</h1>"
            f"<div class=hint>Dieser Bereich ist geschützt. Bitte {lbl} eingeben.</div>{err}"
            f"<form method=post action='/auth/resource/{_e(ctx.get('name'))}'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<label>{lbl}</label>{field}"
            f"<button type=submit>Freischalten</button></form>")
    return _shell(str(ctx.get("label") or "Geschützt"), body)


def _reauth(auth, ctx) -> str:
    """ctx: next, error, username, has_totp. Sudo-Frische: erneut Faktor bestätigen (Step-up)."""
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    if ctx.get("has_totp"):
        field = ("<label>6-stelliger Code aus deiner Authenticator-App</label>"
                 "<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>")
    else:
        field = ("<label>Passwort zur Bestätigung</label>"
                 "<input name=password type=password autocomplete=current-password autofocus>")
    body = (f"<h1>Bestätigung nötig</h1>"
            f"<div class=hint>Für diesen Bereich bitte erneut bestätigen ({_e(ctx.get('username'))}).</div>{err}"
            f"<form method=post action='/auth/reauth'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"{field}<button type=submit>Bestätigen</button></form>"
            f"<div class=hint><a href='/auth/logout' style='color:#9aa4b2'>Abmelden</a></div>")
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
    "reauth": _reauth,
    "resource_unlock": _resource_unlock,
    "account": _account,
    "register": _register,
    "magic_request": _magic_request,
    "magic_invalid": _magic_invalid,
    "forgot": _forgot,
    "reset": _reset,
    "totp_setup": _totp_setup,
}
