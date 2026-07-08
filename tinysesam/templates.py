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


def _shell(title, body, lang="en"):
    return (f"<!doctype html><html lang={html.escape(lang)}><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{html.escape(title)}</title><style>{_CSS}</style></head>"
            f"<body><div class=card>{body}</div></body></html>")


def _e(s) -> str:
    return html.escape(str(s or ""))


def _cf(ctx) -> str:
    """Verstecktes CSRF-Feld für Formulare (leer, wenn CSRF aus → ctx ohne 'csrf')."""
    return f"<input type=hidden name=_csrf value='{_e(ctx.get('csrf', ''))}'>"


def _csrf_js(auth) -> str:
    """JS-Helfer: liest das CSRF-Cookie → tsCsrf(); die fetch-Aufrufe senden X-CSRF-Token."""
    return ("<script>function tsCsrf(){return (document.cookie.match("
            f"/(?:^|; ){_e(auth.cfg.csrf_cookie)}=([^;]+)/)||[])[1]||''}}</script>")


# ---------- Default-Renderer  (fn(auth, ctx) -> str) ----------

def _login(auth, ctx) -> str:
    """ctx: next, error, warn(optional). Zeigt alle aktiven Login-Methoden."""
    cfg = auth.cfg
    t = auth.t
    next_ = ctx.get("next", "/")
    error = ctx.get("error", "")
    methods = cfg.enabled_methods()
    warn = f"<div class=warnbar>{_e(ctx['warn'])}</div>" if ctx.get("warn") else ""
    err = f"<div class=err>{_e(error)}</div>" if error else ""
    _or = f"<div class=or>{_e(t('or'))}</div>"
    remember = ""
    if cfg.remember_me_enabled:
        remember = ("<label class=remember><input type=checkbox name=remember value=1 checked> "
                    f"{_e(t('login.remember'))}</label>")
    pw = ""
    if "password" in methods:
        pw = (f"<form method=post action='{_e(cfg.login_path)}'>"
              f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
              f"<label>{_e(t('login.user'))}</label><input name=username autofocus autocomplete=username>"
              f"<label>{_e(t('login.password'))}</label><input name=password type=password autocomplete=current-password>"
              f"{remember}"
              f"<button type=submit>{_e(t('login.submit'))}</button></form>")
    pin = ""
    if "pin" in methods:
        pin = (f"{_or if pw else ''}<form method=post action='/auth/pin'>"
               f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
               f"<label>{_e(t('login.user'))}</label><input name=username autocomplete=username{'' if pw else ' autofocus'}>"
               f"<label>{_e(t('login.pin'))}</label><input name=pin type=password inputmode=numeric autocomplete=off class=code>"
               f"{remember}"
               f"<button type=submit>{_e(t('login.pin_submit'))}</button></form>")
    magic = ""
    if "magic" in methods:
        magic = f"<a class=btn2 href='/auth/magic/request?next={_e(next_)}'>{_e(t('login.magic'))}</a>"
    oidc = (f"<a class=btn2 href='/auth/oidc/start?next={_e(next_)}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    passkey = f"<button class=btn2 type=button id=pkbtn>{_e(t('login.passkey'))}</button>" if "passkey" in methods else ""
    others = oidc + passkey + magic
    sep = _or if others and (pw or pin) else ""
    links = []
    if cfg.allow_signup:
        links.append(f"<a href='/auth/register?next={_e(next_)}' style='color:#9aa4b2'>{_e(t('login.signup'))}</a>")
    if getattr(cfg, "password_reset_enabled", False) and cfg.magiclink_enabled:
        links.append(f"<a href='/auth/forgot' style='color:#9aa4b2'>{_e(t('login.forgot'))}</a>")
    signup = f"<div class=hint>{' · '.join(links)}</div>" if links else ""
    js = (_csrf_js(auth) + _PASSKEY_LOGIN_JS.replace("__NEXT__", _e(next_))) if "passkey" in methods else ""
    body = f"<h1>{_e(cfg.rp_name)}</h1>{warn}{err}{pw}{pin}{sep}{others}{signup}{js}"
    return _shell(t("login.submit"), body, cfg.lang)


def _totp(auth, ctx) -> str:
    """ctx: next, error."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('totp.title'))}</h1>{err}"
            f"<form method=post action='/auth/totp'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('totp.label'))}</label>"
            f"<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>"
            f"<button type=submit>{_e(t('totp.submit'))}</button></form>"
            f"<div class=hint><a href='/auth/logout' style='color:#9aa4b2'>{_e(t('cancel'))}</a></div>")
    return _shell(t("totp.title"), body, auth.cfg.lang)


def _account(auth, ctx) -> str:
    """ctx: user, methods, has_totp, has_pin, is_admin, admin_path. Selbstverwaltung + Logout.
    Über auth.set_template('account', fn) komplett ersetzbar."""
    u = ctx["user"]
    t = auth.t
    methods = ctx.get("methods", [])
    name = _e(u["display_name"] or u["username"])
    sections = []

    # Passwort ändern
    if "password" in methods:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.password'))}</h2>"
            f"<input id=pw_cur type=password placeholder='{_e(t('acc.pw_cur'))}'>"
            f"<input id=pw_new type=password placeholder='{_e(t('acc.pw_new'))}'>"
            f"<button onclick=changepw()>{_e(t('acc.pw_change'))}</button><span id=pw_msg class=msg></span></div>")

    # PIN
    if "pin" in methods:
        state = t("acc.pin_set_state") if ctx.get("has_pin") else t("acc.pin_unset_state")
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.pin'))} <small>({_e(state)})</small></h2>"
            f"<input id=pin_new type=password inputmode=numeric placeholder='{_e(t('acc.pin_new'))}'>"
            f"<button onclick=setpin()>{_e(t('acc.pin_set'))}</button> "
            f"<button class=warn onclick=delpin()>{_e(t('acc.pin_remove'))}</button><span id=pin_msg class=msg></span></div>")

    # TOTP / 2FA
    if auth.cfg.totp_enabled:
        if ctx.get("has_totp"):
            totp = (f"<span class=ok>{_e(t('acc.totp_active'))}</span> "
                    f"<button class=warn onclick=deltotp()>{_e(t('acc.totp_off'))}</button> "
                    f"<button onclick=recovery()>{_e(t('acc.recovery'))}</button>")
        else:
            totp = f"<a class=btnlink href='/auth/totp/setup'>{_e(t('acc.totp_setup'))}</a>"
        sections.append(f"<div class=sec><h2>{_e(t('acc.totp'))}</h2>{totp}<span id=totp_msg class=msg></span>"
                        "<pre id=rc_out style='white-space:pre-wrap;margin-top:10px'></pre></div>")

    # Passkeys
    if "passkey" in methods:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.passkeys'))}</h2><ul id=pklist></ul>"
            f"<button onclick=addpk()>{_e(t('acc.passkey_add'))}</button><span id=pk_msg class=msg></span></div>")

    # API-Keys
    if auth.cfg.apikey_enabled:
        sections.append(
            f"<div class=sec><h2>{_e(t('acc.keys'))}</h2><ul id=keylist></ul>"
            f"<input id=key_name placeholder='{_e(t('acc.key_name'))}'>"
            f"<button onclick=mkkey()>{_e(t('acc.key_create'))}</button><span id=key_msg class=msg></span></div>")

    # Aktive Sitzungen (immer)
    sections.append(
        f"<div class=sec><h2>{_e(t('acc.sessions'))}</h2><ul id=sesslist></ul>"
        f"<button class=warn onclick=revokeothers()>{_e(t('acc.sessions_revoke'))}</button>"
        "<span id=sess_msg class=msg></span></div>")

    admin_link = (f"<a href='{_e(ctx.get('admin_path', '/auth/admin'))}'>{_e(t('acc.admin'))}</a>"
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
    body = (f"<header><h1>{_e(t('acc.title'))} · {name}</h1>"
            f"<div>{admin_link} <a href='/auth/logout'>{_e(t('logout'))}</a></div></header>"
            + "".join(sections) + _ACCOUNT_JS + pkjs)
    return (f"<!doctype html><html lang={_e(auth.cfg.lang)}><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"<title>{_e(t('acc.title'))}</title><style>{_CSS}{css}</style></head><body>{body}</body></html>")


_ACCOUNT_JS = """
<script>
function tsCsrf(){return (document.cookie.match(/(?:^|; )tinysesam_csrf=([^;]+)/)||[])[1]||''}
const J=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(b||{})});
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
async function loadsess(){const el=document.getElementById('sesslist');if(!el)return;
  const ss=await (await fetch('/auth/sessions')).json();
  el.innerHTML=ss.map(s=>`<li>${new Date(s.created_at*1000).toLocaleString('de-DE')} · ${esc0(s.method)} · ${esc0(s.ip)||'?'} ${s.current?'<b>(diese)</b>':''}<br><small style=color:#6b7280>${esc0(s.user_agent)}</small></li>`).join('')||'<li>keine</li>'}
function esc0(s){return (s??'').toString().replace(/</g,'&lt;')}
async function revokeothers(){if(!confirm('Alle anderen Sitzungen beenden?'))return;
  await J('/auth/sessions/revoke',{scope:'others'});say('sess_msg','\\u2713 beendet',true);loadsess()}
loadkeys();loadpk();loadsess();
</script>
"""

_PASSKEY_REGISTER_JS = """
<script>
async function addpk(){
  try{
    const o=await (await fetch('/auth/passkey/register/begin',{method:'POST',headers:{'X-CSRF-Token':tsCsrf()}})).json();
    o.challenge=Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    o.user.id=Uint8Array.from(atob(o.user.id.replace(/-/g,'+').replace(/_/g,'/')),c=>c.charCodeAt(0));
    (o.excludeCredentials||[]).forEach(c=>c.id=Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')),x=>x.charCodeAt(0)));
    const cred=await navigator.credentials.create({publicKey:o});
    const enc=a=>btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload={id:cred.id,rawId:enc(cred.rawId),type:cred.type,response:{
      clientDataJSON:enc(cred.response.clientDataJSON),attestationObject:enc(cred.response.attestationObject),
      transports:(cred.response.getTransports&&cred.response.getTransports())||[]}};
    const r=await fetch('/auth/passkey/register/finish',{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(payload)});
    say('pk_msg',r.ok?'✓ hinzugefügt':'fehlgeschlagen',r.ok);loadpk();
  }catch(e){say('pk_msg','abgebrochen: '+e,false)}
}
</script>
"""


def _register(auth, ctx) -> str:
    """ctx: next, invite, email, error, invite_only, sent_verify(optional)."""
    t = auth.t
    lang = auth.cfg.lang
    if ctx.get("sent_verify"):
        body = (f"<h1>{_e(t('reg.verify_title'))}</h1>"
                f"<div class=ok>{_e(t('reg.verify'))}</div>"
                f"<div class=hint>{_e(t('reg.verify_hint'))}</div>"
                f"<a class=btn2 href='/auth/login'>{_e(t('magic.to_login'))}</a>")
        return _shell(t("reg.verify_title"), body, lang)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    emailro = " readonly" if ctx.get("invite") and ctx.get("email") else ""
    body = (f"<h1>{_e(t('reg.title'))}</h1>{err}"
            f"<form method=post action='/auth/register'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<input type=hidden name=invite value='{_e(ctx.get('invite', ''))}'>{_cf(ctx)}"
            f"<label>{_e(t('reg.user'))}</label><input name=username autofocus autocomplete=username>"
            f"<label>{_e(t('reg.email'))}</label><input name=email type=email value='{_e(ctx.get('email', ''))}'{emailro} autocomplete=email>"
            f"<label>{_e(t('reg.password'))}</label><input name=password type=password autocomplete=new-password>"
            f"<button type=submit>{_e(t('reg.submit'))}</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>{_e(t('reg.have'))}</a></div>")
    return _shell(t("reg.title"), body, lang)


def _magic_request(auth, ctx) -> str:
    """ctx: next, sent (bool), error. E-Mail-Adresse für den Login-Link."""
    t = auth.t
    lang = auth.cfg.lang
    if ctx.get("sent"):
        body = (f"<h1>{_e(t('magic.sent_title'))}</h1>"
                f"<div class=ok>{_e(t('magic.sent'))}</div>"
                f"<div class=hint>{_e(t('magic.sent_hint'))}</div>"
                f"<a class=btn2 href='/auth/login'>{_e(t('magic.back_login'))}</a>")
        return _shell(t("magic.sent_title"), body, lang)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('magic.title'))}</h1>{err}"
            f"<div class=hint>{_e(t('magic.hint'))}</div>"
            f"<form method=post action='/auth/magic/request'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label>"
            f"<input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('magic.send'))}</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>{_e(t('back'))}</a></div>")
    return _shell(t("magic.title"), body, lang)


def _forgot(auth, ctx) -> str:
    """ctx: sent (bool), error. E-Mail für den Reset-Link."""
    t = auth.t
    lang = auth.cfg.lang
    if ctx.get("sent"):
        return _shell(t("magic.sent_title"),
                      f"<h1>{_e(t('magic.sent_title'))}</h1>"
                      f"<div class=ok>{_e(t('magic.sent'))}</div>"
                      f"<a class=btn2 href='/auth/login'>{_e(t('magic.to_login'))}</a>", lang)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('forgot.title'))}</h1>{err}"
            f"<div class=hint>{_e(t('forgot.hint'))}</div>"
            f"<form method=post action='/auth/forgot'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label><input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('forgot.send'))}</button></form>"
            f"<div class=hint><a href='/auth/login' style='color:#9aa4b2'>{_e(t('back'))}</a></div>")
    return _shell(t("forgot.title"), body, lang)


def _reset(auth, ctx) -> str:
    """ctx: token, error. Neues Passwort setzen."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('reset.title'))}</h1>{err}"
            f"<form method=post action='/auth/reset'>"
            f"<input type=hidden name=token value='{_e(ctx.get('token', ''))}'>{_cf(ctx)}"
            f"<label>{_e(t('reset.new'))}</label>"
            f"<input name=password type=password autocomplete=new-password autofocus>"
            f"<button type=submit>{_e(t('reset.submit'))}</button></form>")
    return _shell(t("reset.title"), body, auth.cfg.lang)


def _magic_invalid(auth, ctx) -> str:
    t = auth.t
    body = (f"<h1>{_e(t('magic.invalid_title'))}</h1>"
            f"<div class=err>{_e(t('magic.invalid'))}</div>"
            f"<a class=btn2 href='/auth/login'>{_e(t('magic.to_login'))}</a>")
    return _shell(t("magic.invalid_title"), body, auth.cfg.lang)


def _resource_unlock(auth, ctx) -> str:
    """ctx: name, kind ('pin'|'password'), label, next, error. Geteiltes Ressourcen-Geheimnis."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    if ctx.get("kind") == "pin":
        field = "<input name=secret type=password inputmode=numeric autocomplete=off class=code autofocus>"
        lbl = t("res.pin")
    else:
        field = "<input name=secret type=password autocomplete=off autofocus>"
        lbl = t("res.word")
    body = (f"<h1>{_e(ctx.get('label'))}</h1>"
            f"<div class=hint>{_e(t('res.hint', kind=lbl))}</div>{err}"
            f"<form method=post action='/auth/resource/{_e(ctx.get('name'))}'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(lbl)}</label>{field}"
            f"<button type=submit>{_e(t('res.submit'))}</button></form>")
    return _shell(str(ctx.get("label") or lbl), body, auth.cfg.lang)


def _reauth(auth, ctx) -> str:
    """ctx: next, error, username, has_totp. Sudo-Frische: erneut Faktor bestätigen (Step-up)."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    if ctx.get("has_totp"):
        field = (f"<label>{_e(t('totp.label'))}</label>"
                 "<input name=code class=code inputmode=numeric autocomplete=one-time-code autofocus maxlength=6>")
    else:
        field = (f"<label>{_e(t('reauth.pw'))}</label>"
                 "<input name=password type=password autocomplete=current-password autofocus>")
    body = (f"<h1>{_e(t('reauth.title'))}</h1>"
            f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>{err}"
            f"<form method=post action='/auth/reauth'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{field}<button type=submit>{_e(t('reauth.submit'))}</button></form>"
            f"<div class=hint><a href='/auth/logout' style='color:#9aa4b2'>{_e(t('logout'))}</a></div>")
    return _shell(t("reauth.title"), body, auth.cfg.lang)


def _totp_setup(auth, ctx) -> str:
    """ctx: data = {secret, uri, qr}."""
    t = auth.t
    data = ctx["data"]
    qr = f"<img class=qr src='{data['qr']}'>" if data.get("qr") else ""
    ok_msg = _e(t("setup.ok")).replace("'", "\\'")
    bad_msg = _e(t("err.code")).replace("'", "\\'")
    body = (f"<h1>{_e(t('setup.title'))}</h1>"
            f"<div class=hint>{_e(t('setup.scan'))}</div>"
            f"{qr}"
            f"<div class=hint>{_e(t('setup.manual'))}</div><div class=mono>{_e(data['secret'])}</div>"
            f"<form onsubmit='return conf(event)'>"
            f"<label>{_e(t('setup.code'))}</label>"
            f"<input name=code class=code inputmode=numeric maxlength=6 autofocus>"
            f"<button type=submit>{_e(t('setup.activate'))}</button></form>"
            f"<div class=hint id=msg></div>"
            "<script>function tsCsrf(){return (document.cookie.match(/(?:^|; )" + _e(auth.cfg.csrf_cookie) + "=([^;]+)/)||[])[1]||''}"
            "async function conf(e){e.preventDefault();const c=e.target.code.value;"
            "const r=await fetch('/auth/totp/setup',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','X-CSRF-Token':tsCsrf()},"
            "body:'code='+encodeURIComponent(c)});const j=await r.json();"
            f"document.getElementById('msg').textContent=j.ok?'{ok_msg}':'{bad_msg}';return false}}</script>")
    return _shell(t("setup.title"), body, auth.cfg.lang)


# Passkey-Login-JS (WebAuthn) — nur eingebunden, wenn passkey aktiv.
_PASSKEY_LOGIN_JS = """
<script>
document.getElementById('pkbtn')?.addEventListener('click', async () => {
  try {
    const o = await (await fetch('/auth/passkey/login/begin', {method:'POST',headers:{'X-CSRF-Token':tsCsrf()}})).json();
    o.challenge = Uint8Array.from(atob(o.challenge.replace(/-/g,'+').replace(/_/g,'/')), c=>c.charCodeAt(0));
    (o.allowCredentials||[]).forEach(c => c.id = Uint8Array.from(atob(c.id.replace(/-/g,'+').replace(/_/g,'/')), x=>x.charCodeAt(0)));
    const cred = await navigator.credentials.get({publicKey:o});
    const enc = a => btoa(String.fromCharCode(...new Uint8Array(a))).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');
    const payload = {id:cred.id, rawId:enc(cred.rawId), type:cred.type, response:{
      clientDataJSON:enc(cred.response.clientDataJSON), authenticatorData:enc(cred.response.authenticatorData),
      signature:enc(cred.response.signature), userHandle:cred.response.userHandle?enc(cred.response.userHandle):null}};
    const r = await fetch('/auth/passkey/login/finish?next=__NEXT__', {method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(payload)});
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
