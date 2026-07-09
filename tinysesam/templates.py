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

from .theme import TOKENS


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


_CSS = TOKENS + """
/* WICHTIG: alles unterhalb von .tsmain gekapselt. Sonst faerbt das Karten-CSS auf `brand_header`
   und `brand_footer` der Host-App ab (nackte button/input/h1-Selektoren). */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;min-height:100vh;display:flex;flex-direction:column;
     background:var(--ts-bg);color:var(--ts-ink)}
.tsmain{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;
     gap:14px;padding:32px 16px}
.tsmain .card{width:340px;max-width:92vw;background:var(--ts-surface);border:1px solid var(--ts-line);
     border-radius:calc(var(--ts-radius) + 2px);padding:26px}
.tsmain h1{font-size:20px;margin:0 0 18px;text-align:center}
.tsmain label{display:block;font-size:12px;color:var(--ts-muted);margin:12px 0 4px}
.tsmain input{width:100%;background:var(--ts-field-bg);color:var(--ts-ink);
     border:1px solid var(--ts-field-line);border-radius:8px;padding:10px 12px;font-size:15px}
.tsmain button,.tsmain .btn2{width:100%;margin-top:18px;padding:11px;border:0;border-radius:8px;
     font-size:15px;cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);
     display:block;text-align:center;text-decoration:none}
.tsmain .btn2{background:var(--ts-neutral);color:var(--ts-neutral-ink);margin-top:10px}
.tsmain .err{background:var(--ts-err-bg);color:var(--ts-err-ink);padding:9px 12px;border-radius:8px;
     font-size:13px;margin-bottom:6px}
.tsmain .ok{background:var(--ts-ok-bg);color:var(--ts-ok-ink);padding:9px 12px;border-radius:8px;
     font-size:13px;margin-bottom:6px}
.tsmain .or{text-align:center;color:var(--ts-muted);font-size:12px;margin:16px 0 4px}
.tsmain .hint{color:var(--ts-muted);font-size:12px;text-align:center;margin-top:14px}
.tsmain .hint a{color:var(--ts-muted)}
.tsmain .remember{display:flex;align-items:center;gap:7px;margin-top:14px;font-size:13px;
     color:var(--ts-muted)}
.tsmain .remember input{width:auto;margin:0}
.tsmain .code{width:100%;text-align:center;letter-spacing:.4em;font-size:22px}
.tsmain img.qr{display:block;margin:14px auto;width:190px;height:190px;background:#fff;
     border-radius:8px;padding:6px}
.tsmain .mono{font-family:var(--ts-mono);background:var(--ts-field-bg);
     border:1px solid var(--ts-field-line);border-radius:6px;padding:6px 8px;font-size:13px;
     text-align:center;word-break:break-all}
.tsmain .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:9px 12px;
     border-radius:8px;font-size:12px;margin-bottom:10px}
/* steht NEBEN der Karte, nicht darin — ein Demo-Hinweis ist kein Teil des Formulars */
.tsmain .demobar{width:340px;max-width:92vw;background:var(--ts-info-bg);color:var(--ts-info-ink);
     padding:11px 14px;border-radius:calc(var(--ts-radius) + 2px);border:1px solid var(--ts-line);
     font-size:12.5px;line-height:1.5}
.tsmain .demobar b{font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.tsmain .demobar button.demofill{width:auto;display:inline;margin:0;padding:1px 7px;border-radius:6px;
     font:inherit;font-weight:700;background:var(--ts-chip);color:var(--ts-info-ink);
     border:1px solid var(--ts-line);cursor:pointer}
.tsmain .demobar button.demofill:hover{filter:brightness(1.08)}
.tsmain .demowarn{margin-top:6px;color:var(--ts-warn-ink);background:var(--ts-warn-bg);padding:6px 8px;
     border-radius:6px;font-size:11.5px}
.tsmain .demowarn code{background:none;border:0;padding:0}
"""


def favicon_link(icon: str) -> str:
    """Favicon-<link> für die eingebauten Seiten. Eine Stelle, damit keine Seite es vergisst."""
    return f"<link rel=icon href='{html.escape(icon)}'>" if icon else ""


def brand(value, auth):
    """`brand_header`/`brand_footer` dürfen ein String oder `fn(auth) -> str` sein — Letzteres,
    wenn der Rumpf vom Request abhängt (Login-Status, Sprache)."""
    if callable(value):
        try:
            return value(auth) or ""
        except Exception:      # ein kaputter Rumpf darf die Login-Seite nicht mitreißen
            return ""
    return value or ""


def _doc(title, body, lang="en", brand_css="", brand_head="", card=True, brand_icon="", top="",
         header="", footer=""):
    """`top` steht außerhalb der Karte (z.B. der Demo-Hinweis) — direkt darüber, gleich breit.
    `header`/`footer` umschließen die Seite, damit die Host-App ihre Navigation drumherum legen kann."""
    inner = f"<div class=card>{body}</div>" if card else body
    return (f"<!doctype html><html lang={html.escape(lang)}><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width,initial-scale=1'>"
            f"{favicon_link(brand_icon)}"
            f"<title>{html.escape(title)}</title><style>{_CSS}{brand_css or ''}</style>{brand_head or ''}</head>"
            f"<body>{header}<div class=tsmain>{top}{inner}</div>{footer}</body></html>")


def _shell(title, body, lang="en"):
    return _doc(title, body)


def _page(auth, title, body, card=True, top=""):
    """Wie _shell, aber mit Branding aus der Config (brand_css/brand_head/brand_icon/brand_header/
    brand_footer) — re-skinnt und umrahmt alle Seiten zentral. `top` landet außerhalb der Karte."""
    cfg = auth.cfg
    return _doc(title, body, cfg.lang, getattr(cfg, "brand_css", ""), getattr(cfg, "brand_head", ""),
                card, getattr(cfg, "brand_icon", ""), top,
                brand(getattr(cfg, "brand_header", ""), auth), brand(getattr(cfg, "brand_footer", ""), auth))


def _e(s) -> str:
    return html.escape(str(s or ""))


def _ident(auth) -> tuple[str, str]:
    """Beschriftung + autocomplete fürs Kennungsfeld, je nach `config.login_identifier`."""
    mode = getattr(auth.cfg, "login_identifier", "both")
    if mode == "email":
        return auth.t("login.email"), "email"
    if mode == "username":
        return auth.t("login.user"), "username"
    return auth.t("login.identifier"), "username"


# Klick auf einen Namen setzt die Zugangsdaten ins Formular. Und: ein vom Browser eingefülltes
# Passwort wird verworfen — sonst tippt man den Benutzernamen über die Autofill-Vorgabe und der
# Login scheitert mit „falsche Zugangsdaten", ohne dass man den Grund sieht.
_DEMO_JS = """<script>
(function(){
  // Browser fuellen gespeicherte Passwoerter zu unterschiedlichen Zeitpunkten ein — deshalb mehrfach
  // nachfassen. Sobald jemand selbst tippt, wird nicht mehr geleert.
  var typed = false;
  function clear(){
    if(typed) return;
    document.querySelectorAll('form input[type=password]').forEach(function(f){ f.value = ''; });
  }
  function init(){
    document.querySelectorAll('form input').forEach(function(f){
      f.addEventListener('input', function(){ typed = true; });
    });
    [0, 80, 250, 700].forEach(function(ms){ setTimeout(clear, ms); });
    document.querySelectorAll('.demofill').forEach(function(b){
      b.addEventListener('click', function(){
        typed = true;
        var form = document.querySelector('form');
        var u = form.querySelector('[name=username]'), p = form.querySelector('[name=password]');
        if(u) u.value = b.dataset.u;
        if(p) p.value = b.dataset.p;
        (p || u).focus();
      });
    });
  }
  if(document.readyState !== 'loading') init(); else document.addEventListener('DOMContentLoaded', init);
  addEventListener('pageshow', function(e){ if(e.persisted) clear(); });   // Zurueck-Taste
})();
</script>"""


def _fill(user, pw) -> str:
    return f"<button type=button class=demofill data-u='{_e(user)}' data-p='{_e(pw)}'>{_e(user)}</button>"


def _demobar(auth, pin=False) -> str:
    """Zugangsdaten + unmissverständliche Warnung — nur wenn `demo_mode` an ist."""
    cfg = auth.cfg
    if not cfg.demo_mode:
        return ""
    t = auth.t
    if pin:
        line, js = t("demo.pin", pin=cfg.demo_pin), ""
    else:
        line = t("demo.creds", user=_fill("demo", cfg.demo_password),
                 admin=_fill("demoadmin", cfg.demo_password), pw=_e(cfg.demo_password))
        js = _DEMO_JS
    return (f"<div class=demobar><b>{_e(t('demo.title'))}</b><br>{line}"
            f"<div class=demowarn>{t('demo.warn')}</div></div>{js}")


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
    id_label, id_ac = _ident(auth)
    # Im Demo-Modus fuellt der Browser sonst ein gespeichertes Passwort ein und der Login schlaegt fehl.
    pw_ac = "new-password" if cfg.demo_mode else "current-password"
    pw = ""
    if "password" in methods:
        pw = (f"<form method=post action='{_e(cfg.login_path)}'>"
              f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
              f"<label>{_e(id_label)}</label><input name=username required autofocus autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false>"
              f"<label>{_e(t('login.password'))}</label><input name=password required type=password autocomplete={pw_ac}>"
              f"{remember}"
              f"<button type=submit>{_e(t('login.submit'))}</button></form>")
    pin = ""
    if "pin" in methods:
        pin = (f"{_or if pw else ''}<form method=post action='/auth/pin'>"
               f"<input type=hidden name=next value='{_e(next_)}'>{_cf(ctx)}"
               f"<label>{_e(id_label)}</label><input name=username autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false{'' if pw else ' autofocus'}>"
               f"<label>{_e(t('login.pin'))}</label><input name=pin required type=password inputmode=numeric autocomplete=off class=code>"
               f"{remember}"
               f"<button type=submit>{_e(t('login.pin_submit'))}</button></form>")
    magic = ""
    if "magic" in methods:
        magic = f"<a class=btn2 href='/auth/magic/request?next={_e(next_)}'>{_e(t('login.magic'))}</a>"
    oidc = (f"<a class=btn2 href='/auth/oidc/start?next={_e(next_)}'>{_e(cfg.oidc_name)}</a>"
            if "oidc" in methods else "")
    saml = (f"<a class=btn2 href='/auth/saml/login?next={_e(next_)}'>{_e(cfg.saml_name)}</a>"
            if "saml" in methods else "")
    passkey = f"<button class=btn2 type=button id=pkbtn>{_e(t('login.passkey'))}</button>" if "passkey" in methods else ""
    others = oidc + saml + passkey + magic
    sep = _or if others and (pw or pin) else ""
    links = []
    if cfg.allow_signup:
        links.append(f"<a href='/auth/register?next={_e(next_)}'>{_e(t('login.signup'))}</a>")
    if getattr(cfg, "password_reset_enabled", False) and cfg.magiclink_enabled:
        links.append(f"<a href='/auth/forgot'>{_e(t('login.forgot'))}</a>")
    signup = f"<div class=hint>{' · '.join(links)}</div>" if links else ""
    js = (_csrf_js(auth) + _PASSKEY_LOGIN_JS.replace("__NEXT__", _e(next_))) if "passkey" in methods else ""
    body = f"<h1>{_e(cfg.rp_name)}</h1>{warn}{err}{pw}{pin}{sep}{others}{signup}{js}"
    return _page(auth, t("login.submit"), body, top=_demobar(auth))


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
            f"<div class=hint><a href='/auth/logout'>{_e(t('cancel'))}</a></div>")
    return _page(auth, t("totp.title"), body)


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
    .tsmain{max-width:640px;margin:0 auto;padding:24px;display:block}
    .tsmain header{display:flex;justify-content:space-between;align-items:center;margin-bottom:18px}
    .tsmain header h1{font-size:20px;margin:0}
    .tsmain .sec{background:var(--ts-surface);border:1px solid var(--ts-line);
         border-radius:var(--ts-radius);padding:16px;margin-bottom:14px}
    .tsmain .sec h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;
         letter-spacing:.05em;margin:0 0 12px}
    .tsmain .sec small{text-transform:none;letter-spacing:0}
    .tsmain .sec input{margin:4px 0}
    .tsmain .sec button,.tsmain .btnlink{width:auto;display:inline-block;margin:8px 6px 0 0;padding:9px 14px}
    .tsmain button.warn{background:var(--ts-danger)}
    .tsmain .btnlink{background:var(--ts-neutral);color:var(--ts-neutral-ink);border-radius:8px;
         text-decoration:none;padding:9px 14px}
    .tsmain .msg{margin-left:8px;font-size:12px;color:var(--ts-muted)}
    .tsmain .msg.good,.tsmain .ok{color:var(--ts-ok-ink);background:none;padding:0}
    .tsmain .msg.bad,.tsmain .bad{color:var(--ts-err-ink)}
    .tsmain ul{list-style:none;padding:0;margin:0 0 8px}
    .tsmain li{padding:4px 0;font-size:13px;border-bottom:1px solid var(--ts-line-soft)}
    .tsmain a{color:var(--ts-link)}
    """
    pkjs = _PASSKEY_REGISTER_JS if "passkey" in methods else ""
    body = (f"<header><h1>{_e(t('acc.title'))} · {name}</h1>"
            f"<div>{admin_link} <a href='/auth/logout'>{_e(t('logout'))}</a></div></header>"
            + "".join(sections) + _ACCOUNT_JS + pkjs)
    # Account nutzt volle Breite (kein Card) + Account-CSS + Branding
    return _page(auth, t("acc.title"), f"<style>{css}</style>{body}", card=False)


_ACCOUNT_JS = """
<script>
function tsCsrf(){return (document.cookie.match(/(?:^|; )tinysesam_csrf=([^;]+)/)||[])[1]||''}
const J=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':tsCsrf()},body:JSON.stringify(b||{})});
const say=(id,t,good)=>{const e=document.getElementById(id);if(e){e.textContent=t;e.className='msg '+(good?'good':'bad')}};
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
  el.innerHTML=ks.map(k=>`<li>${k.prefix} ${k.name||''} ${k.revoked?'<span class=bad>(widerrufen)</span>':`<button class=warn onclick=revk(${k.id})>widerrufen</button>`}</li>`).join('')||'<li>keine</li>'}
async function mkkey(){const r=await (await J('/auth/apikeys',{name:key_name.value})).json();
  if(r.key)prompt('API-Key — JETZT kopieren:',r.key);loadkeys()}
async function revk(id){await J('/auth/apikeys/'+id+'/revoke');loadkeys()}
async function loadpk(){const el=document.getElementById('pklist');if(!el)return;
  const ps=await (await fetch('/auth/passkey/list')).json();
  el.innerHTML=ps.map(p=>`<li>${p.name||'Passkey'} <button class=warn onclick=delpk(${p.id})>löschen</button></li>`).join('')||'<li>keine</li>'}
async function delpk(id){await J('/auth/passkey/delete',{id});loadpk()}
async function loadsess(){const el=document.getElementById('sesslist');if(!el)return;
  const ss=await (await fetch('/auth/sessions')).json();
  el.innerHTML=ss.map(s=>`<li>${new Date(s.created_at*1000).toLocaleString('de-DE')} · ${esc0(s.method)} · ${esc0(s.ip)||'?'} ${s.current?'<b>(diese)</b>':''}<br><small class=msg>${esc0(s.user_agent)}</small></li>`).join('')||'<li>keine</li>'}
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
        return _page(auth, t("reg.verify_title"), body)
    cfg = auth.cfg
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    emailro = " readonly" if ctx.get("invite") and ctx.get("email") else ""
    # Die Felder folgen der Config: im E-Mail-Modus ist die Adresse die Kennung; ein optionales
    # E-Mail-Feld erscheint nur, wenn die App überhaupt etwas damit anfängt (Login-Link,
    # Passwort-vergessen, Bestätigung). Sonst fragt man nach Daten, die man nie benutzt.
    email_mode = cfg.login_identifier == "email"
    email_used = (cfg.signup_require_email or email_mode or cfg.magiclink_enabled
                  or getattr(cfg, "password_reset_enabled", False) or cfg.signup_verify_email)
    emailreq = " required" if (cfg.signup_require_email or email_mode) else ""
    user_field = ("" if email_mode else
                  f"<label>{_e(t('reg.user'))}</label><input name=username required autofocus autocomplete=username autocapitalize=none autocorrect=off spellcheck=false>")
    body = (f"<h1>{_e(t('reg.title'))}</h1>{err}"
            f"<form method=post action='/auth/register'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>"
            f"<input type=hidden name=invite value='{_e(ctx.get('invite', ''))}'>{_cf(ctx)}"
            f"{user_field}"
            + (f"<label>{_e(t('reg.email'))}</label>"
               f"<input name=email type=email value='{_e(ctx.get('email', ''))}'{emailro}{emailreq}"
               f"{' autofocus' if email_mode else ''} autocomplete=email>" if email_used else "") +
            f"<label>{_e(t('reg.password'))}</label><input name=password required type=password autocomplete=new-password>"
            f"<button type=submit>{_e(t('reg.submit'))}</button></form>"
            f"<div class=hint><a href='/auth/login'>{_e(t('reg.have'))}</a></div>")
    return _page(auth, t("reg.title"), body)


def _magic_request(auth, ctx) -> str:
    """ctx: next, sent (bool), error. E-Mail-Adresse für den Login-Link."""
    t = auth.t
    lang = auth.cfg.lang
    if ctx.get("sent"):
        body = (f"<h1>{_e(t('magic.sent_title'))}</h1>"
                f"<div class=ok>{_e(t('magic.sent'))}</div>"
                f"<div class=hint>{_e(t('magic.sent_hint'))}</div>"
                f"<a class=btn2 href='/auth/login'>{_e(t('magic.back_login'))}</a>")
        return _page(auth, t("magic.sent_title"), body)
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('magic.title'))}</h1>{err}"
            f"<div class=hint>{_e(t('magic.hint'))}</div>"
            f"<form method=post action='/auth/magic/request'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label>"
            f"<input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('magic.send'))}</button></form>"
            f"<div class=hint><a href='/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("magic.title"), body)


def _forgot(auth, ctx) -> str:
    """ctx: sent (bool), error. E-Mail für den Reset-Link."""
    t = auth.t
    lang = auth.cfg.lang
    if ctx.get("sent"):
        return _page(auth, t("magic.sent_title"),
                      f"<h1>{_e(t('magic.sent_title'))}</h1>"
                      f"<div class=ok>{_e(t('magic.sent'))}</div>"
                      f"<a class=btn2 href='/auth/login'>{_e(t('magic.to_login'))}</a>")
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    body = (f"<h1>{_e(t('forgot.title'))}</h1>{err}"
            f"<div class=hint>{_e(t('forgot.hint'))}</div>"
            f"<form method=post action='/auth/forgot'>{_cf(ctx)}"
            f"<label>{_e(t('magic.email'))}</label><input name=email type=email autocomplete=email autofocus>"
            f"<button type=submit>{_e(t('forgot.send'))}</button></form>"
            f"<div class=hint><a href='/auth/login'>{_e(t('back'))}</a></div>")
    return _page(auth, t("forgot.title"), body)


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
    return _page(auth, t("reset.title"), body)


def _error(auth, ctx) -> str:
    """ctx: code, message. Themed Fehlerseite (403/404/429/500 …). Über set_template('error') ersetzbar."""
    t = auth.t
    code = ctx.get("code", 500)
    msg = ctx.get("message") or t("error.oops")
    body = (f"<h1 style='font-size:52px;margin:.1em 0'>{_e(code)}</h1>"
            f"<div class=hint style='font-size:14px;margin-top:0'>{_e(msg)}</div>"
            f"<a class=btn2 href='/'>{_e(t('error.home'))}</a>")
    return _page(auth, str(code), body)


def _magic_invalid(auth, ctx) -> str:
    t = auth.t
    body = (f"<h1>{_e(t('magic.invalid_title'))}</h1>"
            f"<div class=err>{_e(t('magic.invalid'))}</div>"
            f"<a class=btn2 href='/auth/login'>{_e(t('magic.to_login'))}</a>")
    return _page(auth, t("magic.invalid_title"), body)


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
    return _page(auth, str(ctx.get("label") or lbl), body)


def _stepup_field(auth, method, first) -> str:
    """Ein Eingabefeld je Step-up-Verfahren. `first` bekommt den Fokus."""
    t = auth.t
    fc = " autofocus" if first else ""
    if method == "totp":
        return (f"<label>{_e(t('totp.label'))}</label>"
                f"<input name=code class=code inputmode=numeric autocomplete=one-time-code{fc} maxlength=6>")
    if method == "pin":
        return (f"<label>{_e(t('reauth.pin'))}</label>"
                f"<input name=pin type=password inputmode=numeric autocomplete=off class=code{fc}>")
    return (f"<label>{_e(t('reauth.pw'))}</label>"
            f"<input name=password type=password autocomplete=current-password{fc}>")


def _reauth(auth, ctx) -> str:
    """ctx: next, error, username, methods (Liste aus auth.stepup_options).
    Sudo-Frische: erneut einen Faktor bestätigen (Step-up)."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    methods = ctx.get("methods") or ["password"]
    fields = f"<div class=or>{_e(t('or'))}</div>".join(
        _stepup_field(auth, m, i == 0) for i, m in enumerate(methods))
    body = (f"<h1>{_e(t('reauth.title'))}</h1>"
            f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>{err}"
            f"<form method=post action='/auth/reauth'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{fields}<button type=submit>{_e(t('reauth.submit'))}</button></form>"
            f"<div class=hint><a href='/auth/logout'>{_e(t('logout'))}</a></div>")
    return _page(auth, t("reauth.title"), body)


def _pin(auth, ctx) -> str:
    """ctx: next, error, username(optional). PIN-Eingabe — ohne Benutzerfeld, wenn schon eingeloggt."""
    t = auth.t
    err = f"<div class=err>{_e(ctx.get('error'))}</div>" if ctx.get("error") else ""
    known = bool(ctx.get("username"))
    id_label, id_ac = _ident(auth)
    user_field = ("" if known else
                  f"<label>{_e(id_label)}</label><input name=username autofocus autocomplete={id_ac} autocapitalize=none autocorrect=off spellcheck=false>")
    hint = (f"<div class=hint>{_e(t('reauth.hint', user=ctx.get('username')))}</div>" if known else "")
    body = (f"<h1>{_e(t('pin.title'))}</h1>{hint}{err}"
            f"<form method=post action='/auth/pin'>"
            f"<input type=hidden name=next value='{_e(ctx.get('next', '/'))}'>{_cf(ctx)}"
            f"{user_field}"
            f"<label>{_e(t('login.pin'))}</label>"
            f"<input name=pin type=password inputmode=numeric autocomplete=off class=code"
            f"{' autofocus' if known else ''}>"
            f"<button type=submit>{_e(t('login.pin_submit'))}</button></form>"
            f"<div class=hint><a href='{_e(auth.cfg.login_path)}'>{_e(t('back'))}</a></div>")
    return _page(auth, t("pin.title"), body, top=_demobar(auth, pin=True))


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
    return _page(auth, t("setup.title"), body)


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
    "pin": _pin,
    "resource_unlock": _resource_unlock,
    "account": _account,
    "register": _register,
    "magic_request": _magic_request,
    "magic_invalid": _magic_invalid,
    "error": _error,
    "forgot": _forgot,
    "reset": _reset,
    "totp_setup": _totp_setup,
}
