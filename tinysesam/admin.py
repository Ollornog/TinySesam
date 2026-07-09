"""Admin-Panel als eigenständiger, montierbarer Router.

    auth.admin_router()                                       # APIRouter, RELATIVE Pfade
    app.include_router(auth.admin_router(), prefix="/admin")  # frei wählbarer Pfad
    # oder auf Sub-App / eigenem Port / Subdomain mounten (Host-Routing der App)

Standardmäßig mountet `auth.router()` es zusätzlich unter `config.admin_path` (Default /auth/admin).
`admin_ui_enabled=False` → nur die JSON-API (`/api/*`), damit die UI in ein bestehendes Panel
eingebettet werden kann. Die eingebaute UI ermittelt ihre Basis-URL selbst → läuft an jedem
Mountpunkt. Nur Admins.
"""
from __future__ import annotations
import json

from fastapi import APIRouter, Request, HTTPException
from fastapi.responses import HTMLResponse

from .store import norm_email, valid_email
from .templates import brand, favicon_link
from .theme import TOKENS


def build_admin_router(auth) -> APIRouter:
    cfg = auth.cfg
    ar = APIRouter(tags=["admin"])

    def guard(request: Request):
        # Admin + (optional) Step-up-MFA. Browser-Seitenaufruf → Redirect zu Login/Reauth;
        # JSON-/fetch-Aufrufe → 401/403 (Panel-UI lädt nach Reauth neu).
        return auth._enforce(request, admin=True, mfa=cfg.admin_require_mfa)

    def uview(u):
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                "email": u["email"], "is_admin": bool(u["is_admin"]), "is_service": bool(u["is_service"]),
                "roles": json.loads(u["roles"] or "[]"), "disabled": bool(u["disabled"]), "created_at": u["created_at"]}

    def kview(k):
        return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
                "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"])}

    # ---------- Benutzer / Service-Accounts ----------
    @ar.get("/api/users")
    def users(request: Request):
        guard(request)
        return [uview(u) for u in auth.store.list_users()]

    @ar.post("/api/users")
    async def user_create(request: Request):
        guard(request)
        b = await auth.json_body(request)
        username = (b.get("username") or "").strip()
        email = norm_email(b.get("email"))
        if email and not valid_email(email):
            raise HTTPException(400, "E-Mail ungültig")
        if email and auth.store.email_taken(email):
            raise HTTPException(409, "E-Mail bereits vergeben")
        # Im E-Mail-Modus ist die Adresse die Kennung — Benutzername darf entfallen.
        if not username and cfg.login_identifier == "email" and not b.get("is_service"):
            username = email or ""
        if not username:
            raise HTTPException(400, "username nötig")
        if auth.store.get_user_by_name(username):
            raise HTTPException(409, "existiert schon")
        roles = b.get("roles") or []
        if b.get("is_service"):
            uid = auth.create_service(username, roles=roles, display_name=b.get("display_name"))
        else:
            uid = auth.create_user(username, password=b.get("password") or None,
                                   is_admin=bool(b.get("is_admin")), roles=roles,
                                   display_name=b.get("display_name"), email=email)
        auth.audit("user_create", detail=f"{username} service={bool(b.get('is_service'))}")
        return {"id": uid}

    @ar.post("/api/users/{uid}/disable")
    async def user_disable(request: Request, uid: int):
        me = guard(request)
        b = await auth.json_body(request)
        disabled = bool(b.get("disabled", True))
        if disabled and uid == me["id"]:
            raise HTTPException(400, "sich selbst nicht sperren")
        auth.store.set_disabled(uid, disabled)
        if disabled:
            auth.store.delete_user_sessions(uid)
        auth.audit("user_disable" if disabled else "user_enable", detail=f"uid={uid}")
        return {"ok": True}

    @ar.post("/api/users/{uid}/password")
    async def user_password(request: Request, uid: int):
        guard(request)
        b = await auth.json_body(request)
        if not b.get("password"):
            raise HTTPException(400, "password nötig")
        auth.set_password(uid, b["password"])
        auth.store.delete_user_sessions(uid)   # Admin-Reset → alle Sitzungen beenden (Re-Login erzwingen)
        auth.audit("user_password_reset", detail=f"uid={uid}")
        return {"ok": True}

    @ar.post("/api/users/{uid}/roles")
    async def user_roles(request: Request, uid: int):
        guard(request)
        b = await auth.json_body(request)
        auth.set_roles(uid, b.get("roles") or [])
        if "is_admin" in b:
            auth.store.set_admin(uid, bool(b["is_admin"]))
        auth.audit("user_roles", detail=f"uid={uid}")
        return {"ok": True}

    # ---------- API-Keys (je User) ----------
    @ar.get("/api/users/{uid}/keys")
    def user_keys(request: Request, uid: int):
        guard(request)
        return [kview(k) for k in auth.list_api_keys(uid)]

    @ar.post("/api/users/{uid}/keys")
    async def user_key_create(request: Request, uid: int):
        guard(request)
        b = await auth.json_body(request)
        return auth.create_api_key(uid, name=b.get("name"), expires_days=b.get("expires_days"), roles=b.get("roles"))

    @ar.post("/api/keys/{kid}/revoke")
    def key_revoke(request: Request, kid: int):
        guard(request)
        auth.revoke_api_key(kid)
        return {"ok": True}

    # ---------- Sitzungen ----------
    @ar.get("/api/sessions")
    def sessions(request: Request):
        guard(request)
        names = {u["id"]: u["username"] for u in auth.store.list_users()}
        return [{"full": s["token"], "user": names.get(s["user_id"], s["user_id"]), "method": s["method"],
                 "ip": s["ip"], "created_at": s["created_at"], "mfa_ok": bool(s["mfa_ok"])}
                for s in auth.store.list_sessions()]

    @ar.post("/api/sessions/revoke")
    async def session_revoke(request: Request):
        guard(request)
        b = await auth.json_body(request)
        if b.get("token"):
            auth.store.delete_session(b["token"])
        elif b.get("user_id"):
            auth.store.delete_user_sessions(int(b["user_id"]))
        auth.audit("session_revoke")
        return {"ok": True}

    # ---------- Einladungen (Magic-Invite) ----------
    if cfg.magiclink_enabled:
        @ar.post("/api/invite")
        async def invite(request: Request):
            guard(request)
            b = await auth.json_body(request)
            email = (b.get("email") or "").strip()
            base = cfg.base_url or str(request.base_url)
            res = auth.create_invite(email or None, base, roles=b.get("roles") or [],
                                     is_admin=bool(b.get("is_admin")), ttl_min=b.get("ttl_min"))
            return {"url": res["url"], "emailed": bool(email and auth.mail_configured())}

    # ---------- Geteilte Ressourcen-Geheimnisse ----------
    if cfg.resource_locks_enabled:
        @ar.get("/api/resources")
        def resources(request: Request):
            guard(request)
            return [{"name": r["name"], "kind": r["kind"], "label": r["label"], "created_at": r["created_at"]}
                    for r in auth.list_resource_secrets()]

        @ar.post("/api/resources")
        async def resource_set(request: Request):
            guard(request)
            b = await auth.json_body(request)
            name = (b.get("name") or "").strip()
            if not name or not b.get("secret"):
                raise HTTPException(400, "name + secret nötig")
            try:
                auth.set_resource_secret(name, b["secret"], kind=b.get("kind") or "pin", label=b.get("label"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            auth.audit("resource_set", detail=name)
            return {"ok": True}

        @ar.post("/api/resources/{name}/delete")
        def resource_delete(request: Request, name: str):
            guard(request)
            auth.remove_resource_secret(name)
            auth.audit("resource_delete", detail=name)
            return {"ok": True}

    # ---------- Härtung / Update / Audit ----------
    @ar.get("/api/security")
    def security_get(request: Request):
        guard(request)
        return auth.all_security()

    @ar.post("/api/security")
    async def security_set(request: Request):
        guard(request)
        for k, v in (await auth.json_body(request)).items():
            auth.set_security(k, v)
        auth.audit("security_update")
        return auth.all_security()

    @ar.get("/api/update")
    def update_get(request: Request):
        guard(request)
        return {"settings": auth.update_settings(), "status": auth.update_status()}

    @ar.post("/api/update/settings")
    async def update_set(request: Request):
        guard(request)
        b = await auth.json_body(request)
        if "mode" in b:
            auth.set_update_setting("mode", b["mode"])
        if "pin" in b:
            auth.set_update_setting("pin", b["pin"])
        return auth.update_settings()

    @ar.post("/api/update/run")
    def update_run(request: Request):
        guard(request)
        return auth.run_update()

    @ar.get("/api/audit")
    def audit(request: Request, limit: int = 100):
        guard(request)
        return [{"ts": a["ts"], "event": a["event"], "username": a["username"], "ip": a["ip"], "detail": a["detail"]}
                for a in auth.store.recent_audit(limit)]

    # ---------- eingebaute UI (optional) ----------
    if cfg.admin_ui_enabled:
        @ar.get("", response_class=HTMLResponse)
        def admin_page(request: Request):
            guard(request)
            warn = ""
            if cfg.https_mode == "warn" and not auth.is_secure(request):
                warn = ("<div class=warnbar>⚠ Unverschlüsselt (kein HTTPS) — Zugangsdaten gehen im Klartext. "
                        "Nur im vertrauenswürdigen Netz nutzen oder HTTPS davorschalten.</div>")
            # Mountpunkt → relative API-Basis
            resp = HTMLResponse(render_panel(auth, request.url.path.rstrip("/"), warn=warn))
            if cfg.csrf_enabled:
                import secrets as _s
                resp.set_cookie(cfg.csrf_cookie, _s.token_urlsafe(24), secure=cfg.cookie_secure,
                                samesite=cfg.cookie_samesite, path=cfg.cookie_path)
            return resp

    return ar


def render_panel(auth, base: str, warn: str = "") -> str:
    """Panel-HTML für eine gegebene API-Basis. Einziger Ort, an dem `_PAGE` befüllt wird —
    damit z.B. eine Demo-/Vorschau-Einbindung dieselbe UI zeigt wie das echte Panel."""
    cfg = auth.cfg
    return (_PAGE.replace("__TOKENS__", TOKENS)
            .replace("__BRANDHEAD__", getattr(cfg, "brand_head", "") or "")
            .replace("__HEADER__", brand(getattr(cfg, "brand_header", ""), auth))
            .replace("__FOOTER__", brand(getattr(cfg, "brand_footer", ""), auth))
            .replace("__RP__", cfg.rp_name).replace("__BASE__", base)
            .replace("__ICON__", favicon_link(getattr(cfg, "brand_icon", "")))
            .replace("__WARN__", warn).replace("__CSRFCK__", cfg.csrf_cookie)
            .replace("__ROLES__", json.dumps(list(cfg.available_roles)))
            .replace("__REQMAIL__", "true" if (cfg.signup_require_email or
                                              cfg.login_identifier == "email") else "false")
            .replace("__BRANDCSS__", getattr(cfg, "brand_css", "") or ""))


_PAGE = r"""<!doctype html><html lang=de><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">__ICON__<title>__RP__ — Admin</title>
<style>
__TOKENS__
/* Alles unter .tsadmin gekapselt — sonst faerbt es auf brand_header/brand_footer ab. */
*{box-sizing:border-box}
body{font-family:var(--ts-font);margin:0;background:var(--ts-bg);color:var(--ts-ink);
  min-height:100vh;display:flex;flex-direction:column}
.tsadmin{flex:1}
.tsadmin .warnbar{background:var(--ts-warn-bg);color:var(--ts-warn-ink);padding:8px 20px;font-size:13px;
  border-bottom:1px solid var(--ts-warn-line)}
.tsadmin header{padding:14px 20px;background:var(--ts-surface);border-bottom:1px solid var(--ts-line);
  display:flex;gap:14px;align-items:center}
.tsadmin header h1{font-size:17px;margin:0}
.tsadmin a{color:var(--ts-link);text-decoration:none}
.tsadmin .tabs{display:flex;gap:6px;padding:12px 20px 0;flex-wrap:wrap}
.tsadmin .tab{padding:7px 13px;border-radius:8px 8px 0 0;background:var(--ts-surface);cursor:pointer;
  font-size:14px;border:1px solid transparent;border-bottom:none}
.tsadmin .tab.on{background:var(--ts-surface-2);border-color:var(--ts-line);color:var(--ts-link)}
.tsadmin .wrap{max-width:1000px;margin:0 auto;padding:18px 20px}
.tsadmin table{width:100%;border-collapse:collapse;font-size:13px}
.tsadmin th{text-align:left;color:var(--ts-muted);font-weight:600}
.tsadmin td,.tsadmin th{padding:7px 8px;border-bottom:1px solid var(--ts-line-soft);white-space:nowrap}
.tsadmin button{cursor:pointer;background:var(--ts-accent);color:var(--ts-accent-ink);border:0;
  border-radius:6px;padding:6px 11px;font-size:13px}
.tsadmin button.sec{background:var(--ts-neutral);color:var(--ts-neutral-ink)}
.tsadmin button.warn{background:var(--ts-danger);color:#fff}
.tsadmin button.ok{background:var(--ts-success);color:#fff}
.tsadmin input,.tsadmin select{background:var(--ts-field-bg);color:var(--ts-ink);
  border:1px solid var(--ts-field-line);border-radius:6px;padding:6px 9px;font-size:13px}
.tsadmin .badge{padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600;
  background:var(--ts-chip);color:var(--ts-muted)}
.tsadmin .badge.red{background:var(--ts-err-bg);color:var(--ts-err-ink)}
.tsadmin .badge.grn{background:var(--ts-ok-bg);color:var(--ts-ok-ink)}
.tsadmin .badge.svc{background:var(--ts-info-bg);color:var(--ts-info-ink)}
.tsadmin .row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
.tsadmin .card{background:var(--ts-surface);border:1px solid var(--ts-line);
  border-radius:calc(var(--ts-radius) - 2px);padding:14px;margin-bottom:14px}
.tsadmin h2{font-size:13px;color:var(--ts-muted);text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
.tsadmin .muted{color:var(--ts-muted)}
.tsadmin code{background:var(--ts-field-bg);border:1px solid var(--ts-field-line);border-radius:5px;
  padding:2px 6px;font-size:12px}
__BRANDCSS__
</style>__BRANDHEAD__</head><body>
__HEADER__
<div class=tsadmin>
__WARN__
<header><h1>🧠 __RP__ · Admin</h1><a href="/">← App</a><a href="/auth/logout">Logout</a></header>
<div class=tabs id=tabs></div>
<div class=wrap id=view></div>
<script>
const B="__BASE__";                                    // Mountpunkt (frei wählbar) → relative API-Aufrufe
const ROLES=__ROLES__;                                 // bekannte Rollen/Gruppen (config.available_roles)
const REQMAIL=__REQMAIL__;                             // config.signup_require_email (E-Mail Pflicht)
const TABS=[["users","Benutzer"],["sessions","Sitzungen"],["security","Härtung"],["update","Update"],["audit","Audit"]];
let cur="users";
const g=(u)=>fetch(B+u).then(r=>r.json());
function tsCsrf(){return (document.cookie.match(/(?:^|; )__CSRFCK__=([^;]+)/)||[])[1]||''}
const p=(u,b)=>fetch(B+u,{method:"POST",headers:{"Content-Type":"application/json","X-CSRF-Token":tsCsrf()},body:JSON.stringify(b||{})}).then(r=>r.json());
const esc=s=>(s??"").toString().replace(/</g,"&lt;");
const dt=t=>t?new Date(t*1000).toLocaleString("de-DE"):"—";
function tabs(){document.getElementById("tabs").innerHTML=TABS.map(([k,l])=>`<div class="tab ${k==cur?'on':''}" onclick="go('${k}')">${l}</div>`).join("")}
function go(k){cur=k;tabs();({users:users,sessions:sessions,security:security,update:update,audit:audit})[k]()}
const V=h=>document.getElementById("view").innerHTML=h;

async function users(){
  const us=await g("/api/users");
  V(`<div class=card><h2>Neuer Benutzer / Service-Account</h2><div class=row>
    <input id=nu placeholder=Benutzername><input id=ne type=email placeholder="E-Mail${REQMAIL?'':' (optional)'}">
    <input id=np type=password placeholder="Passwort (leer=nur SSO/Key)">
    <input id=nr placeholder="Rollen, komma-getrennt" style=width:200px>
    <label><input type=checkbox id=na> Admin</label><label><input type=checkbox id=ns> Service/Daemon</label>
    <button onclick=mkuser()>Anlegen</button></div></div>
    <table><tr><th>User</th><th>E-Mail</th><th>Typ</th><th>Rollen</th><th>Status</th><th>Aktionen</th></tr>`+
    us.map(u=>`<tr><td><b>${esc(u.username)}</b></td>
      <td>${esc(u.email)||'<span class=muted>—</span>'}</td>
      <td>${u.is_admin?'<span class="badge grn">admin</span> ':''}${u.is_service?'<span class="badge svc">service</span>':'<span class=badge>user</span>'}</td>
      <td>${esc((u.roles||[]).join(", "))||'—'}</td>
      <td>${u.disabled?'<span class="badge red">gesperrt</span>':'<span class="badge grn">aktiv</span>'}</td>
      <td>
        <button class="${u.disabled?'ok':'warn'}" onclick="dis(${u.id},${!u.disabled})">${u.disabled?'Entsperren':'Sperren'}</button>
        <button class=sec onclick="pw(${u.id})">PW</button>
        <button class=sec onclick="roles(${u.id},'${esc((u.roles||[]).join(','))}',${u.is_admin?1:0})">Rollen</button>
        <button class=sec onclick="keys(${u.id},'${esc(u.username)}')">Keys</button>
      </td></tr><tr id=r${u.id}></tr><tr id=k${u.id}></tr>`).join("")+`</table>`);
}
async function mkuser(){const b={username:nu.value,email:ne.value,password:np.value,roles:nr.value.split(",").map(s=>s.trim()).filter(Boolean),is_admin:na.checked,is_service:ns.checked};
  if(REQMAIL&&!ns.checked&&!ne.value.trim())return alert("E-Mail nötig");
  const r=await p("/api/users",b);if(r.id)users();else alert(r.detail||"Fehler")}
async function dis(id,d){if(!confirm(d?"Zugang sperren?":"Entsperren?"))return;await p(`/api/users/${id}/disable`,{disabled:d});users()}
async function pw(id){const v=prompt("Neues Passwort:");if(v)await p(`/api/users/${id}/password`,{password:v})&&alert("gesetzt")}
async function roles(id,cur,isadmin){
  const have=new Set((cur||"").split(",").map(s=>s.trim()).filter(Boolean));
  const inner = ROLES.length
    ? ROLES.map(r=>`<label style="margin-right:12px"><input type=checkbox class="rc_${id}" value="${esc(r)}" ${have.has(r)?"checked":""}> ${esc(r)}</label>`).join("")
    : `<input id="rf${id}" value="${esc(cur)}" placeholder="Rollen, komma-getrennt" style=width:280px>`;
  document.getElementById("r"+id).innerHTML=`<td colspan=5><div class=card><h2>Rollen / Gruppen</h2>
    <div class=row>${inner||"<span class=muted>keine Rollen definiert</span>"}</div>
    <div class=row><label><input type=checkbox id="ra${id}" ${isadmin?"checked":""}> Admin</label>
      <button onclick="saveroles(${id})">Speichern</button>
      <button class=sec onclick="document.getElementById('r'+${id}).innerHTML=''">Abbrechen</button></div></div></td>`;
}
async function saveroles(id){
  const roles = ROLES.length
    ? [...document.querySelectorAll(".rc_"+id+":checked")].map(c=>c.value)
    : (document.getElementById("rf"+id).value||"").split(",").map(s=>s.trim()).filter(Boolean);
  await p(`/api/users/${id}/roles`,{roles,is_admin:document.getElementById("ra"+id).checked});users();
}
async function keys(id,name){const ks=await g(`/api/users/${id}/keys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>API-Keys · ${esc(name)}</h2>
    <div class=row><input id=kn placeholder="Key-Name"><input id=ke type=number placeholder="Ablauf Tage (leer=nie)" style=width:150px>
    <button onclick="mkkey(${id})">Key erzeugen</button></div>
    <table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?'<span class="badge red">widerrufen</span>':'<span class="badge grn">aktiv</span>'}</td>
      <td>zuletzt: ${dt(k.last_used)}</td><td>${k.expires_at?'läuft ab '+dt(k.expires_at):'unbefristet'}</td>
      <td>${k.revoked?'':`<button class=warn onclick="revk(${k.id},${id},'${esc(name)}')">Widerrufen</button>`}</td></tr>`).join("")+`</table></div></td>`}
async function mkkey(id){const r=await p(`/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  if(r.key)prompt("API-Key — JETZT kopieren, wird nicht erneut angezeigt:",r.key);keys(id,"")}
async function revk(kid,uid,name){if(confirm("Key widerrufen (sperren)?")){await p(`/api/keys/${kid}/revoke`);keys(uid,name)}}

async function sessions(){const ss=await g("/api/sessions");
  V(`<table><tr><th>User</th><th>Methode</th><th>IP</th><th>seit</th><th>2FA</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn onclick="revs('${s.full}')">Beenden</button></td></tr>`).join("")+`</table>`)}
async function revs(t){await p("/api/sessions/revoke",{token:t});sessions()}

async function security(){const s=await g("/api/security");
  V(`<div class=card><h2>Härtung (Brute-Force / Rate-Limit)</h2>`+
    Object.entries(s).map(([k,v])=>`<div class=row><label style=width:230px>${k}</label><input id=s_${k} value=${v} type=number style=width:120px></div>`).join("")+
    `<div class=row><button onclick='savesec(${JSON.stringify(Object.keys(s))})'>Speichern</button></div></div>`)}
async function savesec(keys){const b={};keys.forEach(k=>b[k]=parseInt(document.getElementById("s_"+k).value));await p("/api/security",b);alert("gespeichert")}

async function update(){const u=await g("/api/update");const st=u.status,se=u.settings;
  V(`<div class=card><h2>Update</h2>
    <div class=row>Installiert: <code>${esc(st.current)}</code> · Neueste: <code>${esc(st.latest||'?')}</code>
      ${st.available?'<span class="badge grn">Update verfügbar</span>':'<span class=badge>aktuell</span>'}</div>
    <div class=row><label style=width:120px>Modus</label><select id=um><option value=manual ${se.mode=='manual'?'selected':''}>manuell</option><option value=auto ${se.mode=='auto'?'selected':''}>automatisch</option></select></div>
    <div class=row><label style=width:120px>Version-Pin</label><input id=up value="${esc(se.pin)}" placeholder="z.B. v0.3.0 (leer=neueste)"></div>
    <div class=row><button onclick=saveupd()>Einstellungen speichern</button>
      <button class="${st.available?'ok':'sec'}" onclick=runupd()>Jetzt aktualisieren</button></div>
    <div class=muted style=font-size:12px>${st.available?'Update verfügbar. ':''}Zieht die gepinnte bzw. neueste Version. Nach dem Update die App neu starten.</div></div>`)}
async function saveupd(){await p("/api/update/settings",{mode:um.value,pin:up.value});update()}
async function runupd(){if(!confirm("Update jetzt ziehen?"))return;const r=await p("/api/update/run");alert(r.ok?"OK — App neu starten":"Fehlgeschlagen:\n"+(r.output||"").slice(-400))}

async function audit(){const a=await g("/api/audit?limit=120");
  V(`<table><tr><th>Zeit</th><th>Event</th><th>User</th><th>IP</th><th>Detail</th></tr>`+
    a.map(e=>`<tr><td>${dt(e.ts)}</td><td>${esc(e.event)}</td><td>${esc(e.username)||'—'}</td><td>${esc(e.ip)||'—'}</td><td>${esc(e.detail)||''}</td></tr>`).join("")+`</table>`)}

tabs();users();
</script>
</div>__FOOTER__</body></html>"""
