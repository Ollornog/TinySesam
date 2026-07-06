"""Admin-Panel (nur Admins): Benutzer + Service-Accounts, API-Keys, Sitzungen, Härtung,
Update, Audit. UI unter /auth/admin, JSON-API unter /auth/admin/api/*. Alles guard-geschützt.
Sperren statt löschen: User werden deaktiviert, Keys/Sitzungen widerrufen."""
from __future__ import annotations
import json

from fastapi import Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse


def register_admin_routes(router, auth):
    cfg = auth.cfg

    def guard(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        if not auth.is_admin(u):
            raise HTTPException(403, "Adminrechte nötig")
        return u

    def uview(u):
        return {"id": u["id"], "username": u["username"], "display_name": u["display_name"],
                "email": u["email"], "is_admin": bool(u["is_admin"]), "is_service": bool(u["is_service"]),
                "roles": json.loads(u["roles"] or "[]"), "disabled": bool(u["disabled"]), "created_at": u["created_at"]}

    def kview(k):
        return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
                "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"])}

    # ---------- Benutzer / Service-Accounts ----------
    @router.get("/auth/admin/api/users")
    def users(request: Request):
        guard(request)
        return [uview(u) for u in auth.store.list_users()]

    @router.post("/auth/admin/api/users")
    async def user_create(request: Request):
        guard(request)
        b = await request.json()
        username = (b.get("username") or "").strip()
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
                                   display_name=b.get("display_name"), email=b.get("email"))
        auth.audit("user_create", detail=f"{username} service={bool(b.get('is_service'))}")
        return {"id": uid}

    @router.post("/auth/admin/api/users/{uid}/disable")
    async def user_disable(request: Request, uid: int):
        me = guard(request)
        b = await request.json()
        disabled = bool(b.get("disabled", True))
        if disabled and uid == me["id"]:
            raise HTTPException(400, "sich selbst nicht sperren")
        auth.store.set_disabled(uid, disabled)
        if disabled:
            auth.store.delete_user_sessions(uid)   # aktive Sitzungen sofort beenden
        auth.audit("user_disable" if disabled else "user_enable", detail=f"uid={uid}")
        return {"ok": True}

    @router.post("/auth/admin/api/users/{uid}/password")
    async def user_password(request: Request, uid: int):
        guard(request)
        b = await request.json()
        if not b.get("password"):
            raise HTTPException(400, "password nötig")
        auth.set_password(uid, b["password"])
        auth.audit("user_password_reset", detail=f"uid={uid}")
        return {"ok": True}

    @router.post("/auth/admin/api/users/{uid}/roles")
    async def user_roles(request: Request, uid: int):
        guard(request)
        b = await request.json()
        auth.set_roles(uid, b.get("roles") or [])
        if "is_admin" in b:
            auth.store.set_admin(uid, bool(b["is_admin"]))
        auth.audit("user_roles", detail=f"uid={uid}")
        return {"ok": True}

    # ---------- API-Keys (je User) ----------
    @router.get("/auth/admin/api/users/{uid}/keys")
    def user_keys(request: Request, uid: int):
        guard(request)
        return [kview(k) for k in auth.list_api_keys(uid)]

    @router.post("/auth/admin/api/users/{uid}/keys")
    async def user_key_create(request: Request, uid: int):
        guard(request)
        b = await request.json()
        return auth.create_api_key(uid, name=b.get("name"), expires_days=b.get("expires_days"),
                                   roles=b.get("roles"))   # 'key' EINMALIG im Klartext

    @router.post("/auth/admin/api/keys/{kid}/revoke")
    def key_revoke(request: Request, kid: int):
        guard(request)
        auth.revoke_api_key(kid)   # sperren, nicht löschen
        return {"ok": True}

    # ---------- Sitzungen ----------
    @router.get("/auth/admin/api/sessions")
    def sessions(request: Request):
        guard(request)
        names = {u["id"]: u["username"] for u in auth.store.list_users()}
        return [{"token": s["token"][:10] + "…", "full": s["token"], "user": names.get(s["user_id"], s["user_id"]),
                 "method": s["method"], "ip": s["ip"], "created_at": s["created_at"],
                 "expires_at": s["expires_at"], "mfa_ok": bool(s["mfa_ok"])}
                for s in auth.store.list_sessions()]

    @router.post("/auth/admin/api/sessions/revoke")
    async def session_revoke(request: Request):
        guard(request)
        b = await request.json()
        if b.get("token"):
            auth.store.delete_session(b["token"])
        elif b.get("user_id"):
            auth.store.delete_user_sessions(int(b["user_id"]))
        auth.audit("session_revoke")
        return {"ok": True}

    # ---------- Härtung ----------
    @router.get("/auth/admin/api/security")
    def security_get(request: Request):
        guard(request)
        return auth.all_security()

    @router.post("/auth/admin/api/security")
    async def security_set(request: Request):
        guard(request)
        for k, v in (await request.json()).items():
            auth.set_security(k, v)
        auth.audit("security_update")
        return auth.all_security()

    # ---------- Update ----------
    @router.get("/auth/admin/api/update")
    def update_get(request: Request):
        guard(request)
        return {"settings": auth.update_settings(), "status": auth.update_status()}

    @router.post("/auth/admin/api/update/settings")
    async def update_set(request: Request):
        guard(request)
        b = await request.json()
        if "mode" in b:
            auth.set_update_setting("mode", b["mode"])
        if "pin" in b:
            auth.set_update_setting("pin", b["pin"])
        return auth.update_settings()

    @router.post("/auth/admin/api/update/run")
    def update_run(request: Request):
        guard(request)
        return auth.run_update()

    # ---------- Audit ----------
    @router.get("/auth/admin/api/audit")
    def audit(request: Request, limit: int = 100):
        guard(request)
        return [{"ts": a["ts"], "event": a["event"], "username": a["username"], "ip": a["ip"], "detail": a["detail"]}
                for a in auth.store.recent_audit(limit)]

    # ---------- UI ----------
    @router.get("/auth/admin", response_class=HTMLResponse)
    def admin_page(request: Request):
        guard(request)
        return _PAGE.replace("__RP__", cfg.rp_name)


_PAGE = r"""<!doctype html><html lang=de><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>__RP__ — Admin</title>
<style>
:root{color-scheme:light dark}*{box-sizing:border-box}
body{font-family:system-ui,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
header{padding:14px 20px;background:#161a22;border-bottom:1px solid #262b36;display:flex;gap:14px;align-items:center}
header h1{font-size:17px;margin:0}a{color:#7dd3fc;text-decoration:none}
.tabs{display:flex;gap:6px;padding:12px 20px 0;flex-wrap:wrap}
.tab{padding:7px 13px;border-radius:8px 8px 0 0;background:#161a22;cursor:pointer;font-size:14px;border:1px solid transparent;border-bottom:none}
.tab.on{background:#1b2130;border-color:#262b36;color:#7dd3fc}
.wrap{max-width:1000px;margin:0 auto;padding:18px 20px}
table{width:100%;border-collapse:collapse;font-size:13px}th{text-align:left;color:#9aa4b2;font-weight:600}
td,th{padding:7px 8px;border-bottom:1px solid #20252f;white-space:nowrap}
button{cursor:pointer;background:#2563eb;color:#fff;border:0;border-radius:6px;padding:6px 11px;font-size:13px}
button.sec{background:#374151}button.warn{background:#b91c1c}button.ok{background:#15803d}
input,select{background:#0f1115;color:#e6e6e6;border:1px solid #303643;border-radius:6px;padding:6px 9px;font-size:13px}
.badge{padding:1px 7px;border-radius:20px;font-size:11px;font-weight:600;background:#22262e;color:#9aa4b2}
.badge.red{background:#3a1520;color:#f87171}.badge.grn{background:#12331f;color:#4ade80}.badge.svc{background:#12283a;color:#60a5fa}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin:10px 0}
.card{background:#161a22;border:1px solid #262b36;border-radius:10px;padding:14px;margin-bottom:14px}
h2{font-size:13px;color:#9aa4b2;text-transform:uppercase;letter-spacing:.05em;margin:0 0 10px}
code{background:#0f1115;border:1px solid #303643;border-radius:5px;padding:2px 6px;font-size:12px}
</style></head><body>
<header><h1>🧠 __RP__ · Admin</h1><a href="/">← App</a><a href="/auth/logout">Logout</a></header>
<div class=tabs id=tabs></div>
<div class=wrap id=view></div>
<script>
const TABS=[["users","Benutzer"],["sessions","Sitzungen"],["security","Härtung"],["update","Update"],["audit","Audit"]];
let cur="users";
const g=(u)=>fetch(u).then(r=>r.json());
const p=(u,b)=>fetch(u,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(b||{})}).then(r=>r.json());
const esc=s=>(s??"").toString().replace(/</g,"&lt;");
const dt=t=>t?new Date(t*1000).toLocaleString("de-DE"):"—";
function tabs(){document.getElementById("tabs").innerHTML=TABS.map(([k,l])=>`<div class="tab ${k==cur?'on':''}" onclick="go('${k}')">${l}</div>`).join("")}
function go(k){cur=k;tabs();({users:users,sessions:sessions,security:security,update:update,audit:audit})[k]()}
const V=h=>document.getElementById("view").innerHTML=h;

async function users(){
  const us=await g("/auth/admin/api/users");
  V(`<div class=card><h2>Neuer Benutzer / Service-Account</h2><div class=row>
    <input id=nu placeholder=Benutzername><input id=np type=password placeholder="Passwort (leer=nur SSO/Key)">
    <input id=nr placeholder="Rollen, komma-getrennt" style=width:200px>
    <label><input type=checkbox id=na> Admin</label><label><input type=checkbox id=ns> Service/Daemon</label>
    <button onclick=mkuser()>Anlegen</button></div></div>
    <table><tr><th>User</th><th>Typ</th><th>Rollen</th><th>Status</th><th>Aktionen</th></tr>`+
    us.map(u=>`<tr><td><b>${esc(u.username)}</b></td>
      <td>${u.is_admin?'<span class="badge grn">admin</span> ':''}${u.is_service?'<span class="badge svc">service</span>':'<span class=badge>user</span>'}</td>
      <td>${esc((u.roles||[]).join(", "))||'—'}</td>
      <td>${u.disabled?'<span class="badge red">gesperrt</span>':'<span class="badge grn">aktiv</span>'}</td>
      <td>
        <button class="${u.disabled?'ok':'warn'}" onclick="dis(${u.id},${!u.disabled})">${u.disabled?'Entsperren':'Sperren'}</button>
        <button class=sec onclick="pw(${u.id})">PW</button>
        <button class=sec onclick="roles(${u.id},'${esc((u.roles||[]).join(','))}',${u.is_admin})">Rollen</button>
        <button class=sec onclick="keys(${u.id},'${esc(u.username)}')">Keys</button>
      </td></tr><tr id=k${u.id}></tr>`).join("")+`</table>`);
}
async function mkuser(){const b={username:nu.value,password:np.value,roles:nr.value.split(",").map(s=>s.trim()).filter(Boolean),is_admin:na.checked,is_service:ns.checked};
  const r=await p("/auth/admin/api/users",b);if(r.id)users();else alert(r.detail||"Fehler")}
async function dis(id,d){if(!confirm(d?"Zugang sperren?":"Entsperren?"))return;await p(`/auth/admin/api/users/${id}/disable`,{disabled:d});users()}
async function pw(id){const v=prompt("Neues Passwort:");if(v)await p(`/auth/admin/api/users/${id}/password`,{password:v})&&alert("gesetzt")}
async function roles(id,cur,adm){const v=prompt("Rollen (komma-getrennt):",cur);if(v===null)return;const a=confirm("Admin?  OK=ja / Abbrechen=nein");await p(`/auth/admin/api/users/${id}/roles`,{roles:v.split(",").map(s=>s.trim()).filter(Boolean),is_admin:a});users()}
async function keys(id,name){const ks=await g(`/auth/admin/api/users/${id}/keys`);
  document.getElementById("k"+id).innerHTML=`<td colspan=5><div class=card><h2>API-Keys · ${esc(name)}</h2>
    <div class=row><input id=kn placeholder="Key-Name"><input id=ke type=number placeholder="Ablauf Tage (leer=nie)" style=width:150px>
    <button onclick="mkkey(${id})">Key erzeugen</button></div>
    <table>`+ks.map(k=>`<tr><td><code>${esc(k.prefix)}</code> ${esc(k.name||'')}</td><td>${k.revoked?'<span class="badge red">widerrufen</span>':'<span class="badge grn">aktiv</span>'}</td>
      <td>zuletzt: ${dt(k.last_used)}</td><td>${k.expires_at?'läuft ab '+dt(k.expires_at):'unbefristet'}</td>
      <td>${k.revoked?'':`<button class=warn onclick="revk(${k.id},${id},'${esc(name)}')">Widerrufen</button>`}</td></tr>`).join("")+`</table></div></td>`}
async function mkkey(id){const r=await p(`/auth/admin/api/users/${id}/keys`,{name:kn.value,expires_days:ke.value?parseInt(ke.value):null});
  if(r.key)prompt("API-Key — JETZT kopieren, wird nicht erneut angezeigt:",r.key);keys(id,"")}
async function revk(kid,uid,name){if(confirm("Key widerrufen (sperren)?")){await p(`/auth/admin/api/keys/${kid}/revoke`);keys(uid,name)}}

async function sessions(){const ss=await g("/auth/admin/api/sessions");
  V(`<table><tr><th>User</th><th>Methode</th><th>IP</th><th>seit</th><th>2FA</th><th></th></tr>`+
    ss.map(s=>`<tr><td><b>${esc(s.user)}</b></td><td>${esc(s.method)}</td><td>${esc(s.ip)}</td><td>${dt(s.created_at)}</td>
      <td>${s.mfa_ok?'✓':'—'}</td><td><button class=warn onclick="revs('${s.full}')">Beenden</button></td></tr>`).join("")+`</table>`)}
async function revs(t){await p("/auth/admin/api/sessions/revoke",{token:t});sessions()}

async function security(){const s=await g("/auth/admin/api/security");
  V(`<div class=card><h2>Härtung (Brute-Force / Rate-Limit)</h2>`+
    Object.entries(s).map(([k,v])=>`<div class=row><label style=width:230px>${k}</label><input id=s_${k} value=${v} type=number style=width:120px></div>`).join("")+
    `<div class=row><button onclick='savesec(${JSON.stringify(Object.keys(s))})'>Speichern</button></div></div>`)}
async function savesec(keys){const b={};keys.forEach(k=>b[k]=parseInt(document.getElementById("s_"+k).value));await p("/auth/admin/api/security",b);alert("gespeichert")}

async function update(){const u=await g("/auth/admin/api/update");const st=u.status,se=u.settings;
  V(`<div class=card><h2>Update</h2>
    <div class=row>Installiert: <code>${esc(st.current)}</code> · Neueste: <code>${esc(st.latest||'?')}</code>
      ${st.available?'<span class="badge grn">Update verfügbar</span>':'<span class=badge>aktuell</span>'}</div>
    <div class=row><label style=width:120px>Modus</label><select id=um><option value=manual ${se.mode=='manual'?'selected':''}>manuell</option><option value=auto ${se.mode=='auto'?'selected':''}>automatisch</option></select></div>
    <div class=row><label style=width:120px>Version-Pin</label><input id=up value="${esc(se.pin)}" placeholder="z.B. v0.3.0 (leer=neueste)"></div>
    <div class=row><button onclick=saveupd()>Einstellungen speichern</button>
      ${st.available?'<button class=ok onclick=runupd()>Jetzt aktualisieren</button>':''}</div>
    <div style=color:#9aa4b2;font-size:12px>Nach dem Update die App neu starten.</div></div>`)}
async function saveupd(){await p("/auth/admin/api/update/settings",{mode:um.value,pin:up.value});update()}
async function runupd(){if(!confirm("Update jetzt ziehen?"))return;const r=await p("/auth/admin/api/update/run");alert(r.ok?"OK — App neu starten":"Fehlgeschlagen:\n"+(r.output||"").slice(-400))}

async function audit(){const a=await g("/auth/admin/api/audit?limit=120");
  V(`<table><tr><th>Zeit</th><th>Event</th><th>User</th><th>IP</th><th>Detail</th></tr>`+
    a.map(e=>`<tr><td>${dt(e.ts)}</td><td>${esc(e.event)}</td><td>${esc(e.username)||'—'}</td><td>${esc(e.ip)||'—'}</td><td>${esc(e.detail)||''}</td></tr>`).join("")+`</table>`)}

tabs();users();
</script></body></html>"""
