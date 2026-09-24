"""Owner-Modell (PO-Entscheid 2026-09-24): Owner sind Admins, die sich nicht löschen, sperren oder
entmachten lassen. Die Rolle lässt sich weitergeben, mehrere können Owner sein, es gibt immer
mindestens einen, und nur ein Owner vergibt sie — oder ändert ein Owner-Konto.
"""
from __future__ import annotations

import io
import sqlite3
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, StateError, TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Owner — nicht löschbar, weitergebbar, mindestens einer")
PW = "Owner-Test-Passwort-1"


def _app(**cfg):
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def _client(app, name):
    c = TestClient(app)
    c.post("/auth/login", data={"username": name, "password": PW}, follow_redirects=False)
    return c


# ── Bootstrap: der erste Admin ist der erste Owner ──────────────────────────────────────
auth, app = _app()
r.check("ensure_admin legt den ersten Admin an — und er ist Owner",
        auth.ensure_admin("gruender", PW) and auth.store.get_user_by_name("gruender")["is_owner"] == 1)
auth_c, _ = _app()
kandidat = auth_c.create_user("claimer", password=PW)
token = auth_c.admin_claim_token()
r.check("… ebenso über /auth/claim-admin (Einmal-Token)",
        auth_c.consume_admin_claim(token, auth_c.get_user(kandidat))
        and auth_c.store.get_user(kandidat)["is_owner"] == 1)

# ── Bestand: Admins ohne Owner → der älteste Hand-Admin wird Owner ─────────────────────
pfad = str(Path(tempfile.mkdtemp()) / "bestand.db")
alt, _ = _app(db_path=pfad)
alt.create_user("idp-admin", password=PW)
alt.store._exec("UPDATE users SET is_admin=2 WHERE username='idp-admin'")      # vom IdP, älter
alt.create_user("hand-admin", password=PW, is_admin=True)
alt.create_user("zweit-admin", password=PW, is_admin=True)
alt.store._exec("UPDATE users SET is_owner=0")
alt.store.db.close()
neu, _ = _app(db_path=pfad)
owner = [u["username"] for u in neu.store.list_users() if u["is_owner"]]
r.check("Bestand ohne Owner: der älteste von Hand gesetzte Admin wird Owner (nicht der IdP-Admin)",
        owner == ["hand-admin"], str(owner))
r.check("… mit Zeile im Audit-Log",
        any(z["event"] == "owner_grant" and "bestand" in (z["detail"] or "") for z in neu.store.recent_audit(20)))

# ── Schutz: nicht löschbar, nicht sperrbar, nicht entmachtbar ──────────────────────────
auth, app = _app()
auth.ensure_admin("chefin", PW)
chefin = auth.store.get_user_by_name("chefin")
admin2 = auth.create_user("admin2", password=PW, is_admin=True)
try:
    auth.delete_user(chefin["id"])
    geloescht = True
except StateError:
    geloescht = False
r.check("ein Owner lässt sich nicht löschen (auch über die Python-API)", not geloescht)
ca = _client(app, "admin2")            # ein Admin, aber kein Owner
co = _client(app, "chefin")            # der Owner
# Gegenprobe: Der Admin ohne Owner-Rolle ist wirklich angemeldet und darf, was ein Admin darf —
# sonst wären alle 403 unten auch ohne Owner-Schutz grün (abgewiesen, weil gar nicht angemeldet).
normalo = auth.create_user("normalo", password=PW)
r.check("Gegenprobe: der Admin ohne Owner-Rolle ist angemeldet und setzt einem normalen Konto ein Passwort",
        ca.get("/auth/admin/api/users").status_code == 200
        and ca.post(f"/auth/admin/api/users/{normalo}/password", json={"password": "Normales-Neues-Pw-1"}).status_code == 200)
r.check("im Panel: löschen → abgewiesen",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/delete").status_code in (403, 409))
r.check("… sperren → abgewiesen",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/disable", json={"disabled": True}).status_code in (400, 403))
r.check("… entmachten (Admin-Haken weg) → abgewiesen",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/roles", json={"roles": [], "is_admin": False}).status_code
        in (400, 403))
r.check("… auch der Owner selbst kann sich nicht sperren oder entmachten, solange er Owner ist",
        co.post(f"/auth/admin/api/users/{chefin['id']}/roles", json={"roles": [], "is_admin": False}).status_code == 400)
r.check("Owner-Konto bleibt, was es war", auth.store.get_user(chefin["id"])["is_admin"] == 1
        and not auth.store.get_user(chefin["id"])["disabled"])

# ── Nur ein Owner ändert ein Owner-Konto (sonst: Passwort setzen und selbst Owner sein) ─
r.check("ein Admin ohne Owner-Rolle setzt dem Owner kein Passwort",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/password", json={"password": "Uebernahme-Versuch-1"}).status_code == 403
        and auth.check_password("chefin", PW) is not None)
r.check("… stellt ihm keinen API-Key aus",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/keys", json={"name": "x"}).status_code == 403)
r.check("… löscht ihm keinen Passkey",
        ca.post(f"/auth/admin/api/users/{chefin['id']}/passkeys/1/delete").status_code == 403)
r.check("… und vergibt die Owner-Rolle nicht (auch nicht an sich selbst)",
        ca.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": True}).status_code == 403
        and not auth.store.get_user(admin2)["is_owner"])

# ── Weitergeben, mehrere, mindestens einer ─────────────────────────────────────────────
r.check("der Owner macht einen anderen zum Owner",
        co.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": True}).status_code == 200
        and auth.store.owner_count() == 2)
r.check("… und gibt seine Rolle dann ab (es bleibt einer)",
        co.post(f"/auth/admin/api/users/{chefin['id']}/owner", json={"owner": False}).status_code == 200
        and auth.store.owner_count() == 1)
co2 = _client(app, "admin2")
r.check("der letzte Owner kann seine Rolle nicht abgeben",
        co2.post(f"/auth/admin/api/users/{admin2}/owner", json={"owner": False}).status_code == 400
        and auth.store.owner_count() == 1)
try:
    auth.set_owner(admin2, False)
    letzter = False
except StateError:
    letzter = True
r.check("… auch nicht über die Python-API (StateError)", letzter)
dienst = auth.create_user("dienst", is_service=True)
try:
    auth.set_owner(dienst, True)
    dienst_owner = True
except ConfigError:
    dienst_owner = False
r.check("ein Service-Konto wird nicht Owner (es kann sich nicht anmelden)", not dienst_owner)
r.check("die Benutzerliste im Panel zeigt, wer Owner ist",
        any(u.get("is_owner") for u in co2.get("/auth/admin/api/users").json()))

# ── Owner und Identity Provider (H-5) ──────────────────────────────────────────────────
idp = auth.create_user("idp-nutzer", password=PW)
auth.apply_idp_groups(idp, ["admins"], {"admins": "__admin__"})
co2.post(f"/auth/admin/api/users/{idp}/owner", json={"owner": True})
auth.apply_idp_groups(idp, [], {"admins": "__admin__"})
r.check("ein Owner, der sein Admin-Recht vom IdP hatte, behält es, wenn der IdP die Gruppe nimmt",
        auth.store.get_user(idp)["is_admin"] == 1 and auth.store.get_user(idp)["is_owner"] == 1)

# ── Befunde aus dem Angriff auf die zweite Runde ───────────────────────────────────────
# Fund 1: Ein vom IdP vergebener Admin (2) wird beim nächsten Start NICHT Owner — sonst entzöge
# ihm kein Provider mehr das Recht.
pfad_i = str(Path(tempfile.mkdtemp()) / "idp.db")
idp_a, _ = _app(db_path=pfad_i)
idp_uid = idp_a.create_user("nur-idp-admin", password=PW)
idp_a.apply_idp_groups(idp_uid, ["admins"], {"admins": "__admin__"})
idp_a.store.db.close()
idp_b, _ = _app(db_path=pfad_i)
r.check("Fund 1: ein vom IdP vergebener Admin wird beim Neustart nicht Owner (bleibt entziehbar)",
        idp_b.store.get_user(idp_uid)["is_owner"] == 0 and idp_b.store.get_user(idp_uid)["is_admin"] == 2)
idp_b.apply_idp_groups(idp_uid, [], {"admins": "__admin__"})
r.check("… und der Provider nimmt ihm das Recht weiterhin", not idp_b.store.get_user(idp_uid)["is_admin"])
idp_b.store.db.close()
# Fund 2: ein gesperrter Hand-Admin wird nicht Owner, ein aktiver schon.
pfad_g = str(Path(tempfile.mkdtemp()) / "gesperrt.db")
g_a, _ = _app(db_path=pfad_g)
alt_admin = g_a.create_user("gefeuert", password=PW, is_admin=True)
aktiv_admin = g_a.create_user("aktiv", password=PW, is_admin=True)
g_a.store._exec("UPDATE users SET is_owner=0")
g_a.store._exec("UPDATE users SET disabled=2 WHERE id=?", (alt_admin,))
g_a.store.db.close()
g_b, _ = _app(db_path=pfad_g)
r.check("Fund 2: im Bestand wird der älteste AKTIVE Hand-Admin Owner, nicht ein gesperrter",
        g_b.store.get_user(aktiv_admin)["is_owner"] == 1 and g_b.store.get_user(alt_admin)["is_owner"] == 0)
g_b.store.db.close()
# Fund 3: ein Admin ohne Owner-Rolle widerruft weder Keys noch Sitzungen des Owners.
auth3, app3 = _app()
auth3.ensure_admin("owner3", PW)
o3 = auth3.store.get_user_by_name("owner3")["id"]
auth3.create_user("admin3", password=PW, is_admin=True)
key3 = auth3.create_api_key(o3, name="ci")
c_owner3 = _client(app3, "owner3")
c_admin3 = _client(app3, "admin3")
r.check("Fund 3: ein Admin ohne Owner-Rolle widerruft keinen Key des Owners",
        c_admin3.post(f"/auth/admin/api/keys/{key3['id']}/revoke").status_code == 403
        and auth3.verify_api_key(key3["key"])[0] is not None)
r.check("… und beendet seine Sitzungen nicht (weder je Konto noch je Handle)",
        c_admin3.post("/auth/admin/api/sessions/revoke", json={"user_id": o3}).status_code == 403
        and c_admin3.post("/auth/admin/api/sessions/revoke",
                          json={"token": auth3.store.list_sessions(o3)[0]["token_hash"]}).status_code == 403
        and c_owner3.get("/auth/me").status_code == 200)
# Fund 12: auch der Code-Weg sperrt keinen Owner, und gc() löscht keinen.
try:
    auth3.store.set_disabled(o3, True, durch_betreiber=True)
    code_sperre = True
except StateError:
    code_sperre = False
r.check("Fund 12: `store.set_disabled` sperrt keinen Owner (StateError)", not code_sperre)
wartend = auth3.create_user("wartend", password=PW, email="wartend@example.com")
auth3.store.set_disabled(wartend, True)
auth3.create_magic_token("verify_email", user_id=wartend)
auth3.store._exec("UPDATE magic_token SET expires_at = 1 WHERE user_id=?", (wartend,))
auth3.store._exec("UPDATE users SET is_owner=1 WHERE id=?", (wartend,))        # konstruiert: wartender Owner
auth3.gc()
r.check("… und `gc()` räumt keinen Owner ab, auch keinen, der auf eine Bestätigung wartet",
        auth3.store.get_user(wartend) is not None)

# ── Notweg über das CLI ────────────────────────────────────────────────────────────────
from tinysesam.__main__ import main as _cli  # noqa: E402
notfall = auth.create_user("notfall", password=PW)
_code = 0
with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
    try:
        _cli(["owner", "--db", auth.cfg.db_path, "notfall"])
    except SystemExit as e:
        _code = e.code or 0
r.check("`tinysesam owner` macht ein Konto zum Owner (wenn keiner mehr herankommt)",
        _code == 0 and auth.store.get_user(notfall)["is_owner"] == 1)
with sqlite3.connect(auth.cfg.db_path) as _db:
    _zeile = _db.execute("SELECT detail FROM audit WHERE event='owner_grant' ORDER BY id DESC LIMIT 1").fetchone()
r.check("… mit Zeile im Audit-Log", _zeile is not None and "cli" in (_zeile[0] or ""))
# (Mutationsproben: die Owner-Prüfung in `delete_user` streichen → „nicht löschen" rot;
#  `owner_schutz` leer → „kein Passwort/Key/Passkey" rot; `owner_count(ohne=…) == 0`-Prüfung in
#  `set_owner` streichen → „der letzte Owner" rot; `_erster_owner` in den Bootstrap-Wegen
#  streichen → erste zwei rot; in `Store.set_owner` `is_admin=1` streichen → „IdP … behält es" rot.)

sys.exit(r.done())
