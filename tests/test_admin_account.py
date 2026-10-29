"""The operator on another person's account: rename (panel, admin API, CLI) and the reason for a lock.

G13 (T-13, 2026-09-26): Until then only the owner of an account (self-service) or the embedding
service (`auth.change_username`) could rename it. Panel and CLI did not know the way — not even
for an identifier collision in the existing data that startup reports. Now: route
`POST <admin_path>/api/users/{id}/username` (owner protection, the same rules as
self-service, as operator: the "self-chosen" marker is cleared) and `tinysesam rename`.

G3 (limit b): The panel names the reason for a lock. Measured via the admin API — the
operator lock via the panel route, the lock of a pending confirmation via real
registration. This revealed: the panel did not deliver the text of the confirmation lock at all
(the key was missing from the list of panel texts, the badge stayed empty), and the button
"Make owner" was never wired up. The class is therefore checked: every text the
panel script reads, and every action a button names.
"""
from __future__ import annotations

import contextlib
import io
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import __main__ as cli_modul  # noqa: E402
from tinysesam.admin import _PAGE, panel_texts  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Admin on someone else's account — rename (G13), reason for the lock (G3)")
PW = "Konto-Test-Pw15"


def _app(**cfg):
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False,
                 csrf_enabled=False, base_url="http://testserver", lang="de",
                 admin_identifiers=["chef-reserviert"])
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def _client(app, name):
    c = TestClient(app)
    c.post("/auth/login", data={"username": name, "password": PW}, follow_redirects=False)
    return c


def _cli(*argv):
    aus = io.StringIO()
    code = 0
    try:
        with contextlib.redirect_stdout(aus), contextlib.redirect_stderr(aus):
            cli_modul.main(list(argv))
    except SystemExit as e:
        code = e.code or 0
    return code, aus.getvalue()


def _umbenannt(auth, uid):
    return [(z["username"], z["detail"]) for z in auth.store.recent_audit(200)
            if z["event"] == "username_changed" and z["username"] == auth.store.get_user(uid)["username"]]


# ── G13: admin API ──────────────────────────────────────────────────────────────────────────
auth, app = _app()
chefin = auth.create_user("chefin", password=PW, is_admin=True)
auth.set_owner(chefin, True)
helfer = auth.create_user("helfer", password=PW, is_admin=True)
anna = auth.create_user("anna", password=PW, email="anna@example.com", self_chosen_name=True)
bert = auth.create_user("bert", password=PW, email="bert@example.com")
ereignisse: list = []
auth.on_security_event = lambda e, konto, d: ereignisse.append((e, d))
ch = _client(app, "helfer")
id_vorher = auth._forward_response_headers(auth.get_user(anna))["Remote-Id"]
a = ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": "anna.neu"})
r.check("G13: an admin renames another account (admin API)",
        a.status_code == 200 and a.json() == {"ok": True, "username": "anna.neu"}
        and auth.store.get_user(anna)["username"] == "anna.neu", f"{a.status_code} {a.text[:160]}")
r.check("… the panel list shows the new name, Remote-Id stays the account ID",
        any(u["id"] == anna and u["username"] == "anna.neu" for u in ch.get("/auth/admin/api/users").json())
        and auth._forward_response_headers(auth.get_user(anna))["Remote-Id"] == id_vorher == str(anna))
_zeilen = _umbenannt(auth, anna)
r.check("… EXACTLY one audit row, as operator and with the admin as actor",
        _zeilen == [("anna.neu", "alt=anna durch=betreiber akteur=helfer")], str(_zeilen))
r.check("… the security event reaches the owner",
        ("username_changed", {"old": "anna", "new": "anna.neu"}) in ereignisse, str(ereignisse))
r.check("… and the “self-chosen” marker (G2-N) is cleared: the name now stands for the operator",
        auth.store.get_user(anna)["name_selbst_gewaehlt"] == 0)
_fehl = {n: ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": n}).status_code
         for n in ("bert", "BERT", "bert@example.com", "fremd@example.com", "chef-reserviert",
                   "zwei\x01", "", "x" * 151)}
r.check("G13: taken (also as an address or look-alike name), someone else's address, allowlist name, "
        "control characters, empty, too long → 400",
        set(_fehl.values()) == {400} and auth.store.get_user(anna)["username"] == "anna.neu", str(_fehl))
r.check("… no name in the body → 400, not 500",
        ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": 7}).status_code == 400
        and ch.post(f"/auth/admin/api/users/{anna}/username", json={}).status_code == 400)
r.check("G13: an account that does not exist → 404",
        ch.post("/auth/admin/api/users/9999/username", json={"username": "neu"}).status_code == 404)
_owner_fremd = ch.post(f"/auth/admin/api/users/{chefin}/username", json={"username": "chefin2"})
r.check("G13: an admin who is not owner does not rename the owner (403)",
        _owner_fremd.status_code == 403 and auth.store.get_user(chefin)["username"] == "chefin",
        f"HTTP {_owner_fremd.status_code}")
cc = _client(app, "chefin")
r.check("… an owner does (also other admins)",
        cc.post(f"/auth/admin/api/users/{chefin}/username", json={"username": "chefin2"}).status_code == 200
        and cc.post(f"/auth/admin/api/users/{helfer}/username", json={"username": "helfer2"}).status_code == 200)
cn = _client(app, "bert")
r.check("G13: no rename without admin right (403)",
        cn.post(f"/auth/admin/api/users/{anna}/username", json={"username": "anna3"}).status_code == 403
        and auth.store.get_user(anna)["username"] == "anna.neu")
auth_m, app_m = _app(login_identifier="email")
auth_m.create_user("admin@example.com", password=PW, email="admin@example.com", is_admin=True)
_mu = auth_m.create_user("mu@example.com", password=PW, email="mu@example.com")
r.check("G13: in mode login_identifier=\"email\" the name follows the address — 400",
        _client(app_m, "admin@example.com").post(f"/auth/admin/api/users/{_mu}/username",
                                                 json={"username": "mu"}).status_code == 400)

# ── G13: panel ─────────────────────────────────────────────────────────────────────────────
_seite = cc.get("/auth/admin").text
_js = next(s for s in re.findall(r"<script\b[^>]*>(.*?)</script[^>]*>", _seite, re.S | re.I) if "const ACT={" in s)
_act = set(re.search(r"const ACT=\{([^}]*)\}", _js).group(1).split(","))
r.check("G13: the panel has the “Rename” button and calls the route",
        'on("ren",u.id,u.username)' in _js and "ren" in _act and "/api/users/${id}/username" in _js)
# The class behind the owner button: a button names its action as data-on; if it is missing from ACT,
# the click silently does nothing.
_knoepfe = set(re.findall(r'\bon\("(\w+)"', _js))
r.check("Panel: every action a button names is wired up (ACT) — also “Make owner”",
        _knoepfe and _knoepfe <= _act and "own" in _knoepfe, f"fehlen: {sorted(_knoepfe - _act)}")
_gelesen = set(re.findall(r"\bL\.(\w+)", _PAGE)) | set(re.findall(r'\bL\["([^"]+)"\]', _PAGE))
_leer = {lang: sorted(k for k in _gelesen if not panel_texts(_app(lang=lang)[0]).get(k))
         for lang in ("de", "en")}
r.check("Panel: every text the script reads is delivered (DE and EN)",
        len(_gelesen) >= 40 and _leer == {"de": [], "en": []}, str(_leer))

# ── G3: the reason for the lock, measured via the admin API ────────────────────────────────────
auth_s, app_s = _app(allow_signup=True, signup_require_email=True, signup_verify_email=True,
                     admin_identifiers=[])
auth_s.set_mailer(lambda *x, **k: True)
auth_s.create_user("panel", password=PW, is_admin=True)
TestClient(app_s).post("/auth/register", data={"username": "wartet", "password": PW,
                                               "email": "wartet@example.com"}, follow_redirects=False)
_betr = auth_s.create_user("betrieb", password=PW)
cs = _client(app_s, "panel")
cs.post(f"/auth/admin/api/users/{_betr}/disable", json={"disabled": True})


def _liste():
    return {u["username"]: u for u in cs.get("/auth/admin/api/users").json()}


_l = _liste()
r.check("G3: pending confirmation (registration) → disabled_by=confirmation",
        "wartet" in _l and _l["wartet"]["disabled"] is True and _l["wartet"]["disabled_by"] == "confirmation",
        str({k: (v["disabled"], v["disabled_by"]) for k, v in _l.items()}))
r.check("G3: locked via the panel route → disabled_by=operator",
        _l["betrieb"]["disabled"] is True and _l["betrieb"]["disabled_by"] == "operator",
        str(_l["betrieb"]))
cs.post(f"/auth/admin/api/users/{_betr}/disable", json={"disabled": False})
_l = _liste()
r.check("… unlocked → disabled_by=null, active accounts likewise",
        _l["betrieb"]["disabled"] is False and _l["betrieb"]["disabled_by"] is None
        and _l["panel"]["disabled_by"] is None, str(_l["betrieb"]))
r.check("… and the panel badge carries both texts (not empty)",
        panel_texts(auth_s)["disabled_confirmation"] and panel_texts(auth_s)["disabled"]
        and panel_texts(auth_s)["disabled_confirmation"] != panel_texts(auth_s)["disabled"])

# ── G13: CLI `tinysesam rename` ───────────────────────────────────────────────────────────────
db = auth.cfg.db_path
auth.store.set_username(anna, "anna.neu", selbst_gewaehlt=True)       # back to "self-chosen"
code, aus = _cli("rename", "--db", db, "anna.neu", "anna2")
r.check("G13 (CLI): rename renames, exit 0",
        code == 0 and auth.store.get_user(anna)["username"] == "anna2" and "anna2" in aus, f"{code} {aus}")
r.check("… audit row as operator with quelle=cli, “self-chosen” marker is cleared",
        _umbenannt(auth, anna)[:1] == [("anna2", "alt=anna.neu durch=betreiber quelle=cli")]
        and auth.store.get_user(anna)["name_selbst_gewaehlt"] == 0, str(_umbenannt(auth, anna)))
_cli_fehl = {n: _cli("rename", "--db", db, "anna2", n) for n in
             ("bert", "BERT", "\uff42\uff45\uff52\uff54", "bert@example.com", "fremd@example.com", "zwei\x01", "",
              "  ", "x" * 151)}
r.check("G13 (CLI): taken (name, address, look-alike name), someone else's address, control characters, empty, "
        "too long → exit 1, nothing changed",
        all(c == 1 for c, _ in _cli_fehl.values()) and auth.store.get_user(anna)["username"] == "anna2",
        str({k: v[0] for k, v in _cli_fehl.items()}))
# The pre-check names the account it collides with — also for the full-width look-alike name that only
# the counting bucket sees. (Without the pre-check only the database would reject, without this information.)
_kollision = ("bert", "BERT", "\uff42\uff45\uff52\uff54")
r.check("… and on a collision names the account the name belongs to (name, NOCASE, counting bucket)",
        all(f"is already taken (account {bert}," in _cli_fehl[n][1] for n in _kollision),
        str({n: _cli_fehl[n][1][-90:] for n in _kollision}))
code, aus = _cli("rename", "--db", db, "anna2", "anna@example.com")
r.check("G13 (CLI): one's own confirmed address as name works (as in the panel)",
        code == 0 and auth.store.get_user(anna)["username"] == "anna@example.com", aus)
code, aus = _cli("rename", "--db", db, f"#{anna}", "anna3")
r.check("G13 (CLI): #<id> finds the account (for a name that cannot be typed in)",
        code == 0 and auth.store.get_user(anna)["username"] == "anna3", aus)
r.check("G13 (CLI): an unknown account and a missing database → exit 1",
        _cli("rename", "--db", db, "niemand", "x1")[0] == 1
        and _cli("rename", "--db", db + ".fehlt", "anna3", "x1")[0] == 1
        and not Path(db + ".fehlt").exists())
# The race with the running service: the pre-check sees nothing, the database rejects (G12c).
# Reproduced by making the pre-check via the counting bucket fail — `ｂｅｒｔ` (full-width) is found
# only by it; NOCASE and the address search do not see it.
_orig_topf = Store.konto_mit_topf
Store.konto_mit_topf = lambda self, kennung, ausser=None: None
try:
    code, aus = _cli("rename", "--db", db, "anna3", "ｂｅｒｔ")
finally:
    Store.konto_mit_topf = _orig_topf
r.check("G13 (CLI): if the database rejects (race), there is exit 1 and a clear message — no traceback",
        code == 1 and "the database rejected" in aus and "Traceback" not in aus
        and auth.store.get_user(anna)["username"] == "anna3", f"{code} {aus[-200:]}")
r.check("G13 (CLI): same maximum length as the web", cli_modul._NAME_MAX == TinySesam.NAME_MAX)
code, aus = _cli("--help")
r.check("… and the help names the command", code == 0 and "rename" in aus)

sys.exit(r.done())
