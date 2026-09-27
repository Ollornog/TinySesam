"""Der Betreiber am fremden Konto: umbenennen (Panel, Admin-API, CLI) und der Grund einer Sperre.

G13 (T-13, 2026-09-26): Ein Konto umbenennen konnte bis dahin nur sein Inhaber (Selbstbedienung)
oder der einbettende Dienst (`auth.change_username`). Panel und CLI kannten den Weg nicht — auch
nicht für eine Kennungs-Kollision im Bestand, die der Start meldet. Jetzt: Route
`POST <admin_path>/api/users/{id}/username` (Owner-Schutz, dieselben Regeln wie die
Selbstbedienung, als Betreiber: Merker „selbst gewählt" fällt) und `tinysesam rename`.

G3 (Grenze b): Das Panel nennt den Grund einer Sperre. Gemessen über die Admin-API — die
Betreiber-Sperre über die Route des Panels, die Sperre einer offenen Bestätigung über die echte
Registrierung. Dabei fiel auf: Das Panel lieferte den Text der Bestätigungs-Sperre gar nicht aus
(der Schlüssel fehlte in der Liste der Panel-Texte, die Plakette blieb leer), und der Knopf
„Zum Owner machen" war nie verdrahtet. Geprüft wird deshalb die Klasse: jeder Text, den das
Panel-Skript liest, und jede Aktion, die ein Knopf nennt.
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

r = Report("Admin am fremden Konto — umbenennen (G13), Grund der Sperre (G3)")
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


# ── G13: Admin-API ──────────────────────────────────────────────────────────────────────────
auth, app = _app()
chefin = auth.create_user("chefin", password=PW, is_admin=True)
auth.set_owner(chefin, True)
helfer = auth.create_user("helfer", password=PW, is_admin=True)
anna = auth.create_user("anna", password=PW, email="anna@example.com", name_selbst_gewaehlt=True)
bert = auth.create_user("bert", password=PW, email="bert@example.com")
ereignisse: list = []
auth.on_security_event = lambda e, konto, d: ereignisse.append((e, d))
ch = _client(app, "helfer")
id_vorher = auth._forward_response_headers(auth.get_user(anna))["Remote-Id"]
a = ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": "anna.neu"})
r.check("G13: ein Admin benennt ein fremdes Konto um (Admin-API)",
        a.status_code == 200 and a.json() == {"ok": True, "username": "anna.neu"}
        and auth.store.get_user(anna)["username"] == "anna.neu", f"{a.status_code} {a.text[:160]}")
r.check("… die Liste im Panel zeigt den neuen Namen, Remote-Id bleibt die Konto-ID",
        any(u["id"] == anna and u["username"] == "anna.neu" for u in ch.get("/auth/admin/api/users").json())
        and auth._forward_response_headers(auth.get_user(anna))["Remote-Id"] == id_vorher == str(anna))
_zeilen = _umbenannt(auth, anna)
r.check("… GENAU eine Audit-Zeile, als Betreiber und mit dem Admin als Akteur",
        _zeilen == [("anna.neu", "alt=anna durch=betreiber akteur=helfer")], str(_zeilen))
r.check("… das Sicherheitsereignis erreicht den Inhaber",
        ("username_changed", {"alt": "anna", "neu": "anna.neu"}) in ereignisse, str(ereignisse))
r.check("… und der Merker „selbst gewählt“ (G2-N) fällt: der Name steht jetzt für den Betreiber",
        auth.store.get_user(anna)["name_selbst_gewaehlt"] == 0)
_fehl = {n: ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": n}).status_code
         for n in ("bert", "BERT", "bert@example.com", "fremd@example.com", "chef-reserviert",
                   "zwei\x01", "", "x" * 151)}
r.check("G13: vergeben (auch als Adresse oder Namensvetter), fremde Adresse, Allowlist-Name, "
        "Steuerzeichen, leer, zu lang → 400",
        set(_fehl.values()) == {400} and auth.store.get_user(anna)["username"] == "anna.neu", str(_fehl))
r.check("… ohne Namen im Körper → 400, nicht 500",
        ch.post(f"/auth/admin/api/users/{anna}/username", json={"username": 7}).status_code == 400
        and ch.post(f"/auth/admin/api/users/{anna}/username", json={}).status_code == 400)
r.check("G13: ein Konto, das es nicht gibt → 404",
        ch.post("/auth/admin/api/users/9999/username", json={"username": "neu"}).status_code == 404)
_owner_fremd = ch.post(f"/auth/admin/api/users/{chefin}/username", json={"username": "chefin2"})
r.check("G13: ein Admin, der nicht Owner ist, benennt den Owner nicht um (403)",
        _owner_fremd.status_code == 403 and auth.store.get_user(chefin)["username"] == "chefin",
        f"HTTP {_owner_fremd.status_code}")
cc = _client(app, "chefin")
r.check("… ein Owner schon (auch andere Admins)",
        cc.post(f"/auth/admin/api/users/{chefin}/username", json={"username": "chefin2"}).status_code == 200
        and cc.post(f"/auth/admin/api/users/{helfer}/username", json={"username": "helfer2"}).status_code == 200)
cn = _client(app, "bert")
r.check("G13: ohne Admin-Recht keine Umbenennung (403)",
        cn.post(f"/auth/admin/api/users/{anna}/username", json={"username": "anna3"}).status_code == 403
        and auth.store.get_user(anna)["username"] == "anna.neu")
auth_m, app_m = _app(login_identifier="email")
auth_m.create_user("admin@example.com", password=PW, email="admin@example.com", is_admin=True)
_mu = auth_m.create_user("mu@example.com", password=PW, email="mu@example.com")
r.check("G13: im Modus login_identifier=\"email\" folgt der Name der Adresse — 400",
        _client(app_m, "admin@example.com").post(f"/auth/admin/api/users/{_mu}/username",
                                                 json={"username": "mu"}).status_code == 400)

# ── G13: Panel ─────────────────────────────────────────────────────────────────────────────
_seite = cc.get("/auth/admin").text
_js = next(s for s in re.findall(r"<script\b[^>]*>(.*?)</script[^>]*>", _seite, re.S | re.I) if "const ACT={" in s)
_act = set(re.search(r"const ACT=\{([^}]*)\}", _js).group(1).split(","))
r.check("G13: das Panel hat den Knopf „Umbenennen“ und ruft die Route",
        'on("ren",u.id,u.username)' in _js and "ren" in _act and "/api/users/${id}/username" in _js)
# Die Klasse hinter dem Owner-Knopf: Ein Knopf nennt seine Aktion als data-on; fehlt sie in ACT,
# tut der Klick still nichts.
_knoepfe = set(re.findall(r'\bon\("(\w+)"', _js))
r.check("Panel: jede Aktion, die ein Knopf nennt, ist verdrahtet (ACT) — auch „Zum Owner machen“",
        _knoepfe and _knoepfe <= _act and "own" in _knoepfe, f"fehlen: {sorted(_knoepfe - _act)}")
_gelesen = set(re.findall(r"\bL\.(\w+)", _PAGE)) | set(re.findall(r'\bL\["([^"]+)"\]', _PAGE))
_leer = {lang: sorted(k for k in _gelesen if not panel_texts(_app(lang=lang)[0]).get(k))
         for lang in ("de", "en")}
r.check("Panel: jeder Text, den das Skript liest, wird ausgeliefert (DE und EN)",
        len(_gelesen) >= 40 and _leer == {"de": [], "en": []}, str(_leer))

# ── G3: der Grund der Sperre, gemessen über die Admin-API ──────────────────────────────────────
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
r.check("G3: offene Bestätigung (Registrierung) → disabled_by=confirmation",
        "wartet" in _l and _l["wartet"]["disabled"] is True and _l["wartet"]["disabled_by"] == "confirmation",
        str({k: (v["disabled"], v["disabled_by"]) for k, v in _l.items()}))
r.check("G3: gesperrt über die Panel-Route → disabled_by=operator",
        _l["betrieb"]["disabled"] is True and _l["betrieb"]["disabled_by"] == "operator",
        str(_l["betrieb"]))
cs.post(f"/auth/admin/api/users/{_betr}/disable", json={"disabled": False})
_l = _liste()
r.check("… entsperrt → disabled_by=null, aktive Konten ebenso",
        _l["betrieb"]["disabled"] is False and _l["betrieb"]["disabled_by"] is None
        and _l["panel"]["disabled_by"] is None, str(_l["betrieb"]))
r.check("… und die Plakette im Panel trägt beide Texte (nicht leer)",
        panel_texts(auth_s)["disabled_confirmation"] and panel_texts(auth_s)["disabled"]
        and panel_texts(auth_s)["disabled_confirmation"] != panel_texts(auth_s)["disabled"])

# ── G13: CLI `tinysesam rename` ───────────────────────────────────────────────────────────────
db = auth.cfg.db_path
auth.store.set_username(anna, "anna.neu", selbst_gewaehlt=True)       # zurück auf „selbst gewählt"
code, aus = _cli("rename", "--db", db, "anna.neu", "anna2")
r.check("G13 (CLI): rename benennt um, Exit 0",
        code == 0 and auth.store.get_user(anna)["username"] == "anna2" and "anna2" in aus, f"{code} {aus}")
r.check("… Audit-Zeile als Betreiber mit quelle=cli, Merker „selbst gewählt“ fällt",
        _umbenannt(auth, anna)[:1] == [("anna2", "alt=anna.neu durch=betreiber quelle=cli")]
        and auth.store.get_user(anna)["name_selbst_gewaehlt"] == 0, str(_umbenannt(auth, anna)))
_cli_fehl = {n: _cli("rename", "--db", db, "anna2", n) for n in
             ("bert", "BERT", "\uff42\uff45\uff52\uff54", "bert@example.com", "fremd@example.com", "zwei\x01", "",
              "  ", "x" * 151)}
r.check("G13 (CLI): vergeben (Name, Adresse, Namensvetter), fremde Adresse, Steuerzeichen, leer, "
        "zu lang → Exit 1, nichts geändert",
        all(c == 1 for c, _ in _cli_fehl.values()) and auth.store.get_user(anna)["username"] == "anna2",
        str({k: v[0] for k, v in _cli_fehl.items()}))
# Die Vorprüfung nennt das Konto, mit dem es kollidiert — auch beim Namensvetter in Vollbreite, den nur
# der Zähl-Topf sieht. (Ohne Vorprüfung wiese erst die Datenbank ab, ohne diese Angabe.)
_kollision = ("bert", "BERT", "\uff42\uff45\uff52\uff54")
r.check("… und nennt bei einer Kollision das Konto, dem der Name gehört (Name, NOCASE, Zähl-Topf)",
        all(f"vergeben (Konto {bert}," in _cli_fehl[n][1] for n in _kollision),
        str({n: _cli_fehl[n][1][-90:] for n in _kollision}))
code, aus = _cli("rename", "--db", db, "anna2", "anna@example.com")
r.check("G13 (CLI): die eigene bestätigte Adresse als Name geht (wie im Panel)",
        code == 0 and auth.store.get_user(anna)["username"] == "anna@example.com", aus)
code, aus = _cli("rename", "--db", db, f"#{anna}", "anna3")
r.check("G13 (CLI): #<id> findet das Konto (für einen Namen, der sich nicht eintippen lässt)",
        code == 0 and auth.store.get_user(anna)["username"] == "anna3", aus)
r.check("G13 (CLI): ein unbekanntes Konto und eine fehlende Datenbank → Exit 1",
        _cli("rename", "--db", db, "niemand", "x1")[0] == 1
        and _cli("rename", "--db", db + ".fehlt", "anna3", "x1")[0] == 1
        and not Path(db + ".fehlt").exists())
# Der Wettlauf mit dem laufenden Dienst: Vorprüfung sieht nichts, die Datenbank weist ab (G12c).
# Nachgestellt, indem die Vorprüfung über den Zähl-Topf ausfällt — `ｂｅｒｔ` (Vollbreite) findet
# nur sie; NOCASE und die Adresssuche sehen es nicht.
_orig_topf = Store.konto_mit_topf
Store.konto_mit_topf = lambda self, kennung, ausser=None: None
try:
    code, aus = _cli("rename", "--db", db, "anna3", "ｂｅｒｔ")
finally:
    Store.konto_mit_topf = _orig_topf
r.check("G13 (CLI): weist die Datenbank ab (Wettlauf), gibt es Exit 1 und eine klare Meldung — kein Traceback",
        code == 1 and "Datenbank" in aus and "Traceback" not in aus
        and auth.store.get_user(anna)["username"] == "anna3", f"{code} {aus[-200:]}")
r.check("G13 (CLI): dieselbe Höchstlänge wie das Web", cli_modul._NAME_MAX == TinySesam.NAME_MAX)
code, aus = _cli("--help")
r.check("… und die Hilfe nennt das Kommando", code == 0 and "rename" in aus)

sys.exit(r.done())
