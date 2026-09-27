"""Funde aus dem Betrieb (2026-09-27) — beim Einbau in eine App mit PocketID und im Container.

  (a) Gruppen-Scope: Eine Gruppenregel über den Claim `groups` ohne den Scope `groups` weist bei
      PocketID jeden still ab — die Konfigurationsprüfung warnt, fordert aber nichts nach.
  (b) Claim-Token im Container-Log: Ohne Admin ging das Einmal-Token für /auth/claim-admin auf
      stderr — im Container ist das `docker logs`. Ist stderr keine Konsole, steht es jetzt in
      `<db_path>.claim` (0600), das Log nennt nur den Pfad und sagt die Wahrheit.
"""
from __future__ import annotations

import contextlib
import io
import logging
import os
import stat
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import konfigpruefung  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Funde aus dem Betrieb (Gruppen-Scope, Claim-Token)")


# ── (a) Gruppen-Scope ────────────────────────────────────────────────────────────────────────────
# PocketID (und jeder Provider, der Claims an Scopes bindet) schickt `groups` nur mit dem Scope
# `groups`. Die Vorgabe `oidc_scopes="openid profile email"` verlangt ihn nicht: Mit
# `oidc_allowed_groups` kam niemand herein, mit `oidc_group_role_map` bekam niemand eine Rolle —
# und der Start sagte nichts.
# (Mutationsprobe: in `konfigpruefung.pruefe` den Aufruf `_gruppen_scope(...)` streichen → rot.)
OIDC = dict(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="app",
            oidc_client_secret="geheim", base_url="https://app.example.com")
MERKMAL = "der Scope 'groups' wird nicht angefordert"


def _warnungen(**felder):
    fehler, warnungen = konfigpruefung.pruefe(TinySesamConfig(**{**OIDC, **felder}))
    return fehler, [w for w in warnungen if MERKMAL in w]


_f, _w = _warnungen(oidc_allowed_groups=["mitarbeiter"])
r.check("(a) oidc_allowed_groups + Claim 'groups' + Vorgabe-Scopes → genau eine Warnung, kein Fehler; "
        "sie nennt oidc_scopes, PocketID und den Weg (Gateway: TINYSESAM_OIDC_SCOPES)",
        not [x for x in _f if "groups" in x] and len(_w) == 1
        and "oidc_scopes='openid profile email'" in _w[0] and "PocketID" in _w[0]
        and "TINYSESAM_OIDC_SCOPES" in _w[0], str(_w))
_, _w = _warnungen(oidc_group_role_map={"redaktion": "editor"})
r.check("(a) … ebenso mit oidc_group_role_map allein (keine Rolle statt Abweisung)", len(_w) == 1, str(_w))
_, _w = _warnungen(oidc_allowed_groups=["mitarbeiter"], oidc_scopes="openid profile email groups")
r.check("(a) mit dem Scope 'groups' → keine Warnung", not _w, str(_w))
_cfg = TinySesamConfig(**{**OIDC, "oidc_allowed_groups": ["mitarbeiter"]})
r.check("(a) nichts wird nachgefordert: oidc_scopes bleibt, wie gesetzt",
        _cfg.oidc_scopes == "openid profile email")
for _name, _felder in (("ohne Gruppenregel", {}),
                       ("anderer Claim (oidc_group_claim='roles')",
                        {"oidc_allowed_groups": ["x"], "oidc_group_claim": "roles"}),
                       ("OIDC aus", {"oidc_allowed_groups": ["x"], "oidc_enabled": False,
                                     "password_enabled": True}),
                       ("Entra ID (Gruppen über optional claims; ein Scope 'groups' bräche die Anmeldung)",
                        {"oidc_allowed_groups": ["x"],
                         "oidc_issuer": "https://login.microsoftonline.com/mandant/v2.0"})):
    _, _w = _warnungen(**_felder)
    r.check(f"(a) keine Warnung: {_name}", not _w, str(_w))

# Je Anwendung (T-14): eigene `scopes`, sonst die globalen; eigene Gruppenregel, sonst die globale.
_clients = {"app.example.com": {"client_id": "a", "client_secret": "s"},
            "wiki.example.com": {"client_id": "w", "client_secret": "s",
                                 "scopes": "openid profile email groups"}}
_, _w = _warnungen(oidc_allowed_groups=["x"], oidc_scopes="openid groups",
                   oidc_clients={**_clients, "neu.example.com": {"client_id": "n", "client_secret": "s",
                                                                   "scopes": "openid email"}},
                   forward_auth_enabled=True, trusted_redirect_hosts=[])
r.check("(a) je Anwendung: eine eigene `scopes`-Angabe ohne 'groups' wird benannt, die anderen nicht",
        len(_w) == 1 and "oidc_clients['neu.example.com']" in _w[0]
        and "app.example.com" not in _w[0] and "oidc_scopes=" not in _w[0], str(_w))
_, _w = _warnungen(oidc_clients={"app.example.com": {"client_id": "a", "client_secret": "s",
                                                     "allowed_groups": ["team-a"]}},
                   forward_auth_enabled=True)
r.check("(a) … eine Gruppenregel nur am Eintrag, Scopes geerbt ohne 'groups' → gewarnt (nur dieser Client)",
        len(_w) == 1 and "oidc_clients['app.example.com']" in _w[0] and "oidc_scopes=" not in _w[0], str(_w))

# Gateway: ohne eigene Variable wäre der Rat nicht umsetzbar gewesen — das Preset nahm immer die
# Vorgabe-Scopes.
from tinysesam import gateway  # noqa: E402

_env = {"TINYSESAM_OIDC_ISSUER": "https://id.example.com", "TINYSESAM_OIDC_CLIENT_ID": "gw",
        "TINYSESAM_OIDC_CLIENT_SECRET": "geheim", "TINYSESAM_BASE_URL": "https://auth.example.com",
        "TINYSESAM_ALLOWED_GROUPS": "mitarbeiter", "TINYSESAM_DB": ":memory:"}
_vorher = {k: os.environ.get(k) for k in [*_env, "TINYSESAM_OIDC_SCOPES"]}
try:
    os.environ.update(_env)
    os.environ.pop("TINYSESAM_OIDC_SCOPES", None)
    _g_vorgabe = gateway.config_from_env()
    os.environ["TINYSESAM_OIDC_SCOPES"] = "openid profile email groups"
    _g_mit = gateway.config_from_env()
finally:
    for _k, _v in _vorher.items():
        if _v is None:
            os.environ.pop(_k, None)
        else:
            os.environ[_k] = _v
_w_vorgabe = [w for w in konfigpruefung.pruefe(_g_vorgabe)[1] if MERKMAL in w]
_w_mit = [w for w in konfigpruefung.pruefe(_g_mit)[1] if MERKMAL in w]
r.check("(a) Gateway: TINYSESAM_ALLOWED_GROUPS ohne TINYSESAM_OIDC_SCOPES warnt; mit "
        "TINYSESAM_OIDC_SCOPES='… groups' kommt der Scope an und die Warnung entfällt",
        _g_vorgabe.oidc_scopes == "openid profile email" and len(_w_vorgabe) == 1
        and _g_mit.oidc_scopes == "openid profile email groups" and not _w_mit,
        f"{_g_vorgabe.oidc_scopes!r} {_w_vorgabe} {_g_mit.oidc_scopes!r} {_w_mit}")


# ── (b) Claim-Token im Container-Log ─────────────────────────────────────────────────────────────
# Gemessen im Container (2026-09-27): stderr IST das Log. Dort stand erst der Token im Klartext,
# dann die Zeile „Der Wert steht bewusst NICHT im Log". Nachgestellt wird der Container, indem
# stderr UND der Sicherheits-Logger in denselben Puffer schreiben — das ist `docker logs`.
# (Mutationsprobe: in `_admin_claim_bekanntgeben` die Bedingung `not konsole` streichen bzw. den
# Rückfall auf die Datei weglassen → der Token steht wieder im Puffer → rot.)
PW = "Betrieb-Pw-2026"          # 15 Zeichen: das Passwort meldet allein an


class _Konsole(io.StringIO):
    """stderr an einem Terminal — `isatty()` wahr, sonst ein Puffer wie jeder andere."""

    def isatty(self):
        return True


def _start(stderr, **felder):
    """TinySesam ohne Admin bauen; stderr und Sicherheits-Log landen gemeinsam in `stderr`."""
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "app.db"), cookie_secure=False,
                 csrf_enabled=False, passkey_enabled=False, allow_signup=True,
                 signup_require_email=False)
    grund.update(felder)
    haken = logging.StreamHandler(stderr)
    seclog.addHandler(haken)
    try:
        with contextlib.redirect_stderr(stderr):
            auth = TinySesam(TinySesamConfig(**grund))
    finally:
        seclog.removeHandler(haken)
    return auth


# Konsole: wie bisher auf stderr — dort liest ein Mensch mit. Keine Datei.
_k = _Konsole()
auth_k = _start(_k)
_tok_k = auth_k.admin_claim_token()
_datei_k = auth_k.cfg.db_path + ".claim"
r.check("(b) stderr ist eine Konsole: der Token steht dort, keine Datei neben der Datenbank, und "
        "die Log-Zeile sagt „auf der Konsole“ ohne den Wert",
        f"/auth/claim-admin?token={_tok_k}" in _k.getvalue() and not os.path.exists(_datei_k)
        and "steht auf der Konsole (stderr), nicht in dieser Zeile" in _k.getvalue()
        and _k.getvalue().count(_tok_k) == 1, _k.getvalue()[-300:])

# Kein Terminal (Container, journal, Pipe): Datei mit 0600, im „Log" nur der Pfad.
_c = io.StringIO()
auth_c = _start(_c)
_tok_c = auth_c.admin_claim_token()
_datei_c = auth_c.cfg.db_path + ".claim"
_inhalt_c = Path(_datei_c).read_text(encoding="utf-8") if os.path.exists(_datei_c) else ""
r.check("(b) stderr keine Konsole: das Token steht in <db_path>.claim — nur dort",
        bool(_tok_c) and _inhalt_c == _tok_c + "\n", repr(_inhalt_c))
r.check("(b) … die Datei hat die Rechte 0600",
        os.path.exists(_datei_c) and stat.S_IMODE(os.stat(_datei_c).st_mode) == 0o600,
        oct(stat.S_IMODE(os.stat(_datei_c).st_mode)) if os.path.exists(_datei_c) else "fehlt")
r.check("(b) … im Log (stderr + Sicherheits-Log) steht der Wert NICHT, wohl aber der Pfad, und der "
        "Text sagt, wo das Token steht",
        _tok_c not in _c.getvalue() and "claim-admin?token=" not in _c.getvalue()
        and f"steht in {_datei_c} (Rechte 0600), nicht im Log" in _c.getvalue()
        and "bewusst NICHT" not in _c.getvalue(), _c.getvalue()[-300:])

# Die Datei trägt, was sie soll: Einlösen macht zum Admin und räumt sie weg.
_app_c = FastAPI()
_app_c.include_router(auth_c.router())
_cl = TestClient(_app_c)
_reg = _cl.post("/auth/register", data={"username": "betreiber", "password": PW}, follow_redirects=False)
_ein = _cl.get(f"/auth/claim-admin?token={_inhalt_c.strip()}", follow_redirects=False)
r.check("(b) der Token aus der Datei macht den Erst-Admin, danach ist die Datei weg",
        _reg.status_code == 303 and _ein.status_code == 303
        and auth_c.store.get_user_by_name("betreiber")["is_admin"] and not os.path.exists(_datei_c),
        f"{_reg.status_code} {_ein.status_code} {os.path.exists(_datei_c)}")

# Ein Rest aus einem früheren Lauf (etwa: Admin später per CLI gesetzt) verschwindet beim Start.
Path(_datei_c).write_text("ALT\n", encoding="utf-8")
_start(io.StringIO(), db_path=auth_c.cfg.db_path)
r.check("(b) gibt es einen Admin, entfernt der Start eine liegengebliebene <db_path>.claim",
        not os.path.exists(_datei_c))

# Verfall: Das abgelaufene Token in der Datei gilt nicht mehr; der nächste Start schreibt das neue.
_v = io.StringIO()
auth_v = _start(_v)
_datei_v = auth_v.cfg.db_path + ".claim"
_alt_v = Path(_datei_v).read_text(encoding="utf-8").strip()
auth_v.store.set_setting("admin_claim", f"{_alt_v}:{int(time.time()) - 1}")
_uid_v = auth_v.create_user("spaet", password=PW)
_abgelaufen = auth_v._consume_admin_claim(_alt_v, auth_v.store.get_user(_uid_v))
_start(io.StringIO(), db_path=auth_v.cfg.db_path)
_neu_v = Path(_datei_v).read_text(encoding="utf-8").strip()
r.check("(b) nach dem Verfall ist der Dateiinhalt ungültig, der nächste Start ersetzt ihn",
        not _abgelaufen and _neu_v and _neu_v != _alt_v
        and _neu_v == auth_v.admin_claim_token(), f"{_abgelaufen} {_alt_v[:6]} {_neu_v[:6]}")

# Rückfall ohne Datei: `:memory:` — dann bleibt nur stderr, und der Text sagt ehrlich, was das heisst.
_m = io.StringIO()
auth_m = _start(_m, db_path=":memory:")
_tok_m = auth_m.admin_claim_token()
r.check("(b) :memory: ohne Konsole: Rückfall auf stderr, und die Log-Zeile sagt, dass der Wert "
        "damit im Log des Dienstes steht (statt „nicht im Log“)",
        f"claim-admin?token={_tok_m}" in _m.getvalue()
        and "stderr ist hier KEINE Konsole: Der Wert steht damit im Log des Dienstes" in _m.getvalue()
        and "nicht im Log" not in _m.getvalue(), _m.getvalue()[-400:])

# Rückfall, wenn die Datei nicht entsteht (an ihrer Stelle liegt ein Verzeichnis).
_s = io.StringIO()
_db_s = str(Path(tempfile.mkdtemp()) / "app.db")
os.mkdir(_db_s + ".claim")
auth_s = _start(_s, db_path=_db_s)
_tok_s = auth_s.admin_claim_token()
r.check("(b) Datei nicht anlegbar: Rückfall auf stderr mit Grund, ehrlich benannt",
        f"claim-admin?token={_tok_s}" in _s.getvalue() and "nicht schreibbar" in _s.getvalue()
        and "Log des Dienstes" in _s.getvalue(), _s.getvalue()[-400:])

# Eine selbst gewählte Datei hat Vorrang — auch an einer Konsole —, und bleibt nach dem Einlösen.
_eigen = str(Path(tempfile.mkdtemp()) / "claim.token")
_e = _Konsole()
auth_e = _start(_e, admin_claim_token_file=_eigen)
_tok_e = auth_e.admin_claim_token()
_uid_e = auth_e.create_user("chefin", password=PW)
_ok_e = auth_e._consume_admin_claim(_tok_e, auth_e.store.get_user(_uid_e))
r.check("(b) admin_claim_token_file geht vor (auch an einer Konsole): Wert in der Datei, nicht auf "
        "stderr, keine <db_path>.claim; die eigene Datei bleibt nach dem Einlösen (Inhalt ungültig)",
        Path(_eigen).read_text(encoding="utf-8") == _tok_e + "\n" and _tok_e not in _e.getvalue()
        and not os.path.exists(auth_e.cfg.db_path + ".claim") and _ok_e and os.path.exists(_eigen)
        and not auth_e._consume_admin_claim(_tok_e, auth_e.store.get_user(_uid_e)),
        _e.getvalue()[-300:])

sys.exit(r.done())
