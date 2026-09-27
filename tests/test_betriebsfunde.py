"""Funde aus dem Betrieb (2026-09-27) — beim Einbau in eine App mit PocketID und im Container.

  (a) Gruppen-Scope: Eine Gruppenregel über den Claim `groups` ohne den Scope `groups` weist bei
      PocketID jeden still ab — die Konfigurationsprüfung warnt, fordert aber nichts nach.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from tinysesam import TinySesamConfig  # noqa: E402
from tinysesam import konfigpruefung  # noqa: E402
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

sys.exit(r.done())
