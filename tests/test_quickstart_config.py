"""T-133: the quickstart (deploy/quickstart) reads its configuration from `tinysesam.toml` — and gets the same gateway
as before, when the environment variables alone built the OIDC preset.

  Q1 the compose file mounts the file read-only and points TINYSESAM_CONFIG at it; every TINYSESAM_* variable it
     passes is one the gateway overlays over the file (or a variable of the start: the port, the file itself).
  Q2 the file with the variables of example.env gives the configuration `TinySesamConfig.oidc_gateway` built from the
     same variables — every field the preset sets, and every other field at the library's default.
  Q3 the variables overlay the file (a set one wins, an empty one changes nothing); the file carries no secret, the
     client secret only as `env:`.

tests/test_quickstart.py starts the real stack from this file with the images of this commit (CI job gate-caddy).
"""
from __future__ import annotations

import dataclasses
import os
import pathlib
import re
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tinysesam import TinySesamConfig  # noqa: E402
from tinysesam import gateway  # noqa: E402

QS = ROOT / "deploy" / "quickstart"
TOML = QS / "tinysesam.toml"


def ok(name):
    print(f"  ✓ {name}")


# ══ Q1: the compose file wires the file in ══════════════════════════════════════════════════════════════════════
compose = (QS / "docker-compose.yml").read_text(encoding="utf-8")
service = compose.split("\n  tinysesam:\n", 1)[1].split("\n  caddy:\n", 1)[0]
assert "TINYSESAM_CONFIG: /etc/tinysesam.toml" in service, service
assert "- ./tinysesam.toml:/etc/tinysesam.toml:ro" in service, service
passed = set(re.findall(r"^\s+(TINYSESAM_[A-Z_]+):", service, re.M))
overlaid = {name for name, _, _ in gateway.ENVIRONMENT_FIELDS} | {"TINYSESAM_OAUTH_RESOURCES"}
start = {"TINYSESAM_CONFIG", "TINYSESAM_PORT"}
assert passed and passed <= overlaid | start, sorted(passed - overlaid - start)
assert {"TINYSESAM_DB", "TINYSESAM_TRUSTED_PROXIES", "TINYSESAM_HTTPS_MODE"}.isdisjoint(passed), \
    "a setting of the file is passed again by the compose file"
ok(f"Q1 the compose file mounts tinysesam.toml read-only, sets TINYSESAM_CONFIG, and passes only variables the gateway "
   f"overlays ({len(passed - start)}) besides the port")

# ══ Q2: the same gateway as the preset ══════════════════════════════════════════════════════════════════════════
example = {k: v for k, v in re.findall(r"^(TS_[A-Z_]+)=(.*)$", (QS / "example.env").read_text(encoding="utf-8"),
                                        re.M)}
ENV = {"TINYSESAM_OIDC_ISSUER": example["TS_OIDC_ISSUER"], "TINYSESAM_OIDC_CLIENT_ID": example["TS_OIDC_CLIENT_ID"],
       "TINYSESAM_OIDC_CLIENT_SECRET": "a client secret of the test", "TINYSESAM_OIDC_SCOPES": "openid profile email",
       "TINYSESAM_BASE_URL": f"https://{example['TS_AUTH_HOST']}",
       "TINYSESAM_COOKIE_DOMAIN": example["TS_COOKIE_DOMAIN"], "TINYSESAM_PROTECTED_HOSTS": example["TS_APP_HOST"],
       "TINYSESAM_ALLOWED_GROUPS": "", "TINYSESAM_OAUTH_RESOURCES": "", "TINYSESAM_OAUTH_SERVICE_CLIENTS": "0",
       "TINYSESAM_TOPBAR_LINKS": "", "TINYSESAM_FORWARD_APPS": ""}
# What the compose file passed before the file (T-133) — the preset's own values for the stack.
BEFORE = {"TINYSESAM_TRUSTED_PROXIES": "172.29.0.0/16", "TINYSESAM_HTTPS_MODE": "warn",
          "TINYSESAM_DB": "/data/gateway.db"}


def built(env: dict) -> TinySesamConfig:
    saved = {k: os.environ.pop(k) for k in list(os.environ) if k.startswith("TINYSESAM_")}
    os.environ.update(env)
    try:
        return gateway.config_from_env()
    finally:
        for k in env:
            os.environ.pop(k, None)
        os.environ.update(saved)


from_file = built({**ENV, "TINYSESAM_CONFIG": str(TOML)})
preset = built({**ENV, **BEFORE})
fields = [f.name for f in dataclasses.fields(TinySesamConfig)]
differ = {f: (getattr(from_file, f), getattr(preset, f)) for f in fields if getattr(from_file, f) != getattr(preset, f)}
assert not differ, differ
assert from_file.oidc_enabled and from_file.forward_auth_enabled and not from_file.password_enabled
assert from_file.trusted_proxies == ["172.29.0.0/16"] and from_file.db_path == "/data/gateway.db"
assert from_file.oidc_client_secret == "a client secret of the test"
ok(f"Q2 tinysesam.toml with the variables of example.env is the OIDC preset field by field ({len(fields)} fields): "
   "the same gateway as before the file")

# ══ Q3: the overlay, and no secret in the file ══════════════════════════════════════════════════════════════════
over = built({**ENV, "TINYSESAM_CONFIG": str(TOML), "TINYSESAM_TRUSTED_PROXIES": "198.51.100.0/24",
              "TINYSESAM_OIDC_SCOPES": "openid profile email groups", "TINYSESAM_ALLOWED_GROUPS": "staff"})
assert over.trusted_proxies == ["198.51.100.0/24"] and over.oidc_allowed_groups == ["staff"], over.trusted_proxies
assert over.oidc_scopes == "openid profile email groups"
empty = built({**ENV, "TINYSESAM_CONFIG": str(TOML), "TINYSESAM_HTTPS_MODE": "", "TINYSESAM_DB": " "})
assert empty.https_mode == "warn" and empty.db_path == "/data/gateway.db", "an empty variable wiped the file"
data = tomllib.loads(TOML.read_text(encoding="utf-8"))
assert data["oidc_client_secret"] == "env:TINYSESAM_OIDC_CLIENT_SECRET", data.get("oidc_client_secret")
assert not {"oidc_issuer", "oidc_client_id", "base_url", "trusted_redirect_hosts"} & set(data), \
    "a value that differs per host stands in the file instead of .env"
ok("Q3 a set variable overlays the file, an empty one changes nothing; the secret only as env:, the per-host values "
   "stay in .env")

print("OK test_quickstart_config")
