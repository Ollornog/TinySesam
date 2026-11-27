"""T-97 (ADR-16): the server is configured by a TOML file with the environment as an overlay.

`TINYSESAM_CONFIG=/etc/tinysesam.toml` builds the full `TinySesamConfig` (local accounts, panel, account page — not
the OIDC-only preset); a key that is no field ends the start with the nearest field named; a secret field takes only
`env:NAME` or `<field>_file`, never a literal; a SET gateway variable wins over the file, an unset or empty one changes
nothing; without the file the gateway reads its variables exactly as before.
"""
from __future__ import annotations

import dataclasses
import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesamConfig  # noqa: E402
from tinysesam import gateway  # noqa: E402
from tinysesam._server_config import (FileError, SECRET_FIELDS, field_names,  # noqa: E402
                                      values_from_file)

TMP = tempfile.mkdtemp()
PW = "a long gateway password 4711"
# The gateway's variables must not leak in from the environment the suite runs in.
for _name in list(os.environ):
    if _name.startswith("TINYSESAM_"):
        del os.environ[_name]


def ok(name):
    print(f"  ✓ {name}")


def write(name: str, text: str) -> str:
    path = os.path.join(TMP, name)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(text)
    return path


def refused(text: str, *fragments, env=None) -> str:
    try:
        values_from_file(write("refused.toml", text), env=env or {})
    except FileError as e:
        message = str(e)
        assert all(f in message for f in fragments), (fragments, message)
        return message
    raise AssertionError(f"accepted: {text!r}")


class Env:
    """Set gateway variables for one block and take them away afterwards."""

    def __init__(self, **values):
        self.values = values

    def __enter__(self):
        os.environ.update(self.values)
        return self

    def __exit__(self, *exc):
        for name in self.values:
            os.environ.pop(name, None)


DB = os.path.join(TMP, "server.db")
LOCAL = write("local.toml", f'''# a server with local accounts, the panel and the account page — no OIDC
base_url = "http://testserver"
db_path = "{DB}"
cookie_secure = false
csrf_enabled = false
https_mode = "off"
lang = "en"
admin_require_mfa = false
trusted_redirect_hosts = ["app.example.com"]
oidc_allowed_groups = ["staff"]
''')

# (a) the file builds the full configuration — the library's defaults, not the gateway preset
with Env(TINYSESAM_CONFIG=LOCAL):
    cfg = gateway.config_from_env()
assert isinstance(cfg, TinySesamConfig) and cfg.db_path == DB and cfg.base_url == "http://testserver"
assert cfg.password_enabled and cfg.admin_enabled and cfg.account_enabled and not cfg.oidc_enabled, \
    "the file starts from the library's defaults: local accounts, panel and account page are on"
assert cfg.trusted_redirect_hosts == ["app.example.com"] and cfg.lang == "en"
ok("TINYSESAM_CONFIG builds the full TinySesamConfig from the file (local accounts, panel, account page)")

# (b) the gateway built from it serves sign-in, panel and account page — no line of Python in the application
with Env(TINYSESAM_CONFIG=LOCAL):
    app = gateway.build_app()
auth = app.state.auth
auth.ensure_admin("root", PW)
with TestClient(app) as c:
    assert c.get("/healthz").json() == {"status": "ok"}
    r = c.post("/auth/login", data={"username": "root", "password": PW}, follow_redirects=False)
    assert r.status_code in (302, 303), (r.status_code, r.text[:200])
    users = c.get("/auth/admin/api/users", headers={"Accept": "application/json"})
    assert users.status_code == 200 and [u["username"] for u in users.json()] == ["root"], users.text[:200]
    assert c.get("/auth/account", headers={"Accept": "text/html"}).status_code == 200
    assert c.get("/auth/me", headers={"Accept": "application/json"}).json().get("username") == "root"
ok("the gateway from the file: sign-in, admin panel, account page and /auth/me answer")

# (c) the environment overlays the file — only what is set; empty is not set
with Env(TINYSESAM_CONFIG=LOCAL, TINYSESAM_BASE_URL="https://auth.example.com",
         TINYSESAM_PROTECTED_HOSTS="wiki.example.com, files.example.com", TINYSESAM_LANG="de",
         TINYSESAM_ALLOWED_GROUPS="", TINYSESAM_GATE="1", TINYSESAM_OAUTH_RESOURCES="https://app.example.com/mcp"):
    cfg = gateway.config_from_env()
assert cfg.base_url == "https://auth.example.com" and cfg.lang == "de"
assert cfg.trusted_redirect_hosts == ["wiki.example.com", "files.example.com"]
assert cfg.gate_token_enabled is True and cfg.oauth_enabled is True
assert cfg.oauth_resources == ["https://app.example.com/mcp"]
assert cfg.db_path == DB and cfg.admin_enabled, "what no variable names stays as the file says"
assert cfg.oidc_allowed_groups == ["staff"], "an empty TINYSESAM_ALLOWED_GROUPS must not open the gate the file closed"
ok("a set gateway variable wins over the file; an empty one and an unset one change nothing")

# (d) every variable of the overlay gives the same value as the gateway without a file (one reader, no drift)
SAMPLES = {
    "TINYSESAM_OIDC_ISSUER": "https://id.example.com", "TINYSESAM_OIDC_CLIENT_ID": "gw",
    "TINYSESAM_OIDC_CLIENT_SECRET": "gw-secret", "TINYSESAM_BASE_URL": "https://auth.example.com",
    "TINYSESAM_COOKIE_DOMAIN": ".example.com", "TINYSESAM_PROTECTED_HOSTS": "app.example.com,wiki.example.com",
    "TINYSESAM_ALLOWED_GROUPS": "staff,ops", "TINYSESAM_OIDC_SCOPES": "openid profile email groups",
    "TINYSESAM_OIDC_NAME": "Example ID", "TINYSESAM_GATE_BRAND": "Example", "TINYSESAM_BRAND_ICON": "/icon.svg",
    "TINYSESAM_BRAND_ICON_TITLE": "Example", "TINYSESAM_BRAND_BACKGROUNDS": "/a.jpg /b.jpg",
    "TINYSESAM_BRAND_BACKGROUND_SECONDS": "20", "TINYSESAM_BRAND_BACKGROUND_CREDIT_TEXT": "Photos",
    "TINYSESAM_BRAND_BACKGROUND_CREDIT_URL": "https://example.com/photos", "TINYSESAM_DB": DB,
    "TINYSESAM_HTTPS_MODE": "force", "TINYSESAM_SECURITY_LOG": os.path.join(TMP, "sec.log"),
    "TINYSESAM_TRUSTED_PROXIES": "192.0.2.0/24", "TINYSESAM_OIDC_REVALIDATE_MINUTES": "15", "TINYSESAM_GATE": "1",
    "TINYSESAM_GATE_LINK": "0", "TINYSESAM_LANG": "de", "TINYSESAM_FORWARD_LOGIN": "page",
    "TINYSESAM_FORWARD_APPS": '{"wiki.example.com": {"name": "Wiki"}}', "TINYSESAM_FORWARD_LOGOUT": "ask",
    "TINYSESAM_FORWARD_LOGGED_OUT_SEC": "5", "TINYSESAM_GATE_TTL_SEC": "120", "TINYSESAM_OAUTH_SERVICE_CLIENTS": "1",
    "TINYSESAM_TOPBAR_LINKS": '[["Wiki", "/wiki"]]', "TINYSESAM_TOPBAR_MENU_LINKS": '[["Help", "/help"]]',
}
assert set(SAMPLES) == {name for name, _, _ in gateway.ENVIRONMENT_FIELDS}, "a sample per overlay variable"
with Env(**SAMPLES):
    preset = gateway.config_from_env()
    overlay = gateway.environment_overlay()
for name, field_name, _ in gateway.ENVIRONMENT_FIELDS:
    assert overlay[field_name] == getattr(preset, field_name), (name, overlay[field_name], getattr(preset, field_name))
assert len({f for _, f, _ in gateway.ENVIRONMENT_FIELDS}) == len(gateway.ENVIRONMENT_FIELDS), "one field per variable"
assert set(overlay) <= set(field_names())
with Env(TINYSESAM_OIDC_CLIENT_APP_EXAMPLE_COM_ID="app", TINYSESAM_OIDC_CLIENT_APP_EXAMPLE_COM_SECRET="s",
         TINYSESAM_PROTECTED_HOSTS="app.example.com"):
    assert gateway.environment_overlay()["oidc_clients"] == {"app.example.com": {"client_id": "app",
                                                                                  "client_secret": "s"}}
assert "oidc_clients" not in gateway.environment_overlay() and "oauth_enabled" not in gateway.environment_overlay()
ok(f"all {len(SAMPLES)} overlay variables read the same value as the gateway without a file; per-host clients too")

# (e) without the file nothing changes: the variables are required as before
try:
    gateway.config_from_env()
    raise AssertionError("no file, no variables — and still a configuration")
except SystemExit as e:
    assert "TINYSESAM_OIDC_ISSUER" in str(e), str(e)
ok("without TINYSESAM_CONFIG the gateway still requires its variables (OIDC preset unchanged)")

# (f) a key that is no field, broken TOML, a missing file: a start error that says what to do
message = refused('password_enabeld = true\n', "password_enabeld", "did you mean 'password_enabled'")
refused('base_url = "x"\n[apps\n', "not valid TOML")
for text, path in (("", os.path.join(TMP, "nothing-here.toml")),):
    with Env(TINYSESAM_CONFIG=path):
        try:
            gateway.config_from_env()
            raise AssertionError("a missing file was accepted")
        except SystemExit as e:
            assert "cannot be read" in str(e) and path in str(e), str(e)
assert set(field_names()) == {f.name for f in dataclasses.fields(TinySesamConfig)}, "every field is a key"
ok("unknown key (with the nearest field), broken TOML and a missing file end the start with a reason")

# (g) secrets: never a literal; env:NAME or <field>_file; nested client secrets the same
for name in SECRET_FIELDS:
    refused(f'{name} = "hunter2-literal"\n', name, "never stands in the file as a literal")
    # The files are written outside the asserts: under `python -O` an assert is dropped with its side effects.
    from_env = values_from_file(write("s.toml", f'{name} = "env:MY_SECRET"\n'), env={"MY_SECRET": "from-env"})
    assert from_env[name] == "from-env"
    refused(f'{name} = "env:MISSING_ONE"\n', "MISSING_ONE", "is not set")
    secret_file = write("secret.txt", "from-file\n")
    from_file = values_from_file(write("s.toml", f'{name}_file = "{secret_file}"\n'), env={})
    assert from_file[name] == "from-file"
    refused(f'{name} = "env:X"\n{name}_file = "{secret_file}"\n', "not both", env={"X": "1"})
    refused(f'{name}_file = "{os.path.join(TMP, "absent")}"\n', "cannot be read")
    empty = values_from_file(write("s.toml", f'{name} = ""\n'), env={})
    assert empty[name] == ""
refused('[oidc_clients."app.example.com"]\nclient_id = "a"\nclient_secret = "literal"\n',
        "oidc_clients", "client_secret", "literal")
clients = values_from_file(write("c.toml", '[oidc_clients."App.Example.com"]\nclient_id = "a"\n'
                                           'client_secret = "env:APP_SECRET"\n'), env={"APP_SECRET": "s3"})["oidc_clients"]
assert clients == {"app.example.com": {"client_id": "a", "client_secret": "s3"}}, clients
ok("secret fields: a literal is refused; env:NAME and <field>_file resolve; both at once or unreadable: refused")

# (h) a file with OIDC through the overlay: the gateway preset's variables still work on top of a file
OIDC = write("oidc.toml", f'''base_url = "https://auth.example.com"
db_path = "{os.path.join(TMP, 'oidc.db')}"
oidc_enabled = true
oidc_client_secret = "env:OIDC_SECRET"
password_enabled = true
''')
with Env(TINYSESAM_CONFIG=OIDC, OIDC_SECRET="s3cr3t", TINYSESAM_OIDC_ISSUER="https://id.example.com",
         TINYSESAM_OIDC_CLIENT_ID="gw"):
    cfg = gateway.config_from_env()
assert cfg.oidc_enabled and cfg.password_enabled and cfg.oidc_issuer == "https://id.example.com"
assert cfg.oidc_client_id == "gw" and cfg.oidc_client_secret == "s3cr3t"
ok("OIDC and local accounts side by side from one file, issuer and client from the environment")
print("OK test_server_config")
