"""F2: Config-Presets — active_directory (LDAP/AD) + entra_id (Azure AD via OIDC)."""
from tinysesam import TinySesamConfig


def ok(name):
    print(f"  ✓ {name}")


# ---------- active_directory: Direkt-Bind per UPN ----------
cfg = TinySesamConfig.active_directory(ldap_url="ldaps://dc.corp:636", upn_suffix="corp.example.com",
                                       allowed_groups=["Domain Users"], db_path="x.db")
assert cfg.ldap_enabled and cfg.ldap_url == "ldaps://dc.corp:636"
assert cfg.ldap_user_dn_template == "{username}@corp.example.com"
assert cfg.ldap_group_attr == "memberOf" and cfg.ldap_allowed_groups == ["Domain Users"]
assert cfg.ldap_attr_name == "displayName" and cfg.db_path == "x.db"
ok("active_directory (UPN): ldap_user_dn_template gesetzt, memberOf-Gate, Attribute")

# ---------- active_directory: Search-then-Bind (sAMAccountName) ----------
cfg = TinySesamConfig.active_directory(ldap_url="ldap://dc.corp:389", bind_dn="CN=svc,DC=corp",
                                       bind_password="pw", base_dn="DC=corp,DC=example,DC=com")
assert cfg.ldap_bind_dn == "CN=svc,DC=corp" and cfg.ldap_user_filter == "(sAMAccountName={username})"
assert cfg.ldap_user_base == "DC=corp,DC=example,DC=com" and not cfg.ldap_user_dn_template
ok("active_directory (Search-then-Bind): sAMAccountName-Filter + Service-Account")

# ---------- entra_id: OIDC gegen Azure AD ----------
cfg = TinySesamConfig.entra_id(tenant_id="abc-123", client_id="cid", client_secret="sec")
assert cfg.oidc_enabled and cfg.oidc_client_id == "cid"
assert cfg.oidc_issuer == "https://login.microsoftonline.com/abc-123/v2.0"
assert "oidc" in cfg.enabled_methods()
ok("entra_id: OIDC-Issuer aus tenant_id, oidc aktiv")

# ---------- overrides greifen ----------
cfg = TinySesamConfig.entra_id(tenant_id="t", client_id="c", client_secret="s", db_path="app.db", lang="de")
assert cfg.db_path == "app.db" and cfg.lang == "de"
ok("Presets: **overrides (db_path/lang …) werden übernommen")

print("\nPRESETS OK ✅")
