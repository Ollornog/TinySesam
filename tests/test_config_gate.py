"""Configuration check for gate operation (T-23): warnings that fit the built state.

Errors (start aborts) are with their function: test_gate.py (cookie name, lifetime, without
forward auth), test_login_modes.py (`direct` next to other methods, typo in forward_apps),
test_logout_modes.py (unknown logout mode). Here the warnings — the start succeeds, but a
setting does not do what its name promises.
"""
import ast
import string
from pathlib import Path

from tinysesam import TinySesamConfig
from tinysesam import config_check


def ok(name):
    print(f"  ✓ {name}")


def warnings(cfg):
    error, warn = config_check.check_config(cfg)
    assert not error, error
    return warn


def lib(**w):
    return TinySesamConfig(db_path=":memory:", **w)


def gateway(**w):
    values = dict(issuer="https://id.example.com", client_id="c", client_secret="s",
                 base_url="https://auth.example.com", db_path=":memory:",
                 trusted_redirect_hosts=["app.example.com"], allowed_groups=["people"],
                 oidc_scopes="openid profile email groups")
    values.update(w)
    return TinySesamConfig.oidc_gateway(**values)


def has(warn, part):
    return any(part in w for w in warn)


# Roles in use but available_roles empty: the admin panel then offers a free-text field instead of checkboxes, and a
# typo there creates a new role silently. The configuration shows the roles of the group maps; the database is checked
# at start (tests/test_admin.py). (Mutation probe: drop `_roles_without_list` from check_config → red.)
_mapped = lib(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="c", oidc_client_secret="s",
              base_url="https://app.example.com", oidc_group_role_map={"staff": "editors", "ops": "__admin__"})
assert has(warnings(_mapped), "available_roles is empty") and has(warnings(_mapped), "editors")
assert not has(warnings(_mapped), "__admin__ ") and not any("'__admin__'" in w for w in warnings(_mapped))
_listed = lib(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="c", oidc_client_secret="s",
              base_url="https://app.example.com", oidc_group_role_map={"staff": "editors"}, available_roles=["editors"])
assert not has(warnings(_listed), "available_roles is empty")
_only_admin = lib(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="c", oidc_client_secret="s",
                  base_url="https://app.example.com", oidc_group_role_map={"ops": "__admin__"})
assert not has(warnings(_only_admin), "available_roles is empty"), "the admin target is no role"
assert not has(warnings(lib(oidc_enabled=True, oidc_issuer="https://id.example.com", oidc_client_id="c",
                            oidc_client_secret="s", base_url="https://app.example.com", admin_enabled=False,
                            oidc_group_role_map={"staff": "editors"})), "available_roles is empty"), "no panel"
ok("group maps assign roles, available_roles empty → warning naming the roles (not with the list, not for __admin__ "
   "only, not without panel)")

# Lifetime of the gate token: above 15 minutes a deliberate revocation delay.
base = dict(forward_auth_enabled=True, gate_token_enabled=True, trusted_redirect_hosts=["app.example.com"])
assert has(warnings(lib(**base, gate_token_ttl_sec=901)), "gate_token_ttl_sec=901")
assert not has(warnings(lib(**base, gate_token_ttl_sec=900)), "gate_token_ttl_sec")
assert not has(warnings(lib(**base)), "gate_token_ttl_sec")
ok("gate_token_ttl_sec above 900 → warning (revocation delay), up to 900 silent")

# Gate on, but no host for which a token would arise.
assert has(warnings(lib(forward_auth_enabled=True, gate_token_enabled=True)), "no protected host")
assert not has(warnings(lib(**base)), "no protected host")
assert not has(warnings(lib(forward_auth_enabled=True, gate_token_enabled=True,
                             base_url="https://auth.example.com")), "no protected host")
ok("gate without protected host → warning; with trusted_redirect_hosts or base_url silent")

# forward_apps without forward auth: nobody reads them.
assert has(warnings(lib(forward_apps={"app.example.com": {"name": "App"}})), "forward_apps is set")
assert not has(warnings(lib(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                             forward_apps={"app.example.com": {"name": "App"}})), "forward_apps is set")
ok("forward_apps without forward_auth_enabled → warning")

# direct + sign-out without provider logout: signing out acted like a reload.
assert not has(warnings(gateway()), "oidc_rp_logout=False")
assert has(warnings(gateway(oidc_rp_logout=False)), "oidc_rp_logout=False")
assert has(warnings(gateway(oidc_rp_logout=False, forward_logout="ask")), "oidc_rp_logout=False")
assert not has(warnings(gateway(oidc_rp_logout=False, forward_logout="app")), "oidc_rp_logout=False")
assert not has(warnings(gateway(oidc_rp_logout=False, forward_login="page")), "oidc_rp_logout=False")
assert has(warnings(gateway(oidc_rp_logout=False, forward_logout="app",
                             forward_apps={"app.example.com": {"logout": "all"}})), "oidc_rp_logout=False")
ok("direct + sign-out all/ask without oidc_rp_logout → warning (also per app); app or page silent")

# “sign out here only” + direct is NO case any more: the lockout on the session holds (T-22).
assert not [w for w in warnings(gateway(forward_logout="app")) if "logout" in w.lower()]
ok("forward_logout=app with direct → no warning (the lockout on the session holds)")

# ---------- Language of the findings: English by default, German with lang="de" ----------
# One configuration that yields an error ("direct" next to the password login) and a warning (gate
# without protected host) at the same time; the text of both comes from `_t(config, …)`.
def _hits(lang):
    return config_check.check_config(lib(forward_auth_enabled=True, gate_token_enabled=True,
                                         forward_login="direct", lang=lang))


def _language_matches():
    """(a) and (b) in one: True only if English is English and German is German."""
    error_en, warn_en = _hits("en")
    error_de, warn_de = _hits("de")
    en = " ".join(error_en + warn_en)
    de = " ".join(error_de + warn_de)
    return (error_en and warn_en and error_de and warn_de
            and has(warn_en, "no protected host") and has(error_en, "the only login method")
            and not any(ch in en for ch in "äöüÄÖÜß") and "kein geschützter Host" not in en
            and "einzige Anmeldemethode" not in en
            and has(warn_de, "kein geschützter Host") and has(error_de, "einzige Anmeldemethode")
            and "no protected host" not in de and "the only login method" not in de)


assert config_check.check_config(lib(forward_auth_enabled=True, gate_token_enabled=True))[1] == _hits("en")[1], \
    "lang default is English"
assert _language_matches()
ok('lang="en" (default): findings in English without umlauts; lang="de": the German wording')


# ---------- Completeness of the German table ----------
def _placeholder(text):
    return {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}


def _used_key_name():
    """Every template that `config_check` passes to `_t(...)` (AST of config_check.py, its parts and config.py)
    plus the values of the label dicts, which `_t(config, for_what)` takes as variable."""
    key_name, variable = set(), 0
    package = Path(config_check.__file__).parent
    # config_check and its parts by feature (`_config_check_<part>.py`, T-112)
    for path in [package / "config_check.py", *sorted(package.glob("_config_check_*.py")), package / "config.py"]:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "_t" and len(node.args) > 1):
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    key_name.add(node.args[1].value)
                else:
                    variable += 1
    for dictionary in (config_check.REQUIRES_MAILER, config_check.REQUIRES_BASE_URL,
                        config_check.BASE_URL_RECOMMENDED, config_check.APPROVAL_FINDINGS):
        key_name.update(dictionary.values())
    return key_name, variable


def _gaps(de):
    """Problems of the table `de` against the keys that the code uses."""
    key_name, _ = _used_key_name()
    problems = [f"missing: {k[:60]!r}" for k in sorted(key_name) if k not in de]
    problems += [f"placeholders differ: {k[:60]!r}" for k in sorted(key_name)
                 if k in de and _placeholder(k) != _placeholder(de[k])]
    return problems


_key_name, _variable = _used_key_name()
# the three `_t(config, for_what)` and the one `_t(config, APPROVAL_FINDINGS[key], …)` of the approval types
assert len(_key_name) > 50 and _variable == 4, (len(_key_name), _variable)
assert _gaps(config_check._DE) == [], _gaps(config_check._DE)
ok("every key that config_check uses is in _DE, placeholders in key and value equal")

# Mutation, on a copy only: remove a key, rename a key, change a placeholder in the value.
_real = config_check._DE
_k = next(k for k in _key_name if "no protected host" in k)
_without = {k: v for k, v in _real.items() if k != _k}
_renamed = {(k + " ") if k == _k else k: v for k, v in _real.items()}
_place = {k: (v.replace("{real}", "{mutated}") if "{real}" in k else v) for k, v in _real.items()}
_foreign = dict(_real)
_foreign["{where} is not in trusted_redirect_hosts — there is no redirect back for this host, the "
       "setting never takes effect."] = "{xx} missing"
assert _real is config_check._DE and _gaps(_real) == []
assert _gaps(_without) and _gaps(_renamed) and _gaps(_place) and _gaps(_foreign)
# … and the effect: with the key missing, lang="de" falls back to English and the language check goes red.
# `_t` reads the table in the shared helpers of the rules (`_config_check_base`, T-112) — the patch goes there.
from tinysesam import _config_check_base  # noqa: E402
_secured = _config_check_base._DE
_config_check_base._DE = _without
try:
    assert not _language_matches(), "the German finding fell back to English and the check did not notice"
finally:
    _config_check_base._DE = _secured
assert _language_matches()
ok("mutation on a copy of _DE (key removed, renamed, placeholder changed) → completeness and language check go red")

print("configuration check gate OK")
