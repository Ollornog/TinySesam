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
                 trusted_redirect_hosts=["app.example.com"], allowed_groups=["leute"],
                 oidc_scopes="openid profile email groups")
    values.update(w)
    return TinySesamConfig.oidc_gateway(**values)


def has(warn, part):
    return any(part in w for w in warn)


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
    """Every template that `config_check` passes to `_t(...)` (AST of config_check.py and config.py)
    plus the values of the label dicts, which `_t(config, wofuer)` takes as variable."""
    key_name, variable = set(), 0
    for file in ("config_check.py", "config.py"):
        tree = ast.parse((Path(config_check.__file__).parent / file).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "_t" and len(node.args) > 1):
                if isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str):
                    key_name.add(node.args[1].value)
                else:
                    variable += 1
    for dictionary in (config_check.REQUIRES_MAILER, config_check.REQUIRES_BASE_URL,
                        config_check.BASE_URL_RECOMMENDED):
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
assert len(_key_name) > 50 and _variable == 3, (len(_key_name), _variable)   # the three `_t(config, wofuer)`
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
       "setting never takes effect."] = "{xx} fehlt"
assert _real is config_check._DE and _gaps(_real) == []
assert _gaps(_without) and _gaps(_renamed) and _gaps(_place) and _gaps(_foreign)
# … and the effect: with the key missing, lang="de" falls back to English and the language check goes red.
_secured = config_check._DE
config_check._DE = _without
try:
    assert not _language_matches(), "the German finding fell back to English and the check did not notice"
finally:
    config_check._DE = _secured
assert _language_matches()
ok("mutation on a copy of _DE (key removed, renamed, placeholder changed) → completeness and language check go red")

print("configuration check gate OK")
