"""Configuration check for gate operation (T-23): warnings that fit the built state.

Errors (start aborts) are with their function: test_gate.py (cookie name, lifetime, without
forward auth), test_login_modes.py (`direct` next to other methods, typo in forward_apps),
test_logout_modes.py (unknown logout mode). Here the warnings — the start succeeds, but a
setting does not do what its name promises.
"""
from tinysesam import TinySesamConfig
from tinysesam import config_check


def ok(name):
    print(f"  ✓ {name}")


def warnungen(cfg):
    fehler, warn = config_check.check_config(cfg)
    assert not fehler, fehler
    return warn


def lib(**w):
    return TinySesamConfig(db_path=":memory:", **w)


def gateway(**w):
    werte = dict(issuer="https://id.example.com", client_id="c", client_secret="s",
                 base_url="https://auth.example.com", db_path=":memory:",
                 trusted_redirect_hosts=["app.example.com"], allowed_groups=["leute"],
                 oidc_scopes="openid profile email groups")
    werte.update(w)
    return TinySesamConfig.oidc_gateway(**werte)


def hat(warn, teil):
    return any(teil in w for w in warn)


# Lifetime of the gate token: above 15 minutes a deliberate revocation delay.
basis = dict(forward_auth_enabled=True, gate_token_enabled=True, trusted_redirect_hosts=["app.example.com"])
assert hat(warnungen(lib(**basis, gate_token_ttl_sec=901)), "gate_token_ttl_sec=901")
assert not hat(warnungen(lib(**basis, gate_token_ttl_sec=900)), "gate_token_ttl_sec")
assert not hat(warnungen(lib(**basis)), "gate_token_ttl_sec")
ok("gate_token_ttl_sec above 900 → warning (revocation delay), up to 900 silent")

# Gate on, but no host for which a token would arise.
assert hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True)), "kein geschützter Host")
assert not hat(warnungen(lib(**basis)), "kein geschützter Host")
assert not hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True,
                             base_url="https://auth.example.com")), "kein geschützter Host")
ok("gate without protected host → warning; with trusted_redirect_hosts or base_url silent")

# forward_apps without forward auth: nobody reads them.
assert hat(warnungen(lib(forward_apps={"app.example.com": {"name": "App"}})), "forward_apps ist gesetzt")
assert not hat(warnungen(lib(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                             forward_apps={"app.example.com": {"name": "App"}})), "forward_apps ist gesetzt")
ok("forward_apps without forward_auth_enabled → warning")

# direct + sign-out without provider logout: signing out acted like a reload.
assert not hat(warnungen(gateway()), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False)), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="ask")), "oidc_rp_logout=False")
assert not hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="app")), "oidc_rp_logout=False")
assert not hat(warnungen(gateway(oidc_rp_logout=False, forward_login="page")), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="app",
                             forward_apps={"app.example.com": {"logout": "all"}})), "oidc_rp_logout=False")
ok("direct + sign-out all/ask without oidc_rp_logout → warning (also per app); app or page silent")

# “sign out here only” + direct is NO case any more: the lockout on the session holds (T-22).
assert not [w for w in warnungen(gateway(forward_logout="app")) if "logout" in w.lower()]
ok("forward_logout=app with direct → no warning (the lockout on the session holds)")

print("configuration check gate OK")
