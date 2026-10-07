"""Konfigurationsprüfung für den Gate-Betrieb (T-23): Warnungen, die zum gebauten Stand passen.

Fehler (Start bricht ab) stehen bei ihrer Funktion: test_gate.py (Cookie-Name, Laufzeit, ohne
Forward-Auth), test_login_modi.py (`direct` neben anderen Methoden, Tippfehler in forward_apps),
test_logout_modi.py (unbekannter Logout-Modus). Hier die Warnungen — der Start gelingt, aber eine
Einstellung tut nicht, was ihr Name verspricht.
"""
from tinysesam import TinySesamConfig
from tinysesam import konfigpruefung


def ok(name):
    print(f"  ✓ {name}")


def warnungen(cfg):
    fehler, warn = konfigpruefung.pruefe(cfg)
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


# Laufzeit des Gate-Tokens: über 15 Minuten ein bewusster Widerrufsverzug.
basis = dict(forward_auth_enabled=True, gate_token_enabled=True, trusted_redirect_hosts=["app.example.com"])
assert hat(warnungen(lib(**basis, gate_token_ttl_sec=901)), "gate_token_ttl_sec=901")
assert not hat(warnungen(lib(**basis, gate_token_ttl_sec=900)), "gate_token_ttl_sec")
assert not hat(warnungen(lib(**basis)), "gate_token_ttl_sec")
ok("gate_token_ttl_sec über 900 → Warnung (Widerrufsverzug), bis 900 still")

# Gate an, aber kein Host, für den ein Token entstünde.
assert hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True)), "kein geschützter Host")
assert not hat(warnungen(lib(**basis)), "kein geschützter Host")
assert not hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True,
                             base_url="https://auth.example.com")), "kein geschützter Host")
ok("Gate ohne geschützten Host → Warnung; mit trusted_redirect_hosts oder base_url still")

# forward_apps ohne Forward-Auth: niemand liest sie.
assert hat(warnungen(lib(forward_apps={"app.example.com": {"name": "App"}})), "forward_apps ist gesetzt")
assert not hat(warnungen(lib(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                             forward_apps={"app.example.com": {"name": "App"}})), "forward_apps ist gesetzt")
ok("forward_apps ohne forward_auth_enabled → Warnung")

# direct + Abmelden ohne Provider-Logout: Abmelden wirkte wie ein Neuladen.
assert not hat(warnungen(gateway()), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False)), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="ask")), "oidc_rp_logout=False")
assert not hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="app")), "oidc_rp_logout=False")
assert not hat(warnungen(gateway(oidc_rp_logout=False, forward_login="page")), "oidc_rp_logout=False")
assert hat(warnungen(gateway(oidc_rp_logout=False, forward_logout="app",
                             forward_apps={"app.example.com": {"logout": "all"}})), "oidc_rp_logout=False")
ok("direct + Abmelden all/ask ohne oidc_rp_logout → Warnung (auch je App); app oder page still")

# „nur hier abmelden" + direct ist KEIN Fall mehr: die Sperre an der Sitzung hält (T-22).
assert not [w for w in warnungen(gateway(forward_logout="app")) if "logout" in w.lower()]
ok("forward_logout=app mit direct → keine Warnung (die Sperre an der Sitzung hält)")

print("Konfigurationsprüfung Gate OK")
