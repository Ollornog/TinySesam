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
assert hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True)), "no protected host")
assert not hat(warnungen(lib(**basis)), "no protected host")
assert not hat(warnungen(lib(forward_auth_enabled=True, gate_token_enabled=True,
                             base_url="https://auth.example.com")), "no protected host")
ok("gate without protected host → warning; with trusted_redirect_hosts or base_url silent")

# forward_apps without forward auth: nobody reads them.
assert hat(warnungen(lib(forward_apps={"app.example.com": {"name": "App"}})), "forward_apps is set")
assert not hat(warnungen(lib(forward_auth_enabled=True, trusted_redirect_hosts=["app.example.com"],
                             forward_apps={"app.example.com": {"name": "App"}})), "forward_apps is set")
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

# ---------- Language of the findings: English by default, German with lang="de" ----------
# One configuration that yields an error ("direct" next to the password login) and a warning (gate
# without protected host) at the same time; the text of both comes from `_t(config, …)`.
def _funde(lang):
    return config_check.check_config(lib(forward_auth_enabled=True, gate_token_enabled=True,
                                         forward_login="direct", lang=lang))


def _sprache_stimmt():
    """(a) and (b) in one: True only if English is English and German is German."""
    fehler_en, warn_en = _funde("en")
    fehler_de, warn_de = _funde("de")
    en = " ".join(fehler_en + warn_en)
    de = " ".join(fehler_de + warn_de)
    return (fehler_en and warn_en and fehler_de and warn_de
            and hat(warn_en, "no protected host") and hat(fehler_en, "the only login method")
            and not any(ch in en for ch in "äöüÄÖÜß") and "kein geschützter Host" not in en
            and "einzige Anmeldemethode" not in en
            and hat(warn_de, "kein geschützter Host") and hat(fehler_de, "einzige Anmeldemethode")
            and "no protected host" not in de and "the only login method" not in de)


assert config_check.check_config(lib(forward_auth_enabled=True, gate_token_enabled=True))[1] == _funde("en")[1], \
    "lang default is English"
assert _sprache_stimmt()
ok('lang="en" (default): findings in English without umlauts; lang="de": the German wording')


# ---------- Completeness of the German table ----------
def _platzhalter(text):
    return {name for _, name, _, _ in string.Formatter().parse(text) if name is not None}


def _benutzte_schluessel():
    """Every template that `config_check` passes to `_t(...)` (AST of config_check.py and config.py)
    plus the values of the label dicts, which `_t(config, wofuer)` takes as variable."""
    schluessel, variabel = set(), 0
    for datei in ("config_check.py", "config.py"):
        baum = ast.parse((Path(config_check.__file__).parent / datei).read_text(encoding="utf-8"))
        for knoten in ast.walk(baum):
            if (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Name)
                    and knoten.func.id == "_t" and len(knoten.args) > 1):
                if isinstance(knoten.args[1], ast.Constant) and isinstance(knoten.args[1].value, str):
                    schluessel.add(knoten.args[1].value)
                else:
                    variabel += 1
    for woerterbuch in (config_check.BRAUCHT_MAILER, config_check.BRAUCHT_BASE_URL,
                        config_check.BASE_URL_EMPFOHLEN):
        schluessel.update(woerterbuch.values())
    return schluessel, variabel


def _luecken(de):
    """Problems of the table `de` against the keys that the code uses."""
    schluessel, _ = _benutzte_schluessel()
    probleme = [f"missing: {k[:60]!r}" for k in sorted(schluessel) if k not in de]
    probleme += [f"placeholders differ: {k[:60]!r}" for k in sorted(schluessel)
                 if k in de and _platzhalter(k) != _platzhalter(de[k])]
    return probleme


_schluessel, _variabel = _benutzte_schluessel()
assert len(_schluessel) > 50 and _variabel == 3, (len(_schluessel), _variabel)   # the three `_t(config, wofuer)`
assert _luecken(config_check._DE) == [], _luecken(config_check._DE)
ok("every key that config_check uses is in _DE, placeholders in key and value equal")

# Mutation, on a copy only: remove a key, rename a key, change a placeholder in the value.
_echt = config_check._DE
_k = next(k for k in _schluessel if "no protected host" in k)
_ohne = {k: v for k, v in _echt.items() if k != _k}
_umbenannt = {(k + " ") if k == _k else k: v for k, v in _echt.items()}
_platz = {k: (v.replace("{real}", "{echt}") if "{real}" in k else v) for k, v in _echt.items()}
_fremd = dict(_echt)
_fremd["{wo} is not in trusted_redirect_hosts — there is no redirect back for this host, the "
       "setting never takes effect."] = "{xx} fehlt"
assert _echt is config_check._DE and _luecken(_echt) == []
assert _luecken(_ohne) and _luecken(_umbenannt) and _luecken(_platz) and _luecken(_fremd)
# … and the effect: with the key missing, lang="de" falls back to English and the language check goes red.
_gesichert = config_check._DE
config_check._DE = _ohne
try:
    assert not _sprache_stimmt(), "the German finding fell back to English and the check did not notice"
finally:
    config_check._DE = _gesichert
assert _sprache_stimmt()
ok("mutation on a copy of _DE (key removed, renamed, placeholder changed) → completeness and language check go red")

print("configuration check gate OK")
