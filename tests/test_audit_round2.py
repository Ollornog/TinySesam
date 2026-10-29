"""Reproduced findings of the second audit (2026-09-21).

The first pass repaired six gaps. This one checks the **repairs** — and three of
them had torn open a hole of their own: the first-admin guard only moved the gap, the
API-key pruning made a key more powerful instead of weaker, and `tinysesam backup`
migrated the very file it was meant to back up.

As in `test_security_findings.py`: named after the ATTACK or the operating case, not after
the function. Whoever sees a line here go red knows at once what has become possible again.
"""
from __future__ import annotations

import itertools as _itertools
import io
import logging
import os
import re
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
_FALSCH = _itertools.count()   # always NEW wrong passwords: a repetition counts only once since 0.24.9

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

import pyotp  # noqa: E402
from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import ConfigError, TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import security as _sec  # noqa: E402
from tinysesam.store import Store  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Audit round 2 — the repairs of the repairs")


def _app(**cfg):
    tmp = tempfile.mkdtemp()
    # `base_url` belongs in the basic setup since it became mandatory for mail paths/OIDC/SAML:
    # without it every setup failed here — for a reason that has nothing to do with the
    # finding under test. A single call still overrides it.
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False,
                 base_url="http://testserver")
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


# ── First admin via the USERNAME ──────────────────────────────────────────────
# The guard from round 1 demands an E-MAIL in `admin_identifiers` when registration is open
# ("whoever has the mailbox has the name"). But `maybe_promote_admin` still compared name OR
# e-mail — and the username is a free text field. The gap had only been moved.
auth_a, _ = _app(admin_identifiers=["chef@example.com"], allow_signup=True,
                 signup_require_email=True, signup_verify_email=True,
                 magiclink_enabled=True, smtp_host="mail.example.com")
angreifer = auth_a.create_user("chef@example.com", password="geheim12345",
                               email="angreifer@evil.example")
r.check("whoever registers under the admin ADDRESS as username does not become admin",
        not auth_a._maybe_promote_admin(auth_a.get_user(angreifer)),
        "he is admin — the guard checks the configuration, the comparison something else")

# Own instance: since R4-12 the same string cannot be the username of one account and the
# e-mail of another. The rightful owner is therefore checked in a clean inventory —
# the question here is the promotion, not the uniqueness.
auth_a2, _ = _app(admin_identifiers=["chef@example.com"], allow_signup=True,
                  signup_require_email=True, signup_verify_email=True,
                  magiclink_enabled=True, smtp_host="mail.example.com")
inhaber = auth_a2.create_user("chefin", password="geheim12345", email="chef@example.com")
r.check("whoever really has the address still becomes admin",
        auth_a2._maybe_promote_admin(auth_a2.get_user(inhaber)),
        "the intended path is closed")

# And conversely: an entry WITHOUT @ applies only to the username.
auth_b, _ = _app(admin_identifiers=["chef"])
mit_mail = auth_b.create_user("jemand", password="geheim12345", email="chef")
r.check("an allowlist name without @ is not checked against the e-mail",
        not auth_b._maybe_promote_admin(auth_b.get_user(mit_mail)),
        "an e-mail that happens to look like the name promotes")


# ── First admin via an IdP address that nobody has confirmed (round 3, F-14) ──
# The T-9 fix above repaired the COMPARISON (address against address) — the PROOF was still missing.
# `oidc.py` read `email` unconditionally and overlooked the standard claim `email_verified` (OIDC
# Core 5.1): whoever entered the admin address at an IdP with self-registration or in a second
# tenant was first admin at the first login. And the guard that forbids allowlist USERNAMES
# depended solely on `allow_signup` — it did not apply at all when an IdP auto-creates accounts,
# although there too the name comes from a foreign hand.
from urllib.parse import parse_qs, urlparse  # noqa: E402

IDP = "https://idp.example.invalid"


class _Claims(dict):
    """What `exchange()` returns. The signature check itself is tested by test_oidc_jwks.py —
    here it is about what TinySesam does WITH the claims."""

    def validate(self, *a, **k):
        pass


def _oidc_app(claims, nutzerinfo=None, **cfg):
    """An app with OIDC but without network: discovery prefilled, token exchange as a dummy.

    `nutzerinfo` is what the /userinfo endpoint returns — kept separate from the ID token,
    because exactly this separation is under test."""
    auth, app = _app(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="probe",
                     oidc_client_secret="geheim", base_url="http://testserver",
                     csrf_enabled=False, **cfg)
    auth.oidc._meta = {"issuer": IDP, "authorization_endpoint": IDP + "/authorize",
                       "token_endpoint": IDP + "/token", "userinfo_endpoint": IDP + "/userinfo",
                       "jwks_uri": IDP + "/jwks"}
    auth.oidc.exchange = lambda code, redirect_uri, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})
    # Only the HTTP fetch is replaced; the `sub` comparison from F-18 runs through the REAL
    # function. A dummy that rebuilds it would check the rebuild instead of the code —
    # a removed check would then go unnoticed here.
    def _userinfo(at, erwartetes_sub=""):
        from tinysesam.oidc import OIDCClient
        return OIDCClient.userinfo_pruefen(dict(nutzerinfo or {}) or {}, erwartetes_sub)

    auth.oidc.userinfo = _userinfo
    return auth, app


def _oidc_login(app):
    """Once through the real flow — start, state, callback from the same browser."""
    c = TestClient(app)
    start = c.get("/auth/oidc/start", follow_redirects=False)
    state = parse_qs(urlparse(start.headers["location"]).query)["state"][0]
    return c.get(f"/auth/oidc/callback?code=x&state={state}", follow_redirects=False)


ANGRIFF = {"sub": "angreifer-123", "preferred_username": "angreifer", "name": "Angreifer",
           "email": "chef@example.com", "email_verified": False}

auth_f, app_f = _oidc_app(ANGRIFF, admin_identifiers=["chef@example.com"])
antwort = _oidc_login(app_f)
konto = auth_f.store.get_user_by_name("angreifer")
r.check("the attacker gets in (the sign-in itself stays allowed)",
        antwort.status_code == 303 and konto is not None,
        f"HTTP {antwort.status_code} — then the rest measures nothing")
r.check("whoever brings an UNCONFIRMED IdP address does not become first admin",
        konto is not None and not konto["is_admin"],
        "he is admin — email_verified is ignored again")
r.check("afterwards the instance still has no admin", not auth_f.admin_exists(),
        "some path promoted after all")
# The address is NOT used (H-3, PO decision 2026-09-24). Until then it was kept
# and passed on as `Remote-Email`, only without rights in TinySesam — but a protected app that
# assigns users by address never saw the note. For a provider that never sends the claim,
# the operator says so explicitly (`oidc_email_verified_default=True`).
r.check("the unconfirmed address is not adopted and is not passed on as Remote-Email",
        konto is not None and not konto["email"]
        and not auth_f._forward_response_headers(konto).get("Remote-Email"),
        f"stored: {konto['email'] if konto else '—'} — the foreign address reaches the app")
r.check("… but is noted as unconfirmed", konto is not None and not konto["email_verified"],
        "the note is missing — then it carries rights again at the next login")
# The note is in the database, not in the sign-in path: otherwise the protection would be open
# exactly here. The same record signed in via a local path (magic link, password) arrives with
# `email_bestaetigt=None` — before the note this would have promoted.
r.check("even a login WITHOUT proof in its luggage does not promote this account",
        not auth_f._maybe_promote_admin(auth_f.get_user(konto["id"])),
        "via a local path the unconfirmed address is first-admin-capable after all")

# Counter-check — without it the check above would also be green if OIDC did nothing at all.
auth_g, app_g = _oidc_app({**ANGRIFF, "sub": "chefin-1", "preferred_username": "chefin",
                           "email_verified": True},
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_g)
chefin = auth_g.store.get_user_by_name("chefin")
r.check("with email_verified=true the intended first admin is still granted",
        chefin is not None and chefin["is_admin"] == 1,
        "the documented bootstrap path is closed")
r.check("and the confirmed address is in the account",
        chefin is not None and chefin["email"] == "chef@example.com"
        and bool(chefin["email_verified"]),
        f"stored: {chefin['email'] if chefin else '—'}")

# The claim is OPTIONAL in OIDC Core 5.1, and some IdPs never send it (the code itself names Entra ID).
# Whoever vouches for their addresses turns the No for the MISSING claim
# around — otherwise `admin_identifiers` would be permanently closed for these IdPs.
auth_v, app_v = _oidc_app({"sub": "entra-1", "preferred_username": "chefin",
                           "email": "chef@example.com"},        # claim missing entirely
                          admin_identifiers=["chef@example.com"],
                          oidc_email_verified_default=True)
_oidc_login(app_v)
entra = auth_v.store.get_user_by_name("chefin")
r.check("with oidc_email_verified_default=True an address without claim counts as proven",
        entra is not None and entra["is_admin"] == 1 and bool(entra["email_verified"]),
        f"Account: {dict(entra) if entra else None} — the path would stay closed for Entra IdPs")
# The switch applies only to the SILENCE of the provider. If it says explicitly "not confirmed",
# a Yes derived from that would be a circumvention of its statement.
auth_v2, app_v2 = _oidc_app({"sub": "entra-2", "preferred_username": "luegner",
                             "email": "chef@example.com", "email_verified": False},
                            admin_identifiers=["chef@example.com"],
                            oidc_email_verified_default=True)
_oidc_login(app_v2)
luegner = auth_v2.store.get_user_by_name("luegner")
r.check("but the switch does not override an explicit email_verified=false",
        luegner is not None and not luegner["is_admin"] and not luegner["email_verified"],
        "the default beats the statement of the provider")

# Existing account: the address is already in the database (created before the fix). Even then
# a login without proof must not promote — otherwise the protection would hang solely on the address in the account.
auth_b3, app_b3 = _oidc_app({"sub": "alt-1", "preferred_username": "altkonto",
                             "email": "chef@example.com"},   # claim missing entirely
                            admin_identifiers=["chef@example.com"])
alt_uid = auth_b3.create_user("altkonto", email="chef@example.com")
auth_b3.store.link_oidc(IDP, "alt-1", alt_uid)
_oidc_login(app_b3)
r.check("an existing account with the address is not promoted retroactively without proof",
        not auth_b3.get_user(alt_uid)["is_admin"],
        "the missing claim counts as confirmed again")
# The same decision directly at the source — shows that the proof carries it and not
# some side effect of the flow: the same line, once without and once with proof.
r.check("maybe_promote_admin refuses with email_bestaetigt=False",
        not auth_b3._maybe_promote_admin(auth_b3.get_user(alt_uid), email_bestaetigt=False))
r.check("and still promotes on a local login (no IdP involved)",
        auth_b3._maybe_promote_admin(auth_b3.get_user(alt_uid)),
        "the local path is closed — there the constructor guard vouches for the confirmation mail")
# That the proof of this existing account survived the OIDC login with a MISSING claim is the
# second half of the same rule: silence is not a statement. If it were, the login would
# just have deleted the confirmation that the operator vouched for at creation.
r.check("a missing claim does not delete the note of an existing account",
        bool(auth_b3.get_user(alt_uid)["email_verified"]),
        "the silence of the provider overwrote the local proof")

# Conversely an explicit statement counts — in both directions, otherwise the note would be a
# one-way valve: a later-delivered `email_verified=true` would have to stay without effect forever, and
# a withdrawn proof would stay in place forever.
def _claims_setzen(auth, claims):
    auth.oidc.exchange = lambda code, ru, nonce, t=None, **_: (
        _Claims({**claims, "nonce": nonce}), {"access_token": "at"})


NACH = {"sub": "nach-1", "preferred_username": "nachtrag", "email": "nach@example.com"}
auth_s, app_s = _oidc_app(NACH)                      # first login: claim missing → unconfirmed
_oidc_login(app_s)
nach = auth_s.store.get_user_by_name("nachtrag")
vorher = bool(nach["email_verified"])
_claims_setzen(auth_s, {**NACH, "email_verified": True})
_oidc_login(app_s)
nachher = bool(auth_s.get_user(nach["id"])["email_verified"])
# Since H-3 the first login creates the account WITHOUT address; the later-delivered proof enters it.
r.check("if the provider delivers the proof later, the address enters the account as proven",
        not vorher and nachher and auth_s.get_user(nach["id"])["email"] == "nach@example.com",
        f"vorher={vorher} nachher={nachher} adresse={auth_s.get_user(nach['id'])['email']}")
_claims_setzen(auth_s, {**NACH, "email_verified": False})
_oidc_login(app_s)
r.check("and if it withdraws it, the note falls again",
        not bool(auth_s.get_user(nach["id"])["email_verified"]),
        "a proof once granted stays in place forever")

# `_flag_wahr` is the only place that turns the claim into a yes/no. The forms come from
# what real providers send. Decisive is the line `"false"` → No: it is the
# difference to any truth test on the raw value (`bool("false")` is true), and with
# such a mutation the suite used to stay green — an address reported as "false" would
# have been first-admin-capable again.
from tinysesam.oidc import _flag_wahr  # noqa: E402

for wert, erwartet in [(True, True), ("true", True), ("True", True), (" TRUE ", True),
                       (1, True), ("1", True),
                       (False, False), ("false", False), ("False", False), (0, False),
                       ("0", False), ("", False), (None, False), ("ja", False), ([], False)]:
    r.check(f"_flag_wahr({wert!r}) → {erwartet}", _flag_wahr(wert) is erwartet,
            f"yields {_flag_wahr(wert)!r}")


# The proof belongs to ITS address — not to the one from the other document.
# The callback merges userinfo document and ID token (`{**nutzerinfo, **claims}`), and
# when merging the address from the ID token won so far, but the proof could come from the
# userinfo document: `email_verified=true` for a DIFFERENT address would have carried the
# unchecked one along. OIDC Core 5.1 means by `email_verified` always the `email` of the SAME response.
auth_m, app_m = _oidc_app({"sub": "misch-1", "preferred_username": "mischer",
                           "email": "chef@example.com"},              # ID token: without proof
                          nutzerinfo={"sub": "misch-1",            # mandatory since F-18
                                      "email": "mischer@fremd.example",
                                      "email_verified": True},        # the proof belongs HERE
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_m)
mischer = auth_m.store.get_user_by_name("mischer")
r.check("a proof from the userinfo document does not carry the address from the ID token",
        mischer is not None and not mischer["is_admin"],
        "Admin — the foreign email_verified was applied to the unchecked address")
r.check("… and it is not adopted at all (H-3)",
        mischer is not None and not mischer["email"] and not mischer["email_verified"],
        f"Account: {dict(mischer) if mischer else None}")

# Counter-check: if the IdP delivers the address ONLY in the userinfo document (common setup),
# the proof there must count normally — otherwise the protection would be a block for everyone.
# Since F-18 the response carries its `sub`: without a matching one it is discarded (OIDC Core 5.3.2),
# which the section below measures separately.
auth_n, app_n = _oidc_app({"sub": "nur-ui-1", "preferred_username": "nurui"},
                          nutzerinfo={"sub": "nur-ui-1",           # mandatory since F-18
                                      "email": "chef@example.com", "email_verified": True},
                          admin_identifiers=["chef@example.com"])
_oidc_login(app_n)
nurui = auth_n.store.get_user_by_name("nurui")
r.check("a confirmed address from the userinfo document still counts",
        nurui is not None and nurui["is_admin"] == 1 and nurui["email"] == "chef@example.com",
        f"Account: {dict(nurui) if nurui else None}")


# The proof exists ONLY with OIDC. SAML has no `email_verified`, and an LDAP `mail`
# is maintained by the user themselves in many directories — via these paths an
# allowlist ADDRESS must therefore NEVER promote. Until rework N4 the latch hung solely on the
# OIDC callback: SAML and LDAP called `apply_factor` without the argument, and `None` meant
# "no IdP involved" — it ran past the latch. Now the FACTOR decides as well: a
# federated path without explicit proof does not promote (fail-closed), so forgetting the
# argument is no longer a hole.
def _bootstrap_probe():
    """Fresh instance with allowlist ADDRESS and an account that carries it.

    Each probe needs its own: `maybe_promote_admin` is not without consequences — a success
    sets the admin flag, and afterwards all further calls only measure `admin_exists`."""
    a, _ = _app(admin_identifiers=["chef@example.com"])
    return a, a.create_user("chefin", email="chef@example.com")


for faktor, beleg, soll, was in (("saml", None, False, "SAML without evidence (argument forgotten)"),
                                 ("oidc", None, False, "OIDC without evidence (argument forgotten)"),
                                 ("saml", False, False, "SAML with an explicit „no evidence\""),
                                 ("password", None, True, "local password login"),
                                 ("oidc", True, True, "OIDC mit email_verified=true")):
    a_p, uid_p = _bootstrap_probe()
    ergebnis = a_p._maybe_promote_admin(a_p.get_user(uid_p), beleg, faktor=faktor)
    r.check(f"{was} → first admin {'YES' if soll else 'NO'}", ergebnis is soll,
            f"maybe_promote_admin returned {ergebnis!r}")


# The latch must also hold the SECOND login — otherwise it is only a delay.
# Without explicit proof `maybe_promote_admin` asks for the note on the account
# (`users.email_verified`), and exactly that was created by `check_ldap`/`check_saml` with the default
# `True`, although via these paths nothing is proven by definition. The attacker signed
# in once (the promotion was correctly refused), set up a PIN or a passkey in his freshly
# signed-in session — self-service — and was first admin at the second login, with a factor that itself claims nothing (B-umgehung-1 from T-13).
# The complete paths via the routes are in `test_ldap.py`/`test_saml.py`; here the
# source of the error: the freshly created account.
class _FakeLDAP:
    """Directory in which the user maintains their `mail` attribute themselves — the F-14 case."""

    @staticmethod
    def authenticate(username, password):
        return {"username": username, "email": "chef@example.com", "name": username,
                "groups": []}


for weg, anlegen in (
        ("LDAP", lambda a: (setattr(a, "ldap", _FakeLDAP()), a._check_ldap("mallory", "x"))[1]),
        ("SAML", lambda a: a._check_saml("mallory", {"email": ["chef@example.com"]}))):
    # Since the PO decision 2026-09-24 the operator says whether he trusts a source
    # (`ldap_email_trusted`, default yes; `saml_email_trusted`, default no). The F-14 case is
    # the source he does NOT trust — then the address is not used at all (as with H-3).
    a_v, _ = _app(admin_identifiers=["chef@example.com"], ldap_enabled=True,
                  ldap_url="ldaps://dir.example.invalid", ldap_email_trusted=False)
    konto = anlegen(a_v)
    r.check(f"an account created via {weg} (source not trusted) does not carry the address",
            konto is not None and not konto["email"] and not konto["email_verified"],
            f"Account: {konto} — the address of an untrusted source ends up on the account")
    # The second jump: a factor the attacker sets up himself (PIN, passkey).
    # It is not federated and hands over no proof — the note alone decides.
    r.check(f"… and a second, self-set-up factor does not promote it after the {weg} login",
            a_v._maybe_promote_admin(a_v.get_user(konto["id"]), faktor="pin") is False,
            "first admin via a detour — the latch only held the first login")
    # Counter-check on the same instance: if the address carries a proof (confirmation mail,
    # operator), exactly the same call promotes. Without it the check above would also
    # be green for a broken promotion.
    a_v.store.set_email(konto["id"], "chef@example.com", verified=True)
    r.check(f"… counter-check: with proof on the account the same call promotes ({weg})",
            a_v._maybe_promote_admin(a_v.get_user(konto["id"]), faktor="pin") is True,
            "the bootstrap path is entirely closed — then the check above measures nothing")


# An address change does not transfer the proof of the OLD address to the NEW one. Since the note
# decides about rights, `store.set_email` would otherwise be a bootstrap path: account with proven
# `eve@example.com` → change the address to the allowlist address → the old proof carries it
# (B-umgehung-8 from T-13). The docstring called that "fail-closed" and meant only the other direction.
a_se, _ = _app(admin_identifiers=["chef@example.com"])
uid_se = a_se.create_user("eve", email="eve@example.com")          # proven (operator)
a_se.store.set_email(uid_se, "chef@example.com")
r.check("an address change via set_email takes the proof away with it",
        not a_se.get_user(uid_se)["email_verified"],
        "the new address carries the proof of the old one")
r.check("… and therefore does not carry the first-admin decision either",
        a_se._maybe_promote_admin(a_se.get_user(uid_se), faktor="password") is False,
        "first admin merely by rewriting an address")
# Counter-check: whoever has a proof for the NEW address says so — then it counts as usual.
a_se2, _ = _app(admin_identifiers=["chef@example.com"])
uid_se2 = a_se2.create_user("eve", email="eve@example.com")
a_se2.store.set_email(uid_se2, "chef@example.com", verified=True)
r.check("… with explicit verified=True the proof stays on the new address",
        a_se2.get_user(uid_se2)["email_verified"] == 1
        and a_se2._maybe_promote_admin(a_se2.get_user(uid_se2), faktor="password") is True,
        "the proven path is closed")


# The operator should learn about this at setup and not while waiting in vain for the
# first admin: the configuration check names the combination and the proven path. Warning,
# not error — with a local password login (confirmed address) the same setup is
# viable, just not via SAML/LDAP.
from tinysesam import config_check as _kp_f14  # noqa: E402

OIDC_AN = dict(oidc_enabled=True, oidc_issuer=IDP, oidc_client_id="c", oidc_client_secret="s")
SAML_AN = dict(saml_enabled=True, saml_idp_sso_url=IDP + "/sso", saml_idp_x509cert="PEM")
LDAP_AN = dict(ldap_enabled=True, ldap_url="ldaps://dir.example.invalid")
for kurz, an in (("SAML", SAML_AN), ("LDAP", LDAP_AN)):
    _f14, _w14 = _kp_f14.check_config(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                                admin_identifiers=["chef@example.com"], **an))
    treffer = [w for w in _w14 if "/auth/claim-admin" in w and kurz in w]
    r.check(f"config_check with admin_identifiers + {kurz} names the path via /auth/claim-admin",
            len(treffer) == 1, f"Warnings: {_w14!r}")
    r.check(f"...and does not turn the {kurz} setup into an error", not _f14, f"Errors: {_f14!r}")

# Counter-checks: OIDC has the proof (there the address continues to carry), and without an IdP
# there is nothing to report at all. A warning that always fires is read by nobody in the end.
_f14b, _w14b = _kp_f14.check_config(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                              admin_identifiers=["chef@example.com"], **OIDC_AN))
r.check("with OIDC it is silent (the claim email_verified is the proof)",
        not any("/auth/claim-admin" in w for w in _w14b), f"{_w14b!r}")
_f14c, _w14c = _kp_f14.check_config(TinySesamConfig(db_path=":memory:", base_url="https://app.example",
                                              admin_identifiers=["chef@example.com"]))
r.check("and without a federated path as well",
        not any("/auth/claim-admin" in w for w in _w14c), f"{_w14c!r}")


# ── R4-12 via the federated paths: the login identifier is ONE space ─────────
# The cross-check sits in `create_user` and thus also applies to the auto-creation from
# OIDC/LDAP/SAML. This half was never measured: four mutations (fallback name → hard 409,
# clean rejection → raw 500) left the full suite green.
auth_k9, app_k9 = _oidc_app({"sub": "k9", "preferred_username": "chef@example.com",
                             "email": "neu@example.com", "email_verified": True})
lokal9 = auth_k9.create_user("chef", password="geheim12345", email="chef@example.com")
antw9 = _oidc_login(app_k9)
r.check("an OIDC name that is the e-mail of an account falls back to a free name",
        antw9.status_code == 303, f"HTTP {antw9.status_code} — the user no longer gets in")
# Since the attack on H-3 (2026-09-24) a `preferred_username` with `@` counts only if it is the
# proven address — here it is a FOREIGN address, so the account is named after the proven one
# (`neu@example.com`), no longer `chef@example.com2`. The promise stays the same: an own,
# free identifier, not an occupied one.
_k9_uid = auth_k9.store.get_oidc_user(IDP, "k9")
_k9_name = auth_k9.store.get_user(_k9_uid)["username"] if _k9_uid else None
r.check("...the new account is named differently", _k9_name not in (None, "chef@example.com", "chef"),
        f"Name {_k9_name!r} — then either rejected or an identifier occupied")
r.check("...and the identifier still points to the local account",
        (auth_k9.find_user("chef@example.com") or {}).get("id") == lokal9,
        "the foreign sign-in took over the identifier")

# What cannot be evaded: the e-mail of the identity. Then only fail-closed remains —
# as a clean rejection, not as a 500 in the middle of the sign-in process.
auth_k11, app_k11 = _oidc_app({"sub": "k11", "preferred_username": "fremd",
                               "email": "kollision@example.com", "email_verified": True})
lokal11 = auth_k11.create_user("kollision@example.com", password="geheim12345")
antw11 = _oidc_login(app_k11)
r.check("an OIDC address that is already a login identifier locally is rejected with 409",
        antw11.status_code == 409, f"HTTP {antw11.status_code} — 500 would be a defect, 303 a hole")
r.check("...and creates no account", auth_k11.store.get_user_by_name("fremd") is None,
        "the account is in the database despite the rejection")
r.check("...the owner keeps their identifier",
        (auth_k11.find_user("kollision@example.com") or {}).get("id") == lokal11,
        "the identifier was occupied")


# ── Allowlist USERNAME while an IdP creates accounts by itself (F-14 b) ──
# The name of an auto-created account comes from `preferred_username` or the
# SAML/LDAP field — confirmed by nobody, just like with open registration.
def _baut_f14(**cfg):
    tmp = tempfile.mkdtemp()
    # `base_url` is not an accessory here but necessary for the probe to say anything at all:
    # without it the constructor throws for OIDC/SAML because of the missing base —
    # `gebaut=False` would then look like a hit of the F-14 guard.
    grund = dict(db_path=str(Path(tmp) / "t.db"), cookie_secure=False,
                 base_url="http://testserver")
    grund.update(cfg)
    try:
        TinySesam(TinySesamConfig(**grund))
        return True, ""
    except ConfigError as e:
        return False, str(e)


gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False, **OIDC_AN)
r.check("allowlist USERNAME + oidc_auto_create is rejected", not gebaut,
        "the instance builds — whoever is called 'chef' at the IdP becomes first admin")
r.check("the rejection names the open door", "oidc_auto_create" in text,
        f"message does not name it: {text[:110]!r}")
for feld, an in (("saml_auto_create", dict(saml_enabled=True,
                                           saml_idp_sso_url=IDP + "/sso",
                                           saml_idp_x509cert="PEM")),
                 ("ldap_auto_create", dict(ldap_enabled=True,
                                           ldap_url="ldaps://dir.example.invalid"))):
    gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False, **an)
    r.check(f"the same for {feld}", not gebaut and feld in text,
            f"gebaut={gebaut}, message: {text[:110]!r}")

# Counter-checks — the guard must not take the viable setups down with it.
gebaut, text = _baut_f14(admin_identifiers=["chef"], allow_signup=False,
                         oidc_auto_create=False, **OIDC_AN)
r.check("without auto-creation the allowlist name stays allowed", gebaut,
        f"too strict: {text[:120]}")
gebaut, text = _baut_f14(admin_identifiers=["chef@example.com"], allow_signup=False, **OIDC_AN)
r.check("an allowlist ADDRESS stays allowed with OIDC (it needs the claim, not a ban)",
        gebaut, f"too strict, the documented bootstrap is closed: {text[:120]}")


# ── An API key scope that shrinks to nothing ─────────────────────────────────
# `["tippfehler"]` became `[]`, and `[]` in the database means "no scope, inherits everything".
# The pruning that was meant to limit made the key more powerful.
auth_k, _ = _app(apikey_enabled=True)
uid_k = auth_k.create_user("bob", password="geheim12345", roles=["kasse", "lager"])

for wunsch, was in ((["lagre"], "typo"), ([], "explicitly empty")):
    try:
        auth_k.create_api_key(uid_k, "k", roles=list(wunsch))
        entstanden = True
    except ConfigError:
        entstanden = False
    r.check(f"a scope that becomes nothing ({was}) creates no key", not entstanden,
            "the key is created — and in the database inherits ALL roles of the account")

schluessel = auth_k.create_api_key(uid_k, "echt", roles=["lager"])
_, rollen = auth_k.verify_api_key(schluessel["key"])
r.check("a valid subset still works", rollen == ["lager"], f"{rollen}")
ohne = auth_k.create_api_key(uid_k, "ohne")
_, rollen2 = auth_k.verify_api_key(ohne["key"])
r.check("without `roles` the key inherits as before", rollen2 is None, f"{rollen2}")


# ── The CSRF off switch in the header ────────────────────────────────────────
# `require_csrf` skipped as soon as any `X-API-Key` was present — unchecked, and afterwards
# the sign-in via the session cookie continued. Also with apikey_enabled=False.
for apikey_an in (False, True):
    auth_c, _ = _app(apikey_enabled=apikey_an)
    chef = auth_c.create_user("chefin", password="geheim12345", is_admin=True)
    app_c = FastAPI()
    app_c.include_router(auth_c.router())
    cc = TestClient(app_c)
    cc.cookies.set(auth_c.cfg.session_cookie,
                   auth_c.store.create_session(chef, 3600, True, "password"))
    mit = cc.post("/auth/admin/api/security", json={"max_login_attempts": 7},
                  headers={"X-API-Key": "voellig-erfunden"})
    r.check(f"an invented X-API-Key does not switch CSRF off (apikey_enabled={apikey_an})",
            mit.status_code == 403, f"HTTP {mit.status_code} — the check can be switched off")

# Counter-check: a REAL key without cookie may still work without a CSRF token.
auth_d, app_d = _app(apikey_enabled=True)
uid_d = auth_d.create_user("daemon", password="geheim12345")
echt = auth_d.create_api_key(uid_d, "bot")["key"]
cd = TestClient(app_d)
r.check("a real key gets through without a CSRF token",
        cd.get("/auth/apikeys", headers={"X-API-Key": echt}).status_code == 200,
        "the daemon path is closed")


# ── A key issues itself a more powerful one ──────────────────────────────────
auth_e, app_e = _app(apikey_enabled=True)
uid_e = auth_e.create_user("bob", password="geheim12345", roles=["kasse", "lager"])
eng = auth_e.create_api_key(uid_e, "eng", roles=["lager"])["key"]
ce = TestClient(app_e)
antwort = ce.post("/auth/apikeys", json={"name": "selbst"}, headers={"X-API-Key": eng})
r.check("an API key cannot issue an API key", antwort.status_code == 403,
        f"HTTP {antwort.status_code} — with it he lifts his own limitation")


# ── A TOTP code that is valid several times ──────────────────────────────────
auth_t, _ = _app()
uid_t = auth_t.create_user("bob", password="geheim12345")
auth_t.totp_begin(uid_t)
geheim = auth_t.store.get_totp(uid_t)["secret"]
auth_t.store.set_totp(uid_t, geheim, confirmed=True)
code = pyotp.TOTP(geheim).now()
r.check("a TOTP code is valid the first time", auth_t._verify_totp(uid_t, code))
r.check("the same code is not valid a second time", not auth_t._verify_totp(uid_t, code),
        "NIST SP 800-63B: „SHALL accept a given OTP only once while it is valid\"")
import time as _t  # noqa: E402

r.check("the next time step still works",
        auth_t._verify_totp(uid_t, pyotp.TOTP(geheim).at(int(_t.time()) + 30)),
        "the one-time booking locks too much")


# ── Unlocked resources in plain text ─────────────────────────────────────────
auth_r2, app_r2 = _app(csrf_enabled=False, resource_locks_enabled=True, pin_enabled=True)
uid_r = auth_r2.create_user("bob", password="geheim12345")
auth_r2.set_resource_secret("tresor", "geheimwort", kind="password", label="Vault")
cr = TestClient(app_r2)
cr.cookies.set(auth_r2.cfg.session_cookie, auth_r2.store.create_session(uid_r, 3600, True, "password"))
cr.post("/auth/resource/tresor", data={"secret": "geheimwort", "next": "/"}, follow_redirects=False)
keks = cr.cookies.get(auth_r2.cfg.resource_cookie)
in_db = [z["token"] for z in auth_r2.store._all("SELECT token FROM resource_unlock")]
r.check("the unlock token is not in plain text in the database",
        keks not in in_db and in_db and len(in_db[0]) == 64,
        f"DB: {in_db[:1]} — whoever reads the file opens every unlocked resource")
r.check("the unlock still works",
        auth_r2.store.is_resource_unlocked(keks, "tresor"),
        "the hashing broke the function")


# ── A log line that points fail2ban at third parties ─────────────────────────
puffer = io.StringIO()
haken = logging.StreamHandler(puffer)
haken.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
_sec.seclog.addHandler(haken)
try:
    auth_f, _ = _app()
    auth_f.create_user("opfer", password="geheim12345")
    auth_f._record_login("opfer\nWARNING failed login user=x ip=198.51.100.5 method=password\nx",
                         "203.0.113.11", success=False, method="password")
finally:
    _sec.seclog.removeHandler(haken)
zeilen = [z for z in puffer.getvalue().splitlines() if "failed login" in z]
r.check("a username with a line break produces exactly ONE log line", len(zeilen) == 1,
        f"{len(zeilen)} lines — fail2ban then counts a foreign IP")
muster = re.compile(r"^\S+ \S+ WARNING failed login user=.* ip=(\S+) method=\S+(?: reason=\S+)?$")
gesehen = [m.group(1) for m in (muster.match(z) for z in zeilen) if m]
r.check("and the bundled filter sees only the real IP", gesehen == ["203.0.113.11"],
        f"{gesehen}")
filter_datei = (ROOT / "deploy" / "fail2ban" / "tinysesam-filter.conf").read_text(encoding="utf-8")
r.check("the filter is anchored to the whole line",
        "^" in filter_datei.split("failregex =")[1].split("\n")[0],
        "without anchoring an inserted line is counted too")


# ── The sign-in fails — and the log does not say why ─────────────────────────
auth_g, _ = _app()
auth_g.create_user("anna", password="geheim12345")
gesperrt = auth_g.create_user("bert", password="geheim12345")
auth_g.store.set_disabled(gesperrt, True)
for name in ("anna", "bert", "carla"):
    auth_g._record_login(name, "203.0.113.9", success=False, method="password")
gruende = {z["username"]: (z["detail"] or "") for z in auth_g.store.recent_audit(20)
           if z["event"] == "login_fail"}
r.check("the log distinguishes wrong secret, locked and missing account",
        "wrong_secret" in gruende.get("anna", "")
        and "account_locked" in gruende.get("bert", "")
        and "no_account" in gruende.get("carla", ""),
        f"{gruende}")


# ── The backup that changes its source ───────────────────────────────────────
ordner = Path(tempfile.mkdtemp())
alt_pfad = ordner / "alt.db"
roh = sqlite3.connect(str(alt_pfad))
roh.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, display_name TEXT,
    is_admin INT DEFAULT 0, disabled INT DEFAULT 0, roles TEXT DEFAULT '[]',
    created_at INT DEFAULT 0, is_service INT DEFAULT 0);
CREATE TABLE session (token TEXT PRIMARY KEY, user_id INT, created_at INT, expires_at INT,
    mfa_ok INT DEFAULT 0, method TEXT);
INSERT INTO users(id, username) VALUES (1, 'admin');
INSERT INTO session VALUES ('KLARTEXT', 1, 0, 99999999999, 1, 'password');""")
roh.commit()
roh.close()
vorher = ([z[1] for z in sqlite3.connect(str(alt_pfad)).execute("PRAGMA table_info(session)")],
          sqlite3.connect(str(alt_pfad)).execute("PRAGMA user_version").fetchone()[0])

lauf = subprocess.run([sys.executable, "-m", "tinysesam", "backup", "--db", str(alt_pfad),
                       str(ordner / "kopie.db")], cwd=ROOT, capture_output=True, text=True)
nachher = ([z[1] for z in sqlite3.connect(str(alt_pfad)).execute("PRAGMA table_info(session)")],
           sqlite3.connect(str(alt_pfad)).execute("PRAGMA user_version").fetchone()[0])
r.check("`tinysesam backup` runs through", lauf.returncode == 0, lauf.stderr[:120])
r.check("...and leaves the SOURCE unchanged", vorher == nachher,
        f"before {vorher} → after {nachher}. Whoever backs up before an update would have migrated "
        "the running installation with it — and closed the way back.")
kopie = sqlite3.connect(str(ordner / "kopie.db"))
r.check("the copy is complete and in the old schema",
        kopie.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 1
        and "token" in [z[1] for z in kopie.execute("PRAGMA table_info(session)")],
        "the backup is not fit for restoring")


# ── The restore that silently does nothing ───────────────────────────────────
# After a crash -wal/-shm are lying next to it; a plain `cp` is overwritten by them.
ordner2 = Path(tempfile.mkdtemp())
ziel = ordner2 / "auth.db"
auth_s = TinySesam(TinySesamConfig(db_path=str(ziel), cookie_secure=False))
for n in ("alt0", "alt1"):
    auth_s.create_user(n, password="geheim12345")
subprocess.run([sys.executable, "-m", "tinysesam", "backup", "--db", str(ziel),
                str(ordner2 / "sicherung.db")], cwd=ROOT, capture_output=True)
auth_s.store.db.close()
# A real crash, not a clean close: the latter checkpoints the WAL and deletes it —
# then the test does not measure the decisive case at all. So a subprocess that ends
# with SIGKILL in the middle of operation.
absturz = (
    "import os, signal\n"
    "from tinysesam import TinySesam, TinySesamConfig\n"
    f"a = TinySesam(TinySesamConfig(db_path={str(ziel)!r}, cookie_secure=False))\n"
    "a.create_user('neu0', password='geheim12345')\n"
    "os.kill(os.getpid(), signal.SIGKILL)\n")
subprocess.run([sys.executable, "-c", absturz], cwd=ROOT, capture_output=True)
r.check("the starting position has a leftover WAL",
        (ordner2 / "auth.db-wal").exists(),
        "without a WAL the test does not measure the decisive case")

# Counter-check: A plain `cp` brings the old state back here — exactly the finding.
import shutil as _sh  # noqa: E402

probe = ordner2 / "probe.db"
for teil in ("", "-wal", "-shm"):
    if (ordner2 / f"auth.db{teil}").exists():
        _sh.copyfile(ordner2 / f"auth.db{teil}", ordner2 / f"probe.db{teil}")
_sh.copyfile(ordner2 / "sicherung.db", probe)
naiv = [z[0] for z in sqlite3.connect(str(probe)).execute("SELECT username FROM users")]
r.check("a plain `cp` of the backup does NOT work (the WAL overwrites it)",
        "neu0" in naiv,
        f"{naiv} — then the test does not measure the difference that `restore` makes")

lauf2 = subprocess.run([sys.executable, "-m", "tinysesam", "restore", "--db", str(ziel),
                        str(ordner2 / "sicherung.db"), "--ja"],
                       cwd=ROOT, capture_output=True, text=True)
r.check("`tinysesam restore` runs through", lauf2.returncode == 0, lauf2.stderr[:140])
namen = [z[0] for z in sqlite3.connect(str(ziel)).execute("SELECT username FROM users")]
r.check("after restoring, the backed-up state is there", namen == ["alt0", "alt1"],
        f"{namen} — the WAL replayed the old state")


# ── A migration that aborts halfway ──────────────────────────────
ordner3 = Path(tempfile.mkdtemp())
halb = ordner3 / "halb.db"
roh3 = sqlite3.connect(str(halb))
roh3.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT, display_name TEXT,
    is_admin INT DEFAULT 0, disabled INT DEFAULT 0, roles TEXT DEFAULT '[]',
    created_at INT DEFAULT 0, is_service INT DEFAULT 0);
CREATE TABLE session (token_hash TEXT PRIMARY KEY, user_id INT, created_at INT, expires_at INT,
    mfa_ok INT DEFAULT 0, method TEXT);
INSERT INTO users(id, username) VALUES (1, 'admin');
INSERT INTO session VALUES ('IMMER-NOCH-KLARTEXT', 1, 0, 99999999999, 1, 'password');
PRAGMA user_version = 2;""")
roh3.commit()
roh3.close()
st3 = Store(str(halb))
werte = [z["token_hash"] for z in st3._all("SELECT token_hash FROM session")]
r.check("a half-migrated file is healed at the next start",
        all(len(w) == 64 for w in werte),
        f"{werte} — plaintext stays forever because the detection never applies again")
r.check("and the old cookie remains valid afterwards",
        st3.get_session("IMMER-NOCH-KLARTEXT") is not None,
        "the healing discarded the session")
st3.db.close()


# ── The healthcheck that does not see database damage ──────────────────
umgebung = dict(os.environ, TINYSESAM_OIDC_ISSUER="https://id.example.com",
                TINYSESAM_OIDC_CLIENT_ID="x", TINYSESAM_OIDC_CLIENT_SECRET="y",
                TINYSESAM_BASE_URL="https://a.example.com",
                TINYSESAM_DB=str(Path(tempfile.mkdtemp()) / "g.db"))
skript = (
    "from fastapi.testclient import TestClient\n"
    "from tinysesam.gateway import build_app\n"
    "app = build_app(); c = TestClient(app)\n"
    "print('gesund', c.get('/healthz').status_code)\n"
    "app.state.auth.store.db.close()\n"
    "print('kaputt', c.get('/healthz').status_code)\n")
lauf3 = subprocess.run([sys.executable, "-c", skript], cwd=ROOT, capture_output=True,
                       text=True, env=umgebung)
ausgabe = lauf3.stdout
r.check("the healthcheck reports a healthy instance with 200", "gesund 200" in ausgabe,
        ausgabe[:120] + lauf3.stderr[-120:])
r.check("...and a broken database with 503", "kaputt 503" in ausgabe,
        f"{ausgabe[:160]} — Docker kept the container permanently as healthy, "
        "while every signed-in request returned 500")


# ── The session token on a change of rights ───────────────────────────────────
auth_w, app_w = _app(csrf_enabled=False)
uid_w = auth_w.create_user("bob", password="geheim12345")
auth_w.totp_begin(uid_w)
geheim_w = auth_w.store.get_totp(uid_w)["secret"]
auth_w.store.set_totp(uid_w, geheim_w, confirmed=True)
cw = TestClient(app_w)
cw.post("/auth/login", data={"username": "bob", "password": "geheim12345", "next": "/"},
        follow_redirects=False)
vor = cw.cookies.get(auth_w.cfg.session_cookie)
cw.post("/auth/totp", data={"code": pyotp.TOTP(geheim_w).now(), "next": "/"},
        follow_redirects=False)
nach = cw.cookies.get(auth_w.cfg.session_cookie)
r.check("the session token is renewed on a change of rights", vor != nach,
        "OWASP: „must be renewed after any privilege level change\"")
r.check("the new session is fully valid",
        bool(auth_w.store.get_session(nach) and auth_w.store.get_session(nach)["mfa_ok"]),
        "the second factor was lost")
r.check("and the old one is gone", auth_w.store.get_session(vor) is None,
        "both tokens are valid — then the renewal was only cosmetic")


# ── The configuration checker that names a field that does not exist ─────────
from tinysesam.config_check import BRAUCHT_MAILER, PFLICHTFELDER, VERFAHREN  # noqa: E402

felder = TinySesamConfig(db_path=":memory:")
unbekannt = sorted({f for fs in PFLICHTFELDER.values() for f in fs if not hasattr(felder, f)}
                   | {v for v in VERFAHREN.values() if not hasattr(felder, v)}
                   | {f for f in BRAUCHT_MAILER if not hasattr(felder, f)})
r.check("every field name of the configuration check really exists", not unbekannt,
        f"{unbekannt} — the warning then always fires and never checks what was meant")

preset = TinySesamConfig.active_directory(ldap_url="ldaps://dc.example.com:636",
                                          upn_suffix="corp.example.com", db_path=":memory:")
from tinysesam.config_check import check_config  # noqa: E402

f_p, w_p = check_config(preset)
r.check("the own active_directory preset triggers no warning", not f_p and not w_p,
        f"errors={f_p} warnings={w_p}")


# ── Stored XSS in the admin panel via the username ──────────────────
# The panel JS built data into `onclick` attributes, and `esc()` replaced only `<`. HTML escaping
# is not enough there anyway: The browser decodes the attribute FIRST and then lets the JS parser
# run over the result — `&#39;` becomes an apostrophe again, which closes the
# string. A user who registered suitably thereby executed code in the browser of the
# signed-in administrator. (CodeQL did not find this: It sees Python, not the
# JavaScript in a Python string.)
panel_js = (ROOT / "tinysesam" / "admin.py").read_text(encoding="utf-8")

r.check("esc() replaces all HTML special characters, not just '<'",
        all(z in panel_js for z in ('"&":"&amp;"', "'\"':\"&quot;\"", '"\'":"&#39;"')),
        "esc() does not cover all characters — in an attribute `<` is not enough")

# Since R8-1, no datum stands in an inline handler at all any more: The panel's CSP would not let it
# run, and an onclick is code. The buttons carry `data-on` (action name) and
# `data-a` (arguments as JSON), a delegated listener reads them with JSON.parse.
r.check("no onclick in the panel any more", not re.search(r"\bon[a-z]+=", panel_js.split("_PAGE = ")[1]),
        "an inline handler is back — under the CSP it does not run, and data in it is code")
r.check("buttons go through on() (JSON in data-a, attribute-escaped)",
        'const on=(f,...a)=>`data-on="${f}" data-a="${esc(JSON.stringify(a))}"`;' in panel_js
        and panel_js.count("${on(") >= 10, f"{panel_js.count('${on(')} uses")
r.check("the listener calls only actions from ACT and reads data-a with JSON.parse",
        "const ACT={" in panel_js and 'JSON.parse(el.dataset.a||"[]")' in panel_js)

# Measure the effect, do not guess in the source text.
#
# The core can be checked without a JS runtime: `on` = JSON list + HTML escaping in a
# double-quoted attribute. There must be NO raw `"` in it (otherwise the attribute ends), and
# after decoding by the browser, JSON.parse must return exactly the name.
ZEICHEN = {"&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"}


def _esc(w):
    return "".join(ZEICHEN.get(z, z) for z in str(w))


def _on(f, *a):
    import json as _j
    return f'data-on="{f}" data-a="{_esc(_j.dumps(list(a), separators=(",", ":")))}"'


angriff = "bob\");alert(document.cookie);//'\"><img src=x onerror=alert(1)>"
attribut = _on("keys", 1, angriff)
_wert = attribut.split('data-a="', 1)[1]
r.check("a crafted username leaves no raw quotation mark in the attribute",
        '"' not in _wert[:-1] and "<" not in _wert and "'" not in _wert, attribut)
import html as _html  # noqa: E402
import json as _json_a  # noqa: E402

r.check("after HTML decoding, JSON.parse returns exactly the arguments",
        _json_a.loads(_html.unescape(_wert[:-1])) == [1, angriff], _wert)

# If node is present, the same against the REAL helpers from the panel — the stronger measurement.
from voraussetzung import pflicht_werkzeug  # noqa: E402

# If node is missing, this is red rather than silently less checked (see `pflicht_werkzeug`).
node = pflicht_werkzeug("node", "panel helpers esc/on against prepared names")
if node:
    import json as _json2

    defs = re.search(r"const esc=.*?\);\n", panel_js, re.S)
    ondef = re.search(r"const on=.*?;\n", panel_js)
    r.check("the JS helpers can be found in the panel", defs is not None and ondef is not None,
            "esc/on not found")
    if defs and ondef:
        probe = defs.group(0) + ondef.group(0) + (
            f"\nprocess.stdout.write(`<button ${{on('keys',1,{_json2.dumps(angriff)})}}>x</button>`);")
        aus = subprocess.run([node, "-e", probe], capture_output=True, text=True).stdout
        r.check("the real panel JS does not break out of the attribute either",
                "<img" not in aus and "&quot;" in aus, f"produced: {aus[:110]}")
        r.check("and the replica above matches the real JS",
                _on("keys", 1, angriff) in aus,
                f"replica: {_on('keys', 1, angriff)!r} — then the check without node measures something else")

# ---------- F-17: a locked account gets nothing at all at SSO login any more ----------
# Up to 0.18.x the callback for a `disabled=1` account ran through completely: Groups were
# taken over, the admin flag could be set, a login entry was created — only the session
# stayed out. But locking means "this person should no longer be able to do anything"; that their roles
# still change meanwhile is the opposite. In the log it also looked like a sign-in.
auth_d, app_d = _oidc_app({"sub": "gesperrt-1", "preferred_username": "gesperrt",
                           "email": "gesperrt@example.com", "email_verified": True,
                           "groups": ["admins"]},
                          oidc_group_role_map={"admins": "chef"})
_oidc_login(app_d)                                   # first login creates the account
_uid_d = auth_d.store.get_user_by_name("gesperrt")["id"]
auth_d.store.set_disabled(_uid_d, True)
auth_d.store._exec("UPDATE users SET roles='[]' WHERE id=?", (_uid_d,))

_antwort_d = _oidc_login(app_d)
_konto_d = auth_d.store.get_user(_uid_d)
r.check("locked account: the SSO callback rejects (403, no session)",
        _antwort_d.status_code == 403, f"HTTP {_antwort_d.status_code}")
r.check("… and the roles from the IdP are NO LONGER taken over",
        _konto_d["roles"] == "[]", f"roles={_konto_d['roles']!r}")
r.check("… the account stays locked", bool(_konto_d["disabled"]))
_ereignisse_d = [e["event"] for e in auth_d.store.recent_audit(limit=20)]
r.check("… and there is an audit line with the reason",
        "oidc_disabled" in _ereignisse_d, f"events: {_ereignisse_d}")

# Counter-check: unlocked, the same path runs through again — otherwise the guard would be a dead end.
auth_d.store.set_disabled(_uid_d, False)
r.check("unlocked: the same login goes through again",
        _oidc_login(app_d).status_code == 303)

# ---------- F-18: the UserInfo response must match the ID token ----------
# The response is not signed and is laid over the claims — it supplies groups, e-mail
# and thereby indirectly roles and the admin flag. If its `sub` does not match, it does not apply at all
# (OIDC Core 5.3.2). What is checked here is the path through the real callback.
auth_x, app_x = _oidc_app({"sub": "echt-1", "preferred_username": "echt"},
                          nutzerinfo={"sub": "JEMAND-ANDERS", "email": "chef@example.com",
                                      "email_verified": True, "groups": ["admins"]},
                          admin_identifiers=["chef@example.com"],
                          oidc_group_role_map={"admins": "chef"})
_oidc_login(app_x)
_echt = auth_x.store.get_user_by_name("echt")
r.check("foreign sub in the userinfo document: neither address nor roles move into the account",
        _echt is not None and not _echt["is_admin"] and _echt["roles"] == "[]"
        and (_echt["email"] or "") != "chef@example.com",
        f"account: {dict(_echt) if _echt else None}")


# ══════════════════════════════════════════════════════════════════════════════════════════
# T-13, area "Audit and forensics": Who, from where, what exactly — and what falsifies the log.
# ══════════════════════════════════════════════════════════════════════════════════════════
import contextlib as _ctxlib  # noqa: E402
from tinysesam.__main__ import _audit as _cli_audit, _gc as _cli_gc  # noqa: E402

auth_t, app_t = _app(csrf_enabled=False, magiclink_enabled=True, passkey_enabled=False,
                     forward_auth_enabled=True)
auth_t.set_mailer(lambda *a, **k: None)
_chef_t = auth_t.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_anna_t = auth_t.create_user("anna", password="Geheim12345!-lang", email="anna@example.com")


def _sitzung_t(uid):
    c = TestClient(app_t)
    c.cookies.set(auth_t.cfg.session_cookie, auth_t.store.create_session(uid, 3600, True, "password"))
    return c


def _zeilen_t(event, n=500):
    return [dict(z) for z in auth_t.store.recent_audit(n) if z["event"] == event]


c_anna, c_chef = _sitzung_t(_anna_t), _sitzung_t(_chef_t)

# ── B5-02: account events carry account and IP ──────────────────────────────────────────
_start = c_anna.post("/auth/totp/setup/start")
_geheim = auth_t.store.get_totp(_anna_t)["secret"]
_best = c_anna.post("/auth/totp/setup", data={"code": pyotp.TOTP(_geheim).now()})
_rc = c_anna.post("/auth/totp/recovery")
r.check("Setup: TOTP set up, recovery codes issued",
        _start.status_code == 200 and _best.json().get("ok") and _rc.status_code == 200,
        f"{_start.status_code} {_best.text[:80]} {_rc.status_code} {_rc.text[:80]}")
_konto_ev = ("totp_setup_start", "totp_enable", "recovery_generate")
_ohne = [(e, z["username"], z["ip"]) for e in _konto_ev for z in _zeilen_t(e)
         if z["username"] != "anna" or not z["ip"]]
r.check("B5-02: every account row names the account AND the IP", not _ohne and all(
    _zeilen_t(e) for e in _konto_ev), f"without account/IP: {_ohne}")
r.check("B5-02: `tinysesam audit --user anna` finds them (filter in SQL on username)",
        {"totp_setup_start", "totp_enable", "recovery_generate"}
        <= {z["event"] for z in auth_t.store.recent_audit(50, username="anna")})

# ── B5-07: TOTP setup is logged, recovery code ≠ TOTP ────────────────────────────
r.check("B5-07: confirming the TOTP setup leaves `totp_enable`",
        len(_zeilen_t("totp_enable")) == 1)
_login_rc = TestClient(app_t)
_login_rc.post("/auth/login", data={"username": "anna", "password": "Geheim12345!-lang"})
_rc_antwort = _login_rc.post("/auth/totp", data={"code": _rc.json()["codes"][0]},
                             follow_redirects=False)
_rc_zeilen = _zeilen_t("recovery_used")
r.check("B5-07: a recovery code in the TOTP step appears as `recovery_used` in the log",
        _rc_antwort.status_code == 303 and len(_rc_zeilen) == 1
        and _rc_zeilen[0]["username"] == "anna" and _rc_zeilen[0]["ip"]
        and "remaining=9" in (_rc_zeilen[0]["detail"] or ""),
        f"HTTP {_rc_antwort.status_code}, rows {_rc_zeilen}")

# ── B5-04 / R6-3: the three panel routes without an actor ───────────────────────────────────────
_key_t = c_chef.post(f"/auth/admin/api/users/{_anna_t}/keys", json={"name": "ci"}).json()
c_chef.post(f"/auth/admin/api/keys/{_key_t['id']}/revoke")
c_chef.post("/auth/admin/api/invite", json={"email": "gast@example.com"})
_panel = {e: (_zeilen_t(e) or [{}])[0] for e in ("apikey_create", "apikey_revoke", "invite_create")}
r.check("B5-04/R6-3: creating/revoking a key names owner, IP and the admin as actor=",
        all(_panel[e].get("username") == "anna" and _panel[e].get("ip")
            and "actor=chef" in (_panel[e].get("detail") or "")
            for e in ("apikey_create", "apikey_revoke")), f"{_panel}")
r.check("B5-04: the invitation names the inviting admin and his IP",
        _panel["invite_create"].get("username") == "chef" and _panel["invite_create"].get("ip"),
        f"{_panel['invite_create']}")

# ── B5-05: key use and key rejection ─────────────────────────────────────────────────────
_key2 = auth_t.create_api_key(_anna_t, name="sync")
for _ in range(3):
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": _key2["key"]})
_nutzung = [z for z in _zeilen_t("apikey_use") if f"key={_key2['id']} " in z["detail"] + " "]
r.check("B5-05: the use of a key appears in the log with owner and IP — throttled, 1× instead of 3×",
        len(_nutzung) == 1 and _nutzung[0]["username"] == "anna" and _nutzung[0]["ip"],
        f"{_nutzung}")
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": _key_t["key"]})     # revoked
    TestClient(app_t).get("/auth/me", headers={"X-API-Key": "tsk_" + "x" * 40})  # unknown
finally:
    _sec.seclog.removeHandler(_sl_h)
_abgewiesen = {z["detail"].split("reason=")[-1]: z for z in _zeilen_t("apikey_denied")}
r.check("B5-05: a REVOKED key that keeps knocking appears in the log (account, IP, reason)",
        _abgewiesen.get("revoked", {}).get("username") == "anna"
        and _abgewiesen["revoked"].get("ip"), f"{_abgewiesen}")
r.check("B5-05: an unknown key likewise — and both in the security log",
        "unknown" in _abgewiesen and _sl_puffer.getvalue().count("api key denied") == 2,
        _sl_puffer.getvalue())

# ── R6-7: Before/after ──────────────────────────────────────────────────────────────────
c_chef.post(f"/auth/admin/api/users/{_anna_t}/roles", json={"roles": ["redaktion"], "is_admin": True})
_rollen_z = _zeilen_t("user_roles")[0]["detail"] or ""
r.check("R6-7: the role change names before → after, including admin flag",
        "roles=-->redaktion" in _rollen_z and "admin=0->1" in _rollen_z, _rollen_z)
c_chef.post(f"/auth/admin/api/users/{_anna_t}/roles", json={"roles": [], "is_admin": False})
_vorher_ma = auth_t._sec("max_login_attempts")
c_chef.post("/auth/admin/api/security", json={"max_login_attempts": _vorher_ma + 995})
_sec_z = _zeilen_t("security_update")[0]["detail"] or ""
r.check("R6-7: the hardening change names the old and the new value",
        f"max_login_attempts={_vorher_ma}->{_vorher_ma + 995}" in _sec_z, _sec_z)
auth_t.set_security("max_login_attempts", _vorher_ma)

# ── B5-12: reading is logged ───────────────────────────────────────────────────────
c_chef.get("/auth/admin/api/sessions")
c_chef.get("/auth/admin/api/audit")
r.check("B5-12: reading the session list and audit log leaves a row with the reader",
        (_zeilen_t("sessions_read") or [{}])[0].get("username") == "chef"
        and (_zeilen_t("audit_read") or [{}])[0].get("username") == "chef")

# ── H-7: own events on the account page ─────────────────────────────────────────────
_konto_seite = c_anna.get("/auth/account").text
r.check("H-7: the account page shows the own events",
        "Recent activity" in _konto_seite and "totp_enable" in _konto_seite
        and "recovery_used" in _konto_seite)
r.check("H-7: … without detail text (for admin actions, foreign accounts stand there)",
        "actor=" not in _konto_seite and "remaining=" not in _konto_seite)

# ── B5-17: rejected forward-auth ───────────────────────────────────────────────────────
_vorher_fw = len(_zeilen_t("forward_denied"))
TestClient(app_t).get("/auth/forward")                                   # without proof
_ohne_nachweis = len(_zeilen_t("forward_denied")) - _vorher_fw
_fw = TestClient(app_t)
_fw.cookies.set(auth_t.cfg.session_cookie, "abgelaufen-oder-geraten")
_fw_status = [_fw.get("/auth/forward").status_code for _ in range(3)]
_fw_z = _zeilen_t("forward_denied")
r.check("B5-17: a 401 with an invalid session cookie appears in the log (throttled: 1× for 3 requests)",
        _fw_status == [401] * 3 and len(_fw_z) - _vorher_fw == 1
        and "reason=session_invalid" in _fw_z[0]["detail"] and _fw_z[0]["ip"],
        f"{_fw_status} {_fw_z}")
r.check("B5-17: … a call without any proof (the first visit), by contrast, does not", _ohne_nachweis == 0)

# ── B5-08 / H-13: revoke passkey, delete account, anonymize log ────────────────────
auth_t.store.add_webauthn(_anna_t, "credid-b5-08", "pubkey", 0, ["usb"], "Stick")
_pk = c_chef.get(f"/auth/admin/api/users/{_anna_t}/passkeys").json()
_pk_weg = c_chef.post(f"/auth/admin/api/users/{_anna_t}/passkeys/{_pk[0]['id']}/delete")
_pk_z = _zeilen_t("passkey_delete")[0]
r.check("B5-08: the admin revokes a foreign passkey — logged for the owner",
        len(_pk) == 1 and _pk_weg.status_code == 200 and not auth_t.store.list_webauthn(_anna_t)
        and _pk_z["username"] == "anna" and "actor=chef" in _pk_z["detail"], f"{_pk} {_pk_z}")
r.check("B5-08: foreign passkey via the wrong account ID → 404, nothing deleted",
        c_chef.post(f"/auth/admin/api/users/{_chef_t}/passkeys/999/delete").status_code == 404)
r.check("B5-08: the own account cannot be deleted in the panel",
        c_chef.post(f"/auth/admin/api/users/{_chef_t}/delete").status_code == 400)
_try_last = None
try:
    auth_t.delete_user(_chef_t)
except Exception as e:        # noqa: BLE001
    _try_last = type(e).__name__
r.check("B5-08: the last admin cannot be deleted (StateError)", _try_last == "StateError",
        str(_try_last))
auth_t.store.audit_log("invite_create", "chef", None, "an anna@example.com und annabell")
_weg = c_chef.post(f"/auth/admin/api/users/{_anna_t}/delete")
_rest = [dict(z) for z in auth_t.store.recent_audit(1000)]
r.check("B5-08: account deleted", _weg.status_code == 200 and auth_t.store.get_user(_anna_t) is None,
        f"HTTP {_weg.status_code} {_weg.text[:80]}")
r.check("H-13: the name appears nowhere in the audit log any more, neither as account nor in the detail",
        not any("anna" == (z["username"] or "") or "anna@example.com" in (z["detail"] or "")
                for z in _rest),
        f"{[z for z in _rest if 'anna' in str(z)][:3]}")
r.check("H-13: … the rows themselves remain (forensics), under `deleted#<id>`",
        len(auth_t.store.recent_audit(1000, username=f"deleted#{_anna_t}")) >= 10)
r.check("H-13: … and only whole words are replaced ('annabell' stays)",
        any("annabell" in (z["detail"] or "") for z in _rest))

# ── B5-11: retention period and IP truncation ──────────────────────────────────────────────
auth_f, _ = _app(audit_retention_days=30, audit_ip_pseudonymize=True)
auth_f.store.audit_log("alt", "x", "203.0.113.77")
auth_f.store.audit_log("neu", "x", "2001:DB8:1234:5678::1")
auth_f.store._exec("UPDATE audit SET ts = ts - 31*86400 WHERE event='alt'")
_ips_f = {z["event"]: z["ip"] for z in auth_f.store.recent_audit(10)}
r.check("B5-11: audit_ip_pseudonymize truncates IPv4 to /24 and IPv6 to /48",
        _ips_f == {"alt": "203.0.113.0/24", "neu": "2001:db8:1234::/48"}, f"{_ips_f}")
_gc_f = auth_f.gc()
r.check("B5-11: gc() deletes audit rows beyond the period, the younger ones stay",
        _gc_f.get("audit") == 1 and [z["event"] for z in auth_f.store.recent_audit(10)] == ["neu"],
        f"{_gc_f}")
auth_g, _ = _app()
auth_g.store.audit_log("alt", "x", "203.0.113.77")
auth_g.store._exec("UPDATE audit SET ts = ts - 3650*86400")
r.check("B5-11: without a period (default) the log stays untouched, and the IP complete",
        "audit" not in auth_g.gc() and auth_g.store.recent_audit(5)[0]["ip"] == "203.0.113.77")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_gc(["--db", auth_g.cfg.db_path, "--audit-days", "30"])
r.check("B5-11: `tinysesam gc --audit-days N` cleans up the same from the command line",
        "audit=1" in _cli_out.getvalue() and not auth_g.store.recent_audit(5), _cli_out.getvalue())
try:
    _app(audit_retention_days=-1)
    _neg = "angenommen"
except ConfigError:
    _neg = "abgewiesen"
r.check("B5-11: a negative period (would delete EVERYTHING) is rejected at setup", _neg == "abgewiesen")

# ── B5-06: Log-Injection in `tinysesam audit` ─────────────────────────────────────────────
auth_i, _ = _app()
auth_i.store.audit_log("login_fail", "x\n2026-01-01 00:00:00  login  admin  198.51.100.1  ok\x1b[2J",
                       "198.51.100.9", "password\nzweite")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_audit(["--db", auth_i.cfg.db_path])
_cli_zeilen = _cli_out.getvalue().splitlines()
r.check("B5-06: a line break in the username produces NO second line in `tinysesam audit`",
        len(_cli_zeilen) == 1 and "\\n" in _cli_zeilen[0] and "\x1b" not in _cli_out.getvalue(),
        repr(_cli_out.getvalue()))

# ── B5-14: control characters in EVERY seclog line, even without fuer_log at the call site ────
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    _sec.seclog.warning("probe user=%s ip=%s", "x\nfailed login user=y ip=192.0.2.66", "192.0.2.1")
finally:
    _sec.seclog.removeHandler(_sl_h)
r.check("B5-14: the logger itself neutralizes line breaks in the arguments (one line, not two)",
        _sl_puffer.getvalue().count("\n") == 1 and "192.0.2.66" in _sl_puffer.getvalue(),
        repr(_sl_puffer.getvalue()))


# ── B5-15: the field `ip` contains an IP ─────────────────────────────────────────────────
class _Anfr:
    def __init__(self, peer, xff):
        self.client = type("C", (), {"host": peer})()
        self.headers = {"x-forwarded-for": xff}


_sec.einmal_melden_zuruecksetzen()
_proxy = ["127.0.0.1/32"]
r.check("B5-15: an X-Forwarded-For without a valid address does not become the client IP",
        _sec.client_ip(_Anfr("127.0.0.1", "evil\nfailed login"), _proxy) == "127.0.0.1")
r.check("B5-15: valid addresses arrive canonical (spelling ≠ new client)",
        _sec.client_ip(_Anfr("127.0.0.1", "2001:DB8:0::1"), _proxy) == "2001:db8::1"
        and _sec.client_ip(_Anfr("127.0.0.1", "198.51.100.7:4711"), _proxy) == "198.51.100.7")
auth_i.store.audit_log("probe", "x", "kein\nip")
r.check("B5-15: the audit log accepts nothing with a line break in the ip column",
        "\n" not in auth_i.store.recent_audit(1)[0]["ip"])


# ══════════════════════════════════════════════════════════════════════════════════════════
# T-13, attack on the audit fixes (A-1 … A-7): what the repairs themselves tore open.
# ══════════════════════════════════════════════════════════════════════════════════════════

# ── A-1: IPv6 zone identifier as a freely adjustable key ────────────────────────────────────
# `ipaddress` accepts any text after the `%`. Through a proxy that merely passes XFF on, every
# zone would be a new client — for rate limit, lockout and log throttle.
_sec.einmal_melden_zuruecksetzen()
_zonen = {_sec.client_ip(_Anfr("127.0.0.1", f"2001:db8::2%z{i}"), _proxy) for i in range(20)}
r.check("A-1: changing IPv6 zones yield ONE client IP (without zone)",
        _zonen == {"2001:db8::2"}, f"{_zonen}")
auth_z, _ = _app(trusted_proxies=["127.0.0.1/32"])
_erlaubt = sum(auth_z._rate_ok(_sec.client_ip(_Anfr("127.0.0.1", f"2001:db8::3%q{i}"), _proxy))
               for i in range(60))
_fest = sum(auth_z._rate_ok("2001:db8::4") for _ in range(60))
r.check("A-1: the rate limit applies with zone rotation just as with a fixed address",
        _erlaubt == _fest < 60, f"Rotation {_erlaubt}/60, fest {_fest}/60")
auth_i.store.audit_log("probe_zone", "x", "fe80::1%a\nFAKE 2026-01-01 login admin")
r.check("A-1: a zone with a line break does not end up in the ip column",
        auth_i.store.recent_audit(1)[0]["ip"] == "fe80::1", repr(auth_i.store.recent_audit(1)[0]["ip"]))

# ── A-2 / A-3: deleting an account does not hit foreign rows, but the sign-in attempts by mail do ──
auth_d, app_d2 = _app(csrf_enabled=False)
auth_d.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_adm = auth_d.create_user("admin", password="Geheim12345!-lang", email="Anna.Admin@example.com",
                          is_admin=True)
_bob = auth_d.create_user("bob", password="Geheim12345!-lang")
_kd = TestClient(app_d2)
_kd.cookies.set(auth_d.cfg.session_cookie, auth_d.store.create_session(_adm, 3600, True, "password"))
_kd.post(f"/auth/admin/api/users/{_bob}/roles", json={"roles": ["ops"], "is_admin": True})
auth_d._record_login("bob", "198.51.100.3", False, "password")
auth_d._record_login("anna.admin@example.com", "198.51.100.4", False, "password")
auth_d._record_login("Anna.Admin@example.com", "198.51.100.4", False, "password")
auth_d.delete_user(_adm)
_zd = [dict(z) for z in auth_d.store.recent_audit(200)]
_rollen_d = next(z for z in _zd if z["event"] == "user_roles")
r.check("A-2: a deleted account `admin` does not mangle `admin=0->1` of a FOREIGN row",
        "admin=0->1" in _rollen_d["detail"] and "deleted" not in _rollen_d["detail"],
        _rollen_d["detail"])
r.check("A-2: … the same row no longer names the deleted admin as the actor",
        _rollen_d["username"] == f"deleted#{_adm}", f"{_rollen_d}")
_bob_fail = next(z for z in _zd if z["event"] == "login_fail" and z["username"] == "bob")
r.check("A-2: the method in the detail of foreign failed attempts stays untouched",
        _bob_fail["detail"].startswith("password "), _bob_fail["detail"])
_mail_rest = [z for z in _zd if "anna.admin@example.com" in str(z).lower()]
r.check("A-3: sign-in attempts under the e-mail address are anonymized in the audit log",
        not _mail_rest and sum(1 for z in _zd if z["event"] == "login_fail"
                               and z["username"] == f"deleted#{_adm}") == 2, f"{_mail_rest}")
_versuche = auth_d.store._all("SELECT username FROM login_attempt", ())
r.check("A-3: … and their login_attempt rows are deleted (only bob remains)",
        [v["username"] for v in _versuche] == ["bob"], f"{[dict(v) for v in _versuche]}")
auth_d.store.audit_log("apikey_create", "bob", None, "key=9 actor=Admin")
auth_d.store.audit_log("user_create", "chef", None, "admin service=False")
auth_d.store.audit_anonymisieren("admin", "deleted#99")
_nach = {z["event"]: z["detail"] for z in auth_d.store.recent_audit(2)}
r.check("A-2: where a name stands (actor=, head of user_create), it is still replaced",
        _nach == {"apikey_create": "key=9 actor=deleted#99",
                  "user_create": "deleted#99 service=False"}, f"{_nach}")
# Old spelling as INPUT (a row from a version before schema 15, written back after a rollback): the name
# behind `akteur=` is replaced all the same, and the replacement is the new `deleted#<id>`.
auth_d.store.audit_log("apikey_create", "bob", None, "key=8 akteur=Altadmin")
auth_d.store.audit_anonymisieren("altadmin", "deleted#98")
_alt_z = auth_d.store.recent_audit(1)[0]
r.check("A-2 (old row): the name behind the old `akteur=` is replaced by `deleted#<id>`",
        _alt_z["event"] == "apikey_create" and "Altadmin" not in (_alt_z["detail"] or "")
        and "deleted#98" in (_alt_z["detail"] or ""), f"{dict(_alt_z)}")

# ── A-4: the CSRF exception checks the key BEFORE current_user — the IP must already be there ─────
auth_k, app_k = _app()
_kchef = auth_k.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_k_weg = auth_k.create_api_key(_kchef, name="alt")
auth_k.revoke_api_key(_k_weg["id"])
_k_ok = auth_k.create_api_key(_kchef, name="ok")
_kc = TestClient(app_k, client=("198.51.100.50", 1))
for _k in (_k_weg["key"], _k_ok["key"]):
    _kc.post(f"/auth/admin/api/users/{_kchef}/roles", json={"roles": []}, headers={"X-API-Key": _k})
_kz = [dict(z) for z in auth_k.store.recent_audit(50) if z["event"].startswith("apikey_")
       and z["event"] != "apikey_create" and z["event"] != "apikey_revoke"]
r.check("A-4: revoked key on a POST route: apikey_denied WITH IP",
        [(z["event"], z["ip"]) for z in _kz if z["event"] == "apikey_denied"]
        == [("apikey_denied", "198.51.100.50")], f"{_kz}")
r.check("A-4: valid key on a POST route: ONE apikey_use row, with IP",
        [(z["event"], z["ip"]) for z in _kz if z["event"] == "apikey_use"]
        == [("apikey_use", "198.51.100.50")], f"{_kz}")

# ── A-5: the account page does not show the admin's IP ─────────────────────────────────────
auth_e, app_e = _app(csrf_enabled=False)
_echef = auth_e.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_eanna = auth_e.create_user("anna", password="Geheim12345!-lang")
_ec = TestClient(app_e, client=("198.51.100.50", 1))
_ec.cookies.set(auth_e.cfg.session_cookie, auth_e.store.create_session(_echef, 3600, True, "password"))
_ea = TestClient(app_e, client=("203.0.113.9", 1))
_ea.cookies.set(auth_e.cfg.session_cookie, auth_e.store.create_session(_eanna, 3600, True, "password"))
_ec.post(f"/auth/admin/api/users/{_eanna}/keys", json={"name": "ci"})
auth_e.audit("password_change", "anna", "203.0.113.9")
_eigene = auth_e.own_events(_eanna)
_seite_e = _ea.get("/auth/account").text
r.check("A-5: an admin action on the own account does not show the admin IP, only 'by an admin'",
        ("apikey_create", None, True) in [(e["event"], e["ip"], e["by_admin"]) for e in _eigene]
        and "198.51.100.50" not in _seite_e and "by an administrator" in _seite_e, f"{_eigene}")
r.check("A-5: … the own rows keep their IP",
        ("password_change", "203.0.113.9", False) in
        [(e["event"], e["ip"], e["by_admin"]) for e in _eigene] and "203.0.113.9" in _seite_e)

# ── A-6: no query string (approval token) in the audit log ─────────────────────────────────
_fw6 = TestClient(app_t, client=("198.51.100.66", 1))
_fw6.cookies.set(auth_t.cfg.session_cookie, "abgelaufen")
_fw6.get("/auth/forward", headers={"x-forwarded-proto": "https", "x-forwarded-host": "app.example.com",
                                   "x-forwarded-uri": "/share?t=GEHEIM#frag"})
_fw6_z = [z["detail"] for z in auth_t.store.recent_audit(50) if z["event"] == "forward_denied"
          and z["ip"] == "198.51.100.66"]
r.check("A-6: forward_denied names host and path, but not the query string",
        len(_fw6_z) == 1 and "GEHEIM" not in _fw6_z[0] and "/share?…" in _fw6_z[0], f"{_fw6_z}")
r.check("A-6: url_fuer_log also for relative targets and without query",
        _sec.url_fuer_log("/a/b?code=x") == "/a/b?…" and _sec.url_fuer_log("https://h.example/p")
        == "https://h.example/p" and _sec.url_fuer_log("/x#t") == "/x?…")

# ── A-7: C1 control characters, line separators and bidi overrides ──────────────────────────────
auth_c, _ = _app()
auth_c.store.audit_log("login_fail", "x\x852026-01-01 login admin zeile\x9b2J‮evil",
                       "198.51.100.9", "d ")
_cli_out = io.StringIO()
with _ctxlib.redirect_stdout(_cli_out):
    _cli_audit(["--db", auth_c.cfg.db_path])
_c7 = _cli_out.getvalue()
r.check("A-7: NEL/U+2028/U+2029 produce no further line in `tinysesam audit`, CSI and "
        "U+202E do not arrive raw",
        len(_c7.splitlines()) == 1 and not any(z in _c7 for z in "\x85\x9b  ‮"),
        repr(_c7))
_sl_puffer = io.StringIO()
_sl_h = logging.StreamHandler(_sl_puffer)
_sec.seclog.addHandler(_sl_h)
try:
    _sec.seclog.warning("probe user=%s ip=%s", "x\x85failed login user=y ip=192.0.2.66‮",
                        "192.0.2.1")
finally:
    _sec.seclog.removeHandler(_sl_h)
r.check("A-7: also in the security log (filter on the logger) and in fuer_log",
        len(_sl_puffer.getvalue().splitlines()) == 1 and "\x85" not in _sl_puffer.getvalue()
        and "‮" not in _sl_puffer.getvalue()
        and _sec.fuer_log("a\x9bb c‮d") == "abcd", repr(_sl_puffer.getvalue()))

# ── F-20/H-12: PKCE through the real flow ──────────────────────────────────────
# `oidc.py` measures the mechanics (challenge, verifier in the POST). Here the wire in between: The
# challenge in the redirect to the provider must match the verifier that the callback passes along at the
# exchange — and the verifier must never appear in the address bar.
import base64 as _b64p  # noqa: E402
import hashlib as _hlp  # noqa: E402

auth_p, app_p = _oidc_app({"sub": "pkce-1", "preferred_username": "pkce"})
_gesehen_p = {}


def _tausch_p(code, ru, nonce, t=None, code_verifier=""):
    _gesehen_p["verifier"] = code_verifier
    return _Claims({"sub": "pkce-1", "preferred_username": "pkce", "nonce": nonce}), {"access_token": "at"}


auth_p.oidc.exchange = _tausch_p
_cp = TestClient(app_p)
_start_p = _cp.get("/auth/oidc/start", follow_redirects=False)
_q_p = parse_qs(urlparse(_start_p.headers["location"]).query)
_antwort_p = _cp.get(f"/auth/oidc/callback?code=x&state={_q_p['state'][0]}", follow_redirects=False)
_v_p = _gesehen_p.get("verifier") or ""
_passend = _b64p.urlsafe_b64encode(_hlp.sha256(_v_p.encode()).digest()).rstrip(b"=").decode()
r.check("PKCE: the redirect to the provider requires S256",
        _q_p.get("code_challenge_method") == ["S256"] and bool(_q_p.get("code_challenge")), _q_p)
r.check("PKCE: the callback exchanges with THE verifier that belongs to the challenge",
        _antwort_p.status_code == 303 and _v_p and _q_p.get("code_challenge") == [_passend],
        f"HTTP {_antwort_p.status_code}, Verifier={_v_p!r}")
r.check("PKCE: the verifier never appears in the address bar",
        _v_p and _v_p not in _start_p.headers["location"])

# ══ Attack on the T-13 integration: gaps at the seams of the branches ══════════════════════════
# Every branch was consistent on its own; the gaps arose because one branch introduced a path and
# another a guarantee that did not know that path. The blocks here therefore check the GUARANTEE
# across all paths that exist today — and a guard each records that there is only ONE path,
# so that the next branch does not silently build in a second one.
import ast as _ast  # noqa: E402
import importlib.util as _ilu  # noqa: E402


def _aufrufe_ausserhalb(methode: str, empfaenger, erlaubt: set, quellen=None) -> list:
    """Where in `tinysesam/` is there a call `<empfaenger>.<methode>(…)` outside `erlaubt`?

    `erlaubt` are pairs (innermost class, innermost function). By AST and not by text search:
    Docstrings and comments name the method too, and a nested function like
    `_zuruecknehmen` must be recognized as itself, not as the route around it.
    `quellen` (list of (file name, text)) replaces `tinysesam/*.py` — for the self-tests."""
    funde = []
    if quellen is None:
        quellen = [(p.name, p.read_text(encoding="utf-8"))
                   for p in sorted((ROOT / "tinysesam").glob("*.py"))]
    for pfadname, text in quellen:
        baum = _ast.parse(text)

        def gehe(knoten, klasse=None, funktion=None):
            for kind in _ast.iter_child_nodes(knoten):
                k, f = klasse, funktion
                if isinstance(kind, _ast.ClassDef):
                    k = kind.name
                elif isinstance(kind, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                    f = kind.name
                if (isinstance(kind, _ast.Call) and isinstance(kind.func, _ast.Attribute)
                        and kind.func.attr == methode and empfaenger(kind.func.value, k)
                        and (k, f) not in erlaubt):
                    funde.append(f"{pfadname}:{kind.lineno} ({k}.{f})")
                gehe(kind, k, f)
        gehe(baum)
    return funde


def _ist_store(knoten, klasse) -> bool:
    """`auth.store.x`, `self.store.x`, `store.x` — and within the store itself `self.x`."""
    return ((isinstance(knoten, _ast.Attribute) and knoten.attr == "store")
            or (isinstance(knoten, _ast.Name) and knoten.id == "store")
            or (isinstance(knoten, _ast.Name) and knoten.id == "self" and klasse == "Store"))


# The guard must be able to trigger itself — otherwise it measures nothing (negative test).
r.check("Guard self-test: a call outside the permission is found",
        any("admin.py" in f for f in _aufrufe_ausserhalb("delete_user_sessions", _ist_store, set()))
        and not _aufrufe_ausserhalb("gibt_es_nicht", _ist_store, set()))

# ── Finding 3: the admin revocation of a passkey notifies the owner ────────────────────────
# The audit branch brought the panel route, the factors branch attached `passkey_removed` only to
# self-service. After the merge, the only factor change without notification was exactly the one
# that a taken-over admin account performs on a FOREIGN account.
# (Mutation probes: remove the `security_event` call in `remove_passkey` → red; let the
#  panel route call `store.delete_webauthn` + `audit` directly again → red, hook AND guard.)
auth_f3, app_f3 = _app(csrf_enabled=False)
_f3_chef = auth_f3.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_f3_anna = auth_f3.create_user("anna", password="Geheim12345!-lang")
_f3_ereig = []
auth_f3.on_security_event = lambda e, k, d: _f3_ereig.append((e, k["username"], dict(d)))
auth_f3.store.add_webauthn(_f3_anna, b"cred-f3-a", b"pk", 0, [], "Laptop")
auth_f3.store.add_webauthn(_f3_anna, b"cred-f3-b", b"pk", 0, [], "Telefon")
_f3_pk, _f3_pk2 = [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)]
_f3_c = TestClient(app_f3, client=("198.51.100.70", 1))
_f3_c.cookies.set(auth_f3.cfg.session_cookie,
                  auth_f3.store.create_session(_f3_chef, 3600, True, "password"))
_f3_r = _f3_c.post(f"/auth/admin/api/users/{_f3_anna}/passkeys/{_f3_pk}/delete")
r.check("Finding 3: the admin revocation removes the passkey and reports passkey_removed to the owner",
        _f3_r.status_code == 200
        and [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)] == [_f3_pk2]
        and [(e, u) for e, u, _ in _f3_ereig] == [("passkey_removed", "anna")]
        and _f3_ereig[0][2].get("passkey_id") == _f3_pk,
        f"HTTP {_f3_r.status_code}, Hook {_f3_ereig}")
_f3_audit = [(z["username"], z["detail"]) for z in auth_f3.store.recent_audit(20)
             if z["event"] == "passkey_delete"]
r.check("Finding 3: … the audit row stands under the owner, the admin as actor=",
        _f3_audit == [("anna", f"id={_f3_pk} actor=chef")], f"{_f3_audit}")
_f3_ereig.clear()
_f3_r2 = _f3_c.post(f"/auth/admin/api/users/{_f3_anna}/passkeys/{_f3_pk}/delete")
r.check("Finding 3: a passkey the account does not (any more) have → 404, no notification, no row",
        _f3_r2.status_code == 404 and _f3_ereig == []
        and len([z for z in auth_f3.store.recent_audit(20) if z["event"] == "passkey_delete"]) == 1,
        f"HTTP {_f3_r2.status_code}, Hook {_f3_ereig}")
# The same path without HTTP — and for a foreign account it does not apply.
r.check("Finding 3: remove_passkey only affects passkeys of THIS account",
        auth_f3.remove_passkey(_f3_chef, _f3_pk2) is False
        and [c["id"] for c in auth_f3.store.list_webauthn(_f3_anna)] == [_f3_pk2] and _f3_ereig == [])
if _ilu.find_spec("webauthn") is not None:
    # Self-service runs through the same method (before: own rows in webauthn_.py —
    # and a foreign or invented passkey still wrote a row AND an event).
    auth_f3s, app_f3s = _app(csrf_enabled=False, passkey_enabled=True, rp_id="localhost",
                             origin="http://localhost")
    _f3s_anna = auth_f3s.create_user("anna", password="Geheim12345!-lang")
    _f3s_ereig = []
    auth_f3s.on_security_event = lambda e, k, d: _f3s_ereig.append((e, k["username"], dict(d)))
    auth_f3s.store.add_webauthn(_f3s_anna, b"cred-f3s", b"pk", 0, [], "Laptop")
    _f3s_pk = auth_f3s.store.list_webauthn(_f3s_anna)[0]["id"]
    _f3s_c = TestClient(app_f3s, client=("203.0.113.70", 1))
    _f3s_c.cookies.set(auth_f3s.cfg.session_cookie,
                       auth_f3s.store.create_session(_f3s_anna, 3600, True, "password"))
    _f3s_fremd = _f3s_c.post("/auth/passkey/delete", json={"id": _f3s_pk + 99})
    _f3s_r = _f3s_c.post("/auth/passkey/delete", json={"id": _f3s_pk})
    r.check("Finding 3: self-service — unknown passkey 404 without event, own 200 with event",
            _f3s_fremd.status_code == 404 and _f3s_r.status_code == 200
            and _f3s_ereig == [("passkey_removed", "anna", {"passkey_id": _f3s_pk})]
            and [(z["username"], z["detail"]) for z in auth_f3s.store.recent_audit(20)
                 if z["event"] == "passkey_delete"] == [("anna", f"id={_f3s_pk}")],
            f"{_f3s_fremd.status_code}/{_f3s_r.status_code}, Hook {_f3s_ereig}")
_f3_weg = _aufrufe_ausserhalb("delete_webauthn", _ist_store, {("TinySesam", "remove_passkey")})
r.check("Finding 3 (guard): only TinySesam.remove_passkey deletes a passkey — every route goes through it",
        not _f3_weg, f"direct calls: {_f3_weg}")

# ── Findings 12/18: ONE deletion path for accounts (H-13 × R4-09/B6-5) ──────────────────────────────────
# H-13 (audit branch) took a deleted account out of the audit log only in `TinySesam.delete_user`.
# The mailwege branch brought further deletion paths — `gc()`, `tinysesam gc` (store) and the rollback
# on a failed confirmation send (B6-5) — which called `store.delete_user` directly. Name,
# foreign IP and the victim's address stayed in the log, and the account page of a later
# namesake showed the stranger's registration including IP as its own event (H-7).
# (Mutation probes: remove `audit_anonymisieren` in `Store.konto_entfernen` → red for all
#  paths; let `gc_unbestaetigte_konten` call `self.delete_user` again → red, traces AND
#  guard; write `signup_expired` with the plain name again → red; let `_zuruecknehmen` call
#  `store.delete_user` again → red, traces AND guard.)
_F12_NAME, _F12_MAIL = "squatter", "opfer@example.com"


def _f12_spuren(a) -> tuple:
    """What remains of the deleted account under name or address in the log and in the attempts."""
    kennungen = (_F12_NAME, _F12_MAIL)
    zeilen = [(z["event"], z["username"], z["detail"]) for z in a.store._all("SELECT * FROM audit")
              if (z["username"] or "").lower() in kennungen
              or any(k in (z["detail"] or "").lower() for k in kennungen)]
    versuche = [z["username"] for z in a.store._all("SELECT username FROM login_attempt")
                if (z["username"] or "").lower() in kennungen]
    return zeilen, versuche


def _f12_unbestaetigt():
    """An account as left behind by registration with a confirmation requirement, with traces: the
    stranger's registration (with his IP) and a failed attempt by the real address owner."""
    a, app_ = _app(csrf_enabled=False)
    uid = a.create_user(_F12_NAME, password="Geheim12345!-lang", email=_F12_MAIL)
    a.store.set_disabled(uid, True)
    a.create_magic_token("verify_email", user_id=uid)
    # The traces arise AFTER the second of creation (the account is a minute old): A
    # sign-in attempt from the creation second itself is deliberately left by `delete_attempts_for` —
    # whether it came before or after cannot be decided (follow-up N-1).
    a.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (uid,))
    a.audit("signup", _F12_NAME, "203.0.113.66")
    TestClient(app_, client=("198.51.100.7", 1)).post(
        "/auth/login", data={"username": _F12_MAIL, "password": f"falsch-falsch-{next(_FALSCH)}"})
    a.store._exec("UPDATE magic_token SET expires_at=0 WHERE user_id=?", (uid,))
    vorher = _f12_spuren(a)
    assert vorher[0] and vorher[1], f"precondition: traces must be there, otherwise this measures nothing: {vorher}"
    return a, app_, uid


for _f12_weg, _f12_lauf in (("gc()", lambda a: a.gc()["unverified_accounts"]),
                            ("tinysesam gc (Store)", lambda a: a.store.gc_unbestaetigte_konten())):
    _f12_a, _, _f12_uid = _f12_unbestaetigt()
    _f12_n = _f12_lauf(_f12_a)
    _f12_rest = _f12_spuren(_f12_a)
    r.check(f"Findings 12/18: {_f12_weg} removes the account and takes it out of audit log and attempts",
            _f12_n == 1 and _f12_a.store.get_user(_f12_uid) is None and _f12_rest == ([], []),
            f"n={_f12_n}, remaining: {_f12_rest}")
    _f12_ablauf = [z["username"] for z in _f12_a.store.recent_audit(20) if z["event"] == "signup_expired"]
    r.check(f"Findings 12/18: {_f12_weg} writes signup_expired under the substitute name",
            _f12_ablauf == [f"deleted#{_f12_uid}"], f"{_f12_ablauf}")

# And the account page of the real Carol afterwards (finding 12 verbatim): only her own rows.
_f12_a, _f12_app, _ = _f12_unbestaetigt()
_f12_a.gc()
_f12_neu = _f12_a.create_user(_F12_NAME, password="Geheim12345!-lang", email="echt@example.com")
_f12_a.audit("signup", _F12_NAME, "198.51.100.8")
_f12_eigene = [(e["event"], e["ip"]) for e in _f12_a.own_events(_f12_neu)]
r.check("Finding 12: a later namesake does not see the stranger's registration",
        _f12_eigene == [("signup", "198.51.100.8")], f"{_f12_eigene}")

# B6-5: the confirmation send fails → the account is rolled back, likewise via the path.
_f12_b, _f12_bapp = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                         csrf_enabled=False)


def _f12_kaputt(*a, **k):
    raise OSError("Mailserver weg")


_f12_b.set_mailer(_f12_kaputt)
_f12_bc = TestClient(_f12_bapp, client=("203.0.113.66", 1), raise_server_exceptions=False)
_f12_br = _f12_bc.post("/auth/register", data={"username": _F12_NAME, "password": "Geheim12345!-lang",
                                                "email": _F12_MAIL, "next": "/"})
_f12_brest = _f12_spuren(_f12_b)
_f12_bzeile = [z["username"] for z in _f12_b.store.recent_audit(20) if z["event"] == "verify_send_error"]
r.check("Findings 12/18: the B6-5 rollback takes the account out of the log, verify_send_error under substitute name",
        _f12_br.status_code == 200 and _f12_b.store.get_user_by_name(_F12_NAME) is None
        and _f12_brest == ([], []) and len(_f12_bzeile) == 1
        and _f12_bzeile[0].startswith("deleted#"), f"HTTP {_f12_br.status_code}, remaining {_f12_brest}, {_f12_bzeile}")

# purge_demo (demo mode off) — the same path, even if the finding did not name it.
_f12_d, _ = _app(demo_mode=True)
_f12_d.audit("login", "demo", "198.51.100.9")
_f12_d._purge_demo()
r.check("Findings 12/18: purge_demo likewise takes the demo accounts out of the log",
        not [z for z in _f12_d.store._all("SELECT * FROM audit") if z["username"] in _f12_d._DEMO_USERS],
        f"{[dict(z) for z in _f12_d.store._all('SELECT * FROM audit')]}")

_f12_weg = _aufrufe_ausserhalb("delete_user", _ist_store, {("Store", "konto_entfernen")})
r.check("Findings 12/18 (guard): only Store.konto_entfernen deletes an account — no way past H-13",
        not _f12_weg, f"direct calls: {_f12_weg}")

# Rows that arose BEFORE the account do not belong to it — also from stocks that an older
# state deleted past H-13, and a failed attempt under a then-free name.
# (Mutation probe: do not pass `seit=` in `own_events` → red.)
_f12_c, _ = _app()
_f12_c.store.audit_log("login_fail", "berta", "203.0.113.66", "password")
_f12_c.store._exec("UPDATE audit SET ts=ts-3600 WHERE username='berta'")
_f12_berta = _f12_c.create_user("berta", password="Geheim12345!-lang")
_f12_c.audit("signup", "berta", "198.51.100.10")
_f12_bev = [(e["event"], e["ip"]) for e in _f12_c.own_events(_f12_berta)]
r.check("Finding 12: the account page shows no rows from before the creation of the account",
        _f12_bev == [("signup", "198.51.100.10")], f"{_f12_bev}")

# ══════════════════════════════════════════════════════════════════════════════════════════
# Follow-up: attack on the integration fixes (deletion path, invitation, passkey ID, guard)
# ══════════════════════════════════════════════════════════════════════════════════════════

# ── N-1/N-6: the one deletion path touches only what arose from the creation of the account ─────────
# Since `gc()`, `tinysesam gc` and the B6-5 rollback delete via `Store.konto_entfernen`, a
# stranger without an account triggers this path: register, never confirm. Without a limit it
# rewrote rows that arose BEFORE his account and belong to others — the admin's invitation
# (address in the detail), a sprayer's failed attempt under the then-free name, that
# of the real address owner — and her login_attempt rows (throttling per IP) vanished.
# Checked in two situations: the foreign rows a minute before the registration (the normal case)
# and in the SAME second (stopped clock — this is how the attacker's proof ran). A limit that is
# only accurate to the second does not hold the second situation; there the registration row decides
# (`Store.anlage_grenze`).
# (Mutation probes: do not pass `seit=`/`nach=` in `konto_entfernen` → red in both
#  situations; do not pass `seit_id` → red only in "same second"; in `delete_attempts_for`
#  `ts > ?` to `ts >= ?` → red in "same second"; in `TinySesam.delete_user`
#  remove `adresse_unbefristet=True` → red at N-6.)
from tinysesam import store as _store_mod  # noqa: E402

_N1_NAME, _N1_MAIL = "root", "carol@example.com"
_N1_IPS = ("203.0.113.9", "198.51.100.50")


@_ctxlib.contextmanager
def _uhr_steht():
    """Stop the store clock: Everything in it carries the same timestamp (the same second).
    Afterwards it continues from there — without lead over the wall clock."""
    uhr = _store_mod._UHR
    alt = (uhr.wand, uhr.mono)
    wand, mono = float(uhr.wand()), float(uhr.mono())
    uhr.wand, uhr.mono = (lambda: wand), (lambda: mono)
    try:
        yield
    finally:
        uhr.wand, uhr.mono = alt


def _n1_fremde(a) -> tuple:
    """The rows that arose before the account: invitation, two failed attempts, two attempts."""
    audit = [(z["event"], z["username"], z["ip"], z["detail"]) for z in a.store._all(
        "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail') AND ip IN (?, ?, ?) "
        "ORDER BY id", ("198.51.100.1", *_N1_IPS))]
    versuche = [(z["username"], z["ip"], z["success"]) for z in a.store._all(
        "SELECT * FROM login_attempt WHERE ip IN (?, ?) ORDER BY id", _N1_IPS)]
    return audit, versuche


def _n1_kaputt(*a, **k):
    raise OSError("550 recipient rejected")


def _n1_lauf(mailer, gleiche_sekunde: bool):
    """Invitation, sprayer, real owner — then a stranger registers name and address."""
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   magiclink_enabled=True, csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)   # the invitation goes out; `mailer` applies afterwards
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    vor_id = a.store._one("SELECT COALESCE(MAX(id), 0) AS m FROM audit")["m"]
    with (_uhr_steht() if gleiche_sekunde else _ctxlib.nullcontext()):
        assert ca.post("/auth/admin/api/invite", json={"email": _N1_MAIL}).status_code == 200
        TestClient(app_, client=(_N1_IPS[0], 1)).post(                # sprayer, name still free
            "/auth/login", data={"username": _N1_NAME, "password": "Passwort1!"})
        TestClient(app_, client=(_N1_IPS[1], 1)).post(                # the real Carol, without an account
            "/auth/login", data={"username": _N1_MAIL, "password": "irgendwas-langes"})
        if not gleiche_sekunde:
            a.store._exec("UPDATE audit SET ts=ts-60")                # one minute before
            a.store._exec("UPDATE login_attempt SET ts=ts-60")
        vorher = _n1_fremde(a)
        assert len(vorher[0]) == 3 and len(vorher[1]) == 2, f"precondition: {vorher}"
        a.set_mailer(mailer)
        reg = TestClient(app_, client=("192.0.2.66", 1), raise_server_exceptions=False).post(
            "/auth/register", data={"username": _N1_NAME, "password": "Fremder-Langes-77",
                                    "email": _N1_MAIL, "next": "/"})
        if gleiche_sekunde:
            _konto = a.store.get_user_by_name(_N1_NAME)
            _ts = {z["ts"] for z in a.store._all("SELECT ts FROM audit WHERE id > ?", (vor_id,))}
            assert len(_ts) == 1 and (_konto is None or {_konto["created_at"]} == _ts), \
                f"precondition: everything in one second ({_ts})"
    return a, app_, reg, vorher


for _n1_lage, _n1_gleich in (("eine Minute davor", False), ("dieselbe Sekunde", True)):
    _n1_a, _n1_app, _n1_reg, _n1_vorher = _n1_lauf(lambda *x, **k: True, _n1_gleich)
    _n1_uid = _n1_a.store.get_user_by_name(_N1_NAME)["id"]
    # The same limit on the account page (H-7): The sprayer's failed attempt under the then
    # free name is not an event of this account — not even from the same second.
    # (Mutation probe: do not pass `seit_id` in `own_events` → red in "same second".)
    _n1_eigen = [(e["event"], e["ip"]) for e in _n1_a.own_events(_n1_uid)]
    r.check(f"N-1 ({_n1_lage}): the account page shows only the own registration, not the sprayer",
            _n1_eigen == [("signup", "192.0.2.66")], f"{_n1_eigen}")
    # After creation: a failed attempt under the name — it hits THIS account and goes along.
    # It comes seconds later (the second of creation itself is left by `delete_attempts_for`).
    TestClient(_n1_app, client=("203.0.113.77", 1)).post(
        "/auth/login", data={"username": _N1_NAME, "password": f"falsch-falsch-{next(_FALSCH)}"})
    _n1_a.store._exec("UPDATE audit SET ts=ts+5 WHERE ip='203.0.113.77'")
    _n1_a.store._exec("UPDATE login_attempt SET ts=ts+5 WHERE ip='203.0.113.77'")
    _n1_a.store._exec("UPDATE magic_token SET expires_at=0 WHERE user_id=? AND purpose='verify_email'",
                      (_n1_uid,))
    _n1_gc = _n1_a.gc()["unverified_accounts"]
    _n1_nach = _n1_fremde(_n1_a)
    r.check(f"N-1 ({_n1_lage}): gc() of a never-confirmed account leaves rows from BEFORE its creation "
            "(admin's invitation, sprayer, real address owner — including attempt rows)",
            _n1_reg.status_code == 200 and _n1_gc == 1 and _n1_nach == _n1_vorher,
            f"HTTP {_n1_reg.status_code}, gc={_n1_gc}\nbefore {_n1_vorher}\nafter {_n1_nach}")
    _n1_danach = [(z["event"], z["username"]) for z in _n1_a.store._all(
        "SELECT * FROM audit WHERE ip IN ('192.0.2.66', '203.0.113.77') ORDER BY id")]
    _n1_versuch77 = _n1_a.store._all("SELECT * FROM login_attempt WHERE ip='203.0.113.77'")
    r.check(f"N-1 ({_n1_lage}): … what arose from the creation on is still taken along (registration, "
            "later failed attempt)",
            _n1_danach == [("signup", f"deleted#{_n1_uid}"), ("login_fail", f"deleted#{_n1_uid}")]
            and not _n1_versuch77, f"{_n1_danach}, attempts {[dict(v) for v in _n1_versuch77]}")

    _n1_b, _, _n1_breg, _n1_bvorher = _n1_lauf(_n1_kaputt, _n1_gleich)
    _n1_bnach = _n1_fremde(_n1_b)
    _n1_bsignup = [z["username"] for z in _n1_b.store._all("SELECT * FROM audit WHERE event='signup'")]
    r.check(f"N-1 ({_n1_lage}): the B6-5 rollback (send fails) leaves the same foreign "
            "rows — and takes the own registration out of the log",
            _n1_breg.status_code == 200 and _n1_b.store.get_user_by_name(_N1_NAME) is None
            and _n1_bnach == _n1_bvorher and len(_n1_bsignup) == 1
            and _n1_bsignup[0].startswith("deleted#"),
            f"HTTP {_n1_breg.status_code}, signup {_n1_bsignup}\nbefore {_n1_bvorher}\n"
            f"after {_n1_bnach}")

# The anchor is the registration row from the second of creation (or the next) — not
# some later one. A registration with the address as name, which already belongs to an account as
# username, writes `signup_taken` under exactly this name; taken as the anchor, the admin's
# row from the creation second would fall out of the anonymization.
# S-3 (final round): The first version checked this only with +5 s. In the creation second itself and
# in the next, `anlage_grenze` did take the foreign row as an anchor — the docstring said the
# opposite. Now `signup_taken` counts only as the creation of a placeholder (no address on the account,
# detail ≠ name); checked with +0, +1 and +5 s.
# (Mutation probes: remove the placeholder condition, i.e. take every `signup_taken` row as the anchor
#  → red at +0 and +1; keep only the condition "account without address" → likewise red. The
#  row condition alone carries: The condition "account without address" is a second guard that
#  no path reaches today — removed, the suite stays green (measured). The time window is measured by the
#  case with a later `signup` row: `ts BETWEEN ? AND ?` to `ts >= ?` → red only there.)
def _n7_lauf(versatz: int, ereignis: str = "signup_taken"):
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    with _uhr_steht():                 # creation and `user_create` in one second
        assert ca.post("/auth/admin/api/users", json={"username": "kasse@example.com"}).status_code == 200
    konto = a.store.get_user_by_name("kasse@example.com")
    if ereignis == "signup_taken":
        antwort = TestClient(app_, client=("203.0.113.66", 1)).post(
            "/auth/register", data={"username": "kasse@example.com", "password": "Anderes-77!-lang-genug",
                                    "email": "kasse@example.com", "next": "/"})
        status = antwort.status_code
    else:                              # an embedding app logs its own sign-in
        a.audit(ereignis, "kasse@example.com", "203.0.113.66")
        status = 200
    a.store._exec("UPDATE audit SET ts=? WHERE event=?", (konto["created_at"] + versatz, ereignis))
    anker = a.store.anlage_grenze(a.store.get_user(konto["id"]))
    a.delete_user(konto["id"])
    zeilen = [z["detail"] for z in a.store._all("SELECT * FROM audit WHERE event='user_create'")]
    return status, konto["id"], anker, zeilen


for _n7_ereignis, _n7_versatz in (("signup_taken", 0), ("signup_taken", 1), ("signup_taken", 5),
                                  ("signup", 5)):
    _n7_status, _n7_uid, _n7_anker, _n7_z = _n7_lauf(_n7_versatz, _n7_ereignis)
    r.check(f"N-1/S-3: a foreign {_n7_ereignis} row (+{_n7_versatz} s after creation) under the "
            "name does not move the limit (user_create from the creation second is anonymized)",
            _n7_status == 200 and _n7_anker[1] == 0 and _n7_z == [f"deleted#{_n7_uid} service=False"],
            f"HTTP {_n7_status}, anlage_grenze {_n7_anker}, {_n7_z}")

# Counter-check: The signup_taken row OF A PLACEHOLDER is its creation and stays the anchor —
# otherwise the whole second would count, and `gc()` would attribute the failed attempt of a sprayer who tried the then-free
# name in the same second to the placeholder (like N-1, only via the
# branch "address taken", R4-03).
_s3_a, _s3_app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                      csrf_enabled=False)
_s3_a.set_mailer(lambda *x, **k: True)
_s3_a.create_user("inhaberin", password="Geheim12345!-lang", email="belegt@example.com")
with _uhr_steht():
    TestClient(_s3_app, client=("203.0.113.9", 1)).post(          # sprayer, name still free
        "/auth/login", data={"username": "platz", "password": "Passwort1!"})
    _s3_reg = TestClient(_s3_app, client=("192.0.2.66", 1)).post(
        "/auth/register", data={"username": "platz", "password": "Fremder-Langes-77",
                                "email": "belegt@example.com", "next": "/"})
_s3_platz = _s3_a.store.get_user_by_name("platz")
_s3_anker = _s3_a.store.anlage_grenze(_s3_platz) if _s3_platz else None
_s3_a.store._exec("UPDATE magic_token SET expires_at=0 WHERE purpose='verify_email'")
_s3_gc = _s3_a.gc()["unverified_accounts"]
_s3_zeilen = [(z["event"], z["username"]) for z in _s3_a.store._all(
    "SELECT * FROM audit WHERE event IN ('login_fail', 'signup_taken') ORDER BY id")]
r.check("S-3: … the signup_taken row of a placeholder stays its anchor — gc() leaves the sprayer "
        "from the same second alone and takes only the own row",
        _s3_reg.status_code == 200 and _s3_platz is not None and not _s3_platz["email"]
        and _s3_anker[1] > 0 and _s3_gc == 1
        and _s3_zeilen == [("login_fail", "platz"), ("signup_taken", f"deleted#{_s3_platz['id']}")],
        f"HTTP {_s3_reg.status_code}, anchor {_s3_anker}, gc={_s3_gc}, {_s3_zeilen}")

# The deliberate deletion of an account whose address is CONFIRMED stays as thorough as
# H-13 promises: The address demonstrably belongs to the account, so it also disappears from
# older rows (the invitation that led to the account). The NAME, however, belonged to nobody before
# creation — the failed attempt under it stays as it was.
_n6_a, _ = _app(csrf_enabled=False)
_n6_a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_n6_a.store.audit_log("invite_create", "chef", "198.51.100.1", "dora@example.com")
_n6_a.store.audit_log("login_fail", "dora", "203.0.113.9", "password reason=no_account")
_n6_a.store.record_attempt("dora", "203.0.113.9", False, "password")
_n6_a.store._exec("UPDATE audit SET ts=ts-60")
_n6_a.store._exec("UPDATE login_attempt SET ts=ts-60")
_n6_dora = _n6_a.create_user("dora", password="Geheim12345!-lang", email="dora@example.com")
_n6_a.delete_user(_n6_dora)
_n6_zeilen = {z["event"]: (z["username"], z["detail"]) for z in _n6_a.store._all(
    "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail')")}
r.check("N-6: deletion by an admin also takes a confirmed address out of older rows (H-13)",
        _n6_zeilen.get("invite_create") == ("chef", f"deleted#{_n6_dora}"), f"{_n6_zeilen}")
r.check("N-6: … but the name only from creation on — the failed attempt under the free name stays together with the attempt",
        _n6_zeilen.get("login_fail") == ("dora", "password reason=no_account")
        and len(_n6_a.store._all("SELECT id FROM login_attempt WHERE username='dora'")) == 1,
        f"{_n6_zeilen}")

# ── S-2: only a PROVEN address is replaced without time limit ─────────────────────────────────────
# N-6 checked only an account whose address the admin had created. But registration created the
# typed-in address as "confirmed" as long as the link was outstanding — without
# confirmation requirement even forever. If an admin deleted such an account (cleanup, deletion request
# of the stranger), the admin's invitation and the failed attempt of the real owner from BEFORE the
# creation passed to `deleted#<id>` — the damage from N-1, only via the deliberate deletion path.
# Now only the redeemed link sets the proof, and `Store.adresse_belegt` sees an open account
# (locked, token open) even if an app creates it with the default `email_verified=True`.
# (Mutation probes: create again without `email_verified=` in `register_submit` → red at "without
#  confirmation requirement" and "open"; remove the token check in `adresse_belegt` → red at
#  "app path"; ask only the note again in `konto_entfernen` → red at "app path"; remove
#  `set_email_verified` in `/auth/verify` → red at "after the link".)
_S2_MAIL = "carol@example.com"


def _s2_lauf(verify: bool):
    a, app_ = _app(allow_signup=True, signup_verify_email=verify, signup_require_email=True,
                   magiclink_enabled=True, csrf_enabled=False)
    post = []
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, text)))
    chef = a.create_user("chef", password="Geheim12345!-lang", is_admin=True)
    ca = TestClient(app_, client=("198.51.100.1", 1))
    ca.cookies.set(a.cfg.session_cookie, a.store.create_session(chef, 3600, True, "password"))
    assert ca.post("/auth/admin/api/invite", json={"email": _S2_MAIL}).status_code == 200
    TestClient(app_, client=("198.51.100.50", 1)).post(          # the real Carol, without an account
        "/auth/login", data={"username": _S2_MAIL, "password": "irgendwas-langes"})
    a.store._exec("UPDATE audit SET ts=ts-60")                    # one minute before creation
    a.store._exec("UPDATE login_attempt SET ts=ts-60")
    return a, app_, ca, post


def _s2_fremde(a) -> list:
    return [(z["event"], z["username"], z["detail"]) for z in a.store._all(
        "SELECT * FROM audit WHERE event IN ('invite_create', 'login_fail') ORDER BY id")]


def _s2_registrieren(app_):
    return TestClient(app_, client=("192.0.2.66", 1)).post(
        "/auth/register", data={"username": "fremder", "password": "Fremder-Langes-77",
                                "email": _S2_MAIL, "next": "/"}, follow_redirects=False)


# (a) Confirmation required, link never redeemed — the admin deletes the open account in the panel.
_s2_a, _s2_app, _s2_ca, _ = _s2_lauf(True)
_s2_vorher = _s2_fremde(_s2_a)
_s2_reg = _s2_registrieren(_s2_app)
_s2_u = _s2_a.store.get_user_by_name("fremder")
_s2_del = _s2_ca.post(f"/auth/admin/api/users/{_s2_u['id']}/delete")
_s2_nach = _s2_fremde(_s2_a)
_s2_versuch = _s2_a.store._all("SELECT * FROM login_attempt WHERE ip='198.51.100.50'")
r.check("S-2 (open): registration creates the typed-in address without proof, and the "
        "deletion in the panel leaves the invitation and failed attempt of the owner from before creation",
        _s2_reg.status_code == 200 and _s2_u["email_verified"] == 0 and _s2_del.status_code == 200
        and _s2_nach == _s2_vorher and len(_s2_versuch) == 1,
        f"HTTP {_s2_reg.status_code}/{_s2_del.status_code}, email_verified={_s2_u['email_verified']}\n"
        f"before {_s2_vorher}\nafter {_s2_nach}, attempts {len(_s2_versuch)}")

# (b) Without confirmation requirement: signed in, but the address is never proven.
_s2_b, _s2_bapp, _, _ = _s2_lauf(False)
_s2_bvorher = _s2_fremde(_s2_b)
_s2_breg = _s2_registrieren(_s2_bapp)
_s2_bu = _s2_b.store.get_user_by_name("fremder")
_s2_b.delete_user(_s2_bu["id"])
_s2_bnach = _s2_fremde(_s2_b)
r.check("S-2 (without confirmation requirement): unproven — delete_user leaves the rows from before creation",
        _s2_breg.status_code == 303 and _s2_bu["email_verified"] == 0 and _s2_bnach == _s2_bvorher,
        f"HTTP {_s2_breg.status_code}, email_verified={_s2_bu['email_verified']}\n"
        f"before {_s2_bvorher}\nafter {_s2_bnach}")

# (c) Counter-check: After the redeemed link the address is proven — H-13 stays as thorough as
# before and also takes it out of the invitation that led to the account.
_s2_c, _s2_capp, _, _s2_post = _s2_lauf(True)
_s2_creg = _s2_registrieren(_s2_capp)
_s2_link = [m.group(1) for zu, text in _s2_post if zu == _S2_MAIL
            for m in [re.search(r"/auth/verify/([\w\-]+)", text)] if m]
_s2_cver = TestClient(_s2_capp, client=("192.0.2.66", 1)).post(
    f"/auth/verify/{_s2_link[-1]}", follow_redirects=False) if _s2_link else None
_s2_cu = _s2_c.store.get_user_by_name("fremder")
_s2_c.delete_user(_s2_cu["id"])
_s2_cnach = dict((e, (u, d)) for e, u, d in _s2_fremde(_s2_c))
r.check("S-2 (after the link): the redeemed link sets the proof, and the deletion takes the "
        "address out of the older invitation too (H-13)",
        _s2_creg.status_code == 200 and _s2_cver is not None and _s2_cver.status_code == 303
        and _s2_cu["email_verified"] == 1
        and _s2_cnach.get("invite_create") == ("chef", f"deleted#{_s2_cu['id']}"),
        f"HTTP {_s2_creg.status_code}/{getattr(_s2_cver, 'status_code', None)}, "
        f"email_verified={_s2_cu['email_verified']}, {_s2_cnach}")

# (d) The app path: `create_user` with the default `email_verified=True`, locked, own
# confirmation link pending. The note says "proven", the open token contradicts.
_s2_d, _, _, _ = _s2_lauf(True)
_s2_dvorher = _s2_fremde(_s2_d)
_s2_duid = _s2_d.create_user("fremder", password="Geheim12345!-lang", email=_S2_MAIL)
_s2_d.store.set_disabled(_s2_duid, True)
_s2_d.create_magic_token("verify_email", user_id=_s2_duid, email=_S2_MAIL)
_s2_offen_belegt = _s2_d.store.adresse_belegt(_s2_d.store.get_user(_s2_duid))
_s2_d.delete_user(_s2_duid)
r.check("S-2 (app path): an open account with the note 'confirmed' does not count as proven",
        _s2_offen_belegt is False and _s2_fremde(_s2_d) == _s2_dvorher,
        f"proven={_s2_offen_belegt}\nbefore {_s2_dvorher}\nafter {_s2_fremde(_s2_d)}")

# ── S-1: the bucket check must not turn registration into an address oracle ─────────────────
# `Store.konto_mit_topf` (N-5) folded all accounts in Python on EVERY call. Registration
# with a FREE address calls it more often than the one with a taken address (there
# `get_user_by_email` hits earlier) — measured with 20 000 accounts: 118 ms versus 151 ms, the ranges
# did not overlap, one request was enough (R4-03 overturned). `gc()` grew with open × all
# accounts. Now the buckets are indexed columns in `users` (schema 10), and the
# NOCASE search by name and address also runs through an index (before, SQLite read every row there,
# on a hit up to it — the same difference, only smaller).
# What is measured is not the wall clock but the database's work: the number of SQLite steps
# (`set_progress_handler(…, 1)`) with 100 and with 3000 accounts. A scan over the accounts costs
# at least one step per row, i.e. thousands; an index access is one step, no matter how
# deep the tree is. The accounts arrive by raw INSERT without a bucket — as from another
# writer —, the first call fills in the buckets (`_toepfe_nachtragen`).
# (Mutation probes: `konto_mit_topf` as a Python loop over all accounts again → red, "free"
#  1 662 → 48 062 steps with 100 → 3000 accounts; do not create the indexes `ix_users_name_nocase`/
#  `ix_users_email_nocase` → red, "taken (first account)" 430 versus "last
#  account" 33 122 — exactly the oracle; `_toepfe_nachtragen` writes nothing → red, 3000 rows
#  without bucket and again the loop over all.)
def _s1_app(n: int):
    a, app_ = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                   csrf_enabled=False)
    a.set_mailer(lambda *x, **k: True)
    a.store.db.executemany(
        "INSERT INTO users(username, display_name, email, is_admin, roles, is_service, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        [(f"konto{i}", None, f"konto{i}@example.com", 0, "[]", 0, 1) for i in range(n)])
    a.store.db.commit()
    a.identifier_taken("aufwaermen")          # fills in the buckets of the raw rows
    return a, app_


def _s1_schritte(a, fn) -> int:
    zaehler = [0]

    def schritt():
        zaehler[0] += 1
        return 0
    a.store.db.set_progress_handler(schritt, 1)
    try:
        fn()
    finally:
        a.store.db.set_progress_handler(None, 1)
    return zaehler[0]


def _s1_messen(n: int) -> dict:
    # With a stopped clock: Deleting an account searches the audit log from its creation
    # (`ts > seit OR (ts = seit AND id >= …)`, via `idx_audit_ts`). With a running clock, the
    # range read a few more or fewer rows from the same second, depending on the position of the second boundary —
    # up to 120 steps, independent of the number of accounts, and the test fluctuated. If the
    # clock stands, every row carries the same second, and only what the number of accounts causes is measured.
    with _uhr_steht():
        return _s1_messen_bei(n)


def _s1_messen_bei(n: int) -> dict:
    a, app_ = _s1_app(n)
    ohne_topf = a.store._one("SELECT COUNT(*) AS n FROM users WHERE topf_name IS NULL "
                             "OR topf_mail IS NULL")["n"]
    letzte, erste = f"konto{n - 1}@example.com", "konto0@example.com"
    m = {"ohne_topf": ohne_topf,
         "frei": _s1_schritte(a, lambda: a.identifier_taken("niemand@example.org")),
         "taken (first account)": _s1_schritte(a, lambda: a.identifier_taken(erste)),
         "taken (last account)": _s1_schritte(a, lambda: a.identifier_taken(letzte)),
         "namesake": _s1_schritte(a, lambda: a.identifier_taken("KONTO7")),
         "registration free": _s1_schritte(a, lambda: TestClient(app_, client=("192.0.2.31", 1)).post(
             "/auth/register", data={"username": "probefrei", "password": "Sehr-Langes-Passwort-77",
                                     "email": "neu@example.org", "next": "/"})),
         "registration taken": _s1_schritte(a, lambda: TestClient(app_, client=("192.0.2.32", 1)).post(
             "/auth/register", data={"username": "probevergeben", "password": "Sehr-Langes-Passwort-77",
                                     "email": letzte, "next": "/"}))}
    for i in range(5):                        # five open accounts, link expired
        uid = a.store.create_user(f"offen{i}", None, f"offen{i}@example.org", False, [], False)
        a.store.set_disabled(uid, True)
        a.create_magic_token("verify_email", user_id=uid)
    a.store._exec("UPDATE magic_token SET expires_at=1 WHERE purpose='verify_email'")
    m["gc (5 open accounts)"] = _s1_schritte(a, a.store.gc_unbestaetigte_konten)
    return m


_s1_klein, _s1_gross = _s1_messen(100), _s1_messen(3000)
# Margin of 100 steps: one more or fewer recording of the clock state (`_uhr_mitschreiben`).
# A scan over 2900 additional accounts lies far above.
_s1_wachsen = {k: (_s1_klein[k], _s1_gross[k]) for k in _s1_klein
               if k != "ohne_topf" and abs(_s1_gross[k] - _s1_klein[k]) > 100}
r.check("S-1: the database work of identifier_taken, of registration (free and taken) and of "
        "gc() does not depend on the number of accounts (100 vs. 3000, SQLite steps)",
        not _s1_wachsen and _s1_gross["ohne_topf"] == 0,
        f"grows: {_s1_wachsen}\n100: {_s1_klein}\n3000: {_s1_gross}")
r.check("S-1: … free and taken differ with 3000 accounts only by a fixed, small amount",
        abs(_s1_gross["registration free"] - _s1_gross["registration taken"]) <= 200
        and abs(_s1_gross["frei"] - _s1_gross["taken (last account)"]) <= 200,
        f"{_s1_gross}")
# The bucket check itself must keep working, also for a row of another writer that
# someone renames: The trigger sets the bucket to NULL, the next call recomputes it.
# (Mutation probe: the trigger sets nothing → red, "ärmel" goes unrecognized, "konto3" hits.)
_s1_a, _ = _s1_app(10)
_s1_a.store.db.execute("UPDATE users SET username='Ärmel' WHERE username='konto3'")
_s1_a.store.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Özlem', NULL, 1)")
_s1_a.store.db.commit()
_s1_treffer = {k: (_s1_a.store.konto_mit_topf(k) or {"username": None})["username"]
               for k in ("ärmel", "özlem", "konto3", "KONTO4@EXAMPLE.COM")}
r.check("S-1: … and still finds namesakes — also after renaming and INSERT past the store",
        _s1_treffer == {"ärmel": "Ärmel", "özlem": "Özlem", "konto3": None,
                        "KONTO4@EXAMPLE.COM": "konto4"}, f"{_s1_treffer}")
# Read-only (volume write-protected): A bucket that cannot be filled in must neither prevent the
# start (that did not happen before either) nor let a namesake be overlooked. At runtime
# genuinely via `PRAGMA query_only`, at startup via a fill-in that fails as on a read-only
# file (locking a file with chmod does not stop a test as root).
# (Mutation probes: remove the catch in `_migrate` → red, startup fails; return `[]` instead of the rows
#  on an error in `_toepfe_nachtragen` → red at "Özlem".)
_s1_a.store.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Ündine', NULL, 1)")
_s1_a.store.db.commit()
_s1_a.store.db.execute("PRAGMA query_only = ON")
try:
    _s1_nur_lesend = (_s1_a.store.konto_mit_topf("ündine") or {"username": None})["username"]
finally:
    _s1_a.store.db.execute("PRAGMA query_only = OFF")
_s1_ro_db = os.path.join(tempfile.mkdtemp(), "ro.db")
_s1_ro = Store(_s1_ro_db)
_s1_ro.create_user("anna", None, "anna@example.com")
_s1_ro.db.execute("INSERT INTO users(username, email, created_at) VALUES ('Özlem', NULL, 1)")
_s1_ro.db.commit()
_s1_ro.db.close()
_s1_schreiben = Store._toepfe_schreiben


def _s1_nicht_schreibbar(self, zeilen):
    if zeilen:
        raise sqlite3.OperationalError("attempt to write a readonly database")


Store._toepfe_schreiben = _s1_nicht_schreibbar
try:
    _s1_ro2 = Store(_s1_ro_db)
    _s1_start = [(_s1_ro2.konto_mit_topf(k) or {"username": None})["username"] for k in ("özlem", "ANNA")]
    _s1_ro2.db.close()
except Exception as _e:        # the start itself fails
    _s1_start = f"{type(_e).__name__}: {_e}"
finally:
    Store._toepfe_schreiben = _s1_schreiben
r.check("S-1: … also without write permission: startup succeeds, and rows without bucket are checked by Python itself",
        _s1_nur_lesend == "Ündine" and _s1_start == ["Özlem", "anna"],
        f"runtime {_s1_nur_lesend}, Start {_s1_start}")
# The writers in the store carry the bucket along themselves, in the same statement — the fill-in is
# there for foreign writers, not for its own.
# (Mutation probes: omit the bucket in `Store.create_user` or `Store.set_email` → red.)
_s1_uid = _s1_a.store.create_user("Ärger", None, "X@Bücher.example")
_s1_nach_anlage = tuple(_s1_a.store._one("SELECT topf_name, topf_mail FROM users WHERE id=?", (_s1_uid,)))
_s1_a.store.set_email(_s1_uid, "Neu@Example.com")
_s1_nach_wechsel = _s1_a.store._one("SELECT topf_mail FROM users WHERE id=?", (_s1_uid,))["topf_mail"]
r.check("S-1: … create_user and set_email write the bucket along right away",
        _s1_nach_anlage == ("ärger", "x@xn--bcher-kva.example") and _s1_nach_wechsel == "neu@example.com",
        f"after creation {_s1_nach_anlage}, after address change {_s1_nach_wechsel}")

# ── N-5: non-ASCII namesakes share a counting bucket ──────────────────────────────────────
# The lockout counter folds with Python `lower()` (`norm_kennung`), `identifier_taken` and
# `get_user_by_name` with SQLite NOCASE — which folds only ASCII. Next to `Émile`, `émile` could therefore
# be created, both counted in the bucket `émile`. Via `konto_entfernen` (gc, B6-5 — anonymously
# triggerable), removing `émile` deleted the failed attempts of `Émile`: The account threshold
# against distributed guessing (R7-6/H-8) could be emptied any number of times for every account with Ö/Ü/Ä/É …
# (Mutation probes: remove the bucket check in `identifier_taken` → red at registration;
#  remove the check for a remaining account in the bucket in `delete_attempts_for` → red at
#  existing stock; compare `delete_attempts_for` only with SQLite `lower()` again → red at the admin.)
_n5_a, _n5_app = _app(allow_signup=True, signup_verify_email=True, signup_require_email=True,
                      csrf_enabled=False)
_n5_a.set_mailer(_n1_kaputt)          # if the registration failed after all, B6-5 would take effect immediately
_n5_a.create_user("Émile", password="Geheim12345!-lang", email="emile@example.com")
_n5_reg = TestClient(_n5_app, client=("203.0.113.99", 1), raise_server_exceptions=False).post(
    "/auth/register", data={"username": "émile", "password": "Irgendwas-Langes-77",
                            "email": "gibtsnicht@example.org", "next": "/"})
_n5_kein = None
try:
    # Lowercase é: SQLite NOCASE sees a different name in it (unlike "ÉMILE", which
    # already fails at ASCII folding) — the path that registration takes above.
    _n5_a.create_user("émile", password="Anderes-77!-lang-genug")
except ConfigError as _e:
    _n5_kein = getattr(_e, "field", "?")
r.check("N-5: 'émile' next to 'Émile' is taken (same counting bucket) — 409, no second account",
        _n5_reg.status_code == 409 and _n5_kein == "username"
        and len(_n5_a.store._all("SELECT id FROM users")) == 1,
        f"HTTP {_n5_reg.status_code}, create_user: {_n5_kein}")
r.check("N-5: … a different bucket stays free ('Emile' without accent)",
        bool(_n5_a.create_user("Emile", password="Anderes-77!-lang-genug")))


def _n5_rate(a, app_, name):
    for _i in range(4):
        _cl = TestClient(app_, client=(f"203.0.113.{_i + 1}", 1))
        for _ in range(4):
            _cl.post("/auth/login", data={"username": name, "password": f"falsch-falsch-{next(_FALSCH)}"})


# Existing stock from a state before this check: the namesake is already in the database.
_n5_b, _n5_bapp = _app(csrf_enabled=False)
_n5_b.create_user("Özlem", password="Geheim12345!-lang", email="oezlem@example.com")
# Raw INSERT without bucket (foreign writer): Since G12c `store.create_user` itself rejects the
# namesake.
_n5_platz = _n5_b.store._exec("INSERT INTO users(username, display_name, created_at) VALUES (?,?,?)",
                              ("özlem", "özlem", _store_mod.jetzt())).lastrowid
# Created a minute before the guess attempts — otherwise they would remain as attempts from the
# creation second, and the probe would not measure the bucket check.
_n5_b.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (_n5_platz,))
_n5_b.store.set_disabled(_n5_platz, True)
_n5_b.create_magic_token("verify_email", user_id=_n5_platz)
_n5_rate(_n5_b, _n5_bapp, "Özlem")


def _n5_topf(a, topf):
    return a.store._one("SELECT COUNT(*) AS n FROM login_attempt WHERE username=? AND success=0",
                        (topf,))["n"]


_n5_vor = _n5_topf(_n5_b, "özlem")
_n5_b.store._exec("UPDATE magic_token SET expires_at=1 WHERE purpose='verify_email'")
_n5_gc = _n5_b.gc()["unverified_accounts"]
_n5_frisch = TestClient(_n5_bapp, client=("198.51.100.200", 1)).post(
    "/auth/login", data={"username": "Özlem", "password": "falsch"})
r.check("N-5: gc() of a namesake from the existing stock does not empty the bucket of the remaining account",
        _n5_vor >= 15 and _n5_gc == 1 and _n5_topf(_n5_b, "özlem") == _n5_vor
        and _n5_frisch.status_code == 429,
        f"before {_n5_vor}, gc={_n5_gc}, after {_n5_topf(_n5_b, 'özlem')}, "
        f"next attempt HTTP {_n5_frisch.status_code}")

# And in the other direction: The bucket of `Émile` is `émile`, SQLite `lower('Émile')`
# is `Émile`. A deletion by the admin therefore left the attempt rows lying — the
# promise of H-13 ("their attempt rows are deleted") applied only to ASCII names.
_n5_c, _n5_capp = _app(csrf_enabled=False)
_n5_c.create_user("chef", password="Geheim12345!-lang", is_admin=True)
_n5_ae = _n5_c.create_user("Ärmel", password="Geheim12345!-lang")
_n5_c.store._exec("UPDATE users SET created_at=created_at-60 WHERE id=?", (_n5_ae,))
_n5_rate(_n5_c, _n5_capp, "Ärmel")
_n5_cvor = _n5_topf(_n5_c, "ärmel")
_n5_c.delete_user(_n5_ae)
r.check("N-5: deleting an account with non-ASCII capital letters also clears its counting bucket",
        _n5_cvor >= 15 and _n5_topf(_n5_c, "ärmel") == 0,
        f"before {_n5_cvor}, after {_n5_topf(_n5_c, 'ärmel')}")

# ── N-2: the GET with an invitation token also leaves a trace (B5-18) ──────────────────────
# `/auth/register?invite=<t>` checks the token via peek and answers differently (403/200
# including the prefilled address) — without audit and fail2ban line. /auth/invite/<t> and the POST
# log; whoever wanted to probe invitation tokens took the silent path.
# (Mutation probe: remove the `token_rejected` call in `register_page` → red.)
_n2_a, _n2_app = _app(allow_signup=True, signup_invite_only=True, magiclink_enabled=True,
                      csrf_enabled=False)
_n2_a.set_mailer(lambda *x, **k: True)
_n2_inv = _n2_a.create_invite("gast@example.com", "http://testserver")
_n2_tok = _n2_inv.get("token") or _n2_inv["url"].rsplit("/", 1)[-1]
_n2_puffer = io.StringIO()
_n2_haken = logging.StreamHandler(_n2_puffer)
_sec.seclog.addHandler(_n2_haken)
_n2_erg = {}
try:
    _n2_c = TestClient(_n2_app, client=("203.0.113.5", 1))
    for _n2_name, _n2_pfad in (("geraten", "/auth/register?invite=geraten-123"),
                               ("echt", f"/auth/register?invite={_n2_tok}"),
                               ("ohne", "/auth/register")):
        _n2_a0 = len(_n2_a.store._all("SELECT id FROM audit WHERE event='token_invalid'"))
        _n2_l0 = len([z for z in _n2_puffer.getvalue().splitlines()
                      if z.startswith(_sec.LOG_PRUEFUNG) and "token_invite" in z])
        _n2_st = _n2_c.get(_n2_pfad).status_code
        _n2_erg[_n2_name] = (
            _n2_st,
            len(_n2_a.store._all("SELECT id FROM audit WHERE event='token_invalid'")) - _n2_a0,
            len([z for z in _n2_puffer.getvalue().splitlines()
                 if z.startswith(_sec.LOG_PRUEFUNG) and "token_invite" in z]) - _n2_l0)
finally:
    _sec.seclog.removeHandler(_n2_haken)
r.check("N-2: GET /auth/register with an invented invitation token → token_invalid + 'failed verification'",
        _n2_erg.get("geraten") == (403, 1, 1), f"{_n2_erg}")
r.check("N-2: … with a valid token and without any token, by contrast, no row",
        _n2_erg.get("echt") == (200, 0, 0) and _n2_erg.get("ohne") == (403, 0, 0), f"{_n2_erg}")

# ── N-3: the self-service passkey ID is an integer — otherwise 400 ──────────────────
# Only TypeError/ValueError were caught. `1e400`, `Infinity` and `-Infinity` are turned by json.loads
# into float('inf'), `int()` raises OverflowError → HTTP 500. `true` was read by `int()` as passkey 1 and
# deleted it, `1.9` as passkey 1.
# (Mutation probe: in `passkey_delete` again `int(b.get("id"))` with TypeError/ValueError → red.)
if _ilu.find_spec("webauthn") is not None:
    _n3_a, _n3_app = _app(csrf_enabled=False, passkey_enabled=True, rp_id="localhost",
                          origin="http://localhost")
    _n3_anna = _n3_a.create_user("anna", password="Geheim12345!-lang")
    _n3_ereig = []
    _n3_a.on_security_event = lambda e, k, d: _n3_ereig.append(e)
    _n3_a.store.add_webauthn(_n3_anna, b"cred-n3", b"pk", 0, [], "Laptop")
    _n3_pk = _n3_a.store.list_webauthn(_n3_anna)[0]["id"]
    _n3_c = TestClient(_n3_app, client=("203.0.113.70", 1), raise_server_exceptions=False)
    _n3_c.cookies.set(_n3_a.cfg.session_cookie,
                      _n3_a.store.create_session(_n3_anna, 3600, True, "password"))
    _n3_status = {}
    for _n3_body in ('{"id": 1e400}', '{"id": Infinity}', '{"id": -Infinity}', '{"id": NaN}',
                     '{"id": true}', f'{{"id": {_n3_pk}.9}}', '{"id": "¹"}', '{"id": " 1"}',
                     '{"id": 99999999999999999999999999}'):
        _n3_status[_n3_body] = _n3_c.post("/auth/passkey/delete", content=_n3_body,
                                          headers={"content-type": "application/json"}).status_code
    r.check("N-3: id from 1e400/Infinity/true/decimal/exponent → 400, nothing deleted, no event",
            all(s in (400, 404) for s in _n3_status.values())
            and all(_n3_status[b] == 400 for b in list(_n3_status)[:8])
            and len(_n3_a.store.list_webauthn(_n3_anna)) == 1 and _n3_ereig == [],
            f"{_n3_status}, remaining {len(_n3_a.store.list_webauthn(_n3_anna))}, hook {_n3_ereig}")
    _n3_ok = _n3_c.post("/auth/passkey/delete", json={"id": str(_n3_pk)})
    r.check("N-3: … an integer (also as a digit string) deletes as before",
            _n3_ok.status_code == 200 and not _n3_a.store.list_webauthn(_n3_anna)
            and _n3_ereig == ["passkey_removed"], f"HTTP {_n3_ok.status_code}, Hook {_n3_ereig}")

# ── N-8: the deletion-path guard also sees alias, getattr and raw SQL ──────────────────────
# `_ist_store` recognized only the literal forms `auth.store.x`, `self.store.x`, `store.x`.
# `st = self.store; st.delete_user(uid)` or a `DELETE FROM users` past the store stayed
# green — exactly the "next new path" that the guard is supposed to stand against. Now reversed: A
# call of `delete_user` counts as a store call as long as its receiver is not demonstrably the
# manager (`auth`, `self` in TinySesam), and raw SQL that deletes accounts or passkeys
# (also with a table name from a variable) stands only in the store building blocks.
# Limit that the guard does not see: a method name that arises only at runtime, and
# SQL whose keyword arises only at runtime from fragments (`"DEL" + "ETE FROM …"`).
# (Mutation probes: set the receiver check back to `_ist_store` → red at the alias;
#  return `_sql_ausserhalb` empty → red at the SQL self-test.)
#
# S-4 (final round): The first version searched after `DELETE FROM` directly for the table name or
# the end of the string — the end of the string fits only for the constant part of an f-string. `'DELETE FROM
# %s' % t`, `'DELETE FROM {}'.format('users')` and `DELETE FROM main.users` stayed green.
# Now reversed: EVERY deleting SQL (`DELETE FROM`, `DROP TABLE`, `REPLACE INTO`) reports itself,
# unless a table name follows that carries neither account nor passkey
# (read from `store.SCHEMA`, without `users`/`webauthn_cred`). A placeholder (`%s`, `{}`,
# `{t}`, end of string), a schema prefix (`main.`), quotation marks, an SQL comment
# in between and an unknown name count as the accounts table or as a name from a variable.
# (Mutation probes: let `_sql_loeschziele` recognize only `users|webauthn_cred|$` again → red
#  at the self-test "%-format, .format(), schema prefix"; a second deletion path in `manager.py` with
#  exactly these three spellings → red at the guard, three findings.)
from tinysesam import store as _store_s4  # noqa: E402

_SQL_KOMMENTAR = re.compile(r"/\*.*?\*/|--[^\n]*", re.S)
_SQL_BEZEICHNER = r"(?:\"[^\"]*\"|`[^`]*`|\[[^\]]*\]|\w+)"
_SQL_LOESCHT = re.compile(
    r"\b(?:DELETE\s+FROM|DROP\s+TABLE(?:\s+IF\s+EXISTS)?|(?:INSERT\s+OR\s+)?REPLACE\s+INTO)\s*"
    rf"(?P<ziel>(?:{_SQL_BEZEICHNER}\s*\.\s*)?{_SQL_BEZEICHNER})?", re.IGNORECASE)
_SQL_HARMLOS = frozenset(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", _store_s4.SCHEMA)) - {
    "users", "webauthn_cred"}


def _sql_loeschziele(text: str) -> list:
    """The tables from which `text` deletes and which are NOT known to be harmless: `users`,
    `webauthn_cred`, or `""` for a name that is only fixed at runtime (placeholder,
    unknown name)."""
    aus = []
    for treffer in _SQL_LOESCHT.finditer(_SQL_KOMMENTAR.sub(" ", text)):
        ziel = treffer.group("ziel") or ""
        name = re.split(r"\s*\.\s*", ziel)[-1].strip("\"`[]").lower() if ziel else ""
        if name in _SQL_HARMLOS:
            continue
        aus.append(name if name in ("users", "webauthn_cred") else "")
    return aus


def _ist_manager(knoten, klasse) -> bool:
    """`auth.x`, `self.auth.x` and in TinySesam `self.x` — the manager, not the store."""
    return ((isinstance(knoten, _ast.Name) and knoten.id == "auth")
            or (isinstance(knoten, _ast.Attribute) and knoten.attr == "auth")
            or (isinstance(knoten, _ast.Name) and knoten.id == "self" and klasse == "TinySesam"))


def _getattr_ausserhalb(methode, erlaubt, quellen=None) -> list:
    """`getattr(x, "<methode>")` outside `erlaubt` — the detour around every receiver check."""
    funde = []
    for name, text in (quellen if quellen is not None else _quelltexte()):
        for pfad, knoten, k, f in _knoten_mit_ort(name, text):
            if (isinstance(knoten, _ast.Call) and isinstance(knoten.func, _ast.Name)
                    and knoten.func.id == "getattr" and len(knoten.args) >= 2
                    and isinstance(knoten.args[1], _ast.Constant) and knoten.args[1].value == methode
                    and (k, f) not in erlaubt):
                funde.append(f"{pfad}:{knoten.lineno} ({k}.{f})")
    return funde


def _sql_ausserhalb(erlaubt: dict, quellen=None) -> list:
    """Raw SQL that can delete accounts/passkeys (`_sql_loeschziele`: every deleting
    statement whose table is not known to be harmless), outside the permitted places.
    `erlaubt` assigns to the table (`""` = name from a variable) the pairs (class, function).
    Docstrings do not count."""
    funde = []
    for name, text in (quellen if quellen is not None else _quelltexte()):
        for pfad, knoten, k, f in _knoten_mit_ort(name, text):
            if not (isinstance(knoten, _ast.Constant) and isinstance(knoten.value, str)):
                continue
            if getattr(knoten, "_ist_docstring", False):
                continue
            for tabelle in _sql_loeschziele(knoten.value):
                if (k, f) not in erlaubt.get(tabelle, set()):
                    funde.append(f"{pfad}:{knoten.lineno} ({k}.{f}) DELETE FROM {tabelle or '{…}'}")
    return funde


def _quelltexte():
    return [(p.name, p.read_text(encoding="utf-8")) for p in sorted((ROOT / "tinysesam").glob("*.py"))]


def _knoten_mit_ort(name, text):
    """Every AST node with (file, node, innermost class, innermost function); docstrings marked."""
    baum = _ast.parse(text)
    for traeger in _ast.walk(baum):
        if isinstance(traeger, (_ast.Module, _ast.ClassDef, _ast.FunctionDef, _ast.AsyncFunctionDef)):
            koerper = traeger.body
            if (koerper and isinstance(koerper[0], _ast.Expr)
                    and isinstance(koerper[0].value, _ast.Constant)
                    and isinstance(koerper[0].value.value, str)):
                koerper[0].value._ist_docstring = True
    aus = []

    def gehe(knoten, klasse=None, funktion=None):
        for kind in _ast.iter_child_nodes(knoten):
            k, f = klasse, funktion
            if isinstance(kind, _ast.ClassDef):
                k = kind.name
            elif isinstance(kind, (_ast.FunctionDef, _ast.AsyncFunctionDef)):
                f = kind.name
            aus.append((name, kind, k, f))
            gehe(kind, k, f)
    gehe(baum)
    return aus


def _nicht_manager(knoten, klasse) -> bool:
    return not _ist_manager(knoten, klasse)


_N8_ERLAUBT_SQL = {"users": {("Store", "delete_user")},
                   "webauthn_cred": {("Store", "delete_user"), ("Store", "delete_webauthn")},
                   "": {("Store", "delete_user")}}
_N8_PROBEN = {
    "Alias": "class TinySesam:\n    def weg(self, uid):\n        st = self.store\n        st.delete_user(uid)\n",
    "Attribut": "class Hilfe:\n    def weg(self, uid):\n        self._s.delete_user(uid)\n",
    "getattr": "def weg(s, uid):\n    getattr(s, 'delete_user')(uid)\n",
    "SQL": "class TinySesam:\n    def weg(self, uid):\n        self.store._exec('DELETE FROM users WHERE id=?', (uid,))\n",
    "SQL-Passkey": "def weg(db):\n    db.execute(\"DELETE  FROM webauthn_cred WHERE id=1\")\n",
    "SQL-Variable": "def weg(db, t):\n    db.execute(f'DELETE FROM {t} WHERE id=1')\n",
}
_n8_selbst = {}
for _n8_art, _n8_text in _N8_PROBEN.items():
    _n8_q = [("probe.py", _n8_text)]
    _n8_selbst[_n8_art] = bool(
        _aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")}, _n8_q)
        or _getattr_ausserhalb("delete_user", set(), _n8_q)
        or _sql_ausserhalb(_N8_ERLAUBT_SQL, _n8_q))
_n8_harmlos = [("probe.py", "def route(auth, uid):\n    '''DELETE FROM users steht nur im Docstring'''\n"
                            "    auth.delete_user(uid)\n")]
r.check("N-8 (guard self-test): alias, foreign attribute, getattr and raw SQL trigger",
        all(_n8_selbst.values()), f"{_n8_selbst}")
r.check("N-8 (guard self-test): … the manager call and a docstring do not",
        not (_aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")}, _n8_harmlos)
             or _sql_ausserhalb(_N8_ERLAUBT_SQL, _n8_harmlos)))

# S-4: the spellings the first version overlooked — each alone against the SQL check
# (the call checks would not see `_exec`/`execute` anyway). Plus counter-checks: deleting SQL
# on a harmless table, also with a schema prefix, stays silent — otherwise the guard reports
# every session cleanup, and in the end nobody reads it any more.
_S4_PROBEN = {
    "%-Format": "class TinySesam:\n    def w(self, t, uid):\n        self.store._exec('DELETE FROM %s WHERE id=?' % t, (uid,))\n",
    ".format()": "class TinySesam:\n    def w(self, uid):\n        self.store._exec('DELETE FROM {} WHERE id=?'.format('users'), (uid,))\n",
    "schema prefix": "class TinySesam:\n    def w(self, uid):\n        self.store._exec('DELETE FROM main.users WHERE id=?', (uid,))\n",
    "schema prefix passkey": "def w(db):\n    db.execute('DELETE FROM main.webauthn_cred WHERE id=1')\n",
    "prefix in quotation marks": "def w(db):\n    db.execute('DELETE FROM \"main\".\"users\" WHERE id=1')\n",
    "comment in between": "def w(db):\n    db.execute('DELETE /* x */ FROM users WHERE id=1')\n",
    "concatenation": "def w(db, t):\n    db.execute('DELETE FROM ' + t + ' WHERE id=1')\n",
    "DROP TABLE": "def w(db):\n    db.execute('DROP TABLE IF EXISTS users')\n",
    "REPLACE INTO": "def w(db):\n    db.execute('INSERT OR REPLACE INTO users(id, username) VALUES (1, ?)', ('x',))\n",
}
_s4_selbst = {art: bool(_sql_ausserhalb(_N8_ERLAUBT_SQL, [("probe.py", text)]))
              for art, text in _S4_PROBEN.items()}
r.check("S-4 (guard self-test): %-format, .format(), schema prefix, comment, concatenation, "
        "DROP TABLE and REPLACE INTO trigger",
        all(_s4_selbst.values()), f"{_s4_selbst}")
_s4_harmlos = [("probe.py", "def w(db):\n    db.execute('DELETE FROM session WHERE user_id=?', (1,))\n"
                            "    db.execute('DELETE FROM main.login_attempt WHERE ts < 1')\n"
                            "    db.execute('DELETE FROM \"magic_token\" WHERE used_at IS NOT NULL')\n")]
r.check("S-4 (guard self-test): … deleting SQL on sessions, attempts and tokens does not",
        not _sql_ausserhalb(_N8_ERLAUBT_SQL, _s4_harmlos) and len(_SQL_HARMLOS) >= 10,
        f"{_sql_ausserhalb(_N8_ERLAUBT_SQL, _s4_harmlos)}, harmless: {sorted(_SQL_HARMLOS)}")
_n8_funde = (_aufrufe_ausserhalb("delete_user", _nicht_manager, {("Store", "konto_entfernen")})
             + _aufrufe_ausserhalb("delete_webauthn", lambda k, c: True, {("TinySesam", "remove_passkey")})
             + _getattr_ausserhalb("delete_user", set()) + _getattr_ausserhalb("delete_webauthn", set())
             + _sql_ausserhalb(_N8_ERLAUBT_SQL))
r.check("N-8 (guard): only the building blocks delete accounts and passkeys — not via alias or SQL either",
        not _n8_funde, f"{_n8_funde}")

# ── G4: the detail search during anonymization does not hold the write lock over the whole search ─────
# No index narrows the search in the detail text (`instr`); with an unlimited address (deletion
# by an admin) it reads the whole audit log. Until 2026-09-26 it did so in ONE
# write transaction under `_lock` — every sign-in, every audit entry and every other worker
# waited out the whole search. What is measured is not the clock but the sequence: A lock that lets a
# parallel writer in at every release — via the same instance (another thread in the
# same worker) AND via a second connection without wait time (another worker, `timeout=0`; it
# fails immediately as long as a write transaction is open).
auth_g4, _ = _app()
st4 = auth_g4.store
_G4_ZEILEN = 120_000
st4.db.executemany(
    "INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
    [(1_700_000_000 + i // 10, "apikey_create" if i % 997 == 0 else "login_fail", f"fremd{i % 50}", None,
      "key=1 actor=g4opfer" if i % 997 == 0 else
      "new=g4opfer@example.com" if i % 1499 == 0 else "password reason=wrong")
     for i in range(_G4_ZEILEN)])
st4.db.commit()
_g4_erste = st4._one("SELECT min(id) AS m FROM audit WHERE detail = 'key=1 actor=g4opfer'")["m"]
_g4_treffer = st4._one("SELECT count(*) AS n FROM audit WHERE instr(detail, 'g4opfer') > 0")["n"]


class _G4Schloss:
    """`Store._lock` with a hook: After every release, a parallel writer writes."""

    def __init__(self, echt):
        self.echt, self.freigaben, self.haken, self._im_haken = echt, 0, None, False

    def __enter__(self):
        self.echt.acquire()
        return self

    def __exit__(self, *a):
        self.echt.release()
        self.freigaben += 1
        if self.haken and not self._im_haken:
            self._im_haken = True
            try:
                self.haken()
            finally:
                self._im_haken = False


_g4_fremd = sqlite3.connect(auth_g4.cfg.db_path, timeout=0, isolation_level=None)
_g4_mess = {"intern": 0, "zweite_verbindung": 0, "gesperrt": 0, "block_gelesen": False, "nachgetragen": False,
            "block_sql": ""}


def _g4_parallel():
    st4.audit_log("g4_parallel", "fremd", None, "intern")            # the same worker, another thread
    _g4_mess["intern"] += 1
    try:
        _g4_fremd.execute("BEGIN IMMEDIATE")                          # another worker, without waiting
        _g4_fremd.execute("INSERT INTO audit(ts, event, username, detail) VALUES (?,?,?,?)",
                          (int(_t.time()), "g4_parallel", "fremd", "zweite_verbindung"))
        _g4_fremd.execute("COMMIT")
        _g4_mess["zweite_verbindung"] += 1
    except sqlite3.OperationalError:
        _g4_mess["gesperrt"] += 1
    # Between reading and writing a block, another one changes the first hit row: The
    # write must take the fresh row, not the state that was read.
    if _g4_mess["block_gelesen"] and not _g4_mess["nachgetragen"]:
        _g4_fremd.execute("UPDATE audit SET detail = detail || ' nachtrag=1' WHERE id = ?", (_g4_erste,))
        _g4_mess["nachgetragen"] = True




def _g4_spur(sql):
    if "instr(lower(detail)" in sql:        # a block of the detail search (parameters substituted)
        _g4_mess["block_gelesen"] = True
        _g4_mess["block_sql"] = _g4_mess["block_sql"] or sql


st4.db.set_trace_callback(_g4_spur)
_g4_schloss = _G4Schloss(st4._lock)
st4._lock = _g4_schloss
_g4_schloss.haken = _g4_parallel
try:
    st4.audit_anonymisieren("g4opfer", "deleted#77", ("g4opfer@example.com",),
                            unbefristet=("g4opfer@example.com",))
finally:
    _g4_schloss.haken = None
    st4._lock = _g4_schloss.echt
    st4.db.set_trace_callback(None)
    _g4_fremd.close()
# At least 20 releases with 120 000 rows: at most 6000 rows under one lock. Fixed, not
# computed from `_ANONYM_BLOCK` — otherwise the limit would move along if someone enlarges the block.
_g4_bloecke = 20
r.check(f"G4: {_G4_ZEILEN} rows — the search releases the write lock between the blocks, and "
        "parallel writers get through (the same worker and a second one without wait time)",
        _g4_schloss.freigaben >= _g4_bloecke and _g4_mess["intern"] >= _g4_bloecke
        and _g4_mess["zweite_verbindung"] >= _g4_bloecke and _g4_mess["gesperrt"] == 0,
        f"{_g4_schloss.freigaben} releases, {_g4_mess} with {_g4_bloecke} blocks")
_g4_rest = st4._one("SELECT count(*) AS n FROM audit WHERE instr(detail, 'g4opfer') > 0")["n"]
_g4_ersetzt = st4._one("SELECT count(*) AS n FROM audit WHERE instr(detail, 'deleted#77') > 0")["n"]
r.check("… and still replaces every hit in the detail text (name as actor=, address everywhere)",
        _g4_treffer > 150 and _g4_rest == 0 and _g4_ersetzt == _g4_treffer,
        f"before {_g4_treffer}, remaining {_g4_rest}, replaced {_g4_ersetzt}")
r.check("… and takes the fresh row when writing (an addition in between is not lost)",
        _g4_mess["nachgetragen"] and st4._one("SELECT detail FROM audit WHERE id=?", (_g4_erste,))["detail"]
        == "key=1 actor=deleted#77 nachtrag=1",
        str(dict(st4._one("SELECT detail FROM audit WHERE id=?", (_g4_erste,)))))
r.check("… the rows of the parallel writers stay as they were",
        st4._one("SELECT count(*) AS n FROM audit WHERE event='g4_parallel' AND username='fremd' "
                 "AND detail IN ('intern', 'zweite_verbindung')")["n"]
        == _g4_mess["intern"] + _g4_mess["zweite_verbindung"])
# And the search stays linear: A block is read via the primary key (the plan of the
# statement as it ran), not via an index on `ts` — otherwise every block would read everything from `seit`.
_g4_plan = [str(tuple(z)) for z in st4.db.execute("EXPLAIN QUERY PLAN " + _g4_mess["block_sql"]).fetchall()] \
    if _g4_mess["block_sql"] else []
r.check("G4: a block reads via the primary key (id range), not via an index on ts",
        len(_g4_plan) == 1 and "INTEGER PRIMARY KEY (rowid>? AND rowid<?)" in _g4_plan[0], str(_g4_plan))

def _g4_schritte_beim_entfernen(name, bestand):
    uid = auth_g4.create_user(name, password="Geheim-G4-Pw15!")
    if bestand:   # account from the time before G2: no watermark, the creation (`seit`) applies
        st4._exec("UPDATE users SET name_audit_ab = NULL, name_versuch_ab = NULL WHERE id = ?", (uid,))
    st4.audit_log("apikey_create", "chef", None, f"key=2 actor={name}")
    zaehler = [0]

    def schritt():
        zaehler[0] += 1
        return 0
    st4.db.set_progress_handler(schritt, 1000)
    try:
        st4.konto_entfernen(uid)
    finally:
        st4.db.set_progress_handler(None, 1000)
    rest = st4._one("SELECT count(*) AS n FROM audit WHERE detail = ?", (f"key=2 actor={name}",))["n"]
    return zaehler[0], rest


_g4_jung = {"Wasserlinie": _g4_schritte_beim_entfernen("g4jung", False),
            "Bestand (seit)": _g4_schritte_beim_entfernen("g4bestand", True)}
r.check("G4: a young account does not read the whole log — with watermark and in existing stock from `seit`",
        all(n < 60 and rest == 0 for n, rest in _g4_jung.values()),
        f"{_g4_jung} (× 1000 SQLite steps, rows remaining) with {_G4_ZEILEN} rows")
# (Mutation probes, run individually: `_ANONYM_BLOCK` to 10**9 → the first check red
#  (one release instead of one per block); do not read the row fresh when writing, but take the
#  state that was read → "fresh row" red; `id + 0` → `id` (the start from `seit` then runs
#  along the table from the beginning) → "young account" red; ignore the start entirely → likewise; write the id range of the block past the primary key (`+id`) →
#  "via the primary key" red; the old version (one write transaction) → the first three red.)


# ── F4 (review round locks/counters 2026-09-27): what the deletion promise H-13 still left out ───────────────
# Already so on main: After deletion, typed-in spellings (4a), earlier names and
# addresses (4b) and the values in the own rows (4c) still stood in the audit log.
_F4_PW = "Loesch-Pw-15xy"


def _f4_app():
    a, ap = _app(csrf_enabled=False, passkey_enabled=False, lang="de")
    a.set_security("rate_limit_max", 100000)
    a.set_security("max_login_attempts", 1000)
    post: list = []
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, text)) or True)
    a.create_user("root", password=_F4_PW, email="root@example.com", is_admin=True)
    return a, ap, post


def _f4_rest(a, *spuren):
    """All audit rows in which one of the traces (casefold) still appears in name or detail."""
    aus = []
    for z in a.store._all("SELECT id, event, username, detail FROM audit ORDER BY id"):
        text = f"{z['username'] or ''} {z['detail'] or ''}".casefold()
        if any(s.casefold() in text for s in spuren):
            aus.append((z["event"], z["username"], z["detail"]))
    return aus


# 4a: `login_fail` writes the RAW input; counting happens in the bucket (strip, NFKC, lower).
_f4a, _f4a_app, _ = _f4_app()
_f4a_uid = _f4a.create_user("Émile", password=_F4_PW, email="emile@example.com")
_f4a_c = TestClient(_f4a_app, client=("192.0.2.9", 4000))
for _eingabe in ("Émile", "émile", "Émile ", " emile@example.com", "ＥＭＩＬＥ@example.com", "ÉMILE"):
    _f4a_c.post("/auth/login", data={"username": _eingabe, "password": "falsch"}, follow_redirects=False)
_f4a_vor = len(_f4_rest(_f4a, "émile", "emile@", "ｅｍｉｌｅ"))
_f4a.delete_user(_f4a_uid)
_f4a_rest = _f4_rest(_f4a, "émile", "emile@", "ｅｍｉｌｅ")
# (Mutation probe: take the comparison in the bucket out of the block scan (`auch_name` empty, `name_trifft`
#  always false) → four rows remain → red.)
r.check("F4a: every typed spelling (whitespace, accented capital, full width) is out of the audit log after "
        "deletion", _f4a_vor >= 6 and _f4a_rest == [], f"before {_f4a_vor}, remaining {_f4a_rest}")
# Counter-check: If a REMAINING account shares the bucket (namesake from the existing stock, raw INSERT),
# a folded spelling stays — it may belong to it (as with `delete_attempts_for`).
_f4n, _f4n_app, _ = _f4_app()
_f4n.create_user("Karl", password=_F4_PW)
_f4n_platz = _f4n.store._exec("INSERT INTO users(username, display_name, created_at) VALUES (?,?,?)",
                              ("karl", "karl", _store_mod.jetzt() - 60)).lastrowid
TestClient(_f4n_app, client=("192.0.2.10", 1)).post("/auth/login", data={"username": " KARL ", "password": "x"})
_f4n.delete_user(_f4n_platz)
r.check("… a bucket shared by a remaining account is not compared folded (counter-check)",
        [z for z in _f4_rest(_f4n, " KARL ") if z[0] == "login_fail"] != [],
        str(_f4_rest(_f4n, "karl")))

# 4b: earlier names and addresses of the same account — renamed, address changed, then deleted.
_f4b, _f4b_app, _f4b_post = _f4_app()
_f4b_uid = _f4b.create_user("bob", password=_F4_PW, email="bob.alt@example.com")
_f4b_c = TestClient(_f4b_app, client=("192.0.2.11", 1))
_f4b_c.post("/auth/login", data={"username": "bob", "password": _F4_PW}, follow_redirects=False)
_f4b_c.post("/auth/login", data={"username": "bob.alt@example.com", "password": "falsch"}, follow_redirects=False)
_f4b.change_username(_f4b_uid, "robert")
_f4b.request_email_change(_f4b_uid, "robert@example.com", "http://testserver")()
_f4b_link = [t for an, t in _f4b_post if an == "robert@example.com"]
_f4b_raw = re.search(r"https?://\S+/([A-Za-z0-9_-]{20,})", _f4b_link[-1]).group(1) if _f4b_link else ""
_f4b_ok = _f4b.confirm_email_change(_f4b_raw)
# Afterwards someone takes over the free name and the free address — their rows do not belong to the account.
_f4b_grenze = _f4b.store._one("SELECT max(id) AS m FROM audit")["m"]
_f4b.create_user("bob", password=_F4_PW, email="bob.alt@example.com")
TestClient(_f4b_app, client=("192.0.2.12", 1)).post("/auth/login", data={"username": "bob", "password": _F4_PW},
                                                     follow_redirects=False)
_f4b.delete_user(_f4b_uid)
_f4b_rest = [z for z in _f4b.store._all("SELECT id, event, username, ip, detail FROM audit WHERE id <= ?",
                                        (_f4b_grenze,))
             if z["username"] == "bob" or any(s in f"{z['username']} {z['detail']}".casefold()
                                               for s in ("robert", "bob.alt@", "old=bob", "alt=bob"))]
_f4b_spaeter = _f4b.store._all("SELECT event, ip FROM audit WHERE id > ? AND username = 'bob'", (_f4b_grenze,))
# (Mutation probe: `_fruehere_kennungen` returns [] → the sign-in under `bob` including IP and the
#  failed attempt under the old address remain → red.)
r.check("F4b: earlier names and addresses — renamed, address changed, deleted: no trace any more",
        _f4b_ok == "ok" and _f4b_rest == [], f"{_f4b_ok}, remaining {[dict(z) for z in _f4b_rest]}")
r.check("… only in their span: the rows of the later holder of name and address stay (counter-check)",
        any(z["event"] == "login" and z["ip"] == "192.0.2.12" for z in _f4b_spaeter),
        str([dict(z) for z in _f4b_spaeter]))

# 4c: the values in the own rows — a never redeemed address change (`new=`), the address from
# LDAP/SAML (`to=`, as `_adresse_aus_quelle_belegen` writes it), the old name (`old=`).
_f4c, _f4c_app, _ = _f4_app()
_f4c_uid = _f4c.create_user("carla", password=_F4_PW, email="carla@example.com")
_f4c.request_email_change(_f4c_uid, "carla.neu@example.com", "http://testserver")()
_f4c.audit("federation_email_confirm", "carla", None, f"account={_f4c_uid} source=ldap to=carla.ldap@example.com")
_f4c.audit("username_changed", "carla", None, "old=frueher-carla by=operator actor=root")
_f4c.audit("email_change_requested", "root", None, "new=root.neu@example.com")      # foreign row
_f4c.delete_user(_f4c_uid)
_f4c_eigen = [z["detail"] for z in _f4c.store._all("SELECT detail FROM audit WHERE username=?",
                                                    (f"deleted#{_f4c_uid}",))]
# (Mutation probe: switch off `_eigene_werte_ersetzen` → `new=carla.neu@…`, `to=…`, `old=…` remain → red.)
r.check("F4c: in the own rows `new=`, `to=` and `old=` are replaced",
        _f4_rest(_f4c, "carla") == [] and any("new=deleted#" in d for d in _f4c_eigen)
        and any("to=deleted#" in d for d in _f4c_eigen) and any("old=deleted#" in d for d in _f4c_eigen),
        f"{_f4_rest(_f4c, 'carla')} {_f4c_eigen}")
r.check("… `actor=` in the own rows and the values in foreign rows stay (counter-check)",
        any("actor=root" in d for d in _f4c_eigen)
        and bool(_f4c.store._one("SELECT 1 AS x FROM audit WHERE username='root' AND detail='new=root.neu@example.com'")),
        str(_f4c_eigen))

sys.exit(r.done())
