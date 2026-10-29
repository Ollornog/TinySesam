"""Addresses from LDAP and SAML (PO decision 2026-09-25).

Default "not trusted": the address from the source does not go directly into the account. The normal route
is the confirmation link — the same as for the address change in self-service. An attribute of the
source can prove the address of THIS login (for IdPs that maintain it), the blanket switch
remains for curated sources. What is measured is the effect: what is in the account, which mail goes
to whom, and the bolts against harassment (open link, once a day, proven address stays) and
against lockout via the shared mail quota. Plus G12a (2026-09-26): "once a day"
counts delivered links in the database, across all workers; only the memory dampens attempts.
"""
from __future__ import annotations

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import config_check as _kp  # noqa: E402
from tinysesam.manager import _REQUEST  # noqa: E402
from tinysesam.ldap_ import _attribute_list  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Addresses from LDAP and SAML — confirmation by link")
BASE = "https://app.example.com"


class Directory:
    """Stand-in for the LDAP client AFTER a successful bind: returns the entry the way
    `LDAPClient.authenticate` returns it (with `email_verified`, if configured)."""

    def __init__(self, entries):
        self.entries = entries

    def authenticate(self, username, password):
        e = self.entries.get(username)
        if not e or e["pw"] != password:
            return None
        return {"username": username, "email": e.get("email"), "name": username, "groups": [],
                "id": e.get("id"), "email_verified": e.get("beleg")}


def _setup(**cfg):
    post: list = []
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False, base_url=BASE, lang="de", ldap_enabled=True,
                 ldap_url="ldap://dummy", ldap_allow_plaintext=True, ldap_auto_create=True)
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    auth.set_mailer(lambda to, subject, text, html=None: post.append((to, subject, text)))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post


def _sign_in(auth, name, entry):
    auth.ldap = Directory({name: {"pw": "pw", **entry}})
    u = auth._check_ldap(name, "pw")
    auth._notice_outcome.wait()
    return u


def _elapse(auth, sec):
    """Let `sec` seconds pass: for the throttles in memory (their timestamps back) and
    for the daily quota in the database (the audit rows back). The process clock
    stays put — a `mock.patch` on `time.time` would leave it set forward for the rest of the run
    (`store._Clock` never runs backwards)."""
    for stamp in auth.rl._hits.values():
        for i in range(len(stamp)):
            stamp[i] -= sec
    auth.store._exec("UPDATE audit SET ts = ts - ?", (int(sec),))


def _link(post):
    hit = [re.search(r"https://app\.example\.com(/auth/email/\S+)", m[2]) for m in post]
    return next((t.group(1) for t in hit if t), "")


# ── LDAP, default: not trusted → confirmation link ─────────────────────────────────────────
auth, app, post = _setup()
r.check("Default: the directory is not trusted wholesale", auth.cfg.ldap_email_trusted is False)
u = _sign_in(auth, "bob", {"email": "Bob@Example.com", "id": "uuid-bob"})
account = auth.get_user(u["id"])
r.check("First sign-in: the account has no address yet", not account["email"], str(dict(account)))
r.check("… a confirmation link went to the address from the directory",
        [m[0] for m in post] == ["bob@example.com"] and _link(post), str(post))
r.check("… with audit row (source and target)",
        auth.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm' "
                        "AND detail LIKE '%source=ldap%to=bob@example.com%'") is not None)
link = _link(post)
post.clear()
_sign_in(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("Second sign-in, link still open: no new link", post == [], str(post))
# An open link remains a bolt of its own — even if the daily limit were free again
# (a link lives up to seven days, `email_change_ttl_min`). A day passes for memory AND
# database; the link (real clock) is then still open.
_elapse(auth, 86401)
_sign_in(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("… not even after the daily limit has passed, as long as the link is open", post == [], str(post))
done = TestClient(app).post(link, follow_redirects=False)
auth._notice_outcome.wait()
account = auth.get_user(u["id"])
r.check("Click on the link: the address is in the account, WITH proof",
        done.status_code == 303 and account["email"] == "bob@example.com" and account["email_verified"],
        f"{done.status_code} {dict(account)}")
r.check("… and goes to the app as Remote-Email",
        auth._forward_response_headers(auth.get_user(u["id"])).get("Remote-Email") == "bob@example.com")
post.clear()
_sign_in(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("After confirmation: no more links", post == [], str(post))

# Daily limit: link expired (gone), still no second one on the same day. A quarter of an hour
# later — the dampening in memory is over then (G12a), what counts is the delivery in the database.
auth2, _, post2 = _setup()
u2 = _sign_in(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
auth2.store._exec("DELETE FROM magic_token")
_elapse(auth2, 901)
post2.clear()
_sign_in(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("Link expired, same day (+15 min): no second link (at most one per day)",
        post2 == [], str(post2))
_elapse(auth2, 86401)                     # "one day later" — the audit row is older
_sign_in(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("… the next day one again", [m[0] for m in post2] == ["cleo@example.com"], str(post2))

# An account with a proven address keeps it — even one other than that of the source.
auth3, _, post3 = _setup()
u3 = _sign_in(auth3, "dana", {"email": "dana@example.com", "id": "uuid-dana"})
auth3.store.set_email(u3["id"], "dana.privat@example.com", verified=True)
_elapse(auth3, 86401)                     # daily quota free: only the proof bolts
auth3.store._exec("DELETE FROM magic_token")
post3.clear()
_sign_in(auth3, "dana", {"email": "dana@example.com", "id": "uuid-dana"})
r.check("Account with proven own address: no link, the address stays",
        post3 == [] and auth3.get_user(u3["id"])["email"] == "dana.privat@example.com", str(post3))

# The address already belongs to another account: no link, audit only.
auth4, _, post4 = _setup()
auth4.create_user("erna", email="erna@example.com")
u4 = _sign_in(auth4, "eve", {"email": "erna@example.com", "id": "uuid-eve"})
r.check("Address of another account: no link, the account stays without address, audit row",
        post4 == [] and not auth4.get_user(u4["id"])["email"]
        and auth4.store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None, str(post4))

# Switched off or without preconditions: nothing at all.
for title, cfg in (("federation_email_confirm=False", {"federation_email_confirm": False}),
                   ("ohne base_url", {"base_url": ""})):
    a_, _, p_ = _setup(**cfg)
    u_ = _sign_in(a_, "fritz", {"email": "fritz@example.com", "id": "uuid-fritz"})
    r.check(f"{title}: no link, no address", p_ == [] and not a_.get_user(u_["id"])["email"], str(p_))

# An address from `admin_identifiers` gets no link: a user who maintains their `mail` attribute
# themselves would otherwise carry it, proven, on the account after the owner's good-faith click.
a4b, _, p4b = _setup(admin_identifiers=["boss@example.com"])
u4b = _sign_in(a4b, "mallory", {"email": "boss@example.com", "id": "uuid-mallory"})
r.check("Allowlist address from the directory: no link, no address, not admin",
        p4b == [] and not a4b.get_user(u4b["id"])["email"] and not a4b.get_user(u4b["id"])["is_admin"], str(p4b))

# ── LDAP: trusted wholesale or proven by attribute ─────────────────────────────────────────
a5, _, p5 = _setup(ldap_email_trusted=True)
u5 = _sign_in(a5, "gina", {"email": "gina@example.com", "id": "uuid-gina"})
k5 = a5.get_user(u5["id"])
r.check("ldap_email_trusted=True: address directly WITH proof, no link",
        k5["email"] == "gina@example.com" and k5["email_verified"] and p5 == [], f"{dict(k5)} {p5}")

a6, _, p6 = _setup(ldap_attr_email_verified="emailVerified")
r.check("The proof attribute is also requested from the directory",
        "emailVerified" in _attribute_list(a6.cfg), str(_attribute_list(a6.cfg)))
u6 = _sign_in(a6, "hans", {"email": "hans@example.com", "id": "uuid-hans", "beleg": "TRUE"})
k6 = a6.get_user(u6["id"])
r.check("Proof attribute \"TRUE\": address directly WITH proof, no link",
        k6["email"] == "hans@example.com" and k6["email_verified"] and p6 == [], f"{dict(k6)} {p6}")
u6b = _sign_in(a6, "ida", {"email": "ida@example.com", "id": "uuid-ida", "beleg": "FALSE"})
r.check("Proof attribute \"FALSE\": not trusted — link instead of address",
        not a6.get_user(u6b["id"])["email"] and [m[0] for m in p6] == ["ida@example.com"], str(p6))
p6.clear()
u6c = _sign_in(a6, "jan", {"email": "jan@example.com", "id": "uuid-jan"})
r.check("Proof attribute missing in the entry: not trusted",
        not a6.get_user(u6c["id"])["email"] and [m[0] for m in p6] == ["jan@example.com"], str(p6))
a6b, _, p6b = _setup()
u6d = _sign_in(a6b, "kai", {"email": "kai@example.com", "id": "uuid-kai", "beleg": "TRUE"})
r.check("Without a configured proof attribute a supplied one does not count",
        not a6b.get_user(u6d["id"])["email"], str(dict(a6b.get_user(u6d["id"]))))

# Via the login route: the proof attribute carries the allowlist address like the switch — right
# at THIS sign-in, not only at the next one via a local factor.
for value, should in (("TRUE", True), ("FALSE", False)):
    a_b, app_b, _ = _setup(admin_identifiers=["boss@example.com"], ldap_attr_email_verified="emailVerified")
    a_b.ldap = Directory({"bossin": {"pw": "pw", "email": "boss@example.com", "id": "uuid-bossin", "beleg": value}})
    response = TestClient(app_b).post("/auth/login", data={"username": "bossin", "password": "pw"},
                                     follow_redirects=False)
    account_b = a_b.store.get_user_by_name("bossin")
    r.check(f"Login route, proof attribute {value}: first admin {'yes' if should else 'no'}",
            response.status_code == 303 and bool(account_b["is_admin"]) is should,
            f"{response.status_code} {dict(account_b) if account_b else None}")
_w_attr = " ".join(_kp.check_config(TinySesamConfig(
    db_path=":memory:", admin_identifiers=["boss@example.com"], ldap_enabled=True,
    ldap_url="ldaps://d.example", ldap_auto_create=True, ldap_attr_email_verified="emailVerified"))[1])
r.check("Config check: with proof attribute \"trusted source\", not \"NEVER\"",
        "trusted source" in _w_attr and "NEVER" not in _w_attr, _w_attr[:200])

# ── SAML ─────────────────────────────────────────────────────────────────────────────────
a7, _, p7 = _setup()
u7 = a7._check_saml("lena", {"email": ["lena@example.com"]})
a7._notice_outcome.wait()
r.check("SAML, default: no account attribute, link to the address from the assertion",
        not a7.get_user(u7["id"])["email"] and [m[0] for m in p7] == ["lena@example.com"], str(p7))
a8, _, p8 = _setup(saml_attr_email_verified="email_verified")
u8 = a8._check_saml("mia", {"email": ["mia@example.com"], "email_verified": ["true"]})
a8._notice_outcome.wait()
k8 = a8.get_user(u8["id"])
r.check("SAML, proof attribute \"true\": address directly WITH proof, no link",
        k8["email"] == "mia@example.com" and k8["email_verified"] and p8 == [], f"{dict(k8)} {p8}")
u8b = a8._check_saml("nils", {"email": ["nils@example.com"], "email_verified": ["false"]})
a8._notice_outcome.wait()
r.check("SAML, proof attribute \"false\": link instead of address",
        not a8.get_user(u8b["id"])["email"] and [m[0] for m in p8] == ["nils@example.com"], str(p8))

# SAML, proof attribute and name (attack round, finding 1): the attribute proves the ADDRESS, not
# the name. An IdP with self-registration lets the user choose the NameID — `bob@example.com`
# as name, their own address confirmed. Without this rule situation 4 bound the local account
# `bob@example.com` via the name: takeover, also of an admin.
a10, _, _ = _setup(saml_attr_email_verified="email_verified")
victim10 = a10.create_user("bob@example.com", password="Opfer-Passwort1", email="bob@example.com")
a10.store.set_admin(victim10, True)
u10 = a10._check_saml("bob@example.com", {"email": ["angreifer@evil.example"], "email_verified": ["true"]})
r.check("SAML, proof attribute: an @ name that is NOT the proven address hits no local account",
        u10 is None or (u10["id"] != victim10 and u10["username"].startswith("saml-") and not u10["is_admin"]),
        str(u10))
u10b = a10._check_saml("mia@example.com", {"email": ["mia@example.com"], "email_verified": ["true"]})
r.check("… if it is exactly the proven address, it remains the account name (like OIDC with email_verified)",
        u10b is not None and u10b["username"] == "mia@example.com", str(u10b))
a10c, _, _ = _setup(saml_attr_email_verified="email_verified", saml_attr_username="email")
a10c.create_user("chefin", password="Opfer-Passwort1")
u10c = a10c._check_saml("id-1", {"email": ["chefin"], "email_verified": ["true"]})
r.check("… and a name from the address attribute that is not an address stays unproven",
        u10c is None or u10c["username"] != "chefin", str(u10c))

# Proof attribute made of whitespace (finding 2): check and runtime read the same, trimmed value.
a11, app11, _ = _setup(admin_identifiers=["boss@example.com"], ldap_attr_email_verified=" ")
k11 = a11.create_user("bossin", email="boss@example.com")
a11.store.set_email_verified(k11, True)
a11.ldap = Directory({"bossin": {"pw": "pw", "email": "boss@example.com"}})
TestClient(app11).post("/auth/login", data={"username": "bossin", "password": "pw"}, follow_redirects=False)
import dataclasses as _dc
_w11 = " ".join(_kp.check_config(_dc.replace(a11.cfg, lang="en"))[1])
_w11_de = " ".join(_kp.check_config(a11.cfg)[1])      # the suite runs with lang="de": same finding in German
r.check("Proof attribute \" \": the check says \"NEVER\", and the runtime does not promote either",
        "NEVER" in _w11 and "NIE" in _w11_de and not a11.get_user(k11)["is_admin"], f"is_admin={a11.get_user(k11)['is_admin']}")

# ── G12a: deliveries count, attempts dampen ───────────────────────────────────────────────────
# Until 2026-09-26 the ATTEMPT already consumed the daily quota, per process in memory: a
# throttled target address or a failed delivery cost the link for a day, and two
# workers sent two. Now the database counts deliveries (`federation_email_confirm account=<id>`
# only after delivery); the memory only dampens attempts.

# (a) The target address is currently throttled: no link — but one after the throttle window.
g_a, _, p_a = _setup()
for _ in range(int(g_a._sec("mail_per_address_max"))):
    g_a.rl.allow("wechsel:gerd@example.com", g_a._sec("mail_per_address_max"),
                 g_a._sec("mail_per_address_window_sec"))
_sign_in(g_a, "gerd", {"email": "gerd@example.com", "id": "uuid-gerd"})
r.check("G12a: target address throttled → no link, no federation_email_confirm row",
        p_a == [] and g_a.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None,
        str(p_a))
_elapse(g_a, int(g_a._sec("mail_per_address_window_sec")) + 1)
_sign_in(g_a, "gerd", {"email": "gerd@example.com", "id": "uuid-gerd"})
r.check("… after the throttle window (+15 min) same day: the link comes",
        [m[0] for m in p_a] == ["gerd@example.com"] and _link(p_a), str(p_a))

# (b) The first delivery fails: no row, the token is not valid — a link after the window.
g_b, _, p_b = _setup()
attempts = {"n": 0}


def _first_broken(to, subject, text, html=None):
    attempts["n"] += 1
    if attempts["n"] == 1:
        raise OSError("mail server unreachable")
    p_b.append((to, subject, text))


g_b.set_mailer(_first_broken)
u_b = _sign_in(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("G12a: first delivery failed → no federation_email_confirm row, no open link",
        attempts["n"] == 1 and p_b == []
        and g_b.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None
        and not g_b.store.open_token(u_b["id"], "email_change", "hilde@example.com"),
        f"{attempts} {p_b}")
_sign_in(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("… right afterwards (same process, within the window) no new attempt yet",
        attempts["n"] == 1, str(attempts))
_elapse(g_b, int(g_b._sec("mail_per_address_window_sec")) + 1)
_sign_in(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("… after the window same day: the link is delivered, now with row (account=<id> first)",
        [m[0] for m in p_b] == ["hilde@example.com"] and _link(p_b)
        and g_b.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm' AND detail LIKE ?",
                           (f"account={u_b['id']} source=ldap to=hilde@example.com",)) is not None,
        f"{attempts} {p_b}")

# (c) Two workers on one database: each with its own memory, but ONE daily quota.
db_c = str(Path(tempfile.mkdtemp()) / "t.db")
w1, _, p_c1 = _setup(db_path=db_c)
w2, _, p_c2 = _setup(db_path=db_c)
_sign_in(w1, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
w1.store._exec("DELETE FROM magic_token")          # link expired / cleared away
_elapse(w2, 901)                                 # same day, a quarter of an hour later
_sign_in(w2, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
r.check("G12a: two workers, same day: the second sends no second link",
        [m[0] for m in p_c1] == ["ines@example.com"] and p_c2 == [], f"{p_c1} {p_c2}")
_sign_in(w2, "jonas", {"email": "jonas@example.com", "id": "uuid-jonas"})
r.check("… the quota applies per account: another account gets its link on the same day",
        [m[0] for m in p_c2] == ["jonas@example.com"], str(p_c2))
p_c2.clear()
_elapse(w2, 86401)
_sign_in(w2, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
r.check("… the next day ines gets one again", [m[0] for m in p_c2] == ["ines@example.com"], str(p_c2))

# (d) Taken address: never a link — and its audit row at most once a day, not on
# every sign-in (the intent of the old daily quota stays).
g_d, _, p_d = _setup()
g_d.create_user("karla", email="karla@example.com")
for _ in range(3):
    _sign_in(g_d, "kurt", {"email": "karla@example.com", "id": "uuid-kurt"})
    _elapse(g_d, int(g_d._sec("mail_per_address_window_sec")) + 1)
_lines_d = g_d.store._one("SELECT COUNT(*) AS n FROM audit WHERE event='email_change_taken'")["n"]
r.check("G12a: taken address, three sign-ins 15 min apart → exactly one audit row, no link",
        _lines_d == 1 and p_d == []
        and g_d.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None,
        f"{_lines_d} {p_d}")

# The row is created in the outbox, but carries IP and actor of the request as before.
g_e, _, _ = _setup()
_brand = _REQUEST.set({"ip": "203.0.113.7", "akteur": None})
try:
    _sign_in(g_e, "lars", {"email": "lars@example.com", "id": "uuid-lars"})
finally:
    _REQUEST.reset(_brand)
_line_e = g_e.store._one("SELECT ip FROM audit WHERE event='federation_email_confirm'")
r.check("… the federation_email_confirm row carries the IP of the request",
        _line_e is not None and _line_e["ip"] == "203.0.113.7", str(dict(_line_e) if _line_e else None))

# Account page of an LDAP account (G12b): the same events, whether the address from the directory is free
# or taken — `federation_email_confirm` arises only for a free one and stays absent there.
_view = {}
for kind, address in (("frei", "mona@example.com"), ("vergeben", "nora@example.com")):
    a_k, _, _ = _setup()
    a_k.create_user("nora", email="nora@example.com")
    u_k = _sign_in(a_k, "mona", {"email": address, "id": "uuid-mona"})
    _view[kind] = [e["event"] for e in a_k.own_events(u_k["id"], limit=50)]
r.check("G12b: account page of an LDAP account the same for free and taken address, without federation_email_confirm",
        _view["frei"] == _view["vergeben"] and "email_change_requested" in _view["frei"]
        and not {None, "federation_email_confirm", "email_change_taken"} & set(_view["frei"] + _view["vergeben"]),
        str(_view))

# ── Attack round 2026-09-26 (a1-02): no oracle across several workers ─────────────────────────
# G12a counted the delivered link in the database, but the rejection of a taken address
# only in memory — per worker and until restart. An LDAP user sets their `mail` to a
# foreign address and signs in via changing workers: for a free one their account page showed
# exactly one request, for a taken one one more with every further worker
# (measured: [1, 1, 1, 1, 1] versus [1, 2, 2, 2, 3]). Now the rejection is also counted in the database.
def _alternate_everything(auth, sec):
    """Like `_elapse`, plus the links: their validity also expires with time."""
    _elapse(auth, sec)
    auth.store._exec("UPDATE magic_token SET expires_at = expires_at - ?", (int(sec),))


def _worker_execution(grant, **cfg):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    w1, _, p1 = _setup(db_path=db, **cfg)
    w2, _, p2 = _setup(db_path=db, **cfg)
    if grant:
        w1.create_user("opfer", email="ziel@example.com")
    number = []

    def _view(w):
        u = _sign_in(w, "mallory", {"email": "ziel@example.com", "id": "uuid-mallory"})
        number.append([e["event"] for e in w.own_events(u["id"], limit=50)].count("email_change_requested"))
    for w in (w1, w2, w1, w2):
        _view(w)
    w3, _, p3 = _setup(db_path=db, **cfg)          # a restart: fresh memory, same file
    _view(w3)
    lines = w3.store._one("SELECT COUNT(*) AS n FROM audit WHERE event IN "
                           "('email_change_requested', 'email_change_taken')")["n"]
    return {"sicht": number, "zeilen": lines, "post": [m[0] for m in p1 + p2 + p3], "w": w3, "sichtbar": _view}


_free, _cmp = _worker_execution(False), _worker_execution(True)
_res = _worker_execution(False, admin_identifiers=["ziel@example.com"])     # reserviert (Allowlist)
r.check("a1-02: account page after four sign-ins across two workers and a restart the same "
        "whether the address is free, taken or reserved (exactly one request each)",
        _free["sicht"] == _cmp["sicht"] == _res["sicht"] == [1, 1, 1, 1, 1],
        f"frei {_free['sicht']} vergeben {_cmp['sicht']} reserviert {_res['sicht']}")
r.check("… in the operator's audit log one row each, the link only to the free address",
        _free["zeilen"] == _cmp["zeilen"] == 1 and _free["post"] == ["ziel@example.com"]
        and _cmp["post"] == _res["post"] == []
        and _res["w"].store._one("SELECT COUNT(*) AS n FROM audit WHERE event='email_change_reserved'")["n"] == 1,
        f"{_free['zeilen']}/{_cmp['zeilen']} {_free['post']} {_cmp['post']} {_res['post']}")
r.check("… the row carries `account=<id> source=ldap` first, built the same for every outcome",
        all(re.fullmatch(r"account=\d+ source=ldap new=ziel@example\.com", z["detail"] or "")
            for execution in (_free, _cmp, _res) for z in execution["w"].store._all(
                "SELECT detail FROM audit WHERE event LIKE 'email_change_%'")))
for execution in (_free, _cmp):
    _alternate_everything(execution["w"], 86401)
    execution["sichtbar"](execution["w"])
r.check("… the next day exactly one further request for both",
        _free["sicht"][-1] == _cmp["sicht"][-1] == 2, f"{_free['sicht']} {_cmp['sicht']}")

# If the link lives longer than a day, the rejection holds off exactly as long as an open link.
_free7, _cmp7 = _worker_execution(False, email_change_ttl_min=3 * 24 * 60), _worker_execution(True, email_change_ttl_min=3 * 24 * 60)
for execution in (_free7, _cmp7):
    _alternate_everything(execution["w"], 86401)
    execution["sichtbar"](execution["w"])
r.check("… with email_change_ttl_min = 3 days: also the next day no further request for either",
        _free7["sicht"] == _cmp7["sicht"] == [1, 1, 1, 1, 1, 1], f"{_free7['sicht']} {_cmp7['sicht']}")
for execution in (_free7, _cmp7):
    _alternate_everything(execution["w"], 2 * 86400)
    execution["sichtbar"](execution["w"])
r.check("… after the link expires exactly one further for both",
        _free7["sicht"][-1] == _cmp7["sicht"][-1] == 2, f"{_free7['sicht']} {_cmp7['sicht']}")

# ── Review round 2026-09-27 (p2 F2): the in-flight window of the outbox ─────────────────────────────
# The row `federation_email_confirm` arises only after delivery, the rejection of a taken
# address immediately. `open_token` asked only for a link to the SAME address. If the link to
# ziel@ is still in worker 1's outbox (slow relay), the user sets their `mail` to probe@
# and signs in via worker 2: that sent a link to probe@ if ziel@ was free, and
# none if it was taken — plus two links on the same day. Now every open link holds it off.
import threading  # noqa: E402


def _flight_window(grant):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    w1, _, post1 = _setup(db_path=db)
    w2, _, post2 = _setup(db_path=db)
    brake = threading.Event()

    def _slow(to, subject, text, html=None):
        brake.wait(10)                               # the link from worker 1 hangs in the outbox
        post1.append((to, subject, text))
    w1.set_mailer(_slow)
    if grant:
        w1.create_user("opfer", email="ziel@example.com")
    dirname = Directory({"mallory": {"pw": "pw", "email": "ziel@example.com", "id": "uuid-mallory"}})
    w1.ldap = w2.ldap = dirname
    try:
        u = w1._check_ldap("mallory", "pw")
        dirname.entries["mallory"]["email"] = "probe@example.com"     # changed their own `mail`
        w2._check_ldap("mallory", "pw")
        w2._notice_outcome.wait()
    finally:
        brake.set()
    w1._notice_outcome.wait()
    return {"post1": [m[0] for m in post1], "post2": [m[0] for m in post2],
            "sicht": sorted(e["event"] for e in w2.own_events(u["id"], limit=50)
                            if e["event"] and e["event"].startswith("email_change"))}


_ff_free, _ff_cmp = _flight_window(False), _flight_window(True)
# (Mutation probe: in `_address_proven_by_source` again `open_token(…, adresse)` → free: post
#  to probe@ at worker 2, two requests → red.)
r.check("p2 F2: link to ziel@ hangs in worker 1's outbox, `mail` changed, worker 2 sends "
        "none to probe@ — whether ziel@ is free or taken",
        _ff_free["post2"] == [] and _ff_cmp["post2"] == []
        and _ff_free["post1"] == ["ziel@example.com"] and _ff_cmp["post1"] == [],
        f"frei {_ff_free} vergeben {_ff_cmp}")
r.check("… and the account page shows the same one request in both cases",
        _ff_free["sicht"] == _ff_cmp["sicht"] == ["email_change_requested"],
        f"frei {_ff_free['sicht']} vergeben {_ff_cmp['sicht']}")

# ── Review round 2026-09-27: a full queue discards the token ─────────────────────────────────
# If the notice outbox returns the job (queue full), the link never goes out.
# Its token stayed open and held off every new link via `open_token` until expiry.
g_q, _, p_q = _setup()
g_q._notice_outcome.max_unclosed = 0
u_q = _sign_in(g_q, "quentin", {"email": "quentin@example.com", "id": "uuid-quentin"})
_unclosed_q = g_q.store.open_token(u_q["id"], "email_change")
g_q._notice_outcome.max_unclosed = 50
_elapse(g_q, int(g_q._sec("mail_per_address_window_sec")) + 1)
_sign_in(g_q, "quentin", {"email": "quentin@example.com", "id": "uuid-quentin"})
# (Mutation probe: leaving out `senden.verwerfen()` after the overflow → open token, no second
#  link → red.)
r.check("Queue full: no link, no open token — after the throttle window the link comes",
        not _unclosed_q and [m[0] for m in p_q] == ["quentin@example.com"] and _link(p_q),
        f"offen {_unclosed_q}, {p_q}")

# ── Quota: change requests to an address do not lock out its later owner ─────
# Every request reaches the throttle, also the one to a taken address (G12b). Delicate is the
# still FREE one: a stranger requests the change to it until its quota is used up;
# if the owner registers right afterwards, their sign-in link would no longer arrive in the same bucket.
a9, _, p9 = _setup()
perpetrator = a9.create_user("taeter", email="taeter@example.com")
for _ in range(int(a9._sec("mail_per_address_max")) + 2):
    a9.request_email_change(perpetrator, "spaeter@example.com", BASE)
a9.create_user("spaet", email="spaeter@example.com")
p9.clear()
a9.send_login_link("spaeter@example.com", BASE)
r.check("Change requests by others to the address do not consume the quota of the sign-in link",
        [m[0] for m in p9] == ["spaeter@example.com"]
        and a9.store._one("SELECT 1 FROM audit WHERE event='mail_ratelimit' AND detail LIKE 'login%'") is None,
        str(p9))
# (Mutation probes: `_proof_true` always true → "FALSE" red; `open_token` removed → "as long as the
#  link is open" red; the daily limit removed → "same day" red; the bolt for proven accounts
#  removed → "proven own address" red; `federation_email_confirm` ignored → red; the bucket
#  `wechsel` back to `mail` → quota red; default `ldap_email_trusted=True` → default red.
#  G12a: quota again before the attempt for one day → (a)/(b) red; audit row
#  before delivery → (b) red; check in the database removed → (c) and "same day" red; quota
#  not per account → "another account" red. a1-02: rejection not counted in the database → (d) and
#  "account page the same" red; `account=` not in the detail → likewise; expiry only one day → "3 days" red.)

sys.exit(r.done())
