"""Self-service: change username and e-mail address (PO decision 2026-09-25).

Everyone changes both themselves, with a fresh step-up; the address only applies after the click on the link
to the NEW one. Everything hangs on the account ID — outwardly `Remote-Id` carries it, stable across every
change. The effect is measured through the routes, plus the bolts: foreign or allowlist names,
addresses as names, no oracle for taken addresses, collision on confirmation, old links.
Since G12b (2026-09-26) "no oracle" means more than the same response: the same notice to the
own address, the same quota, the same account page and the same work of the database.
"""
from __future__ import annotations

import re
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Self-service — change username and address")
PW = "Selbst-Test-Pw15"
HTML = {"accept": "text/html"}


def _setup(**cfg):
    mails: list = []
    reason = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False, base_url="http://testserver", lang="de",
                 admin_identifiers=["chef-reserviert", "Boss@Example.com"], password_reset_enabled=True)
    reason.update(cfg)
    auth = TinySesam(TinySesamConfig(**reason))
    auth.set_mailer(lambda to, subject, text, html=None: mails.append((to, subject, text)))
    app = FastAPI()
    app.include_router(auth.router())
    events: list = []
    auth.on_security_event = lambda e, account, d: events.append((e, d))
    return auth, app, mails, events


def _login(app, name):
    c = TestClient(app)
    c.post("/auth/login", data={"username": name, "password": PW}, follow_redirects=False)
    return c


def _alternate(auth):
    auth.store._exec("UPDATE session SET mfa_at=?", (int(time.time()) - 100000,))


# ── Benutzername ─────────────────────────────────────────────────────────────────────────
auth, app, mails, ev = _setup()
uid = auth.create_user("anna", password=PW, email="anna@example.com")
auth.create_user("bert", password=PW, email="bert@example.com")
c = _login(app, "anna")
page_html = c.get("/auth/account", headers=HTML).text
r.check("account page offers username and address", "data-act=setname" in page_html and "data-act=setmail" in page_html)
id_before = auth._forward_response_headers(auth.get_user(uid))["Remote-Id"]
a = c.post("/auth/account/username", json={"username": "anna.neu"})
r.check("username changed (freshly signed in)", a.status_code == 200 and auth.get_user(uid)["username"] == "anna.neu",
        f"{a.status_code} {a.text[:120]}")
head = auth._forward_response_headers(auth.get_user(uid))
r.check("… Remote-Id stays the account ID, Remote-User follows the new name",
        head["Remote-Id"] == id_before == str(uid) and head["Remote-User"] == "anna.neu")
r.check("… the session stays (it hangs on the ID)", c.get("/auth/me").status_code == 200)
r.check("… security event and audit row",
        ("username_changed", {"old": "anna", "new": "anna.neu"}) in ev
        and auth.store._one("SELECT 1 FROM audit WHERE event='username_changed'") is not None, str(ev))
r.check("… signing in with the new name works, with the old one not",
        _login(app, "anna.neu").get("/auth/me").status_code == 200
        and _login(app, "anna").get("/auth/me").status_code == 401)
fail = {n: c.post("/auth/account/username", json={"username": n}).status_code
        for n in ("bert", "bert@example.com", "fremd@example.com", "chef-reserviert", "CHEF-reserviert",
                  "zwei\x01", "", "x" * 151)}
r.check("taken, foreign address, allowlist name, control characters, empty, too long → 400",
        set(fail.values()) == {400} and auth.get_user(uid)["username"] == "anna.neu", str(fail))
r.check("… the own CONFIRMED address works as a name",
        c.post("/auth/account/username", json={"username": "anna@example.com"}).status_code == 200)
_alternate(auth)
old_ = c.post("/auth/account/username", json={"username": "anna3"})
r.check("without fresh step-up → 403 with reauth hint", old_.status_code == 403
        and old_.headers.get("x-tinysesam-reauth"), f"{old_.status_code} {dict(old_.headers)}")
key = auth.create_api_key(uid, name="skript", kind="human")["key"]
with_key = TestClient(app).post("/auth/account/username", json={"username": "per-key"},
                               headers={"Authorization": f"Bearer {key}"})
r.check("an API key changes no name", with_key.status_code in (401, 403), str(with_key.status_code))

auth_e, app_e, _, _ = _setup(login_identifier="email", signup_require_email=True)
auth_e.create_user("emil@example.com", password=PW, email="emil@example.com")
ce = _login(app_e, "emil@example.com")
r.check("mail mode: no separate name change (the name follows the address), page does not offer it",
        ce.post("/auth/account/username", json={"username": "emil"}).status_code == 400
        and "data-act=setname" not in ce.get("/auth/account", headers=HTML).text)

# ── Address ──────────────────────────────────────────────────────────────────────────────
auth, app, mails, ev = _setup()
uid = auth.create_user("carla", password=PW, email="carla@example.com")
auth.create_user("dora", password=PW, email="dora@example.com")
c = _login(app, "carla")
reset_old = auth.create_magic_token("reset_password", user_id=uid, email="carla@example.com")
mails.clear()
a = c.post("/auth/account/email", json={"email": "Carla.Neu@Example.com"})
auth._notice_outcome.wait()
r.check("address change requested → link to the NEW address, the account does not change yet",
        a.status_code == 200 and a.json() == {"ok": True, "sent": True}
        and [m[0] for m in mails if "/auth/email/" in m[2]] == ["carla.neu@example.com"]
        and auth.get_user(uid)["email"] == "carla@example.com", f"{a.text} {mails}")
r.check("… the mail names the account being confirmed",
        any(m[0] == "carla.neu@example.com" and "„carla“" in m[2] for m in mails), str(mails))
_request = [m for m in mails if m[0] == "carla@example.com"]
r.check("… the request itself goes as a notice to the previous occupied address — without link",
        len(_request) == 1 and "carla.neu@example.com" in _request[0][2] and "://" not in _request[0][2],
        str(mails))
link = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1) if mails else ""
page_html = c.get(link, headers=HTML)
r.check("… the link shows a confirmation page (GET redeems nothing)",
        page_html.status_code == 200 and "<form" in page_html.text and auth.get_user(uid)["email"] == "carla@example.com")
mails.clear()
done = TestClient(app).post(link, follow_redirects=False)       # also from another browser
auth._notice_outcome.wait()
account = auth.get_user(uid)
r.check("… redeemed: new address WITH proof, back to the account page",
        done.status_code == 303 and done.headers["location"] == "/auth/account"
        and account["email"] == "carla.neu@example.com" and account["email_verified"], f"{done.status_code} {dict(account)}")
r.check("… the old address gets a notice — without link (nothing whose base would need checking)",
        [m[0] for m in mails] == ["carla@example.com"] and "://" not in mails[0][2], str(mails))
r.check("… open links to the old address no longer apply",
        auth.peek_magic(reset_old, purpose="reset_password") is None)
r.check("… security event with old/new",
        ("email_changed", {"old": "carla@example.com", "new": "carla.neu@example.com"}) in ev, str(ev))
r.check("… the same link a second time: invalid", TestClient(app).post(link).status_code == 400)

# Taken/reserved: no link — but the notice to the own address as with every request
# (G12b; until 2026-09-26 it was left out, and exactly that revealed "taken").
_NOTICE = ("carla.neu@example.com", "Änderung deiner E-Mail-Adresse beantragt")
mails.clear()
grant = c.post("/auth/account/email", json={"email": "dora@example.com"})
auth._notice_outcome.wait()
r.check("a taken address: same response, no link, only the notice to the own one, row in the audit log",
        grant.status_code == 200 and grant.json() == {"ok": True, "sent": True}
        and [m[:2] for m in mails] == [_NOTICE]
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None, str(mails))
r.check("invalid address → 400", c.post("/auth/account/email", json={"email": "kaputt"}).status_code == 400)
# Allowlist address: if its owner clicked the link (on an instance without admin), the foreign
# account would carry the occupied address and be first admin at the next login.
mails.clear()
reserved = c.post("/auth/account/email", json={"email": "boss@EXAMPLE.com"})
auth._notice_outcome.wait()
r.check("an address from admin_identifiers: same response, no link, only the notice, row in the audit log",
        reserved.status_code == 200 and reserved.json() == {"ok": True, "sent": True}
        and [m[:2] for m in mails] == [_NOTICE]
        and auth.store._one("SELECT 1 FROM audit WHERE event='email_change_reserved'") is not None, str(mails))
# Both requests used up the account's quota like a free one (G12b) — a fresh window
# for the following cases.
auth.rl = type(auth.rl)()
mails.clear()
c.post("/auth/account/email", json={"email": "spaeter.boss@example.com"})
link3 = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1)
auth.cfg.admin_identifiers.append("spaeter.boss@example.com")
r.check("… if it only enters the list after the request: 409 on redeeming, nothing changed",
        TestClient(app).post(link3).status_code == 409 and auth.get_user(uid)["email"] == "carla.neu@example.com")
# Collision on confirm: between request and click another account takes the address.
mails.clear()
c.post("/auth/account/email", json={"email": "frei@example.com"})
link2 = re.search(r"http://testserver(/auth/email/[^\s]+)", mails[0][2]).group(1)
auth.create_user("frieda", password=PW, email="frei@example.com")
r.check("… if the address is taken by the click: 409, nothing changed",
        TestClient(app).post(link2).status_code == 409 and auth.get_user(uid)["email"] == "carla.neu@example.com")
_carla = [e["event"] for e in auth.own_events(uid, limit=100)]
r.check("account page: every request is called email_change_requested (5), only the rejection ON confirm "
        "keeps its name (the 409 said it anyway)",
        _carla.count("email_change_requested") == 5 and _carla.count("email_change_taken") == 1
        and _carla.count("email_change_reserved") == 1, str(_carla))
_alternate(auth)
r.check("without fresh step-up → 403", c.post("/auth/account/email", json={"email": "x@example.com"}).status_code == 403)

# ── An open change does not survive a defence (attack round, finding 1) ───────────────────
# An intruder with a fresh session requests the change to HIS address; the link is in
# his mailbox. The owner resets the password, changes it or ends sessions — the
# link must lapse with that, otherwise the intruder clicks afterwards, and the next reset goes to him.
def _defense_setup():
    a, ap, post, _ = _setup()
    a.create_user("chefin", password=PW, email="chefin@example.com")
    a.store.set_admin(a.store.get_user_by_name("chefin")["id"], True)
    u = a.create_user("opfer", password=PW, email="opfer@example.com")
    return a, ap, post, u


def _intruder_requested(a, ap, post):
    post.clear()
    _login(ap, "opfer").post("/auth/account/email", json={"email": "dieb@example.org"})
    a._notice_outcome.wait()
    return re.search(r"http://testserver(/auth/email/[^\s]+)",
                     next(m[2] for m in post if m[0] == "dieb@example.org")).group(1)


def _reset(a, ap, u):
    raw = a.create_magic_token("reset_password", user_id=u, email="opfer@example.com")
    TestClient(ap).post("/auth/reset", data={"token": raw, "password": "Ganz-Neues-Pw15"})


def _pw_change(a, ap, u):
    _login(ap, "opfer").post("/auth/password", json={"current": PW, "new": "Ganz-Neues-Pw15"})


def _end_all(a, ap, u):
    _login(ap, "opfer").post("/auth/sessions/revoke", json={"scope": "all"})


def _end_other(a, ap, u):
    _login(ap, "opfer").post("/auth/sessions/revoke", json={"scope": "others"})


def _admin_reset(a, ap, u):
    _login(ap, "chefin").post(f"/auth/admin/api/users/{u}/password", json={"password": "Admin-Setzt-Pw15"})


for title, defense in (("Passwort-Reset", _reset), ("Passwortwechsel auf der Konto-Seite", _pw_change),
                      ("alle Sitzungen beenden", _end_all), ("andere Sitzungen beenden", _end_other),
                      ("Passwort-Reset durch den Admin", _admin_reset)):
    a_, ap_, post_, u_ = _defense_setup()
    link_ = _intruder_requested(a_, ap_, post_)
    defense(a_, ap_, u_)
    later = TestClient(ap_).post(link_, follow_redirects=False)
    r.check(f"{title}: the intruder's open change link no longer applies afterwards",
            later.status_code == 400 and a_.get_user(u_)["email"] == "opfer@example.com",
            f"{later.status_code} {a_.get_user(u_)['email']}")

# Scattering: an account does not send change mails to arbitrarily many foreign addresses (finding 3).
a_s, ap_s, post_s, _ = _setup()
a_s.create_user("streuer", password=PW, email="streuer@example.com")
c_s = _login(ap_s, "streuer")
for i in range(12):
    c_s.post("/auth/account/email", json={"email": f"ziel{i}@example.org"})
a_s._notice_outcome.wait()
_destinations = {m[0] for m in post_s if "/auth/email/" in m[2]}
r.check("an account reaches with change links at most as many addresses as the quota allows",
        0 < len(_destinations) <= int(a_s._sec("mail_per_address_max"))
        and a_s.store._one("SELECT 1 FROM audit WHERE event='mail_ratelimit' AND detail LIKE 'email_change account=%'")
        is not None, f"{len(_destinations)} addresses")

# Checked folded (finding 3 LDAP/SAML round): `＠` (U+FF20) would fold to two `@`.
r.check("an address that is only invalid when folded → 400",
        _login(ap_s, "streuer").post("/auth/account/email",
                                     json={"email": "x\uff20evil.example@example.com"}).status_code == 400)

# ── G12b: no oracle for taken addresses ─────────────────────────────────────────────────────
# Measured until 2026-09-26, with an identical response: the notice to the own address only for
# a free one, the account's quota used up only by free ones, the account page named
# `email_change_taken`, and the database wrote one row less for a taken one. One
# fresh setup per target — same starting point, only the target differs.
DESTINATIONS = (("vergeben", "bert@example.com"), ("reserviert", "boss@example.com"), ("frei", "neu@example.com"))


def _g12b_setup():
    a, ap, post, _ = _setup()
    account = a.create_user("anna", password=PW, email="anna@example.com")
    a.create_user("bert", password=PW, email="bert@example.com")
    return a, ap, post, account


def _form(sql):
    """A statement without its values: which table, which columns, which condition."""
    return re.sub(r"\b\d+\b", "?", re.sub(r"'(?:[^']|'')*'", "?", sql)).strip()


_g = {}
for kind, destination in DESTINATIONS:
    a, ap, post, account = _g12b_setup()
    c_g = _login(ap, "anna")
    post.clear()
    reply = c_g.post("/auth/account/email", json={"email": destination})
    a._notice_outcome.wait()
    _g[kind] = {"auth": a, "antwort": (reply.status_code, reply.text),
               "eigene": [m[1] for m in post if m[0] == "anna@example.com"],
               "ziel": [m[1] for m in post if m[0] == destination],
               "ereignisse": [e["event"] for e in a.own_events(account, limit=50)],
               "seite": re.findall(r"email_change_\w+|federation_email_confirm",
                                   c_g.get("/auth/account", headers=HTML).text)}
r.check("G12b: same response for taken, reserved and free",
        len({str(g["antwort"]) for g in _g.values()}) == 1, str({k: g["antwort"] for k, g in _g.items()}))
r.check("G12b: to the own address exactly one notice in all three cases",
        all(g["eigene"] == ["Änderung deiner E-Mail-Adresse beantragt"] for g in _g.values()),
        str({k: g["eigene"] for k, g in _g.items()}))
r.check("… to the taken and the reserved one nothing, to the free one the link",
        _g["vergeben"]["ziel"] == [] and _g["reserviert"]["ziel"] == []
        and _g["frei"]["ziel"] == ["Neue E-Mail-Adresse bestätigen"], str({k: g["ziel"] for k, g in _g.items()}))
r.check("G12b: account page (own_events) the same in all three cases, the request as email_change_requested",
        _g["vergeben"]["ereignisse"] == _g["reserviert"]["ereignisse"] == _g["frei"]["ereignisse"]
        and "email_change_requested" in _g["frei"]["ereignisse"], str({k: g["ereignisse"] for k, g in _g.items()}))
r.check("… likewise the rendered account page",
        all(g["seite"] == ["email_change_requested"] for g in _g.values()), str({k: g["seite"] for k, g in _g.items()}))
r.check("… the operator's audit log keeps the real names",
        _g["vergeben"]["auth"].store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None
        and _g["reserviert"]["auth"].store._one("SELECT 1 FROM audit WHERE event='email_change_reserved'") is not None)

# Quota: three requests for a taken address use it up like three for free ones — afterwards
# no link goes even to an own control address any more. Before, exactly that revealed "taken".
_control = {}
for kind, destinations in (("vergeben", ["bert@example.com"] * 3),
                   ("frei", ["x1@example.com", "x2@example.com", "x3@example.com"])):
    a, ap, post, _k = _g12b_setup()
    c_k = _login(ap, "anna")
    for z in destinations:
        c_k.post("/auth/account/email", json={"email": z})
    a._notice_outcome.wait()
    post.clear()
    c_k.post("/auth/account/email", json={"email": "kontrolle@example.com"})
    a._notice_outcome.wait()
    _control[kind] = [m[0] for m in post if m[0] == "kontrolle@example.com"]
r.check("G12b: after 3× taken as after 3× free no link to the control address",
        _control == {"vergeben": [], "frei": []}, str(_control))

# Work of the database, without a stopwatch: the same sequence of statements (without their values), the same
# number of rows written — token and audit row in every case.
_trace = {}
for kind, destination in DESTINATIONS:
    a, _ap, post, account = _g12b_setup()
    commands: list = []
    a.store._clock_secured = time.monotonic()      # do not save the clock state in the middle of it
    before = a.store.db.total_changes
    a.store.db.set_trace_callback(commands.append)
    try:
        send = a.request_email_change(account, destination, "http://testserver")
    finally:
        a.store.db.set_trace_callback(None)
    written = a.store.db.total_changes - before
    _trace[kind] = {"folge": [_form(b) for b in commands], "zeilen": written,
                  "gesendet": send() if send else None, "auth": a, "konto": account}
r.check("G12b: the same sequence of statements for taken, reserved and free",
        _trace["vergeben"]["folge"] == _trace["reserviert"]["folge"] == _trace["frei"]["folge"]
        and any(f.startswith("INSERT INTO magic_token") for f in _trace["frei"]["folge"]),
        "\n".join(f"{k}: {v['folge']}" for k, v in _trace.items()))
r.check("… the same number of rows written (token + audit = 2)",
        [v["zeilen"] for v in _trace.values()] == [2, 2, 2], str([v["zeilen"] for v in _trace.values()]))
r.check("… always one sender; it says whether a link went out (False, False, True)",
        [v["gesendet"] for v in _trace.values()] == [False, False, True],
        str([v["gesendet"] for v in _trace.values()]))

# If sending the link fails, the notice to the own address still goes out — otherwise a mail server
# rejecting the free address would again reveal the difference. The error stays visible.
a_f, _ap_f, post_f, account_f = _g12b_setup()


def _link_broken(to, subject, text, html=None):
    if to == "neu@example.com":
        raise OSError("Mailserver weist ab")
    post_f.append((to, subject))


a_f.set_mailer(_link_broken)
send_f = a_f.request_email_change(account_f, "neu@example.com", "http://testserver")
try:
    send_f()
    _thrown = False
except OSError:
    _thrown = True
r.check("G12b: if the link fails, the notice to the own address still goes out (the error stays)",
        _thrown and post_f == [("anna@example.com", "Änderung deiner E-Mail-Adresse beantragt")],
        f"{_thrown} {post_f}")

# The throwaway token is harmless: expired from the start, no open link, `gc()` clears it.
_st = _trace["vergeben"]["auth"].store
_now_s = int(time.time())
r.check("G12b: the token for “taken” is already expired at creation, no open link",
        _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com'")["n"] == 1
        and _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com' AND expires_at >= ?",
                     (_now_s,))["n"] == 0
        and not _st.open_token(_trace["vergeben"]["konto"], "email_change", "bert@example.com"))
_trace["vergeben"]["auth"].gc()
r.check("… and gc() clears it away",
        _st._one("SELECT COUNT(*) AS n FROM magic_token WHERE email='bert@example.com'")["n"] == 0)
_sf = _trace["frei"]["auth"].store
r.check("… while the link to the free address applies",
        _sf.open_token(_trace["frei"]["konto"], "email_change", "neu@example.com"))

# Review round 2026-09-27: if the outbox is full, the link never goes out — its token expires
# immediately. Since p2 F2 every open link of the account blocks the way via LDAP/SAML; one never
# delivered would do so until its expiry.
a_v, ap_v, post_v, _ = _setup()
uid_v = a_v.create_user("voll", password=PW, email="voll@example.com")
a_v._outbox.max_unclosed = 0
_reply_v = _login(ap_v, "voll").post("/auth/account/email", json={"email": "voll.neu@example.com"})
# (Mutation probe: leave out `on_overflow=send.discard` in the route → open token → red.)
r.check("outbox full: same response, no link, and no open token remains",
        _reply_v.status_code == 200 and not [m for m in post_v if "/auth/email/" in m[2]]
        and a_v.store._one("SELECT COUNT(*) AS n FROM magic_token WHERE purpose='email_change'")["n"] == 1
        and not a_v.store.open_token(uid_v, "email_change"), f"{_reply_v.status_code} {post_v}")

# Without base_url and with a foreign host: the response says "no mail sending", not the internals of the
# base check (CodeQL py/unreachable-except: `ConfigError` is a `ValueError`).
a_b, ap_b, post_b, _ = _setup(base_url="", password_reset_enabled=False)
a_b.create_user("ohnebasis", password=PW, email="ohnebasis@example.com")
_without = _login(ap_b, "ohnebasis").post("/auth/account/email", json={"email": "neu@example.com"},
                                       headers={"host": "evil.example"})
r.check("without base_url, foreign host: 400 with the message “no mail sending”, no link",
        _without.status_code == 400 and _without.json().get("detail") == a_b.t("api.no_mail") and not post_b,
        f"{_without.status_code} {_without.text[:160]}")

# Mail mode: the username moves along.
auth_e, app_e, mails_e, _ = _setup(login_identifier="email", signup_require_email=True)
uid_e = auth_e.create_user("emil@example.com", password=PW, email="emil@example.com")
ce = _login(app_e, "emil@example.com")
ce.post("/auth/account/email", json={"email": "emil.neu@example.com"})
link_e = re.search(r"http://testserver(/auth/email/[^\s]+)", next(m[2] for m in mails_e if "/auth/email/" in m[2])).group(1)
TestClient(app_e).post(link_e)
r.check("mail mode: after confirmation the username is the new address",
        auth_e.get_user(uid_e)["username"] == "emil.neu@example.com")

# Without mail sending the path does not exist (the page does not offer it, the route says 400).
auth_o, app_o, _, _ = _setup()
auth_o.set_mailer(None)
auth_o.create_user("otto", password=PW, email="otto@example.com")
co = _login(app_o, "otto")
r.check("without mailer: no address change",
        "data-act=setmail" not in co.get("/auth/account", headers=HTML).text
        and co.post("/auth/account/email", json={"email": "o2@example.com"}).status_code == 400)
# (Mutation probes: the step-up in `_fresh_for_identifier` removed → “without fresh step-up” red; the
#  allowlist check removed → allowlist name red; the @ rule removed → “foreign address” red; the
#  identifier comparison on confirm removed → 409 red; `revoke_user_magic_tokens` removed → “open links”
#  red; `verified=True` removed → “WITH proof” red; `Remote-Id` removed → Remote-Id red.
#  G12b: notice only without “no” → notice red; throttle of the account only for free ones →
#  quota red; mapping in `own_events` removed → account page red; throwaway token removed → sequence red;
#  token with a real deadline → “already expired” red.)

sys.exit(r.done())
