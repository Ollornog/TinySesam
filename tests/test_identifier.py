"""Login identifier: username, email or both — plus email requirement/uniqueness/confirmation."""
import os
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from tinysesam import TinySesam, TinySesamConfig
from tinysesam.store import norm_email, valid_email


def build(**over):
    db = os.path.join(tempfile.mkdtemp(), "t.db")
    cfg = TinySesamConfig(db_path=db, csrf_enabled=False, lang="de", cookie_secure=False,
                          passkey_enabled=False, **over)
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    return auth, TestClient(app), db


def login(c, ident, pw="geheim12345-lang-genug"):
    return c.post("/auth/login", data={"username": ident, "password": pw, "next": "/"},
                  follow_redirects=False)


# ---------- Normalization + validation ----------
assert norm_email("  Max@Example.COM ") == "max@example.com"
assert norm_email("") is None and norm_email(None) is None
assert valid_email("a@b.de") and valid_email("a.b+c@sub.example.co.uk")
assert not valid_email("ab.de") and not valid_email("a@b") and not valid_email("a b@c.de")
assert not valid_email("a@@b.de") and not valid_email("@b.de") and not valid_email("a@.de")
print("  norm_email/valid_email ok")

# ---------- R4-06: compatibility characters, IDNA, look-alikes ----------
assert norm_email("ａｄｍｉｎ@ｅｘａｍｐｌｅ.com") == "admin@example.com", "NFKC folds full-width"
assert norm_email("u@Bücher.example") == norm_email("u@xn--bcher-kva.example") == "u@xn--bcher-kva.example"
# IDNA 2003 (stdlib) turned straße.example into strasse.example — a different domain. Stays unchanged.
assert norm_email("u@straße.example") == "u@straße.example"
assert not valid_email("аdmin@example.com"), "Cyrillic а between Latin letters"
assert not valid_email("admin@exаmple.com"), "look-alike in the domain"
assert not valid_email("ad​min@example.com") and not valid_email("ad‍min@example.com"), "invisible"
assert valid_email("müller@example.com") and valid_email("иван@example.com"), "a single script stays allowed"
# Attack A6: scripts that belong together in one language may mix — Japanese writes
# kanji with hiragana/katakana. Latin stays out of every group.
assert valid_email("山田たろう@example.jp") and valid_email("user@例え.テスト"), "Japanese mixes kanji and kana"
assert valid_email("ラーメン@example.jp") and valid_email("홍길동漢@example.kr"), "kana long vowel mark, Hangul+Hanja"
assert not valid_email("山田a@example.jp") and not valid_email("たаро@example.jp"), "Latin/Cyrillic does not mix in"
auth, c, db = build(login_identifier="email", allow_signup=True)
auth.create_user("admin@example.com", password="geheim12345-lang-genug", email="admin@example.com")
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "ａｄｍｉｎ@example.com", "next": "/"})
assert r.status_code == 409, "full-width doppelganger is the same identifier"
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "аdmin@example.com", "next": "/"})
assert r.status_code == 400, "look-alike is rejected"
assert auth.store._exec("SELECT COUNT(*) FROM users").fetchone()[0] == 1
# Existing accounts from BEFORE R4-06: an umlaut domain in Unicode form is still found
auth.store._exec("INSERT INTO users(username, email, created_at) VALUES ('alt', 'alt@bücher.example', 0)")
assert auth.store.get_user_by_email("Alt@Bücher.example")["username"] == "alt"
os.unlink(db)
print("  R4-06: NFKC, IDNA A-label, look-alikes rejected, existing accounts still findable ok")

# ---------- Mode "both": login with either ----------
auth, c, db = build(login_identifier="both")
auth.create_user("max", password="geheim12345-lang-genug", email="Max@Example.com")
assert login(c, "max").status_code == 303, "username login"
assert login(c, "max@example.com").status_code == 303, "email login"
assert login(c, "MAX@EXAMPLE.COM").status_code == 303, "email case-insensitive"
assert login(c, "max", "falsch").status_code != 303
assert login(c, "gibtsnicht@example.com").status_code != 303
c.cookies.clear()          # otherwise /auth/login redirects a signed-in user to /
assert "Benutzer oder E-Mail" in c.get("/auth/login").text
print("  both: username + email + case-insensitive ok")
os.unlink(db)

# ---------- Mode "username": email must NOT work ----------
auth, c, db = build(login_identifier="username")
auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
assert login(c, "max").status_code == 303
assert login(c, "max@example.com").status_code != 303, "email must not apply in username mode"
c.cookies.clear()
page = c.get("/auth/login").text
assert "Benutzer</label>" in page and "Benutzer oder E-Mail" not in page
os.unlink(db)

# ---------- Mode "email": username must NOT work ----------
auth, c, db = build(login_identifier="email")
auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
assert login(c, "max@example.com").status_code == 303
assert login(c, "max").status_code != 303, "username must not apply in email mode"
c.cookies.clear()
assert "E-Mail</label>" in c.get("/auth/login").text
os.unlink(db)
print("  username-/email-only: only the permitted identifier each ok")

# ---------- PIN uses the same identifier ----------
auth, c, db = build(login_identifier="both", pin_enabled=True)
uid = auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
auth.set_pin(uid, "2468")
r = c.post("/auth/pin", data={"username": "max@example.com", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, "PIN login by email"
os.unlink(db)
print("  PIN accepts the same identifier ok")

# ---------- Email unique ----------
auth, c, db = build()
auth.create_user("a", password="geheim12345-lang-genug", email="dup@example.com")
try:
    auth.create_user("b", password="geheim12345-lang-genug", email="DUP@example.com")
    raise AssertionError("duplicate was accepted")
except ValueError:
    pass
assert auth.store.email_taken("dup@example.com")
assert not auth.store.email_taken("dup@example.com", exclude_id=auth.store.get_user_by_name("a")["id"])
os.unlink(db)
print("  email uniqueness (case-insensitive) ok")

# ---------- Registration: email required (default) ----------
auth, c, db = build(allow_signup=True)
assert auth.cfg.signup_require_email is True, "default = required"
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug", "next": "/"})
assert r.status_code == 400 and "E-Mail nötig" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug", "email": "keine-mail", "next": "/"})
assert r.status_code == 400 and "gültige E-Mail" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug",
                                   "email": "Neu@Example.com", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.text[:300]
assert auth.store.get_user_by_name("neu")["email"] == "neu@example.com", "stored canonically"
r = c.post("/auth/register", data={"username": "neu2", "password": "geheim12345-lang-genug",
                                   "email": "NEU@example.com", "next": "/"})
assert r.status_code == 409 and "bereits registriert" in r.text
c.cookies.clear()
reg = c.get("/auth/register").text
email_tag = "<input name=email" + reg.split("<input name=email", 1)[1].split(">", 1)[0]
assert "required" in email_tag, "email field marked as required"
os.unlink(db)
print("  registration: required + format + duplicate ok")

# ---------- Registration follows login_identifier ----------
auth, c, db = build(allow_signup=True, login_identifier="email")
page = c.get("/auth/register").text
assert "name=username" not in page, "no username field in email mode"
assert "name=email" in page and "required" in page
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "Solo@Example.com", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303, r.text[:300]
u = auth.store.get_user_by_email("solo@example.com")
assert u["username"] == "solo@example.com", "the email is the identifier"
c.cookies.clear()
assert login(c, "solo@example.com").status_code == 303
os.unlink(db)

auth, c, db = build(allow_signup=True, login_identifier="username", signup_require_email=False)
page = c.get("/auth/register").text
assert "name=username" in page
if "<input name=email" in page:
    email_tag = "<input name=email" + page.split("<input name=email", 1)[1].split(">", 1)[0]
    assert "required" not in email_tag, "email must not be required here"
os.unlink(db)
print("  registration follows login_identifier ok")

# ---------- Registration: email can be switched off as optional ----------
auth, c, db = build(allow_signup=True, signup_require_email=False)
r = c.post("/auth/register", data={"username": "ohne", "password": "geheim12345-lang-genug", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user_by_name("ohne")["email"] is None
os.unlink(db)
print("  signup_require_email=False: account without email ok")

# ---------- Email confirmation (optional) ----------
sent = []
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
auth.set_mailer(lambda to, subject, text, html=None: sent.append((to, text)))
r = c.post("/auth/register", data={"username": "verify", "password": "geheim12345-lang-genug",
                                   "email": "v@example.com", "next": "/"})
assert r.status_code == 200 and "Fast fertig" in r.text, r.text[:200]
u = auth.store.get_user_by_name("verify")
assert u["disabled"], "account locked until confirmation"
assert login(c, "v@example.com").status_code != 303, "locked account must not get in"
assert sent and sent[0][0] == "v@example.com"
link = re.search(r"https?://\S+/auth/verify/(\S+)", sent[0][1]).group(1).rstrip(".,)")
c.post(f"/auth/verify/{link}", follow_redirects=False)   # R4-02: redeemed via POST
assert not auth.store.get_user_by_name("verify")["disabled"], "unlocked after confirmation"
assert login(c, "v@example.com").status_code == 303
os.unlink(db)
print("  signup_verify_email: locked → link → unlocked → login ok")

# ---------- Confirmation on, but no mailer → hard error instead of a silent bypass ----------
# `base_url` is set here because since this version it is mandatory as soon as a mail route is on
# (otherwise the constructor already fails). What is checked is the situation afterwards: base yes, mailer no.
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
r = c.post("/auth/register", data={"username": "x", "password": "geheim12345-lang-genug",
                                   "email": "x@example.com", "next": "/"})
assert r.status_code == 500 and "kein Mailer" in r.text
assert auth.store.get_user_by_name("x") is None, "no half-finished account created"
os.unlink(db)
print("  verify without mailer: 500, no account ok")

# ---------- Config sanity ----------
for bad in ("mail", "", "Username"):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier=bad))
        raise AssertionError(f"login_identifier={bad!r} akzeptiert")
    except ValueError:
        pass
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier="email",
                              allow_signup=True, signup_require_email=False))
    raise AssertionError("email-only without mandatory email accepted")
except ValueError:
    pass
print("  config sanity ok")

# ---------- Cross collision: the ConfigError carries field and owner (R4-12) ----------
# Promised in the CHANGELOG under "For embedding apps": the message text stays the one from 0.18.x
# ("… ist bereits vergeben"), so that a caller who checks the text does not break on this fix
# — and the case can now be told apart WITHOUT text comparison by `e.field` and
# `e.owner_id` (until 0.21.x `e.feld`/`e.besitzer_id`). Both halves of the promise were covered by not a
# single line: mutation M25 (no longer setting the attributes) and M34 (wording back
# to "… ist bereits als Login-Kennung vergeben") each ran through green with 46/46.
# `grep -rn "besitzer_id" tests/` found nothing. Exactly the promise that was to replace the text comparison, and exactly the text comparison
# that it was to save.
from tinysesam import ConfigError  # noqa: E402

auth, c, db = build(login_identifier="both")
opfer_id = auth.create_user("opfer", password="geheim12345-lang-genug", email="chef@example.com")
for kennung, mail, feld in (("chef@example.com", None, "username"),   # name == foreign email
                            ("neu", "chef@example.com", "email")):    # email == foreign email
    try:
        auth.create_user(kennung, email=mail)
        raise AssertionError(f"{feld}: the cross check does not take effect, the account was created")
    except ConfigError as e:
        assert "is already taken" in str(e), (
            f"{feld}: wording changed ({str(e)!r}) — callers from 0.18.x check exactly this "
            "text, and the CHANGELOG promises them that it stays")
        assert getattr(e, "field", None) == feld, (
            f"e.field is {getattr(e, 'field', '<missing>')!r}, expected {feld!r} — without the attribute "
            "the text comparison remains the only way to tell the two cases apart")
        assert getattr(e, "owner_id", None) == opfer_id, (
            f"e.owner_id is {getattr(e, 'owner_id', '<missing>')!r}, expected {opfer_id}")
# Control: a free identifier does not raise — otherwise "always raises" would be green too.
frei_id = auth.create_user("frei", email="frei@example.com")
assert frei_id and auth.store.get_user(frei_id)["username"] == "frei"
os.unlink(db)
print("  cross collision: wording stays, e.field/e.owner_id name the case ok")

# ---------- The lockout bucket folds like find_user — also NFKC and IDNA ----------
# The account threshold against distributed guessing counts under `norm_kennung()`. That used to be strip + lower;
# but `find_user` looks an address up via `norm_email()`, and since R4-06 that also folds NFKC
# and IDNA. `ｖｉｃｔｉｍ@example.com`, `victim＠example.com` (full-width @) and every mixed form
# hit the same account, but each filled a bucket of its own — for this one address alone
# 2^16 spellings. Measured: 40 failed attempts from 40 addresses, none locked, the owner
# afterwards in with 303. (Mutation probe: `norm_kennung` back to `strip().lower()` → the
# bucket check and the volley turn red; only NFKC without `norm_email` → the IDNA line turns red.)
from tinysesam.store import norm_kennung  # noqa: E402

VOLL = {ch: chr(ord(ch) + 0xFEE0) for ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@."}


def _voll(text, maske):
    """The characters at the positions whose bit is set in `maske`, in full width."""
    return "".join(VOLL.get(z, z) if (maske >> i) & 1 else z for i, z in enumerate(text))


auth, c, db = build(login_identifier="both")
opfer_id = auth.create_user("opfer", "Richtiges-Passwort-42x", email="victim@example.com")
idn_id = auth.create_user("idn", "Idn-Passwort-2026x", email="u@bücher.example")
basis = "victim@example.com"
varianten = [_voll(basis, m) for m in (0b1, 0b111111, 0b1000000, 0b111111111111111111, 0b10101010101,
                                       (1 << 18) - 1 - 0b1000000)]
varianten += ["VICTIM＠EXAMPLE.COM", " ｖｉｃｔｉｍ@example.com\t", "\xa0victim@ｅｘａｍｐｌｅ.ｃｏｍ"]
for v in varianten:
    gefunden = auth.find_user(v)
    assert gefunden and gefunden["id"] == opfer_id, f"precondition: {v!r} does not hit the account"
    assert norm_kennung(v) == norm_kennung(basis), \
        f"{v!r} hits the account, but counts in bucket {norm_kennung(v)!r} instead of {norm_kennung(basis)!r}"
# IDNA: A-label and Unicode form of the same domain are the same mailbox, hence one bucket.
for v in ("u@bücher.example", "u@xn--bcher-kva.example", "U@BÜCHER.EXAMPLE", "u@ｂüｃｈｅｒ.example"):
    assert auth.find_user(v)["id"] == idn_id, f"precondition: {v!r} does not hit the IDN account"
    assert norm_kennung(v) == norm_kennung("u@bücher.example"), f"IDNA spelling {v!r} has its own bucket"
print(f"  lockout bucket: {len(varianten) + 4} spellings that find_user assigns to the same account count together ok")

# And via the route: distributed guessing with full-width spellings, every request from a
# different address. The check must not get past the account threshold.
auth.set_security("rate_limit_max", 1000)
app_k = FastAPI()
app_k.include_router(auth.router())
DECKEL = auth._sec("max_login_attempts") * auth._sec("account_attempt_factor")
geprueft = 0
for i in range(DECKEL + 25):
    ci = TestClient(app_k, client=(f"198.51.100.{i + 1}", 40000))
    r = ci.post("/auth/login", data={"username": _voll(basis, i + 1), "password": f"falsch-{i}"},
                follow_redirects=False)
    geprueft += r.status_code == 401
assert geprueft <= DECKEL, f"{geprueft} guesses via full-width spellings, promised are at most {DECKEL}"
r = TestClient(app_k, client=("192.0.2.200", 40000)).post(
    "/auth/login", data={"username": basis, "password": "Richtiges-Passwort-42x"}, follow_redirects=False)
assert r.status_code == 429, f"the account threshold did not take effect after {geprueft} attempts: {r.status_code}"
# Lifting hits the same bucket: counting was done under the folded address.
assert auth.lift_lockout(opfer_id) == geprueft
os.unlink(db)
print(f"  lockout bucket via the route: {geprueft} checked, then closed (account threshold {DECKEL}) ok")

# ---------- H-13 × lockout bucket: deleting clears the attempts under the folded identifier ----------
# Since the lockout bucket folds NFKC and IDNA (above), the attempts of an account are under
# `norm_kennung(...)`. But `delete_user` searched for them via SQLite `lower()` under the STORED
# name or the stored address. A name with compatibility characters (`ｂｅｒｔａ`, `ﬁnn` —
# `create_user` does not fold names, they come e.g. from LDAP or OIDC) and an existing address
# from before R4-06 in Unicode form (`u2@bücher.example`) left identifier and IP standing after deletion
# — against the H-13 promise "their attempt rows are deleted". (Mutation probe:
# `delete_attempts_for` again only with the raw form and `lower(username)=lower(?)` → red.)
auth, c, db = build(login_identifier="both")
berta_id = auth.create_user("ｂｅｒｔａ", "Berta-Passwort-2026x")
finn_id = auth.create_user("ﬁnn", "Finn-Passwort-2026x")
bestand_id = auth.create_user("bestand", "Bestand-Passwort-2026x", email="u2@example.org")
auth.store.db.execute("UPDATE users SET email='u2@bücher.example' WHERE id=?", (bestand_id,))
auth.store.db.commit()
assert auth.find_user("u2@bücher.example")["id"] == bestand_id, "precondition: existing address is found"
# Make the accounts a minute older: the deletion path (`Store.konto_entfernen`) clears only attempts
# AFTER the second of creation — what happened within it cannot be attributed and stays.
# Here it is about the folding, not about this boundary.
auth.store.db.execute("UPDATE users SET created_at = created_at - 60 WHERE id IN (?, ?, ?)",
                      (berta_id, finn_id, bestand_id))
auth.store.db.commit()
for i, kennung in enumerate(("ｂｅｒｔａ", "ﬁnn", "u2@bücher.example", "BESTAND")):
    for ip in ("198.51.100.1", "198.51.100.2"):
        r = login(TestClient(c.app, client=(ip, 40000 + i)), kennung, "falsch-geraten-1")
        assert r.status_code == 401, (kennung, r.status_code)


def _versuche(a):
    return [(z["username"], z["ip"]) for z in a.store._all("SELECT username, ip FROM login_attempt")]


assert len(_versuche(auth)) == 8, f"precondition: eight failed attempts stand: {_versuche(auth)}"
for uid in (berta_id, finn_id, bestand_id):
    assert auth.delete_user(uid)
assert _versuche(auth) == [], f"after delete_user attempts of deleted accounts still stand: {_versuche(auth)}"
os.unlink(db)
print("  H-13: delete_user clears the attempts also under an NFKC-/IDNA-folded identifier ok")

# …but not the bucket of ANOTHER account. `ｃｌａｒａ` and `clara` are two accounts (the name
# is unique only ASCII-NOCASE), but count in one bucket: whoever types `ｃｌａｒａ` guesses against
# the same thing that protects `clara`. Deleting one must not reset the lockout of the other —
# otherwise "create account, guess, have the account deleted" would be a way past the
# account threshold. (Mutation probe: in `delete_attempts_for` remove the exception for a bucket that
# `konto_mit_topf` assigns to a remaining account → red.)
auth, c, db = build()
auth.set_security("rate_limit_max", 1000)
voll_id = auth.create_user("ｃｌａｒａ", "Clara-Voll-2026x")
# The namesake can no longer be created anew (`identifier_taken` asks the bucket, since
# G12c the store rejects it too) — it comes from an existing state from before, hence as a raw
# INSERT without bucket, as from a foreign writer.
from tinysesam.store import jetzt as _jetzt  # noqa: E402
clara_id = auth.store._exec("INSERT INTO users(username, display_name, created_at) VALUES (?,?,?)",
                            ("clara", "clara", _jetzt())).lastrowid
auth.set_password(clara_id, "Clara-Ascii-2026x")
fehl = auth._sec("max_login_attempts") * auth._sec("account_attempt_factor")   # account threshold across all addresses
for i in range(fehl):
    login(TestClient(c.app, client=(f"198.51.100.{i + 1}", 40000)), "clara", f"falsch-{i}")
r = login(TestClient(c.app, client=("192.0.2.50", 40000)), "clara", "Clara-Ascii-2026x")
assert r.status_code == 429, f"precondition: clara is locked after {fehl} failed attempts ({r.status_code})"
assert auth.delete_user(voll_id)
r = login(TestClient(c.app, client=("192.0.2.51", 40000)), "clara", "Clara-Ascii-2026x")
assert r.status_code == 429, f"deleting ｃｌａｒａ lifted the lockout of clara ({r.status_code})"
assert len(_versuche(auth)) >= fehl, _versuche(auth)
os.unlink(db)
print("  H-13: a bucket shared by a remaining account stays standing ok")

print("OK test_identifier")
