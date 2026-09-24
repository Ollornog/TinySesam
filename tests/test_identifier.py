"""Login-Kennung: Benutzername, E-Mail oder beides — plus E-Mail-Pflicht/Eindeutigkeit/Bestätigung."""
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


# ---------- Normalisierung + Validierung ----------
assert norm_email("  Max@Example.COM ") == "max@example.com"
assert norm_email("") is None and norm_email(None) is None
assert valid_email("a@b.de") and valid_email("a.b+c@sub.example.co.uk")
assert not valid_email("ab.de") and not valid_email("a@b") and not valid_email("a b@c.de")
assert not valid_email("a@@b.de") and not valid_email("@b.de") and not valid_email("a@.de")
print("  norm_email/valid_email ok")

# ---------- R4-06: Kompatibilitätszeichen, IDNA, Verwechsler ----------
assert norm_email("ａｄｍｉｎ@ｅｘａｍｐｌｅ.com") == "admin@example.com", "NFKC faltet Vollbreite"
assert norm_email("u@Bücher.example") == norm_email("u@xn--bcher-kva.example") == "u@xn--bcher-kva.example"
# IDNA 2003 (stdlib) machte aus straße.example ein strasse.example — eine andere Domain. Bleibt unverändert.
assert norm_email("u@straße.example") == "u@straße.example"
assert not valid_email("аdmin@example.com"), "kyrillisches а zwischen lateinischen Buchstaben"
assert not valid_email("admin@exаmple.com"), "Verwechsler in der Domain"
assert not valid_email("ad\u200bmin@example.com") and not valid_email("ad\u200dmin@example.com"), "unsichtbar"
assert valid_email("müller@example.com") and valid_email("иван@example.com"), "eine Schrift bleibt erlaubt"
# Angriff A6: Schriften, die in einer Sprache zusammengehören, dürfen mischen — Japanisch schreibt
# Kanji mit Hiragana/Katakana. Latein bleibt aus jeder Gruppe draussen.
assert valid_email("山田たろう@example.jp") and valid_email("user@例え.テスト"), "Japanisch mischt Kanji und Kana"
assert valid_email("ラーメン@example.jp") and valid_email("홍길동漢@example.kr"), "Kana-Langzeichen, Hangul+Hanja"
assert not valid_email("山田a@example.jp") and not valid_email("たаро@example.jp"), "Latein/Kyrillisch mischt nicht mit"
auth, c, db = build(login_identifier="email", allow_signup=True)
auth.create_user("admin@example.com", password="geheim12345-lang-genug", email="admin@example.com")
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "ａｄｍｉｎ@example.com", "next": "/"})
assert r.status_code == 409, "Vollbreiten-Doppelgänger ist dieselbe Kennung"
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "аdmin@example.com", "next": "/"})
assert r.status_code == 400, "Verwechsler wird abgewiesen"
assert auth.store._exec("SELECT COUNT(*) FROM users").fetchone()[0] == 1
# Bestand von VOR R4-06: eine Umlaut-Domain in Unicode-Form wird weiter gefunden
auth.store._exec("INSERT INTO users(username, email, created_at) VALUES ('alt', 'alt@bücher.example', 0)")
assert auth.store.get_user_by_email("Alt@Bücher.example")["username"] == "alt"
os.unlink(db)
print("  R4-06: NFKC, IDNA-A-Label, Verwechsler abgewiesen, Bestand weiter auffindbar ok")

# ---------- Modus "both": Login mit beidem ----------
auth, c, db = build(login_identifier="both")
auth.create_user("max", password="geheim12345-lang-genug", email="Max@Example.com")
assert login(c, "max").status_code == 303, "Username-Login"
assert login(c, "max@example.com").status_code == 303, "E-Mail-Login"
assert login(c, "MAX@EXAMPLE.COM").status_code == 303, "E-Mail case-insensitiv"
assert login(c, "max", "falsch").status_code != 303
assert login(c, "gibtsnicht@example.com").status_code != 303
c.cookies.clear()          # sonst leitet /auth/login als Angemeldeter auf / um
assert "Benutzer oder E-Mail" in c.get("/auth/login").text
print("  both: Username + E-Mail + case-insensitiv ok")
os.unlink(db)

# ---------- Modus "username": E-Mail darf NICHT gehen ----------
auth, c, db = build(login_identifier="username")
auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
assert login(c, "max").status_code == 303
assert login(c, "max@example.com").status_code != 303, "E-Mail darf im Username-Modus nicht greifen"
c.cookies.clear()
page = c.get("/auth/login").text
assert "Benutzer</label>" in page and "Benutzer oder E-Mail" not in page
os.unlink(db)

# ---------- Modus "email": Username darf NICHT gehen ----------
auth, c, db = build(login_identifier="email")
auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
assert login(c, "max@example.com").status_code == 303
assert login(c, "max").status_code != 303, "Username darf im E-Mail-Modus nicht greifen"
c.cookies.clear()
assert "E-Mail</label>" in c.get("/auth/login").text
os.unlink(db)
print("  username-/email-only: jeweils nur die erlaubte Kennung ok")

# ---------- PIN nutzt dieselbe Kennung ----------
auth, c, db = build(login_identifier="both", pin_enabled=True)
uid = auth.create_user("max", password="geheim12345-lang-genug", email="max@example.com")
auth.set_pin(uid, "2468")
r = c.post("/auth/pin", data={"username": "max@example.com", "pin": "2468", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, "PIN-Login per E-Mail"
os.unlink(db)
print("  PIN akzeptiert dieselbe Kennung ok")

# ---------- E-Mail eindeutig ----------
auth, c, db = build()
auth.create_user("a", password="geheim12345-lang-genug", email="dup@example.com")
try:
    auth.create_user("b", password="geheim12345-lang-genug", email="DUP@example.com")
    raise AssertionError("Dublette wurde angenommen")
except ValueError:
    pass
assert auth.store.email_taken("dup@example.com")
assert not auth.store.email_taken("dup@example.com", exclude_id=auth.store.get_user_by_name("a")["id"])
os.unlink(db)
print("  E-Mail-Eindeutigkeit (case-insensitiv) ok")

# ---------- Registrierung: E-Mail Pflicht (Default) ----------
auth, c, db = build(allow_signup=True)
assert auth.cfg.signup_require_email is True, "Default = Pflicht"
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug", "next": "/"})
assert r.status_code == 400 and "E-Mail nötig" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug", "email": "keine-mail", "next": "/"})
assert r.status_code == 400 and "gültige E-Mail" in r.text
r = c.post("/auth/register", data={"username": "neu", "password": "geheim12345-lang-genug",
                                   "email": "Neu@Example.com", "next": "/"}, follow_redirects=False)
assert r.status_code == 303, r.text[:300]
assert auth.store.get_user_by_name("neu")["email"] == "neu@example.com", "kanonisch gespeichert"
r = c.post("/auth/register", data={"username": "neu2", "password": "geheim12345-lang-genug",
                                   "email": "NEU@example.com", "next": "/"})
assert r.status_code == 409 and "bereits registriert" in r.text
c.cookies.clear()
reg = c.get("/auth/register").text
email_tag = "<input name=email" + reg.split("<input name=email", 1)[1].split(">", 1)[0]
assert "required" in email_tag, "E-Mail-Feld als Pflicht markiert"
os.unlink(db)
print("  Registrierung: Pflicht + Format + Dublette ok")

# ---------- Registrierung folgt login_identifier ----------
auth, c, db = build(allow_signup=True, login_identifier="email")
page = c.get("/auth/register").text
assert "name=username" not in page, "im E-Mail-Modus kein Benutzernamen-Feld"
assert "name=email" in page and "required" in page
r = c.post("/auth/register", data={"password": "geheim12345-lang-genug", "email": "Solo@Example.com", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303, r.text[:300]
u = auth.store.get_user_by_email("solo@example.com")
assert u["username"] == "solo@example.com", "E-Mail ist die Kennung"
c.cookies.clear()
assert login(c, "solo@example.com").status_code == 303
os.unlink(db)

auth, c, db = build(allow_signup=True, login_identifier="username", signup_require_email=False)
page = c.get("/auth/register").text
assert "name=username" in page
if "<input name=email" in page:
    email_tag = "<input name=email" + page.split("<input name=email", 1)[1].split(">", 1)[0]
    assert "required" not in email_tag, "E-Mail darf hier nicht Pflicht sein"
os.unlink(db)
print("  Registrierung folgt login_identifier ok")

# ---------- Registrierung: E-Mail optional abschaltbar ----------
auth, c, db = build(allow_signup=True, signup_require_email=False)
r = c.post("/auth/register", data={"username": "ohne", "password": "geheim12345-lang-genug", "next": "/"},
           follow_redirects=False)
assert r.status_code == 303
assert auth.store.get_user_by_name("ohne")["email"] is None
os.unlink(db)
print("  signup_require_email=False: Konto ohne E-Mail ok")

# ---------- E-Mail-Bestätigung (optional) ----------
sent = []
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
auth.set_mailer(lambda to, subject, text, html=None: sent.append((to, text)))
r = c.post("/auth/register", data={"username": "verify", "password": "geheim12345-lang-genug",
                                   "email": "v@example.com", "next": "/"})
assert r.status_code == 200 and "Fast fertig" in r.text, r.text[:200]
u = auth.store.get_user_by_name("verify")
assert u["disabled"], "Konto bis zur Bestätigung gesperrt"
assert login(c, "v@example.com").status_code != 303, "gesperrtes Konto darf nicht rein"
assert sent and sent[0][0] == "v@example.com"
link = re.search(r"https?://\S+/auth/verify/(\S+)", sent[0][1]).group(1).rstrip(".,)")
c.post(f"/auth/verify/{link}", follow_redirects=False)   # R4-02: eingelöst wird per POST
assert not auth.store.get_user_by_name("verify")["disabled"], "nach Bestätigung entsperrt"
assert login(c, "v@example.com").status_code == 303
os.unlink(db)
print("  signup_verify_email: gesperrt → Link → entsperrt → Login ok")

# ---------- Bestätigung an, aber kein Mailer → harter Fehler statt stiller Bypass ----------
# `base_url` steht hier, weil sie seit dieser Fassung Pflicht ist, sobald ein Mail-Weg an ist
# (sonst scheitert schon der Konstruktor). Geprüft wird die Lage danach: Basis ja, Mailer nein.
auth, c, db = build(allow_signup=True, signup_verify_email=True, magiclink_enabled=True,
                    base_url="http://testserver")
r = c.post("/auth/register", data={"username": "x", "password": "geheim12345-lang-genug",
                                   "email": "x@example.com", "next": "/"})
assert r.status_code == 500 and "kein Mailer" in r.text
assert auth.store.get_user_by_name("x") is None, "kein halbfertiges Konto angelegt"
os.unlink(db)
print("  verify ohne Mailer: 500, kein Konto ok")

# ---------- Config-Sanity ----------
for bad in ("mail", "", "Username"):
    try:
        TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier=bad))
        raise AssertionError(f"login_identifier={bad!r} akzeptiert")
    except ValueError:
        pass
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "datei"), login_identifier="email",
                              allow_signup=True, signup_require_email=False))
    raise AssertionError("email-only ohne E-Mail-Pflicht akzeptiert")
except ValueError:
    pass
print("  Config-Sanity ok")

# ---------- Kreuz-Kollision: der ConfigError trägt Feld und Besitzer (R4-12) ----------
# Zugesagt im CHANGELOG unter „Für einbettende Apps": Der Meldungstext bleibt der von 0.18.x
# („… ist bereits vergeben"), damit ein Aufrufer, der den Text prüft, an diesem Fix nicht bricht
# — und unterscheiden lässt sich der Fall jetzt OHNE Textvergleich an `e.feld` und
# `e.besitzer_id`. Beide Hälften der Zusage waren von keiner einzigen Zeile gedeckt: Mutation
# M25 (die Attribute nicht mehr setzen) und M34 (Wortlaut zurück auf „… ist bereits als
# Login-Kennung vergeben") liefen je mit 46/46 grün durch. `grep -rn "besitzer_id" tests/` fand
# nichts. Genau die Zusage, die den Textvergleich ersetzen sollte, und genau der Textvergleich,
# den sie retten sollte.
from tinysesam import ConfigError  # noqa: E402

auth, c, db = build(login_identifier="both")
opfer_id = auth.create_user("opfer", password="geheim12345-lang-genug", email="chef@example.com")
for kennung, mail, feld in (("chef@example.com", None, "username"),   # Name == fremde E-Mail
                            ("neu", "chef@example.com", "email")):    # E-Mail == fremde E-Mail
    try:
        auth.create_user(kennung, email=mail)
        raise AssertionError(f"{feld}: die Kreuzprüfung greift nicht, das Konto entstand")
    except ConfigError as e:
        assert "bereits vergeben" in str(e), (
            f"{feld}: Wortlaut geändert ({str(e)!r}) — Aufrufer aus 0.18.x prüfen genau diesen "
            "Text, und der CHANGELOG sagt ihnen zu, dass er bleibt")
        assert getattr(e, "feld", None) == feld, (
            f"e.feld ist {getattr(e, 'feld', '<fehlt>')!r}, erwartet {feld!r} — ohne das Attribut "
            "bleibt der Textvergleich der einzige Weg, die beiden Fälle zu trennen")
        assert getattr(e, "besitzer_id", None) == opfer_id, (
            f"e.besitzer_id ist {getattr(e, 'besitzer_id', '<fehlt>')!r}, erwartet {opfer_id}")
# Gegenprobe: eine freie Kennung wirft nicht — sonst wäre „wirft immer" auch grün.
frei_id = auth.create_user("frei", email="frei@example.com")
assert frei_id and auth.store.get_user(frei_id)["username"] == "frei"
os.unlink(db)
print("  Kreuz-Kollision: Wortlaut bleibt, e.feld/e.besitzer_id benennen den Fall ok")

# ---------- Der Sperr-Topf faltet wie find_user — auch NFKC und IDNA ----------
# Die Konto-Schwelle gegen verteiltes Raten zählt unter `norm_kennung()`. Das war strip + lower;
# `find_user` sucht eine Adresse aber über `norm_email()`, und das faltet seit R4-06 auch NFKC
# und IDNA. `ｖｉｃｔｉｍ@example.com`, `victim＠example.com` (Vollbreiten-@) und jede Mischform
# trafen dasselbe Konto, füllten aber je einen eigenen Topf — allein für diese eine Adresse
# 2^16 Schreibweisen. Gemessen: 40 Fehlversuche aus 40 Adressen, keiner gesperrt, der Inhaber
# danach mit 303 drin. (Mutationsprobe: `norm_kennung` wieder auf `strip().lower()` → die
# Topf-Prüfung und die Salve werden rot; nur NFKC ohne `norm_email` → die IDNA-Zeile wird rot.)
from tinysesam.store import norm_kennung  # noqa: E402

VOLL = {ch: chr(ord(ch) + 0xFEE0) for ch in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@."}


def _voll(text, maske):
    """Die Zeichen an den Stellen, deren Bit in `maske` gesetzt ist, in Vollbreite."""
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
    assert gefunden and gefunden["id"] == opfer_id, f"Vorbedingung: {v!r} trifft das Konto nicht"
    assert norm_kennung(v) == norm_kennung(basis), \
        f"{v!r} trifft das Konto, zählt aber im Topf {norm_kennung(v)!r} statt {norm_kennung(basis)!r}"
# IDNA: A-Label und Unicode-Form derselben Domain sind dasselbe Postfach, also ein Topf.
for v in ("u@bücher.example", "u@xn--bcher-kva.example", "U@BÜCHER.EXAMPLE", "u@ｂüｃｈｅｒ.example"):
    assert auth.find_user(v)["id"] == idn_id, f"Vorbedingung: {v!r} trifft das IDN-Konto nicht"
    assert norm_kennung(v) == norm_kennung("u@bücher.example"), f"IDNA-Schreibweise {v!r} hat eigenen Topf"
print(f"  Sperr-Topf: {len(varianten) + 4} Schreibweisen, die find_user demselben Konto zuordnet, zählen zusammen ok")

# Und über die Route: verteiltes Raten mit Vollbreiten-Schreibweisen, jede Anfrage von einer
# anderen Adresse. Mehr als die Konto-Schwelle darf die Prüfung nicht erreichen.
auth.set_security("rate_limit_max", 1000)
app_k = FastAPI()
app_k.include_router(auth.router())
DECKEL = auth.sec("max_login_attempts") * auth.sec("account_attempt_factor")
geprueft = 0
for i in range(DECKEL + 25):
    ci = TestClient(app_k, client=(f"198.51.100.{i + 1}", 40000))
    r = ci.post("/auth/login", data={"username": _voll(basis, i + 1), "password": f"falsch-{i}"},
                follow_redirects=False)
    geprueft += r.status_code == 401
assert geprueft <= DECKEL, f"{geprueft} Rateversuche über Vollbreiten-Schreibweisen, zugesagt sind höchstens {DECKEL}"
r = TestClient(app_k, client=("192.0.2.200", 40000)).post(
    "/auth/login", data={"username": basis, "password": "Richtiges-Passwort-42x"}, follow_redirects=False)
assert r.status_code == 429, f"die Konto-Schwelle hat bei {geprueft} Versuchen nicht gegriffen: {r.status_code}"
# Aufheben trifft denselben Topf: gezählt wurde unter der gefalteten Adresse.
assert auth.sperre_aufheben(opfer_id) == geprueft
os.unlink(db)
print(f"  Sperr-Topf über die Route: {geprueft} geprüft, dann zu (Konto-Schwelle {DECKEL}) ok")

# ---------- H-13 × Sperr-Topf: das Löschen räumt die Versuche unter der gefalteten Kennung ----------
# Seit der Sperr-Topf NFKC und IDNA faltet (oben), stehen die Versuche eines Kontos unter
# `norm_kennung(...)`. `delete_user` suchte sie aber per SQLite `lower()` unter dem GESPEICHERTEN
# Namen bzw. der gespeicherten Adresse. Ein Name mit Kompatibilitätszeichen (`ｂｅｒｔａ`, `ﬁnn` —
# `create_user` faltet Namen nicht, sie kommen etwa aus LDAP oder OIDC) und eine Bestandsadresse
# von vor R4-06 in Unicode-Form (`u2@bücher.example`) liessen Kennung und IP nach dem Löschen
# stehen — gegen die H-13-Zusage „deren Versuchszeilen werden gelöscht". (Mutationsprobe:
# `delete_attempts_for` wieder nur mit der Rohform und `lower(username)=lower(?)` → rot.)
auth, c, db = build(login_identifier="both")
berta_id = auth.create_user("ｂｅｒｔａ", "Berta-Passwort-2026x")
finn_id = auth.create_user("ﬁnn", "Finn-Passwort-2026x")
bestand_id = auth.create_user("bestand", "Bestand-Passwort-2026x", email="u2@example.org")
auth.store.db.execute("UPDATE users SET email='u2@bücher.example' WHERE id=?", (bestand_id,))
auth.store.db.commit()
assert auth.find_user("u2@bücher.example")["id"] == bestand_id, "Vorbedingung: Bestandsadresse wird gefunden"
# Die Konten eine Minute älter machen: Der Löschweg (`Store.konto_entfernen`) räumt nur Versuche
# NACH der Sekunde der Anlage — was in ihr geschah, lässt sich nicht zuordnen und bleibt stehen.
# Hier geht es um die Faltung, nicht um diese Grenze.
auth.store.db.execute("UPDATE users SET created_at = created_at - 60 WHERE id IN (?, ?, ?)",
                      (berta_id, finn_id, bestand_id))
auth.store.db.commit()
for i, kennung in enumerate(("ｂｅｒｔａ", "ﬁnn", "u2@bücher.example", "BESTAND")):
    for ip in ("198.51.100.1", "198.51.100.2"):
        r = login(TestClient(c.app, client=(ip, 40000 + i)), kennung, "falsch-geraten-1")
        assert r.status_code == 401, (kennung, r.status_code)


def _versuche(a):
    return [(z["username"], z["ip"]) for z in a.store._all("SELECT username, ip FROM login_attempt")]


assert len(_versuche(auth)) == 8, f"Vorbedingung: acht Fehlversuche stehen: {_versuche(auth)}"
for uid in (berta_id, finn_id, bestand_id):
    assert auth.delete_user(uid)
assert _versuche(auth) == [], f"nach delete_user stehen noch Versuche gelöschter Konten: {_versuche(auth)}"
os.unlink(db)
print("  H-13: delete_user räumt die Versuche auch unter NFKC-/IDNA-gefalteter Kennung ok")

# …aber nicht den Topf eines ANDEREN Kontos. `ｃｌａｒａ` und `clara` sind zwei Konten (der Name
# ist nur ASCII-NOCASE eindeutig), zählen aber in einem Topf: Wer `ｃｌａｒａ` tippt, rät gegen
# dasselbe, was `clara` schützt. Das Löschen des einen darf die Sperre des anderen nicht
# zurücksetzen — sonst wäre „Konto anlegen, raten, Konto löschen lassen" ein Weg an der
# Konto-Schwelle vorbei. (Mutationsprobe: in `delete_attempts_for` die Ausnahme für einen Topf, den
# `konto_mit_topf` einem verbleibenden Konto zuordnet, streichen → rot.)
auth, c, db = build()
auth.set_security("rate_limit_max", 1000)
voll_id = auth.create_user("ｃｌａｒａ", "Clara-Voll-2026x")
# Neu anlegen lässt sich der Namensvetter nicht mehr (`kennung_vergeben` fragt den Topf) — er
# kommt aus einem Bestand von vorher, deshalb am Manager vorbei direkt in den Store.
clara_id = auth.store.create_user("clara")
auth.set_password(clara_id, "Clara-Ascii-2026x")
fehl = auth.sec("max_login_attempts") * auth.sec("account_attempt_factor")   # Konto-Schwelle über alle Adressen
for i in range(fehl):
    login(TestClient(c.app, client=(f"198.51.100.{i + 1}", 40000)), "clara", f"falsch-{i}")
r = login(TestClient(c.app, client=("192.0.2.50", 40000)), "clara", "Clara-Ascii-2026x")
assert r.status_code == 429, f"Vorbedingung: clara ist nach {fehl} Fehlversuchen gesperrt ({r.status_code})"
assert auth.delete_user(voll_id)
r = login(TestClient(c.app, client=("192.0.2.51", 40000)), "clara", "Clara-Ascii-2026x")
assert r.status_code == 429, f"das Löschen von ｃｌａｒａ hat die Sperre von clara aufgehoben ({r.status_code})"
assert len(_versuche(auth)) >= fehl, _versuche(auth)
os.unlink(db)
print("  H-13: ein Topf, den ein verbleibendes Konto teilt, bleibt stehen ok")

print("OK test_identifier")
