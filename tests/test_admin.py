"""Admin-Panel: Zugriffsschutz, User-/Service-/Key-Verwaltung, User sperren/entsperren,
Sitzungen, Härtung, Update, Audit."""
import os
import tempfile, os
from fastapi import FastAPI
from fastapi.testclient import TestClient
from tinysesam import TinySesam, TinySesamConfig

db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(csrf_enabled=False, lang="de", db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
auth.ensure_admin("admin", "pw12345")
auth.create_user("bob", password="bobpw", is_admin=False)

app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)


def by_name(n):
    return next(u for u in c.get("/auth/admin/api/users").json() if u["username"] == n)


# ohne Admin-Login gesperrt
assert c.get("/auth/admin/api/users").status_code in (401, 403)
# bob (kein Admin) darf nicht
cb = TestClient(app)
cb.post("/auth/login", data={"username": "bob", "password": "bobpw"})
assert cb.get("/auth/admin/api/users").status_code == 403
print("  ✓ Zugriffsschutz: nur Admins")

# Admin-Login
c.post("/auth/login", data={"username": "admin", "password": "pw12345"})
assert c.get("/auth/admin/api/users").status_code == 200
print("  ✓ Admin sieht Benutzer-Liste")

# Service-Account + Key anlegen
sid = c.post("/auth/admin/api/users", json={"username": "svc1", "is_service": True, "roles": ["reader"]}).json()["id"]
key = c.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "k1"}).json()["key"]
assert key.startswith("tsk_")
print("  ✓ Admin legt Service-Account + API-Key an")

# User SPERREN (disable, nicht löschen) → Login blockiert, Konto bleibt
bid = by_name("bob")["id"]
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert by_name("bob")["disabled"] is True
assert TestClient(app).post("/auth/login", data={"username": "bob", "password": "bobpw"}).status_code == 401
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert by_name("bob")["disabled"] is False
print("  ✓ Admin sperrt/entsperrt User explizit (nicht gelöscht, Login blockiert)")

# Selbst-Sperre verhindert
mid = by_name("admin")["id"]
assert c.post(f"/auth/admin/api/users/{mid}/disable", json={"disabled": True}).status_code == 400
print("  ✓ Selbst-Sperre verhindert")

# Sitzungen sichtbar + widerrufbar
assert len(c.get("/auth/admin/api/sessions").json()) >= 1
print("  ✓ Sitzungen einsehbar")

# Härtung lesen/setzen
assert "max_login_attempts" in c.get("/auth/admin/api/security").json()
c.post("/auth/admin/api/security", json={"max_login_attempts": 7})
assert auth.sec("max_login_attempts") == 7
print("  ✓ Härtungs-Schwellen im Panel setzbar")

# Version — nur anzeigen. Die früheren Update-Routen sind bewusst weg: über sie konnte ein
# übernommener Admin-Zugang auf eine alte, lückenhafte Version zurückschalten.
assert c.get("/auth/admin/api/version").json()["version"][0].isdigit()
for gone in ("/auth/admin/api/update", "/auth/admin/api/update/run"):
    assert c.get(gone).status_code == 404, f"{gone} lebt noch"
print("  ✓ Version wird angezeigt; kein Update-Endpunkt mehr")

# Audit + HTML
assert len(c.get("/auth/admin/api/audit").json()) >= 1
assert c.get("/auth/admin").status_code == 200 and "Admin" in c.get("/auth/admin").text
print("  ✓ Audit-Log + Admin-UI-Seite")

# R8-3: `rp_name` ist Text. Login-, Konto- und Fehlerseite escapten ihn längst, das Panel setzte
# ihn roh in <title> und <h1> — wer den Namen aus einer Mandanten-Einstellung oder Umgebung
# übernimmt, gab damit Markup in die mächtigste Seite der Installation.
from tinysesam.admin import render_panel  # noqa: E402

auth.cfg.rp_name = "</title><script>alert(1)</script>"
_panel = render_panel(auth, "/auth/admin")
assert "<script>alert(1)" not in _panel and "&lt;/title&gt;&lt;script&gt;" in _panel, \
    "rp_name steht roh im Panel"
assert _panel.count("&lt;/title&gt;") == 2, "rp_name nicht an beiden Stellen (<title>, <h1>) escaped"
# Der Mountpunkt geht in einen JS-String — als JSON-Literal, nicht roh eingesetzt.
_panel_b = render_panel(auth, '/x"</script><script>alert(2)//')
assert "<script>alert(2)" not in _panel_b and 'const B="/x\\"\\u003c/script>' in _panel_b, \
    _panel_b[_panel_b.index("const B="):][:60]
print("  ✓ rp_name und Mountpunkt landen escaped im Panel")

# ---------- R6-1: den letzten Admin nicht entmachten ----------
# Ohne Admin öffnet sich der Erst-Admin-Weg neu (Einmal-Token im Log), und niemand kann es
# im Panel zurückdrehen. Geprüft wird VOR dem Schreiben: auch die Rollen bleiben unverändert.
mid = by_name("admin")["id"]
r = c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": ["x"], "is_admin": False})
assert r.status_code == 400, r.status_code
assert by_name("admin")["is_admin"] is True and by_name("admin")["roles"] == [], by_name("admin")
# Ein GESPERRTER zweiter Admin zählt nicht — er kann sich nicht anmelden.
bid = by_name("bob")["id"]
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": True}).status_code == 200
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": True})
assert c.post(f"/auth/admin/api/users/{mid}/roles", json={"roles": [], "is_admin": False}).status_code == 400
assert by_name("admin")["is_admin"] is True
# Gegenprobe: Mit einem zweiten AKTIVEN Admin geht das Entmachten (die Regel sperrt nicht alles).
c.post(f"/auth/admin/api/users/{bid}/disable", json={"disabled": False})
assert c.post(f"/auth/admin/api/users/{bid}/roles", json={"roles": [], "is_admin": False}).status_code == 200
assert by_name("bob")["is_admin"] is False and by_name("admin")["is_admin"] is True
print("  ✓ R6-1: letzter aktiver Admin nicht entmachtbar (gesperrte zählen nicht), sonst schon")
# (Mutationsprobe: `and not andere_aktive_admins(uid)` → `and False` in admin.user_roles → rot.)

# ---------- R6-2: kein Admin-Service-Konto ----------
r = c.post("/auth/admin/api/users", json={"username": "svc2", "is_service": True, "is_admin": True})
assert r.status_code == 400, r.status_code
assert not any(u["username"] == "svc2" for u in c.get("/auth/admin/api/users").json())
assert c.post(f"/auth/admin/api/users/{sid}/roles", json={"roles": ["reader"], "is_admin": True}).status_code == 400
assert by_name("svc1")["is_admin"] is False
print("  ✓ R6-2: Service-Konto wird weder beim Anlegen noch über die Rollen zum Admin")

# ---------- R6-4 / B2-9: Härtungs-Schwellen mit Grenzen ----------
from tinysesam import ConfigError, security  # noqa: E402
vorher = auth.sec("max_login_attempts")
for boese in ({"rate_limit_max": 0}, {"max_login_attempts": 0}, {"lockout_window_sec": 10**9},
              {"password_min_length": 1}, {"rate_limit_max": "viele"}, {"gibtsnicht": 5},
              {"max_login_attempts": True}):
    assert c.post("/auth/admin/api/security", json=boese).status_code == 400, boese
# Alles-oder-nichts: ein gültiger Wert neben einem ungültigen wird NICHT geschrieben.
assert c.post("/auth/admin/api/security",
              json={"max_login_attempts": vorher + 2, "rate_limit_max": 0}).status_code == 400
assert auth.sec("max_login_attempts") == vorher and auth.sec("rate_limit_max") == 30
try:
    auth.set_security("rate_limit_max", 0)
    raise AssertionError("set_security nahm 0 an")
except ConfigError:
    pass
# Ein Wert, der schon in der Datenbank steht (Fassung ohne Grenzen): Er wird an die nächste
# Grenze gezogen — 0 legte die Instanz still, die Untergrenze hält sie am Leben.
auth.store.set_setting("rate_limit_max", "0")
assert auth.sec("rate_limit_max") == 3, auth.sec("rate_limit_max")
auth.store.set_setting("rate_limit_max", "keine Zahl")          # nur Unlesbares fällt auf die Vorgabe
assert auth.sec("rate_limit_max") == 30, auth.sec("rate_limit_max")
auth.store.set_setting("rate_limit_max", "30")
print("  ✓ R6-4/B2-9: Grenzen im Panel und in set_security, alles-oder-nichts, Altwert an die Grenze")
# (Mutationsprobe: in security.pruefe_haertung die Bereichsprüfung auskommentieren → rot.)

# ---------- A1: ein Upgrade lockert keine strengere Bestandseinstellung ----------
# Bis 0.19.x schrieb set_security jeden Wert. Wer dort STRENGER eingestellt hatte, als die
# Grenzen der ersten Fassung erlaubten, bekam nach dem Upgrade still die schwächere Vorgabe.
streng = {"max_login_attempts": 2, "pin_max_attempts": 2, "lockout_window_sec": 7 * 86400,
          "rate_limit_window_sec": 7200}
for k, v in streng.items():
    auth.store.set_setting(k, str(v))
    assert auth.sec(k) == v, (k, auth.sec(k))
# Jenseits der Grenze: an die Grenze, nicht auf die Vorgabe — die Richtung der Verschärfung bleibt.
auth.store.set_setting("password_min_length", "200")
assert auth.sec("password_min_length") == 128, auth.sec("password_min_length")
auth.store.set_setting("lockout_window_sec", str(10**9))
assert auth.sec("lockout_window_sec") == 30 * 86400, auth.sec("lockout_window_sec")
# Was sec() dann liefert, nimmt das Panel auch an — die Logzeile rät zu nichts Unmöglichem.
assert c.post("/auth/admin/api/security", json={**streng, "password_min_length": 128}).status_code == 200
for k, v in streng.items():
    assert auth.sec(k) == v, (k, auth.sec(k))
auth.set_security("max_login_attempts", 1)                     # ein Versuch: hart, aber zulässig
for k, v in security.SECURITY_DEFAULTS.items():
    auth.set_security(k, v)
print("  ✓ A1: strengere Altwerte bleiben, Werte jenseits der Grenze landen an der Grenze")
# (Mutationsprobe: in manager.sec() wieder `return security.SECURITY_DEFAULTS[key]` statt
#  klemme_haertung → rot; SECURITY_GRENZEN max_login_attempts wieder (3, …) → rot.)
# Jede Härtungs-Schwelle hat Grenzen. Ohne Eintrag warf `pruefe_haertung` einen KeyError, also
# ein 500 im Panel — so geschehen, als drei Zweige je eine neue Schwelle brachten und keiner die
# Grenzen nachzog. Die Schleife oben trifft das nur für die Vorgaben; hier steht es als Regel.
assert set(security.SECURITY_GRENZEN) == set(security.SECURITY_DEFAULTS), \
    set(security.SECURITY_GRENZEN) ^ set(security.SECURITY_DEFAULTS)

# ---------- A4: Infinity ist ein 400, kein 500 ----------
r = c.post("/auth/admin/api/security", content=b'{"max_login_attempts": Infinity}',
           headers={"content-type": "application/json"})
assert r.status_code == 400, r.status_code
try:
    auth.set_security("max_login_attempts", float("inf"))
    raise AssertionError("set_security nahm inf an")
except ConfigError:
    pass
assert auth.sec("max_login_attempts") == security.SECURITY_DEFAULTS["max_login_attempts"]
print("  ✓ A4: Infinity im Panel → 400, in set_security → ConfigError")
# (Mutationsprobe: OverflowError aus dem except in pruefe_haertung nehmen → rot.)

# ---------- R6-8: Key-Route antwortet 400 statt 500 ----------
for boese in ({"name": "x", "roles": ["gibtsnicht"]}, {"name": "x", "expires_days": 0},
              {"name": "x", "expires_days": "morgen"}):
    r = c.post(f"/auth/admin/api/users/{sid}/keys", json=boese)
    assert r.status_code == 400, (boese, r.status_code)
# Selbstbedienung: dieselbe Klasse.
assert c.post("/auth/apikeys", json={"name": "x", "roles": ["gibtsnicht"]}).status_code == 400
print("  ✓ R6-8: unbrauchbarer Scope/Ablauf → 400 mit Grund (Panel und /auth/apikeys)")

# ---------- R6-6: ein Key mintet keinen Key ----------
# (a) fail-closed für eine Key-Art, die es nicht gibt: Das Admin-Flag fällt weg, nicht nur bei
#     "automat". Vorher behielt `kind="Automat"` (Tippfehler in der Spalte) die Admin-Rechte.
k = auth.create_api_key(mid, name="ci")
auth.store._exec("UPDATE api_key SET kind='Automat' WHERE id=?", (k["id"],))
ohne = TestClient(app)
assert ohne.get("/auth/admin/api/users", headers={"x-api-key": k["key"]}).status_code == 403
# (b) Die Panel-Route verlangt selbst eine Sitzung — unabhängig davon, ob R6-5 das Admin-Flag
#     schon wegnimmt. Simuliert wird ein per Key angemeldeter Admin (der Fall, den R6-5 heute
#     verhindert); die Route darf trotzdem keinen Key ausgeben.
echt = auth.current_user
auth.current_user = lambda req: {**dict(auth.store.get_user(mid)), "_via": "apikey"}
try:
    r = ohne.post(f"/auth/admin/api/users/{sid}/keys", json={"name": "gemintet"})
    assert r.status_code == 403, r.status_code
finally:
    auth.current_user = echt
assert not any(x["name"] == "gemintet" for x in auth.list_api_keys(sid))
print("  ✓ R6-6: unbekannte Key-Art trägt kein Admin-Flag; Panel-Key nur aus einer Sitzung")
# (Mutationsproben: `art != "mensch"` → `art == "automat"` in current_user → (a) rot;
#  die `_via`-Prüfung in admin.user_key_create entfernen → (b) rot.)

# ---------- B2-13: das Panel hält dieselbe Passwortregel ein ----------
# Bis T-13 nahm der Admin-Weg jedes Passwort an — `1` für ein neues Konto, `password` beim
# Zurücksetzen. (Mutationsprobe: die beiden `passwort_mangel`-Aufrufe in admin.py streichen → rot.)
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "1"})
assert r.status_code == 400 and "zu kurz" in r.json()["detail"], r.text
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "password123"})
assert r.status_code == 400 and "leicht zu erraten" in r.json()["detail"], r.text
r = c.post("/auth/admin/api/users", json={"username": "karl", "password": "Karl1990!"})
assert r.status_code == 400, "der Benutzername ist ein Kontextwort"
assert auth.store.get_user_by_name("neu1") is None and auth.store.get_user_by_name("karl") is None
r = c.post("/auth/admin/api/users", json={"username": "neu1", "password": "brauchbar-und-lang"})
assert r.status_code == 200, r.text
_bob = auth.store.get_user_by_name("bob")["id"]
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "Letmein-2024"})
assert r.status_code == 400 and "leicht zu erraten" in r.json()["detail"], r.text
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "x" * 300})
assert r.status_code == 400 and "zu lang" in r.json()["detail"], r.text
assert auth.check_password("bob", "bobpw"), "abgelehnt heisst: das alte Passwort gilt weiter"
r = c.post(f"/auth/admin/api/users/{_bob}/password", json={"password": "ein-gutes-neues"})
assert r.status_code == 200 and auth.check_password("bob", "ein-gutes-neues")
# Ohne Passwort anlegen bleibt erlaubt (SSO-/Passkey-Konten).
assert c.post("/auth/admin/api/users", json={"username": "nurssso"}).status_code == 200
print("  ✓ B2-13: Anlegen und Zurücksetzen im Panel prüfen Länge, Blockliste und Kontextwörter")

# ---------- Integrationsfund 8: Rollen, die keine Texte sind → 400 VOR jedem Schreibzugriff ----------
# Die Vorher/Nachher-Zeile (R6-7) entstand erst NACH `set_roles`/`set_admin`, mit `','.join`.
# Bei `roles=[1]` warf das: HTTP 500, das Admin-Flag stand schon in der Datenbank, und die
# Audit-Zeile fehlte — ein Konto wurde Admin, ohne dass es im Protokoll stand. Und solange die
# Rollen kaputt blieben, lief jede weitere Änderung an dem Konto ebenso ungeschrieben durch.
# (Mutationsproben: den `rollen_aus`-Aufruf in `user_roles` streichen → rot (200, `[1]` gespeichert);
#  die Detailzeile wieder mit `sorted(...)` ohne `str` bauen → rot beim Altbestand unten.)
import json as _json  # noqa: E402


def _zeilen(ereignis):
    return len([z for z in auth.store.recent_audit(500) if z["event"] == ereignis])


_carl = auth.create_user("carl", password="carl-geheim-1")
_vorher8 = _zeilen("user_roles")
for _koerper in ({"roles": [1], "is_admin": True}, {"roles": [None], "is_admin": True},
                 {"roles": "admin", "is_admin": True}, {"roles": {"a": 1}}, {"roles": ["ok", 2]}):
    r = c.post(f"/auth/admin/api/users/{_carl}/roles", json=_koerper)
    assert r.status_code == 400 and "roles" in r.json()["detail"], (_koerper, r.status_code, r.text)
    _z = auth.store.get_user(_carl)
    assert _json.loads(_z["roles"]) == [] and not _z["is_admin"], (_koerper, dict(_z))
assert _zeilen("user_roles") == _vorher8, "abgewiesen heisst: nichts geschrieben, nichts zu protokollieren"
# Anlegen und Einladen nehmen dieselbe Prüfung — sonst stünde die kaputte Rolle in der
# Datenbank und träfe die nächste Rollenänderung.
r = c.post("/auth/admin/api/users", json={"username": "dora", "roles": [1]})
assert r.status_code == 400 and auth.store.get_user_by_name("dora") is None, r.text
r = c.post("/auth/admin/api/users", json={"username": "dora", "roles": ["leser"]})
assert r.status_code == 200 and auth.user_roles(auth.store.get_user_by_name("dora")) == ["leser"], r.text
# Altbestand (aus einer Zeit ohne Prüfung): die Änderung geht durch UND steht im Protokoll.
auth.store._exec("UPDATE users SET roles=? WHERE id=?", ("[1, null]", _carl))
r = c.post(f"/auth/admin/api/users/{_carl}/roles", json={"roles": ["x"], "is_admin": False})
assert r.status_code == 200, (r.status_code, r.text)
_z8 = [z["detail"] for z in auth.store.recent_audit(20) if z["event"] == "user_roles"]
assert _zeilen("user_roles") == _vorher8 + 1 and "rollen=1,None->x" in _z8[0], _z8
print("  ✓ Fund 8: Rollen ohne Text → 400 vor jedem Schreiben; Altbestand wird protokolliert statt 500")

# ---------- Integrationsfund 10: das Panel zeigt, was der Server abweist ----------
# Der Server weist seit R6-1/R6-4/B2-13 ab (letzter Admin, Härtungswert ausserhalb der Grenzen,
# schwaches Passwort) — das Panel-JS sah nur den Körper: `savesec` meldete „gespeichert", `pw`
# „Passwort gesetzt", `saveroles` lud still neu. Die Admin-Person glaubte, es sei geschehen.
# (Mutationsproben: in `savesec` wieder `await p(…);alert(L.saved)` → rot; in `p` den Blick auf
#  `r.ok` entfernen → rot — mit node in der Laufzeitprobe, ohne node in der Strukturprüfung von
#  `p()` darunter. Vorher entfiel die Laufzeitprobe ohne node still, und das Image von ci-local
#  hatte bis 2026-09-24 kein node: Dort blieb genau diese Mutation grün. Schlussrunde: in `p` wieder
#  `return {detail:L["err.generic"]}` → rot, mit und ohne node; ebenso `(j&&j.detail)||…`.)
import re as _re  # noqa: E402
import subprocess as _sp  # noqa: E402

_panel = c.get("/auth/admin").text
_skripte = [s for s in _re.findall(r"<script[^>]*>(.*?)</script>", _panel, _re.S) if "const ACT={" in s]
assert len(_skripte) == 1, "Panel-Skript nicht gefunden"
_js = _skripte[0]
# Ohne Laufzeit: Jede Aktion, die `p()` ruft, führt das Ergebnis über `abgewiesen` — die nächste
# neue Aktion fällt sonst wieder in dasselbe Loch.
# Gezählt werden die Aktionen aus ACT (nur die ruft ein Knopf auf), ohne Kommentarzeilen.
_act = set(_re.search(r"const ACT=\{([^}]*)\}", _js).group(1).split(","))
_stuecke = {m.group(1): "\n".join(z for z in m.group(0).splitlines() if not z.lstrip().startswith("//"))
            for m in _re.finditer(r"(?:async )?function (\w+)\(.*?(?=\n(?:async )?function \w+\(|\nconst ACT=)",
                                  _js, _re.S)}
_schreibend = [n for n in sorted(_act) if _re.search(r"(?<![\w.])p\(", _stuecke.get(n, ""))]
_ohne = [n for n in _schreibend if "abgewiesen(" not in _stuecke[n]]
assert not _ohne, f"Aktionen ohne Anzeige der Abweisung: {_ohne}"
assert len(_schreibend) >= 10 and _act <= set(_stuecke), (_schreibend, _act - set(_stuecke))
# Und `p()` selbst: Ohne den Blick auf `r.ok` gibt sie bei 400/500 den Körper zurück, und
# `abgewiesen()` sieht bei einem 500 ohne JSON-Körper nichts. Die Laufzeitprobe unten braucht
# node; diese Prüfung läuft immer.
#
# Bis zur Schlussrunde verlangte sie nur `if(r.ok)return`, `return {detail:` und irgendwo den Text
# L["err.generic"]. `return {detail:L["err.generic"]}` bestand das: Das Panel zeigte statt „Das ist
# der letzte aktive Admin“ nur noch „Fehler“, und ohne node (ci-local) blieb es grün (Schlussfund
# audit-3). Jetzt wird der Ausdruck hinter `detail:` gelesen, nicht nach Zeichen gesucht: Ein
# kleiner Parser für den Teil von JavaScript, der dort vorkommt (`&&`, `||`, `?:`, `typeof`,
# Vergleiche, `.`/`?.`/`[…]`), bestimmt, welche Werte als `detail` herauskommen KÖNNEN, und unter
# welchen Bedingungen. Verlangt: Ein möglicher Wert ist der Grund des Servers (`<Körper>.detail`),
# und zwar nur, wenn er ein Text ist (`typeof … === "string"`; FastAPI schickt bei 422 eine Liste)
# und der Körper nicht null ist (davor geprüft oder `?.`) — und ein anderer ist der Rückfalltext.
# Gleich wie geschrieben: `a&&b||c`, `c?a:b`, `j?.detail`, `j["detail"]`, `"string"===typeof …`.
# Grenze: Das bleibt Struktur, keine Ausführung. Was ausserhalb des Teils liegt (eine Funktion,
# ein Template-String), wird abgewiesen statt geraten (fail-closed); Anweisungen ZWISCHEN dem
# Lesen des Körpers und der Rückgabe (`j.detail = …`) sieht der Parser nicht, ebenso wenig einen
# falschen Text-Schlüssel. Das deckt nur die node-Laufzeitprobe darunter.
_JS_TOKEN = _re.compile(r"""\s*(?:(?P<str>"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(?P<op>===|!==|==|!=|&&|\|\||\?\.|[()\[\].?:!])"""
                        r"""|(?P<name>[A-Za-z_$][\w$]*)|(?P<num>\d+(?:\.\d+)?))""")


def _js_ausdruck(text):
    """Einen JS-Ausdruck aus dem kleinen Teil oben lesen — als verschachtelte Tupel."""
    toks, i = [], 0
    while i < len(text):
        if text[i:].strip() == "":
            break
        m = _JS_TOKEN.match(text, i)
        if not m or m.end() == i:
            raise ValueError(f"nicht auswertbar ab {text[i:i + 20]!r}")
        art = m.lastgroup
        toks.append((art, m.group(art)))
        i = m.end()
    pos = [0]

    def nimm(wert=None):
        if pos[0] < len(toks) and (wert is None or toks[pos[0]][1] == wert):
            pos[0] += 1
            return toks[pos[0] - 1]
        return None

    def muss(wert):
        if not nimm(wert):
            raise ValueError(f"erwartet {wert!r} bei Stück {pos[0]}")

    def bedingt():
        a = oder()
        if nimm("?"):
            x = bedingt()
            muss(":")
            return ("cond", a, x, bedingt())
        return a

    def kette(art, op, weiter):
        teile = [weiter()]
        while nimm(op):
            teile.append(weiter())
        return teile[0] if len(teile) == 1 else (art, teile)

    def oder():
        return kette("or", "||", und)

    def und():
        return kette("and", "&&", gleich)

    def gleich():
        a = einstellig()
        while pos[0] < len(toks) and toks[pos[0]][1] in ("===", "!==", "==", "!="):
            op = nimm()[1]
            a = ("eq", op, a, einstellig())
        return a

    def einstellig():
        if nimm("!"):
            return ("not", einstellig())
        if nimm("typeof"):
            return ("typeof", einstellig())
        return glied()

    def glied():
        t = nimm()
        if t is None:
            raise ValueError("Ausdruck endet zu früh")
        if t[1] == "(":
            a = bedingt()
            muss(")")
        elif t[0] in ("name", "num"):
            a = (t[0], t[1])
        elif t[0] == "str":
            a = ("str", t[1][1:-1])
        else:
            raise ValueError(f"unerwartet {t[1]!r}")
        while True:
            if nimm(".") or nimm("?."):
                optional = toks[pos[0] - 1][1] == "?."
                n = nimm()
                if not n or n[0] != "name":
                    raise ValueError("nach . fehlt ein Name")
                a = ("mem", a, n[1], optional)
            elif nimm("["):
                k = bedingt()
                muss("]")
                if k[0] != "str":
                    raise ValueError("Index ist kein fester Text")
                a = ("mem", a, k[1], False)
            else:
                return a

    baum = bedingt()
    if pos[0] != len(toks):
        raise ValueError(f"Rest nach dem Ausdruck: {toks[pos[0]:][:3]}")
    return baum


def _js_ergebnisse(a, bedingungen=()):
    """Jeder Wert, den der Ausdruck als Ergebnis liefern kann (ausser den kurzgeschlossenen
    falschen), mit den Bedingungen, die dann in dieser Reihenfolge wahr waren."""
    if a[0] == "or":
        return [e for t in a[1] for e in _js_ergebnisse(t, bedingungen)]
    if a[0] == "and":
        return _js_ergebnisse(a[1][-1], bedingungen + tuple(a[1][:-1]))
    if a[0] == "cond":
        wahr = tuple(a[1][1]) if a[1][0] == "and" else (a[1],)   # `x&&y?…` heisst: x, dann y
        return _js_ergebnisse(a[2], bedingungen + wahr) + _js_ergebnisse(a[3], bedingungen)
    return [(a, bedingungen)]


def _p_detail_stelle(code):
    """(Anfang, Ende) des Ausdrucks hinter `return {detail:` — oder None."""
    m = _re.search(r"return\s*\{\s*detail\s*:", code)
    if not m:
        return None
    tiefe, i, zeichen = 0, m.end(), None
    while i < len(code):
        c = code[i]
        if zeichen:
            if c == "\\":
                i += 1
            elif c == zeichen:
                zeichen = None
        elif c in "\"'`":
            zeichen = c
        elif c in "([{":
            tiefe += 1
        elif c in ")]}":
            if tiefe == 0:
                return m.end(), i
            tiefe -= 1
        elif c == "," and tiefe == 0:
            return m.end(), i
        i += 1
    return None


def _p_pruefen(code):
    """Was p() fehlt, um eine Abweisung samt Grund weiterzugeben — leer, wenn nichts."""
    probleme = []
    rm = _re.search(r"\.then\(\s*(?:async\s*)?\(?\s*(\w+)\s*\)?\s*=>", code)
    r_ = rm.group(1) if rm else "r"
    if not _re.search(rf"if\s*\(\s*{r_}\.ok\s*\)\s*\{{?\s*return", code):
        probleme.append("p() liest r.ok nicht")
    jm = _re.search(rf"(\w+)\s*=\s*await\s+{r_}\.json\(\)", code)
    if not jm:
        probleme.append("p() liest den Körper der Antwort nicht")
    stelle = _p_detail_stelle(code)
    if stelle is None:
        return probleme + ["p() gibt eine Abweisung nicht als {detail: …} zurück"]
    try:
        ergebnisse = _js_ergebnisse(_js_ausdruck(code[stelle[0]:stelle[1]]))
    except ValueError as e:
        return probleme + [f"detail-Ausdruck nicht auswertbar ({e}): {code[stelle[0]:stelle[1]]}"]
    j = jm.group(1) if jm else "j"

    def ist_grund(a):
        return a[0] == "mem" and a[1] == ("name", j) and a[2] == "detail"

    def ist_textpruefung(b):
        if b[0] != "eq" or b[1] not in ("===", "=="):
            return None
        for x, y in ((b[2], b[3]), (b[3], b[2])):
            if x[0] == "typeof" and ist_grund(x[1]) and y == ("str", "string"):
                return x[1]
        return None

    def ist_nicht_null(b):
        return b == ("name", j) or (b[0] == "eq" and b[1] in ("!==", "!=") and ("name", j) in (b[2], b[3])
                                    and ({("name", "null"), ("name", "undefined")} & {b[2], b[3]}))

    def geschuetzt(bedingungen):
        for n, b in enumerate(bedingungen):
            gelesen = ist_textpruefung(b)
            if gelesen and (gelesen[3] or any(ist_nicht_null(v) for v in bedingungen[:n])):
                return True
        return False

    if not any(ist_grund(w) and geschuetzt(bed) for w, bed in ergebnisse):
        probleme.append(f"p() reicht den Grund des Servers ({j}.detail, nur als Text, null-sicher) nicht durch")
    if not any(w == ("mem", ("name", "L"), "err.generic", False) for w, _ in ergebnisse):
        probleme.append('p() hat keinen Rückfalltext L["err.generic"]')
    return probleme


_p_def = _re.search(r"^const p=\(u,b\)=>(.*?)^(?:const|function|async function) ", _js, _re.S | _re.M)
assert _p_def, "p() nicht gefunden"
_p_code = "\n".join(z for z in _p_def.group(1).splitlines() if not z.lstrip().startswith("//"))
assert not _p_pruefen(_p_code), f"{_p_pruefen(_p_code)}: {_p_code}"
# Selbstprobe: jede kaputte Fassung von p() fällt auf, jede gleichwertige Schreibweise nicht.
# Die Fassungen tauschen nur den Ausdruck hinter `detail:` (die Prüfung findet ihn selbst) oder
# ersetzen p() ganz — kein Textanker in admin.py.
_p_stelle = _p_detail_stelle(_p_code)
assert _p_stelle, _p_code


def _p_mit(detail):
    return _p_code[:_p_stelle[0]] + detail + _p_code[_p_stelle[1]:]


_p_kaputt = {
    "Schlussfund audit-3": _p_mit('L["err.generic"]'),
    "fester Text statt Grund": _p_mit('(j&&typeof j.detail==="string"&&"Fehler")||L["err.generic"]'),
    "Grund ohne Text- und null-Prüfung": _p_mit('j.detail||L["err.generic"]'),
    "Grund ohne Textprüfung": _p_mit('(j&&j.detail)||L["err.generic"]'),
    "typeof vor der null-Prüfung": _p_mit('(typeof j.detail==="string"&&j&&j.detail)||L["err.generic"]'),
    "Textprüfung verneint": _p_mit('(j&&typeof j.detail!=="string"&&j.detail)||L["err.generic"]'),
    "Textprüfung an einem anderen Feld": _p_mit('(j&&typeof j.fehler==="string"&&j.detail)||L["err.generic"]'),
    "null-Prüfung verneint": _p_mit('(!j&&typeof j.detail==="string"&&j.detail)||L["err.generic"]'),
    "Grund aus einer anderen Variable": _p_mit('(j&&typeof j.detail==="string"&&k.detail)||L["err.generic"]'),
    "Zweige vertauscht": _p_mit('j&&typeof j.detail==="string"?L["err.generic"]:j.detail'),
    "ohne Rückfalltext": _p_mit('(j&&typeof j.detail==="string"&&j.detail)'),
    "Funktionsaufruf (ausserhalb des Teils)": _p_mit('grund(j)||L["err.generic"]'),
    "ohne Blick auf r.ok": _re.sub(r"if\s*\(\s*r\.ok\s*\)\s*return[^;]*;", "", _p_code),
    "Fund 4": '.then(r=>r.json());\n',
    "Fund 7 (Körper immer)": '.then(async r=>{let j=null;try{j=await r.json()}catch(e){} return j});\n',
}
_p_durch = [n for n, c in _p_kaputt.items() if not _p_pruefen(c)]
assert not _p_durch and _p_kaputt["ohne Blick auf r.ok"] != _p_code, f"Strukturprüfung übersieht: {_p_durch}"
_p_gleichwertig = [
    'j&&typeof j.detail==="string"?j.detail:L["err.generic"]',
    '(typeof j?.detail==="string"&&j.detail)||L["err.generic"]',
    '(j!==null&&"string"===typeof j["detail"]&&j["detail"])||L[\'err.generic\']',
]
_p_fehlalarm = [d for d in _p_gleichwertig if _p_pruefen(_p_mit(d))]
assert not _p_fehlalarm, f"Strukturprüfung lehnt Gleichwertiges ab: {_p_fehlalarm}"

from voraussetzung import pflicht_werkzeug  # noqa: E402

# Fehlt node, ist das rot — überall, nicht nur auf GitHub (s. `pflicht_werkzeug`). Seit das
# ci-local-Abbild node mitbringt, prüft Ebene 1 hier genauso viel wie das Gate.
# (Mutationsprobe: mit PATH ohne node → rot; mit TINYSESAM_OHNE_NODE=1 → ⚠-Zeile.)
_node = pflicht_werkzeug("node", "Fund 10: Laufzeitprobe der Panel-Aktionen")
if _node:
    _probe = ("const A=[];let ANTWORT=null;const E={};\n"
              "const document={cookie:'',addEventListener(){},querySelectorAll:()=>[],"
              "getElementById:i=>E[i]||(E[i]={value:'0',checked:false,textContent:'',innerHTML:''})};\n"
              "const alert=m=>A.push(String(m));const confirm=()=>true;const prompt=()=>'neu-und-lang';\n"
              # Das Panel liest Eingabefelder über ihre ID als globale Namen (Browser-Verhalten).
              "const kn={value:'k'},ke={value:''};\n"
              "const fetch=async()=>({ok:ANTWORT[0]<400,status:ANTWORT[0],"
              "json:async()=>{if(ANTWORT[1]===null)throw new Error('kein JSON');return ANTWORT[1]}});\n"
              + _js.replace("tabs();users();", "")
              + "\nusers=async()=>{};keys=async()=>{};pks=async()=>{};sessions=async()=>{};\n"
              "const FAELLE=[['savesec',[['rate_limit_max']]],['saveroles',[1]],['pw',[1]],['dis',[1,true]],"
              "['delpk',[1,2,'x']],['revk',[1,1,'x']],['mkkey',[1]],['deluser',[1]]];\n"
              "(async()=>{const E2={};for(const [name,args] of FAELLE){\n"
              "  for(const [k,antw] of [['400',[400,{detail:'Grund vom Server'}]],['500',[500,null]],"
              "['200',[200,{ok:true}]]]){\n"
              "    ANTWORT=antw;A.length=0;await (globalThis[name]||eval(name))(...args);"
              "E2[name+' '+k]=[...A]}}\n"
              "  process.stdout.write(JSON.stringify(E2))})();\n")
    _aus = _sp.run([_node, "-e", _probe], capture_output=True, text=True, timeout=30)
    assert _aus.returncode == 0, _aus.stderr[-600:]
    _erg = _json.loads(_aus.stdout)
    _Lp = _json.loads(_re.search(r"const L=(\{.*?\});", _js).group(1))   # die Texte des Panels
    for _name in ("savesec", "saveroles", "pw", "dis", "delpk", "revk", "mkkey", "deluser"):
        assert _erg[f"{_name} 400"] == ["Grund vom Server"], (_name, _erg[f"{_name} 400"])
        assert len(_erg[f"{_name} 500"]) == 1 and _erg[f"{_name} 500"][0] not in ("", "undefined"), \
            (_name, _erg[f"{_name} 500"])
    assert _erg["savesec 200"] == [_Lp["saved"]] and _erg["pw 200"] == [_Lp["pw_set"]] \
        and _erg["saveroles 200"] == [], _erg
    assert _Lp["saved"] not in _erg["savesec 400"] + _erg["savesec 500"], _erg
    assert _erg["pw 500"] == [_Lp["err.generic"]], _erg
    print("  ✓ Fund 10 (node): 400/500 zeigen den Grund statt „gespeichert“, 200 bleibt still bzw. meldet Erfolg")
print("  ✓ Fund 10 (Struktur): jede Panel-Aktion, die schreibt, führt das Ergebnis über abgewiesen(),"
      " und p() liest r.ok und reicht den Grund des Servers durch")

os.remove(db)
print("\nADMIN-PANEL OK ✅")
