"""Adressen aus LDAP und SAML (PO-Entscheid 2026-09-25).

Vorgabe „nicht vertraut": Die Adresse aus der Quelle kommt nicht direkt ins Konto. Der Normalweg
ist der Bestätigungslink — derselbe wie beim Adresswechsel der Selbstbedienung. Ein Attribut der
Quelle kann die Adresse DIESES Logins belegen (für IdPs, die das führen), der pauschale Schalter
bleibt für gepflegte Quellen. Gemessen wird die Wirkung: was im Konto steht, welche Mail an wen
geht, und die Riegel gegen Belästigung (offener Link, einmal am Tag, belegte Adresse bleibt) und
gegen Aussperrung über das gemeinsame Mail-Kontingent. Dazu G12a (2026-09-26): „einmal am Tag"
zählt zugestellte Links in der Datenbank, über alle Worker; Versuche dämpft nur der Speicher.
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
from tinysesam import konfigpruefung as _kp  # noqa: E402
from tinysesam.manager import _ANFRAGE  # noqa: E402
from tinysesam.ldap_ import _attributliste  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Adressen aus LDAP und SAML — Bestätigung per Link")
BASIS = "https://app.example.com"


class Verzeichnis:
    """Attrappe des LDAP-Clients NACH erfolgreichem Bind: liefert den Eintrag so, wie
    `LDAPClient.authenticate` ihn zurückgibt (mit `email_verified`, wenn konfiguriert)."""

    def __init__(self, eintraege):
        self.eintraege = eintraege

    def authenticate(self, username, password):
        e = self.eintraege.get(username)
        if not e or e["pw"] != password:
            return None
        return {"username": username, "email": e.get("email"), "name": username, "groups": [],
                "id": e.get("id"), "email_verified": e.get("beleg")}


def _aufbau(**cfg):
    post: list = []
    grund = dict(db_path=str(Path(tempfile.mkdtemp()) / "t.db"), cookie_secure=False, csrf_enabled=False,
                 passkey_enabled=False, base_url=BASIS, lang="de", ldap_enabled=True,
                 ldap_url="ldap://dummy", ldap_allow_plaintext=True, ldap_auto_create=True)
    grund.update(cfg)
    auth = TinySesam(TinySesamConfig(**grund))
    auth.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff, text)))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app, post


def _anmelden(auth, name, eintrag):
    auth.ldap = Verzeichnis({name: {"pw": "pw", **eintrag}})
    u = auth.check_ldap(name, "pw")
    auth._hinweis_ausgang.abwarten()
    return u


def _vergehen(auth, sek):
    """`sek` Sekunden vergehen lassen: für die Drosseln im Speicher (ihre Zeitstempel zurück) und
    für das Tageskontingent in der Datenbank (die Audit-Zeilen zurück). Die Uhr des Prozesses
    bleibt stehen — ein `mock.patch` auf `time.time` hielte sie für den Rest des Laufs vorgestellt
    (`store._Uhr` läuft nie rückwärts)."""
    for stempel in auth.rl._hits.values():
        for i in range(len(stempel)):
            stempel[i] -= sek
    auth.store._exec("UPDATE audit SET ts = ts - ?", (int(sek),))


def _link(post):
    treffer = [re.search(r"https://app\.example\.com(/auth/email/\S+)", m[2]) for m in post]
    return next((t.group(1) for t in treffer if t), "")


# ── LDAP, Vorgabe: nicht vertraut → Bestätigungslink ─────────────────────────────────────────
auth, app, post = _aufbau()
r.check("Vorgabe: dem Verzeichnis wird nicht pauschal vertraut", auth.cfg.ldap_email_trusted is False)
u = _anmelden(auth, "bob", {"email": "Bob@Example.com", "id": "uuid-bob"})
konto = auth.get_user(u["id"])
r.check("Erste Anmeldung: das Konto hat noch keine Adresse", not konto["email"], str(dict(konto)))
r.check("… ein Bestätigungslink ging an die Adresse aus dem Verzeichnis",
        [m[0] for m in post] == ["bob@example.com"] and _link(post), str(post))
r.check("… mit Audit-Zeile (Quelle und Ziel)",
        auth.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm' "
                        "AND detail LIKE '%quelle=ldap%an=bob@example.com%'") is not None)
link = _link(post)
post.clear()
_anmelden(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("Zweite Anmeldung, Link noch offen: kein neuer Link", post == [], str(post))
# Offener Link bleibt ein Riegel für sich — auch wenn die Tagesgrenze schon wieder frei wäre
# (ein Link lebt bis zu sieben Tage, `email_change_ttl_min`). Ein Tag vergeht für Speicher UND
# Datenbank; der Link (echte Uhr) ist dann noch offen.
_vergehen(auth, 86401)
_anmelden(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("… auch nach Ablauf der Tagesgrenze nicht, solange der Link offen ist", post == [], str(post))
fertig = TestClient(app).post(link, follow_redirects=False)
auth._hinweis_ausgang.abwarten()
konto = auth.get_user(u["id"])
r.check("Klick auf den Link: die Adresse steht im Konto, MIT Beleg",
        fertig.status_code == 303 and konto["email"] == "bob@example.com" and konto["email_verified"],
        f"{fertig.status_code} {dict(konto)}")
r.check("… und geht als Remote-Email an die App",
        auth.forward_response_headers(auth.get_user(u["id"])).get("Remote-Email") == "bob@example.com")
post.clear()
_anmelden(auth, "bob", {"email": "bob@example.com", "id": "uuid-bob"})
r.check("Nach der Bestätigung: keine Links mehr", post == [], str(post))

# Tagesgrenze: Link abgelaufen (weg), am selben Tag trotzdem kein zweiter. Eine Viertelstunde
# später — die Dämpfung im Speicher ist dann vorbei (G12a), es zählt der Versand in der Datenbank.
auth2, _, post2 = _aufbau()
u2 = _anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
auth2.store._exec("DELETE FROM magic_token")
_vergehen(auth2, 901)
post2.clear()
_anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("Link verfallen, derselbe Tag (+15 min): kein zweiter Link (höchstens einer am Tag)",
        post2 == [], str(post2))
_vergehen(auth2, 86401)                     # „ein Tag später" — die Audit-Zeile ist älter
_anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("… am nächsten Tag wieder einer", [m[0] for m in post2] == ["cleo@example.com"], str(post2))

# Ein Konto mit belegter Adresse behält sie — auch eine andere als die der Quelle.
auth3, _, post3 = _aufbau()
u3 = _anmelden(auth3, "dana", {"email": "dana@example.com", "id": "uuid-dana"})
auth3.store.set_email(u3["id"], "dana.privat@example.com", verified=True)
_vergehen(auth3, 86401)                     # Tageskontingent frei: Es riegelt nur der Beleg
auth3.store._exec("DELETE FROM magic_token")
post3.clear()
_anmelden(auth3, "dana", {"email": "dana@example.com", "id": "uuid-dana"})
r.check("Konto mit belegter eigener Adresse: kein Link, die Adresse bleibt",
        post3 == [] and auth3.get_user(u3["id"])["email"] == "dana.privat@example.com", str(post3))

# Die Adresse gehört schon einem anderen Konto: kein Link, nur Audit.
auth4, _, post4 = _aufbau()
auth4.create_user("erna", email="erna@example.com")
u4 = _anmelden(auth4, "eve", {"email": "erna@example.com", "id": "uuid-eve"})
r.check("Adresse eines anderen Kontos: kein Link, das Konto bleibt ohne Adresse, Audit-Zeile",
        post4 == [] and not auth4.get_user(u4["id"])["email"]
        and auth4.store._one("SELECT 1 FROM audit WHERE event='email_change_taken'") is not None, str(post4))

# Abgeschaltet oder ohne Voraussetzungen: gar nichts.
for titel, cfg in (("federation_email_confirm=False", {"federation_email_confirm": False}),
                   ("ohne base_url", {"base_url": ""})):
    a_, _, p_ = _aufbau(**cfg)
    u_ = _anmelden(a_, "fritz", {"email": "fritz@example.com", "id": "uuid-fritz"})
    r.check(f"{titel}: kein Link, keine Adresse", p_ == [] and not a_.get_user(u_["id"])["email"], str(p_))

# Eine Adresse aus `admin_identifiers` bekommt keinen Link: Ein Nutzer, der sein `mail`-Attribut
# selbst pflegt, trüge sie sonst nach einem gutgläubigen Klick des Inhabers belegt am Konto.
a4b, _, p4b = _aufbau(admin_identifiers=["boss@example.com"])
u4b = _anmelden(a4b, "mallory", {"email": "boss@example.com", "id": "uuid-mallory"})
r.check("Allowlist-Adresse aus dem Verzeichnis: kein Link, keine Adresse, nicht Admin",
        p4b == [] and not a4b.get_user(u4b["id"])["email"] and not a4b.get_user(u4b["id"])["is_admin"], str(p4b))

# ── LDAP: pauschal vertraut oder per Attribut belegt ─────────────────────────────────────────
a5, _, p5 = _aufbau(ldap_email_trusted=True)
u5 = _anmelden(a5, "gina", {"email": "gina@example.com", "id": "uuid-gina"})
k5 = a5.get_user(u5["id"])
r.check("ldap_email_trusted=True: Adresse direkt MIT Beleg, kein Link",
        k5["email"] == "gina@example.com" and k5["email_verified"] and p5 == [], f"{dict(k5)} {p5}")

a6, _, p6 = _aufbau(ldap_attr_email_verified="emailVerified")
r.check("Das Beleg-Attribut wird beim Verzeichnis mit angefragt",
        "emailVerified" in _attributliste(a6.cfg), str(_attributliste(a6.cfg)))
u6 = _anmelden(a6, "hans", {"email": "hans@example.com", "id": "uuid-hans", "beleg": "TRUE"})
k6 = a6.get_user(u6["id"])
r.check("Beleg-Attribut „TRUE“: Adresse direkt MIT Beleg, kein Link",
        k6["email"] == "hans@example.com" and k6["email_verified"] and p6 == [], f"{dict(k6)} {p6}")
u6b = _anmelden(a6, "ida", {"email": "ida@example.com", "id": "uuid-ida", "beleg": "FALSE"})
r.check("Beleg-Attribut „FALSE“: nicht vertraut — Link statt Adresse",
        not a6.get_user(u6b["id"])["email"] and [m[0] for m in p6] == ["ida@example.com"], str(p6))
p6.clear()
u6c = _anmelden(a6, "jan", {"email": "jan@example.com", "id": "uuid-jan"})
r.check("Beleg-Attribut fehlt im Eintrag: nicht vertraut",
        not a6.get_user(u6c["id"])["email"] and [m[0] for m in p6] == ["jan@example.com"], str(p6))
a6b, _, p6b = _aufbau()
u6d = _anmelden(a6b, "kai", {"email": "kai@example.com", "id": "uuid-kai", "beleg": "TRUE"})
r.check("Ohne konfiguriertes Beleg-Attribut zählt ein mitgeliefertes nicht",
        not a6b.get_user(u6d["id"])["email"], str(dict(a6b.get_user(u6d["id"]))))

# Über die Login-Route: Das Beleg-Attribut trägt die Allowlist-Adresse wie der Schalter — gleich
# bei DIESER Anmeldung, nicht erst bei der nächsten über einen lokalen Faktor.
for wert, soll in (("TRUE", True), ("FALSE", False)):
    a_b, app_b, _ = _aufbau(admin_identifiers=["boss@example.com"], ldap_attr_email_verified="emailVerified")
    a_b.ldap = Verzeichnis({"bossin": {"pw": "pw", "email": "boss@example.com", "id": "uuid-bossin", "beleg": wert}})
    antwort = TestClient(app_b).post("/auth/login", data={"username": "bossin", "password": "pw"},
                                     follow_redirects=False)
    konto_b = a_b.store.get_user_by_name("bossin")
    r.check(f"Login-Route, Beleg-Attribut {wert}: Erst-Admin {'ja' if soll else 'nein'}",
            antwort.status_code == 303 and bool(konto_b["is_admin"]) is soll,
            f"{antwort.status_code} {dict(konto_b) if konto_b else None}")
_w_attr = " ".join(_kp.pruefe(TinySesamConfig(
    db_path=":memory:", admin_identifiers=["boss@example.com"], ldap_enabled=True,
    ldap_url="ldaps://d.example", ldap_auto_create=True, ldap_attr_email_verified="emailVerified"))[1])
r.check("Konfig-Prüfung: mit Beleg-Attribut „vertraute Quelle“, nicht „NIE“",
        "vertraute Quelle" in _w_attr and "NIE" not in _w_attr, _w_attr[:200])

# ── SAML ─────────────────────────────────────────────────────────────────────────────────────
a7, _, p7 = _aufbau()
u7 = a7.check_saml("lena", {"email": ["lena@example.com"]})
a7._hinweis_ausgang.abwarten()
r.check("SAML, Vorgabe: kein Konto-Attribut, Link an die Adresse aus der Assertion",
        not a7.get_user(u7["id"])["email"] and [m[0] for m in p7] == ["lena@example.com"], str(p7))
a8, _, p8 = _aufbau(saml_attr_email_verified="email_verified")
u8 = a8.check_saml("mia", {"email": ["mia@example.com"], "email_verified": ["true"]})
a8._hinweis_ausgang.abwarten()
k8 = a8.get_user(u8["id"])
r.check("SAML, Beleg-Attribut „true“: Adresse direkt MIT Beleg, kein Link",
        k8["email"] == "mia@example.com" and k8["email_verified"] and p8 == [], f"{dict(k8)} {p8}")
u8b = a8.check_saml("nils", {"email": ["nils@example.com"], "email_verified": ["false"]})
a8._hinweis_ausgang.abwarten()
r.check("SAML, Beleg-Attribut „false“: Link statt Adresse",
        not a8.get_user(u8b["id"])["email"] and [m[0] for m in p8] == ["nils@example.com"], str(p8))

# SAML, Beleg-Attribut und Name (Angriffsrunde, Fund 1): Das Attribut belegt die ADRESSE, nicht
# den Namen. Ein IdP mit Selbstregistrierung lässt den Nutzer die NameID wählen — `bob@example.com`
# als Name, die eigene Adresse bestätigt. Ohne diese Regel band Lage 4 das lokale Konto
# `bob@example.com` über den Namen: Übernahme, auch eines Admins.
a10, _, _ = _aufbau(saml_attr_email_verified="email_verified")
opfer10 = a10.create_user("bob@example.com", password="Opfer-Passwort1", email="bob@example.com")
a10.store.set_admin(opfer10, True)
u10 = a10.check_saml("bob@example.com", {"email": ["angreifer@evil.example"], "email_verified": ["true"]})
r.check("SAML, Beleg-Attribut: ein @-Name, der NICHT die belegte Adresse ist, trifft kein lokales Konto",
        u10 is None or (u10["id"] != opfer10 and u10["username"].startswith("saml-") and not u10["is_admin"]),
        str(u10))
u10b = a10.check_saml("mia@example.com", {"email": ["mia@example.com"], "email_verified": ["true"]})
r.check("… ist er genau die belegte Adresse, bleibt er Kontoname (wie OIDC mit email_verified)",
        u10b is not None and u10b["username"] == "mia@example.com", str(u10b))
a10c, _, _ = _aufbau(saml_attr_email_verified="email_verified", saml_attr_username="email")
a10c.create_user("chefin", password="Opfer-Passwort1")
u10c = a10c.check_saml("id-1", {"email": ["chefin"], "email_verified": ["true"]})
r.check("… und ein Name aus dem Adress-Attribut, der keine Adresse ist, bleibt unbelegt",
        u10c is None or u10c["username"] != "chefin", str(u10c))

# Beleg-Attribut aus Leerraum (Fund 2): Prüfung und Laufzeit lesen dieselbe, getrimmte Angabe.
a11, app11, _ = _aufbau(admin_identifiers=["boss@example.com"], ldap_attr_email_verified=" ")
k11 = a11.create_user("bossin", email="boss@example.com")
a11.store.set_email_verified(k11, True)
a11.ldap = Verzeichnis({"bossin": {"pw": "pw", "email": "boss@example.com"}})
TestClient(app11).post("/auth/login", data={"username": "bossin", "password": "pw"}, follow_redirects=False)
_w11 = " ".join(_kp.pruefe(a11.cfg)[1])
r.check("Beleg-Attribut \" \": die Prüfung sagt „NIE“, und die Laufzeit befördert auch nicht",
        "NIE" in _w11 and not a11.get_user(k11)["is_admin"], f"is_admin={a11.get_user(k11)['is_admin']}")

# ── G12a: Versände zählen, Versuche dämpfen ───────────────────────────────────────────────────
# Bis 2026-09-26 verbrauchte schon der VERSUCH das Tageskontingent, je Prozess im Speicher: Eine
# gedrosselte Zieladresse oder ein gescheiterter Versand kostete den Link für einen Tag, und zwei
# Worker schickten zwei. Jetzt zählt die Datenbank Versände (`federation_email_confirm konto=<id>`
# erst nach dem Versand); der Speicher dämpft nur die Versuche.

# (a) Die Zieladresse ist gerade gedrosselt: kein Link — aber nach dem Fenster der Drossel einer.
g_a, _, p_a = _aufbau()
for _ in range(int(g_a.sec("mail_per_address_max"))):
    g_a.rl.allow("wechsel:gerd@example.com", g_a.sec("mail_per_address_max"),
                 g_a.sec("mail_per_address_window_sec"))
_anmelden(g_a, "gerd", {"email": "gerd@example.com", "id": "uuid-gerd"})
r.check("G12a: Zieladresse gedrosselt → kein Link, keine Zeile federation_email_confirm",
        p_a == [] and g_a.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None,
        str(p_a))
_vergehen(g_a, int(g_a.sec("mail_per_address_window_sec")) + 1)
_anmelden(g_a, "gerd", {"email": "gerd@example.com", "id": "uuid-gerd"})
r.check("… nach dem Fenster der Drossel (+15 min) derselbe Tag: der Link kommt",
        [m[0] for m in p_a] == ["gerd@example.com"] and _link(p_a), str(p_a))

# (b) Der erste Versand scheitert: keine Zeile, der Token gilt nicht — nach dem Fenster ein Link.
g_b, _, p_b = _aufbau()
versuche = {"n": 0}


def _erst_kaputt(to, betreff, text, html=None):
    versuche["n"] += 1
    if versuche["n"] == 1:
        raise OSError("Mailserver nicht erreichbar")
    p_b.append((to, betreff, text))


g_b.set_mailer(_erst_kaputt)
u_b = _anmelden(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("G12a: erster Versand gescheitert → keine Zeile federation_email_confirm, kein offener Link",
        versuche["n"] == 1 and p_b == []
        and g_b.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None
        and not g_b.store.offener_token(u_b["id"], "email_change", "hilde@example.com"),
        f"{versuche} {p_b}")
_anmelden(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("… gleich danach (derselbe Prozess, im Fenster) noch kein neuer Versuch",
        versuche["n"] == 1, str(versuche))
_vergehen(g_b, int(g_b.sec("mail_per_address_window_sec")) + 1)
_anmelden(g_b, "hilde", {"email": "hilde@example.com", "id": "uuid-hilde"})
r.check("… nach dem Fenster derselbe Tag: der Link wird zugestellt, jetzt mit Zeile (konto=<id> vorn)",
        [m[0] for m in p_b] == ["hilde@example.com"] and _link(p_b)
        and g_b.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm' AND detail LIKE ?",
                           (f"konto={u_b['id']} quelle=ldap an=hilde@example.com",)) is not None,
        f"{versuche} {p_b}")

# (c) Zwei Worker auf einer Datenbank: je ein eigener Speicher, aber EIN Tageskontingent.
db_c = str(Path(tempfile.mkdtemp()) / "t.db")
w1, _, p_c1 = _aufbau(db_path=db_c)
w2, _, p_c2 = _aufbau(db_path=db_c)
_anmelden(w1, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
w1.store._exec("DELETE FROM magic_token")          # Link verfallen / weggeräumt
_vergehen(w2, 901)                                 # derselbe Tag, eine Viertelstunde später
_anmelden(w2, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
r.check("G12a: zwei Worker, derselbe Tag: der zweite schickt keinen zweiten Link",
        [m[0] for m in p_c1] == ["ines@example.com"] and p_c2 == [], f"{p_c1} {p_c2}")
_anmelden(w2, "jonas", {"email": "jonas@example.com", "id": "uuid-jonas"})
r.check("… das Kontingent gilt je Konto: ein anderes Konto bekommt seinen Link am selben Tag",
        [m[0] for m in p_c2] == ["jonas@example.com"], str(p_c2))
p_c2.clear()
_vergehen(w2, 86401)
_anmelden(w2, "ines", {"email": "ines@example.com", "id": "uuid-ines"})
r.check("… am nächsten Tag bekommt ines wieder einen", [m[0] for m in p_c2] == ["ines@example.com"], str(p_c2))

# (d) Vergebene Adresse: nie ein Link — und ihre Audit-Zeile höchstens einmal am Tag, nicht bei
# jeder Anmeldung (die Absicht des alten Tageskontingents bleibt).
g_d, _, p_d = _aufbau()
g_d.create_user("karla", email="karla@example.com")
for _ in range(3):
    _anmelden(g_d, "kurt", {"email": "karla@example.com", "id": "uuid-kurt"})
    _vergehen(g_d, int(g_d.sec("mail_per_address_window_sec")) + 1)
_zeilen_d = g_d.store._one("SELECT COUNT(*) AS n FROM audit WHERE event='email_change_taken'")["n"]
r.check("G12a: vergebene Adresse, drei Anmeldungen im Abstand von 15 min → genau eine Audit-Zeile, kein Link",
        _zeilen_d == 1 and p_d == []
        and g_d.store._one("SELECT 1 FROM audit WHERE event='federation_email_confirm'") is None,
        f"{_zeilen_d} {p_d}")

# Die Zeile entsteht im Postausgang, trägt aber IP und Akteur der Anfrage wie bisher.
g_e, _, _ = _aufbau()
_marke = _ANFRAGE.set({"ip": "203.0.113.7", "akteur": None})
try:
    _anmelden(g_e, "lars", {"email": "lars@example.com", "id": "uuid-lars"})
finally:
    _ANFRAGE.reset(_marke)
_zeile_e = g_e.store._one("SELECT ip FROM audit WHERE event='federation_email_confirm'")
r.check("… die Zeile federation_email_confirm trägt die IP der Anfrage",
        _zeile_e is not None and _zeile_e["ip"] == "203.0.113.7", str(dict(_zeile_e) if _zeile_e else None))

# Kontoseite eines LDAP-Kontos (G12b): dieselben Ereignisse, ob die Adresse aus dem Verzeichnis frei
# oder vergeben ist — `federation_email_confirm` entsteht nur bei einer freien und bleibt dort weg.
_ansicht = {}
for art, adresse in (("frei", "mona@example.com"), ("vergeben", "nora@example.com")):
    a_k, _, _ = _aufbau()
    a_k.create_user("nora", email="nora@example.com")
    u_k = _anmelden(a_k, "mona", {"email": adresse, "id": "uuid-mona"})
    _ansicht[art] = [e["event"] for e in a_k.own_events(u_k["id"], limit=50)]
r.check("G12b: Kontoseite eines LDAP-Kontos gleich für freie und vergebene Adresse, ohne federation_email_confirm",
        _ansicht["frei"] == _ansicht["vergeben"] and "email_change_requested" in _ansicht["frei"]
        and not {None, "federation_email_confirm", "email_change_taken"} & set(_ansicht["frei"] + _ansicht["vergeben"]),
        str(_ansicht))

# ── Angriffsrunde 2026-09-26 (a1-02): kein Orakel über mehrere Worker ─────────────────────────
# G12a zählte den zugestellten Link in der Datenbank, die Abweisung einer vergebenen Adresse aber
# nur im Speicher — je Worker und bis zum Neustart. Ein LDAP-Nutzer setzt sein `mail` auf eine
# fremde Adresse und meldet sich über wechselnde Worker an: Bei einer freien stand auf seiner
# Kontoseite genau ein Antrag, bei einer vergebenen mit jedem weiteren Worker einer mehr
# (gemessen: [1, 1, 1, 1, 1] gegen [1, 2, 2, 2, 3]). Jetzt zählt auch die Abweisung in der Datenbank.
def _altern_alles(auth, sek):
    """Wie `_vergehen`, dazu die Links: Auch ihre Gültigkeit läuft mit der Zeit ab."""
    _vergehen(auth, sek)
    auth.store._exec("UPDATE magic_token SET expires_at = expires_at - ?", (int(sek),))


def _worker_lauf(vergeben, **cfg):
    db = str(Path(tempfile.mkdtemp()) / "t.db")
    w1, _, p1 = _aufbau(db_path=db, **cfg)
    w2, _, p2 = _aufbau(db_path=db, **cfg)
    if vergeben:
        w1.create_user("opfer", email="ziel@example.com")
    zahl = []

    def _sicht(w):
        u = _anmelden(w, "mallory", {"email": "ziel@example.com", "id": "uuid-mallory"})
        zahl.append([e["event"] for e in w.own_events(u["id"], limit=50)].count("email_change_requested"))
    for w in (w1, w2, w1, w2):
        _sicht(w)
    w3, _, p3 = _aufbau(db_path=db, **cfg)          # ein Neustart: frischer Speicher, dieselbe Datei
    _sicht(w3)
    zeilen = w3.store._one("SELECT COUNT(*) AS n FROM audit WHERE event IN "
                           "('email_change_requested', 'email_change_taken')")["n"]
    return {"sicht": zahl, "zeilen": zeilen, "post": [m[0] for m in p1 + p2 + p3], "w": w3, "sichtbar": _sicht}


_frei, _verg = _worker_lauf(False), _worker_lauf(True)
_res = _worker_lauf(False, admin_identifiers=["ziel@example.com"])     # reserviert (Allowlist)
r.check("a1-02: Kontoseite nach vier Anmeldungen über zwei Worker und einem Neustart gleich, "
        "ob die Adresse frei, vergeben oder reserviert ist (je genau ein Antrag)",
        _frei["sicht"] == _verg["sicht"] == _res["sicht"] == [1, 1, 1, 1, 1],
        f"frei {_frei['sicht']} vergeben {_verg['sicht']} reserviert {_res['sicht']}")
r.check("… im Audit-Log des Betreibers je eine Zeile, der Link nur an die freie Adresse",
        _frei["zeilen"] == _verg["zeilen"] == 1 and _frei["post"] == ["ziel@example.com"]
        and _verg["post"] == _res["post"] == []
        and _res["w"].store._one("SELECT COUNT(*) AS n FROM audit WHERE event='email_change_reserved'")["n"] == 1,
        f"{_frei['zeilen']}/{_verg['zeilen']} {_frei['post']} {_verg['post']} {_res['post']}")
r.check("… die Zeile trägt `konto=<id> quelle=ldap` vorn, für jedes Ergebnis gleich gebaut",
        all(re.fullmatch(r"konto=\d+ quelle=ldap neu=ziel@example\.com", z["detail"] or "")
            for lauf in (_frei, _verg, _res) for z in lauf["w"].store._all(
                "SELECT detail FROM audit WHERE event LIKE 'email_change_%'")))
for lauf in (_frei, _verg):
    _altern_alles(lauf["w"], 86401)
    lauf["sichtbar"](lauf["w"])
r.check("… am nächsten Tag für beide genau ein weiterer Antrag",
        _frei["sicht"][-1] == _verg["sicht"][-1] == 2, f"{_frei['sicht']} {_verg['sicht']}")

# Lebt der Link länger als einen Tag, hält die Abweisung genauso lange auf wie ein offener Link.
_frei7, _verg7 = _worker_lauf(False, email_change_ttl_min=3 * 24 * 60), _worker_lauf(True, email_change_ttl_min=3 * 24 * 60)
for lauf in (_frei7, _verg7):
    _altern_alles(lauf["w"], 86401)
    lauf["sichtbar"](lauf["w"])
r.check("… mit email_change_ttl_min = 3 Tage: auch am nächsten Tag für beide kein weiterer Antrag",
        _frei7["sicht"] == _verg7["sicht"] == [1, 1, 1, 1, 1, 1], f"{_frei7['sicht']} {_verg7['sicht']}")
for lauf in (_frei7, _verg7):
    _altern_alles(lauf["w"], 2 * 86400)
    lauf["sichtbar"](lauf["w"])
r.check("… nach Ablauf des Links für beide genau ein weiterer",
        _frei7["sicht"][-1] == _verg7["sicht"][-1] == 2, f"{_frei7['sicht']} {_verg7['sicht']}")

# ── Kontingent: Wechselanträge auf eine Adresse sperren deren späteren Inhaber nicht aus ─────
# Jeder Antrag erreicht die Drossel, auch der auf eine vergebene Adresse (G12b). Heikel ist die
# noch FREIE: Ein Fremder beantragt den Wechsel darauf, bis ihr Kontingent aufgebraucht ist;
# registriert sich der Inhaber gleich danach, käme sein Anmelde-Link im selben Topf nicht mehr an.
a9, _, p9 = _aufbau()
taeter = a9.create_user("taeter", email="taeter@example.com")
for _ in range(int(a9.sec("mail_per_address_max")) + 2):
    a9.request_email_change(taeter, "spaeter@example.com", BASIS)
a9.create_user("spaet", email="spaeter@example.com")
p9.clear()
a9.send_login_link("spaeter@example.com", BASIS)
r.check("Wechselanträge anderer auf die Adresse verbrauchen nicht das Kontingent des Anmelde-Links",
        [m[0] for m in p9] == ["spaeter@example.com"]
        and a9.store._one("SELECT 1 FROM audit WHERE event='mail_ratelimit' AND detail LIKE 'login%'") is None,
        str(p9))
# (Mutationsproben: `_beleg_wahr` immer wahr → „FALSE“ rot; `offener_token` weg → „solange der
#  Link offen ist“ rot; die Tagesgrenze weg → „derselbe Tag“ rot; der Riegel für belegte Konten
#  weg → „belegte eigene Adresse“ rot; `federation_email_confirm` nicht beachtet → rot; der Topf
#  `wechsel` zurück auf `mail` → Kontingent rot; Vorgabe `ldap_email_trusted=True` → Vorgabe rot.
#  G12a: Kontingent wieder vor dem Versuch für einen Tag → (a)/(b) rot; Audit-Zeile
#  vor dem Versand → (b) rot; Prüfung in der Datenbank weg → (c) und „derselbe Tag" rot; Kontingent
#  nicht je Konto → „anderes Konto" rot. a1-02: Abweisung nicht in der Datenbank gezählt → (d) und
#  „Kontoseite gleich" rot; `konto=` nicht im Detail → ebenso; Frist nur ein Tag → „3 Tage" rot.)

sys.exit(r.done())
