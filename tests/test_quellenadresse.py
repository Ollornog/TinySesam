"""Adressen aus LDAP und SAML (PO-Entscheid 2026-09-25).

Vorgabe „nicht vertraut": Die Adresse aus der Quelle kommt nicht direkt ins Konto. Der Normalweg
ist der Bestätigungslink — derselbe wie beim Adresswechsel der Selbstbedienung. Ein Attribut der
Quelle kann die Adresse DIESES Logins belegen (für IdPs, die das führen), der pauschale Schalter
bleibt für gepflegte Quellen. Gemessen wird die Wirkung: was im Konto steht, welche Mail an wen
geht, und die Riegel gegen Belästigung (offener Link, einmal am Tag, belegte Adresse bleibt) und
gegen Aussperrung über das gemeinsame Mail-Kontingent.
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
from tinysesam import security  # noqa: E402
from tinysesam import konfigpruefung as _kp  # noqa: E402
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
# (ein Link lebt bis zu sieben Tage, `email_change_ttl_min`).
auth.rl = security.RateLimiter()
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

# Tagesgrenze: Link abgelaufen (weg), am selben Tag trotzdem kein zweiter.
auth2, _, post2 = _aufbau()
u2 = _anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
auth2.store._exec("DELETE FROM magic_token")
post2.clear()
_anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("Link verfallen, derselbe Tag: kein zweiter Link (höchstens einer am Tag)", post2 == [], str(post2))
auth2.rl = security.RateLimiter()          # „ein Tag später"
_anmelden(auth2, "cleo", {"email": "cleo@example.com", "id": "uuid-cleo"})
r.check("… am nächsten Tag wieder einer", [m[0] for m in post2] == ["cleo@example.com"], str(post2))

# Ein Konto mit belegter Adresse behält sie — auch eine andere als die der Quelle.
auth3, _, post3 = _aufbau()
u3 = _anmelden(auth3, "dana", {"email": "dana@example.com", "id": "uuid-dana"})
auth3.store.set_email(u3["id"], "dana.privat@example.com", verified=True)
auth3.rl = security.RateLimiter()
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

# ── Kontingent: Wechselanträge auf eine Adresse sperren deren späteren Inhaber nicht aus ─────
# Eine vergebene Adresse erreicht die Drossel gar nicht (kein Link, nur Audit). Offen ist die noch
# FREIE: Ein Fremder beantragt den Wechsel darauf, bis ihr Kontingent aufgebraucht ist; registriert
# sich der Inhaber gleich danach, käme sein Anmelde-Link im selben Topf nicht mehr an.
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
#  `wechsel` zurück auf `mail` → Kontingent rot; Vorgabe `ldap_email_trusted=True` → Vorgabe rot.)

sys.exit(r.done())
