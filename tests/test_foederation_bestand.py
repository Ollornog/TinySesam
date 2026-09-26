"""Bindung über den Namen: Frist, Bestandsbindung, selbst gewählte Namen (G1, G2-N aus T-13).

Konten aus der Zeit vor den Kennungen (F-11) binden sich bei der nächsten Anmeldung über LDAP/SAML
über ihren Namen (Lage 4). Bis 2026-09-26 ohne jede Grenze: Ein ruhendes Konto — jemand ist
ausgeschieden — fiel samt Admin-Recht an die nächste Person, die im Verzeichnis denselben Namen
bekommt (G1). Und ein lokales Konto, das sich selbst nach jemandem aus dem Verzeichnis benannte,
bekam bei dessen Anmeldung Kennung und Gruppen (G2-N).

Gemessen wird die Wirkung: wer nach einer Anmeldung in welchem Konto landet, welche Bindung steht,
welche Rolle das Konto trägt, was im Audit- und Sicherheits-Log steht — dazu die Bestandsbindung
(`foederation_nachbinden`) mit einer Attrappe und gegen ldap3 (MOCK_SYNC), die Startmeldung und
der Nachtrag für den Bestand.
"""
from __future__ import annotations

import io
import logging
import os
import re
import sqlite3
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
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.ldap_ import LDAPClient, VerzeichnisNichtErreichbar  # noqa: E402
from tinysesam.security import seclog  # noqa: E402
from tinysesam.store import SCHEMA, Store, jetzt  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Bindung über den Namen — Frist, Bestandsbindung, selbst gewählte Namen (G1, G2-N)")
TAG = 86400
PW = "Kiefer-Spur-478"


class Mitschnitt:
    """Das Sicherheits-Log mitschneiden (ohne Zeitstempel)."""

    def __enter__(self):
        self.puffer = io.StringIO()
        self.haken = logging.StreamHandler(self.puffer)
        self.haken.setFormatter(logging.Formatter("%(levelname)s %(message)s"))
        seclog.addHandler(self.haken)
        return self

    def __exit__(self, *_):
        seclog.removeHandler(self.haken)

    def zeilen(self, wort=""):
        return [z for z in self.puffer.getvalue().splitlines() if wort in z]


class Verzeichnis:
    """Attrappe des LDAP-Clients: `authenticate` nach erfolgreichem Bind, `eintrag_suchen` wie die
    Bestandssuche (Liste der Treffer). Ein Wert als Liste = mehrere Einträge unter dem Namen."""

    def __init__(self, eintraege=None, ausfall_bei=None):
        self.eintraege = eintraege or {}
        self.ausfall_bei = ausfall_bei
        self.gefragt: list = []

    @staticmethod
    def _info(name, e):
        return {"username": name, "email": e.get("email"), "name": e.get("name", name),
                "groups": e.get("groups", []), "id": e.get("id")}

    def authenticate(self, username, password):
        e = self.eintraege.get(username)
        if not e or isinstance(e, list) or e.get("pw", "pw") != password:
            return None
        return self._info(username, e)

    def eintrag_suchen(self, username):
        self.gefragt.append(username)
        if username == self.ausfall_bei:
            raise VerzeichnisNichtErreichbar("Attrappe: Verzeichnis weg")
        e = self.eintraege.get(username)
        if e is None:
            return []
        return [self._info(username, x) for x in (e if isinstance(e, list) else [e])]


def _db():
    return str(Path(tempfile.mkdtemp()) / "t.db")


def _ldap(db=None, **cfg):
    grund = dict(db_path=db or _db(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 lang="de", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
                 ldap_allow_plaintext=True, ldap_auto_create=True,
                 ldap_group_role_map={"cn=chefs": "chef"})
    grund.update(cfg)
    return TinySesam(TinySesamConfig(**grund))


def _saml(db=None, **cfg):
    grund = dict(db_path=db or _db(), cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
                 lang="de", base_url="https://app.example.com", saml_enabled=True,
                 saml_attr_username="uid", saml_auto_create=True)
    grund.update(cfg)
    return TinySesam(TinySesamConfig(**grund))


def _altern(auth, *uids, quelle="ldap", tage=31):
    """Die Frist ist vorbei: Merker der Quelle `tage` zurück, die Konten zwei Jahre alt."""
    auth.store._exec("INSERT OR REPLACE INTO setting(key, value) VALUES (?, ?)",
                     (f"foederation_seit:{quelle}", str(jetzt() - tage * TAG)))
    for uid in uids:
        auth.store._exec("UPDATE users SET created_at=? WHERE id=?", (jetzt() - 730 * TAG, uid))


def _audit(auth, event):
    return [dict(z) for z in auth.store._all("SELECT * FROM audit WHERE event=? ORDER BY id", (event,))]


def _flag(auth, uid):
    return auth.store._one("SELECT name_selbst_gewaehlt AS f FROM users WHERE id=?", (uid,))["f"]


def _anmelden(auth, name, eintrag, pw="pw"):
    auth.ldap = Verzeichnis({name: dict(eintrag, pw=pw)})
    return auth.check_ldap(name, pw)


# ══ G1: Frist für die Bindung über den Namen ═══════════════════════════════════════════════════
a = _ldap()
r.check("Vorgabe: federation_name_binding_days = 30", a.cfg.federation_name_binding_days == 30)
r.check("Der Merker der Quelle steht schon nach dem Aufbau (ldap_enabled), SAML ohne Schalter nicht",
        a.store.get_setting("foederation_seit:ldap") is not None
        and a.store.get_setting("foederation_seit:saml") is None)

# (1) Ruhendes Konto mit Admin-Recht, Frist vorbei, neuer Eintrag mit fremder Kennung.
js = a.create_user("jsmith", is_admin=True)
_altern(a, js)
with Mitschnitt() as log:
    u = _anmelden(a, "jsmith", {"id": "uuid-neu", "groups": ["cn=chefs"]})
zu = _audit(a, "ldap_namensbindung_zu")
r.check("Frist vorbei: der neue jsmith aus dem Verzeichnis übernimmt das ruhende Konto NICHT",
        u is None and a.store.get_federated_kennung("ldap", js) is None, str(u))
r.check("… das Konto behält Admin-Recht und bekommt keine Rolle aus dem Verzeichnis",
        a.get_user(js)["is_admin"] == 1 and a.user_roles(a.store.get_user(js)) == [])
r.check("… Audit `ldap_namensbindung_zu` mit Grund und Kennung",
        len(zu) == 1 and zu[0]["username"] == "jsmith" and zu[0]["detail"] == "grund=frist kennung=uuid-neu",
        str(zu))
r.check("… die Logzeile nennt Kennung und Abhilfe (loese_fremde_bindung, foederation_nachbinden)",
        any("uuid-neu" in z and f"loese_fremde_bindung('ldap', {js})" in z
            and "foederation_nachbinden('ldap')" in z for z in log.zeilen("jsmith")), log.puffer.getvalue()[-600:])

# (4) Der Betreiber öffnet die Bindung ausdrücklich — die nächste Anmeldung bindet.
weg = a.loese_fremde_bindung("ldap", js)
offen = a.store._one("SELECT bis FROM namensbindung WHERE quelle='ldap' AND user_id=?", (js,))
r.check("loese_fremde_bindung auf ein ungebundenes Konto: 0 gelöst, Bindung über den Namen geöffnet",
        weg == 0 and offen is not None and offen["bis"] > jetzt() + 29 * TAG, str(offen and dict(offen)))
u = _anmelden(a, "jsmith", {"id": "uuid-neu"})
r.check("… danach bindet die nächste Anmeldung über den Namen, auch nach der Frist",
        u is not None and u["id"] == js and a.store.get_federated_kennung("ldap", js) == "uuid-neu")
r.check("… und die Öffnung ist verbraucht (Zeile weg)",
        a.store._one("SELECT 1 AS x FROM namensbindung WHERE user_id=?", (js,)) is None)
u = _anmelden(a, "jsmith", {"id": "uuid-dritter"})
r.check("… eine weitere fremde Kennung unter dem Namen bleibt draussen (Lage 3, Tür wieder zu)",
        u is None and a.store.get_federated_kennung("ldap", js) == "uuid-neu")

# (1b) Ersatz eines Herkunfts-Platzhalters nach der Frist.
kai = a.create_user("kai")
a.store.link_federated("ldap", f"{Store.OHNE_KENNUNG}{kai}", kai, jetzt())
_altern(a, kai)
u = _anmelden(a, "kai", {"id": "uuid-kai-neu"})
r.check("Platzhalter nach der Frist: keine neue Kennung, der Platzhalter bleibt stehen",
        u is None and a.store.get_federated_kennung("ldap", kai) == f"{Store.OHNE_KENNUNG}{kai}",
        str(a.store.get_federated_kennung("ldap", kai)))

# (2) Vorab-Anlage: frisch angelegtes Konto, Frist der Quelle längst vorbei — eigene Frist ab Anlage.
vera = a.create_user("vera")
u = _anmelden(a, "vera", {"id": "uuid-vera"})
r.check("Vorab-Anlage im Panel (frisch): bindet über den Namen, auch wenn der Merker alt ist",
        u is not None and u["id"] == vera and a.store.get_federated_kennung("ldap", vera) == "uuid-vera")

# (2b) Gegenprobe Bestand innerhalb der Frist: altes Konto, frischer Merker.
b = _ldap()
alt = b.create_user("altbestand")
b.store._exec("UPDATE users SET created_at=? WHERE id=?", (jetzt() - 730 * TAG, alt))
u = _anmelden(b, "altbestand", {"id": "uuid-alt"})
r.check("Bestandskonto (ohne Passwort, nicht selbst benannt) in der Frist: bindet weiter nach",
        u is not None and u["id"] == alt and _audit(b, "ldap_kennung_gebunden")[-1]["detail"]
        == "nachgebunden beim Login")

# (3) -1 = alter Stand, 0 = nur ausdrücklich, -2 = Aufbaufehler.
c1 = _ldap(federation_name_binding_days=-1)
x = c1.create_user("xaver")
_altern(c1, x, tage=4000)
u = _anmelden(c1, "xaver", {"id": "uuid-x"})
r.check("federation_name_binding_days=-1: bindet unbegrenzt (Verhalten bis 0.20.x)",
        u is not None and u["id"] == x)
c0 = _ldap(federation_name_binding_days=0)
y = c0.create_user("yara")
u = _anmelden(c0, "yara", {"id": "uuid-y"})
r.check("federation_name_binding_days=0: auch ein frisches Konto bindet sich nicht selbst",
        u is None and c0.store.get_federated_kennung("ldap", y) is None)
c0.loese_fremde_bindung("ldap", y)
u = _anmelden(c0, "yara", {"id": "uuid-y"})
r.check("… nur ausdrücklich (loese_fremde_bindung öffnet für mindestens einen Tag)",
        u is not None and u["id"] == y)
try:
    _ldap(federation_name_binding_days=-2)
    _wirft = False
except ConfigError as e:
    _wirft = "federation_name_binding_days" in str(e)
r.check("federation_name_binding_days=-2: ConfigError beim Aufbau", _wirft)

# (5) Der Merker entsteht genau einmal — auch über einen Neustart.
pfad = _db()
m1 = _ldap(pfad)
_altern(m1, tage=40)
vorher = m1.store.get_setting("foederation_seit:ldap")
m1.store.db.close()
m2 = _ldap(pfad)
r.check("Merker einmalig: ein zweiter Start setzt ihn nicht neu (sonst schenkte jeder Neustart eine Frist)",
        m2.store.get_setting("foederation_seit:ldap") == vorher, f"{vorher} → {m2.store.get_setting('foederation_seit:ldap')}")

# (1c) SAML: dasselbe über die NameID.
s = _saml()
r.check("SAML: der Merker steht nach dem Aufbau", s.store.get_setting("foederation_seit:saml") is not None)
sam = s.create_user("sam", is_admin=True)
_altern(s, sam, quelle="saml")
u = s.check_saml("nid-neu", {"uid": ["sam"]})
r.check("SAML nach der Frist: eine neue NameID unter dem Namen übernimmt das ruhende Konto nicht",
        u is None and s.store.get_federated_kennung("saml", sam) is None
        and [z["detail"] for z in _audit(s, "saml_namensbindung_zu")] == ["grund=frist kennung=nid-neu"])
sina = s.create_user("sina")
u = s.check_saml("nid-sina", {"uid": ["sina"]})
r.check("SAML Vorab-Anlage: bindet", u is not None and u["id"] == sina)

# (10) Ohne Kennung: die ERSTE Zuordnung eines vorhandenen Kontos geht durch dieselbe Tür.
n = _ldap()
otto = n.create_user("otto")
_altern(n, otto)
u = _anmelden(n, "otto", {})
r.check("Ohne Kennung, Frist vorbei: das vorhandene Konto wird nicht über den Namen zugeordnet",
        u is None and n.store.get_federated_kennung("ldap", otto) is None)
pia = n.create_user("pia")
u = _anmelden(n, "pia", {})
r.check("Ohne Kennung, frisches Konto: zugeordnet, Herkunft festgehalten",
        u is not None and u["id"] == pia
        and n.store.get_federated_kennung("ldap", pia) == f"{Store.OHNE_KENNUNG}{pia}")
_altern(n, pia)
u = _anmelden(n, "pia", {})
r.check("… ein Konto, das die Quelle schon kennt (Platzhalter), meldet sich nach der Frist weiter an",
        u is not None and u["id"] == pia)

# ══ G2-N: selbst gewählte Namen binden nie über den Namen ══════════════════════════════════════
# Der Befund als Test: `eve` benennt sich in `chefin` um, einen Namen, den es nur im Verzeichnis gibt.
g = _ldap()
eve = g.create_user("eve", password=PW)
r.check("Vom Betreiber angelegtes Konto: Merker 0", _flag(g, eve) == 0)
g.change_username(eve, "chefin")
r.check("Selbst umbenannt (change_username): Merker 1", _flag(g, eve) == 1)
with Mitschnitt() as log:
    u = _anmelden(g, "chefin", {"id": "uuid-chefin", "groups": ["cn=chefs"]}, pw="ldap-pw")
zu = _audit(g, "ldap_namensbindung_zu")
r.check("PoC: die echte chefin aus dem Verzeichnis landet NICHT in eves Konto, keine Bindung",
        u is None and g.store.get_federated_kennung("ldap", eve) is None, str(u))
r.check("… eve hat danach keine Rolle `chef`, auch nicht über ihr lokales Passwort",
        g.check_password("chefin", PW) is not None
        and "chef" not in g.user_roles(g.store.get_user(eve)))
r.check("… Abweisung wie Lage 3: Audit mit Grund und Kennung, Logzeile mit dem Weg",
        [z["detail"] for z in zu] == ["grund=name_selbst_gewaehlt kennung=uuid-chefin"]
        and any("uuid-chefin" in z and f"loese_fremde_bindung('ldap', {eve})" in z
                for z in log.zeilen("selbst gewählt")), str(zu))
g.loese_fremde_bindung("ldap", eve)
u = _anmelden(g, "chefin", {"id": "uuid-chefin"}, pw="ldap-pw")
r.check("Der Betreiber entscheidet ausdrücklich (loese_fremde_bindung): dann bindet es",
        u is not None and u["id"] == eve)

# Umbenennen durch den Betreiber: der Name steht für den Betreiber.
op = g.create_user("olaf", password=PW)
g.change_username(op, "olga")
g.change_username(op, "oskar", durch_betreiber=True)
u = _anmelden(g, "oskar", {"id": "uuid-oskar"})
r.check("Umbenannt durch den Betreiber (durch_betreiber=True): Merker 0, bindet",
        _flag(g, op) == 0 and u is not None and u["id"] == op)
r.check("… die Audit-Zeile sagt durch=betreiber",
        _audit(g, "username_changed")[-1]["detail"] == "alt=olga durch=betreiber")

# SAML und ohne Kennung: dieselbe Regel.
s2 = _saml()
sv = s2.create_user("svenja", password=PW)
s2.change_username(sv, "saskia")
u = s2.check_saml("nid-saskia", {"uid": ["saskia"]})
r.check("SAML: ein selbst umbenanntes Konto wird nicht über den Namen gebunden",
        u is None and s2.store.get_federated_kennung("saml", sv) is None)
n2 = _ldap()
nv = n2.create_user("nora", password=PW)
n2.change_username(nv, "nele")
u = _anmelden(n2, "nele", {})
r.check("LDAP ohne Kennung: ein selbst umbenanntes Konto wird nicht über den Namen zugeordnet",
        u is None and n2.store.get_federated_kennung("ldap", nv) is None)

# Registrierung (allow_signup) und Umbenennen über die Konto-Seite.
reg = _ldap(allow_signup=True, signup_verify_email=False, base_url="http://testserver")
app = FastAPI()
app.include_router(reg.router())
c = TestClient(app)
antwort = c.post("/auth/register", data={"username": "chefin", "password": PW,
                                         "email": "chefin.privat@example.com"}, follow_redirects=False)
rid = reg.store.get_user_by_name("chefin")
r.check("Registrierung: das Konto trägt den Merker",
        antwort.status_code in (200, 303) and rid is not None and _flag(reg, rid["id"]) == 1,
        f"HTTP {antwort.status_code}")
u = _anmelden(reg, "chefin", {"id": "uuid-chefin", "groups": ["cn=chefs"]}, pw="ldap-pw")
r.check("… die Verzeichnis-chefin übernimmt das registrierte Konto nicht",
        u is None and reg.store.get_federated_kennung("ldap", rid["id"]) is None)
ks = reg.create_user("konrad", password=PW)
c2 = TestClient(app)
c2.post("/auth/login", data={"username": "konrad", "password": PW}, follow_redirects=False)
antwort = c2.post("/auth/account/username", json={"username": "karla"})
r.check("Umbenennen über die Konto-Seite (/auth/account/username): Merker 1",
        antwort.status_code == 200 and _flag(reg, ks) == 1, f"HTTP {antwort.status_code} {antwort.text[:120]}")

# ══ Der gemeinsame Entscheid: Name = unbelegter mail-Wert ══════════════════════════════════════
# Anmeldung und Bestandsbindung fragen denselben Helfer (`_ldap_name_belegt`) — die Bestandsbindung
# steht unten (gina); hier die Anmeldung: Ist der eingetippte Name der unbelegte `mail`-Wert des
# Eintrags, wird das gleichnamige lokale Konto nicht zugeordnet.
ge = _ldap()
gl = ge.create_user("gerda")
u = _anmelden(ge, "gerda", {"id": "u-gerda", "email": "gerda"})
r.check("Anmeldung: Name = unbelegter mail-Wert → kein Zugriff auf das gleichnamige lokale Konto",
        u is not None and u["id"] != gl and ge.store.get_federated_kennung("ldap", gl) is None
        and u["username"].startswith("ldap-"), str(u and u["username"]))

# ══ Bestandsbindung: foederation_nachbinden ════════════════════════════════════════════════════
m = _ldap()
ids = {n: m.create_user(n) for n in ("anna", "bert", "cara", "dora", "emil", "fritz", "gina", "ida",
                                      "jo", "kim", "lea")}
ids["hans"] = m.create_user("hans", password=PW)
ids["ina"] = m.create_user("ina", name_selbst_gewaehlt=True)
m.create_service("dienst")
m.store.link_federated("ldap", "u-fritz", ids["fritz"], jetzt())
m.store.link_federated("ldap", f"{Store.OHNE_KENNUNG}{ids['lea']}", ids["lea"], jetzt())
m.store.set_disabled(ids["jo"], True, durch_betreiber=True)
_altern(m, ids["kim"])          # Frist vorbei — die Bestandsbindung ist der ausdrückliche Weg
vz = Verzeichnis({
    "anna": {"id": "u-anna", "name": "Anna A.", "email": "anna@example.com"},
    "cara": {},                                                   # Eintrag ohne stabile Kennung
    "dora": [{"id": "u-dora-1"}, {"id": "u-dora-2"}],               # zwei Einträge
    "emil": {"id": "u-fritz"},                                     # Kennung gehört fritz
    "gina": {"id": "u-gina", "email": "gina"},                      # Name = unbelegter mail-Wert
    "hans": {"id": "u-hans"}, "ina": {"id": "u-ina"}, "jo": {"id": "u-jo"},
    "kim": {"id": "u-kim"}, "lea": {"id": "u-lea"}, "ida": {"id": "u-ida"},
})
m.ldap = vz


def _namen(bericht, teil):
    return sorted(e["username"] for e in bericht[teil])


def _gebunden(auth):
    return {z["user_id"]: z["kennung"] for z in auth.store._all("SELECT * FROM federated_identity")}


vorher = _gebunden(m)
tr = m.foederation_nachbinden("ldap")
r.check("Trockenlauf (Vorgabe): nichts geschrieben", _gebunden(m) == vorher and tr["ausgefuehrt"] is False
        and not _audit(m, "ldap_kennung_gebunden"))
r.check("… meldet, was gebunden würde (auch nach der Frist und den Platzhalter)",
        _namen(tr, "gebunden") == ["anna", "ida", "kim", "lea"], str(_namen(tr, "gebunden")))
anna = next(e for e in tr["gebunden"] if e["username"] == "anna")
r.check("… mit Anzeigename und Adresse hier und im Verzeichnis nebeneinander",
        anna["verzeichnis"] == {"name": "Anna A.", "email": "anna@example.com"}
        and anna["lokal"]["name"] == "anna" and anna["kennung"] == "u-anna", str(anna))
r.check("… Konflikt (Kennung gehört einem anderen Konto) mit dem Besitzer",
        [(e["username"], e["gebunden_an"]) for e in tr["konflikt"]] == [("emil", ids["fritz"])], str(tr["konflikt"]))
r.check("… mehrdeutig, nicht im Verzeichnis, ohne Kennung",
        _namen(tr, "mehrdeutig") == ["dora"] and tr["mehrdeutig"][0]["treffer"] == 2
        and _namen(tr, "nicht_im_verzeichnis") == ["bert"] and _namen(tr, "ohne_kennung") == ["cara"])
r.check("… abgewiesen mit Grund: unbelegter mail-Wert als Name, selbst gewählt, gesperrt",
        sorted((e["username"], e["grund"]) for e in tr["abgewiesen"])
        == [("gina", "adresse_als_name"), ("ina", "name_selbst_gewaehlt"), ("jo", "gesperrt")],
        str(tr["abgewiesen"]))
r.check("… Konto mit lokalem Passwort nur berichtet; Service-Konten und gebundene gar nicht gefragt",
        _namen(tr, "lokal") == ["hans"] and "dienst" not in vz.gefragt and "fritz" not in vz.gefragt,
        str(vz.gefragt))
with Mitschnitt() as log:
    ab = m.foederation_nachbinden("ldap", ausfuehren=True)
jetzt_gebunden = _gebunden(m)
r.check("ausfuehren=True: gebunden wie angekündigt, der Platzhalter ist ersetzt",
        all(jetzt_gebunden.get(ids[n]) == f"u-{n}" for n in ("anna", "ida", "kim", "lea"))
        and _namen(ab, "gebunden") == ["anna", "ida", "kim", "lea"], str(jetzt_gebunden))
r.check("… nichts sonst: keine Bindung für hans, ina, gina, emil, jo",
        all(ids[n] not in jetzt_gebunden for n in ("hans", "ina", "gina", "emil", "jo"))
        and jetzt_gebunden[ids["fritz"]] == "u-fritz")
r.check("… je Bindung Audit `ldap_kennung_gebunden detail=migration`, eine Summenzeile im Log",
        sorted(z["username"] for z in _audit(m, "ldap_kennung_gebunden") if z["detail"] == "migration")
        == ["anna", "ida", "kim", "lea"] and len(log.zeilen("foederation_nachbinden(ldap): 4 gebunden")) == 1,
        log.puffer.getvalue()[-400:])
u = _anmelden(m, "kim", {"id": "u-kim"})
r.check("… danach meldet sich das gebundene Konto an (Lage 1)", u is not None and u["id"] == ids["kim"])
r.check("Zweiter Lauf: die Gebundenen sind keine Kandidaten mehr",
        m.foederation_nachbinden("ldap")["gebunden"] == [])

# Ein Ausfall mitten im Lauf: nichts geschrieben.
w = _ldap()
w1, w2 = w.create_user("wim"), w.create_user("wolf")
w.ldap = Verzeichnis({"wim": {"id": "u-wim"}, "wolf": {"id": "u-wolf"}}, ausfall_bei="wolf")
try:
    w.foederation_nachbinden("ldap", ausfuehren=True)
    _abbruch = False
except VerzeichnisNichtErreichbar:
    _abbruch = True
r.check("Verzeichnis-Ausfall: der Lauf bricht ab, bevor irgendetwas gebunden ist",
        _abbruch and _gebunden(w) == {})

# Zuordnung (SAML aus einem Export des IdP).
z = _saml()
sara, tom, udo = z.create_user("sara"), z.create_user("tom"), z.create_user("udo")
zb = z.create_user("zeno", name_selbst_gewaehlt=True)
z.store.link_federated("saml", "nid-udo", udo, jetzt())
leer = z.create_user("leer")
zr = z.foederation_nachbinden("saml", zuordnung={"sara": "nid-sara", "tom": "nid-udo", "niemand": "nid-x",
                                                 "zeno": "nid-zeno", "leer": ""}, ausfuehren=True)
r.check("SAML mit zuordnung: bindet, verweigert die Kennung eines anderen Kontos, meldet Unbekanntes",
        _gebunden(z).get(sara) == "nid-sara" and tom not in _gebunden(z) and leer not in _gebunden(z)
        and [e["username"] for e in zr["konflikt"]] == ["tom"] and _namen(zr, "ohne_kennung") == ["leer"]
        and sorted((e["username"], e["grund"]) for e in zr["abgewiesen"])
        == [("niemand", "kein_konto"), ("zeno", "name_selbst_gewaehlt")], str(zr))
u = z.check_saml("nid-sara", {"uid": ["sara"]})
r.check("… danach meldet sich sara über die NameID an", u is not None and u["id"] == sara)
zd = _saml()
d1, d2 = zd.create_user("doppel1"), zd.create_user("doppel2")
zdr = zd.foederation_nachbinden("saml", zuordnung={"doppel1": "nid-d", "doppel2": "nid-d"}, ausfuehren=True)
r.check("Zuordnung mit Dublette (zwei Konten, eine Kennung): keines gebunden",
        _gebunden(zd) == {} and sorted(e["username"] for e in zdr["konflikt"]) == ["doppel1", "doppel2"])
try:
    zd.foederation_nachbinden("saml")
    _saml_ohne = False
except ValueError:
    _saml_ohne = True
fremd = _ldap()
fremd.ldap = type("NurAnmelden", (), {"authenticate": lambda self, u, p: None})()
try:
    fremd.foederation_nachbinden("ldap")
    _ohne_suche = False
except ConfigError:
    _ohne_suche = True
r.check("SAML ohne zuordnung → ValueError; ein Client ohne eintrag_suchen → ConfigError",
        _saml_ohne and _ohne_suche)

# Atomar gegen eine Anmeldung, die zwischen Prüfung und Schreiben gebunden hat.
st = _ldap()
k1, k2 = st.create_user("k1"), st.create_user("k2")
st.store.link_federated("ldap", "u-k", k1, jetzt())
r.check("Store.nachbinden nimmt keinem Konto seine Kennung weg (kein INSERT OR REPLACE)",
        st.store.nachbinden("ldap", "u-k", k2, jetzt()) is False and _gebunden(st) == {k1: "u-k"})
st.store.link_federated("ldap", "u-k2", k2, jetzt())
r.check("… und bindet kein Konto ein zweites Mal",
        st.store.nachbinden("ldap", "u-k2b", k2, jetzt()) is False
        and st.store.get_federated_user("ldap", "u-k2b") is None)

# ── Der echte Suchweg gegen ldap3 (MOCK_SYNC) ────────────────────────────────────────────────
import ldap3  # noqa: E402

GUID = bytes(range(16))
_srv = ldap3.Server("mock-verzeichnis", get_info=ldap3.NONE)
_fuell = ldap3.Connection(_srv, client_strategy=ldap3.MOCK_SYNC)
_fuell.strategy.add_entry("cn=svc,dc=example,dc=com", {"objectClass": "person", "userPassword": "svc-pw"})
_fuell.strategy.add_entry("uid=alice,ou=people,dc=example,dc=com",
                          {"objectClass": "person", "uid": "alice", "cn": "Alice A.",
                           "mail": "alice@example.com", "objectGUID": GUID, "userPassword": "pw-alice"})
_fuell.strategy.add_entry("uid=carl,ou=people,dc=example,dc=com",
                          {"objectClass": "person", "uid": "carl", "entryUUID": "e-carl"})
_fuell.strategy.add_entry("uid=bob,ou=people,dc=example,dc=com",
                          {"objectClass": "person", "uid": "bob", "entryUUID": "e-bob-1"})
_fuell.strategy.add_entry("uid=bob,ou=extern,ou=people,dc=example,dc=com",
                          {"objectClass": "person", "uid": "bob", "entryUUID": "e-bob-2"})
_Echt = ldap3.Connection


class _MockVerbindung(_Echt):
    """Jede Verbindung des Clients geht an das vorbereitete Verzeichnis im Speicher."""

    def __init__(self, server, *args, **kw):
        kw["client_strategy"] = ldap3.MOCK_SYNC
        auto = kw.pop("auto_bind", None)       # MOCK_SYNC bindet damit nicht von selbst
        super().__init__(_srv, *args, **kw)
        if auto not in (None, False, ldap3.AUTO_BIND_NONE):
            self.bind()


ldap3.Connection = _MockVerbindung
try:
    such = LDAPClient(TinySesamConfig(
        db_path=":memory:", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
        ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="svc-pw",
        ldap_user_base="ou=people,dc=example,dc=com", ldap_user_filter="(uid={username})"))
    t_alice, t_carl, t_bob, t_leer = (such.eintrag_suchen(x) for x in ("alice", "carl", "bob", "nobody"))
    r.check("ldap3: objectGUID (Bytes) kommt als Hex, dazu Name und Adresse",
            len(t_alice) == 1 and t_alice[0]["id"] == GUID.hex() and t_alice[0]["name"] == "Alice A."
            and t_alice[0]["email"] == "alice@example.com", str(t_alice))
    r.check("ldap3: entryUUID", [t["id"] for t in t_carl] == ["e-carl"], str(t_carl))
    r.check("ldap3: zwei Einträge unter dem Namen → beide (genau einer wird verlangt), keiner → leer",
            sorted(t["id"] for t in t_bob) == ["e-bob-1", "e-bob-2"] and t_leer == [], str(t_bob))
    tmpl = LDAPClient(TinySesamConfig(
        db_path=":memory:", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
        ldap_allow_plaintext=True, ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com"))
    r.check("ldap3 Direkt-Bind-Vorlage: BASE-Suche auf den gebauten DN (anonym), kein DN → leer",
            [t["id"] for t in tmpl.eintrag_suchen("carl")] == ["e-carl"] and tmpl.eintrag_suchen("nobody") == [])
    falsch = LDAPClient(TinySesamConfig(
        db_path=":memory:", ldap_enabled=True, ldap_url="ldap://verzeichnis.example.com",
        ldap_allow_plaintext=True, ldap_bind_dn="cn=svc,dc=example,dc=com", ldap_bind_password="falsch",
        ldap_user_base="ou=people,dc=example,dc=com"))
    try:
        falsch.eintrag_suchen("alice")
        _dienst = False
    except VerzeichnisNichtErreichbar:
        _dienst = True
    r.check("ldap3: ein abgewiesenes Dienstkonto ist ein Ausfall, kein „nicht im Verzeichnis“", _dienst)
    e2e = _ldap(ldap_url="ldap://verzeichnis.example.com", ldap_bind_dn="cn=svc,dc=example,dc=com",
                ldap_bind_password="svc-pw", ldap_user_base="ou=people,dc=example,dc=com")
    ea, eb = e2e.create_user("alice"), e2e.create_user("bob")
    eb_ber = e2e.foederation_nachbinden("ldap", ausfuehren=True)
    r.check("ldap3 von Anfang bis Ende: alice an ihre GUID gebunden, bob mehrdeutig",
            _gebunden(e2e) == {ea: GUID.hex()} and _namen(eb_ber, "mehrdeutig") == ["bob"], str(eb_ber))
    # Der Anmeldeweg liest die Kennung genauso (`authenticate` → `_stabile_kennung`): Eine GUID,
    # die zufällig gültiges UTF-8 ist, dekodierte ldap3 ohne Schema zu Text mit Steuerzeichen —
    # die Formprüfung wies sie ab, die Person kam über LDAP nie hinein.
    login = _ldap(ldap_url="ldap://verzeichnis.example.com", ldap_bind_dn="cn=svc,dc=example,dc=com",
                  ldap_bind_password="svc-pw", ldap_user_base="ou=people,dc=example,dc=com")
    ul = login.check_ldap("alice", "pw-alice")
    r.check("ldap3 Anmeldung: dieselbe GUID als Hex, das neue Konto ist an sie gebunden",
            ul is not None and login.store.get_federated_kennung("ldap", ul["id"]) == GUID.hex(),
            str(ul and login.store.get_federated_kennung("ldap", ul["id"])))
finally:
    ldap3.Connection = _Echt

# ══ Startmeldung ═══════════════════════════════════════════════════════════════════════════════
pfad = _db()
sm = _ldap(pfad)
a1, a2 = sm.create_user("a1"), sm.create_user("a2", password=PW)
sm.create_service("svc1")
b1, p1 = sm.create_user("b1"), sm.create_user("p1")
sm.store.link_federated("ldap", "u-b1", b1, jetzt())
sm.store.link_federated("ldap", f"{Store.OHNE_KENNUNG}{p1}", p1, jetzt())
sm.store.db.close()
with Mitschnitt() as log:
    sm = _ldap(pfad)
zeile = log.zeilen("ohne Bindung an eine Kennung")
r.check("Startmeldung: 3 Konten ohne Kennung (Service-Konto und gebundenes zählen nicht, der "
        "Platzhalter schon), davon 2 ohne lokales Passwort, mit dem Weg",
        len(zeile) == 1 and "LDAP: 3 Konto(en)" in zeile[0] and "davon 2 ohne lokales Passwort" in zeile[0]
        and "auth.foederation_nachbinden('ldap')" in zeile[0], str(zeile))
sm.ldap = Verzeichnis({"a1": {"id": "u-a1"}, "p1": {"id": "u-p1"}})
sm.foederation_nachbinden("ldap", ausfuehren=True)
sm.store._exec("DELETE FROM users WHERE id=?", (a2,))
sm.store.db.close()
with Mitschnitt() as log:
    sm = _ldap(pfad)
r.check("… nach der Bestandsbindung: keine Zeile mehr", not log.zeilen("ohne Bindung an eine Kennung"),
        str(log.zeilen("ohne Bindung")))
sm.create_user("spaet")
_altern(sm, tage=31)
sm.store.db.close()
with Mitschnitt() as log:
    sm = _ldap(pfad)
r.check("… nach der Frist schweigt sie (die Tür ist zu, jede Abweisung meldet sich selbst)",
        not log.zeilen("ohne Bindung an eine Kennung"))
pfad = _db()
ss = _saml(pfad)
ss.create_user("s1")
ss.store.db.close()
with Mitschnitt() as log:
    _saml(pfad)
r.check("SAML-Startmeldung nennt die zuordnung",
        any("SAML: 1 Konto(en)" in z and "zuordnung=" in z for z in log.zeilen("ohne Bindung")),
        str(log.zeilen("ohne Bindung")))

# ══ Bestand: Datei auf Schema 11 ohne Tabelle und Spalte, Merker aus dem Audit-Log ════════════
# Gebaut aus SCHEMA ohne die beiden Neuerungen (ein `DROP COLUMN` scheitert an den Kommentaren in
# der Tabellendefinition) — wie ein Stand von vor diesem Commit, Stempel 11.
_alt, _n1 = re.subn(r"(mail_audit_ab\s+INTEGER),\n.*?name_selbst_gewaehlt INTEGER NOT NULL DEFAULT 0\n",
                    r"\1\n", SCHEMA, flags=re.S)
_alt, _n2 = re.subn(r"CREATE TABLE IF NOT EXISTS namensbindung \(.*?\n\);\n", "", _alt, flags=re.S)
pfad = _db()
os.close(os.open(pfad, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600))
roh = sqlite3.connect(pfad)
roh.executescript(_alt)
jetzt_ = jetzt()
for name in ("sig", "ren", "alt", "op"):
    roh.execute("INSERT INTO users(username, created_at) VALUES (?, ?)", (name, jetzt_ - 10 * TAG))
for event, name, vor in (("signup", "sig", 9), ("username_changed", "ren", 5), ("signup", "alt", 400),
                         ("user_create", "op", 9), ("login", "op", 8)):
    roh.execute("INSERT INTO audit(ts, event, username) VALUES (?,?,?)", (jetzt_ - vor * TAG, event, name))
roh.execute("PRAGMA user_version = 11")
roh.commit()
_vorher_sp = {z[1] for z in roh.execute("PRAGMA table_info(users)")}
_vorher_tab = {z[0] for z in roh.execute("SELECT name FROM sqlite_master WHERE type='table'")}
roh.close()
r.check("Vorbedingung: Datei auf Stempel 11 ohne `namensbindung` und ohne `users.name_selbst_gewaehlt`",
        _n1 == 1 and _n2 == 1 and "name_selbst_gewaehlt" not in _vorher_sp
        and "namensbindung" not in _vorher_tab and "fehlserie" in _vorher_tab, f"{_n1}/{_n2}")
neu = _ldap(pfad)
tab = {z["name"] for z in neu.store._all("SELECT name FROM sqlite_master WHERE type='table'")}
fl = {z["username"]: z["name_selbst_gewaehlt"] for z in neu.store._all("SELECT * FROM users")}
r.check("Schema 11 ohne die Neuerungen: Tabelle und Spalte kommen dazu, der Stempel bleibt 11",
        "namensbindung" in tab and len(fl) == 4
        and int(neu.store.db.execute("PRAGMA user_version").fetchone()[0]) == 11 and Store.SCHEMA_VERSION == 11)
r.check("Bestand: Registrierte und selbst Umbenannte tragen den Merker, ein älterer Namensvetter und "
        "ein vom Betreiber angelegtes Konto nicht",
        fl == {"sig": 1, "ren": 1, "alt": 0, "op": 0}, str(fl))
u = _anmelden(neu, "sig", {"id": "u-sig"})
r.check("… und das nachgetragene Konto bindet nicht über den Namen", u is None)
neu.store._exec("INSERT INTO audit(ts, event, username) VALUES (?,?,?)", (jetzt(), "username_changed", "op"))
neu.store.db.close()
nochmal = _ldap(pfad)
r.check("Zweiter Start: idempotent, der Nachtrag läuft nicht noch einmal",
        nochmal.store._one("SELECT name_selbst_gewaehlt AS f FROM users WHERE username='op'")["f"] == 0
        and nochmal.store.get_setting(Store.NAME_SELBST_NACHGETRAGEN) is not None)
lo = nochmal.create_user("loesch")
nochmal.loese_fremde_bindung("ldap", lo)
nochmal.delete_user(lo)
r.check("Konto gelöscht: seine geöffnete Namensbindung geht mit",
        nochmal.store._one("SELECT COUNT(*) AS n FROM namensbindung")["n"] == 0)

# ══ Konfigurationsprüfung ═════════════════════════════════════════════════════════════════════
_, warn = _kp.pruefe(TinySesamConfig(db_path=":memory:", ldap_enabled=True, ldap_url="ldaps://v.example.com",
                                     federation_name_binding_days=-1))
_, warn_aus = _kp.pruefe(TinySesamConfig(db_path=":memory:", federation_name_binding_days=-1))
fehler, _ = _kp.pruefe(TinySesamConfig(db_path=":memory:", federation_name_binding_days=-2))
r.check("Konfigurationsprüfung: -1 mit LDAP warnt, ohne föderierte Quelle nicht, -2 ist ein Fehler",
        any("federation_name_binding_days=-1" in w for w in warn)
        and not any("federation_name_binding_days" in w for w in warn_aus)
        and any("federation_name_binding_days=-2" in f for f in fehler), str(warn))

sys.exit(r.done())
