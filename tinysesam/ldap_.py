"""LDAP/lldap-Backend: Passwort gegen einen Verzeichnis-Bind prüfen (Extra `[ldap]`, ldap3).

Zwei Modi:
- **Direkt-Bind** (`ldap_user_dn_template`, z.B. lldap `uid={username},ou=people,dc=…`): bindet direkt
  mit dem User-DN + Passwort und liest anschließend Attribute.
- **Search-then-Bind** (`ldap_bind_dn`/`ldap_bind_password` + `ldap_user_base`/`ldap_user_filter`):
  Service-Account sucht den User, dann Re-Bind mit dessen DN + Passwort.

Gibt bei Erfolg {username, email, name, groups} zurück, sonst None. Fehler/Bind-Fehler → None.
Benutzernamen werden für Filter/DN escaped (LDAP-Injection-Schutz). **Verweisen (Referrals) folgt
dieses Modul nie** — sonst bindet ldap3 auf dem verwiesenen Host mit denselben Zugangsdaten
(s. `_OHNE_REFERRALS`). Ein verworfener Verweis wird ins Sicherheits-Log geschrieben
(`_verweis_melden`), damit der Betrieb den Grund der Abweisung sieht und nicht bloß
„Passwort falsch" für jeden Nutzer.
"""
from __future__ import annotations


from . import errors
from .security import fuer_log, seclog


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Aus einem nackten Importfehler eine Meldung machen, die sagt, was zu tun ist.

    Die Extras werden hier bewusst LAZY importiert (erst beim Benutzen). Der Preis dafür war
    bis 0.18.0 ein `ModuleNotFoundError: ldap3` mitten im Anmeldevorgang — für den Betreiber
    ein Defekt, dabei fehlte nur eine Zeile im Install-Befehl."""
    return errors.MissingExtra(
        "Das Extra [ldap] ist nicht installiert (pip install 'tinysesam[ldap]') — "
        f"es fehlt: {e.name or 'ldap3'}.", extra="ldap")


#: Referrals NICHT verfolgen — auf JEDER Verbindung, die dieses Modul aufmacht.
#:
#: ldap3 folgt einem Verweis (`SearchResultDone resultCode=10`) von sich aus und baut dazu eine
#: neue Verbindung zu dem Host auf, den die ANTWORT nennt — mit denselben Zugangsdaten
#: (`create_referral_connection` reicht `user`/`password` der Connection weiter). Damit genügt
#: eine eingeschobene oder von einem übernommenen Verzeichnis gesetzte Referral, um DN und
#: Passwort des Dienstkontos an einen fremden Server zu schicken; auf der Benutzer-Verbindung
#: wäre es das Passwort des Anmeldenden. Nachgestellt mit zwei LDAP-Servern auf Loopback: beim
#: fremden Host kam der vollständige BindRequest samt Klartext-Passwort an (Audit T-13, F-28).
#:
#: Bewusst hart und ohne Schalter: Ein Verweis, dem man mit Zugangsdaten folgt, ist kein
#: Betriebsmodus, den ein Konfigurationsfeld zurückholen sollte. Wer über mehrere AD-Domänen
#: suchen muss, fragt den Global Catalog (Port 3268/3269) ab, statt Verweisen zu folgen.
#: Ohne Verfolgung endet die Suche ergebnislos → `authenticate()` gibt `None` zurück (fail-closed).
#: Damit das nicht stumm passiert, meldet `_verweis_melden()` den Fall im Sicherheits-Log.
_OHNE_REFERRALS = {"auto_referrals": False}


def _verweis_melden(conn, was: str, username: str) -> None:
    """Eine Suche, die das Verzeichnis mit einem VERWEIS beantwortet hat, ins Sicherheits-Log
    schreiben — sonst endet der Login stumm als „Passwort falsch".

    Ohne diese Zeile war der Preis des F-28-Fixes unsichtbar: Wer über mehrere AD-Domänen sucht,
    bekam nach dem Update für **jeden** Nutzer eine Abweisung und nichts, was auf die Ursache
    zeigt (der Global-Catalog-Hinweis stand nur im Quelltext). Gemeldet wird nur der
    Verweis-Fall; eine gewöhnlich leere Suche (Konto gibt es nicht) ist keine Auffälligkeit
    und würde das Log fluten.

    Die Verweis-Adresse kommt aus einer FREMDEN Antwort und geht deshalb durch `fuer_log` —
    ein Zeilenumbruch darin wäre eine zusätzliche, frei erfundene Zeile in genau dem Log, das
    fail2ban liest (dieselbe Falle wie beim Benutzernamen).
    """
    try:
        ergebnis = getattr(conn, "result", None) or {}
        verweise = ergebnis.get("referrals") or []
        code = ergebnis.get("result")
    except Exception:            # fremdes/unerwartetes Connection-Objekt — nie den Login stören
        return
    if not verweise and code != 10:
        return
    seclog.warning(
        "LDAP: %s für user=%s endete mit einem VERWEIS (referral) auf %s — dem folgt TinySesam "
        "bewusst nicht (sonst ginge das Passwort an den verwiesenen Host, Fund F-28). Die "
        "Anmeldung scheitert deshalb, obwohl das Konto existieren kann. Wer über mehrere "
        "AD-Domänen sucht, fragt den Global Catalog ab (Port 3268/3269) und setzt "
        "ldap_user_base auf die Wurzel.",
        was, fuer_log(username),
        ", ".join(fuer_log(v) for v in verweise[:3]) or "(Host nicht genannt)")


class LDAPClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _server(self):
        try:
            import ldap3
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        # `allowed_referral_hosts=[]` ist das zweite Schloss gegen die Referral-Falle (s.
        # `_OHNE_REFERRALS`): ldap3 vergibt hier per Vorgabe `[('*', True)]` — „jeder Host, und
        # zwar mit Zugangsdaten". Selbst wenn irgendwann jemand eine Connection ohne
        # `auto_referrals=False` anlegt, findet ldap3 dann keinen erlaubten Verweis-Host mehr.
        return ldap3.Server(self.cfg.ldap_url, get_info=ldap3.NONE, allowed_referral_hosts=[])

    def authenticate(self, username: str, password: str):
        if not username or not password:
            return None
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
            from ldap3.utils.dn import escape_rdn
        except ModuleNotFoundError as e:
            # NICHT verschlucken. Diese Stelle ist der Weg, den ein Login nimmt: Ohne `ldap3`
            # gab `authenticate()` einfach `None` zurück, die App antwortete 401, und das sah
            # aus wie ein falsches Passwort. Der Betreiber sucht dann tagelang am falschen Ende
            # — während anderswo (`_server()`) korrekt ein `MissingExtra` flog.
            raise _fehlt_extra(e) from e
        except Exception:
            return None
        cfg = self.cfg
        server = self._server()
        try:
            if cfg.ldap_user_dn_template:
                user_dn = cfg.ldap_user_dn_template.format(username=escape_rdn(username))
            else:
                # Search-then-Bind: erst mit Service-Account suchen
                svc = ldap3.Connection(server, user=cfg.ldap_bind_dn or None,
                                       password=cfg.ldap_bind_password or None, auto_bind=True,
                                       **_OHNE_REFERRALS)
                if cfg.ldap_start_tls:
                    svc.start_tls()
                flt = cfg.ldap_user_filter.format(username=escape_filter_chars(username))
                attrs = [a for a in (cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr) if a]
                svc.search(cfg.ldap_user_base, flt, attributes=attrs)
                if not svc.entries:
                    _verweis_melden(svc, "die Benutzersuche", username)
                    svc.unbind()
                    return None
                user_dn = svc.entries[0].entry_dn
                svc.unbind()
            # Re-Bind mit dem User-DN + Passwort → prüft das Passwort
            conn = ldap3.Connection(server, user=user_dn, password=password,
                                    **_OHNE_REFERRALS)
            if cfg.ldap_start_tls:
                conn.start_tls()
            if not conn.bind():
                return None
            attrs = [a for a in (cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr) if a]
            conn.search(user_dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            entry = conn.entries[0] if conn.entries else None
            if entry is None:
                # Auch hier: Ein Verweis auf der Attribut-Suche lässt E-Mail, Name und Gruppen
                # fehlen — mit ldap_allowed_groups ist das eine Abweisung ohne erkennbaren Grund.
                _verweis_melden(conn, "die Attribut-Suche", username)
            info: dict = {"username": username, "email": None, "name": username, "groups": []}
            if entry is not None:
                info["email"] = _first(entry, cfg.ldap_attr_email)
                info["name"] = _first(entry, cfg.ldap_attr_name) or username
                info["groups"] = _list(entry, cfg.ldap_group_attr)
            conn.unbind()
            return info
        except Exception:
            return None


def _first(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return None
    if isinstance(v, (list, tuple)):
        return v[0] if v else None
    return v


def _list(entry, attr):
    try:
        v = entry[attr].value if attr in entry else None
    except Exception:
        return []
    if v is None:
        return []
    return list(v) if isinstance(v, (list, tuple)) else [v]
