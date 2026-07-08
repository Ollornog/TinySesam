"""LDAP/lldap-Backend: Passwort gegen einen Verzeichnis-Bind prüfen (Extra `[ldap]`, ldap3).

Zwei Modi:
- **Direkt-Bind** (`ldap_user_dn_template`, z.B. lldap `uid={username},ou=people,dc=…`): bindet direkt
  mit dem User-DN + Passwort und liest anschließend Attribute.
- **Search-then-Bind** (`ldap_bind_dn`/`ldap_bind_password` + `ldap_user_base`/`ldap_user_filter`):
  Service-Account sucht den User, dann Re-Bind mit dessen DN + Passwort.

Gibt bei Erfolg {username, email, name, groups} zurück, sonst None. Fehler/Bind-Fehler → None.
Benutzernamen werden für Filter/DN escaped (LDAP-Injection-Schutz).
"""
from __future__ import annotations


class LDAPClient:
    def __init__(self, cfg):
        self.cfg = cfg

    def _server(self):
        import ldap3
        return ldap3.Server(self.cfg.ldap_url, get_info=ldap3.NONE)

    def authenticate(self, username: str, password: str):
        if not username or not password:
            return None
        try:
            import ldap3
            from ldap3.utils.conv import escape_filter_chars
            from ldap3.utils.dn import escape_rdn
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
                                       password=cfg.ldap_bind_password or None, auto_bind=True)
                if cfg.ldap_start_tls:
                    svc.start_tls()
                flt = cfg.ldap_user_filter.format(username=escape_filter_chars(username))
                attrs = [a for a in (cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr) if a]
                svc.search(cfg.ldap_user_base, flt, attributes=attrs)
                if not svc.entries:
                    svc.unbind()
                    return None
                user_dn = svc.entries[0].entry_dn
                svc.unbind()
            # Re-Bind mit dem User-DN + Passwort → prüft das Passwort
            conn = ldap3.Connection(server, user=user_dn, password=password)
            if cfg.ldap_start_tls:
                conn.start_tls()
            if not conn.bind():
                return None
            attrs = [a for a in (cfg.ldap_attr_email, cfg.ldap_attr_name, cfg.ldap_group_attr) if a]
            conn.search(user_dn, "(objectClass=*)", search_scope=ldap3.BASE, attributes=attrs)
            entry = conn.entries[0] if conn.entries else None
            info = {"username": username, "email": None, "name": username, "groups": []}
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
