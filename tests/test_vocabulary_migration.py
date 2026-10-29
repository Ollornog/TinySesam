"""The key vocabulary in English (schema 15): migration of a real old database, idempotence, free text, read paths.

PO decision 2026-10-29: the audit log (`audit.event`, `audit.detail`, `audit.username`) and the kinds of the
failed-attempt streak (`fehlserie.art`, `login_attempt.method`) carried German event names, `key=value` keys and
tokens up to 0.24.x (`grund=kein_konto`, `oidc_widerruf`, `gelöscht#<id>`). Schema 15 rewrites an existing file once
(`Store._vokabular_englisch`), and every read path still understands an old row (`tinysesam/_vokabular.py`) — an older
version that ran on the file after a rollback, or a writer outside the process, leaves old rows behind again.

This suite measures that against a REAL schema-14 file, not against the mapping tables:

* `tests/fixtures/schema14_audit.sql` is plain SQL, produced by the code of 0.24.x (114 audit rows, two streak rows
  with a collision, one method row, the old trigger message). `PAIRS` below spells out, row by row, what the
  file holds and what must come out — written out by hand from the code that wrote the old rows and from
  the code that writes the new ones. The expectations are NOT derived from `_vokabular.py`; otherwise the test would
  prove the table with itself.
* (A) the migration rewrites exactly that and nothing else, (B) a second run changes nothing, (C) free text that only
  happens to contain a similar word stays as it is, (D) the read paths take both spellings after a rollback,
  (E) a file that cannot be written starts anyway, (F) new code writes only the new spelling, (G) the mutations: every
  guard turns this suite red when it is broken (done in the test by a deliberately broken copy of a table or function,
  never in the source).

All checks work without extras.
"""
from __future__ import annotations

import contextlib
import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from fastapi import FastAPI                                    # noqa: E402
from fastapi.testclient import TestClient                      # noqa: E402

from tinysesam import TinySesam, TinySesamConfig               # noqa: E402
from tinysesam import _vokabular as V                           # noqa: E402
from tinysesam.__main__ import main as cli_main                # noqa: E402
from tinysesam.errors import ConfigError                       # noqa: E402
from tinysesam.store import Store                              # noqa: E402
from _kit.report import Report                                 # noqa: E402

r = Report("Key vocabulary in English (schema 15): migration, idempotence, free text, read paths")

FIXTURE = ROOT / "tests" / "fixtures" / "schema14_audit.sql"
PW = "Probe-Pw-12345-xyz"
BASIS = "https://app.example.com"
MELDUNG = "rewritten to the English vocabulary"      # the log line of a migration that changed something

# (old event, old username, old detail) -> (new event, new username, new detail) for the 114 audit rows of the fixture,
# in the order of their ids. Taken from what 0.24.x wrote and what the current code writes. The last block must
# NOT be touched (free text, look-alikes, new spellings): old and new column are the same there, except where a real
# key stands inside it.
PAIRS = [
    # --- API keys
    ("apikey_create", "alice", "user=1 key=1 name=ci art=automat ablauf=unbefristet verworfene_rollen=x,y",
     "apikey_create", "alice", "user=1 key=1 name=ci kind=automation expiry=unlimited dropped_roles=x,y"),
    ("apikey_use", "alice", "key=1 art=mensch", "apikey_use", "alice", "key=1 kind=human"),
    ("apikey_denied", None, "grund=unbekannt", "apikey_denied", None, "reason=unknown"),
    ("apikey_denied", "alice", "key=2 grund=abgelaufen", "apikey_denied", "alice", "key=2 reason=expired"),
    ("apikey_denied", "alice", "key=2 grund=idp_nein", "apikey_denied", "alice", "key=2 reason=idp_no"),
    ("apikey_denied", "alice", "key=2 grund=idp_unbestaetigt", "apikey_denied", "alice", "key=2 reason=idp_unconfirmed"),
    ("api_keys_ruhen", "alice", "client=wiki grund=invalid_grant anzahl=2",
     "api_keys_dormant", "alice", "client=wiki reason=invalid_grant count=2"),
    ("api_keys_ruhen", "alice", "client=wiki grund=gruppe anzahl=1",
     "api_keys_dormant", "alice", "client=wiki reason=group count=1"),
    # --- sign-in
    ("login_fail", "x", "password grund=kein_konto", "login_fail", "x", "password reason=no_account"),
    ("login_fail", "x", "password grund=falsches_bereichsgeheimnis quelle=lokal+ldap",
     "login_fail", "x", "password reason=wrong_area_secret source=local+ldap"),
    ("login_fail", "x", "password grund=wiederholt", "login_fail", "x", "password reason=repeated"),
    ("login_ldap", "x", "password quelle=ldap", "login_ldap", "x", "password source=ldap"),
    ("login_lokal", "x", "password quelle=lokal", "login_local", "x", "password source=local"),
    ("login", "x", "password", "login", "x", "password"),
    ("lockout_serie", "x", "fehlversuche_in_folge=100", "lockout_series", "x", "failed_in_a_row=100"),
    ("sperrhinweis", "x", "grund=lockout_serie", "lockout_notice", "x", "reason=lockout_series"),
    ("sperrhinweis", "x", "grund=lockout_user", "lockout_notice", "x", "reason=lockout_user"),
    ("unlock_cli", "x", "fehlversuche=3 in_folge=2", "unlock_cli", "x", "failed_attempts=3 in_a_row=2"),
    ("unlock_cli", "x", "fehlversuche=3 in_folge=2 kennung=Max Muster",
     "unlock_cli", "x", "failed_attempts=3 in_a_row=2 identifier=Max Muster"),
    ("unlock_cli", "x", "fehlversuche=0 in_folge=0 ohne_konto=1",
     "unlock_cli", "x", "failed_attempts=0 in_a_row=0 without_account=1"),
    ("passkey_failed", "x", "grund=InvalidAuthenticationResponse", "passkey_failed", "x", "reason=InvalidAuthenticationResponse"),
    ("saml_denied", None, "grund=kein_name", "saml_denied", None, "reason=no_name"),
    ("saml_denied", "x", "grund=gruppe verlangt=['a', 'b']", "saml_denied", "x", "reason=group required=['a', 'b']"),
    ("saml_denied", "x", "grund=kein_konto saml_auto_create=False", "saml_denied", "x", "reason=no_account saml_auto_create=False"),
    ("saml_denied", "x", "grund=konto_gesperrt", "saml_denied", "x", "reason=account_locked"),
    ("ldap_group_denied", "x", "verlangt=['a']", "ldap_group_denied", "x", "required=['a']"),
    ("oidc_group_denied", "x", "app=wiki verlangt=['a']", "oidc_group_denied", "x", "app=wiki required=['a']"),
    ("oidc_email_unverified", "x@y.z", "verwendet=0", "oidc_email_unverified", "x@y.z", "used=0"),
    ("oidc_email_taken", "x", "nachgetragen=0", "oidc_email_taken", "x", "backfilled=0"),
    ("oidc_email_taken", "x", "nachgetragen=0 wettlauf=1", "oidc_email_taken", "x", "backfilled=0 race=1"),
    ("oidc_email_added", "x", "beleg=1", "oidc_email_added", "x", "proof=1"),
    ("oidc_unbestaetigt", "x", "client=wiki stunden=25", "oidc_unconfirmed", "x", "client=wiki hours=25"),
    ("oidc_widerruf", "x", "client=wiki grund=invalid_grant", "oidc_revoked", "x", "client=wiki reason=invalid_grant"),
    ("oidc_widerruf", "x", "client=wiki grund=gruppe", "oidc_revoked", "x", "client=wiki reason=group"),
    ("oidc_app_revalidate", "x", "app=wiki grund=fehlt", "oidc_app_revalidate", "x", "app=wiki reason=missing"),
    ("oidc_app_revalidate", "x", "app=wiki grund=veraltet", "oidc_app_revalidate", "x", "app=wiki reason=stale"),
    ("forward_denied", None, "grund=mfa_offen url=https://a.example/", "forward_denied", None, "reason=mfa_open url=https://a.example/"),
    ("forward_role_denied", "x", "url=https://a.example/ fehlt=chef,redaktion;admin",
     "forward_role_denied", "x", "url=https://a.example/ missing=chef,redaktion;admin"),
    ("oidc_disabled", "x", "app=wiki sub=abc", "oidc_disabled", "x", "app=wiki sub=abc"),
    # --- owner / admin
    ("owner_grant", "x", "quelle=cli", "owner_grant", "x", "source=cli"),
    ("owner_grant", "x", "quelle=erst_admin", "owner_grant", "x", "source=first_admin"),
    ("owner_grant", "x", "quelle=bestand aeltester_admin", "owner_grant", "x", "source=existing oldest_admin"),
    ("idp_admin_grant", "x", "quelle=idp", "idp_admin_grant", "x", "source=idp"),
    ("idp_admin_revoke", "x", "quelle=idp gruppe_entfallen=1", "idp_admin_revoke", "x", "source=idp group_removed=1"),
    ("admin_bootstrap_denied", "x", "nach_idp_entzug", "admin_bootstrap_denied", "x", "after_idp_withdrawal"),
    ("admin_bootstrap_denied", "x", "email_unbestaetigt", "admin_bootstrap_denied", "x", "email_unconfirmed"),
    ("admin_bootstrap_denied", "x", "ohne_beleg:oidc", "admin_bootstrap_denied", "x", "without_proof:oidc"),
    ("admin_bootstrap", "x", "admin_identifiers", "admin_bootstrap", "x", "admin_identifiers"),
    ("user_roles", "admin", "uid=2 rollen=a,b->c admin=0->1", "user_roles", "admin", "uid=2 roles=a,b->c admin=0->1"),
    ("user_delete", "gelöscht#7", "uid=7 audit_anonymisiert=4", "user_delete", "deleted#7", "uid=7 audit_anonymized=4"),
    ("password_reset", "x", "uid=1 fehlversuche_verworfen=3 api_keys_revoked=1 links_revoked=2",
     "password_reset", "x", "uid=1 failed_attempts_discarded=3 api_keys_revoked=1 links_revoked=2"),
    ("sessions_revoke", "x", "scope=others nach_einschreibung=1", "sessions_revoke", "x", "scope=others after_enrollment=1"),
    ("sessions_revoke", "x", "scope=others", "sessions_revoke", "x", "scope=others"),
    # --- name and address
    ("username_changed", "bobby", "alt=bob", "username_changed", "bobby", "old=bob"),
    ("username_changed", "bobby", "alt=Max Muster durch=betreiber quelle=cli",
     "username_changed", "bobby", "old=Max Muster by=operator source=cli"),
    ("username_changed", "bobby", "alt=Max Muster durch=betreiber akteur=admin",
     "username_changed", "bobby", "old=Max Muster by=operator actor=admin"),
    ("username_changed", "bobby", "alt=Max konto=1 Muster", "username_changed", "bobby", "old=Max konto=1 Muster"),
    ("username_changed", "bobby", "alt=gelöscht#4", "username_changed", "bobby", "old=deleted#4"),
    ("email_changed", "x", "alt=a@b.c neu=d@e.f", "email_changed", "x", "old=a@b.c new=d@e.f"),
    ("email_changed", "x", "alt= neu=d@e.f", "email_changed", "x", "old= new=d@e.f"),
    ("email_change_requested", "x", "neu=d@e.f", "email_change_requested", "x", "new=d@e.f"),
    ("email_change_requested", "x", "konto=2 quelle=ldap neu=d@e.f", "email_change_requested", "x", "account=2 source=ldap new=d@e.f"),
    ("email_change_requested", "x", "konto=2 quelle=quelle neu=d@e.f", "email_change_requested", "x", "account=2 source=source new=d@e.f"),
    ("email_change_taken", "x", "neu=d@e.f beim_bestaetigen=1", "email_change_taken", "x", "new=d@e.f on_confirmation=1"),
    ("email_change_taken", "x", "neu=d@e.f beim_bestaetigen=1 wettlauf=1", "email_change_taken", "x", "new=d@e.f on_confirmation=1 race=1"),
    ("email_change_reserved", "x", "neu=d@e.f beim_bestaetigen=1", "email_change_reserved", "x", "new=d@e.f on_confirmation=1"),
    ("federation_email_confirm", "x", "konto=2 quelle=ldap an=d@e.f", "federation_email_confirm", "x", "account=2 source=ldap to=d@e.f"),
    ("ldap_email_taken", "x", "nachgetragen=0 wettlauf=1", "ldap_email_taken", "x", "backfilled=0 race=1"),
    ("quelle_email_taken", "x", "nachgetragen=0 wettlauf=1", "source_email_taken", "x", "backfilled=0 race=1"),
    ("mail_ratelimit", None, "magic an=a@b.c", "mail_ratelimit", None, "magic to=a@b.c"),
    ("mail_ratelimit", "x", "email_change konto=2", "mail_ratelimit", "x", "email_change account=2"),
    ("signup_taken", "x", "a@b.c wettlauf=1", "signup_taken", "x", "a@b.c race=1"),
    ("signup_taken", "x", "a@b.c", "signup_taken", "x", "a@b.c"),
    # --- other
    ("token_invalid", None, "zweck=reset_password grund=ungueltig", "token_invalid", None, "purpose=reset_password reason=invalid"),
    ("token_invalid_throttled", None, "mehr als 20 in 60s — weitere nur im Sicherheits-Log",
     "token_invalid_throttled", None, "more than 20 in 60s — further ones only in the security log"),
    ("totp_setup_denied", "x", "user=1 grund=bereits_bestaetigt", "totp_setup_denied", "x", "user=1 reason=already_confirmed"),
    ("totp_disable", "x", "user=1 recovery_codes_geloescht=9", "totp_disable", "x", "user=1 recovery_codes_deleted=9"),
    ("recovery_used", "x", "user=1 verbleibend=9", "recovery_used", "x", "user=1 remaining=9"),
    ("recovery_verwaist_geloescht", "x", "user=1 n=3", "recovery_orphan_deleted", "x", "user=1 n=3"),
    ("mfa_enrollment_granted", "x", "minuten=30", "mfa_enrollment_granted", "x", "minutes=30"),
    ("mfa_enrollment_denied", "x", "art=strict", "mfa_enrollment_denied", "x", "kind=strict"),
    ("mfa_enrollment_denied", "x", "account has a passkey that is missing in this session",
     "mfa_enrollment_denied", "x", "account has a passkey that is missing in this session"),
    # --- federation
    ("ldap_kennung_abgewiesen", "x", "grund=kennung_zweier_konten lokal=2 verzeichnis=neu",
     "ldap_identifier_rejected", "x", "reason=identifier_of_two_accounts local=2 directory=new"),
    ("saml_kennung_abgewiesen", "x", "grund=kennung_zweier_konten lokal=2 verzeichnis=1",
     "saml_identifier_rejected", "x", "reason=identifier_of_two_accounts local=2 directory=1"),
    ("ldap_namensbindung_zu", "x", "grund=adresse_als_name kennung=-", "ldap_name_binding_closed", "x", "reason=address_as_name identifier=-"),
    ("ldap_namensbindung_zu", "x", "grund=kennung_ungueltig kennung=uid=bob,ou=x", "ldap_name_binding_closed", "x", "reason=invalid_identifier identifier=uid=bob,ou=x"),
    ("saml_namensbindung_zu", "x", "grund=konflikt kennung=abc", "saml_name_binding_closed", "x", "reason=conflict identifier=abc"),
    ("saml_namensbindung_zu", "x", "grund=anders_gebunden kennung=abc", "saml_name_binding_closed", "x", "reason=bound_elsewhere identifier=abc"),
    ("ldap_namensbindung_zu", "x", "grund=name_selbst_gewaehlt kennung=abc", "ldap_name_binding_closed", "x", "reason=self_chosen_name identifier=abc"),
    ("ldap_namensbindung_zu", "x", "grund=name_aus_quelle kennung=abc", "ldap_name_binding_closed", "x", "reason=name_from_other_source identifier=abc"),
    ("saml_namensbindung_zu", "x", "grund=frist kennung=abc", "saml_name_binding_closed", "x", "reason=binding_window_expired identifier=abc"),
    ("ldap_kennung_geloest", "x", "namensbindung_offen_bis=1795828847", "ldap_identifier_unbound", "x", "name_binding_open_until=1795828847"),
    ("ldap_kennung_geloest", "x", None, "ldap_identifier_unbound", "x", None),
    ("ldap_kennung_ungueltig", "x", "Rand-/Steuerzeichen", "ldap_identifier_invalid", "x", "edge_or_control_characters"),
    ("saml_kennung_ungueltig", "x", "Platzhalter-Form", "saml_identifier_invalid", "x", "placeholder_form"),
    ("ldap_kennung_wechsel", "x", "rejected: account already carries a different identifier",
     "ldap_identifier_change", "x", "rejected: account already carries a different identifier"),
    ("ldap_kennung_gebunden", "x", "migration", "ldap_identifier_bound", "x", "migration"),
    ("ldap_kennung_gebunden", "x", "nachgebunden beim Login", "ldap_identifier_bound", "x", "bound later at sign-in"),
    ("oidc_kennung_gebunden", "x", "migration", "oidc_identifier_bound", "x", "migration"),
    ("ldap_ohne_kennung", "x", "abgewiesen", "ldap_without_identifier", "x", "rejected"),
    ("saml_ohne_kennung", "x", "abgewiesen: Adresse als Name", "saml_without_identifier", "x", "rejected: address as name"),
    # --- must NOT be touched
    ("ldap_unavailable", "x", "grund=foo quelle=bar", "ldap_unavailable", "x", "grund=foo quelle=bar"),
    ("resource_unlock", None, "grund=bar quelle=x", "resource_unlock", None, "grund=bar quelle=x"),
    ("user_create", "gelöscht#99", "gelöscht#99 service=False", "user_create", "deleted#99", "deleted#99 service=False"),
    ("user_create", "Max konto=1", "Max konto=1 service=False", "user_create", "Max konto=1", "Max konto=1 service=False"),
    ("invite_create", None, "a@b.c", "invite_create", None, "a@b.c"),
    ("login_fail", "gelöscht#5abc", "password grund=kein_konto", "login_fail", "gelöscht#5abc", "password reason=no_account"),
    ("login_fail", "gelöscht#", "password", "login_fail", "gelöscht#", "password"),
    ("login_fail", "x", "password altgrund=kein_konto", "login_fail", "x", "password altgrund=kein_konto"),
    ("login_fail", "x", "password mygrund=kein_konto", "login_fail", "x", "password mygrund=kein_konto"),
    ("login_fail", "x", "password reason=no_account", "login_fail", "x", "password reason=no_account"),
    ("username_changed", "x", "old=Alt alt=Neu", "username_changed", "x", "old=Alt alt=Neu"),
    ("email_changed", "x", "alt=a@b.c neu=d@e.f actor=x", "email_changed", "x", "old=a@b.c new=d@e.f actor=x"),
    ("login_fail", "x", "password grund=wiederholt akteur=gelöscht#5", "login_fail", "x", "password reason=repeated actor=deleted#5"),
]

# Rows where a look-alike of the old vocabulary is correct (free text, look-alikes kept on purpose).
AUSNAHMEN = {p[3:] for p in PAIRS[-13:]} | {("username_changed", "bobby", "old=Max konto=1 Muster")}

# The old audit events (exact names) and the families — spelled out here, independent of `_vokabular.py`.
ALTE_EREIGNISSE = ("api_keys_ruhen", "lockout_serie", "login_lokal", "oidc_unbestaetigt", "oidc_widerruf",
                   "quelle_email_taken", "recovery_verwaist_geloescht", "sperrhinweis")
ALTE_FAMILIEN = ("_kennung_abgewiesen", "_kennung_gebunden", "_kennung_geloest", "_kennung_ungueltig",
                 "_kennung_wechsel", "_namensbindung_zu", "_ohne_kennung")
# The old keys of `key=value` pairs, spelled out. Used to find a leftover of the old vocabulary in new rows.
ALTE_SCHLUESSEL = ("grund", "konto", "quelle", "durch", "akteur", "alt", "neu", "an", "anzahl", "beleg", "verlangt",
                   "verwendet", "nachgetragen", "fehlversuche", "in_folge", "fehlversuche_in_folge",
                   "fehlversuche_verworfen", "kennung", "lokal", "verzeichnis", "zweck", "fehlt", "ohne_konto",
                   "gruppe_entfallen", "beim_bestaetigen", "nach_einschreibung", "namensbindung_offen_bis",
                   "recovery_codes_geloescht", "audit_anonymisiert", "verbleibend", "art", "ablauf",
                   "verworfene_rollen", "stunden", "minuten", "wettlauf", "rollen")
ALT_SCHLUESSEL_RE = re.compile(r"(?<!\S)(?:" + "|".join(ALTE_SCHLUESSEL) + r")=")
# Events whose detail is free text; their keys are not touched.
FREITEXT = ("ldap_unavailable", "resource_unlock", "user_create")


def alt_vokabular(event, username, detail) -> list:
    """What of the old vocabulary is still in this audit row (a list of reasons, empty = clean)?"""
    funde = []
    ev = str(event or "")
    if ev in ALTE_EREIGNISSE or any(ev.startswith(q) and ev[len(q):] in ALTE_FAMILIEN
                                    for q in ("oidc", "saml", "ldap")):
        funde.append(f"event {ev}")
    if re.fullmatch(r"gelöscht#\d+", str(username or "")):
        funde.append(f"username {username}")
    if ev not in FREITEXT and ALT_SCHLUESSEL_RE.search(str(detail or "")):
        funde.append(f"detail key in {detail!r}")
    if re.search(r"(?<![\w@.-])gelöscht#\d", str(detail or "")) and ev not in FREITEXT[:2]:
        funde.append(f"detail name in {detail!r}")
    return funde


# ── helpers ──────────────────────────────────────────────────────────────────────────────────────
def _mitschreiben(fn):
    """(result, text) — what the logger `tinysesam` says meanwhile, from INFO."""
    puffer = io.StringIO()
    haken = logging.StreamHandler(puffer)
    log = logging.getLogger("tinysesam")
    stufe = log.level
    log.addHandler(haken)
    log.setLevel(logging.INFO)
    try:
        ergebnis = fn()
    finally:
        log.removeHandler(haken)
        log.setLevel(stufe)
    return ergebnis, puffer.getvalue()


@contextlib.contextmanager
def patch(obj, name, wert):
    """Replace `obj.name` for the duration of the block — the mutation tests use this, never the source."""
    original = getattr(obj, name)
    setattr(obj, name, wert)
    try:
        yield
    finally:
        setattr(obj, name, original)


def _neuer_pfad(name="t.db") -> str:
    return os.path.join(tempfile.mkdtemp(), name)


def _roh(pfad: str, *sql) -> None:
    """Write directly into the file like an older version (or the operator with `sqlite3`)."""
    con = sqlite3.connect(pfad)
    try:
        for s in sql:
            con.execute(*s) if isinstance(s, tuple) else con.executescript(s)
        con.commit()
    finally:
        con.close()


def _fixture_laden(pfad: str, extra=()) -> None:
    """A fresh file from the schema-14 fixture (plain SQL); `extra`: audit rows (event, username, detail) appended."""
    con = sqlite3.connect(pfad)
    try:
        con.executescript(FIXTURE.read_text(encoding="utf-8"))
        os.chmod(pfad, 0o600)       # as the store creates its own files (otherwise it warns about the mode)
        for ev, user, det in extra:
            con.execute("INSERT INTO audit(ts, event, username, ip, detail) VALUES (1793237238, ?, ?, NULL, ?)",
                        (ev, user, det))
        con.commit()
    finally:
        con.close()


def _lesen(pfad: str, sql: str, *args) -> list:
    con = sqlite3.connect(pfad)
    try:
        return con.execute(sql, args).fetchall()
    finally:
        con.close()


def _stempel(pfad: str) -> int:
    return _lesen(pfad, "PRAGMA user_version")[0][0]


def _audit(pfad: str) -> list:
    return _lesen(pfad, "SELECT id, ts, event, username, ip, detail FROM audit ORDER BY id")


def _tabellen(pfad: str) -> tuple:
    """The three tables the migration touches, complete and ordered — for before/after comparisons."""
    return (_audit(pfad),
            _lesen(pfad, "SELECT topf, art, anzahl, seit, zuletzt FROM fehlserie ORDER BY topf, art"),
            _lesen(pfad, "SELECT id, ts, username, ip, method, offen FROM login_attempt ORDER BY id"))


def _start(pfad: str):
    """Open the file with `Store` (that runs the migration) — (store, log text)."""
    return _mitschreiben(lambda: Store(pfad))


def _app(a: TinySesam) -> FastAPI:
    app = FastAPI()
    app.include_router(a.router())
    return app


def _aufbau(pfad: str, post: list | None = None, **cfg) -> TinySesam:
    kw = dict(db_path=pfad, cookie_secure=False, csrf_enabled=False, passkey_enabled=False,
              base_url=BASIS, notify_login_failures=True)
    kw.update(cfg)
    a = TinySesam(TinySesamConfig(**kw))
    a.set_mailer(lambda to, betreff, text, html=None: post.append((to, betreff)) if post is not None else None)
    return a


def neu_von(zeilen: list, ev: str, user, det) -> tuple:
    """The migrated row (event, username, detail) that belongs to the OLD row (ev, user, det) of `PAIRS`."""
    i = [p[:3] for p in PAIRS].index((ev, user, det))
    return zeilen[i][2], zeilen[i][3], zeilen[i][5]


# ── the checks of the fixture migration, as a function: the same ones run again under a mutation ──────
def fixture_probleme(pfad: str) -> list:
    """Migrate the fixture at `pfad` (a fresh schema-14 file) and list what is wrong afterwards (empty = right)."""
    vorher = _audit(pfad)
    store, log = _start(pfad)
    store.db.close()
    problem = []
    nachher = _audit(pfad)
    if _stempel(pfad) != 15:
        problem.append(f"stamp {_stempel(pfad)}")
    if MELDUNG not in log:
        problem.append("the migration does not say that it rewrote something")
    if len(nachher) != len(PAIRS):
        problem.append(f"row count {len(nachher)}")
    for p, z in zip(PAIRS, nachher):
        if (z[2], z[3], z[5]) != p[3:]:
            problem.append(f"row {z[0]}: {(z[2], z[3], z[5])} instead of {p[3:]}")
    if [(z[0], z[1], z[4]) for z in vorher] != [(z[0], z[1], z[4]) for z in nachher]:
        problem.append("id, ts or ip of a row changed")
    if _lesen(pfad, "SELECT topf, art, anzahl, seit, zuletzt FROM fehlserie ORDER BY topf, art") != [
            ("alice", "pin_chain", 5, 1793237188, 1793237233),
            ("bob", "pin_chain", 4, 1793237188, 1793237233),
            ("bob", "totp", 1, 1793237188, 1793237233)]:
        problem.append("fehlserie")
    if _lesen(pfad, "SELECT id, method FROM login_attempt ORDER BY id") != [(1, "pin_chain"), (2, "pin")]:
        problem.append("login_attempt.method")
    return problem


# ═══ (A) The real schema-14 file is rewritten correctly ═════════════════════════════════════════════
pfad_a = _neuer_pfad("a.db")
_fixture_laden(pfad_a)
vorher_a = _audit(pfad_a)
r.check("precondition: the fixture is a schema-14 file with the 114 rows of PAIRS in their old spelling",
        _stempel(pfad_a) == 14 and len(vorher_a) == len(PAIRS) == 114
        and [(z[2], z[3], z[5]) for z in vorher_a] == [p[:3] for p in PAIRS],
        f"{_stempel(pfad_a)} {len(vorher_a)}")
r.check("precondition: the old trigger message and the colliding streak rows are in the fixture",
        any("kennung vergeben" in str(z[0]) for z in _lesen(
            pfad_a, "SELECT sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_users_kennung_%'"))
        and _lesen(pfad_a, "SELECT art FROM fehlserie WHERE topf='alice' ORDER BY art") == [("pin_chain",), ("pin_folge",)])
alt_pruefung = [alt_vokabular(z[2], z[3], z[5]) for z in vorher_a]
r.check("precondition: the old-vocabulary detector (independent of `_vokabular.py`) finds the old rows in the fixture",
        sum(1 for f in alt_pruefung if f) >= 80, str(sum(1 for f in alt_pruefung if f)))

store_a, log_a = _start(pfad_a)
store_a.db.close()
nachher_a = _audit(pfad_a)
r.check("(A) the start migrates: stamp 15 and a log line that says something was rewritten",
        _stempel(pfad_a) == 15 == Store.SCHEMA_VERSION and MELDUNG in log_a, f"{_stempel(pfad_a)} {log_a[-300:]!r}")
falsch = [(z[0], (z[2], z[3], z[5]), p[3:]) for p, z in zip(PAIRS, nachher_a) if (z[2], z[3], z[5]) != p[3:]]
r.check("(A) all 114 audit rows come out exactly as spelled out in PAIRS (event, username, detail)",
        not falsch and len(nachher_a) == 114, str(falsch[:3]))
r.check("(A) id, ts and ip of every row are untouched, no row was added or dropped",
        [(z[0], z[1], z[4]) for z in vorher_a] == [(z[0], z[1], z[4]) for z in nachher_a])
r.check("(A) nothing of the old vocabulary is left in the rows that are not free text",
        not [(z[0], f) for z in nachher_a for f in [alt_vokabular(z[2], z[3], z[5])]
             if f and (z[2], z[3], z[5]) not in AUSNAHMEN],
        str([(z[0], alt_vokabular(z[2], z[3], z[5])) for z in nachher_a if alt_vokabular(z[2], z[3], z[5])][:3]))

# Event families and the exact names, one row each (the fixture carries them).
EREIGNIS_ERWARTUNG = {"api_keys_ruhen": "api_keys_dormant", "lockout_serie": "lockout_series",
                      "login_lokal": "login_local", "oidc_unbestaetigt": "oidc_unconfirmed",
                      "oidc_widerruf": "oidc_revoked", "quelle_email_taken": "source_email_taken",
                      "recovery_verwaist_geloescht": "recovery_orphan_deleted", "sperrhinweis": "lockout_notice",
                      "ldap_kennung_abgewiesen": "ldap_identifier_rejected",
                      "saml_kennung_abgewiesen": "saml_identifier_rejected",
                      "ldap_kennung_gebunden": "ldap_identifier_bound",
                      "oidc_kennung_gebunden": "oidc_identifier_bound",
                      "ldap_kennung_geloest": "ldap_identifier_unbound",
                      "ldap_kennung_ungueltig": "ldap_identifier_invalid",
                      "saml_kennung_ungueltig": "saml_identifier_invalid",
                      "ldap_kennung_wechsel": "ldap_identifier_change",
                      "ldap_namensbindung_zu": "ldap_name_binding_closed",
                      "saml_namensbindung_zu": "saml_name_binding_closed",
                      "ldap_ohne_kennung": "ldap_without_identifier", "saml_ohne_kennung": "saml_without_identifier"}
gesehen = {alt: sorted({n[2] for v, n in zip(vorher_a, nachher_a) if v[2] == alt}) for alt in EREIGNIS_ERWARTUNG}
r.check("(A) every event family (`<q>_kennung_*`, `<q>_namensbindung_zu`, `<q>_ohne_kennung`) and every exact name "
        "(`oidc_widerruf`, `lockout_serie`, `sperrhinweis`, …) has its row, rewritten",
        all(gesehen[alt] == [neu] for alt, neu in EREIGNIS_ERWARTUNG.items()), str(gesehen))
neue_ereignisse = {z[2] for z in nachher_a}
r.check("(A) the families are rewritten for `oidc_`, `saml_` and `ldap_` alike: no old family name is left, the new names "
        "of all three sources are there",
        not [z for z in nachher_a if any(z[2] == q + alt for q in ("oidc", "saml", "ldap") for alt in ALTE_FAMILIEN)]
        and {"oidc_identifier_bound", "ldap_identifier_bound", "saml_identifier_rejected", "ldap_identifier_rejected",
             "saml_name_binding_closed", "ldap_name_binding_closed", "saml_identifier_invalid",
             "ldap_identifier_invalid", "saml_without_identifier", "ldap_without_identifier",
             "ldap_identifier_change", "ldap_identifier_unbound"} <= neue_ereignisse)

# Detail keys, tokens and flags: one explicit row per kind of rewrite.
n = lambda ev, u, d: neu_von(nachher_a, ev, u, d)       # noqa: E731
r.check("(A) key `grund=` -> `reason=` with its token (`kein_konto` -> `no_account`, `konto_gesperrt` -> "
        "`account_locked`, `falsches_bereichsgeheimnis` -> `wrong_area_secret`, `wiederholt` -> `repeated`)",
        n("login_fail", "x", "password grund=kein_konto")[2] == "password reason=no_account"
        and n("saml_denied", "x", "grund=konto_gesperrt")[2] == "reason=account_locked"
        and n("login_fail", "x", "password grund=falsches_bereichsgeheimnis quelle=lokal+ldap")[2]
        == "password reason=wrong_area_secret source=local+ldap"
        and n("login_fail", "x", "password grund=wiederholt")[2] == "password reason=repeated")
r.check("(A) key `konto=`/`quelle=`/`an=` -> `account=`/`source=`/`to=` (address-change and directory rows)",
        n("email_change_requested", "x", "konto=2 quelle=ldap neu=d@e.f")[2] == "account=2 source=ldap new=d@e.f"
        and n("federation_email_confirm", "x", "konto=2 quelle=ldap an=d@e.f")[2] == "account=2 source=ldap to=d@e.f")
r.check("(A) key `durch=` -> `by=` and `akteur=` -> `actor=` with the token behind it (`betreiber` -> `operator`)",
        n("username_changed", "bobby", "alt=Max Muster durch=betreiber quelle=cli")[2]
        == "old=Max Muster by=operator source=cli"
        and n("username_changed", "bobby", "alt=Max Muster durch=betreiber akteur=admin")[2]
        == "old=Max Muster by=operator actor=admin")
r.check("(A) key `rollen=` -> `roles=` and `verlangt=` -> `required=`, `fehlt=` -> `missing=`, `stunden=`/`minuten=` -> "
        "`hours=`/`minutes=`, `verbleibend=` -> `remaining=`",
        n("user_roles", "admin", "uid=2 rollen=a,b->c admin=0->1")[2] == "uid=2 roles=a,b->c admin=0->1"
        and n("saml_denied", "x", "grund=gruppe verlangt=['a', 'b']")[2] == "reason=group required=['a', 'b']"
        and n("forward_role_denied", "x", "url=https://a.example/ fehlt=chef,redaktion;admin")[2]
        == "url=https://a.example/ missing=chef,redaktion;admin"
        and n("oidc_unbestaetigt", "x", "client=wiki stunden=25")[2] == "client=wiki hours=25"
        and n("mfa_enrollment_granted", "x", "minuten=30")[2] == "minutes=30"
        and n("recovery_used", "x", "user=1 verbleibend=9")[2] == "user=1 remaining=9")
r.check("(A) keys `alt=`/`neu=` -> `old=`/`new=` (address change), the old name in `username_changed` is free text "
        "and keeps a `konto=` inside it",
        n("email_changed", "x", "alt=a@b.c neu=d@e.f")[2] == "old=a@b.c new=d@e.f"
        and n("email_changed", "x", "alt= neu=d@e.f")[2] == "old= new=d@e.f"
        and n("username_changed", "bobby", "alt=Max konto=1 Muster")[2] == "old=Max konto=1 Muster")
r.check("(A) flag `beim_bestaetigen=1` -> `on_confirmation=1`, `wettlauf=1` -> `race=1`",
        n("email_change_taken", "x", "neu=d@e.f beim_bestaetigen=1 wettlauf=1")[2] == "new=d@e.f on_confirmation=1 race=1"
        and n("email_change_reserved", "x", "neu=d@e.f beim_bestaetigen=1")[2] == "new=d@e.f on_confirmation=1")
r.check("(A) the failed-attempt rows: `fehlversuche_in_folge=` -> `failed_in_a_row=`, `fehlversuche=`/`in_folge=` -> "
        "`failed_attempts=`/`in_a_row=`, `kennung=` -> `identifier=`, `ohne_konto=` -> `without_account=`",
        n("lockout_serie", "x", "fehlversuche_in_folge=100")[2] == "failed_in_a_row=100"
        and n("unlock_cli", "x", "fehlversuche=3 in_folge=2 kennung=Max Muster")[2]
        == "failed_attempts=3 in_a_row=2 identifier=Max Muster"
        and n("unlock_cli", "x", "fehlversuche=0 in_folge=0 ohne_konto=1")[2]
        == "failed_attempts=0 in_a_row=0 without_account=1")
r.check("(A) token values behind other keys: `art=automat ablauf=unbefristet` -> `kind=automation expiry=unlimited`, "
        "`quelle=erst_admin` -> `source=first_admin`, `verzeichnis=neu` -> `directory=new`",
        n("apikey_create", "alice", "user=1 key=1 name=ci art=automat ablauf=unbefristet verworfene_rollen=x,y")[2]
        == "user=1 key=1 name=ci kind=automation expiry=unlimited dropped_roles=x,y"
        and n("owner_grant", "x", "quelle=erst_admin")[2] == "source=first_admin"
        and n("ldap_kennung_abgewiesen", "x", "grund=kennung_zweier_konten lokal=2 verzeichnis=neu")[2]
        == "reason=identifier_of_two_accounts local=2 directory=new")
r.check("(A) the binding reasons: `adresse_als_name`, `kennung_ungueltig`, `konflikt`, `anders_gebunden`, "
        "`name_selbst_gewaehlt`, `name_aus_quelle`, `frist` -> their English codes",
        [n("ldap_namensbindung_zu", "x", "grund=adresse_als_name kennung=-")[2],
         n("ldap_namensbindung_zu", "x", "grund=kennung_ungueltig kennung=uid=bob,ou=x")[2],
         n("saml_namensbindung_zu", "x", "grund=konflikt kennung=abc")[2],
         n("saml_namensbindung_zu", "x", "grund=anders_gebunden kennung=abc")[2],
         n("ldap_namensbindung_zu", "x", "grund=name_selbst_gewaehlt kennung=abc")[2],
         n("ldap_namensbindung_zu", "x", "grund=name_aus_quelle kennung=abc")[2],
         n("saml_namensbindung_zu", "x", "grund=frist kennung=abc")[2]]
        == ["reason=address_as_name identifier=-", "reason=invalid_identifier identifier=uid=bob,ou=x",
            "reason=conflict identifier=abc", "reason=bound_elsewhere identifier=abc",
            "reason=self_chosen_name identifier=abc", "reason=name_from_other_source identifier=abc",
            "reason=binding_window_expired identifier=abc"])
r.check("(A) the fixed phrases of an event: `nachgebunden beim Login`, `abgewiesen`, `Rand-/Steuerzeichen`, "
        "`nach_idp_entzug`, `ohne_beleg:`, and the throttle text",
        [n("ldap_kennung_gebunden", "x", "nachgebunden beim Login")[2], n("ldap_ohne_kennung", "x", "abgewiesen")[2],
         n("ldap_kennung_ungueltig", "x", "Rand-/Steuerzeichen")[2],
         n("admin_bootstrap_denied", "x", "nach_idp_entzug")[2], n("admin_bootstrap_denied", "x", "ohne_beleg:oidc")[2],
         n("token_invalid_throttled", None, "mehr als 20 in 60s — weitere nur im Sicherheits-Log")[2]]
        == ["bound later at sign-in", "rejected", "edge_or_control_characters", "after_idp_withdrawal",
            "without_proof:oidc", "more than 20 in 60s — further ones only in the security log"])
r.check("(A) `audit.username` `gelöscht#<id>` -> `deleted#<id>` (digits only): `user_delete`/`user_create` rows move, "
        "`gelöscht#5abc` and `gelöscht#` stay",
        n("user_delete", "gelöscht#7", "uid=7 audit_anonymisiert=4")[1:] == ("deleted#7", "uid=7 audit_anonymized=4")
        and n("user_create", "gelöscht#99", "gelöscht#99 service=False")[1:] == ("deleted#99", "deleted#99 service=False")
        and n("login_fail", "gelöscht#5abc", "password grund=kein_konto")[1] == "gelöscht#5abc"
        and n("login_fail", "gelöscht#", "password")[1] == "gelöscht#"
        and sorted(u for (u,) in _lesen(pfad_a, "SELECT DISTINCT username FROM audit WHERE username LIKE 'gelöscht#%'"))
        == ["gelöscht#", "gelöscht#5abc"])
r.check("(A) the replacement name inside a detail: `alt=gelöscht#4` -> `old=deleted#4`, `akteur=gelöscht#5` -> "
        "`actor=deleted#5`",
        n("username_changed", "bobby", "alt=gelöscht#4")[2] == "old=deleted#4"
        and n("login_fail", "x", "password grund=wiederholt akteur=gelöscht#5")[2]
        == "password reason=repeated actor=deleted#5")
r.check("(A) free-text events keep their keys (`ldap_unavailable`, `resource_unlock`, `user_create` with `konto=`)",
        n("ldap_unavailable", "x", "grund=foo quelle=bar")[2] == "grund=foo quelle=bar"
        and n("resource_unlock", None, "grund=bar quelle=x")[2] == "grund=bar quelle=x"
        and n("user_create", "Max konto=1", "Max konto=1 service=False")[1:] == ("Max konto=1", "Max konto=1 service=False"))
r.check("(A) a detail that is already in the new form stays (`reason=no_account`), and a key that is only the end of a "
        "longer word stays (`altgrund=`, `mygrund=`)",
        n("login_fail", "x", "password reason=no_account")[2] == "password reason=no_account"
        and n("login_fail", "x", "password altgrund=kein_konto")[2] == "password altgrund=kein_konto"
        and n("login_fail", "x", "password mygrund=kein_konto")[2] == "password mygrund=kein_konto")
fehl = _lesen(pfad_a, "SELECT topf, art, anzahl, seit, zuletzt FROM fehlserie ORDER BY topf, art")
r.check("(A) `fehlserie.art` `pin_folge` -> `pin_chain`; where both exist (the collision) the counts are ADDED up "
        "(3+2), the window widens (earliest start, latest end), exactly one row is left",
        fehl == [("alice", "pin_chain", 5, 1793237188, 1793237233), ("bob", "pin_chain", 4, 1793237188, 1793237233),
                 ("bob", "totp", 1, 1793237188, 1793237233)], str(fehl))
r.check("(A) `login_attempt.method` `pin_folge` -> `pin_chain`, other methods stay",
        _lesen(pfad_a, "SELECT id, method FROM login_attempt ORDER BY id") == [(1, "pin_chain"), (2, "pin")])
def trigger_texte(pfad: str) -> list:
    return [z[0] for z in _lesen(pfad, "SELECT sql FROM sqlite_master WHERE type='trigger' "
                                       "AND name LIKE 'trg_users_kennung_%'")]


trigger_a = trigger_texte(pfad_a)
r.check("(A) the identifier triggers carry the new message and none the old one",
        len(trigger_a) == 2 and all("tinysesam: identifier taken" in t and "kennung vergeben" not in t
                                    for t in trigger_a), str(trigger_a)[:200])

# The new message is what a collision raises; the callers recognise the case by IntegrityError, not by the text.
def kollision(pfad: str):
    """Two identifiers in one counting bucket, the pre-check suppressed (a race): (type of the error, message of the cause)."""
    app = _aufbau(pfad)
    app.create_user("Anna", password=PW)
    app.identifier_taken = lambda *a, **k: None
    try:
        app.create_user("ANNA", password=PW)
        res = ("no error", "")
    except ConfigError as e:
        res = (type(e).__name__, str(e.__cause__))
    app.store.db.close()
    return res


kollision_a = kollision(pfad_a)
r.check("(A) a collision on the migrated file: the trigger aborts with `tinysesam: identifier taken`, the caller turns "
        "it into a `ConfigError`",
        kollision_a == ("ConfigError", "tinysesam: identifier taken"), str(kollision_a))

# ═══ (B) Idempotence ═════════════════════════════════════════════════════════════════════════════════
def idempotenz_probleme(pfad: str) -> list:
    """Migrate a fresh fixture, then run it again in three ways; list what the second run changed (empty = idempotent)."""
    problem = []
    st, _ = _start(pfad)
    st.db.close()
    s1 = _tabellen(pfad)
    st, log2 = _start(pfad)                                  # (1) an ordinary second start (stamp 15)
    st.db.close()
    if _tabellen(pfad) != s1 or MELDUNG in log2:
        problem.append("second start changed something")
    _roh(pfad, "PRAGMA user_version = 14;")                 # (2) the step runs again over migrated data
    st, log3 = _start(pfad)
    st.db.close()
    if _tabellen(pfad) != s1 or MELDUNG in log3 or _stempel(pfad) != 15:
        problem.append(f"forced second run changed something ({log3[-120:]!r})")
    st = Store(pfad)                                         # (3) the step itself: 0 rows, 0 changes on the connection
    vor = st.db.total_changes
    with st._schreibend():
        zeilen = st._vokabular_englisch()
    st.db.rollback()
    delta = st.db.total_changes - vor
    st.db.close()
    if zeilen != 0 or delta != 0 or _tabellen(pfad) != s1:
        problem.append(f"direct second call: {zeilen} rows, {delta} changes")
    return problem


pfad_b = _neuer_pfad("b.db")
_fixture_laden(pfad_b)
r.check("(B) a second start, a forced second run (stamp back to 14) and a direct second call change 0 rows: the tables "
        "stay identical, no log line, 0 changes on the connection",
        idempotenz_probleme(pfad_b) == [], str(idempotenz_probleme(_neuer_pfad())))
# A file made by the current code (new spellings from the start): the step finds nothing, even when it runs again.
pfad_b2 = _neuer_pfad("b2.db")
st_b2, log_b2 = _start(pfad_b2)
st_b2.audit_log("oidc_revoked", "x", None, "client=wiki reason=group actor=deleted#7")
st_b2.audit_log("login_fail", "deleted#3", None, "password reason=no_account")
st_b2.db.close()
neu_b2 = _tabellen(pfad_b2)
_roh(pfad_b2, "PRAGMA user_version = 14;")
st_b2, log_b2 = _start(pfad_b2)
st_b2.db.close()
r.check("(B) a file that never held old values: the step run over it (stamp forced back to 14) rewrites nothing",
        _tabellen(pfad_b2) == neu_b2 and MELDUNG not in log_b2 and len(neu_b2[0]) == 2, log_b2[-200:])

# ═══ (C) Free text stays untouched ═════════════════════════════════════════════════════════════════════
# Rows whose text only happens to contain a word of the vocabulary. They sit at the end of an otherwise old file, next
# to one row that MUST be rewritten (the companion — a migration that did nothing would otherwise pass).
FREI = [
    ("login_fail", "x", "password das konto wurde gesperrt, grund unklar"),          # words, no `=`
    ("login_fail", "kontoinhaber", "password reason=no_account"),                      # a name that contains `konto`
    ("login_fail", "konto", "konto"),                                                  # name and detail are the word
    ("note", "x", "password kein_konto"),                                              # a token without its key
    ("login_fail", "x", "password mykonto=1 xgrund=2 unter_quelle=3"),                 # key as the end of a longer word
    ("login_fail", "x", "password konto =1 grund = kein_konto"),                       # blank before `=`
    ("login_fail", "x", "password konto:1 grund:wiederholt"),                          # colon instead of `=`
    ("login_fail", "x", "password url=https://a.example/?konto=1&grund=kein_konto"),  # inside a value
    ("login_fail", "x", "password foo.gelöscht#5 xgelöscht#6"),                       # a name merely containing the prefix
    ("login_fail", "Konto gelöscht#3", "password"),                                    # username that merely contains it
    ("xoidc_widerruf", "x", "client=wiki"),                                            # event that only ends like an old one
    ("oidc_kennung_gebunden_x", "x", "migration"),                                     # family name with a suffix
    ("ldap_unavailable", "x", "LDAPSocketOpenError konto=1 grund=timeout"),           # free-text event
]
COMPANION = ("login_fail", "x", "password grund=kein_konto")


def freitext_probleme(pfad: str) -> list:
    """Migrate a fresh fixture with the free-text rows appended; list the rows that were wrongly changed (empty = right)."""
    _fixture_laden(pfad, FREI + [COMPANION])
    st, _ = _start(pfad)
    st.db.close()
    zeilen = _audit(pfad)
    neu = [(z[2], z[3], z[5]) for z in zeilen[len(PAIRS):]]
    problem = [f"changed: {alt} -> {nach}" for alt, nach in zip(FREI, neu[:-1]) if alt != nach]
    if neu[-1] != ("login_fail", "x", "password reason=no_account"):
        problem.append(f"companion not migrated: {neu[-1]}")
    return problem


r.check("(C) free text that merely contains a word of the vocabulary (`konto` without `=`, in a name, as the end of a "
        "word, behind `?`, `kein_konto` without its key, a name with `gelöscht#` inside) is not changed — and the "
        "companion row next to them is",
        freitext_probleme(_neuer_pfad("c.db")) == [], str(freitext_probleme(_neuer_pfad("c2.db"))[:3]))

# ═══ (D) The read paths take both spellings (a rollback leaves old rows behind) ═══════════════════════════
pfad_d = _neuer_pfad("d.db")
post_d: list = []
d = _aufbau(pfad_d, post_d)
st_d = d.store
JETZT = int(time.time())


def alt_zeile(ev, user, det, ip=None):
    """Write a row like another writer outside of this process (an older version, or the operator)."""
    _roh(pfad_d, ("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)", (JETZT, ev, user, ip, det)))


# recent_audit: hiding an event takes both spellings, in both directions
alt_zeile("sperrhinweis", "bob", "grund=lockout_serie")
alt_zeile("lockout_notice", "bob", "reason=lockout_series")
alt_zeile("login", "bob", "password")
ev_neu = [z["event"] for z in st_d.recent_audit(50, ohne_events=("lockout_notice",))]
ev_alt = [z["event"] for z in st_d.recent_audit(50, ohne_events=("sperrhinweis",))]
r.check("(D) `recent_audit(ohne_events=…)` hides the event in both spellings, whichever one is asked for",
        "sperrhinweis" not in ev_neu and "lockout_notice" not in ev_neu and "login" in ev_neu
        and "sperrhinweis" not in ev_alt and "lockout_notice" not in ev_alt and "login" in ev_alt, f"{ev_neu} {ev_alt}")
# recent_audit(username=<replacement name>)
alt_zeile("login", "gelöscht#42", "password")
alt_zeile("login", "deleted#42", "password")
alt_zeile("login", "deleted#4", "password")
r.check("(D) `recent_audit(username=…)` finds a replacement name in both spellings, and not another id",
        len(st_d.recent_audit(50, username="deleted#42")) == 2 and len(st_d.recent_audit(50, username="gelöscht#42")) == 2
        and len(st_d.recent_audit(50, username="deleted#4")) == 1)
# quellmail_seit: `konto=` and `account=`
bob = d.create_user("bob", password=PW, email="bob@example.com")
carol = d.create_user("carol", password=PW, email="carol@example.com")
alt_zeile("federation_email_confirm", "bob", f"konto={bob} quelle=ldap an=x@y.z")
r.check("(D) `quellmail_seit` recognises the old row (`konto=<id> `), not for another account",
        st_d.quellmail_seit(bob, 0) and not st_d.quellmail_seit(carol, 0))
alt_zeile("federation_email_confirm", "carol", f"account={carol} source=ldap to=x@y.z")
r.check("(D) … and the new row (`account=<id> `)", st_d.quellmail_seit(carol, 0))
# own_events: old and new rows of the same account
dora = d.create_user("dora", password=PW, email="dora@example.com")
for ev_, det, ip_ in (("email_change_taken", "neu=x@y.z beim_bestaetigen=1", "203.0.113.9"),
                      ("email_change_taken", "new=x@y.z on_confirmation=1", "203.0.113.9"),
                      ("email_change_taken", "neu=x@y.z", "203.0.113.9"),
                      ("email_change_taken", "new=x@y.z", "203.0.113.9"),
                      ("ldap_kennung_abgewiesen", "grund=kennung_zweier_konten lokal=3 verzeichnis=1", "203.0.113.9"),
                      ("ldap_identifier_rejected", "reason=identifier_of_two_accounts local=3 directory=1", "203.0.113.9"),
                      ("federation_email_confirm", "konto=3 quelle=ldap an=x@y.z", "203.0.113.9"),
                      ("oidc_widerruf", "client=wiki grund=gruppe", "203.0.113.9"),
                      ("password_reset", "uid=1 akteur=admin", "203.0.113.9"),
                      ("password_reset", "uid=1 actor=admin", "203.0.113.9")):
    alt_zeile(ev_, "dora", det, ip_)
own = d.own_events(dora, 50)
namen = [e["event"] for e in own]
r.check("(D) `own_events` hides the directory rejection and the confirmation mail row in both spellings",
        "ldap_kennung_abgewiesen" not in namen and "ldap_identifier_rejected" not in namen
        and "federation_email_confirm" not in namen, str(namen))
r.check("(D) … a conflict at confirmation (`beim_bestaetigen=1` and `on_confirmation=1`) keeps its event name, the "
        "same event at the request (`neu=`/`new=` only) shows as `email_change_requested`",
        namen.count("email_change_taken") == 2 and namen.count("email_change_requested") == 2, str(namen))
r.check("(D) … an old event name is shown in the English spelling",
        "oidc_revoked" in namen and "oidc_widerruf" not in namen, str(namen))
adm = [e for e in own if e["event"] == "password_reset"]
r.check("(D) … `akteur=` and `actor=` both mark the line as done by an admin (`by_admin`, no IP); the others keep their IP",
        [e["by_admin"] for e in adm] == [True, True] and all(e["ip"] is None for e in adm)
        and all(e["ip"] == "203.0.113.9" for e in own if e["event"] == "oidc_revoked"), str(adm))
# the lockout notice: a row of an older version still throttles the next one
eva = d.create_user("eva", password=PW, email="eva@example.com")
post_d.clear()
alt_zeile("sperrhinweis", "eva", "grund=lockout_serie")
d._sperrhinweis("eva", "203.0.113.1", "lockout_series")
d._hinweis_ausgang.abwarten()
r.check("(D) `_sperrhinweis`: a notice row in the OLD spelling inside the window throttles the next notice (no mail)",
        post_d == [], str(post_d))
fred = d.create_user("fred", password=PW, email="fred@example.com")
d._sperrhinweis("fred", "203.0.113.1", "lockout_series")
d._hinweis_ausgang.abwarten()
r.check("(D) … without one the notice goes out and is written in the new spelling",
        len(post_d) == 1 and st_d._one("SELECT detail FROM audit WHERE event='lockout_notice' AND username='fred'")["detail"]
        == "reason=lockout_series", str(post_d))
# deleting an account: old rows of the same account are anonymised as well
gus = d.create_user("gus", password=PW, email="gus@example.com")
hal = d.create_user("hal", password=PW, email="hal@example.com")
alt_zeile("password_reset", "hal", "uid=9 akteur=gus")
alt_zeile("password_reset", "hal", "uid=9 actor=gus")
alt_zeile("username_changed", "gus", "alt=gus0 durch=betreiber akteur=hal")
alt_zeile("email_change_requested", "gus", "neu=future@example.com")
d.delete_user(gus)
rest = " ".join(f"{z['event']} {z['username']} {z['detail']}" for z in st_d._all("SELECT * FROM audit"))
r.check("(D) `delete_user` finds the account in old rows too: `akteur=gus` and `actor=gus` both become `deleted#<id>`; "
        "its earlier name and a pending address are gone",
        f"akteur=deleted#{gus}" in rest and f"actor=deleted#{gus}" in rest and "=gus" not in rest
        and "gus0" not in rest and "future@" not in rest, rest[-300:])

# Display paths: the CLI and the panel show the new spelling for every row, old or new.
BLEIBT_ALT = re.compile(r"(?<!\S)(?:grund|konto|quelle|durch|akteur|alt|neu|an|verlangt|nachgetragen|wettlauf)=|gelöscht#|"
                        r"\boidc_widerruf\b|\bsperrhinweis\b|\bldap_kennung_|\blockout_serie\b")
alt_zeile("oidc_widerruf", "bob", "client=wiki grund=gruppe akteur=gelöscht#7")
alt_zeile("ldap_kennung_gebunden", "bob", "nachgebunden beim Login")
alt_zeile("oidc_widerruf", "gelöscht#7", "client=wiki grund=invalid_grant")
puffer_cli = io.StringIO()
with contextlib.redirect_stdout(puffer_cli):
    try:
        cli_main(["audit", "--db", pfad_d, "-n", "500"])
    except SystemExit:
        pass
cli = puffer_cli.getvalue()
r.check("(D) `tinysesam audit` shows the new spelling for old rows (event, `reason=`, `actor=deleted#7`, username) and "
        "leaves the new rows as they are",
        "oidc_revoked" in cli and "reason=group actor=deleted#7" in cli and "reason=invalid_grant" in cli
        and "deleted#7" in cli and "ldap_identifier_bound" in cli and "bound later at sign-in" in cli
        and "lockout_notice" in cli and "reason=lockout_series" in cli and not BLEIBT_ALT.search(cli),
        f"{BLEIBT_ALT.search(cli)} {cli[-600:]}")
d.create_user("chefin", password=PW, is_admin=True)
tc = TestClient(_app(d))
tc.post("/auth/login", data={"username": "chefin", "password": PW}, follow_redirects=False)
antwort = tc.get("/auth/admin/api/audit?limit=500")
zeilen_api = antwort.json() if antwort.status_code == 200 else []
text_api = " ".join(f"{z['event']} {z['username']} {z['detail']}" for z in zeilen_api)
r.check("(D) the panel API (`/api/audit`) shows the new spelling for old rows and does not mix: no old event, key or name",
        antwort.status_code == 200 and len(zeilen_api) > 20 and not BLEIBT_ALT.search(text_api)
        and "oidc_revoked" in text_api and "reason=group actor=deleted#7" in text_api, f"{antwort.status_code} {text_api[-300:]}")
st_d.db.close()

# The address-change conflict on confirmation is the `own_events` check above (`on_confirmation=1` / `beim_bestaetigen=1`).
# The trigger of a file that was rolled back keeps the OLD message; the caller must not depend on the text.
pfad_t = _neuer_pfad("t.db")
t0 = _aufbau(pfad_t)
t0.store.db.close()
for name_, sql_ in _lesen(pfad_t, "SELECT name, sql FROM sqlite_master WHERE type='trigger' AND name LIKE 'trg_users_kennung_%'"):
    _roh(pfad_t, f"DROP TRIGGER {name_};", sql_.replace("tinysesam: identifier taken", "tinysesam: kennung vergeben"))
def nicht_ersetzen(self):                                                   # a start that cannot rewrite the trigger
    raise sqlite3.OperationalError("attempt to write a readonly database")
with patch(Store, "_trigger_setzen", nicht_ersetzen):
    alt_trigger = kollision(pfad_t)
r.check("(D) a trigger that still carries the OLD message (`kennung vergeben`) aborts as well, and the caller reports "
        "the same `ConfigError` — it recognises the case by `IntegrityError`, not by the text",
        alt_trigger == ("ConfigError", "tinysesam: kennung vergeben"), str(alt_trigger))

# ═══ (E) A file that cannot be written starts anyway ════════════════════════════════════════════════
# Stamp 15 with old rows, as after a rollback, on a volume that was mounted read-only. The connection is opened with
# `mode=ro` (SQLite's own read-only mode, what the kernel does for a read-only mount): a file permission would not hold
# for a test that runs as root, and `PRAGMA query_only` also refuses the `BEGIN IMMEDIATE` of the start, which a real
# read-only file does not.
pfad_e = _neuer_pfad("e.db")
e0 = _aufbau(pfad_e)
e0.create_user("anna", password=PW)
e0.store.db.close()
_roh(pfad_e, ("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)",
              (int(time.time()), "oidc_widerruf", "anna", None, "client=wiki grund=gruppe akteur=gelöscht#7")))
_roh(pfad_e, ("INSERT INTO fehlserie(topf, art, anzahl, seit, zuletzt) VALUES ('anna', 'pin_folge', 2, 1, 2)"))
vor_e = _tabellen(pfad_e)
verbindung = sqlite3.connect


def nur_lesen(pfad, *a, **k):
    return verbindung(f"file:{pfad}?mode=ro", *a, uri=True, **k)


sqlite3.connect = nur_lesen
try:
    try:
        e1, log_e = _mitschreiben(lambda: _aufbau(pfad_e))
        start_e = "ok"
    except Exception as fehler:        # noqa: BLE001 — the start itself fails
        e1, log_e, start_e = None, "", f"{type(fehler).__name__}: {fehler}"
finally:
    sqlite3.connect = verbindung
r.check("(E) a read-only file at stamp 15 with old rows (event, detail, name, streak kind): the start succeeds",
        start_e == "ok" and _stempel(pfad_e) == 15, start_e)
if start_e == "ok":
    zeilen_e = e1.store.recent_audit(10)
    r.check("(E) … nothing is rewritten (the old rows are still there, byte for byte) and no log line claims it",
            _tabellen(pfad_e) == vor_e and MELDUNG not in log_e, log_e[-200:])
    r.check("(E) … and the old rows are read in the new spelling: `own_events`, the display mapping",
            [x["event"] for x in e1.own_events(1, 10)] == ["oidc_revoked"]
            and V.audit_zeile_neu(zeilen_e[0])["detail"] == "client=wiki reason=group actor=deleted#7")
    e1.store.db.close()

# ═══ (F) New code writes only the new spelling ═════════════════════════════════════════════════════════
pfad_f = _neuer_pfad("f.db")
post_f: list = []
f = _aufbau(pfad_f, post_f, apikey_allow_unlimited=True)
anna = f.create_user("anna", password=PW, email="anna@example.com")
bert = f.create_user("bert", password=PW, email="bert@example.com")
f.ensure_admin("chefin", PW)
cf = TestClient(_app(f))
cf.post("/auth/login", data={"username": "anna", "password": "falsch-falsch-1"}, follow_redirects=False)
cf.post("/auth/login", data={"username": "niemand", "password": "falsch-falsch-1"}, follow_redirects=False)
f.create_api_key(anna, name="ci", expires_days=0)
f.create_api_key(anna, name="cli", kind="human")
f.verify_api_key("tsk_" + "x" * 40)
f.change_username(anna, "anna2", "203.0.113.5")
f.change_username(bert, "bert2", "203.0.113.5", by_operator=True)
f.request_email_change(anna, "anna.neu@example.com", BASIS)()
f._sperrhinweis("anna2", "203.0.113.5", "lockout_series")
f._hinweis_ausgang.abwarten()
f.set_disabled(bert, True)
f.delete_user(bert)
zeilen_f = f.store._all("SELECT event, username, detail FROM audit ORDER BY id")
events_f = {z["event"] for z in zeilen_f}
text_f = " | ".join(f"{z['event']}:{z['username']}:{z['detail']}" for z in zeilen_f)
r.check("(F) real operations (wrong password, unknown name, API keys, rename by the user and by the operator, address "
        "change, lockout notice, lock, delete) leave rows — and none of them in the old spelling",
        {"login_fail", "apikey_create", "apikey_denied", "username_changed", "email_change_requested",
         "lockout_notice", "user_disable", "user_delete"} <= events_f
        and not [alt_vokabular(z["event"], z["username"], z["detail"]) for z in zeilen_f
                 if alt_vokabular(z["event"], z["username"], z["detail"])], text_f[-400:])
erwartet_f = ("reason=wrong_secret", "reason=no_account", "kind=human", "kind=automation", "expiry=unlimited",
              "old=anna", "by=operator", "reason=lockout_series", f"user_delete:deleted#{bert}:uid={bert} audit_anonymized=")
fehlt_f = [x for x in erwartet_f if x not in text_f]
r.check("(F) … in the expected new form: `reason=wrong_secret`/`reason=no_account`, `kind=human`/`kind=automation` "
        "with `expiry=unlimited`, `old=anna`, `by=operator`, `reason=lockout_series`, `deleted#<id>` with `audit_anonymized=`",
        not fehlt_f, f"missing {fehlt_f} in {text_f[-500:]}")
r.check("(F) the series kind and the method of a failed PIN step are written as `pin_chain` (no `pin_folge` anywhere "
        "in the tables)",
        not _lesen(pfad_f, "SELECT 1 FROM fehlserie WHERE art='pin_folge' UNION ALL "
                           "SELECT 1 FROM login_attempt WHERE method='pin_folge'"))
f.store.db.close()

# ═══ (G) Mutations: every guard turns the suite red when it is broken ═══════════════════════════════
# Each one breaks a COPY of a table or one function for the length of the block (never the source) and runs the same
# check function as the real run above; the suite is red exactly when that function reports a problem.
def mutiert(name: str, bruch, pruefung) -> None:
    """`pruefung` ran green above. Under the break `bruch()` (a context manager) it must find a problem."""
    with bruch():
        probleme = pruefung()
    r.check(f"mutation: {name} — the check turns red", bool(probleme), "the break was not noticed")


def ohne_eintrag(tabelle_name: str, schluessel: str):
    @contextlib.contextmanager
    def _b():
        kaputt = {k: v for k, v in getattr(V, tabelle_name).items() if k != schluessel}
        with patch(V, tabelle_name, kaputt):
            yield
    return _b


def frisch_fixture() -> str:
    p = _neuer_pfad("m.db")
    _fixture_laden(p)
    return p


r.check("mutation baseline: the unbroken fixture migration reports no problem",
        fixture_probleme(frisch_fixture()) == [])
mutiert("`oidc_widerruf` removed from AUDIT_EREIGNISSE_ALT", ohne_eintrag("AUDIT_EREIGNISSE_ALT", "oidc_widerruf"),
        lambda: fixture_probleme(frisch_fixture()))
mutiert("`sperrhinweis` removed from AUDIT_EREIGNISSE_ALT", ohne_eintrag("AUDIT_EREIGNISSE_ALT", "sperrhinweis"),
        lambda: fixture_probleme(frisch_fixture()))
mutiert("`_kennung_gebunden` removed from AUDIT_FAMILIEN_ALT", ohne_eintrag("AUDIT_FAMILIEN_ALT", "_kennung_gebunden"),
        lambda: fixture_probleme(frisch_fixture()))
mutiert("`_namensbindung_zu` removed from AUDIT_FAMILIEN_ALT", ohne_eintrag("AUDIT_FAMILIEN_ALT", "_namensbindung_zu"),
        lambda: fixture_probleme(frisch_fixture()))
mutiert("`pin_folge` removed from KINDS_ALT (the series kinds stay old)", ohne_eintrag("KINDS_ALT", "pin_folge"),
        lambda: fixture_probleme(frisch_fixture()))


def trigger_probleme() -> list:
    p = frisch_fixture()
    st, _ = _start(p)
    st.db.close()
    problem = []
    texte = trigger_texte(p)
    if len(texte) != 2 or not all("tinysesam: identifier taken" in t and "kennung vergeben" not in t for t in texte):
        problem.append("trigger text")
    if kollision(p) != ("ConfigError", "tinysesam: identifier taken"):
        problem.append("collision message")
    return problem


@contextlib.contextmanager
def ohne_token():
    """`kein_konto` missing in the value table of `reason=`: the key is renamed, its value stays German."""
    kaputt = {**V.AUDIT_WERTE_ALT, "reason": {k: v for k, v in V.AUDIT_WERTE_ALT["reason"].items() if k != "kein_konto"}}
    with patch(V, "AUDIT_WERTE_ALT", kaputt):
        yield


r.check("mutation baseline: the unbroken trigger replacement reports no problem", trigger_probleme() == [])
mutiert("the trigger message is still the old one", lambda: patch(Store, "KENNUNG_VERGEBEN", "tinysesam: kennung vergeben"),
        trigger_probleme)
mutiert("the replacement prefix is not translated (`deleted#` -> `deleted_`)", lambda: patch(V, "ERSATZ_PRAEFIX", "deleted_"),
        lambda: fixture_probleme(frisch_fixture()))
mutiert("`kein_konto` removed from the token table of `reason=`", ohne_token, lambda: fixture_probleme(frisch_fixture()))


@contextlib.contextmanager
def ohne_wortgrenze():
    """The key pattern without the word boundary in front: `mykonto=1` and `?konto=1` would be rewritten."""
    muster = re.compile(r"(" + "|".join(sorted(map(re.escape, V.AUDIT_SCHLUESSEL_ALT), key=len, reverse=True)) + r")=(\S*)")
    with patch(V, "_SCHLUESSEL_RE", muster):
        yield


mutiert("`audit_detail_neu` without the word boundary in front of the key", ohne_wortgrenze,
        lambda: freitext_probleme(_neuer_pfad("mf.db")))
mutiert("`audit_detail_neu` without the word boundary — the fixture rows themselves go wrong too", ohne_wortgrenze,
        lambda: fixture_probleme(frisch_fixture()))


@contextlib.contextmanager
def alles_ersetzen():
    """A value replaced anywhere in the text, not only behind its key (a token as a free word)."""
    echt = V.audit_detail_neu

    def kaputt(detail, event=None):
        detail = echt(detail, event)
        if isinstance(detail, str) and event not in V.FREITEXT_EREIGNISSE:
            for alt, neu in V.TOKENS_ALT.items():
                detail = re.sub(rf"(?<![\w=]){re.escape(alt)}(?!\w)", neu, detail)
        return detail
    with patch(V, "audit_detail_neu", kaputt):
        yield


mutiert("`audit_detail_neu` replaces a token as a free word (`kein_konto` without its key)", alles_ersetzen,
        lambda: freitext_probleme(_neuer_pfad("mt.db")))


@contextlib.contextmanager
def aufwand_ungeschuetzt():
    """The step writes every row again on every run, "just to be safe" (an unguarded UPDATE: it also fails on a read-only file)."""
    echt = Store._vokabular_englisch

    def kaputt(self):
        return echt(self) + self.db.execute("UPDATE audit SET detail = detail").rowcount
    with patch(Store, "_vokabular_englisch", kaputt):
        yield


@contextlib.contextmanager
def nicht_idempotent():
    """A mapping that is not idempotent: it adds a blank behind `reason=` on every pass."""
    echt = V.audit_detail_neu

    def kaputt(detail, event=None):
        detail = echt(detail, event)
        return detail.replace("reason=", "reason= ") if isinstance(detail, str) else detail
    with patch(V, "audit_detail_neu", kaputt):
        yield


def idempotenz_frisch() -> list:
    p = _neuer_pfad("mi.db")
    _fixture_laden(p)
    return idempotenz_probleme(p)


r.check("mutation baseline: the unbroken step is idempotent", idempotenz_frisch() == [])
mutiert("the step runs twice with effort (an unguarded UPDATE on every run)", aufwand_ungeschuetzt, idempotenz_frisch)
mutiert("the mapping is not idempotent (a second pass changes the text again)", nicht_idempotent, idempotenz_frisch)


# The read paths: break one spelling and the (D) checks must see it. The checks are re-run as functions.
def lesepfad_probleme() -> list:
    p = _neuer_pfad("ml.db")
    x = _aufbau(p)
    stx = x.store
    zeit = int(time.time()) + 60
    probleme = []
    u = x.create_user("dora", password=PW, email="dora@example.com")
    for ev_, det in (("sperrhinweis", "grund=lockout_serie"), ("lockout_notice", "reason=lockout_series"),
                     ("email_change_taken", "neu=x@y.z beim_bestaetigen=1"), ("email_change_taken", "new=x@y.z on_confirmation=1"),
                     ("password_reset", "uid=1 akteur=admin"), ("password_reset", "uid=1 actor=admin"),
                     ("ldap_kennung_abgewiesen", "grund=kennung_zweier_konten lokal=3 verzeichnis=1"),
                     ("federation_email_confirm", f"konto={u} quelle=ldap an=x@y.z")):
        _roh(p, ("INSERT INTO audit(ts, event, username, ip, detail) VALUES (?,?,?,?,?)", (zeit, ev_, "dora", "203.0.113.9", det)))
    ev = [z["event"] for z in stx.recent_audit(50, ohne_events=("lockout_notice",))]
    if "sperrhinweis" in ev or "lockout_notice" in ev:
        probleme.append("recent_audit shows a hidden event")
    eigen = x.own_events(u, 50)
    if [e["by_admin"] for e in eigen if e["event"] == "password_reset"] != [True, True]:
        probleme.append("own_events misses an actor")
    if [e["event"] for e in eigen].count("email_change_taken") != 2:
        probleme.append("own_events misses the conflict on confirmation")
    if "ldap_kennung_abgewiesen" in [e["event"] for e in eigen]:
        probleme.append("own_events shows the rejection")
    if not stx.quellmail_seit(u, 0):
        probleme.append("quellmail_seit misses the old row")
    stx.db.close()
    return probleme


r.check("mutation baseline: the unbroken read paths report no problem", lesepfad_probleme() == [])


@contextlib.contextmanager
def nur_neue_ereignisse():
    with patch(V, "ereignis_formen", lambda *ev: tuple(V.audit_ereignis_neu(e) for e in ev)):
        yield


@contextlib.contextmanager
def nur_neuer_schluessel():
    with patch(V, "detail_hat_schluessel", lambda detail, s: bool(detail) and (s + "=") in str(detail).split(" ")[0:99]
               or bool(detail) and any(t.startswith(s + "=") for t in str(detail).split(" "))):
        yield


@contextlib.contextmanager
def nur_neues_flag():
    with patch(V, "detail_hat_wert", lambda detail, s, w: bool(detail) and f"{s}={w}" in str(detail).split(" ")):
        yield


@contextlib.contextmanager
def quellmail_nur_neu():
    echt = Store.quellmail_seit

    def kaputt(self, user_id, seit):
        return bool(self._one("SELECT 1 FROM audit WHERE ts >= ? AND event IN (?, ?, ?) AND detail LIKE ? LIMIT 1",
                              (int(seit), *self.QUELLMAIL_ERLEDIGT, f"account={int(user_id)} %")))
    with patch(Store, "quellmail_seit", kaputt):
        yield


mutiert("`ereignis_formen` knows only the new spelling (an old event is no longer hidden)", nur_neue_ereignisse,
        lesepfad_probleme)
mutiert("`detail_hat_schluessel` knows only `actor=` (an old `akteur=` line shows the admin's IP)", nur_neuer_schluessel,
        lesepfad_probleme)
mutiert("`detail_hat_wert` knows only `on_confirmation=1` (the old conflict shows as a request)", nur_neues_flag,
        lesepfad_probleme)
mutiert("`quellmail_seit` looks only for `account=<id>`", quellmail_nur_neu, lesepfad_probleme)

raise SystemExit(r.done())
