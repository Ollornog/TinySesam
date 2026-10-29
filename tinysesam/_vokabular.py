"""The stored and logged key vocabulary: German up to 0.24.x, English from schema 15.

Until then the audit log (`audit.event`, `audit.detail`, `audit.username`), the security log and two
stored kinds (`fehlserie.art`, `login_attempt.method`) carried German event names, `key=value` keys and
tokens (`grund=kein_konto`, `oidc_widerruf`, `gelöscht#<id>`). The PO decision of 2026-10-29 made them
English; `Store._vokabular_englisch` rewrites existing databases once (schema 15).

This module holds the mapping as **pure functions without database access**, so that one source serves

* the migration (`Store._vokabular_englisch`),
* every read path that must accept an old row as well as a new one — an older version that ran on the file
  after a rollback, or a writer outside this process, leaves old values behind again
  (`Store.recent_audit`, `Store.quellmail_seit`, `Store.audit_anonymisieren`,
  `TinySesam.own_events`, `TinySesam._sperrhinweis`, the panel and `tinysesam audit`), and
* the tests (a fixture with old values must come out as the new form, and the new form must stay as it is).

Rules that hold for every function here:

* **Idempotent.** A value that is already in the new form comes back unchanged; applying a function twice
  changes nothing more than applying it once.
* **Nothing is guessed.** Only the names in the tables below are mapped; free text that merely contains a
  similar word stays untouched. A key is replaced only where it stands as a key: at the start of the detail
  or after a space, directly followed by `=`. A value is replaced only behind the key it belongs to
  (`reason=kein_konto`, not the word `kein_konto` anywhere).
* **Read paths take both forms.** `ereignis_formen` gives the new and the old spelling of an event name for
  an SQL `IN (…)`, `detail_hat_schluessel` finds a key in either spelling.
"""
from __future__ import annotations

import re
from typing import Optional

#: The sources whose audit events carry the family names (`<source>_kennung_gebunden` …).
AUDIT_QUELLEN = ("oidc", "saml", "ldap")

#: Audit event names up to 0.24.x and their English replacement (exact names).
#: `login_lokal` is written when a sign-in was settled locally while LDAP is switched on; `quelle_email_taken`
#: only by a caller that names no source.
AUDIT_EREIGNISSE_ALT = {
    "api_keys_ruhen": "api_keys_dormant",
    "lockout_serie": "lockout_series",
    "login_lokal": "login_local",
    "oidc_unbestaetigt": "oidc_unconfirmed",
    "oidc_widerruf": "oidc_revoked",
    "quelle_email_taken": "source_email_taken",
    "recovery_verwaist_geloescht": "recovery_orphan_deleted",
    "sperrhinweis": "lockout_notice",
}

#: The families `<source>_<suffix>` with `source` from `AUDIT_QUELLEN`: old suffix → new suffix.
AUDIT_FAMILIEN_ALT = {
    "_kennung_abgewiesen": "_identifier_rejected",
    "_kennung_gebunden": "_identifier_bound",
    "_kennung_geloest": "_identifier_unbound",
    "_kennung_ungueltig": "_identifier_invalid",
    "_kennung_wechsel": "_identifier_change",
    "_namensbindung_zu": "_name_binding_closed",
    "_ohne_kennung": "_without_identifier",
}

#: Keys in `key=value` form (audit detail, security log) up to 0.24.x and their English replacement.
AUDIT_SCHLUESSEL_ALT = {
    "grund": "reason",
    "konto": "account",
    "quelle": "source",
    "durch": "by",
    "akteur": "actor",
    "alt": "old",
    "neu": "new",
    "an": "to",
    "anzahl": "count",
    "beleg": "proof",
    "verlangt": "required",
    "verwendet": "used",
    "nachgetragen": "backfilled",
    "fehlversuche": "failed_attempts",
    "in_folge": "in_a_row",
    "fehlversuche_in_folge": "failed_in_a_row",
    "fehlversuche_verworfen": "failed_attempts_discarded",
    "kennung": "identifier",
    "lokal": "local",
    "verzeichnis": "directory",
    "zweck": "purpose",
    "fehlt": "missing",
    "ohne_konto": "without_account",
    "gruppe_entfallen": "group_removed",
    "beim_bestaetigen": "on_confirmation",
    "nach_einschreibung": "after_enrollment",
    "namensbindung_offen_bis": "name_binding_open_until",
    "recovery_codes_geloescht": "recovery_codes_deleted",
    "audit_anonymisiert": "audit_anonymized",
    "verbleibend": "remaining",
    "art": "kind",
    "ablauf": "expiry",
    "verworfene_rollen": "dropped_roles",
    "stunden": "hours",
    "minuten": "minutes",
    "wettlauf": "race",
    "rollen": "roles",
}

#: Tokens (the value behind `reason=`, and the reasons that `Store`/`TinySesam` hand on to the log) up to
#: 0.24.x and their English replacement. `lockout_serie` is also the reason code of a lock by the streak
#: of failed attempts; `pin_folge` is the kind of the streak behind an already provided factor (stored in
#: `fehlserie.art`, mapped by `kind_neu`, not by `reason=`).
TOKENS_ALT = {
    "kein_konto": "no_account",
    "konto_gesperrt": "account_locked",
    "falsches_geheimnis": "wrong_secret",
    "falsches_bereichsgeheimnis": "wrong_area_secret",
    "kein_passwort_gesetzt": "no_password_set",
    "ungueltig": "invalid",
    "unbekannt": "unknown",
    "fehlt": "missing",
    "veraltet": "stale",
    "widerrufen": "revoked",
    "abgelaufen": "expired",
    "api_key_ungueltig": "api_key_invalid",
    "sitzung_ungueltig": "session_invalid",
    "mfa_offen": "mfa_open",
    "email_unbestaetigt": "email_unconfirmed",
    "idp_unbestaetigt": "idp_unconfirmed",
    "idp_nein": "idp_no",
    "gruppe": "group",
    "kennung_zweier_konten": "identifier_of_two_accounts",
    "kein_name": "no_name",
    "bereits_bestaetigt": "already_confirmed",
    "unbekannter_schluessel": "unknown_key",
    "wiederholt": "repeated",
    "lockout_serie": "lockout_series",
    # the codes of `_NACHBINDUNG_PROTOKOLL` (reason why an account is not bound via its name)
    "adresse_als_name": "address_as_name",
    "kennung_ungueltig": "invalid_identifier",
    "konflikt": "conflict",
    "anders_gebunden": "bound_elsewhere",
    "name_selbst_gewaehlt": "self_chosen_name",
    "name_aus_quelle": "name_from_other_source",
    "frist": "binding_window_expired",
}

#: The kinds of the streak of failed attempts (`fehlserie.art`) and the methods in `login_attempt.method`.
KINDS_ALT = {"pin_folge": "pin_chain"}

#: The values of other keys: key (new spelling) → {old value → new value}. `reason` is `TOKENS_ALT`.
AUDIT_WERTE_ALT = {
    "reason": TOKENS_ALT,
    "source": {"erst_admin": "first_admin", "lokal": "local", "lokal+ldap": "local+ldap",
               "quelle": "source"},
    "by": {"betreiber": "operator"},
    "kind": {"automat": "automation", "mensch": "human"},
    "expiry": {"unbefristet": "unlimited"},
    "directory": {"neu": "new"},
}

#: Details that are one fixed phrase and belong to a family/event: (event suffix or name, old detail) → new.
#: Only used with an `event`: the same words as the detail of another event are not touched.
_FESTE_DETAILS_ALT = {
    ("_without_identifier", "abgewiesen"): "rejected",
    ("_without_identifier", "abgewiesen: Adresse als Name"): "rejected: address as name",
    ("_identifier_bound", "nachgebunden beim Login"): "bound later at sign-in",
    ("_identifier_invalid", "Rand-/Steuerzeichen"): "edge_or_control_characters",
    ("_identifier_invalid", "Platzhalter-Form"): "placeholder_form",
    ("admin_bootstrap_denied", "nach_idp_entzug"): "after_idp_withdrawal",
    ("admin_bootstrap_denied", "email_unbestaetigt"): "email_unconfirmed",
    ("owner_grant", "quelle=bestand aeltester_admin"): "source=existing oldest_admin",
}

#: Events whose detail is free text of a third party (an exception text, a realm name, a username in
#: front): no key in it is replaced.
FREITEXT_EREIGNISSE = frozenset({"ldap_unavailable", "resource_unlock", "user_create"})

#: The replacement name of a deleted account in the audit log: `deleted#<id>` (was `gelöscht#<id>`).
ERSATZ_PRAEFIX = "deleted#"
ERSATZ_PRAEFIX_ALT = "gelöscht#"

_NEU_ZU_ALT_EREIGNIS = {neu: alt for alt, neu in AUDIT_EREIGNISSE_ALT.items()}
_NEU_ZU_ALT_FAMILIE = {neu: alt for alt, neu in AUDIT_FAMILIEN_ALT.items()}
_SCHLUESSEL_NEU_ZU_ALT = {neu: alt for alt, neu in AUDIT_SCHLUESSEL_ALT.items()}

# A key stands at the start of the detail or after whitespace and is followed by `=`: `(?<!\S)key=`.
# Longest key first, so that `fehlversuche_in_folge` is not taken for `fehlversuche`.
_SCHLUESSEL_RE = re.compile(
    r"(?<!\S)(" + "|".join(sorted(map(re.escape, AUDIT_SCHLUESSEL_ALT), key=len, reverse=True)) + r")=(\S*)")
_ERSATZ_RE = re.compile(r"(?<![\w@.-])" + re.escape(ERSATZ_PRAEFIX_ALT) + r"(?=\d)")
_ERSATZ_VOLL_RE = re.compile(r"^" + re.escape(ERSATZ_PRAEFIX_ALT) + r"(\d+)$")
_DROSSEL_TEXT_RE = re.compile(r"^mehr als (\d+) in (\d+)s — weitere nur im Sicherheits-Log$")
_OHNE_BELEG_RE = re.compile(r"^ohne_beleg:")
# `username_changed`: `alt=<name, may contain spaces>[ durch=…][ quelle=…][ akteur=…]` — the name ends at the first
# of these markers (the same parse as `Store._ALT_NAME`).
_NAMENSWECHSEL_RE = re.compile(r"^alt=(.*?)(?= durch=| quelle=| akteur=|$)(.*)$", re.S)


def audit_ereignis_neu(event):
    """The English spelling of an audit event name; an unknown name (and one already English) comes
    back as it is. Also the families `<oidc|saml|ldap>_kennung_gebunden` etc."""
    if not isinstance(event, str):
        return event
    neu = AUDIT_EREIGNISSE_ALT.get(event)
    if neu is not None:
        return neu
    for quelle in AUDIT_QUELLEN:
        if event.startswith(quelle + "_"):
            rest = event[len(quelle):]
            if rest in AUDIT_FAMILIEN_ALT:
                return quelle + AUDIT_FAMILIEN_ALT[rest]
    return event


def audit_ereignis_alt(event):
    """The spelling of an audit event name up to 0.24.x (the reverse of `audit_ereignis_neu`)."""
    if not isinstance(event, str):
        return event
    alt = _NEU_ZU_ALT_EREIGNIS.get(event)
    if alt is not None:
        return alt
    for quelle in AUDIT_QUELLEN:
        if event.startswith(quelle + "_"):
            rest = event[len(quelle):]
            if rest in _NEU_ZU_ALT_FAMILIE:
                return quelle + _NEU_ZU_ALT_FAMILIE[rest]
    return event


def ereignis_formen(*events) -> tuple:
    """Every spelling (new, then old) of these event names, without duplicates — for an SQL `IN (…)`
    or `NOT IN (…)`. An event with only one spelling appears once."""
    aus: list = []
    for e in events:
        for form in (audit_ereignis_neu(e), audit_ereignis_alt(audit_ereignis_neu(e))):
            if form not in aus:
                aus.append(form)
    return tuple(aus)


def kind_neu(kind):
    """`fehlserie.art` / `login_attempt.method` in the English spelling (`pin_folge` → `pin_chain`)."""
    return KINDS_ALT.get(kind, kind) if isinstance(kind, str) else kind


def ersatzname_neu(name):
    """`gelöscht#<id>` → `deleted#<id>`; every other name unchanged."""
    if isinstance(name, str):
        m = _ERSATZ_VOLL_RE.match(name)
        if m:
            return ERSATZ_PRAEFIX + m.group(1)
    return name


def ist_ersatzname(name) -> bool:
    """Is this the replacement name of a deleted account (`deleted#<id>`, or up to 0.24.x `gelöscht#<id>`)?"""
    if not isinstance(name, str):
        return False
    for praefix in (ERSATZ_PRAEFIX, ERSATZ_PRAEFIX_ALT):
        if name.startswith(praefix) and name[len(praefix):].isascii() and name[len(praefix):].isdigit():
            return True
    return False


def ersatz_formen(name) -> tuple:
    """A name for an SQL `lower(username) IN (…)`: a replacement name in both spellings (`deleted#4` and
    `gelöscht#4`), every other name as it is — a row of an older version after a rollback carries the old one."""
    if isinstance(name, str):
        for praefix in (ERSATZ_PRAEFIX, ERSATZ_PRAEFIX_ALT):
            rest = name[len(praefix):]
            if name.startswith(praefix) and rest.isascii() and rest.isdigit():
                return (ERSATZ_PRAEFIX + rest, ERSATZ_PRAEFIX_ALT + rest)
    return (name,)


def _ersetzen(m: "re.Match") -> str:
    schluessel = AUDIT_SCHLUESSEL_ALT[m.group(1)]
    wert = m.group(2)
    wert = AUDIT_WERTE_ALT.get(schluessel, {}).get(wert, wert)
    return f"{schluessel}={wert}"


def _schluessel_neu(detail: str) -> str:
    return _SCHLUESSEL_RE.sub(_ersetzen, detail)


def audit_detail_neu(detail, event: Optional[str] = None):
    """The detail text of an audit row in the English spelling: keys and tokens as in the tables above,
    `gelöscht#<id>` as `deleted#<id>`. `None`/empty come back as they are.

    With the `event` of the row (old or new spelling) the fixed phrases of that event are mapped too
    (`abgewiesen`, `nachgebunden beim Login`, `nach_idp_entzug`, …); without it only keys, tokens and the
    replacement name. A detail of a free-text event (`FREITEXT_EREIGNISSE`) keeps its keys.

    Idempotent: a new-form detail comes back unchanged."""
    if not isinstance(detail, str) or not detail:
        return detail
    ev = audit_ereignis_neu(event) if isinstance(event, str) else ""
    if ev:
        for (ziel, alt), neu in _FESTE_DETAILS_ALT.items():
            if detail == alt and (ev == ziel or (ziel.startswith("_") and ev.endswith(ziel))):
                return neu
        if ev == "token_invalid_throttled":
            m = _DROSSEL_TEXT_RE.match(detail)
            if m:
                return f"more than {m.group(1)} in {m.group(2)}s — further ones only in the security log"
        if ev == "admin_bootstrap_denied":
            detail = _OHNE_BELEG_RE.sub("without_proof:", detail)
    if ev in FREITEXT_EREIGNISSE:
        return _ERSATZ_RE.sub(ERSATZ_PRAEFIX, detail)
    if ev == "username_changed":
        if detail.startswith("old="):      # already the new form: the name in it is free text
            return _ERSATZ_RE.sub(ERSATZ_PRAEFIX, detail)
        m = _NAMENSWECHSEL_RE.match(detail)
        if m:        # the old name is free text: only the tail behind it carries keys
            detail = "old=" + m.group(1) + _schluessel_neu(m.group(2))
            return _ERSATZ_RE.sub(ERSATZ_PRAEFIX, detail)
    return _ERSATZ_RE.sub(ERSATZ_PRAEFIX, _schluessel_neu(detail))


def detail_hat_schluessel(detail, schluessel: str) -> bool:
    """Does the detail contain this key — in its English spelling or the one up to 0.24.x? Directly
    behind the start or a space, followed by `=`. `schluessel` is the NEW spelling (`actor`, …)."""
    if not detail:
        return False
    formen = {schluessel, _SCHLUESSEL_NEU_ZU_ALT.get(schluessel, schluessel)}
    return re.search(r"(?<!\S)(?:" + "|".join(map(re.escape, sorted(formen))) + r")=", detail) is not None


def detail_hat_wert(detail, schluessel: str, wert: str) -> bool:
    """`key=value` as a whole word (value up to the next space) in either spelling of the key — for flags
    such as `on_confirmation=1`. `schluessel` and `wert` are the NEW spelling."""
    if not detail:
        return False
    formen = {schluessel, _SCHLUESSEL_NEU_ZU_ALT.get(schluessel, schluessel)}
    return re.search(r"(?<!\S)(?:" + "|".join(map(re.escape, sorted(formen))) + r")="
                     + re.escape(wert) + r"(?!\S)", detail) is not None


def audit_zeile_neu(zeile) -> dict:
    """An audit row (`sqlite3.Row` or dict) as a dict in the English spelling: `event`, `detail`, and a
    replacement name in `username`. Other fields as they are. For every display path (panel, CLI, account
    page)."""
    d = dict(zeile)
    d["event"] = audit_ereignis_neu(d.get("event"))
    d["detail"] = audit_detail_neu(d.get("detail"), d.get("event"))
    d["username"] = ersatzname_neu(d.get("username"))
    return d
