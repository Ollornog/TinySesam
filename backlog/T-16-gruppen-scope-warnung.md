---
id: T-16
type: Task
title: Warnen, wenn eine Gruppenregel über den Claim groups läuft und der Scope groups fehlt
status: erledigt
milestone: M-2
tags: [oidc, gruppen, konfiguration, pocketid, betrieb]
created: 2026-09-27
---

# T-16 — Gruppen-Scope: warnen statt still abweisen

**Fund aus dem Betrieb (2026-09-27, Einbau in eine App mit PocketID):** `oidc_allowed_groups` war
gesetzt, `oidc_group_claim` stand auf der Vorgabe `groups`, `oidc_scopes` auf der Vorgabe
`openid profile email`. PocketID schickt den Claim `groups` nur mit dem Scope `groups` — jeder
wurde abgewiesen („keine passende Gruppe“, Audit `oidc_group_denied`), und nichts beim Start
deutete auf die Ursache. Mit `oidc_group_role_map` wäre es leiser gewesen: keine Rolle, kein Fehler.

**Fertig, wenn:** die Konfigurationsprüfung warnt, sobald eine Gruppenregel (`oidc_allowed_groups`
oder `oidc_group_role_map`) über den Claim `groups` läuft und der Scope `groups` nicht angefordert
wird — je Client, auch für `oidc_clients` mit eigenen `scopes`; eine Warnung, kein Fehler, und
kein automatisches Nachfordern (andere Provider liefern den Claim über einen Mapper ohne Scope,
manche lehnen einen unbekannten Scope ab); das Gateway den Scope überhaupt setzen kann; Test und
Mutation.

## Erledigt 2026-09-27

- `konfigpruefung._gruppen_scope()`: eine Warnung, die die betroffenen Clients nennt und den Weg
  (`oidc_scopes`, Gateway `TINYSESAM_OIDC_SCOPES`, `scopes` am Eintrag). Schweigt für Entra ID
  (`login.microsoftonline.com`): Dort ist `groups` kein Scope, der Rat bräche die Anmeldung
  (AADSTS650053); Gruppen kommen als „optional claim“.
- Gateway: neue Variable `TINYSESAM_OIDC_SCOPES` (Vorgabe `openid profile email`). Ohne sie nahm
  das Preset immer die Vorgabe — der Rat der Warnung wäre im Gateway nicht umsetzbar gewesen.
- **SAML und LDAP:** kein Gegenstück in der Konfiguration. Es gibt dort keine Scopes; ob der IdP
  das Gruppenattribut freigibt oder das Verzeichnis `memberOf` liefert (OpenLDAP: memberof-Overlay),
  steht auf der anderen Seite. `docs/BETRIEB.md` nennt das Symptom (Audit `saml_denied
  grund=gruppe` bzw. `ldap_group_denied` für jeden).
- Test: `tests/test_betriebsfunde.py` (a) — Warnung mit allowed_groups und mit dem Rollen-Mapping,
  keine mit Scope, ohne Regel, mit anderem Claim, ohne OIDC, bei Entra ID; je Anwendung; Gateway
  mit und ohne `TINYSESAM_OIDC_SCOPES`. Doku: README EN/DE (Rollen & Gruppen), `docs/BETRIEB.md`,
  Compose-Beispiel, CHANGELOG.
