---
id: T-25
type: Task
title: E2E-Bühne — die OIDC-Zeremonie scheitert am Identity Provider
status: erledigt
milestone: M-2
tags: [e2e, oidc, stage]
created: 2026-10-03
---

# T-25 — OIDC auf der E2E-Bühne wieder grün

Seit v0.20.1 läuft `tests/e2e_stage.py` auf der Bühne ([T-6](T-6-stage-per-playbook.md)) für Passkey und SAML grün,
für **OIDC rot**. Der Provider (PocketID) lehnt die Anmeldung ab mit „You are not allowed to access this service“.

**Ursache:** Das Testkonto gehört keiner Gruppe, die für den OIDC-Client der Bühne freigegeben ist. Seit PocketID v2
ist ein Client ohne Gruppenfreigabe für niemanden offen. Das ist kein Fehler in TinySesam, aber solange OIDC rot ist,
prüft der E2E-Lauf nur zwei der drei Wege aus [T-1](T-1-e2e-gegen-echten-idp.md).

## Die Bühne wird je Lauf neu gebaut

Entscheidung vom 2026-10-03: Die Bühne ist kein Dauerbetrieb. Sie wird aufgebaut, der Lauf fährt, danach wird sie
abgebaut. Die Freigabe muss deshalb dort liegen, wo sie einen Neubau überlebt: beim Provider (Gruppe des Testkontos
bzw. freigegebene Gruppe des Clients), nicht in der Bühne.

## Fertig, wenn

- Das Testkonto beim Provider einer Gruppe angehört, die für den Client der Bühne freigegeben ist, oder der Client
  eine eigene Testgruppe freigibt.
- Ein Lauf auf einer **frisch gebauten** Bühne alle drei Wege grün meldet.
- Die Gegenprobe hält: Ohne die Freigabe wird OIDC rot und nicht stillschweigend übersprungen.

Verwandt: [T-14](T-14-mehrere-oidc-clients.md) — die Freigabe je App liegt beim Identity Provider.

## Erledigt 2026-10-07

- Beim Provider eine eigene Testgruppe angelegt (PO-Freigabe 2026-10-07). Mitglied ist nur das Testkonto,
  freigegeben nur für den OIDC-Client der Bühne. Die übrigen Gruppen und Clients sind unverändert.
- Lauf auf einer **frisch gebauten** Bühne (Stand `main` nach T-18): `passkey: grün · saml: grün · oidc: grün`,
  OIDC angemeldet als das Testkonto.
- Gegenprobe: Testkonto aus der Gruppe genommen, derselbe Lauf → `oidc: ROT` („You are not allowed to access
  this service“), Exit 1 — rot, nicht übersprungen. Danach Mitgliedschaft wiederhergestellt, Bühne abgebaut.
