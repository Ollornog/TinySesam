---
id: ADR-1
type: Decision
title: PyPI-Veröffentlichung bis 1.0 vertagt
status: erledigt
tags: [release, supply-chain]
created: 2026-07-10
---

# ADR-1 — PyPI-Veröffentlichung bis 1.0 vertagt

## Kontext

Ein Auth-Paket ließe sich per `pip install` deutlich bequemer einbinden als über einen gepinnten
Git-Tag. Die Namen sind frei.

## Optionen

1. **Jetzt veröffentlichen** — bequemste Installation, größte Reichweite.
2. **Bis 1.0 warten** — Installation über gepinnten Git-Tag.

## Entscheidung

**Warten (2).**

## Begründung

- **Jede PyPI-Version ist unwiderruflich.** Die API bewegt sich noch — 0.12.0 hat das
  Selbst-Update ersatzlos entfernt ([ADR-2](ADR-2-kein-selbst-update.md)). Ein Paket, dessen
  Oberfläche sich in Monatsabständen ändert, gehört nicht in einen unveränderlichen Index.
- **Ein Auth-Paket ist ein Supply-Chain-Ziel.** Wer das Konto übernimmt, schiebt Code in fremde
  Anmeldevorgänge. Der gepinnte Tag verlagert das Vertrauen auf einen Commit-Hash.

## Konsequenzen

- Installation läuft bis 1.0 über `pip install git+…@<tag>`.
- Wenn veröffentlicht wird, dann mit **Trusted Publishing** (PyPI vertraut dem Workflow per OIDC),
  kein Token im Repo.
- Zu prüfen bei [M-1](M-1-api-stabil-1-0.md).
