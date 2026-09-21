---
id: ADR-1
type: Decision
title: PyPI-Veröffentlichung bis 1.0 vertagt
status: verworfen
superseded_by: ADR-6
tags: [release, supply-chain]
created: 2026-07-10
---

# ADR-1 — PyPI-Veröffentlichung bis 1.0 vertagt

> **Überholt durch [ADR-6](ADR-6-pypi-veroeffentlichen.md) (2026-09-21).** Was unten steht, war
> richtig, solange die Bedingung nicht erfüllt war: Die Entscheidung lautete „bis 1.0 warten", und
> mit 1.0 ist genau dieser Punkt erreicht. Der Text bleibt stehen, weil die Gründe nicht hinfällig
> sind — sie sind beantwortet, und ADR-6 sagt womit.

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

## Nachtrag (2026-09-21)

Eingelöst wurde beides, was hier als Auflage stand: Veröffentlicht wird per **Trusted Publishing**,
und der Zeitpunkt ist 1.0. Was die Begründung angeht, ist nur der erste Punkt überholt — die API
wird seit 0.16.0 gemessen statt behauptet. Der zweite (Auth-Paket als Lieferketten-Ziel) gilt
unverändert; ADR-6 beantwortet ihn, statt ihn zu verwerfen.
