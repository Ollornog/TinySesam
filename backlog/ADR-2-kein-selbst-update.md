---
id: ADR-2
type: Decision
title: Kein Selbst-Update — die Version bestimmt, wer installiert
status: erledigt
tags: [sicherheit, release]
created: 2026-07-09
---

# ADR-2 — Kein Selbst-Update

## Kontext

Bis 0.11 konnte sich TinySesam über eine Panel-Route selbst aktualisieren (`updater.py`,
`update_mode`, `update_pin`).

## Entscheidung

**Ersatzlos entfernt in 0.12.0.** Ein Hygiene-Test hält den Knopf draußen.

## Begründung

Ein Auth-Dienst, der sich selbst Code nachlädt, hebelt genau die Kontrolle aus, für die er da ist:
Wer das Panel übernimmt, übernimmt die nächste Version. Aktualisieren ist Sache dessen, der
installiert — über die Paketverwaltung oder das Container-Abbild.

## Konsequenzen

- `update_mode` und `update_pin` sind fort und dürfen nicht zurückkommen; ein Test erzwingt das.
- Wer aktualisiert, tauscht Tag oder Abbild-Digest.
