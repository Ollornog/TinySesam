---
id: T-11
type: Task
title: zizmor meldet 2× excessive-permissions — blockiert den Push, sobald das Gate scharf ist
status: offen
milestone: M-1
tags: [ci, sicherheit, workflows]
created: 2026-09-22
---

# T-11 — zizmor: `excessive-permissions` in den Workflows

**Gefunden am 2026-09-22** bei einer repoübergreifenden CI-Härtung, nicht in diesem Repo selbst.

## Worum es geht

`ci-infra` verankert `actionlint` und `zizmor` fest in `ci-local` — also **vor jeder Suite und
damit vor jedem Push** (der `pre-push`-Hook ruft `ci-local`). Gemessen wurde dabei: TinySesam ist
mit dem neuen Gate **rot**, mit **zwei** `excessive-permissions`-Befunden von zizmor.

Das heißt konkret: Sobald `ci-infra#27` gemergt ist, scheitert hier jeder `git push` — an einem
Befund, der nichts mit der jeweiligen Änderung zu tun hat.

## Was zu tun ist

Die beiden Stellen haben zu weite `permissions:`-Blöcke. zizmor nennt Datei und Zeile:

```bash
docker run --rm -v "$PWD:/repo" -w /repo ghcr.io/zizmorcore/zizmor:latest --persona=regular .
```

Richtig ist das kleinstmögliche Recht je Job, nicht je Workflow — GitHub setzt alle übrigen
Berechtigungen automatisch auf `none`, sobald **eine** explizit gesetzt ist.

## Warum es nicht sofort behoben wurde

Am 2026-09-22 arbeitete parallel ein Agent an diesem Repo (PR #55, OIDC-Discovery). Der PO hat
TinySesam deshalb ausdrücklich aus der Härtungsrunde ausgenommen — ein zweiter Schreiber im selben
Arbeitsbaum ist teurer als ein Tag Verzögerung. Die betroffene Sitzung wurde gewarnt.

## Notausgang, falls es dringend wird

`git push --no-verify` umgeht den Hook. Das ist hier vertretbar, weil die GitHub-CI weiterhin
prüft — aber es ist ein Notausgang, keine Lösung: die Befunde sind echt.

## Zusammenhang

Zweite Falle derselben Runde: `~/.local/bin/ci-local` ist ein **Symlink in einen auscheckbaren
Arbeitsbaum**. Das Gate hing dadurch zeitweise am unversionierten Zwischenstand eines fremden
Agenten — derselbe Commit war um 01:31 grün und um 01:33 rot. Wer hier einen unerklärlichen
Push-Fehlschlag sieht, prüft zuerst, worauf `ci-infra` gerade ausgecheckt ist.
