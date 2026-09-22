---
id: T-11
type: Task
title: zizmor excessive-permissions — bei Anlage bereits behoben, Eintrag bleibt als Lehre
status: erledigt
milestone: M-1
tags: [ci, sicherheit, workflows]
created: 2026-09-22
---

# T-11 — zizmor: `excessive-permissions` (gegenstandslos)

**Angelegt und am selben Tag zurückgezogen.** Der Eintrag bleibt stehen, weil der Fehler
lehrreicher ist als der angebliche Befund.

## Was behauptet wurde

Bei einer repoübergreifenden CI-Härtung am 2026-09-22 meldete ein Agent, TinySesam sei mit dem
neuen Gate (`actionlint` + `zizmor` in `ci-local`) rot — **2× `excessive-permissions`**. Daraus
wurde eine Warnung an die laufende Sitzung und dieser Backlog-Punkt.

## Was tatsächlich galt

Die Befunde waren zu dem Zeitpunkt **schon behoben**: PR #53 (gemergt als `230b10e`, 01:40)
trägt `pages:write`/`id-token:write` nur noch im deploy-Job von `pages.yml`. Nachgemessen gegen
`origin/main`:

```
zizmor --persona=regular  →  26 findings, davon 0 high, 0× excessive-permissions
```

Die Gegenmessung lief bewusst **nicht** im Arbeitsbaum (dort stand ein Audit-Branch), sondern
gegen die aus `origin/main` geholten Workflow-Dateien in einem Wegwerf-Verzeichnis.

## Die Lehre

**Ein Befund altert.** Zwischen Messung und Meldung lagen hier wenige Stunden, und in dieser Zeit
wurde die Ursache in einem anderen PR behoben. Wer einen fremden Befund weiterreicht, misst ihn
**gegen den Stand nach**, auf den er sich bezieht — nicht gegen den, bei dem er entstand.
Zweiter Teil derselben Lehre: Der Agent maß gegen einen Branch, nicht gegen `main`.

Dieselbe Klasse wie der Fehlalarm `REPLACE_ME_TOKEN` am selben Tag: formal korrekt gemessen,
inhaltlich falsch.

## Was davon bestehen bleibt

Die zweite Beobachtung der Runde ist **echt und unabhängig davon**:
`~/.local/bin/ci-local` ist ein **Symlink in einen auscheckbaren Arbeitsbaum**. Das lokale Gate
hängt damit am gerade ausgecheckten Stand von `ci-infra` — derselbe Commit war um 01:31 grün und
um 01:33 rot. Wer hier einen unerklärlichen Push-Fehlschlag sieht, prüft zuerst, worauf `ci-infra`
gerade ausgecheckt ist. Geführt wird das im Tower-Register `context/pipeline-fehler.md`.
