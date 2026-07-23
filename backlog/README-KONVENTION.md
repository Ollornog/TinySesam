# Backlog — Konvention

Der Backlog dieses Repos ist **Markdown im Repo**, keine externe Liste. Eine Datei je Vorgang,
Frontmatter für die Struktur, Rumpf für die Begründung.

## Warum hier und nicht in GitHub Issues

**Issues sind der Posteingang, dieser Ordner ist die Wahrheit.** Jeder darf ein Issue öffnen —
Bugreports, Wünsche, Fragen. Was davon angenommen wird, bekommt hier einen Eintrag. Gründe:

- **Der Eintrag wandert im selben Commit wie der Code.** Ein Task schließt sich im PR, der ihn
  erledigt — im Diff sichtbar, nicht in einem separaten Board.
- **Die Hygiene-Prüfung greift.** `scripts/check.sh` liest den Backlog wie jede andere Datei mit;
  eine interne Adresse fällt sofort auf. In einem Issue fängt sie niemand — nie.
- **Offline und ohne Token.** Kein API-Zugriff nötig, um zu wissen, was ansteht.
- **Versioniert.** Warum eine Entscheidung fiel, steht neben dem Code, den sie erklärt.

## Frontmatter

```yaml
---
id: T-12                 # Pflicht. M-/T-/ADR-/B- + Zahl, eindeutig, = Dateiname-Präfix
type: Task               # Pflicht: Milestone | Task | Decision | Bug
title: Kurzer Satz       # Pflicht
status: offen            # Pflicht: offen | in-arbeit | erledigt | verworfen
milestone: M-1           # Pflicht bei Task und Bug
blocked_by: [T-11]       # optional
superseded_by: ADR-7     # Pflicht bei verworfenen Decisions
tags: [auth, cookies]
created: 2026-07-23
---
```

Enthält ein Wert einen Doppelpunkt, gehört er in Anführungszeichen.

## Die vier Typen

| Typ | wofür | Rumpf enthält |
|---|---|---|
| **Milestone** | eine Reihe von Aufgaben mit gemeinsamem Ziel | Was ist wahr, wenn er fertig ist |
| **Task** | eine Arbeitseinheit | Was zu tun ist, woran man Fertigsein erkennt |
| **Decision** | Architekturentscheidung (ADR) | Kontext · Optionen · Wahl · Konsequenzen |
| **Bug** | reproduzierbarer Defekt | Repro-Schritte, erwartetes vs. tatsächliches Verhalten |

## Entscheidungen werden nicht gelöscht

Ändert sich eine Entscheidung, bekommt die alte `status: verworfen` **und** `superseded_by`.
Sie bleibt lesbar. Wer später fragt „warum eigentlich nicht X?", findet die Antwort statt sie
neu zu erarbeiten — und sieht, dass sie überholt ist. Ein Wächter erzwingt den Verweis: eine
verworfene Entscheidung ohne Nachfolger ist eine Sackgasse.

## Bedienung

```bash
python3 scripts/_backlog.py list            # offene Punkte nach Meilenstein
python3 scripts/_backlog.py list --alle     # auch erledigte
python3 scripts/_backlog.py list --type Decision
python3 scripts/_backlog.py check           # Strukturprüfung (läuft auch in der Suite)
python3 scripts/_backlog.py index           # README.md neu erzeugen
```

`README.md` ist **generiert** — nie von Hand pflegen.
