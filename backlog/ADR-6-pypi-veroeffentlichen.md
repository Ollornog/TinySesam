---
id: ADR-6
type: Decision
title: TinySesam wird ab 1.0 auf PyPI veröffentlicht
status: erledigt
supersedes: ADR-1
tags: [release, supply-chain, pypi]
created: 2026-09-21
---

# ADR-6 — TinySesam wird ab 1.0 auf PyPI veröffentlicht

## Kontext

[ADR-1](ADR-1-pypi-vertagt.md) hat die Veröffentlichung **bis 1.0 vertagt**, nicht abgelehnt. Mit
diesem Release ist die Bedingung erreicht. Der Weg dorthin führte über die Installation aus Git:

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.17.0
```

Das funktioniert, kostet aber bei jedem Einbindenden etwas: `git` muss auf dem Bau-Rechner liegen
(in schlanken Abbildern nicht selbstverständlich), die Auflösung von Abhängigkeiten zweiter Ordnung
ist umständlich, `pip index`/`pip download` kennen das Paket nicht, und Werkzeuge, die
Aktualisierungen melden, sehen keine neue Version. Bei drei eigenen Anwendungen war das zu tragen;
als Standard-Anmeldeschicht für weitere ist es eine Reibung, die sich bei jeder Einbindung
wiederholt.

## Optionen

1. **Bei Git bleiben.** Kein neuer Verteilweg, kein neues Konto, keine unwiderrufliche Version.
2. **Auf PyPI veröffentlichen, mit API-Token im Repo.** Üblicher Weg, ein Geheimnis mehr.
3. **Auf PyPI veröffentlichen, per Trusted Publishing.** PyPI vertraut dem Release-Workflow über
   dessen OIDC-Identität; es gibt kein Token.

## Entscheidung

**(3) — veröffentlichen, per Trusted Publishing, ausgelöst allein durch einen Git-Tag.**

## Begründung

- **Die Sorge aus ADR-1 ist nicht verschwunden, sie ist beantwortet.** „Die API bewegt sich noch"
  war 2026-07 eine zutreffende Beobachtung und kein messbarer Zustand: Zwei Releases in Folge haben
  gebrochen, und beide Male fiel es erst beim Schreiben des CHANGELOG auf. Seit 0.16.0 hält
  `tests/test_api_surface.py` die Oberfläche fest (231 Namen) und trennt **Bruch** von
  **Erweiterung**. Eine unwiderrufliche Version ist vertretbar, wenn ein Bruch nicht mehr
  unbemerkt passieren kann.
- **Ein Auth-Paket bleibt ein Lieferketten-Ziel — deshalb kein Token.** Der Einwand aus ADR-1 gilt
  unverändert. Ein API-Token wäre ein Geheimnis, das im Repo liegt, das rotiert werden muss und
  das jemand aus einem Lauf herausziehen kann. Trusted Publishing hat keins: PyPI prüft die
  OIDC-Identität des Workflows (Owner, Repo, Workflow-Datei, Environment) und stellt daraufhin ein
  kurzlebiges Token aus. Dazu trägt jede Datei eine PEP-740-Attestation — wer das Wheel zieht, kann
  prüfen, aus welchem Commit es gebaut wurde.
- **Nichts rollt automatisch.** Ausgelöst wird der Upload von einem Tag, den ein Mensch setzt. Das
  ist dieselbe Trennung wie beim Ausrollen: Delivery, kein Deployment. Das Environment `pypi` ist
  der Ort, an dem sich bei Bedarf eine zweite Hand dazwischenschalten lässt.
- **Der Git-Weg bleibt bestehen.** Wer heute per Tag pinnt, muss nichts ändern. PyPI kommt dazu, es
  ersetzt nichts.

## Konsequenzen

- Installation ab 1.0: `pip install tinysesam` bzw. `pip install "tinysesam[all]==1.0.0"`.
- Der Sperrriegel `Private :: Do Not Upload` fällt aus `pyproject.toml`; `tests/test_packaging.py`
  achtet darauf, dass er nicht zurückkommt — und dass Wheel und sdist vollständig sind. Ein Wheel,
  dem eine Datei fehlt, installiert sauber und fällt erst beim Nutzer auf.
- **Jede veröffentlichte Version ist endgültig.** Eine zurückgezogene Version gibt ihre Nummer nicht
  frei; ein Fehler kostet eine neue Nummer, keinen Rückbau.
- **Einmalige Einrichtung auf pypi.org**, bevor der erste Tag fällt — die genauen Felder stehen im
  Kopf von [`.github/workflows/release.yml`](../.github/workflows/release.yml), damit sie dort
  liegen, wo jemand sie beim Release sucht: ein „pending publisher" für `tinysesam` mit Owner
  `Ollornog`, Repository `TinySesam`, Workflow `release.yml`, Environment `pypi`, dazu ein
  gleichnamiges Environment in den Repo-Einstellungen.
- Der Paketname `tinysesam` war am 2026-09-21 frei (`https://pypi.org/pypi/tinysesam/json` → 404).
  Frei bleibt er nur bis zum ersten Upload — durch wen auch immer.
