---
id: M-1
type: Milestone
title: 1.0 — API stabil genug für PyPI
status: offen
tags: [release, api]
created: 2026-07-23
---

# M-1 — 1.0: API stabil genug für PyPI

**Fertig, wenn:** die öffentliche API sich über zwei Minor-Versionen nicht mehr gebrochen hat,
die Ceremony-Pfade (Passkey/OIDC/SAML) einmal gegen echte Gegenstellen liefen, und ein Release
ohne Handgriffe durchläuft.

Erst dann ist PyPI vertretbar — siehe [ADR-1](ADR-1-pypi-vertagt.md). Bis dahin ist der gepinnte
Git-Tag das ehrlichere Artefakt.

## Offen: die Oberfläche ist gemessen, nicht ausgewählt (2026-09-21)

`tests/api_surface.json` friert **alles ein, was keinen führenden Unterstrich trägt** — 105
Methoden. 68 davon kamen in keiner Doku vor; sie sind eingefroren, weil sie so aussehen, nicht
weil jemand entschieden hätte, dass sie zur öffentlichen Oberfläche gehören.

Seit 0.18.0 ist die Lage wenigstens sichtbar: Jede dieser Methoden hat einen Docstring, und
[API.md](../API.md) führt sie vollständig auf (generiert, mit Prüfung). Der Wächter erfasst
seither auch Rückgabetypen und die **Vorgabewerte** der Config-Felder — ohne die liesse sich
`session_ttl_hours` still von 168 auf 1 setzen.

**Was offen bleibt und vor 1.0 entschieden werden muss:** Welche dieser 105 Namen sollen auf
Dauer öffentlich sein? Alles einzufrieren ist die sichere, aber teure Antwort — jede interne
Umbenennung wird dann zum Bruch. Die Entscheidung ist inhaltlich (was verspricht TinySesam?)
und gehört nicht in einen Reparaturlauf.

## Stand: wieder offen (2026-09-21, nach der Reifeprüfung)

Der Meilenstein war für einen Tag geschlossen und ist es nicht mehr. Eine Reifeprüfung mit vier
unabhängigen Blickwinkeln (Sicherheit, Paket/Installation, API-Vertrag, Betrieb) fand **47 Befunde**;
12 davon wurden einzeln nachgestellt — **12 haltbar, 11 als Blocker bestätigt**.

Darunter sechs Sicherheitslücken, jede mit eigenem Nachstellungs-Skript belegt: Rollen-Eskalation
über selbst ausgestellte API-Keys, Konto-Unterschiebung über OIDC (`state` ohne Browser-Bindung)
und SAML (`InResponseTo` ungeprüft), sechs schreibende Routen ohne CSRF-Prüfung (darunter
„2FA abschalten", ohne Audit-Eintrag), eine zurücksetzbare Brute-Force-Sperre und ein
Admin-Bootstrap, bei dem der Erste gewinnt, der die Adresse eintippt.

**Ein Auth-Paket mit Rollen-Eskalation trägt kein „Production/Stable", und eine PyPI-Version ist
unwiderruflich.** Deshalb 0.18.0 statt 1.0.0.

### Warum es niemandem auffiel — der Befund hinter den Befunden

`tests/run_all.py` hat echte Fehlschläge als **„übersprungen"** verbucht. Die Suite war grün, weil
sie nicht gemessen hat. Selbst der schlimmste Fall blieb dadurch unsichtbar: `pip install tinysesam`
mit Vorgabe-Konfiguration startet nicht (`ModuleNotFoundError: webauthn`) — der allererste Schritt
jedes neuen Nutzers, und die CI konnte es nicht sehen.

Das ist zuerst repariert worden. Alles andere wäre auf Sand gebaut.

### Die Bedingungen, Stand jetzt

| Bedingung | Stand |
|---|---|
| Zeremonien gegen echte Gegenstellen | erfüllt |
| Release ohne Handgriffe | erfüllt |
| zwei Minor-Versionen ohne API-Bruch | **Uhr startet mit 0.18.0 neu** |
| **keine offenen Sicherheitsbefunde** | **neu — siehe M-2** |

Die vierte Bedingung stand vorher nicht da, weil niemand danach gesucht hatte. Sie gehört dazu:
Eine stabile Oberfläche über einem Paket mit Rollen-Eskalation misst das Falsche.

## Stand 2026-09-27: T-13 erledigt, offen nur die API-Einstufung

[T-13](T-13-audit-2026-09-22-runde-3.md) (drittes Audit samt Nachträgen, Grenzen und der Prüfrunde
Sperren/Zähler) ist abgeschlossen: Jeder Punkt ist behoben mit Test, per Mutation belegt, oder als
„bewusst so, begründet" markiert. Für diesen Meilenstein offen ist damit nur noch die **Einstufung
der öffentlichen API in A/B/C** (PO-Entscheid 2026-09-26) — die inhaltliche Frage oben, welche der
eingefrorenen Namen auf Dauer öffentlich sein sollen. Sie liegt beim PO.

## Stand 2026-09-27: Einstufung gebaut, die Uhr für A startet mit 0.21.0

Der PO hat die Stufen am 2026-09-26 entschieden („klingt gut — go“); gebaut ist Schritt 1:

- **Jeder der 339 öffentlichen Namen trägt eine Stufe** in `tests/api_surface.json` —
  A 225 (davon 158 Konfigurationsfelder), B 64, C 50. `tests/test_api_surface.py` ist rot, wenn
  einer keine oder eine unbekannte trägt; `--update` übernimmt Stufen, vergibt aber nie eine.
  Damit ist die Frage oben („gemessen, nicht ausgewählt“) beantwortet: Ausgewählt ist, was A ist.
- **Nur für A gilt die Bedingung „zwei Minor-Versionen ohne Bruch“**, gezählt ab 0.21.0 — dem
  Release, das die Einstufung bringt. Ein Bruch an B (nur nach `DeprecationWarning` über zwei
  Minor-Versionen) oder C (intern, fällt mit 1.0) setzt die Uhr nicht zurück; der Wächter meldet
  ihn trotzdem, mit der Stufe davor.
- `API.md` gliedert nach Stufe, die READMEs erklären die Stufen und führen die B-Bausteine im
  Abschnitt für Fortgeschrittene.

| Bedingung | Stand |
|---|---|
| Einstufung der öffentlichen API | **gebaut** (Stufen, Wächter, Doku) |
| C-Namen mit Unterstrich, alter Name als warnender Alias bis 1.0 | **gebaut** (49 Aliase, Wächter, Warnfilter in `run_all.py`) |
| sicherer Baustein für eigene Login-Seiten (die inneren Prüfer drosseln nicht, PO-Befund) | offen — Schritt 3 |
| zwei Minor-Versionen ohne Bruch **an Stufe A** | Uhr startet mit 0.21.0 |

**Schritt 2 (2026-09-27): Stufe C ist ein warnender Alias.** Die Implementierung heisst `_name`
(42 Methoden, 6 Konstanten; `complete_mfa` zeigt auf `complete_totp`), der alte Name ist ein
`Veraltet` aus `tinysesam/_veraltet.py` und warnt beim Aufruf genau einmal mit Ersatz. Paket,
Beispiele, Skripte und Tests rufen nur noch die neuen Namen. Der Wächter hält Ablage und Klasse
gegeneinander, prüft Warnung, Ziel und Weiterreichen jedes Alias, verbietet alte Namen im eigenen
Code (AST) und wird mit 1.0 rot, solange noch ein Alias steht; `tests/run_all.py` macht eine solche
Warnung aus dem Paket selbst zum Fehler. `SERIE_PIN_FOLGE` war nie veröffentlicht und heisst ohne
Alias `_SERIE_PIN_FOLGE` — Stand jetzt 338 Namen, C 49. Die Ersatztexte der ungedrosselten Prüfer
nennen die eingebauten Routen; mit Schritt 3 kommt der Baustein dazu, auf den sie zeigen sollen.

Nicht gemessen und damit ausserhalb der Einstufung: Instanzattribute (`auth.store`, `auth.cfg`,
`on_security_event` …), die HTTP-Routen und die Logger-Namen (`tinysesam.security`). Ob sie in
die Zusage gehören, liegt als offene Frage beim PO.

<!-- Was vorher hier stand (Schliessung mit 1.0.0), ist mit dem Meilenstein selbst hinfaellig. -->
