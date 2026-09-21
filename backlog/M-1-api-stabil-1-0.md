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

<!-- Was vorher hier stand (Schliessung mit 1.0.0), ist mit dem Meilenstein selbst hinfaellig. -->
