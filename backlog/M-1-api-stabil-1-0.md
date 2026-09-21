---
id: M-1
type: Milestone
title: 1.0 — API stabil genug für PyPI
status: erledigt
tags: [release, api]
created: 2026-07-23
---

# M-1 — 1.0: API stabil genug für PyPI

**Fertig, wenn:** die öffentliche API sich über zwei Minor-Versionen nicht mehr gebrochen hat,
die Ceremony-Pfade (Passkey/OIDC/SAML) einmal gegen echte Gegenstellen liefen, und ein Release
ohne Handgriffe durchläuft.

Erst dann ist PyPI vertretbar — siehe [ADR-1](ADR-1-pypi-vertagt.md). Bis dahin ist der gepinnte
Git-Tag das ehrlichere Artefakt.

## Stand: geschlossen mit 1.0.0 (2026-09-21)

| Bedingung | Stand |
|---|---|
| Zeremonien gegen echte Gegenstellen | **erfüllt** — [T-1](T-1-e2e-gegen-echten-idp.md), Bühne per [T-6](T-6-stage-per-playbook.md) reproduzierbar |
| Release ohne Handgriffe | **erfüllt** — `scripts/_release.py` setzt alle Versionsstellen und schliesst den CHANGELOG-Abschnitt; Tag und Push bleiben bewusst beim Menschen |
| zwei Minor-Versionen ohne Bruch | **eine erreicht, nicht zwei** — vorzeitig abgehakt, Entscheidung des Projektinhabers |

**Die dritte Bedingung ist nicht erfüllt, sondern erlassen.** Das gehört hier hin, weil ein
Meilenstein, der sich seine Kriterien im Nachhinein passend macht, keiner mehr ist. Die Uhr lief
seit 0.16.0; 0.17.0 war die erste der beiden Minor-Versionen, 0.18.0 hätte die zweite werden
müssen. Stattdessen folgt auf 0.17.0 direkt 1.0.0.

Was **gemessen** wurde statt behauptet: Zwischen `v0.16.0` und dem Stand vor 1.0.0 meldet
`tests/test_api_surface.py` **null Brüche und null Erweiterungen** — 231 Namen, Zeichen für
Zeichen dieselben. Gegengeprüft wurde nicht mit dem festgeschriebenen `api_surface.json` (das
entstand erst in 0.17.0 und wäre ein Zirkelschluss), sondern mit der Oberfläche, die derselbe
Code aus dem Baum bei `v0.16.0` berechnet.

Die Zusage, die 1.0 trägt, ist damit belegt — nur eben über eine Minor-Version statt über zwei.
Der Unterschied ist nicht nichts: Zwei Versionen zeigen, dass die Oberfläche **auch unter
Änderungen** hält; 0.17.0 hat die Bibliothek gar nicht angefasst. Wer das nachliest, soll es
wissen und nicht aus einem Häkchen schliessen, es sei durchgestanden worden.

Was sich erarbeiten liess, ist die **Messbarkeit**: `tests/test_api_surface.py` hält die
öffentliche Oberfläche (231 Namen: Manager-Methoden, Config-Felder, Presets, Exporte) in
`tests/api_surface.json` fest und meldet jede Abweichung. Der Test unterscheidet dabei **Bruch**
(entfernt, umbenannt, Signatur unverträglich geändert) von **Erweiterung** (Parameter mit
Vorgabewert angehängt) — ein Wächter, der bei Harmlosem schreit, wird weggeklickt, und dann
übersieht man den echten.

Gegenprobe mit den beiden Brüchen, die tatsächlich passiert sind: Die keyword-only gewordene
Signatur von `require_role` meldet er als **BRUCH**, den zusätzlichen `purpose`-Parameter von
`magic_url` als **Erweiterung**. Beide Male fiel der Unterschied vorher erst beim Schreiben des
CHANGELOG auf — seitdem fällt er beim Testlauf auf.

**Was ab 1.0 gilt:** Ein Bruch ist jetzt keine zurückgesetzte Uhr mehr, sondern eine neue
Hauptversion. Das ist die eigentliche Zusage von 1.0 — und sie gilt ab dem ersten Tag, unabhängig
davon, wie viele Minor-Versionen ihr vorausgingen.
