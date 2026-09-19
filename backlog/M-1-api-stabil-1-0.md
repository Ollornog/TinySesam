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

## Stand (2026-09-20)

| Bedingung | Stand |
|---|---|
| Zeremonien gegen echte Gegenstellen | **erfüllt** — [T-1](T-1-e2e-gegen-echten-idp.md), Bühne per [T-6](T-6-stage-per-playbook.md) reproduzierbar |
| Release ohne Handgriffe | **erfüllt** — `scripts/_release.py` setzt alle Versionsstellen und schliesst den CHANGELOG-Abschnitt; Tag und Push bleiben bewusst beim Menschen |
| zwei Minor-Versionen ohne Bruch | **offen, Uhr startet bei 0.16.0** |

Die dritte Bedingung ist die einzige, die sich nicht *erarbeiten* lässt — sie vergeht. Was sich
erarbeiten liess, ist ihre **Messbarkeit**: `tests/test_api_surface.py` hält die öffentliche
Oberfläche (231 Namen: Manager-Methoden, Config-Felder, Presets, Exporte) in
`tests/api_surface.json` fest und meldet jede Abweichung. Der Test unterscheidet dabei **Bruch**
(entfernt, umbenannt, Signatur unverträglich geändert) von **Erweiterung** (Parameter mit
Vorgabewert angehängt) — ein Wächter, der bei Harmlosem schreit, wird weggeklickt, und dann
übersieht man den echten.

Gegenprobe mit den beiden Brüchen, die tatsächlich passiert sind: Die keyword-only gewordene
Signatur von `require_role` meldet er als **BRUCH**, den zusätzlichen `purpose`-Parameter von
`magic_url` als **Erweiterung**. Beide Male fiel der Unterschied vorher erst beim Schreiben des
CHANGELOG auf — künftig fällt er beim Testlauf auf.

**Was 1.0 jetzt noch verlangt:** zwei Minor-Versionen, in denen `test_api_surface.py` keinen Bruch
meldet. Das ist keine Arbeit, sondern eine Haltung: Änderungen an der Oberfläche additiv bauen,
und wenn ein Bruch nötig ist, ihn bewusst annehmen und die Uhr neu starten.
