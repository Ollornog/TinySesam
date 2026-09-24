---
id: ADR-8
type: Decision
title: Eine PIN darf der erste Faktor sein — bewusst, einstellbar, mit eigener Grenze
status: erledigt
tags: [pin, faktoren, härtung]
created: 2026-09-24
---

# ADR-8 — Eine PIN darf der erste Faktor sein

## Kontext

Das dritte Audit (T-13, Fund **B2-8**) stellte fest: Eine vierstellige PIN ist in TinySesam ein
vollwertiger, zentral geprüfter Erstfaktor. Nach NIST SP 800-63B ist ein so kurzes Geheimnis als
alleiniger Faktor schwach — es hat 10.000 Werte.

## Entscheidung

**Die PIN bleibt als Erstfaktor erlaubt** (PO-Entscheid 2026-09-24, „ausdrücklich ja"). Der
Anwendungsfall ist real: eine allgemeine Seite hinter einer PIN, eine Detailseite hinter mehr —
über eine Kette je Route (`auth.require(factors=["pin", "password"])`).

Sie bleibt **einstellbar**:

- `pin_login` (Konfiguration, Vorgabe `True`): Mit `False` ist die PIN kein Weg hinein, nur noch
  Step-up-Faktor.
- `pin_max_attempts` (Panel, Vorgabe 5): der eigene PIN-Zähler je Konto, je Adresse das
  `ip_attempt_factor`-fache. Er steht im Panel **direkt bei der Login-Sperre**, weil er dort
  zusammen mit ihr eingestellt wird.
- `account_max_consecutive_failures` (Panel, Vorgabe 100, B2-6): PIN-Fehlgriffe zählen in die
  Serie. Mehr als 99 Rateversuche am Stück bekommt niemand, auch verteilt nicht. Ein
  Passwort-Reset der Inhaberin beginnt eine neue Serie — sonst sperrte ein Fremder mit falschen
  PINs das Konto über den Reset hinaus (R2-2). Wer das Raten ganz ausschliessen will, nimmt die PIN
  von der Login-Seite (`pin_login=False`).

## Folgen

- Wer die PIN als Erstfaktor einsetzt, nimmt die Stärke eines kurzen Geheimnisses in Kauf. Die
  Grenzen oben machen daraus höchstens 100 Versuche aus 10.000 in Folge, danach ist neu zu binden.
- Die Doku nennt das beim Namen (README „PIN und Step-up", `docs/BETRIEB.md`, Tabelle der
  Anmeldewege) und zeigt das Muster „allgemeine Seite / Detailseite".
- Gemessen in `tests/test_t13_entscheide.py` (PIN allein → allgemeine Seite, Detailseite verlangt
  das Passwort, `pin_login=False` nimmt die PIN von der Login-Seite, Reihenfolge im Panel).
