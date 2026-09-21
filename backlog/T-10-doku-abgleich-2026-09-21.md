---
id: T-10
type: Task
title: Doku gegen den Code gemessen — 70 Stellen, 10 echte Mängel
status: erledigt
milestone: M-1
tags: [doku, sicherheit, betrieb, tests]
created: 2026-09-21
---

# T-10 — Doku-Abgleich, 2026-09-21

Nach [T-8](T-8-reifepruefung-restbefunde.md) und [T-9](T-9-audit-2026-09-21-runde-2.md) ein dritter
Durchgang, diesmal **von der Doku her**: Jede Aussage über das Verhalten wurde gegen den Code
gemessen — beide READMEs, CHANGELOG, Docstrings, `deploy/`, `web/`, Backlog, dazu die Repo-Doku
auf dem Tower. **70 Stellen wichen ab.**

Der Ertrag lag nicht bei den veralteten Sätzen. **Zehn der Abweichungen waren Mängel im Code oder
in einer ausgelieferten Vorlage** — sichtbar nur, weil daneben eine Zusage stand, die jemand
gelesen hat. Ein Test prüft, was sein Autor zu prüfen dachte; ein Docstring hält die Absicht fest,
und wo Absicht und Rumpf auseinandergehen, ist eines von beidem falsch.

## Blocker

- **0.18.0 hätte jede scrypt-Installation ausgesperrt.** Das Format `scrypt$salt$dk` trug seine
  Parameter nicht mit, und 0.18.0 hob `p` von 1 auf 3 (OWASP). `verify_password` rechnete jeden
  Bestandshash mit dem neuen Wert nach — ohne Fehler, ohne Meldung, nur „Passwort stimmt nicht",
  für jedes Konto ohne `[argon2]` gleichzeitig. Genau die Installationen, für die der Fallback
  gebaut ist. Format trägt die Parameter jetzt; das alte wird mit den Werten von damals
  nachgerechnet und beim nächsten Login angehoben.
- **`login_chain=["password","totp"]` war eine Sackgasse** für jedes Konto ohne eingerichtetes
  TOTP: Das richtige Passwort führte auf `/auth/totp`, das mangels Geheimnis auf die Login-Seite
  zurückleitete, und die Einrichtungsseite verlangte einen voll angemeldeten Nutzer, den es unter
  dieser Kette nie geben kann. Weder herein noch an die Einrichtung.
- **`nginx.conf` reichte einen Client-Header an die App durch.** `Remote-Name` fehlte in der
  Vorlage — ein nicht gesetzter Header wird von nginx nicht weggelassen, sondern weitergereicht.
- **Die Caddy-Vorlage schützte nichts.** `reverse_proxy /auth/forward <upstream>` ist ein
  Pfad-Matcher, kein Rewrite: Die Prüfung lief nur für Anfragen auf `/auth/forward`, jeder andere
  Pfad fiel durch. Dazu ein Login-Redirect, der wegen der Go-Header-Kanonisierung leer blieb.
- **`seed_demo()` prüfte `demo_mode` nicht** — der Docstring versprach es seit jeher. Ein direkter
  Aufruf legte `demoadmin` mit `is_admin=1` und dem dokumentierten Standardpasswort an.

## Weitere Mängel

- Die Migration liess Klartext-Freigaben liegen (`0 < user_version < 4` traf genau den Fall nicht,
  für den sie geschrieben war — `user_version` kam selbst erst mit 0.18.0).
- `tinysesam audit --user` siebte die jüngsten Zeilen nach, statt in SQL zu filtern: „Keine
  Einträge zu 'X'." samt Exit 0 im Anlassfall.
- Das mitgelieferte Compose ergab einen Stack, der nicht läuft (`127.0.0.1` im Caddy-Container).
- Der `HEALTHCHECK` folgte Redirects, entgegen dem Kommentar daneben.
- `Documentation=` in `tinysesam-gc.service` verwarf systemd still (Umlaut im Anker).
- `stepup_methods` war nur ein Wunsch: Wer keines der genannten Verfahren eingerichtet hatte,
  bestätigte mit allem, was er hatte — inklusive des Passworts, mit dem er sich gerade angemeldet
  hatte. Neu: `stepup_strict`.

## Was den Rückfall verhindert

- `tests/test_bestandsdaten.py` — 28 Prüfungen zu dem, was ein Upgrade überleben muss. Jede wurde
  gegen die Mutation gegengeprüft: Fix zurückgedreht → Prüfung rot.
- Drei Wächter in `tests/test_repo.py`: Die in beiden READMEs genannte Zahl der Testdateien und die
  Python-Spanne werden gegen die Wirklichkeit gemessen, und solange die Version unter 1.0 liegt,
  darf keine README eine PyPI-Installation zeigen. Genau diese drei Zahlen waren falsch — „17 bzw.
  22 Testdateien" bei 46, „Python 3.10–3.13" bei einer Matrix bis 3.14, und `pip install tinysesam`
  als allererster Befehl, obwohl der Name dort nicht registriert ist.

## Offen

Die READMEs nennen `v0.18.0` als Tag, Wheel-URL und Abbild-Tag. Den Tag gibt es noch nicht — er
entsteht mit dem Release, das ein Mensch auslöst; `scripts/_release.py` zieht alle Stellen mit.
Bis dahin zeigen sie ins Leere. Kein Fehler dieses Durchgangs, aber der Zustand auf `main`.
