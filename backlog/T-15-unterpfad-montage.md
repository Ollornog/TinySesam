---
id: T-15
type: Task
title: Eingebaute Seiten unter einem Unterpfad montierbar machen
status: erledigt
milestone: M-2
tags: [routen, templates, deployment]
created: 2026-09-22
---

# T-15 — Eingebaute Seiten unter einem Unterpfad montierbar machen

`base_url` trägt den Unterpfad, und die **verschickten Links** tragen ihn seit 0.19 genau einmal
(Reset, Anmelde-Link, Bestätigung, Einladung; gemessen in `tests/test_sicherheit_befunde.py`).
Die **eingebauten Seiten** tragen ihn nicht: Formularziele und Verweise in `templates.py` stehen
als wurzel-absolute Pfade (`/auth/register`, `/auth/forgot`, `/auth/magic/request`, `/auth/totp`,
…), und die Umleitungen nehmen `login_path`/`login_redirect`/`logout_redirect` unverändert.

Montiert man die App unter `--root-path /sso` hinter einem Proxy, der `/sso` abschneidet, zeigt
jeder dieser Pfade aus der Montage heraus: Der Besucher landet auf `https://example.com/auth/login`
statt `…/sso/auth/login` — 404. Die Bestätigungsmail funktioniert dabei, die Anmeldung nicht.

**Stand heute:** Die Doku sagt genau das (README, `i18n/README.de.md`, `KONFIGURATION.md`,
CHANGELOG): Der Unterpfad gehört in `base_url` und gilt für die verschickten Links; die eingebauten
Seiten setzen voraus, dass die App an der Wurzel ihres Hosts liegt. Eine Grenze, die ausgesprochen
ist, statt einer Zusage, die nicht trägt (Befund B-regression-3, dritte Audit-Runde).

**Fertig, wenn:** die Seiten ihre Ziele aus **einer** Quelle ableiten (`root_path` der Anfrage bzw.
ein Feld wie `mount_prefix`), eine Montage unter `/sso` ohne weitere Einstellung durch Login,
Registrierung, Magic-Link, Reset und Konto-Seite trägt, und ein Test das an einer echten Montage
misst — nicht an einer nachgebauten URL. Erst dann darf in der Doku „trägt den Unterpfad" ohne
Einschränkung stehen.

## Erledigt 2026-09-25

Eine Quelle: `TinySesam._praefix(request)` liest `scope["root_path"]` (Form geprüft: nur
`/teil/teil` aus A–Z a–z 0–9 . _ ~ -, sonst leer und eine Warnung — der Wert landet unmaskiert
in Attributen und Skripten). Die eingebauten Seiten schreiben `__TS_P__` vor jeden Pfad der App
(Formulare, Links, fetch-Aufrufe), `render_page` setzt den Präfix ein; ein eigenes Template ohne
Platzhalter bleibt unberührt. Umleitungen auf Pfade der App gehen über `auth.pfad(request, p)`;
ein `next`-Ziel ist schon ein Pfad des Browsers und bekommt keinen zweiten. `safe_next(next,
request)` gibt dem Rückfall `login_redirect` den Präfix; die Routen haben `next=""` statt `"/"`
als Vorgabe, damit ein fehlendes `next` wirklich auf `login_redirect` führt (so stand es schon in
der Konfiguration). Gemessen in `tests/test_unterpfad.py` an einer Starlette-Montage, an einem
Scope wie von `uvicorn --root-path` und an der Wurzel (unverändert), sechs Mutationen rot.

**Grenze:** `FastAPI(root_path=...)` an der App selbst lässt den Pfad der Anfrage ohne Präfix —
Seiten und Umleitungen stimmen, aber `next=`-Ziele aus `request.url.path` zeigen aus der Montage
heraus. Der Weg ist `--root-path` am Server oder eine Montage (README).
