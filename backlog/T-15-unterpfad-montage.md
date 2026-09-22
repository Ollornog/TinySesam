---
id: T-15
type: Task
title: Eingebaute Seiten unter einem Unterpfad montierbar machen
status: offen
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
