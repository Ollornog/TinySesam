# TinySesam — TODO

> **Umgezogen (2026-07-23):** Offene Punkte, Meilensteine und Architekturentscheidungen leben
> jetzt als Einzeldateien unter **[`backlog/`](backlog/README.md)** — mit Struktur,
> Verweisen und einer Pruefung in der Testsuite. Diese Datei bleibt als **Historie** der
> erledigten Versionen stehen.
>
> ```bash
> python3 scripts/_backlog.py list      # was ist offen
> python3 scripts/_backlog.py list --type Decision
> ```
>
> Konventionen: [`backlog/README-KONVENTION.md`](backlog/README-KONVENTION.md).

## Erledigt in 0.5
- **Forward-Auth-Modus** (Reverse-Proxy, für fremde/nicht-änderbare Apps): `/auth/forward` +
  `/auth/verify` (200 + `Remote-*` bzw. 401 + `X-TinySesam-Location`), `cookie_domain`,
  `trusted_redirect_hosts`; Beispiel-Configs `deploy/forward-auth/` (Caddy/nginx/Traefik).
- Faktor-Ketten (geordnet, global + per Route), Step-up/per-Route-MFA, „Angemeldet bleiben",
  persönliche PIN, geteiltes Ressourcen-Geheimnis (PIN/Passphrase), Magic-Link + Mailer-Hook,
  Registrierung + Einladung, eingebaute Konto-Seite, austauschbares Frontend (Template-Registry),
  Open-Redirect-Härtung (`safe_next`).

## Erledigt in 0.13
- **Gateway als Container-Abbild**: `Dockerfile` (nicht-root, ohne pip/git, `HEALTHCHECK`),
  `release.yml` schiebt multi-arch nach GHCR, Compose nutzt das Abbild statt `pip install` zur
  Laufzeit. Neuer Endpunkt `GET /healthz`.
- **Erstes echtes Release**: `v0.12.0` mit Wheel, sdist und `SHA256SUMS`.

## Erledigt in 0.12
- **Selbst-Update entfernt** (`updater.py`, Panel-Routen, `update_mode`/`update_pin`). Die Version
  bestimmt, wer installiert. Ein Hygiene-Test hält den Knopf draußen.
- **`release.yml`**: Tag → Versionsabgleich → Suite → Wheel + sdist + `SHA256SUMS` ans Release.
- **Hygiene-Test gegen private Infrastruktur** (generische Muster, Eigennamen nur als Prüfsumme).

## Erledigt in 0.6–0.11
- LDAP/AD, SAML 2.0, Redis-Rate-Limit über mehrere Worker, CSRF (double-submit, Default an),
  Recovery-Codes, Passwort-vergessen, eigene Sitzungsverwaltung, i18n (en/de),
  Rollen-/Gruppen-Verwaltung inkl. IdP-Gruppen-Mapping, Erst-Admin-Bootstrap, Demo-Modus.

## CI — erledigt: bleibt auf `ubuntu-latest`
Self-hosted Runner sind für dieses Repo **ausgeschlossen**, nicht aufgeschoben. Bei einem
öffentlichen Repo kann jeder einen Fork-PR öffnen, dessen Workflow dann auf fremder Hardware
liefe; nicht-ephemere Runner sind damit dauerhaft kompromittierbar — GitHub rät ausdrücklich ab.
Kosten sind kein Gegenargument: öffentliche Repos haben unbegrenzte Minuten.

## Continuous Deployment — entschieden: nein (2026-07-09)
Kein automatisches Ausrollen. Die Website deployt GitHub Pages selbst (`pages.yml`), das ist
zustandslos; alles andere bleibt Handarbeit. Erledigt, nicht offen.
