# TinySesam — TODO

## Erledigt in 0.5
- **Forward-Auth-Modus** (Reverse-Proxy, für fremde/nicht-änderbare Apps): `/auth/forward` +
  `/auth/verify` (200 + `Remote-*` bzw. 401 + `X-TinySesam-Location`), `cookie_domain`,
  `trusted_redirect_hosts`; Beispiel-Configs `deploy/forward-auth/` (Caddy/nginx/Traefik).
- Faktor-Ketten (geordnet, global + per Route), Step-up/per-Route-MFA, „Angemeldet bleiben",
  persönliche PIN, geteiltes Ressourcen-Geheimnis (PIN/Passphrase), Magic-Link + Mailer-Hook,
  Registrierung + Einladung, eingebaute Konto-Seite, austauschbares Frontend (Template-Registry),
  Open-Redirect-Härtung (`safe_next`).

## Offen

### Auslieferung
- **Erstes echtes Release erzeugen:** `git tag v0.12.0 && git push --tags`. Tags gibt es seit
  `v0.2.0`, **Releases bisher keine** — also nie ein Wheel. `release.yml` baut es beim Tag-Push.
- **PyPI: Entscheidung offen.** Ohne PyPI gibt es kein `pip install tinysesam`; wer die Bibliothek
  nutzen will, braucht die Git-URL, und Renovate/Dependabot finden Updates nicht ohne Weiteres.
  Mit PyPI ist der Name dauerhaft vergeben und Versionen sind unwiderruflich. Der saubere Weg wäre
  **Trusted Publishing** (OIDC statt API-Token im Repo).
- **Gateway-Image** (`Dockerfile` + GHCR): nicht-root, `HEALTHCHECK`, nur das `[oidc]`-Extra.
  `[all]` zöge `python3-saml` → `libxmlsec1` und damit lange qemu-Builds für arm64.
  Bis dahin installiert `deploy/forward-auth/docker-compose.yml` den gepinnten Git-Tag.

### Funktion
- **Passkey/OIDC/SAML end-to-end** gegen echte Domain und echten Provider verifizieren
  (bisher nur struktur-getestet — siehe „Was Tests nicht können").
- **Forward-Auth**: optionale Feinsteuerung, welche `Remote-*`-Header gesetzt werden.
- **E-Mail-Verifikation/Invite ohne Magic-Link-Endpoint** (aktuell nutzen sie `/auth/magic/{token}`).

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
