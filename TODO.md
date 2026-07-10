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
- **PyPI: vertagt bis 1.0** (entschieden 2026-07-10). Bis dahin ist der gepinnte Git-Tag das
  ehrlichere Artefakt: Jede PyPI-Version ist unwiderruflich, und die API bewegt sich noch —
  0.12.0 hat gerade das Selbst-Update ersatzlos entfernt. Dazu ist ein Auth-Paket auf PyPI ein
  Supply-Chain-Ziel: wer das Konto übernimmt, schiebt Code in fremde Anmeldevorgänge.
  Wenn: dann mit **Trusted Publishing** (PyPI vertraut dem Workflow per OIDC, kein Token im Repo).
  Die Namen `tinysesam` und `tiny-sesam` sind Stand 2026-07-10 beide frei.
- **Abbild-Signatur / SBOM** erwägen (`cosign`, `provenance`) — ein Digest belegt Unverändertheit,
  aber nicht Herkunft. Erst sinnvoll, wenn Fremde das Abbild produktiv einsetzen.

### Tests
- **Freien Port nicht selbst suchen.** `tests/test_browser.py: free_port()` bindet einen Port,
  schließt ihn und gibt die Nummer zurück — dazwischen kann ein anderer Prozess ihn belegen.
  Robuster: Chrome mit `--remote-debugging-port=0` starten und die tatsächliche Nummer aus
  `DevToolsActivePort` im Profilverzeichnis lesen. (Aus dem DashMyBoard-Bau; dort bewährt.)

### Funktion
- **Das Admin-Panel ist nicht übersetzt.** `tinysesam/admin.py` trägt sein Deutsch fest im
  Template: `<html lang=de>`, die Reiter „Benutzer / Sitzungen / Härtung / Audit", alle
  Feldbeschriftungen. `cfg.lang="en"` ändert daran nichts. Login-, Konto- und Fehlerseiten
  gehen längst über `auth.t()` — das Panel ist der letzte Rest. Sichtbar geworden, als die
  gebaute Demo-Seite (`web/demo.py`) auf der englischen Fassung ein deutsches Panel zeigte;
  sie baut es deshalb bewusst nur **einmal** statt zweimal identisch (`PER_LANG`).
  **Wenn behoben:** `"admin"` in `web/demo.py: PER_LANG` aufnehmen, dann entsteht je Sprache eine
  Datei, und `tests/test_site.py` erwartet `admin.en.html`/`admin.de.html`.
- **End-to-End-Test gegen einen echten Identity Provider** — der größte verbliebene blinde Fleck.
  Passkey/WebAuthn, OIDC und SAML sind bisher nur **struktur-getestet**: Die Ceremony gegen einen
  echten Browser auf einer echten HTTPS-Domain, gegen einen echten IdP, hat nie stattgefunden.
  Ein Fehler dort fiele erst im Betrieb auf.
  - **Was fehlt:** öffentlich erreichbare Domain mit gültigem Zertifikat (WebAuthn verlangt eine
    echte `rp_id` und HTTPS), ein IdP mit registriertem Client, ein Passkey-fähiger Browser.
  - **Wie:** dieselbe CDP-Suite wie `tests/test_browser.py`, aber mit `BASE_URL=https://…` gegen
    die deployte Instanz — also ein **Smoke-Test nach dem Deploy**, kein CI-Test. WebAuthn lässt
    sich über CDP mit `WebAuthn.enable` + `WebAuthn.addVirtualAuthenticator` fahren, ohne echten
    Sicherheitsschlüssel.
  - **Warum kein CI-Test:** Die CI hat keine Domain, kein Zertifikat und keinen IdP. Ein Test, der
    das vortäuscht, prüft die Attrappe.
- **Forward-Auth**: optionale Feinsteuerung, welche `Remote-*`-Header gesetzt werden.
- **E-Mail-Verifikation/Invite ohne Magic-Link-Endpoint** (aktuell nutzen sie `/auth/magic/{token}`).

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
