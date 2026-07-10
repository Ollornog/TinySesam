# TinySesam — TODO

## Erledigt in 0.5
- **Forward-Auth-Modus** (Reverse-Proxy, für fremde/nicht-änderbare Apps): `/auth/forward` +
  `/auth/verify` (200 + `Remote-*` bzw. 401 + `X-TinySesam-Location`), `cookie_domain`,
  `trusted_redirect_hosts`; Beispiel-Configs `deploy/forward-auth/` (Caddy/nginx/Traefik).
- Faktor-Ketten (geordnet, global + per Route), Step-up/per-Route-MFA, „Angemeldet bleiben",
  persönliche PIN, geteiltes Ressourcen-Geheimnis (PIN/Passphrase), Magic-Link + Mailer-Hook,
  Registrierung + Einladung, eingebaute Konto-Seite, austauschbares Frontend (Template-Registry),
  Open-Redirect-Härtung (`safe_next`).

## Offen / Ideen
- **Optionale LDAP/lldap-Anbindung** als andockbarer Faktor/Backend.
- **Passkey/OIDC end-to-end** gegen echte Domain/echten Provider verifizieren (bisher struktur-getestet).
- **Rate-Limit über mehrere Worker**: aktuell In-Memory-Token-Bucket pro Prozess + DB-Lockout;
  für viele Worker ggf. zentraler Bucket (Redis o.ä.).
- **CSRF-Tokens** für die Formulare (derzeit über `SameSite=Lax` abgesichert) — bei Bedarf explizit.
- **Forward-Auth**: optionale Feinsteuerung, welche `Remote-*`-Header gesetzt werden.
- **E-Mail-Verifikation/Invite ohne Magic-Link-Endpoint** (aktuell nutzen sie `/auth/magic/{token}`).

## CI — erledigt: bleibt auf `ubuntu-latest`
Self-hosted Runner sind für dieses Repo **ausgeschlossen**, nicht aufgeschoben. Bei einem
öffentlichen Repo kann jeder einen Fork-PR öffnen, dessen Workflow dann auf fremder Hardware
liefe; nicht-ephemere Runner sind damit dauerhaft kompromittierbar — GitHub rät ausdrücklich ab.
Kosten sind kein Gegenargument: öffentliche Repos haben unbegrenzte Minuten.

## Continuous Deployment — entschieden: nein (2026-07-09)
Kein automatisches Ausrollen. Die Website deployt GitHub Pages selbst (`pages.yml`), das ist
zustandslos; alles andere bleibt Handarbeit. Erledigt, nicht offen.
