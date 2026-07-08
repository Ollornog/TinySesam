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
