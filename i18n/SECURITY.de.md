# Sicherheit

<a href="../SECURITY.md">English</a> · <b>Deutsch</b>
<br /><br />

## Schwachstellen melden

Bitte Sicherheitslücken **nicht** über öffentliche Issues melden, sondern privat über die
**GitHub Security Advisories** dieses Repos (Reiter *Security* → *Report a vulnerability*).
Ich bemühe mich um eine erste Rückmeldung innerhalb weniger Tage.

## Status / Umfang

TinySesam ist ein selbst gebautes Auth-Modul und **nicht extern auditiert**. Es setzt bewusst auf
etablierte Bausteine (argon2id/scrypt für Passwörter & PINs, server-seitige revozierbare Sessions,
`SameSite`/`HttpOnly`/`Secure`-Cookies, OIDC-ID-Token gegen JWKS + `iss`/`aud`/`exp`/`nonce`,
WebAuthn mit `sign_count`-Klon-Erkennung, sha256-gehashte Einmal-/API-Tokens, Brute-Force-Lockout +
Rate-Limit, Open-Redirect-Schutz via `safe_next`). Trotzdem: vor produktivem Einsatz selbst prüfen.

## Betriebshinweise (wichtig)

- **Immer hinter HTTPS** betreiben; `rp_id`/`origin` müssen exakt zur Domain passen.
- Echte Client-IP nur hinter vertrauenswürdigem Proxy (`trusted_proxies`), sonst ist `X-Forwarded-For` fälschbar.
- `trusted_redirect_hosts` nur auf tatsächlich eigene Hosts setzen (Open-Redirect/Forward-Auth).
- Secrets (OIDC-Client-Secret, SMTP-Passwort) über Umgebung/Secret-Store, nicht im Code.

## Unterstützte Versionen

Sicherheitsfixes landen auf der jeweils neuesten Minor-Version (aktuell `0.5.x`).

<br /><br />
<p align="right"><img src="../docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
