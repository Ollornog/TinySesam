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
- **Bekannte Grenze — das Erst-Admin-Einmal-Token reist in einer URL.** Eingelöst wird es mit
  `GET /auth/claim-admin?token=…`, und bei nicht angemeldetem Aufruf spiegelt der Login-Redirect
  es in den `Location`-Header. Eine URL ist kein vertraulicher Kanal: Sie steht im Access-Log
  eines vorgeschalteten Proxys, im `Referer` und in der Browser-History — bevor der Token
  verbraucht ist. Der Wert geht per Vorgabe zudem auf **stderr**, und das sammeln journald,
  `docker logs` und jedes Log-Shipping ein. Beides gibt kein dauerhaftes Geheimnis her (genau
  einmal einlösbar, läuft nach `admin_claim_ttl_min` ab, die Route antwortet 404, sobald es einen
  Admin gibt) — aber behandelt wird es entsprechend: `admin_claim_ttl_min` kurz halten, wo stderr
  eingesammelt wird `admin_claim_token_file` (Rechte `0600`) nehmen, sofort einlösen, und wo gar
  kein Token in einer URL stehen soll, den ersten Admin über `auth.ensure_admin(...)` oder
  `admin_identifiers` setzen.

## Unterstützte Versionen

Sicherheitsfixes landen auf der jeweils neuesten veröffentlichten Minor-Version — welche das ist,
steht oben in [CHANGELOG.md](../CHANGELOG.md). Ältere Linien bekommen keine Rückportierung: einen
Tag pinnen und den Pin weiterziehen, wenn ein Release etwas behebt. (Hier stand früher eine feste
Version, und sie war dreizehn Minor-Versionen alt — ein Versprechen, das niemand nachgemessen hat.)

<br /><br />
<p align="right"><img src="../docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
