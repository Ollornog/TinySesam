# Sicherheit

<a href="../SECURITY.md">English</a> · <b>Deutsch</b>
<br /><br />

## Schwachstellen melden

Bitte Sicherheitslücken **nicht** über öffentliche Issues melden. Zwei vertrauliche Wege:

1. **Private Schwachstellenmeldung auf GitHub** — Reiter *Security* → *Report a vulnerability*
   (<https://github.com/Ollornog/TinySesam/security/advisories/new>). Bevorzugt: Meldung,
   Rückfragen und das spätere Advisory bleiben an einer Stelle.
2. **E-Mail** an <tinysesam-github@ollornog.de> mit dem Betreff `[security] TinySesam` — für alle
   ohne GitHub-Konto, oder wenn das Formular nicht erreichbar ist.

Worauf Verlass ist (Kalendertage, ab Eingang der Meldung):

| Schritt | Frist |
| --- | --- |
| Eingangsbestätigung | **7 Tage** |
| Erste Einschätzung (bestätigt / nicht nachstellbar / ausserhalb des Umfangs) | **14 Tage** |
| Behobenes Release oder veröffentlichtes Advisory mit Umgehung | **90 Tage** |

Koordinierte Offenlegung: Details bitte vertraulich halten, bis ein Fix veröffentlicht ist oder
die 90 Tage vorbei sind — was zuerst eintritt. Reisst eine Frist, kommt eine Nachricht mit dem
Grund; Schweigen ist keine Antwort. Nennung im Advisory und im CHANGELOG, wenn gewünscht.

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
- **Bekannte Grenze — TOTP-Geheimnisse liegen unverschlüsselt in der Datenbank.** Passwörter,
  PINs, Recovery-Codes und API-Keys stehen dort nur als Hash; das TOTP-Geheimnis kann das nicht,
  denn der Server muss daraus jeden Code nachrechnen. Wer die SQLite-Datei (oder eine Sicherung
  davon) lesen kann, erzeugt damit für jedes Konto gültige Codes — der zweite Faktor hängt dann
  nur noch am Passwort. Eine Verschlüsselung mit einem Schlüssel ausserhalb der Datenbank ist
  geplant (T-13, H-14/H-15). Bis dahin: Datenbank und Sicherungen wie ein Geheimnis behandeln
  (Rechte `0600`, verschlüsselte Backups), und wer den zweiten Faktor auch gegen einen
  Datenbankabfluss braucht, setzt auf Passkeys — dort liegt nur ein öffentlicher Schlüssel.
- **Inhaber über Faktor-Änderungen benachrichtigen — `auth.on_security_event`.** Opt-in-Hook,
  gerufen als `hook(ereignis, konto, details)` mit `konto = {id, username, email, display_name}`,
  sobald ein Anmeldefaktor angelegt, geändert, entfernt oder verbraucht wird: `password_changed`,
  `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled`, `recovery_codes_generated`,
  `recovery_code_used` (`details={"verbleibend": n}`), `passkey_added`, `passkey_removed`,
  `api_key_created`. TinySesam verschickt selbst nichts; die Mail geht aus dem Hook (am besten über
  eine Warteschlange — er läuft synchron im Request). Ein Fehler im Hook macht die Änderung nie
  rückgängig, landet aber im Sicherheits-Log.
- **Ein TOTP-Code gilt genau einmal — auch der Einrichtungscode.** Der Code, der die Einrichtung
  bestätigt, ist danach verbraucht. Unter `login_chain=["password","totp"]` schliesst diese
  Bestätigung den TOTP-Schritt der Anmeldung gleich mit ab; überall sonst braucht die Anmeldung den
  *nächsten* Code. Integrationstests, die `totp_confirm(uid, now())` und danach
  `verify_totp(uid, now())` mit demselben Code rufen, werden seit T-13 rot — dort mit dem Code des
  vorigen Zeitschritts bestätigen.

## Unterstützte Versionen

Sicherheitsfixes landen auf der jeweils neuesten veröffentlichten Minor-Version — welche das ist,
steht oben in [CHANGELOG.md](../CHANGELOG.md). Ältere Linien bekommen keine Rückportierung: einen
Tag pinnen und den Pin weiterziehen, wenn ein Release etwas behebt. (Hier stand früher eine feste
Version, und sie war dreizehn Minor-Versionen alt — ein Versprechen, das niemand nachgemessen hat.)

<br /><br />
<p align="right"><img src="../docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
