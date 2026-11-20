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
- **Umkehrbare Geheimnisse liegen verschlüsselt — zu hüten ist der Schlüssel.** Passwörter, PINs,
  Recovery-Codes und API-Keys stehen nur als Hash in der Datenbank. Was der Server zurücklesen
  muss — TOTP-Geheimnisse, OIDC-Refresh- und ID-Tokens —, ist mit AES-256-GCM verschlüsselt
  (Pflicht seit 0.21.0; ein Wert von vorher wird beim Start verschlüsselt). Der Schlüssel kommt
  aus `TINYSESAM_SECRETS_KEY`, sonst aus `secrets_key_file`, sonst aus einer Datei `<db>.key`
  (Rechte `0600`), die neben der Datenbank entsteht. Diese Vorgabe schützt vor einer
  Datenbankdatei, die allein abfließt, **nicht** vor einer Kopie des ganzen Verzeichnisses. Seit
  T-48 (ADR-12) hat jeder Schlüssel einen Zweck und eigenes Material: Der Signaturschlüssel der
  Gate-Tokens (ADR-9) und der OAuth-Pepper sind zufällige Schlüssel, **nie abgeleitet** aus dem
  Tresor-Schlüssel — der Tresor-Schlüssel allein (eine abgeflossene Umgebung, eine
  Schlüsselsicherung) prägt kein Gate-Token. Ohne eigene Quelle (`TINYSESAM_GATE_KEY`,
  `gate_key_file`) liegt der Gate-Schlüssel mit dem Tresor-Schlüssel verschlüsselt in der Datenbank;
  `<db>.key` neben der Datenbank gibt also beides her, wer das ganze Verzeichnis liest —
  `config_check` sagt das bei eingeschaltetem Gate. Im Betrieb, und für das Gateway mit Gate-Tokens
  immer, gehört der Tresor-Schlüssel außerhalb des Datenverzeichnisses (`TINYSESAM_SECRETS_KEY` als
  Container-Secret oder `secrets_key_file`) und getrennt von der Datenbank gesichert: Ohne ihn sind
  alle TOTP-Einrichtungen verloren. Jeder Wert trägt seine Schlüssel-ID und ist an seine Zeile
  gebunden (AES-GCM mit zugeordneten Daten, T-54), und jeder Schlüssel lässt sich ohne Verlust
  rotieren (`tinysesam keys rotate|reencrypt|retire`, docs/OPERATIONS.md „Keys"). Passkeys bleiben
  der Faktor, der einen Datenbankabfluss übersteht — dort liegt nur ein öffentlicher Schlüssel.
- **Bekannte Grenze — ohne `__Host-`-Präfix am Sitzungs-Cookie gilt jeder Host unter der
  übergeordneten Domain als vertrauenswürdig.** Das Sitzungs-Cookie trägt `__Host-` nur mit
  `cookie_secure=True`, leerem `cookie_domain`, `cookie_path="/"` und `cookie_host_prefix=True` —
  den Vorgaben. SSO über Subdomains braucht `cookie_domain`, und ein Cookie für die ganze Domain
  kann das Präfix nicht tragen; `cookie_host_prefix=False`, ein anderer `cookie_path` und
  `cookie_secure=False` nehmen es ebenfalls weg. Ohne Präfix heißt das Cookie schlicht
  `tinysesam_session`, und jeder Host unter der übergeordneten Domain — auch eine geschützte App
  hinter Forward-Auth — kann ein eigenes Cookie dieses Namens für die ganze Domain setzen (cookie
  tossing), mit oder ohne `cookie_domain`: Ein abgemeldeter Besucher ist danach als das Konto
  angemeldet, dessen Token dieser Host besitzt, ein angemeldeter meist ebenso, weil das jüngere
  Cookie gewinnt. Dafür braucht es keinen Request an TinySesam, also halten weder CSRF-Token noch
  Herkunftsprüfung das auf; sie schließen nur den Weg über ein Formular (Login-CSRF per POST an
  TinySesam), und über reines HTTP nicht einmal den, weil Browser dort kein `Sec-Fetch-Site`
  schicken. `cookie_domain` nur setzen, wenn jeder Host darunter einem selbst gehört und so
  vertrauenswürdig ist wie TinySesam. Sonst leer lassen und die übrigen drei auf ihren Vorgaben
  lassen: Dann bleibt die Sitzung host-only mit `__Host-`, und kein anderer Host kann sie setzen.
  (Apps auf dem Host von TinySesam selbst, wie im pfadbasierten Forward-Auth-Aufbau, teilen seinen
  Origin und gelten ohnehin als vertrauenswürdig.)
- **Inhaber über Faktor-Änderungen benachrichtigen — `auth.on_security_event`.** Opt-in-Hook,
  gerufen als `hook(ereignis, konto, details)` mit `konto = {id, username, email, display_name}`,
  sobald ein Anmeldefaktor angelegt, geändert, entfernt oder verbraucht wird: `password_changed`,
  `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled` (`details={"recovery_codes_deleted": n}`),
  `recovery_codes_generated` (`details={"count": n}`), `recovery_code_used`
  (`details={"remaining": n}`), `passkey_added` (`details={"name": …}`), `passkey_removed`
  (`details={"passkey_id": n}`), `api_key_created` (`details={"key_id": n, "name": …}`),
  `api_key_revoked` (`details={"key_id": n}`), `email_changed` und `username_changed`
  (`details={"old": …, "new": …}` — Selbstbedienung, 2026-09-25) und `api_keys_revoked`
  (`details={"count": n, "reason": …}`, `reason` eines von `password_reset`, `account_disabled`,
  `admin_password_reset`, `sessions_revoked` — gesammelt beim Reset, bei der Sperre, beim
  Admin-Passwort und bei `sessions/revoke` mit `scope=all`). Verbundene Programme (OAuth, T-36):
  `oauth_device_connected` (`details={"grant_id": n, "client_id": …, "client_name": …, "resource": …}` — ein
  Programm hat nach der Zustimmung seine ersten Tokens bekommen), `oauth_device_revoked`
  (`details={"grant_id": n, "client_id": …, "reason": …}`, `reason` eines von `user`, `admin`, `client`,
  `account_disabled`) und `oauth_token_reuse` (`details={"grant_id": n, "client_id": …, "kind": "code"|"refresh"}`
  — ein schon benutzter Code oder Refresh-Token kam zurück, die Verbindung wurde widerrufen: das Token
  wurde vermutlich kopiert). Neue Zugänge, die kein eigener Faktor sind (H2, T-47): `signin_link_issued`
  (`details={"ttl_min": n, "by_operator": bool}` — für das Konto wurde ein Anmeldelink ausgestellt) und
  `device_signed_in` (`details={"method": "qr_login", "ip": …, "agent": …}` — ein Gerät hat sich über eine
  geräteübergreifende Bestätigung angemeldet); `password_changed` trägt `details={"by_operator": bool}`
  (`True`: ein Administrator hat es gesetzt). App-Passwörter (T-66): `app_password_created`
  (`details={"app_password_id": n, "name": …, "hosts": [...]}`), `app_password_revoked`
  (`details={"app_password_id": n}`) und `app_passwords_revoked` (`details={"count": n, "reason": …}`, dieselben
  Gründe wie `api_keys_revoked`). Dienste (T-60): `oauth_service_paired` (`details={"client_id": …, "client_name":
  …, "resources": [...]}` — ein Dienst wurde gekoppelt und handelt als das Konto) und `oauth_service_revoked`
  (`details={"client_id": …, "client_name": …, "reason": …}`, `reason` eines von `user`, `admin` und den Gründen von
  `api_keys_revoked`). Die vollständige Liste der Ereignisnamen ist
  `TinySesam.SECURITY_EVENTS`. Die Schlüssel in `details` und die
  Gründe sind seit 0.22.0 englisch (bis 0.21.x `verbleibend`, `alt`/`neu`, `anzahl`/`grund` mit
  deutschen Gründen). Das gilt auch für Änderungen, die ein Admin im Panel an
  einem fremden Konto vornimmt (Passwort zurücksetzen, API-Key ausstellen, Passkey widerrufen) — die
  Mail also so schreiben, dass sie nicht unterstellt, der Inhaber sei es gewesen. Ausser dem Hook
  verschickt TinySesam mit konfiguriertem Versand zwei Arten Mail selbst, beide nur an eine belegte
  Adresse und ohne Link: den Hinweis an ein Konto, das wegen Fehlversuchen gesperrt wurde (ASVS 6.3.5;
  abschaltbar mit `notify_login_failures=False`), und seit H2 einen Hinweis auf **neue Zugänge** (T-47,
  NIST SP 800-63B-4 §4.1.2.1; abschaltbar mit `notify_new_access=False`) bei `passkey_added`,
  `totp_enabled`, `pin_set`, `api_key_created`, `device_signed_in`, `signin_link_issued`,
  `password_changed` durch einen Administrator, `oauth_device_connected`, `oauth_token_reuse`,
  `app_password_created` und `oauth_service_paired` —
  höchstens einer je Konto und Ereignis pro Minute. Dieselben Ereignisse stehen auf der Kontoseite unter
  „Letzte Ereignisse“. Weitere eigene Mails gehen aus dem Hook (am besten über eine
  Warteschlange — er läuft synchron im Request). Ein Fehler im Hook macht die Änderung
  nie rückgängig, landet aber im Sicherheits-Log.
- **Dienste weisen sich mit ihrem eigenen Schlüssel aus, nicht mit einem Geheimnis (T-60, ADR-13).** Mit
  `oauth_service_clients` bekommt ein Dienst kurzlebige Access-Tokens per `client_credentials` mit `private_key_jwt`
  (RFC 7523): TinySesam speichert nur seinen öffentlichen Schlüssel, eine kopierte Datenbank, ein Proxy-Log oder eine
  Sicherung bringt also nichts, womit man ein Token bekommt. Die Assertion prüft joserfc (Extra `[services]`) mit
  einer Algorithmenliste (`Ed25519`, `ES256`, `EdDSA` für einen Ed25519-Schlüssel), gebunden an den Typ des
  gespeicherten Schlüssels — kein `none`, kein HMAC, kein Schlüssel aus dem JWT-Kopf; `aud` muss der Aussteller als
  einziger Wert sein (RFC 10070 — die Adresse des Token-Endpunkts wird gegen Audience-Injection abgelehnt), `exp`
  höchstens 5 Minuten voraus, `jti` bis dahin nur einmal. Eine Ablehnung antwortet allgemein `invalid_client`; der
  Grund steht im Audit-Log (`oauth_client_auth_failed`). Koppeln braucht einen Einmalcode aus einer frisch bestätigten
  Sitzung oder dem Admin-Panel und einen Nachweis, dass der Dienst den privaten Schlüssel hält. Das Token trägt nie
  das Admin-Merkmal; Sperre, Widerruf oder entzogene Rolle wirken bei der nächsten Anfrage. Was bleibt: **Die
  Schlüsseldatei ist der Dienst** — wer sie kopiert (Vorgabe Modus 0600), bekommt Tokens, bis der Schlüssel
  gewechselt (`oauth_service_key_days`, der Client wechselt zur halben Laufzeit) oder der Dienst widerrufen ist. Ein
  Access-Token selbst ist für seine Laufzeit (15 min) an seiner Ressource ein Bearer-Token; die Bindung an den
  Schlüssel (DPoP, RFC 9449) ist als T-68 offen.
- **Bekannte Grenze — Basic-Auth hat keinen zweiten Faktor; deshalb nimmt sie nur App-Passwörter an (T-66).**
  WebDAV-, CalDAV/CardDAV- und Git-Clients schicken Benutzername und Passwort mit jeder Anfrage und können weder eine
  TOTP-Abfrage beantworten noch einen Passkey halten. Mit `forward_apps[host]["app_passwords"] = True` nimmt das Gate
  für diesen Host `Authorization: Basic` an — aber **nur** mit einem App-Passwort: ein erzeugtes Geheimnis mit
  ≈ 124 Bit (NIST SP 800-63B §5.1.2.1 verlangt 112 für ein Nachschlage-Geheimnis ohne Drossel), gespeichert als
  HMAC-Digest mit dem Pepper-Schlüsselbund, gebunden an sein Konto und die beim Anlegen gewählten Anwendungen, ohne
  Admin-Rechte, angelegt nur nach frischer Bestätigung und widerrufen mit den API-Keys bei Sperre, Admin-Passwort und
  „überall abmelden“. Das eigene Passwort des Kontos wird dort nie verglichen (es hat nicht einmal das Format), der
  zweite Faktor lässt sich per Basic-Auth also nicht umgehen. Was bleibt: Ein App-Passwort ist ein Inhaber-Geheimnis —
  wer es vom Gerät kopiert (oder ohne HTTPS mitliest), kann es an seinen Anwendungen nutzen, bis es abläuft oder
  widerrufen wird; es geht mit jeder Anfrage mit, der Proxy davor darf `Authorization` also nicht protokollieren, und
  vor der Anwendung gehört der Header entfernt (`header_up -Authorization`). Fehlversuche sind `failed login …
  method=app_password` im Sicherheits-Log (fail2ban) und zählen in einem eigenen Topf, Raten am Gate sperrt also nicht
  die Anmeldung im Browser. Samba und andere Protokolle ohne HTTP sind nicht Teil davon.
- **Ein TOTP-Code gilt genau einmal — auch der Einrichtungscode.** Der Code, der die Einrichtung
  bestätigt, ist danach verbraucht. Unter `login_chain=["password","totp"]` schliesst diese
  Bestätigung den TOTP-Schritt der Anmeldung gleich mit ab; überall sonst braucht die Anmeldung den
  *nächsten* Code. Integrationstests, die `totp_confirm(uid, now())` rufen und sich danach mit
  demselben Code anmelden (`POST /auth/totp`), werden seit T-13 rot — dort mit dem Code des
  vorigen Zeitschritts bestätigen.
- **Eigene Login-, Step-up- oder Passwortwechsel-Seite: auf den Bausteinen bauen.**
  `login_password`, `login_pin`, `login_totp`, `confirm_password`, `confirm_pin`, `confirm_totp`
  und `change_password` (Stufe A, seit 0.22.0) drosseln, zählen, sperren und protokollieren genau
  wie die eingebauten Routen — die rufen sie. Die inneren Prüfer (`_check_password`,
  `_verify_user_password`, `_verify_user_pin`, `_verify_totp` und ihre alten Namen der Stufe C) tun
  nichts davon: Auf einer Seite darüber lassen sich Passwörter, PINs und Codes so schnell raten, wie
  der Server antwortet — ohne Zeile für fail2ban. Ein API-Key zählt bei diesen
  Bausteinen nie: Er bestätigt keinen Menschen und ändert kein Passwort (`POST /auth/password`
  weist ihn seit 0.22.0 mit 403 ab).

## Verwundbare Abhängigkeiten

Fristen, in denen eine bekannte Schwachstelle in einer Abhängigkeit des Pakets oder des
Gateway-Abbilds behoben wird (ASVS 15.1.1), gezählt ab dem Tag, an dem eine behobene Version
verfügbar ist:

| Schwere (CVSS) | Frist |
| --- | --- |
| Kritisch | **7 Tage** |
| Hoch | **30 Tage** |
| Mittel / niedrig | mit dem nächsten regulären Release |

Wie sie gehalten werden: `pip-audit` prüft jede Auflösung des Pakets und die Sperrliste des
Abbilds bei jedem Pull-Request und nächtlich, ein Fund lässt den Lauf scheitern; das gebaute
Gateway-Abbild durchsucht Grype bei jedem Pull-Request, und ein behebbarer Fund ab Schwere
*hoch* lässt ihn scheitern; Dependabot schlägt die Updates vor. Ein Fund, der sich nicht
fristgerecht beheben lässt (etwa weil das behobene Betriebssystempaket noch nicht im gepinnten
Basisabbild steckt), darf nur in `.grype.yaml` ausgenommen werden, mit Begründung und einem
`until`-Datum innerhalb dieser Fristen — nach diesem Datum scheitert der Scan wieder.

## Unterstützte Versionen

Sicherheitsfixes landen auf der jeweils neuesten veröffentlichten Minor-Version — welche das ist,
steht oben in [CHANGELOG.md](../CHANGELOG.md). Ältere Linien bekommen keine Rückportierung: einen
Tag pinnen und den Pin weiterziehen, wenn ein Release etwas behebt. (Hier stand früher eine feste
Version, und sie war dreizehn Minor-Versionen alt — ein Versprechen, das niemand nachgemessen hat.)

<br /><br />
<p align="right"><img src="../docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
