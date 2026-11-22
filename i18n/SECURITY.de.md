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
WebAuthn mit `sign_count`-Klon-Erkennung, sha256-gehashte Einmal-/API-Tokens, Sitzungs-Handles als HMAC mit einem Pepper außerhalb der Datenbankdatei, Brute-Force-Lockout +
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
  (`details={"grant_id": n, "client_id": …, "reason": …}`, `reason` eines von `user`, `admin`, `client`
  und den Gründen von `api_keys_revoked` — seit der Angriffsrunde vom 2026-11-21 (A-1) trennen auch ein Reset, ein
  Admin-Passwort-Reset und „überall abmelden“ die verbundenen Programme, nicht nur eine Sperre) und `oauth_token_reuse` (`details={"grant_id": n, "client_id": …, "kind": "code"|"refresh"}`
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
  `api_keys_revoked`). Eine vollständige Anmeldung nach mindestens drei Fehlversuchen in Folge (T-63, ASVS 6.3.5):
  `signed_in_after_failures` (`details={"failures": n, "ip": …}` — die Serie zählt jeden fehlgeschlagenen
  Anmeldeversuch unter den Namen des Kontos seit der letzten vollständigen Anmeldung, über alle Verfahren; dazu das
  Audit-Ereignis `login_after_failures`). Freigaben (Etappe A): `approval_approved` (`details={"approval_id": …,
  "type": …, "result": …}` — die Inhaberin hat eine Aktion bestätigt, die ein Token angefragt hatte, und TinySesam hat
  sie ausgeführt; TinySesam selbst verschickt dazu keine Mail). Die vollständige Liste der Ereignisnamen ist
  `TinySesam.SECURITY_EVENTS`. Die Schlüssel in `details` und die
  Gründe sind seit 0.22.0 englisch (bis 0.21.x `verbleibend`, `alt`/`neu`, `anzahl`/`grund` mit
  deutschen Gründen). Das gilt auch für Änderungen, die ein Admin im Panel an
  einem fremden Konto vornimmt (Passwort zurücksetzen, API-Key ausstellen, Passkey widerrufen) — die
  Mail also so schreiben, dass sie nicht unterstellt, der Inhaber sei es gewesen. Ausser dem Hook
  verschickt TinySesam mit konfiguriertem Versand zwei Arten Mail selbst, beide nur an eine belegte
  Adresse und ohne Link: den Hinweis an ein Konto, das wegen Fehlversuchen gesperrt wurde, und seit T-63 einen über
  eine Anmeldung nach Fehlversuchen (ASVS 6.3.5; beide abschaltbar mit `notify_login_failures=False`), und seit H2 einen Hinweis auf **neue Zugänge** (T-47,
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
- **Delegierte können die Konten in ihrem Bereich übernehmen — gewollt (T-74).** Eine Delegiertenrolle
  (`admin_delegates`) lässt ihre Träger für jedes Konto in ihrem Bereich einen Anmeldelink ausstellen; wer ihn
  einlöst, ist in diesem Konto angemeldet. Ein Delegierter hält damit faktisch jede verwaltete Rolle: Er kann auch ein
  Konto mit diesen Rollen anlegen und sich darin anmelden. In einer Hierarchie geht das nach unten: `area-admin` kann
  jedes Konto der Teams darunter und jeden `team-*-admin` übernehmen, den er verwaltet, ein `team-a-admin` nur
  einfache Konten von Team A — nie einen Gleichrangigen, ein Konto darüber, einen fremden Zweig, einen Administrator,
  einen Owner oder ein Dienstkonto, nie über einen API-Key, ein OAuth-Token oder ein App-Passwort. Es steht hinter
  demselben Step-up wie bei einem Administrator, ein Anmeldelink immer hinter einer frischen Bestätigung, und jede
  Aktion steht mit dem handelnden Konto im Audit-Log. Eine Delegiertenrolle nur an jemanden vergeben, dem man jedes
  verwaltete Konto anvertrauen würde; `signin_link` (und `invite`, `create`) aus `can` nehmen, wo das zu viel ist. Ein
  Delegierter kann auch ein Konto entsperren, das ein Administrator gesperrt hat (die Sperre merkt sich nicht, wer sie
  gesetzt hat): Um ein Konto der Reichweite eines Delegierten zu entziehen, ihm die verwalteten Rollen nehmen.
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
  die Vorlagen entfernen den Header vor der Anwendung (nächster Punkt). Fehlversuche sind `failed login …
  method=app_password` im Sicherheits-Log (fail2ban) und zählen in einem eigenen Topf, Raten am Gate sperrt also nicht
  die Anmeldung im Browser. Samba und andere Protokolle ohne HTTP sind nicht Teil davon.
- **Zugangsdaten an der Anwendung — die Vorlagen entfernen sie.** Jede Proxy-Vorlage in `deploy/` (Caddy, nginx,
  Traefik) entfernt `Authorization` und `X-Api-Key` auf dem Weg zur Anwendung, NACHDEM Forward-Auth entschieden hat:
  Caddy `header_up -Authorization` / `header_up -X-Api-Key` in jedem `reverse_proxy` zur Anwendung, nginx
  `proxy_set_header Authorization ""` (FastCGI `fastcgi_param HTTP_AUTHORIZATION ""`, damit bleiben auch
  `PHP_AUTH_USER`/`PHP_AUTH_PW` leer), Traefik die Middleware `tinysesam-strip-credentials` nach `tinysesam-auth`.
  Wer angemeldet ist, erfährt die Anwendung aus `Remote-*`; das Geheimnis braucht sie nie. Bis zur Angriffsrunde vom
  2026-11-21 (A-3) stand das in den Vorlagen nur als Kommentar, und Header-Log, Debug-Seite oder Fehlerbericht einer
  Anwendung bekamen App-Passwörter, OAuth-Access-Tokens und — am schlimmsten — API-Keys (`tsk_…`, gültig an jedem
  Host und an TinySesams eigener API, mit Rollen, bis zu 90 Tage). **Deine Anwendung prüft `Authorization` selbst**
  (eigene Basic-Auth oder Token-Prüfung hinter dem Gate)? Dann lösch diese Zeilen für genau diesen Host oder diese
  Location, bewusst — und nimm in Kauf, dass dann in dem, was sie protokolliert, das Geheimnis steht. Das
  `webdav`-Profil des Schnellstarts braucht das nicht (der WebDAV-Server dort hat keine eigene Anmeldung).
  `tests/test_attack_round_a.py` prüft jede Vorlage unter `deploy/` darauf, auch eine neue; `tests/test_gate_caddy.py`
  misst es durch ein echtes Caddy.
- **Zugangsdaten landen auch nicht im Proxy-Log.** Das Gate-Plugin caddy-jwt (v1.4.0) nimmt `Authorization` als
  Token-Kandidaten, egal was konfiguriert ist, und protokolliert einen Kandidaten, der kein JWT ist, auf Level error mit
  einem Drittel von Anfang und Ende. Bis 0.26.0 schrieb `deploy/forward-auth/Caddyfile.gate` so einen halben API-Key,
  ein halbes OAuth-Token oder App-Passwort jedes API- und MCP-Aufrufs ins Caddy-Log. Seit 0.26.1 geht eine Anfrage mit
  `Authorization` oder ohne Gate-Cookie direkt an `/auth/forward`; jwtauth sieht nur das Gate-Cookie. Das protokolliert
  Caddy weiterhin gekürzt (ein JWT von höchstens `gate_token_ttl_sec`) bei jeder Anfrage, die es durchlässt.
- **Ein TOTP-Code gilt genau einmal — auch der Einrichtungscode.** Der Code, der die Einrichtung
  bestätigt, ist danach verbraucht. Unter `login_chain=["password","totp"]` schliesst diese
  Bestätigung den TOTP-Schritt der Anmeldung gleich mit ab; überall sonst braucht die Anmeldung den
  *nächsten* Code. Integrationstests, die `totp_confirm(uid, now())` rufen und sich danach mit
  demselben Code anmelden (`POST /auth/totp`), werden seit T-13 rot — dort mit dem Code des
  vorigen Zeitschritts bestätigen. **Welche Schritte zählen**, sagt `totp_window` (T-57, RFC 6238 §5.2):
  als Vorgabe der laufende und der vorige; bis 0.25.x zählte auch der nächste (`"previous_and_next"` behält das).
  Ein Test, der sich mit dem Code des *nächsten* Schritts anmeldet, braucht jetzt diesen Schalter. `"current"`
  nimmt nur den laufenden Schritt — die 30 Sekunden aus ASVS 6.5.5, um den Preis von Codes, die genau beim
  Schrittwechsel getippt werden.
- **Eine Neuanmeldung beim OIDC-Anbieter wird an `auth_time` gemessen (T-49, ASVS 6.8.4).** Eine Runde durch die
  laufende Sitzung des Anbieters ist still — kein Passwort, kein Faktor. Mit `oidc_reauth_check` (Vorgabe an)
  bietet die Bestätigungsseite einem mit ihm verknüpften Konto „Mit <Anbieter> bestätigen“ an; diese Runde
  verlangt eine aktive Anmeldung (`prompt=login`, `max_age=0`, OIDC Core §3.1.2.1) und bestätigt nur mit einem
  `auth_time` nach der Anfrage (60 s Uhrentoleranz) — sonst sagt die Seite das, und nichts ist bestätigt (Audit
  `oidc_reauth_stale`). Jede andere Runde auf einer vollen Sitzung (die Freigabe für eine weitere Anwendung)
  frischt die Bestätigung nicht mehr auf (`stepup_not_counted reason=no_fresh_auth_time`), und eine neue Sitzung
  gilt ab dem `auth_time` des Anbieters als bestätigt, nicht ab der Runde: eine stille Anmeldung eine Stunde nach
  dem letzten Passwort ist für `stepup_max_age_sec` eine Stunde alt. **Rückfall ohne `auth_time`** (der Anbieter
  sendet den Claim nicht): eine neue Sitzung zählt wie bisher ab TinySesams eigener Anmeldung — dem Anbieter wird
  zugetraut, mindestens mit seinem schwächsten Verfahren angemeldet zu haben; der Anbieter-Knopf bestätigt dann
  nie, das Konto bestätigt mit eigenen Faktoren oder durch eine neue Anmeldung. Anbieter, die `prompt=login`
  ignorieren, fallen genauso auf. `oidc_reauth_check=False` stellt das Verhalten bis 0.25.x wieder her. SAML hat
  diese Prüfung noch nicht (`ForceAuthn` wird nicht gesendet, `AuthnInstant` nicht gelesen; Backlog T-70): eine
  SAML-Runde über die laufende Sitzung des Anbieters zählt weiter als frische Bestätigung.
- **Eigene Login-, Step-up- oder Passwortwechsel-Seite: auf den Bausteinen bauen.**
  `login_password`, `login_pin`, `login_totp`, `confirm_password`, `confirm_pin`, `confirm_totp`
  und `change_password` (Stufe A, seit 0.22.0) drosseln, zählen, sperren und protokollieren genau
  wie die eingebauten Routen — die rufen sie. Die inneren Prüfer (`_check_password`,
  `_verify_user_password`, `_verify_user_pin`, `_verify_totp` und ihre alten Namen der Stufe C) tun
  nichts davon: Auf einer Seite darüber lassen sich Passwörter, PINs und Codes so schnell raten, wie
  der Server antwortet — ohne Zeile für fail2ban. Ein API-Key zählt bei diesen
  Bausteinen nie: Er bestätigt keinen Menschen und ändert kein Passwort (`POST /auth/password`
  weist ihn seit 0.22.0 mit 403 ab).

## Freigaben (Etappe A): Ein Token schlägt vor, der Mensch bestätigt

Mit `approvals_enabled=True` kann ein API-Key eines Kontos eine von drei TinySesam-Aktionen **anfragen**, die er selbst
nicht darf: `tinysesam.account.set_roles` (Rollen hinzufügen und entfernen), `tinysesam.apikey.revoke`,
`tinysesam.account.disable`. TinySesam speichert die Anfrage und antwortet mit einem Link und einem sechsstelligen
Prüfcode; der Mensch öffnet den Link in seiner Browser-Sitzung, bestätigt noch einmal und entscheidet. Dafür gelten
diese Regeln:

- **Der Token schlägt nur vor.** `POST /auth/api/approvals` schreibt eine Zeile, es gewährt nichts. Anfragen darf nur
  ein API-Key (ein `human`-Key nur neben einer Sitzung seines Kontos, wie überall); eine Sitzung hat das Panel, ein
  OAuth- oder MCP-Token wird abgewiesen, bis TinySesam selbst eine MCP-Ressource ist, ein App-Passwort nie. Der Key
  eines Dienstkontos bekommt `no_approver`: Niemand könnte bestätigen.
- **Entscheiden kann nur eine Browser-Sitzung desselben Kontos** (`POST /auth/approvals/{id}`). Eine Anfrage mit
  `Authorization` oder `X-Api-Key` wird mit 403 abgewiesen, auch ein `human`-Key neben seiner Sitzung. Ein anderes
  Konto sieht eine neutrale Seite („gibt es nicht oder gehört zu einem anderen Konto“), dieselbe Antwort wie für eine
  unbekannte ID; die ID selbst hat 128 Bit Zufall.
- **Step-up je Freigabe, nie ein Zeitfenster.** Passwort, PIN oder TOTP (was `stepup_options()` anbietet, also durch
  `stepup_methods` eingeengt), ein Passkey, dessen WebAuthn-Challenge SHA-256(`"tinysesam-approval:"` ‖
  Server-Zufallswert ‖ ID ‖ Nutzlast-Hash) ist — einmalig und an genau diese Aktion gebunden, sodass ein Agent im
  Browser keine Geste wiederholen kann —, oder eine frische Anmeldung beim Anbieter (`prompt=login`, `max_age=0`),
  deren `auth_time` nach der Anfrage liegen muss (ohne `auth_time`: keine Freigabe, fail-closed). Eine frische Sitzung
  zählt nicht, und eine Freigabe macht die Sitzung nicht frisch. Die Geheimnis-Prüfungen laufen durch Sperre, Zähler
  und fail2ban-Zeilen der Reauth-Seite.
- **Es zählen die Rechte zur Bestätigungszeit (E4).** TinySesam führt mit dem Code des Admin-Panels aus
  (`admin.PanelActions`), als die bestätigende Sitzung: ein Admin, ein Delegierter in seinem Bereich (T-74), die
  Inhaberin für ihren eigenen Key. Endet eine Delegation dazwischen, steht `result=forbidden`. **Admin-Rechte gehen
  nie über diesen Weg:** `set_roles` nimmt nur `add`/`remove` von Rollen, nie die Admin-Flag — ein Typ, der sie
  vergibt, braucht eine eigene Entscheidung des Maintainers, nicht nur Code.
- **Nichts Bleibendes.** Eine Aktion, einmal, für Minuten (`approval_pending_sec`, 120–1800 s). Jeder Zustandswechsel
  ist ein `UPDATE … WHERE state = <alt>`: Bei doppeltem oder parallelem Bestätigen gibt es genau einen Gewinner, und
  nur er führt aus. Ein GET entscheidet nie etwas; der POST trägt CSRF und den `payload_hash`, den die Seite gezeigt
  hat — eine Anfrage, die sich dazwischen geändert hat, wird abgewiesen.
- **Kein freier Text vom Anfrager.** Titel und Zusammenfassung sind TinySesams eigene Texte, gefüllt aus der
  gespeicherten Nutzlast und dem DB-Stand beim Anzeigen; jeder Wert ist escaped und bidi-isoliert, Steuerzeichen und
  Kommas in Rollennamen werden abgelehnt, nicht entfernt. Ein Zielkonto oder Key, das die Betrachterin gerade nicht
  verwalten darf, erscheint nur mit seiner ID. Die Seite wird nie eingebettet: `frame-ancestors 'none'` und
  `X-Frame-Options: DENY`, egal was `csp` sagt.
- **Müdigkeit und Spam.** Keine Sammelbestätigung; offene Anfragen je Konto (`approval_open_per_account`, 5) und je
  Key (`approval_open_per_token`, 3), neue je Konto und Stunde (`approval_requests_per_hour`, 20), und
  `approval_reject_limit` (3) Ablehnungen eines Typs von einem Key binnen einer Stunde sperren diesen Key für diesen Typ
  eine Stunde — jeweils `429`, im Audit als `approval_throttled`.
- **Audit ohne Werte:** `approval_requested`, `approval_approved` (mit `amr`), `approval_rejected`,
  `approval_withdrawn`, `approval_expired`, `approval_executed` (mit `result`), `approval_throttled`,
  `approval_denied` (`reason=token|other_account|stepup|payload_changed|no_approver`) tragen ID, Typ, Key und
  Nutzlast-Hash — die Werte bleiben in der Zeile. `approval_approved` erreicht `on_security_event`.

Restrisiko: ein Mensch, der bestätigt, ohne zu lesen. Prüfcode, Step-up je Freigabe und die Limits erschweren das,
verhindern es aber nicht — die Seite ist bewusst schlicht: wer fragt (Key-Name und Datum), was (ein Satz und die
Werte), der Code, die Restzeit. Den anfragenden Key zu widerrufen beendet eine Flut von Anfragen.

## Konten-API für Anwendungen (Etappe A)

Mit einer Anwendung in `apps`, die einen `provisioning`-Block hat, verwaltet die Anwendung die Konten, **die sie selbst
anlegt**, über `/auth/api/users`: anlegen (mit einem Einmal-Link bis zur ersten Anmeldung), lesen, Anzeigename und die
Rollen ihrer Allowlist ändern, sperren und entsperren. Sie ruft TinySesam direkt mit einem Automation-Key ihres
Dienstkontos auf.

**Was ein geleakter Anwendungs-Key höchstens kann:** Konten mit den Rollen der Allowlist anlegen (`create_per_hour`,
`max_accounts`) und deren Einmal-Links bekommen — also eigene Zugänge mit den Rollen der Anwendung; darum sollten diese
Rollen nur der Anwendung gehören (`config_check` warnt bei einer Rolle ohne Präfix `<app>-`); Allowlist-Rollen auf den
Konten der Anwendung ändern; sie sperren und entsperren (nur die eigene Sperre, `disable_per_hour`); Namen, Adressen,
Allowlist-Rollen und Anmeldezeitpunkte der Konten der Anwendung lesen.

**Was er nicht kann:** Administrator oder Delegierter werden, ein anderes Konto sehen oder ändern, ein benutztes Konto
übernehmen (kein Link nach der ersten Anmeldung, keine Adressänderung, kein Passwort, kein Faktor), Keys oder
App-Passwörter ausstellen, Dienstkonten anlegen, eine Sperre des Betreibers aufheben. Die Regeln dahinter:

- **Nur der Key zählt.** Der Aufrufer wird allein über `verify_api_key` aufgelöst, nie über `current_user()` — ein
  Sitzungs-Cookie meldet weder an noch ändert es etwas (401 ohne Key). Verlangt: ein Automation-Key, ein Konto mit
  `is_service == 1`, als `account` einer Anwendung mit `provisioning` genannt (sonst 403 `not_a_provisioning_app`).
  Regel E4 bleibt: Der Key trägt weder Admin-Flag noch Delegiertenrolle; die Konten-API ist eine eigene, enge Tür und
  öffnet keine Panel-Route.
- **Eigentum nur über `users.managed_by`** — gesetzt, wenn die Anwendung das Konto anlegt, nie aus Rollen abgeleitet.
  Ein Konto, das die Anwendung nicht angelegt hat, ein Administrator, Eigentümer, Dienstkonto oder Delegierter antwortet
  mit **404** wie ein Konto, das es nicht gibt, auf jeder Route, entschieden vor jedem Feld der Anfrage.
  Ganzkonto-Aktionen (Anzeigename, Sperre, Link) verlangen zusätzlich alle Rollen des Kontos in der Allowlist (sonst
  `409 account_shared` — die Anwendung sieht das Konto, das ist also kein Orakel); die Regel ist
  `config_check.may_manage`, dieselbe wie für die Delegierten des Panels.
- **Rollen nur aus der Allowlist,** nie `admin`, eine Delegiertenrolle oder eine Rolle, die eine Gruppen-Abbildung
  vergibt (`config_check`-Fehler). Eine Rolle außerhalb wird abgewiesen (400 `role_not_allowed`), nie still verworfen.
  `PATCH` schreibt `(aktuell − Allowlist) ∪ gewünscht` in einer Transaktion, Rollen des Betreibers bleiben also.
  `is_admin`, `is_service` und `password` werden abgewiesen; ein Name oder eine Adresse aus `admin_identifiers`
  antwortet wie eine vergebene.
- **Kein Zugriff auf Anmeldemethoden.** Kein Passwort, Passkey oder TOTP wird gesetzt oder zurückgesetzt; die Adresse
  nimmt die API nur beim Anlegen an (`email_verified=0`), nie per `PATCH` — sonst setzte ein Key die eigene Adresse und
  übernähme das Konto über „Passwort vergessen“.
- **Der Einmal-Link nur vor der ersten Anmeldung** (danach `409 already_signed_in` — dann wäre ein Link vom Key eine
  Übernahme). Ein neuer Link verwirft die offenen. Den Link gibt es nur in der Antwort: Die Datenbank speichert den
  Hash, das Audit nennt `ttl_min`, keine Logzeile enthält ihn. Der Inhaber erfährt davon (`signin_link_issued`).
- **Die eigene Sperre der Anwendung** (`disabled=3`): Sie stuft keine andere Sperre herab (`UPDATE … WHERE
  disabled=0`), und `enable` hebt nur `3` auf (sonst `409 disabled_by_operator`). Jede Prüfung liest `disabled <> 0`,
  `3` meldet also nirgends an — nicht per Passwort, Passkey, Anmeldelink, OIDC, SAML, LDAP oder Key. Das Sperren beendet
  Sitzungen, Keys, Geräte, App-Passwörter und offene Links wie jede Sperre.
- **Der Mensch hinter dem Aufruf ist behauptet, nicht belegt.** Schreibaufrufe tragen `TinySesam-On-Behalf-Of` (die ID
  einer aktiven Person oder `-` für einen Job; ohne 400). Das Audit nennt das Dienstkonto als Akteur und die Behauptung
  als `actor_claimed=<name>#<id>`. Antworten `actor_invalid` zählen gegen `taken_per_hour` wie Antworten „vergeben“:
  sonst ließen sich Konten aufzählen.
- **Grenzen je Anwendung** in der Datenbank (von allen Workern geteilt): Anlagen, Sperren, Links und Antworten
  „vergeben“ je Stunde (`429` mit `Retry-After`, einer Warnung im Sicherheitslog und `provision_throttled`);
  `max_accounts`.

Restrisiko: Wer den Key hat, kann Konten mit den Rollen der Anwendung anlegen, bis eine Grenze greift, und die Konten
der Anwendung sperren. Den Key des Dienstkontos im Panel zu widerrufen schließt die API sofort; das Audit
(`provision_*`, `apikey_use`) zeigt, was geschah.

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
