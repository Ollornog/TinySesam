# Betrieb — was TinySesam tut, wenn etwas ausfällt

Diese Seite ist für den Betreiber: Was passiert, wenn ein Teil wegbricht, wie man Sitzungen und
fremde Identitäten verwaltet, und wie stark die einzelnen Anmeldewege wirklich sind. Die READMEs
zeigen, wie man TinySesam einbaut; hier steht, womit man danach rechnen muss.

Jede Aussage hier ist am Code nachgestellt. Wo ein Verhalten eine bekannte Schwäche ist, steht die
Backlog-Kennung dabei ([T-13](../backlog/T-13-audit-2026-09-22-runde-3.md)).

## Ausfallverhalten

Grundregel: **Fällt eine Prüfinstanz aus, wird nicht angemeldet** (fail-closed). Zwei bewusste
Ausnahmen stehen unten ausdrücklich dabei (Redis, Sicherheits-Log): Dort wird eine *Bremse*
schwächer oder fällt ein *Protokoll* weg, nicht die Prüfung selbst.

| Was fällt aus | Was der Nutzer sieht | Was der Betreiber sieht |
|---|---|---|
| **Datenbank nur lesbar** (Read-only-Mount, Rechte nach einem Rückspielen) | Anmeldung scheitert mit 500, sobald eine Sitzung geschrieben wird. Bestehende Sitzungen lesen weiter. | Gateway: `/healthz` → **503** `degraded` (Schreibprobe, B6-4). Log: `Healthcheck: Datenbank nicht beschreibbar`. |
| **Datenbank-Volume voll** | wie oben, sobald SQLite neuen Platz braucht | `/healthz` → 503, **wenn** die Schreibprobe Platz braucht. Eine Probe, die in schon belegte Seiten schreibt, sieht einen fast vollen Datenträger nicht — Plattenplatz gehört zusätzlich in die Überwachung des Hosts. |
| **Datenbank gesperrt** (zweiter Schreiber: weiterer Worker, `tinysesam` auf der Kommandozeile, Sicherung) | Die Anfrage wartet bis zu **10 s** (`Store.BUSY_TIMEOUT_MS`, B6-11), dann 500 (`database is locked`). Die nächste Anfrage läuft normal: Ein gescheiterter Schreibzugriff rollt zurück und lässt keine Transaktion offen. | die 500 steht im Log des ASGI-Servers. `/healthz` wartet ebenso und meldet erst nach 10 s 503 — der HEALTHCHECK des Abbilds wartet deshalb 12 s. Bis zur Integration von T-13 hinterliess ein solcher Fehlschlag (auch der Schreibprobe von `/healthz`) eine offene Transaktion, und jede folgende Anmeldung endete mit 500, bis zufällig ein anderer Schreibzugriff committete. Findet der Anmeldeweg trotzdem eine vor, verwirft er sie und schreibt `Offene Transaktion … verworfen` ins Log — das ist dann ein Fehler an anderer Stelle. |
| **Redis** (`redis_url`) nicht erreichbar | nichts: Anmeldungen gehen weiter | **gedrosselt je Prozess** — ein eingebauter In-Memory-Limiter übernimmt (bei `--workers N` also bis zu N-mal so grosszügig, aber eine Grenze; B6-1). Gemeldet wird der Wechsel, nicht jede Anfrage: einmal `Redis-Rate-Limit nicht erreichbar …`, einmal bei der Rückkehr (B6-2); schon der Start fragt Redis per `ping`. Nach einem Fehler ruht Redis 30 s, dann folgt der nächste Versuch. Die Kontosperre (in der Datenbank) greift unverändert. |
| **SMTP / Mailer** | Magic-Link und „Passwort vergessen": dieselbe Erfolgsseite wie immer (keine Konto-Enumeration), aber keine Mail. Registrierung mit Bestätigungsmail: ebenfalls die übliche Seite („Mail unterwegs"); das eben angelegte Konto wird wieder entfernt und die Registrierung lässt sich wiederholen (B6-5). Ist gar kein Mailer eingerichtet (kein `smtp_host`, kein `set_mailer`), lehnt die Registrierung mit Bestätigung sofort mit 500 ab. | Audit: `magic_send_error`, `reset_send_error` bzw. `verify_send_error` (mit „Konto entfernt"). Das Token der nicht zugestellten Mail ist sofort abgelaufen (B6-12) — ein Relay, das die Mail doch noch nachreicht, trägt einen toten Link. |
| **OIDC-Provider** | Neue Anmeldungen über OIDC scheitern (Fehlerseite). Bestehende Sitzungen laufen weiter bis `session_ttl_hours`. | Mit mehreren Anwendungen und `oidc_revalidate_minutes`: Nach Ablauf der Frist schickt Forward-Auth den Nutzer zum Provider — ist der weg, endet der Zugang zu **dieser** Anwendung (fail-closed). |
| **LDAP-Server** | 503 „Verzeichnis nicht erreichbar" — für jedes Konto dieselbe Antwort. Lokale Konten mit eigenem Passwort (der Notfall-Admin) melden sich weiter an. | Ein Ausfall ist kein Fehlversuch: keine Sperre, kein `failed login` (F-23); ein falsches **lokales** Passwort zählt weiter (A-1). Audit `ldap_unavailable`, im Sicherheits-Log `LDAP nicht erreichbar user=… grund=…`. Nach dem ersten Fehlschlag, der das Verzeichnis als Ganzes betrifft (Verbindungsaufbau, TLS, Dienstkonto, oder eine Frage, die bis zum Timeout hing), fragt TinySesam das Verzeichnis **30 s lang gar nicht** (`ldap_.AUSFALL_PAUSE_SEK`), danach fragt eine einzelne Anmeldung nach. Bricht das Verzeichnis nur **eine** Anfrage schnell ab, nachdem deren Eingaben gesendet waren (etwa slapd bei einer PDU über `sockbuf_max_incoming`), bekommt nur diese 503 (`grund=LDAP: nur diese Anfrage abgebrochen …` im Sicherheits-Log) — sonst schaltete eine präparierte Anmeldung LDAP für alle ab. Benutzernamen über 256 und Passwörter über 1024 Zeichen (`ldap_.LDAP_NAME_MAX`, `LDAP_PASSWORT_MAX`) gehen gar nicht erst ans Verzeichnis und zählen wie ein falsches Passwort (401, `failed login`); Ausfall und Rückkehr stehen je einmal im Log (`LDAP-Verzeichnis nicht erreichbar (…)`, `… wieder erreichbar`). Ohne diese Pause hing bei einem Verzeichnis, das Pakete verwirft, jeder Anlauf bis zum Timeout (10 s, `ldap_.VERBINDUNGS_TIMEOUT`) und zählte derweil als vorgebuchter Versuch — hinter einer NAT-Adresse bekam dann auch der Notfall-Admin 429, und fail2ban las `failed login`. **Bekannte Lücke:** das erste solche Fenster je Ausfall und Prozess; wer in diesen höchstens 10 s anklopft, schwebt noch. |
| **Extra fehlt zur Laufzeit** (`[oidc]`, `[saml]`, `[ldap]`, `[passkey]`) | Anmeldung über dieses Verfahren scheitert mit einer lesbaren Meldung | Beim Start eine Warnzeile mit `pip install 'tinysesam[…]'` (der Start selbst bleibt möglich — ein eigener Client lässt sich setzen); beim ersten Versuch `MissingExtra` mit dem Paketnamen statt einer 500 aus der Tiefe. |
| **Extra `[argon2]` fehlt** (neues Abbild, venv neu aufgesetzt) | Jedes Konto mit argon2-Hash: „Passwort falsch". | Beim Start eine Zeile mit der Zahl der betroffenen Hashes und `pip install 'tinysesam[argon2]'`; im Betrieb einmal je Prozess dieselbe Abhilfe (B6-8). scrypt-Hashes prüft jede Installation. |
| **Systemuhr springt zurück** (NTP, Pi ohne Pufferbatterie, VM-Snapshot) | nichts — Fristen laufen normal weiter | Warnzeile `Die Systemuhr steht … hinter der zuletzt benutzten Zeit`. TinySesam zählt monoton weiter; abgelaufene Sitzungen, Einmal-Token und Step-ups leben nicht wieder auf (B6-9). Über einen **Neustart** trägt die Datenbank den Stand: Sie sichert ihn höchstens jede Minute (`uhr_stand`, bei jedem Schreibzugriff und bei der Schreibprobe von `/healthz`). Was in der Zeit danach ablief — die letzte Minute, oder die ganze Ruhezeit einer Instanz ohne Healthcheck und ohne Anmeldungen —, gilt nach einem Boot mit altem Datum wieder, bis die Uhr diesen Abstand aufgeholt hat. Sprang die Uhr einmal falsch nach **vorn**, bleiben Zeitstempel dort, bis die Wanduhr aufholt. |
| **Sicherheits-Log** (`security_log`) nicht schreibbar | nichts | Beim Start: `security_log … nicht schreibbar — fail2ban bekommt nichts zu lesen`. Angemeldet wird trotzdem — ein fehlendes Protokoll ist kein Grund, den Dienst stillzulegen. |

**Healthcheck.** Das Gateway (`python -m tinysesam.gateway`) bringt `/healthz` mit: ohne Anmeldung
erreichbar, auch bei `https_mode="force"` über HTTP, Antwort 200 `{"status": "ok"}` oder 503
`{"status": "degraded"}` — der Fehlertext bleibt im Log, nicht im Netz. Wer TinySesam als Bibliothek
einbindet, baut denselben Check mit `auth.store.schreibprobe()`: Sie wirft die sqlite3-Ausnahme, wenn
kein Commit durchgeht. Ein `SELECT 1` genügt nicht — er gelingt auch auf einer nur lesbaren Datei.
Geschrieben wird höchstens alle 5 s (`Store.SCHREIBPROBE_SEK`, auch ein Commit einer Anmeldung
zählt), dazwischen prüft die Probe nur die Verbindung: `/healthz` ist ohne Anmeldung erreichbar, und
ein Commit je Aufruf liesse jeden, der ihn flutet, die Schreibsperre belegen. Eine gerade nur lesbar
gewordene Datenbank meldet der Check deshalb spätestens nach 5 s.

**Aufräumen.** Abgelaufene Sitzungen, Flows, Einmal-Token und alte Fehlversuche bleiben liegen, bis
jemand `auth.gc()` bzw. `tinysesam gc` aufruft (regelmässig, z.B. per Timer). Gelesen werden sie
nicht mehr — aber die Tabellen wachsen. Das Audit-Log räumt `gc` bewusst nicht ab (B5-11).

## Sitzungen verwalten

Eine Sitzung ist eine Zeile in `session`; im Cookie steht das Token, in der Datenbank nur dessen
sha256 (das **Handle**). Mit einem Handle lässt sich eine Sitzung benennen und beenden, aber nicht
übernehmen.

| Wer | Was | Wie |
|---|---|---|
| Nutzer | eigene Sitzungen ansehen | `GET /auth/sessions` (Anlage, IP, Methode, Browser, „diese hier") |
| Nutzer | andere eigene Sitzungen beenden | `POST /auth/sessions/revoke` mit `{"scope": "others"}` — API-Keys bleiben, die Antwort nennt ihre Zahl |
| Nutzer | alles beenden (Panik-Taste) | `{"scope": "all"}` — beendet auch die aktuelle Sitzung **und widerruft alle API-Keys** |
| Admin | alle Sitzungen sehen | Panel bzw. `GET <admin_path>/api/sessions` (`full` ist das Handle) |
| Admin | eine / alle eines Kontos beenden | `POST <admin_path>/api/sessions/revoke` mit `{"token": <Handle>}` oder `{"user_id": …}` |
| Admin | Konto sperren | `POST <admin_path>/api/users/{id}/disable` — beendet alle Sitzungen, widerruft API-Keys und verwirft offene Einmal-Token (Anmelde-, Bestätigungs-, Reset-Link). Die Sperre trägt den Betreiber-Vermerk: Auch ein Bestätigungslink, der erst danach entsteht, hebt sie nicht auf — nur „Entsperren" im Panel (H-18). Sperren aus Fassungen bis 0.19.x hebt die Migration auf Schema 10 auf den Vermerk und verwirft dabei ihre offenen Token, sofern das Audit-Log die Sperre noch kennt — auch eine, die eine ältere Fassung nach einem Rückschritt auf eine Schema-10-Datei gesetzt hat: Jeder Start liest die Audit-Zeilen seit dem letzten Start nach (Setting `panel_sperren_bis`) und warnt im Log, wenn er fündig wird; eine ältere (schon weggeräumte Zeile, `audit_retention_days`) sperrt derselbe Aufruf mit `{"disabled": true}` erneut, ohne zu entsperren — das Panel bietet für ein gesperrtes Konto nur „Entsperren" an. |
| Code | dasselbe ohne HTTP | `auth.store.list_sessions(user_id)`, `delete_session_by_handle(handle)`, `delete_user_sessions(user_id)`, `delete_user_sessions_except(user_id, handle)`; sperren mit dem Vermerk des Panels: `set_disabled(user_id, True, durch_betreiber=True)` — ohne den Vermerk ist es die Sperre einer ausstehenden Bestätigung, die der Bestätigungslink aufhebt. Sitzungen, Keys und Token räumt das nicht mit ab (`delete_user_sessions`, `revoke_user_api_keys`, `revoke_user_magic_tokens`) |

Was eine Sitzung **von selbst** beendet: Inaktivität (`session_idle_minutes`, Vorgabe 8 h — für
jede Sitzung, bei der „Angemeldet bleiben" nicht **ausdrücklich** angehakt wurde, auch eine
dauerhafte aus OIDC oder einem Anmelde-Link; `session_idle_minutes_remember`, Vorgabe aus), ein Nein des Identity Providers
bei der Nachprüfung (4a, OIDC) und ihr Ablauf (`session_ttl_hours`, Vorgabe 7 Tage mit
„Angemeldet bleiben", sonst `session_ttl_transient_hours`), die eigene Passwortänderung (alle
anderen Sitzungen), ein Passwort-Reset per Link (alle), ein Admin-Reset des Passworts, die Sperre
des Kontos. Eine Sitzung, deren Konto gesperrt ist, öffnet nichts mehr, auch wenn sie noch nicht
abgelaufen ist — und kein Anmeldeweg legt einem gesperrten Konto eine neue an (H-18).

Ein **Step-up** (Reauth, erneuter Faktor) gibt der Sitzung ein neues Token (F-06). Das alte gilt
noch `session_rotation_grace_sec` (Vorgabe 10) Sekunden weiter, damit eine Anfrage aus einem zweiten
Tab, die in dem Moment schon unterwegs war, nicht scheitert (A-6) — ohne Step-up-Frische (keine
Sudo-Route), nicht als eigene Sitzung in der Liste, und es endet mit der neuen. `0` = sofort tot.

Was sie **nicht** beendet — bewusst benannt, weil man es erwartet:

- **Mit „Angemeldet bleiben" kein Inaktivitäts-Timeout** (Vorgabe von
  `session_idle_minutes_remember`): Die Sitzung lebt bis zu ihrem absoluten Ablauf, auch unbenutzt.
- **Der Identity Provider ohne Refresh-Token.** Gibt er keine aus, bleibt die Sitzung nach einer
  Sperre dort bis zum Ablauf gültig (4a greift nicht). Die Nachprüfung je Anwendung
  (`oidc_revalidate_minutes`, nur mit mehreren Clients) begrenzt das für Forward-Auth; sonst ist
  der Weg: im Panel sperren oder die Sitzungen des Kontos beenden.
- **API-Keys** hängen an keiner Sitzung: „andere beenden" lässt sie stehen, „alles beenden", die
  Sperre und der Admin-Reset widerrufen sie — **ein Nein des Identity Providers (4a) nicht**.
- **Step-up** ist eine Frist an der Sitzung (`stepup_max_age_sec`, Vorgabe 15 min), keine eigene
  Sitzung: Sie verfällt, die Sitzung bleibt.

## Benutzername und Adresse ändern (Selbstbedienung)

Seit 2026-09-25 ändert jeder beides selbst auf der Konto-Seite, mit frischem Step-up. Alles, was am
Konto hängt — Sitzungen, Keys, Faktoren, Rollen, Bindungen an OIDC/LDAP/SAML —, hängt an der
**Konto-ID** und bleibt. Nach aussen ändert sich `Remote-User` bzw. `Remote-Email`; stabil ist
**`Remote-Id`** — eine App ordnet Nutzer darüber zu.

| | Regel |
|---|---|
| Benutzername | frei in Namen UND Adressen; keine Steuerzeichen, höchstens 150 Zeichen; kein `@`, ausser der eigenen bestätigten Adresse; kein Name aus `admin_identifiers` (dieselbe Antwort wie „vergeben"); im Modus `login_identifier="email"` nicht selbst änderbar — der Name folgt der Adresse. Schalter `self_service_username_change` |
| Adresse | Link an die NEUE (`email_change_ttl_min`, Vorgabe 60); erst der Klick macht sie zur Adresse des Kontos, mit Beleg. Eine vergebene Adresse bekommt keinen Link, die Antwort ist dieselbe (kein Orakel). Eine Adresse aus `admin_identifiers` bekommt ebenso keinen Link — sonst trüge ein fremdes Konto nach einem gutgläubigen Klick des Inhabers die belegte Allowlist-Adresse und wäre Erst-Admin. Beim Klick wird beides noch einmal geprüft (409). Danach: offene Links an die alte Adresse ungültig, Hinweis an die alte (ASVS 6.3.7). Braucht einen Mailer. Schalter `self_service_email_change` |

Ereignisse: `username_changed`, `email_changed` (`on_security_event`), Audit-Zeilen
`username_changed`, `email_change_requested`, `email_change_taken`, `email_change_reserved`
(Allowlist-Adresse), `email_changed`, `federation_email_confirm` (Link an eine Adresse aus
LDAP/SAML). Die Links
eines Wechsels haben ein eigenes Kontingent je Zieladresse (Topf `wechsel`) — Anträge Fremder auf
eine Adresse verbrauchen nicht das des Anmelde-Links. Derselbe Weg bestätigt Adressen aus LDAP und
SAML (Tabelle unter „Föderierte Identitäten verwalten").

## Owner

Owner sind Admins, die sich nicht löschen, sperren oder entmachten lassen. Es gibt immer mindestens
einen; die Rolle lässt sich weitergeben, mehrere können Owner sein. Nur ein Owner vergibt sie, und
nur ein Owner ändert ein Owner-Konto (Passwort, API-Keys, Passkeys, Sitzungen, Sperre, Rollen) — sonst setzte
ein Admin dem Owner ein Passwort und wäre selbst einer.

| Was | Wie |
|---|---|
| Owner vergeben / abgeben | Panel „Zum Owner machen" / „Owner abgeben" bzw. `POST <admin_path>/api/users/{id}/owner` `{"owner": true|false}` — nur als Owner; abgeben nur, wenn ein anderer bleibt |
| Code | `auth.set_owner(uid, True|False)` (`StateError` beim letzten Owner, `ConfigError` bei Service-/gesperrtem Konto) |
| Härtungswerte (Sperrschwellen, Rate-Limits, Passwortlängen, PIN-Versuche) | speichert nur ein Owner (`POST <admin_path>/api/security`, sonst 403); lesen darf jeder Admin. Ohne Owner im Bestand wie bisher jeder Admin |
| Notweg (kein Owner kommt mehr heran) | `tinysesam owner --db <datei> <benutzer>` — wer die Datenbank hat, betreibt die Instanz ohnehin |
| Erster Owner | der erste Admin (`/auth/claim-admin`, `admin_identifiers`, `ensure_admin`); im Bestand der älteste **aktive**, von Hand gesetzte Admin — kein Service-Konto, nicht gesperrt (`owner_grant` im Audit-Log). Gibt es keinen (nur Admins vom Identity Provider oder gesperrte), bleibt die Instanz ohne Owner und das Log nennt den Notweg |

Ein Owner ist immer ein Admin „von Hand" (`is_admin=1`): Kein Identity Provider nimmt ihm das Recht (H-5).

## Schlüssel der TOTP-Geheimnisse

TOTP-Geheimnisse liegen AES-256-GCM-verschlüsselt in der Datenbank (H-14/H-15, Pflicht). Der
Schlüssel (32 Byte, Base64) kommt aus `TINYSESAM_SECRETS_KEY`, sonst aus `secrets_key_file`, sonst
aus `<db_path>.key` (beim ersten Start angelegt, 0600, mit Warnung im Log; atomar, auch wenn
mehrere Worker gleichzeitig zum ersten Mal starten).

- **Getrennt sichern.** Ohne den Schlüssel sind alle TOTP-Einrichtungen verloren; die Datenbank
  allein nützt dafür nichts — und genau das ist der Zweck. `tinysesam backup` erinnert daran.
- **Neben der Datenbank** schützt er gegen eine Datenbankdatei, die allein abfliesst, nicht gegen
  eine Sicherung des ganzen Verzeichnisses. Für echte Trennung über die Umgebung oder eine Datei an
  einem anderen Ort (Docker-Secret).
- **Falscher Schlüssel** → der Start bricht ab (`ConfigError`), statt jede TOTP-Anmeldung still
  scheitern zu lassen — geprüft an TOTP-Geheimnissen und Refresh-Tokens, also auch auf einer
  Instanz ohne TOTP. Gelöschtes überschreibt SQLite (`secure_delete`), damit ein ersetzter
  Klartext nicht in freien Seiten der Datei bleibt. Einen Schlüsselwechsel (Rotation) gibt es noch nicht.
- Ebenfalls mit diesem Schlüssel: die Refresh-Tokens der OIDC-Sitzungen (unten).

## Föderierte Identitäten verwalten

Eine fremde Identität wird an ein lokales Konto **gebunden** — über eine Kennung, die der fremden
Seite gehört und sich nicht ändert:

| Quelle | Gebunden über | Tabelle |
|---|---|---|
| OIDC | `iss` + `sub` | `oidc_identity` |
| LDAP | `objectGUID` / `entryUUID` (`_stabile_kennung`) | `federated_identity` (`quelle="ldap"`) |
| SAML | `NameID` | `federated_identity` (`quelle="saml"`) |

- **Erste Anmeldung**: Gibt es noch keine Bindung, wird das Konto über den Namen gesucht bzw. mit
  `*_auto_create` angelegt und dann gebunden. Bestandskonten aus der Zeit vor den Bindungen binden
  sich beim nächsten Login selbst nach (F-11).
- **Ein Konto trägt je Quelle genau eine Kennung.** Taucht im Verzeichnis unter demselben Namen eine
  neue Kennung auf (Konto gelöscht und neu angelegt), wird das lokale Konto **nicht** übernommen.
- **Umzug im Verzeichnis** (die alte Kennung ist wirklich tot): `auth.loese_fremde_bindung(quelle,
  user_id)` löst die Bindung für LDAP/SAML; die nächste Anmeldung bindet neu. Der Vorgang steht im
  Audit-Log (`<quelle>_kennung_geloest`). Für OIDC gibt es keinen eigenen Aufruf — dort ist die
  Kennung `sub` des Providers per Definition stabil.
- **Freigaben je Anwendung** (mehrere OIDC-Clients): `auth.store.drop_oidc_grants_for_user(user_id,
  client=None)` entzieht sie sofort, ohne die Sitzung zu beenden — der Weg, wenn der Provider
  jemanden von einer Anwendung ausgeschlossen hat.
- **Gruppen aus dem Provider** (`apply_idp_groups`) werden bei jeder Anmeldung übernommen und
  entzogen, wenn sie beim Provider wegfallen — gemappte Rollen seit jeher, seit H-5 auch das
  Admin-Flag, **sofern der Provider es vergeben hat** (`users.is_admin=2`). Ein Admin aus Panel,
  CLI, `admin_identifiers` oder `/auth/claim-admin` bleibt, ein Owner ohnehin.
- **Widerruf folgt dem Provider (4a).** Eine OIDC-Sitzung trägt ihr Refresh-Token (verschlüsselt);
  alle `oidc_session_refresh_minutes` (Vorgabe 15) stösst die nächste Anfrage den Tausch an — je
  Client eine Zeile, im Hintergrund (die Anfrage wartet nicht auf den Provider; das Ergebnis gilt
  ab der Anfrage danach), und von vielen parallelen Anfragen tauscht genau eine. Gesperrte Konten
  fragt niemand nach. Verweigert der Provider, endet die Sitzung (`oidc_widerruf`), und die
  API-Keys des Kontos **ruhen** (unten); frische Gruppen werden neu bewertet (ein Gruppen-
  Claim, der ganz fehlt, ändert nichts). Nicht erreichbar → Sitzung bleibt, neuer Versuch nach einer
  Minute. **Voraussetzung:** Der Provider gibt Refresh-Tokens aus (bei manchen nur mit Scope
  `offline_access`, dann `oidc_scopes` ergänzen). Gibt er keine, bleibt es beim Stand davor: Die
  Sitzung läuft bis `session_ttl_hours`. **Obergrenze ohne Ja:** Hat der Provider eine Sitzung
  `oidc_session_max_unverified_hours` lang (Vorgabe 25) nicht bestätigt — dauerhafter Fehler des
  Clients, Provider weg —, endet sie (`oidc_unbestaetigt` im Audit-Log). Das ist kein Nein des
  Providers: Die API-Keys ruhen dadurch nicht. Preis: Ist der Provider länger als die Grenze weg,
  sind danach alle OIDC-Sitzungen abgemeldet. `0` = keine Grenze.
- **API-Keys folgen dem Provider (Fund 8).** Für Konten mit OIDC-Bindung gilt ein Key nur, solange
  der Provider das Konto trägt: Sagt er bei 4a Nein (auch: aus der erlaubten Gruppe genommen),
  ruhen die Keys sofort (`api_keys_ruhen` im Audit-Log, Abweisung `idp_nein`). Und ohne Bestätigung
  binnen `oidc_apikey_confirm_days` (Vorgabe 30; Login über den Provider oder Refresh-Tausch mit
  Ja) ruhen sie ebenfalls (`idp_unbestaetigt`) — so fällt auch jemand auf, der nur noch per Skript
  arbeitet und keine Sitzung hat, die 4a nachprüfen könnte. **Gelöscht wird nichts**: Ein
  `invalid_grant` unterscheidet nicht zwischen „gesperrt" und „abgelaufen" (RFC 6749 5.2) — die
  nächste Anmeldung über den Provider weckt die Keys. Reine Automatik gehört auf ein Service-Konto
  (keine OIDC-Bindung, nicht betroffen). Bestand: Die Frist beginnt mit dem Update. `0` schaltet nur
  die Frist ab, das Nein zählt weiter. Mit Keycloak beachten: Läuft dort die SSO-Sitzung per
  Leerlauf ab, antwortet der Refresh ebenfalls `invalid_grant` — dann endet auch die
  TinySesam-Sitzung, und die Keys ruhen bis zum nächsten Login. **Ein Fehler des Clients ist kein
  Nein**: `invalid_client` (nach einer Secret-Rotation), `unauthorized_client`,
  `unsupported_grant_type`, jede 401 und jede 5xx zählen wie ein nicht erreichbarer Provider und
  stehen als Warnung im Sicherheits-Log; jede andere 4xx ist ein Nein. Wird eine Anwendung aus
  `oidc_clients` genommen oder beim Provider neu angelegt (andere `client_id`), verwirft 4a ihre
  Zeilen — die Sitzungen laufen dann bis zu ihrem Ablauf, ohne Nachprüfung.
- **Serien-Sperre (B2-6) und LDAP-Umbenennung:** Gezählt wird unter dem eingetippten Namen.
  Heisst ein Konto im Verzeichnis inzwischen anders als lokal (gebunden über die stabile Kennung),
  räumen die Rückwege nur den lokalen Namen und die Adresse — eine Serie unter dem neuen
  Verzeichnisnamen hebt `tinysesam unlock <name wie eingetippt>` auf (die Logzeile nennt ihn).
- **`admin_identifiers` nach einem IdP-Entzug (H-5):** Entzieht der Provider dem letzten Admin das
  Flag und steht dessen belegte Adresse in `admin_identifiers`, befördert der Erst-Admin-Weg ihn im
  selben Login wieder — dann mit dem Vermerk „von Hand" (1). Das ist die Allowlist, wie der Betreiber
  sie eingetragen hat; wer den Entzug will, nimmt die Adresse aus der Liste.
- **Adressen ohne Beleg** (OIDC ohne `email_verified=true`) werden nicht verwendet: kein Kontoname,
  keine Adresse im Konto, kein `Remote-Email` (H-3). Liefert der Provider den Beleg später, wird sie
  nachgetragen, wenn sie frei ist. Für einen Provider, der den Claim nie schickt, aber jede Adresse
  prüft: `oidc_email_verified_default=True`.
- **SAML und LDAP liefern keinen Beleg** — der Betreiber sagt je Quelle, ob er ihren Adressen traut
  (PO-Entscheide 2026-09-24 und 2026-09-25):

  | Schalter | Vorgabe | vertraut | nicht vertraut |
  |---|---|---|---|
  | `ldap_email_trusted` | **aus** | Adresse gilt als belegt: ins Konto, als `Remote-Email`, trägt Rechte bis zum Erst-Admin über `admin_identifiers` | Adresse nicht direkt verwendet (wie H-3); Bestätigung per Link (unten) |
  | `saml_email_trusted` | **aus** | wie oben | wie oben; dazu weicht ein Kontoname mit `@` (NameID emailAddress, UPN) einem Ersatznamen `saml-<hash>` |

  Drei Wege zum Vertrauen, vom schwächsten zum stärksten Anspruch an die Quelle:

  1. **Bestätigung per Link — der Normalweg**, sobald Mail eingerichtet ist
     (`federation_email_confirm`, Vorgabe an; braucht Mailer und `base_url`). Nach der Anmeldung
     geht ein Link an die Adresse aus der Quelle; erst der Klick macht sie zur Adresse des Kontos,
     mit Beleg. Derselbe Weg wie beim Adresswechsel der Selbstbedienung. Nur für Konten ohne
     belegte Adresse, höchstens einer je Konto und Tag, keiner, solange einer offen ist. Gehört die
     Adresse schon einem anderen Konto, geht kein Link hinaus (Audit `email_change_taken`).
  2. **Beleg-Attribut** für IdPs, die es führen: `ldap_attr_email_verified` bzw.
     `saml_attr_email_verified` nennt ein Attribut, dessen wahrer Wert (`true`, `1`, `yes`) die
     Adresse DIESES Logins belegt — z. B. ein Keycloak-Mapper auf `emailVerified`. Nur tragfähig,
     wenn Nutzer das Attribut nicht selbst setzen können.
  3. **Pauschaler Schalter** für gepflegte Quellen: `ldap_email_trusted=True` für ein Verzeichnis,
     in dem niemand sein `mail`-Attribut selbst ändert; `saml_email_trusted=True` für einen
     Firmen-IdP ohne Selbstregistrierung. Wer ihn setzt, wo Nutzer ihre Adresse selbst pflegen,
     öffnet F-14 wieder: Jemand trägt sich die Adresse aus `admin_identifiers` ein und ist beim
     ersten Login Erst-Admin.

  Vertraut belegt ein Login dieselbe Adresse, die schon am Konto steht, nur nach oben; ein Konto
  ohne Adresse bekommt sie, wenn sie frei ist. Ein neuer Wert in der Quelle ändert die Adresse
  eines bestehenden Kontos nicht — das tut der Inhaber selbst über die Konto-Seite.
  Bei nicht vertrauter Quelle wird ein unbelegter Name **nie über den Namen** einem vorhandenen
  Konto zugeordnet — nur über die stabile Kennung, sonst abgewiesen. Unbelegt: bei SAML ein Name
  mit `@` (NameID emailAddress) oder einer aus dem Adress-Attribut selbst (`saml_attr_username` =
  `saml_attr_email`); bei LDAP eine Eingabe, die dem `mail`-Wert des gefundenen Eintrags gleicht
  (ein Filter wie `(|(uid={username})(mail={username}))`, auch mit `mail=chefin` ohne `@`). Ein UPN
  als Bind-Kennung bleibt Kontoname. Neue Konten heissen dann `saml-…` bzw. `ldap-…`. Wer diese
  Namen nicht will und dem IdP traut, setzt den Schalter. Eine Kennung mit Rand-Leerraum oder
  Steuerzeichen weist TinySesam ab, statt sie zu trimmen (sie fiele sonst auf eine fremde Bindung).
- **Erst-Admin**: Eine föderierte Adresse macht nur mit Beleg zum Admin (`email_verified` bei OIDC;
  bei SAML/LDAP der Schalter oben). Der sichere Weg ist `/auth/claim-admin` (F-14).

## Anmeldewege und ihre Stärke

**In der Vorgabe ist TinySesam einfaktorig:** Passwort allein meldet vollständig an. Ein zweiter
Faktor gilt erst, wenn der Nutzer TOTP einrichtet (dann wird es bei jedem Login verlangt) oder der
Betreiber eine Kette erzwingt (`login_chain=["password", "totp"]`, `login_chain_strict=True`).

Ohne Kette gilt die **klassische Policy**: ein identifizierender Faktor, dazu TOTP, *falls* das
Konto eines hat. Daraus folgen unterschiedlich starke Wege zum selben Konto:

| Weg (Faktor) | Was er belegt | TOTP danach (ohne Kette) | Anmerkung |
|---|---|---|---|
| Passwort (`password`) | Wissen | ja, wenn eingerichtet | auch LDAP läuft als `password` |
| PIN (`pin`, mit `pin_login`) | Wissen (kurz) | ja, wenn eingerichtet | schwächer als ein Passwort, als Erstfaktor bewusst erlaubt (ADR-8); Sperre über `pin_max_attempts` und die Serie (`account_max_consecutive_failures`) |
| Passkey (`passkey`) | Besitz + Nutzerprüfung (`passkey_user_verification="required"`) | **nein** — gilt allein als vollwertig | stärkster Weg, wenn UV erzwungen ist (B2-10) |
| Anmelde-Link (`magic`) | Zugriff aufs Postfach | ja, wenn eingerichtet — ebenso ein Passkey, und das auch in einer Kette wie `["magic"]` (`magiclink_require_second_factor`, Vorgabe an) | ohne zweiten Faktor ist das Postfach der einzige Faktor (ASVS 6.3.6) |
| OIDC (`oidc`) / SAML (`saml`) | was der Provider geprüft hat | ja, wenn lokal eingerichtet | TinySesam sieht nicht, ob der Provider MFA verlangt hat |
| Passwort-Reset per Link | Postfach → neues Passwort | ja, beim anschliessenden Login | beendet alle Sitzungen, meldet selbst nicht an |
| Recovery-Code | Ersatz für TOTP, einmalig | — | nur im TOTP-Schritt |
| API-Key | Besitz des Schlüssels | nie (kein interaktiver Faktor) | trägt als Automaten-Key kein Admin-Flag, erreicht keine Step-up-Route (R6-5, R3-3) |

**Die Stärke eines Kontos ist die seines schwächsten eingeschalteten Wegs.** Ein Konto mit TOTP oder
Passkey ist über den Anmelde-Link genauso gut geschützt wie über das Passwort — ohne zweiten Faktor
ist der Anmelde-Link so stark wie das Postfach. Eine Route-Kette `require(factors=["magic"])` prüft
nur ihre eigene Liste; sie verlangt den zweiten Faktor nicht. Wer das angleichen will, erzwingt eine Kette oder schaltet schwache
Wege ab. ASVS 6.3.4 („alle Wege gleich stark") erfüllt die Vorgabe damit **nicht**; eine Kette
tut es.

## Was für ASVS Level 3 fehlt

TinySesam zielt auf Level 2. Vier Anforderungen aus V6.3 (ASVS 5.0) gehören zu Level 3 (B1-12). Seit
2026-09-24 sind drei davon erfüllt (6.3.5, 6.3.7, 6.3.8 mit Bestätigung), 6.3.6 für Konten mit
zweitem Faktor:

| ASVS | Anforderung | Stand |
|---|---|---|
| 6.3.5 | Nutzer über verdächtige Anmeldeversuche benachrichtigen | erfüllt, sobald Versand konfiguriert ist: Greift eine Konto-Sperre (Fenster oder Serie), geht ein Hinweis an die belegte Adresse — höchstens einer je Sperrfenster, ohne Link (`notify_login_failures`, Vorgabe an). Nachgeschlagen und verschickt im Hintergrund, die Antwort verrät weder Existenz noch Laufzeit |
| 6.3.6 | E-Mail weder als alleiniger noch als zweiter Faktor | teilweise (PO-Entscheid 2026-09-24, Option C): Hat ein Konto TOTP oder Passkey, verlangt die Anmeldung über den Anmelde-Link ihn zusätzlich (`magiclink_require_second_factor`, Vorgabe an; `False` = der Link genügt). Konten ohne zweiten Faktor meldet der Link weiter allein an — dort ist das Postfach der einzige Faktor. Streng erfüllt nur ohne `magiclink_enabled` |
| 6.3.7 | Nutzer nach Änderung ihrer Anmeldedaten benachrichtigen | erfüllt über den Opt-in-Hook `on_security_event` (H-6): Er läuft, sobald ein Anmeldefaktor angelegt, geändert, entfernt oder verbraucht wird (Passwort samt Reset, PIN, TOTP, Wiederherstellungscodes, Passkey), auch wenn ein Admin im Panel eingreift, und seit 2026-09-24 auch beim Widerruf von API-Keys (`api_key_revoked`, gesammelt `api_keys_revoked`). Die Mail verschickt der Hook (s. SECURITY.md). Ohne Hook wird nur protokolliert. Adresse oder Benutzername ändern lässt TinySesam niemanden über eine Oberfläche; `store.set_email` ist ein Werkzeug für den Betreiber und löst den Hook nicht aus |
| 6.3.8 | Gültige Konten nicht aus Fehlschlägen ableitbar | erfüllt mit `signup_verify_email=True`: gleiche Antwort und Rechenzeit am Login (`dummy_verify`) und an der Registrierung (dieselbe Arbeit in beiden Zweigen, 2026-09-24). Ohne Bestätigung verrät die Registrierung vergebene Adressen zwangsläufig (sofortige Anmeldung vs. 409) — die Konfigurationsprüfung warnt |
