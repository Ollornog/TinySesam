# Betrieb — was TinySesam tut, wenn etwas ausfällt

Diese Seite ist für den Betreiber: Was passiert, wenn ein Teil wegbricht, wie man Sitzungen und
fremde Identitäten verwaltet, und wie stark die einzelnen Anmeldewege wirklich sind. Die READMEs
zeigen, wie man TinySesam einbaut; hier steht, womit man danach rechnen muss.

Jede Aussage hier ist am Code nachgestellt. Wo ein Verhalten eine bekannte Schwäche ist, steht die
Backlog-Kennung dabei ([T-13](../backlog/T-13-audit-2026-09-22-runde-3.md)).

## Ausfallverhalten

Grundregel: **Fällt eine Prüfinstanz aus, wird nicht angemeldet** (fail-closed). Zwei bewusste
Ausnahmen stehen unten ausdrücklich dabei (Redis, Sicherheits-Log): Dort fällt eine *Bremse* oder
ein *Protokoll* weg, nicht die Prüfung selbst.

| Was fällt aus | Was der Nutzer sieht | Was der Betreiber sieht |
|---|---|---|
| **Datenbank nur lesbar** (Read-only-Mount, Rechte nach einem Rückspielen) | Anmeldung scheitert mit 500, sobald eine Sitzung geschrieben wird. Bestehende Sitzungen lesen weiter. | Gateway: `/healthz` → **503** `degraded` (Schreibprobe, B6-4). Log: `Healthcheck: Datenbank nicht beschreibbar`. |
| **Datenbank-Volume voll** | wie oben, sobald SQLite neuen Platz braucht | `/healthz` → 503, **wenn** die Schreibprobe Platz braucht. Eine Probe, die in schon belegte Seiten schreibt, sieht einen fast vollen Datenträger nicht — Plattenplatz gehört zusätzlich in die Überwachung des Hosts. |
| **Datenbank gesperrt** (zweiter Schreiber: weiterer Worker, `tinysesam` auf der Kommandozeile, Sicherung) | Die Anfrage wartet bis zu **10 s** (`Store.BUSY_TIMEOUT_MS`, B6-11), dann 500 (`database is locked`). Die nächste Anfrage läuft normal: Ein gescheiterter Schreibzugriff rollt zurück und lässt keine Transaktion offen. | die 500 steht im Log des ASGI-Servers. `/healthz` wartet ebenso und meldet erst nach 10 s 503 — der HEALTHCHECK des Abbilds wartet deshalb 12 s. Bis zur Integration von T-13 hinterliess ein solcher Fehlschlag (auch der Schreibprobe von `/healthz`) eine offene Transaktion, und jede folgende Anmeldung endete mit 500, bis zufällig ein anderer Schreibzugriff committete. Findet der Anmeldeweg trotzdem eine vor, verwirft er sie und schreibt `Offene Transaktion … verworfen` ins Log — das ist dann ein Fehler an anderer Stelle. |
| **Redis** (`redis_url`) nicht erreichbar | nichts: Anmeldungen gehen weiter | **fail-open** — die Drossel (`rate_ok`) lässt durch, je Anfrage eine Warnzeile `redis rate-limit fail-open`. Die Kontosperre (`is_locked`, in der Datenbank) greift weiter. Bekannte Lücken: B6-1, B6-2. Ist Redis schon beim Start weg: `Redis-Rate-Limit nicht verfügbar → In-Memory-Fallback`. |
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
| Admin | Konto sperren | `POST <admin_path>/api/users/{id}/disable` — beendet alle Sitzungen, widerruft API-Keys und verwirft offene Einmal-Token (Anmelde-, Bestätigungs-, Reset-Link). Die Sperre trägt den Betreiber-Vermerk: Auch ein Bestätigungslink, der erst danach entsteht, hebt sie nicht auf — nur „Entsperren" im Panel (H-18). Sperren aus Fassungen bis 0.19.x hebt die Migration auf Schema 10 auf den Vermerk und verwirft dabei ihre offenen Token, sofern das Audit-Log die Sperre noch kennt; eine ältere (schon weggeräumte Zeile, `audit_retention_days`) sperrt derselbe Aufruf mit `{"disabled": true}` erneut, ohne zu entsperren — das Panel bietet für ein gesperrtes Konto nur „Entsperren" an. |
| Code | dasselbe ohne HTTP | `auth.store.list_sessions(user_id)`, `delete_session_by_handle(handle)`, `delete_user_sessions(user_id)`, `delete_user_sessions_except(user_id, handle)`; sperren mit dem Vermerk des Panels: `set_disabled(user_id, True, durch_betreiber=True)` — ohne den Vermerk ist es die Sperre einer ausstehenden Bestätigung, die der Bestätigungslink aufhebt. Sitzungen, Keys und Token räumt das nicht mit ab (`delete_user_sessions`, `revoke_user_api_keys`, `revoke_user_magic_tokens`) |

Was eine Sitzung **von selbst** beendet: ihr Ablauf (`session_ttl_hours`, Vorgabe 7 Tage mit
„Angemeldet bleiben", sonst `session_ttl_transient_hours`), die eigene Passwortänderung (alle
anderen Sitzungen), ein Passwort-Reset per Link (alle), ein Admin-Reset des Passworts, die Sperre
des Kontos. Eine Sitzung, deren Konto gesperrt ist, öffnet nichts mehr, auch wenn sie noch nicht
abgelaufen ist — und kein Anmeldeweg legt einem gesperrten Konto eine neue an (H-18).

Was sie **nicht** beendet — bewusst benannt, weil man es erwartet:

- **Kein Inaktivitäts-Timeout.** Eine Sitzung lebt bis zu ihrem absoluten Ablauf, auch unbenutzt (F-05).
- **Der Identity Provider.** Wird ein Nutzer dort gelöscht, gesperrt oder aus der Gruppe genommen,
  bleibt seine TinySesam-Sitzung bis zum Ablauf gültig. Die Nachprüfung je Anwendung
  (`oidc_revalidate_minutes`, nur mit mehreren Clients) begrenzt das für Forward-Auth; sonst ist
  der Weg: im Panel sperren oder die Sitzungen des Kontos beenden.
- **API-Keys** hängen an keiner Sitzung: „andere beenden" lässt sie stehen, „alles beenden", die
  Sperre und der Admin-Reset widerrufen sie.
- **Step-up** ist eine Frist an der Sitzung (`stepup_max_age_sec`, Vorgabe 15 min), keine eigene
  Sitzung: Sie verfällt, die Sitzung bleibt.

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
- **Gruppen aus dem Provider** (`apply_idp_groups`) werden bei jeder Anmeldung übernommen, aber
  nicht entzogen, wenn sie beim Provider wegfallen (H-5).
- **Erst-Admin**: Eine föderierte Adresse macht nur mit Beleg zum Admin (`email_verified` bei OIDC;
  SAML und LDAP liefern keinen). Der sichere Weg ist `/auth/claim-admin` (F-14).

## Anmeldewege und ihre Stärke

**In der Vorgabe ist TinySesam einfaktorig:** Passwort allein meldet vollständig an. Ein zweiter
Faktor gilt erst, wenn der Nutzer TOTP einrichtet (dann wird es bei jedem Login verlangt) oder der
Betreiber eine Kette erzwingt (`login_chain=["password", "totp"]`, `login_chain_strict=True`).

Ohne Kette gilt die **klassische Policy**: ein identifizierender Faktor, dazu TOTP, *falls* das
Konto eines hat. Daraus folgen unterschiedlich starke Wege zum selben Konto:

| Weg (Faktor) | Was er belegt | TOTP danach (ohne Kette) | Anmerkung |
|---|---|---|---|
| Passwort (`password`) | Wissen | ja, wenn eingerichtet | auch LDAP läuft als `password` |
| PIN (`pin`, mit `pin_login`) | Wissen (kurz) | ja, wenn eingerichtet | schwächer als ein Passwort; Sperre über `pin_max_attempts` |
| Passkey (`passkey`) | Besitz + Nutzerprüfung (`passkey_user_verification="required"`) | **nein** — gilt allein als vollwertig | stärkster Weg, wenn UV erzwungen ist (B2-10) |
| Anmelde-Link (`magic`) | Zugriff aufs Postfach | ja, wenn eingerichtet | ohne TOTP ist das Postfach der einzige Faktor (ASVS 6.3.6) |
| OIDC (`oidc`) / SAML (`saml`) | was der Provider geprüft hat | ja, wenn lokal eingerichtet | TinySesam sieht nicht, ob der Provider MFA verlangt hat |
| Passwort-Reset per Link | Postfach → neues Passwort | ja, beim anschliessenden Login | beendet alle Sitzungen, meldet selbst nicht an |
| Recovery-Code | Ersatz für TOTP, einmalig | — | nur im TOTP-Schritt |
| API-Key | Besitz des Schlüssels | nie (kein interaktiver Faktor) | trägt als Automaten-Key kein Admin-Flag, erreicht keine Step-up-Route (R6-5, R3-3) |

**Die Stärke eines Kontos ist die seines schwächsten eingeschalteten Wegs.** Ein Konto mit TOTP ist
über den Anmelde-Link genauso gut geschützt wie über das Passwort — ohne TOTP ist der Anmelde-Link
so stark wie das Postfach. Wer das angleichen will, erzwingt eine Kette oder schaltet schwache
Wege ab. ASVS 6.3.4 („alle Wege gleich stark") erfüllt die Vorgabe damit **nicht**; eine Kette
tut es.

## Was für ASVS Level 3 fehlt

TinySesam zielt auf Level 2. Vier Anforderungen aus V6.3 (ASVS 5.0) gehören zu Level 3 (B1-12). Drei
davon sind offen oder nur teilweise erfüllt. 6.3.7 erfüllt der Hook `on_security_event`, sobald die
App ihn setzt:

| ASVS | Anforderung | Stand |
|---|---|---|
| 6.3.5 | Nutzer über verdächtige Anmeldeversuche benachrichtigen | fehlt — Fehlversuche stehen im Audit- und Sicherheits-Log, der Nutzer erfährt nichts. `on_security_event` meldet Faktorwechsel, keine Fehlversuche |
| 6.3.6 | E-Mail weder als alleiniger noch als zweiter Faktor | nicht erfüllt, sobald `magiclink_enabled` ohne erzwungene Kette läuft (s. Tabelle oben); abschaltbar |
| 6.3.7 | Nutzer nach Änderung ihrer Anmeldedaten benachrichtigen | erfüllt über den Opt-in-Hook `on_security_event` (H-6): Er läuft, sobald ein Anmeldefaktor angelegt, geändert, entfernt oder verbraucht wird (Passwort samt Reset, PIN, TOTP, Wiederherstellungscodes, Passkey, API-Key), auch wenn ein Admin im Panel eingreift. Die Mail verschickt der Hook, TinySesam selbst verschickt nichts (s. SECURITY.md). Ohne Hook wird nur protokolliert. Adresse oder Benutzername ändern lässt TinySesam niemanden über eine Oberfläche; `store.set_email` ist ein Werkzeug für den Betreiber und löst den Hook nicht aus |
| 6.3.8 | Gültige Konten nicht aus Fehlschlägen ableitbar | teilweise — gleiche Antwort und Rechenzeit am Login (`dummy_verify`), Registrierung verrät Kennungen noch (R4-03) |
