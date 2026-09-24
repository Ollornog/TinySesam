# Changelog

Alle nennenswerten Änderungen. Format lose nach [Keep a Changelog](https://keepachangelog.com/de/).

## [Unveröffentlicht]

**Die offenen T-13-Punkte, nach Entscheidung des Betreibers — dazu Owner, Inaktivitäts-Timeout,
verschlüsselte TOTP-Geheimnisse und der Widerruf über den Identity Provider.** Was beim Update
auffällt:

- **Neue Passwörter brauchen 15 Zeichen**, solange das Passwort allein anmelden kann (Vorgabe).
  Bestehende bleiben gültig.
- **Neue Pflichtabhängigkeit `cryptography`**; TOTP-Geheimnisse liegen jetzt verschlüsselt. Ohne
  `TINYSESAM_SECRETS_KEY`/`secrets_key_file` legt TinySesam `<db>.key` neben der Datenbank an —
  **diesen Schlüssel getrennt sichern**, ohne ihn müssen alle Konten TOTP neu einrichten.
- **Sitzungen ohne ausdrücklich gewähltes „Angemeldet bleiben" enden nach 8 Stunden Inaktivität**
  (`session_idle_minutes`) — auch OIDC- und Link-Sitzungen.
- **Es gibt Owner**: Der älteste aktive, von Hand gesetzte Admin wird beim ersten Start Owner.
- **Vor dem Update die Datenbank sichern** — Schema 11; 0.20.x öffnet sie danach mit Warnung.

### Hinzugefügt

- **Owner.** Owner sind Admins, die sich nicht löschen, sperren oder entmachten lassen; die Rolle
  lässt sich weitergeben, mehrere können Owner sein, es gibt immer mindestens einen. Nur ein Owner
  vergibt sie — und nur ein Owner ändert ein Owner-Konto (Passwort, Keys, Passkeys, Sitzungen,
  Sperre, Rollen); der Schutz gilt auch im Code (`set_disabled`, `delete_user`). **Die
  Härtungswerte im Panel speichert nur ein Owner** — sonst verschärfte ein Admin die Sperre und
  sperrte den Owner mit ein paar Fehlversuchen aus; lesen dürfen sie alle Admins, und ohne Owner
  (Bestand nur mit IdP-Admins) bleibt es wie bisher. Der erste Admin
  einer Instanz ist ihr erster Owner; im Bestand wird der älteste aktive, von Hand gesetzte Admin
  Owner (kein Service-Konto, nicht gesperrt; Zeile `owner_grant` im Audit-Log) — gibt es keinen,
  nennt das Log den Notweg. Ein Owner ist immer ein Admin „von Hand" — kein
  Identity Provider nimmt ihm das Recht (H-5). Notweg: `tinysesam owner --db … <name>`.
  Panel: Spalte und Knopf „Zum Owner machen / Owner abgeben". API: `auth.set_owner(uid, bool)`.
- **Inaktivitäts-Timeout (F-05, ASVS 7.3.1).** `session_idle_minutes` (Vorgabe 8 h) für jede
  Sitzung, bei der „Angemeldet bleiben" nicht ausdrücklich gewählt wurde (auch dauerhafte aus OIDC
  oder einem Anmelde-Link), `session_idle_minutes_remember` (Vorgabe aus) für die gewählten. Die letzte Anfrage
  steht an der Sitzung (`session.zuletzt`, höchstens einmal je Minute geschrieben).
- **Widerruf folgt dem Identity Provider (4a).** Das Refresh-Token einer OIDC-Sitzung liegt
  verschlüsselt an ihr, je Client eine Zeile; alle `oidc_session_refresh_minutes` (Vorgabe 15)
  stösst die nächste Anfrage den Tausch beim Provider an — im Hintergrund, ohne auf ihn zu warten,
  und von vielen parallelen Anfragen genau eine (Rotation). Gesperrte Konten fragt niemand nach. Verweigert er (gesperrt, gelöscht, entgruppt, der Anwendung entzogen),
  endet die Sitzung (`oidc_widerruf` im Audit-Log); Gruppen, erlaubte Gruppen und das vom Provider
  vergebene Admin-Flag werden neu bewertet — H-5 wirkt damit binnen Minuten. Ein nicht erreichbarer
  Provider meldet niemanden ab (neuer Versuch nach einer Minute). Braucht einen Provider, der
  Refresh-Tokens ausgibt.
- **Hinweis an den Inhaber, wenn sein Konto wegen Fehlversuchen gesperrt wird (ASVS 6.3.5).** Mit
  konfiguriertem Versand an die belegte Adresse, höchstens einer je Sperrfenster (gezählt im
  Audit-Log, also über alle Worker), ohne Link.
  Opt-out: `notify_login_failures=False`. Nachgeschlagen und verschickt wird im Hintergrund, über
  einen eigenen Postausgang — die Antwort verrät weder Existenz noch Laufzeit.
- **Sicherheitsereignisse für den Widerruf von API-Keys**: `api_key_revoked`, `api_keys_revoked`
  (Grenze e).

### Sicherheit

- **TOTP-Geheimnisse ruhend verschlüsselt, Pflicht (H-14/H-15).** AES-256-GCM (`cryptography`); der
  Schlüssel kommt aus `TINYSESAM_SECRETS_KEY`, `secrets_key_file` oder `<db>.key` (0600, neben der
  Datenbank — dann laut gewarnt). Bestand wird beim Start verschlüsselt; ein Schlüssel, der nicht
  passt, bricht den Start ab, statt jede TOTP-Anmeldung still scheitern zu lassen (geprüft auch an
  den Refresh-Tokens). Die Schlüsseldatei entsteht atomar, auch mit mehreren Workern. `tinysesam
  backup` erinnert daran, den Schlüssel getrennt zu sichern. SQLite überschreibt Gelöschtes
  (`secure_delete`), damit ersetzter Klartext nicht in freien Seiten der Datei bleibt.
- **Registrierung ohne Laufzeit-Orakel (ASVS 6.3.8).** Mit Bestätigung und Name = Adresse schrieb
  der Zweig „Adresse vergeben" nur eine Audit-Zeile, der freie Zweig Konto, Sperre und Token —
  messbar an der Antwortzeit. Jetzt dieselbe Arbeit (Platzhalter mit Zufallsnamen, von `gc()`
  geräumt). Ohne Bestätigung verrät die Registrierung vergebene Adressen zwangsläufig; die
  Konfigurationsprüfung warnt davor.
- **Eine vollständige Anmeldung räumt nur Fehlversuche ab der Kontoanlage** (Grenze a) — nicht die,
  die vorher unter demselben Namen oder derselben Adresse gezählt wurden.

- **Anmeldung gesperrt nach 100 Fehlversuchen in Folge (B2-6).** Die bisherigen Schwellen zählen nur
  im Fenster (`lockout_window_sec`) — wer langsamer rät als die Schwelle, riet beliebig lange. Jetzt
  verlängert jeder gescheiterte Anmeldeversuch unter einem Namen eine Serie; an der Grenze
  (`account_max_consecutive_failures`, Panel, 10…100000) ist die Anmeldung gesperrt, auch mit dem
  richtigen Passwort, und die Sperre **läuft nicht ab**. Sie endet mit einer vollständigen Anmeldung
  (auch über Passkey, Anmelde-Link oder OIDC), einem Passwort-Reset, einem neuen Passwort aus dem
  Panel oder `tinysesam unlock`. Gezählt wird je Name, ob es das Konto gibt oder nicht — die Meldung
  („Zu viele Fehlversuche in Folge …") verrät nichts. Ein Fehlgriff, der keine Anmeldung ist
  (Passwortwechsel, Step-up, Bereichs-PIN), zählt nicht. `gc()` räumt nicht ausgelöste Serien nach
  90 Tagen Ruhe, ausgelöste nie. Geprüft und vorgebucht wird die Serie **in derselben Transaktion**
  wie der Versuch (eine parallele Salve an der Grenze bekommt einen Versuch, nicht einen je Anfrage);
  ein richtiger erster Faktor nimmt nur seine eigene Vorbuchung zurück, ein Verzeichnis-Ausfall
  zählt nicht. Der **Selbstbedienungs-Reset räumt die Anteile der ersten Faktoren** (Passwort, PIN —
  die kann jeder erzeugen, auch ein Fremder ohne Geheimnis); **TOTP-Fehlgriffe bleiben stehen**
  (derselbe Grund wie R4-13: Das Postfach beweist den zweiten Faktor nicht, und TOTP-Fehlgriffe
  erzeugt nur, wer das Passwort schon hat). Der Betreiber räumt ganz: Passwort-Reset im Panel,
  `tinysesam unlock`.
- **Passwort-Mindestlänge 15, wenn das Passwort allein anmelden kann (B2-4, NIST SP 800-63B).** Neue
  Schwelle `password_min_length_single_factor` (Panel, Vorgabe 15). Sie gilt, solange die globale
  Kette keinen zweiten Faktor erzwingt — also in der Vorgabe — **und auch dann, wenn Konten den
  verlangten zweiten Faktor selbst einrichten dürfen** (`mfa_enrollment` `first_login`/`grace`):
  Wer nur das Erstpasswort kennt, bindet dort seinen eigenen Authenticator. Erst mit
  `login_chain=[…zweiter Faktor…]` UND `mfa_enrollment="strict"` gilt `password_min_length` (8).
  Wer die strengere Regel nicht will, stellt die neue Schwelle auf 8. Das CLI kennt die
  Konfiguration nicht und nimmt die strengere.
- **Ein vom Identity Provider vergebenes Admin-Flag geht wieder, wenn er die Gruppe nicht mehr
  liefert (H-5).** Gemappte Rollen wurden schon entzogen, das Admin-Flag war „nur grant". Es trägt
  jetzt einen Vermerk (`users.is_admin=2`, weiterhin ein Wahrheitswert); nur dieses Flag nimmt der
  Provider beim nächsten Login wieder, mit Zeile `idp_admin_revoke`. Ein Admin aus Panel, CLI,
  `admin_identifiers` oder `/auth/claim-admin` bleibt unberührt. Flags aus der Zeit davor tragen den
  Vermerk nicht und bleiben ebenfalls stehen. Das Panel schreibt das Admin-Flag nur noch bei einer
  echten Änderung — vorher machte jedes Speichern der Rollen aus der 2 still eine 1.
- **Eine IdP-Adresse ohne Beleg wird nicht verwendet (H-3).** Bisher übernahm OIDC eine Adresse ohne
  `email_verified=true` ins Konto und reichte sie als `Remote-Email` weiter, nur ohne Rechte in
  TinySesam — eine geschützte App, die Nutzer über die Adresse zuordnet, sah den Vermerk nie. Jetzt:
  kein Kontoname aus ihr (auch nicht über ein `preferred_username`, das eine Adresse ist — Keycloak
  „Email as username", Entra-UPN —, geprüft nach der Unicode-Faltung, also auch `＠`), keine Adresse
  im Konto, kein `Remote-Email`. Liefert der Provider den Beleg
  später, wird sie nachgetragen, sofern sie frei ist. Ein Provider, der den Claim nie schickt (Entra
  ID), braucht `oidc_email_verified_default=True`. SAML und LDAP sind unverändert (sie liefern keinen
  Beleg; offen zur Entscheidung).
- **E-Mail-Kollision beim OIDC-Login (F-27)** war bereits abgefangen (409, `oidc_ident_taken`) und
  hat jetzt einen Test; eine unbelegte fremde Adresse kollidiert seit H-3 gar nicht mehr.

### Geändert

- **PIN als Erstfaktor bleibt erlaubt — als Entscheidung festgehalten (B2-8, ADR-8).** Nichts ändert
  sich am Verhalten; die PIN-Versuche (`pin_max_attempts`) stehen im Panel jetzt direkt bei der
  Login-Sperre, PIN-Fehlgriffe zählen in die Serie (B2-6). README und `docs/BETRIEB.md` zeigen das
  Muster „allgemeine Seite mit PIN, Detailseite mit `require(factors=["pin", "password"])`".
- Reihenfolge der Härtungswerte im Panel: was zusammen eingestellt wird, steht zusammen.
- **Das Panel nennt den Grund einer Sperre** (Grenze b): „gesperrt (Bestätigung / App)" (hebt der
  Bestätigungslink auf) statt nur „gesperrt" (Betreiber).
- **Indizes auf dem Audit-Log** (Grenze c) für die Suche nach Name und Zeit.
- **Kette mit Pflicht-Einrichtung (password → totp → pin): das Angebot, die übrigen Sitzungen zu
  beenden, kommt wieder** (Grenze d, ASVS 7.4.3). Die Seite fragt nach der Einrichtung; eingelöst
  wird die Zustimmung, sobald der letzte Faktor bestätigt ist (`/auth/sessions/revoke-after-login`,
  Antwortfeld `other_sessions_after`).


- **Der Knopf im Release-Workflow ist ein Trockenlauf.** Von Hand ausgelöst (`workflow_dispatch`)
  prüft und baut `release.yml` alles, auch das Abbild für beide Plattformen, veröffentlicht aber
  nichts — kein Release, kein PyPI, kein Abbild in der Registry, keine Beglaubigung. Bisher wäre
  der Knopf am Tag-Vergleich gescheitert (ein Zweigname ist kein Tag). Ohne Tag prüft
  `scripts/_release.py --pruefen` die Versionsstände; `tests/test_repo.py` hält fest, dass jeder
  veröffentlichende Job am Tag hängt.

- **Testbasis auf Kit 0.21.8:** Die Kit-Prüfung, die `splitlines()` sucht, schliesst ihre Dateien wieder
  (CodeQL `file-not-closed`, in 0.20.1 als Kit-Fund abgewiesen und an der Quelle behoben). Neu
  verdrahtet: `pruefe_veroeffentlichen_am_tag` — in einem tag-getriggerten Workflow mit Knopf
  veröffentlicht nichts ohne Tag (die allgemeine Fassung des Wächters aus dem Release-Trockenlauf).

## [0.20.1] — 2026-09-24

**Sicherheits-Nachschlag — zügig einspielen, wer einen zweiten Faktor oder API-Keys nutzt.** Über
`/auth/reauth` ersetzten API-Key und Passwort den zweiten Faktor, über `/auth/pin` wurde aus
Automaten-Key und PIN eine volle Admin-Sitzung (beide vorbestehend, siehe „Sicherheit").

Nachschlag zu 0.20.0. Zwei Abnehmer haben beim Heben Befunde **in** TinySesam gemeldet: Beide
mussten für das CSRF-Cookie ihrer eigenen Seiten TinySesam nachbauen, und die Zusage „frisches
CSRF-Token beim Login" galt nur am Ende eines TOTP-Schritts. Der Angriff auf diese Änderungen fand
dazu eine vorbestehende Lücke im Step-up (`/auth/reauth`, siehe „Sicherheit"), eine zweite Runde
dieselbe Klasse in `/auth/pin`: Aus Automaten-Key und PIN wurde eine volle Admin-Sitzung. Kein
Schema-Wechsel, keine neue Konfiguration.

**Vor dem Update:** nichts einzustellen. Zu wissen:

1. **Nach einer Anmeldung gilt das CSRF-Token von vorher nicht mehr.** Ein Formular, das in einem
   anderen Reiter vor der Anmeldung geöffnet wurde, antwortet einmal mit 403. Tests, die ein vor
   der Anmeldung gelesenes Token danach weiterschicken, ebenso — das Token nach der Anmeldung neu
   aus dem Cookie lesen.
2. **Wer für eigene Seiten `csrf_cookie_name` + `issue_csrf()` + eine kopierte Set-Cookie-Zeile
   kombiniert**, kann das durch `auth.ensure_csrf(request, response)` ersetzen. Wer nach einer
   eigenen Anmeldung in **derselben** Antwort ein Formular rendert, holt dessen Token mit
   `ensure_csrf()` **nach** `set_cookie()` — über den FastAPI-Antwortparameter. Eine fertige
   Antwort (Jinjas `TemplateResponse`) ist dann schon gerendert, ihr Formular trüge das alte
   Token (403): Eine Antwort, die an- oder abmeldet, leitet um, statt ein Formular auszuliefern.
3. **`/auth/reauth` antwortet einem API-Key mit 403** (`api.stepup_session`). Bestätigen konnte
   ein Key dort nie etwas — Step-up-Frische erreicht er nicht —, aber die Route nahm ihn an und
   liess sich damit missbrauchen (siehe „Sicherheit"). Wer sie aus einer Automatik ruft, erhält
   jetzt die Abweisung statt einer wirkungslosen 303.
4. **Für `/auth/pin` ist ein API-Key ein Gast.** Ohne volle Sitzung antwortet der POST bei
   `pin_login=False` mit 404 und der GET leitet zur Anmeldung; bei `pin_login=True` braucht die
   PIN das Benutzerfeld wie bei jedem Gast. Als Zusatzfaktor ohne Benutzerfeld gilt die PIN nur
   noch für eine Sitzung. Dasselbe gilt für den TOTP-Schritt, die TOTP-Einrichtung und das
   Abmelden: Sie sehen nur das Konto aus dem Cookie. **Eigene Routen**, die `apply_factor()` für
   „das angemeldete Konto" rufen oder die Sitzung auffrischen, nehmen das Konto aus dem neuen
   `auth.session_user(request)` statt aus `current_user()` (siehe „Sicherheit").

### Hinzugefügt

- **`auth.session_user(request) -> Optional[dict]`** — das Konto der vollen Sitzung dieses
  Requests, nie aus einem API-Key; eine halbe Sitzung liefert None (die liest `pending_user()`).
  `current_user()` fällt ohne volle Sitzung auf den Key zurück und ist damit die falsche Quelle
  für jede Stelle, die einen Faktor auf die Sitzung anwendet (`apply_factor`, `complete_totp`),
  sie auffrischt oder beendet (siehe „Sicherheit"). Die eingebauten Routen nehmen das Konto dort
  seitdem von hier; die Regel steht im Docstring beider Methoden.
- **`auth.ensure_csrf(request, response) -> str`** — ein gültiges CSRF-Cookie sicherstellen und
  das Token fürs Formular holen, ohne TinySesam nachzubauen. Ein vorhandenes, gültiges Token
  bleibt (keine Set-Cookie-Zeile, die Formulare anderer Reiter gelten weiter); sonst setzt es ein
  neues, mit denselben Attributen wie `issue_csrf()`. Hat die Antwort das Token schon gedreht
  (Anmeldung) oder gelöscht (Abmelden), liefert es das neue bzw. setzt ein frisches — nie das alte
  aus dem Request. Für fertige Antworten (Jinjas `TemplateResponse`): `csrf_token(request)` vor
  dem Rendern, `ensure_csrf(request, antwort)` danach; beide liefern in derselben Anfrage dasselbe
  Token — nicht in einer Antwort, die an- oder abmeldet: Die Seite ist gerendert, bevor das Token
  wechselt, ihr Formular trüge das alte. Dort umleiten (nachgetragen nach dem Angriff auf die
  Änderung: die Zusage „dasselbe Token" hatte an dieser Stelle still nicht gegolten, fail-closed
  mit 403; `tests/test_csrf.py` hält die Grenze und den Ausweg fest). Beispiele für Template und
  JS in beiden READMEs („CSRF auf eigenen Seiten"). Bisher gab es nur `issue_csrf()` (würfelt
  immer neu — die „Formular abgelaufen"-Falle in den anderen Reitern) und `csrf_token()` (setzt
  kein Cookie).
- **Die Properties stehen in der eingefrorenen API-Oberfläche** — `session_cookie_name`,
  `csrf_cookie_name`, `resource_cookie_name` (`tests/api_surface.json`, neuer Bereich
  `TinySesam.eigenschaften`; `API.md` mit eigenem Abschnitt). Der Wächter schloss Properties bis
  hierher ausdrücklich aus: Ausgerechnet die Namen, zu denen der Abschnitt 0.20.0 jede einbettende
  App schickt, liessen sich still umbenennen. Eine Selbstprüfung im Test verlangt die drei und
  misst, dass ein Umbenennen als Bruch gemeldet wird — auch vor `--update`.

### Geändert

- **Testbasis auf Kit 0.21.6:** Die Hygiene-Prüfungen nennen Zeilennummern wie der Editor
  (vorher verschob `splitlines()` sie hinter U+2028 und Verwandten).

- **Ein CSRF-Cookie, das nicht wie ein Token aussieht, wird ersetzt** statt übernommen — in
  `render_page()`, `csrf_token()`, `ensure_csrf()` und im Admin-Panel gleich: nur `A–Z a–z 0–9 _ -`,
  32 bis 128 Zeichen. Vorher landete jeder Cookie-Wert unbesehen im Formularfeld. Der Vergleich
  des Double-Submit (`verify_csrf`) ist unverändert.
- **Das Admin-Panel setzt sein CSRF-Cookie über `ensure_csrf()`** und damit mit denselben
  Attributen wie jeder andere Setzer.
- **`issue_csrf()` und `csrf_rotieren()` ersetzen eine CSRF-Zeile**, die die Antwort schon trägt,
  statt eine zweite anzuhängen.

### Sicherheit

- **Jede Anmeldung dreht das CSRF-Token, das Abmelden löscht es** — wie es der Docstring von
  `csrf_rotieren()` zusagt („beim Login"; OWASP CSRF Prevention Cheat Sheet: „changes with each
  login"). Gerufen wurde es nur am Ende eines TOTP-Schritts. Passwort, PIN, Anmelde-Link,
  Registrierung, OIDC, SAML und Passkey liessen das Token stehen, und `auth.logout()` löschte das
  Cookie nicht: Das Token überlebte Abmelden und Neuanmelden bis zum Schliessen des Browsers.
  Jetzt zentral statt je Route: Jede Sitzungszeile entsteht in `_sitzung_anlegen()`, eine dort
  schon voll angemeldete wird vorgemerkt, und `set_cookie()` dreht das Token in derselben Antwort.
  Das gilt für jeden eingebauten Weg und für eine eigene Anmelderoute der App (`start_session` +
  `set_cookie`). Ein Step-up (`/auth/reauth`, TOTP auf voller Sitzung, `rotate_session`) und der
  erste Schritt einer Kette drehen nicht. `logout()` — damit auch `POST /auth/logout` und das
  Abmelden per GET von der eigenen Seite — löscht das CSRF-Cookie mit Secure und Pfad; die nächste
  Seite setzt ein frisches. `tests/test_csrf.py` fährt jeden Anmeldeweg einzeln durch (altes Token
  403, neues gilt, die Folgeseite rendert mit dem neuen), ein Wächter über den Quelltext hält fest,
  dass Sitzungen nur in `_sitzung_anlegen()` entstehen und das Sitzungs-Cookie nur in
  `set_cookie()` gesetzt wird.
- **`/auth/reauth` bestätigt nur noch eine Sitzung, nie einen API-Key — Key und Passwort ersetzten
  dort den zweiten Faktor** (vorbestehend, nachgestellt auf 0.20.0; gefunden beim Angriff auf die
  CSRF-Änderungen). Die Route prüfte den Faktor des Kontos aus `current_user()` und machte danach
  die Sitzung aus dem Cookie voll. Bei einer **halben** Sitzung (erster Faktor erbracht, TOTP
  offen) fällt `current_user()` auf den API-Key zurück, Prüfung und Wirkung trafen also
  verschiedene Dinge: Mit dem Sitzungs-Cookie einer halb angemeldeten fremden Person, dem eigenen
  Automaten-Key und dem eigenen Passwort war deren Sitzung voll angemeldet, ohne dass ihr TOTP je
  gefragt wurde. Im eigenen Konto ersetzten Automaten-Key und Passwort das TOTP und brachten das
  Admin-Flag zurück, das ein Automaten-Key allein nicht trägt (R6-5). Voraussetzung waren ein
  gültiger API-Key (`apikey_enabled`) und — für das fremde Konto — dessen halbes Sitzungs-Cookie.
  Jetzt antworten `GET` und `POST /auth/reauth` einem Konto, das nicht aus der Sitzung kommt, mit
  403 (`api.stepup_session`), bevor ein Faktor geprüft wird; ein Key kann Step-up-Frische
  ohnehin nie erreichen (`stepup_fresh()`). `tests/test_stepup.py` stellt beide Wege nach und
  prüft, dass der Step-up einer vollen Sitzung per TOTP weiterläuft.
- **`/auth/pin` machte aus Automaten-Key und PIN eine volle Admin-Sitzung — auch bei
  `pin_login=False`** (vorbestehend, nachgestellt auf 0.20.0; zweite Angriffsrunde gegen 0.20.1,
  dieselbe Klasse wie `/auth/reauth` darüber). `pin_submit` las „schon angemeldet" aus
  `current_user()`, und das fällt ohne volle Sitzung auf den API-Key zurück. Eine reine
  Key-Anfrage ohne Cookie galt damit als angemeldet: Der Riegel `pin_login=False` („die PIN ist
  kein Erstfaktor") griff nicht, geprüft wurde die PIN des Key-Kontos, und `apply_factor()` legte
  mangels Sitzung eine neue, volle an — samt dem Admin-Flag, das ein Automaten-Key nie trägt
  (R6-5), und damit Admin-Panel, Schlüsselverwaltung und Faktor-Anlage. Mit der halben Sitzung
  einer anderen Person im Cookie ersetzte dieselbe Anfrage deren Cookie. Voraussetzung waren ein
  gültiger Key (`apikey_enabled`), `pin_enabled` und die PIN des Key-Kontos; bei `pin_login=True`
  ist die PIN ohnehin ein Erstfaktor, der Key brachte dort nichts. **Jetzt zentral statt je
  Route:** Das Konto einer Stelle mit Sitzungswirkung kommt aus `auth.session_user()` (neu, siehe
  „Hinzugefügt"), für die ein Key „nicht angemeldet" ist — in `/auth/pin` (GET und POST),
  `/auth/reauth` (der Riegel von oben läuft jetzt darüber), dem TOTP-Schritt, der
  TOTP-Einrichtung und dem Abmelden. Beim Durchgehen der Klasse fielen zwei harmlosere Stellen
  mit auf: Der TOTP-Schritt prüfte auf der vollen Sitzung eines gesperrten Kontos den Code des
  Key-Kontos, und das Abmelden protokollierte bei Key ohne Sitzung dessen Konto. Ein Wächter in
  `tests/test_stepup.py` liest jede Funktion des Pakets: Wer eine Sitzung anlegt, ihr einen
  Faktor anhängt, sie auffrischt oder beendet, darf sein Konto weder direkt noch über einen
  lokalen Helfer aus `current_user()`, `require_user()`, `require_role()` oder `require_admin()`
  nehmen; Selbstproben halten fest, dass er jede zugesagte Form auch sieht. Die Verhaltensprobe
  daneben stellt den Weg nach (Key + PIN → 404, keine Sitzung, kein Admin; halbe fremde Sitzung
  bleibt unverändert; die PIN als Zusatzfaktor einer vollen Sitzung läuft weiter).

### Behoben

- **Doku: Sicherung vor dem Update, wenn die Installation bei 0.17.x oder älter steht.** Der
  Hinweis „vor dem Update `tinysesam backup`" ging dort nicht auf: Den Unterbefehl gibt es erst
  seit 0.18.0, und der erste Start des neuen Abbilds migriert schon. Beide READMEs und der
  Abschnitt 0.20.0 nennen jetzt den Weg: die Sicherung mit der neuen Fassung vor ihrem Start
  ziehen (`docker compose run --rm --no-deps --entrypoint tinysesam <dienst> backup …`, bei der
  Bibliothek nach dem Installieren und vor dem Neustart), oder bei angehaltenem Dienst die `.db`
  samt `-wal`/`-shm` kopieren. Nachgestellt an einer mit 0.16.0 angelegten Datei: Die Sicherung
  trägt das alte Schema, die Quelle bleibt unverändert.
- **Doku: der CSRF-Cookie-Name in eigenem JS.** „Eigenes JS liest den CSRF-Namen aus
  `auth.csrf_cookie_name`" (0.20.0) verkürzte: JavaScript kann keine Python-Property lesen. Die
  Seite reicht den Namen per Template-Variable oder `<meta>` weiter, oder das Skript nimmt das
  Token aus dem Formularfeld von `ensure_csrf()`. Präzisiert im Abschnitt 0.20.0, in beiden
  READMEs und in `KONFIGURATION.md` (`cookie_host_prefix`).
- **Doku: 0.19.0 versprach bei der Faktor-Anlage zu viel.** Verhaltensänderung Nr. 3 sagte, auch
  die Anlage (`totp/setup`, `passkey/register/*`) verlange eine frisch bestätigte Sitzung. Der Code
  verlangt dort eine interaktive Sitzung (`require_session()`, kein API-Key), keine frische
  Bestätigung — so steht es auch im Befund weiter unten. Der Satz ist datiert berichtigt, der Code
  bleibt.

## [0.20.0] — 2026-09-24

**Sicherheits-Release, mit Brüchen — jede Installation sollte es einspielen, aber nicht blind.**
Es schliesst die übrigen drei 1.0-Blocker des dritten Audits (F-11 stabile Kennung für LDAP und
SAML, F-12 LDAP-Transport, F-16 SP-Identität) und die übrigen Befunde aus T-13; danach wurde
die Zusammenführung selbst angegriffen und gehärtet.

**Vor dem Update:**

1. **Sicherung ziehen** (`tinysesam backup`). Die Datenbank wandert von Schema 8 auf **10**; ein
   Rückschritt auf 0.19.x braucht die Sicherung. **Von 0.17.x oder älter** (ergänzt in 0.20.1):
   Den Unterbefehl gibt es erst seit 0.18.0, und schon der erste Start des neuen Abbilds migriert.
   Die Sicherung deshalb mit der neuen Fassung ziehen, bevor sie startet — `docker compose pull`,
   dann `docker compose run --rm --no-deps --entrypoint tinysesam <dienst> backup --db
   /data/gateway.db /data/vor-update.db`, erst danach `docker compose up -d`; bei der Bibliothek
   `python -m tinysesam backup --db … <ziel>` nach dem Installieren, vor dem Neustart. `backup`
   öffnet die Quelle nur lesend. Oder den Dienst anhalten und die `.db` samt `-wal` und `-shm`
   kopieren.
2. **Jeder ist nach dem Update einmal abgemeldet** (`__Host-`-Cookies).
3. **Eigenes JS und eigene Routen prüfen:** den CSRF-Cookie-Namen aus `auth.csrf_cookie_name`
   lesen (nicht aus `cfg.csrf_cookie`, nicht fest `tinysesam_csrf`); eigenes JS bekommt ihn von
   der Seite, per Template-Variable oder `<meta>` — eine Python-Property kann es nicht lesen
   (präzisiert in 0.20.1; seit 0.20.1 setzt `auth.ensure_csrf()` Cookie und Token für eigene
   Seiten). Das Rückgabe-Token von `complete_totp()` ins Cookie setzen; Abmelden per
   `POST /auth/logout`.
4. **Konfiguration prüfen:** `ldap://` ohne StartTLS ist ein Aufbaufehler, ebenso Text statt Zahl
   in Zahlenfeldern (`smtp_port="587"`). `base_url` setzen, wenn Mails oder SSO im Spiel sind.
5. **Wer die nginx-Vorlage übernommen hat**, zieht die `map`-Zeilen nach.

Die Einzelheiten folgen — erst die Punkte aus den Blockern, dann „T-13: die übrigen Befunde" und
„T-13: Angriff auf die Integration".

**Verhaltensänderung.** `ldap://` ohne StartTLS ist jetzt ein **Aufbaufehler**. Wer ein
Verzeichnis im Klartext anspricht, muss das mit `ldap_allow_plaintext=True` ausdrücklich sagen.
→ **Zu tun:** entweder `ldaps://` in der URL, oder `ldap_start_tls=True`, oder den Schalter
setzen (nur sinnvoll, wenn der Verkehr die Maschine nie verlässt).

### Geändert

- **Das Release-Skript ersetzt nur noch Pins** (`scripts/_release.py`): Bisher schrieb es jede
  Fundstelle der alten Version um, auch erzählenden Text wie „0.19.0 hob auf Schema 8". Es
  erkennt jetzt auch den deutschen Abschnitt `[Unveröffentlicht]`.
- **Testbasis auf Kit 0.21.5** (von 0.18.0). Neu verdrahtet: `pruefe_testdateien_gerufen` fragt
  von aussen, ob jede Testdatei einen Läufer hat — ein nicht verkabelter Test besteht seine eigene
  Aufruf-Prüfung dadurch, dass er schweigt. Der Geheimnis-Zaun kennt `pat`-Zuweisungen und das
  `nbp_`-Format; der Namens-Zaun prüft auch Wortbestandteile. Die CI hält vor der Suite den Stand
  des Baums fest und prüft danach gegen ihn: Seit Kit 0.20.1 meldet der Rückstands-Check ohne
  Vorher-Stand nur noch „nicht entscheidbar" (Exit 2) statt eines belegten Rückstands. Seit
  0.21.2 zählt ein Sammler (`tests/run_all.py`) nur, wenn ein Läufer ihn auch ruft.

- **Das Container-Abbild baut auf Python 3.14** statt 3.12 (`python:3.14-slim`, per Digest
  gepinnt). 3.14 ist die Obergrenze der unterstützten Matrix; vor dem Wechsel geprüft, dass alle
  Extras im Zielabbild installieren und importieren.

### Sicherheit

- **Jeder `actions/checkout` setzt `persist-credentials: false`** (neun Stellen, keine Ausnahme).
  **Ebene dieser Regel: eigene Härtung, kein belegter Standard** — GitHub empfiehlt es nirgends
  ausdrücklich. Was sie bringt: Mit der Vorgabe legt checkout das Token so ab, dass **jeder
  spätere Schritt im selben Job** es lesen kann. Seit v6 liegt es unter `$RUNNER_TEMP` statt in
  `.git/config`, das Risiko ist also kleiner als die oft zitierte Begründung nahelegt — es
  verschwindet aber nicht, und nach dem Checkout läuft hier fremder Code (`pip install -e`,
  Actions Dritter). Keine Ausnahme nötig, weil kein Job dieses Repos per git pusht oder taggt;
  nachgemessen, nicht angenommen.

- **Dependabot bündelt nur noch patch und minor** (`update-types`). Ein Major landete sonst im
  monatlichen Sammel-PR und würde mit ihm durchgewinkt: Dieselbe Prüfung, die für drei harmlose
  Patches genügt, entschiede dann auch über einen Versionssprung mit Bruch. Majors kommen einzeln
  — dort ist der CHANGELOG des Pakets die Arbeit, nicht der grüne Haken der CI.

- **LDAP und SAML binden an eine stabile Kennung, nicht an den Benutzernamen** (F-11, Schema 9).
  Ein Name ist nicht fälschungssicher: Wer im Verzeichnis umbenennt oder ein gelöschtes Konto
  unter demselben Namen neu anlegt, bekam bis 0.19.0 **dasselbe lokale Konto mitsamt seinen
  Rollen** — ohne das lokale Passwort zu kennen. Zusammen mit der ungeprüften SP-Identität
  (F-16) war das die Kontoübernahme, die der Auditbericht als kritisch einstufte. OIDC hatte mit
  `issuer`+`sub` von Anfang an eine eigene Zuordnung; LDAP und SAML hatten keine.

  Zugeordnet wird jetzt über `objectGUID`/`entryUUID` (LDAP, `ldap_attr_id`) beziehungsweise die
  `NameID` (SAML, `saml_attr_id` für IdPs mit transienten NameIDs). Vier Lagen, und die dritte
  ist der Riegel: Kennung bekannt → dieses Konto, **auch bei geändertem Namen**. Kennung
  unbekannt und Name frei → anlegen und binden. Kennung unbekannt, aber das Konto dieses Namens
  trägt schon eine **andere** Kennung → **abweisen**, mit Audit-Zeile. Kennung unbekannt und das
  Konto noch ungebunden → **nachbinden**, einmal, ebenfalls protokolliert.

  Die Nachbindung ist der Bestandsweg: Konten aus der Zeit vor dieser Fassung haben keine
  Kennung, und irgendwann muss jedes einmal daran. Sie verlässt sich ein letztes Mal auf den
  Namen — danach nie wieder. Wer im Verzeichnis wirklich umgezogen ist, löst die Bindung
  ausdrücklich (`auth.loese_fremde_bindung("ldap", uid)`); dass das ein bewusster Schritt ist
  und kein Nebeneffekt einer Anmeldung, ist der Punkt.

  **Liefert das Verzeichnis keine stabile Kennung**, bleibt es beim Namen — dem ungeschützten
  Zustand —, und das sagt eine Zeile je Quelle im Sicherheits-Log.
  `federation_require_stable_id=True` macht daraus eine Abweisung. Vorgabe ist die weiche
  Fassung, damit nach dem Update niemand vor verschlossener Tür steht.

- **Die SAML-Selbstauskunft hört nicht mehr auf den Anfragenden** (F-16). python3-saml baut aus
  `https`, `http_host` und `script_name` die Adresse, die es für die eigene hält, und vergleicht
  damit die `Destination` der Assertion. Diese drei Angaben kamen aus `X-Forwarded-Proto` und dem
  `Host`-Header — der Anfragende bestimmte den Vergleich also mit: Er legte eine Assertion vor,
  deren `Destination` auf seinen Namen lautet, und setzte den Header passend dazu. Die Prüfung
  ging auf, obwohl die Assertion nie für uns gedacht war. Zusammen mit der Bindung über den
  blossen Benutzernamen (F-11) war das eine Kontoübernahme ohne Kenntnis des lokalen Passworts.

  Der `req`-Satz kommt jetzt aus `saml_.request_kontext()` und damit aus der **geprüften
  Basis** — derselben, aus der auch Entity-ID und ACS-URL gebaut werden. Alle drei Angaben sagen
  dasselbe, und keine hört auf den Anfragenden. Der Pfadanteil einer unter einem Unterpfad
  montierten App wandert mit, aber nicht doppelt.

- **Das Passwort des Dienstkontos ging im Klartext über die Leitung** (F-12). Bei
  Search-then-Bind stand `auto_bind=True` in der Verbindung und `start_tls()` eine Zeile später:
  Der Bind war also schon durch, bevor die Leitung verschlüsselt wurde. Ein Mitleser brauchte
  keinen Angriff, nur Geduld — und zwar bei **jeder** Anmeldung, denn die Suche läuft jedes Mal.
  Jetzt schaltet `AUTO_BIND_TLS_BEFORE_BIND` zuerst auf TLS um; die Benutzer-Verbindung machte es
  von Anfang an richtig.

- **Das Zertifikat des Verzeichnisses wird geprüft** (F-12, `ldap_tls_verify`, Vorgabe an).
  `ldap3.Server(...)` ohne `tls=` prüft gar nichts — verschlüsselt hiess damit nur „nicht
  mitlesbar von jemandem, der nicht dazwischensitzt". Wer den Verkehr umlenkt, hält ein eigenes
  Zertifikat hin, bekommt beide Passwörter und reicht die Antwort an das echte Verzeichnis
  weiter; für beide Seiten sieht der Vorgang normal aus. Eine interne CA gehört in
  `ldap_tls_ca_file`; `ldap_tls_verify=False` bleibt möglich und meldet sich beim Aufbau.

- **Klartext ist kein Vorgabewert mehr** (F-12, `ldap_allow_plaintext`, Vorgabe aus). Bis 0.19.0
  war `ldap://` ohne StartTLS der Auslieferungszustand, und die Konfigurationsprüfung sagte dazu
  nichts. Jetzt scheitert der Aufbau mit einem Text, der beide Auswege nennt.

### Sicherheit — T-13: die übrigen Befunde des Auditberichts

Zehn Bereiche, **161 Punkte behoben**, 2 waren schon erledigt, 6 bleiben mit Begründung offen
(Backlog T-13). Jeder Fix wurde danach gezielt angegriffen und nachgebessert.

**Verhaltensänderungen — vor dem Update lesen:**

- **Jeder ist nach dem Update einmal abgemeldet.** Sitzungs-, CSRF- und Freigabe-Cookie heissen
  jetzt `__Host-tinysesam_*` (wo der Browser es zulässt). Eigener Code nimmt den CSRF-Namen aus
  `auth.csrf_cookie_name`; eigenes JS bekommt ihn von der Seite (Template-Variable oder `<meta>`,
  präzisiert in 0.20.1 — dort auch `ensure_csrf()`). Abschalten: `cookie_host_prefix=False`.
- **Abmelden ist ein POST** (`POST /auth/logout` mit CSRF). Ein `GET` von fremder Seite fragt nach.
- **Anmelde- und Bestätigungslinks lösen erst per Knopf ein** (POST), nicht mehr beim Öffnen —
  Mail-Scanner verbrauchen sie so nicht mehr.
- **Login-Sperre zählt je Konto+IP**; ein Fremder sperrt kein Konto mehr aus. Neue Schwelle
  `account_attempt_factor` je Konto über alle IPs.
- **LDAP-Gruppen vergleichen nach DN-Bestandteilen**, nicht per Teilstring. Ein Schlüssel, der nur
  noch als Teilstring träfe, meldet sich einmal im Sicherheits-Log.
- **Passwort-Reset per Mail widerruft die API-Keys**; reine SSO-Konten bekommen keinen Reset-Link.
- **`set_security()` prüft Grenzen** und wirft `ConfigError` statt still zu übernehmen.
- **Neue Blockliste für Passwörter** an jeder Setzstelle (offline, erweiterbar).
- **SMTP prüft das Zertifikat** (`smtp_ca_file` für eigene CA).
- **Nie bestätigte Konten** räumt `gc()` nach Ablauf des Links weg.
- **Schema 10** (erster Start migriert): indizierte Zähl-Töpfe, Betreiber-Vermerk an Panel-Sperren.
  Vorher sichern (`tinysesam backup`) — ein Rückschritt braucht die Sicherung.
- **Das CSRF-Cookie heisst auch mit `cookie_domain` `__Host-tinysesam_csrf`.** Wer es selbst setzt
  oder im JS liest, nimmt den Namen aus `auth.csrf_cookie_name` (nicht aus `cfg.csrf_cookie`); ins
  JS gelangt er über die Seite, per Template-Variable oder `<meta>` (präzisiert in 0.20.1).
- **Bruch: `complete_totp()`/`complete_mfa()` drehen das Token auch beim Step-up** — das
  Rückgabe-Token gehört ins Cookie, sonst ist der Nutzer abgemeldet.
- **Text statt Zahl in Zahlenfeldern der Config ist ein Aufbaufehler** (z. B. `smtp_port="587"`
  direkt aus einer Umgebungsvariable) — vorher selbst mit `int()` umwandeln.
- **Die Selbst-Registrierung legt die Adresse als unbestätigt an**, bis der Link eingelöst ist
  (Ausnahme: Einladung an genau diese Adresse).
- **`trusted_redirect_hosts` zählen nicht mehr als eigener Origin** in der CSRF-Herkunftsprüfung;
  hinter einem Proxy, der den Host umschreibt, `base_url` setzen.

#### Sitzung, Cookies, CSRF

**Sicherheit**
- Sitzungs-, CSRF- und Freigabe-Cookie heißen jetzt `__Host-tinysesam_session`, `__Host-tinysesam_csrf` und `__Host-tinysesam_runlock`, wo der Browser das zulässt (Secure, kein `cookie_domain`, `cookie_path="/"`). Das CSRF-Cookie und die Flow-Cookies von OIDC, SAML und Passkey sind immer host-only und tragen das Präfix auch bei gesetztem `cookie_domain`. Wo das Präfix greift, kann eine Nachbar-Subdomain damit keine Cookies mehr unterschieben (Cookie-Tossing, Login-CSRF). Ohne `__Host-` am Sitzungs-Cookie, also mit `cookie_domain`, `cookie_host_prefix=False`, einem anderen `cookie_path` oder `cookie_secure=False`, kann sie das Sitzungs-Cookie weiter setzen (bekannte Grenze, SECURITY.md). Abschalten mit `cookie_host_prefix=False`. **Bruch:** Nach dem Update ist jeder einmal abgemeldet. Eigener Code nimmt den Namen aus `auth.csrf_cookie_name` statt aus `csrf_cookie`; eigenes JS bekommt ihn von der Seite, per Template-Variable oder `<meta>` (präzisiert in 0.20.1). (H-1, F-02, A-1, A-7)
- Die CSRF-Prüfung prüft vor dem Token-Vergleich die Herkunft: Bei `Sec-Fetch-Site: same-origin` ist sie bestanden, sonst muss ein gesetzter `Origin` ein eigener Host sein. Fremde Herkunft und Nachbar-Subdomains bekommen 403. **Grenze:** Fehlt ein brauchbarer `Origin` (fehlt oder `null`) und fehlt auch `Sec-Fetch-Site`, entscheidet allein das Token. Das gilt für jeden Browser über HTTP (`cookie_secure=False`, außer `localhost`), denn Browser schicken `Sec-Fetch-Site` nur an HTTPS. Dort kommt eine Nachbar-Subdomain mit `Origin: null` also bis zum Token durch, und das CSRF-Cookie trägt ohne `Secure` kein `__Host-`. Über HTTP schützt die Herkunftsprüfung deshalb nicht vor Login-CSRF aus der Nachbarschaft. Hinter einem Proxy, der den Host umschreibt, ohne `X-Forwarded-Host` zu setzen, scheitern Browser ohne `Sec-Fetch-Site` (Safari vor 16.4, jeder Browser über HTTP). Dafür `base_url` setzen oder notfalls `csrf_origin_check=False`. (H-2, A-3)
- Eine Bereichs-Freischaltung vergibt jedes Mal ein neues Freigabe-Token, ein untergeschobenes Token hält danach nichts mehr (F-01). Der Logout beendet auch die Bereichs-Freigaben dieses Browsers (F-08).
- Ein Step-up (Reauth oder erneuter Faktor) gibt der Sitzung ein neues Token. Laufzeit, Anmeldezeitpunkt und Cookie-Art („Angemeldet bleiben“ ja oder nein) bleiben erhalten. (F-06, A-2)
- `GET /auth/logout` von einer fremden Seite meldet nicht mehr ab, sondern fragt nach. Neu ist `POST /auth/logout` mit CSRF-Prüfung. (F-07)
- `POST /auth/sessions/revoke` verlangt eine frische Bestätigung (`X-TinySesam-Reauth`). `GET /auth/sessions` verlangt eine echte Sitzung, ein API-Key reicht nicht. (F-09)
- `csrf_enabled=False` zusammen mit `cookie_samesite='none'` bricht den Aufbau ab. (F-03)
- `cookie_secure=False` bei einem Request über HTTPS (auch hinter einem TLS-Proxy) steht einmal je Instanz im Sicherheits-Log. (F-04)

**Geändert**
- Faktor-Änderungen (TOTP, PIN, Passkey) melden in der Antwort `other_sessions`. Die Kontoseite und die TOTP-Einrichtung bieten danach an, die übrigen Sitzungen zu beenden. Bei der Pflicht-Einrichtung von TOTP während der Anmeldung kommt das Angebot nur, wenn die Bestätigung die Anmeldung abschließt (TOTP ist der letzte Schritt der Kette). **Bekannte Grenze:** Folgt noch ein Schritt (`password → totp → pin`), meldet die Einrichtung `other_sessions: 0`, und auch der PIN-Schritt danach bietet nichts an. Das Angebot entfällt dann ganz, der Weg zu den übrigen Sitzungen ist die Sitzungsliste auf der Kontoseite. Ist die Bestätigung zu alt, führt der Weg über die Reauth zurück zur Kontoseite (`?revoke_others=1`), dort wird noch einmal gefragt. (B1-7, A-5)
- `set_cookie(response, token)` richtet die Cookie-Art ohne `remember` jetzt nach der Sitzung, zu der das Token gehört. Vorher war die Vorgabe immer „persistent“. Mit ausdrücklichem `remember` bleibt alles wie bisher. (A-2)
- Neu: `auth.session_cookie_name`, `auth.csrf_cookie_name`, `auth.resource_cookie_name`, `auth.flow_cookie_name(basis)` sowie die Config-Felder `cookie_host_prefix` und `csrf_origin_check`.

#### Kopfzeilen und Injection in Seiten

**Sicherheit**
- Jede Antwort einer TinySesam-Route trägt jetzt `X-Content-Type-Options: nosniff`, `Referrer-Policy: same-origin`, `Cache-Control: no-store` und `Vary: Cookie`. Das gilt auch für geworfene Fehler (401/403/Umleitungen über `exc.headers`), für das 422 der Eingabeprüfung und für die Fehlerseiten sowie den JSON-500 aus `install_error_pages`. Das 422 baut weiter der Handler, den die App dafür registriert hat. Routen des Gastgebers bleiben unberührt (Routen-Klasse statt Middleware). Bei `csp='strict'` kommt `X-Frame-Options: SAMEORIGIN` dazu. (R8-5, R4-08, R5-2, A2)
- Das Admin-Panel läuft unter derselben Nonce-CSP wie die übrigen Seiten, ohne Inline-Handler und ohne `style=`. (R8-1)
- Escaping: `rp_name` im Admin-Panel (R8-3), Key-, Passkey- und Sitzungsfelder auf der Konto-Seite (`esc0` ersetzt alle fünf HTML-Sonderzeichen, R8-6), Benutzername im Showcase auf `/demo` (R8-2).
- `csp`: Ein Tippfehler wie `'Strict'` oder eine Policy ohne eine einzige bekannte Direktive bricht den Aufbau ab, statt die CSP still abzuschalten. `pruefen()` meldet das auch nachträglich. Eine unbekannte Direktive neben bekannten (z. B. `require-sri-for`, `disown-opener`) erzeugt nur eine Warnung, denn der Browser wendet den Rest der Policy an. (B3-2, A3)

**Behoben**
- Die Härtungskopfzeilen in `exc.headers` schreiben vorhandene Schlüssel nicht mehr klein. Ein Exception-Handler des Gastgebers, der `exc.headers["Location"]` liest, leitet beim Admin-Panel ohne Sitzung wieder korrekt um. (A1)

#### OIDC, SAML, LDAP (inkl. Proxy-Vorlagen)

**Sicherheit**
- **OIDC: PKCE (S256) ist immer an** (F-20, H-12). Der Verifier bleibt auf dem Server, ein abgefangener Code lässt sich ohne ihn nicht einlösen.
- **OIDC: ID-Token ohne `exp` wird abgewiesen** (F-25). Ein paar Sekunden Uhrvorlauf beim IdP werden toleriert (`leeway=60`, F-26).
- **OIDC: Eine Fehlerantwort des IdP bei Discovery oder JWKS wird nicht mehr zwischengespeichert** (F-24).
- **SAML: SHA-1 in Signatur oder Digest wird abgewiesen** (F-21).
- **SAML: Die ACS ist ratenbegrenzt, und jede fachliche Abweisung (Gruppe, kein Konto, gesperrt) steht mit Grund und IP im Audit-Log** (F-22).
- **LDAP: Gruppen werden nicht mehr per Teilstring verglichen** (F-19). `group_match` wirkt jetzt auch für LDAP. Ein `memberOf`-DN trifft als ganzer DN, als Teil-DN von vorn (`cn=admins,ou=groups`) oder über den CN (`admins`), jeweils nur mit ganzen Bestandteilen. `admin` trifft also nicht mehr `cn=nicht-admin,…`. Das gilt auch für `ldap_allowed_groups`. **Verhaltensänderung:** Ein Schlüssel, der nur als Teilstring griff (z. B. `ou=groups` oder `staff` für `cn=staffextern`), greift nicht mehr. Das Sicherheits-Log meldet ihn beim ersten betroffenen Login einmal. `group_match="substring"` holt den alten Vergleich zurück.
- **LDAP: Ein Verzeichnis-Ausfall ist kein Fehlversuch** (F-23). Die Login-Route antwortet mit 503 und schreibt eine Audit-Zeile `ldap_unavailable`. Gegen LDAP-Nutzer wird weder eine Sperre noch ein `failed login` für fail2ban verbucht. Ein falsches **lokales** Passwort zählt auch während des Ausfalls als Fehlversuch, sonst wäre das lokale Notfallkonto unbegrenzt ratbar (A-1). Verbindungs-Timeout 10 s.
- **Kein Reset-Link für reine SSO-Konten** (H-4): Konten, die an OIDC, LDAP oder SAML gebunden sind und kein lokales Passwort haben, bekommen keinen Reset-Link. Die Antwort nach außen bleibt gleich. Kommt ein Konto aus einem Verzeichnis ohne stabile Kennung, merkt sich TinySesam beim Login trotzdem die Herkunft (A-4). Kommt später eine echte Kennung, ersetzt sie diesen Vermerk.
- **Proxy-Vorlagen: Die TinySesam-Cookies gehen nicht mehr an die geschützte App** (B-20, A-2, A-5). Caddy und beide nginx-Vorlagen entfernen alle `tinysesam_*`-Cookies (Sitzung, Freigabe, CSRF, auch mit `__Host-`/`__Secure-`) vor der App bzw. vor PHP und lassen andere Cookies stehen. Traefik kann einzelne Cookies nicht entfernen. `traefik.yml` benennt die Lücke und bringt die Middleware `tinysesam-cookies-weg` für Apps ohne eigene Cookies mit. **Bestandsinstallationen: die eigene Proxy-Konfiguration nachziehen.** Wer Cookies umbenannt hat, trägt die Namen ins Muster ein.
- **nginx-Vorlagen setzen `X-Forwarded-For` im Sub-Request selbst** (NEU-1). Vorher kam der vom Client mitgeschickte Wert bei TinySesam an und bestimmte Rate-Limit, IP-Sperre und fail2ban.

**Geändert**
- LDAP-Anmeldungen und lokale Anmeldungen sind im Audit-Log getrennt (`login_ldap` / `login_lokal`), `login_fail` nennt `quelle=` (F-29).
- Die Konfigurationsprüfung nennt `ldap_enabled` nicht mehr als Abhilfe für „keine Methode“ und warnt bei LDAP ohne `password_enabled` (F-30).
- Caddy-Vorlage: Kommentar und Test zur Go-kanonischen Schreibweise in `{rp.header.…}` (H-16).

#### Mail-Wege und Registrierung

**Sicherheit**
- **Einmal-Links lösen nicht mehr per GET ein (R4-02).** `GET /auth/magic/{token}` und `GET /auth/verify/{token}` zeigen nur noch eine Bestätigungsseite (neue Seite `magic_confirm`). Eingelöst wird per `POST` mit CSRF-Token. Mail-Scanner und Vorschau-Bots verbrauchen den Link damit nicht mehr und melden niemanden an. **Zu tun:** Wer die Seite `magic_confirm` per `set_template` ersetzt oder den Link selbst per GET einlöst, stellt auf POST um.
- **Keine Konto-Erkundung über die Registrierung (R4-03, Nachbesserung A1).** Mit `signup_verify_email` antwortet eine vergebene Adresse wie eine freie, und der Inhaber bekommt einen Hinweis ohne Token. Der Benutzername wird jetzt vor der Adresse geprüft. Bei vergebener Adresse belegt ein gesperrter Platzhalter ohne Adresse den Namen, und `gc()` entfernt ihn nach Ablauf. Ein Benutzername darf dabei keine fremde E-Mail-Adresse sein (neue Meldung `err.username_is_address`). Ohne Bestätigung bleibt es bei 409.
- **Drossel je Zieladresse (R4-04, Nachbesserung A2):** `mail_per_address_max` / `mail_per_address_window_sec` (3 je 15 min) für Anmelde-Link und Reset. Abgewiesen wird unsichtbar, im Audit-Log steht `mail_ratelimit`. Der Registrierungshinweis hat einen eigenen Topf, damit Fremde den Inhaber nicht von seinen eigenen Links aussperren können.
- **Versand nach der Antwort (R4-05, B6-6).** Die eingebauten Routen verschicken über einen eigenen Mail-Arbeiter (`mailer.Postausgang`) mit gedeckelter Warteschlange. Das beseitigt das Timing-Orakel, und ein hängender Mailserver belegt den Threadpool nicht mehr.
- **E-Mail-Normalisierung (R4-06, Nachbesserungen A5/A6).** `norm_email` faltet per NFKC und schreibt Umlaut-Domains als A-Label. `valid_email` weist unsichtbare Zeichen und Schriftmischung ab, lässt aber die Schriften einer Sprache zusammen zu (Kanji mit Kana, Hanja mit Hangul, Han mit Bopomofo). Bestandsadressen in Unicode-Form findet die Suche weiterhin, auch wenn die Eingabe als A-Label kommt.
- **Nie bestätigte Konten werden aufgeräumt (R4-09).** `gc()` und `tinysesam gc` entfernen sie, sobald der Bestätigungslink abgelaufen ist (Zähler `unverified_accounts`).
- **Links gehen an die gespeicherte Adresse (R4-11)**, nicht an die Eingabe.
- **Gescheiterter Versand (B6-5, B6-12).** Der Token läuft sofort ab. Scheitert die Bestätigungsmail einer Registrierung, wird das Konto zurückgenommen, statt mit HTTP 500 als Leiche liegen zu bleiben.
- **Ungültige Einmal-Token hinterlassen eine Spur (B5-18, Nachbesserung A3).** Sie stehen im Audit-Log als `token_invalid`, global gedeckelt auf 20 je Minute plus eine Zeile `token_invalid_throttled`. Im Sicherheits-Log steht jede als `failed verification` (nicht die Login-Jail). `GET /auth/reset` ohne Token zählt nicht.
- **SMTP-TLS prüft Zertifikat und Hostnamen (B3-1, Nachbesserung A4).** Eine eigene CA gibt man über `smtp_ca_file` an. **BRUCH – Zu tun:** Ein Relay mit selbstsigniertem Zertifikat braucht jetzt `smtp_ca_file`, und ein Relay per IP-Adresse braucht als `smtp_host` den Namen aus dem Zertifikat. Sonst geht keine Mail mehr hinaus. Ein fehlender `smtp_ca_file`-Pfad ist ein Aufbaufehler. `smtp_host` als IP-Adresse löst beim Start eine Warnung aus. Ein Zertifikatsfehler beim Versand nennt im Log die Abhilfe.

#### Sperren und Drosselung

- **Sperren atomar (R7-2, R3-2, R3-7):** Login, TOTP, PIN, Bereichs-PIN, Step-up und Passwortwechsel prüfen und verbuchen einen Versuch jetzt in einem Schritt (`versuch_beginnen()`, `Store.reserve_attempt` mit `BEGIN IMMEDIATE`). Eine parallele Salve kommt nicht mehr über die Sperrgrenze.
- **Keine Fremd-Aussperrung mehr (R7-6/H-8):** Die erste Schwelle des Login-Lockouts gilt je Paar aus Konto und IP (`max_login_attempts`). Je Konto gilt über alle IPs eine höhere Schwelle (neu: `account_attempt_factor`, Vorgabe 3). Ein einzelner Fremder sperrt den Inhaber nicht mehr aus, verteiltes Raten bleibt begrenzt. **Verhaltensänderung.**
- **Konto-Schwelle zählt unter der gefalteten Kennung (R7-6/H-8, Nachprüfung):** Gezählt wurde unter der roh eingetippten Kennung. Varianten wie `' opfer'` oder `'OPFER\t'` trafen dasselbe Konto, füllten aber je einen eigenen Zähler, und die Konto-Schwelle band damit nichts. Jetzt zählen, räumen und entsperren (`tinysesam unlock`) alle Wege unter derselben Kennung, getrimmt und klein (`norm_kennung`).
- **Bereichs-PIN (R7-3):** je IP `resource_max_attempts`, je Bereich das `account_attempt_factor`-fache davon. Ein Fremder sperrt einen Bereich nicht mehr für alle. **Verhaltensänderung.**
- **Volle Anmeldung räumt alle Anmelde-Fehlversuche (R7-1):** neu `sperre_aufheben()`, für Benutzername und E-Mail. Die eigenen Töpfe von Kontoseite, Step-up und Bereich bleiben stehen.
- **Reset hebt die Passwort-Sperre auf (R4-13/H-10):** Die Zahl steht im Audit-Log, TOTP- und PIN-Fehlversuche bleiben stehen.
- **Redis-Ausfall (B6-1, B6-2):** Rückfall auf einen In-Memory-Limiter statt „alles erlauben“, Ping beim Start, je eine Meldung für Ausfall und Rückkehr, Pause nach einem Fehler, kurze Socket-Timeouts.
- **In-Memory-RateLimiter gedeckelt (R7-5):** höchstens `max_keys` Schlüssel (LRU).
- **`/auth/claim-admin` gedrosselt (B5-16):** Fehlgriffe landen im Audit-Log (`admin_claim_fail`) und im Sicherheits-Log als `failed verification`.
- `is_pin_locked` meldet seine Abweisung. Die Bereichs-PIN schreibt `grund=falsches_bereichsgeheimnis` statt `kein_konto`.

#### Passwort und Faktoren

**Geändert — Passwortregel an jeder Setzstelle (T-13: B2-5/H-17, R4-07, B2-13; Nacharbeit A-3, A-5, A-6, A-7)**
- **Neue Passwörter werden überall gegen eine offline geführte Blockliste geprüft.** Das gilt für Registrierung, Reset, Kontoseite, Admin-Panel und `tinysesam passwd`. Abgelehnt werden bekannte Passwörter (auch aufgehübscht, z.B. `Passwort2026!`) und triviale Muster: Wiederholungen, Zähl- und Tastaturreihen, auch absteigend, mit Umbruch oder zusammengesetzt (`0987654321`, `12341234`, `asdfasdf`, `11112222`, `qwerasdf`). Ebenso Kontextwörter: `rp_name`, Benutzername und Namensteil der E-Mail, **auch in ihren Teilen** (`Mustermann1990!` für `max.mustermann@…`). Zusammensetzungsregeln gibt es keine (NIST SP 800-63B). **Verhaltensänderung:** Bisher angenommene schwache Passwörter werden jetzt mit 400 abgelehnt. Das Admin-Panel prüfte bis dahin gar nicht.
- **Höchstlänge 256 Zeichen** für neue Passwörter an allen Setzstellen (R4-07).
- **Neu: `password_blocklist_file`**, eine eigene Blockliste (ein Passwort je Zeile, `#` = Kommentar). Zeilen, die kein UTF-8 sind, werden als Latin-1 gelesen. Gemischte Leak-Listen wie `rockyou.txt` laden damit, statt den Start abzubrechen. Eine fehlende oder unlesbare Datei bricht den Start mit `ConfigError` ab.
- **`tinysesam passwd` hält dieselbe Regel ein:** Neu sind `--blocklist-file` und `--rp-name`, weil das CLI keine Config liest.

**Hinzugefügt — Benachrichtigung bei Faktor-Änderungen (T-13: B2-2/H-6)**
- **`auth.on_security_event = hook`**, Aufruf als `hook(ereignis, konto, details)` für `password_changed`, `pin_set`, `pin_disabled`, `totp_enabled`, `totp_disabled`, `recovery_codes_generated`, `recovery_code_used` (mit Rest), `passkey_added`, `passkey_removed` und `api_key_created`. Opt-in, TinySesam verschickt selbst nichts. Ein Fehler im Hook macht die Änderung nicht rückgängig, landet aber im Sicherheits-Log. Beschrieben in SECURITY.md.

**Geändert — TOTP-Einrichtung (T-13: B2-3, B2-12/R3-6; Nacharbeit A-1, A-4)**
- **Der Einrichtungscode gilt genau einmal.** Nach der Bestätigung meldet er an `/auth/totp` nicht mehr an. **Verhaltensänderung für Integratoren:** Tests, die `totp_confirm(uid, now())` und danach `verify_totp(uid, now())` mit demselben Code rufen, werden rot. Dort mit dem Code des vorigen Zeitschritts bestätigen.
- **Pflicht-Einrichtung unter `login_chain=["password","totp"]`:** Die Bestätigung schließt den TOTP-Schritt der Anmeldung gleich mit ab (neues Sitzungs-Token, JSON `{"ok": true, "next": …}`), und die Seite leitet zum Ziel weiter. `next` wandert durch die Einrichtung. Vorher hätte der verbrauchte Code an `/auth/totp` den Login-Lockout und die fail2ban-Jail gefüttert.
- **`POST /auth/totp/setup`** ist gedrosselt, hat einen eigenen Sperrtopf (`totp_setup_max_attempts`, getrennt vom Login-Lockout) und protokolliert (Audit `totp_enable`). Bei schon bestätigtem TOTP antwortet er mit **409** wie GET und `/start`. `totp_confirm` lehnt ein bestätigtes TOTP ab: kein falsches `totp_enabled`, kein zweiter Code-Prüfer.

**Geändert — Recovery-Codes und Reset (T-13: B2-7, R4-14; Nacharbeit A-8)**
- Ein verbrauchter Recovery-Code erzeugt die Audit-Zeile `recovery_used` mit Rest, eine Sicherheits-Log-Zeile und das Ereignis `recovery_code_used`. Die Kontoseite zeigt den Rest und warnt ab drei.
- **Der Passwort-Reset per Mail widerruft die API-Keys** wie der Admin-Reset (Verhaltensänderung).
- `POST /auth/reset` prüft den Link vor der Passwortregel. Ein ungültiger oder abgelaufener Link meldet sofort „Link ungültig“ statt „Passwort zu leicht“.

**Sicherheit — bekannte Grenze (T-13: H-14/H-15)**
- TOTP-Geheimnisse liegen unverschlüsselt in der Datenbank. Das ist jetzt in SECURITY.md als Grenze beschrieben, mit Betriebsempfehlung. Die Verschlüsselung selbst ist zurückgestellt.

#### Audit und Forensik

- **Audit-Log: wer, von wo, was genau (T-13).** `audit()` ergänzt IP und angemeldetes Konto aus der laufenden Anfrage. TOTP-, Recovery-, PIN-, Key-, Reset- und Verify-Zeilen nennen deshalb Konto und IP, und `tinysesam audit --user X` findet sie (B5-02). Wenn ein Admin im Panel einen Key anlegt oder widerruft oder eine Einladung verschickt, steht `akteur=<admin>` samt IP im Log (B5-04, R6-3). Wird ein Key benutzt, entsteht `apikey_use` (gedrosselt je Key, IP und Stunde); wird er abgewiesen, entsteht `apikey_denied` mit Grund und eine seclog-Zeile. Das gilt auch an POST-Routen mit CSRF-Ausnahme (B5-05). `totp_enable` wird beim Bestätigen geschrieben, `recovery_used` mit Restzahl beim Einlösen (B5-07). `user_roles` und `security_update` protokollieren den Stand vorher → nachher (R6-7). Wer Audit-Log oder Sitzungsliste im Panel liest, hinterlässt selbst eine Zeile (B5-12).
- **Log-Injection geschlossen (B5-06, B5-14).** `tinysesam audit` und der Logger `tinysesam.security` machen Steuerzeichen in jedem Argument unschädlich. Das umfasst C0, DEL, C1 (NEL, CSI), U+2028/U+2029 und Bidi-Steuerzeichen.
- **Die ip-Spalte enthält eine IP (B5-15).** `X-Forwarded-For` wird nur als gültige, kanonische Adresse übernommen, eine IPv6-Zonenangabe (`%…`) fällt dabei weg. Wer über einen durchreichenden Proxy die Zone je Anfrage wechselt, entgeht damit weder Rate-Limit noch IP-Sperre.
- **Abgewiesene Forward-Auth (B5-17).** Eine 401 mit ungültigem Nachweis erzeugt gedrosselt `forward_denied`. `forward_denied` und `forward_role_denied` schreiben die URL ohne Query und Fragment (`?…`), damit Freigabe-Token und Codes nicht im Log landen.
- **Aufbewahrung und Löschen (B5-11, H-13).** Neu sind `audit_retention_days` (greift über `gc()` und `tinysesam gc --audit-days N`) und `audit_ip_pseudonymize` (kürzt auf /24 bzw. /48). `delete_user` ersetzt das Konto im Audit-Log durch `gelöscht#<id>`: in der Spalte `username`, auch bei Anmeldeversuchen unter der E-Mail-Adresse (deren Versuchszeilen werden gelöscht), außerdem bei `akteur=` und bei der Adresse im Detailtext. Gleichnamige Wörter in fremden Zeilen, etwa `admin=0->1`, bleiben stehen.
- **Panel: fremde Passkeys widerrufen, Konten löschen (B5-08).** Das eigene Konto und der letzte Admin lassen sich nicht löschen.
- **Kontoseite: letzte Ereignisse (H-7).** Die Liste zeigt Zeit, Ereignis und IP, aber keinen Detailtext. Hat ein Admin das Ereignis ausgelöst, steht dort „durch einen Administrator“ statt seiner IP.

#### Admin und Konfigurationsprüfung

**Sicherheit**

- **Admin-Panel: Der letzte aktive Admin lässt sich nicht mehr entmachten** (R6-1). Die Anfrage bekommt 400. Gesperrte Konten und Service-Konten zählen nicht als „anderer Admin“.
- **Kein Admin-Service-Konto mehr über das Panel** (R6-2). Beim Anlegen und über die Rollen-Route gibt es 400, vorher wurde das still verworfen bzw. still gesetzt.
- **Härtungs-Schwellen haben Grenzen** (R6-4, B2-9, `security.SECURITY_GRENZEN`). Bisher konnte ein Tippfehler die Instanz dauerhaft stilllegen, etwa `rate_limit_max=0` (jede Anmeldung abgewiesen, auch die zum Zurückdrehen) oder `max_login_attempts=0`. Das Panel prüft jetzt nach dem Prinzip alles oder nichts. Die Grenzen verbieten das Stilllegen, nicht das Verschärfen: Versuchszähler ab 1, `lockout_window_sec` 60 s bis 30 Tage, `rate_limit_max` ab 3, `rate_limit_window_sec` bis 1 Tag, `password_min_length` 8 bis 128.
  **Verhaltensänderung:** `set_security()` wirft bei unbekanntem Schlüssel oder Wert ausserhalb der Grenzen `ConfigError`. Bis 0.19.x fiel ein unbekannter Schlüssel still weg, und jeder Wert wurde übernommen. Ein Altwert in der Datenbank jenseits der Grenzen wird **an die nächste Grenze gezogen**, nicht auf die Vorgabe gesetzt. So lockert ein Upgrade keine strengere Einstellung, nur ein unlesbarer Wert fällt auf die Vorgabe. Beim ersten Lesen steht dazu eine Zeile im Security-Log. `Infinity` im Panel ergibt 400 statt 500.
- **Ein API-Key mintet keinen Key mehr** (R6-6). Die Panel-Key-Route verlangt eine Sitzung. Das Admin-Flag fällt bei jeder Key-Art ausser `mensch` weg (fail-closed), vorher nur bei `automat`.
- **Unbrauchbarer Scope oder Ablauf beim Key-Anlegen ergibt 400 mit Grund statt HTTP 500** (R6-8), im Panel wie unter `/auth/apikeys`.
- **Login-URL am Forward-Auth** (R5-1): Bei `cookie_secure=True` stuft `X-Forwarded-Proto: http` das Schema nicht mehr herab (ausser Loopback). Eine Benutzerangabe aus `X-Original-URL` (`https://fremd.example@app.example.com`) landet nicht mehr vor dem Host.
- **`trusted_proxies`: Ein ungültiger Eintrag entwertet nicht mehr die ganze Liste** (B3-3). Jeder Eintrag wird einzeln geprüft, und die Konfigurationsprüfung weist Hostnamen und Tippfehler ab.
- **Nachträgliche Config-Änderungen werden vor dem Routenbau geprüft** (B3-14, A2). `router()` und `admin_router()` prüfen alles erneut, was den Konstruktor hätte scheitern lassen: `konfigpruefung`, Cookie-Felder und die Riegel des Konstruktors (`admin_identifiers` neben offener Registrierung/Auto-Anlage, `login_identifier`, `forward_headers`, `totp_required`). Vorher baute zum Beispiel `auth.cfg.allow_signup = True` nach dem Konstruktor neben `admin_identifiers=["chef"]` einen Router, in dem sich der erste Besucher als Erst-Admin registrierte. `pruefen()` liefert weiter eine Liste.

**Geändert**

- **Neue Konfigurationsfehler, die bestehende Configs am Start scheitern lassen können. Vor dem Upgrade prüfen:**
  - `stepup_methods` mit einem unbekannten Verfahren (`"topt"`) oder einem abgeschalteten (`"pin"` ohne `pin_enabled`) (B3-6). Vorher fiel die Bestätigung still auf das Passwort zurück.
  - `trusted_proxies` mit einem Eintrag, der kein IP-Netz ist (B3-3).
  - `passkey_enabled`: `origin` ist kein Origin (Pfad, Schrägstrich am Ende) oder `rp_id` passt nicht dazu (B3-10). Weicht `origin` von `base_url` ab oder stehen noch die Entwicklerwerte da, gibt es eine Warnung. `origin` darf wie bei py_webauthn eine **Liste** sein, jeder Eintrag wird geprüft.
  - Zahlenfelder ausserhalb ihrer Grenzen (B3-12, `konfigpruefung.ZAHLENGRENZEN`), zum Beispiel `session_ttl_hours=0`, `magiclink_ttl_min=0`, `recovery_code_count=0` oder ein negatives `stepup_max_age_sec`. `True` statt einer Zahl ist ebenfalls ein Fehler, und **Text statt Zahl auch**: `smtp_port="587"`, etwa direkt aus einer Umgebungsvariable, bricht den Aufbau jetzt mit „ist keine ganze Zahl“ ab. In 0.19.0 baute Text in diesen Feldern noch, neu brechen also: `pin_min_length`, `apikey_default_days`, `resource_unlock_ttl_hours`, `magiclink_ttl_min`, `smtp_port`, `smtp_timeout`, `recovery_code_count`, `mfa_enrollment_grace_days`, `stepup_max_age_sec`, `session_ttl_hours`, `session_ttl_transient_hours` und `oidc_revalidate_minutes`, also jedes Feld in `ZAHLENGRENZEN` bis auf zwei. `admin_claim_ttl_min` scheiterte schon in 0.19.0 mit einem `TypeError` statt einer Meldung (außer mit `admin_enabled=False`), und `audit_retention_days` ist neu. → **Zu tun:** vorher selbst umwandeln, `smtp_port=int(os.environ["SMTP_PORT"])`. Das mitgelieferte Gateway wandelt seine Umgebungsvariablen schon um.
  - `signup_verify_email=True` ohne `signup_require_email=True` (B3-16). Wer keine Adresse angab, war ohne Bestätigung sofort aktiv. Ebenfalls Fehler: `cookie_domain`, die den Host von `base_url` nicht umfasst, und `admin_path`/`login_path`/`oidc_callback_path` ohne führendes `/`. Warnungen gibt es für vertauschte Sitzungsdauern und für `signup_invite_only` ohne `allow_signup`.
  - `demo_mode=True` neben OIDC/SAML/LDAP/Forward-Auth und auf einer Datenbank mit Bestandskonten, die nie eine Demo war (B3-8). Eine echte Demo startet weiter, auch mit registrierten Besuchern.
- **Warnung bei offenem Forward-Auth-Tor** (H-11, B3-9): Auto-Anlage ohne `*_allowed_groups` bzw. ohne `oidc_clients`, oder offene Selbst-Registrierung vor Forward-Auth. Das mitgelieferte Compose und die Gateway-Doku sagen, wo der Kreis begrenzt wird.
- **Wird `base_url` nach dem Konstruktor geleert, antworten die Mail-Routen und die Admin-Einladung mit HTTP 503 statt mit einem ungefangenen 500.** Die 503 kommt aus der Route (`router._mail_basis`). → **Integrator:** Den Absatz „**Der 500 bleibt.** … und die 500 als das, was heute herauskommt“ im Eintrag zu `require_public_base()` (CHANGELOG.md um Zeile 495-500) entsprechend auf 503 korrigieren.

**Doku**

- **KONFIGURATION.md: Beschreibungen verrutschten nicht mehr** (B3-15). Der Generator hängt eingerückte Fortsetzungszeilen an das richtige Feld und entfernt den `#:`-Doppelpunkt. Die Datei ist neu erzeugt, ebenso API.md.

#### Betrieb und Laufzeit

**Geändert**
- **`/healthz` schreibt jetzt, statt nur zu lesen** (B6-4): Eine nur lesbare Datenbank oder eine tote Verbindung meldet **503** `{"status": "degraded"}` statt dauerhaft 200. Wer TinySesam als Bibliothek einbindet, baut denselben Check mit dem neuen `auth.store.schreibprobe()`. Wirklich geschrieben wird höchstens alle 5 s (`Store.SCHREIBPROBE_SEK`), dazwischen prüft die Probe nur die Verbindung. Eine Flut auf den offenen Pfad belegt so nicht die Schreibsperre und nutzt keine SD-Karte ab. Eine gerade nur lesbar gewordene Datenbank fällt spätestens nach 5 s auf.
- **HEALTHCHECK im Abbild wartet 12 s/15 s statt 4 s/5 s**: länger als die Wartezeit auf eine gesperrte Datenbank, damit eine kurze Sperre (Checkpoint, Sicherung) den Container nicht als unhealthy markiert.
- **`busy_timeout` ausdrücklich 10 s** (`Store.BUSY_TIMEOUT_MS`, B6-11) statt der stillen 5 s von Python: Ein zweiter Schreiber lässt eine Anmeldung warten und bricht sie nicht mit `database is locked` ab.
- **Gesperrte Konten bekommen `403 api.account_disabled` statt einer Sitzung** (H-18): Anmelde-Link, Passkey und jeder andere Faktor legen einem gesperrten Konto keine Sitzung mehr an. TOTP macht eine halbe Sitzung nach der Sperre nicht mehr vollwertig. Die Sperre im Panel verwirft offene Einmal-Token (neu: `Store.revoke_user_magic_tokens()`), ein alter Bestätigungslink hebt sie also nicht mehr auf.
- **Monotone Zeitquelle für alle Fristen in der Datenbank** (B6-9, neu: `tinysesam.store.jetzt()`): Springt die Systemuhr zurück (NTP, Pi ohne Pufferbatterie, VM-Snapshot), leben abgelaufene Sitzungen, Einmal-Token und Step-ups nicht mehr auf. Über einen Neustart trägt die Datenbank den Stand: Sie sichert ihn höchstens jede Minute im Setting `uhr_stand`. Grenze: Was in der letzten Minute vor dem Neustart ablief oder während einer Ruhezeit ganz ohne Schreiben, gilt nach einem Boot mit altem Datum wieder, bis die Uhr aufgeholt hat. Sprang die Uhr falsch nach vorn, bleiben Zeitstempel dort, bis die Wanduhr aufholt.
- **Für Tests einbettender Apps:** `time.time` wird bei jedem Aufruf nachgeschlagen und nicht beim Import gebunden. `mock.patch`, `monkeypatch` und freezegun stellen TinySesams Uhr also mit vor. Zurückdrehen lässt sie sich so nicht: Nach dem Entpatchen zählt sie vom vorgestellten Stand weiter, unter freezegun bleibt sie dort, bis die echte Zeit aufholt (der Schutz aus B6-9).
- **Fehlt `[argon2]` zur Laufzeit** (B6-8), nennt der Start die Zahl der betroffenen Hashes samt `pip install 'tinysesam[argon2]'`. Im Betrieb erscheint die Abhilfe einmal je Prozess im Log (neu: `Store.zaehle_argon2_hashes()`).

**Behoben**
- `pop_flow()` gibt WebAuthn-Challenge und OIDC-`state` genau einmal heraus, auch bei zwei gleichzeitigen Callbacks und über Prozessgrenzen hinweg (R3-8).

**Doku**
- Neu: `docs/BETRIEB.md` mit Ausfallverhalten (B6-13), Sitzungs- und Föderationsverwaltung (F-10), Anmeldewegen und ihrer Stärke (B1-11) sowie den offenen ASVS-L3-Punkten (B1-12). `test_repo` prüft die Zahlen der Seite gegen den Code, auch das Verhältnis HEALTHCHECK zu `busy_timeout`.

#### Lieferkette und Veröffentlichung

**Sicherheit**

- **Schwachstellen-Tor in der CI** (B4-2). Der neue Workflow `audit.yml` fährt `pip-audit --strict` über die neueste und über die niedrigste erlaubte Auflösung (`lowest-direct`) aller Extras. Dazu kommt jede gehashte Sperrliste. Er läuft bei jedem PR, auf `main` und nächtlich. Bis 0.19.0 wurde ein PR mit einer verwundbaren Auflösung grün, denn eine Dependabot-Meldung ist kein Tor. Seine eigenen Werkzeuge holt das Tor aus einer gepinnten, gehashten Liste.
- **Die Sperrliste des Abbilds wird auf Vollständigkeit geprüft** (B4-7, Nachprüfung). Das Abbild installiert mit `--no-deps`. Bringt ein Dependabot-Bump eine neue Abhängigkeit mit, fehlt sie in der Liste, und pip merkt das nicht. Das Abbild bräche dann erst beim Start ab. Jetzt laufen `pip check` und der Import im Dockerfile. `audit.yml` fährt dieselben Schritte bei jedem PR auf Python 3.14.
- **Kein pip im Endabbild, wieder wahr.** Seit dem Wechsel auf 3.14 zeigten die Löschpfade noch auf `python3.12`, pip lag also wieder im Abbild. Die Pfade stehen jetzt als Muster da, und ein Test verlangt die Python-Reihe aus dem `FROM`.
- **Wer eine Identität hält, führt keinen fremden Code aus** (B4-4). `release.yml` ist aufgeteilt. Prüfen und Bauen laufen nur mit Leserecht. Release, PyPI und die Beglaubigung des Abbilds laufen ohne Checkout und ohne pip. Bis 0.19.0 lief `pip install ".[all]"` im selben Job, der mit `id-token: write` beglaubigte. Jede Abhängigkeit hätte damit eine Attestation auf die Identität des Workflows ausstellen können. `tests/test_repo.py` liest die Rechte in jeder Schreibweise: Block, Flow-Map, `write-all` und von der Workflow-Ebene geerbt. Solche Jobs dürfen in `run:` nur eine kurze Liste von Befehlen starten, und lokale Actions sind dort verboten.
- **Werkzeuge der Actions in fester Fassung** (B4-6). `setup-qemu` und `setup-buildx` zogen `tonistiigi/binfmt:latest` (läuft privilegiert), `buildkit:buildx-stable-1` und das buildx des Runners. Jetzt ist jedes dieser Werkzeuge mit Version und Digest gepinnt. `build` und `setuptools` kommen aus einer gehashten Liste, und gebaut wird ohne Isolierung.
- **Das Gateway-Abbild ist reproduzierbar** (B4-7). Es installiert aus `deploy/gateway/requirements.txt`, gepinnt samt Hashes und universal für amd64 und arm64. TinySesam selbst wird ohne Netz installiert. Es gibt kein `pip install --upgrade pip` mehr, und der Bau läuft mit `SOURCE_DATE_EPOCH` und `rewrite-timestamp`.
- **Scorecard-Kriterien bewacht** (B4-14). Dangerous-Workflow, Token-Permissions, Pinned-Dependencies (Teil), SAST, Security-Policy, License, Dependency-Update-Tool, CI-Tests und Binary-Artifacts werden offline geprüft. Der Injektions-Wächter prüft jeden `${{ … }}`-Ausdruck, der `github.event` oder `github.head_ref` anfasst. Das gilt auch innerhalb von `toJSON()` oder `format()` und im `script:` von `actions/github-script`.

**Geändert**

- **Verhaltensänderung: Der Referenz-Stack ist gehärtet** (B4-11). `deploy/forward-auth/docker-compose.yml` pinnt Caddy auf Version und Digest statt auf `caddy:2`. Beide Dienste laufen `read_only`, mit `cap_drop: [ALL]` und `no-new-privileges`. Caddy bekommt nur `NET_BIND_SERVICE` zurück. → **Zu tun**, wenn du das Compose übernommen hast: Alles, was ein Dienst zur Laufzeit schreibt, braucht ein Volume oder ein `tmpfs`. Eigene Zusätze, die weitere Capabilities brauchen, müssen sie ausdrücklich zurückholen.
- **Wheel und sdist sind bit-reproduzierbar** (B4-8). Beide Artefakte werden mit `SOURCE_DATE_EPOCH` = Zeitstempel des Commits gebaut und danach mit `scripts/_artefakte_normalisieren.py` normalisiert. Das sdist bekommt feste Zeitstempel, Reihenfolge, Eigentümer, Rechte und einen festen gzip-Kopf. Im Wheel werden die Dateirechte festgelegt, denn setuptools übernimmt sonst die umask des Checkouts (0002 auf Ubuntu/Mint, 0022 auf dem Runner). Nachbauen geht so: dieselben Schritte auf dem Tag ausführen, dann `sha256sum -c SHA256SUMS`.
- **Dependabot hebt, was gepinnt ist** (B4-3, B4-12). Der pip-Eintrag für `/` war wirkungslos, weil Dependabot offene `>=`-Böden nie anhebt. Er ist ersetzt durch Einträge für die gehashten Sperrlisten und für den Compose-Stack. Die Böden prüft jetzt das Audit-Tor.
- **Das sdist enthält nichts Gitignoriertes mehr** (B4-13). `MANIFEST.in` spiegelt `.gitignore`. Vorher landete bei `python -m build` aus einem benutzten Arbeitsbaum zum Beispiel eine `examples/app.db` oder eine `.env` im Paket.
- **`SECURITY.md` nennt erreichbare Meldewege und Fristen** (B4-10). Es gibt zwei Wege: das private Advisory und eine E-Mail für alle ohne GitHub-Konto. Die Fristen lauten 7, 14 und 90 Tage, in beiden Sprachen gleich.

### Sicherheit — T-13: Angriff auf die Integration

Die zehn Zweige wurden zusammengeführt und danach selbst angegriffen: 18 Funde an den Nahtstellen,
je zweifach nachgestellt, behoben; die Fixes wurden erneut angegriffen und nachgebessert. Was
davon beim Update zählt:

- **Sperren:** Die Kontosperre zählt Unicode-Schreibweisen einer Adresse zusammen (NFKC, IDNA —
  vorher gab es für `victim@example.com` 2^16 Töpfe). Die TOTP-Einrichtung prüft und bucht in
  einem Schritt. Ein Verzeichnis-Ausfall wird 30 s lang nicht erneut gefragt
  (`ldap_.AUSFALL_PAUSE_SEK`), danach fragt genau eine Anmeldung nach; so schweben vorgebuchte
  Versuche nicht mehr bis zum Timeout. LDAP-Eingaben über 256 (Name) bzw. 1024 Zeichen
  (Passwort) gehen nicht mehr ans Verzeichnis. Ein gescheiterter Schreibzugriff (etwa die
  Schreibprobe von `/healthz`) lässt keine offene Transaktion mehr zurück, die jede Anmeldung mit
  500 beantwortete.
- **Ein Löschweg:** `gc()`, `tinysesam gc`, die Rücknahme einer Registrierung und `delete_user`
  laufen über `Store.konto_entfernen`: Audit-Log anonymisiert, Anmeldeversuche weg — aber nur,
  was ab der Anlage des Kontos entstand. Namensvetter wie `Émile`/`émile` gelten als vergeben.
  Die Topf-Prüfung dafür ist indiziert (Schema 10); in der ersten Fassung machte sie die
  Registrierung zum Laufzeit-Orakel für vergebene Adressen.
- **Admin:** Der Widerruf eines fremden Passkeys meldet `passkey_removed`
  (`auth.remove_passkey`). Rollen werden vor dem Schreiben geprüft (`roles=[1]` gab ein Admin-Flag
  ohne Audit-Zeile). Das Panel zeigt den Grund einer Abweisung an, statt „gespeichert" zu melden.
  Sperren im Panel tragen den Betreiber-Vermerk (`disabled=2`); kein Bestätigungslink hebt sie
  auf, auch keiner, der erst danach entsteht, und die Migration hebt Sperren aus 0.19.x mit
  offenem Link darauf (soweit das Audit-Log sie noch kennt).
- **Spuren:** Ungültige Token an `POST /auth/reset` und `GET /auth/register?invite=` schreiben
  wieder `token_invalid` / `failed verification`.
- **Sitzung:** Der Step-up über `POST /auth/totp` dreht das Token (F-06). Die Herkunftsprüfung
  weist über HTTPS `Origin: null` aus der Nachbarschaft ab; über HTTP senden Browser kein
  `Sec-Fetch-Site`, dort entscheidet allein das Token. Cookies unter den Altnamen von vor
  `__Host-` löscht jede eingebaute Route, die die Sitzung schreibt, dazu `auth.logout()` und
  `auth.rotate_session()`. Die nginx-Vorlagen filtern zwölf TinySesam-Cookies und geben bei mehr
  gar keinen Cookie weiter (fail closed) — **Zu tun:** übernommene `map`-Zeilen nachziehen.
- **Konfiguration:** Grenzen für `audit_retention_days` (0–3660) und `oidc_revalidate_minutes`
  (0–43200, Warnung über 1440); `tinysesam gc` prüft Fristen vor dem ersten Löschschritt;
  `tinysesam passwd` liest die Mindestlänge über denselben Weg wie das Web
  (`security.haertung_lesen`). Der Bestätigungstoken entsteht in der Anfrage, nur der Versand
  wartet.
- **Bekannte Grenzen** (SECURITY.md, BETRIEB.md, Backlog T-13): Mit `cookie_domain`,
  `cookie_host_prefix=False`, anderem `cookie_path` oder über HTTP kann jeder Host unter der
  Domain ein Sitzungs-Cookie unterschieben. In einer Kette `password → totp → pin` entfällt das
  Angebot, die übrigen Sitzungen zu beenden. Im ersten Fenster eines LDAP-Ausfalls schweben
  Versuche weiter bis zum Timeout. API-Keys melden `on_security_event` nur bei der Anlage.
- **Tests:** Fehlt `node`, ist das rot statt still übersprungen (`TINYSESAM_OHNE_NODE=1` als
  sichtbares Opt-out). Die Wächter über Transaktionen, Settings-Zugriffe, Zahlenfelder und
  Löschwege erkennen die Klasse statt einer Schreibweise und tragen je eine Selbstprobe.

## [0.19.0] — 2026-09-22

**Sicherheits-Release.** Das dritte Audit (Red/Blue, 139 bestätigte Befunde) hatte 16 Punkte als
Blocker für 1.0 benannt; diese Fassung schliesst sie bis auf die drei, die LDAP und SAML betreffen
(F-11, F-12, F-16 — sie stehen in T-13 und brauchen eine Migration der Identitätsbindung). Dazu
kommt T-14: mehrere Anwendungen hinter **einer** Installation, mit einer Freigabe je Anwendung,
die dem Identity Provider folgt.

**Die Datenbank wandert von Schema 5 auf 8.** Sicherung vor dem Update ziehen — ein Rückschritt
auf 0.18.x braucht sie (`tinysesam backup`).


**Verhaltensänderungen in dieser Runde.** Sechs Punkte ändern, was eine bestehende Installation
tut — je Punkt steht dahinter, was zu tun ist; die Begründung steht weiter unten bei dem Befund,
aus dem der Punkt kommt.

1. **`base_url` ist Pflicht**, sobald ein Mail-Weg (`magiclink_enabled`, `password_reset_enabled`,
   `signup_verify_email`), `oidc_enabled` oder `saml_enabled` an ist. Aus der Warnung ist ein
   **Fehler** geworden: Die Instanz startet sonst nicht mehr. → **Zu tun:** die öffentliche
   Adresse dieser App eintragen (`base_url="https://auth.example.com"`, lokal
   `"http://127.0.0.1:8000"`, unter einem Unterpfad mit Präfix `"https://example.com/sso"`). Die
   Fehlermeldung beim Start nennt genau das. Wer die Basis selbst übergibt, nimmt sie ab jetzt aus
   `auth.public_base(request)`, nicht aus dem Request.
2. **Eine E-Mail-Adresse trägt eine Rechte-Entscheidung nur noch mit Beleg** (neue Spalte
   `users.email_verified`, Schema 5). Über OIDC zählt der Claim `email_verified`, über SAML und
   LDAP gibt es keinen — dort befördert eine Adresse aus `admin_identifiers` nie mehr.
   → **Zu tun:** Bestandskonten sind nicht betroffen (`ALTER TABLE … DEFAULT 1`). Wer den
   Erst-Admin bisher über `admin_identifiers` + SAML/LDAP setzte, nimmt `/auth/claim-admin` und
   danach das Gruppen-Mapping. Wer einen IdP fährt, der den optionalen Claim nie schickt (Entra ID),
   und seine Adressen selbst verantwortet, setzt `oidc_email_verified_default=True`.
3. **Die Selbstverwaltung der Faktoren steht hinter Step-up.** `totp/disable`, `totp/recovery`,
   `pin/set`, `pin/disable`, `passkey/delete` verlangen eine frisch bestätigte Sitzung.
   (Korrektur 0.20.1: Hier stand, seit dem Nachschlag verlange auch die **Anlage**
   (`totp/setup`, `passkey/register/*`) eine frisch bestätigte Sitzung. Das stimmte nie — der Code
   verlangt dort eine interaktive Sitzung (`require_session()`, kein API-Key), aber keine frische
   Bestätigung; so steht es auch im Befund zur Faktor-Anlage weiter unten.)
   → **Zu tun:** nichts konfigurieren; wer eine **eigene** Konto-Seite baut, wertet den Hinweis-Header
   `X-TinySesam-Reauth` aus und schickt auf `/auth/reauth`, sonst scheitern die Knöpfe stumm mit 403.
4. **Ein API-Key kommt auf diese Routen nicht mehr** — er ist ein Maschinen-Credential und erbringt
   nie einen interaktiven Faktor; die Antwort ist **403**. → **Zu tun:** Automatisierung, die bisher
   per Key Faktoren setzte oder abbaute, auf einen anderen Weg legen (Admin-API bzw. Datenbank). Ein
   abgeflossener CI-Key kann dafür im Gegenzug nichts mehr.
5. **Die Untergrenzen der Abhängigkeiten sind gehoben** — `fastapi>=0.133.0`,
   `python-multipart>=0.0.31`, `authlib>=1.6.12`, ohne obere Schranken. → **Zu tun:** wer Versionen
   festhält (Lockfile, Constraints, Distributionspaket), zieht sie nach; mit `authlib 1.3.0` war ein
   gefälschtes ID-Token möglich.
6. **Fehlversuche zählen in eigene Töpfe statt in den Login-Topf.** Passwortwechsel, Step-up-
   Bestätigung und Bereichs-PIN haben eigene Schwellen (`password_change_max_attempts`,
   `reauth_max_attempts`, `resource_max_attempts`, je 5); ihre Log-Zeilen tragen das eigene Wort
   `failed verification` und treffen die mitgelieferte fail2ban-Jail **nicht** mehr.
   → **Zu tun:** wer die Jail einsetzt, übernimmt die aktualisierte
   `deploy/fail2ban/tinysesam-filter.conf`; wer auch diese Fehlgriffe bannen will, nimmt zusätzlich
   `tinysesam-verify-filter.conf` samt der milderen, standardmässig abgeschalteten Jail.

⚠️ **Für einbettende Apps** kommen zwei Änderungen an dokumentierten Methoden dazu: `create_user()`
wirft beim doppelten **Benutzernamen** jetzt `ConfigError` statt `sqlite3.IntegrityError`, und
`store.set_email()` schreibt den Bestätigungs-Vermerk mit, vorgabegemäss **unbestätigt**
(`verified=True` für den belegten Fall). Beides steht unten bei seinem Befund.

**Doku-Abgleich: 70 Stellen, an denen die Doku etwas anderes sagte als der Code.** Sieben Flächen
wurden gegen die Wirklichkeit gemessen — beide READMEs, CHANGELOG, Docstrings, `deploy/`, `web/`,
Backlog. Der Befund war nicht, dass Sätze veraltet klangen: **Zehn der Stellen waren Mängel im
Code oder in einer ausgelieferten Vorlage**, die nur deshalb sichtbar wurden, weil jemand die
Zusage daneben gelesen hat. Die stehen unter „Behoben" und „Sicherheit".

### Behoben — 0.18.0 hätte jede scrypt-Installation ausgesperrt

**Wer TinySesam ohne das Extra `[argon2]` betreibt, konnte sich nach dem Update auf 0.18.0 nicht
mehr anmelden.** Das Hash-Format `scrypt$salt$dk` trug seine Parameter nicht mit, und 0.18.0 hob
`p` von 1 auf 3 (OWASP): `verify_password` rechnete jeden Bestandshash mit dem neuen Wert nach und
kam auf ein anderes Ergebnis. Kein Fehler, keine Meldung — nur „Passwort stimmt nicht", für jedes
Konto gleichzeitig. Das neue Format `scrypt$n$r$p$salt$dk` nennt die Parameter; das alte wird mit
den Werten von damals nachgerechnet und beim nächsten Login still auf die heutigen gehoben.
Getroffen hätte es genau die Installationen, für die der Fallback gebaut ist.

### Behoben

- **`login_chain=["password","totp"]` war für Konten ohne TOTP eine Sackgasse.** Das richtige
  Passwort führte auf `/auth/totp`, das mangels Geheimnis auf die Login-Seite zurückleitete — und
  die Einrichtungsseite verlangte einen voll angemeldeten Nutzer, den es unter dieser Kette nie
  geben kann. Weder herein noch an die Einrichtung; der Betreiber musste an die Datenbank. Jetzt
  führt der Weg zur Einrichtung (neu: `auth.totp_enrollment_user(request)`). Wer dort steht, hat
  seinen Erstfaktor bereits erbracht; angemeldet ist er erst nach einem Code aus dem neuen Geheimnis.
- **Die Migration liess Klartext-Freigaben liegen.** Die Bereinigung von `resource_unlock` hing an
  `0 < PRAGMA user_version < 4` — der Stempel kam selbst erst mit 0.18.0, eine Bestandsdatei trägt
  dort die 0. Die Bedingung war also in genau dem Fall falsch, für den sie geschrieben war. Erkannt
  wird jetzt am Wert, nicht am Stempel.
- **`tinysesam audit --user NAME` fand die Einträge oft nicht.** Gefiltert wurde nicht in SQL,
  sondern in den jüngsten Zeilen nachgesiebt: Eine Brute-Force-Welle schob das Gesuchte aus dem
  Fenster, und das Kommando meldete „Keine Einträge zu 'X'." samt Exit 0 — im Anlassfall.
- **Die mitgelieferte Caddy-Vorlage schützte nichts.** `reverse_proxy /auth/forward <upstream>`
  ist in Caddy ein **Pfad-Matcher**, kein Rewrite: Die Auth-Prüfung lief nur für Anfragen auf
  `/auth/forward`, jeder andere Pfad fiel direkt auf die App durch. Jetzt `rewrite /auth/forward`
  im Block, wie in Caddys eigener Expansion von `forward_auth`.
- **Der Login-Redirect der Caddy-Vorlage zeigte ins Leere.** `{rp.header.X-TinySesam-Location}`
  fand nichts: Caddy legt Antwort-Header unter dem Go-kanonischen Namen ab
  (`X-Tinysesam-Location`), und der Platzhalter wird Zeichen für Zeichen gesucht. Ergebnis war eine
  302 mit leerem `Location`.
- **`deploy/forward-auth/docker-compose.yml` ergab einen Stack, der nicht läuft.** Die eingehängte
  Caddyfile zeigte auf `127.0.0.1:8000` — im Caddy-Container lauscht dort nichts. Die Upstreams
  kommen jetzt aus der Umgebung; das Compose setzt die Service-Namen.
- **Der `HEALTHCHECK` des Abbilds folgte Redirects**, obwohl der Kommentar daneben das Gegenteil
  behauptete: `urlopen` bringt den Redirect-Handler im Standard-Opener mit und meldete den Status
  des Umleitungsziels. Jetzt über `http.client`, das von sich aus nie umleitet.
- **`Documentation=` in `tinysesam-gc.service` verwarf systemd still** — der Umlaut im URL-Anker
  machte die Zeile ungültig.
- **Der Quickstart beider READMEs baute nicht mehr.** Der erste Block, den ein neuer Nutzer
  kopiert, schaltet `oidc_enabled=True` und setzte kein `base_url` — seit der Verschärfung weiter
  unten ist genau das ein `ConfigError` im Konstruktor. Die Regel kam, das Beispiel blieb stehen:
  dieselbe Klasse Fehler wie `pip install tinysesam`, die erste Zeile, die jemand ausprobiert,
  war die erste, die fehlschlug. `base_url` steht jetzt in beiden Beispielen, mit dem Satz warum.
  Damit das nicht wieder passiert, **baut die Hygiene jedes Konfig-Beispiel beider READMEs** und
  führt die vollständigen Blöcke in einem Wegwerf-Verzeichnis aus (`tests/test_repo.py`) — bisher
  maß sie nur Zahlen im Text, nicht, ob ein Beispiel läuft.
- **Zwei Betreiber-Meldungen nannten Wege, die es nicht gibt.** Der neue Kollisions-Wächter beim
  Start riet „Eine der beiden Kennungen ändern (Admin-Panel oder CLI)" — keins von beiden kann
  das: Die Admin-API kennt Anlegen, Sperren, Rollen, Passwort und Keys, aber kein Umbenennen, und
  das CLI legt überhaupt keine Konten an. Genannt wird jetzt, was existiert
  (`store.set_email(…)`, sonst die Datenbank) — samt der Nebenwirkung, die dieser Weg seit dem
  Punkt zu `set_email()` weiter unten hat: Die neue Adresse wird **unbestätigt** abgelegt
  (`users.email_verified=0`), wer einen Beleg für sie hat, übergibt `verified=True`. Ebenso in
  der Konfigurationsprüfung: „Der
  Erst-Admin kommt dann nur über `admin_identifiers` oder die CLI zustande" → `ensure_admin()`
  im eigenen Dienst. Es ist dieselbe falsche CLI-Zusage, die dieser Eintrag an anderer Stelle
  schon einmal zurückgenommen hat.

### Sicherheit

- **Ein Passkey muss den Menschen prüfen, nicht nur den Schlüssel** (`passkey_user_verification`,
  Vorgabe `"required"`, B2-10). Ein Passkey meldet in TinySesam **allein** an — er ist kein zweiter
  Faktor, sondern ein vollständiger Login. Ohne Nutzerprüfung belegt er nur den **Besitz**: der
  entsperrte Rechner, der eingesteckte Stick, das kurz aus der Hand gelegte Telefon genügen dann.

  Bis 0.18.x stand in der Anfrage `preferred` **und** die Antwort wurde nicht einmal geprüft
  (`require_user_verification=False`) — ein Authenticator konnte also nein sagen und galt trotzdem.
  Die Bitte war in beide Richtungen unverbindlich. Jetzt wird sie verlangt und geprüft.
  `"preferred"` bleibt möglich für einen Bestand alter Authentikatoren, meldet sich aber beim
  Aufbau und in der Konfigurationsprüfung.

- **Der Passkey-Pfad ist gedrosselt und hinterlässt Spuren** (B2-10, B5-01). Er war die einzige
  Anmeldestrecke ohne Bremse, und jeder Aufruf von `login/begin` legte eine `flow`-Zeile an, die
  erst nach fünf Minuten verfiel — ein bequemer Weg, die Datenbank wachsen zu lassen. Protokolliert
  wurde gar nichts: weder die Anlage eines Passkeys (ein neuer vollwertiger Login-Weg am Konto),
  noch seine Löschung, noch eine Fehlanmeldung. Wer hier durchprobierte, tat das unbeobachtet.
  Jetzt zählt der Rate-Limit-Topf mit, und Anlage, Löschung und Fehlversuch stehen im Audit-Log;
  der Fehlversuch trägt zusätzlich das Ereigniswort, auf das die fail2ban-Jail matcht — er **ist**
  einer.

- **Zwei Arten API-Key, und keine davon ist mehr eine Admin-API** (`kind`, R6-5). Ein Key war
  bisher eine vollständige Schreib-Schnittstelle im Namen seines Besitzers. Bei einem Admin hiess
  das: Nutzer anlegen, `is_admin` setzen, Passwörter zurücksetzen, Schwellen ändern — ohne zweiten
  Faktor und ohne die CSRF-Schicht, weil für einen Key beides nicht greift. Ein abgeflossener
  CI-Key war die Instanz. Der vorhandene Rollen-Scope half nicht: Er verengt die **Rollen**, das
  Admin-Flag kommt aus der Kontozeile und blieb unberührt.

  Jetzt sagt ein Key, was er ist. `kind="automat"` (Vorgabe) arbeitet allein, trägt aber **nie
  das Admin-Flag** seines Besitzers und erfüllt keine Route, die Admin verlangt — der Weg für
  Dienste, Skripte und CI. `kind="mensch"` gilt **nur zusammen mit einer gültigen Sitzung
  desselben Kontos** und trägt dafür die vollen Rechte — der Weg für ein Werkzeug, das ein Mensch
  selbst bedient. Allein abgeflossen ist so ein Key wertlos. Die Sitzung muss dem Konto des Keys
  gehören; irgendeine Anmeldung genügt nicht.

- **Ein API-Key läuft jetzt von selbst ab** (`apikey_default_days`, Vorgabe 90;
  `apikey_allow_unlimited`, Vorgabe aus). Ohne Angabe war ein Key bisher **unbefristet**, und das
  war der häufigste Fall — ein Geheimnis, das niemand mehr zurücknimmt, das den Menschen überlebt,
  der es ausgestellt hat, und das Projekt, für das es gedacht war. `expires_days=0` heisst weiter
  ausdrücklich „unbefristet", braucht aber die Erlaubnis und steht dann im Audit-Eintrag. Ein
  negativer Wert bleibt ein Ablauf in der Vergangenheit, also ein von vornherein toter Key.

  **Bestandsdateien:** Schema 7 trägt die Art nach, und zwar als `automat` — die engere Auslegung.
  Ein Key, der bisher Admin-Routen bedienen konnte, verliert das; genau darum geht es. Ein
  abgewiesener Aufruf hinterlässt eine Zeile im Sicherheits-Log.

- **Ein gesperrtes Konto bekommt beim SSO-Login gar nichts mehr** (F-17). Der OIDC-Callback lief
  für ein `disabled=1`-Konto vollständig durch: Gruppen wurden übernommen, das Admin-Flag konnte
  gesetzt werden, ein Login-Eintrag entstand — nur die Sitzung blieb am Ende aus. Ein Konto zu
  sperren ist aber die Antwort auf „diese Person soll nichts mehr können"; dass ihre Rollen sich
  dabei noch ändern, ist das Gegenteil davon, und im Protokoll sah der Vorgang aus wie eine
  gelungene Anmeldung. Die Prüfung steht jetzt **vor** jedem Schreibzugriff, mit Audit-Zeile und
  einer Zeile im Sicherheits-Log. Lokaler Passwort-Login und Panel prüften das seit jeher; die
  föderierte Seite war die Lücke.

- **Die UserInfo-Antwort muss zum ID-Token gehören** (F-18). Sie wird im Callback über die Claims
  gelegt und liefert Gruppen, E-Mail und damit mittelbar Rollen und das Admin-Flag — ist aber im
  Gegensatz zum ID-Token **nicht signiert**, sondern eine gewöhnliche Antwort auf einen
  Bearer-Token. OIDC Core 5.3.2 verlangt deshalb ausdrücklich, ihr `sub` gegen das des ID-Tokens
  zu prüfen und die Antwort sonst **nicht zu verwenden**. Genau das fehlte: Wer einen Access-Token
  eines anderen Kontos vorlegte, schob die Merkmale einer fremden Person in die eigene Sitzung.
  Passt das `sub` nicht, wird die Antwort jetzt ganz verworfen — nicht teilweise übernommen —,
  und die Claims des signierten Tokens bleiben die einzige Quelle.

- **Ein ID-Token für eine andere Anwendung wird abgewiesen** (F-15, OIDC Core 3.1.3.7). Geprüft
  wurde nur, dass die eigene `client_id` in `aud` **vorkommt**. Ein Token darf aber mehrere
  Empfänger nennen, und dann sagt erst `azp`, für wen es ausgestellt wurde. Ohne diese Prüfung
  genügte ein Token, das für eine andere Anwendung desselben Providers gemacht wurde und uns nur
  mitnennt (Token-Substitution): Wer bei irgendeinem Client dieses Providers ein Token bekam, kam
  damit auch hier herein. Drei Regeln gelten jetzt — mehrere `aud` verlangen ein `azp`, ein
  vorhandenes `azp` muss die eigene `client_id` sein, und die muss in `aud` stehen. Seit
  `oidc_clients` (T-14) wiegt das doppelt: Sonst wäre das Token von App A auch an App B gut und
  die Freigabe je Client umgangen.

- **Ein erfundener `Host` kann keine Warnung mehr abschalten.** `security.einmal_melden()` hält
  fest, worüber schon eine Hinweiszeile im Security-Log steht, damit ein Seitenaufruf mit zwanzig
  Unterressourcen nicht zwanzig gleiche Zeilen schreibt. Der Schlüssel ist der **Host aus der
  Anfrage**, und der Deckel von 512 Einträgen galt für die Lebensdauer des Prozesses: Wer 512
  verschiedene `Host`-Werte durchprobierte, legte die Stelle bis zum Neustart still — danach blieb
  auch der Hinweis auf den **echten** Betriebsfehler aus. Aus Lärm wurde so gezieltes Abschalten.
  Der Deckel gilt jetzt je Zeitfenster (`_GEMELDET_FENSTER_SEK`, eine Stunde), und das Erreichen
  des Deckels schreibt **eine** Zeile — eine unsichtbare Unterdrückung wäre dasselbe Loch noch
  einmal. Gefunden beim Angriff auf die eigenen Fixes dieser Runde (C-4).

- **`base_url` wird nach derselben Regel geprüft wie eine abgeleitete Basis.** Die Formprüfung
  steht jetzt in `security.normalisiere_basis()`; `security.sichere_basis()` setzt nur noch die
  Frage „ist das ein eigener Host?" davor. Vorher lief allein der **abgeleitete** Zweig durch die
  Prüfung, während ein konfiguriertes `base_url` lediglich `strip().rstrip("/")` sah und die
  Konfigurationsprüfung es mit einem groben Schema-und-Host-Muster abnahm. Damit kam durch, was im
  anderen Zweig scheitert: eine Benutzerangabe im Host (`https://wer:was@auth.example` — sie stünde
  in jedem Reset-Link und in jeder Redirect-URI), ein Fragment oder eine Abfrage (der angehängte
  Token landete hinter dem `#` und erreichte den Server nie), ein unzulässiger Port, ein Pfad mit
  `..`. Die Konfigurationsprüfung weist das jetzt beim Aufbau ab und meldet zusätzlich, wenn eine
  brauchbare Adresse unterwegs **verändert** würde — mit dem Wert, den man stattdessen eintragen
  sollte. `public_base()` normalisiert als Boden darunter (eine Config lässt sich nach dem
  Konstruktor noch ändern). (C-7)

- **Die Zusage „eine ersetzte Basis meldet sich" gilt auch bei gleichem Host.** Verglichen wurde
  nur der Hostname, gemeldet also nur ein Wechsel des Namens. Eine unter `/sso` montierte App, die
  ihrem eigenen Formular `https://auth.example.com/falsch` durchreicht, bekam keine Zeile — obwohl
  genau dieses falsche Präfix beim Empfänger als 404 ankommt. Verglichen wird jetzt die ganze
  normalisierte Basis. (C-5)

- **Das ID-Token bestimmt nicht mehr selbst, wie es geprüft wird.** `authlib.jose.jwt` ist ein
  Dekoder mit Vorgabesatz, und dieser Satz enthält HS256: Wird beim Dekodieren kein Verfahren
  genannt, entscheidet der **Header des Tokens** — also der Absender. Bis authlib 1.3.0 liess sich
  damit ein ID-Token mit dem öffentlichen Schlüssel aus dem JWKS als HMAC-Geheimnis fälschen
  (GHSA-5357-c2jx-v7qh, Algorithmen-Konfusion); der öffentliche Schlüssel ist per Definition
  öffentlich, das `sub` hätte der Angreifer sich ausgesucht. Dazu passte der deklarierte Boden:
  `authlib>=1.3` erlaubte genau diese Fassung, und wer eine Fassung festhält (Lockfile,
  Constraints, Distributionspaket), bekam sie auch. Jetzt beides — `OIDCClient.ID_TOKEN_ALGS`
  nennt ausschliesslich asymmetrische Verfahren (RS/PS/ES/EdDSA) und wird beim Dekodieren gesetzt,
  versionsunabhängig; eine spätere Erweiterung um HS\* oder `none` weist der Client mit
  `ConfigError` ab. Und die Untergrenzen sind gehoben, auf den gemessenen lückenfreien Boden
  (OSV, Stand 2026-09-22): `fastapi>=0.133.0` (erst ab da ist starlette >= 1.3.1 erlaubt),
  `python-multipart>=0.0.31`, `authlib>=1.6.12`. **Keine** oberen Schranken — ein Deckel in einer
  Bibliothek blockiert genau die Aktualisierung, die den nächsten Fix bringt.
  `tests/test_packaging.py` misst die Grenzen gegen eine eingefrorene Tabelle mit, damit der Boden
  nicht wieder altert. Gefunden im dritten Audit (B4-1 aus [T-13](backlog/T-13-audit-2026-09-22-runde-3.md)).
- **Eine unbestätigte IdP-Adresse konnte den ersten Admin bestimmen.** `admin_identifiers` ist der
  dokumentierte Bootstrap-Weg. Für die offene Registrierung verlangt TinySesam dafür eine bestätigte
  Adresse — der OIDC-Weg las `email` dagegen bedingungslos und übersah den Standard-Claim
  `email_verified` (OIDC Core 5.1). Wer sich bei einem IdP mit Selbstregistrierung oder in einem
  zweiten Mandanten die Admin-Adresse eintrug, war beim ersten Login Erst-Admin. Jetzt gilt ein
  fehlender Claim als *unbestätigt* (fail-closed, mit Protokoll- und Audit-Zeile), und diese
  Adresse trägt in keinem Fall die Erst-Admin-Entscheidung — auch nicht bei einem Bestandskonto,
  das sie schon führt, und auch nicht über einen späteren Login, der selbst keinen Beleg
  mitbringt (`maybe_promote_admin(user, email_bestaetigt=…)`, durchgereicht von `apply_factor`;
  ohne diesen Parameter entscheidet der Vermerk am Konto). **Geführt wird die Adresse
  trotzdem:** Getrennt gemerkt wird nur der Beleg, in der neuen Spalte `users.email_verified`
  (Schema-Version 5; ein `ALTER TABLE` mit `DEFAULT 1` lässt jedes Bestandskonto genau so
  wirken wie bisher). Die Adresse zu *verwerfen* war die erste Fassung dieses Fixes, und sie
  kostete mehr, als sie schützte: Ein IdP, der den optionalen Claim nie schickt (Entra ID),
  liess damit jedes neu angelegte Konto `oidc-<sub>` heissen statt wie die Adresse, und
  `Remote-Email` ging leer an die geschützte App — dieselbe Person landete nach dem Update in
  einem *anderen* Konto der App, und Reset wie Magic-Link waren für sie zu. Weil der Claim
  optional ist, entscheidet neu `oidc_email_verified_default` (Vorgabe `False`), was das
  **Schweigen** eines Providers bedeutet; wer seine Adressen selbst verantwortet, stellt es auf
  `True` und kann `admin_identifiers` auch mit so einem IdP nutzen. Ein Claim, der ausdrücklich
  `false` sagt, bleibt in beiden Fällen ein Nein — und `_flag_wahr` liest ihn in den Formen, die
  echte Provider senden (`True`, `"true"`, `"True"`, `1`, `"1"`; alles andere, auch die
  Zeichenkette `"false"`, ist Nein — eine Wahrheitsprüfung auf dem rohen Wert hätte sie
  durchgelassen, und kein Test hielt das fest). Adresse und
  Beleg werden immer aus DEMSELBEN Dokument genommen: Der Callback legt ID-Token und
  userinfo-Dokument zusammen, und beim Mischen konnte ein `email_verified=true` aus dem einen an die
  Adresse aus dem anderen geraten. Zweitens hing der Wächter, der Allowlist-**Benutzernamen**
  verbietet, allein an `allow_signup` — beim Auto-Anlegen durch einen IdP (`oidc_auto_create`,
  `saml_auto_create`, `ldap_auto_create`) griff er nicht, obwohl der Name auch dort aus fremder
  Hand kommt (`preferred_username`); er fasst jetzt alle vier Türen.
  **Über SAML und LDAP gibt es diesen Beleg gar nicht — dort befördert eine Allowlist-Adresse
  nie.** Der Riegel hing zunächst allein am OIDC-Callback: SAML-ACS und LDAP-Login riefen
  `apply_factor` ohne das Argument, und `None` heisst „kein fremder IdP im Spiel" — es lief am
  Riegel vorbei, ein IdP mit Selbstregistrierung oder ein Verzeichnis, in dem der Nutzer sein
  `mail`-Attribut selbst pflegt, bestimmte also weiter den ersten Admin. Jetzt reichen beide
  Wege ausdrücklich „kein Beleg" durch, und die Regel selbst ist **fail-closed**:
  `maybe_promote_admin` bekommt den **Faktor** mit, und für einen föderierten Faktor (neu:
  `TinySesam.FOEDERIERTE_FAKTOREN`) zählt eine Adresse nur mit einem ausdrücklichen `True` —
  ein künftiger föderierter Weg, der den Beleg zu übergeben vergisst, verweigert damit, statt zu
  befördern. LDAP braucht den ausdrücklichen Durchreicher zusätzlich, weil es bewusst den Faktor
  `password` schreibt und am Faktornamen nicht zu erkennen ist. Die Konfigurationsprüfung nennt
  die Kombination Allowlist-**Adresse** + `saml_auto_create`/`ldap_auto_create` und den belegten
  Weg (`/auth/claim-admin`, danach das Gruppen-Mapping). Die Adresse selbst bleibt im Konto
  stehen — sie ist das Attribut, das Verzeichnis oder IdP liefert; sie trägt nur keine
  Rechte-Entscheidung mehr.
  **Das schloss zunächst nur den ersten Login, und der Angriff brauchte danach genau einen
  Klick mehr.** Ohne ausdrücklichen Beleg entscheidet der **Vermerk am Konto**
  (`users.email_verified`) — und den legten `check_ldap`/`check_saml` mit der Vorgabe „belegt"
  an, obwohl über diese Wege per Definition nichts belegt ist. Der Angreifer meldete sich also
  einmal über das Verzeichnis an (Beförderung korrekt verweigert), richtete sich in seiner
  frisch angemeldeten Sitzung eine PIN oder einen Passkey ein — Selbstbedienung, in der
  eigenen Sitzung gewollt — und war beim zweiten Login Erst-Admin: Dieser Faktor ist nicht
  föderiert, reicht keinen Beleg mit, und der Vermerk sagte „belegt". Gemessen mit einem
  Verzeichnis, in dem der Nutzer sein `mail`-Attribut selbst pflegt. **Jetzt legen beide Wege
  mit `email_verified=False` an**: Die Adresse steht im Konto, der Vermerk behauptet nichts.
  Damit ist die Regel über alle Anmeldewege dieselbe — eine Adresse trägt eine
  Rechte-Entscheidung nur, wenn *dieser* Login sie belegt (OIDC-Claim) oder ein eigener
  Bestätigungsweg sie belegt hat. Die zwei Riegel für SAML (Durchreicher der ACS-Route,
  `FOEDERIERTE_FAKTOREN`) und der eine für LDAP werden jetzt **einzeln** gemessen: Bisher deckte
  einer den anderen, ein Umbau hätte den verbleibenden unbemerkt verlieren können.
  Belege in `tests/test_saml.py`, `tests/test_ldap.py` und `tests/test_audit_runde2.py`.
  Gefunden im dritten Audit (F-14 aus T-13; die beiden Nachschläge B-umgehung-1 und
  B-umgehung-10 der zweiten Angriffsrunde).
- **⚠️ `store.set_email()` nimmt den Bestätigungs-Vermerk jetzt mit — Verhaltensänderung für
  Einbettende.** Seit `users.email_verified` über Rechte entscheidet, war ein stehengelassener
  Vermerk der Beleg der **alten** Adresse auf der **neuen**: Ein Konto mit bestätigtem
  `eve@example.com`, dessen Adresse auf die Allowlist-Adresse umgeschrieben wurde, war beim
  nächsten Login Erst-Admin, ohne dass jemand etwas bestätigt hat. Der Docstring nannte das
  Stehenlassen ausdrücklich „fail-closed" und begründete es mit der *anderen* Richtung
  (unbestätigt bleibt unbestätigt) — diese hier war fail-**open**. Adresse und Vermerk gehen
  jetzt in EINER Anweisung in die Datenbank, vorgabegemäss als **unbestätigt**; wer einen Beleg
  für die neue Adresse hat, sagt es (`set_email(uid, mail, verified=True)`). Im Paket selbst
  hat die Methode keinen Aufrufer — die Falle stand für Einbettende bereit. Beleg in
  `tests/test_audit_runde2.py`. Gefunden im dritten Audit (B-umgehung-8 aus
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md)).
- **LDAP folgt keinem Verweis (Referral) mehr — er kostete das Passwort des Dienstkontos.** ldap3
  verfolgt einen `SearchResultDone resultCode=10` von sich aus und baut dazu eine neue Verbindung
  zu dem Host auf, den die **Antwort** nennt — mit denselben Zugangsdaten. TinySesam setzte den
  Parameter nirgends. Mit zwei LDAP-Servern auf Loopback nachgestellt: Server A beantwortete die
  Suche mit einem Verweis, und beim fremden Server B kam der vollständige BindRequest mit DN und
  Klartext-Passwort des Dienstkontos an — auf der Benutzer-Verbindung wäre es das Passwort des
  Anmeldenden gewesen. Eine Referral braucht dafür kein übernommenes Verzeichnis: Auf einer
  Klartext-Verbindung schiebt sie jeder Zwischenhörer ein. Jetzt `auto_referrals=False` auf
  **jeder** Verbindung und `allowed_referral_hosts=[]` am Server (zweites Schloss, falls einmal
  eine Verbindung ohne den Parameter entsteht); ohne Verfolgung endet die Suche ergebnislos und
  die Anmeldung scheitert, statt Zugangsdaten zu verschenken. Bewusst hart und ohne Schalter —
  wer über mehrere AD-Domänen sucht, fragt den Global Catalog ab. Damit dieser Preis nicht
  **stumm** anfällt (ohne Verfolgung sieht jede Anmeldung aus wie ein falsches Passwort, und
  zwar für jeden Nutzer der Domäne gleichzeitig), schreibt der verworfene Verweis jetzt eine
  Zeile über `tinysesam.security` und nennt den verwiesenen Host — durch dieselbe Bereinigung
  wie der Benutzername, ein Umbruch aus einer fremden Antwort erzeugt also keine zweite,
  erfundene Logzeile. Der Global-Catalog-Hinweis (Port 3268/3269) steht jetzt im
  LDAP-Abschnitt **beider READMEs** statt nur im Quelltext. Fund **F-28** aus
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md). Nebenbefund derselben Stelle: `ldap_bind_dn`
  ohne `ldap_bind_password` lehnt ldap3 ab, der Fehler wurde im Login verschluckt und sah für
  jeden Nutzer wie ein falsches Passwort aus — die Kombination meldet jetzt die
  Konfigurationsprüfung beim Aufbau.
- **Der `Host`-Header vergiftete Reset-, Anmelde- und Bestätigungslink.** An zehn Stellen leitete
  TinySesam die öffentliche Adresse aus der Anfrage selbst ab — sechsmal als
  `cfg.base_url or str(request.base_url)` (Magic-Link, Reset, Bestätigung, OIDC-Post-Logout,
  OIDC-Redirect-URI, Admin-Einladung), dreimal für SAML, einmal in der Forward-Auth-Umleitung.
  Der abgeleitete Teil ist der rohe `Host`-Header, also eine Eingabe des Anfragenden (kein Proxy
  und kein ASGI-Server prüft ihn). Wer „Passwort vergessen" für ein **fremdes** Postfach
  anstieß und dabei `Host:` setzte, ließ die echte App
  eine echte Mail mit einem **gültigen Reset-Token** verschicken, deren Link auf den Server des
  Angreifers zeigte; dasselbe für Magic-Link, E-Mail-Bestätigung und Admin-Einladung.
  `trusted_redirect_hosts` schützte nur `?next=`, nicht diesen Weg (CWE-644). Jetzt entscheidet
  überall `TinySesam.public_base()`: `base_url` gewinnt, sonst gilt ein abgeleiteter Host nur,
  wenn er in `trusted_redirect_hosts` steht oder Loopback ist. Dieselbe Prüfung deckt
  OIDC-Redirect-URI und Post-Logout, SAML-Entity-ID/ACS und die Forward-Auth-Umleitung; jede
  dieser Stellen wird einzeln gemessen (`tests/test_sicherheit_befunde.py`), nachdem sich in einer
  Mutationsprobe alle vier auf die alte Form zurückbauen ließen, ohne dass eine Prüfung rot wurde.

  **Auch die dokumentierten Methoden folgen jetzt derselben Regel** — `magic_url()`, wo alle vier
  Mail-Wege zusammenlaufen, und davor `send_password_reset`, `send_login_link`, `send_verify_email`
  und `create_invite`. Vorher saß die Prüfung nur in der Route: Eine App mit eigenem „Passwort
  vergessen"-Formular, die dem naheliegenden Muster `str(request.base_url)` folgte, blieb voll
  angreifbar, während ihr die eingebaute Route längst abriegelte. Es ist **eine** Regel, kein
  zweites Regelwerk: `_gepruefte_basis()` ruft `public_base()` und macht aus dem leeren Ergebnis
  einen Fehler. Steht `base_url`, **gewinnt sie auch hier unbedingt** — die übergebene Adresse kommt
  gar nicht zum Zug. Das ist mehr als „ein fremder Host wird abgewiesen": Stehen mehrere eigene
  Namen in `trusted_redirect_hosts` (beim SSO der Normalfall), konnte der `Host`-Header sonst weiter
  *auswählen*, welcher davon in den Reset-Link kommt. Ohne `base_url` — der einzige Aufbau, in dem
  überhaupt abgeleitet wird — wird eine fremde Basis mit `ConfigError` abgewiesen, und zwar **vor**
  der Token-Vergabe (kein unbrauchbarer Token bleibt liegen) und vor der Kontosuche (die Ausnahme
  verrät nicht, ob es die Adresse gibt). Die Prüfung ist **idempotent**: Die Absender prüfen vor der
  Token-Vergabe, `magic_url()` prüft danach noch einmal — der Pfadanteil wächst dabei nicht mehr
  (eine Zwischenfassung hängte ihn bei jedem Durchgang erneut an und schickte Links mit vierfachem
  Präfix, also 404, hinaus). Ein Test zählt die Vorkommen, statt `startswith` zu prüfen.

  **`base_url` ist jetzt Pflicht — eine bewusste Verhaltensänderung, und die erste Fassung dieses
  Fixes war zu weich.** Der Absatz hier versprach „sichtbarer Fehler statt geratener Adresse";
  für die beiden häufigsten Wege stimmte nur die erste Hälfte. `/auth/forgot` und
  `/auth/magic/request` schrieben bei fehlender Basis eine Audit-Zeile und rendeten
  **unverändert die Erfolgsseite**: HTTP 200, „Mail ist unterwegs", keine Mail. Dieselbe generische
  Antwort verhindert die Benutzer-Enumeration und verdeckte hier einen Totalausfall — wer ohne
  `base_url` aktualisierte, verlor Passwort-Reset und Magic-Link für **alle** Nutzer, sichtbar nur
  in einer Logzeile. Die übrigen Wege (OIDC-Start, Registrierung mit Bestätigung, Admin-Einladung,
  SAML) antworteten mit **500** mitten im Anmeldeversuch, obwohl schon beim Aufbau feststand, dass
  es nicht gehen kann. Und `konfigpruefung` nannte das nur eine **Warnung**: Blieb `base_url` leer
  und standen — beim Forward-Auth/SSO der Normalfall — mehrere Namen in
  `trusted_redirect_hosts`, genügte der Laufzeit-Prüfung jeder davon; der Angreifer stieß den
  Reset für ein fremdes Postfach an, setzte `Host:` auf einen **anderen** mitvertrauten Host und
  der Token ging dorthin hinaus.

  Beides ist geschlossen: `konfigpruefung` meldet ein leeres `base_url` als **Fehler**, sobald ein
  Mail-Weg (`magiclink_enabled`, `password_reset_enabled`, `signup_verify_email`), `oidc_enabled`
  oder `saml_enabled` an ist — der Aufbau scheitert dann mit `ConfigError`, statt einen Betrieb zu
  erlauben, der still das Falsche tut. Damit gewinnt `base_url` überall dort, wo eine absolute
  Adresse **in fremde Hand** geht — Mail-Link, OIDC-Redirect-URI, Post-Logout, SAML-Entity-ID/ACS —,
  und der `Host`-Header hat dort keine Stimme mehr. **Eine Ausnahme, und sie ist benannt:** Ohne
  `cookie_domain` baut `forward_login_url()` die Login-Seite auf dem angefragten Host, wenn der in
  `trusted_redirect_hosts` steht. Das Session-Cookie gilt dann host-only; zeigte die Login-URL
  woandershin, drehte sich die Anmeldung still im Kreis. `konfigpruefung` sagt diesen Fall beim
  Start an, und weiter als `trusted_redirect_hosts` reicht er nicht.

  Zur Laufzeit gibt es keinen stillen Erfolg: die neue Methode
  `TinySesam.require_public_base()` wirft `ConfigError` mit klarer Meldung, wo bisher eine
  Erfolgsseite stand („Mail ist unterwegs", HTTP 200, keine Mail — dieselbe Antwort, die die
  Benutzer-Enumeration verhindert, verdeckte damit den Totalausfall). `forward_auth_enabled`
  bleibt eine Warnung — seine Umleitung bleibt ohne Basis relativ und trifft denselben Browser;
  wo vorher der `Host`-Header eine absolute Adresse in `X-TinySesam-Location` schrieb, steht jetzt
  ein Pfad. **Der 500 bleibt.** Hier stand zunächst „wo bisher eine Erfolgsseite oder ein 500
  stand"; das versprach mehr, als gemessen ist. Den `ConfigError` fängt keine Route ab, ein
  ASGI-Server macht daraus einen Serverfehler — für den regulären Aufbau ist das bedeutungslos,
  weil `konfigpruefung` ihn gar nicht mehr entstehen lässt, es trifft nur eine Config, die NACH dem
  Konstruktor geändert wurde. Beides ist gemessen (`tests/test_sicherheit_befunde.py`): kein 200,
  kein Mailversand, und die 500 als das, was heute herauskommt. Der Hinweis auf die fehlende Basis
  steht **einmal je Prozess und Host** im Security-Log, nicht je Anfrage: Der Forward-Auth fragt
  bei jeder anonymen Anfrage nach, ein Seitenaufruf sind zwanzig Unterressourcen — genau die Datei,
  auf die die fail2ban-Jail zeigt, lief sonst voll.

  Zusätzlich kommt der **`root_path`** mit — **für die verschickten Links**:
  `base_url="https://example.com/sso"` behält ihr Präfix, eine abgeleitete Basis übernimmt den
  Unterpfad aus dem Request, und beide tragen ihn im Link genau **einmal**; vorher verschickte eine
  unter einem Unterpfad montierte App Links ins 404. **Die eingebauten Seiten tragen den Unterpfad
  nicht:** Ihre Formularziele und Verweise stehen wurzel-absolut (`/auth/register`, `/auth/forgot`,
  …), und `login_path`/`login_redirect`/`logout_redirect` gehen unverändert hinaus. Wer unter
  `--root-path /sso` hinter einem Proxy montiert, der `/sso` abschneidet, bekommt funktionierende
  Mails und eine Anmeldung ins 404. Die Grenze ist gemessen (`tests/test_sicherheit_befunde.py`
  an einer echten Montage) und als Aufgabe geführt: [`backlog/T-15`](backlog/T-15-unterpfad-montage.md).

  **Für Betreiber — was einzutragen ist:** Wer bisher ohne `base_url` fuhr und einen Mail-Weg,
  OIDC oder SAML nutzt, muss `base_url` auf die öffentliche Adresse dieser App setzen, sonst
  startet die Instanz nicht mehr: `base_url="https://auth.example.com"` (lokal
  `base_url="http://127.0.0.1:8000"`, unter einem Unterpfad montiert mit Präfix,
  `"https://example.com/sso"` — für die Mail-Links, siehe oben). Die Fehlermeldung beim Start
  nennt genau das.

  **Für Einbettende:** Wer die Basis selbst übergibt, nimmt sie nicht aus dem Request, sondern aus
  `auth.public_base(request)` (leer = abbrechen). Steht `base_url`, ersetzt sie eine abweichende
  Angabe — das hebt auch ein `http://` aus einem TLS-terminierenden Proxy auf die konfigurierte
  Adresse, statt es still in den Mail-Link wandern zu lassen; einmal je Host steht eine Zeile
  darüber im Security-Log. Ohne `base_url` bekommt ein fremder Host `ConfigError` statt eines Links.
  Gefunden im dritten Audit (R4-01 = R8-4 aus [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)),
  nachgeschärft in den Nacharbeitsrunden N1 und N6 dazu.
- **Eine fremde Registrierung konnte die Login-Kennung eines bestehenden Kontos besetzen.** Geprüft
  wurden die beiden Namensräume nur getrennt — die Adresse gegen `users.email`, der Benutzername
  gegen `users.username`. Im Vorgabe-Modus `login_identifier="both"` durchsucht die Anmeldung aber
  **beide** Spalten und lässt bei einer Kennung mit `@` die E-Mail gewinnen: Wer die E-Mail eines
  bestehenden Kontos als *Benutzernamen* eintrug — oder dessen Benutzernamen als E-Mail —, besetzte
  dessen Kennung. Der Inhaber, auch ein Admin, bekam ab da 401 trotz richtigem Passwort, und
  `/auth/password` prüfte für die Sitzung des Fremden sein Geheimnis statt des eigenen: ein
  Passwort-Orakel ohne Drossel, Sperre und Protokollzeile. Beide Kennungen müssen jetzt **kreuzweise**
  frei sein; die Prüfung sitzt in `create_user` und gilt damit für jeden Weg, der ein Konto
  anlegt — Registrierung, Einladung, Admin-API, `ensure_admin`/`create_service` und die
  automatische Anlage aus OIDC/LDAP/SAML, die fail-closed scheitert, statt eine fremde Kennung
  zu überschreiben. (Das CLI stand hier zunächst mit in der Liste — es kann gar keine Konten
  anlegen.) Was diese Zusage auf den **föderierten** Wegen bedeutet, steht jetzt auch in
  Tests: OIDC weicht auf einen freien Namen aus (geprüft werden beide Namensräume), eine nicht
  ausweichbare Adresse endet mit **409**, LDAP mit **401**, SAML mit **403** — je eine saubere
  Abweisung mit Audit-Zeile (`oidc_ident_taken`, `ldap_ident_taken`, `saml_ident_taken`), kein
  500 mitten im Anmeldevorgang. `/auth/password` prüft zusätzlich gegen die
  **ID** der eigenen Sitzung statt über die Kennung, damit eine Kollision aus einem Altbestand dort
  nicht mehr wirkt. Neu: `auth.kennung_vergeben(kennung, exclude_id=None)`.
  **Für einbettende Apps — ⚠️ hier ändert sich Verhalten:** Bei einer doppelten **E-Mail**
  bleibt alles wie in 0.18.x (`ConfigError`, Wortlaut „E-Mail-Adresse ist bereits vergeben").
  Ein doppelter **Benutzername** dagegen lief bis 0.18.x in die Datenbank und kam als
  `sqlite3.IntegrityError` („UNIQUE constraint failed: users.username") zurück; jetzt fängt
  `create_user()` ihn vorher ab und wirft ebenfalls `ConfigError`, mit dem Text „Benutzername
  ist bereits vergeben". Wer auf `IntegrityError` fängt, fängt diesen Fall nicht mehr — die
  Signatur ist unverändert, `api_surface.json` sieht den Wechsel also nicht; er steht deshalb
  hier und im Docstring (→ API.md). Ebenso ist der **Wortlaut feldabhängig**: Der neue Auslöser
  (Benutzername gleich fremder E-Mail und umgekehrt) trägt den Text des Feldes, das kollidiert,
  nicht immer den der E-Mail. Ein früherer Entwurf dieses Eintrags behauptete das Gegenteil.
  Unterscheiden lässt sich der Fall ohnehin besser **ohne** Textvergleich: `e.feld` ist
  `"username"` oder `"email"`, `e.besitzer_id` nennt das Konto, dem die Kennung gehört. Und weil die Datenbank keinen UNIQUE-Index über BEIDE
  Namensräume kennt — Prüfung und INSERT in `create_user` sind nicht atomar, und eine Datenbank
  von vor dem Fix trägt die Kollision längst —, **meldet der Start jetzt vorhandene
  Kreuz-Kollisionen** mit beiden Konto-IDs, statt sie schweigend mitzuführen
  (`store.kennungs_kollisionen()`). Bereinigt wird von Hand: welches Konto den Namen behält,
  kann keine Bibliothek entscheiden. Gefunden im dritten Audit (R4-12 aus T-13).
- **`/auth/password` war ein stilles Passwort-Orakel — und es prüfte nicht einmal das eigene Konto.**
  Die Abfrage des alten Passworts lief als einzige Geheimnis-Prüfung ohne den Dreiklang des
  Login-Pfads: keine Drossel, keine Sperre, kein verbuchter Fehlversuch — beliebig viele Versuche,
  nie eine 429, keine Zeile fürs Sicherheits-Log oder fail2ban, während derselbe Fehlgriff am Login
  nach wenigen Anläufen sperrt. Dazu löste sie das Konto über die **Login-Kennung** auf
  (`check_password(u["username"], …)` → `find_user`) statt über die ID der eigenen Sitzung: Wer ein
  Konto besitzt, dessen Benutzername der E-Mail eines anderen gleicht, riet darüber das Passwort
  **dieses fremden Kontos** — und ein Treffer setzte still das eigene Passwort, blieb also auch im
  Erfolg unsichtbar. Jetzt: `verify_user_password(u["id"], …)` plus `rate_ok` →
  `is_password_change_locked` → `record_login(…, "password_change")`; die eigene Methode sorgt
  dafür, dass ein Treffer hier die Fehlversuche des Login-Pfads nicht wegräumt.
  Die Sperre ist ein **eigener, methodengebundener Topf** mit eigener Schwelle
  (`password_change_max_attempts`, Vorgabe 5) — dieselbe Bauform wie der PIN-Zähler. Der erste
  Anlauf hängte die Route an den Login-Lockout, und der zählt methodenblind: Fünf Tippfehler auf
  der eigenen Kontoseite sperrten damit die **Anmeldung** für `lockout_window_sec`, samt der
  Route, über die man die Sperre hätte abtragen können — und hinter NAT verriegelten drei
  vertippte Kollegen über `ip_attempt_factor` den Login eines völlig unbeteiligten Vierten.
  Deshalb zählt `is_locked` jetzt nur noch, was ein **Anmeldeversuch** war
  (`security.NICHT_LOGIN_METHODEN` als Ausnahmeliste, damit eine neue Anmeldemethode von sich
  aus mitzählt). Gedrosselt, gesperrt und protokolliert wird das Raten unverändert — nur eben
  dort, wo geraten wurde. **Der Preis, offen gesagt:** Statt eines Topfes gibt es am Ende dieser
  Runde **fünf** — Anmeldung, PIN-Anmeldung, Passwortwechsel, Step-up-Bestätigung und Bereichs-PIN,
  je 5 Versuche im Fenster (die letzten drei kamen mit der Nacharbeit unten dazu). Die Step-up-Seite
  prüft dabei auch die PIN-Sperre der Anmeldung mit, sonst liesse sich eine dort gesperrte PIN hier
  weiterraten. Wer alle Töpfe ausreizt, hat
  mehr Versuche als vorher; dafür verriegelt ein Tippfehler auf der Kontoseite niemandem mehr die
  Anmeldung, und jeder Topf trifft genau den, der geraten hat.
  Neu: `auth.is_password_change_locked(username, ip)` und
  `store.count_fails(..., exclude_methods=…)`. Belege in `tests/test_hardening.py`.
  Gefunden im dritten Audit (R4-10 aus [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)).
  **Nachgearbeitet (zweite Angriffsrunde) — der Fix war an drei Stellen zu kurz:**
  1. **Die Ausnahmeliste nannte nur `password_change`.** `record_login()` wird im Router mit
     fünf Methoden gerufen; `reauth` (Step-up-Bestätigung) und `resource` (Bereichs-PIN ohne
     Konto) zählten weiter in den Login-Topf. Fünf Tippfehler an der Reauth-Seite sperrten
     damit die **Anmeldung** desselben Kontos, und bei der Bereichs-PIN — die jeder Besucher
     probieren darf — genügten drei Bereiche à fünf Fehlgriffe, um über `ip_attempt_factor`
     die Anmeldung wildfremder Konten von derselben Adresse zu verriegeln. Beide haben jetzt
     ihren eigenen Topf (`auth.is_reauth_locked`, `auth.is_resource_locked`, Schwellen
     `reauth_max_attempts`/`resource_max_attempts`); `NICHT_LOGIN_METHODEN` wird aus der
     Zuordnung `security.EIGENE_SPERRE` **abgeleitet**, eine Methode ohne eigene Bremse lässt
     sich also gar nicht mehr eintragen. Ein Test hält die Liste per AST gegen die Methoden,
     mit denen der Router wirklich ruft — genau das fehlte, sonst wäre die Lücke aufgefallen.
  2. **Die Nicht-Login-Zeile traf die mitgelieferte fail2ban-Jail.** `failed login user=…
     ip=… method=password_change` passte Zeichen für Zeichen auf die ausgelieferte `failregex`
     (`maxretry = 6`): Acht Tippfehler eines **angemeldeten** Nutzers am eigenen alten Passwort
     erzeugten acht bannbare Zeilen, und ab der App-Sperre beschleunigte jeder weitere Klick den
     Bann. Nicht-Anmeldungen tragen jetzt das eigene Ereigniswort **`failed verification`**
     (`security.log_ereignis`) und laufen an der Jail vorbei; wer sie trotzdem bannen will,
     nimmt den neuen Filter `deploy/fail2ban/tinysesam-verify-filter.conf` samt der milderen,
     standardmässig **abgeschalteten** zweiten Jail dazu (sinnvoll vor allem für öffentlich
     angebotene Bereichs-PINs). Protokolliert wird unverändert alles.
  3. **Der eigene Topf brachte die NAT-Verstärkung mit, die er abschaffen sollte.** Er zählte
     zunächst auch pro IP (`limit * ip_attempt_factor`): Drei vertippte Kollegen sperrten dem
     vierten seinen **eigenen** Passwortwechsel — eine Sperre, die es auf 0.18.x gar nicht gab.
     `is_password_change_locked` und `is_reauth_locked` zählen jetzt **nur pro Konto**; wer dort
     rät, braucht ohnehin schon eine gültige Sitzung genau dieses Kontos, das Opfer ist also
     immer der Angemeldete selbst. Gegen Klopfen von aussen steht weiter `rate_ok(ip)`.
     `is_resource_locked` behält die IP-Schwelle: Dort rät ein Unangemeldeter, und ohne sie
     liesse sich über immer neue Bereichsnamen endlos weiterraten.
- **Ein `GET` auf `/auth/totp/setup` konnte den bestätigten zweiten Faktor entfernen.** Die Seite
  rief `totp_begin()` unbedingt und schrieb ein frisches, unbestätigtes Geheimnis über das alte:
  TOTP fiel auf „unbestätigt", die zehn Recovery-Codes blieben verwaist liegen, es entstand keine
  Audit-Zeile — und danach genügte das Passwort allein für eine vollwertige Sitzung. CSRF half
  dagegen nicht: Ein GET trägt kein Token, und `SameSite=Lax` (Vorgabe) schickt das
  Sitzungscookie bei einer Top-Level-Navigation mit; ein Klick auf einen fremden Link reichte.
  Jetzt verweigert `totp_begin()` den Start, solange ein **bestätigtes** TOTP existiert (neuer
  Fehlertyp `StateError`, exportiert), die Route antwortet mit `409`, der abgewehrte Versuch geht
  als `totp_setup_denied` ins Audit-Log, und eine neue Einrichtung räumt verwaiste Recovery-Codes
  ab. Der Weg zum Authenticator-Wechsel führt über das reguläre Abschalten
  (`POST /auth/totp/disable`, CSRF-geschützt und protokolliert); die Einrichtung für Konten
  **ohne** TOTP — auch aus einer `login_chain` heraus — bleibt unverändert offen.
  **Nachgearbeitet:** Der Fundtext verlangte zwei Dinge — bei bestätigtem TOTP verweigern *und*
  die Einrichtung nur auf ausdrückliche Anforderung beginnen. Das Zweite fehlte: Für jedes Konto
  ohne bestätigtes TOTP erzeugte weiterhin **jeder** GET ein frisches Geheimnis und ersetzte
  damit einen laufenden Einrichtungsversuch — ein fremder Link entwertete das eben gescannte
  QR-Bild (die Bestätigung schlug danach unerklärlich fehl) und stiess Audit-Zeilen von aussen
  an. Das Geheimnis entsteht jetzt ausschliesslich in der neuen, CSRF-geschützten Route
  **`POST /auth/totp/setup/start`**; der GET zeigt nur noch den Knopf, der sie auslöst (neue
  Texte `setup.start`/`setup.start_hint`, de/en). **Für einbettende Apps mit eigener TOTP-Seite:**
  `totp_begin()` **wirft** jetzt, und zwar `StateError` — der erbt von
  `TinySesamError`/`RuntimeError` und **nicht** von `ConfigError`; wer den dokumentierten Typ
  fängt, bekommt in seiner eigenen Route sonst einen 500. Weil `api_surface.json` Signaturen
  einfriert und geworfene Typen gar nicht sieht, listet [API.md](API.md) ab sofort die
  Fehlertypen samt Hierarchie (erzeugt aus den Docstrings).
  Fund **B2-1** aus [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md).
- **Das Erst-Admin-Einmal-Token stand im Klartext in der `security.log`.** Solange es keinen Admin
  gibt, schreibt TinySesam beim Start einen Hinweis auf `/auth/claim-admin?token=…` — bis 0.18.x
  mitsamt dem Wert, und zwar über `security.seclog`. Mit gesetztem `security_log` ist das genau die
  Datei, auf die die mitgelieferte fail2ban-Jail zeigt: sie entstand ohne Rechtevorgabe (gemessen
  `-rw-rw-r--`), logrotate hebt sie wochenlang auf, jedes Log-Shipping nimmt sie mit. Wer sie lesen
  konnte und irgendein Konto auf der Instanz hatte, löste den Token ein und war Admin. Jetzt geht
  der Wert auf **stderr** — die Konsole des Betreibers, der einzige Empfänger, den der Docstring je
  gemeint hat — oder, neu, in eine eigene Datei: `admin_claim_token_file` (wird mit **0600**
  angelegt, Rechte auch bei einer vorhandenen Datei vor dem Schreiben gesetzt). Im Log steht nur
  noch, *wo* der Token liegt. Dazu legt `attach_security_log()` die Logdatei selbst mit **0640** an
  statt mit der umask — auch die nach einer Rotation neu entstandene —, denn darin stehen
  Benutzernamen und IP-Adressen; eine schon vorhandene welt-lesbare Datei wird gemeldet, aber nicht
  umgeschrieben. Eine Konfigurationsprüfung verweigert `admin_claim_token_file == security_log`.
  **Für Betreiber:** 0640 heisst Eigentümer und Gruppe. Ein Log-Versand, der als *dritter*
  Benutzer läuft (weder Eigentümer noch in der Gruppe), verliert den Lesezugriff — und zwar nicht
  beim Update, sondern erst bei der nächsten Rotation, wenn der Handler die Datei neu anlegt. Wer
  ihn braucht, gibt sie über die Gruppe frei: logrotate-Zeile `create 0640 tinysesam adm`. Die
  stand bisher nur in der fail2ban-Vorlage und steht jetzt auch im `security_log`-Abschnitt von
  KONFIGURATION.md und beider READMEs. Was der Fix **nicht** löst und deshalb als bekannte Grenze
  in SECURITY.md und beiden READMEs steht: Eingelöst wird der Token über eine **URL**
  (`GET /auth/claim-admin?token=…`, bei nicht angemeldetem Aufruf zusätzlich im `Location` des
  Login-Redirects) und läuft damit durch Proxy-Access-Logs, `Referer` und Browser-History; per
  Vorgabe geht er ausserdem auf **stderr**, das journald, `docker logs` und jedes Log-Shipping
  einsammeln. Ein dauerhaftes Geheimnis gibt beides nicht her (genau einmal einlösbar, Ablauf per
  `admin_claim_ttl_min`, Route 404 sobald ein Admin existiert) — kurze Frist setzen, wo stderr
  gesammelt wird `admin_claim_token_file` nehmen, sofort einlösen.
  Gefunden im dritten Audit (B5-03 aus [T-13](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-13-audit-2026-09-22-runde-3.md)).
- **Das OIDC-Discovery-Dokument wird jetzt gegen den konfigurierten Issuer geprüft.** Bisher nahm
  TinySesam `issuer`, `token_endpoint` und `jwks_uri` ungeprüft aus dem Dokument und folgte beim Abruf
  auch Umleitungen — ein 3xx auf dem Well-Known-Pfad hätte genügt, um alle drei zu ersetzen, und die
  ID-Token-Prüfung hätte gegen den Issuer *aus dem Dokument* geprüft (RFC 8414 §3.3, OIDC Discovery §4.3
  verlangen den Vergleich). Jetzt: kein Redirect, nur 200, und `issuer` muss `oidc_issuer` entsprechen —
  sonst `ConfigError` mit beiden Werten. Der Schlüssel, unter dem Konten in der Datenbank liegen, bleibt
  der Issuer aus dem Dokument; er ist durch den Vergleich jetzt derselbe wie in der Konfiguration.
  Gefunden im dritten Audit (PocketID-Symbiose, RB-03).
- **CodeQL-Bestand bereinigt.** 61 offene Alerts lagen auf `main`, unbewertet. Sie tun nichts — bis ein Pull Request eine
  ihrer Zeilen berührt und der Merge an einem `note`-Thread hängt. Durchgesehen ([T-12](https://github.com/Ollornog/TinySesam/blob/main/backlog/T-12-codeql-bestand.md)):
  **ein echter Fund** — `examples/showcase.py` setzte den Benutzernamen unescaped in die Demo-Seiten
  `/app` und `/sensibel` (behoben mit `html.escape`); **neun Fehlalarme** mit Begründung abgewiesen
  (feste Redirect-Pfade, geloggte IPs statt Geheimnisse, sha256 für zufällige API-Keys, eine
  absichtlich 0644-Datei im Test); der Rest mechanisch bereinigt (nicht geschlossene Dateien in Tests,
  URL-Substring-Prüfungen, ungenutzte Importe, leere `except` mit Begründung). Neu:
  `scripts/_codeql_backlog.py` schreibt die offene Liste in den Backlog, damit neue Alerts im Repo
  landen und nicht nur im Postfach.
- **`auth.seed_demo()` prüft jetzt selbst, ob `demo_mode` an ist.** Der Docstring versprach das seit
  jeher, der Rumpf hielt es nicht: Ein direkter Aufruf legte `demo` und `demoadmin` an — letzteres
  mit `is_admin=1` und dem dokumentierten Standardpasswort, beide sofort anmeldefähig, ohne die
  Warnung im Log, die der Demo-Modus sonst ausgibt.
- **`deploy/forward-auth/nginx.conf` reichte einen Client-Header an die App durch.** `Remote-Name`
  fehlte in der Vorlage, und ein nicht gesetzter Header wird von nginx nicht weggelassen, sondern
  unverändert weitergereicht: Wer `Remote-Name: chef` mitschickte, bekam ihn hinter der
  Auth-Prüfung zugestellt, als käme er von TinySesam. Alle vier Header werden jetzt gesetzt.
- **Der fail2ban-Filter versprach einen Schutz, den er nicht leistet.** Die Verankerung `^…$` hält
  Fragmente heraus, aber eine eingeschobene Zeile aus einem manipulierten Benutzernamen ist
  vollständig und wohlgeformt — sie matcht genauso. Der Schutz ist allein die Bereinigung in
  0.18.0; der Kommentar sagt das jetzt.
- **Der zweite Faktor liess sich ohne frische Bestätigung abbauen — und per API-Key.**
  `POST /auth/totp/disable`, `/auth/totp/recovery`, `/auth/pin/set`, `/auth/pin/disable` und
  `/auth/passkey/delete` hingen allein an `current_user()`. Eine Sitzung, deren Step-up längst
  abgelaufen war — auf jedem `require(mfa=True)`-Guard ein 403 —, durfte damit TOTP löschen, sich
  zehn frische Recovery-Codes ausstellen und PIN wie Passkey entfernen: Ausgerechnet die
  Verwaltung der Faktoren stand hinter keiner Schranke. Dazu kam die zweite Hälfte: `current_user()`
  akzeptiert auch einen **API-Key**, und ein Maschinen-Credential erbringt nie einen interaktiven
  Faktor — ein abgeflossener CI-Key baute den zweiten Faktor seines Besitzers lautlos ab. Alle
  fünf Routen verlangen jetzt `require_mfa()`: interaktive Sitzung mit frischer Bestätigung, für
  einen API-Key konstruktiv unerreichbar (403, „Step-up-MFA nötig — nur per interaktiver Sitzung").
  Bei `/auth/pin/set` gilt das für das **Ersetzen** einer PIN; dass dieselbe Route auch die erste
  anlegt, ist der Sonderfall im Punkt unten. Die Konto-Seite wertet den Hinweis-Header
  `X-TinySesam-Reauth` jetzt selbst aus und schickt zur Reauth-Seite, statt stumm zu scheitern —
  gemessen wird das jetzt dort, wo es stattfindet: im Browser-Test (abgelaufene Frische, Klick auf
  „2FA abschalten", Landung auf `/auth/reauth`, der Faktor steht danach noch). Dabei fiel auf, dass
  die beiden Lösch-Knöpfe der Konto-Seite **unbedingt** Erfolg meldeten („✓ entfernt") und neu
  luden — auch bei 403 oder 500. Sie prüfen die Antwort jetzt. Fund **R3-3** aus
  [T-13](backlog/T-13-audit-2026-09-22-runde-3.md).
- **Der Riegel gegen den abbauenden API-Key war über die Faktor-ANLAGE umgehbar.** `require_mfa()`
  deckte nur den Abbau; `GET/POST /auth/totp/setup` und `POST /auth/passkey/register/{begin,finish}`
  hingen weiter allein an `current_user()` — und das akzeptiert einen API-Key, für den die
  CSRF-Prüfung ohnehin entfällt (`_csrf_entbehrlich`). Damit standen zwei Wege offen: Der Key liest
  das TOTP-Geheimnis im Klartext aus der Antwort der Einrichtungsseite und bestätigt es (danach
  kontrolliert der **Key-Inhaber** den zweiten Faktor — der echte Nutzer ist ausgesperrt, mit
  bekanntem Passwort ist es die volle Übernahme), oder er registriert einen eigenen Passkey. Ein
  Passkey ist ein vollwertiger Login: Über ihn bekam der Key eine frische interaktive Sitzung und
  stand damit doch vor genau den Routen, die ihn aussperren sollten. Die Anlage verlangt jetzt
  dasselbe wie der Abbau — eine Sitzung, kein Maschinen-Credential (neu:
  **`auth.require_session()`**, 403 „Einen Anmeldefaktor richtet ein Mensch ein …"). `register/finish`
  bindet den neuen Passkey zusätzlich an das angemeldete Konto statt nur an das Flow-Cookie.
  Angriff gegen den R3-3-Fix, nachgestellt im dritten Audit.
- **Die erste PIN eines rein föderierten Kontos war hinter `require_mfa()` unerreichbar.**
  `/auth/pin/set` ersetzt eine PIN — und ist zugleich der einzige Weg, sie **anzulegen**. Ein Konto
  ohne Passwort, PIN und TOTP (OIDC/SAML/LDAP) hat nichts, womit es einen Step-up leisten könnte:
  `stepup_options()` ist leer, und nach Ablauf von `stepup_max_age_sec` (Vorgabe 900 s ab Login)
  antwortete die Route 403 — die Reauth-Seite bot dazu ein **Passwortfeld** an, das dieses Konto
  nicht hat, und jeder aussichtslose Versuch zählte in dieselbe Brute-Force-Sperre. Für ein Konto, das **gar keinen** Faktor hat, hängt das
  **Anlegen** jetzt am Alter der Anmeldung (neu: **`auth.login_fresh()`**, dieselbe Spanne,
  gemessen ab Login statt ab Faktor-Bestätigung); **Ersetzen, Abbauen — und das Anlegen für
  jedes Konto, das überhaupt etwas zum Bestätigen hat — bleiben hinter `require_mfa()`**. Die
  Einschränkung ist Absicht: Mit `pin_login` ist eine PIN ein vollwertiger Erstfaktor, ein
  gestohlenes frisches Sitzungscookie richtete sich sonst einen eigenen, den Diebstahl
  überdauernden Zugang ein. Für ein Konto mit Passwort heisst das: erst bestätigen (die
  Kontoseite führt über `X-TinySesam-Reauth` von selbst dorthin), dann die erste PIN. Ein
  früherer Entwurf dieses Eintrags las sich, als genüge überall die frische Anmeldung — die
  Regel ist jetzt in `tests/test_pin_stepup.py` gemessen, statt nur beschrieben. Ist auch die Anmeldung zu alt, sagt die Antwort, was hilft („melde dich neu
  an"), und verweist **nicht** mehr auf die Reauth-Seite. Die zeigt bei leerer Methodenliste jetzt
  gar kein Formular, und ein POST dorthin wird nicht als Fehlversuch protokolliert.

### Hinzugefügt

- **Mehrere Anwendungen hinter einer Installation** (`oidc_clients`, T-14). Wer in welche
  Anwendung darf, entscheidet der Identity Provider — bei PocketID über die Gruppenfreigabe je
  OIDC-Client. Diese Freigabe hängt am **Client**, nicht am Benutzer: Mit einem einzigen Client
  gibt es für alle Anwendungen nur eine Antwort, und wer in eine darf, darf in alle. Die bisherige
  Abhilfe war eine eigene Instanz je Anwendung — drei Container, drei Datenbanken, drei
  Audit-Logs für dieselben Menschen.

  Jetzt ordnet `oidc_clients` jedem geschützten Host einen eigenen Client beim **selben** Provider
  zu (`client_id`, `client_secret`, optional `scopes`, `allowed_groups`, `group_role_map`). Alle
  zeigen auf **eine** Redirect-URI: Welcher Client gemeint ist, steht im Vorgang auf dem Server,
  nicht in der Adresse — beim Provider trägt man deshalb überall dieselbe ein. `/auth/forward`
  fragt ab jetzt zwei Dinge statt einem: angemeldet, **und** für diese Anwendung freigegeben.
  Fehlt die Freigabe, geht es nicht mit 403 gegen den Menschen, sondern mit 401 über den Provider
  — er entscheidet, er zeigt seine eigene Absage.

  Die Freigabe steht in der neuen Tabelle `oidc_grant` (Schema 6), je Sitzung und Anwendung, mit
  den Rollen, die der Provider **für diese Anwendung** ergab. Eine Konfiguration ohne
  `oidc_clients` verhält sich um kein Byte anders als in 0.18.0.

- **Der Widerruf folgt dem Provider** (`oidc_revalidate_minutes`, Vorgabe 0 = aus; das Preset
  `oidc_gateway()` setzt 60). Ohne Nachprüfung galt eine einmal erteilte Freigabe bis zum Ablauf
  der Sitzung — in der Vorgabe **sieben Tage**. Ein Gruppenentzug im Provider wirkte so lange
  nicht, und genau das ist der Fall, für den man die Freigabe dort pflegt. Läuft die Frist ab,
  nimmt die nächste Anfrage den Weg über den Provider; dessen Sitzung besteht in aller Regel
  weiter, der Mensch sieht ein Flackern statt einer Anmeldemaske. Sagt der Provider Nein, ist die
  Freigabe **für diese eine Anwendung** weg — die Sitzung und die übrigen Anwendungen bleiben.

  Bewusst **ohne Refresh-Token in der Datei**: Der stille Weg über einen Refresh-Grant hätte ein
  benutzbares Geheimnis je Sitzung in die Datenbank gelegt. Der Sprung über den Provider braucht
  keines und beantwortet dieselbe Frage.

  Die Stunde ist eine Abwägung, keine Formel: Jede Nachprüfung ist ein Sprung über den Provider,
  und der ist für einen Menschen am Browser ein Flackern, für ein offenes Formular oder eine
  laufende XHR-Anfrage dagegen ein Bruch. Gegenüber sieben Tagen ist die Größenordnung das
  Entscheidende; zwischen 15 und 60 Minuten entscheidet sich selten ein Entzug, wohl aber,
  wie oft es jemanden mitten in der Arbeit trifft.

- **Gateway-Umgebungsvariablen** dafür: `TINYSESAM_OIDC_CLIENTS` als JSON oder je Host
  `TINYSESAM_OIDC_CLIENT_<HOST>_ID`/`_SECRET`. Der Hostname aus dem Variablennamen wird gegen
  `TINYSESAM_PROTECTED_HOSTS` abgeglichen, weil ein `_` im Namen für einen Punkt **oder** einen
  Bindestrich stehen kann — ohne den Abgleich entstünde stillschweigend ein Eintrag für einen
  Host, den es nicht gibt, und die Zuordnung griffe nie. Passt nichts, sagt eine Logzeile das.

- **`stepup_strict`** (Vorgabe `False`): macht aus `stepup_methods` eine Schranke. Bisher war die
  Liste nur ein Wunsch — wer keines der genannten Verfahren eingerichtet hatte, bestätigte mit
  allem, was er hatte, inklusive des Passworts, mit dem er sich gerade angemeldet hatte. Das ist
  kein Step-up. Mit `True` bleibt der Bereich verschlossen, bis das Verfahren eingerichtet ist;
  die Seite sagt das jetzt auch, statt ein Formular ohne Felder zu zeigen.
- **`auth.require_session(request)`** und **`auth.login_fresh(request)`** — die beiden Schranken
  aus den Punkten oben, auch für eigene Konto-Seiten: „angemeldet, aber nicht per API-Key" und
  „die Anmeldung ist höchstens `stepup_max_age_sec` alt". Reine Erweiterung, kein Bruch.
- **`auth.is_reauth_locked(username, ip)` und `auth.is_resource_locked(username, ip)`** samt
  den Schwellen **`reauth_max_attempts`** und **`resource_max_attempts`** (je 5, im Panel
  änderbar wie die übrigen): die eigenen Töpfe für Step-up-Bestätigung und Bereichs-PIN. Dazu
  `security.EIGENE_SPERRE` (Methode → Riegel; `NICHT_LOGIN_METHODEN` ist daraus abgeleitet) und
  `security.log_ereignis(method)` für das Ereigniswort der Log-Zeile.
- **`deploy/fail2ban/tinysesam-verify-filter.conf`** plus die Jail `[tinysesam-verify]` in der
  Vorlage — die mildere, standardmässig abgeschaltete zweite Jail für `failed verification`.
- **`recent_audit(limit, username=…)`** filtert in SQL (siehe `audit --user` oben).
- **Drei Wächter in `tests/test_repo.py`**: Die in beiden READMEs genannte Zahl der Testdateien und
  die Python-Spanne werden gegen die Wirklichkeit gemessen, und solange die Version unter 1.0 liegt,
  darf keine README eine PyPI-Installation zeigen. Genau diese drei Zahlen waren falsch — Zahlen,
  die niemand nachmisst, veralten beim nächsten Commit.
- **`tests/test_bestandsdaten.py`** — 28 Prüfungen zu dem, was ein Upgrade überleben muss.
- **Zusagen dieses Zyklus, die niemand gemessen hat, haben jetzt einen Test** — jede per
  Mutationsprobe belegt (Rückbau → rot, sonst grün), nachdem sich alle mit voller Suite 46/46
  zurückbauen liessen: `ConfigError.feld`/`.besitzer_id` **und** der unveränderte Meldungstext
  „… ist bereits vergeben" (`tests/test_identifier.py`); der **PIN**-Lösch-Knopf der Konto-Seite,
  der Erfolg erst nach `r.ok` meldet — gedeckt war nur der 2FA-Knopf, und zwar im Browser-Test,
  der die PIN-Sektion gar nicht zu sehen bekommt (`tests/test_account.py`); die Bindung von
  `passkey/register/finish` an das angemeldete Konto, gegen einen untergeschobenen fremden Flow
  (`tests/test_methods.py`); und dass die beiden Betreiber-Meldungen nur Wege nennen, die es gibt
  (`tests/test_security_log.py`, `tests/test_sicherheit_befunde.py`).

### Geändert — Python 3.12 ist die neue Untergrenze (Matrix 3.12 / 3.13 / 3.14)

**`requires-python` steigt von `>=3.10` auf `>=3.12`.** Wer TinySesam auf 3.10 oder 3.11
betreibt, bekommt beim nächsten Update von pip kein neues Paket mehr — das ist der Zweck der
Angabe, und sie ist die einzige Stelle, die das ehrlich sagen kann.

Dahinter steht keine Zahl, sondern ein Fenster: **die letzten drei stable Minors**. Python 3.10
geht am 31.10.2026 EOL. Die Zusage „läuft ab 3.10" war zuletzt ohnehin dünn — sie stand im
pyproject, aber die Untergrenze wanderte nie mit, und jede Bibliothek darunter zieht früher oder
später nach.

Die Matrix fährt damit **3.12, 3.13, 3.14** statt bisher 3.10–3.14; die Classifier für 3.10 und
3.11 sind entfallen (eine ungemessene Zusage ist eine Behauptung — die Suite erzwingt das). Die
Obergrenze bleibt bewusst bei 3.14: **3.15 erscheint am 01.10.2026**, läuft aber weiterhin nur im
nightly-Job mit `continue-on-error` und rückt erst ins Gate, wenn sie dort wirklich grün war.

Geführt wird die Matrix jetzt an **einer** Stelle statt an dreien.

### Geändert

- **Die Installationsanleitung führt mit dem Git-Tag.** Beide READMEs begannen mit
  `pip install tinysesam` — der Name ist auf PyPI nicht registriert, der Befehl endet mit
  `No matching distribution found`. Die erste Zeile, die jemand ausprobiert, war die erste, die
  fehlschlug. Veröffentlicht wird mit 1.0 ([ADR-6](backlog/ADR-6-pypi-veroeffentlichen.md)).
- **Der Status-Abschnitt beider READMEs** beschrieb den Stand 0.5/0.6 (»17 bzw. 22 Testdateien«)
  in einem Paket mit zwei Sicherheitsaudits, SAML, Gateway und Kommandozeile hinter sich.
- **`web/flows.py` nennt `ldap_enabled`** beim Abschnitt „Externer IdProvider". Die Seite
  verspricht im Vorspann, neben jeder Überschrift stehe die Config, die sie einschaltet — für
  eines der drei genannten Verfahren stand sie nicht da.
- **Docstrings**, die nicht mehr stimmten: `mailer` (es gibt kein `send()`, der Mailer wird
  aufgerufen), `gateway` (`[gateway]`, nicht `[oidc]` — das ist die Bibliothek ohne Server),
  `router` (14 bedingte Blöcke, nicht zwei), `mfa_pending` (kein „global erzwungen" mehr),
  `create_api_key` (wirft bei leerem Scope).

## [0.18.0] — 2026-09-21

**Sicherheits-Release. Wer TinySesam einsetzt, sollte aktualisieren** — sechs Lücken, jede mit
einem eigenen Nachstellungs-Skript belegt, darunter Rollen-Eskalation und Konto-Unterschiebung.
Die Einzelheiten stehen unter „Behoben"; die Tests dazu halten jeden nachgestellten Angriff fest,
damit er nicht zurückkommt.

**Diese Version ist bewusst NICHT 1.0.** Der Sprung war vorbereitet und wurde zurückgenommen:
Eine Reifeprüfung mit vier unabhängigen Blickwinkeln fand 47 Befunde, von denen 12 einzeln
nachgestellt wurden — **12 haltbar, 11 davon Blocker**. Ein Paket mit Rollen-Eskalation trägt kein
„Production/Stable", und eine PyPI-Version ist unwiderruflich. Der Reifegrad steht deshalb weiter
auf `4 - Beta`.

**Warum das niemandem auffiel, ist der eigentliche Befund:** `tests/run_all.py` hat echte
Fehlschläge als „übersprungen" verbucht. Die Suite war grün, weil sie nicht gemessen hat. Das ist
zuerst repariert worden — alles andere wäre auf Sand gebaut.

**Die Vorbereitung für PyPI bleibt drin** (Metadaten, Trusted Publishing, Packaging-Test,
`MANIFEST.in`) — veröffentlicht wird sie erst mit 1.0. Bis dahin gilt weiter die Installation
über den gepinnten Git-Tag.

### Hinzugefügt — Lieferketten-Hygiene (CodeQL, Dependabot für pip, Digest-Pin)

Aus einer Recherche dazu, was ein quelloffenes Auth-Paket vor 1.0 haben sollte:

- **Statische Analyse** lief bisher gar keine. Neu: `.github/workflows/codeql.yml`
  (`security-and-quality`, wöchentlich und bei jedem PR). Für ein Auth-Paket war das die
  auffälligste Lücke — der OpenSSF-Scorecard-Check `SAST` hätte 0 ergeben.
- **Dependabot deckte nur `github-actions` ab**, nicht `pip`: Für `fastapi`, `authlib`,
  `python3-saml` & Co. gab es keine regulären Versions-PRs. Sicherheitslücken meldet Dependabot
  ohnehin repo-weit — aber ein Auth-Paket sollte nicht auf der Version von vorgestern sitzen
  bleiben, bis jemand eine findet. Gruppiert zu einem PR je Monat, damit ein Solo-Projekt nicht
  in Rauschen ertrinkt. Das Basis-Abbild wird ebenfalls beobachtet.
- **Das Docker-Basis-Abbild ist per Digest gepinnt** statt per Tag. `python:3.12-slim` zeigt
  heute hierhin und morgen woanders; zwei Bauläufe desselben Commits ergaben verschiedene
  Abbilder.

Bereits erfüllt und deshalb nur der Vollständigkeit halber: **Private Vulnerability Reporting**
ist im Repo eingeschaltet (nachgeprüft, nicht angenommen) — SECURITY.md verspricht den Weg, und
er existiert auch.

### Sicherheit — zweites Audit: die Reparaturen der Reparaturen

Vier unabhängige Blickwinkel, diesmal auf den frischen Code selbst gerichtet. **43 Befunde, 5
Blocker** — und drei davon waren Löcher, die beim Schliessen der ersten sechs entstanden sind.
Das ist der eigentliche Ertrag dieser Runde: Wer eine Lücke schliesst, prüft seinen eigenen
Verschluss nicht. Belege in `tests/test_audit_runde2.py` ([T-9](backlog/T-9-audit-2026-09-21-runde-2.md)).

**Der Erst-Admin liess sich weiterhin kapern — über den Benutzernamen.** Der neue Wächter
verlangt bei offener Registrierung eine *E-Mail* in `admin_identifiers`, mit der Begründung „den
Namen hat, wer das Postfach hat". `maybe_promote_admin` verglich aber weiter *Name ODER E-Mail*,
und ein Benutzername ist ein freies Textfeld: Wer sich als `username="chef@example.com"`
registrierte und sein eigenes Postfach bestätigte, wurde Erst-Admin. Die Lücke war nur
verschoben. Jetzt gilt: Eintrag mit `@` nur gegen die E-Mail, ohne `@` nur gegen den Namen.

**Ein API-Key-Scope, der zu nichts zusammenschrumpfte, wurde zu „erbt alles".** `["lagre"]` — ein
Tippfehler — beschnitt auf `[]`, und `[]` heisst in der Datenbank „kein Scope". Die Beschneidung,
die begrenzen sollte, machte den Key **mächtiger**. Ein solcher Key entsteht jetzt gar nicht
erst; was gemeint war, weiss nur der Aufrufer.

**Die CSRF-Prüfung hatte einen vom Client gewählten Ausschalter.** `require_csrf` übersprang,
sobald irgendein `X-API-Key`-Header dastand — ungeprüft, auch bei `apikey_enabled=False`, und
danach lief die Anmeldung über das Sitzungs-Cookie weiter. Übersprungen wird jetzt nur bei einem
**echten** Key ohne Sitzung.

**Ein gescopter Key stellte sich selbst einen mächtigeren aus.** Schlüsselverwaltung verlangt
jetzt eine interaktive Sitzung: Schlüssel gibt ein Mensch aus, kein Schlüssel.

**Ein TOTP-Code galt 90 Sekunden lang beliebig oft** — zwei getrennte Clients konnten sich mit
demselben Code voll anmelden. NIST SP 800-63B ist eindeutig: „Verifiers SHALL accept a given OTP
only once while it is valid." Der verbrauchte Zeitschritt wird jetzt gebucht (Schema 3).

**Der Freigabe-Token für gesperrte Ressourcen lag im Klartext** in der Datenbank und war
identisch mit dem Cookie — dasselbe Bedrohungsmodell, das die Sitzungs-Umstellung begründet, nur
eine Tabelle weiter (Schema 4).

**Die Migration war nicht atomar.** `ALTER TABLE` committet für sich; ein Abbruch davor
hinterliess Klartext-Token in der Spalte `token_hash` — dauerhaft, weil die Erkennung danach nie
wieder greift. Jetzt läuft alles in einer Transaktion (`BEGIN IMMEDIATE`), und die Erkennung
sucht Zeilen, die nicht wie ein Hash aussehen: Das **heilt** eine bereits beschädigte Datei.
Nebenbei gelöst: Bei mehreren Workern starb einer beim Start mit `no such column: "token"`.

**Der Erst-Admin-Wächter, `POST /auth/magic/request`** (einzige zustandsändernde Route ohne
CSRF) und **[B-1](backlog/B-1-admin-panel-rotiert-csrf.md)** (das Panel würfelte bei jedem
Aufruf ein neues CSRF-Token) sind ebenfalls zu — B-1 lag auf „nach 1.0" und traf durch die neuen
CSRF-Prüfungen inzwischen mehr Wege.

**Weiteres:** Recovery-Codes 64 → **112 Bit** (die NIST-Schwelle für ungesalzenes Hashing);
scrypt-Fallback auf eine zugelassene OWASP-Kombination; scrypt-Hashes steigen jetzt auf argon2
auf, wenn das Extra nachinstalliert wird (vorher blieben Bestandskonten für immer auf dem
schwächeren Verfahren); das Sitzungs-Token wird beim Rechtewechsel erneuert und das CSRF-Token
beim Login rotiert (beides OWASP); `/auth/oidc/start` ist ratenbegrenzt (vorher die einzige
flow-erzeugende Route ohne).

### Behoben — `tinysesam backup` veränderte die Datei, die es sichern sollte

`_oeffne()` nahm den vollen `Store`-Konstruktor — der setzt `journal_mode=WAL`, legt Tabellen an
und **migriert**, alles bevor eine Kopie existiert. Wer vor einem Update das einzig Richtige tat
und sicherte, hob damit die laufende Installation auf das neue Schema, während noch der alte Code
lief. Der Rückweg war zu, und eine Datei im alten Schema gab es danach nirgends mehr.

`Store.sichere_datei()` öffnet jetzt read-only. Gemessen an einer echten 0.17.0-Datei: Quelle
unverändert, Kopie vollständig und im alten Schema.

**Und das Zurückspielen war nicht dokumentiert** — mit derselben WAL-Falle spiegelverkehrt: Nach
einem Absturz liegen `-wal`/`-shm` daneben, SQLite spielt sie auf die frisch zurückgespielte
Datei, der alte Stand ist zurück, und `integrity_check` sagt `ok`. Neu: **`tinysesam restore`**,
das die Reihenfolge erzwingt und die Sicherung prüft, bevor es irgendetwas überschreibt.

### Hinzugefügt — Werkzeuge für den Störfall

**`tinysesam audit`** und **`tinysesam unlock`**. Das Audit-Log war nur über das Admin-Panel
lesbar, also nur als angemeldeter Admin — ausgerechnet dann unerreichbar, wenn die Anmeldung das
Problem ist. Und eine Brute-Force-Sperre liess sich gar nicht gezielt aufheben; übrig blieb
`gc --attempts-older-than 0`, das die Fehlversuche **aller** Konten wegräumt.

Dazu hält das Protokoll jetzt fest, **warum** eine Anmeldung scheiterte (`kein_konto`,
`konto_gesperrt`, `falsches_geheimnis`). Die HTTP-Antwort tut das bewusst weiterhin nicht — im
Protokoll liest nur der Betreiber mit, und dort waren die drei häufigsten Ursachen bisher
byte-identisch.

**Der Healthcheck fragt die Datenbank** (`SELECT 1`, 503 bei Defekt). Vorher meldete er nur, dass
der Prozess lebt: Nach einem Rollback oder bei vollem Volume lieferte der Dienst allen
angemeldeten Nutzern 500, während Docker den Container dauerhaft als `healthy` führte.

**`deploy/systemd/`** bringt Timer und Service für `gc` mit — die README verwies darauf, ohne
dass eine Vorlage dabei lag — samt einem Wort zur Aufbewahrung des Audit-Logs (es speichert
IP-Adressen) und dem `VACUUM`, ohne das `gc` keinen Plattenplatz zurückgibt.

**Das mitgelieferte Compose und die mitgelieferte fail2ban-Jail passten nicht zusammen:** Das
Compose setzte kein `TINYSESAM_SECURITY_LOG` und mountete kein Logverzeichnis, die Jail zeigte
also auf eine Datei, die es nie gab. Zwei Bausteine, die einzeln richtig aussahen und zusammen
nichts taten.

### Behoben — fail2ban liess sich gegen Dritte richten

Der Benutzername ging **ungefiltert** in die Logzeile, die fail2ban liest. Ein `\n` darin erzeugt
eine zusätzliche Zeile; mit einem Umbruch vorn und hinten schiebt man die echte `ip=`-Angabe auf
eine Folgezeile, die der Filter nicht mehr matcht, und lässt dazwischen eine frei erfundene
stehen. fail2ban zählt dann die Fehlversuche einer **vom Angreifer gewählten** IP, während die
echte null Treffer erzeugt — bei `maxretry = 6` genügen sechs Anfragen, um eine beliebige Adresse
auszusperren. Gegen echtes fail2ban 1.1.1 belegt.

Steuerzeichen fliegen jetzt raus, die Länge ist gedeckelt, und der mitgelieferte Filter ist auf
die ganze Zeile verankert (`^…$`) — wer eine ältere Fassung fährt, sollte den Filter übernehmen.

### Behoben — die eigenen Prüfungen behaupteten mehr, als sie messen

Jede Zusage wurde per Mutation gegengeprüft; sieben hielten nicht:

- **Im git-worktree wand sich die gesamte Repo-Hygiene ab** — dort ist `.git` eine *Datei*, und
  die Prüfung fragte `.is_dir()`. Privat­e Infrastruktur, Geheimnisse, SHA-Pins: alles weg, Lauf
  grün.
- **`run_all.py` kannte keinen Boden:** Exit 0 auch bei „0 grün, alles übersprungen".
- Der **PyPI-Geheimnis-Check** liess sich mit einem `name:` über dem Schritt aushebeln.
- **`test_repo`** fing `import subprocess`, aber nicht `from subprocess import run` und nicht
  `os.system` — daneben steht eine Sicherheitsaussage. Läuft jetzt über den Syntaxbaum, inklusive
  Alias-Auflösung.
- **`test_api_surface`** fror Klassenattribute nicht ein (`FORWARD_HEADERS_DEFAULT` ist in der
  Doku eine Zusage und liesse sich still ändern).
- **`test_kern_install`** mass an zwei Stellen Textvorkommen statt Verhalten.
- **`test_typen`** fuhr mypy ohne `--check-untyped-defs`: 120 von 410 Funktionen ungeprüft,
  darunter alle vier Presets. Mit der Tiefe fielen sofort sechs echte Fehler an.

Zwei Suiten hatten ausserdem den **TOTP-Replay festgeschrieben** (derselbe Code zweimal). Ein
Test, der ein kaputtes Verhalten absichert, ist selbst ein Fund.

### Geändert — ⚠️ beim Update beachten: was sich im Verhalten ändert

**Die öffentliche Oberfläche bricht fast nicht:** Keine Methode wurde entfernt oder umbenannt, kein
Parameter ist weggefallen, kein Config-Feld hat seinen Typ geändert. Die sieben Signaturen, die
`tests/api_surface.json` als geändert verzeichnet, sind ausschließlich `x: bool = None` →
`x: Optional[bool] = None` — zur Laufzeit identisch, nur ehrlicher annotiert.

**Eine Ausnahme: `passkey_enabled` steht jetzt auf `False`** (vorher `True`) — der einzige
Vorgabewert, der sich geändert hat. Er stand auf `True`, obwohl `webauthn` nicht im Kern liegt,
sondern im Extra `[passkey]`: Der allererste Schritt einer Installation ohne Extras stürzte damit
mit `ModuleNotFoundError: webauthn` ab. Wer Passkeys nutzt und den Schalter **nie gesetzt hat**,
muss ihn jetzt setzen (`passkey_enabled=True` plus das Extra) — sonst verschwinden nach dem Update
die Passkey-Routen und der Knopf auf der Login-Seite. Hinterlegte Credentials bleiben in der
Datenbank und sind sofort wieder nutzbar, sobald der Schalter steht.

**Das Verhalten ändert sich trotzdem**, und zwar dort, wo ein Sicherheitsfix es verlangt. Das
sieht kein API-Wächter. Die Liste, nach Auswirkung sortiert:

**Der Start bricht ab, wenn die Konfiguration sich widerspricht** (neu, vorher lief sie):

| Konfiguration | Warum jetzt `ConfigError` |
|---|---|
| `totp_required=True` | Der Schalter wurde nie gelesen — er versprach 2FA und lieferte keine. Ersatz: `login_chain=['password','totp']` |
| `admin_identifiers=[…]` + `allow_signup=True` | Wer die Adresse errät, registriert sich darunter und wird Admin. Erlaubt mit bestätigter E-Mail |
| `cookie_samesite` außerhalb `lax/strict/none` | Starlette prüfte erst beim ersten Cookie — und unter `python -O` gar nicht |
| `cookie_samesite='none'` ohne `cookie_secure` | Der Browser verwirft so ein Cookie; die Anmeldung käme nie an |
| keine aktive Anmelde-Methode | Niemand kann sich anmelden, und nichts sagte es |
| `login_chain` mit abgeschaltetem oder unbekanntem Schritt | Die Kette ist unerfüllbar, der Nutzer landet in einer Schleife |

**Wer die Store-API direkt benutzt**, liest `row["token_hash"]` statt `row["token"]` —
Sitzungs-Token stehen nur noch als sha256 in der Datenbank. Die Schreibwege
(`set_session_mfa`, `set_session_factors`, `delete_session_by_handle`) nehmen dieses Handle und
**werfen** bei einem Klartext-Token, statt still ins Leere zu laufen. Die Datenbank migriert sich
beim ersten Start selbst; **bestehende Anmeldungen bleiben gültig**.

**Sechs nutzerseitige Methoden liefern jetzt ein `dict`** statt einer `sqlite3.Row` (`get_user`,
`find_user`, `check_password`, `check_ldap`, `check_saml`, `pending_user`). Zugriffe per
`u["name"]` funktionieren unverändert; `.get()` geht jetzt zusätzlich. Wer auf `sqlite3.Row`
typprüft, muss anpassen.

**Vier Routen verlangen jetzt ein CSRF-Token** — `POST /auth/totp/disable`, `/auth/totp/recovery`,
`/auth/pin/disable`, `/auth/apikeys/{id}/revoke` —, im Admin-Panel gilt es für **jede** nicht-lesende
Methode. Eine eigene UI, die diese Endpunkte ohne `X-CSRF-Token` aufruft, bekommt 403.

**Weitere Verhaltensänderungen:**

- **SAML ist jetzt ausschließlich SP-initiiert.** IdP-initiierte Logins funktionieren nicht mehr
  (Einstieg ist `/auth/saml/login`), und das Flow-Cookie übersteht den Cross-Site-POST des IdP nur
  mit `cookie_secure=True`.
- **Forward-Auth-Header gehen immer als UTF-8 über die Leitung.** Eine nachgelagerte App, die
  `Remote-Name` als Latin-1 liest, sieht bei Umlauten verstellte Zeichen — dafür funktionieren
  Namen wie „Иван" überhaupt erst.
- **API-Keys werden beim Aussperren mitgenommen:** Admin-Passwort-Reset, Konto sperren und
  „**alle** Sitzungen beenden" (`scope=all`) widerrufen sie. Der eigene Passwortwechsel nicht.
- **Ein API-Key kann nie mehr Rollen haben als sein Besitzer.** Keys, die bisher erfundene Rollen
  trugen, verlieren sie beim nächsten Gebrauch.
- **Ein erfolgreicher Login räumt nur noch die Fehlversuche derselben Methode.** Wer sich auf das
  frühere Verhalten verließ, sieht länger bestehende Sperren auf anderen Faktoren.
- **HTTP-Fehlertexte sind übersetzt.** Wer auf den deutschen Wortlaut einer `detail`-Meldung
  geprüft hat, muss auf den Statuscode umstellen.
- **Eine neu angelegte Datenbank bekommt `0600`.** Bestehende Dateien werden nicht umgestellt —
  aber ein zweiter Prozess unter anderer Kennung kann eine neue Datei nicht mehr lesen.

**Aus dem zweiten Audit kamen weitere Verhaltensänderungen dazu:**

- **Ein TOTP-Code gilt genau einmal.** Wer denselben Code zweimal einreicht — eine Automatik, ein
  Test, ein Doppelklick auf „Absenden" —, bekommt beim zweiten Mal eine Ablehnung. Zwei eigene
  Suiten hatten genau das getan.
- **API-Keys werden aus einer Sitzung ausgestellt, nicht mit einem API-Key.**
  `POST /auth/apikeys` und `…/revoke` antworten mit 403, wenn der Aufrufer per Key angemeldet ist.
- **Ein API-Key-Scope, der keine Rolle des Besitzers trifft, wird abgewiesen** statt beschnitten
  (`ConfigError`). Vorher entstand daraus ein Key, der *alle* Rollen erbte.
- **Die CSRF-Ausnahme gilt nur noch bei einem echten API-Key ohne Sitzung.** Wer bisher einen
  beliebigen `X-API-Key`-Header mitschickte und sich per Cookie anmeldete, bekommt jetzt 403.
- **`POST /auth/magic/request` verlangt ein CSRF-Token.**
- **Das Sitzungs-Token wird beim zweiten Faktor erneuert.** Wer das Token selbst festhält (statt
  dem Cookie zu folgen), muss den neuen Wert übernehmen; `complete_totp()` gibt ihn zurück.
- **`admin_identifiers` unterscheidet jetzt:** Ein Eintrag mit `@` gilt nur für die E-Mail, einer
  ohne nur für den Benutzernamen. Wer beides gemeint hat, trägt beides ein.
- **Freigaben für gesperrte Ressourcen aus der Zeit vor dem Update werden verworfen** — sie sind
  nicht umrechenbar. Betroffene öffnen die Ressource mit ihrem Geheimnis neu.
- **`forward_headers` verlangt Strings oder Listen davon**; `None` und Zahlen werden jetzt beim
  Aufbau abgewiesen statt später ein 500 zu erzeugen.

**Nicht betroffen:** `complete_mfa()` bleibt als Alias von `complete_totp()` erhalten, alle
bisherigen Exporte bleiben, und die vier neuen Fehlertypen erben von dem eingebauten Typ, den sie
ersetzen — `except ValueError` und `except RuntimeError` fangen weiter.

### Sicherheit — sechs Lücken geschlossen, jede mit ihrem Angriff festgehalten

Gefunden bei der Reifeprüfung vor dem geplanten 1.0. Jede der sechs ist einzeln nachgestellt
worden, bevor sie repariert wurde, und jede hat jetzt eine Prüfung in
`tests/test_sicherheit_befunde.py` — benannt nach dem **Angriff**, nicht nach der Funktion: Wer
eine davon rot sieht, weiss sofort, was wieder möglich ist. Jeder Fix wurde zusätzlich durch
Abschalten gegengeprüft (Mutation): ohne ihn wird die Prüfung rot, mit ihm grün.

**Rollen-Eskalation über selbst ausgestellte API-Keys.** Ein Nutzer konnte einem eigenen Key
beliebige Rollen mitgeben — auch `admin`. `create_api_key` beschneidet sie jetzt auf die Rollen
des Besitzers und meldet die verworfenen zurück. Und weil ein Key den Besitzer überdauert: beim
Prüfen wird erneut mit dessen aktuellen Rollen geschnitten, ein entzogenes Recht lebt im Key
nicht weiter.

**OIDC-Callback war an keinen Anmeldeversuch gebunden.** Wer einen gültigen Autorisierungs-Code
besass, konnte ihn im Browser eines Fremden einlösen (Login-CSRF). Der Flow hängt jetzt an einem
kurzlebigen, httponly gesetzten Cookie; der Callback verlangt es, vergleicht in konstanter Zeit
und löscht es danach.

**SAML nahm Assertions an, die nie angefordert wurden.** `InResponseTo` band die Antwort an
nichts — python3-saml prüft das Feld nur, wenn es überhaupt dasteht, eine Antwort ganz ohne es
ging durch. Die ID des AuthnRequests wird jetzt aufbewahrt und beim Einlösen hart verlangt.
Damit ist diese Fassung ausdrücklich **SP-initiiert**: IdP-initiierte Logins gibt es nicht mehr.
Beachten: Das Flow-Cookie muss den Cross-Site-POST des IdP überleben, was nur mit
`SameSite=None; Secure` geht — bei `cookie_secure=False` bleibt es beim Config-Wert und ein
echter IdP-Login scheitert (der Grund steht dann im Log `tinysesam.security`).

**Vier zustandsändernde Routen ohne CSRF-Schutz.** Das Abschalten von TOTP, das Neuausgeben der
Wiederherstellungs-Codes, das Abschalten der PIN und das Widerrufen von API-Keys liessen sich
von fremden Seiten aus auslösen — der zweite Faktor war per Formular abschaltbar. Alle vier
verlangen jetzt ein Token; im Admin-Panel gilt das für **jede** nicht-lesende Methode. Ausserdem
stand das Abschalten von TOTP und PIN in keinem Protokoll: Wer den zweiten Faktor verliert, soll
das nachlesen können.

**Ein erfolgreiches Passwort löschte die Sperre des zweiten Faktors.** `record_login` räumte
beim Erfolg *alle* Fehlversuche eines Kontos weg, auch die des TOTP — wer das Passwort hatte,
setzte damit den Zähler zurück und konnte den zweiten Faktor weiter raten. Geräumt wird jetzt
nur noch die Methode, die tatsächlich geklappt hat.

**Der Erst-Admin liess sich per Registrierung kapern.** `admin_identifiers` verbürgt, welcher
*Name* Admin wird — nicht, wer ihn bekommt. Zusammen mit offener Selbst-Registrierung meldete
sich der Erste, der die Adresse erriet, genau darunter an. Der Konstruktor weist diese
Kombination jetzt ab und nennt die tragfähigen Wege (bestätigte E-Mail-Adresse, oder der
Einmal-Token unter `/auth/claim-admin`).

### Hinzugefügt — zwei Nachschlagewerke, beide generiert

**[`KONFIGURATION.md`](KONFIGURATION.md)** führt alle **119** Config-Felder mit Typ, Vorgabe und
Bedeutung. 39 davon kamen vorher in keiner Doku vor. Erzeugt aus den Kommentaren in `config.py`
(`scripts/_config_doku.py`), damit es nicht wieder auseinanderläuft — und 32 Felder, die gar
keinen Kommentar hatten, haben jetzt einen. Eine Prüfung verlangt beides: Abzug aktuell, kein
Feld ohne Erklärung.

**[`API.md`](API.md)** führt die eingefrorene Oberfläche mit Signatur und erstem Satz: **106
Methoden** von `TinySesam` plus die 6 Presets von `TinySesamConfig`, zusammen 112 Einträge.
68 davon kamen in keiner Doku vor: Wer TinySesam einbettet, sah die Zusage „diese Oberfläche
bleibt stabil" ohne eine Stelle, an der steht, was sie enthält. Alle haben jetzt einen Docstring.
(Erzeugt wie `KONFIGURATION.md` — die Zahl in diesem Absatz ist der Stand dieses Release, die
aktuelle steht in der Datei selbst.)

**Offen und bewusst nicht nebenbei entschieden:** *welche* dieser Methoden auf Dauer öffentlich
sein sollen. Die Oberfläche ist gemessen (alles ohne führenden Unterstrich), nicht ausgewählt —
das ist eine Produktentscheidung und steht in [M-1](backlog/M-1-api-stabil-1-0.md).

### Behoben — Widersprüche in der Konfiguration fielen erst beim Login auf

Eine App **ohne eine einzige aktive Anmelde-Methode** startete klaglos. Eine `login_chain`, die
ein abgeschaltetes Verfahren nennt, ist unerfüllbar und schickt den Nutzer im Kreis. OIDC ohne
`issuer` scheiterte erst beim Klick auf „Anmelden". `tinysesam/konfigpruefung.py` prüft das jetzt
beim Aufbau und meldet **alle** Funde gemeinsam — wer drei Dinge falsch hat, soll sie einmal
lesen und nicht dreimal starten.

Die Grenze zwischen Fehler und Warnung ist nicht Strenge, sondern Reparierbarkeit: Was aus sich
heraus unerfüllbar ist, bricht den Aufbau ab; was später noch kommen kann — ein Mailer wird
typischerweise nach dem Konstruktor gesetzt — wird geloggt. Dazu ein Wächter für
`cookie_samesite`, den Starlette bisher erst beim ersten Cookie prüfte (und unter `python -O`
gar nicht).

### Geändert — `complete_totp()` statt `complete_mfa()`

Der alte Name versprach mehr, als die Methode tut: MFA ist die ganze Kette, hier geht es um genau
einen Faktor — und der Docstring nannte ihn selbst „rückwärtskompatibel", ohne dass es einen
anderen gegeben hätte. `complete_mfa` bleibt als Alias und wird nicht entfernt.

### Geändert — der API-Wächter erfasst mehr

Er verzeichnete Name und Typ der Config-Felder, aber **nicht die Vorgabewerte**: `session_ttl_hours`
liess sich still von 168 auf 1 setzen — ein Verhaltensbruch für jeden, der das Feld nie angefasst
hat. Ebenso fehlten die **Rückgabetypen** der Methoden; `-> dict` zu `-> str` wäre unbemerkt
durchgegangen. Beides wird jetzt mitgemessen.

### Geändert — das Quellpaket trägt die Testsuite, vollständig

Bis 0.18.0 stand `prune tests` in `MANIFEST.in`, mit dieser Begründung: setuptools zieht nach
einer alten Heuristik nur `tests/test_*.py` hinein (ohne `run_all.py`, ohne `_kit/`), und zwei
Suiten brauchen ohnehin, was ein sdist nie enthält. Die Begründung trägt nicht mehr. Seit dieser
Version sagt eine Suite **selbst ab**, wenn ihr eine Voraussetzung fehlt (`tests/voraussetzung.py`,
Exit 77) — die repo-gebundenen überspringen sich im Quellpaket also sauber und nennen den Grund.

Wer TinySesam neu paketiert (eine Distribution, conda, ein internes Rad), kann den Bau damit
prüfen, und das ist der Sinn eines Quellpakets. Gemessen im ausgepackten sdist dieses Release
(die Zahlen wachsen mit jeder neuen Suite, der Satz dahinter bleibt: nichts fällt um, und was
absagt, sagt ab):

```
41/45 grün, 4 übersprungen, 0 fehlgeschlagen
```

Mit dabei sind jetzt auch `examples/showcase.py` und `deploy/` — beide sind in der README
verlinkt, und ein toter Verweis ist in einem Tarball ärgerlicher als im Web, wo GitHub danebensteht.
`web/` bleibt draußen: der Generator der Projektseite ist Repo-Sache, nicht Quelle der Bibliothek.

### Behoben — Fehlertypen, Schema-Stempel, Recovery-Codes

**Es gab keine Fehlertypen, auf die man reagieren kann.** Geworfen wurden `ValueError`
(Konfiguration) und `RuntimeError` (fehlendes Extra); wer beim Starten unterscheiden wollte, ob
die Konfiguration falsch ist oder ein Paket fehlt, musste den Meldungstext lesen — und der ist
seit dieser Version übersetzt. Neu und exportiert: `TinySesamError`, `ConfigError`, `MissingExtra`
(trägt den Namen des Extras als Feld), `MailNotConfigured`. Jeder erbt zusätzlich von dem
eingebauten Typ, den er ersetzt — `except ValueError` fängt weiter, nichts bricht.

**Ein fehlendes Extra meldete sich je nach Methode anders**: bei Passkey verständlich, sonst als
`ModuleNotFoundError` aus dem Innern der Bibliothek oder erst beim ersten Login als 500. Jetzt
zweistufig:

* **Beim Aufbau** warnt TinySesam, wenn ein vollständig konfiguriertes Verfahren sein Modul
  nicht findet — im Log, mit der fehlenden Installationszeile.
* **Beim ersten echten Gebrauch** fliegt ein lesbarer `MissingExtra` (mit dem Extra-Namen als
  Feld) statt eines nackten `ModuleNotFoundError`.

Warum nicht einfach beim Aufbau abbrechen: Ein Client ist ersetzbar — `auth.ldap = eigener_client`
ist ein legitimer Weg, und vier eigene Suiten gehen ihn. Ein Wächter, der schon am Schalter
anschlägt, verbietet ihn. Die erste Fassung tat genau das und legte den `minimal`-Job der CI
lahm; geworfen wird jetzt nur dort, wo es nie falsch sein kann.

**Die Datenbank trug keinen Schema-Stempel.** Welchen Stand eine Datei hat, war nur an ihren
Spaltennamen zu erraten, und eine Datei aus einer *neueren* Fassung öffnete eine ältere Version
stillschweigend. Jetzt steht `PRAGMA user_version`, und eine Datei aus der Zukunft meldet sich.

**Recovery-Codes trugen 48 Bit.** Sie ersetzen den zweiten Faktor und gelten, bis sie benutzt
werden — anders als ein TOTP-Code, der nach 30 Sekunden wertlos ist. Neu erzeugte tragen
**112 Bit** (`RECOVERY_BYTES = 7`, zwei Hälften je Code); bestehende bleiben gültig (gespeichert
wird ohnehin nur der Hash). Oben im selben Abschnitt steht der Wert richtig — hier stand bis
2026-09-21 die 64 aus einem Zwischenstand.

### Behoben — die Antworten sprachen Deutsch, auch auf Englisch

**32 HTTP-Antworten trugen festen deutschen Text** — CSRF-Fehler, „Adminrechte nötig", OIDC- und
Passkey-Meldungen —, auch in einer Installation mit `lang="en"`. Die UI war zweisprachig, die
Antworten an Maschinen und Proxys nicht. Sie laufen jetzt über die Übersetzungstabelle
(Präfix `api.*`, getrennt von den `err.*` der UI-Seiten). Eine Hygiene-Prüfung verbietet festen
Text in einer `HTTPException`, damit die Lücke nicht von selbst nachwächst.

`OIDCClient.exchange()` nimmt dafür die Übersetzungsfunktion des Aufrufers entgegen (`t=auth.t`).
Der Client selbst kennt keine Sprache — er spricht das Protokoll, nicht mit dem Nutzer; ohne `t`
bleiben seine beiden Meldungen englisch, statt einem Aufrufer mit `lang="en"` Deutsch
unterzuschieben.

### Behoben — das Gateway startete nach der eigenen Anleitung nicht

Die README nannte `pip install 'tinysesam[oidc]'` und `python -m tinysesam.gateway` in einem
Atemzug. `[oidc]` bringt aber keinen ASGI-Server mit: Der Startbefehl endete in einem
`ModuleNotFoundError: uvicorn`, was wie ein Defekt aussah statt wie eine fehlende Zeile im
Install-Befehl. Dass das Docker-Abbild lief, lag an einem Flicken im `Dockerfile`, das `uvicorn`
von Hand danebeninstallierte — er verdeckte die Lücke im Extra.

Neu: **`pip install 'tinysesam[gateway]'`** (= `[oidc]` plus Server). Fehlt der Server trotzdem,
sagt das Gateway, welche Zeile fehlt, statt einen Stacktrace zu zeigen. `--help` gibt jetzt eine
Hilfe aus und endet mit 0 — vorher landete die Frage im uvicorn-Import und danach in einem Server
auf `0.0.0.0:8000`: Wer wissen wollte, wie das Ding heißt, hatte es laufen. Ein unbekanntes
Argument endet mit 2.

### Behoben — die PyPI-Seite zeigte ein totes Logo und sieben tote Verweise

`README.md` ist zugleich die Projektbeschreibung auf PyPI, und dort löst nichts relative
Repo-Pfade auf. Alle Verweise in dieser Datei sind jetzt absolut; eine Prüfung hält es fest. Die
deutsche Fassung unter `i18n/` wird nur auf GitHub gelesen und darf relativ bleiben.

Im selben Zug: Beide READMEs bewarben einen **Update-Knopf** im Admin-Panel („Modus manual/auto,
Version-Pin, jetzt aktualisieren"). Den gibt es seit 0.12.0 bewusst nicht mehr
([ADR-2](backlog/ADR-2-kein-selbst-update.md)) — das Panel zeigt die Version und einen Hinweis.

### Behoben — `Typing :: Typed` war eine Zusage, die niemand gemessen hat

Das Paket trägt den Classifier und eine `py.typed`: die Zusage an jeden Nutzer, dass die
Annotationen stimmen und sein Typprüfer sich darauf verlassen darf. Bei der ersten Messung
standen **30 Fehler in 6 Dateien**.

Der greifbarste davon: Sechs nutzerseitige Methoden waren `-> Optional[dict]` annotiert und
lieferten eine `sqlite3.Row`. Wer der Zusage glaubte und `user.get("email")` schrieb, bekam
einen `AttributeError` aus einer Zeile, die laut Typ nicht falsch sein konnte. `get_user`,
`find_user`, `check_password`, `check_ldap`, `check_saml` und `pending_user` liefern jetzt
wirklich ein `dict` — auf der Store-Ebene bleibt die Row, dort ist sie dokumentiert und gewollt.

Die übrigen 24 waren Annotationsfehler ohne Laufzeitwirkung (vor allem `x: bool = None` statt
`Optional[bool]`), plus zwei Stellen, an denen ein Abbruchpfad nicht als solcher annotiert war
(`_deny`, `_redirect_factor` sind jetzt `NoReturn`).

**Dabei fiel ein echter Fehler auf:** `cookie_samesite` wurde nie geprüft. Starlette lehnt einen
falschen Wert per `assert` ab — also erst beim ersten Cookie, und unter `python -O` gar nicht;
dann stünde der Tippfehler im `Set-Cookie`-Header. Der Konstruktor prüft ihn jetzt, samt der
Kombination `samesite='none'` ohne `cookie_secure` (die ein Browser verwirft).

Damit die Zusage gemessen **bleibt**: `tests/test_typen.py` fährt mypy über die Bibliothek und
prüft zusätzlich am echten Rückgabewert, was die Signaturen versprechen. mypy läuft in der CI und
ist ins `ci-python-web`-Abbild aufgenommen — ohne das übersprang sich die Suite selbst, und der
Lauf sah trotzdem grün aus.

**Zur API-Oberfläche:** `tests/api_surface.json` verzeichnet die neuen Annotationen als „Bruch".
Das ist er nicht: `x: bool = None` und `x: Optional[bool] = None` verhalten sich zur Laufzeit
gleich, die Signatur ist nur ehrlicher geworden. Kein Aufrufer muss etwas ändern.

### Behoben — ein Sicherheitsschalter, der nie etwas tat, und eine Seitenliste, die nicht stimmte

**`totp_required` hatte keinen Draht.** Der Schalter stand in der Config, in beiden READMEs
(„2FA erzwingen") und auf der Website — und wurde an keiner Stelle gelesen. Wer ihn setzte,
glaubte den zweiten Faktor erzwungen zu haben und hatte ihn nicht. Ein wirkungsloser
Sicherheitsschalter ist gefährlicher als gar keiner, weil er die Suche nach dem richtigen Weg
beendet. Der Konstruktor weist ihn jetzt ab und nennt den Weg, der greift:
`login_chain=['password', 'totp']`. Die Doku nennt ihn ebenfalls.

**`set_template` nahm Namen an, die es nicht gab.** Der Docstring führte `'magic_sent'` und
`'resource_pin'` auf — beide hat es nie gegeben — und ließ sieben echte Seiten weg. Ein
Tippfehler blieb folgenlos-still: Die eigene Seite wurde eingetragen und nie aufgerufen. Die
Liste steht jetzt als `TinySesam.SEITEN` im Code, ein unbekannter Name ist ein Fehler, und eine
Prüfung vergleicht sie gegen die Seiten, die `render_page()` wirklich bedient.

**SECURITY.md nannte `0.5.x`** als die Reihe, die Sicherheitsfixes bekommt — dreizehn
Minor-Versionen alt. Es verweist jetzt auf den CHANGELOG-Kopf statt auf eine Zahl, die veraltet.

### Behoben — hinter einem Proxy erschienen alle Nutzer unter einer IP

Vier Befunde, ein Thema. Gemeinsame Folge: Sperre, Rate-Limit und fail2ban wirkten **kollektiv**
statt pro Nutzer — und im Ernstfall bannt fail2ban den Proxy, also alle. Nichts davon sah nach
einem Fehler aus.

**SSO- und Passkey-Logins schrieben die rohe Peer-IP.** `oidc.py` und `webauthn_.py` griffen
direkt auf `request.client.host` zu und umgingen damit `trusted_proxies`; hinter einem Proxy
landete dessen Adresse in der Sitzungsliste, im Protokoll und in der IP-Sperre. Beide nehmen
jetzt `client_ip()`. Ein ungenutzter Helfer in `router.py`, der dasselbe falsch vormachte, ist
weg.

**Die Vorgabe passt im Container nicht — und das blieb still.** `trusted_proxies` steht auf
`127.0.0.1/32`; im Container ist der Proxy aber ein anderer Container. X-Forwarded-For wird dann
verworfen, ohne dass irgendetwas davon berichtet. `client_ip()` sagt jetzt einmal je Peer
Bescheid, mit dem konkreten Rat (`trusted_proxies=['<Netz des Proxys>']`).

**`0.0.0.0/0` entwertet X-Forwarded-For, statt ihm zu vertrauen.** Gilt jede Adresse als Proxy,
bleibt keine als Client übrig — `client_ip()` fällt auf die Peer-IP zurück. Das klingt großzügig
und ist das Gegenteil. Auch dieser Fall meldet sich jetzt.

**Das mitgelieferte Compose machte genau diesen Fehler.** `TINYSESAM_TRUSTED_PROXIES: "0.0.0.0/0"`
ist ersetzt: Das Beispiel bringt ein eigenes Netz mit festem Subnetz mit und trägt dieses ein —
eine vom Docker-Daemon vergebene Bridge-Adresse ließe sich gar nicht eintragen. Eine Prüfung
hält das fest.

### Behoben — zugesagte Python-Versionen werden jetzt gemessen

Die Classifier versprachen 3.10 bis 3.14, die CI-Matrix fuhr **3.10, 3.12 und 3.14** — 3.11 und
3.13 waren eine Behauptung. Die Matrix fährt jetzt alle fünf, und eine Hygiene-Prüfung vergleicht
Classifier gegen Matrix: Wer künftig eine Version verspricht, muss sie auch fahren (oder den
Classifier streichen).

Der Anlass war ein eigener Fehlschlag: `tests/test_kern_install.py` importierte `tomllib`, das es
erst ab 3.11 gibt — auf 3.10 starb der Test. Weil `ci-local` nur **eine** Python-Version fährt,
fiel das erst in der GitHub-Matrix auf; das Gate hat getan, wofür es da ist. Der Test liest die
Kern-Abhängigkeiten jetzt aus den **Paket-Metadaten** (`importlib.metadata.requires`) statt aus
`pyproject.toml` — das läuft auf jeder Version und misst obendrein näher am Gegenstand: was nach
`pip install tinysesam` wirklich da ist. Eine zweite Hygiene-Prüfung fängt Standardbibliotheks-
Namen, die jünger sind als die älteste zugesagte Version.

### Behoben — Betrieb: Sicherung, Aufräumen, Protokoll ([T-8](backlog/T-8-reifepruefung-restbefunde.md))

**Eine Datei-Kopie der Datenbank war wertlos.** Sie läuft im WAL-Modus; wer nur die `.db` sichert,
bekommt einen Torso — gemessen enthielt die Kopie einer Instanz mit fünf Konten nicht einmal die
Tabelle `users`, und das merkt man erst beim Zurückspielen. Neu: `tinysesam backup --db … <ziel>`
und `store.backup(pfad)` über SQLites Online-Backup, im laufenden Betrieb, mit denselben engen
Rechten wie die Quelle.

**Das Aufräumen hatte keinen Weg von aussen.** `auth.gc()` gab es, aber nichts rief es, und im
Gateway-Abbild kam man nicht heran. Neu: `tinysesam gc --db …` für Cron oder systemd-Timer.
Nebenbei: `python -m tinysesam --help` endet jetzt mit 0 statt 2 — eine Frage ist kein Tippfehler.

**Ab der ersten Logrotation wachte der Wächter nicht mehr.** Das Sicherheits-Log lief über einen
`FileHandler`, der den Inode offen hält: logrotate benennt um, legt neu an, und ab da schrieb
TinySesam in die *umbenannte* Datei. Die fail2ban-Jail las die leere neue — ohne Fehler, ohne
Meldung. Jetzt ein `WatchedFileHandler`, der vor jeder Zeile Inode und Gerät prüft.

**Der App-Lockout blendete fail2ban aus.** Solange ein Konto gesperrt war, antwortete die App 429,
ohne einen Versuch zu protokollieren — das Log verstummte genau in dem Moment, in dem die IP
hätte gebannt werden sollen. Abweisungen wegen Sperre oder Rate-Limit schreiben jetzt eine Zeile,
**im selben Format wie ein echter Fehlversuch**, damit der mitgelieferte Filter sofort greift,
auch in Installationen, die ihre Filterdatei nie anfassen. Der Grund steht als `reason=` dabei
(`lockout_user`, `lockout_ip`, `ratelimit`).

**Admin-Aktionen standen ohne Akteur und ohne IP im Protokoll.** Es hielt fest, *dass* ein Konto
gesperrt wurde, nicht von wem — bei mehreren Admins genau die Frage, die man hinterher stellt.
Alle acht Panel-Aktionen laufen jetzt über einen gemeinsamen Weg, der beides mitschreibt.

### Sicherheit — vier Befunde aus der zweiten Runde ([T-8](backlog/T-8-reifepruefung-restbefunde.md))

Die Reifeprüfung meldete 35 weitere Befunde, die niemand einzeln nachgestellt hatte. Sie werden
der Reihe nach geprüft — bestätigt, widerlegt oder als Geschmacksfrage abgelegt. Diese vier waren
bestätigt:

**Sitzungs-Token lagen im Klartext in der Datenbank.** Jetzt steht dort nur ihr sha256; der
Klartext lebt zwischen `create_session()` und dem Cookie. Alles, was aus einer Sitzungs-Zeile
kommt (`token_hash`), ist damit ein Handle: Es benennt eine Sitzung zum Beenden und taugt nicht
zum Anmelden. Das Muster gab es im selben Haus schon — `magic_token` hält es von Anfang an so.
**Bestehende Anmeldungen überleben die Umstellung:** Der Hash ist aus dem Klartext berechenbar,
die Migration rechnet ihn beim ersten Start aus. Wer die Store-API direkt nutzt, liest
`row["token_hash"]` statt `row["token"]`; die Schreibwege (`set_session_mfa`,
`set_session_factors`, `delete_session_by_handle`) nehmen dieses Handle und **werfen** bei einem
Klartext-Token, statt still ins Leere zu laufen.

**Das Admin-Panel gab die Sitzungstoken aller Nutzer heraus.** `GET /admin/api/sessions` lieferte
das echte Token jeder fremden Sitzung an den Browser — zum Beenden gedacht, zum Übernehmen
geeignet. Es liefert jetzt das Handle.

**Die Datenbank wurde welt-lesbar angelegt (0644).** Darin stehen Passwort-Hashes,
TOTP-Geheimnisse und E-Mail-Adressen. Eine neue Datei entsteht jetzt direkt mit `0600` — nicht
per `chmod` danach, das hätte ein Zeitfenster, in dem sie offen dasteht, und genau darin schreibt
SQLite das Schema hinein. WAL und SHM tragen dieselben Daten und bekommen dieselben Rechte. Eine
**bestehende** Datenbank wird nicht umgeschrieben (eine bewusste Gruppenfreigabe ist die
Entscheidung des Betreibers), aber sie wird mit dem nötigen Befehl im Log benannt.

**API-Keys überlebten das Aussperren.** Ein Key hängt an keiner Sitzung; wer ein Konto
zurücksetzte, schloss nur die Haustür. Jetzt gilt: Der **Admin-Reset** und das **Sperren** eines
Kontos widerrufen die Keys (dort ist die Absicht eindeutig). Der **eigene** Passwortwechsel lässt
sie absichtlich stehen — ein Routine-Wechsel soll keine Automatiken stilllegen —, nennt aber ihre
Zahl in der Antwort (`api_keys_active`) und im Protokoll. „Alle Sitzungen beenden" (`scope=all`)
nimmt sie mit, „andere beenden" nicht. (Der Key eines **deaktivierten** Kontos war nie gültig —
`verify_api_key` prüft das Flag; der gemeldete Befund reichte hier weiter, als er trug.)

### Hinzugefügt — die Veröffentlichung auf PyPI ist vorbereitet (noch nicht vollzogen)

Metadaten, `MANIFEST.in`, ein Packaging-Test und der Release-Workflow stehen bereit. **Installiert
wird weiterhin über den gepinnten Git-Tag** — der Upload erfolgt erst mit 1.0, und 1.0 kommt erst,
wenn die Befunde aus der Reifeprüfung abgearbeitet sind.

Der Packaging-Test hat sich sofort bezahlt gemacht: Das sdist enthielt eine **halbe Testsuite**
(setuptools zog `tests/test_*.py` nach einer alten Heuristik hinein, ohne `run_all.py` und ohne
`_kit/`) — ausgeliefert worden wäre eine Suite, die beim Import scheitert.

**Veröffentlicht wird ohne Geheimnis.** Der Release-Workflow weist sich gegenüber PyPI über seine
eigene OIDC-Identität aus (Trusted Publishing) — kein Token im Repo, keins zum Rotieren, keins, das
sich aus einem Lauf herausziehen liesse. Jede Datei trägt zusätzlich eine PEP-740-Attestation:
prüfbar, aus welchem Commit sie gebaut wurde. Ausgelöst wird das allein von einem Tag, den ein
Mensch setzt. Begründung und die einmalige Einrichtung: [ADR-6](backlog/ADR-6-pypi-veroeffentlichen.md),
Felder im Kopf von `.github/workflows/release.yml`.

[ADR-1](backlog/ADR-1-pypi-vertagt.md) („bis 1.0 vertagt") steht damit auf `verworfen` — mit
Verweis auf den Nachfolger und unverändertem Text. Die Entscheidung war nicht falsch, sie ist
eingelöst.

**Zur API-Oberfläche.** Für das Fenster `v0.16.0` → `v0.17.0` gemessen: **null Brüche, null
Erweiterungen** — dort ist die Oberfläche Zeichen für Zeichen dieselbe. Das war die dritte
Bedingung für 1.0 und ist für diesen Zeitraum belegt. **Für 0.18.0 gilt das nicht mehr**: Dieses
Release bringt neue Methoden (`complete_totp`, `csrf_rotieren`), neue Exporte (`TinySesamError`,
`ConfigError`, `MissingExtra`, `MailNotConfigured`) und den geänderten Vorgabewert von
`passkey_enabled` — die Uhr für „zwei Minor-Versionen ohne Bruch" startet damit neu.

Sie trägt 1.0 trotzdem nicht: Die Zusage musste nie unter Änderungen halten, weil 0.17.0 die
Bibliothek gar nicht angefasst hat. Und die Sicherheitsfixes dieser Version ändern **Verhalten**,
das Nutzer bisher (falsch) voraussetzen konnten — eine gemessene Oberfläche sagt darüber nichts.
[M-1](backlog/M-1-api-stabil-1-0.md) bleibt offen.

### Hinzugefügt — `tests/test_packaging.py`: das Paket, wie es ankommt

Bis hierher wurde geprüft, was im Repo liegt. Auf PyPI zählt, was im Wheel liegt — und das sind
zwei verschiedene Listen. Ein Wheel, dem eine Datei fehlt, installiert sauber und fällt erst auf
einem fremden Rechner auf; eine Version im Index lässt sich nicht zurückholen.

Die Suite **baut** deshalb Wheel und sdist (offline, aus den versionierten Dateien, ausserhalb des
Arbeitsbaums) und sieht hinein: Jede versionierte Datei unter `tinysesam/` ist im Wheel — heute ist
das nur `py.typed`, aber die erste Vorlage, die jemand dazulegt, fehlt ohne Eintrag unter
`[tool.setuptools.package-data]` stillschweigend. Dazu die Metadaten, an denen der Index hängt:
kein `Private :: Do Not Upload` mehr, Reifegrad passend zur Version, jede von der CI gefahrene
Python-Fassung auch als Classifier ausgewiesen, Untergrenze gleich `requires-python`, alle fünf
Projekt-Links gesetzt, README als Markdown im Paket. Und dass der Release-Workflow ohne Geheimnis
veröffentlicht.

`setuptools` gehört damit zur Testumgebung — seit Python 3.12 bringt eine frische Umgebung es nicht
mehr mit. Die CI-Jobs und `scripts/check.sh` installieren es ausdrücklich; fehlt es, ist die Suite
rot statt übersprungen. Ein Test ohne Voraussetzungen darf nicht grün aussehen.

### Behoben — das sdist enthielt eine Testsuite, die sich nicht starten liess

Gefunden vom neuen Packaging-Test, beim ersten Lauf. setuptools zieht nach einer alten Heuristik
`tests/test_*.py` ins Quellpaket — aber weder `tests/run_all.py` noch `tests/_kit/` noch
`tests/api_surface.json`. Wer das sdist auspackte, fand eine Suite vor, die beim Import scheitert.
Das ist schlimmer als keine: Sie behauptet eine Prüfbarkeit, die es nicht gibt.

Ein `MANIFEST.in` entscheidet die Frage jetzt ausdrücklich. Die erste Antwort darauf war
`prune tests` — das sdist als **Quelle der Bibliothek**, ohne Testsuite, weil zwei Suiten ohnehin
brauchen, was ein Quellpaket nie enthält. Diese Antwort hat **im selben Release nicht gehalten**
und wurde ersetzt: Seit dieser Version sagt eine Suite selbst ab, wenn ihr eine Voraussetzung
fehlt (Exit 77), und damit trägt das sdist die **vollständige** Suite (`graft tests`, dazu
`examples/` und `deploy/`). Der Abschnitt weiter oben — „das Quellpaket trägt die Testsuite,
vollständig" — ist der Stand, der ausgeliefert wird.

### Geändert — Paket-Metadaten vervollständigt

`Development Status` auf `4 - Beta` (im ersten Anlauf stand hier `5 - Production/Stable` — mit dem
Rückzug von 1.0 zurückgenommen, die Begründung steht im Kopf dieses Release), die unterstützten
Python-Fassungen (3.10–3.14)
als Classifier, dazu `Typing :: Typed`, `Topic :: Security` und die Zielgruppe der Administratoren.
`[project.urls]` nennt jetzt alle fünf Ziele, die ein Besucher der Index-Seite sucht: Website,
Doku, Repo, CHANGELOG, Issues. Die Kurzbeschreibung ist englisch wie README und Website, statt
deutsch und dreimal so lang.

Bewusst **nicht** umgestellt: `license` bleibt die Tabellenform statt des SPDX-Ausdrucks aus
PEP 639. Der verlangt setuptools ≥ 77, und gebaut wird auch mit älteren — der Grund steht im
`pyproject.toml` daneben, damit er beim nächsten Anlauf nicht neu erarbeitet werden muss.

## [0.17.0] — 2026-09-20

Ein Release **ohne Änderung an der Bibliothek**: Wer TinySesam einbindet, bekommt denselben Code
wie mit 0.16.0 — das Wheel unterscheidet sich nur in der Versionsnummer. Es lohnt trotzdem, weil
das Abbild mit aktualisierten Werkzeugen gebaut wird und weil ab hier die **Uhr für 1.0 läuft**:
`tests/test_api_surface.py` hält die öffentliche Oberfläche fest, und M-1 verlangt zwei
Minor-Versionen ohne Bruch. 0.17.0 ist die erste davon.

Wer auf 0.16.0 steht und nichts davon braucht, kann es überspringen.


### Geändert — alle GitHub-Actions auf den neuesten Stand

Acht Actions aktualisiert, darunter ein Major (`setup-python` 6 → 7: entfernt den `pip-install`-Input,
den wir nie genutzt haben). Bei jeder wurde die **Laufzeit am neuen SHA** nachgesehen — alle acht
laufen auf `node24`. Das ist der Punkt, den ein SHA-Pin allein nicht abdeckt: Er friert die Action
ein, nicht die Node-Version, auf der sie läuft; eine veraltete Laufzeit fällt erst auf, wenn GitHub
sie abschaltet.

Fünf der Updates kamen als einzelne Vorschläge, drei hatte noch niemand gemeldet. Zusammengefasst,
weil `main` „aktuell sein" verlangt: Jeder einzelne Merge hätte die übrigen vier veraltet gemacht
und sechs CI-Läufe nach sich gezogen.

### Hinzugefügt — die öffentliche API wird gemessen, nicht behauptet

Beide letzten Releases haben die API gebrochen, und beide Male fiel es erst beim Schreiben des
CHANGELOG auf. `tests/test_api_surface.py` hält die Oberfläche jetzt fest (Manager-Methoden,
Config-Felder, Presets, Exporte — 231 Namen) und meldet jede Abweichung. Er verbietet nichts, er
erzwingt eine bewusste Entscheidung: `python tests/test_api_surface.py --update`, dann committen.

Wichtig dabei ist die Unterscheidung: **Bruch** (entfernt, umbenannt, Signatur unverträglich) ist
etwas anderes als **Erweiterung** (Parameter mit Vorgabewert angehängt — bestehende Aufrufe laufen
weiter). Ein Wächter, der bei Harmlosem schreit, wird weggeklickt, und dann übersieht man den
echten. Gegenprobe mit den zwei echten Fällen: `require_role` (keyword-only) wird als Bruch
gemeldet, `magic_url` (neuer Parameter mit Vorgabewert) als Erweiterung.

### Hinzugefügt — `scripts/_release.py`: die Handgriffe vor einem Release

Die Version steht an sechs Stellen und im CHANGELOG. Das von Hand zu pflegen hat funktioniert,
weil ein Test schimpft, wenn man eine vergisst — aber „funktioniert, weil ein Test schimpft" ist
eine Schleife aus Fehler und Korrektur, kein Verfahren. `python3 scripts/_release.py 0.17.0` setzt
alles und schliesst den CHANGELOG-Abschnitt; `--pruefen` kontrolliert nur.

Bewusst **nicht** dabei: taggen und pushen. Den Knopf drückt ein Mensch — dieselbe Trennung wie
beim Ausrollen. Beides zahlt auf [M-1](backlog/M-1-api-stabil-1-0.md) ein.

## [0.16.0] — 2026-09-19

> ⚠️ **Breaking Change.** Bereits verschickte `/auth/magic/…`-Bestätigungs- und Einladungslinks
> werden ungültig — wer solche Mails im Umlauf hat, verschickt sie nach dem Update neu.

Das Release aus dem Praxiseinsatz. Wer TinySesam als **Forward-Auth vor fremde Apps** hängt, sollte
es einspielen: Dort lag eine stille Redirect-Schleife, Rollen liessen sich am Proxy gar nicht
prüfen, und welche Header hinausgehen, war nicht einstellbar. Wer es **in** seiner App einbindet,
bekommt eigene Endpunkte für E-Mail-Bestätigung, Einladung und Passwort-Reset (die hingen bis
hierher alle am Magic-Link), `require_role()` mit mehreren Rollen und ein Wartungskommando für den
Fall, dass das Admin-Passwort weg ist.

Dazu zwei Dinge, die man nicht sieht und trotzdem zählen: Die drei Anmelde-Zeremonien
(Passkey, OIDC, SAML) sind erstmals **gegen echte Gegenstellen** gelaufen — und haben dabei gleich
einen Fehler gefunden. Und jedes Artefakt dieses Releases trägt eine signierte Herkunfts-Attestation
samt SBOM.


### Geändert — die E2E-Bühne entsteht per Playbook, nicht mehr von Hand

`tests/e2e_stage.py` braucht eine Instanz mit echter Domain, echtem Zertifikat und einem
Identity Provider daneben. Die gab es bisher nur, weil jemand sie eingerichtet hatte — was genau
lief, wusste nur, wer dabei war. Jetzt baut ein Lauf sie aus einem frischen Wegwerf-Container,
und der zweite Lauf ändert nichts mehr. Das Playbook liegt im Deploy-Repo: Adressen und
Zugangsdaten gehören nicht in ein öffentliches Repo; von hier führt nur der Aufruf hin. Erledigt
[T-6](backlog/T-6-stage-per-playbook.md).

### Hinzugefügt — Herkunft und Inhalt der Artefakte sind jetzt beglaubigt

Ein Digest belegt, dass sich ein Artefakt seit dem Bau nicht verändert hat — **nicht, wer es
gebaut hat**. Wer Zugang zur Registry erbeutet, kann ein eigenes Abbild unter denselben Tag
schieben; wer nur den Tag zieht, merkt nichts.

Jedes Release trägt deshalb jetzt eine über **Sigstore** signierte Herkunfts-Attestation und eine
**SBOM** — für das Gateway-Abbild wie für Wheel und sdist. Signiert wird mit der OIDC-Identität
des Release-Workflows: kein Schlüssel, den man herausgeben, und keiner, den man verlieren kann.
Die Attestation des Abbilds liegt zusätzlich in der Registry und ist damit auch ohne dieses Repo
prüfbar.

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:vX.Y.Z --owner Ollornog
```

Die SBOM entsteht aus dem **geschobenen** Abbild, nicht aus dem Bauverzeichnis — sonst beschriebe
sie etwas anderes als das Ausgelieferte. Erledigt
[T-5](backlog/T-5-abbild-signatur-pruefen.md).

### Behoben — eine abgelehnte SAML-Assertion war nicht diagnostizierbar

`SAMLClient.process()` warf `get_errors()` und `get_last_error_reason()` weg und gab nur `None`
zurück; der ACS zeigte daraufhin die **Magic-Link**-Fehlerseite („dieser Link ist ungültig,
abgelaufen oder schon benutzt"). Wer eine SAML-Anmeldung debuggte, sah also eine Meldung über
einen Link, den es nie gab, und im Log stand nichts.

Der Grund geht jetzt an den Logger `tinysesam.security` — und nur dorthin: Wer die Antwort
schickt, soll nicht erfahren, woran sie scheiterte. Der ACS antwortet mit 400 und einer Meldung,
die vom Identity Provider spricht.

Gefunden beim ersten Lauf gegen einen **echten** IdP: Keycloaks Entity-ID ist `…/realms/<realm>`,
nicht die SSO-URL. Ohne `saml_idp_entity_id` lehnt die Prüfung deshalb jede Assertion ab — vorher
schweigend. Das Feld gab es bereits; an der Config und in beiden READMEs steht jetzt, wann man es
setzen muss.

### Hinzugefügt — `tests/e2e_stage.py`: die Ceremony gegen eine echte Instanz

Passkey, SAML und OIDC waren bisher nur **struktur**-getestet: geprüft wurde, dass die richtigen
Felder gesetzt und die richtigen Weichen gestellt werden — nie die Ceremony selbst gegen einen
echten Provider auf einer echten HTTPS-Domain.

Der neue Lauf tut genau das, im echten Browser über das DevTools-Protokoll: Passkey registrieren
und sich danach passwortlos anmelden (virtueller Authenticator, aber echte `rp_id`), SAML gegen
einen echten IdP, OIDC gegen einen echten Provider. Bedient wird die **eingebaute** Oberfläche,
nicht nachgebautes JS — sonst prüfte der Test seinen eigenen Code.

Bewusst **kein** CI-Test und bewusst nicht `test_*.py` benannt (sonst sammelt `run_all.py` ihn
ein): Die CI hat keine Domain, kein Zertifikat und keinen IdP; ein Test, der das nachbaut, prüft
die Attrappe. Gedacht als Smoke-Test nach dem Deploy. Adressen und Zugangsdaten kommen aus der
Umgebung, nie aus dem Repo; jeder Teil ohne Konfiguration wird **übersprungen** und als solcher
gemeldet, nie still als bestanden.

Zwei Dinge, die der Lauf beim Bauen selbst gelernt hat: Er wartet auf **Zustände** statt auf die
Uhr (feste Wartezeiten machten ihn launisch), und er **räumt hinter sich auf** — sonst sammelt das
Konto bei jedem Durchgang einen weiteren Passkey an. Ein Rate-Limit oder Lockout meldet er als
solchen, statt „Anmeldung fehlgeschlagen" zu sagen und die Suche in die falsche Richtung zu
schicken. Alle drei Wege laufen gegen echte Gegenstellen durch, und der Lauf wird rot, wenn man ihn
bricht (falsches Passwort am IdP, unbekanntes Credential: Exit 1). Erledigt
[T-1](backlog/T-1-e2e-gegen-echten-idp.md).

### Geändert — geteilte Testbasis auf repokit 0.9.0

`repokit sync`. Zwei Fixes, beide aus einem frischen Bootstrap gemeldet: Der Hygiene-Test schlug
bei `runs-on: ubuntu-latest  # niemals self-hosted` an — also ausgerechnet bei einer Zeile, die
die Regel befolgt und begründet (er liest jetzt den Code ohne den Kommentar dahinter, und nur
den). Und `_backlog.py index` schrieb für einen Meilenstein ohne Aufgaben „— — erledigt", wo
Kästchen und Text sich widersprachen.

### Geändert — E-Mail-Bestätigung, Einladung und Passwort-Reset haben eigene Endpunkte

> ⚠️ **Breaking Change.** Bereits verschickte `/auth/magic/…`-Bestätigungs- und Einladungslinks
> werden ungültig.

Alle vier Token-Zwecke liefen über `/auth/magic/{token}`, und diese Route gab es nur bei
`magiclink_enabled=True`. Wer den Anmelde-Link per E-Mail abschaltete — naheliegend, sobald man
Passwörter oder SSO nutzt — verlor damit **auch E-Mail-Bestätigung und Einladung**, zwei Dinge,
die damit nichts zu tun haben. Beim Umbau kam ein dritter Fall dazu: die Reset-Route verlangte
`password_reset_enabled AND magiclink_enabled`, obwohl sie ihren eigenen Endpunkt längst hatte.

| Zweck | vorher | jetzt |
|---|---|---|
| Anmelde-Link | `/auth/magic/{token}` | unverändert |
| Adresse bestätigen | `/auth/magic/{token}` | `/auth/verify/{token}` (hängt an `signup_verify_email`) |
| Einladung | `/auth/magic/{token}` | `/auth/invite/{token}` (hängt an `allow_signup`) |
| Passwort-Reset | `/auth/magic/{token}` → Umweg | `/auth/reset?token=…` direkt (hängt an `password_reset_enabled`) |

**Breaking:** Bereits verschickte Bestätigungs- und Einladungslinks auf `/auth/magic/…` sind
ungültig. Wer solche Mails im Umlauf hat, verschickt sie nach dem Update neu. `/auth/magic/{token}`
nimmt nur noch `login`-Token an und weist andere ab, **ohne sie zu verbrauchen**.

Wer die Links selbst baut: `auth.magic_url(raw, base_url, purpose)` wählt den Pfad je Zweck
(`TinySesam.TOKEN_PATHS`). Erledigt
[T-4](backlog/T-4-verifikation-ohne-magic-endpoint.md).

### Behoben — Browser-Test: der Testserver-Port war ein Wettlauf

`tests/test_browser.py` suchte sich den Port für den uvicorn-Testserver, indem es einen Socket
band, wieder schloss und die Nummer weitergab. Dazwischen konnte ihn ein anderer Prozess belegen —
auf einem Runner mit parallelen Jobs kein Gedankenspiel, und rot wird der Test dann selten und
unerklärlich. Der Socket bleibt jetzt gebunden und wird an `uvicorn.Server.run(sockets=[...])`
übergeben; das Fenster gibt es nicht mehr. Chrome löste dasselbe Problem schon länger auf seinem
Weg (`--remote-debugging-port=0` + `DevToolsActivePort`). Erledigt
[T-2](backlog/T-2-freien-port-nicht-selbst-suchen.md).

### Hinzugefügt — `forward_headers`: welche Header die Forward-Auth-Antwort setzt

Der Satz war fest: `Remote-User/-Name/-Email/-Groups`, die Authelia-Konvention. Nicht jede
nachgelagerte App versteht diese Namen (Grafana will `X-WEBAUTH-USER`, oauth2-proxy-geprägte
Anwendungen `X-Auth-Request-*`), und nicht jeder Betreiber will alle vier herausgeben — die
E-Mail-Adresse etwa. Beides ging bisher nur, indem man es im Proxy umbog.

`forward_headers` bildet **Feld → Headername** ab (`user` · `name` · `email` · `groups`), ein Feld
darf auf mehrere Namen zeigen. Die Zuordnung ist die **vollständige** Liste, keine Ergänzung:
`{"user": "X-WEBAUTH-USER"}` verschickt genau diesen einen Header. Weglassen ist damit der Weg,
etwas nicht herauszugeben. Leer = unverändert der bisherige Satz.

Geprüft wird beim Start: ein Tippfehler im Feldnamen liesse den Header sonst still weg, und ein
Header-Name mit Zeilenumbruch wäre Header-Injection. Erledigt
[T-3](backlog/T-3-forward-auth-header-feinsteuerung.md).

## [0.15.0] — 2026-09-19

Forward-Auth aus dem Praxiseinsatz — vier Befunde aus einem Fremd-Deployment, das TinySesam vor
eine gewachsene Site gehängt hat, plus der Nachzug in der App. Wer TinySesam **in** seiner App
einbindet, bekommt `require_role()` mit mehreren Rollen (siehe Bruchstelle unten) und mit
`security_log` eine fail2ban-Jail, die ohne Handarbeit funktioniert. Wer es als **Forward-Auth vor
fremde Apps** hängt, sollte dieses Release einspielen: dort lag eine stille Redirect-Schleife.

Dazu, wie im vorigen Zyklus begonnen, die Arbeiten am Sicherheitsnetz (Backlog im Repo,
nonce-basierte CSP) — die sind für Einbindende unsichtbar.

### Behoben — Forward-Auth schickte in eine stille Endlosschleife

Ohne `cookie_domain` ist das Session-Cookie **host-only**. Die Login-URL wurde trotzdem immer auf
`base_url` gebaut: TinySesam setzte das Cookie auf Host A und schickte den Browser nach Host B, wo
es nicht mitgeschickt wird — der Proxy fragte erneut, es ging wieder zum Login. Keine Fehlermeldung,
keine Logzeile, nur eine Schleife. Aus einem Fremd-Deployment gemeldet.

Ohne `cookie_domain` entsteht die Login-URL jetzt **auf dem angefragten Host**, sofern der in
`trusted_redirect_hosts` steht — dieselbe Whitelist verhindert, dass ein gefälschter
`X-Forwarded-Host` jemanden umbiegt. `base_url` bleibt unangetastet: OIDC-/SAML-Callbacks brauchen
weiter die eine feste Adresse. Beim Start sagt TinySesam außerdem, dass mehrere Hosts ohne
`cookie_domain` **kein** gemeinsames SSO ergeben — das ist vorab beweisbar, die Hosts stehen in der
eigenen Konfiguration.

Dazu: Der Host der eigenen `base_url` zählt jetzt immer als erlaubtes `?next=`-Ziel und muss nicht
mehr in `trusted_redirect_hosts` wiederholt werden. Vergaß man das beim Ein-Host-Betrieb, wurde das
absolute `next=` stillschweigend verworfen und man landete nach dem Login auf `login_redirect`.

### Geändert — `require_role()` nimmt mehrere Rollen, eine davon genügt

Nachzug zur Rollenprüfung im Forward-Auth: Dort konnte man seit dem vorigen Eintrag
`?roles=redaktion,lektorat` sagen, in der App aber nicht — `require_role()` nahm genau eine Rolle,
für ein ODER musste man sich eine eigene Dependency schreiben. Dieselbe Frage („wer darf durch?")
bedeutete also je nach Betriebsmodus etwas anderes, ausgerechnet zulasten des Grundmodells
([ADR-3](backlog/ADR-3-in-app-statt-proxy.md)).

Jetzt: `require_role("redaktion", "lektorat")` oder `require_role(liste_aus_der_config)`, ebenso
`require(role=[...])`. Wer **alle** Rollen verlangt, stapelt zwei Guards — `Depends`-Abhängigkeiten
laufen ohnehin alle. Die 403-Meldung nennt jetzt alle geprüften Rollen.

Der Aufruf mit einer Rolle bleibt unverändert. **Einzige Bruchstelle:** `mfa` und `admin_implies`
sind keyword-only geworden. Ein positionales `require_role("editor", True)` meinte früher
`mfa=True` und wäre jetzt eine zweite Rolle namens `True` — das bricht laut mit einer Erklärung,
statt still etwas anderes zu prüfen.

### Hinzugefügt — Rollen im Forward-Auth (`?roles=` / `X-TinySesam-Roles`)

`/auth/forward` war binär: angemeldet oder nicht. Rollen reisten nur als `Remote-Groups`-Header mit,
womit ein Reverse-Proxy nichts anfangen kann — `require_role` existierte faktisch nur im In-App-Modus.

Jetzt sagt der Proxy, was er verlangt: `GET /auth/forward?roles=redaktion,admin` oder der Header
`X-TinySesam-Roles`. Eine der genannten Rollen genügt, `admin_implies_roles` gilt wie sonst auch.
Fehlt sie, antwortet TinySesam **403** — kein 401, der schickte den Angemeldeten zum Login und von
dort mit derselben fehlenden Rolle zurück. Die Abweisung steht als `forward_role_denied` im
Audit-Log; eine 403 im Proxy-Log sagt nicht, wer woran gescheitert ist. Ohne die Angabe bleibt alles
wie bisher. Mehrere Angaben werden UND-verknüpft, damit ein selbst angehängter Parameter die Prüfung
nur verschärfen kann. Begründung und die verworfene Alternative (Regeltabelle im Authelia-Stil):
[ADR-5](backlog/ADR-5-rollen-im-forward-auth.md).

### Hinzugefügt — `security_log`: die fail2ban-Jail funktioniert ohne Handarbeit

`deploy/fail2ban/tinysesam-jail.conf` zeigte auf `/var/log/tinysesam/security.log`, aber dorthin
schrieb nichts — die Verdrahtung stand als auskommentierter Python-Schnipsel in der Jail-Datei.
Wer sie übernahm, bekam eine Jail, die still eine Datei bewachte, die nie entstand.
`TinySesamConfig(security_log="…")` hängt den Handler jetzt selbst an (idempotent, mit Zeitstempel
im Format, das fail2ban datiert). Ein nicht schreibbarer Pfad warnt beim Start — eine Logdatei ist
kein Grund, die Anmeldung stillzulegen.

### Hinzugefügt — `tinysesam passwd`: der Weg zurück ohne Mailserver

Mit `local_accounts()` sind „Passwort vergessen" und Magic-Link aus (es gibt keinen Mailer), und die
Erst-Admin-Wege greifen nur, solange kein Admin existiert. Wer sein Admin-Passwort verlor, hatte
keinen dokumentierten Weg zurück. Neu: `python -m tinysesam passwd --db auth.db admin` — offline auf
der Datenbankdatei, beendet die offenen Sitzungen des Kontos und schreibt einen Audit-Eintrag.
Das widerspricht „kein Selbst-Update" nicht; die Grenze dort ist *Code nachladen*, nicht *offline
warten* ([ADR-2](backlog/ADR-2-kein-selbst-update.md)).

### Hinzugefügt — `deploy/forward-auth/nginx-pfad.conf`

Zweites nginx-Beispiel für den anderen verbreiteten Zuschnitt: ein Host, nur einzelne Pfade
geschützt, dahinter statische Dateien und PHP. Es stellt drei Fallen aus, die alle nachgestellt
wurden: `location ^~` schaltet die Regex-Locations ab (`.env` wird ausgerechnet im geschützten
Ordner ausgeliefert), `proxy_set_header Remote-User` erreicht PHP-FPM nicht (es braucht
`fastcgi_param HTTP_REMOTE_USER`), und die `Remote-*`-Header müssen in den offenen Locations
geleert werden, sonst schickt ein Client sie einfach selbst mit.

### Hinzugefügt — Backlog im Repo (`backlog/`)

Meilensteine, Aufgaben und **Architekturentscheidungen (ADR)** liegen jetzt als Markdown mit
Frontmatter unter `backlog/` — eine Datei je Vorgang, geprüft von der Testsuite
(`python3 scripts/_backlog.py list|check|index`).

GitHub Issues bleiben der Posteingang; was angenommen wird, bekommt hier einen Eintrag. Der
Vorteil: Ein Task schließt **in dem PR, der ihn erledigt** — im Diff sichtbar. Und der
Hygiene-Test liest den Backlog mit, was bei einem öffentlichen Repo den Unterschied macht.

Vier bereits getroffene Entscheidungen sind als ADR nachgetragen: PyPI bis 1.0 vertagt,
kein Selbst-Update, Schutz in der App statt am Proxy, keine self-hosted Runner.
Verworfene Entscheidungen werden nicht gelöscht, sondern bekommen `status: verworfen` **und**
`superseded_by` — ein Wächter erzwingt den Verweis.

`TODO.md` behält die Historie der erledigten Versionen und verweist auf den Backlog.

### Hinzugefügt — nonce-basierte Content-Security-Policy für die eingebauten Seiten

Die eingebauten Seiten (Login, Account, TOTP-Setup, Fehler) liefern jetzt eine **strenge,
nonce-basierte CSP** aus — ohne `unsafe-inline`. Pro Antwort entsteht ein Nonce; er wandert zentral
in jedes `<script>`/`<style>` und in den `Content-Security-Policy`-Header. Möglich wurde das, weil die
Seiten **inline-frei** umgebaut sind: kein `onclick`/`onsubmit` mehr (ein delegierter Click-Listener
statt Inline-Handlern, `data-act`-Attribute), keine `style=`-Attribute (in Klassen ausgelagert). Ein
CSP-Nonce deckt genau `<script>`/`<style>`-Blöcke ab — Inline-Handler und `style=` **nicht**, deshalb
mussten sie weg.

Der Schalter ist **`config.csp`**: `"strict"` (Vorgabe), `"off"` (kein Header — z.B. wenn ein Proxy
oder die App die CSP zentral setzt) oder eine **eigene Policy** (ein enthaltenes `{nonce}` wird pro
Antwort ersetzt). Ein Template-Override, das eine `Response` liefert, bleibt unberührt — es setzt seine
CSP selbst; `ctx["nonce"]` steht ihm zur Verfügung.

Warum das zählt: Wer TinySesam einbettet, kann seine App jetzt unter eine strenge CSP stellen, ohne
dass die Login-/Account-Seite bricht — sie bringt ihre eigene, passende CSP mit. Bewiesen im Browser
(`test_browser.py`): unter der strengen CSP feuert **kein** `securitypolicyviolation`; mit absichtlich
falschem Nonce blockt Chrome jedes Skript/Style (Negativtest). Fachtest: `test_csp.py`.

### Geändert — widersprüchliche HTTPS-Konfiguration wird beim Bau abgelehnt

Zwei Löcher, beide still:

`https_mode` wurde **gar nicht geprüft**. Ausgewertet wird nur `== "force"` — alles andere heißt
„kein Redirect". Ein Tippfehler (`"forse"`) schaltete den HTTPS-Zwang also wortlos ab, ohne Fehler,
ohne Hinweis. Jetzt sind nur noch `off`/`warn`/`force` erlaubt, wie schon bei `login_identifier`.

`https_mode="force"` zusammen mit `cookie_secure=False` widerspricht sich: Die App leitet jeden
Request auf HTTPS um und gibt das Session-Cookie trotzdem ohne `Secure`-Flag heraus — ein einziger
HTTP-Aufruf reicht, damit es im Klartext mitgeht. Diese Kombination wird abgelehnt.
`cookie_secure=False` bleibt für lokale Aufbauten ohne Zertifikat richtig und erlaubt.

Geprüft wird **nur, was die App über ihr eigenes Verhalten sagt**, nicht, was sie über die Außenwelt
behauptet. Eine erste Fassung schlug auch bei `base_url="https://…"` + `cookie_secure=False` an. Das
klang nach demselben Fehler, war aber keiner: `base_url` ist die öffentliche Adresse, aus der SAML
und OIDC ihre Callbacks bauen — sie sagt nichts über den Transport zwischen Browser und App. Vier
eigene Suiten brauchen genau diese Kombination (öffentliche HTTPS-URL, `TestClient` auf `http://`),
und ein Wächter, der im eigenen Haus viermal falsch anschlägt, tut es bei Nutzern erst recht. Die
Regel ist deshalb wieder raus.

### Hinzugefügt — die Cookie-Flags stehen jetzt unter Aufsicht

Die Flags standen im Code richtig, aber kein Test hielt sie fest: `grep -rln "httponly" tests/`
kam leer zurück. Ein Refactor, der am Session-Cookie `httponly=True` verliert, wäre grün durch
die Suite gegangen — eine Auth-Bibliothek, die ihre Sitzung an jedes XSS weiterreicht, ohne dass
irgendwo etwas rot wird. `tests/test_cookies.py` nagelt das fest: HttpOnly, Secure, SameSite,
Path, Max-Age, für jedes Cookie einzeln, am rohen `Set-Cookie`-Header statt am Cookie-Jar des
Clients (der verschluckt Attribute und legt Secure-Cookies über `http://` gar nicht erst ab).

Die Erwartung steht **je Cookie**, nicht als eine Regel für alle. `tinysesam_csrf` darf gerade
**kein** HttpOnly haben — Double-Submit braucht den JS-Lesezugriff. Ein pauschales „alle Cookies
HttpOnly" hätte ausgerechnet das richtige Cookie angemeckert, und wer den Test daraufhin
aufweicht, verliert ihn für die Cookies, die zählen. Ein Cookie, das gesetzt wird und in der
Erwartungsliste fehlt, gilt als Verstoß: Wer eins einführt, muss seine Flags erklären.

Dabei fiel auf, dass es **drei** CSRF-Setzer gibt. `issue_csrf()` — die öffentliche API für
fremde Templates — wird jetzt mitgeprüft; täte sie es nicht, wäre ausgerechnet die
Fremd-Integration die schwächste Stelle. Der dritte Setzer sitzt im Admin-Panel und gehört zu
`test_adminmount.py`; das steht als Lücke im Kopf der Suite, nicht stillschweigend übergangen.

Parser und Prüfregel kommen aus dem geteilten Kit (`_kit/headers.py`, ab repokit 0.7.0) — sie
sind nicht TinySesam-eigen, und jede App mit Cookies braucht sie. Hier steht nur noch, welche
Cookies es gibt und was jedes mitbringen muss.

### Geändert — die Doku spricht durchgängig beide Sprachen

Der Sprachwechsler war Flickwerk. Die README trug ihn zentriert im Kopf (aktuelle Sprache fett,
die andere als Link); `CONTRIBUTING` verwies kursiv und linksbündig auf die Gegenfassung; der
`CODE_OF_CONDUCT` lag zwar in beiden Sprachen vor, verlinkte sie aber gar nicht miteinander.
Jetzt tragen `CODE_OF_CONDUCT` und `CONTRIBUTING` denselben Kopf wie die README — zentrierte
Überschrift, zentrierter Wechsler.

`SECURITY` gab es nur auf Deutsch. Die deutsche Fassung heißt jetzt `SECURITY.de.md`, daneben
steht `SECURITY.md` auf Englisch; beide sind über denselben Kopf verbunden. Die In-App-Fußzeile
verlinkt die zur Anzeigesprache passende Datei, `tests/test_repo.py` erzwingt das Paar. `CHANGELOG`
und `TODO` bleiben bewusst einsprachig deutsch.

Zum Feinschliff: die README-Badges (Tests, Lizenz, Python) stehen jetzt rechtsbündig, und die
Doku-Unterseiten tragen das Wizard-Icon rechtsbündig am Fuß — dasselbe Bild wie die README
(250 px), auf den Unterseiten in klein (60 px).

### Geändert — Bildnachweis verweist direkt auf die Autorenseite

Der Flaticon-Link im Fuß der README zeigte auf die Suchseite. Er führt jetzt direkt zur
Autorenseite (max.icons) und öffnet in neuem Tab; das Format ist mit den übrigen Repos
vereinheitlicht: `Icon: … PNG Image by … - flaticon.com`.

Die Übersetzungen liegen jetzt unter `i18n/` (`i18n/README.de.md`, `i18n/CODE_OF_CONDUCT.de.md`,
`i18n/CONTRIBUTING.de.md`, `i18n/SECURITY.de.md`), im Root nur noch die englischen Fassungen.
Grund: GitHubs Health-File-Detektor sucht `CODE_OF_CONDUCT`/`SECURITY`/… in Root, `.github/` und
`docs/` und wählt bei mehreren Treffern die alphabetisch erste — also `CODE_OF_CONDUCT.de.md` vor
`.md`. Damit zeigte das Community-Profil die deutsche Fassung als „Other" statt die englische als
Contributor Covenant. Aus `i18n/` heraus sieht der Detektor nur noch die englischen Root-Dateien.
Die In-App-Fußzeile und `tests/test_repo.py` folgen dem neuen Ort; der Sprachwechsler bleibt.

Die Unterseiten tragen jetzt eine Standard-Markdown-Überschrift statt eines zentrierten HTML-Kopfes.
Für den *Contributor Covenant* zählt aber mehr: GitHubs Vorlagen-Abgleich verträgt **gar keinen**
Fremdinhalt in der Datei — auch keinen am Ende. Die englische `CODE_OF_CONDUCT.md` bleibt deshalb
**pur** (nur Überschrift und Vorlagentext), damit GitHub sie als Contributor Covenant erkennt und
nicht als „Other". Die übrigen Unterseiten (deutsche CoC-Fassung, `CONTRIBUTING`, `SECURITY`, je
zweisprachig) tragen den Sprachwechsler direkt unter der Überschrift und das Logo rechtsbündig am
Fuß der Seite — dasselbe Muster in allen eigenen Repos.

Die Kontaktadressen (Verhaltenskodex, Beitrag, Impressum) laufen jetzt einheitlich über
`tinysesam-github@ollornog.de` statt `admin@`/`tinysesam@` — eine repo-eigene Adresse pro Projekt.

### Geändert — die Testbasis ist geteilt, nicht mehr kopiert

Die allgemeinen Hygiene-Prüfungen, die Sperrlisten und der Rückstands-Check standen in jedem
Projekt als eigene Kopie — und liefen auseinander. Diese Suite kannte sieben verbotene Namen,
das Schwesterprojekt dreizehn; die Muster für private Netze hatten nur in einem von beiden die
Ausnahme für CIDR-Masken in der Doku. Gleiche Absicht, verschiedene Wirkung.

Jetzt liegen sie unter `tests/_kit/` als **eingecheckte, geteilte Basis**: die Regeln als reine
Daten (`hygiene_policy.json`), die Prüfungen als stdlib-only Funktionen (`hygiene.py`). Sie werden
erzeugt, nicht von Hand geschrieben.

Wichtig für alle, die das Projekt klonen: **es kommt nichts hinzu, was geladen werden müsste.**
Kein pip-Paket, kein Submodul, kein Netz zur Testzeit. `tests/_kit/` liegt in jedem `git clone`,
jedem ZIP und jedem Release-Tarball. Käme der Wächter, der „keine private Infrastruktur" erzwingt,
selbst aus dem Netz, wäre er das Leck, das er verhindern soll.

Die Prüffunktionen geben Listen von Verstößen zurück, statt zu werfen. Deshalb bleibt diese Suite
bei ihrem `assert`-Stil, während das Schwesterprojekt sammelnd berichtet — derselbe Code, zwei
Idiome.

### Behoben — die CI ignorierte `.ci-allow-dirty`

Der Rückstands-Check existierte fünffach. Der `pre-push`-Hook und `ci-local` lasen `.ci-allow-dirty`;
die beiden CI-Fassungen prüften rohes `git status --porcelain` und kannten die Datei nicht. Das
verbindliche Gate widersprach damit dem lokalen Netz — auf der strengeren Seite, was den Fehler
lange harmlos aussehen ließ. Hook und CI fahren jetzt dieselbe Datei, `scripts/_residue_check.sh`.

### Behoben — der eigene Name stand auf der Sperrliste

Die vereinigte Namens-Sperrliste enthielt den GitHub-Owner. Der ist aber ausdrücklich erlaubt:
Repo-URL, Copyright-Zeile, Impressumsadresse und Pages-Adresse müssen ihn nennen dürfen. Im
Schwesterprojekt fiel das nie auf, weil dessen Identitäts-Maskierung die URL-Zeilen zufällig traf;
hier, mit Impressum und Pages-URL, schlug er sofort an. Der Eintrag ist entfernt. Die eigentliche
Gefahr bleibt gefangen: eine Dienst-Subdomain trifft weiterhin das Subdomain-Muster, die nackte
Domain nicht.

### Hinzugefügt — Community-Dateien

- **`CODE_OF_CONDUCT.md`** (+ deutsche Fassung): der Contributor Covenant 2.1, Kontakt
  `admin@ollornog.de`. Er gilt für die Leute, die Issues und PRs öffnen — nicht für den Code.
- **`CONTRIBUTING.md`** (+ deutsche Fassung): Grundregeln (Tests gehören zur Änderung,
  wiederholbare Suite, Sicherheitsänderungen sind nicht kosmetisch, keine private Infrastruktur,
  Optionales bleibt optional) und der Feature-Branch-Workflow.

Beide stehen auf GitHubs *community profile checklist*; sie fehlten bisher.

### Hinzugefügt — belegte Standards werden jetzt maschinell erzwungen

Vier Regeln aus einer Standards-Recherche (mit Primärquellen) prüft die Hygiene-Suite jetzt selbst:

- **Actions per vollem Commit-SHA gepinnt**, nicht per Tag. GitHub nennt den SHA „the only way to
  use an action as an immutable release" — ein Tag lässt sich verschieben. Die Version steht als
  Kommentar dahinter, und `.github/dependabot.yml` hält sie aktuell, damit der Pin nicht still veraltet.
- **`permissions:` auf oberster Ebene jedes Workflows.** Es gibt keinen sicheren Default.
- **CHANGELOG-Kategorien aus Keep a Changelog** (eine Sprache je Repo).
- **`README.de.md` folgt der Überschriften-Struktur von `README.md`** — GitHub wählt die README nach
  Ort aus, nicht nach Sprache, eine Übersetzung veraltet also unbemerkt.

Dazu aktiviert: Private Vulnerability Reporting und Dependabot Security Updates.

### Behoben — der `pre-push`-Hook riet zum falschen Befehl

War Docker nicht erreichbar, nannte der Hook `docker info` als Prüfung und `git push --no-verify`
als Ausweg. `docker info` beantwortet aber drei verschiedene Ursachen gleich: die Gruppe `docker`
fehlt wirklich; die Shell ist älter als das `usermod`, die Mitgliedschaft also längst erteilt und
nur diesem Prozess unbekannt; oder der Daemon läuft nicht. Wer aus dem zweiten Fall „die Gruppe
fehlt" schließt, vergibt ein root-äquivalentes Recht ein zweites Mal, obwohl `sg docker -c '…'`
sofort hilft — und ein Ratschlag, der zum Abschalten der Prüfung führt, ist kein Sicherheitsnetz.

Der Hook fragt jetzt die Gruppen-Datenbank (`id -nG "$benutzer"`) und die Prozess-Credentials
(`id -nG`) getrennt ab und nennt zu jedem Fall den Befehl, der ihn behebt. Als *Funktionstest*
bleibt `docker info` richtig: dort ist nur „Container startbar, ja oder nein" gefragt.

### Hinzugefügt — generierte Artefakte dürfen nicht im Repo liegen

`pip install -e .` schreibt `<paket>.egg-info/` bei jedem Lauf neu. Ist das Verzeichnis versioniert,
hinterlässt jeder Testlauf eine geänderte Datei, und die Suite ist nicht mehr wiederholbar. Der
Fehler bleibt lange unsichtbar: `PKG-INFO` ändert sich nur, wenn sich Metadaten ändern — Version,
Beschreibung, Abhängigkeiten. Bis dahin ist der Baum *zufällig* sauber. In einem Schwesterprojekt
überlebte er so sechs grüne Läufe und kippte erst beim Versionssprung; keine Testsuite fand ihn.

`tests/test_repo.py` verbietet nun `*.egg-info`, `*.dist-info`, `build/`, `dist/`, `__pycache__`
und `*.pyc` unter `git ls-files`. Die `.gitignore` allein genügt nicht: sie schützt nur, was noch
nicht eingecheckt ist.

## [0.14.0] — 2026-07-10

Die Projekt-Website, das Demo-Frontend — und die letzte Seite, die noch nicht übersetzt war.
Keine Änderung an Guards, Sessions oder Anmeldewegen; wer nur die Bibliothek einbindet, merkt
von diesem Release nur die neuen `admin.*`-Schlüssel in `messages.py`.

### Hinzugefügt — das Admin-Panel spricht beide Sprachen
- **`/auth/admin` folgt `cfg.lang`**, wie Login-, Konto- und Fehlerseite. Vorher trug
  `tinysesam/admin.py` sein Deutsch fest im Template: `<html lang=de>`, die Reiter
  „Benutzer / Sitzungen / Härtung / Audit", jede Feldbeschriftung, jede Rückfrage. Ein
  englisch konfiguriertes TinySesam zeigte seinen Administratoren ein deutsches Panel.
- Das Panel baut seine Oberfläche im Browser, deshalb reisen die Texte als JSON mit
  (`const L`) statt in den Vorlagentext eingesetzt zu werden. Sie kommen aus derselben
  Tabelle wie alle anderen Seiten (`messages.py`, Vorsatz `admin.`) und lassen sich damit
  auch wie alle anderen überschreiben — `auth.add_messages("fr", {"admin.tab.users": …})`.
  `neue Sprache` heißt jetzt: eine Tabelle, nicht ein Fork des Panels.
- **`admin.locale`** (`en-GB` / `de-DE`) steuert `toLocaleString()` — sonst stünden englische
  Datumsangaben im deutschen Panel.
- Zwei Absicherungen: `json.dumps(..., ensure_ascii=False)`, damit „Härtung" auch als
  „Härtung" in der UTF-8-Seite steht, und `<` wird zu `<` maskiert — eine eigene
  Übersetzung mit `</script>` hätte sonst den Skriptblock beendet.
- `tests/test_i18n.py` prüft jetzt, dass **beide Tabellen dieselben Schlüssel** tragen (170).
  Ein fehlender Eintrag fiele stumm auf Englisch zurück: die Seite wirkt übersetzt, einzelne
  Wörter sind es nicht. Genau so blieb das Panel unbemerkt deutsch. Der Browser-Test fährt
  `?lang=` durch die Vorschau-iframes bis in den Reiter hinein.

### Hinzugefügt — die Demo-Seite gibt es jetzt auch gebaut
- **`demo.html` auf der Website.** GitHub Pages liefert nur Dateien aus, kein Serverprozess —
  die Live-Demo konnte dort nie laufen, und ein Link dorthin fehlte deshalb. Jetzt rendert
  **`web/demo.py`** die drei Vorschauen (Login, Konto, Admin-Panel) **zur Bauzeit aus der
  Bibliothek selbst** nach `demo/*.html`; `demo.html` bindet sie wie bisher als gesperrte
  iframes ein. Es sind dieselben Seiten wie live, nur eben schon gerendert.
  - Gebaut wird gegen eine **In-Memory-Datenbank** (`db_path=":memory:"`): kein temporäres
    File, nichts aufzuräumen, kein Konto angelegt. Was das Admin-Panel zeigt, sind die
    hartkodierten Beispieldaten aus `MOCK` — die es per `fetch` aus daneben abgelegten
    JSON-Dateien holt, genau wie live aus der Attrappen-Route.
  - Jedes Panel entsteht **je Sprache einmal** (`login.de.html`, `admin.en.html`, …); die
    Seite blendet den passenden Rahmen per `l-en`/`l-de` ein — dasselbe Sprachsystem wie
    überall, keine Sprach-Dateinamen in der URL.
  - **`web/demo.py` ist die einzige Quelle** für Config, Beispieldaten, Panel-Texte und
    Rahmen-CSS. `examples/showcase.py` benutzt sie ebenfalls, statt sie zu duplizieren.
    Vorher lagen dieselben Sätze und dieselbe Config an zwei Stellen — und liefen
    auseinander: die Attrappen-API meldete hartkodiert Version `0.12.0`.
  - `pages.yml` installiert dafür die Bibliothek (`pip install .`) und baut die Seite auch
    dann neu, wenn sich `tinysesam/**` ändert — die Panels sind ja ihr Abbild.

### Geändert
- **Der Kopierknopf steht in einer eigenen Zeile im Codeblock**, oben rechts, statt über dem
  Code zu schweben. Rahmen und Hintergrund sitzen dafür auf `.cw` statt auf `.code`;
  `overflow-x` bleibt beim Code, damit eine lange Zeile den Knopf nicht mit wegscrollt.
- **Die Extras-Liste hat eine einheitliche Schriftgröße.** `code` schrumpft global auf `.86em`,
  die Beschreibung daneben nicht — nebeneinander sah das ungleich aus. Beide stehen jetzt auf
  der kleineren Größe, wie die Sätze darüber und darunter.
- **Auch die Live-Demo startet auf Englisch.** `lang_of()` fiel auf `"de"` zurück, die Website
  längst nicht mehr.

### Behoben
- **Die Website war offline (404).** Nicht der Baujob war schuld, sondern das Ziel: Die
  Pages-Quelle des Repos stand auf *„Deploy from a branch"* (`main`, Pfad `/docs`). In `docs/`
  liegen aber nur `theme.css` und `wizard.png` — die Seiten entstehen aus `web/site.py` und
  werden von `pages.yml` als Artefakt hochgeladen. Pages lieferte also einen Ordner ohne
  `index.html` aus. Derselbe Automatik-Build belegte zusätzlich das Deployment, woran
  `actions/deploy-pages` mit *„in progress deployment"* scheiterte. Der Workflow sagt es im
  Kopfkommentar: Source muss **GitHub Actions** sein. Kein Code-Fix, eine Einstellung:
  `gh api -X PUT repos/<owner>/<repo>/pages -f build_type=workflow`.

### Geändert
- **Englisch ist der Standard der Website.** `LANG_JS` wertete bisher `navigator.language` aus,
  ein deutscher Browser bekam also ungefragt die deutsche Fassung. Jetzt gilt `?lang=` vor
  Cookie vor `LANGS[0]` (= `en`); die aktive Wahl bleibt in `ts_lang` erhalten. `tests/test_site.py`
  friert das ein — der Test verbietet `navigator.language` ausdrücklich.
- **Die Extras stehen als Liste**, nicht mehr als Fließtext mit Mittelpunkten: `[argon2]`,
  `[oidc]`, `[saml]`, `[ldap]`, `[passkey]`, `[qr]`, `[redis]` je in einer Zeile mit ihrer
  Wirkung. Sie sind jetzt **Daten** (`extras` als Paarliste, `extras_intro`/`extras_outro`), das
  Layout steht einmal im Renderer. Das Raster liegt auf der `<ul>`, die `<li>` sind
  `display:contents` — läge es auf dem `li`, wäre jede Zeile ihr eigenes Raster und die
  Beschreibungen flüchteten nicht.

## [0.13.1] — 2026-07-10

### Behoben
- **Das Abbild wurde nie gebaut.** `${{ github.repository_owner }}` liefert die Schreibweise des
  GitHub-Kontos; Container-Registries verlangen kleingeschriebene Namen, und `buildx` brach mit
  *„invalid tag …: repository name must be lowercase"* ab. Der `release`-Job war grün, nur das
  Abbild fehlte — sichtbar erst im Job-Log. Jetzt wird der Eigentümer vorher kleingeschrieben,
  und ein Hygiene-Test verbietet `repository_owner` in der `tags:`-Zeile.

## [0.13.0] — 2026-07-10

### Hinzugefügt — Gateway als Container-Abbild
- **`Dockerfile`** für das OIDC-Forward-Auth-Gateway. Mehrstufig: die Bau-Stufe installiert
  `.[oidc]` **aus dem Build-Kontext** (nicht aus dem Netz) in ein venv, die Laufzeit-Stufe kopiert
  nur dieses venv. Endabbild **ohne `pip` und ohne `git`**, Lauf als **Nicht-root** (uid 1000),
  `HEALTHCHECK` auf `/healthz`, Daten unter `/data`.
  Nur das `[oidc]`-Extra: `[all]` zöge `python3-saml` und damit `libxmlsec1` nach, das für arm64
  unter Emulation kompiliert werden müsste — für ein Extra, das das Gateway nicht benutzt.
- **`release.yml` baut und schiebt das Abbild** nach `ghcr.io/ollornog/tinysesam:<tag>`, für
  `linux/amd64` und `linux/arm64`, und gibt den **Digest** aus. Bewusst **kein `latest`**: ein
  wandernder Tag macht jeden Neustart zum Glücksspiel.
- **`GET /healthz`** im Gateway — ohne Anmeldung, meldet Status und laufende Version. Bei
  `https_mode=force` ist er von der HTTPS-Umleitung ausgenommen: Der Health-Check spricht den
  Prozess von innen über HTTP an, und ein Check, der einen Redirect zurückbekommt, prüft nichts.

### Geändert
- **`deploy/forward-auth/docker-compose.yml` nutzt das Abbild** statt zur Laufzeit zu installieren.
  Kein `pip install` beim Containerstart mehr, kein `command:`. Update per `docker compose pull`.
- Der Browser-Test lässt Chrome seinen Debug-Port selbst wählen und liest ihn aus
  `DevToolsActivePort`. Ein vorab reservierter Port war ein Wettlauf: zwischen dem
  Schließen des Probe-Sockets und dem Start von Chrome konnte ihn ein anderer Prozess
  belegen — auf einem Runner mit parallelen Jobs kein Gedankenspiel.

## [0.12.0] — 2026-07-10

### Entfernt — Selbst-Update (Bruch der öffentlichen API)
- **`tinysesam/updater.py` ist weg**, samt `self_update()`, `update_available()`, `latest_version()`
  und `pip_url()`. Ebenso die Manager-Methoden `update_settings/set_update_setting/update_status/
  run_update/auto_update`, die Panel-Routen `/api/update*`, der Reiter „Update" und die
  Store-Einstellungen `update_mode`/`update_pin`.
  **Grund:** Die Ziel-Version war über das Admin-Panel frei setzbar. Wer eine Admin-Sitzung
  übernimmt, konnte auf eine alte Version mit bekannter Lücke zurückschalten und die Instanz so
  dauerhaft verwundbar machen — ausgerechnet in der Komponente, die alles andere schützt. In einem
  Container ist ein Selbst-Update ohnehin sinnlos: der nächste Neustart verwirft es. Kein
  etabliertes Auth-Projekt hat so einen Knopf.
  **Ersatz:** Die Version bestimmt, wer installiert — gepinnter Git-Tag oder Wheel aus dem Release.
  `python -m tinysesam version` und das Panel unter „Härtung" zeigen die laufende Version.
  Ein Hygiene-Test hält den Knopf draußen.
- **CLI abgespeckt:** `python -m tinysesam version` bleibt, `check` und `update` sind weg.

### Hinzugefügt — Auslieferung
- **`.github/workflows/release.yml`** — ein Tag `vX.Y.Z` baut Wheel + sdist, prüft vorher, dass der
  Tag zur Version in `pyproject.toml` passt, fährt die Suite und hängt die Dateien samt
  `SHA256SUMS` an das GitHub-Release.
- **README: „Installation und Updates"** (beide Sprachen) — die zwei Betriebsarten, der Pin je
  Betriebsart und woher man von einer neuen Version erfährt.
- **`deploy/forward-auth/docker-compose.yml` pinnt die Version.** Vorher lief dort ein
  `pip install …@main` beim Containerstart: jeder Neustart zog den aktuellen Hauptzweig, zwei
  Container derselben Datei konnten verschiedene Versionen fahren, ohne Netz startete nichts,
  und ein Rollback gab es nicht.

### Geändert — Hygiene
- **Keine private Infrastruktur mehr im Repo.** Die Trennlinie ist Identität gegen Infrastruktur:
  Autor, Impressum, Lizenz und Repo-URL sind erlaubt (und teils rechtlich nötig) — Dienst-Subdomains,
  interne Hostnamen, private IPs, Container-Nummern, Heimatverzeichnisse, Kundennamen und
  API-Token-Kennungen nicht. `admin@example.de` ist harmlos, `paperless.example.de` verrät, wo ein
  Paperless läuft.
  Die Muster sind **generisch**, die verbliebenen Eigennamen stehen nur als **SHA256-Anfang** im
  Test: Eine wörtliche Verbotsliste würde in einem öffentlichen Repo genau das veröffentlichen, was
  sie schützen soll. Elf Köder-Zeilen belegen, dass der Wächter greift.
- Beispieldaten des Showcase nutzen jetzt **RFC-5737-Adressen** (`203.0.113.7`) statt einer
  erfundenen Adresse aus einem echten privaten Bereich. Eine solche lässt den eigenen Hygiene-Test
  anschlagen und verleitet dazu, ihn aufzuweichen.
- Die Attrappen-API des Showcase bediente noch `/api/update`, obwohl es die Route nicht mehr gibt.
- **README:** die Live-Demo ist ausdrücklich ein **mitgeliefertes Beispiel-Frontend**, kein
  Bestandteil der Bibliothek und keine Vorgabe.
- **`.githooks/pre-push` läuft auch ohne `ci-local`.** Der Hook verlangte einen Container-Wrapper,
  den nur der Rechner des Autors kennt, und brach bei allen anderen auf Feature-Branches ab.
  Jetzt: nativer Lauf als Standard; nur wer `ci-local` eingerichtet hat, muss auch Docker laufen
  haben. Der Pfad zu einem privaten Verzeichnis ist raus.
- **`scripts/ci-status.sh` und `scripts/ci_status.py` entfernt** — Behelf für Rechner ohne `gh`.
  Mit installiertem `gh` erledigt `gh run watch --exit-status` dasselbe, kennt das Repo aus dem
  Remote und liefert im Gegensatz zum anonymen API-Weg auch die Logs.
- Hygiene-Test bewacht zusätzlich: kein `self-hosted`-Runner in den Workflows (bei einem
  öffentlichen Repo liefe ein Fork-PR sonst auf fremder Hardware) und kein `pip`-Aufruf zur Laufzeit.

### Hinzugefügt — Absicherung
- **`tests/test_browser.py`** — headless Chrome über das DevTools-Protokoll gegen das laufende Showcase:
  Konsolenfehler, fehlschlagende Anfragen, Rumpf auf jeder Seite, gleiche Breiten, Icon-Größen,
  `?lang=`-Umschaltung, Dunkelmodus bis in die Vorschau-iframes, leeres Formular ohne JSON-Wand und der
  Login mit simuliertem Passwort-Autofill. Übersprungen ohne Chrome/`websockets`.
- **`tests/test_repo.py`** — Versionen konsistent, Pflichtdateien da, kein generiertes HTML, keine
  Geheimnisse, kein `print()` in der Bibliothek, Farbwerte nur in `theme.py`, jede Suite im Sammellauf.
- CI: neuer Job **`browser`**, der zusätzlich die Website baut.
- **`scripts/check.sh`** — ein Tor vor jedem Push (Suiten + Browser + Hygiene + Website-Build),
  gefahren vom **`.githooks/pre-push`**-Hook (`git config core.hooksPath .githooks`).
  Nach dem Push wird das CI-Ergebnis aktiv abgeholt (`gh run watch --exit-status`) — ein Push
  ohne Rückmeldung gilt als nicht verifiziert.
- `tests/run_all.py --no-browser` für Zwischenläufe; `tests/test_repo.py` bewacht jetzt auch, dass
  Tor, Hook und CI-Jobs existieren und dass beide READMEs die Tests erklären.

### Geändert — CI und lokale Prüfung
- **`pre-push`: shellcheck-Direktive repariert.** `# shellcheck disable=SC2053  -- Grund` ist keine
  gültige Direktive — der Parser bricht daran ab (`SC1072/SC1073`) und prüft **den Rest der Datei nicht
  mehr**. Der Hook galt dadurch als geprüft, war es aber nicht. Der Grund steht jetzt in einer eigenen
  Zeile darüber; shellcheck meldet den Hook nun sauber (0 Fundstellen).
- **`pre-push` prüft auch nativ auf Rückstände.** Den Rückstands-Check macht sonst nur `ci-local`,
  nicht `check.sh` — wer ohne Container pusht, bekam die Wiederholbarkeits-Prüfung also nicht.
  Der Hook vergleicht jetzt `git status --porcelain` vor und nach dem Lauf und bricht ab, wenn die
  Suite etwas hinterlassen hat. Ein bereits schmutziger Arbeitsbaum gilt nicht als Rückstand;
  Ausnahmen kommen wie bei `ci-local` in `.ci-allow-dirty`.
- **Browser-Test war flaky** — auf kalten CI-Runnern startete Chrome mitunter länger als die 10 s,
  die der Test wartete, und seine Ausgabe landete in `DEVNULL`: Die Meldung lautete stets
  „Chrome antwortet nicht", ohne Grund. Jetzt 30 s (per `CHROME_START_TIMEOUT` überschreibbar),
  Chromes Ausgabe wird eingefangen und bei Fehlschlag mitgedruckt, und ein bereits gestorbener
  Chrome bricht **sofort** ab, statt den Deckel abzuwarten. Die Logdatei wird mit aufgeräumt.
- **Tests sind wiederholbar** — `tests/run_all.py` gibt jeder Suite ein **eigenes Wegwerf-Verzeichnis**
  (`TMPDIR`, `HOME`, `XDG_*` zeigen dorthin, danach gelöscht). Kein Zustand aus einem Lauf kann den
  nächsten beeinflussen, keine Suite die andere stören.
- **Neuer CI-Job `repeat`**: fährt `scripts/check.sh` zweimal hintereinander und prüft anschließend,
  dass der Baum unverändert ist. Ein Test, der beim zweiten Lauf rot wird, ist kaputt — nicht der Code.
  Bewusst nicht im `pre-push`-Hook, das verdoppelte die Wartezeit bei jedem Push.
  Lokales Äquivalent: `ci-local --full`.
- **Versions-Matrix auf `3.10 / 3.12 / 3.14`** (min + prod + max) statt `3.10`–`3.13`. Die alte Matrix
  ließ **3.14 ungetestet**, obwohl das seit Oktober 2025 die aktuelle stabile Version ist. Getestet
  werden jetzt die Ränder, die `requires-python` zusagt, plus die Version, die im Betrieb läuft.
- **Prerelease getrennt:** neuer Workflow `.github/workflows/nightly.yml` fährt Python 3.15
  (`allow-prereleases`) nachts mit `continue-on-error` — ein RC-Bug blockiert damit keinen Push mehr.
- **Feature-Branches lösen keine CI mehr aus** (`on.push.branches: [main]` statt `["**"]`).
  Volle CI läuft beim Pull Request und auf `main`; dazwischen prüft der lokale Container-Lauf.
  Notausgang für WIP auf `main`: `[skip ci]` in der Commit-Message.
- **`.githooks/pre-push` nutzt den Container, wenn es ihn gibt.** Liegt ein `ci-local` im `PATH`,
  läuft die Suite dort — dieselbe Toolchain wie die CI. Wer ihn eingerichtet hat, aber dessen Docker
  nicht antwortet, bekommt auf Feature-Branches einen **Abbruch** (dort läuft keine GitHub-CI, ein
  stiller Rückfall wäre ein Loch im Netz); auf `main` genügt der native Lauf, weil die CI folgt.
  Ohne `ci-local` läuft die Suite schlicht nativ — sonst könnte niemand außer dem Autor pushen.

### Geändert
- **Codeblöcke folgen dem Thema** — bisher waren sie in beiden Themen dunkel, weil `--code-bg` auch
  im hellen Satz ein Dunkelton war. Jetzt helles Blatt auf hellem Papier, dunkel im dunklen Thema;
  die Syntaxfarben liegen als eigene Tokens (`--code-com/-key/-str`) in `docs/theme.css` und sind für
  beide Untergründe kontrastgeprüft.
- **Kopierknopf an jedem Codeblock** (`web/ui.py: codeblock()`). Kopiert wird `innerText`, also der
  reine Befehl ohne Auszeichnung. Wo `navigator.clipboard` fehlt — das Showcase läuft im LAN über
  `http://`, also ohne sicheren Kontext — springt ein `execCommand`-Notweg ein.

### Behoben
- Die **Konto-Vorschau** lud per `fetch` nach, lief ins `401` und warf `TypeError: ks.map is not a
  function` in die Konsole. `render_page("account", static=True)` lädt nichts nach; zusätzlich prüfen
  `loadkeys`/`loadsess` jetzt, ob überhaupt eine Liste zurückkam. (Vom neuen Browser-Test gefunden.)
- Codeblöcken fehlte `white-space:pre` — der mehrzeilige Benutzungs-Block war zu **einer** langen
  Zeile kollabiert. Fiel erst auf, als der Kopierknopf ihn in die Zwischenablage legen sollte.

### Hinzugefügt
- **Impressum & Datenschutz** (`legal.html`, in der Demo `/legal`) — Angaben nach § 5 DDG, Hinweis auf
  GitHub Pages als Hoster (Server-Logs, USA, EU-US Data Privacy Framework), was der Browser speichert
  (`ts_lang`, `ts-theme` — beides angefordert, kein Tracking, kein Cookie-Banner) und die Rechte nach
  Art. 15–21 DSGVO. Die eigenen Daten stehen in `OWNER` in `web/site.py`; unausgefüllte Platzhalter
  werden rot dargestellt. Aus der Fußzeile jeder Seite verlinkt.

### Geändert — UI neu gebaut
- **Ein Sprachsystem, kein zweites.** `?lang=xx` schaltet, das Cookie `ts_lang` merkt — auf der Website
  wie in der App. Die Sprach-Dateinamen (`index.de.html`, `flows.de.html`) sind ersatzlos weg: weil
  GitHub Pages keinen Server hat, trägt jede Datei **beide** Sprachen und blendet eine per CSS aus.
  Aus vier Dateien werden zwei, aus zwei Mechanismen einer.
- **`web/ui.py`**: der komplette Seitenrumpf an einer Stelle — Kopf (Titelzeile + zwei Navreihen in
  *einem* Container), Fußzeile, Aufklapper, Wechsel-Pillen, Icons, CSS und JS. Website, Demo **und**
  die eingebauten TinySesam-Seiten benutzen dieselben Funktionen; `Nav` beschreibt die App einmal,
  `Ctx` den Request. `web/site.py` enthält jetzt nur noch Texte und Seiteninhalt.
- Einziger Sonderfall bleibt die Startseite: dort ersetzt der Titelbereich die Markenzeile.
- Die GitHub-/Doku-Icons sind so hoch wie die Wechsel-Pillen (22 px Rahmen, 20 px Symbol). Dafür muss
  `nav.row a` das Polster per `:not(.ilink)` aussparen — sonst gewinnt es gegen `.ilink` (höhere
  Spezifität), es bleiben 4 px Inhaltsbreite und das Symbol wird zu einem Strich gequetscht.

### Behoben
- **Ein leeres Login-Formular lieferte eine 422-JSON-Wand** statt der Seite mit Fehlermeldung.
  Betroffen waren Login, PIN, TOTP, Registrierung, Ressourcen-PIN, Magic-Link und Passwort-Reset:
  alle nutzten `Form(...)`, dessen Validierungsfehler FastAPI als JSON ausgibt. Jetzt `Form("")` plus
  eine eigene Prüfung → 400 mit „Bitte alle Felder ausfüllen."; die Felder tragen zusätzlich `required`.
- Der Demo-Hinweis erschien auch in der Login-**Vorschau** auf `/demo`, wo er nichts zu suchen hat.
  `render_page("login", demo_hint=False)` unterdrückt ihn.
- **Das Admin-Panel bekam `brand_head` nie** — deshalb blieb es im Dark-Mode hell (das frühe
  Theme-Skript fehlte). Neuer Platzhalter `__BRANDHEAD__`.
- **Der Sprachwechsler war auf den Website-Seiten tot** (`flows.de.html`, `index.de.html`): er zeigte
  auf `…?lang=en`, aber dort steckt die Sprache im **Dateinamen** und überstimmt den Parameter.
  Jetzt verweist er auf die andere Datei. Die Demo-Seiten (`/demo`, `/demo/flows`) benutzen weiter
  `?lang=`, weil sie keine Sprachvarianten als Datei haben.
- **Das eingebaute CSS färbte auf den Rumpf der Host-App ab.** `_CSS` stylte nackte
  `button`/`input`/`h1`-Selektoren; sobald `brand_header`/`brand_footer` gesetzt waren, zerlegte das
  die fremde Navigation (Pillen wurden zu vollbreiten Knöpfen). Alles ist jetzt unter `.tsmain`
  gekapselt, das Admin-Panel unter `.tsadmin`.
- **Der Demo-Login scheiterte durch Browser-Autofill.** Das Passwortfeld wurde mit einem gespeicherten
  Passwort vorbelegt; wer nur den Benutzernamen darüber tippte, bekam „falsche Zugangsdaten" (im
  Server-Log: `demo FAIL password`). Jetzt: `autocomplete=new-password`, ein Skript verwirft ein
  eingefülltes Passwort (mehrfach nachfassend, aber nie nach eigener Eingabe), und die Namen im
  Demo-Hinweis sind **Knöpfe, die das Formular füllen**. Im echten Chrome per DevTools-Protokoll
  gegengeprüft: Autofill wird verworfen, Klick füllt, Login geht durch, Selbstgetipptes bleibt stehen.
- Showcase: die Sprach-/Kontext-Middleware ist reines ASGI. `BaseHTTPMiddleware` führt die App in
  einem eigenen Task aus, dort war die dort gesetzte `ContextVar` nicht mehr sichtbar.
- **Anmeldung schlug mit 403 fehl, wenn zwischendurch eine andere Seite geladen wurde.**
  `render_page()` würfelte bei *jedem* Rendern ein neues CSRF-Token und überschrieb das Cookie —
  damit war jedes offene Formular (auch eine zweite Registerkarte oder eine Fehlerseite) sofort
  ungültig, ohne Fehlermeldung. Das Token wird nun wiederverwendet, solange das Cookie existiert;
  `render_page(..., request=request)` reicht es durch, neu `auth.csrf_token(request)`.
  Der Schutz bleibt unverändert scharf: falsches oder fehlendes Token → 403.

### Geändert
- **Demo-Hinweis steht außerhalb der Login-Karte** — er gehört nicht ins Formular. `_page(..., top=…)`
  bzw. `_doc(..., top=…)` rendern Inhalt oberhalb der Karte (Body ist jetzt eine zentrierte Spalte).

### Hinzugefügt
- **`brand_header` / `brand_footer`** — eigene Navigation und Fußzeile um **jede** eingebaute Seite
  (Login, PIN, TOTP, Konto, Admin-Panel, Fehlerseiten). String oder `fn(auth) -> str`, wenn der Rumpf
  vom Request abhängt. Der Inhalt sitzt in `.tsmain` mittig dazwischen; wirft der Rumpf eine Ausnahme,
  wird er stillschweigend weggelassen statt die Seite mitzureißen.

### Geändert (Website & Showcase)
- Reihenfolge der Leisten: **Titel/Marke → nav2 → Werkzeugleiste** (die schmale mit GitHub/Doku links
  und den beiden Wechslern rechts). Die Trennlinie sitzt unter nav2; das Einblenden beim Laden gilt
  jetzt für alle drei Leisten und liegt in `NAV_CSS` — vorher fehlte es auf der Flow-Seite ganz.
- Der Beispielseiten-Aufklapper springt nicht mehr von selbst auf, wenn man auf einer dieser Seiten ist —
  er wird nur noch markiert.
- Startseite: unter „Installation" stehen jetzt die **Extras** und was sie bringen (`[oidc]`, `[saml]`,
  `[ldap]`, `[passkey]`, `[qr]`, `[redis]`, `[argon2]`) — man muss nicht `[all]` nehmen.
- Showcase: `stepup_methods=["totp", "pin"]` — der sensible Bereich fragt nach der PIN, und sobald 2FA
  eingerichtet ist, steht der Einmalcode zusätzlich zur Wahl.
- **Dritte, schmale Leiste ganz oben**: links GitHub und Doku als Icon-Verweis, rechts die beiden
  Wechsler (Sprache, Hell/Dunkel). Die Markenleiste darunter trägt nur noch das Logo; auf der
  Startseite entfällt sie, weil der Titelbereich sie zeigt.
- Kennungsfelder mit `autocapitalize=none autocorrect=off spellcheck=false` — Tastaturen
  schrieben den Benutzernamen sonst groß.
- **Sprache und Hell/Dunkel als Wechsel-Pillen** in der ersten Leiste (statt Dropdown bzw. Knopf) —
  kompakt (18 px hoch); Marke und Titel in der ersten Leiste dafür größer.
- **Profil-Aufklapper** statt Konto-Knopf: Icon + Benutzername, darunter Konto, Admin-Panel, Abmelden.
- Aufklapper schließen jetzt bei Klick daneben und mit `Escape` (`<details>` tut das von sich aus nicht).
- Fußzeile: die Trennlinie sitzt am Inhalt, nicht am Fensterrand — gleiche Breite wie die Leisten (`--nav-w`).
- Typografie: deutlich mehr Luft vor Überschriften und um die zweite Leiste; Überschriften größer
  (h1 50 px, Abschnitts-Label 18 px, Flow-Überschriften 31 px), Abschnittsabstand 112 px; die Leisten nutzen **eine** Schriftgröße (`--nav-fs`) statt drei.
- Dunkles Theme (`docs/theme.css`): Hintergrund, Flächen und Trennlinien eine Spur heller —
  reines Fast-Schwarz wirkte flach, die Karten hoben sich kaum ab.

## [0.11.0] — 2026-07-09

Großer Sammelrelease: Login-Kennung, PIN als Zusatzfaktor, Erst-Admin-Bootstrap, Demo-Modus,
zweisprachige Website — plus die Rechte-Fallen aus dem ersten Produktiveinsatz.

### Sicherheit
- **`has_role()` verlieh Admins jede Rolle.** Das bleibt der Default (`admin_implies_roles=True`),
  ist aber jetzt abschaltbar — global oder je Guard: `require_role("editor", admin_implies=False)`.
  Wer Rechte allein aus einer IdP-Gruppe ableitet, sollte das tun; sonst ist jeder lokale Admin
  stillschweigend auch „editor".
- **IdP-Gruppen werden exakt verglichen** (`group_match="exact"`, neuer Default). Vorher galt
  Teilstring — der Schlüssel `admin` passte damit auch auf eine Gruppe `nicht-admin`. Für LDAP
  bleibt Teilstring aktiv (dort kommen ganze `memberOf`-DNs an), sonst per Config/Parameter.
- **Erst-Admin-Token nur, wenn lokale Admins vorgesehen sind.** Mit `admin_enabled=False` (reine
  OIDC-App ohne Panel) wird kein Token mehr erzeugt und keins mehr eingelöst — vorher stand eins im
  Log, obwohl die App gar keinen lokalen Admin kannte.
- Doku: **uvicorn ohne `--proxy-headers` starten.** Sonst ersetzt uvicorn `request.client.host` durch
  die geforwardete IP, `trusted_proxies` prüft ins Leere und Rate-Limit/Lockout/fail2ban sind umgehbar.

### Hinzugefügt
- **`auth.issue_csrf(response) -> str`** — CSRF-Cookie setzen und Token holen, für eigene Templates
  (Jinja & Co.), die nicht über `render_page()` laufen. No-op, wenn CSRF aus ist.
- **`oidc_callback_path`** — der Callback war fest verdrahtet. Beim Start loggt TinySesam jetzt
  zusätzlich die erwartete Redirect-URI, damit ein Tippfehler nicht erst der IdP meldet.
- Neue Suite `tests/test_authz_hardening.py`.

- **Erst-Admin ohne „wer zuerst kommt"** — zwei explizite Wege, beide nur wirksam, solange es
  keinen Admin gibt: `admin_identifiers=[…]` (Allowlist auf Name/E-Mail, greift bei **jeder**
  Login-Methode, auch OIDC/SAML/LDAP) und ein **Einmal-Token** im Log →
  `GET /auth/claim-admin?token=…` (`admin_claim_ttl_min`, danach ist die Route 404).
- **Demo-Modus** (`demo_mode=True`) — legt `demo` + `demoadmin` an, zeigt die Zugangsdaten auf der
  Login-Seite (und die PIN auf der PIN-Seite) und warnt sichtbar. Beim Abschalten werden **genau
  diese** Konten wieder gelöscht (`seed_demo`/`purge_demo`, `store.delete_user`).
- Showcase: durchgängige Sprachumschaltung (`?lang=` + Cookie) für Demo-Seiten **und** die
  eingebauten TinySesam-Seiten (`cfg.lang` per Middleware).
- **Login-Kennung wählbar** — `login_identifier="username" | "email" | "both"` (Default **`both`**).
  Passwort- und PIN-Login gehen über `auth.find_user(...)`; das Kennungsfeld beschriftet sich
  passend („Benutzer" / „E-Mail" / „Benutzer oder E-Mail"). Der Timing-Schutz gegen
  User-Enumeration (Dummy-Hash) bleibt in allen Modi erhalten.
- **E-Mail als vollwertige Kennung** — `signup_require_email` (Default **an**), Formatprüfung,
  kanonische Speicherung (getrimmt/klein) und **Eindeutigkeit** per partiellem UNIQUE-Index
  (`users(lower(email))`, Konten ohne Adresse bleiben erlaubt). `store.norm_email`/`valid_email`/`email_taken`.
- **Registrierung folgt `login_identifier`:** im Modus `"email"` entfällt das Benutzernamen-Feld,
  die Adresse ist die Kennung; sonst wie gehabt. Das Admin-Panel darf den Namen dort ebenfalls weglassen.
- Admin-Panel: E-Mail beim Anlegen (Pflicht folgt der Config) + eigene Spalte in der Benutzertabelle.
- **`brand_icon`** — Favicon für **alle** eingebauten Seiten aus einem Config-Wert (Login/PIN/TOTP/
  Konto/Register/Magic/Admin-Panel/Fehlerseiten). Vorher hatte keine davon eins.
- Showcase: **Demo-Postfach** (`/demo/postfach`) — die Demo verschickt nichts, `set_mailer` legt die
  Mails dort ab. Login-Link und Passwort-vergessen sind damit wirklich ausprobierbar.
- **PIN ohne Login-Rolle** — `pin_login=False`: die PIN existiert, erscheint aber **nicht** auf der
  Login-Seite. Sie dient dann nur als Zusatzfaktor (`require(factors=[…, "pin"])`) oder als Step-up.
- **Step-up mit PIN** — `stepup_methods=["pin"]` (leer = alles, was der User hat: TOTP → PIN → Passwort).
  `/auth/reauth` konnte bisher nur TOTP oder Passwort; jetzt auch PIN, und `auth.stepup_options(user)`
  sagt, was für den jeweiligen Nutzer in Frage kommt (Fallback, falls die Wunschmethode fehlt).
- **`/auth/pin` für Eingeloggte** — GET rendert eine echte PIN-Seite (bisher: Redirect auf die Login-Seite),
  ohne Benutzerfeld, wenn eine Sitzung läuft; POST leitet die Identität aus der Sitzung ab.
  Neues Template `pin`, `auth.verify_user_pin` / `verify_user_password` prüfen gegen eine bekannte Identität.
- **Preset `TinySesamConfig.local_accounts(...)`** — nur Benutzername + Passwort, ganz ohne E-Mail
  (kein Magic-Link, kein Passwort-vergessen, keine Bestätigung). Das Registrierungsformular zeigt
  **kein E-Mail-Feld mehr**, wenn die App mit der Adresse ohnehin nichts anfängt.
- **Website zweisprachig und generiert** — Quelle `web/site.py` + `web/flows.py`, Ausgabe
  `index.html` / `index.de.html` / `flows.html` / `flows.de.html` mit Sprachumschalter.
  `python -m web.build` baut sie, die Action `.github/workflows/pages.yml` deployt sie bei jedem
  Push. Die HTML-Dateien liegen **nicht mehr im Repo** (nur `theme.css` + `wizard.png`).
  *Einmalig nötig: Settings → Pages → Source = „GitHub Actions".*
- **Login-Flows als Diagramm** — neun Wege, zweisprachig, aus einer Quelle. Auf der Website steht
  neben jedem der Config-Schalter, der ihn einschaltet; in der Demo (`/demo/flows`) stattdessen
  „aktiv/aus", aus der laufenden Config gelesen.
- **Kopf, zweite Leiste und Fußzeile aus einer Quelle** (`web/site.py`) — auf jeder Seite dieselben,
  in Website wie Demo. `nav_top` = Marke + Werkzeuge (Sprachwechsel, **Dark-Mode-Umschalter**),
  `nav_sub` = Seiten + Beispielseiten-Aufklapper links, An-/Abmelden bzw. Konto/Admin rechts,
  `footer(lang)` = eine Funktion. Sprache in der Leiste als Kürzel (DE/EN), im Menü ausgeschrieben.
  Einziger Sonderfall bleibt die Startseite: `nav_top(brand_href=None)` lässt die Marke weg,
  weil der Titelbereich sie groß zeigt.
- **Dark-Mode-Umschalter** — setzt `data-theme` auf `<html>` (das `docs/theme.css` schon kennt) und
  merkt sich die Wahl; ein Inline-Skript im `<head>` verhindert das Aufblitzen des falschen Themes.
  Neue Suiten `tests/test_pin_stepup.py`, `tests/test_site.py`.

### Behoben
- Showcase: die zweite Leiste fiel nicht mit ein (`rise`-Animation galt nur für Hero und Abschnitte).
- Das offene Dropdown wirkte durchsichtig: die animierten Abschnitte bilden eigene Stapelkontexte und
  malten darüber. `nav.sub` bekommt jetzt einen eigenen Kontext (`position:relative;z-index:30`) und
  einen Hintergrund; das Menü liegt bei `z-index:40`.
- Kopf-, Nav- und Fußzeile richten sich über `--nav-w` nach der Inhaltsbreite der Seite
  (Startseite 720 px, sonst 900 px) — vorher waren sie überall 900 px breit.
- Showcase: die Admin-Vorschau war regelmäßig unten abgeschnitten — ihre Tabelle kommt per `fetch`
  **nach** dem `load`-Event. Der Rahmen misst jetzt per `ResizeObserver` nach (plus Nachzügler-Timer).
- Showcase: auf der Flow-Seite stand die erste Leiste **unter** der zweiten — die Demo klebte ihre
  Leiste hinter `<body>`, die Seite brachte ihre eigene Nav mit. Beide kommen jetzt aus `web/site.py`.
- `signup_verify_email` ist jetzt belastbar: Bestätigung an, aber **kein Mailer** konfiguriert →
  klarer Fehler statt stillem Durchwinken; es wird auch **kein halbfertiges Konto** angelegt.
  Neue Suite `tests/test_identifier.py`.

### Hinzugefügt (Showcase & Design)
- **Showcase-Frontend** (`examples/showcase.py`): `/` ist die Projekt-Website (`docs/index.html`)
  **eins zu eins**, ergänzt um einen Demo-Knopf. `/demo` ist das Demo-Frontend — Nav mit Logo und Titel,
  Anmelden/Registrieren, darunter Login-, Konto- und Admin-Panel als **read-only Live-Vorschau**.
  Die Vorschauen rendern die **echten** Bausteine (`auth.render_page(...)`, `admin.render_panel(...)`),
  sind also nie veraltet; die Admin-Vorschau läuft gegen eine lesende Attrappen-API.
- `tinysesam.admin.render_panel(auth, base, warn="")` — öffentlich, damit das Panel-HTML an genau
  einer Stelle erzeugt wird (Panel und Demo-Vorschau können nicht auseinanderlaufen).
- Showcase: zweite Nav-Leiste mit den Testseiten; Konto und Admin-Panel erscheinen erst, wenn man
  angemeldet ist bzw. Admin-Rechte hat. GitHub-/Doku-Knöpfe mit Icon.

### Geändert
- **Alle eingebauten Seiten stylen sich jetzt über CSS-Variablen** (neu: `tinysesam/theme.py`).
  Login, Konto und Admin-Panel hatten je eigene, hart kodierte Farben — ein `brand_css` konnte sie
  nicht vollständig überschreiben (Konto/Panel blieben dunkel). Ein Satz Tokens re-skinnt nun alles.
  Aussehen der Defaults unverändert (dunkles Theme).
- Website und Showcase teilen sich die Palette `docs/theme.css` (die Website lädt sie per `<link>`,
  die App reicht sie als `brand_css` weiter).
- **README zweisprachig**: `README.md` (Englisch, Default) + `README.de.md` (Deutsch), mit Sprachumschalter.

### Behoben
- Showcase: „Anmelden"/„Konto erstellen" wirkten im eingeloggten Zustand tot (`/auth/login` → `303 /`).
  Das Demo-Frontend kennt jetzt den Login-Status und zeigt stattdessen Konto/Abmelden.

## [0.10.0] — 2026-07-09

### Hinzugefügt
- **Zentraler Theming-Hook:** `brand_css` / `brand_head` re-skinnen mit einem Config-Wert ALLE
  eingebauten Seiten (Login/PIN/TOTP/Reauth/Magic/Register/Konto/Admin-Panel) — kein Nachbau je Seite.
- **Themed Fehlerseiten:** `auth.install_error_pages(app)` — 403/404/429/500 als gebrandete HTML-Seite
  für Browser, JSON für API-Clients; Redirects (Login/Reauth/Faktor) bleiben Redirects. `error`-Template
  über `set_template('error')` ersetzbar.
- Admin-Panel: **„Jetzt aktualisieren"** immer verfügbar (nicht nur bei erkanntem Update).
- Showcase: vollständig gebrandetes Beispiel (ein `brand_css`) inkl. 404-/500-Demo.

## [0.9.0] — 2026-07-09

### Hinzugefügt
- **Rollen/Gruppen-Verwaltung:** `available_roles` (bekannte Rollen) → Admin-Panel bietet sie als
  **Checkboxen** je User (Fallback Freitext). `auth.apply_idp_groups(...)`.
- **IdP-Gruppen → lokale Rollen:** `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`
  (Teilstring-Match, Ziel `__admin__` setzt Admin-Flag). Beim Login gesetzt; gemappte Rollen werden
  synchronisiert, manuelle bleiben. Konsistente `require_role(...)`-Autorisierung über alle Login-Wege.

### Behoben
- CI: `[all]`-Job installiert `libxmlsec1-dev` (SAML/xmlsec); Test-Runner überspringt Suiten mit
  fehlenden Extras (onelogin/ldap3/redis/xmlsec) statt zu scheitern (Minimal-Job wieder grün).

## [0.8.0] — 2026-07-09

### Hinzugefügt
- **SAML 2.0 SP-Login** (Extra `[saml]`, python3-saml) — `/auth/saml/login|acs|metadata`, Signatur-
  geprüfte Assertion (ACS von CSRF ausgenommen), Attribute→User, Gruppen-Gate, Faktor `saml`.
- **Presets** — `TinySesamConfig.active_directory(...)` (AD via LDAP, UPN- oder sAMAccountName-Bind)
  und `TinySesamConfig.entra_id(...)` (Azure AD/Entra via OIDC).
- README/Website: problem-orientierter Pitch (Login-Layer für selbstgebaute Apps).

**Hinweis:** Kerberos/NTLM/GSSAPI-SSO bleibt bewusst außen vor (LAN-/domänengebunden, schwere Ops-Kopplung,
redundant zu OIDC/SAML für AD).

## [0.7.0] — 2026-07-08

### Hinzugefügt
- **i18n** — eingebaute Texte in **Englisch (neuer Default)** und **Deutsch**; `config.lang`,
  `auth.t(key)`, `auth.add_messages(lang, {...})`. **Achtung:** Default ist jetzt Englisch —
  deutschsprachige Integrationen setzen `lang="de"`.
- **CSRF-Schutz** (Double-Submit-Cookie, `csrf_enabled`, Default an) auf allen state-ändernden POSTs;
  eingebaute Formulare/JS erledigen es automatisch, API-Key-Requests sind ausgenommen.
- **Prozessübergreifendes Rate-Limit** über Redis (`redis_url`, Extra `[redis]`) für Multi-Worker;
  `auth.set_rate_limiter()` für eigene Backends. Fallback In-Memory, fail-open bei Redis-Ausfall.
- Projekt-**Icon** + minimale **GitHub-Pages-Website** (`docs/`).

## [0.6.0] — 2026-07-08

### Hinzugefügt
- **LDAP/lldap-Backend** (Extra `[ldap]`) — Passwort gegen Verzeichnis-Bind (Direkt- oder Search-then-Bind),
  Auto-Create lokaler User, optionales Gruppen-Gate. Koexistiert mit lokalen Passwörtern.
- **TOTP-Recovery-Codes** — Einmal-Codes als 2FA-Ersatz (im TOTP-Schritt einlösbar, Self-Service-Regenerierung).
- **Forgot-Password** — Self-Service-Reset per E-Mail (`password_reset_enabled`, nutzt Magic-Link/Mailer).
- **Eigene Sitzungen verwalten** — `/auth/sessions` (maskiert) + „andere/überall abmelden"; auf der Konto-Seite.
- **Optionaler OIDC-RP-Logout** (`oidc_rp_logout`) — Abmelden auch beim Provider (`end_session`).
- `auth.gc()` (DB-Housekeeping), `py.typed` (Typinfos werden mitgeliefert).

### Sicherheit
- Sessions werden nach Passwortwechsel invalidiert (Self: außer aktueller; Admin-Reset: alle).
- Dummy-Hash-Verify gegen **User-Enumeration** per Timing (Login & PIN).
- Ungültiger JSON-Body → **400** statt 500. Test-Runner `tests/run_all.py` + CI (Py 3.10–3.13).

## [0.5.0] — 2026-07-08

Großer Feature-Ausbau; alles **optional** (per Config an/aus), einzeln und kombiniert nutzbar,
Frontend über eine Template-Registry komplett austauschbar. Der klassische Pfad (ein Erstfaktor +
TOTP falls eingerichtet) bleibt unverändert.

### Hinzugefügt
- **Template-Override-Registry** (`auth.set_template(name, fn)`) — jede Seite ersetzbar (String oder Response).
- **Remember-me** — persistentes vs. reines Session-Cookie (`remember_me_enabled`, `session_ttl_transient_hours`).
- **Step-up / per-Route-MFA** — `auth.require(mfa=True)`, Sudo-Frische `stepup_max_age_sec`, `/auth/reauth`, `admin_require_mfa`.
- **Faktor-Ketten** (geordnet) — global `login_chain` + per Route `require(factors=[...], strict=...)`; z.B. OIDC→Passwort.
- **Persönliche PIN** pro User (`pin_enabled`), eigener strenger Lockout, mit TOTP kombinierbar.
- **Geteiltes Ressourcen-Geheimnis** (PIN/Passphrase, ohne Konto) — `require_resource(name)`.
- **Magic-Link** (Einmal-Login per E-Mail) + **Mailer-Hook** (`set_mailer`) / SMTP.
- **Registrierung + Einladung** — `allow_signup`, `signup_verify_email`, `signup_invite_only`, `create_invite`.
- Eingebaute **Konto-Seite** `/auth/account` + Selbst-Passwortänderung `/auth/password`.
- **Forward-Auth** (`/auth/forward` + `/auth/verify`) für Reverse-Proxys; Beispiele Caddy/nginx/Traefik.
- **OIDC-Gateway-Preset** — `TinySesamConfig.oidc_gateway(...)`, `python -m tinysesam.gateway`, docker-compose.
- **Test-Runner** `tests/run_all.py` + **GitHub-Actions-CI** (Py 3.10–3.13, voll + Minimal-Lauf).

### Geändert
- Zentraler **Open-Redirect-Schutz** `safe_next` auf allen `?next=`-Zielen; `cookie_domain` für Subdomain-SSO.
- Ungültiger JSON-Body → **400** statt 500 (`TinySesam.json_body`).
- Store-Auto-Migration (`session.mfa_at`/`remember`/`factors_done`), neues Modul `mailer.py`.

## [0.4.0] — 2026-07-06
Admin-Panel als eigenständiger, frei montierbarer Router (Prefix/Subdomain/Port) + nur-JSON-API-Modus;
HTTPS-Modi `off`/`warn`/`force`.

## [0.3.0] — 2026-07-06
API-Keys + Service-/Daemon-Accounts (gehasht, Ablauf, Rollen-Scope) + eingebautes Admin-Panel.

## [0.2.0] — 2026-07-06
Härtung (Brute-Force-Lockout, Rate-Limit, fail2ban-Log, Audit, Trusted-Proxy) + Self-Update von GitHub.

## [0.1.0] — 2026-07-06
Erstversion: Passwort + TOTP + Passkey/WebAuthn + OIDC, server-seitige Sessions, optionale Rollen.
