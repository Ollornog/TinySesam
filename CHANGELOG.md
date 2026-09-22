# Changelog

Alle nennenswerten Änderungen. Format lose nach [Keep a Changelog](https://keepachangelog.com/de/).

## [Unveröffentlicht]

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

### Sicherheit

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
  fehlender Claim als *unbestätigt* (fail-closed, mit Protokoll- und Audit-Zeile): Die Adresse kommt
  gar nicht erst ins Konto (neu: `oidc_require_verified_email`, Vorgabe `True` — sie ginge sonst auch
  als `Remote-Email` an die geschützte App weiter) und trägt in keinem Fall die
  Erst-Admin-Entscheidung, auch nicht bei einem Bestandskonto, das sie schon führt
  (`maybe_promote_admin(user, email_bestaetigt=…)`, durchgereicht von `apply_factor`). Adresse und
  Beleg werden dabei immer aus DEMSELBEN Dokument genommen: Der Callback legt ID-Token und
  userinfo-Dokument zusammen, und beim Mischen konnte ein `email_verified=true` aus dem einen an die
  Adresse aus dem anderen geraten. Zweitens hing der Wächter, der Allowlist-**Benutzernamen**
  verbietet, allein an `allow_signup` — beim Auto-Anlegen durch einen IdP (`oidc_auto_create`,
  `saml_auto_create`, `ldap_auto_create`) griff er nicht, obwohl der Name auch dort aus fremder
  Hand kommt (`preferred_username`); er fasst jetzt alle vier Türen. Gefunden im dritten Audit
  (F-14 aus T-13).
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

### Hinzugefügt

- **`stepup_strict`** (Vorgabe `False`): macht aus `stepup_methods` eine Schranke. Bisher war die
  Liste nur ein Wunsch — wer keines der genannten Verfahren eingerichtet hatte, bestätigte mit
  allem, was er hatte, inklusive des Passworts, mit dem er sich gerade angemeldet hatte. Das ist
  kein Step-up. Mit `True` bleibt der Bereich verschlossen, bis das Verfahren eingerichtet ist;
  die Seite sagt das jetzt auch, statt ein Formular ohne Felder zu zeigen.
- **`recent_audit(limit, username=…)`** filtert in SQL (siehe `audit --user` oben).
- **Drei Wächter in `tests/test_repo.py`**: Die in beiden READMEs genannte Zahl der Testdateien und
  die Python-Spanne werden gegen die Wirklichkeit gemessen, und solange die Version unter 1.0 liegt,
  darf keine README eine PyPI-Installation zeigen. Genau diese drei Zahlen waren falsch — Zahlen,
  die niemand nachmisst, veralten beim nächsten Commit.
- **`tests/test_bestandsdaten.py`** — 28 Prüfungen zu dem, was ein Upgrade überleben muss.

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
