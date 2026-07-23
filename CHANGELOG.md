# Changelog

Alle nennenswerten Änderungen. Format lose nach [Keep a Changelog](https://keepachangelog.com/de/).

## [Unreleased]

Arbeiten am Sicherheitsnetz, alle unsichtbar für alle, die nur die Bibliothek einbinden.

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
