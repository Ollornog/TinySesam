---
id: T-9
type: Task
title: Befunde des zweiten Audits (vier Blickwinkel) abarbeiten
status: erledigt
milestone: M-1
tags: [sicherheit, betrieb, tests, audit]
created: 2026-09-21
---

# T-9 — zweites Audit, 2026-09-21

Nach [T-8](T-8-reifepruefung-restbefunde.md) ein zweiter Durchgang mit vier unabhängigen
Blickwinkeln, diesmal **auf den frischen Code selbst** gerichtet: Was ist an den Fixes falsch?
**43 Befunde, 5 davon Blocker** — und mehrere sind Regressionen der Reparaturen aus T-8. Das ist
der Wert eines zweiten Blicks: Wer eine Lücke schliesst, prüft seinen eigenen Verschluss nicht.

Jeder Punkt wird wie in T-8 erst am Code nachgestellt, bevor er angefasst wird.

## Blocker

- [x] **Erst-Admin über den BENUTZERNAMEN kapern.** Der T-8-Wächter verlangt bei offener
      Registrierung eine *E-Mail* in `admin_identifiers` — `maybe_promote_admin` verglich aber
      weiter „Name ODER E-Mail". Wer sich als `username="chef@example.com"` registriert und sein
      eigenes Postfach bestätigt, wurde Erst-Admin. Die Lücke war nur verschoben.
- [x] **`tinysesam backup` migriert die Quelldatenbank.** `_oeffne()` nimmt den vollen
      `Store`-Konstruktor, der `_migrate()` fährt — **bevor** kopiert wird. Wer vor dem Update
      das einzig Richtige tut und sichert, hebt damit die laufende Installation auf das neue
      Schema, während der alte Code läuft. Der Rückweg ist danach zu, und eine Datei im alten
      Schema existiert nirgends mehr. Gilt für `gc` genauso.
- [x] **Rücksicherung ist nicht dokumentiert und schlägt still fehl.** Nach einem Absturz liegen
      `-wal`/`-shm` herum; ein `cp sicherung.db auth.db` wird beim Start von der liegengebliebenen
      WAL überschrieben — der alte Stand ist zurück, `integrity_check` sagt `ok`.
- [x] **`konfigpruefung.py` prüft ein Feld, das es nicht gibt** (`ldap_server` statt `ldap_url`).
      Zwei Fehler in einer Zeile: Die Warnung feuert bei **jeder** LDAP-Konfiguration, und die
      gemeinte Prüfung findet **nie** statt. Die eigenen Presets lösen sie aus.
- [x] **Der PyPI-Geheimnis-Check lässt sich mit einem `name:` aushebeln**
      (`test_packaging.py:235`). Ein Schritt in gewöhnlicher Schreibweise mit
      `password: ${{ secrets.… }}` läuft grün durch. Vor einer Erstveröffentlichung der teuerste.

## Rechte und Zugriff

- [x] **Leerer API-Key-Scope wurde zu „erbt alles".** `["tippfehler"]` schrumpft auf `[]`, und
      `[]` heisst im Schema „kein Scope". Ein Scope, der begrenzen sollte, erweiterte.
- [x] Ein **gescopter API-Key stellt sich selbst einen weiteren mit allen Besitzer-Rollen aus**
      (`create_api_key` schneidet gegen die Konto-, nicht gegen die effektiven Rollen).
- [x] **Die CSRF-Prüfung hat einen vom Client gewählten Ausschalter:** ein beliebiger
      `X-API-Key`-Header überspringt sie — auch bei `apikey_enabled=False`, auch wenn danach die
      Sitzung benutzt wird.
- [x] `POST /auth/magic/request` ohne CSRF-Prüfung (einzige zustandsändernde Route ohne).
- [x] **Das Admin-Panel würfelt bei jedem Aufruf ein neues CSRF-Token** (= [B-1](B-1-admin-panel-rotiert-csrf.md),
      lag auf M-2). Durch die neuen CSRF-Prüfungen trifft es jetzt mehr Wege als bei der Meldung.
- [x] `login_chain` akzeptiert `ldap`/`apikey` als Schritt — beide können nie erfüllt werden.
- [x] `pin_login=False` wird von der „keine Anmelde-Methode"-Prüfung nicht gesehen → leere
      Login-Seite, kein Fund.

## Krypto und Sitzungen

- [x] **Die Migration ist nicht atomar.** `ALTER TABLE` committet für sich; ein Abbruch davor
      hinterlässt Klartext-Token in der Spalte `token_hash` — dauerhaft, weil die
      Erkennungsbedingung danach nie wieder wahr wird. Alle betroffenen Anmeldungen sind tot.
- [x] **Die Migration verträgt keinen zweiten Prozess** (`uvicorn --workers N`): `no such column:
      "token"`, der Worker stirbt beim Start.
- [x] **Ein TOTP-Code gilt 90 Sekunden lang beliebig oft** — zwei getrennte Clients melden sich
      mit demselben Code voll an. NIST SP 800-63B: „SHALL accept a given OTP only once".
- [x] `resource_unlock.token` liegt im **Klartext** in der Datenbank (identisch mit dem Cookie) —
      dasselbe Bedrohungsmodell, das die Sitzungs-Umstellung begründet.
- [x] Recovery-Codes: 64 bit mit ungesalzenem sha256 — NIST verlangt unter 112 bit ein
      Passwort-Hashverfahren.
- [x] scrypt-Fallback unter den OWASP-Parametern (`N=2^15, p=1` ist keine zugelassene Kombination).
- [x] scrypt-Hashes werden **nie** auf argon2 gehoben, auch wenn das Extra nachinstalliert wird.
- [x] Sitzungs-Token wird beim Rechtewechsel (zweiter Faktor) nicht erneuert.
- [x] CSRF-Token wird beim Login nicht rotiert (naives Double-Submit).

## Betrieb

- [x] **fail2ban lässt sich gegen Dritte richten:** Der Benutzername geht ungefiltert ins Log;
      ein `\n` darin erzeugt eine gefälschte Zeile mit fremder IP, während die echte unsichtbar
      wird. Gegen echtes fail2ban 1.1.1 belegt.
- [x] Die mitgelieferte **fail2ban-Jail kann im mitgelieferten Compose nichts lesen** — dort wird
      weder `TINYSESAM_SECURITY_LOG` gesetzt noch ein Logverzeichnis gemountet.
- [x] `/auth/oidc/start` ist die einzige flow-erzeugende Route **ohne Rate-Limit**; jeder Abbruch
      hinterlässt eine Zeile. `gc` gibt den Platz nicht zurück (kein `VACUUM`).
- [x] **Störfall-Diagnose:** falsches Passwort, deaktiviertes Konto und Tippfehler im Namen sind
      im Protokoll byte-identisch; eine aktive Sperre steht gar nicht im Audit; OIDC-Abweisungen
      (Gruppe fehlt / kein Konto) hinterlassen nichts. Es gibt keinen CLI-Weg ans Audit-Log.
- [x] Der **Healthcheck merkt einen Datenbankschaden nicht** — `/healthz` bleibt 200, während
      jede angemeldete Anfrage 500 liefert.
- [x] **Rollback-Falle:** Alter Code auf neuer Datei startet, `/healthz` grün, Konten lesbar,
      jede Sitzungsoperation wirft. Nirgends dokumentiert.
- [x] Keine Timer-/Cron-Vorlage für `gc`, obwohl die README darauf verweist.
- [x] Kein Wort zur Aufbewahrung des Audit-Logs (speichert IP-Adressen).

## Die eigenen Prüfungen

- [x] **Im git-worktree überspringt sich die gesamte Hygiene** (`.git` ist dort eine Datei, nicht
      ein Verzeichnis) — und `run_all` meldet grün.
- [x] **`run_all.py` kennt keinen Boden:** Exit 0 auch bei „0 grün, alles übersprungen".
- [x] `test_repo.py` fängt `import subprocess`, aber nicht `from subprocess import run` oder
      `os.system` — obwohl daneben eine Sicherheitsaussage steht.
- [x] `test_api_surface.py` friert Klassenattribute nicht ein — `FORWARD_HEADERS_DEFAULT` ist in
      der Doku eine Zusage und liesse sich still ändern.
- [x] `test_kern_install.py` misst an zwei Stellen **Textvorkommen statt Verhalten**.
- [x] `test_typen.py` fährt mypy ohne `--check-untyped-defs`: 120 von 410 Funktionen werden nie
      geprüft, darunter alle vier Presets (Nutzer sehen dort `Any`).
- [x] Die Konstruktor-Wächter sind durch Ändern der Config **nach** dem Bau umgehbar — das
      eigene `examples/showcase.py` tut genau das.
- [x] `forward_headers={"user": None}` passiert den Wächter und kippt jeden Forward-Auth-Request
      in ein 500; `{"user": 123}` tötet den Konstruktor mit rohem `TypeError`.
- [x] `_fehlt_extra` in `webauthn_.py` ist toter Code; der Passkey-Fall wirft `RuntimeError`
      statt `MissingExtra`.
- [x] `ldap_.authenticate()` **verschluckt** das fehlende Extra und antwortet wie bei einem
      falschen Passwort; `saml_.metadata()` importiert ungeschützt → 500.

## Stand: abgearbeitet (2026-09-21)

**Alle 43 Befunde bearbeitet.** Jeder wurde erst am Code nachgestellt, bevor er angefasst wurde;
die Belege stecken in `tests/test_audit_runde2.py` (36 Prüfungen) und in der bestehenden
Sicherheits-Suite.

Die drei Regressionen von heute früh sind der eigentliche Ertrag dieser Runde: Der
Erst-Admin-Wächter prüfte die *Konfiguration* und liess den *Vergleich* unverändert; die
API-Key-Beschneidung machte aus „keine passende Rolle" ein „erbt alles"; und `tinysesam backup`
migrierte die Datei, die es sichern sollte. Alle drei entstanden beim Schliessen einer Lücke —
keiner davon wäre ohne einen zweiten, unabhängigen Blick aufgefallen.

## Widerlegt

- **„CSRF-Ausnahme für API-Keys ist kein Bypass"** (Blickwinkel Krypto) gegen **„vom Client
  wählbarer Ausschalter"** (Blickwinkel Sicherheitsfixes): Der zweite hat recht und hat es
  belegt — der Header wird nicht validiert, und danach greift die Sitzung. Der erste hat nur
  die CORS-Seite betrachtet.
