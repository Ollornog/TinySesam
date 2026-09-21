---
id: T-8
type: Task
title: Die 35 nicht einzeln nachgestellten Befunde der Reifeprüfung abarbeiten
status: in-arbeit
milestone: M-1
tags: [sicherheit, betrieb, paket, api, doku]
created: 2026-09-21
---

# T-8 — die 35 Restbefunde der Reifeprüfung

Die Reifeprüfung vom 2026-09-21 (vier unabhängige Blickwinkel) fand **47 Befunde**. 12 wurden
einzeln nachgestellt und sind erledigt — die sechs Sicherheitslücken samt Tests, der Kern-Install,
der blinde Testlauf. Die übrigen **35 sind gemeldet, aber nicht verifiziert**: Sie stammen aus den
Berichten der Prüfer, nicht aus einem eigenen Nachstellungsversuch.

**Das ist der Unterschied, der zählt.** Ein gemeldeter Befund ist eine Behauptung. Jeder Punkt
hier wird deshalb erst am Code geprüft und dann entschieden: bestätigt → beheben mit Test;
widerlegt → hier mit Begründung streichen; Geschmacksfrage → ADR. Kein Punkt wird „weil er
dasteht" umgebaut.

**Fertig, wenn** jeder Punkt eine dieser drei Markierungen trägt und die bestätigten behoben sind.
[M-1](M-1-api-stabil-1-0.md) bleibt bis dahin offen.

## Sicherheit und Härtung

- [x] Das Admin-Panel gibt die Sitzungstoken aller Nutzer im Klartext heraus
- [x] Sitzungs-Token liegen im Klartext in der Datenbank — behoben: gespeichert wird der sha256,
      bestehende Anmeldungen wurden migriert
- [ ] Recovery-Codes tragen nur 48 Bit (zweite Hälfte desselben Befunds, noch offen)
- [x] Die Datenbank wird welt-lesbar angelegt (0644)
- [x] API-Keys überleben Passwortwechsel und „alle Sitzungen beenden"
- [ ] Die `trusted_proxies`-Vorgabe ist fälschungssicher, kippt hinter einem Container-Proxy aber
- [ ] Das mitgelieferte Compose-Beispiel macht jede Client-IP zur Proxy-IP
- [ ] SSO- und Passkey-Logins schreiben die Proxy-IP statt der Client-IP
- [ ] Forward-Auth: Header-*Namen* werden geprüft, Header-*Werte* nicht (IdP-Anzeigename)
- [ ] OIDC: Der JWKS wird einmal geholt und nie erneuert
- [ ] Es gibt keine Konfigurationsprüfung — Widersprüche fallen erst beim Login auf
      (teilweise angegangen: die Kombinations-Wächter im Konstruktor)

Der CSRF-Umlauf des Admin-Panels ist schon als [B-1](B-1-admin-panel-rotiert-csrf.md) erfasst.

## Betrieb, Protokoll, Datenhaltung

- [x] Ein naives Backup der Datenbank liefert eine LEERE Datenbank (WAL)
- [ ] `_migrate()` rüstet nur `session`-Spalten nach — es gibt keinen Schema-Stempel
- [x] Das Aufräumen läuft nie von selbst, und im Gateway-Abbild gibt es keinen Weg, es anzustoßen
      — behoben: `tinysesam gc --db …` für Cron/Timer
- [x] Nach der ersten Logrotation schreibt TinySesam in die umbenannte Datei — die fail2ban-Jail
      läuft danach blind — behoben: `WatchedFileHandler`
- [x] Das Sicherheits-Log nennt keinen Grund und schweigt beim Lockout — behoben: Abweisungen
      melden sich mit `reason=`, im Format des vorhandenen Filters (die Regel passte also doch,
      es fehlten die Zeilen)
- [x] Admin-Aktionen werden ohne Akteur und ohne IP protokolliert

## Paket und Installation

- [ ] `python -m tinysesam.gateway` läuft nach dem dokumentierten pip-Install nicht (uvicorn)
- [ ] `--help` beim **Gateway** startet einen Server auf `0.0.0.0:8000` (für `python -m tinysesam`
      erledigt: Exit 0 statt 2; der Gateway-Einstieg steht noch aus)
- [x] Die Classifier versprechen Python 3.11 und 3.13, die CI fährt beide nicht
      — behoben: Matrix auf alle fünf, plus Hygiene-Prüfung Classifier ↔ Matrix
- [ ] Das sdist enthält keine Tests — wer neu paketiert, kann den Bau nicht prüfen
- [ ] SECURITY.md nennt 0.5.x als die Reihe, die Sicherheitsfixes bekommt
- [ ] Ein fehlendes Extra meldet sich als 500 oder gar nicht, statt als Klartext
      (für `[passkey]` behoben; die übrigen offen)

## Der API-Vertrag

- [ ] `Typing :: Typed` und `py.typed` sind eine Zusage, die nie geprüft wurde
- [ ] `check_password` & Co. sind als `Optional[dict]` annotiert, liefern aber `sqlite3.Row`
- [ ] Es gibt keine Fehlertypen, auf die ein Nutzer reagieren kann
- [ ] `complete_mfa` heißt im eigenen Docstring „rückwärtskompatibler Name" und wird trotzdem geführt
- [ ] Die öffentliche Oberfläche wurde gemessen, nicht entschieden: 62 der 104 eingefrorenen Namen
- [ ] Der API-Wächter friert weniger ein, als „231 Namen" nahelegt: keine Vorgabewerte, keine Typen
- [ ] `set_template` nennt im Docstring zwei Seitennamen, die es nicht gibt

## Doku, Website, Sprache

- [ ] 31 harte deutsche Fehlertexte in HTTP-Antworten — auch bei `lang="en"`
      (in der Prüfung dreifach gemeldet, ist ein Befund)
- [ ] `totp_required` ist ein toter Schalter — in beiden READMEs und auf der Website als 2FA beworben
- [ ] Beide READMEs bewerben einen Update-Knopf, den es seit 0.12.0 bewusst nicht gibt
- [ ] Kein vollständiger Konfigurations-Nachschlag: 36 von 119 Feldern kommen in keiner Doku vor
- [ ] Die PyPI-Projektseite zeigt ein kaputtes Logo und sieben tote Links
- [ ] Die README wird zur PyPI-Beschreibung, enthält aber sieben relative Verweise

## Herkunft

Die Belege der nachgestellten Befunde liegen unter `.befunde-2026-09-21/` (nicht eingecheckt).
Die Titel hier sind die Kurzfassung aus dem Prüfbericht; die Langfassungen liefen mit den
Prüf-Agenten ab. Wo ein Titel knapp ist, entscheidet ohnehin der Code.
