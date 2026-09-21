---
id: T-8
type: Task
title: Die 35 nicht einzeln nachgestellten Befunde der Reifeprüfung abarbeiten
status: erledigt
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

## Stand: abgearbeitet (2026-09-21)

**35 behoben, 1 als Produktentscheidung an [M-1](M-1-api-stabil-1-0.md) übergeben.** Jeder Punkt
wurde erst am Code geprüft. Drei Befunde trugen weiter, als sie gemeldet waren (die Datei-Kopie
der Datenbank enthielt nicht einmal die Tabelle `users`; ein Anzeigename wie „Иван" brach die
Forward-Auth mit 500, ganz ohne Angreifer; der App-Lockout blendete fail2ban aus). Zwei
widerlegten sich beim Nachmessen:

* **„API-Keys überleben die Deaktivierung"** — tun sie nicht. `verify_api_key` prüft das Flag;
  die erste Messung war falsch, weil die Methode `(user, roles)` zurückgibt und ein nicht-leeres
  Tupel immer wahr ist.
* **„`resource_locks_enabled` braucht `pin_enabled`"** — eine daraus gebaute Prüfung war ein
  Fehlalarm, den eine eigene Suite sofort widerlegte: Eine gesperrte Ressource wird mit ihrem
  eigenen Geheimnis freigegeben, nicht mit der Login-PIN.

[M-1](M-1-api-stabil-1-0.md) bleibt offen — jetzt aber aus einem benannten Grund und nicht
wegen eines Stapels ungeprüfter Meldungen.

## Sicherheit und Härtung

- [x] Das Admin-Panel gibt die Sitzungstoken aller Nutzer im Klartext heraus
- [x] Sitzungs-Token liegen im Klartext in der Datenbank — behoben: gespeichert wird der sha256,
      bestehende Anmeldungen wurden migriert
- [x] Recovery-Codes tragen nur 48 Bit — behoben: 64 Bit, bestehende bleiben gültig
- [x] Die Datenbank wird welt-lesbar angelegt (0644)
- [x] API-Keys überleben Passwortwechsel und „alle Sitzungen beenden"
- [x] Die `trusted_proxies`-Vorgabe ist fälschungssicher, kippt hinter einem Container-Proxy aber
      — behoben: `client_ip()` meldet den Fehlbetrieb einmal je Peer
- [x] Das mitgelieferte Compose-Beispiel macht jede Client-IP zur Proxy-IP — behoben: eigenes
      Netz mit festem Subnetz statt `0.0.0.0/0`, plus Prüfung
- [x] SSO- und Passkey-Logins schreiben die Proxy-IP statt der Client-IP — behoben: beide
      nehmen `client_ip()`
- [x] Forward-Auth: Header-*Namen* werden geprüft, Header-*Werte* nicht — behoben; dabei fiel
      auf, dass ein Name wie „Иван" die Forward-Auth mit 500 brach, ganz ohne Angreifer
- [x] OIDC: Der JWKS wird einmal geholt und nie erneuert — behoben: Lebensdauer + ein
      gedrosselter Neu-Abruf bei Signaturfehler (`tests/test_oidc_jwks.py`)
- [x] Es gibt keine Konfigurationsprüfung — behoben: `konfigpruefung.py` meldet alle
      Widersprüche gemeinsam beim Aufbau; Fehler brechen ab, Reparierbares warnt

Der CSRF-Umlauf des Admin-Panels ist schon als [B-1](B-1-admin-panel-rotiert-csrf.md) erfasst.

## Betrieb, Protokoll, Datenhaltung

- [x] Ein naives Backup der Datenbank liefert eine LEERE Datenbank (WAL)
- [x] `_migrate()` rüstet nur `session`-Spalten nach — behoben: `PRAGMA user_version`, und
      eine Datei aus einer neueren Fassung meldet sich
- [x] Das Aufräumen läuft nie von selbst, und im Gateway-Abbild gibt es keinen Weg, es anzustoßen
      — behoben: `tinysesam gc --db …` für Cron/Timer
- [x] Nach der ersten Logrotation schreibt TinySesam in die umbenannte Datei — die fail2ban-Jail
      läuft danach blind — behoben: `WatchedFileHandler`
- [x] Das Sicherheits-Log nennt keinen Grund und schweigt beim Lockout — behoben: Abweisungen
      melden sich mit `reason=`, im Format des vorhandenen Filters (die Regel passte also doch,
      es fehlten die Zeilen)
- [x] Admin-Aktionen werden ohne Akteur und ohne IP protokolliert

## Paket und Installation

- [x] `python -m tinysesam.gateway` läuft nach dem dokumentierten pip-Install nicht — behoben:
      Extra `[gateway]`, verständliche Meldung, Doku und Dockerfile nachgezogen
- [x] `--help` beim Gateway startete einen Server auf `0.0.0.0:8000` — behoben: Hilfe und
      Exit 0; ein unbekanntes Argument endet mit 2
- [x] Die Classifier versprechen Python 3.11 und 3.13, die CI fährt beide nicht
      — behoben: Matrix auf alle fünf, plus Hygiene-Prüfung Classifier ↔ Matrix
- [x] Das sdist enthält keine Tests — behoben: `graft tests`, im ausgepackten sdist
      40/44 grün bei 4 sauberen Absagen; `examples/` und `deploy/` sind mit dabei
- [x] SECURITY.md nennt 0.5.x als die Reihe, die Sicherheitsfixes bekommt — behoben: verweist
      jetzt auf den CHANGELOG-Kopf statt auf eine Zahl
- [x] Ein fehlendes Extra meldet sich als 500 oder gar nicht — behoben: ein Wächter für alle
      vier Verfahren, `MissingExtra` mit maschinenlesbarem `extra`-Feld

## Der API-Vertrag

- [x] `Typing :: Typed` und `py.typed` sind eine Zusage, die nie geprüft wurde — behoben:
      30 Typfehler bereinigt, mypy in CI und Abbild, `tests/test_typen.py`
- [x] `check_password` & Co. sind als `Optional[dict]` annotiert, liefern aber `sqlite3.Row`
      — behoben: sie liefern jetzt dicts
- [x] Es gibt keine Fehlertypen, auf die ein Nutzer reagieren kann — behoben: `tinysesam/errors.py`
- [x] `complete_mfa` heißt im eigenen Docstring „rückwärtskompatibler Name" — behoben:
      `complete_totp` ist der klare Name, `complete_mfa` bleibt als Alias
- [~] Die öffentliche Oberfläche wurde gemessen, nicht entschieden — **sichtbar gemacht**:
      jede der 105 Methoden hat einen Docstring, `API.md` führt sie auf. Die Auswahl selbst
      ist eine Produktentscheidung und steht in [M-1](M-1-api-stabil-1-0.md)
- [x] Der API-Wächter friert weniger ein, als „231 Namen" nahelegt — behoben: Vorgabewerte
      der Config-Felder und Rückgabetypen werden jetzt mit erfasst
- [x] `set_template` nennt im Docstring zwei Seitennamen, die es nicht gibt — behoben:
      `TinySesam.SEITEN`, unbekannter Name wirft, Prüfung gegen `render_page`

## Doku, Website, Sprache

- [x] 31 harte deutsche Fehlertexte in HTTP-Antworten — behoben: 35 Meldungen über `api.*`
      zweisprachig, Hygiene-Prüfung verbietet festen Text in `HTTPException`
      (in der Prüfung dreifach gemeldet, ist ein Befund)
- [x] `totp_required` ist ein toter Schalter — behoben: wird abgewiesen, Doku nennt `login_chain`
- [x] Beide READMEs bewerben einen Update-Knopf, den es seit 0.12.0 bewusst nicht gibt — behoben
- [x] Kein vollständiger Konfigurations-Nachschlag — behoben: `KONFIGURATION.md`, generiert,
      alle 119 Felder erklärt, mit Prüfung
- [x] Die PyPI-Projektseite zeigt ein kaputtes Logo und sieben tote Links — behoben
- [x] Die README wird zur PyPI-Beschreibung, enthält aber sieben relative Verweise — behoben:
      absolute URLs, plus Prüfung in `test_repo.py`

## Herkunft

Die Belege der nachgestellten Befunde liegen unter `.befunde-2026-09-21/` (nicht eingecheckt).
Die Titel hier sind die Kurzfassung aus dem Prüfbericht; die Langfassungen liefen mit den
Prüf-Agenten ab. Wo ein Titel knapp ist, entscheidet ohnehin der Code.
