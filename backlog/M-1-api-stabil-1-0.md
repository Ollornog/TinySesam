---
id: M-1
type: Milestone
title: 1.0 — API stabil genug für PyPI
status: offen
tags: [release, api]
created: 2026-07-23
---

# M-1 — 1.0: API stabil genug für PyPI

**Fertig, wenn:** die öffentliche API sich über zwei Minor-Versionen nicht mehr gebrochen hat,
die Ceremony-Pfade (Passkey/OIDC/SAML) einmal gegen echte Gegenstellen liefen, und ein Release
ohne Handgriffe durchläuft.

Erst dann ist PyPI vertretbar — siehe [ADR-1](ADR-1-pypi-vertagt.md). Bis dahin ist der gepinnte
Git-Tag das ehrlichere Artefakt.

## Offen: die Oberfläche ist gemessen, nicht ausgewählt (2026-09-21)

`tests/api_surface.json` friert **alles ein, was keinen führenden Unterstrich trägt** — 105
Methoden. 68 davon kamen in keiner Doku vor; sie sind eingefroren, weil sie so aussehen, nicht
weil jemand entschieden hätte, dass sie zur öffentlichen Oberfläche gehören.

Seit 0.18.0 ist die Lage wenigstens sichtbar: Jede dieser Methoden hat einen Docstring, und
[API.md](../API.md) führt sie vollständig auf (generiert, mit Prüfung). Der Wächter erfasst
seither auch Rückgabetypen und die **Vorgabewerte** der Config-Felder — ohne die liesse sich
`session_ttl_hours` still von 168 auf 1 setzen.

**Was offen bleibt und vor 1.0 entschieden werden muss:** Welche dieser 105 Namen sollen auf
Dauer öffentlich sein? Alles einzufrieren ist die sichere, aber teure Antwort — jede interne
Umbenennung wird dann zum Bruch. Die Entscheidung ist inhaltlich (was verspricht TinySesam?)
und gehört nicht in einen Reparaturlauf.

## Stand: wieder offen (2026-09-21, nach der Reifeprüfung)

Der Meilenstein war für einen Tag geschlossen und ist es nicht mehr. Eine Reifeprüfung mit vier
unabhängigen Blickwinkeln (Sicherheit, Paket/Installation, API-Vertrag, Betrieb) fand **47 Befunde**;
12 davon wurden einzeln nachgestellt — **12 haltbar, 11 als Blocker bestätigt**.

Darunter sechs Sicherheitslücken, jede mit eigenem Nachstellungs-Skript belegt: Rollen-Eskalation
über selbst ausgestellte API-Keys, Konto-Unterschiebung über OIDC (`state` ohne Browser-Bindung)
und SAML (`InResponseTo` ungeprüft), sechs schreibende Routen ohne CSRF-Prüfung (darunter
„2FA abschalten", ohne Audit-Eintrag), eine zurücksetzbare Brute-Force-Sperre und ein
Admin-Bootstrap, bei dem der Erste gewinnt, der die Adresse eintippt.

**Ein Auth-Paket mit Rollen-Eskalation trägt kein „Production/Stable", und eine PyPI-Version ist
unwiderruflich.** Deshalb 0.18.0 statt 1.0.0.

### Warum es niemandem auffiel — der Befund hinter den Befunden

`tests/run_all.py` hat echte Fehlschläge als **„übersprungen"** verbucht. Die Suite war grün, weil
sie nicht gemessen hat. Selbst der schlimmste Fall blieb dadurch unsichtbar: `pip install tinysesam`
mit Vorgabe-Konfiguration startet nicht (`ModuleNotFoundError: webauthn`) — der allererste Schritt
jedes neuen Nutzers, und die CI konnte es nicht sehen.

Das ist zuerst repariert worden. Alles andere wäre auf Sand gebaut.

### Die Bedingungen, Stand jetzt

| Bedingung | Stand |
|---|---|
| Zeremonien gegen echte Gegenstellen | erfüllt |
| Release ohne Handgriffe | erfüllt |
| zwei Minor-Versionen ohne API-Bruch | **Uhr startet mit 0.18.0 neu** |
| **keine offenen Sicherheitsbefunde** | **neu — siehe M-2** |

Die vierte Bedingung stand vorher nicht da, weil niemand danach gesucht hatte. Sie gehört dazu:
Eine stabile Oberfläche über einem Paket mit Rollen-Eskalation misst das Falsche.

## Stand 2026-09-27: T-13 erledigt, offen nur die API-Einstufung

[T-13](T-13-audit-2026-09-22-runde-3.md) (drittes Audit samt Nachträgen, Grenzen und der Prüfrunde
Sperren/Zähler) ist abgeschlossen: Jeder Punkt ist behoben mit Test, per Mutation belegt, oder als
„bewusst so, begründet" markiert. Für diesen Meilenstein offen ist damit nur noch die **Einstufung
der öffentlichen API in A/B/C** (PO-Entscheid 2026-09-26) — die inhaltliche Frage oben, welche der
eingefrorenen Namen auf Dauer öffentlich sein sollen. Sie liegt beim PO.

## Stand 2026-09-27: Einstufung gebaut, die Uhr für A startet mit 0.22.0

Der PO hat die Stufen am 2026-09-26 entschieden („klingt gut — go“); gebaut ist Schritt 1:

- **Jeder der 339 öffentlichen Namen trägt eine Stufe** in `tests/api_surface.json` —
  A 225 (davon 158 Konfigurationsfelder), B 64, C 50. `tests/test_api_surface.py` ist rot, wenn
  einer keine oder eine unbekannte trägt; `--update` übernimmt Stufen, vergibt aber nie eine.
  Damit ist die Frage oben („gemessen, nicht ausgewählt“) beantwortet: Ausgewählt ist, was A ist.
- **Nur für A gilt die Bedingung „zwei Minor-Versionen ohne Bruch“**, gezählt ab 0.22.0 — dem
  Release, das die Einstufung bringt. Ein Bruch an B (nur nach `DeprecationWarning` über zwei
  Minor-Versionen) oder C (intern, fällt mit 1.0) setzt die Uhr nicht zurück; der Wächter meldet
  ihn trotzdem, mit der Stufe davor.
- `API.md` gliedert nach Stufe, die READMEs erklären die Stufen und führen die B-Bausteine im
  Abschnitt für Fortgeschrittene.

| Bedingung | Stand |
|---|---|
| Einstufung der öffentlichen API | **gebaut** (Stufen, Wächter, Doku) |
| C-Namen mit Unterstrich, alter Name als warnender Alias bis 1.0 | **gebaut** (50 Aliase, Wächter, Warnfilter in `run_all.py`) |
| sicherer Baustein für eigene Login-Seiten (die inneren Prüfer drosseln nicht, PO-Befund) | **gebaut** — Schritt 3 (`login_*`, `LoginResult`, die Routen rufen ihn; englisch seit dem Nachtrag unten) |
| dasselbe für eigene Step-up- und Passwortwechsel-Seiten (PO-Entscheid 2026-09-27) | **gebaut** — `confirm_*` (→ `LoginResult`), `change_password` (→ `PasswordChangeResult`), `/auth/reauth` und `POST /auth/password` rufen sie; Nachtrag unten |
| zwei Minor-Versionen ohne Bruch **an Stufe A** | Uhr startet mit 0.22.0 |

**Schritt 2 (2026-09-27): Stufe C ist ein warnender Alias.** Die Implementierung heisst `_name`
(42 Methoden, 6 Konstanten; `complete_mfa` zeigt auf `complete_totp`), der alte Name ist ein
`Veraltet` aus `tinysesam/_veraltet.py` und warnt beim Aufruf genau einmal mit Ersatz. Paket,
Beispiele, Skripte und Tests rufen nur noch die neuen Namen. Der Wächter hält Ablage und Klasse
gegeneinander, prüft Warnung, Ziel und Weiterreichen jedes Alias, verbietet alte Namen im eigenen
Code (AST) und wird mit 1.0 rot, solange noch ein Alias steht; `tests/run_all.py` macht eine solche
Warnung aus dem Paket selbst zum Fehler. `SERIE_PIN_FOLGE` war nie veröffentlicht und heisst ohne
Alias `_SERIE_PIN_FOLGE` — Stand nach Schritt 2: 338 Namen, C 49.

**Schritt 3 (2026-09-27): ein sicherer Login-Baustein für eigene Seiten.** (Mit den Namen von
damals — seit dem Nachtrag „Der Login-Baustein heisst englisch“ unten gelten die englischen.) Der
PO-Befund: Die README schickte eigene Login-Seiten zu `check_password` + `start_session`, und die
inneren Prüfer drosseln nicht. Jetzt gibt es `anmelden_passwort`, `anmelden_pin` und
`anmelden_totp` (Stufe A) mit dem Ergebnistyp `tinysesam.Anmeldung` (Export, Stufe A): Sie
drosseln, zählen und sperren wie die eingebauten Routen — weil `POST /auth/login`, `/auth/pin` und `/auth/totp` genau sie rufen und nur
noch das Ergebnis rendern (eine Quelle; ein AST-Wächter in `tests/test_anmelden.py` verbietet den
Routen jeden inneren Prüfer). Gemessen ist die Gleichheit Zeile für Zeile: dieselbe Folge über die
eingebaute und über eine eigene Route ergibt dieselben Status, Audit-, Log- und Zählerzeilen. Die
README zeigt beide Wege (nur Aussehen: `set_template`; eigene Route: `anmelden_passwort`), ihr
Beispiel läuft im Test wörtlich und muss sperren. Die Ersatztexte der C-Aliase nennen den Baustein.
Der Wächter misst den Ergebnistyp mit (Bereich `Anmeldung`: Felder, Methoden, `GRUENDE`) — Stand
353 Namen: A 240, B 64, C 49.

**Nachtrag 2026-09-27: 0.21.0 ging ohne die Einstufung hinaus** (vorgezogen für einen
Produktivgang). Sie erscheint mit **0.22.0**: `seit` der Aliase, der Zähler für A, die Warntexte
und die Doku nennen 0.22.0. Weil nur geprüft war, *ob* `seit` dasteht, prüft der Wächter jetzt auch
den Wert gegen das CHANGELOG (`seit_befunde`): Führt `[Unveröffentlicht]` einen Alias ein, liegt
`seit` über dem jüngsten Release, sonst ist es genau das einführende Release.
Eine Folge davon: `SERIE_PIN_FOLGE` war bei Schritt 2 „nie veröffentlicht“ und hiess ohne Alias
`_SERIE_PIN_FOLGE` — mit 0.21.0 ist er veröffentlicht (G7; dessen CHANGELOG nennt ihn für eigene
PIN-Seiten). Er ist jetzt ein Alias wie jeder C-Name: Stand 354 Namen, A 240, B 64, C 50.

**Nachtrag 2026-09-27 (PO-Entscheid): Der Login-Baustein heisst englisch** und bleibt Stufe A,
wie der Rest der Stufe-A-Oberfläche: `login_password`, `login_pin`, `login_totp`; der Ergebnistyp
`tinysesam.LoginResult` (Modul `tinysesam/login_result.py`) mit `ok`, `reason`, `status`,
`message`, `next_url`, `next_factor`, `done`, `user`, `set_cookie(response)` und `redirect()`;
die Gründe in `REASONS`: `ok`, `missing`, `invalid`, `locked`, `locked_series`, `ratelimit`,
`directory_down`, `method_disabled`, `no_session`. Umbenannt vor dem Release und darum **ohne
Alias** — die Namen aus Schritt 3 (`anmelden_*`, `Anmeldung`, `GRUENDE`, `cookie_setzen` …)
standen in keinem Release (`git show v0.21.0:tinysesam/manager.py` kennt sie nicht). Nur die
Namen des Bausteins sind betroffen: Audit- und Log-Zeilen (`login_fail … grund=…`, die Zeilen für
fail2ban) bleiben, wie sie sind; `reason` ist ein Kürzel für Programme, keine Logzeile. Ein
Wächter (`tests/test_anmelden.py`, Abschnitt k) misst die Oberfläche des Bausteins am Objekt —
jede Methode, die ein `LoginResult` liefert, samt Parametern; Typ, Modul, Felder, Methoden,
`REASONS` — und verlangt: kein deutsches Wort aus einer kurzen Liste, jeder Name Stufe A. Stand
unverändert 354 Namen, A 240, B 64, C 50.

~~Offen für diesen Meilenstein, als Befund aus Schritt 3: Der Wächter hält Signaturen ohne den
Stern der Nur-Schlüsselwort-Parameter fest.~~ **Behoben 2026-09-27:** `signatur()` misst `*` und
`/` mit (10 Signaturen neu gemessen, keine geändert), ein eingefügtes `*` ist ein Bruch; eine
Ablage von vor 0.22.0 wird ohne Marken eingelesen und ohne Marken verglichen, der Vergleich mit
`v0.21.0`/`v0.20.1` meldet nur echte Unterschiede. `API.md` zeigt die Marken ebenfalls.

Nicht gemessen und damit ausserhalb der Einstufung: Instanzattribute (`auth.store`, `auth.cfg`,
`on_security_event` …), die HTTP-Routen und die Logger-Namen (`tinysesam.security`). Ob sie in
die Zusage gehören, liegt als offene Frage beim PO.

**Nachtrag 2026-09-27 (PO-Entscheid): Die ganze Oberfläche der Stufen A und B heisst englisch,
ohne Alias.** Nach dem Login-Baustein jetzt der Rest: 11 Methoden, 5 Konstanten, 2 Methoden von
`TinySesamConfig`, 18 Parameter in 14 Methoden, `ConfigError.feld`/`.besitzer_id` →
`.field`/`.owner_id` und `MissingExtra(nachricht, …)` → `MissingExtra(message, …)` (Tabelle im
CHANGELOG unter „Was beim Update auffällt“). Anders als beim Baustein standen diese Namen in
0.21.0 — sie fallen trotzdem **ohne Alias**, weil die Zusagen der Stufen erst mit 0.22.0 beginnen
und keiner der bekannten Abnehmer einen davon benutzt (geprüft: kein Aufruf, kein Parameter, kein
Konfigurationsfeld). Die Stufen bleiben, wie sie waren. Kein Konfigurationsfeld war betroffen —
sie hiessen schon englisch. Werte bleiben: Grund-Kürzel, Audit- und Log-Zeilen, die Schlüssel des
Berichts von `federation_bind_existing`, Datenbank-Spalten.

Der Namens-Wächter aus Abschnitt (k) ist dafür auf die ganze Oberfläche ausgedehnt
(`tests/test_api_surface.py`, `pruefe_namen`): jeder Name in A oder B, jeder Parameter am lebenden
Objekt, jedes Konfigurationsfeld, die Attribute und Konstruktor-Parameter der Fehlertypen — 566
Einträge; Wörter, Stämme (auch mitten im Wort) und Umlaute; Mindestmenge und Selbstproben. Stand
unverändert 354 Namen, A 240, B 64, C 50.

Offen (nicht Teil dieses Entscheids, Rückfrage beim PO): Rückgabewerte und Daten tragen noch
deutsche Schlüssel — der Bericht von `federation_bind_existing` (`quelle`, `ausgefuehrt`,
`gebunden`, `konflikt`, `mehrdeutig`, `nicht_im_verzeichnis`, `ohne_kennung`, `abgewiesen`,
`lokal`, je Eintrag `verzeichnis`, `kennung`, `grund`, `gebunden_an`, `treffer`), `gc()`
(`fehlserien`), die Nutzlast von `on_security_event` (`alt`, `neu`), die Werte von `api_key_kind`
(`automat`, `mensch`) und der Kontext für eigene Seiten (`ctx["praefix"]`, `ctx["zweck"]`). Der
Wächter misst Namen, keine Werte; ob diese Schlüssel vor 1.0 englisch werden, ist eine eigene
Entscheidung — jede Änderung dort bricht Code, der sie liest.

**Nachtrag 2026-09-27 (PO-Entscheid): Bausteine für eigene Step-up- und Passwortwechsel-Seiten**
(Stufe A, englisch). Nach dem Login-Baustein fehlte dasselbe für die Bestätigung vor heiklen
Aktionen und den eigenen Passwortwechsel: Es gab nur die Routen `/auth/reauth` und
`POST /auth/password`, und die inneren Prüfer (`_verify_user_password`, `_verify_user_pin`,
`_verify_totp`) drosseln nicht. Jetzt:

- `confirm_password(request, password, *, next="", csrf=None)`, `confirm_pin(…, pin, …)`,
  `confirm_totp(…, code, …)` → **`LoginResult`**. Drei Namen wie bei `login_*` statt eines
  `confirm(…)` mit drei optionalen Feldern: je Aufruf genau ein Geheimnis, keine Reihenfolge, die
  still ein Feld übergeht. `LoginResult` statt eines eigenen Typs: Eine Bestätigung ist eine
  erneute Anmeldung an der laufenden Sitzung, die Felder passen ohne Rest, und `redirect()`/
  `set_cookie()` braucht es für das erneuerte Token. `next` kam gegenüber dem Auftrag hinzu — wie
  bei `login_*`, damit `redirect()` ein geprüftes Ziel hat.
- `change_password(request, current, new, *, csrf=None)` → **`PasswordChangeResult`** (neuer
  Export): `ok`, `reason`, `status`, `message`, `api_keys_active`. Ein eigener Typ, weil ein
  Passwortwechsel niemanden anmeldet und kein Token dreht.
- Die Routen sind Hüllen darum; ein AST-Wächter (`tests/test_bestaetigen.py`, h) verbietet ihnen
  jeden inneren Prüfer, gemessen ist die Gleichheit Zeile für Zeile (g). Drei Verhaltensänderungen
  an den Routen stehen im CHANGELOG unter „Was beim Update auffällt“: `POST /auth/password` nimmt
  keinen API-Key mehr (403), ein leeres Feld zählt an beiden nicht mehr, ein nicht angebotenes
  Verfahren an `/auth/reauth` ist 403 ohne Fehlversuch.

Stand 365 Namen: A 251 (+ 4 Methoden, der Export und 6 Namen an `PasswordChangeResult`), B 64,
C 50; der Namens-Wächter misst 593 Einträge.

<!-- Was vorher hier stand (Schliessung mit 1.0.0), ist mit dem Meilenstein selbst hinfaellig. -->
