# Mitwirken

<a href="../CONTRIBUTING.md">English</a> · <b>Deutsch</b>
<br /><br />

Danke, dass du dir die Zeit nimmst. TinySesam ist eine Authentifizierungs-Bibliothek — eine kleine
Fläche, der andere Projekte ihre Eingangstür anvertrauen. Eine Änderung, die diese Fläche klein und
durchschaubar hält, ist meistens die bessere.

## Grundregeln

1. **Tests gehören zur Änderung, nicht zur Nachbereitung.** Wer Verhalten ändert, ändert im selben
   Commit einen Test. Doku und `CHANGELOG.md` wandern mit.
2. **Die Suite ist wiederholbar.** Der nächtliche Wiederholungslauf (`nightly-repeat`: die CI-Suite zweimal auf
   `main`) prüft das; vor dem Push genügt der schnelle Pre-push-Hook, `PREPUSH_VOLL=1 git push` fährt den vollen Lauf.
   Ein Test, der beim zweiten Lauf rot wird, ist kaputt, nicht der Code. Der Rückstands-Check
   erzwingt das.
3. **Sicherheitsänderungen sind nicht kosmetisch.** Alles, was Sitzungen, Guards, Faktor-Ketten,
   Token-Handhabung oder den Login-Weg berührt, bekommt einen Test, der ohne den Fix fehlschlüge.
   „Funktioniert offensichtlich" ist kein Review.
4. **Keine persönlichen Namen im Repository.** Keine internen Hostnamen, keine Dienst-Subdomains,
   keine Kundennamen — nicht in Code, Doku, Tests oder Commit-Nachrichten. Identität ist erlaubt
   (Autor, Kontaktadresse, Repo-URL), Infrastruktur nicht. `tests/test_repo.py` erzwingt das.
5. **Alles Optionale bleibt optional.** Ein Feature (ein neuer Faktor, ein Provider) darf keine harte
   Abhängigkeit des Kerns werden. Das Frontend ist austauschbar; halte es so.
6. **Das Datenbankschema beginnt bei einer Grundlinie** (Schema 26, der Stand von 0.30.0). Eine Schemaänderung bringt
   genau einen Migrationsschritt vom Stand davor und einen Test, der eine Datenbank dieses Stands öffnet — keine Kette
   von älteren Versionen, keine Fixtures alter Dateien (`AGENTS.md`, Pitfalls).

## Ablauf

Auf einem Feature-Branch arbeiten. Dort läuft keine CI — `ci-local` (bzw. `./scripts/check.sh`) ist
dein Sicherheitsnetz. Einen Pull Request öffnen; die CI läuft auf dem PR und auf `main`, und `main`
merged nur, wenn sie grün ist.

```bash
git switch -c meine-aenderung
python -m venv .venv && . .venv/bin/activate
pip install -e ".[all]"
git config core.hooksPath .githooks    # einmal pro Klon; fährt die Suite vor jedem Push
# ... bearbeiten, dann:
./scripts/check.sh
```

## Einen Commit vor dem Release testen

Ein Commit zwischen zwei Releases trägt die Version des letzten Releases. `pip install "tinysesam @ git+…@<sha>"` über
einem installierten Release meldet „already satisfied“ und installiert nichts — der Dienst läuft mit dem alten Code
weiter (oder nach einem Neustart dazwischen mit einem halb ersetzten). Die Neuinstallation erzwingen — mit den
Abhängigkeiten; das ist auch sicher, wenn der Commit ein Extra oder eine Abhängigkeit hinzufügt oder ändert oder wenn
man die Extras wechselt (etwa auf `[all]`):

```bash
pip install --force-reinstall "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@<sha>"
```

Schneller, wenn sich weder Extras noch Abhängigkeiten ändern: `--no-deps` anhängen — nur das Paket wird ersetzt. Bei
einem geänderten Extra fehlen damit Pakete.

Danach den Dienst neu starten; `pip freeze | grep -i tinysesam` nennt den installierten Commit.

## Stil

Schreib wie der Code drumherum: gleiche Benennung, gleiche Kommentardichte. Ein Kommentar nennt eine
Bedingung, die der Code nicht zeigen kann — nicht, was die nächste Zeile tut. Projektsprache ist
Englisch: Bezeichner (Funktionen, Klassen, Parameter, Variablen, Konstanten, Dateinamen), Namen von
Datenbanktabellen und -spalten, Kommentare, Docstrings, Dokumentation, Commit-Nachrichten und Pull
Requests sind englisch. Deutsch gibt es nur als Übersetzung der Oberfläche (`lang="de"`, `i18n/`).
`tests/test_english_code.py` erzwingt das: ein deutsches Wort in einem Bezeichner, Dateinamen, SQL oder
Kommentar macht die Suite rot.

## Einen Fehler melden

Führe `python -m tinysesam diagnose` aus (Gateway-Abbild: `python -m tinysesam.gateway diagnose`) und öffne den Link,
den der Befehl ausgibt: Er füllt das Fehlerformular mit einem geschwärzten Bericht — keine Netzwerkanfrage, nichts
wird gesendet, bevor du abschickst. Siehe README, [„Einen Fehler melden“](README.de.md#einen-fehler-melden).

## Eine Schwachstelle melden

Für Sicherheitsprobleme **kein** öffentliches Issue öffnen. Nutze GitHubs privates
Schwachstellen-Reporting (den Knopf *Report a vulnerability* unter *Security*) oder schreib an
tinysesam-github@ollornog.de. Siehe [`SECURITY.de.md`](SECURITY.de.md).

<br /><br />
<p align="right"><img src="../docs/wizard.png" alt="TinySesam" width="60" height="60"></p>
