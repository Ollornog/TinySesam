# Mitwirken

*[English version](CONTRIBUTING.md)*

Danke, dass du dir die Zeit nimmst. TinySesam ist eine Authentifizierungs-Bibliothek — eine kleine
Fläche, der andere Projekte ihre Eingangstür anvertrauen. Eine Änderung, die diese Fläche klein und
durchschaubar hält, ist meistens die bessere.

## Grundregeln

1. **Tests gehören zur Änderung, nicht zur Nachbereitung.** Wer Verhalten ändert, ändert im selben
   Commit einen Test. Doku und `CHANGELOG.md` wandern mit.
2. **Die Suite ist wiederholbar.** `./scripts/check.sh` zweimal laufen lassen — beide Läufe grün.
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

## Stil

Schreib wie der Code drumherum: gleiche Benennung, gleiche Kommentardichte. Ein Kommentar nennt eine
Bedingung, die der Code nicht zeigen kann — nicht, was die nächste Zeile tut. Doku und Kommentare auf
Deutsch; Bezeichner bleiben englisch.

## Eine Schwachstelle melden

Für Sicherheitsprobleme **kein** öffentliches Issue öffnen. Nutze GitHubs privates
Schwachstellen-Reporting (den Knopf *Report a vulnerability* unter *Security*) oder schreib an
admin@ollornog.de. Siehe [`SECURITY.md`](SECURITY.md).
