---
id: T-7
type: Task
title: "Lizenzangabe auf den SPDX-Ausdruck umstellen (Frist: 18.02.2027)"
status: erledigt
milestone: M-2
tags: [packaging, frist]
created: 2026-09-21
---

# T-7 — Lizenzangabe auf den SPDX-Ausdruck umstellen

**Frist steht fest:** setuptools meldet beim Bau

> `project.license` as a TOML table is deprecated …
> By 2027-Feb-18, you need to update your project and remove deprecated calls
> or your builds will no longer be supported.

Betroffen sind zwei Stellen in `pyproject.toml`: `license = { text = "MIT" }` und der Classifier
`License :: OSI Approved :: MIT License`. Beide ersetzt PEP 639 durch

```toml
license = "MIT"
license-files = ["LICENSE"]
```

## Warum es 2026-09 nicht schon geschehen ist

Der SPDX-Ausdruck verlangt **setuptools ≥ 77**. Gebaut wird aber nicht nur mit dem neuesten:
`tests/test_packaging.py` baut Wheel und sdist **offline und ohne Bau-Isolierung**, also mit dem
setuptools, das in der jeweiligen Umgebung liegt — im lokalen CI-Abbild ist das eine ältere
Fassung, die `license` als Zeichenkette zurückweist. Die Umstellung würde die Suite dort brechen,
und eine Suite, die nur auf dem Papier grün ist, wäre der schlechtere Tausch.

Die veröffentlichten Artefakte entstehen davon unberührt mit dem neuesten setuptools (`python -m
build` baut isoliert) — die Metadaten im Index sind also heute schon die aktuellen
(Metadata 2.4).

## Erledigt 2026-09-25

Alle Umgebungen, in denen gebaut wird, bringen setuptools ≥ 77 mit (CI-Abbild `ci-python-web`: 84,
GitHub-Jobs installieren das neueste, der Release baut isoliert). Umgestellt: `license = "MIT"`,
`license-files = ["LICENSE"]`, `build-system.requires = ["setuptools>=77"]`, Lizenz-Classifier
entfernt. `tests/test_packaging.py` prüft `License-Expression` und `License-File`, lehnt einen
Lizenz-Classifier daneben ab und bricht mit älterem setuptools laut ab statt kryptisch. Der Bau
meldet keine Deprecation mehr. Mutationen: anderer Ausdruck → rot; Classifier zurück → der Bau
selbst lehnt ab.

## Fertig, wenn

1. Die Umgebungen, in denen die Suite läuft, bringen setuptools ≥ 77 mit.
2. `pyproject.toml` nennt `license = "MIT"` + `license-files`, der Lizenz-Classifier ist raus.
3. `tests/test_packaging.py` prüft weiter die Lizenz — dann über `License-Expression` statt über
   den Classifier — und ist in allen Umgebungen grün.
4. Der Bau meldet keine Deprecation mehr.
