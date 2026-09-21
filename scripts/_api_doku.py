#!/usr/bin/env python3
"""Erzeugt API.md — die öffentliche Oberfläche von `TinySesam`, mit Signatur und erstem Satz.

Warum: 68 der 105 eingefrorenen Methoden kamen in keiner Doku vor. Wer TinySesam einbettet,
sah eine Zusage („diese Oberfläche bleibt stabil") ohne eine Stelle, an der steht, was sie
enthält. Der Wächter `tests/test_api_surface.py` misst dieselbe Menge — hier ist sie lesbar.

    python3 scripts/_api_doku.py              # schreiben
    python3 scripts/_api_doku.py --dry-run    # nur prüfen (Exit 1 = veraltet)

Offen und bewusst nicht hier entschieden: WELCHE dieser Methoden öffentlich sein *sollen*. Die
Oberfläche ist gemessen (alles ohne führenden Unterstrich), nicht ausgewählt. Das ist eine
Produktentscheidung und steht in `backlog/M-1-api-stabil-1-0.md`.
"""
from __future__ import annotations

import inspect
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
ZIEL = ROOT / "API.md"

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402

KOPF = """# API — die öffentliche Oberfläche von `TinySesam`

<!-- GENERIERT von scripts/_api_doku.py — nicht von Hand pflegen.
     Neu bauen: `python3 scripts/_api_doku.py` -->

Diese Namen hält `tests/api_surface.json` fest: Was hier steht, ändert sich nicht ohne eine
bewusste Entscheidung und einen Eintrag im CHANGELOG.

Die READMEs zeigen die **Wege** (welche Methode wofür, wie man sie kombiniert). Hier steht, was
es überhaupt gibt — die Frage „gibt es dafür schon etwas?" beantwortet diese Seite, nicht der
Quelltext.

> **Gemessen, nicht ausgewählt.** Erfasst ist alles ohne führenden Unterstrich. Welche dieser
> Methoden auf Dauer öffentlich sein *sollen*, ist eine offene Entscheidung für 1.0
> ([M-1](backlog/M-1-api-stabil-1-0.md)) — bis dahin gilt: eingefroren ist, was hier steht.

Die Konfigurationsfelder stehen in [KONFIGURATION.md](KONFIGURATION.md).

"""


def erster_satz(fn) -> str:
    text = (inspect.getdoc(fn) or "").strip()
    if not text:
        return "—"
    satz = text.split("\n\n")[0].replace("\n", " ").strip()
    return satz.replace("|", "\\|")


def signatur(fn) -> str:
    try:
        s = inspect.signature(fn)
    except (TypeError, ValueError):
        return "(…)"
    teile = [str(p) for name, p in s.parameters.items() if name != "self"]
    zurueck = "" if s.return_annotation is inspect.Signature.empty else \
        f" -> {inspect.formatannotation(s.return_annotation)}"
    return "(" + ", ".join(teile) + ")" + zurueck


def bauen() -> str:
    teile = [KOPF, "## `TinySesam`\n\n"]
    methoden = [(n, f) for n, f in inspect.getmembers(TinySesam, callable) if not n.startswith("_")]
    for name, fn in methoden:
        teile.append(f"### `{name}{signatur(fn)}`\n\n{erster_satz(fn)}\n\n")

    teile.append("## `TinySesamConfig` — Presets\n\n")
    presets = [(n, f) for n, f in inspect.getmembers(TinySesamConfig, callable)
               if not n.startswith("_")]
    for name, fn in presets:
        teile.append(f"### `TinySesamConfig.{name}{signatur(fn)}`\n\n{erster_satz(fn)}\n\n")

    teile.append(f"---\n\n{len(methoden)} Methoden, {len(presets)} Presets — "
                 "erzeugt aus den Docstrings.\n")
    return "".join(teile)


def main() -> int:
    neu = bauen()
    alt = ZIEL.read_text(encoding="utf-8") if ZIEL.exists() else ""
    if "--dry-run" in sys.argv:
        if alt != neu:
            print(f"{ZIEL.name} ist veraltet — `python3 scripts/_api_doku.py` fahren", file=sys.stderr)
            return 1
        return 0
    ZIEL.write_text(neu, encoding="utf-8")
    print(f"geschrieben: {ZIEL.name}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
