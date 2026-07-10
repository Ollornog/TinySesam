#!/usr/bin/env python3
"""Baut die Projekt-Website nach `_site/` — das, was GitHub Pages ausliefert.

    python -m web.build [ziel]        # Standard: _site/

Erzeugt `index.html`, `demo.html`, `flows.html` und `legal.html` (jeweils zweisprachig) aus
`web/site.py` und kopiert die statischen Beilagen (`docs/theme.css`, `docs/wizard.png`). Die
GitHub-Action `.github/workflows/pages.yml` ruft das bei jedem Push auf `main` auf — die
HTML-Dateien liegen deshalb **nicht** im Repo.

Zur Demo-Seite gehören die drei Vorschau-Panels unter `demo/`. Sie werden aus der Bibliothek
selbst gerendert (`web/demo.py`) und brauchen daher ein importierbares `tinysesam` samt
FastAPI — die Website allein käme ohne aus. Fehlt es, bricht der Bau ab, statt eine Demo-Seite
mit toten Rahmen auszuliefern.
"""
import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from web.demo import build as build_demo  # noqa: E402
from web.site import build_pages  # noqa: E402

ASSETS = ("theme.css", "wizard.png")


def main(target: str = "_site") -> int:
    out = Path(target) if Path(target).is_absolute() else ROOT / target
    out.mkdir(parents=True, exist_ok=True)
    (out / ".nojekyll").write_text("", encoding="utf-8")

    for name, html in build_pages().items():
        (out / name).write_text(html, encoding="utf-8")
        print(f"  {name}")

    for asset in ASSETS:
        shutil.copy2(ROOT / "docs" / asset, out / asset)
        print(f"  {asset}")

    theme = (ROOT / "docs" / "theme.css").read_text(encoding="utf-8")
    for name in build_demo(out, theme, "../wizard.png"):
        print(f"  {name}")

    print(f"→ {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(*sys.argv[1:2]))
