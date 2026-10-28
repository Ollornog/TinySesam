#!/usr/bin/env python3
"""Builds the project website into `_site/` — what GitHub Pages serves.

    python -m web.build [target]        # default: _site/

Produces `index.html`, `demo.html`, `flows.html` and `legal.html` (each bilingual) from
`web/site.py` and copies the static extras (`docs/theme.css`, `docs/wizard.png`). The
GitHub Action `.github/workflows/pages.yml` calls this on every push to `main` — so the
HTML files are **not** in the repo.

The demo page comes with the three preview panels under `demo/`. They are rendered from the
library itself (`web/demo.py`) and therefore need an importable `tinysesam` plus
FastAPI — the website alone could do without. If it is missing, the build aborts instead of
shipping a demo page with dead frames.
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
