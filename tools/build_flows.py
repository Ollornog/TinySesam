#!/usr/bin/env python3
"""Backt `docs/flows.html` aus `examples/flows.py` — statisch, für GitHub Pages.

    python tools/build_flows.py

Dieselben Diagramme rendert die Demo unter `/demo/flows` (dort mit „aktiv/aus" aus der laufenden
Config, hier mit dem Config-Schalter, der den Weg einschaltet). Nach Änderungen an `flows.py`
neu laufen lassen und `docs/flows.html` mitcommitten — Pages liefert nur statische Dateien aus.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "examples"))

from flows import CSS as FLOW_CSS, render  # noqa: E402

REPO = "https://github.com/Ollornog/TinySesam"

PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>TinySesam — sign-in flows</title>
<meta name="description" content="Every TinySesam sign-in flow as a diagram: password, PIN, TOTP,
 step-up, factor chains, shared secrets, magic links, OIDC/SAML and forward-auth.">
<link rel="icon" href="wizard.png">
<link rel="stylesheet" href="theme.css">
<style>
  *{box-sizing:border-box}
  body{margin:0;background:var(--paper);color:var(--ink);line-height:1.6;font-size:17px;
    font-family:var(--ts-font);-webkit-font-smoothing:antialiased}
  a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
  nav{max-width:820px;margin:0 auto;padding:16px 22px;display:flex;align-items:center;
    justify-content:space-between;gap:14px;border-bottom:1px solid var(--line)}
  nav .brand{display:flex;align-items:center;gap:10px;color:var(--ink)}
  nav .brand img{width:28px;height:28px}
  nav .brand span{font-weight:700;font-size:17px}
  nav .brand b{color:var(--accent)}
  nav .links{display:flex;gap:16px;font-size:14px}
  main{max-width:820px;margin:0 auto;padding:34px 22px 64px}
  h1{font-family:var(--ts-serif);font-weight:600;font-size:40px;letter-spacing:-.01em;
    margin:.1em 0 .12em;text-wrap:balance}
  .lead{color:var(--muted);font-size:18px;max-width:60ch;text-wrap:balance}
  code{font-family:var(--ts-mono);font-size:.86em;background:var(--chip);
    border:1px solid var(--line);border-radius:5px;padding:1px 5px}
  hr.rule{height:1px;background:var(--line);border:0;margin:40px 0}
  footer{max-width:820px;margin:0 auto;padding:24px 22px 60px;border-top:1px solid var(--line);
    color:var(--muted);font-size:14px;text-align:center}
  footer a{margin:0 9px}
__FLOWCSS__
</style>
</head>
<body>
<nav>
  <a class="brand" href="index.html"><img src="wizard.png" alt=""><span><b>Tiny</b>Sesam</span></a>
  <span class="links"><a href="index.html">Overview</a><b>Sign-in flows</b><a href="__REPO__">GitHub</a></span>
</nav>
<main>
  <h1>Sign-in flows</h1>
  <p class="lead">Every route in is its own switch, and they combine. The tag next to each heading is
    the config that turns it on — nothing here is mandatory, and the whole front end is replaceable.</p>
  <hr class="rule">
__FLOWS__
  <hr class="rule">
  <p class="lead">Curious how it feels? The showcase in
    <a href="__REPO__/blob/main/examples/showcase.py"><code>examples/showcase.py</code></a>
    renders these same diagrams — but marks what its own config actually has switched on.</p>
</main>
<footer>
  <a href="index.html">Overview</a>·
  <a href="__REPO__">GitHub</a>·
  <a href="__REPO__/blob/main/README.md">Docs</a>·
  <a href="__REPO__/blob/main/LICENSE">MIT License</a>
</footer>
</body>
</html>
"""


def main() -> int:
    out = ROOT / "docs" / "flows.html"
    html = (PAGE.replace("__FLOWCSS__", FLOW_CSS.strip())
                .replace("__FLOWS__", render("en", cfg=None))
                .replace("__REPO__", REPO))
    out.write_text(html, encoding="utf-8")
    print(f"{out.relative_to(ROOT)} geschrieben ({len(html)} Zeichen)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
