"""C22 adapter (tinysesam/c22.css, `c22_stylesheet`): TinySesam's pages in the look of a C22 app.

Checked here:
* complete — every --ts-* token of theme.TOKENS has exactly one entry, and none that TOKENS lacks;
* fallback — each entry reads `var(<C22 token or helper>, <TinySesam default>)` with the default of TOKENS,
  so without C22 on the page nothing changes (measured in a real browser, too);
* names — every C22 token the adapter reads is in the pinned list tests/fixtures/c22_tokens.txt
  (refreshed with tools/c22_tokens.py; nothing here reads the C22 repository);
* wiring — `c22_stylesheet` puts the adapter between TOKENS and brand_css, the stylesheet and the
  light/dark restore carry the nonce, the CSP stays strict, a foreign address is refused.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam.errors import ConfigError  # noqa: E402
from tinysesam.theme import C22_ADAPTER, TOKENS  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))


def ok(name):
    print(f"  ✓ {name}")


def declarations(css: str) -> dict:
    """`--name: value` pairs of the `:root{…}` block, comments removed, whitespace normalised."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    block = re.search(r":root\s*\{(.*?)\}", css, re.S).group(1)
    out = {}
    for decl in block.split(";"):
        if ":" in decl:
            name, value = decl.split(":", 1)
            name = name.strip()
            if name.startswith("--"):
                assert name not in out, f"{name} defined twice"
                out[name] = re.sub(r"\s+", " ", value.strip())
    return out


def split_var(value: str):
    """`var(--x, fallback)` → ("--x", "fallback"); anything else → None."""
    m = re.fullmatch(r"var\(\s*(--[A-Za-z0-9_-]+)\s*(?:,\s*(.*))?\)", value)
    return (m.group(1), m.group(2)) if m else None


def nows(s):
    return re.sub(r"\s+", "", s or "")


tokens = declarations(TOKENS)
adapter = declarations(C22_ADAPTER)
helpers = {n: v for n, v in adapter.items() if n.startswith("--ts-c22-")}
entries = {n: v for n, v in adapter.items() if not n.startswith("--ts-c22-")}
with open(os.path.join(HERE, "fixtures", "c22_tokens.txt"), encoding="utf-8") as f:
    fixture = f.read()
c22_names = {line.strip() for line in fixture.splitlines() if line.strip() and not line.startswith("#")}
assert re.search(r"^# C22 commit: [0-9a-f]{40}$", fixture, re.M), "fixture names no C22 commit"

# --- complete -------------------------------------------------------------------------------------
missing = sorted(set(tokens) - set(entries))
assert not missing, f"adapter has no entry for {missing}"
stale = sorted(set(entries) - set(tokens))
assert not stale, f"adapter maps tokens TOKENS does not have: {stale}"
ok(f"every one of the {len(tokens)} --ts-* tokens has an entry, none extra")

# --- fallback = TinySesam's default ---------------------------------------------------------------
literal = []
for name, value in entries.items():
    parts = split_var(value)
    if parts is None:
        # No C22 counterpart: the entry repeats the default literally.
        assert nows(value) == nows(tokens[name]), f"{name}: {value!r} is neither var(…) nor the default"
        literal.append(name)
        continue
    source, fallback = parts
    assert fallback is not None, f"{name}: {value!r} has no fallback — without C22 it would be empty"
    assert nows(fallback) == nows(tokens[name]), \
        f"{name}: fallback {fallback!r} ≠ TinySesam default {tokens[name]!r}"
    if source.startswith("--ts-c22-"):
        assert source in helpers, f"{name}: helper {source} is not defined"
    else:
        assert source in c22_names, f"{name}: {source} is no C22 token (tests/fixtures/c22_tokens.txt)"
ok(f"every entry falls back to TinySesam's own default ({len(literal)} without C22 counterpart: "
   f"{', '.join(sorted(literal))})")

# Helpers read only C22 tokens and never with a fallback: only then do they turn invalid without C22,
# and the entry reading them takes TinySesam's default.
for name, value in helpers.items():
    refs = re.findall(r"var\(\s*(--[A-Za-z0-9_-]+)\s*(,)?", value)
    assert refs, f"{name}: reads no C22 token"
    for ref, comma in refs:
        assert ref in c22_names, f"{name}: {ref} is no C22 token (tests/fixtures/c22_tokens.txt)"
        assert not comma, f"{name}: var({ref}, …) has a fallback — without C22 it would not drop out"
    assert name in {split_var(v)[0] for v in entries.values() if split_var(v)}, f"{name} is read by nothing"
ok(f"{len(helpers)} helpers read only listed C22 tokens, without a fallback, and each is used")


# --- wiring ---------------------------------------------------------------------------------------
def auth_with(**kw):
    return TinySesam(TinySesamConfig(csrf_enabled=False, passkey_enabled=False,
                                     db_path=os.path.join(tempfile.mkdtemp(), "t.db"), **kw))


plain = auth_with(brand_css=":root{--ts-accent:#123456}")
page = plain.render_page("login", next="/").body.decode()
assert "--ts-c22-" not in page and "rel=stylesheet" not in page and "themeMode" not in page
ok("without c22_stylesheet: no adapter, no stylesheet, no script for it")

c22 = auth_with(c22_stylesheet="/static/c22-vega.css", brand_css=":root{--ts-accent:#123456}")
resp = c22.render_page("login", next="/")
page = resp.body.decode()
nonce = re.search(r"nonce=\"([^\"]+)\"", page).group(1)
assert f'<link nonce="{nonce}" rel=stylesheet href="/static/c22-vega.css">' in page, page[:2000]
assert page.index("--ts-bg:#0f1115") < page.index("--ts-bg:var(--background") < page.index("--ts-accent:#123456"), \
    "order must be TOKENS → adapter → brand_css (the app's own overrides still win)"
assert re.search(rf'<script nonce="{nonce}">\(function\(\)\{{var m=null;try\{{m=localStorage.getItem\(\'themeMode\'\)',
                 page), "light/dark restore missing or without nonce"
csp = resp.headers["content-security-policy"]
assert f"style-src 'nonce-{nonce}';" in csp and "'self'" not in csp.split("style-src")[1].split(";")[0], csp
assert ".tsadmin .tabs{flex-direction:row}" in page and ".tsmain a{text-decoration:underline}" in page, \
    "layout repairs against C22's global .card/.tabs rules and its link reset are missing"
ok("with c22_stylesheet: TOKENS → adapter → brand_css; stylesheet + restore carry the nonce; CSP unchanged")

from tinysesam.admin import render_panel  # noqa: E402  (the one place that fills the panel)
panel = render_panel(c22, "/auth/admin/api")
assert 'rel=stylesheet href="/static/c22-vega.css"' in panel and "themeMode" in panel
assert panel.index("--ts-bg:#0f1115") < panel.index("--ts-bg:var(--background") < panel.index("--ts-accent:#123456")
ok("admin panel: the same stylesheet and restore, TOKENS → adapter → brand_css")

for bad in ("https://cdn.example.com/c22.css", "//cdn.example.com/c22.css", "c22.css", '/a"b.css', "/a b.css"):
    try:
        auth_with(c22_stylesheet=bad)
    except ConfigError as e:
        assert "c22_stylesheet" in str(e), e
    else:
        raise AssertionError(f"c22_stylesheet={bad!r} accepted")
ok("foreign addresses and attribute breakouts are refused")


# --- in a real browser: without C22 nothing changes, with C22 the tokens follow --------------------
CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser") if shutil.which(b)), None)
if CHROME is None:
    print("  – browser part skipped: no Chrome (the CI has one)")
else:
    probe = ("<script>const s=getComputedStyle(document.documentElement);document.body.textContent="
             f"JSON.stringify({sorted(tokens)}.map(n=>[n,s.getPropertyValue(n).trim()]))</script>")
    fake_c22 = (":root{" + "".join(f"{n}:rgb(1,2,3);" for n in sorted(c22_names) if n not in
                                  ("--radius", "--font-sans", "--font-mono"))
                + "--radius:3px;--font-sans:Probe;--font-mono:ProbeMono}")

    def computed(css):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "p.html")
        with open(p, "w", encoding="utf-8") as f:
            f.write(f"<!doctype html><html><head><style>{css}</style></head><body>{probe}</body></html>")
        out = subprocess.run([CHROME, "--headless", "--no-sandbox", "--disable-gpu", f"--user-data-dir={d}/u",
                              "--dump-dom", "file://" + p], capture_output=True, text=True, timeout=60).stdout
        import html as _h
        import json
        return dict(json.loads(_h.unescape(re.search(r"<body>(.*)</body>", out, re.S).group(1))))

    base = computed(TOKENS)
    with_adapter = computed(TOKENS + C22_ADAPTER)
    differ = {n: (base[n], with_adapter[n]) for n in base if base[n] != with_adapter[n]}
    assert not differ, f"the adapter without C22 changes: {differ}"
    assert all(base.values()), [n for n, v in base.items() if not v]
    ok("browser: adapter without C22 on the page → every --ts-* computes exactly as without it")

    themed = computed(fake_c22 + TOKENS + C22_ADAPTER)
    unmoved = sorted(n for n in entries if split_var(entries[n]) and themed[n] == base[n])
    assert not unmoved, f"these do not follow C22: {unmoved}"
    assert themed["--ts-radius"] == "3px" and themed["--ts-bg"] == "rgb(1,2,3)", themed
    ok("browser: with C22 tokens on the page every mapped --ts-* follows them")

print("C22 adapter OK")
