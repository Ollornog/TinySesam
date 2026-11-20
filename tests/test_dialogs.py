"""Own dialogs instead of the browser's system dialogs (T-35).

Wish (PO 2026-11-20): a new API key used to appear in the browser's `prompt` box — unstyled, blocking the tab, without
a copy button. Every built-in page now uses one building block (`tinysesam/dialog.py`). This suite measures the
structure; what the person experiences (keyboard, focus, clipboard, CSP) is measured in `tests/test_browser.py`.

1. **No system dialog left** — no call of `alert`, `confirm` or `prompt` in the Python and JavaScript sources of the
   package, the website and the examples (a self-test proves the scanner finds each spelling and passes the own ones).
2. **The pages that ask carry the building block** — account page, login with passkey, TOTP setup, admin panel —
   once, under the response's nonce, and an own template gets it as `ctx["dialog"]`.
3. **Tokens only, no markup from data** — the dialog CSS names no colour of its own, the script builds no HTML string.
4. **de + en** — every dialog text exists in both languages and is not the English one in the German table.
"""
import os
import pathlib
import re
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import dialog  # noqa: E402
from tinysesam.admin import render_panel  # noqa: E402
from tinysesam.messages import MESSAGES  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent


def ok(name):
    print(f"  ✓ {name}")


# ---------- 1) No system dialog left ----------
# A call is the bare name (or `window.` in front of it) followed by `(`. A method of some other object
# (`auth.totp_confirm(`, `x.confirm(`) and the own functions (`tsConfirm(`) are not one.
# Directly followed by `(`: prose such as "confirm (with a factor)" in a docstring is no call.
_CALL = re.compile(r"(?<![\w$.])(alert|confirm|prompt)\(|\bwindow\s*\.\s*(alert|confirm|prompt)\b")


def system_dialogs(text: str) -> list:
    """Every line with a system dialog call: `[(line number, line), …]`."""
    return [(n, line.strip()) for n, line in enumerate(text.splitlines(), 1) if _CALL.search(line)]


# Self-test: each spelling is found, the own ones and foreign methods are not.
for found in ("if(!confirm(x))return;", "alert(r.detail)", "const v=prompt(L.pw)", "window.confirm(x)",
              "window.alert = m => m", "await window . prompt ('x')", "x=>alert(1)", "{alert(1)}"):
    assert system_dialogs(found), f"scanner misses: {found!r}"
for passed in ("await tsConfirm(x)", "tsAlert(r.detail)", "tsPrompt(L.pw)", "auth.totp_confirm(uid, c)",
               "self.confirm(x)", "def confirm_link(x):", "the browser's alert box", "confirm (`stepup_options()` empty", "tsSecret(t, v, n)"):
    assert not system_dialogs(passed), f"scanner false alarm: {passed!r}"

_sources = [p for d in ("tinysesam", "web", "examples") for p in sorted((ROOT / d).rglob("*"))
            if p.suffix in (".py", ".js", ".html") and "__pycache__" not in p.parts]
assert len(_sources) >= 20 and ROOT / "tinysesam" / "admin.py" in _sources, len(_sources)
_left = {str(p.relative_to(ROOT)): hits for p in _sources
         if (hits := system_dialogs(p.read_text(encoding="utf-8")))}
assert not _left, f"system dialogs left: {_left}"
ok(f"no alert/confirm/prompt call in {len(_sources)} sources (scanner self-test: 8 found, 9 passed)")

# ---------- 2) The pages that ask carry the building block ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, csrf_enabled=False, cookie_secure=False, apikey_enabled=True,
                                 passkey_enabled=False, totp_enabled=True, lang="en"))
# The passkey button (and its script) only needs the switch to render — not the `[passkey]` extra, which the narrow
# CI run (core only) lacks. Switched on after construction, which would import `webauthn`.
auth.cfg.passkey_enabled = True
_MARK = "window.tsSecret="


def _check(name, resp_or_html, nonce=None):
    body = resp_or_html if isinstance(resp_or_html, str) else resp_or_html.body.decode()
    assert body.count(_MARK) == 1, f"{name}: dialog building block {body.count(_MARK)}× (expected once)"
    assert "dialog.tsdlg{" in body, f"{name}: dialog CSS missing"
    if nonce:
        block = re.search(r"<script([^>]*)>(?:(?!</script>).)*" + re.escape(_MARK), body, re.S)
        assert block and f'nonce="{nonce}"' in block.group(1), f"{name}: dialog script without the nonce"
    return body


def _nonce(resp):
    m = re.search(r"'nonce-([\w-]+)'", resp.headers.get("content-security-policy", ""))
    return m.group(1) if m else None


_user = {"username": "u", "display_name": "U", "id": 1}
pages = {
    "account": auth.render_page("account", request=None, user=_user, methods=["password", "passkey"],
                                has_totp=True, recovery_left=5),
    "login (passkey)": auth.render_page("login", request=None, next="/"),
    "totp_setup": auth.render_page("totp_setup", request=None,
                                   data={"secret": "JBSWY3DPEHPK3PXP", "uri": "otpauth://x", "qr": ""}),
}
for name, resp in pages.items():
    _check(name, resp, _nonce(resp))
_acc = pages["account"].body.decode()
assert "tsSecret(TXT.key_title,r.key,TXT.key_note)" in _acc, "account: new API key not in the secret dialog"
assert "tsSecret(TXT.recovery_title" in _acc, "account: recovery codes not in the secret dialog"
assert "id=rc_out" not in _acc, "account: the recovery codes must not stay on the page"
_setup = pages["totp_setup"].body.decode()
assert "id=rccopy" in _setup and "tsCopy(" in _setup, "TOTP setup: no copy button for the recovery codes"
# A page without a question carries nothing extra.
_plain = auth.render_page("error", request=None, code=404, message="x").body.decode()
assert _MARK not in _plain, "error page: dialog building block without a use"
ok("account, login (passkey), TOTP setup: building block once, under the nonce; API key + recovery codes in tsSecret")

_panel = _check("admin panel", render_panel(auth, "/auth/admin"))
assert _panel.index(_MARK) < _panel.index("const ACT={"), "panel: dialogs must be defined before the panel script"
assert "tsSecret(L.key_new,r.key,L.key_once)" in _panel, "panel: new API key not in the secret dialog"
assert 'on("copylink",id)' in _panel and "copylink}" in _panel, "panel: sign-in link without copy button"
ok("admin panel: building block before the panel script, API key in tsSecret, sign-in link with copy button")

# An own template gets the building block as ctx["dialog"] — and the nonce covers it like every other block.
auth.set_template("register", lambda a, ctx: f"<!doctype html><title>x</title>{ctx['dialog']}<p>own</p>")
_own = auth.render_page("register", request=None)
_check("own template", _own, _nonce(_own))
ok('own template: ctx["dialog"] holds the building block, render_page gives it the nonce')

# ---------- 3) Tokens only, no markup from data ----------
_colour = re.compile(r"#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(|(?<![\w-])(?:white|black|red|green|blue)(?![\w-])")
assert not _colour.search(dialog.CSS), f"dialog CSS with an own colour: {_colour.search(dialog.CSS).group(0)}"
assert dialog.CSS.count("var(--ts-") >= 12, "dialog CSS does not style through the tokens"
assert not re.search(r"(?m)^\s*(?:[a-z]+|\*)\s*[{,]", dialog.CSS), "dialog CSS with a bare selector (bleeds out)"
for forbidden in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "localStorage",
                  "sessionStorage", "console.", "location", "onclick", "eval("):
    assert forbidden not in dialog._JS, f"dialog script uses {forbidden!r}"
ok("dialog CSS: tokens only, scoped to dialog.tsdlg; script: no HTML strings, no storage, no URL, no log")

# ---------- 4) de + en ----------
for key in dialog.KEYS:
    en, de = MESSAGES["en"].get(key), MESSAGES["de"].get(key)
    assert en and de, f"{key}: missing in {'en' if not en else 'de'}"
    assert key == "dlg.ok" or en != de, f"{key}: the German table carries the English text"
auth.cfg.lang = "de"
_de = render_panel(auth, "/auth/admin")
assert '"dlg.copy": "Kopieren"' in _de and '"copy": "Kopieren"' in _de, "panel (de): copy texts not German"
ok(f"{len(dialog.KEYS)} dialog texts in en + de; the panel speaks German with lang=de")

# The panel answers over HTTP with the building block under its nonce too.
auth.cfg.lang = "en"
auth.ensure_admin("admin", "admin-pw-12345")
app = FastAPI()
app.include_router(auth.router())
c = TestClient(app)
c.post("/auth/login", data={"username": "admin", "password": "admin-pw-12345"})
_r = c.get("/auth/admin")
assert _r.status_code == 200, _r.status_code
_check("admin panel (HTTP)", _r.text, _nonce(_r))
ok("admin panel over HTTP: dialog script under the response's nonce")

os.remove(db)
print("OK test_dialogs")
