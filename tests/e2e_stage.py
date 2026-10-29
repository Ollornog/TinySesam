"""End-to-end against a REAL instance: OIDC, SAML and passkey in a real browser.

Not a CI test and deliberately **not** `test_*.py`: `run_all.py` collects by glob and would
otherwise pick it up. CI has no domain, no certificate and no identity provider — a test that
rebuilds them checks the dummy, not the ceremony (see `backlog/T-1-e2e-against-real-idp.md`).
Meant as a **smoke test after the deploy** against a rolled-out stage.

Everything environment-specific comes from the ENVIRONMENT — addresses and credentials do not belong
in a public repo:

    STAGE_BASE_URL          https://<stage>            (required)
    STAGE_ADMIN_USER/_PW    local account for the passkey part
    STAGE_SAML_USER/_PW     account in the SAML IdP
    STAGE_OIDC_CRED         file with an exported WebAuthn credential of the IdP account
                            (JSON from WebAuthn.getCredentials) — the IdP signs in passwordless

    python tests/e2e_stage.py            # everything that is configured
    python tests/e2e_stage.py saml       # only one part

Every part whose variables are missing is **skipped** and reported as such — never silently
as passed. Exit 0 = everything checked green, 1 = a part red.
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

BASE = (os.environ.get("STAGE_BASE_URL") or "").rstrip("/")
CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser")
               if shutil.which(b)), None)


def ok(name):
    print(f"  ✓ {name}")


class Browser:
    """Headless Chrome over the DevTools protocol — the same mechanism as test_browser.py.

    Chrome picks its debug port itself (`--remote-debugging-pplace=0`) and writes it into the
    profile: a port reserved in advance is a race.
    """

    def __init__(self):
        self.profile = tempfile.mkdtemp()
        self.proc = subprocess.Popen(
            [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
             "--window-size=1280,900", f"--user-data-dir={self.profile}",
             "--remote-debugging-port=0", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = self._port()
        self._n = 0

    def _port(self):
        file = os.path.join(self.profile, "DevToolsActivePort")
        end = time.time() + 30
        while time.time() < end:
            if self.proc.poll() is not None:
                raise RuntimeError("Chrome died at startup")
            try:
                with open(file, encoding="utf-8") as fh:
                    first = fh.readline().strip()
                if first.isdigit():
                    return int(first)
            except OSError:
                pass  # file is still missing or half written — next round
            time.sleep(0.1)
        raise RuntimeError("Chrome reports no debug port")

    async def __aenter__(self):
        import websockets
        tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json"))
        url = next(t["webSocketDebuggerUrl"] for t in tabs if t["type"] == "page")
        self.ws = await websockets.connect(url, max_size=None)
        await self.cmd("Page.enable")
        await self.cmd("Runtime.enable")
        return self

    async def __aexit__(self, *_):
        await self.ws.close()
        self.proc.terminate()
        shutil.rmtree(self.profile, ignore_errors=True)

    async def cmd(self, method, params=None, deadline=60):
        """Send a DevTools command and wait for ITS response — with a deadline.

        Two things that would otherwise let a run hang forever (found in the stage test for
        0.20.0, 15 minutes without output): if the page opens a `confirm()` dialog — since B1-7 the
        account page asks after a factor change whether the other sessions should end —,
        Chrome answers no `Runtime.evaluate` until it is closed. The dialog
        is therefore rejected immediately here (the offer is not the subject of this test) and
        reported. And every response has a deadline; without it an error waits silently instead of loudly.
        """
        self._n += 1
        my = self._n
        await self.ws.send(json.dumps({"id": my, "method": method, "params": params or {}}))
        end = time.time() + deadline
        while True:
            rest = end - time.time()
            if rest <= 0:
                raise RuntimeError(f"{method}: no response after {deadline} s")
            m = json.loads(await asyncio.wait_for(self.ws.recv(), rest))
            if m.get("method") == "Page.javascriptDialogOpening":
                print(f"    (Dialog abgelehnt: {m['params'].get('message', '')[:80]!r})")
                self._n += 1
                await self.ws.send(json.dumps({"id": self._n, "method": "Page.handleJavaScriptDialog",
                                               "params": {"accept": False}}))
                continue
            if m.get("id") == my:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})

    async def js(self, expression):
        r = await self.cmd("Runtime.evaluate", {"expression": expression, "returnByValue": True,
                                                "awaitPromise": True})
        return r["result"].get("value")

    async def go(self, path, wait=3.0):
        await self.cmd("Page.navigate", {"url": path if "://" in path else BASE + path})
        await asyncio.sleep(wait)

    async def wait_until(self, expression, seconds=20, was="Zustand"):
        """Wait for a state, not for the clock.

        Fixed waits make an E2E test moody: the machine is sometimes faster, the
        provider sometimes slower, and the test then goes red for a reason that has nothing to do with
        the code. The expression is evaluated in the browser until it is true.
        """
        end = time.time() + seconds
        while time.time() < end:
            try:
                if await self.js(expression):
                    return True
            except RuntimeError:
                pass          # during a navigation the context is briefly gone
            await asyncio.sleep(0.4)
        return False

    async def csrf(self):
        """The CSRF token from the cookie — regardless of which page we are currently on.

        The built-in helper `tsCsrf()` exists only on TinySesam's own pages; on a page
        of the application it is missing. The double-submit cookie is deliberately not HttpOnly, precisely so
        that own scripts can read it. Over HTTPS it has been called `__Host-tinysesam_csrf` since H-1.
        """
        return await self.js(
            "(document.cookie.split('; ').find(c => c.startsWith('__Host-tinysesam_csrf=')"
            " || c.startsWith('tinysesam_csrf=')) || '')"
            ".split('=')[1] || ''")

    async def signed_in_as(self, wait=0):
        """Username according to /auth/me, or None. Patient for `wait` seconds, if desired."""
        end = time.time() + wait
        while True:
            raw = await self.js("fetch('/auth/me').then(r => r.json()).then(j => JSON.stringify(j))")
            d = json.loads(raw or "{}")
            if d.get("authenticated"):
                return d.get("username")
            if time.time() >= end:
                return None
            await asyncio.sleep(0.5)

    async def fill(self, fields: dict, submit: str = None):
        """Fill in and submit a form — waiting, not guessing.

        First wait until all fields are there (a page that is still building accepts no values),
        then `requestSubmit()`: that is the standards-compliant way, which triggers validation and
        `submit` handlers — a click on the button did that here sometimes, sometimes not, depending on
        how far along the page was. Afterwards wait until the page has actually changed.
        """
        for sel in fields:
            if not await self.wait_until(f"!!document.querySelector({sel!r})", 15):
                raise RuntimeError(f"Field {sel} does not appear — wrong page?")
        set_value = "".join(
            f"document.querySelector({s!r}).value = {w!r};" for s, w in fields.items())
        where = next(iter(fields))
        await self.js(f"(() => {{ {set_value} "
                      f"document.querySelector({where!r}).form.requestSubmit(); return true; }})()")
        await self.wait_until("document.readyState === 'complete'", 20)
        await asyncio.sleep(1.5)
        await self.check_regulation()

    async def check_regulation(self):
        """Report rate limit and lockout as such, not as "sign-in failed".

        Whoever runs this test several times in a row runs into their own brute-force brake —
        and an error message that then sounds like a wrong password sends the searcher in
        completely the wrong direction. (The same lesson as with the SAML finding: first the diagnosis, then
        the troubleshooting.)
        """
        text = (await self.js("document.body.innerText")) or ""
        for pattern, was in (("too many", "rate limit"), ("zu viele", "rate limit"),
                            ("locked", "account lockout"), ("gesperrt", "account lockout")):
            if pattern in text.lower():
                raise RuntimeError(
                    f"The instance's {was} kicked in — sign-in is not broken, "
                    f"there were just too many attempts. Wait briefly and run again. "
                    f"Page says: {text[:80].strip()!r}")


async def part_passkey():
    """Passkey: register and then sign in passwordless — against the REAL rp_id.

    The virtual authenticator replaces the hardware, not the ceremony: origin, `rp_id` and
    certificate are those of the running instance. The built-in UI is operated, not
    self-built JS — otherwise the test would check its own code.
    """
    user = os.environ.get("STAGE_ADMIN_USER", "admin")
    pw = os.environ.get("STAGE_ADMIN_PW")
    if not pw:
        return "skipped (STAGE_ADMIN_PW missing)"
    async with Browser() as b:
        await b.cmd("WebAuthn.enable")
        auth_id = (await b.cmd("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}}))["authenticatorId"]

        await b.go("/auth/login", 2)
        await b.fill({"[name=username]": user, "[name=password]": pw})
        assert await b.signed_in_as(10) == user, "password login failed"

        await b.go("/auth/account", 2)
        await b.js("document.querySelector('[data-act=addpk]').click(); true")
        await asyncio.sleep(4)
        await b.wait_until("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length > 0)", 20)
        items = await b.js("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length)")
        assert items, "no passkey stored"
        assert (await b.cmd("WebAuthn.getCredentials", {"authenticatorId": auth_id}))["credentials"]
        ok(f"Passkey registered ({items} on the account, 1 in the authenticator)")

        # Sign out like the built-in UI: POST with CSRF (since F-07; a GET only asks back
        # depending on origin).
        tok = await b.csrf()
        await b.js(f"fetch('/auth/logout', {{method: 'POST', headers: {{'X-CSRF-Token': {tok!r}}}}})"
                   ".then(r => r.status)")
        assert await b.signed_in_as() is None, "sign-out via POST did not take effect"
        await b.go("/auth/login", 2)
        await b.js("document.querySelector('#pkbtn').click(); true")
        assert await b.signed_in_as(20) == user, "passkey login failed"
        ok("signed in passwordless (WebAuthn against the real rp_id)")

        # Remove the created passkey again: one run must not influence the next,
        # otherwise the account accumulates another key on every pass.
        tok = await b.csrf()
        await b.js(f"""(async () => {{
            const ps = await (await fetch('/auth/passkey/list')).json();
            for (const p of ps) {{
                await fetch('/auth/passkey/delete', {{method: 'POST',
                    headers: {{'Content-Type': 'application/json', 'X-CSRF-Token': {tok!r}}},
                    body: JSON.stringify({{id: p.id}})}});
            }}
            return true; }})()""")
        rest = await b.js("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length)")
        assert rest == 0, f"cleanup incomplete ({rest} passkeys remain)"
        ok("cleaned up: account without passkey, the next run starts the same")
    return "green"


async def part_saml():
    """SAML: AuthnRequest → IdP login → signed assertion at the ACS → session."""
    user, pw = os.environ.get("STAGE_SAML_USER"), os.environ.get("STAGE_SAML_PW")
    if not (user and pw):
        return "skipped (STAGE_SAML_USER/_PW missing)"
    async with Browser() as b:
        await b.go("/auth/saml/login", 4)
        where_to = await b.js("location.href")
        assert BASE not in where_to or "/idp" in where_to, f"no redirect to the IdP: {where_to}"
        ok("AuthnRequest: redirected to the IdP")

        await b.fill({"#username": user, "#password": pw})
        person = await b.signed_in_as(20)
        assert person, "assertion was not accepted (the reason is in the instance log)"
        ok(f"Assertion accepted, signed in as {person}")
    return "green"


async def part_oidc():
    """OIDC: authorization code flow against the real provider.

    The provider signs in passwordless (passkey), so the virtual authenticator gets a
    previously exported credential injected (`STAGE_OIDC_CRED`). Register once by hand,
    then automatically as often as you like — without a secret ending up in the repo.
    """
    cred_file = os.environ.get("STAGE_OIDC_CRED")
    if not cred_file or not os.path.exists(cred_file):
        return "skipped (STAGE_OIDC_CRED missing)"
    with open(cred_file, encoding="utf-8") as fh:
        cred = json.load(fh)
    async with Browser() as b:
        await b.cmd("WebAuthn.enable")
        auth_id = (await b.cmd("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}}))["authenticatorId"]
        await b.cmd("WebAuthn.addCredential", {"authenticatorId": auth_id, "credential": cred})

        await b.go("/auth/oidc/start", 4)
        where_to = await b.js("location.origin")
        assert BASE not in where_to, f"no redirect to the provider: {where_to}"
        ok("Authorization request: redirected to the provider")

        # The provider leads through several steps: first sign in (the passkey comes from the
        # injected credential), then agree to the approval. How many pages that is depends
        # on the provider and on whether it already knows the consent — so we keep clicking
        # as long as we are still at it, instead of assuming a fixed number of steps.
        for _ in range(4):
            if BASE.startswith(await b.js("location.origin") or "x"):
                break
            clicked = await b.js("""(() => {
                const b = [...document.querySelectorAll('button')].find(e =>
                    /anmelden|sign in|authorize|autorisieren|zustimmen|erlauben|allow|continue|weiter|akzeptieren/i
                        .test(e.innerText) && !/abbrechen|cancel|deny|ablehnen/i.test(e.innerText));
                if (!b) return null; b.click(); return b.innerText.trim(); })()""")
            if not clicked:
                break
            ok(f"confirmed at the provider: {clicked!r}")
            await asyncio.sleep(4)
        person = await b.signed_in_as(25)
        assert person, ("no access token redeemed — last page: "
                     + ((await b.js("document.body.innerText")) or "")[:120].replace(chr(10), " | "))
        ok(f"Code redeemed, signed in as {person}")
    return "green"


PARTS = {"passkey": part_passkey, "saml": part_saml, "oidc": part_oidc}


async def main(names):
    if not BASE:
        sys.exit("STAGE_BASE_URL missing — this test runs against a deployed instance.")
    if not CHROME:
        sys.exit("kein Chrome gefunden")
    print(f"E2E gegen {BASE}")
    result, red = {}, False
    for name in names:
        print(f"\n▸ {name}")
        try:
            result[name] = await PARTS[name]()
        except Exception as e:
            result[name] = f"ROT: {e}"
            red = True
        if result[name].startswith("skipped"):
            print(f"  – {result[name]}")
        elif result[name].startswith("ROT"):
            print(f"  ✗ {result[name]}")
    print("\n" + " · ".join(f"{k}: {v.split(':')[0]}" for k, v in result.items()))
    sys.exit(1 if red else 0)


if __name__ == "__main__":
    chosen = [a for a in sys.argv[1:] if a in PARTS] or list(PARTS)
    asyncio.run(main(chosen))
