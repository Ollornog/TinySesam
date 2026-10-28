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

    Chrome picks its debug port itself (`--remote-debugging-port=0`) and writes it into the
    profile: a port reserved in advance is a race.
    """

    def __init__(self):
        self.profil = tempfile.mkdtemp()
        self.proc = subprocess.Popen(
            [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
             "--window-size=1280,900", f"--user-data-dir={self.profil}",
             "--remote-debugging-port=0", "about:blank"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.port = self._port()
        self._n = 0

    def _port(self):
        datei = os.path.join(self.profil, "DevToolsActivePort")
        ende = time.time() + 30
        while time.time() < ende:
            if self.proc.poll() is not None:
                raise RuntimeError("Chrome ist beim Start gestorben")
            try:
                with open(datei, encoding="utf-8") as fh:
                    erste = fh.readline().strip()
                if erste.isdigit():
                    return int(erste)
            except OSError:
                pass  # file is still missing or half written — next round
            time.sleep(0.1)
        raise RuntimeError("Chrome meldet keinen Debug-Port")

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
        shutil.rmtree(self.profil, ignore_errors=True)

    async def cmd(self, method, params=None, frist=60):
        """Send a DevTools command and wait for ITS response — with a deadline.

        Two things that would otherwise let a run hang forever (found in the stage test for
        0.20.0, 15 minutes without output): if the page opens a `confirm()` dialog — since B1-7 the
        account page asks after a factor change whether the other sessions should end —,
        Chrome answers no `Runtime.evaluate` until it is closed. The dialog
        is therefore rejected immediately here (the offer is not the subject of this test) and
        reported. And every response has a deadline; without it an error waits silently instead of loudly.
        """
        self._n += 1
        mein = self._n
        await self.ws.send(json.dumps({"id": mein, "method": method, "params": params or {}}))
        ende = time.time() + frist
        while True:
            rest = ende - time.time()
            if rest <= 0:
                raise RuntimeError(f"{method}: keine Antwort nach {frist} s")
            m = json.loads(await asyncio.wait_for(self.ws.recv(), rest))
            if m.get("method") == "Page.javascriptDialogOpening":
                print(f"    (Dialog abgelehnt: {m['params'].get('message', '')[:80]!r})")
                self._n += 1
                await self.ws.send(json.dumps({"id": self._n, "method": "Page.handleJavaScriptDialog",
                                               "params": {"accept": False}}))
                continue
            if m.get("id") == mein:
                if "error" in m:
                    raise RuntimeError(f"{method}: {m['error']}")
                return m.get("result", {})

    async def js(self, ausdruck):
        r = await self.cmd("Runtime.evaluate", {"expression": ausdruck, "returnByValue": True,
                                                "awaitPromise": True})
        return r["result"].get("value")

    async def geh(self, pfad, warte=3.0):
        await self.cmd("Page.navigate", {"url": pfad if "://" in pfad else BASE + pfad})
        await asyncio.sleep(warte)

    async def warte_bis(self, ausdruck, sekunden=20, was="Zustand"):
        """Wait for a state, not for the clock.

        Fixed waits make an E2E test moody: the machine is sometimes faster, the
        provider sometimes slower, and the test then goes red for a reason that has nothing to do with
        the code. The expression is evaluated in the browser until it is true.
        """
        ende = time.time() + sekunden
        while time.time() < ende:
            try:
                if await self.js(ausdruck):
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

    async def angemeldet_als(self, warte=0):
        """Username according to /auth/me, or None. Patient for `warte` seconds, if desired."""
        ende = time.time() + warte
        while True:
            roh = await self.js("fetch('/auth/me').then(r => r.json()).then(j => JSON.stringify(j))")
            d = json.loads(roh or "{}")
            if d.get("authenticated"):
                return d.get("username")
            if time.time() >= ende:
                return None
            await asyncio.sleep(0.5)

    async def fuelle(self, felder: dict, absenden: str = None):
        """Fill in and submit a form — waiting, not guessing.

        First wait until all fields are there (a page that is still building accepts no values),
        then `requestSubmit()`: that is the standards-compliant way, which triggers validation and
        `submit` handlers — a click on the button did that here sometimes, sometimes not, depending on
        how far along the page was. Afterwards wait until the page has actually changed.
        """
        for sel in felder:
            if not await self.warte_bis(f"!!document.querySelector({sel!r})", 15):
                raise RuntimeError(f"Feld {sel} erscheint nicht — falsche Seite?")
        setzen = "".join(
            f"document.querySelector({s!r}).value = {w!r};" for s, w in felder.items())
        wo = next(iter(felder))
        await self.js(f"(() => {{ {setzen} "
                      f"document.querySelector({wo!r}).form.requestSubmit(); return true; }})()")
        await self.warte_bis("document.readyState === 'complete'", 20)
        await asyncio.sleep(1.5)
        await self.pruefe_regulierung()

    async def pruefe_regulierung(self):
        """Report rate limit and lockout as such, not as "sign-in failed".

        Whoever runs this test several times in a row runs into their own brute-force brake —
        and an error message that then sounds like a wrong password sends the searcher in
        completely the wrong direction. (The same lesson as with the SAML finding: first the diagnosis, then
        the troubleshooting.)
        """
        text = (await self.js("document.body.innerText")) or ""
        for muster, was in (("too many", "Rate-Limit"), ("zu viele", "Rate-Limit"),
                            ("locked", "Konto-Lockout"), ("gesperrt", "Konto-Lockout")):
            if muster in text.lower():
                raise RuntimeError(
                    f"{was} der Instanz hat zugeschlagen — nicht die Anmeldung ist kaputt, "
                    f"sondern es kamen zu viele Versuche. Kurz warten und erneut fahren. "
                    f"Seite sagt: {text[:80].strip()!r}")


async def teil_passkey():
    """Passkey: register and then sign in passwordless — against the REAL rp_id.

    The virtual authenticator replaces the hardware, not the ceremony: origin, `rp_id` and
    certificate are those of the running instance. The built-in UI is operated, not
    self-built JS — otherwise the test would check its own code.
    """
    user = os.environ.get("STAGE_ADMIN_USER", "admin")
    pw = os.environ.get("STAGE_ADMIN_PW")
    if not pw:
        return "übersprungen (STAGE_ADMIN_PW fehlt)"
    async with Browser() as b:
        await b.cmd("WebAuthn.enable")
        auth_id = (await b.cmd("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}}))["authenticatorId"]

        await b.geh("/auth/login", 2)
        await b.fuelle({"[name=username]": user, "[name=password]": pw})
        assert await b.angemeldet_als(10) == user, "password login failed"

        await b.geh("/auth/account", 2)
        await b.js("document.querySelector('[data-act=addpk]').click(); true")
        await asyncio.sleep(4)
        await b.warte_bis("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length > 0)", 20)
        liste = await b.js("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length)")
        assert liste, "no passkey stored"
        assert (await b.cmd("WebAuthn.getCredentials", {"authenticatorId": auth_id}))["credentials"]
        ok(f"Passkey registered ({liste} on the account, 1 in the authenticator)")

        # Sign out like the built-in UI: POST with CSRF (since F-07; a GET only asks back
        # depending on origin).
        tok = await b.csrf()
        await b.js(f"fetch('/auth/logout', {{method: 'POST', headers: {{'X-CSRF-Token': {tok!r}}}}})"
                   ".then(r => r.status)")
        assert await b.angemeldet_als() is None, "sign-out via POST did not take effect"
        await b.geh("/auth/login", 2)
        await b.js("document.querySelector('#pkbtn').click(); true")
        assert await b.angemeldet_als(20) == user, "passkey login failed"
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
    return "grün"


async def teil_saml():
    """SAML: AuthnRequest → IdP login → signed assertion at the ACS → session."""
    user, pw = os.environ.get("STAGE_SAML_USER"), os.environ.get("STAGE_SAML_PW")
    if not (user and pw):
        return "übersprungen (STAGE_SAML_USER/_PW fehlen)"
    async with Browser() as b:
        await b.geh("/auth/saml/login", 4)
        wohin = await b.js("location.href")
        assert BASE not in wohin or "/idp" in wohin, f"no redirect to the IdP: {wohin}"
        ok("AuthnRequest: redirected to the IdP")

        await b.fuelle({"#username": user, "#password": pw})
        wer = await b.angemeldet_als(20)
        assert wer, "assertion was not accepted (the reason is in the instance log)"
        ok(f"Assertion accepted, signed in as {wer}")
    return "grün"


async def teil_oidc():
    """OIDC: authorization code flow against the real provider.

    The provider signs in passwordless (passkey), so the virtual authenticator gets a
    previously exported credential injected (`STAGE_OIDC_CRED`). Register once by hand,
    then automatically as often as you like — without a secret ending up in the repo.
    """
    cred_datei = os.environ.get("STAGE_OIDC_CRED")
    if not cred_datei or not os.path.exists(cred_datei):
        return "übersprungen (STAGE_OIDC_CRED fehlt)"
    with open(cred_datei, encoding="utf-8") as fh:
        cred = json.load(fh)
    async with Browser() as b:
        await b.cmd("WebAuthn.enable")
        auth_id = (await b.cmd("WebAuthn.addVirtualAuthenticator", {"options": {
            "protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
            "hasUserVerification": True, "isUserVerified": True,
            "automaticPresenceSimulation": True}}))["authenticatorId"]
        await b.cmd("WebAuthn.addCredential", {"authenticatorId": auth_id, "credential": cred})

        await b.geh("/auth/oidc/start", 4)
        wohin = await b.js("location.origin")
        assert BASE not in wohin, f"no redirect to the provider: {wohin}"
        ok("Authorization request: redirected to the provider")

        # The provider leads through several steps: first sign in (the passkey comes from the
        # injected credential), then agree to the approval. How many pages that is depends
        # on the provider and on whether it already knows the consent — so we keep clicking
        # as long as we are still at it, instead of assuming a fixed number of steps.
        for _ in range(4):
            if BASE.startswith(await b.js("location.origin") or "x"):
                break
            geklickt = await b.js("""(() => {
                const b = [...document.querySelectorAll('button')].find(e =>
                    /anmelden|sign in|authorize|autorisieren|zustimmen|erlauben|allow|continue|weiter|akzeptieren/i
                        .test(e.innerText) && !/abbrechen|cancel|deny|ablehnen/i.test(e.innerText));
                if (!b) return null; b.click(); return b.innerText.trim(); })()""")
            if not geklickt:
                break
            ok(f"confirmed at the provider: {geklickt!r}")
            await asyncio.sleep(4)
        wer = await b.angemeldet_als(25)
        assert wer, ("no access token redeemed — last page: "
                     + ((await b.js("document.body.innerText")) or "")[:120].replace(chr(10), " | "))
        ok(f"Code redeemed, signed in as {wer}")
    return "grün"


TEILE = {"passkey": teil_passkey, "saml": teil_saml, "oidc": teil_oidc}


async def main(namen):
    if not BASE:
        sys.exit("STAGE_BASE_URL fehlt — dieser Test läuft gegen eine ausgerollte Instanz.")
    if not CHROME:
        sys.exit("kein Chrome gefunden")
    print(f"E2E gegen {BASE}")
    ergebnis, rot = {}, False
    for name in namen:
        print(f"\n▸ {name}")
        try:
            ergebnis[name] = await TEILE[name]()
        except Exception as e:
            ergebnis[name] = f"ROT: {e}"
            rot = True
        if ergebnis[name].startswith("über"):
            print(f"  – {ergebnis[name]}")
        elif ergebnis[name].startswith("ROT"):
            print(f"  ✗ {ergebnis[name]}")
    print("\n" + " · ".join(f"{k}: {v.split(':')[0]}" for k, v in ergebnis.items()))
    sys.exit(1 if rot else 0)


if __name__ == "__main__":
    gewaehlt = [a for a in sys.argv[1:] if a in TEILE] or list(TEILE)
    asyncio.run(main(gewaehlt))
