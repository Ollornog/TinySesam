"""End-to-End gegen eine ECHTE Instanz: OIDC, SAML und Passkey im echten Browser.

Kein CI-Test und bewusst **nicht** `test_*.py`: `run_all.py` sammelt per Glob und würde ihn sonst
einsammeln. Die CI hat keine Domain, kein Zertifikat und keinen Identity Provider — ein Test, der
das nachbaut, prüft die Attrappe, nicht die Ceremony (siehe `backlog/T-1-e2e-gegen-echten-idp.md`).
Gedacht als **Smoke-Test nach dem Deploy** gegen eine ausgerollte Stage.

Alles Umgebungsspezifische kommt aus der UMGEBUNG — Adressen und Zugangsdaten gehören nicht in ein
öffentliches Repo:

    STAGE_BASE_URL          https://<stage>            (Pflicht)
    STAGE_ADMIN_USER/_PW    lokales Konto für den Passkey-Teil
    STAGE_SAML_USER/_PW     Konto im SAML-IdP
    STAGE_OIDC_CRED         Datei mit einem exportierten WebAuthn-Credential des IdP-Kontos
                            (JSON aus WebAuthn.getCredentials) — der IdP meldet passwortlos an

    python tests/e2e_stage.py            # alles, was konfiguriert ist
    python tests/e2e_stage.py saml       # nur einen Teil

Jeder Teil, dessen Variablen fehlen, wird **übersprungen** und als solcher gemeldet — nie still
als bestanden. Exit 0 = alles Geprüfte grün, 1 = ein Teil rot.
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
    """Headless Chrome über das DevTools-Protokoll — dieselbe Mechanik wie test_browser.py.

    Chrome wählt seinen Debug-Port selbst (`--remote-debugging-port=0`) und schreibt ihn ins
    Profil: Ein vorab reservierter Port ist ein Wettlauf.
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
                pass  # Datei fehlt noch oder ist halb geschrieben — nächste Runde
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
        """Einen DevTools-Befehl senden und auf SEINE Antwort warten — mit Frist.

        Zwei Dinge, die einen Lauf sonst endlos hängen liessen (gefunden beim Bühnentest für
        0.20.0, 15 Minuten ohne Ausgabe): Öffnet die Seite einen `confirm()`-Dialog — die
        Kontoseite fragt seit B1-7 nach einer Faktor-Änderung, ob die übrigen Sitzungen enden
        sollen —, beantwortet Chrome bis zum Schließen kein `Runtime.evaluate` mehr. Der Dialog
        wird deshalb hier sofort abgelehnt (das Angebot ist nicht Gegenstand dieses Tests) und
        gemeldet. Und jede Antwort hat eine Frist; ohne sie wartet ein Fehler still statt laut.
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
        """Auf einen Zustand warten, nicht auf die Uhr.

        Feste Wartezeiten machen einen E2E-Test launisch: Der Rechner ist mal schneller, der
        Provider mal langsamer, und rot wird der Test dann aus einem Grund, der nichts mit dem
        Code zu tun hat. Der Ausdruck wird im Browser ausgewertet, bis er wahr ist.
        """
        ende = time.time() + sekunden
        while time.time() < ende:
            try:
                if await self.js(ausdruck):
                    return True
            except RuntimeError:
                pass          # während einer Navigation ist der Kontext kurz weg
            await asyncio.sleep(0.4)
        return False

    async def csrf(self):
        """Das CSRF-Token aus dem Cookie — unabhängig davon, auf welcher Seite wir gerade sind.

        Die eingebaute Hilfe `tsCsrf()` gibt es nur auf TinySesams eigenen Seiten; auf einer Seite
        der Anwendung fehlt sie. Das Double-Submit-Cookie ist bewusst nicht HttpOnly, genau damit
        eigene Skripte es lesen können. Über HTTPS heisst es seit H-1 `__Host-tinysesam_csrf`.
        """
        return await self.js(
            "(document.cookie.split('; ').find(c => c.startsWith('__Host-tinysesam_csrf=')"
            " || c.startsWith('tinysesam_csrf=')) || '')"
            ".split('=')[1] || ''")

    async def angemeldet_als(self, warte=0):
        """Username laut /auth/me, oder None. `warte` Sekunden lang geduldig, wenn gewünscht."""
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
        """Formular ausfüllen und abschicken — wartend, nicht ratend.

        Erst warten, bis alle Felder da sind (eine Seite, die noch baut, nimmt keine Werte an),
        dann `requestSubmit()`: Das ist der standardkonforme Weg, der Validierung und
        `submit`-Handler auslöst — ein Klick auf den Knopf tat das hier mal, mal nicht, je nachdem
        wie weit die Seite war. Danach warten, bis die Seite tatsächlich gewechselt hat.
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
        """Rate-Limit und Lockout als solche melden, nicht als „Anmeldung fehlgeschlagen".

        Wer diesen Test mehrmals hintereinander fährt, läuft in die eigene Brute-Force-Bremse —
        und eine Fehlermeldung, die dann nach falschem Passwort klingt, schickt den Suchenden in
        die völlig falsche Richtung. (Dieselbe Lehre wie beim SAML-Fund: erst die Diagnose, dann
        die Fehlersuche.)
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
    """Passkey: registrieren und danach passwortlos anmelden — gegen die ECHTE rp_id.

    Der virtuelle Authenticator ersetzt die Hardware, nicht die Ceremony: Origin, `rp_id` und
    Zertifikat sind die der laufenden Instanz. Bedient wird die eingebaute Oberfläche, nicht
    selbst nachgebautes JS — sonst prüfte der Test seinen eigenen Code.
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
        assert await b.angemeldet_als(10) == user, "Passwort-Login fehlgeschlagen"

        await b.geh("/auth/account", 2)
        await b.js("document.querySelector('[data-act=addpk]').click(); true")
        await asyncio.sleep(4)
        await b.warte_bis("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length > 0)", 20)
        liste = await b.js("fetch('/auth/passkey/list').then(r => r.json()).then(j => j.length)")
        assert liste, "kein Passkey gespeichert"
        assert (await b.cmd("WebAuthn.getCredentials", {"authenticatorId": auth_id}))["credentials"]
        ok(f"Passkey registriert ({liste} am Konto, 1 im Authenticator)")

        # Abmelden wie die eingebaute Oberfläche: POST mit CSRF (seit F-07; ein GET fragt je nach
        # Herkunft nur nach).
        tok = await b.csrf()
        await b.js(f"fetch('/auth/logout', {{method: 'POST', headers: {{'X-CSRF-Token': {tok!r}}}}})"
                   ".then(r => r.status)")
        assert await b.angemeldet_als() is None, "Abmelden per POST hat nicht gegriffen"
        await b.geh("/auth/login", 2)
        await b.js("document.querySelector('#pkbtn').click(); true")
        assert await b.angemeldet_als(20) == user, "Passkey-Login fehlgeschlagen"
        ok("passwortlos angemeldet (WebAuthn gegen echte rp_id)")

        # Den angelegten Passkey wieder entfernen: Ein Lauf darf den nächsten nicht beeinflussen,
        # sonst sammelt das Konto bei jedem Durchgang einen weiteren Schlüssel an.
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
        assert rest == 0, f"Aufräumen unvollständig ({rest} Passkeys bleiben)"
        ok("aufgeräumt: Konto ohne Passkey, der nächste Lauf startet gleich")
    return "grün"


async def teil_saml():
    """SAML: AuthnRequest → IdP-Login → signierte Assertion am ACS → Sitzung."""
    user, pw = os.environ.get("STAGE_SAML_USER"), os.environ.get("STAGE_SAML_PW")
    if not (user and pw):
        return "übersprungen (STAGE_SAML_USER/_PW fehlen)"
    async with Browser() as b:
        await b.geh("/auth/saml/login", 4)
        wohin = await b.js("location.href")
        assert BASE not in wohin or "/idp" in wohin, f"kein Redirect zum IdP: {wohin}"
        ok("AuthnRequest: zum IdP weitergeleitet")

        await b.fuelle({"#username": user, "#password": pw})
        wer = await b.angemeldet_als(20)
        assert wer, "Assertion wurde nicht angenommen (Grund steht im Log der Instanz)"
        ok(f"Assertion angenommen, angemeldet als {wer}")
    return "grün"


async def teil_oidc():
    """OIDC: Authorization-Code-Flow gegen den echten Provider.

    Der Provider meldet passwortlos an (Passkey), deshalb bekommt der virtuelle Authenticator ein
    zuvor exportiertes Credential eingespielt (`STAGE_OIDC_CRED`). Einmal von Hand registrieren,
    danach beliebig oft automatisch — ohne dass ein Geheimnis im Repo landet.
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
        assert BASE not in wohin, f"kein Redirect zum Provider: {wohin}"
        ok("Authorization-Request: zum Provider weitergeleitet")

        # Der Provider führt durch mehrere Schritte: erst anmelden (der Passkey kommt aus dem
        # eingespielten Credential), dann der Freigabe zustimmen. Wie viele Seiten das sind, hängt
        # am Provider und daran, ob er die Zustimmung schon kennt — deshalb klicken wir weiter,
        # solange wir noch bei ihm sind, statt eine feste Zahl Schritte anzunehmen.
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
            ok(f"beim Provider bestätigt: {geklickt!r}")
            await asyncio.sleep(4)
        wer = await b.angemeldet_als(25)
        assert wer, ("kein Zugangstoken eingelöst — letzte Seite: "
                     + ((await b.js("document.body.innerText")) or "")[:120].replace(chr(10), " | "))
        ok(f"Code eingelöst, angemeldet als {wer}")
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
