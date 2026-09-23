"""Die Seiten im ECHTEN Browser prüfen — Design und Verhalten, nicht nur HTML-Strings.

Startet das Showcase mit uvicorn, fährt Chrome headless über das DevTools-Protokoll und misst,
was der Nutzer sieht: Konsolenfehler, kaputte Anfragen, Breiten, Sprachwechsel, Hell/Dunkel bis in
die Vorschau-iframes, den Login und die Fehlerbehandlung leerer Formulare.

Wird übersprungen, wenn Chrome oder `websockets` fehlen (`run_all.py` kennt das).
Deshalb bricht kein Entwickler-Setup, aber die CI führt es aus.
"""
import asyncio
import json
import shutil
import socket
import subprocess
import os
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pathlib  # noqa: E402
from voraussetzung import braucht, braucht_modul  # noqa: E402

# Drei Voraussetzungen, alle drei als Zusage DIESER Suite — nicht als Rateaufgabe für den Runner.
# Der raubte sich das früher aus dem stderr zusammen und konnte „dem Test fehlt etwas" nicht von
# „die Bibliothek stürzt ab" unterscheiden.
braucht_modul("websockets")
braucht_modul("uvicorn")

import websockets            # noqa: E402
import uvicorn               # noqa: E402

# `browser-actions/setup-chrome` legt die Binärdatei als `chrome` ab, Debian als `chromium`.
CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser")
               if shutil.which(b)), None)
braucht(CHROME, "kein Chrome gefunden")
# Das Showcase liegt im Repo, nicht im sdist — dort absagen statt rot werden.
braucht((pathlib.Path(__file__).resolve().parent.parent / "examples").is_dir(),
        "kein `examples/` — der Browser-Test fährt das Showcase aus dem Repo")
braucht((pathlib.Path(__file__).resolve().parent.parent / "web").is_dir(),
        "kein `web/` — das Showcase rendert die Seiten des Website-Generators")


def _server_socket():
    """Lauschenden Socket für den Testserver aufmachen — und **gebunden lassen**.

    Die naheliegende Fassung (binden, schließen, Nummer merken, uvicorn damit starten) hat ein
    Fenster: zwischen Schließen und erneutem Binden kann ein anderer Prozess denselben Port
    nehmen. Auf einem Runner mit parallelen Jobs ist das kein Gedankenspiel, und rot wird der
    Test dann selten und unerklärlich. uvicorn nimmt fertige Sockets entgegen (`run(sockets=…)`),
    also geben wir diesen hier nie wieder her — damit gibt es das Fenster nicht.

    Chrome löst dasselbe Problem auf seinem Weg: `--remote-debugging-port=0` und die tatsächliche
    Nummer aus `DevToolsActivePort` (siehe `_cdp_port`).
    """
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(128)
    return s


_app_sock = _server_socket()
APP_PORT = _app_sock.getsockname()[1]
BASE = f"http://127.0.0.1:{APP_PORT}"

# Eigene DB, damit ein laufendes Demo-Showcase nicht dazwischenfunkt
_db = os.path.join(tempfile.mkdtemp(), "t.db")
os.environ["TINYSESAM_SHOWCASE_DB"] = _db
import examples.showcase as showcase   # noqa: E402

_server = uvicorn.Server(uvicorn.Config(showcase.app, log_level="critical"))
# Den bereits gebundenen Socket übergeben, nicht host/port — sonst bindet uvicorn neu und die
# Lücke von oben wäre wieder da (dann sogar als "Address already in use").
threading.Thread(target=lambda: _server.run(sockets=[_app_sock]), daemon=True).start()
for _ in range(100):
    try:
        urllib.request.urlopen(f"{BASE}/demo", timeout=1)
        break
    except Exception:
        time.sleep(0.1)
else:
    raise RuntimeError("Showcase startet nicht")

_profile = tempfile.mkdtemp()

# Chromes Ausgabe NICHT nach DEVNULL: stirbt er beim Start, war die Fehlermeldung
# bisher weg und der Test meldete nur "Chrome antwortet nicht" — ohne Grund.
# In eine Datei (nicht PIPE): ein volllaufender Pipe-Puffer würde Chrome blockieren.
_chrome_log = tempfile.NamedTemporaryFile(prefix="chrome-", suffix=".log", delete=False)
_chrome = subprocess.Popen(
    # --disable-dev-shm-usage: CI-Container haben ein winziges /dev/shm, sonst stirbt der Renderer.
    [CHROME, "--headless=new", "--disable-gpu", "--no-sandbox", "--disable-dev-shm-usage",
     "--window-size=1280,900", f"--user-data-dir={_profile}",
     "--remote-debugging-port=0", "about:blank"],
    stdout=_chrome_log, stderr=subprocess.STDOUT)

# Auf einem kalten CI-Runner braucht der erste Chrome-Start regelmäßig länger als
# die früheren 10 s — daher der großzügigere Deckel. Der Test wartet nur, solange
# Chrome wirklich startet: ist der Prozess tot, bricht er sofort ab.
CHROME_START_TIMEOUT = float(os.environ.get("CHROME_START_TIMEOUT", "30"))


def _chrome_output():
    try:
        _chrome_log.flush()
        with open(_chrome_log.name, encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()[-2000:]
    except OSError:
        return "(keine Ausgabe)"


def _cdp_port():
    """Chrome wählt den Port selbst und schreibt ihn ins Profil.

    Ein vorab reservierter Port ist ein Wettlauf: zwischen dem Schließen des Probe-Sockets
    und dem Start von Chrome kann ihn ein anderer Prozess belegen. Auf einem CI-Runner mit
    parallelen Jobs ist das kein Gedankenspiel.
    """
    port_file = os.path.join(_profile, "DevToolsActivePort")
    deadline = time.time() + CHROME_START_TIMEOUT
    while time.time() < deadline:
        if _chrome.poll() is not None:
            raise RuntimeError(
                f"Chrome ist beim Start gestorben (Exit {_chrome.returncode}).\n"
                f"--- Chrome-Ausgabe ---\n{_chrome_output()}")
        try:
            with open(port_file, encoding="utf-8", errors="replace") as fh:
                erste = fh.readline().strip()
            if erste.isdigit():
                return int(erste)
        except OSError:
            pass  # Port-Datei noch nicht da — Chrome startet noch
        time.sleep(0.1)
    raise RuntimeError(
        f"Chrome schrieb keinen DevTools-Port (nach {CHROME_START_TIMEOUT:.0f}s).\n"
        f"--- Chrome-Ausgabe ---\n{_chrome_output()}")


def _ws_url():
    port = _cdp_port()
    deadline = time.time() + CHROME_START_TIMEOUT
    while time.time() < deadline:
        if _chrome.poll() is not None:
            raise RuntimeError(
                f"Chrome ist beim Start gestorben (Exit {_chrome.returncode}).\n"
                f"--- Chrome-Ausgabe ---\n{_chrome_output()}")
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{port}/json"))
            return [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(
        f"Chrome antwortet nicht (nach {CHROME_START_TIMEOUT:.0f}s auf Port {port}).\n"
        f"--- Chrome-Ausgabe ---\n{_chrome_output()}")


class Page:
    """Ein sehr kleiner CDP-Client: navigieren, JS auswerten, Konsole und Netzwerk mitschneiden."""

    def __init__(self, ws):
        self.ws, self._id = ws, 0
        self.console, self.failed = [], []

    async def cmd(self, method, **params):
        self._id += 1
        await self.ws.send(json.dumps({"id": self._id, "method": method, "params": params}))
        while True:
            m = json.loads(await self.ws.recv())
            if m.get("method") == "Runtime.consoleAPICalled" and m["params"]["type"] == "error":
                self.console.append(m["params"])
            if m.get("method") == "Runtime.exceptionThrown":
                self.console.append(m["params"])
            if m.get("method") == "Network.responseReceived":
                r = m["params"]["response"]
                if r["status"] >= 400 and "/gibtsnicht" not in r["url"] and "/boom" not in r["url"]:
                    self.failed.append((r["status"], r["url"]))
            if m.get("id") == self._id:
                return m.get("result", {})

    async def js(self, expr):
        r = await self.cmd("Runtime.evaluate", expression=expr, returnByValue=True)
        if "exceptionDetails" in r:
            raise AssertionError(f"JS-Fehler: {r['exceptionDetails'].get('text')} — {expr[:60]}")
        return r.get("result", {}).get("value")

    async def go(self, path, wait=1.4):
        await self.cmd("Page.navigate", url=BASE + path)
        await asyncio.sleep(wait)

    async def click(self, selector):
        await self.js(f"document.querySelector({selector!r}).click()")
        await asyncio.sleep(1.2)


PAGES = ["/", "/demo", "/demo/flows", "/legal", "/auth/login", "/auth/register", "/gibtsnicht"]


async def run():
    async with websockets.connect(_ws_url(), max_size=30_000_000) as ws:
        p = Page(ws)
        await p.cmd("Page.enable")
        await p.cmd("Runtime.enable")
        await p.cmd("Network.enable")

        # CSP-Verstoesse laufen NICHT ueber die JS-Konsole (Runtime), sondern muessen im
        # Dokument abgefangen werden. Der Listener wird bei JEDEM neuen Dokument frisch
        # installiert (window.__csp startet leer) → nach dem Laden ist er der Beleg, ob
        # die strenge nonce-CSP der eingebauten Seiten ein <script>/<style> geblockt hat.
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source=(
            "window.__csp=[];addEventListener('securitypolicyviolation',function(e){"
            "window.__csp.push(e.effectiveDirective+' blockte '+(e.blockedURI||'inline'))})"))

        # ---------- 1) Jede Seite lädt, ohne Konsolenfehler und ohne kaputte Anfragen ----------
        for path in PAGES:
            await p.go(path)
            assert await p.js("document.querySelectorAll('header.shell').length") == 1, path
            assert await p.js("document.querySelectorAll('nav.row').length") == 2, path
            assert await p.js("document.querySelectorAll('footer').length") == 1, path
        assert not p.console, f"Konsolenfehler: {p.console[:2]}"
        assert not p.failed, f"kaputte Anfragen: {p.failed[:3]}"
        print("  jede Seite: ein Kopf, zwei Navreihen, eine Fußzeile; keine Konsolenfehler")

        # ---------- CSP: die eingebauten Auth-Seiten laufen unter strenger nonce-CSP ----------
        # Kein Verstoss = der Browser hat jedes <script>/<style> per Nonce akzeptiert; ein
        # falscher/fehlender Nonce haette sie geblockt und hier einen Eintrag erzeugt.
        for path in ("/auth/login", "/auth/register"):
            await p.go(path)
            viol = await p.js("JSON.stringify(window.__csp===undefined?['(kein Listener)']:window.__csp)")
            assert viol == "[]", f"CSP-Verstoss auf {path}: {viol}"
        print("  Auth-Seiten unter strenger CSP: kein Verstoss (Nonce akzeptiert)")

        # ---------- 2) Kopf, Inhalt und Fußzeile sind gleich breit ----------
        for path in ("/demo", "/legal", "/demo/flows"):
            await p.go(path)
            w = json.loads(await p.js("""JSON.stringify({
                nav:Math.round(document.querySelector('nav.row').getBoundingClientRect().width),
                main:Math.round(document.querySelector('main').getBoundingClientRect().width),
                foot:Math.round(document.querySelector('footer .inner').getBoundingClientRect().width)})"""))
            assert w["nav"] == w["main"] == w["foot"], (path, w)
        print("  Breiten: Nav = Inhalt = Fußzeile, auf jeder Seite")

        # ---------- 3) Icons so groß wie gedacht (nicht vom Nav-Polster gequetscht) ----------
        await p.go("/demo")
        box = json.loads(await p.js("""JSON.stringify((function(){
            const a=document.querySelector('.ilink'), s=a.querySelector('svg');
            const rs=s.getBoundingClientRect(), ra=a.getBoundingClientRect();
            const rp=document.querySelector('.pill2').getBoundingClientRect();
            return {svg:[Math.round(rs.width),Math.round(rs.height)],
                    icon_h:Math.round(ra.height), pill_h:Math.round(rp.height)};})())"""))
        assert box["svg"] == [20, 20], box
        assert box["icon_h"] == box["pill_h"], box
        print(f"  Icons {box['svg']} in {box['icon_h']}px-Rahmen = Pillenhöhe {box['pill_h']}px")

        # ---------- 4) Ein Sprachsystem: `?lang=` auf jeder Seite ----------
        for path in ("/", "/demo", "/demo/flows", "/legal"):
            await p.cmd("Network.clearBrowserCookies")
            await p.go(path + "?lang=en")
            en = await p.js("document.title")
            await p.go(path + "?lang=de")
            de = await p.js("document.title")
            assert en != de, (path, en)
            assert await p.js("document.documentElement.lang") == "de", path
        print("  Sprache: `?lang=` schaltet auf allen Seiten, `<html lang>` folgt")

        # ---------- 4b) …und bis in die Panels hinein ----------
        # Das Admin-Panel baut seine Oberfläche im Browser. Nur hier sieht man, ob die Texte
        # wirklich ankommen — im Quelltext stehen sie als JSON, nicht als Markup.
        panel = """(function(){const f=[...document.querySelectorAll('.frame iframe')]
            .find(f=>f.src.includes('admin'));
            const d=f&&f.contentDocument; if(!d||!d.body) return '';
            return d.documentElement.lang + '|' + d.body.innerText;})()"""
        for lang, want, nope in (("en", "Hardening", "Härtung"), ("de", "Härtung", "Hardening")):
            await p.cmd("Network.clearBrowserCookies")
            await p.go(f"/demo?lang={lang}", wait=2.4)
            got = await p.js(panel)
            assert got, f"Admin-Vorschau nicht lesbar ({lang})"
            head, text = got.split("|", 1)
            assert head == lang, (lang, head)
            assert want in text and nope not in text, (lang, text[:120])
        print("  Admin-Panel folgt `?lang=` wie jede andere Seite (Reiter, Karten, `<html lang>`)")

        # ---------- 5) Hell/Dunkel bis in die Vorschau-iframes ----------
        await p.go("/demo")
        await p.js("localStorage.setItem('ts-theme','dark')")
        await p.go("/demo", wait=3.0)
        assert await p.js("document.documentElement.dataset.theme") == "dark"
        frames = json.loads(await p.js("""JSON.stringify([...document.querySelectorAll('.frame iframe')]
            .map(f=>{try{const d=f.contentDocument;
              return {theme:d.documentElement.dataset.theme, bg:getComputedStyle(d.body).backgroundColor};}
              catch(e){return {err:''+e};}}))"""))
        assert len(frames) == 3, frames
        for f in frames:
            assert f.get("theme") == "dark", frames
            assert f["bg"] != "rgb(246, 241, 236)", "iframe blieb hell"
        print("  Dunkelmodus greift auch in allen drei Vorschau-iframes")

        # ---------- 5b) Codeblöcke folgen dem Thema und lassen sich kopieren ----------
        # Der Knopf braucht `navigator.clipboard`; wir ersetzen es, um zu sehen, WAS ankommt.
        # Kopiert gehört der reine Text — ohne die Spans der Syntaxfarbe.
        # Gemessen wird an `.cw`: der Kasten (Hintergrund, Rahmen) sitzt dort, `.code` ist
        # transparent — nur so kann der Kopierknopf in einer eigenen Zeile im Block stehen.
        lum = """(function(s){const m=getComputedStyle(document.querySelector(s)).backgroundColor
            .match(/\\d+/g).map(Number); return (m[0]*.299+m[1]*.587+m[2]*.114)/255;})('.cw')"""
        for theme, hell in (("light", True), ("dark", False)):
            await p.js(f"localStorage.setItem('ts-theme','{theme}')")
            await p.go("/", wait=1.6)
            assert await p.js("document.querySelectorAll('.cw .copy').length") == 2, theme
            l = await p.js(lum)
            assert (l > 0.85 if hell else l < 0.2), f"Codeblock im {theme}-Thema: Helligkeit {l:.2f}"
            # Der Knopf steht in einer eigenen Zeile über dem Code — er überlappt ihn nicht.
            over = await p.js("""(function(){
                const b=document.querySelector('.cw .copy').getBoundingClientRect(),
                      c=document.querySelector('.cw .code').getBoundingClientRect();
                return b.bottom <= c.top + 1;})()""")
            assert over, f"Kopierknopf überlappt den Code ({theme})"
        # Der Klick — im dunklen Thema, egal, es geht um die Zwischenablage.
        await p.js("window.__copied=null;"
                   "navigator.clipboard.writeText=t=>{window.__copied=t;return Promise.resolve();}")
        await p.js("document.querySelector('.cw .copy').click()")
        await asyncio.sleep(0.3)          # unter den 1,6 s, die der Haken stehen bleibt
        got = await p.js("window.__copied")
        assert got and got.startswith("pip install "), f"kopiert: {got!r}"
        assert "<span" not in got, "die Auszeichnung ist mitkopiert worden"
        assert await p.js("document.querySelector('.cw .copy').classList.contains('done')")
        # Zweiter Block: mehrzeilig — beweist, dass `white-space:pre` die Umbrüche erhält.
        await p.js("document.querySelectorAll('.cw .copy')[1].click()")
        await asyncio.sleep(0.2)
        code2 = await p.js("window.__copied")
        assert code2.count("\n") >= 4, f"Umbrüche verloren: {code2!r}"
        assert code2.startswith("auth = TinySesam("), code2[:40]
        await p.js("localStorage.removeItem('ts-theme')")
        print("  Codeblöcke: hell im hellen Thema, dunkel im dunklen; Kopierknopf liefert Klartext")

        # ---------- 6) Die Vorschauen sind gesperrt und ohne Demo-Hinweis ----------
        await p.go("/demo/preview/login")
        assert await p.js("getComputedStyle(document.documentElement).pointerEvents") == "none"
        assert await p.js("!document.querySelector('.demobar')"), "Hinweis gehört auf die echte Seite"
        print("  Vorschauen: read-only, ohne Demo-Hinweis")

        # ---------- 7) Leeres Formular → Fehlermeldung, kein JSON ----------
        # Ab hier ist genau ein 400 erwartet (das leere Formular) — alles andere bleibt ein Fehler.
        p.failed.clear()
        await p.js("localStorage.removeItem('ts-theme')")
        await p.cmd("Network.clearBrowserCookies")
        await p.go("/auth/login")
        assert await p.js("!document.querySelector('form').checkValidity()"), "required fehlt"
        await p.js("document.querySelectorAll('form [required]').forEach(e=>e.removeAttribute('required'));"
                   "document.querySelector('form').submit()")
        await asyncio.sleep(1.5)
        assert not await p.js("!!document.querySelector('pre')"), "422-JSON statt Seite"
        err = (await p.js("(document.querySelector('.err')||{textContent:''}).textContent")).strip()
        assert err, "keine Fehlermeldung"
        print(f"  leeres Formular: {err!r} statt JSON")

        # ---------- 8) Login funktioniert — auch wenn der Browser ein Passwort einfüllt ----------
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source="""
            (function(){var n=0,iv=setInterval(function(){var f=document.querySelector('[name=password]');
              if(f){f.value='falschesAltesPasswort';clearInterval(iv);} if(++n>40)clearInterval(iv);},5);})();""")
        await p.go("/auth/login", wait=2.0)
        assert await p.js("document.querySelector('[name=password]').value") == "", "Autofill nicht verworfen"
        await p.click(".demofill[data-u=demoadmin]")
        assert await p.js("document.querySelector('[name=username]').value") == "demoadmin"
        await p.js("document.querySelector('form').submit()")
        await asyncio.sleep(2.0)
        who = (await p.js("(document.querySelector('.dd.r summary')||{textContent:''}).textContent")).strip()
        assert who == "demoadmin", f"nicht angemeldet: {who!r}"
        await p.go("/app")
        assert "demoadmin" in await p.js("document.querySelector('h1').textContent")
        print("  Login: Autofill verworfen, Knopf füllt, angemeldet, /app erreichbar")

        # ---------- 9) Abgelaufene Step-up-Frische: der Knopf schickt zur Reauth ----------
        # R3-3 legte die Faktor-Verwaltung hinter `require_mfa()`. Seither antwortet
        # /auth/totp/disable mit 403 + `X-TinySesam-Reauth`, sobald die Step-up-Frische
        # abgelaufen ist — und der Knopf auf der Konto-Seite scheiterte **stumm**: Die Seite lud
        # einfach neu, der Faktor stand noch. Die Weiche im Konto-JS ist die einzige
        # Oberflächen-Änderung dieser Runde; nur im Browser ist sie überhaupt messbar.
        vorher_frische = showcase.auth.cfg.stepup_max_age_sec
        demoadmin_id = showcase.auth.store.get_user_by_name("demoadmin")["id"]
        # Einen zweiten Faktor einrichten, damit die Konto-Seite den Knopf „2FA abschalten"
        # überhaupt zeigt — er ist der Weg, den R3-3 hinter die Frische gelegt hat.
        showcase.auth.totp_begin(demoadmin_id)
        showcase.auth.store.confirm_totp(demoadmin_id)
        try:
            showcase.auth.cfg.stepup_max_age_sec = 1        # die Frische künstlich altern lassen
            await p.go("/auth/account", wait=1.6)
            assert await p.js("!!document.querySelector('[data-act=deltotp]')"), \
                "kein 2FA-Knopf auf der Konto-Seite — dann misst der Test nichts"
            await p.js("window.confirm=()=>true")           # die Rückfrage des Knopfes bejahen
            await asyncio.sleep(1.5)                        # … jetzt ist die Bestätigung zu alt
            await p.click("[data-act=deltotp]")
            ziel = await p.js("location.pathname + location.search")
            assert ziel.startswith("/auth/reauth"), \
                f"blieb auf {ziel!r} — der 403 scheitert stumm, die Seite lädt bloss neu"
            assert "auth%2Faccount" in ziel or "/auth/account" in ziel, ziel
            assert await p.js("!!document.querySelector('form')"), "Reauth-Seite ohne Formular"
            assert showcase.auth.store.has_confirmed_totp(demoadmin_id), \
                "der zweite Faktor wurde ohne frische Bestätigung entfernt"
        finally:
            showcase.auth.cfg.stepup_max_age_sec = vorher_frische
        print("  Konto-Seite: abgelaufene Frische → Reauth-Seite statt stummem 403")

        # ---------- 10) Angebot nach Faktor-Änderung: `offer()` wirklich ausführen (B1-7, A-5) ----------
        # Vorher prüfte nur ein String-Test, dass `offer(` im HTML steht. Gemessen wird hier, was
        # der Nutzer erlebt: Die Zustimmung beendet die andere Sitzung — und geht bei
        # abgelaufener Frische nicht verloren, sondern kommt nach der Reauth als Rückfrage wieder.
        antwort = "new Response(JSON.stringify({ok:true,other_sessions:1}),{status:200})"
        andere, _ = showcase.auth.start_session(demoadmin_id, "password")
        await p.go("/auth/account", wait=1.6)
        await p.js("window.confirm=()=>true")
        await p.js(f"offer({antwort}).then(()=>{{window.__offer_fertig=true}});1")
        await asyncio.sleep(1.2)
        assert await p.js("window.__offer_fertig===true"), "offer() kam nicht zurück"
        assert showcase.auth.store.get_session(andere) is None, \
            "bestätigtes Angebot, die andere Sitzung läuft trotzdem weiter"
        # Frische abgelaufen: Umweg über die Reauth, die Zustimmung reist als ?revoke_others=1 mit.
        andere, _ = showcase.auth.start_session(demoadmin_id, "password")
        try:
            showcase.auth.cfg.stepup_max_age_sec = 1
            await asyncio.sleep(1.5)
            await p.js(f"offer({antwort});1")
            await asyncio.sleep(1.4)
            ziel = await p.js("location.pathname + decodeURIComponent(location.search)")
            assert ziel.startswith("/auth/reauth") and "/auth/account?revoke_others=1" in ziel, \
                f"blieb auf {ziel!r} — die Zustimmung ginge verloren"
            assert showcase.auth.store.get_session(andere) is not None, "ohne Frische beendet"
        finally:
            showcase.auth.cfg.stepup_max_age_sec = vorher_frische   # ≙ Reauth bestanden
        await p.cmd("Page.addScriptToEvaluateOnNewDocument", source="window.confirm=()=>true")
        await p.go("/auth/account?revoke_others=1", wait=1.8)
        assert showcase.auth.store.get_session(andere) is None, \
            "nach der Reauth nicht nachgefragt/beendet — die Zustimmung ist verloren"
        assert await p.js("location.search") == "", "?revoke_others bleibt in der Adresse stehen"
        print("  Konto-Seite: Angebot beendet die anderen Sitzungen, auch über den Reauth-Umweg")

        assert not p.console, f"Konsolenfehler: {p.console[:2]}"
        # Erwartet sind genau drei Fehlschläge: das leere Formular (400) und die 403, mit denen
        # Faktor-Verwaltung und Sitzungs-Beenden die abgelaufene Frische abweisen (Abschnitt 9, 10).
        unexpected = [f for f in p.failed
                      if not (f[0] == 400 and f[1].endswith("/auth/login"))
                      and not (f[0] == 403 and f[1].endswith("/auth/totp/disable"))
                      and not (f[0] == 403 and f[1].endswith("/auth/sessions/revoke"))]
        assert not unexpected, f"kaputte Anfragen: {unexpected[:3]}"


try:
    asyncio.run(run())
    print("OK test_browser")
finally:
    _chrome.terminate()
    _server.should_exit = True
    shutil.rmtree(_profile, ignore_errors=True)
    # Chrome-Logdatei mit abräumen — der Test darf nichts hinterlassen.
    try:
        _chrome_log.close()
        os.unlink(_chrome_log.name)
    except OSError:
        pass  # Log schon weg — nichts aufzuräumen
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_db + suffix)
        except OSError:
            pass  # Datei gab es nicht — beim Aufräumen kein Fehler
