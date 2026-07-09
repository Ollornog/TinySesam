"""Die Seiten im ECHTEN Browser prüfen — Design und Verhalten, nicht nur HTML-Strings.

Startet das Showcase mit uvicorn, fährt Chrome headless über das DevTools-Protokoll und misst,
was der Nutzer sieht: Konsolenfehler, kaputte Anfragen, Breiten, Sprachwechsel, Hell/Dunkel bis in
die Vorschau-iframes, den Login und die Fehlerbehandlung leerer Formulare.

Wird übersprungen, wenn Chrome oder `websockets` fehlen (`run_all.py` kennt das).
Deshalb bricht kein Entwickler-Setup, aber die CI führt es aus.
"""
import asyncio
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import websockets            # noqa: E402  (optional — run_all überspringt sonst)
import uvicorn               # noqa: E402

# `browser-actions/setup-chrome` legt die Binärdatei als `chrome` ab, Debian als `chromium`.
CHROME = next((b for b in ("google-chrome", "chrome", "chromium", "chromium-browser")
               if shutil.which(b)), None)
if not CHROME:
    raise ImportError("kein Chrome gefunden")   # run_all wertet das als „übersprungen"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


APP_PORT, CDP_PORT = free_port(), free_port()
BASE = f"http://127.0.0.1:{APP_PORT}"

# Eigene DB, damit ein laufendes Demo-Showcase nicht dazwischenfunkt
_db = tempfile.mktemp(suffix=".db")
os.environ["TINYSESAM_SHOWCASE_DB"] = _db
import examples.showcase as showcase   # noqa: E402

_server = uvicorn.Server(uvicorn.Config(showcase.app, host="127.0.0.1", port=APP_PORT,
                                        log_level="critical"))
threading.Thread(target=_server.run, daemon=True).start()
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
     f"--remote-debugging-port={CDP_PORT}", "about:blank"],
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


def _ws_url():
    deadline = time.time() + CHROME_START_TIMEOUT
    while time.time() < deadline:
        if _chrome.poll() is not None:
            raise RuntimeError(
                f"Chrome ist beim Start gestorben (Exit {_chrome.returncode}).\n"
                f"--- Chrome-Ausgabe ---\n{_chrome_output()}")
        try:
            tabs = json.load(urllib.request.urlopen(f"http://127.0.0.1:{CDP_PORT}/json"))
            return [t for t in tabs if t["type"] == "page"][0]["webSocketDebuggerUrl"]
        except Exception:
            time.sleep(0.1)
    raise RuntimeError(
        f"Chrome antwortet nicht (nach {CHROME_START_TIMEOUT:.0f}s auf Port {CDP_PORT}).\n"
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

        # ---------- 1) Jede Seite lädt, ohne Konsolenfehler und ohne kaputte Anfragen ----------
        for path in PAGES:
            await p.go(path)
            assert await p.js("document.querySelectorAll('header.shell').length") == 1, path
            assert await p.js("document.querySelectorAll('nav.row').length") == 2, path
            assert await p.js("document.querySelectorAll('footer').length") == 1, path
        assert not p.console, f"Konsolenfehler: {p.console[:2]}"
        assert not p.failed, f"kaputte Anfragen: {p.failed[:3]}"
        print("  jede Seite: ein Kopf, zwei Navreihen, eine Fußzeile; keine Konsolenfehler")

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
        lum = """(function(s){const m=getComputedStyle(document.querySelector(s)).backgroundColor
            .match(/\\d+/g).map(Number); return (m[0]*.299+m[1]*.587+m[2]*.114)/255;})('.cw .code')"""
        for theme, hell in (("light", True), ("dark", False)):
            await p.js(f"localStorage.setItem('ts-theme','{theme}')")
            await p.go("/", wait=1.6)
            assert await p.js("document.querySelectorAll('.cw .copy').length") == 2, theme
            l = await p.js(lum)
            assert (l > 0.85 if hell else l < 0.2), f"Codeblock im {theme}-Thema: Helligkeit {l:.2f}"
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

        assert not p.console, f"Konsolenfehler: {p.console[:2]}"
        unexpected = [f for f in p.failed if not (f[0] == 400 and f[1].endswith("/auth/login"))]
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
        pass
    for suffix in ("", "-wal", "-shm"):
        try:
            os.unlink(_db + suffix)
        except OSError:
            pass
