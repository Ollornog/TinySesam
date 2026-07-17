"""Geteilte Prüfungen für HTTP-Antworten: Security-Header und Cookie-Flags.

Diese Datei wird von `repokit sync` hierher kopiert — nicht von Hand ändern.

**Kein Netz, keine Abhängigkeiten, kein Prozessstart.** Nur stdlib — wie `hygiene.py`.
Das ist die Naht: dieses Modul kennt nur die REGELN und bekommt die fertige Antwort
gereicht. Die Antwort zu beschaffen (App starten, Request absetzen) ist Sache des
Repos, das die App ohnehin schon startet. Damit bleibt das Kit rein und trotzdem
prüfbar — dasselbe Muster wie `pruefe_private_infrastruktur(root, dateien)`, wo das
Repo die `git ls-files`-Liste liefert.

**Jede Prüfung gibt eine Liste von Verstößen zurück, sie wirft nicht** — wie überall
im Kit, damit `assert not pruefe_...()` und `r.check(name, not pruefe_...())` beide gehen.

Abgrenzung, wichtig beim Verdrahten: Was die APP verantwortet (Cookie-Flags, CSP, wenn
sie sie selbst baut) gehört in die Repo-Suite. Was der REVERSE-PROXY setzt (HSTS, TLS)
kann eine App-Suite gar nicht sehen — das prüft ein Smoke-Test gegen die deployte
Instanz. `pruefe_hsts` liegt hier trotzdem bereit: derselbe Assert, andere Ebene.
"""
from __future__ import annotations

import re

# Referrer-Werte, die keine vollständige URL an fremde Hosts geben.
SICHERE_REFERRER = ("no-referrer", "same-origin", "strict-origin",
                    "strict-origin-when-cross-origin", "no-referrer-when-downgrade")

# Was eine App selbst setzen kann und soll. HSTS steht bewusst NICHT drin (Proxy-Sache).
# Tupel = einer der Werte genügt; True = muss vorhanden sein, Inhalt egal.
STANDARD_POLICY: dict = {
    "x-content-type-options": "nosniff",
    "x-frame-options": ("deny", "sameorigin"),
    "referrer-policy": SICHERE_REFERRER,
    "content-security-policy": True,
}

# Ein Header, dessen Wert eine Versionsnummer enthält, verrät die Angriffsfläche.
_VERSION = re.compile(r"\d+\.\d+")


# ---------------------------------------------------------------------------
# Einlesen

def rohe_set_cookie(response) -> list[str]:
    """Alle `Set-Cookie`-Zeilen einer Antwort, egal welcher Client sie gebaut hat.

    httpx nennt es `get_list`, starlette `getlist`. Beide kommen vor: das eine ist die
    Antwort eines TestClients, das andere eine direkt gebaute `Response`. Dupliziert
    absichtlich kein httpx — hier wird nur nach Attributen gefragt, nichts importiert.
    """
    h = response.headers
    if hasattr(h, "get_list"):
        return list(h.get_list("set-cookie"))
    if hasattr(h, "getlist"):
        return list(h.getlist("set-cookie"))
    # Letzter Ausweg: ein einzelner Header als String. Mehrere Cookies wären hier
    # bereits verschmolzen und nicht mehr sicher trennbar -> lieber nichts behaupten.
    einer = h.get("set-cookie")
    return [einer] if einer else []


def parse_set_cookie(zeilen: list[str]) -> dict:
    """`Set-Cookie`-Zeilen → {name: {"_wert": …, "httponly": True, "samesite": "lax", …}}.

    Attributnamen kleingeschrieben. Flags ohne Wert (HttpOnly, Secure) werden zu `True`,
    damit `attrs.get("httponly") is True` und `"httponly" not in attrs` beide klar lesbar
    sind. Der Cookie-Wert steht unter `_wert` (kein echtes Attribut, darum der Unterstrich).

    Bewusst der ROHE Header und nicht der Cookie-Jar des Clients: ein Jar wirft Attribute
    weg und legt Secure-Cookies über http:// gar nicht erst ab. Man prüfte dann, was der
    Client behalten hat — nicht, was die App gesendet hat.
    """
    out: dict = {}
    for zeile in zeilen:
        teile = [t.strip() for t in str(zeile).split(";")]
        if not teile or "=" not in teile[0]:
            continue
        name, _, wert = teile[0].partition("=")
        attrs: dict = {"_wert": wert}
        for t in teile[1:]:
            if not t:
                continue
            k, _, v = t.partition("=")
            attrs[k.strip().lower()] = v.strip() if v else True
        out[name.strip()] = attrs
    return out


def _normalisiere(headers) -> dict:
    """Header-Mapping → {kleingeschriebener name: wert}. Verträgt dict und Header-Objekte."""
    roh = dict(headers.items()) if hasattr(headers, "items") else dict(headers)
    return {str(k).lower(): v for k, v in roh.items()}


# ---------------------------------------------------------------------------
# Cookies

def pruefe_cookie_flags(gesetzt: dict, erwartung: dict) -> list[str]:
    """Flags jedes GESETZTEN Cookies gegen seine Erwartung prüfen.

    `gesetzt`     — Ausgabe von `parse_set_cookie()`.
    `erwartung`   — {cookie_name: {"httponly": True, "secure": True, "samesite": "lax"}}
        True  → Flag MUSS vorhanden sein
        False → Flag darf NICHT vorhanden sein
        str   → Attribut muss diesen Wert haben (Vergleich ohne Groß/Klein)

    Warum je Cookie eine eigene Erwartung statt einer Regel für alle: Ein Double-Submit-
    CSRF-Cookie MUSS für JavaScript lesbar sein, darf also gerade nicht HttpOnly haben.
    Ein pauschales „alle Cookies HttpOnly" würde genau das richtige Cookie anmeckern —
    und wer den Test dann aufweicht, verliert ihn für die Cookies, die zählen.

    Ein gesetztes Cookie OHNE Eintrag in `erwartung` ist ein Verstoß: Wer ein neues
    Cookie einführt, soll seine Flags erklären müssen. Ob ein Cookie überhaupt gesetzt
    sein muss, prüft der Aufrufer — das hängt an der Antwort, nicht an der Politik.
    """
    verstoesse: list[str] = []
    for name, attrs in sorted(gesetzt.items()):
        if name not in erwartung:
            verstoesse.append(f"{name}: gesetzt, aber ohne Erwartung — Flags deklarieren")
            continue
        for flag, soll in sorted(erwartung[name].items()):
            ist = attrs.get(flag)
            if soll is True and ist is not True:
                verstoesse.append(f"{name}: {flag} fehlt")
            elif soll is False and flag in attrs:
                verstoesse.append(f"{name}: {flag} gesetzt, darf hier nicht sein")
            elif isinstance(soll, str) and str(ist or "").lower() != soll.lower():
                verstoesse.append(f"{name}: {flag}={ist!r}, erwartet {soll!r}")
    return verstoesse


# ---------------------------------------------------------------------------
# Header

def pruefe_security_header(headers, policy: dict | None = None) -> list[str]:
    """Antwort-Header gegen eine Policy prüfen. Ohne `policy` gilt `STANDARD_POLICY`.

    Policy-Werte: `True` = muss da sein · `str` = genau dieser Wert (ohne Groß/Klein) ·
    Tupel/Liste = einer davon genügt.
    """
    regeln = STANDARD_POLICY if policy is None else policy
    h = _normalisiere(headers)
    verstoesse: list[str] = []
    for name, soll in sorted(regeln.items()):
        ist = h.get(name.lower())
        if ist is None:
            verstoesse.append(f"{name}: fehlt")
            continue
        wert = str(ist).strip().lower()
        if soll is True:
            continue
        if isinstance(soll, str):
            if wert != soll.lower():
                verstoesse.append(f"{name}: {ist!r}, erwartet {soll!r}")
        elif not any(wert == str(s).lower() for s in soll):
            verstoesse.append(f"{name}: {ist!r}, erwartet einen von {list(soll)!r}")
    return verstoesse


def pruefe_csp(csp: str) -> list[str]:
    """Content-Security-Policy auf die Löcher prüfen, die sie wirkungslos machen.

    Kein vollständiger Bypass-Check (dafür gäbe es Googles csp-evaluator, npm-only und
    darum hier fehl am Platz) — aber die vier Fehler, die eine CSP zur Attrappe machen.
    """
    verstoesse: list[str] = []
    if not csp or not csp.strip():
        return ["CSP: leer"]
    text = csp.lower()
    direktiven = {}
    for teil in text.split(";"):
        teil = teil.strip()
        if not teil:
            continue
        name, *werte = teil.split()
        direktiven[name] = werte

    skript = direktiven.get("script-src", direktiven.get("default-src", []))
    if "'unsafe-inline'" in skript:
        verstoesse.append("CSP: script-src erlaubt 'unsafe-inline' — hebt den XSS-Schutz auf")
    if "'unsafe-eval'" in skript:
        verstoesse.append("CSP: script-src erlaubt 'unsafe-eval'")
    if "*" in skript:
        verstoesse.append("CSP: script-src erlaubt jede Quelle (*)")
    if "default-src" not in direktiven and "script-src" not in direktiven:
        verstoesse.append("CSP: weder default-src noch script-src — greift für Skripte nicht")
    return verstoesse


def pruefe_hsts(wert: str | None, min_alter: int = 15768000) -> list[str]:
    """Strict-Transport-Security prüfen. Gehört auf die Proxy-/Deploy-Ebene, nicht in eine App-Suite.

    `min_alter` = 6 Monate in Sekunden — die Schwelle, ab der ein HSTS-Header üblicherweise
    als vollwertig gilt; ein zu kurzes max-age lässt genau das Fenster offen, das HSTS
    schließen soll.
    """
    if not wert:
        return ["HSTS: fehlt"]
    m = re.search(r"max-age\s*=\s*(\d+)", str(wert).lower())
    if not m:
        return [f"HSTS: kein max-age in {wert!r}"]
    alter = int(m.group(1))
    if alter < min_alter:
        return [f"HSTS: max-age={alter} < {min_alter} (zu kurz)"]
    return []


def pruefe_kein_versions_leak(headers) -> list[str]:
    """Header, die eine Versionsnummer preisgeben (`Server`, `X-Powered-By`).

    Eine Version im Header spart einem Angreifer den Fingerprint: Er muss nicht mehr
    raten, welche CVE-Liste er durchprobiert.
    """
    h = _normalisiere(headers)
    verstoesse = []
    for name in ("server", "x-powered-by", "x-aspnet-version"):
        wert = h.get(name)
        if wert and _VERSION.search(str(wert)):
            verstoesse.append(f"{name}: {wert!r} verrät eine Version")
    return verstoesse
