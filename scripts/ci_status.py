#!/usr/bin/env python3
"""CI-Ergebnis für einen Commit über die öffentliche GitHub-API (kein Token nötig).

Notlösung für Rechner ohne `gh`. Die anonyme API erlaubt nur **60 Anfragen pro Stunde** —
deshalb wird sparsam gepollt und ein erschöpftes Kontingent sofort gemeldet, statt es
schweigend leerzudrehen. Wer öfter braucht: `gh auth login` (5000/h).

Exit 0 = alle Läufe grün · 1 = mindestens einer rot · 2 = kein Ergebnis.
Wird von `scripts/ci-status.sh` aufgerufen, wenn `gh` fehlt.
"""
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

OK = ("success", "skipped", "neutral")
DEADLINE = 600            # zehn Minuten reichen für den vollen Lauf
POLL = (20, 30, 45, 60)   # ansteigend: ~40 Anfragen in zehn Minuten, nicht 60


def say(*a):
    print(*a, flush=True)           # sonst verschluckt ein Abbruch die ganze Ausgabe


class RateLimited(Exception):
    def __init__(self, reset: str):
        self.reset = reset


def api(path: str):
    req = urllib.request.Request(f"https://api.github.com/repos/{path}",
                                 headers={"Accept": "application/vnd.github+json",
                                          "User-Agent": "tinysesam-ci-status"})
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        if e.code in (403, 429) and e.headers.get("X-RateLimit-Remaining") == "0":
            ts = e.headers.get("X-RateLimit-Reset")
            when = datetime.fromtimestamp(int(ts)).strftime("%H:%M") if ts else "unbekannt"
            raise RateLimited(when) from None
        raise


def pushed(repo: str, sha: str) -> bool:
    """Kennt GitHub den Commit? Sonst wartet man auf einen Lauf, den nie jemand anlegt."""
    try:
        api(f"{repo}/commits/{sha}")
        return True
    except urllib.error.HTTPError as e:
        return e.code != 404
    except RateLimited:
        raise
    except Exception:
        return True                 # Netz weg — nicht als „nicht gepusht" deuten


def main(repo: str, sha: str) -> int:
    deadline, tries, checked_push = time.time() + DEADLINE, 0, False
    while time.time() < deadline:
        try:
            rs = api(f"{repo}/actions/runs?head_sha={sha}&per_page=20")["workflow_runs"]
            if not rs and not checked_push:
                checked_push = True
                if not pushed(repo, sha):
                    say(f"\n{sha[:8]} liegt nicht auf GitHub — erst pushen.")
                    return 2
        except RateLimited as e:
            say(f"\nGitHub-Kontingent erschöpft (60 Anfragen/Stunde ohne Anmeldung),"
                f" frei ab {e.reset} Uhr."
                f"\nDauerhafte Abhilfe: `gh auth login` — dann 5000/Stunde und echte Logs."
                f"\n  https://github.com/{repo}/actions")
            return 2
        except Exception as e:      # Netz weg, 5xx … kein Grund zum Abbruch
            say(f"  API nicht erreichbar ({e})")
            rs = None

        if rs is None:
            pass
        elif not rs:
            say("  noch kein Lauf angelegt …")
        elif any(r["status"] != "completed" for r in rs):
            say(f"  läuft noch: {', '.join(r['name'] for r in rs if r['status'] != 'completed')}")
        else:
            for r in rs:
                say(f"  {'✓' if r['conclusion'] in OK else '✗'} {r['name']}: {r['conclusion']}")
            bad = [r for r in rs if r["conclusion"] not in OK]
            if bad:
                say(f"\nCI ROT — {bad[0]['html_url']}")
                return 1
            say("\nCI grün.")
            return 0

        time.sleep(POLL[min(tries, len(POLL) - 1)])
        tries += 1

    say(f"\nkein Ergebnis nach {DEADLINE // 60} Minuten — https://github.com/{repo}/actions")
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
