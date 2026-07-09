#!/usr/bin/env python3
"""CI-Ergebnis für einen Commit über die öffentliche GitHub-API (kein Token nötig).

Exit 0 = alle Läufe grün · 1 = mindestens einer rot · 2 = kein Ergebnis.
Wird von `scripts/ci-status.sh` aufgerufen, wenn `gh` fehlt.
"""
import json
import sys
import time
import urllib.request

OK = ("success", "skipped", "neutral")


def runs(repo: str, sha: str):
    url = f"https://api.github.com/repos/{repo}/actions/runs?head_sha={sha}&per_page=20"
    req = urllib.request.Request(url, headers={"Accept": "application/vnd.github+json",
                                               "User-Agent": "tinysesam-ci-status"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r).get("workflow_runs", [])


def main(repo: str, sha: str) -> int:
    deadline = time.time() + 600          # zehn Minuten reichen für den vollen Lauf
    while time.time() < deadline:
        try:
            rs = runs(repo, sha)
        except Exception as e:            # Netz weg, Rate-Limit … kein Grund zum Abbruch
            print(f"  API nicht erreichbar ({e}) — erneut in 10 s")
            time.sleep(10)
            continue
        if not rs:
            print("  noch kein Lauf angelegt …")
        elif any(r["status"] != "completed" for r in rs):
            busy = [r["name"] for r in rs if r["status"] != "completed"]
            print(f"  läuft noch: {', '.join(busy)}")
        else:
            bad = [r for r in rs if r["conclusion"] not in OK]
            for r in rs:
                mark = "✓" if r["conclusion"] in OK else "✗"
                print(f"  {mark} {r['name']}: {r['conclusion']}")
            if bad:
                print(f"\nCI ROT — {bad[0]['html_url']}", file=sys.stderr)
                return 1
            print("\nCI grün.")
            return 0
        time.sleep(10)
    print(f"\nkein Ergebnis nach 10 Minuten — https://github.com/{repo}/actions", file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1], sys.argv[2]))
