#!/usr/bin/env python3
"""Pull open CodeQL alerts into the backlog — instead of into a mailbox.

    python3 scripts/_codeql_backlog.py            # refresh the table in backlog/T-12-codeql-backlog.md
    python3 scripts/_codeql_backlog.py --show    # only print, write nothing

CodeQL reports every finding as an e-mail and — on a pull request — as a review thread that
blocks the merge as long as it is open (even at severity "note"). What is open on `main`, by
contrast, nobody sees until a PR happens to touch the same lines. This script fetches the open
list via the GitHub API and writes it as a table between the markers in the backlog file;
everything outside the markers stays as it is. Needs a signed-in `gh`.

Assessed alerts are dismissed in GitHub with a reason (`gh api -X PATCH …/alerts/N`), not
struck out here — otherwise they would come back on the next run.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DESTINATION = os.path.join(ROOT, "backlog", "T-12-codeql-backlog.md")
START, ENDE = "<!-- CODEQL:START -->", "<!-- CODEQL:END -->"
RANK = {"error": 0, "warning": 1, "note": 2}
JQ = (".[] | {n:.number, rule:.rule.id, sev:.rule.severity, path:.most_recent_instance.location.path,"
      " line:.most_recent_instance.location.start_line, url:.html_url}")


def hole_alerts() -> list[dict]:
    repo = subprocess.run(["gh", "repo", "view", "--json", "nameWithOwner", "--jq", ".nameWithOwner"],
                          capture_output=True, text=True, check=True, cwd=ROOT).stdout.strip()
    raw = subprocess.run(
        ["gh", "api", "--paginate", f"repos/{repo}/code-scanning/alerts?state=open&per_page=100",
         "--jq", JQ],
        capture_output=True, text=True, check=True, cwd=ROOT).stdout
    alerts = [json.loads(z) for z in raw.splitlines() if z.strip()]
    return sorted(alerts, key=lambda a: (RANK.get(a["sev"], 9), a["path"], a["line"]))


def table(alerts: list[dict]) -> str:
    if not alerts:
        return "_No open alerts._"
    lines = ["| # | Severity | Rule | Location |", "|---|---|---|---|"]
    for a in alerts:
        lines.append(f"| [{a['n']}]({a['url']}) | {a['sev']} | `{a['rule']}` | `{a['path']}:{a['line']}` |")
    per = {}
    for a in alerts:
        per[a["sev"]] = per.get(a["sev"], 0) + 1
    total = ", ".join(f"{n} {s}" for s, n in sorted(per.items(), key=lambda x: RANK.get(x[0], 9)))
    return f"**{len(alerts)} open** ({total}).\n\n" + "\n".join(lines)


def main(argv: list[str]) -> int:
    alerts = hole_alerts()
    text = table(alerts)
    if "--show" in argv:
        print(text)
        return 0
    with open(DESTINATION, encoding="utf-8") as fh:
        old = fh.read()
    if START not in old or ENDE not in old:
        print(f"Markers {START} / {ENDE} missing in {DESTINATION}", file=sys.stderr)
        return 1
    head, rest = old.split(START, 1)
    _, fuss = rest.split(ENDE, 1)
    new = f"{head}{START}\n{text}\n{ENDE}{fuss}"
    if new != old:
        with open(DESTINATION, "w", encoding="utf-8") as fh:
            fh.write(new)
    print(f"{len(alerts)} open alerts → {os.path.relpath(DESTINATION, ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
