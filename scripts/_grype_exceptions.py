#!/usr/bin/env python3
"""Checks the exceptions of the image CVE scan (`.grype.yaml`) before the scan runs (H1).

    python3 scripts/_grype_exceptions.py            # exit 0 = every exception valid, 1 = not
    python3 scripts/_grype_exceptions.py --today 2026-12-08   # the same for another day (tests)
    python3 scripts/_grype_exceptions.py --report gw.json --report caddy.json   # AFTER the scans (see below)

An exception without an end turns the gate into a list of things nobody looks at again. Every rule must
therefore carry `reason: "until YYYY-MM-DD: <why>"` — the date not in the past and at most MAX_DAYS ahead
(the "high" deadline of SECURITY.md). Read without PyYAML: the runner's system Python brings no YAML
library, and the file has a fixed, simple form.

With `--report` (the JSON reports of every scan that reads .grype.yaml, T-59) it runs after the scans: it prints the
findings as a table — the scan steps write JSON, not a table — and fails on a rule that matched NOTHING in any report.
Such a rule has outlived its reason (the base bump carried the fix, or the base changed: the zlib rule for
python:3.15-slim stood there after the image had moved to distroless) and would wave the same CVE through unseen if it
came back in another package. Without this check it stayed until its date ran out.
"""
from __future__ import annotations

import datetime as dt
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / ".grype.yaml"
MAX_DAYS = 31
_UNTIL = re.compile(r'^\s+reason:\s*"until (\d{4}-\d{2}-\d{2}): \S')


def problems(text: str, today: dt.date) -> list[str]:
    """What is wrong with the exceptions in `text` — empty = valid."""
    found = []
    block = re.split(r"^ignore:", text, maxsplit=1, flags=re.M)
    rules = re.split(r"^  - ", block[1], flags=re.M)[1:] if len(block) == 2 else []
    for rule in rules:
        name = (re.search(r"vulnerability:\s*(\S+)", rule) or re.search(r"(\S+)", rule)).group(1)
        m = next((_UNTIL.match(z) for z in rule.splitlines() if _UNTIL.match(z)), None)
        if not m:
            found.append(f"{name}: reason without 'until YYYY-MM-DD: <why>'")
            continue
        until = dt.date.fromisoformat(m.group(1))
        if until < today:
            found.append(f"{name}: exception expired on {until} — fix it or renew it with a reason")
        elif (until - today).days > MAX_DAYS:
            found.append(f"{name}: until {until} is more than {MAX_DAYS} days ahead")
    return found


def rules(text: str) -> list[tuple[str, str]]:
    """(vulnerability, package name or "") of every rule in `text`."""
    block = re.split(r"^ignore:", text, maxsplit=1, flags=re.M)
    out = []
    for rule in re.split(r"^  - ", block[1], flags=re.M)[1:] if len(block) == 2 else []:
        vuln = re.search(r"vulnerability:\s*(\S+)", rule)
        name = re.search(r"^\s+name:\s*(\S+)", rule, re.M)
        out.append((vuln.group(1) if vuln else "", name.group(1) if name else ""))
    return out


def unmatched(text: str, reports: list[dict]) -> list[str]:
    """Rules that no ignored match of any report was ignored by — empty = every rule still does something."""
    used = set()
    for report in reports:
        for m in report.get("ignoredMatches") or []:
            for r in m.get("appliedIgnoreRules") or []:
                used.add((r.get("vulnerability") or "", (r.get("package") or {}).get("name") or ""))
    return [f"{v or '?'}{f' ({n})' if n else ''}: matches nothing in the scanned images — remove the rule"
            for v, n in rules(text) if (v, n) not in used]


def table(report: dict) -> list[str]:
    rows = sorted(((m["vulnerability"].get("severity", "?"), m["vulnerability"]["id"], m["artifact"]["name"],
                    m["artifact"]["version"], m["vulnerability"].get("fix", {}).get("state", "?"))
                   for m in report.get("matches") or []), key=lambda r: (r[0], r[1], r[2]))
    return [f"  {s:<10} {i:<22} {n:<28} {v:<36} {f}" for s, i, n, v, f in rows]


def main(argv: list[str]) -> int:
    today = dt.date.today()
    if "--today" in argv:
        today = dt.date.fromisoformat(argv[argv.index("--today") + 1])
    text = FILE.read_text(encoding="utf-8")
    paths = [argv[i + 1] if i + 1 < len(argv) else "" for i, a in enumerate(argv) if a == "--report"]
    if paths:
        return after_scans(text, paths)
    found = problems(text, today)
    for p in found:
        print(f"::error file=.grype.yaml::{p}")
    if not found:
        n = len(re.findall(r"^  - ", text, re.M))
        print(f".grype.yaml: {n} exception(s), all within their deadline")
    return 1 if found else 0


def after_scans(text: str, paths: list[str]) -> int:
    reports, missing = [], []
    for path in paths:
        if not path or not Path(path).is_file():
            missing.append(path or "(empty)")
            continue
        report = json.loads(Path(path).read_text(encoding="utf-8"))
        reports.append(report)
        target = (report.get("source") or {}).get("target")
        name = target.get("userInput", "?") if isinstance(target, dict) else str(target)
        lines = table(report)
        print(f"{name}: {len(lines)} finding(s) after .grype.yaml (the scan step's own settings decide red/green)")
        print("\n".join(lines))
    if missing:
        # Not "no orphan": a scan that wrote no report has not looked. The scan step above is red already.
        print(f"::error file=.grype.yaml::no report from {missing} — a scan did not run or did not write one; "
              "whether every exception still matches something is unknown")
        return 1
    found = unmatched(text, reports)
    for p in found:
        print(f"::error file=.grype.yaml::{p}")
    if not found:
        print(f".grype.yaml: every one of {len(rules(text))} exception(s) matched a finding in {len(reports)} report(s)")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
