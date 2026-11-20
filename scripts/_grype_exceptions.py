#!/usr/bin/env python3
"""Checks the exceptions of the image CVE scan (`.grype.yaml`) before the scan runs (H1).

    python3 scripts/_grype_exceptions.py            # exit 0 = every exception valid, 1 = not
    python3 scripts/_grype_exceptions.py --today 2026-12-08   # the same for another day (tests)

An exception without an end turns the gate into a list of things nobody looks at again. Every rule must
therefore carry `reason: "until YYYY-MM-DD: <why>"` — the date not in the past and at most MAX_DAYS ahead
(the "high" deadline of SECURITY.md). Read without PyYAML: the runner's system Python brings no YAML
library, and the file has a fixed, simple form.
"""
from __future__ import annotations

import datetime as dt
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


def main(argv: list[str]) -> int:
    today = dt.date.today()
    if "--today" in argv:
        today = dt.date.fromisoformat(argv[argv.index("--today") + 1])
    text = FILE.read_text(encoding="utf-8")
    found = problems(text, today)
    for p in found:
        print(f"::error file=.grype.yaml::{p}")
    if not found:
        n = len(re.findall(r"^  - ", text, re.M))
        print(f".grype.yaml: {n} exception(s), all within their deadline")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
