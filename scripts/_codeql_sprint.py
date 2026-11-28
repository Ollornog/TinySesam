#!/usr/bin/env python3
"""CodeQL in the sprint lane: fail on findings a sprint pull request adds compared with `main` (T-139).

    python3 scripts/_codeql_sprint.py --sarif sarif --category /language:python
    python3 scripts/_codeql_sprint.py --sarif pr.sarif --base base.sarif   # offline, the test does this

A pull request into `sprint/<name>` runs the CodeQL analysis without uploading it (`.github/workflows/codeql.yml`, job
`sprint`): an upload for a branch without an analysis of its own gives GitHub's check nothing to compare against. This
script compares the pull request's SARIF with the SARIF of `main`'s analyses of the same category, fetched through the
code-scanning API: the newest one and the one at the merge base of the pull request's head (a finding fixed on `main`
after the sprint branched is not the sprint's). A finding is the same when rule, file and CodeQL's
`primaryLocationLineHash` agree (the hash of the line's content, so a moved line is still the same finding); a result
without that hash compares by rule, file and message. Findings count as a multiset: a second identical finding is new.
Dismissed alerts on `main` stay in its SARIF and never turn a sprint red.

Exit 0: nothing new. Exit 1: new findings (each printed, and as an `::error` annotation). Exit 2: nothing to compare
with — red, never a silent green.
"""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import subprocess
import sys
from collections import Counter


def results(sarif: dict) -> list[dict]:
    """Every result of every run of one SARIF document."""
    return [r for run in sarif.get("runs", []) for r in run.get("results", [])]


def where(result: dict) -> tuple[str, int]:
    loc = (result.get("locations") or [{}])[0].get("physicalLocation", {})
    return loc.get("artifactLocation", {}).get("uri", "?"), int(loc.get("region", {}).get("startLine", 0) or 0)


def rule_of(result: dict) -> str:
    return result.get("ruleId") or result.get("rule", {}).get("id", "?")


def key(result: dict) -> tuple[str, str, str]:
    """What makes two results the same finding: rule, file and the line hash (else the message)."""
    line_hash = (result.get("partialFingerprints") or {}).get("primaryLocationLineHash")
    return rule_of(result), where(result)[0], line_hash or "message:" + result.get("message", {}).get("text", "")


def new_findings(head: list[dict], bases: list[list[dict]]) -> list[dict]:
    """The results of `head` that none of the base analyses holds, counted as a multiset.

    With several base analyses a finding is known up to the highest count any of them has: the union, not the sum.
    """
    known: Counter = Counter()
    for base in bases:
        for k, n in Counter(key(r) for r in base).items():
            known[k] = max(known[k], n)
    seen: Counter = Counter()
    fresh = []
    for r in head:
        k = key(r)
        seen[k] += 1
        if seen[k] > known[k]:
            fresh.append(r)
    return fresh


def pick_analyses(analyses: list[dict], category: str, merge_base: str | None) -> list[int]:
    """Ids of `main`'s analyses to compare with: the newest of the category and the one at the merge base."""
    mine = sorted((a for a in analyses if a.get("category") == category),
                  key=lambda a: a.get("created_at", ""), reverse=True)
    picked = [a["id"] for a in mine[:1]]
    at_base = next((a["id"] for a in mine if merge_base and a.get("commit_sha") == merge_base), None)
    if at_base is not None and at_base not in picked:
        picked.append(at_base)
    return picked


def gh(*args: str) -> str:
    return subprocess.run(["gh", "api", *args], capture_output=True, text=True, check=True).stdout


def fetch_bases(repo: str, category: str, head_sha: str, base_ref: str) -> list[list[dict]]:
    merge_base = None
    if head_sha:
        merge_base = json.loads(gh(f"repos/{repo}/compare/{base_ref}...{head_sha}")).get(
            "merge_base_commit", {}).get("sha")
    analyses = json.loads(gh(f"repos/{repo}/code-scanning/analyses?ref=refs/heads/{base_ref}"
                             "&tool_name=CodeQL&per_page=100"))
    ids = pick_analyses(analyses, category, merge_base)
    print(f"comparing with {base_ref}: analyses {ids} (merge base {(merge_base or '?')[:12]})")
    return [results(json.loads(gh("-H", "Accept: application/sarif+json",
                                  f"repos/{repo}/code-scanning/analyses/{i}"))) for i in ids]


def load(path: str) -> list[dict]:
    p = pathlib.Path(path)
    files = sorted(p.glob("*.sarif")) if p.is_dir() else [p]
    return [r for f in files for r in results(json.loads(f.read_text(encoding="utf-8")))]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n", 1)[0])
    ap.add_argument("--sarif", required=True, help="the pull request's SARIF file or a directory of them")
    ap.add_argument("--category", default="", help="the analysis category, e.g. /language:python")
    ap.add_argument("--base", action="append", default=[], help="a base SARIF file (offline; repeatable)")
    ap.add_argument("--base-ref", default="main")
    args = ap.parse_args(argv)
    head = load(args.sarif)
    if args.base:
        bases = [load(b) for b in args.base]
    else:
        repo = os.environ.get("GITHUB_REPOSITORY", "")
        if not repo or not args.category:
            print("no --base and no GITHUB_REPOSITORY/--category: nothing to compare with", file=sys.stderr)
            return 2
        bases = fetch_bases(repo, args.category, os.environ.get("HEAD_SHA", ""), args.base_ref)
    if not bases:
        print(f"no CodeQL analysis of {args.category or 'the base'} on {args.base_ref}: nothing to compare with",
              file=sys.stderr)
        return 2
    fresh = new_findings(head, bases)
    print(f"{len(head)} finding(s) in the pull request, {max(len(b) for b in bases)} on {args.base_ref}, "
          f"{len(fresh)} new")
    for r in fresh:
        path, line = where(r)
        text = " ".join(r.get("message", {}).get("text", "").split())
        print(f"  NEW {rule_of(r)}  {path}:{line}  {text}")
        print(f"::error file={path},line={line},title=CodeQL {rule_of(r)}::{text}")
    if fresh:
        print("Fix the finding in code (or, for a real false positive, see .github/codeql/accepted.md).")
    return 1 if fresh else 0


if __name__ == "__main__":
    sys.exit(main())
