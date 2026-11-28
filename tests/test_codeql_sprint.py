"""CodeQL in the sprint lane (T-139): a finding a sprint pull request adds compared with `main` turns it red.

The sprint lane skipped CodeQL, and the closing pull request was red on it three sprints in a row (S4, S5, S6), each
time a round of about 45 minutes. `.github/workflows/codeql.yml` now runs the Python and JavaScript analysis on a pull
request into `sprint/<name>` without uploading it, and `scripts/_codeql_sprint.py` compares its SARIF with `main`'s.
Checked here:

  (a) the comparison: a new finding is new, a known one (also on a moved line, also only in the merge-base analysis,
      also dismissed — it stays in the SARIF) is not, a second identical finding is new, no base is exit 2
  (b) the choice of `main`'s analyses: the newest of the category and the one at the merge base
  (c) the workflow: the job `sprint` runs only on a pull request into a sprint branch, never uploads, holds no write
      permission and analyses what the main jobs analyse; every other job skips there
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import _codeql_sprint as cs  # noqa: E402


def finding(rule, path, line, line_hash, text="message"):
    r = {"ruleId": rule, "message": {"text": text},
         "locations": [{"physicalLocation": {"artifactLocation": {"uri": path}, "region": {"startLine": line}}}]}
    if line_hash:
        r["partialFingerprints"] = {"primaryLocationLineHash": line_hash}
    return r


def sarif(*found):
    return {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "CodeQL"}}, "results": list(found)}]}


# ── (a) the comparison ───────────────────────────────────────────────────────────────────────────────────────────────
KNOWN = finding("py/unused-import", "tests/test_x.py", 3, "aaaa:1")
REDOS = finding("js/polynomial-redos", "clients/js/src/permissions.ts", 40, "bbbb:1", "This regular expression ...")
TAG = finding("py/bad-tag-filter", "tests/test_y.py", 12, "cccc:1")

assert cs.new_findings([KNOWN], [[KNOWN]]) == [], "a finding of main counts as new"
moved = finding("py/unused-import", "tests/test_x.py", 90, "aaaa:1")
assert cs.new_findings([moved], [[KNOWN]]) == [], "the same line moved down counts as new (the hash is the line's)"
assert cs.new_findings([KNOWN, REDOS], [[KNOWN]]) == [REDOS], "js/polynomial-redos added by the sprint is not new"
assert cs.new_findings([TAG], [[KNOWN]]) == [TAG], "py/bad-tag-filter added by the sprint is not new"
assert cs.new_findings([KNOWN, KNOWN], [[KNOWN]]) == [KNOWN], "a second identical finding is not new (multiset)"
other_file = finding("py/unused-import", "tests/test_z.py", 3, "aaaa:1")
assert cs.new_findings([other_file], [[KNOWN]]) == [other_file], "the same line in another file counts as known"
other_rule = finding("py/side-effect-in-assert", "tests/test_x.py", 3, "aaaa:1")
assert cs.new_findings([other_rule], [[KNOWN]]) == [other_rule], "another rule on a known line counts as known"
# Union of the base analyses, not the sum: known once in each of two analyses is known once.
assert cs.new_findings([KNOWN], [[], [KNOWN]]) == [], "a finding only in the merge-base analysis counts as new"
assert cs.new_findings([KNOWN, KNOWN], [[KNOWN], [KNOWN]]) == [KNOWN], "two base analyses add up their counts"
# Without the line hash: rule, file and message.
bare = finding("py/x", "a.py", 1, None, "same text")
assert cs.new_findings([finding("py/x", "a.py", 7, None, "same text")], [[bare]]) == []
assert len(cs.new_findings([finding("py/x", "a.py", 1, None, "other text")], [[bare]])) == 1
print("  ✓ comparison: new, moved, duplicate, other file/rule, union of bases, no hash")


def run(head, *bases):
    with tempfile.TemporaryDirectory() as d:
        Path(d, "pr").mkdir()
        Path(d, "pr", "python.sarif").write_text(json.dumps(sarif(*head)), encoding="utf-8")
        args = ["--sarif", os.path.join(d, "pr")]
        for i, b in enumerate(bases):
            Path(d, f"base{i}.sarif").write_text(json.dumps(sarif(*b)), encoding="utf-8")
            args += ["--base", os.path.join(d, f"base{i}.sarif")]
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = cs.main(args)
        return code, out.getvalue()


code, out = run([KNOWN, REDOS], [KNOWN])
assert code == 1, f"a new finding must fail: {code}"
assert "NEW js/polynomial-redos  clients/js/src/permissions.ts:40" in out, out
assert "::error file=clients/js/src/permissions.ts,line=40,title=CodeQL js/polynomial-redos::" in out, out
assert "py/unused-import" not in out.split("new", 1)[1], f"the known finding is reported: {out}"
code, out = run([KNOWN], [KNOWN])
assert code == 0 and "0 new" in out, (code, out)
code, _ = run([], [])
assert code == 0, "an empty pull request against an empty main must be green"
saved = os.environ.pop("GITHUB_REPOSITORY", None)
try:
    code, _ = run([REDOS])
finally:
    if saved is not None:
        os.environ["GITHUB_REPOSITORY"] = saved
assert code == 2, "without anything to compare with the script must be red, not green"
print("  ✓ script: exit 1 with annotation on a new finding, 0 on known ones, 2 without a base")

# ── (b) which analyses of main ───────────────────────────────────────────────────────────────────────────────────────
ANALYSES = [
    {"id": 5, "category": "/language:python", "commit_sha": "c3", "created_at": "2026-11-28T03:00:00Z"},
    {"id": 4, "category": "/language:javascript-typescript", "commit_sha": "c3", "created_at": "2026-11-28T03:00:00Z"},
    {"id": 3, "category": "/language:python", "commit_sha": "c2", "created_at": "2026-11-27T03:00:00Z"},
    {"id": 1, "category": "/language:python", "commit_sha": "c1", "created_at": "2026-11-26T03:00:00Z"},
]
assert cs.pick_analyses(ANALYSES, "/language:python", "c2") == [5, 3], "newest plus merge base"
assert cs.pick_analyses(ANALYSES, "/language:python", "c3") == [5], "merge base = newest: once"
assert cs.pick_analyses(ANALYSES, "/language:python", "gone") == [5], "merge base not analysed: the newest"
assert cs.pick_analyses(ANALYSES, "/language:javascript-typescript", "c2") == [4], "another category leaks in"
assert cs.pick_analyses(ANALYSES, "/language:rust", "c2") == [], "no analysis of the category must give nothing"
print("  ✓ analyses of main: the newest of the category and the one at the merge base")

# ── (c) the workflow ─────────────────────────────────────────────────────────────────────────────────────────────────
WF = (ROOT / ".github/workflows/codeql.yml").read_text(encoding="utf-8")
body = WF.split("\njobs:\n", 1)[1]
parts = re.split(r"^  ([A-Za-z0-9_-]+):\s*$", body, flags=re.M)
JOBS = dict(zip(parts[1::2], parts[2::2]))
assert re.search(r"^  pull_request:\n(?:\s+#.*\n)*    branches: \[main, \"sprint/\*\"\]$", WF, re.M), \
    "codeql.yml: no pull_request trigger for main and sprint/*"
SPRINT_IF = "    if: ${{ startsWith(github.base_ref, 'sprint/') }}"
NOT_SPRINT_IF = "    if: ${{ !startsWith(github.base_ref, 'sprint/') }}"
sprint = JOBS["sprint"]
assert SPRINT_IF in sprint.splitlines(), "job `sprint` runs outside the sprint lane"
assert "upload: never" in sprint and "security-events: write" not in sprint, "job `sprint` uploads or may write"
assert "security-events: read" in sprint, "job `sprint` cannot read main's analyses"
assert "python3 scripts/_codeql_sprint.py --sarif sarif" in sprint, "job `sprint` does not compare"
assert "output: sarif\n" in sprint, "the comparison reads a directory the analysis does not write"
langs = re.findall(r"^\s+- language: (\S+)$", sprint, re.M)
assert langs == ["python", "javascript-typescript"], f"job `sprint` analyses {langs}"
assert "queries: security-and-quality" in sprint and "queries: security-and-quality" in JOBS["analyse"]
js_scope = re.search(r"config: \|\n\s+paths:\n\s+- (\S+)", JOBS["analyse-js"]).group(1)
assert f"- {js_scope}" in sprint, f"job `sprint` analyses other JavaScript than `analyse-js` ({js_scope})"
for name, text in JOBS.items():
    if name == "sprint":
        continue
    if "\n    needs:" in text:
        continue   # skips with the job it needs
    assert NOT_SPRINT_IF in text.splitlines(), f"codeql.yml job `{name}` runs in the sprint lane too"
print(f"  ✓ codeql.yml: `sprint` only in the sprint lane, no upload, read only; {len(JOBS) - 1} other jobs skip there")
