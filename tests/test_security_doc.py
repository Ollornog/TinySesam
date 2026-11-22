"""SECURITY.md against the code and the CI (H1).

Until H1 both SECURITY.md said TOTP secrets were stored unencrypted — wrong since 0.21.0, and nothing noticed. Checked:

  (a) en + de describe the vault as built: AES-256-GCM, the key variable and file of `vault.py`, the gate key as a key
      of its own (ADR-12, no longer derived from it); neither claims the secrets are unencrypted or unrotatable
  (b) the deadlines for vulnerable dependencies are named, and the image scan in release.yml enforces what they say
      (fixable findings from "high", exceptions only via .grype.yaml, checked before the scan)
  (c) scripts/_grype_exceptions.py: a rule without an end, an expired one and one too far ahead are each refused;
      the shipped .grype.yaml is well-formed
  (d) … --report, after both image scans: a rule that matches nothing in any report is refused (T-59)
"""
from __future__ import annotations

import contextlib
import datetime as dt
import io
import json
import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from tinysesam import vault  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


EN = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
DE = (ROOT / "i18n" / "SECURITY.de.md").read_text(encoding="utf-8")

# ---------- (a) the vault as built ----------
assert vault.PREFIX == "v1:" and vault.ENV_VAR == "TINYSESAM_SECRETS_KEY"
vault_src = (ROOT / "tinysesam" / "vault.py").read_text(encoding="utf-8")
assert "AES-256-GCM" in vault_src and "AESGCM" in vault_src
for name, text in (("SECURITY.md", EN), ("SECURITY.de.md", DE)):
    for must in ("AES-256-GCM", vault.ENV_VAR, "secrets_key_file", "<db>.key", "0.21.0", "ADR-9", "ADR-12",
                 "TINYSESAM_GATE_KEY", "tinysesam keys rotate"):
        assert must in text, f"{name}: {must!r} missing"
    flat = " ".join(text.split()).lower()
    for wrong in ("stored unencrypted", "liegen unverschlüsselt", "is planned (t-13", "ist geplant (t-13",
                  "same key derives the signing key", "aus demselben schlüssel entsteht", "rotation) does not exist",
                  "rotation) gibt es noch nicht"):
        assert wrong not in flat, f"{name} still says {wrong!r}"
ok("SECURITY.md en/de: vault as built (AES-256-GCM, TINYSESAM_SECRETS_KEY, <db>.key, own gate key, rotation), "
   "no 'unencrypted', no 'derived', no 'no rotation'")

# ---------- (b) deadlines ↔ the image scan ----------
assert re.search(r"\| Critical \| \*\*7 days\*\* \|", EN) and re.search(r"\| High \| \*\*30 days\*\* \|", EN)
assert re.search(r"\| Kritisch \| \*\*7 Tage\*\* \|", DE) and re.search(r"\| Hoch \| \*\*30 Tage\*\* \|", DE)
release = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
probe = release.split("\n  image-probe:\n", 1)[1].split("\n  image:\n", 1)[0]
steps = probe.split("\n      - ")
i_exc = next(i for i, s in enumerate(steps) if "scripts/_grype_exceptions.py" in s)
i_scan = next(i for i, s in enumerate(steps) if "anchore/scan-action@" in s)
assert i_exc < i_scan, "the exceptions must be checked BEFORE the scan"
scan = steps[i_scan]
for must in ("image: tinysesam-probe:local", "fail-build: true", "severity-cutoff: high", "only-fixed: true",
             "config: .grype.yaml"):
    assert must in scan, f"release.yml image scan without {must!r}"
assert re.search(r"anchore/scan-action@[0-9a-f]{40}\b", scan), "scan-action not pinned by SHA"
assert "continue-on-error" not in probe
# Both images are scanned in every run: a red gateway step must not skip the Caddy build and scan (2026-11-22: the job
# then reported only "no report from ['(empty)']"). Each Caddy step runs unless the run was cancelled; the scan needs
# its own build. The job stays red through the failed step itself — no continue-on-error (above).
caddy_build = next(s for s in steps if 'name: "Caddy image: build' in s)
caddy_scan = next(s for s in steps if 'name: "Caddy image: scan' in s)
assert re.search(r"^\s*if: \$\{\{ !cancelled\(\) \}\}$", caddy_build, re.M) and "id: build-caddy" in caddy_build, \
    "the Caddy build is skipped when a gateway step is red"
assert "if: ${{ !cancelled() && steps.build-caddy.outcome == 'success' }}" in caddy_scan, \
    "the Caddy scan is skipped when a gateway step is red, or runs without its build"
assert "if: always()" in next(s for s in steps if "--report" in s), "the report step must run after a red scan"
ok("deadlines named (en/de); image scan: fixable ≥ high fails, exceptions from .grype.yaml checked before the scan; "
   "the Caddy image is built and scanned also after a red gateway step")

# ---------- (c) the exception check ----------
import _grype_exceptions as ge  # noqa: E402

today = dt.date(2026, 11, 20)
rule = '''ignore:
  - vulnerability: CVE-1
    package:
      name: x
    reason: "until {d}: because"
'''
assert ge.problems(rule.format(d="2026-12-07"), today) == []
assert ge.problems(rule.format(d="2026-11-20"), today) == []
assert "expired" in ge.problems(rule.format(d="2026-11-19"), today)[0]
assert "more than 31 days" in ge.problems(rule.format(d="2026-12-22"), today)[0]
assert "without 'until" in ge.problems(rule.replace('"until {d}: because"', '"because"'), today)[0]
assert ge.problems("# nothing excepted\nignore: []\n", today) == []
shipped = (ROOT / ".grype.yaml").read_text(encoding="utf-8")
n_rules = len(re.findall(r"^  - vulnerability:", shipped, re.M))
until = [dt.date.fromisoformat(d) for d in re.findall(r'reason:\s*"until (\d{4}-\d{2}-\d{2}):', shipped)]
assert len(until) == n_rules, "a rule in .grype.yaml without 'until YYYY-MM-DD:'"
# Form only: the date itself is the CI's business (a suite that turns red by the calendar would block unrelated work).
assert all(not ge.problems(shipped, d) for d in until), "a shipped exception is malformed or reaches too far"
# The deadline works through the command the CI runs (`--today` feeds the clock): the last valid day is green, the
# next one red — for every shipped rule, measured on the file itself.
if until:
    with contextlib.redirect_stdout(io.StringIO()) as _cli:
        assert ge.main(["--today", min(until).isoformat()]) == 0, "a shipped exception is refused on its last day"
        assert ge.main(["--today", (max(until) + dt.timedelta(days=1)).isoformat()]) == 1, \
            "an expired exception does not turn the check red"
    assert "expired" in _cli.getvalue()
ok(f"_grype_exceptions: no end / expired / > 31 days each refused; .grype.yaml well-formed ({n_rules} rule(s)); "
   "the CLI is red the day after the deadline")

# ---------- (d) no exception that matches nothing (T-59) ----------
# After the scans: a rule that no ignored match in any report names has outlived its reason. The zlib rule for
# python:3.15-slim would have stayed until its date after the image moved to distroless.
def _report(*applied):
    return {"matches": [], "ignoredMatches": [{"appliedIgnoreRules": list(applied)}]}


_hit = {"vulnerability": "CVE-1", "package": {"name": "x"}}
_ok_rule = rule.format(d="2026-12-07")
assert ge.unmatched(_ok_rule, [_report(_hit)]) == []
assert ge.unmatched(_ok_rule, [_report(), _report(_hit)]) == [], "a rule needs a match in ONE of the reports"
assert "matches nothing" in ge.unmatched(_ok_rule, [_report({"namespace": "", "fix-state": "not-fixed"})])[0]
assert ge.unmatched(_ok_rule, [_report({"vulnerability": "CVE-1", "package": {"name": "y"}})]), \
    "the same CVE in a different package is not the excepted finding"
assert ge.unmatched("ignore: []\n", [_report(_hit)]) == []
with tempfile.TemporaryDirectory() as _d:
    _p = Path(_d, "r.json")
    _p.write_text(json.dumps(_report()), encoding="utf-8")
    with contextlib.redirect_stdout(io.StringIO()) as _out:
        assert ge.after_scans(_ok_rule, [str(_p)]) == 1
        assert ge.after_scans(_ok_rule, [str(_p), ""]) == 1, "a missing report is not 'nothing unmatched'"
        assert ge.after_scans("ignore: []\n", [str(_p)]) == 0
    assert "no report from" in _out.getvalue()
# Wired: after BOTH scans, also when one is red, with the JSON report of each.
i_after = next(i for i, s in enumerate(steps) if "--report" in s)
scans = [i for i, s in enumerate(steps) if "anchore/scan-action@" in s]
assert len(scans) == 2 and i_after > max(scans), "the exception check does not run after both scans"
assert "if: always()" in steps[i_after], "the exception check is skipped when a scan is red"
for i in scans:
    _id = re.search(r"^\s+id: (\S+)", steps[i], re.M)
    assert _id and "output-format: json" in steps[i], f"scan step {i} without id or JSON report"
    assert f"steps.{_id.group(1)}.outputs.json" in steps[i_after], f"the report of {_id.group(1)} is not checked"
ok("_grype_exceptions --report: a rule without a match in any image is refused, a missing report too; "
   "runs after both scans with always()")

print("\nSECURITY DOC OK ✅")
