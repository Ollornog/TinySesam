"""SECURITY.md against the code and the CI (H1).

Until H1 both SECURITY.md said TOTP secrets were stored unencrypted — wrong since 0.21.0, and nothing noticed. Checked:

  (a) en + de describe the vault as built: AES-256-GCM, the key variable and file of `vault.py`, the gate key as a key
      of its own (ADR-12, no longer derived from it); neither claims the secrets are unencrypted or unrotatable
  (b) the deadlines for vulnerable dependencies are named, and the image scan in release.yml enforces what they say
      (fixable findings from "high", exceptions only via .grype.yaml, checked before the scan)
  (c) scripts/_grype_exceptions.py: a rule without an end, an expired one and one too far ahead are each refused;
      the shipped .grype.yaml is well-formed
"""
from __future__ import annotations

import datetime as dt
import re
import sys
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
ok("deadlines named (en/de); image scan: fixable ≥ high fails, exceptions from .grype.yaml checked before the scan")

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
ok(f"_grype_exceptions: no end / expired / > 31 days each refused; .grype.yaml well-formed ({n_rules} rule(s))")

print("\nSECURITY DOC OK ✅")
