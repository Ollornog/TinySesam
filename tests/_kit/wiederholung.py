"""The nightly repeat run of a repo — built from the kit template and checked against it (since kit 0.59.0).

This file is copied here by `repokit sync` — do not edit by hand.

WHY (PO 2026-11-23): `ci-local` and "scripts/check.sh twice green" are no longer required before a push; the pre-push
hook runs only the fast checks, the full suite runs in the PR CI. Repeatability — the same commit gives the same answer
— is shown once a night instead: `.github/workflows/nightly-repeat.yml` calls the repo's CI workflow twice in a row on
the default branch and compares. One green and one red is a flaky test, and the run is red; the CI watch reports a red
run on the default branch like any other (topic per workflow name, closed by the next green run).

Opt-in per repo, like the auto-merge was: `repokit wiederholung <repo> [--suite ci.yml]` builds it, `repokit sync`
rebuilds an existing one (the cron line stays), and `pruefe()` (called from manifest.pruefe, so from every repo's
tests/test_repo.py) rebuilds it and compares. Without the workflow there is no finding: the CI workflow must offer
`workflow_call` first, which is the repo's own change.

Derived, not entered (one free value only, the cron line):
  - `runs-on` of the compare job: self-hosted if another workflow of the repo runs there (private), else
    ubuntu-latest (automerge.runner — public repos never run on own runners).
  - The permissions of the two calls: the union of every `permissions:` in the CI workflow. A called workflow may only
    lower what the caller grants; a job asking for more than the call grants does not start.
  - `secrets: inherit` only if the CI workflow names a secret other than GITHUB_TOKEN.
  - The time comment from the cron line (UTC; Europe/Berlin in winter and summer).

stdlib-only, no YAML parser: the workflow files are read line by line like in automerge.py.
"""
from __future__ import annotations

import os
import re
import zlib

WORKFLOW = ".github/workflows/nightly-repeat.yml"
VORLAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vorlage_wiederholung.yml.in")
ANFANG = "    # --- per repo: start\n"
ENDE = "    # --- per repo: end\n"
STANDARD_SUITE = "ci.yml"
# Daily only: "M H * * *". A weekly or monthly repeat would leave a flaky test unseen for days.
CRON = re.compile(r'^    - cron: "([0-5]?[0-9]) ([01]?[0-9]|2[0-3]) \* \* \*"$')
STUFE = {"none": 0, "read": 1, "write": 2}


def _lies(pfad: str) -> str | None:
    try:
        with open(pfad, encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return None


def _automerge():
    """automerge.py from the same folder (runner(), ausloeser(), _workflows()) — one source for the derivations."""
    import importlib.util
    pfad = os.path.join(os.path.dirname(os.path.abspath(__file__)), "automerge.py")
    spec = importlib.util.spec_from_file_location("_kit_automerge_fuer_wiederholung", pfad)
    modul = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def zeit_kommentar(minute: int, stunde: int) -> str:
    """The cron time in UTC and Europe/Berlin (CET = UTC+1 in winter, CEST = UTC+2 in summer)."""
    winter, sommer = (stunde + 1) % 24, (stunde + 2) % 24
    return (f"{stunde:02d}:{minute:02d} UTC = {winter:02d}:{minute:02d} Europe/Berlin in winter (CET, UTC+1), "
            f"{sommer:02d}:{minute:02d} in summer (CEST, UTC+2).")


def standard_cron(repo_name: str) -> str:
    """A start time between 01:00 and 01:59 UTC (02:xx/03:xx Berlin), the minute spread by the repo name so that the
    repos do not all queue for the runners at the same minute."""
    minute = zlib.crc32(repo_name.encode("utf-8")) % 60
    return f'    - cron: "{minute} 1 * * *"\n'


def rechte(text: str) -> tuple[str | None, dict[str, str]]:
    """Every `permissions:` of a workflow, joined: (scalar like read-all/write-all or None, scope -> highest level)."""
    skalar: str | None = None
    aus: dict[str, str] = {}

    def nimm(scope: str, stufe: str) -> None:
        scope, stufe = scope.strip().strip("\"'"), stufe.strip().strip("\"'")
        if stufe in STUFE and STUFE[stufe] > STUFE.get(aus.get(scope, "none"), 0):
            aus[scope] = stufe

    zeilen = text.split("\n")
    for i, z in enumerate(zeilen):
        m = re.match(r"^(\s*)permissions:\s*(.*?)\s*(?:#.*)?$", z)
        if not m:
            continue
        tiefe, rest = len(m.group(1)), m.group(2)
        if rest in ("read-all", "write-all"):
            if skalar != "write-all":
                skalar = rest
            continue
        if rest.startswith("{"):
            for teil in rest.strip("{}").split(","):
                if ":" in teil:
                    nimm(*teil.split(":", 1))
            continue
        if rest:
            continue
        for z2 in zeilen[i + 1:]:
            if not z2.strip() or z2.lstrip().startswith("#"):
                continue
            if len(z2) - len(z2.lstrip()) <= tiefe:
                break
            inhalt = re.sub(r"\s+#.*$", "", z2.strip())
            if ":" in inhalt:
                nimm(*inhalt.split(":", 1))
    return skalar, aus


def _rechte_zeilen(text: str) -> str:
    skalar, aus = rechte(text)
    if skalar:
        return f"    permissions: {skalar}\n"
    aus = {k: v for k, v in aus.items() if v != "none"} or {"contents": "read"}
    return "    permissions:\n" + "".join(f"      {k}: {aus[k]}\n" for k in sorted(aus))


def braucht_geheimnisse(text: str) -> bool:
    """Does the CI workflow use a secret other than GITHUB_TOKEN (outside comments)?"""
    for z in text.split("\n"):
        code = re.sub(r"(^|\s)#.*$", "", z)
        for name in re.findall(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)", code):
            if name != "GITHUB_TOKEN":
                return True
    return False


def je_repo_block(text: str) -> str | None:
    if ANFANG not in text or ENDE not in text:
        return None
    return text.split(ANFANG, 1)[1].split(ENDE, 1)[0]


def suite_aus(text: str) -> str | None:
    """Which CI workflow an existing nightly-repeat calls (the first `uses: ./.github/workflows/<file>`)."""
    m = re.search(r"^\s*uses:\s*\./\.github/workflows/([\w.-]+\.ya?ml)\s*$", text, re.M)
    return m.group(1) if m else None


def rendere(root: str, je_repo: str, suite: str) -> tuple[str, list[str]]:
    """Build the workflow for this repo. Returns (text, problems); problems are conditions without which the run would
    be silently wrong or would not start."""
    probleme: list[str] = []
    vorlage = _lies(VORLAGE)
    if vorlage is None:
        return "", [f"template missing: {VORLAGE}"]
    am = _automerge()
    wfs = {n: t for n, t in am._workflows(root).items() if n != os.path.basename(WORKFLOW)}
    zeilen = [z for z in je_repo.split("\n") if z.strip()]
    m = CRON.match(zeilen[0]) if len(zeilen) == 1 else None
    if not m:
        probleme.append('per repo block: exactly one line `    - cron: "M H * * *"` (daily, UTC) expected, found '
                        f"{len(zeilen)} line(s)")
        minute, stunde = 0, 1
    else:
        minute, stunde = int(m.group(1)), int(m.group(2))
    text_suite = wfs.get(suite)
    if text_suite is None:
        probleme.append(f"CI workflow {suite} does not exist (`repokit wiederholung --suite <file>`)")
        text_suite = ""
    elif "workflow_call" not in am.ausloeser(text_suite):
        probleme.append(f"{suite} has no `workflow_call` trigger — the nightly run cannot call it "
                        f"(add `workflow_call:` under `on:`)")
    geheim = "    secrets: inherit\n" if braucht_geheimnisse(text_suite) else ""
    text = (vorlage.replace("@@ZEIT@@", zeit_kommentar(minute, stunde))
            .replace("@@JE_REPO@@\n", je_repo if je_repo.endswith("\n") else je_repo + "\n")
            .replace("@@SUITE@@", suite)
            .replace("@@RECHTE@@\n", _rechte_zeilen(text_suite))
            .replace("@@SECRETS@@\n", geheim)
            .replace("@@RUNNER@@", am.runner(wfs)))
    return text, probleme


def baue(root: str, suite: str | None = None) -> tuple[str, list[str]]:
    """New or rebuilt workflow text: an existing file keeps its cron line and (without `suite`) its CI workflow."""
    alt = _lies(os.path.join(root, WORKFLOW))
    block = je_repo_block(alt) if alt else None
    if block is None:
        block = standard_cron(os.path.basename(os.path.abspath(root)))
    if suite is None:
        suite = (suite_aus(alt) if alt else None) or STANDARD_SUITE
    return rendere(root, block, suite)


def pruefe(root: str) -> list[str]:
    """Deviations of the nightly repeat run from the template; empty means "matches" or "not set up" (opt-in)."""
    text = _lies(os.path.join(root, WORKFLOW))
    if text is None:
        return []
    block = je_repo_block(text)
    if block is None:
        return [f"{WORKFLOW}: block “per repo: start/end” missing — not built from the template"]
    suite = suite_aus(text)
    if suite is None:
        return [f"{WORKFLOW}: no `uses: ./.github/workflows/<file>` — not built from the template"]
    soll, probleme = rendere(root, block, suite)
    fehler = [f"{WORKFLOW}: {p}" for p in probleme]
    if text != soll:
        ist_z, soll_z = text.split("\n"), soll.split("\n")
        for nr, (a, b) in enumerate(zip(ist_z, soll_z), 1):
            if a != b:
                fehler.append(f"{WORKFLOW}:{nr}: differs from the template — is `{a.strip()}`, should be "
                              f"`{b.strip()}` (`repokit wiederholung` rebuilds it)")
                break
        else:
            fehler.append(f"{WORKFLOW}: length differs from the template ({len(ist_z)} instead of {len(soll_z)} lines)")
    return fehler
