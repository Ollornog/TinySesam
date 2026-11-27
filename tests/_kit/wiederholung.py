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

Only when needed (0.60.0): the scheduled run starts the two passes only if the default branch has a commit the last
green nightly-repeat run did not see (job `gate` in the template); started by hand it always runs.

Since 0.60.0 `fallen()` also reads the CALLED CI workflow. With `workflow_call` the github context belongs to the
caller: `github.event_name` is `schedule` (or `workflow_dispatch` by hand) and `github.workflow` is `nightly-repeat`.
So a job that publishes (docker push, release, pages, fc-pin, uploads) and runs on those events publishes twice
(finding = error), and a job that tests but is skipped on those events is silently missing from the repeat (warning).
The way out for both is a `github.workflow == 'nightly-repeat'` term in the `if:` (README, "Called by nightly-repeat").

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


# ---- the called CI workflow: what happens when nightly-repeat calls it (since 0.60.0)
# Markers of a step that publishes or deploys something outside the run. `actions/upload-artifact` is no marker:
# two runs leave two artifacts, nothing is overwritten or published twice.
VEROEFFENTLICHT = re.compile(
    r"docker\s+(?:image\s+)?push\b|docker/build-push-action|\bgh\s+release\b|action-gh-release|upload-release-asset"
    r"|deploy-pages|upload-pages-artifact|\bfc-pin\b|\btwine\s+upload|pypi-publish|\bnpm\s+publish|\bcargo\s+publish")
NACHTLAUF_NAME = "nightly-repeat"
EREIGNISSE_NACHTS = ("schedule", "workflow_dispatch")   # what the caller's github.event_name can be


def _ohne_kommentar(zeile: str) -> str:
    return re.sub(r"(^|\s)#.*$", "", zeile).rstrip()


def _veroeffentlicht(text: str) -> bool:
    return bool(VEROEFFENTLICHT.search(text)) and not re.search(r"push:\s*false\b", text)


def _token(ausdruck: str) -> list[str]:
    return re.findall(r"'[^']*'|\"[^\"]*\"|&&|\|\||==|!=|[()!,]|[^\s()!,=&|]+", ausdruck)


def auswerten(ausdruck: str, ereignis: str, workflow: str) -> bool | None:
    """Three-valued evaluation of an `if:` expression: True / False, or None where it depends on something unknown
    (branch, needs, vars). Known: github.event_name, github.workflow, always()/success() (true), cancelled()/failure()
    (false). Without a condition the job runs (True)."""
    ausdruck = ausdruck.strip()
    m = re.fullmatch(r"\$\{\{(.*)\}\}", ausdruck, re.S)
    if m:
        ausdruck = m.group(1)
    if not ausdruck.strip():
        return True
    tok = _token(ausdruck)
    pos = 0

    def kopf() -> str | None:
        return tok[pos] if pos < len(tok) else None

    def und_oder(werte: list, op: str):
        if op == "&&":
            return False if False in werte else (None if None in werte else True)
        return True if True in werte else (None if None in werte else False)

    def oder():
        nonlocal pos
        werte = [und()]
        while kopf() == "||":
            pos += 1
            werte.append(und())
        return und_oder(werte, "||")

    def und():
        nonlocal pos
        werte = [nicht()]
        while kopf() == "&&":
            pos += 1
            werte.append(nicht())
        return und_oder(werte, "&&")

    def nicht():
        nonlocal pos
        if kopf() == "!":
            pos += 1
            w = nicht()
            return None if w is None else (not w)
        return vergleich()

    def operand():
        nonlocal pos
        a = kopf()
        pos += 1
        if a is None:
            return None
        if a == "(":
            w = oder()
            if kopf() == ")":
                pos += 1
            return w
        if a[0] in "'\"":
            return ("text", a[1:-1])
        if kopf() == "(":                     # function call: skip the arguments, balanced
            tiefe = 0
            while kopf() is not None:
                tiefe += (kopf() == "(") - (kopf() == ")")
                pos += 1
                if tiefe == 0:
                    break
            return {"always": True, "success": True, "cancelled": False, "failure": False}.get(a.split("(")[0], None)
        if a == "github.event_name":
            return ("text", ereignis)
        if a == "github.workflow":
            return ("text", workflow)
        if a in ("true", "false"):
            return a == "true"
        return None

    def vergleich():
        nonlocal pos
        links = operand()
        if kopf() in ("==", "!="):
            op = kopf()
            pos += 1
            rechts = operand()
            if not (isinstance(links, tuple) and isinstance(rechts, tuple)):
                return None
            gleich = links[1].lower() == rechts[1].lower()
            return gleich if op == "==" else not gleich
        return links if isinstance(links, bool) or links is None else None

    try:
        return oder()
    except (IndexError, TypeError):           # an expression we do not understand is "unknown", never a finding
        return None


def _einheiten(text: str) -> list[dict]:
    """The units of the CI workflow that can publish: every step, or the whole job where it has no steps.
    Returns dicts: job, name, bedingung (job `if` AND step `if`, as a list of the two strings), text (without comments)."""
    zeilen = [_ohne_kommentar(z) for z in text.split("\n")]
    jobs: list[tuple[str, list[str]]] = []
    in_jobs, aktuell = False, None
    for z in zeilen:
        if re.match(r"^jobs:\s*$", z):
            in_jobs = True
            continue
        if in_jobs:
            if z and not z.startswith(" "):
                in_jobs = False
                continue
            m = re.match(r"^  ([\w-]+):\s*$", z)
            if m:
                aktuell = (m.group(1), [])
                jobs.append(aktuell)
            elif aktuell is not None:
                aktuell[1].append(z)

    def wert_von_if(block: list[str], tiefe: int) -> str:
        for i, z in enumerate(block):
            m = re.match(rf"^\s{{{tiefe}}}(?:- )?if:\s*(.*)$", z)
            if m:
                rest = m.group(1).strip()
                if rest in ("", ">", "|", ">-", "|-", ">+", "|+"):      # block scalar: the deeper lines
                    teil = []
                    for z2 in block[i + 1:]:
                        if z2.strip() and len(z2) - len(z2.lstrip()) <= tiefe:
                            break
                        teil.append(z2.strip())
                    return " ".join(t for t in teil if t)
                return rest
        return ""

    aus: list[dict] = []
    for name, block in jobs:
        job_if = wert_von_if(block, 4)
        schritte: list[list[str]] = []
        in_steps = False
        for z in block:
            if re.match(r"^    steps:\s*$", z):
                in_steps = True
                continue
            if in_steps:
                if re.match(r"^    \S", z):
                    in_steps = False
                elif re.match(r"^      - ", z):
                    schritte.append([z])
                elif schritte:
                    schritte[-1].append(z)
        if not schritte:
            aus.append({"job": name, "name": name, "ifs": [job_if], "text": "\n".join(block)})
        for s in schritte:
            m = re.search(r"^\s*(?:- )?name:\s*(.+)$", "\n".join(s), re.M)
            aus.append({"job": name, "name": (m.group(1).strip() if m else re.sub(r"^\s*-\s*", "", s[0])), "text": "\n".join(s),
                        "ifs": [job_if, wert_von_if([s[0].replace("- ", "  ", 1)] + s[1:], 8)]})
    return aus


def _bedingung(ifs: list[str], ereignis: str, workflow: str) -> bool | None:
    werte = [auswerten(i, ereignis, workflow) for i in ifs]
    return False if False in werte else (None if None in werte else True)


def fallen(text: str) -> tuple[list[str], list[str]]:
    """What happens when nightly-repeat calls this CI workflow. Returns (errors, warnings), both worded for the CI log.

    (a) error: a step that publishes/deploys (VEROEFFENTLICHT) is not certain to be skipped when the caller's
        `github.event_name` is schedule or workflow_dispatch, its `if` names `github.event_name` or `github.ref`,
        and nothing in its conditions names `github.workflow` → published a second time by the nightly run.
    (b) warning: a step that does not publish is skipped on schedule although it runs on push or pull_request →
        missing from the repeat.
    """
    fehler: list[str] = []
    warnungen: list[str] = []
    gemeldet: set[str] = set()      # jobs already reported as a whole
    einheiten = _einheiten(text)
    # A job with a publishing step is meant to be skipped in the nightly run (only the error case (a) applies).
    veroeffentlichend = {e["job"] for e in einheiten if _veroeffentlicht(e["text"])}
    for e in einheiten:
        ort = f"job `{e['job']}`" + ("" if e["name"] == e["job"] else f", step `{e['name']}`")
        bed = " ".join(i for i in e["ifs"] if i)
        garde = "github.workflow" in bed
        if _veroeffentlicht(e["text"]):
            wo = [ev for ev in EREIGNISSE_NACHTS if _bedingung(e["ifs"], ev, NACHTLAUF_NAME) is not False]
            if wo and not garde and ("github.event_name" in bed or "github.ref" in bed):
                fehler.append(f"{ort} publishes or deploys and is not skipped when the caller's `github.event_name` is "
                              f"{' or '.join(wo)}: called by nightly-repeat it would publish a second time. Guard it "
                              f"with `github.workflow != 'nightly-repeat'` in the `if:`")
            continue
        if e["job"] in veroeffentlichend:
            continue
        job_aus = _bedingung(e["ifs"][:1], "schedule", NACHTLAUF_NAME) is False
        if job_aus and e["job"] in gemeldet:
            continue
        if (_bedingung(e["ifs"], "schedule", NACHTLAUF_NAME) is False
                and (_bedingung(e["ifs"], "push", "ci") is not False
                     or _bedingung(e["ifs"], "pull_request", "ci") is not False)):
            if job_aus:
                gemeldet.add(e["job"])
                ort = f"job `{e['job']}`"
            warnungen.append(f"{ort} is skipped when nightly-repeat calls this workflow (`github.event_name` is "
                             f"schedule there): the repeat does not run it. Add "
                             f"`|| github.workflow == 'nightly-repeat'` to its `if:` if it should run")
    return fehler, warnungen


def warnungen(root: str, suite: str | None = None) -> list[str]:
    """Warnings about the CI workflow that nightly-repeat calls (empty without nightly-repeat; never a failure)."""
    text = _lies(os.path.join(root, WORKFLOW))
    if text is None:
        return []
    suite = suite or suite_aus(text) or STANDARD_SUITE
    ci = _lies(os.path.join(root, ".github", "workflows", suite))
    return [f"{suite}: {w}" for w in fallen(ci)[1]] if ci else []


def je_repo_block(text: str) -> str | None:
    if ANFANG not in text or ENDE not in text:
        return None
    return text.split(ANFANG, 1)[1].split(ENDE, 1)[0]


def suite_aus(text: str) -> str | None:
    """Which CI workflow an existing nightly-repeat calls (the first `uses: ./.github/workflows/<file>`)."""
    m = re.search(r"^\s*uses:\s*\./\.github/workflows/([\w.-]+\.ya?ml)\s*(?:#.*)?$", text, re.M)
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
    probleme.extend(f"{suite}: {f}" for f in fallen(text_suite)[0])
    geheim = "    secrets: inherit\n" if braucht_geheimnisse(text_suite) else ""
    text = (vorlage.replace("@@ZEIT@@", zeit_kommentar(minute, stunde))
            .replace("@@JE_REPO@@\n", je_repo if je_repo.endswith("\n") else je_repo + "\n")
            .replace("@@SUITE@@", suite)
            .replace("@@RECHTE@@\n", _rechte_zeilen(text_suite))
            .replace("@@SECRETS@@\n", geheim)
            .replace("@@RUNNER@@", am.runner(wfs))
            .replace("@@LASTVERMERK@@\n", am.lastvermerk_schritt(probleme)))
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
