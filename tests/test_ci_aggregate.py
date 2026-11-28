"""The branch protection names one aggregate job per workflow, not the legs of a matrix (T-115); the sprint lane (T-131).

A required check carries the name of a matrix leg (`full (3.14)`, `test (php 8.4)`); dropping or adding a release then
blocks every merge until someone edits the protection. The aggregate job (`suite-ok`, `client-go-ok` …) needs every
other job of its workflow, runs `always()` and is red unless every one of them succeeded — cancelled and failed count as
not green, skipped only in the sprint or text lane.

Sprint lane (T-131): a pull request into `sprint/<name>` runs only the fast checks; the full suite runs once in the
closing pull request into main. Every workflow with heavy jobs has a job `classify` that asks the shared kit's
`scripts/_nur_text.sh` and answers `nur_text=ja`; the heavy jobs skip on that answer (the kit's fail-safe form, checked
by `hygiene.pruefe_nur_text` in `tests/test_repo.py`), every job after them skips with them. The script of `classify` is
run here against a throwaway repository with a pull request's merge commit, the aggregate's script against the results
it must turn green or red.
"""
import json
import os
import pathlib
import re
import shutil
import subprocess
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = {  # workflow file → (aggregate job, the jobs it needs: every job with a matrix; ci.yml has other required jobs)
    "ci.yml": ("suite-ok", ["classify", "full"]),
    "client-go.yml": ("client-go-ok", None),
    "client-js.yml": ("client-js-ok", None),
    "client-php.yml": ("client-php-ok", None),
    "client-rust.yml": ("client-rust-ok", None),
}
# Workflows of the sprint lane → jobs that run on a pull request although the lane skips the rest, with the reason.
# Every other job is either gated on `classify` or needs a job that is (it skips with it).
LANE = {
    "ci.yml": {"repeat": "runs scripts/check.sh, whose hygiene runs the fast checks of the sprint lane"},
    "client-go.yml": {},
    "client-js.yml": {},
    "client-php.yml": {},
    "client-rust.yml": {},
    "audit.yml": {},
    "release.yml": {"automatik": "release automation, workflow_dispatch only"},
}
GATE = "${{ !cancelled() && needs.classify.outputs.nur_text != 'ja'"
# The browser suites have a classifier of their own in ci.yml (scope `browser` of scripts/_client_scope.sh), and since
# T-107 an aggregate of their own: the required check `browser` over the matrix `browser-suite`.
BROWSER_AGG = {"ci.yml": "browser"}
BROWSER_GATE = "${{ !cancelled() && needs.classify-browser.outputs.nur_text != 'ja' }}"


def jobs_of(text):
    """{job id: its text} — the jobs sit two spaces deep under the top-level `jobs:`."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\s*$", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


def without_comments(job):
    return "\n".join(z for z in job.splitlines() if z.strip() and not z.lstrip().startswith("#"))


def needs_of(job):
    m = re.search(r"^    needs: (?:\[([^\]]*)\]|([A-Za-z0-9_-]+))\s*$", job, re.M)
    if not m:
        return []
    return [x.strip() for x in (m.group(1) or m.group(2)).split(",") if x.strip()]


def if_of(job):
    m = re.search(r"^    if: (.+(?:\n      .+)*)", job, re.M)
    return " ".join(m.group(1).split()) if m else ""


def step_script(job, step_name):
    """The `run: |` block of the step `- name: <step_name>` (dedented), and the env names of that step."""
    lines = job.splitlines()
    start = next(i for i, z in enumerate(lines) if z.strip().startswith(f"- name: {step_name}"))
    env, script, i = [], [], start + 1
    while i < len(lines) and not lines[i].strip().startswith("- "):
        z = lines[i]
        m = re.match(r"^          ([A-Z_]+): ", z)
        if m:
            env.append(m.group(1))
        if z.strip() == "run: |":
            i += 1
            while i < len(lines) and (lines[i].startswith("          ") or not lines[i].strip()):
                script.append(lines[i][10:])
                i += 1
            break
        i += 1
    assert script, f"step {step_name!r}: no `run: |` block"
    return "\n".join(script) + "\n", env


texts = {wf: (ROOT / ".github/workflows" / wf).read_text(encoding="utf-8") for wf in set(WORKFLOWS) | set(LANE)}

# ── Aggregate jobs ───────────────────────────────────────────────────────────────────────────────────────────────────
for wf, (agg, expected) in WORKFLOWS.items():
    jobs = jobs_of(texts[wf])
    assert agg in jobs, f"{wf}: aggregate job `{agg}` missing"
    text = jobs[agg]
    others = expected or sorted(j for j in jobs if j != agg)
    m = re.search(r"^    needs: \[([^\]]*)\]\s*$", text, re.M)
    assert m, f"{wf}/{agg}: `needs: [...]` missing"
    needed = sorted(x.strip() for x in m.group(1).split(","))
    assert needed == sorted(others), f"{wf}/{agg}: needs {needed}, but expected {sorted(others)}"
    assert re.search(r"^    if: \$\{\{ always\(\) \}\}\s*$", text, re.M), \
        f"{wf}/{agg}: without `if: ${{{{ always() }}}}` the job is skipped when a leg fails — a skipped required check hangs"
    assert re.search(rf"^    name: {re.escape(agg)}\s*$", text, re.M), f"{wf}/{agg}: the check name must be `{agg}`"
    assert "continue-on-error" not in text, f"{wf}/{agg}: a check that cannot turn red checks nothing"
    print(f"  {wf}: `{agg}` needs {', '.join(needed)}, runs always()")

# The aggregate's script, run: the verdict for every combination that matters. Every workflow carries the same script.
agg_scripts = {wf: step_script(jobs_of(texts[wf])[agg], "Every job it needs succeeded") for wf, (agg, _) in WORKFLOWS.items()}
script, env_names = agg_scripts["ci.yml"]
for wf, got in agg_scripts.items():
    assert got == (script, env_names), f"{wf}: the aggregate's step differs from the one in ci.yml"
assert env_names == ["NEEDS", "LANE_ANSWER"], f"aggregate: env {env_names}, expected NEEDS and LANE_ANSWER"
assert "LANE_ANSWER: ${{ needs.classify.outputs.nur_text }}" in jobs_of(texts["ci.yml"])["suite-ok"], \
    "suite-ok: LANE_ANSWER must be the answer of `classify`"
assert shutil.which("jq") and shutil.which("bash"), "jq and bash are needed to run the aggregate's script (GitHub's runners carry both)"

# T-107: the browser suites run as a matrix (`browser-suite`, one leg per suite); the required check `browser` is its
# aggregate — the same rules and the same script, with the answer of `classify-browser` instead of `classify`.
_ci_jobs = jobs_of(texts["ci.yml"])
_b = _ci_jobs[BROWSER_AGG["ci.yml"]]
assert needs_of(_b) == ["classify-browser", "browser-suite"], f"browser: needs {needs_of(_b)}"
assert re.search(r"^    if: \$\{\{ always\(\) \}\}\s*$", _b, re.M), "browser: without always() a failed leg leaves it skipped"
assert re.search(r"^    name: browser\s*$", _b, re.M) and "continue-on-error" not in _b, "browser: the check name"
assert "strategy:" in _ci_jobs["browser-suite"] and "fail-fast: false" in _ci_jobs["browser-suite"], \
    "browser-suite: a matrix whose legs all run"
assert "LANE_ANSWER: ${{ needs.classify-browser.outputs.nur_text }}" in _b, "browser: LANE_ANSWER of classify-browser"
_bscript, _benv = step_script(_b, "Every job it needs succeeded")
assert _benv == env_names and _bscript.rstrip() == script.replace('del(.classify)', 'del(.["classify-browser"])') \
    .replace('echo "classify: nur_text', 'echo "classify-browser: nur_text').rstrip(), "browser: the aggregate's step differs"
print("  ci.yml: `browser` aggregates the matrix browser-suite (classify-browser), runs always(), the same script")


def verdict(results, lane):
    needs = {k: {"result": v, "outputs": {}} for k, v in results.items()}
    run = subprocess.run(["bash", "-c", script], env={"PATH": os.environ["PATH"], "NEEDS": json.dumps(needs),
                                                     "LANE_ANSWER": lane}, capture_output=True, text=True, timeout=30)
    return run.returncode == 0


CASES = [  # (results of the needed jobs, answer of classify, green?)
    ({"classify": "success", "full": "success"}, "", True),                # full suite, all green
    ({"classify": "success", "full": "skipped"}, "ja", True),              # sprint lane / text only
    ({"classify": "success", "full": "skipped"}, "", False),               # skipped without the lane: never green
    ({"classify": "success", "full": "failure"}, "ja", False),             # a failure stays red in any lane
    ({"classify": "success", "full": "cancelled"}, "ja", False),
    ({"classify": "failure", "full": "success"}, "", True),                # broken classifier: the job ran and decides
    ({"classify": "failure", "full": "failure"}, "", False),
    ({"classify": "success", "full": "success", "image": "skipped"}, "no", False),
]
for results, lane, green in CASES:
    assert verdict(results, lane) is green, f"aggregate: {results} with nur_text={lane!r} must be {'green' if green else 'red'}"
print(f"  aggregate script: {len(CASES)} combinations, skipped is green only with nur_text=ja")

# ── Sprint lane: every heavy job gated, everything after it follows ──────────────────────────────────────────────────
classify_ci = jobs_of(texts["ci.yml"])["classify"]
for wf, exempt in LANE.items():
    jobs = jobs_of(texts[wf])
    assert "classify" in jobs, f"{wf}: job `classify` missing (T-131)"
    assert without_comments(jobs["classify"]) == without_comments(classify_ci), \
        f"{wf}: job `classify` differs from the one in ci.yml"
    agg = WORKFLOWS.get(wf, (None,))[0]
    gated = {j for j, t in jobs.items() if GATE in if_of(t)}
    browser_gated = {j for j, t in jobs.items() if if_of(t) == BROWSER_GATE}
    if wf == "ci.yml":
        assert browser_gated == {"browser-suite"} and needs_of(jobs["browser-suite"]) == ["classify-browser"], \
            browser_gated
    else:
        assert not browser_gated and "classify-browser" not in jobs, f"{wf}: classify-browser belongs to ci.yml"
    for j in gated:
        cond = if_of(jobs[j])
        assert "classify" in needs_of(jobs[j]), f"{wf}/{j}: gated on classify without `needs: classify`"
        assert cond == GATE + " }}" or (cond.startswith(GATE + " && (") and cond.endswith(") }}")), \
            f"{wf}/{j}: `if: {cond}` — an older condition goes only behind the gate, in brackets"
    # Jobs that follow a gated job: skipped with it — unless their `if` runs them anyway, then they must ask for success.
    follows = set(gated)
    changed = True
    while changed:
        changed = False
        for j, t in jobs.items():
            if j in follows or j in ("classify", "classify-browser", agg, BROWSER_AGG.get(wf)) or j in exempt \
                    or j in browser_gated:
                continue
            before = [n for n in needs_of(t) if n in follows]
            if not before:
                continue
            cond = if_of(t)
            if "always()" in cond or "!cancelled()" in cond or "failure()" in cond:
                assert any(f"needs.{n}.result == 'success'" in cond for n in before), \
                    f"{wf}/{j}: its `if` runs it when {before} skipped — ask for `needs.<job>.result == 'success'`"
            follows.add(j)
            changed = True
    rest = sorted(set(jobs) - follows - {"classify", "classify-browser", agg, BROWSER_AGG.get(wf)} - set(exempt)
                  - browser_gated)
    assert not rest, f"{wf}: {rest} run in the sprint lane — gate them on classify or name the reason in LANE"
    for j in exempt:
        assert j in jobs, f"{wf}: LANE names `{j}`, which is not a job"
        assert j not in follows, f"{wf}/{j}: gated, but LANE names it as running in the sprint lane"
    print(f"  {wf}: gated {', '.join(sorted(gated))}; {len(follows) - len(gated)} job(s) follow; runs anyway: "
          f"{', '.join(exempt) or 'nothing'}")

# ── Required checks of a called workflow: they must report in the lane too ───────────────────────────────────────────
# A job that calls a reusable workflow (`uses:` at job level) produces the checks `<caller> / <inner job>`. When the
# caller is SKIPPED, GitHub reports only `<caller>` and never the inner checks — a required `provenance / rebuild` then
# hangs for good, the pull request stays blocked although everything is green (#395, a backlog-only pull request into
# main after T-131). A skipped ordinary job does report "skipped" (green). So in every required workflow (the list the
# auto-merge waits for, in dependabot-auto-merge.yml) a caller must run whenever the lane skips the jobs it needs, and hand the
# lane on as `skip`; the called workflow's jobs without `needs` skip by their OWN `if: !inputs.skip`. The caller sees
# the lane in the `skipped` of a job it needs that carries exactly the lane's gate (that job skips only in the lane;
# the kit allows `outputs.nur_text` in an `if:` only in the gate's form). For a tag `skip` is false whatever the
# classifier answers. (Mutation probes: the old caller `needs: [build, checksums]` without `if:`; drop the `if:` of
# `rebuild`; drop `github.ref_type != 'tag'` from `skip`; drop the success of `checksums` → each red.)
CALLER_IF = "${{ !cancelled() && ("
SKIP_INPUT = "skip: ${{ github.ref_type != 'tag' && needs.classify.outputs.nur_text == 'ja' }}"
_am = (ROOT / ".github/workflows/dependabot-auto-merge.yml").read_text(encoding="utf-8")
_m = re.search(r'PFLICHT_WORKFLOWS: "([^"]+)"', _am)
assert _m, "dependabot-auto-merge.yml: PFLICHT_WORKFLOWS missing"
_callers_seen = 0
for wf in _m.group(1).split():
    jobs = jobs_of((ROOT / ".github/workflows" / wf).read_text(encoding="utf-8"))
    # Jobs that skip in the lane: gated on classify, or needing one that is — unless their `if:` runs them anyway
    # (`always()`, or the lane's own answer `nur_text == 'ja'`); asking for success of a skipped job skips too.
    lane_skipped = set()
    changed = True
    while changed:
        changed = False
        for j, tx in jobs.items():
            if j in lane_skipped or re.search(r"^    uses: ", tx, re.M):
                continue
            cond = if_of(tx)
            if GATE in cond or (any(n in lane_skipped for n in needs_of(tx)) and
                                cond != "${{ always() }}" and "needs.classify.outputs.nur_text == 'ja'" not in cond):
                lane_skipped.add(j)
                changed = True
    for j, tx in jobs.items():
        m_uses = re.search(r"^    uses: (\S+)", tx, re.M)
        if not m_uses:
            continue
        _callers_seen += 1
        cond, before = if_of(tx), [n for n in needs_of(tx) if n in lane_skipped]
        if not before:
            assert not cond, f"{wf}/{j}: a call with its own `if: {cond}` — when it skips, `{j} / <job>` never reports"
            continue
        gates = [n for n in before if if_of(jobs[n]) == GATE + " }}"]
        assert "classify" in needs_of(tx) and cond.startswith(CALLER_IF) and \
            any(f"(needs.{g}.result == 'skipped' || (" in cond for g in gates), \
            f"{wf}/{j}: needs {before}, which skip in the sprint/text lane, and would skip with them — then its " \
            f"required checks `{j} / <job>` never report. Run it in the lane: " \
            f"`if: {CALLER_IF}needs.<gated job>.result == 'skipped' || (<success of the others>)) }}}}`"
        rest = [n for n in before if f"needs.{n}.result == 'skipped'" not in cond]
        assert rest and all(f"needs.{n}.result == 'success'" in cond for n in rest), \
            f"{wf}/{j}: outside the lane it must ask for `needs.<job>.result == 'success'` of {rest}"
        assert SKIP_INPUT in [z.strip() for z in tx.splitlines()], \
            f"{wf}/{j}: hands the lane on without `{SKIP_INPUT}` (never skipped for a tag)"
        called = (ROOT / m_uses.group(1)).read_text(encoding="utf-8")
        assert re.search(r"^      skip:\s*$", called.split("\njobs:\n", 1)[0], re.M), \
            f"{m_uses.group(1)}: no input `skip`"
        for inner, itx in jobs_of(called).items():
            if not needs_of(itx):
                assert "!inputs.skip" in if_of(itx), \
                    f"{m_uses.group(1)}/{inner}: without `if: ${{{{ !inputs.skip }}}}` the check `{j} / {inner}` runs " \
                    f"in the lane (or, skipped by the caller, never reports)"
        print(f"  {wf}: call `{j}` runs in the lane and hands on `skip`; {m_uses.group(1)} skips by its own `if:`")
assert _callers_seen, "no reusable call found in the required workflows — adjust guard (release.yml calls build-provenance.yml)"

# ── The classify script, run against a pull request's merge commit ───────────────────────────────────────────────────
classify_script, _ = step_script(classify_ci, "Classify")
GIT = ["git", "-c", "user.name=probe", "-c", "user.email=probe@example.com", "-c", "commit.gpgsign=false",
       "-c", "init.defaultBranch=main"]


def classify(base_ref, changed, workflow="tests"):
    """Answer of `classify` in <workflow> for a pull request into <base_ref> that writes <changed> (path → text)."""
    with tempfile.TemporaryDirectory() as d:
        env = {"PATH": os.environ["PATH"], "HOME": d, "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
               "LC_ALL": "C"}

        def git(*a):
            return subprocess.run(GIT + list(a), cwd=d, env=env, check=True, capture_output=True, text=True).stdout.strip()

        git("init", "-q")
        os.makedirs(os.path.join(d, "scripts"))
        for script in ("_nur_text.sh", "_client_scope.sh"):
            shutil.copy(ROOT / "scripts" / script, os.path.join(d, "scripts", script))
        for path in ("README.md", "app.py", *changed):
            os.makedirs(os.path.dirname(os.path.join(d, path)), exist_ok=True)
            with open(os.path.join(d, path), "w", encoding="utf-8") as f:
                f.write("# probe\n")
        git("add", "-A")
        git("commit", "-q", "-m", "base")
        git("switch", "-q", "-c", "feature")
        for path, content in changed.items():
            with open(os.path.join(d, path), "a", encoding="utf-8") as f:
                f.write(content)
        git("commit", "-q", "-am", "change")
        git("switch", "-q", "main")
        git("merge", "-q", "--no-ff", "-m", "merge", "feature")
        out = os.path.join(d, "github_output")
        open(out, "w").close()
        run = subprocess.run(["bash", "-c", classify_script], cwd=d, capture_output=True, text=True, timeout=60,
                             env=env | {"GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "pull_request",
                                        "GITHUB_BASE_REF": base_ref, "GITHUB_SHA": git("rev-parse", "HEAD"),
                                        "GITHUB_OUTPUT": out, "WORKFLOW": workflow})
        assert run.returncode == 0, f"classify failed: {run.stdout}{run.stderr}"
        with open(out, encoding="utf-8") as f:
            return f.read().strip(), run.stdout


answer, log = classify("sprint/2026-11-27-probe", {"app.py": "print(2)\n"})
assert answer == "nur_text=ja" and "SPRINT LANE" in log, f"sprint PR with code: {answer!r} {log!r}"
answer, log = classify("main", {"app.py": "print(2)\n"})
assert answer == "", f"PR into main with code must run the full suite: {answer!r} {log!r}"
answer, log = classify("main", {"README.md": "more text\n"})
assert answer == "nur_text=ja", f"PR into main with text only: {answer!r} {log!r}"
answer, log = classify("sprint/a/b", {"app.py": "print(2)\n"})
assert answer == "", f"not a sprint branch (two slashes) must run the full suite: {answer!r} {log!r}"
print("  classify: sprint PR → fast lane, PR into main with code → full suite, text only → fast lane")

# Sprint lane, T-150: a sprint PR that changes a gate client or spec/ runs that client's jobs (the closing PR of S7 was
# red at the clients' HTTP tests because every client job had skipped). The workflow's name reaches the script through
# the step's env `WORKFLOW: ${{ github.workflow }}`. (Mutation probes: `classify` without the scope check, a client
# dropped from scripts/_client_scope.sh, spec/ dropped from a pattern → each red.)
assert "WORKFLOW: ${{ github.workflow }}" in classify_ci, "classify: the workflow's name must reach _client_scope.sh"
CLIENTS = ["client-go", "client-js", "client-php", "client-rust"]
for wf in CLIENTS:
    name = re.search(r"^name: (\S+)\s*$", texts[wf + ".yml"], re.M).group(1)
    assert name == wf, f"{wf}.yml: `name: {name}` — scripts/_client_scope.sh knows the client by the workflow's name"
    folder = wf.removeprefix("client-")
    for path in (f"clients/{folder}/probe.txt", "spec/vectors/probe.json", f".github/workflows/{wf}.yml"):
        answer, log = classify("sprint/2026-11-28-probe", {path: "x\n"}, wf)
        assert answer == "" and "SPRINT LANE" in log and "tests run" in log, \
            f"{wf}: a sprint PR changing {path} must run the client's jobs: {answer!r} {log!r}"
    for other in CLIENTS:
        if other != wf:
            answer, log = classify("sprint/2026-11-28-probe", {f"clients/{other.removeprefix('client-')}/x.txt": "x\n"}, wf)
            assert answer == "nur_text=ja", f"{wf}: a sprint PR changing only {other} must skip: {answer!r} {log!r}"
    answer, log = classify("sprint/2026-11-28-probe", {"app.py": "print(2)\n"}, wf)
    assert answer == "nur_text=ja", f"{wf}: a sprint PR without a client change must skip: {answer!r} {log!r}"
for wf in ("tests", "audit", "release"):
    answer, log = classify("sprint/2026-11-28-probe", {"spec/vectors/probe.json": "x\n"}, wf)
    assert answer == "nur_text=ja", f"{wf}: no gate client — the sprint lane stays fast: {answer!r} {log!r}"
answer, log = classify("sprint/2026-11-28-probe", {"clients/go/go.mod": "x\n"}, "")
assert answer == "nur_text=ja", f"an empty workflow name names no client: {answer!r} {log!r}"
# Every scope step of a client job asks the same script with its own name (no second copy of the pattern).
scope_steps = 0
for wf in CLIENTS:
    for step in re.split(r"\n      - ", texts[wf + ".yml"]):
        if "id: scope" in step:
            scope_steps += 1
            code = without_comments(step)
            assert f"scripts/_client_scope.sh {wf};" in code and "grep" not in code, \
                f"{wf}: the scope step must ask scripts/_client_scope.sh {wf}"
assert scope_steps == 5, f"{scope_steps} scope steps in the client workflows, expected 5 (php has two jobs) — adjust guard"
# The browser classifier is `classify` with the fixed scope `browser` (S8: #445 changed Ex4 and its browser suite in
# the sprint lane, the browser job skipped, the closing PR was red). Its script is run like the other.
cb = jobs_of(texts["ci.yml"])["classify-browser"]
browser_script, _ = step_script(cb, "Classify")
assert without_comments(browser_script) == without_comments(classify_script.replace('"$WORKFLOW"', "browser")), \
    "classify-browser differs from classify (other than the fixed scope `browser`)"
classify_script_saved = classify_script
classify_script = browser_script
for path in ("tests/test_headless_browser.py", "tests/_test_idp.py", "tinysesam/templates.py", "clients/js/examples/ex4/app.js",
             "examples/showcase.py", "deploy/ex4/tinysesam.toml", ".github/workflows/ci.yml"):
    answer, log = classify("sprint/2026-11-28-probe", {path: "x\n"})
    assert answer == "" and "its tests run" in log, f"browser: a sprint PR changing {path} must run it: {answer!r} {log!r}"
for path in ("scripts/probe.py", "clients/go/x.txt", "spec/vectors/x.json", "tests/test_core.py"):
    answer, log = classify("sprint/2026-11-28-probe", {path: "x\n"})
    assert answer == "nur_text=ja", f"browser: a sprint PR changing only {path} must skip it: {answer!r} {log!r}"
answer, log = classify("main", {"README.md": "more text\n"})
assert answer == "nur_text=ja", f"browser: text only into main skips: {answer!r}"
classify_script = classify_script_saved
# The browser job installs what the examples it drives switch on: Ex4 offers passkeys (T-149), and without the extra
# [passkey] its server does not start (`MissingExtra` at the router) — the closing PR of S8 was red on exactly that.
_ex4 = (ROOT / "deploy/ex4/tinysesam.toml").read_text(encoding="utf-8")
_browser = without_comments(jobs_of(texts["ci.yml"])["browser-suite"])
if re.search(r"^passkey_enabled = true", _ex4, re.M):
    assert re.search(r"pip install -e \"\.\[[a-z,]*passkey[a-z,]*\]\"", _browser), \
        "ci.yml/browser-suite: Ex4 switches passkeys on, the job must install the extra [passkey]"
# T-107: the provider's accounts of the acceptance matrix sign in through tests/_test_idp.py — TinySesam's OIDC client
# needs the extra [oidc]; a suite that asks for that extra would skip without it.
_asks_oidc = [f for f in ("test_shell_browser.py", "test_hybrid_browser.py", "test_headless_browser.py")
              if 'extra="oidc"' in (ROOT / "tests" / f).read_text(encoding="utf-8")]
if _asks_oidc:
    assert re.search(r"pip install -e \"\.\[[a-z,]*oidc[a-z,]*\]\"", _browser), \
        f"ci.yml/browser-suite: {_asks_oidc} need the extra [oidc], the job must install it"
print("  classify-browser: a sprint PR touching the library, the examples or the browser suites runs the browser job; "
      "it installs the extras Ex4 needs")
print(f"  classify (T-150): a sprint PR changing a client, spec/ or the workflow runs that client's jobs "
      f"({len(CLIENTS)} clients), anything else skips")

# ── T-107: the acceptance matrix — every cell done, named in both READMEs, carried by a suite of `browser-suite` ──────
_cells = {f"ex{n}/{o}" for n in range(1, 5) for o in ("local", "idp", "mixed")}
_suite_job = jobs_of(texts["ci.yml"])["browser-suite"]
for _readme, _head in (("README.md", "### The acceptance matrix"), ("i18n/README.de.md", "### Die Abnahmematrix")):
    _text = (ROOT / _readme).read_text(encoding="utf-8")
    assert _head in _text, f"{_readme}: section {_head!r} missing"
    _section = _text.split(_head, 1)[1].split("\n## ", 1)[0].split("\n### ", 1)[0]
    _rows = [z for z in _section.splitlines() if re.match(r"^\| Ex[1-4] ", z)]
    assert len(_rows) == 4, f"{_readme}: the matrix has {len(_rows)} example rows, not 4"
    _seen = set()
    for _row in _rows:
        _suite = re.search(r"`(test_[a-z_]+\.py)`", _row)
        assert _suite, f"{_readme}: no suite named in {_row!r}"
        _src = (ROOT / "tests" / _suite.group(1)).read_text(encoding="utf-8")
        assert f"python tests/{_suite.group(1)}" in _suite_job, f"ci.yml/browser-suite does not run {_suite.group(1)}"
        for _m in re.findall(r"`\[(ex[1-4]/(?:local|idp|mixed))\]`", _row):
            # The marker stands in the text of an `ok(...)` of that suite: printed only once its checks passed.
            _oks = [part.split(")\n", 1)[0] for part in _src.split(" ok(")[1:]]
            assert any(f"[{_m}]" in _call for _call in _oks), \
                f"{_readme}: cell {_m} is not confirmed by an ok() of {_suite.group(1)}"
            _seen.add(_m)
    assert _seen == _cells, f"{_readme}: cells missing from the matrix: {sorted(_cells - _seen)}"
print(f"  acceptance matrix (T-107): {len(_cells)} cells in both READMEs, each confirmed by an ok() of a suite that "
      "runs in browser-suite")

print("OK test_ci_aggregate")
