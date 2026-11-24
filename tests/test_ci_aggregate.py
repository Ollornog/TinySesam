"""The branch protection names one aggregate job per workflow, not the legs of a matrix (T-115).

A required check carries the name of a matrix leg (`full (3.14)`, `test (php 8.4)`); dropping or adding a release then
blocks every merge until someone edits the protection. The aggregate job (`suite-ok`, `client-go-ok` …) needs every
other job of its workflow, runs `always()` and is red unless every one of them succeeded — skipped, cancelled and failed
all count as not green.
"""
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKFLOWS = {  # workflow file → (aggregate job, the jobs it needs: every job with a matrix; ci.yml has other required jobs)
    "ci.yml": ("suite-ok", ["full"]),
    "client-go.yml": ("client-go-ok", None),
    "client-js.yml": ("client-js-ok", None),
    "client-php.yml": ("client-php-ok", None),
    "client-rust.yml": ("client-rust-ok", None),
}


def jobs_of(text):
    """{job id: its text} — the jobs sit two spaces deep under the top-level `jobs:`."""
    body = text.split("\njobs:\n", 1)[1]
    parts = re.split(r"^  ([A-Za-z0-9_-]+):\s*$", body, flags=re.M)
    return dict(zip(parts[1::2], parts[2::2]))


for wf, (agg, expected) in WORKFLOWS.items():
    jobs = jobs_of((ROOT / ".github/workflows" / wf).read_text(encoding="utf-8"))
    assert agg in jobs, f"{wf}: aggregate job `{agg}` missing"
    text = jobs[agg]
    others = expected or sorted(j for j in jobs if j != agg)
    m = re.search(r"^    needs: \[([^\]]*)\]\s*$", text, re.M)
    assert m, f"{wf}/{agg}: `needs: [...]` missing"
    needed = sorted(x.strip() for x in m.group(1).split(","))
    assert needed == others, f"{wf}/{agg}: needs {needed}, but expected {others}"
    assert re.search(r"^    if: \$\{\{ always\(\) \}\}\s*$", text, re.M), \
        f"{wf}/{agg}: without `if: ${{{{ always() }}}}` the job is skipped when a leg fails — a skipped required check hangs"
    assert re.search(rf"^    name: {re.escape(agg)}\s*$", text, re.M), f"{wf}/{agg}: the check name must be `{agg}`"
    assert "toJSON(needs)" in text and ".result == \"success\"" in text and "jq -e 'all(" in text, \
        f"{wf}/{agg}: the job must fail unless every needed job has the result `success`"
    assert "continue-on-error" not in text, f"{wf}/{agg}: a check that cannot turn red checks nothing"
    print(f"  {wf}: `{agg}` needs {', '.join(needed)}, runs always(), red unless all succeeded")

print("OK test_ci_aggregate")
