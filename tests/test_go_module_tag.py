"""The Go module tag `clients/go/vX.Y.Z` (scripts/_go_module_tag.py) against a throwaway git repository.

The proxy and the checksum database keep a module version forever, so what decides about the tag is measured here
against real git: a bare "remote" and a clone, with release tags, module tags on the right and on a wrong commit,
lightweight tags, a foreign tagger, a wrong module path and a pre-release. No network: the proxy probe runs against a
closed local port and must only warn.
"""
import os
import pathlib
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import _go_module_tag as gmt  # noqa: E402

work = pathlib.Path(tempfile.mkdtemp(prefix="gomodtag-"))
ENV = {**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1", "LC_ALL": "C",
       "GIT_AUTHOR_NAME": "Probe", "GIT_AUTHOR_EMAIL": "probe@example.com",
       "GIT_COMMITTER_NAME": "Probe", "GIT_COMMITTER_EMAIL": "probe@example.com"}
os.environ.update({k: ENV[k] for k in ENV if k.startswith(("GIT_", "LC_"))})


def git(repo, *args, env=None):
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True,
                          env=env or ENV).stdout.strip()


def tagger_env(name, email):
    return {**ENV, "GIT_COMMITTER_NAME": name, "GIT_COMMITTER_EMAIL": email}


remote = work / "remote.git"
clone = work / "clone"
subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True, env=ENV)
subprocess.run(["git", "init", "-q", "-b", "main", str(clone)], check=True, env=ENV)
git(clone, "remote", "add", "origin", str(remote))
(clone / "clients/go").mkdir(parents=True)
(clone / "clients/go/go.mod").write_text(f"module {gmt.MODULE_PATH}\n\ngo 1.26.0\n", encoding="utf-8")
git(clone, "add", ".")
git(clone, "commit", "-q", "-m", "one")
first = git(clone, "rev-parse", "HEAD")
(clone / "README").write_text("two\n", encoding="utf-8")
git(clone, "add", ".")
git(clone, "commit", "-q", "-m", "two")
second = git(clone, "rev-parse", "HEAD")
git(clone, "tag", "-a", "v1.0.0", "-m", "release", first)
git(clone, "tag", "-a", "v1.1.0", "-m", "release", second)
git(clone, "tag", "-a", "v1.2.0-rc.1", "-m", "pre-release", second)
git(clone, "push", "-q", "origin", "main", "--tags")
OLLORNOG = tagger_env(gmt.TAGGER_NAME, gmt.TAGGER_EMAIL)


def refused(fn, *args, contains):
    try:
        fn(*args)
    except gmt.Refused as e:
        assert contains in str(e), f"refused for another reason: {e}"
        return
    raise AssertionError(f"{fn.__name__}{args[2:]} was not refused ({contains})")


def push_tag(name, commit, *, annotated=True, env=OLLORNOG):
    if annotated:
        git(clone, "tag", "-a", name, "-m", "module", commit, env=env)
    else:
        git(clone, "tag", name, commit)
    git(clone, "push", "-q", "origin", f"refs/tags/{name}")


def drop_tag(name):
    git(clone, "tag", "-d", name)
    git(clone, "push", "-q", "origin", f":refs/tags/{name}")


# 1. Not a plain vX.Y.Z: no module tag, neither planned nor checked.
for tag in ("v1.2.0-rc.1", "v1.2", "1.1.0", "v1.1.0+build"):
    assert gmt.plan(str(clone), "origin", tag, second) is False, tag
    assert gmt.verify(str(clone), "origin", tag, second) is False, tag
print("  pre-release and malformed tags: no Go module tag")

# 2. The release tag must exist on the remote and point to the commit of the run.
refused(gmt.plan, str(clone), "origin", "v9.9.9", second, contains="does not exist")
refused(gmt.plan, str(clone), "origin", "v1.1.0", first, contains="points to")
refused(gmt.plan, str(clone), "origin", "v1.1.0", "abc", contains="not a full SHA")
print("  release tag missing or on another commit: refused")

# 3. Missing module tag → create; the same on a rerun after it was created → nothing to do.
assert gmt.plan(str(clone), "origin", "v1.1.0", second) is True
push_tag("clients/go/v1.1.0", second)
assert gmt.plan(str(clone), "origin", "v1.1.0", second) is False
assert gmt.verify(str(clone), "origin", "v1.1.0", second) is True
print("  missing → create; present on the same commit → nothing to do, verify passes")

# 4. Present on ANOTHER commit → red, never moved; verify says the same.
push_tag("clients/go/v1.0.0", second)
refused(gmt.plan, str(clone), "origin", "v1.0.0", first, contains="never moved")
refused(gmt.verify, str(clone), "origin", "v1.0.0", first, contains="points to")
drop_tag("clients/go/v1.0.0")
print("  present on another commit: refused, not moved")

# 5. verify: a lightweight tag and a foreign tagger are not what release.yml sets.
push_tag("clients/go/v1.0.0", first, annotated=False)
refused(gmt.verify, str(clone), "origin", "v1.0.0", first, contains="lightweight")
drop_tag("clients/go/v1.0.0")
push_tag("clients/go/v1.0.0", first, env=tagger_env("github-actions[bot]", "41898282+github-actions[bot]@users.noreply.github.com"))
refused(gmt.verify, str(clone), "origin", "v1.0.0", first, contains="tagger")
drop_tag("clients/go/v1.0.0")
refused(gmt.verify, str(clone), "origin", "v1.0.0", first, contains="does not exist")
print("  verify: missing, lightweight and foreign tagger refused")

# 6. go.mod at the tag commit decides — a wrong module path or no go.mod is red.
(clone / "clients/go/go.mod").write_text("module example.com/other\n", encoding="utf-8")
git(clone, "commit", "-q", "-am", "wrong module")
third = git(clone, "rev-parse", "HEAD")
git(clone, "tag", "-a", "v1.3.0", "-m", "release", third)
git(clone, "rm", "-q", "clients/go/go.mod")
git(clone, "commit", "-q", "-m", "no module")
fourth = git(clone, "rev-parse", "HEAD")
git(clone, "tag", "-a", "v1.4.0", "-m", "release", fourth)
git(clone, "push", "-q", "origin", "main", "--tags")
refused(gmt.plan, str(clone), "origin", "v1.3.0", third, contains="names module")
refused(gmt.plan, str(clone), "origin", "v1.4.0", fourth, contains="go.mod missing")
print("  wrong module path or no go.mod at the tag commit: refused")

# 7. main(): `plan` writes its decision to $GITHUB_OUTPUT, a refusal is exit 1.
out = work / "github_output"
os.environ["GITHUB_OUTPUT"] = str(out)
assert gmt.main(["plan", "--repo", str(clone), "--tag", "v1.0.0", "--commit", first]) == 0
assert out.read_text(encoding="utf-8").splitlines() == ["create=true", "name=clients/go/v1.0.0", f"commit={first}"]
assert gmt.main(["plan", "--repo", str(clone), "--tag", "v1.3.0", "--commit", third]) == 1
del os.environ["GITHUB_OUTPUT"]
print("  main: decision in GITHUB_OUTPUT, refusal = exit 1")

# 8. The proxy probe: case encoding of the protocol, and an unreachable proxy only warns.
assert gmt.proxy_escape(gmt.MODULE_PATH) == "github.com/!ollornog/!tiny!sesam/clients/go"
assert gmt.proxy_probe("v1.1.0", base="http://127.0.0.1:9", attempts=2, pause=0) is False
assert gmt.main(["verify", "--repo", str(clone), "--tag", "v1.1.0", "--commit", second,
                 "--proxy", "http://127.0.0.1:9", "--proxy-pause", "0"]) == 0, "an unreachable proxy turned verify red"
print("  proxy probe: !-escaping; unreachable proxy warns, verify stays green")

# 9. This repository's own go.mod names the module the tag prefix belongs to.
assert gmt.check() == 0
assert gmt.TAG_PREFIX == gmt.MODULE_DIR + "/" and gmt.MODULE_PATH.endswith("/" + gmt.MODULE_DIR)
print("OK test_go_module_tag")
