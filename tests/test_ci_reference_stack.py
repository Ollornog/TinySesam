"""The step "Accept the reference stack" of ci.yml (job `gate-caddy`) skips the OWN image at the right moments.

The compose example names `ghcr.io/<owner>/tinysesam:v<version>`. That image only exists once the release run of the
tag `v<version>` has pushed it. Three situations, measured here against the SHIPPED step (it is cut out of ci.yml and run with
a throwaway `origin`, a fake `docker` and `docker compose`):

 (1) tag unset (release PR): the own image is skipped, everything else is pulled.
 (2) tag set and pointing at the commit under test (the push run for the merge commit meets the release run
     that is still building the image — main was red after every release, 0.25.2 and 0.25.3): skipped as well.
 (3) tag set at an OLDER commit (every later commit): the own image must be pullable, so it is pulled — a missing
     image then turns the step red. Lightweight and annotated tags behave the same.

Mutations (each turns a case red): comparison with HEAD removed -> (2); empty-tag test removed -> (1); peeled ref not read -> (2, annotated);
always skipping -> (3); never skipping -> (1).
"""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CI = os.path.join(ROOT, ".github", "workflows", "ci.yml")
STEP = "Accept the reference stack (docker-compose)"
VERSION = "9.9.9"
OWN = f"ghcr.io/ollornog/tinysesam:v{VERSION}"
OTHER = "caddy:2.11.4@sha256:" + "0" * 64


def ok(name):
    print(f"  ✓ {name}")


def step_script():
    """The `run:` block of the step, as the runner would execute it."""
    with open(CI, encoding="utf-8") as fh:
        lines = fh.read().split("\n")
    start = next(i for i, ln in enumerate(lines) if ln.strip() == f"- name: {STEP}")
    assert lines[start + 1].strip() == "run: |", lines[start + 1]
    body = []
    for ln in lines[start + 2:]:
        if ln.strip() and not ln.startswith(" " * 10):
            break
        body.append(ln[10:] if ln.strip() else "")
    return "\n".join(body) + "\n"


def sh(args, cwd, env=None, check=True):
    return subprocess.run(args, cwd=cwd, env=env, check=check, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT)


def run_step(tag, annotated, tag_at_head):
    """Run the step in a fresh clone; return (exit code, list of `docker pull` arguments)."""
    tmp = tempfile.mkdtemp(prefix="refstack-")
    try:
        origin = os.path.join(tmp, "origin.git")
        work = os.path.join(tmp, "work")
        sh(["git", "init", "-q", "--bare", origin], tmp)
        sh(["git", "init", "-q", work], tmp)
        git = ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "commit.gpgsign=false",
               "-c", "tag.gpgsign=false"]
        os.makedirs(os.path.join(work, "deploy", "forward-auth"))
        with open(os.path.join(work, "pyproject.toml"), "w") as fh:
            fh.write(f'[project]\nname = "x"\nversion = "{VERSION}"\n')
        with open(os.path.join(work, "deploy", "forward-auth", "Caddyfile"), "w") as fh:
            fh.write(":80\n")
        with open(os.path.join(work, "deploy", "forward-auth", "docker-compose.yml"), "w") as fh:
            fh.write("services: {}\n")
        sh(git + ["add", "-A"], work)
        sh(git + ["commit", "-q", "-m", "release"], work)
        if tag != "unset":
            if tag_at_head is False:
                sh(git + ["commit", "-q", "--allow-empty", "-m", "later"], work)
                tagged = "HEAD~1"
            else:
                tagged = "HEAD"
            cmd = git + ["tag"] + (["-a", "-m", "v"] if annotated else []) + [f"v{VERSION}", tagged]
            sh(cmd, work)
        sh(["git", "remote", "add", "origin", origin], work)
        sh(git + ["push", "-q", "origin", "HEAD:refs/heads/main", "--tags"], work)

        bin_dir = os.path.join(tmp, "bin")
        os.makedirs(bin_dir)
        log = os.path.join(tmp, "pulls.log")
        fake = (
            "#!/bin/sh\n"
            'if [ "$1" = compose ]; then\n'
            '  case "$*" in\n'
            '    *"config --images"*) printf "%s\\n%s\\n" "' + OWN + '" "' + OTHER + '" ;;\n'
            "  esac\n"
            "  exit 0\n"
            "fi\n"
            'if [ "$1" = pull ]; then echo "$3" >> "' + log + '"; [ "$3" = "' + OWN + '" ] && exit 1; exit 0; fi\n'
            "exit 0\n"
        )
        # `docker pull` of the own image fails (manifest unknown), as in the registry before the release run ends.
        with open(os.path.join(bin_dir, "docker"), "w") as fh:
            fh.write(fake)
        os.chmod(os.path.join(bin_dir, "docker"), os.stat(os.path.join(bin_dir, "docker")).st_mode | stat.S_IXUSR)
        env = dict(os.environ, PATH=bin_dir + os.pathsep + os.environ["PATH"], GITHUB_REPOSITORY_OWNER="Ollornog",
                   GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        script = os.path.join(tmp, "step.sh")
        with open(script, "w") as fh:
            fh.write(step_script())
        res = sh(["bash", "-e", script], work, env=env, check=False)
        pulls = open(log).read().split() if os.path.exists(log) else []
        return res.returncode, pulls, res.stdout
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    assert re.search(r"tag_commit=", step_script()), "the step no longer reads the commit of the tag"

    rc, pulls, out = run_step("unset", False, True)
    assert rc == 0 and OWN not in pulls, (rc, pulls, out)
    assert OTHER in pulls, "the other images must still be pulled"
    ok("tag unset: own image skipped, the others pulled")

    for annotated in (False, True):
        kind = "annotated" if annotated else "lightweight"
        rc, pulls, out = run_step("set", annotated, True)
        assert rc == 0 and OWN not in pulls, (kind, rc, pulls, out)
        assert OTHER in pulls
        ok(f"{kind} tag at the commit under test: own image skipped (release run still building)")

        rc, pulls, out = run_step("set", annotated, False)
        assert rc != 0 and OWN in pulls, (kind, rc, pulls, out)
        ok(f"{kind} tag at an older commit: own image is pulled, a missing image turns the step red")
    print("Reference stack step OK")


if __name__ == "__main__":
    sys.exit(main())
