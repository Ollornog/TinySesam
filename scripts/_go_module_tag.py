#!/usr/bin/env python3
"""go_module_tag — the Go module tag `clients/go/vX.Y.Z` of a release. stdlib-only.

    python3 scripts/_go_module_tag.py check                              module path of clients/go/go.mod (worktree)
    python3 scripts/_go_module_tag.py plan   --tag vX.Y.Z --commit SHA   create the tag? (writes $GITHUB_OUTPUT)
    python3 scripts/_go_module_tag.py verify --tag vX.Y.Z --commit SHA   is it there, on that commit, as it should be?

Go finds a module in a subdirectory only by a tag with the directory as prefix: `clients/go/v0.29.0`, not `v0.29.0`.
release.yml sets that tag on the same commit as the release tag, as its very last step — the Go module proxy and the
checksum database keep a version forever, so a wrong tag can never be taken back. That is why:

- `plan` runs only once everything else of the release is green, checks the module path in `go.mod` AT the commit of
  the tag and asks the remote whether the module tag already exists. Already there on the same commit → nothing to do
  (a rerun, or a tag set by hand). There on a DIFFERENT commit → exit 1, never moved. Not a plain `vX.Y.Z` (a
  pre-release or anything else) → nothing to do.
- the creating job (`go-module-tag`) holds `contents: write`, so it runs no repo code: two `gh api` calls with what
  `plan` decided (annotated tag object with the maintainer as tagger, then the ref).
- `verify` fetches the tag and checks: annotated, tagger as expected, peeled to the release commit. Then it asks
  proxy.golang.org for the version — only a warning when that fails, the proxy can lag.

Tested against a throwaway git repository in `tests/test_go_module_tag.py`.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent
MODULE_DIR = "clients/go"
MODULE_PATH = "github.com/Ollornog/TinySesam/clients/go"
TAG_PREFIX = MODULE_DIR + "/"
TAGGER_NAME = "Ollornog"
TAGGER_EMAIL = "168935741+Ollornog@users.noreply.github.com"
RELEASE_TAG = re.compile(r"^v\d+\.\d+\.\d+$")   # no pre-release, no build metadata
SHA = re.compile(r"^[0-9a-f]{40}$")
PROXY = "https://proxy.golang.org"


class Refused(Exception):
    """A state in which no tag may be set (or the set one is wrong)."""


def git(repo: str, *args: str) -> str:
    return subprocess.run(["git", "-C", repo, *args], check=True, capture_output=True, text=True).stdout


def module_path(go_mod: str) -> str | None:
    m = re.search(r"^module\s+(\S+)\s*$", go_mod, re.M)
    return m.group(1) if m else None


def remote_tag(repo: str, remote: str, name: str) -> tuple[str, str] | None:
    """(object, peeled commit) of `refs/tags/<name>` on the remote, None when missing. A lightweight tag has object ==
    commit; for an annotated one `ls-remote` lists the peeled `^{}` line as well."""
    ref = f"refs/tags/{name}"
    lines = git(repo, "ls-remote", remote, ref, ref + "^{}").split()
    found = dict(zip(lines[1::2], lines[0::2]))
    if ref not in found:
        return None
    return found[ref], found.get(ref + "^{}", found[ref])


def module_tag(tag: str) -> str:
    return TAG_PREFIX + tag


def plan(repo: str, remote: str, tag: str, commit: str) -> bool:
    """True = create the module tag, False = nothing to do. Raises Refused for a state that must stay red."""
    if not RELEASE_TAG.match(tag):
        print(f"  {tag} is not a release tag vX.Y.Z (pre-release?) — no Go module tag")
        return False
    if not SHA.match(commit):
        raise Refused(f"commit {commit!r} is not a full SHA")
    release = remote_tag(repo, remote, tag)
    if release is None:
        raise Refused(f"the release tag {tag} does not exist on {remote}")
    if release[1] != commit:
        raise Refused(f"{tag} points to {release[1]}, the run was started for {commit}")
    try:
        go_mod = git(repo, "show", f"{commit}:{MODULE_DIR}/go.mod")
    except subprocess.CalledProcessError as e:
        raise Refused(f"{MODULE_DIR}/go.mod missing at {commit}: {e.stderr.strip()}") from None
    if module_path(go_mod) != MODULE_PATH:
        raise Refused(f"{MODULE_DIR}/go.mod at {commit} names module {module_path(go_mod)!r}, expected {MODULE_PATH}")
    name = module_tag(tag)
    existing = remote_tag(repo, remote, name)
    if existing is None:
        print(f"  {name} does not exist yet — create it on {commit}")
        return True
    if existing[1] == commit:
        print(f"  {name} already exists on {commit} — nothing to do")
        return False
    raise Refused(f"{name} already exists on {existing[1]}, not on {commit} — a module version is never moved")


def verify(repo: str, remote: str, tag: str, commit: str) -> bool:
    """The module tag exists on the remote, is annotated, carries the maintainer as tagger and peels to `commit`."""
    if not RELEASE_TAG.match(tag):
        print(f"  {tag} is not a release tag vX.Y.Z — no Go module tag to check")
        return False
    name = module_tag(tag)
    existing = remote_tag(repo, remote, name)
    if existing is None:
        raise Refused(f"{name} does not exist on {remote}")
    obj, peeled = existing
    if peeled != commit:
        raise Refused(f"{name} points to {peeled}, expected {commit}")
    if obj == peeled:
        raise Refused(f"{name} is a lightweight tag — expected an annotated one")
    git(repo, "fetch", "--quiet", "--no-tags", remote, f"+refs/tags/{name}:refs/tags/{name}")
    tagger = git(repo, "for-each-ref", "--format=%(taggername) %(taggeremail)", f"refs/tags/{name}").strip()
    if tagger != f"{TAGGER_NAME} <{TAGGER_EMAIL}>":
        raise Refused(f"{name} has the tagger {tagger!r}, expected {TAGGER_NAME} <{TAGGER_EMAIL}>")
    print(f"  {name}: annotated, tagger {TAGGER_NAME}, on {commit}")
    return True


def proxy_escape(path: str) -> str:
    """The case encoding of the module proxy protocol: an upper-case letter becomes `!` plus the lower-case one."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def proxy_probe(tag: str, base: str = PROXY, attempts: int = 4, pause: float = 30.0) -> bool:
    """Ask the Go module proxy for the version (that also makes it fetch it). Only reports — the proxy can lag."""
    url = f"{base}/{proxy_escape(MODULE_PATH)}/@v/{tag}.info"
    for attempt in range(1, attempts + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as response:   # noqa: S310 — fixed https URL
                body = response.read(4096).decode("utf-8", "replace")
            if f'"Version":"{tag}"' in body.replace(" ", ""):
                print(f"  proxy.golang.org serves {MODULE_PATH}@{tag}")
                return True
            reason = f"unexpected answer {body[:200]!r}"
        except (urllib.error.URLError, OSError) as e:
            reason = str(e)
        print(f"  proxy attempt {attempt}/{attempts}: {reason}")
        if attempt < attempts:
            time.sleep(pause)
    print(f"::warning::proxy.golang.org does not serve {MODULE_PATH}@{tag} yet — check later: "
          f"GOPROXY=https://proxy.golang.org go list -m {MODULE_PATH}@{tag}")
    return False


def check() -> int:
    go_mod = (ROOT / MODULE_DIR / "go.mod").read_text(encoding="utf-8")
    found = module_path(go_mod)
    if found != MODULE_PATH:
        print(f"  ✗ {MODULE_DIR}/go.mod names module {found!r}, expected {MODULE_PATH} (tag prefix {TAG_PREFIX})")
        return 1
    print(f"  ✓ {MODULE_DIR}/go.mod: module {MODULE_PATH} — release tags it as {TAG_PREFIX}vX.Y.Z")
    return 0


def write_output(**values: str) -> None:
    target = os.environ.get("GITHUB_OUTPUT")
    if target:
        with open(target, "a", encoding="utf-8") as f:
            for k, v in values.items():
                f.write(f"{k}={v}\n")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="The Go module tag clients/go/vX.Y.Z of a release.")
    parser.add_argument("step", choices=["check", "plan", "verify"])
    parser.add_argument("--tag", default="")
    parser.add_argument("--commit", default="")
    parser.add_argument("--repo", default=str(ROOT), help="git working tree (default: this repository)")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--proxy", default=PROXY, help="module proxy for `verify`; empty = no probe")
    parser.add_argument("--proxy-attempts", type=int, default=4)
    parser.add_argument("--proxy-pause", type=float, default=30.0, help="seconds between proxy attempts")
    args = parser.parse_args(argv)
    if args.step == "check":
        return check()
    try:
        if args.step == "plan":
            create = plan(args.repo, args.remote, args.tag, args.commit)
            write_output(create=str(create).lower(), name=module_tag(args.tag), commit=args.commit)
        else:
            if verify(args.repo, args.remote, args.tag, args.commit) and args.proxy:
                proxy_probe(args.tag, args.proxy, args.proxy_attempts, args.proxy_pause)
    except Refused as e:
        print(f"::error::{e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
