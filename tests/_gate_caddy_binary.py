"""The Caddy binary with caddy-jwt for tests/test_gate_caddy.py, built once and kept by content (T-116).

CI builds it from deploy/forward-auth/caddy-gate and passes the path in TINYSESAM_GATE_CADDY. On a machine with Docker the
suite builds it itself: `docker build` of the same directory, the binary copied out of the image, kept in
`$XDG_CACHE_HOME/tinysesam/gate-caddy/<hash>/caddy` where the hash covers every file the build reads. A change of the
Dockerfile, go.mod, go.sum or main.go gives a new hash and a new build; the older directories are removed (a cache that
does not expire is a leak). Without Docker the answer is the name of the missing tool.
"""
import hashlib
import os
import pathlib
import shutil
import subprocess

ROOT = pathlib.Path(__file__).resolve().parent.parent
BUILD_DIR = ROOT / "deploy/forward-auth/caddy-gate"
INPUTS = ("Dockerfile", "go.mod", "go.sum", "main.go")


def content_hash():
    h = hashlib.sha256()
    for name in INPUTS:
        h.update(name.encode() + b"\0" + (BUILD_DIR / name).read_bytes() + b"\0")
    return h.hexdigest()[:16]


def cache_root():
    base = os.environ.get("XDG_CACHE_HOME") or str(pathlib.Path.home() / ".cache")
    return pathlib.Path(base) / "tinysesam" / "gate-caddy"


def _docker(*args, timeout=900):
    return subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)


def ensure_binary():
    """(path, reason): the binary and None, or None and why there is none (the tool that is missing)."""
    root = cache_root()
    target = root / content_hash() / "caddy"
    if target.is_file() and os.access(target, os.X_OK):
        return str(target), None
    if not shutil.which("docker"):
        return None, "`docker` is missing — it builds the Caddy with caddy-jwt (or set TINYSESAM_GATE_CADDY)"
    probe = _docker("info", "--format", "{{.ServerVersion}}", timeout=60)
    if probe.returncode != 0:
        return None, "`docker` does not answer (daemon down or no permission) — " + probe.stderr.strip()[:160]
    tag = f"tinysesam-caddy-gate-test:{content_hash()}"
    print(f"  building the Caddy with caddy-jwt ({tag}); kept in {root} for the next run")
    built = _docker("build", "-q", "-t", tag, str(BUILD_DIR))
    assert built.returncode == 0, f"docker build of deploy/forward-auth/caddy-gate failed:\n{built.stderr[-2000:]}"
    made = _docker("create", tag)
    assert made.returncode == 0, f"docker create failed: {made.stderr[-500:]}"
    cid = made.stdout.strip()
    try:
        target.parent.mkdir(parents=True, exist_ok=True)
        part = target.with_name("caddy.part")
        copied = _docker("cp", f"{cid}:/usr/bin/caddy", str(part))
        assert copied.returncode == 0, f"docker cp failed: {copied.stderr[-500:]}"
        os.chmod(part, 0o700)
        os.replace(part, target)
    finally:
        _docker("rm", cid)
    for old in root.iterdir():
        if old.is_dir() and old != target.parent:
            shutil.rmtree(old, ignore_errors=True)
    return str(target), None
