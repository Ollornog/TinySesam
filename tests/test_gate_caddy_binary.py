"""The Caddy binary for the gate suite is built once and kept by content (T-116, tests/_gate_caddy_binary.py).

Measured with a stand-in `docker` (a script that logs its calls and copies a fake binary): the first call builds and
keeps the binary, the second needs no Docker at all, a changed build input gives a new build and removes the old
directory, and without Docker the answer names the missing tool instead of failing.
"""
import os
import pathlib
import shutil
import stat
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import _gate_caddy_binary as gcb  # noqa: E402

tmp = pathlib.Path(tempfile.mkdtemp())
try:
    log = tmp / "docker.log"
    bindir = tmp / "bin"
    bindir.mkdir()
    fake = bindir / "docker"
    fake.write_text(
        '#!/bin/sh\n'
        'echo "$1" >> "$FAKE_DOCKER_LOG"\n'
        'case "$1" in\n'
        '  info) echo 27 ;;\n'
        '  build) exit 0 ;;\n'
        '  create) echo cid1 ;;\n'
        '  cp) printf "#!/bin/sh\\necho fake caddy\\n" > "$3" ;;\n'
        '  rm) exit 0 ;;\n'
        'esac\n', encoding="utf-8")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
    cache = tmp / "cache"
    os.environ.update({"XDG_CACHE_HOME": str(cache), "FAKE_DOCKER_LOG": str(log)})
    real_path = os.environ["PATH"]

    # 1. Without Docker (and nothing kept): no binary, the reason names the tool.
    os.environ["PATH"] = str(tmp / "empty")
    path, why = gcb.ensure_binary()
    assert path is None and "`docker` is missing" in why, (path, why)
    print("  without Docker: no binary, the reason names `docker`")

    # 2. With Docker: built, copied out, kept by content.
    os.environ["PATH"] = f"{bindir}{os.pathsep}{real_path}"
    path, why = gcb.ensure_binary()
    assert why is None and path == str(cache / "tinysesam/gate-caddy" / gcb.content_hash() / "caddy"), (path, why)
    assert os.access(path, os.X_OK), "the kept binary is not executable"
    calls = log.read_text().split()
    assert calls == ["info", "build", "create", "cp", "rm"], calls
    print("  with Docker: built once (info, build, create, cp, rm), kept under the content hash")

    # 3. Second call: from the cache, Docker is not called, not even when it is gone.
    os.environ["PATH"] = str(tmp / "empty")
    again, why = gcb.ensure_binary()
    assert again == path and why is None, (again, why)
    assert log.read_text().split() == calls, "the second call must not run Docker"
    print("  second call: from the cache, Docker not needed")

    # 4. A changed build input: new hash, new build, the old directory is gone.
    os.environ["PATH"] = f"{bindir}{os.pathsep}{real_path}"
    fake_dir = tmp / "caddy-gate"
    shutil.copytree(gcb.BUILD_DIR, fake_dir)
    gcb.BUILD_DIR = fake_dir
    with open(fake_dir / "main.go", "a", encoding="utf-8") as fh:
        fh.write("\n// changed\n")
    new, why = gcb.ensure_binary()
    assert why is None and new != path and os.access(new, os.X_OK), (new, why)
    assert not pathlib.Path(path).parent.exists(), "the directory of the old content hash is still there"
    assert log.read_text().split().count("build") == 2
    print("  changed main.go: new hash, rebuilt, the old directory removed")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

# The repo extra of the pre-push hook starts the suite for a change near the gate (a change in deploy/forward-auth/ names
# no test by file name) and treats the skip of the suite as a named hint, not as red.
extras = sorted(p for p in (gcb.ROOT / ".githooks").glob("pre-push.*"))
assert len(extras) == 1, f"the repo extra of the pre-push hook (.githooks/pre-push.<extra>) is missing or doubled: {extras}"
hook_extra = extras[0]
text = hook_extra.read_text(encoding="utf-8")
assert os.access(hook_extra, os.X_OK), "the pre-push extra is not executable — the hook aborts the push on that"
assert "deploy/forward-auth/" in text and "tests/test_gate_caddy.py" in text, "the extra does not name the gate files"
assert "-eq 77" in text, "the extra must handle the skip (exit 77) of the suite itself"
print("  pre-push extra: executable, starts the suite for deploy/forward-auth/, names the skip")

print("OK test_gate_caddy_binary")
