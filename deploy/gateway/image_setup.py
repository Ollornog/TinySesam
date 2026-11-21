"""Runtime stage of the gateway image (Dockerfile, T-59): set up the account, then check the image is complete.

Runs ONCE at build time, as root, inside the runtime stage — bind-mounted, so it leaves no file behind. The stage has
no shell, which is why this is Python and not a `RUN useradd … && mkdir …`.

1. The account `tinysesam` with uid/gid 1000 and its home, and /data owned by it. 1000 as in every image before:
   existing /data volumes belong to that uid, a different one would lock the gateway out of its own database.
2. No shell, no package manager, no pip (program or package) on disk — whoever gets code execution in the container
   finds no tool to fetch more. Red at build time if a base bump brings one back (the image-probe job checks the
   running container again from outside).
3. Every native module of the interpreter and of the venv loads: the runtime base brings only some Debian libraries,
   the Dockerfile copies the rest. A module whose library is missing would only fail on the first request that imports
   it; here it fails the build, on every platform.
4. The default TLS context knows the CA certificates — stdlib clients such as smtplib use it, not certifi. The base
   has no /usr/lib/ssl (OpenSSL's compiled-in default); measured 2026-11-20, Python 3.15 finds Debian's bundle in
   /etc/ssl/certs anyway. If a later interpreter stops doing so, this fails instead of every STARTTLS. And the gateway
   imports.
"""
from __future__ import annotations

import importlib
import importlib.machinery
import os
import pathlib
import ssl
import sys
import sysconfig

UID = GID = 1000
NAME = "tinysesam"
HOME = f"/home/{NAME}"

#: Programs that must not exist in the runtime image, searched in every directory a shell would look in.
FORBIDDEN = ("sh", "bash", "dash", "ash", "busybox", "toybox", "apt", "apt-get", "dpkg", "apk", "pip", "pip3",
             "curl", "wget")
# `/busybox`: where distroless's `debug` variants keep their shell — a tag swap must not slip one in.
BIN_DIRS = ("/bin", "/sbin", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin", "/opt/venv/bin", "/busybox")
#: pip as a package, not only as a program: the venv's own, the system one, the wheel ensurepip would install from.
PIP_GLOBS = ("/usr/local/lib/python3.*/site-packages/pip", "/opt/venv/lib/python3.*/site-packages/pip",
             "/usr/local/lib/python3.*/ensurepip", "/usr/lib/python3*/dist-packages/pip")


def _append_once(path: str, line: str) -> None:
    text = pathlib.Path(path).read_text(encoding="utf-8")
    if not any(row.split(":", 1)[0] == NAME for row in text.splitlines()):
        with open(path, "a", encoding="utf-8") as f:
            f.write(("" if text.endswith("\n") or not text else "\n") + line + "\n")


def account() -> None:
    _append_once("/etc/passwd", f"{NAME}:x:{UID}:{GID}:{NAME}:{HOME}:/sbin/nologin")
    _append_once("/etc/group", f"{NAME}:x:{GID}:")
    for path, mode in ((HOME, 0o700), ("/data", 0o755)):
        os.makedirs(path, exist_ok=True)
        os.chown(path, UID, GID)
        os.chmod(path, mode)


def no_tools() -> list[str]:
    found = []
    for d in BIN_DIRS:
        for name in FORBIDDEN:
            p = os.path.join(d, name)
            if os.path.lexists(p):
                found.append(p)
        if os.path.isdir(d):
            found += [os.path.join(d, n) for n in os.listdir(d) if n.startswith(("pip3.", "python3-config"))]
    for pattern in PIP_GLOBS:
        found += [str(p) for p in pathlib.Path("/").glob(pattern.lstrip("/"))]
    return sorted(set(found))


def _module_name(path: pathlib.Path, root: pathlib.Path) -> str:
    rel = path.relative_to(root)
    base = rel.name.split(".", 1)[0]
    return ".".join((*rel.parent.parts, base)) if rel.parent.parts else base


def native_modules() -> tuple[dict[str, int], list[str]]:
    """Import every extension module; returns (count per root, failures)."""
    # The interpreter's own modules sit next to the stdlib, NOT under sysconfig's `platstdlib` — inside the venv that
    # names /opt/venv/lib/python3.x, which has no lib-dynload (the first draft checked 0 stdlib modules and was green).
    roots = {"stdlib": pathlib.Path(os.__file__).parent / "lib-dynload",
             "venv": pathlib.Path(sysconfig.get_path("purelib"))}
    suffixes = tuple(importlib.machinery.EXTENSION_SUFFIXES)
    count, failed = dict.fromkeys(roots, 0), []
    for label, root in roots.items():
        for so in sorted(root.rglob("*.so")):
            rel_dirs = so.relative_to(root).parent.parts
            if not so.name.endswith(suffixes) or any(d.endswith(".libs") for d in rel_dirs):
                continue          # a library vendored by a wheel (auditwheel's `<pkg>.libs`), not a module
            name = _module_name(so, root)
            count[label] += 1
            try:
                importlib.import_module(name)
            except ImportError as e:
                failed.append(f"{name} ({so}): {e}")
    return count, failed


def main() -> int:
    if os.geteuid() != 0:
        print("image_setup: must run as root in the runtime stage", file=sys.stderr)
        return 1
    account()
    errors = []
    tools = no_tools()
    if tools:
        errors.append(f"shell, package manager or pip in the runtime image: {tools}")
    count, failed = native_modules()
    errors += [f"native module does not load: {f}" for f in failed]
    errors += [f"no native modules found in the {label} — the check looks in the wrong place"
               for label, n in count.items() if not n]
    if not ssl.create_default_context().cert_store_stats().get("x509_ca"):
        errors.append(f"the default TLS context has no CA certificates ({ssl.get_default_verify_paths()})")
    try:
        importlib.import_module("tinysesam.gateway")
    except ImportError as e:
        errors.append(f"tinysesam.gateway does not import: {e}")
    if errors:
        print("image_setup: the runtime image is not complete:\n  " + "\n  ".join(errors), file=sys.stderr)
        return 1
    print(f"image_setup: account {NAME} ({UID}:{GID}), native modules load ({count['stdlib']} stdlib, "
          f"{count['venv']} venv), no shell/package manager/pip, CA certificates present, tinysesam.gateway imports")
    return 0


if __name__ == "__main__":
    sys.exit(main())
