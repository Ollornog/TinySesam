"""T-134: the recipe for an own server image with SAML (`deploy/saml-server/Dockerfile`) builds, and the server in it
signs a person in through SAML.

The recipe is built from THIS checkout (`--build-context src=…`, the package copied into a throwaway directory), the
container runs the server with a TOML configuration (`TINYSESAM_CONFIG`), and the suite's test identity provider
(`tests/_saml_idp.py`, really signed assertions) answers the AuthnRequest: the ACS accepts it, the session cookie opens
`account.json` for that person; an answer signed by a foreign key is refused. Inside the image python3-saml checks with
its libxmlsec1 — exactly what the recipe has to bring.

Docker is needed: the CI job `gate-caddy` sets `TINYSESAM_SAML_IMAGE=1` and the test is mandatory there; without the
variable it reports "skipped" (locally: `sg docker -c 'TINYSESAM_SAML_IMAGE=1 python tests/test_saml_image.py'`). The
container and the image carry the label `tinysesam.test=saml-image` and a name of this run; only they are removed —
never a foreign container, never a prune. The port is bound to 127.0.0.1.
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from voraussetzung import braucht  # noqa: E402

braucht(os.environ.get("TINYSESAM_SAML_IMAGE") == "1",
        "TINYSESAM_SAML_IMAGE not set — builds the SAML server image in Docker (the CI job gate-caddy sets it)")
# From here on the test is mandatory: a missing tool or extra is red, never a skip.
assert shutil.which("docker"), "TINYSESAM_SAML_IMAGE=1 but no docker"
for _module in ("onelogin", "lxml", "cryptography", "httpx"):
    assert importlib.util.find_spec(_module), f"TINYSESAM_SAML_IMAGE=1 but {_module} is missing — pip install '.[saml]'"

import httpx  # noqa: E402

import _saml_idp  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
RECIPE = ROOT / "deploy" / "saml-server"
LABEL = "tinysesam.test=saml-image"
RUN_ID = f"{os.getpid()}-{uuid.uuid4().hex[:8]}"
TAG = f"tinysesam-saml-test:{RUN_ID}"
NAME = f"tinysesam-saml-test-{RUN_ID}"
BASE = "https://auth.example.com"


def ok(name):
    print(f"  ✓ {name}")


def docker(*args, check=True, timeout=300):
    p = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout)
    if check and p.returncode:
        raise AssertionError(f"docker {' '.join(args)} → {p.returncode}\n{p.stdout[-3000:]}\n{p.stderr[-3000:]}")
    return p


def source_copy() -> str:
    """The package as pip needs it, without the checkout's caches and virtual environments."""
    out = tempfile.mkdtemp(prefix="tinysesam-saml-src-", dir=work)
    for name in ("pyproject.toml", "README.md", "LICENSE"):
        shutil.copy(ROOT / name, out)
    shutil.copytree(ROOT / "tinysesam", pathlib.Path(out) / "tinysesam",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    return out


idp = _saml_idp.IdP(BASE)
work = tempfile.mkdtemp(prefix="tinysesam-saml-image-")
config = pathlib.Path(work) / "tinysesam.toml"
config.write_text(
    "# The test's server: SAML against the suite's test identity provider, the account page, no OIDC.\n"
    'db_path = "/data/saml.db"\n'
    f'base_url = "{BASE}"\n'
    'https_mode = "warn"\n'
    "cookie_secure = false\n"
    "account_enabled = true\n"
    "saml_enabled = true\n"
    f'saml_idp_sso_url = "{idp.entity}"\n'
    f'saml_idp_x509cert = "{idp.cert_b64}"\n', encoding="utf-8")
config.chmod(0o644)                     # read by the image's account (uid 1000), not only by whoever runs the test

try:
    started = time.monotonic()
    docker("build", "--label", LABEL, "--build-context", f"src={source_copy()}",
           "--build-arg", "TINYSESAM=/src[gateway,saml]", "-t", TAG, str(RECIPE), timeout=1500)
    labels = docker("image", "inspect", "-f", '{{index .Config.Labels "tinysesam.test"}}', TAG).stdout.strip()
    assert labels == "saml-image", f"the image carries no test label: {labels!r}"
    ok(f"deploy/saml-server/Dockerfile builds from this checkout ({time.monotonic() - started:.0f} s), "
       "python3-saml with libxmlsec1 imports in the runtime stage")

    refused = subprocess.run(["docker", "build", "--progress=plain", "--label", LABEL, str(RECIPE)],
                             capture_output=True, text=True, timeout=1500)
    # The refusal's own line, as the build prints a step's output ("#7 0.123 set --build-arg …") — not the RUN line
    # BuildKit echoes, which contains the same words.
    assert refused.returncode != 0 and re.search(r"^#\d+ [\d.]+ set --build-arg TINYSESAM=",
                                                 refused.stdout + refused.stderr, re.M), \
        "the recipe built (or failed for another reason) without a pinned TinySesam:\n" + refused.stderr[-1500:]
    ok("without --build-arg TINYSESAM the recipe refuses to build (the operator pins the version)")

    docker("run", "-d", "--rm", "--label", LABEL, "--name", NAME, "-p", "127.0.0.1::8000",
           "-v", f"{config}:/etc/tinysesam.toml:ro", "-e", "TINYSESAM_CONFIG=/etc/tinysesam.toml", TAG)
    port = docker("port", NAME, "8000/tcp").stdout.strip().splitlines()[0].rsplit(":", 1)[1]
    url = f"http://127.0.0.1:{port}"
    deadline, healthy = time.monotonic() + 90, False
    while time.monotonic() < deadline:
        try:
            healthy = httpx.get(url + "/healthz", timeout=3).status_code == 200
        except httpx.HTTPError:
            healthy = False
        if healthy:
            break
        time.sleep(1)
    assert healthy, "the server did not answer /healthz within 90 s:\n" + docker("logs", NAME, check=False).stderr[-3000:]
    ok("the container starts the server from the TOML file (TINYSESAM_CONFIG) and answers /healthz")

    with httpx.Client(base_url=url, timeout=20) as c:
        assert c.get("/auth/saml/metadata").status_code == 200
        r = _saml_idp.round_trip(c, idp, "sami")
        assert r.status_code == 303, (r.status_code, r.text[:500], docker("logs", NAME, check=False).stderr[-2000:])
        me = c.get("/auth/account.json", headers={"Accept": "application/json"})
        assert me.status_code == 200 and "sami" in me.text, (me.status_code, me.text[:300])
    ok("a SAML sign-in through the test identity provider: ACS 303, account.json names the person")

    stranger = _saml_idp.IdP(BASE)                 # the same addresses, another signing key
    with httpx.Client(base_url=url, timeout=20) as c:
        rid, _ = _saml_idp.start(c)
        r = _saml_idp.acs(c, stranger, rid, "mallory")
        assert r.status_code == 400 and c.get("/auth/account.json").status_code in (401, 303), r.status_code
    ok("an answer signed by a foreign key is refused inside the image (400, no session)")
finally:
    # Only what this run made: its container (by name, checked for the label) and its image.
    inspected = docker("inspect", "-f", '{{index .Config.Labels "tinysesam.test"}}', NAME, check=False)
    if inspected.returncode == 0 and inspected.stdout.strip() == "saml-image":
        docker("rm", "-f", NAME, check=False)
    docker("image", "rm", "-f", TAG, check=False)
    shutil.rmtree(work, ignore_errors=True)
