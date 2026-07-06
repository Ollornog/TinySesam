"""Selbst-Update von GitHub — funktioniert auch, wenn TinySesam als Dependency in einer
anderen App eingebettet ist (pip aktualisiert die installierte Distribution im aktuellen
Environment). Version wird verglichen (Release/Tag/Branch → __init__.py). Nur stdlib.

Programmatisch (fürs Admin-Panel):     tinysesam.update_available() -> {current, latest, available}
CLI:                                    python -m tinysesam check | update [ref]
Env-Overrides:  TINYSESAM_REPO=Ollornog/TinySesam   TINYSESAM_GIT_URL=git+ssh://…  (privat/Alias)
"""
from __future__ import annotations
import os
import re
import sys
import json
import subprocess
import urllib.request

REPO = os.environ.get("TINYSESAM_REPO", "Ollornog/TinySesam")
DEFAULT_BRANCH = os.environ.get("TINYSESAM_BRANCH", "main")


def _ver_tuple(s: str):
    nums = re.findall(r"\d+", s or "")
    t = tuple(int(x) for x in nums[:3])
    return t + (0,) * (3 - len(t))


def current_version() -> str:
    """Installierte Version — bevorzugt die Distribution-Metadaten (korrekt auch eingebettet)."""
    try:
        from importlib.metadata import version
        return version("tinysesam")
    except Exception:
        try:
            from . import __version__
            return __version__
        except Exception:
            return "0.0.0"


def _get(url, timeout=10, accept_json=True):
    req = urllib.request.Request(url, headers={"User-Agent": "tinysesam-updater",
                                               "Accept": "application/vnd.github+json" if accept_json else "*/*"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read().decode("utf-8", "replace")
    return json.loads(raw) if accept_json else raw


def latest_version(repo: str = None, timeout: int = 10):
    """Neueste Version auf GitHub. Reihenfolge: Release → Tags → __init__.py auf dem Default-Branch.
    Gibt {version, ref, source, url?} oder None."""
    repo = repo or REPO
    try:
        rel = _get(f"https://api.github.com/repos/{repo}/releases/latest", timeout)
        if rel.get("tag_name"):
            return {"version": rel["tag_name"].lstrip("v"), "ref": rel["tag_name"],
                    "source": "release", "url": rel.get("html_url")}
    except Exception:
        pass
    try:
        tags = _get(f"https://api.github.com/repos/{repo}/tags", timeout)
        if isinstance(tags, list) and tags:
            newest = max(tags, key=lambda t: _ver_tuple(t.get("name", "")))
            return {"version": newest["name"].lstrip("v"), "ref": newest["name"], "source": "tag"}
    except Exception:
        pass
    try:
        txt = _get(f"https://raw.githubusercontent.com/{repo}/{DEFAULT_BRANCH}/tinysesam/__init__.py",
                   timeout, accept_json=False)
        m = re.search(r'__version__\s*=\s*["\']([^"\']+)["\']', txt)
        if m:
            return {"version": m.group(1), "ref": DEFAULT_BRANCH, "source": "branch"}
    except Exception:
        pass
    return None


def update_available(repo: str = None, timeout: int = 10, pin: str = None) -> dict:
    """pin gesetzt (z.B. 'v0.2.0') → Ziel ist genau diese Version (available, wenn nicht drauf).
    Ohne pin → neueste Version von GitHub (available nur bei höherer Version)."""
    cur = current_version()
    if pin:
        pv = pin.lstrip("v")
        return {"current": cur, "latest": pv, "ref": pin, "source": "pin",
                "available": _ver_tuple(pv) != _ver_tuple(cur)}
    latest = latest_version(repo, timeout)
    if not latest:
        return {"current": cur, "latest": None, "available": False,
                "error": "GitHub nicht erreichbar oder keine Version gefunden"}
    return {"current": cur, "latest": latest["version"], "ref": latest["ref"],
            "source": latest["source"], "url": latest.get("url"),
            "available": _ver_tuple(latest["version"]) > _ver_tuple(cur)}


def pip_url(ref: str = None, repo: str = None, git_url: str = None, scheme: str = "https") -> str:
    """git-URL für pip. git_url (bzw. env TINYSESAM_GIT_URL) überschreibt alles — für private
    Repos / SSH-Alias. scheme https = öffentliches Repo ohne Auth."""
    repo = repo or REPO
    ref = ref or DEFAULT_BRANCH
    base = git_url or os.environ.get("TINYSESAM_GIT_URL")
    if not base:
        base = f"git+ssh://git@github.com/{repo}.git" if scheme == "ssh" else f"git+https://github.com/{repo}.git"
    return f"{base}@{ref}"


def self_update(ref: str = None, repo: str = None, git_url: str = None,
                scheme: str = "https", force: bool = False) -> dict:
    """Aktualisiert die installierte TinySesam-Instanz per pip von GitHub — auch eingebettet.
    Die Host-App muss danach neu gestartet werden, damit der neue Code geladen wird."""
    url = pip_url(ref, repo, git_url, scheme)
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade"]
    if force:
        cmd += ["--force-reinstall", "--no-deps"]
    cmd.append(url)
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return {"ok": p.returncode == 0, "cmd": " ".join(cmd),
                "output": (p.stdout + p.stderr)[-3000:], "restart_required": True}
    except Exception as e:
        return {"ok": False, "cmd": " ".join(cmd), "output": repr(e), "restart_required": False}
