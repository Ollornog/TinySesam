#!/usr/bin/env python3
"""Test-Runner für TinySesam — führt alle (oder ausgewählte) tests/test_*.py aus.

    python tests/run_all.py                # alle Suiten
    python tests/run_all.py test_core.py   # nur bestimmte

Exit-Code 0 = alles grün, 1 = mind. ein Fehlschlag. Kein pytest nötig (Suiten sind
eigenständige assert-Skripte). Suiten, die nur wegen einer FEHLENDEN OPTIONALEN
Abhängigkeit nicht importieren (z.B. webauthn/authlib bei Minimal-Install), werden
als „skip" gewertet, nicht als Fehler — so läuft der Runner auch ohne Extras sinnvoll.

Jede Suite läuft in einem EIGENEN Wegwerf-Verzeichnis (TMPDIR/HOME/XDG_* zeigen
dorthin, danach wird es gelöscht). So kann kein Zustand aus einem Lauf den nächsten
beeinflussen und keine Suite die andere stören — die Tests sind wiederholbar.
Nachweis: `ci-local --full` fährt die Suite zweimal im selben Baum.
"""
import sys
import os
import glob
import shutil
import subprocess
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OPTIONAL = ("webauthn", "authlib", "httpx", "argon2", "qrcode",   # Extras: [passkey]/[oidc]/[argon2]/[qr]
            "onelogin", "xmlsec", "ldap3", "redis",               # [saml]/[ldap]/[redis]
            "websockets", "uvicorn", "kein Chrome gefunden")      # der Browser-Test


def main(argv):
    # --no-browser: der Browser-Test ist der langsamste. Nur für Zwischenläufe, nie vor einem Push.
    skip_browser = "--no-browser" in argv
    argv = [a for a in argv if a != "--no-browser"]
    if argv:
        files = [os.path.join(HERE, a if a.endswith(".py") else f"test_{a}.py") for a in argv]
    else:
        files = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    if skip_browser:
        files = [f for f in files if not f.endswith("test_browser.py")]
    ok, skipped, failed = [], [], []
    for path in files:
        name = os.path.basename(path)
        if not os.path.exists(path):
            print(f"  ??   {name} (nicht gefunden)")
            failed.append(name)
            continue

        # Jede Suite bekommt ein EIGENES Wegwerf-Verzeichnis: TMPDIR, HOME und die
        # XDG-Pfade zeigen dorthin. Damit kann kein Zustand einen zweiten Lauf
        # beeinflussen -- und keine Suite die naechste stoeren. Danach wird es geloescht.
        # (Policy: "Tests sind wiederholbar"; Nachweis: `ci-local --full`.)
        sandbox = tempfile.mkdtemp(prefix=f"tinysesam-{name[:-3]}-")
        env = {
            **os.environ,
            "PYTHONPATH": ROOT,
            "TMPDIR": sandbox, "TMP": sandbox, "TEMP": sandbox,
            "HOME": sandbox,
            "XDG_CACHE_HOME": os.path.join(sandbox, ".cache"),
            "XDG_CONFIG_HOME": os.path.join(sandbox, ".config"),
            "XDG_DATA_HOME": os.path.join(sandbox, ".local", "share"),
        }
        try:
            r = subprocess.run([sys.executable, path], cwd=ROOT, env=env,
                               capture_output=True, text=True)
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
        if r.returncode == 0:
            print(f"  ok   {name}")
            ok.append(name)
        elif ("ModuleNotFoundError" in r.stderr or "ImportError" in r.stderr) \
                and any(m in r.stderr for m in OPTIONAL):
            print(f"  skip {name} (optionale Abhängigkeit fehlt)")
            skipped.append(name)
        else:
            print(f"  FAIL {name}")
            sys.stdout.write((r.stdout or "")[-2000:])
            sys.stderr.write((r.stderr or "")[-2000:])
            failed.append(name)
    total = len(files)
    print(f"\n{len(ok)}/{total} grün, {len(skipped)} übersprungen, {len(failed)} fehlgeschlagen")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
