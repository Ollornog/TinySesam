#!/usr/bin/env python3
"""Test-Runner für TinySesam — führt alle (oder ausgewählte) tests/test_*.py aus.

    python tests/run_all.py                # alle Suiten
    python tests/run_all.py test_core.py   # nur bestimmte

Exit-Code 0 = alles grün, 1 = mind. ein Fehlschlag. Kein pytest nötig (Suiten sind
eigenständige assert-Skripte). Suiten, die nur wegen einer FEHLENDEN OPTIONALEN
Abhängigkeit nicht importieren (z.B. webauthn/authlib bei Minimal-Install), werden
als „skip" gewertet, nicht als Fehler — so läuft der Runner auch ohne Extras sinnvoll.
"""
import sys
import os
import glob
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
OPTIONAL = ("webauthn", "authlib", "httpx", "argon2", "qrcode",   # Extras: [passkey]/[oidc]/[argon2]/[qr]
            "onelogin", "xmlsec", "ldap3", "redis",               # [saml]/[ldap]/[redis]
            "websockets", "uvicorn", "kein Chrome gefunden")      # der Browser-Test


def main(argv):
    if argv:
        files = [os.path.join(HERE, a if a.endswith(".py") else f"test_{a}.py") for a in argv]
    else:
        files = sorted(glob.glob(os.path.join(HERE, "test_*.py")))
    env = {**os.environ, "PYTHONPATH": ROOT}
    ok, skipped, failed = [], [], []
    for path in files:
        name = os.path.basename(path)
        if not os.path.exists(path):
            print(f"  ??   {name} (nicht gefunden)")
            failed.append(name)
            continue
        r = subprocess.run([sys.executable, path], cwd=ROOT, env=env,
                           capture_output=True, text=True)
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
