"""Update-Mechanismus: Versions-Vergleich, pip-URL, Version-Pin, manuell/automatisch —
ohne echtes pip oder Netz (die self_update-URL wird nur konstruiert, nicht ausgeführt)."""
import tempfile, os
from tinysesam import TinySesam, TinySesamConfig, updater, current_version, update_available

assert current_version() and current_version()[0].isdigit()
print("  ✓ current_version:", current_version())

assert updater._ver_tuple("v0.3.0") > updater._ver_tuple("0.2.9")
assert updater._ver_tuple("0.2.0") == updater._ver_tuple("v0.2.0")
print("  ✓ Versions-Vergleich (semver-Tupel)")

assert updater.pip_url("v0.2.0") == "git+https://github.com/Ollornog/TinySesam.git@v0.2.0"
assert updater.pip_url("main", scheme="ssh").startswith("git+ssh://git@github.com/")
assert updater.pip_url("main", git_url="git+ssh://git@github-tinysesam/Ollornog/TinySesam.git") == \
       "git+ssh://git@github-tinysesam/Ollornog/TinySesam.git@main"
print("  ✓ pip-URL (https / ssh / Alias-Override, mit @ref)")

st = update_available(pin="v9.9.9")
assert st["available"] and st["source"] == "pin" and st["ref"] == "v9.9.9"
assert update_available(pin="v" + current_version())["available"] is False
print("  ✓ Version-Pin: Update nur wenn ≠ gepinnter Version")

db = tempfile.mktemp(suffix=".db")
auth = TinySesam(TinySesamConfig(db_path=db, passkey_enabled=False, oidc_enabled=False))
assert auth.update_settings() == {"mode": "manual", "pin": ""}
auth.set_update_setting("mode", "auto")
auth.set_update_setting("pin", "v0.2.0")
assert auth.update_settings() == {"mode": "auto", "pin": "v0.2.0"}
stx = auth.update_status()
assert stx["ref"] == "v0.2.0" and stx["source"] == "pin" and stx["mode"] == "auto"
auth.set_update_setting("mode", "manual")
assert auth.auto_update().get("skipped")
print("  ✓ Einstellungen: Modus manual/auto + Version-Pin, auto_update respektiert Modus")

os.remove(db)
print("\nUPDATE-MECHANISMUS OK ✅")
