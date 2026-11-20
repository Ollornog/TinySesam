"""The shipped list of common passwords (H1, ASVS 6.2.4 — at least the top 3000 the policy allows).

Until H1 the built-in blocklist held 128 entries, 86 of them long enough to be chosen at all. Checked here:

  (a) the file: 10,000 entries, 8–256 characters, lower case, unique, no control characters; source and
      license in the header (MIT notice of SecLists, public-domain origin of the data)
  (b) EVERY entry is rejected as a new password — and thousands of them got through with the hand list
      alone (presence is not effect: the file must be read, not just lie in the package)
  (c) through the library: registration-style policy check rejects an entry, accepts a long passphrase
  (d) the generator's selection rule on a small input (`scripts/_blocklist.py`)
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "scripts"))

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import passwords as pw  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


# ---------- (a) the file ----------
path = Path(pw.COMMON_PASSWORDS_FILE)
assert path.parent == ROOT / "tinysesam", path
text = path.read_text(encoding="utf-8")
header = [z for z in text.splitlines() if z.startswith("#")]
entries = [z for z in text.splitlines() if z and not z.startswith("#")]
assert len(entries) == 10_000, len(entries)
assert len(set(entries)) == len(entries), "duplicates"
assert all(8 <= len(e) <= pw.PASSWORD_MAX_LENGTH for e in entries)
assert all(e == e.lower() and e == e.strip() for e in entries)
assert not any(c < " " or c == "\x7f" for e in entries for c in e)
head = "\n".join(header)
for must in ("MIT License", "Copyright (c) 2018 Daniel Miessler", "public domain",
             "xato-net-10-million-passwords-100000.txt", "sha256 "):
    assert must in head, f"header without {must!r}"
assert entries[:3] == ["password", "12345678", "123456789"], entries[:3]   # frequency order
ok("common_passwords.txt: 10,000 entries of 8–256 characters, lower case, unique; source and MIT notice in the header")

# ---------- (b) every entry is rejected, and the file is what does it ----------
hand_only = pw.with_cores(pw.BLOCKLIST)
passed_before = [e for e in entries
                 if e not in hand_only and pw._core(e) not in hand_only and not pw._trivial(e)]
assert len(passed_before) > 5000, len(passed_before)
rejected = [e for e in entries if pw.password_defect(e, 8) == ("weak", {})]
assert len(rejected) == len(entries), [e for e in entries if e not in set(rejected)][:5]
# Upper case does not help (the comparison is lower case).
assert pw.password_defect(passed_before[0].upper(), 8) == ("weak", {}), passed_before[0]
ok(f"all 10,000 entries rejected as a new password — {len(passed_before)} of them passed with the hand list alone")

# ---------- (c) through the library ----------
db = os.path.join(tempfile.mkdtemp(), "t.db")
auth = TinySesam(TinySesamConfig(db_path=db, passkey_enabled=False, oidc_enabled=False, cookie_secure=False))
probe = passed_before[0]
assert auth.password_policy_error(probe, api=True) is not None
assert auth.password_policy_error("a breeze over the quiet ridge at dawn") is None
ok(f"password_policy_error: {probe!r} rejected, a long passphrase accepted")

# ---------- (d) the generator's selection rule ----------
import _blocklist  # noqa: E402

raw = "\n".join(["short", "Password1", "password1", "  spaced-out  ", "ctrl\x01char1", "# comment line",
                 "x" * 300, "ÄÖÜäöüßxx"]).encode() + b"\n\xff\xfebadutf8\n"
old = _blocklist.ENTRIES
try:
    _blocklist.ENTRIES = 3
    assert _blocklist.select(raw) == ["password1", "spaced-out", "äöüäöüßxx"], _blocklist.select(raw)
    _blocklist.ENTRIES = 4
    try:
        _blocklist.select(raw)
        raise AssertionError("too few entries must abort")
    except SystemExit:
        pass
finally:
    _blocklist.ENTRIES = old
ok("scripts/_blocklist.py: length 8–256, lower case, no duplicates/control characters/comments; too few → abort")

print("\nBLOCKLIST OK ✅")
