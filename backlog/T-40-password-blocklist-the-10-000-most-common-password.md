---
id: T-40
type: Task
title: 'Password blocklist: the 10,000 most common passwords shipped (ASVS 6.2.4)'
status: erledigt
milestone: M-5
tags: [password, security, asvs]
created: '2026-11-20'
---
# T-40 — Password blocklist: the 10,000 most common passwords shipped (ASVS 6.2.4)

Source: Security review 2026-11-20 (ASVS 5.0.0, NIST SP 800-63B-4; state main b1d166c), finding M3 — ASVS 6.2.4 (L1) asks for at least the top 3000 that match the policy.

**Was:** 128 hand-picked entries, 86 of them ≥ 8 characters.

## Done (H1)
- `tinysesam/common_passwords.txt` (package data, ~91 KB, under 40 KB compressed): the first 10,000 passwords with
  8–256 characters from SecLists `xato-net-10-million-passwords-100000.txt`, pinned by commit and SHA-256, lower case,
  in frequency order. License: SecLists MIT (notice in the file header); the data itself was released to the public
  domain by its author (Mark Burnett, 2015). Offline as before (H-17).
- `scripts/_blocklist.py` regenerates and checks it (`--check`); `tests/test_blocklist.py`: every entry is rejected,
  9,427 of them passed with the hand list alone.
