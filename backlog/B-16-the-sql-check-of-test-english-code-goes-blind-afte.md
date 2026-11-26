---
type: Bug
title: The SQL check of test_english_code goes blind after an apostrophe in a SCHEMA comment
status: erledigt
id: B-16
milestone: M-1
created: '2026-11-22'
---
# B-16 — The SQL check of test_english_code goes blind after an apostrophe in a SCHEMA comment

Found while building the approvals (T-89): sql_findings() strips 'string literals' before looking for German words, with the pattern '[^']*'. An apostrophe inside a -- comment of the schema script ("the requester's channel") opens a literal that only the next apostrophe closes, and everything in between — table and column names included — is no longer checked. The mutation self-test ('a German table in the schema') turned red and caught it; the apostrophe was taken out of the comment, the check itself stays fragile. Fix: drop -- comments line by line before stripping literals (or tokenize the SQL), and add a self-probe with an apostrophe in a comment.

**Done (2026-11-24):** `sql_code()` scans the SQL once from left to right (closed literal with `''`, `-- comment`, code), both the SQL check and the string check use it; self-probes for an apostrophe in a comment and a `--` inside a literal, each proven by a mutation back to the old two-step stripping (literals first, comments first).
