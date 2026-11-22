---
type: Bug
title: The SQL check of test_english_code goes blind after an apostrophe in a SCHEMA comment
status: offen
id: B-16
milestone: M-2
created: '2026-11-22'
---
# B-16 — The SQL check of test_english_code goes blind after an apostrophe in a SCHEMA comment

Found while building the approvals (T-89): sql_findings() strips 'string literals' before looking for German words, with the pattern '[^']*'. An apostrophe inside a -- comment of the schema script ("the requester's channel") opens a literal that only the next apostrophe closes, and everything in between — table and column names included — is no longer checked. The mutation self-test ('a German table in the schema') turned red and caught it; the apostrophe was taken out of the comment, the check itself stays fragile. Fix: drop -- comments line by line before stripping literals (or tokenize the SQL), and add a self-probe with an apostrophe in a comment.
