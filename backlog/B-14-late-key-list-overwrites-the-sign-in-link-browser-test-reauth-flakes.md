---
id: B-14
type: Bug
title: 'Admin panel: a late key list overwrote the sign-in link; browser test ran out after a dialog that navigates'
status: erledigt
milestone: M-2
tags: [admin, ci, tests, flaky]
created: '2026-11-21'
---
# B-14 — Admin panel: a late key list overwrote the sign-in link; browser test ran out after a dialog that navigates

**Seen:** the browser test went red now and then in the CI job `repeat` and in local runs under load, in the reauth
and dialog steps: “the dialog did not close (at …/auth/reauth?next=…revoke_others=1)” (a Dependabot pull request),
“panel: no sign-in link” (two suites at once). Reproduced in the CI image: 40 runs of the browser test, six at a time,
next to eight busy loops, an fsync writer and 1.5 GiB of held memory — **4 of 40 red**, all “the dialog did not
close”.

## Cause 1 — the test: `answer()` after a dialog whose answer navigates
`answer()` clicked the button and then waited for `!window.__tsAnswered.isConnected`. When the answer makes the page
navigate (a 403 with `X-TinySesam-Reauth` sends it to the reauth page) and the navigation is quicker than the first
poll, the next document has no `__tsAnswered`: the condition threw on every poll, `until()` swallowed the error and
ran out. Forced: a pause of 1.5 s between click and first poll turns it red on every run with exactly the CI message;
with the fix it stays green.

**Fix:** a page that navigated away counts as a closed dialog
(`!(window.__tsAnswered && window.__tsAnswered.isConnected)`), and `until()` names the last error its condition threw
when it runs out.

## Cause 2 — the product: a late reply overwrote a newer view in the admin panel
`mkkey` refreshed the key list without waiting for it. When that reply came back after the sign-in link issued next,
it replaced the link card — and the link is shown once, never again. Forced in the browser: the server holds the
refresh until the link is out → “panel: no sign-in link” on every run; with the fix green.

**Fix:** each view of an account's detail row (keys, passkeys, sign-in link) claims the row before it asks the server
and writes only while its claim is the newest (`claimRow` in `tinysesam/admin.py`). The browser test now forces the
order itself (the page's `fetch` holds the refresh until the link is on screen) and checks the link stays; with the
old panel it goes red.

## Not reproduced
Once (a full suite under load, before the diagnostics of attack round B) the reauth step of `h2_stepup_qr` stayed on
the reauth page and the server logged a wrong, non-empty password. In 80 runs under load it did not come back (in
the 40 with the fix, a spy on `confirm_password` saw all 80 reauth submissions carry the right password); a slowed
reauth page, which makes `both_widths` measure the old document while the reload is pending, leaves the step green
(the form submission wins over the pending reload). The diagnostics from attack round B (field value at the click,
the page's answer) stay in place.

**After the fix:** 0 of 40 runs red under the same load.
