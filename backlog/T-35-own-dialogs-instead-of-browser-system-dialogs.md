---
id: T-35
type: Task
title: Own dialogs instead of the browser's system dialogs, with a copy button
status: erledigt
milestone: M-2
tags: [ui, dialog, api-keys, recovery-codes, accessibility, csp]
created: '2026-11-20'
---
# T-35 — Own dialogs instead of the browser's system dialogs, with a copy button

Wish (PO 2026-11-20): a new API key opened in the browser's system box — an own popup is better, and a copy button.

**Before:** 23 calls of `alert`/`confirm`/`prompt` (10 in `tinysesam/templates.py`: account page, passkey sign-in,
the offer after a factor change; 13 in `tinysesam/admin.py`). Unstyled, blocking the tab, the API key in a plain
text field, no copy button; recovery codes stayed printed on the account page.

Done when: one reusable building block (native `<dialog>`, Promise-based `tsAlert`/`tsConfirm`/`tsPrompt`/
`tsSecret`, tokens only, no inline handler, CSP nonce, focus trap, Escape = cancel, Enter = confirm, focus back,
`aria-*`, de + en) in both surfaces; every call replaced and a guard that keeps it so; a copy button on every secret
shown once (API key on account page and panel, the admin's sign-in link, recovery codes on the account page and the
TOTP setup page) with a fallback without the clipboard API; browser test with real key presses; README de + en,
CHANGELOG.

## Done (2026-11-20)

- `tinysesam/dialog.py`: CSS (scoped to `dialog.tsdlg`, `--ts-*` only) + script; included by the account page, the
  login page (with passkeys), the TOTP setup page and the admin panel; own templates get it as `ctx["dialog"]`.
- All 23 calls replaced; `tests/test_dialogs.py` fails on any call in `tinysesam/`, `web/`, `examples/`.
- `tests/test_browser.py` (`own_dialogs`, in a tab of its own): Escape/Enter/Cancel values, Tab trap, focus return,
  clipboard read back, fallback selection, no CSP violation. Mutation: Escape → confirm, copy fallback without
  selection, a system dialog back in the panel → red each. Focus return: two mechanisms, each enough on its own —
  Chrome restores the focus natively on `close()`, and `finish()` returns it explicitly (for browsers that do not).
  Removing one stays green (measured both ways), removing both → red.
