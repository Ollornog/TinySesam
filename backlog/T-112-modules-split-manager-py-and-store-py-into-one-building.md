---
id: T-112
type: Task
title: "Modules: split manager.py and store.py into one building block per feature; a feature that is off loads nothing"
status: erledigt
points: 21
milestone: M-5
blocked_by: [T-111]
tags: [architecture, modules, refactor]
created: 2026-11-23
---
# T-112 — Modules: one building block per feature

**Story points:** 21 · **Estimate:** 30–40 h (not measured) · **Milestone:** [M-5](M-5-clean-baseline-and-modules-before-shell-and-headless.md)

**Rule (maintainer, 2026-11-23):** build in modules, avoid monoliths. Every feature is a building block of its own;
only what is switched on is loaded — no routes, no code in the request path.

**Measured (main at 0.29.1):** `tinysesam/manager.py` 9,807 lines (the class `TinySesam`, about 445 methods),
`tinysesam/store.py` 5,628 lines, `config_check.py` 3,882, `router.py` 2,364.

## Content

- One package per feature (proposal, the inventory decides the cut): password and PIN, TOTP and recovery codes,
  passkeys, sign-in links and invitations, QR sign-in, OIDC, SAML, LDAP, API keys and pairing, OAuth authorization
  server, OAuth services, app passwords, approvals, account API (provisioning), roles and role catalog, delegated
  admins, admin panel, gate and forward auth, topbar and app frame, audit and security log, mail.
- Each feature brings its routes, its store part (tables and queries), its `config_check` rules and its messages.
  `TinySesam` becomes a thin facade: the tier-A/B methods stay on it (same names, same signatures) and delegate.
- A feature registry decides from `TinySesamConfig` what is loaded; [T-97](T-97-stage-s1-the-server-can-do-everything-toml-configuratio.md)
  then builds that configuration from the TOML file. Heavy optional imports (webauthn, ldap3, python3-saml, authlib)
  only inside their feature.
- `config_check.py` and `router.py` are split along the same lines.
- The layout table in `AGENTS.md` and the module map in `CONTRIBUTING.md` follow the new cut.
- No behaviour change: this is a pure restructuring; every behaviour change found on the way gets its own entry.

## Acceptance

- `manager.py` and `store.py` each below 1,500 lines; no module in `tinysesam/` above 2,000 lines (a guard in the
  suite, extended from an existing size or structure check, not a new tool).
- `tests/api_surface.json`: tiers A and B unchanged (0 changes), the HTTP contract unchanged.
- **A feature that is off loads nothing:** a test starts an application with each feature switched off in turn and
  proves that (a) none of its routes is in `app.routes`, (b) its module is not in `sys.modules` after start and a
  first request. A mutation (an unconditional import or route) turns it red.
- Suite green twice (`nightly-repeat`), import time of a minimal configuration measured before and after.

## Progress

- **Part 1 — the store (2026-11-25):** `store.py` 4,835 → below 1,500 lines. The core (connection, schema stamp,
  flow state, settings, backup) stays; 280 methods moved verbatim into 13 parts `tinysesam/_store_<part>.py` (users,
  factors, keys, federation, gate, sessions, throttle, tokens, audit, approvals, API keys, OAuth, roles), the schema
  text into `_store_schema.py`. A part is imported on the first use of one of its methods (`Store` looks it up in the
  index `_PART_METHODS` and fixes the method on the class); `tests/test_store_parts.py` pins index, lazy loading and
  the size limits for the store files. No behaviour change. The cut follows the sections of the old file; the parts
  move into the feature packages when manager, router and `config_check` are split.
- **Part 2 — config_check (#365):** 3,882 → 1,675 lines; rules by feature in `_config_check_roles.py`,
  `_config_check_apps.py`, the German table in `_config_check_de.py`, shared helpers in the leaf `_config_check_base.py`
  (no import cycle).
- **Part 3 — router:** the forward-auth block as `_routes_forward.py`, registered only with `forward_auth_enabled`;
  router.py 2,379 → 1,868. The HTTP-contract measurement (`tests/_contract.py`) reads the new module.
- **Part 4 — manager:** 9,661 → 1,428 lines; 374 methods in 15 building blocks `_manager_<part>.py`, loaded on first
  use; the feature registry `_features.py` loads only what a configuration switches on; qrcode/Pillow only when a QR
  is drawn.
- **Part 5 — guards:** `tests/test_store_parts.py` pins both indexes, "a feature that is off loads nothing" (with a
  counter-probe) and the size limits for every module; module map in `CONTRIBUTING.md`.
- Acceptance: manager.py 1,428 and store.py 1,322 lines (< 1,500), largest module 1,868 (router.py) (< 2,000); tiers A
  and B of `tests/api_surface.json` unchanged, HTTP contract unchanged (measured); start of a minimal configuration
  (import + construction, median of 7) 187 ms before, 194 ms after. The two `nightly-repeat` runs are the sprint end.
