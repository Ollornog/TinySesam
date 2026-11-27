---
id: T-104
type: Task
title: "Stage S8 — hybrid: TinySesam area with name and icon, library layout slot"
status: offen
points: 13
milestone: M-2
blocked_by: [T-103]
tags: [hybrid, ui]
created: 2026-11-23
---
# T-104 — Stage S8 — hybrid: TinySesam area with name and icon, library layout slot

**Story points:** 13 · **Estimate:** 18–24 h (from the concept, not measured) · **Milestone:** [M-2](M-2-shell-and-headless-every-ui-mode-local-idp-mixed-users.md)

The application draws its own navigation; everything of TinySesam sits in a delimited TinySesam area.

## Content
- `apps[id].icon`, taken over from [T-100](T-100-stage-s4-permissions-app-identity-registration-assignme.md) on
  2026-11-27: it enters the configuration together with its reader, the area's frame and the gate heading (ADR-19);
  within the re-estimate at the start.
- `/auth/area?app=<id>`: tiles for account, security, sessions, programs, approvals and — for administrators of the application — administration, framed with the application's name, links and return path.
- Library: slot `page_layout` (head and foot HTML of the application, nonce from TinySesam, CSP unchanged).
- Mail links carry the frame (`app=` inside the token).
- **No "look per host"** with tokens: the gate shows the application's name and icon only ([ADR-19](ADR-19-gate-look-like-a-provider-sign-in-heading-and-icon-of-t.md)). The estimate of 18–24 h comes from the concept and included the look per host; re-estimate at the start.
- No area on the application's origin behind a proxy (an XSS of the application could post TinySesam forms).

## Acceptance
- **Ex3** hybrid (PHP or Node behind the server, mixed accounts): own navigation, one link "Account", everything else in the TinySesam area, return path.
