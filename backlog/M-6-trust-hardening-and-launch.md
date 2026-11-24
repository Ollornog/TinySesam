---
id: M-6
type: Milestone
title: "Trust, hardening and launch — before TinySesam is promoted widely"
status: offen
rank: 3
tags: [security, hardening, supply-chain, launch, roadmap]
created: 2026-11-23
---
# M-6 — Trust, hardening and launch

**Done when (measured):**

- Server-side fuzzing: at least eight targets in `nightly`, a planted parser bug is found
  ([T-121](T-121-server-side-fuzzing.md)).
- A public threat model, every promise linked to a test ([T-122](T-122-public-threat-model.md)).
- An independent review report exists, every finding fixed or accepted with a reason
  ([T-123](T-123-independent-review-external-penetration-test-or-human.md)); until then the README says "hardened, not
  independently reviewed".
- Crypto inventory with a guard against unlisted cryptographic calls, measured TLS groups, algorithm agility test
  ([T-124](T-124-crypto-inventory-and-post-quantum-readiness.md)).
- Gateway image without Authlib and Pillow; pip-audit and the image scan show the smaller surface
  ([T-110](T-110-dependency-diet-joserfc-instead-of-authlib-jose-qr-as-s.md)).
- Then the launch plan runs ([T-30](T-30-launch-plan.md)).

**Order in the roadmap:** after [M-5](M-5-clean-baseline-and-modules-before-shell-and-headless.md) (the fuzz targets,
the inventory and the diet need the module cut) and after the core of
[M-4](M-4-shell-and-headless-every-ui-mode-local-idp-mixed-users.md); not on the critical path of M-4. 1.0
([M-1](M-1-api-stable-1-0.md)) may come before; the launch comes after this milestone.

## Tasks

| Task | Title | SP | Hours |
|---|---|---|---|
| [T-110](T-110-dependency-diet-joserfc-instead-of-authlib-jose-qr-as-s.md) | dependency diet | 5 | 8–12 |
| [T-121](T-121-server-side-fuzzing.md) | server-side fuzzing | 5 | 8–12 |
| [T-122](T-122-public-threat-model.md) | public threat model | 3 | 4–6 |
| [T-124](T-124-crypto-inventory-and-post-quantum-readiness.md) | crypto inventory and PQ readiness | 5 | 8–12 |
| [T-123](T-123-independent-review-external-penetration-test-or-human.md) | independent review (own share) | 3 | 6–10 |
| [T-30](T-30-launch-plan.md) | launch plan | 5 | 8–12 |
| **Sum** | | see `dokutool offen` | |

The external review itself takes calendar time outside the project. Estimates, not measured.
