---
id: T-6
type: Task
title: Build the E2E stage with a playbook instead of by hand
status: erledigt
milestone: M-1
tags: [e2e, deploy, testlab]
created: 2026-09-19
---

# T-6 — Make the stage for `e2e_stage.py` reproducible

[T-1](T-1-e2e-against-real-idp.md) proved that the three ceremony paths run against real
counterparts. The instance for that was, however, set up **by hand**: distribute the certificate,
reverse proxy, service, IdP with realm import, configuration. Next time that is manual work again —
and only those who were there know what exactly ran.

**Done when:** one run from a fresh throwaway container builds the complete stage
(proxy + service + IdP + configuration), `e2e_stage.py` then runs through green, and a second run
changes nothing. Addresses and credentials come from the environment, not from the repo.

**Note:** the peer name of the throwaway container is not stable as long as the old peer is not
cleaned up — otherwise an identifier creeps into the name and the redirect URI registered with the
provider no longer matches.

## Done (2026-09-19)

One run builds the complete stage from a fresh throwaway container: peer with a fixed name,
certificate, reverse proxy, own SAML provider, application with all three sign-in paths.
`tests/e2e_stage.py` then runs green against it; the second run reports `changed=0`.

The playbook lives in the deploy repo, not here — it is infrastructure, and addresses and
credentials do not belong in a public repo anyway. From here only the invocation leads there:
first build the stage, then `STAGE_BASE_URL=… python tests/e2e_stage.py`.

The warning above was confirmed, and more sharply than expected: the name gets an identifier
**even when** it is free. This is fixed by renaming through the API — but only if the name changes
in the process; a write with the same name does not recompute the label. The detour via an
intermediate name is documented as a comment in the playbook.
