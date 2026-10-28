# TinySesam — TODO

> **Moved (2026-07-23):** Open items, milestones and architecture decisions now live
> as individual files under **[`backlog/`](backlog/README.md)** — with structure,
> references and a check in the test suite. This file stays as the **history** of the
> completed versions.
>
> ```bash
> python3 scripts/_backlog.py list      # what is open
> python3 scripts/_backlog.py list --type Decision
> ```
>
> Conventions: [`backlog/README-KONVENTION.md`](backlog/README-KONVENTION.md).

## Done in 0.5
- **Forward-auth mode** (reverse proxy, for third-party/unmodifiable apps): `/auth/forward` +
  `/auth/verify` (200 + `Remote-*` or 401 + `X-TinySesam-Location`), `cookie_domain`,
  `trusted_redirect_hosts`; example configs `deploy/forward-auth/` (Caddy/nginx/Traefik).
- Factor chains (ordered, global + per route), step-up/per-route MFA, "stay signed in",
  personal PIN, shared resource secret (PIN/passphrase), magic link + mailer hook,
  registration + invitation, built-in account page, replaceable frontend (template registry),
  open-redirect hardening (`safe_next`).

## Done in 0.13
- **Gateway as a container image**: `Dockerfile` (non-root, without pip/git, `HEALTHCHECK`),
  `release.yml` pushes multi-arch to GHCR, Compose uses the image instead of `pip install` at
  runtime. New endpoint `GET /healthz`.
- **First real release**: `v0.12.0` with wheel, sdist and `SHA256SUMS`.

## Done in 0.12
- **Self-update removed** (`updater.py`, panel routes, `update_mode`/`update_pin`). The version
  is determined by whoever installs. A hygiene test keeps the button out.
- **`release.yml`**: tag → version check → suite → wheel + sdist + `SHA256SUMS` on the release.
- **Hygiene test against private infrastructure** (generic patterns, proper names only as a checksum).

## Done in 0.6–0.11
- LDAP/AD, SAML 2.0, Redis rate limit across several workers, CSRF (double-submit, on by default),
  recovery codes, forgot password, own session management, i18n (en/de),
  role/group management incl. IdP group mapping, first-admin bootstrap, demo mode.

## CI — done: stays on `ubuntu-latest`
Self-hosted runners are **ruled out** for this repo, not postponed. With a
public repo anyone can open a fork PR whose workflow would then run on foreign hardware;
non-ephemeral runners are thereby permanently compromisable — GitHub explicitly advises against it.
Cost is no counter-argument: public repos have unlimited minutes.

## Continuous Deployment — decided: no (2026-07-09)
No automatic rollout. GitHub Pages deploys the website itself (`pages.yml`), which is
stateless; everything else stays manual. Done, not open.
