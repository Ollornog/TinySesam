# Account API for applications — client specification (stage A)

Language-neutral description of `/auth/api/users` for clients in any language. The server side, its configuration
(`apps[…].provisioning`) and its security rules are in the README ("Accounts for applications") and `SECURITY.md`
("Account API for applications").

## 1. Calling

- **Base:** the TinySesam instance itself (its `base_url`), not the reverse proxy of the application.
- **Credential:** an automation key of the application's service account, as `X-Api-Key: tsk_…` or
  `Authorization: Bearer tsk_…`. No cookie, no CSRF token.
- **Actor:** every write (`POST`, `PATCH`) carries `TinySesam-On-Behalf-Of: <account id>` — the TinySesam account of
  the person the application acts for — or `TinySesam-On-Behalf-Of: -` for a job without a person. TinySesam records
  it as a claim; it does not check that the person may do the action.
- **Bodies** are JSON objects; an unknown member is refused (`400 invalid`), never ignored.
- **Answers** are JSON with `Cache-Control: no-store`. There is no CORS.

## 2. Routes

| Method and path | Scope | Success |
|---|---|---|
| `POST /auth/api/users` | `users:invite` | `201` `{"id", "username", "signin_url", "expires_at", "qr", "user"}` |
| `GET /auth/api/users/{id}` | `users:read` | `200` account (§3) |
| `GET /auth/api/users?limit=&after=&role=&state=` | `users:read` | `200` `{"users": [account, …], "next": id or null}` |
| `PATCH /auth/api/users/{id}` | `users:update` | `200` account |
| `POST /auth/api/users/{id}/disable` | `users:disable` | `200` account |
| `POST /auth/api/users/{id}/enable` | `users:disable` | `200` account |
| `POST /auth/api/users/{id}/signin-link` | `users:invite` | `200` `{"id", "signin_url", "expires_at", "qr"}` |
| `GET /auth/api/provisioning` | — | `200` `{"app", "name", "scopes", "roles", "link_ttl_min", "max_accounts", "accounts", "limits", "remaining"}` |

- **Create:** `{"username", "display_name"?, "email"?, "roles"}`. `roles` holds at least one role, all from the
  allowlist. In the mode where the address is the sign-in name, `username` may be left out and follows `email`.
  `password`, `is_admin` and `is_service` are refused. The address is stored unconfirmed and cannot be changed later
  through this API.
- **List:** `limit` 1–200 (default 100), `after` = the `next` of the previous page, `role` = one allowlist role,
  `state` = one of §3. Pages are in id order.
- **Update:** `{"display_name"?, "roles"?}` — `roles` is the whole wanted set within the allowlist (an empty list is
  allowed); roles outside the allowlist stay untouched. `email`, `username`, `is_admin`, `password` → `400 invalid`.
- **Disable/enable:** the application's own lock. Disabling an account that is already locked by the operator changes
  nothing (state `disabled_operator`); enabling it answers `409 disabled_by_operator`.
- **Sign-in link:** only while the account has never signed in (`first_login_at` is null); every older open link of the
  account dies. The link and the QR code (a PNG data URI, or null) exist only in the answer — store them nowhere,
  hand them to the person.

## 3. The account

```json
{"id": 42, "username": "lena", "display_name": "Lena M.", "email": "lena@example.org", "email_verified": false,
 "roles": ["example-member"], "other_roles": false, "state": "active",
 "created_at": 1767226200, "first_login_at": null, "last_login_at": null, "delete_after": null}
```

- `roles`: only the roles of the application's allowlist. `other_roles: true` says the account also holds others
  (granted by the operator) — then `display_name`, disable/enable and the sign-in link answer `409 account_shared`.
- `state`: `active` · `disabled` (by the application) · `disabled_operator` (by the operator or a pending confirmation;
  only the operator lifts it) · `deleting` (stage B, with `delete_after`).
- Times are Unix seconds (UTC) or null.

## 4. Errors

`{"error": "<code>", "error_description": "<text>"}` — the text is for people; a client branches on `error` and the
status.

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid` | malformed body, unknown or unchangeable member, bad query parameter |
| 400 | `actor_required` / `actor_invalid` | no `TinySesam-On-Behalf-Of` on a write / not an active person's id |
| 400 | `role_not_allowed` | a role outside the allowlist (or none on create); the answer carries `"roles": [allowlist]` |
| 400 | `name_invalid` / `email_invalid` | the username or the address is not acceptable |
| 401 | `unauthenticated` | no key, or not a valid one |
| 403 | `not_a_provisioning_app` | the key does not belong to an application's service account (or is not an automation key) |
| 403 | `scope_missing` | the application does not hold the scope (named in `error_description`) |
| 404 | `not_found` | no such account — or one the application does not own, an administrator, a service account or a delegate |
| 409 | `username_taken` / `email_taken` | the name or address is in use |
| 409 | `quota_reached` | `max_accounts` reached |
| 409 | `account_shared` | whole-account action on an account with roles outside the allowlist |
| 409 | `already_signed_in` | sign-in link after the first sign-in |
| 409 | `account_disabled` | sign-in link for a locked account |
| 409 | `disabled_by_operator` | enable on a lock that is not the application's |
| 429 | `limit` | an hourly limit (`error_description` names it); wait `Retry-After` seconds |

**Reserved:** a write route may answer `202` with `{"approval": {"id", "approve_url", "match_code"}}` once approvals
for these actions exist. A client treats `202` as "not done yet" from the start.

## 5. Recommended client behaviour

- Call `GET /auth/api/provisioning` at start and refuse to run when scopes or roles differ from what the application
  expects.
- After a network error on create, look the account up in the list (`GET /auth/api/users`) and issue a new link with
  `POST …/signin-link` instead of creating again (that answers `409 username_taken`).
- Never log `signin_url` or `qr`.
