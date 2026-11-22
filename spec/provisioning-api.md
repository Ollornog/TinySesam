# Account API for applications — client specification (stage A, with the access reset)

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
| `GET /auth/api/provisioning` | — | `200` `{"app", "name", "scopes", "roles", "approver_role", "link_ttl_min", "max_accounts", "accounts", "limits", "remaining"}` |
| `POST /auth/api/approvals` (type `tinysesam.account.reset_access`) | `users:reset` | `201` `{"id", "state", "match_code", "approve_url", "expires_at"}` — §5 |
| `GET /auth/api/approvals/{id}?wait=` | — | `200` status; once, after the confirmation, with `output` — §5 |
| `DELETE /auth/api/approvals/{id}` | — | `200` status (`withdrawn`) while still `pending` |

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

## 5. Resetting the access of an account (approval `tinysesam.account.reset_access`)

The common case after the first sign-in: a person has a new phone (the TOTP is gone) or forgot the password. The key
alone cannot help — a link after the first sign-in would be a takeover. Instead the application asks for an
**approval** that a person confirms in the browser: the application's team admin, who must hold the role
`apps[…].provisioning.approver_role` at the moment of confirming. That role is granted only by the operator (or a
delegate allowed to), never through this API.

1. **Ask** (scope `users:reset`), with the same key, no actor header needed:

   ```http
   POST /auth/api/approvals
   X-Api-Key: tsk_…(key of svc-example)

   {"type": "tinysesam.account.reset_access", "subject": "17", "fields": {"account": "42"}}
   ```

   `subject` = the TinySesam account id of the team admin who confirms, `fields.account` = the account to reset — both
   decimal ids **as strings**. Answer `201` `{"id": "apv_…", "state": "pending", "match_code": "418 207",
   "approve_url": "https://auth.example.com/auth/approvals/apv_…", "expires_at": …}`. Show the team admin the match
   code and send them to `approve_url`.
2. **Confirm** (the team admin, in the browser): the page names the account, the application and what happens, the
   person compares the code and confirms with a step-up of this approval (password, PIN, TOTP, passkey or the
   provider). Then every sign-in factor of the account is deleted — password, PIN, TOTP with its recovery codes,
   passkeys — its sessions end, its API keys, app passwords and connected programs are revoked, open links die.
   `first_login_at` stays; the new link is the only way back in.
3. **Pick up** the link — exactly once:

   ```http
   GET /auth/api/approvals/apv_…?wait=25
   X-Api-Key: tsk_…
   ```

   Before the decision: `{"state": "pending", …}` (with `wait` the call returns as soon as it changes). The first read
   after the confirmation answers `{"state": "consumed", "result": "ok", "output": {"account": "42", "signin_url": …,
   "expires_at": …, "qr": …}}` — the link lives `link_ttl_min` minutes. Every later read answers `consumed` without
   `output`; if the answer is lost, ask for a new reset. Not picked up within `approval_pending_sec` after the
   confirmation → `expired` (the factors are deleted all the same; ask again).
4. **Results** besides `ok` (state `consumed`, no `output`): `forbidden` — the person who confirmed does not hold
   `approver_role` (any more), is the account itself, or the application lost `users:reset`; `not_found` — the account
   is no longer the application's (deleted, became administrator, delegate or service account); `conflict` — it holds
   a role outside the allowlist now, it is disabled, or no link could be issued. Other states: `rejected`,
   `withdrawn`, `expired` — nothing changed.

Errors of the request (`{"error", "error_description"}`):

| Status | `error` | Meaning |
|---|---|---|
| 400 | `invalid_type` | another type (an application asks only for `tinysesam.account.reset_access`) |
| 400 | `invalid_request` | malformed body, unknown member, an id that is not a decimal string |
| 400 | `invalid_subject` | `subject` is no active person (counts against `taken_per_hour`) |
| 403 | `scope_missing` | the application does not hold `users:reset` (or has no valid `approver_role`) |
| 403 | `forbidden` | `subject` and `account` are the same account |
| 403 | `no_approver` | the key belongs to a service account that is no application |
| 404 | `not_found` | not the application's account — or an administrator, service account or delegate |
| 409 | `account_shared` | the account holds roles outside the allowlist |
| 409 | `account_disabled` | the account is disabled |
| 429 | `too_many_requests` | `approval_open_per_token` open requests of this application, `approval_requests_per_hour` for the subject, or the rejection lock |

Whether `subject` holds `approver_role` is not checked when asking (the key would learn who the approvers are); a
subject without it sees the page with "your right: missing", and confirming ends in `forbidden`.

## 6. Recommended client behaviour

- Call `GET /auth/api/provisioning` at start and refuse to run when scopes or roles differ from what the application
  expects.
- After a network error on create, look the account up in the list (`GET /auth/api/users`) and issue a new link with
  `POST …/signin-link` instead of creating again (that answers `409 username_taken`).
- Never log `signin_url` or `qr` — also not the `output` of an approval.
- Poll an access reset with `?wait=25` and keep the first answer that carries `output`; there is no second.
