"""Approvals, stage A: a token proposes one sensitive TinySesam action, the person confirms it in the browser.

    TinySesamConfig(approvals_enabled=True, base_url="https://auth.example.com")

A script or Claude holds an API key of the account. It may not change roles, revoke a key of someone else or disable
an account on its own — those are admin actions, and an API key never carries the admin flag nor a delegate role
(R6-5, E4). With approvals it can **ask**:

    POST /auth/api/approvals        {"type": "tinysesam.account.set_roles",
    X-Api-Key: tsk_…                  "fields": {"account": "17", "add": ["editors"], "remove": ["viewers"]}}
    → 201 {"id": "apv_…", "state": "pending", "match_code": "418 207", "approve_url": "…", "expires_at": …}

The person opens `approve_url` in their browser session (only the account the key belongs to can, and only with a
session — never with a token), compares the match code, confirms once more for THIS approval (password, PIN, TOTP,
a passkey whose challenge is bound to the approval id and its payload hash, or a fresh sign-in at the provider with
`max_age=0`) and TinySesam executes the action with the admin panel's own code (`admin.PanelActions`), checking the
rights the session has at that moment. The token reads the outcome with `GET /auth/api/approvals/{id}`.

Why this does not soften E4 ("delegate and admin rights never through tokens"): the token only writes a row; the
decision happens in a browser session of the same account with a fresh step-up per approval; the rights checked are
the session's at confirmation time; nothing lasting is granted (one action, once, for minutes); the audit names both
the requester (the key) and the person who confirmed. See SECURITY.md "Approvals".

Every state change is one `UPDATE … WHERE state = <old>` (`Store.approval_transition`): two confirmations race to
exactly one winner, and only the winner executes.
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import secrets
import time
from typing import Any, Optional

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from . import security

#: The class (a) types of stage A and their fields (`str_id` = a positive decimal id as a string, `roles` = a list of
#: role names). `tinysesam.` is reserved for these; application types (class b) come with stage B.
TYPES: dict[str, dict[str, str]] = {
    "tinysesam.account.set_roles": {"account": "str_id", "add": "roles", "remove": "roles"},
    "tinysesam.apikey.revoke": {"key": "str_id"},
    "tinysesam.account.disable": {"account": "str_id"},
}
#: Fields a type may leave out (an empty list then).
OPTIONAL_FIELDS = {"tinysesam.account.set_roles": {"add", "remove"}}
#: Types whose effect cannot be undone — the page says so with a symbol AND a word, never with colour alone.
IRREVERSIBLE = frozenset({"tinysesam.apikey.revoke"})

STATES = ("pending", "approved", "consumed", "rejected", "expired", "withdrawn")
#: Outcome of a class (a) action (`result`): what the panel code answered, in one word.
RESULTS = ("ok", "forbidden", "not_found", "invalid", "conflict")

_ID = re.compile(r"^apv_[a-z2-7]{26}$")
_STR_ID = re.compile(r"^[1-9][0-9]{0,17}$")
_MAX_ROLES = 50
_MAX_ROLE_LEN = 100
#: The longest long-poll (`GET …?wait=`), in seconds.
MAX_WAIT_SEC = 25
#: How long closed rows are kept when `audit_retention_days` sets no deadline.
KEEP_DAYS = 30
#: How long a passkey challenge or a provider confirmation for one approval stays usable.
STEPUP_TTL_SEC = 300
#: Prefix of the passkey challenge: SHA-256("tinysesam-approval:" ‖ nonce ‖ id ‖ payload_hash).
CHALLENGE_PREFIX = b"tinysesam-approval:"
#: RFC 8176 `amr` per step-up method; the provider confirmation has no RFC value of its own (the provider decides how
#: it signed the person in), so TinySesam records `oidc`.
AMR = {"password": ["pwd"], "pin": ["pin"], "totp": ["otp"], "passkey": ["hwk", "user"], "oidc": ["oidc"]}


class ApprovalError(Exception):
    """A refused request: `code` is the machine word in the JSON answer, `status` the HTTP status."""

    def __init__(self, code: str, status: int, detail: str = ""):
        super().__init__(code)
        self.code, self.status, self.detail = code, status, detail


def _now() -> int:
    return int(time.time())


def canonical(obj: Any) -> str:
    """RFC 8785 (JCS) for the values an approval holds — strings, integers, booleans, lists and objects with ASCII
    keys: sorted keys, no whitespace, UTF-8 instead of escapes. Python's `json` writes exactly that for these values
    (control characters, which JCS escapes the same way, are refused before)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def payload_hash(payload: str) -> str:
    """SHA-256 over the canonical payload, base64url without padding."""
    return base64.urlsafe_b64encode(hashlib.sha256(payload.encode("utf-8")).digest()).rstrip(b"=").decode("ascii")


def new_id() -> str:
    """`apv_` + 128 bits of randomness, base32 (lower case, no padding): public in the link, not guessable."""
    return "apv_" + base64.b32encode(secrets.token_bytes(16)).decode("ascii").rstrip("=").lower()


def new_match_code() -> str:
    """Six digits in two groups — shown by the requester and on the page, against mixing up two requests."""
    n = f"{secrets.randbelow(10 ** 6):06d}"
    return f"{n[:3]} {n[3:]}"


def valid_id(value: str) -> bool:
    return bool(_ID.match(str(value or "")))


def _role_ok(r) -> bool:
    return (isinstance(r, str) and 0 < len(r) <= _MAX_ROLE_LEN and "," not in r and r == r.strip()
            and not any(ord(z) < 32 or ord(z) == 127 for z in r))


def normalize(type_: Any, fields: Any) -> dict:
    """The stored payload of a request — `{"type": …, <fields>}` like an RFC 9396 `authorization_details` entry —
    or `ApprovalError("invalid_request", 400)`. Unknown, missing or wrongly typed fields are refused, never dropped;
    control characters are refused, never removed."""
    if not isinstance(type_, str) or type_ not in TYPES:
        raise ApprovalError("invalid_type", 400, "type")
    if not isinstance(fields, dict):
        raise ApprovalError("invalid_request", 400, "fields")
    spec = TYPES[type_]
    unknown = sorted(set(fields) - set(spec))
    if unknown:
        raise ApprovalError("invalid_request", 400, f"unknown field {unknown[0]}")
    out: dict = {"type": type_}
    for name, kind in spec.items():
        if name not in fields:
            if name in OPTIONAL_FIELDS.get(type_, ()):
                out[name] = []
                continue
            raise ApprovalError("invalid_request", 400, f"missing field {name}")
        value = fields[name]
        if kind == "str_id":
            if not isinstance(value, str) or not _STR_ID.match(value):
                raise ApprovalError("invalid_request", 400, f"field {name}")
            out[name] = value
        elif kind == "roles":
            if (not isinstance(value, list) or len(value) > _MAX_ROLES or not all(_role_ok(r) for r in value)
                    or len(set(value)) != len(value)):
                raise ApprovalError("invalid_request", 400, f"field {name}")
            out[name] = sorted(value)
    if type_ == "tinysesam.account.set_roles":
        if not out["add"] and not out["remove"]:
            raise ApprovalError("invalid_request", 400, "add or remove")
        if set(out["add"]) & set(out["remove"]):
            raise ApprovalError("invalid_request", 400, "a role in add and remove")
    return out


def challenge(nonce: bytes, approval_id: str, digest: str) -> bytes:
    """The passkey challenge of one approval: SHA-256(prefix ‖ nonce ‖ id ‖ payload_hash). The nonce lies on the
    server and is used once — so the gesture is bound to exactly this action and cannot be replayed."""
    return hashlib.sha256(CHALLENGE_PREFIX + nonce + approval_id.encode("ascii") + digest.encode("ascii")).digest()


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _detail(value) -> str:
    """A value for an audit detail: no spaces or control characters (the detail is `key=value` pairs)."""
    return "".join(z if z > " " and z != "\x7f" else "_" for z in str(value or ""))[:120] or "-"


class Approvals:
    """The approvals of one TinySesam instance (`auth._approvals()`): requests, decisions, execution, cleanup."""

    def __init__(self, auth):
        self.auth = auth
        self.cfg = auth.cfg
        self.store = auth.store

    # ---------- requester (a token) ----------
    def requester(self, request: Request) -> tuple[dict, dict]:
        """(account, key row) of the API key this request carries — the only credential that may ask (stage A).

        A session is not enough (it has the panel), an OAuth or MCP token not yet (until TinySesam is an MCP resource
        itself), an app password never. A `human` key counts only beside a session of the same account, as
        everywhere (R6-5). A service account never asks for itself: nobody could confirm (`no_approver`)."""
        auth = self.auth
        key = auth._extract_api_key(request)
        if not key:
            if (request.headers.get("authorization") or "").strip():
                raise ApprovalError("unsupported_token", 403, "only an API key can request an approval")
            raise ApprovalError("unauthorized", 401)
        auth._remember_request(request)
        u, _scope = auth.verify_api_key(key)
        row = self.store.get_api_key_by_hash(hashlib.sha256(key.encode()).hexdigest()) if u else None
        if u is None or row is None:
            raise ApprovalError("unauthorized", 401)
        if auth._key_kind(row) == "human":
            s = auth._session_from_request(request)
            if not (s and s["mfa_ok"] and s["user_id"] == u["id"]):
                raise ApprovalError("unauthorized", 401)
        auth._remember_request(request, u)
        if u.get("is_service"):
            auth.audit("approval_denied", u["username"], auth.client_ip(request), f"reason=no_approver key={row['id']}")
            raise ApprovalError("no_approver", 403, "a service account cannot confirm an approval")
        return u, row

    # ---------- limits ----------
    def _throttled(self, uid: int, ref: str, type_: str, now: int) -> Optional[str]:
        cfg = self.cfg
        if self.store.count_approvals_pending(uid, now) >= int(cfg.approval_open_per_account):
            return "open_per_account"
        if self.store.count_approvals_open_by("apikey", ref, now) >= int(cfg.approval_open_per_token):
            return "open_per_token"
        if self.store.count_approvals_since(uid, now - 3600) >= int(cfg.approval_requests_per_hour):
            return "per_hour"
        limit = int(cfg.approval_reject_limit)
        times = self.store.approval_rejections("apikey", ref, type_, now - 7200)
        for i in range(limit - 1, len(times)):
            if times[i] - times[i - limit + 1] <= 3600 and times[i] > now - 3600:
                return "rejections"
        return None

    # ---------- create / read / withdraw ----------
    def create(self, request: Request, body: Any) -> dict:
        auth = self.auth
        u, key = self.requester(request)
        if not isinstance(body, dict):
            raise ApprovalError("invalid_request", 400, "body")
        if "subject" in body:
            # Class (a) always concerns the account of the token; naming another one is an application's request
            # (class b, stage B) — refused, not ignored.
            raise ApprovalError("invalid_request", 400, "subject is not allowed for TinySesam actions")
        extra = sorted(set(body) - {"type", "fields"})
        if extra:
            raise ApprovalError("invalid_request", 400, f"unknown member {extra[0]}")
        payload = normalize(body.get("type"), body.get("fields"))
        now = _now()
        ref = str(key["id"])
        ip = auth.client_ip(request)
        why = self._throttled(int(u["id"]), ref, payload["type"], now)
        if why:
            auth.audit("approval_throttled", u["username"], ip, f"type={payload['type']} key={ref} reason={why}")
            raise ApprovalError("too_many_requests", 429, why)
        text = canonical(payload)
        row = {"id": new_id(), "class": "tinysesam", "type": payload["type"], "app_id": None,
               "subject_id": int(u["id"]), "requester_kind": "apikey", "requester_ref": ref,
               "payload": text, "payload_hash": payload_hash(text), "match_code": new_match_code(),
               "return_url": None, "state": "pending", "created_at": now,
               "expires_at": now + int(self.cfg.approval_pending_sec), "ip_request": ip}
        self.store.add_approval(row)
        auth.audit("approval_requested", u["username"], ip,
                   f"id={row['id']} type={row['type']} key={ref} hash={row['payload_hash']}")
        return {"id": row["id"], "state": "pending", "match_code": row["match_code"],
                "approve_url": self.approve_url(row["id"]), "expires_at": row["expires_at"]}

    def approve_url(self, approval_id: str) -> str:
        base = (security.normalize_base(str(self.cfg.base_url or "").strip()) or "").rstrip("/")
        return f"{base}/auth/approvals/{approval_id}"

    def _expire_if_due(self, row):
        """An open row past its deadline becomes `expired` now (the cleanup does the same for all) — returns the
        current row."""
        if row is not None and row["state"] in ("pending", "approved") and row["expires_at"] < _now():
            if self.store.approval_transition(row["id"], row["state"], "expired", decided_at=_now()):
                self.auth.audit("approval_expired", self.auth._account_name(row["subject_id"]), None,
                                f"id={row['id']} type={row['type']}")
            row = self.store.get_approval(row["id"])
        return row

    def own(self, request: Request, approval_id: str):
        """The row of an approval this request's key asked for — otherwise 404 (no oracle: a foreign id and an
        unknown one answer alike)."""
        _u, key = self.requester(request)
        row = self.store.get_approval(approval_id) if valid_id(approval_id) else None
        if row is None or row["requester_kind"] != "apikey" or row["requester_ref"] != str(key["id"]):
            raise ApprovalError("not_found", 404)
        return self._expire_if_due(row)

    @staticmethod
    def status(row) -> dict:
        out = {"id": row["id"], "state": row["state"], "type": row["type"], "expires_at": row["expires_at"]}
        if row["state"] == "consumed" and row["class"] == "tinysesam":
            out["result"] = row["result"]
        if row["decided_at"]:
            out["decided_at"] = row["decided_at"]
        return out

    def withdraw(self, request: Request, approval_id: str) -> dict:
        row = self.own(request, approval_id)
        if row["state"] != "pending" or not self.store.approval_transition(row["id"], "pending", "withdrawn",
                                                                          decided_at=_now()):
            raise ApprovalError("conflict", 409, self.store.get_approval(row["id"])["state"])
        self.auth.audit("approval_withdrawn", self.auth._account_name(row["subject_id"]),
                        self.auth.client_ip(request), f"id={row['id']} type={row['type']}")
        return self.status(self.store.get_approval(row["id"]))

    # ---------- the person (a browser session) ----------
    def pending_count(self, user) -> int:
        try:
            uid = int(user["id"])
        except (KeyError, IndexError, TypeError, ValueError):
            return 0
        return self.store.count_approvals_pending(uid, _now())

    def methods(self, u: dict) -> list:
        """The step-up methods the approval page offers this account: what the reauth page offers (`stepup_options`,
        narrowed by `stepup_methods`), a passkey when the account has one, the provider when it is linked there."""
        auth = self.auth
        out = list(auth.stepup_options(u))
        if auth.webauthn is not None and auth.store.list_webauthn(u["id"]):
            out.append("passkey")
        if auth._confirms_at_provider(u):
            out.append("oidc")
        return out

    def view(self, row, viewer: dict) -> dict:
        """What the page shows of an approval — built from the payload AND the current database state, every value
        as data (the templates escape it). A target the viewer may not manage right now is named by its id only:
        the page must not tell a token holder the names of accounts it could not see in the panel."""
        auth = self.auth
        payload = json.loads(row["payload"])
        scopes = None if auth.is_admin(viewer) else auth._delegate_scopes(viewer)
        rows: list = []

        def account(uid_text):
            target = auth.store.get_user(int(uid_text))
            visible = target is not None and (
                int(target["id"]) == int(viewer["id"]) or auth.is_admin(viewer)
                or (scopes is not None and self._panel().visible(target, viewer, scopes)))
            if not visible:
                return f"#{uid_text}", None, False
            return f"{target['username']} (#{uid_text})", target, True

        t = auth.t
        type_ = row["type"]
        if type_ == "tinysesam.account.set_roles":
            label, target, visible = account(payload["account"])
            current = sorted(map(str, auth.user_roles(target))) if visible else None
            after = (sorted((set(current) - set(payload["remove"])) | set(payload["add"]))
                     if current is not None else None)
            summary = t("apv.sum.set_roles", account=label, add=", ".join(payload["add"]) or "—",
                        remove=", ".join(payload["remove"]) or "—")
            rows = [(t("apv.f.account"), label), (t("apv.f.add"), ", ".join(payload["add"]) or "—"),
                    (t("apv.f.remove"), ", ".join(payload["remove"]) or "—")]
            if current is not None:
                rows += [(t("apv.f.current"), ", ".join(current) or "—"), (t("apv.f.after"), ", ".join(after or []) or "—")]
            else:
                rows.append((t("apv.f.current"), t("apv.not_visible")))
        elif type_ == "tinysesam.account.disable":
            label, target, visible = account(payload["account"])
            summary = t("apv.sum.disable", account=label)
            rows = [(t("apv.f.account"), label)]
            if not visible:
                rows.append((t("apv.f.state"), t("apv.not_visible")))
            elif target is not None:
                rows.append((t("apv.f.state"), t("apv.disabled") if target["disabled"] else t("apv.active")))
        else:  # tinysesam.apikey.revoke
            k = auth.store.get_api_key(int(payload["key"]))
            mine = k is not None and int(k["user_id"]) == int(viewer["id"])
            if k is not None and (mine or auth.is_admin(viewer)):
                owner = auth._account_name(k["user_id"]) or "?"
                label = f"{k['name'] or '—'} ({k['prefix']}, #{payload['key']})"
                rows = [(t("apv.f.key"), label), (t("apv.f.owner"), owner),
                        (t("apv.f.state"), t("apv.revoked") if k["revoked"] else t("apv.active"))]
            else:
                label = f"#{payload['key']}"
                rows = [(t("apv.f.key"), label), (t("apv.f.state"), t("apv.not_visible"))]
            summary = t("apv.sum.revoke", api_key=label)
        key = auth.store.get_api_key(int(row["requester_ref"])) if row["requester_kind"] == "apikey" else None
        via = (t("apv.via_key", name=key["name"] or "—", prefix=key["prefix"],
                 date=time.strftime("%Y-%m-%d", time.gmtime(key["created_at"] or 0)))
               if key is not None else t("apv.via_gone"))
        return {"id": row["id"], "type": type_, "title": t("apv.title." + type_), "summary": summary, "rows": rows,
                "irreversible": type_ in IRREVERSIBLE, "match_code": row["match_code"], "via": via,
                "state": row["state"], "result": row["result"], "payload_hash": row["payload_hash"],
                "expires_at": row["expires_at"], "minutes_left": max(0, (row["expires_at"] - _now() + 59) // 60)}

    def _panel(self):
        from .admin import PanelActions
        return PanelActions(self.auth)

    # ---------- passkey bound to the approval ----------
    def passkey_options(self, request: Request, approval_id: str) -> str:
        """WebAuthn request options whose challenge is bound to this approval (see `challenge`)."""
        auth = self.auth
        u = auth.session_user(request)
        row = self.store.get_approval(approval_id) if valid_id(approval_id) else None
        if u is None or row is None or int(row["subject_id"]) != int(u["id"]):
            raise HTTPException(404, auth.t("api.not_found"))
        row = self._expire_if_due(row)
        if row["state"] != "pending":
            raise HTTPException(409, auth.t("apv.closed"))
        if auth.webauthn is None or not auth.store.list_webauthn(u["id"]):
            raise HTTPException(400, auth.t("apv.no_passkey"))
        nonce = secrets.token_bytes(32)
        auth.store.put_flow("apvpk:" + row["id"], {"nonce": _b64u(nonce), "user_id": int(u["id"])},
                            ttl=STEPUP_TTL_SEC)
        from .webauthn_ import approval_options
        return approval_options(auth, u, challenge(nonce, row["id"], row["payload_hash"]))

    def _passkey_ok(self, u: dict, row, answer: str) -> bool:
        flow = self.store.pop_flow("apvpk:" + row["id"])
        if not flow or int(flow.get("user_id") or 0) != int(u["id"]) or self.auth.webauthn is None:
            return False
        from .webauthn_ import approval_verify
        return approval_verify(self.auth, u, answer,
                               challenge(_unb64u(str(flow["nonce"])), row["id"], row["payload_hash"]))

    def _provider_ok(self, u: dict, row) -> Optional[int]:
        """The provider's `auth_time` of a fresh sign-in (`max_age=0`) started from THIS approval's page for this
        account, consumed once — or None. Without `auth_time` from the provider there is none (fail-closed)."""
        grant = self.store.pop_flow("apvoidc:" + row["id"])
        if not grant or int(grant.get("user_id") or 0) != int(u["id"]):
            return None
        at = grant.get("auth_time")
        if not isinstance(at, int) or at < int(row["created_at"]):
            return None
        return at

    def provider_ready(self, u: dict, row) -> bool:
        """Is a provider confirmation for this approval waiting (read only — the POST consumes it)?"""
        r = self.store._one("SELECT data, expires_at FROM flow WHERE key=?", ("apvoidc:" + row["id"],))
        if not r or r["expires_at"] < _now():
            return False
        try:
            return int(json.loads(r["data"]).get("user_id") or 0) == int(u["id"])
        except (ValueError, TypeError):
            return False

    # ---------- the decision ----------
    def decide(self, request: Request, approval_id: str, form: dict) -> tuple[int, str, dict]:
        """`POST /auth/approvals/{id}` — (status, outcome, row view). Raises for what is no decision at all.

        Order: a token in the request ends it (403) — only a browser session decides, never a key, not even a
        `human` key beside its session; CSRF; the session's account must be the subject; the request must still be
        open; the payload must be the one the page showed (`payload_hash`); then, for approve, the step-up of THIS
        approval — never the session's freshness window; then the one atomic transition; then the action with the
        rights of the session at this moment."""
        auth = self.auth
        ip = auth.client_ip(request)
        if request.headers.get("authorization") or request.headers.get("x-api-key"):
            auth.audit("approval_denied", None, ip, f"id={_detail(approval_id)} reason=token")
            raise HTTPException(403, auth.t("apv.token_refused"))
        auth.require_csrf(request, form.get("_csrf"))
        u = auth.session_user(request)
        if u is None:
            raise HTTPException(401, auth.t("api.not_signed_in"))
        row = self.store.get_approval(approval_id) if valid_id(approval_id) else None
        if row is None or int(row["subject_id"]) != int(u["id"]):
            if row is not None:
                auth.audit("approval_denied", u["username"], ip, f"id={row['id']} reason=other_account")
            return 404, "foreign", {}
        row = self._expire_if_due(row)
        decision = str(form.get("decision") or "")
        if decision not in ("approve", "reject"):
            raise HTTPException(400, auth.t("api.invalid", reason="decision"))
        if row["state"] != "pending":
            return 409, "closed", self.view(row, u)
        sent = str(form.get("payload_hash") or "")
        if not sent or not secrets.compare_digest(sent, row["payload_hash"]) \
                or payload_hash(row["payload"]) != row["payload_hash"]:
            auth.audit("approval_denied", u["username"], ip, f"id={row['id']} reason=payload_changed")
            return 409, "changed", self.view(row, u)
        now = _now()
        if decision == "reject":
            if not self.store.approval_transition(row["id"], "pending", "rejected", decided_at=now, ip_decision=ip):
                return 409, "closed", self.view(self.store.get_approval(row["id"]), u)
            auth.audit("approval_rejected", u["username"], ip, f"id={row['id']} type={row['type']} "
                                                               f"key={row['requester_ref']}")
            return 200, "rejected", self.view(self.store.get_approval(row["id"]), u)
        method, refusal = self._step_up(request, u, row, form)
        if method is None:
            auth.audit("approval_denied", u["username"], ip, f"id={row['id']} reason=stepup")
            status = refusal.status if refusal is not None else 401
            view = self.view(row, u)
            view["error"] = refusal.message if refusal is not None else auth.t("apv.stepup_failed")
            return status, "stepup", view
        amr, at = method
        # THE transition: only one confirmation wins, and only the winner executes.
        if not self.store.approval_transition(row["id"], "pending", "approved", decided_at=now, ip_decision=ip,
                                              stepup_amr=json.dumps(amr), auth_time=at):
            return 409, "closed", self.view(self.store.get_approval(row["id"]), u)
        auth.audit("approval_approved", u["username"], ip,
                   f"id={row['id']} type={row['type']} key={row['requester_ref']} amr={','.join(amr)} "
                   f"hash={row['payload_hash']}")
        result = self.execute(request, u, json.loads(row["payload"]))
        self.store.approval_transition(row["id"], "approved", "consumed", result=result)
        auth.audit("approval_executed", u["username"], ip, f"id={row['id']} type={row['type']} result={result}")
        auth._security_event("approval_approved", u["id"], approval_id=row["id"], type=row["type"], result=result)
        return 200, "done", self.view(self.store.get_approval(row["id"]), u)

    def _step_up(self, request: Request, u: dict, row, form: dict):
        """((amr, auth_time), None) for a step-up of THIS approval that succeeded, otherwise (None, refusal)."""
        auth = self.auth
        offered = self.methods(u)
        if form.get("webauthn"):
            if "passkey" in offered and self._passkey_ok(u, row, str(form["webauthn"])):
                return (AMR["passkey"], _now()), None
            return None, None
        if form.get("method") == "oidc":
            at = self._provider_ok(u, row) if "oidc" in offered else None
            return ((AMR["oidc"], at), None) if at is not None else (None, None)
        if form.get("code"):
            procedure, secret = "totp", form["code"]
        elif form.get("pin"):
            procedure, secret = "pin", form["pin"]
        else:
            procedure, secret = "password", form.get("password")
        refused = auth._stepup_secret(request, u, procedure, str(secret or ""), "/")
        if refused is not None:
            return None, refused
        return (AMR[procedure], _now()), None

    def execute(self, request: Request, me: dict, payload: dict) -> str:
        """Run a confirmed class (a) action with the admin panel's code, as the confirming session — its rights at
        THIS moment decide (E4): an administrator, a delegate within their scope (T-74), or the holder for their own
        key. Returns one word of `RESULTS`."""
        auth = self.auth
        pa = self._panel()
        scopes = None if auth.is_admin(me) else auth._delegate_scopes(me)
        delegate = scopes is not None
        type_ = payload["type"]
        try:
            if type_ == "tinysesam.apikey.revoke":
                kid = int(payload["key"])
                owner = auth.store.api_key_owner(kid)
                if owner is None:
                    return "not_found" if auth.is_admin(me) else "forbidden"
                if int(owner) == int(me["id"]):
                    auth.revoke_api_key(kid, me["id"])
                    return "ok"
                if not auth.is_admin(me):
                    return "forbidden"
                pa.revoke_key(me, kid)
                return "ok"
            if not auth.is_admin(me) and not delegate:
                return "forbidden"
            uid = int(payload["account"])
            if type_ == "tinysesam.account.disable":
                pa.disable(me, scopes, uid, True)
                return "ok"
            target = auth.store.get_user(uid)
            if target is None:
                return "forbidden" if delegate else "not_found"
            current = [str(r) for r in auth.user_roles(target)]
            roles = [r for r in current if r not in payload["remove"]] + \
                    [r for r in payload["add"] if r not in current]
            pa.set_roles(request, me, scopes, uid, {"roles": roles})
            return "ok"
        except HTTPException as e:
            if e.status_code == 403 or (e.status_code == 404 and delegate):
                return "forbidden"
            return {404: "not_found", 400: "invalid", 409: "conflict"}.get(e.status_code, "invalid")

    # ---------- cleanup ----------
    def gc(self) -> dict:
        """Open approvals past their deadline become `expired` (one audit line each), closed rows older than
        `audit_retention_days` (or `KEEP_DAYS`) are deleted."""
        days = int(self.cfg.audit_retention_days or 0) or KEEP_DAYS
        now = _now()
        stale, away = self.store.gc_approvals(now, now - days * 86400)
        for row in stale:
            self.store.audit_log("approval_expired", self.auth._account_name(row["subject_id"]), None,
                                 f"id={row['id']} type={row['type']} source=gc")
        return {"approvals_expired": len(stale), "approvals_deleted": away}


# ---------- routes ----------

def _no_framing(resp: Response) -> Response:
    """The approval pages are never framed (clickjacking) — `frame-ancestors 'none'` and `X-Frame-Options: DENY`
    whatever `csp` says: with `csp="off"` (the proxy sets the policy) and with an own policy as well."""
    policy = resp.headers.get("content-security-policy", "")
    parts = [d.strip() for d in policy.split(";") if d.strip()]
    out = [d for d in parts if d.split(None, 1)[0].lower() != "frame-ancestors"]
    out.append("frame-ancestors 'none'")
    resp.headers["Content-Security-Policy"] = "; ".join(out)
    resp.headers["X-Frame-Options"] = "DENY"
    return resp


def register_routes(r, auth) -> None:
    """The approval routes on TinySesam's router (only with `approvals_enabled`)."""
    svc = auth._approvals()

    def error(e: ApprovalError) -> JSONResponse:
        body = {"error": e.code}
        if e.detail:
            body["error_description"] = e.detail
        headers = {"Cache-Control": "no-store"}
        if e.status == 429:
            headers["Retry-After"] = "60"
        return JSONResponse(body, status_code=e.status, headers=headers)

    def ok_json(data: dict, status: int = 200) -> JSONResponse:
        return JSONResponse(data, status_code=status, headers={"Cache-Control": "no-store"})

    # --- the token's side ---
    @r.post("/auth/api/approvals")
    async def approval_request(request: Request):
        try:
            try:
                body = await request.json()
            except Exception:
                body = None
            return ok_json(svc.create(request, body), 201)
        except ApprovalError as e:
            return error(e)

    @r.get("/auth/api/approvals/{approval_id}")
    async def approval_status(request: Request, approval_id: str, wait: int = 0):
        try:
            row = svc.own(request, approval_id)
            deadline = time.monotonic() + max(0, min(int(wait), MAX_WAIT_SEC))
            while row["state"] == "pending" and time.monotonic() < deadline:
                await asyncio.sleep(min(1.0, max(0.05, deadline - time.monotonic())))
                fresh = auth.store.get_approval(row["id"])
                if fresh is None:            # removed meanwhile (account deleted): the same answer as unknown
                    raise ApprovalError("not_found", 404)
                row = svc._expire_if_due(fresh)
            return ok_json(svc.status(row))
        except ApprovalError as e:
            return error(e)

    @r.delete("/auth/api/approvals/{approval_id}")
    def approval_withdraw(request: Request, approval_id: str):
        try:
            return ok_json(svc.withdraw(request, approval_id))
        except ApprovalError as e:
            return error(e)

    # --- the person's side ---
    def to_login(request: Request, path: str):
        from urllib.parse import quote
        return RedirectResponse(f"{auth.browser_path(request, auth.cfg.login_path)}?next={quote(path, safe='')}", 303)

    @r.get("/auth/approvals")
    def approvals_page(request: Request):
        u = auth.session_user(request)
        if u is None:
            return to_login(request, auth.browser_path(request, "/auth/approvals"))
        items = [svc.view(row, u) for row in auth.store.list_approvals_pending(u["id"], _now())]
        return _no_framing(auth.render_page("approvals", request=request, items=items))

    @r.get("/auth/approvals/{approval_id}")
    def approval_page(request: Request, approval_id: str, stepup: str = ""):
        # No side effect: a link never decides anything (only the POST below does).
        u = auth.session_user(request)
        if u is None:
            return to_login(request, auth.browser_path(request, f"/auth/approvals/{approval_id}"))
        row = auth.store.get_approval(approval_id) if valid_id(approval_id) else None
        if row is None or int(row["subject_id"]) != int(u["id"]):
            return _no_framing(auth.render_page("approval", status=404, request=request, outcome="foreign"))
        if row["state"] in ("pending", "approved") and row["expires_at"] < _now():
            row = dict(row)
            row["state"] = "expired"            # shown as expired; the row itself changes on a POST or in the gc
        view = svc.view(row, u)
        if row["state"] != "pending":
            return _no_framing(auth.render_page("approval", request=request, outcome="closed", approval=view))
        error_text = auth.t("err.oidc_reauth_stale") if stepup == "stale" else ""
        return _no_framing(auth.render_page("approval", request=request, outcome="open", approval=view,
                                            methods=svc.methods(u), provider_ready=svc.provider_ready(u, row),
                                            error=error_text))

    @r.post("/auth/approvals/{approval_id}")
    async def approval_decide(request: Request, approval_id: str):
        form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        status, outcome, view = svc.decide(request, approval_id, form)
        ctx: dict = {"outcome": outcome, "approval": view}
        if outcome == "stepup":
            u = auth.session_user(request)
            ctx.update(outcome="open", methods=svc.methods(u) if u else [], error=view.get("error", ""),
                       provider_ready=False)
        elif outcome == "changed":
            # The request is not the one the page showed: show the current one again, to be read anew.
            u = auth.session_user(request)
            ctx.update(outcome="open", methods=svc.methods(u) if u else [], error=auth.t("apv.changed"),
                       provider_ready=False)
        return _no_framing(auth.render_page("approval", status=status, request=request, **ctx))

    if auth.webauthn is not None:
        @r.post("/auth/approvals/{approval_id}/passkey")
        def approval_passkey(request: Request, approval_id: str):
            if request.headers.get("authorization") or request.headers.get("x-api-key"):
                raise HTTPException(403, auth.t("apv.token_refused"))
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            return Response(content=svc.passkey_options(request, approval_id), media_type="application/json",
                            headers={"Cache-Control": "no-store"})
