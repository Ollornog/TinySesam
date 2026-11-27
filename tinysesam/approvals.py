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

One type is asked for by an APPLICATION, not by the account itself: `tinysesam.account.reset_access`. The requester is
the service account of an application in `apps` with `provisioning` (automation key, scope `users:reset`), `subject`
names the person who must confirm (the application's team admin), the field `account` one of the application's own
accounts. Confirming needs the role `apps[…].provisioning.approver_role` at THAT moment — a role no application can
grant (`config_check`), so a leaked key cannot confirm through a straw account it created itself. The effect: every
sign-in factor of the account deleted, sessions and standing credentials revoked; the row then waits in `approved`
until the application picks up the new one-time link — exactly once (`approved` → `consumed`), only in that answer,
never in the audit, a log or a URL.

Stage B — actions of an APPLICATION (class b). An application in `apps` with an `approvals` block asks for one of the
action types the operator lists there (`apps[…].approvals.types`, fixed texts in English and German, a field schema,
names that begin with the application's id) — with its service account's automation key, for a `subject`:

    POST /auth/api/approvals   {"type": "example.collection.delete_permanently", "subject": "42",
    X-Api-Key: tsk_…             "fields": {"collection": "c_81f2", "name": "Project Alpha"},
                                 "return_url": "https://app.example.com/approvals/return", "state": "k3J…"}

The person confirms on the same page (the operator's text, every value escaped and bidi-isolated, the match code, a
step-up of THIS approval); TinySesam carries nothing out. The application then picks up ONE signed confirmation
(`tinysesam.approval_token`): the first status read after the confirmation moves `approved` → `consumed` and signs it
then — so it exists in that one answer only, never in the audit, a log or the return URL — and the application checks
it against `/auth/approvals/jwks.json` (purpose `approval`, never the gate key) before it acts. With `return_url` and
`state` the person started in the application (browser entry, like RFC 9126): the page sends the browser back to
exactly that registered address with `?approval=<id>&state=<state>` (and `&result=rejected|expired`), never with the
confirmation.
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

from . import config_check, security

#: The class (a) types of stage A and their fields (`str_id` = a positive decimal id as a string, `roles` = a list of
#: role names). `tinysesam.` is reserved for these; application types (class b) come with stage B.
TYPES: dict[str, dict[str, str]] = {
    "tinysesam.account.set_roles": {"account": "str_id", "add": "roles", "remove": "roles"},
    "tinysesam.apikey.revoke": {"key": "str_id"},
    "tinysesam.account.disable": {"account": "str_id"},
    "tinysesam.account.reset_access": {"account": "str_id"},
}
#: The access reset of an application's account (draft "account API" §13): requested by the application's service
#: account for a `subject`, confirmed by a holder of `provisioning.approver_role`.
RESET_ACCESS = "tinysesam.account.reset_access"
#: Types only an application (its service account, `apps[…].provisioning`) requests — with a `subject`.
APP_TYPES = frozenset({RESET_ACCESS})
#: Types whose output the requester picks up exactly once: confirmed and executed they wait in `approved`, the first
#: status read moves them to `consumed` and carries the output (stage B hands out its confirmations the same way).
PICKUP_TYPES = frozenset({RESET_ACCESS})
#: The scope of `apps[…].provisioning.scopes` an application needs to ask for an access reset.
RESET_SCOPE = "users:reset"
#: Fields a type may leave out (an empty list then).
OPTIONAL_FIELDS = {"tinysesam.account.set_roles": {"add", "remove"}}
#: Types whose effect cannot be undone — the page says so with a symbol AND a word, never with colour alone.
IRREVERSIBLE = frozenset({"tinysesam.apikey.revoke", RESET_ACCESS})

#: Members of a request by an application for one of its own action types (class b).
APP_ACTION_MEMBERS = ("type", "subject", "fields", "return_url", "state")
#: The `state` of the browser entry: printable ASCII without spaces, at most 128 characters (it becomes `nonce`).
_STATE = re.compile(r"^[\x21-\x7e]{1,128}$")
#: What a string field value of an application action may not contain: C0 and C1 control characters, DEL, the bidi
#: controls and the line and paragraph separators — refused, never removed (the page isolates every value in `<bdi>`,
#: but a value must not reorder or break its own text either).
_FORBIDDEN_IN_VALUE = re.compile("[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028-\u202e\u2066-\u2069\ud800-\udfff]")
#: JSON-safe integers in every language.
_INT_LIMIT = 2 ** 53 - 1

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
#: it signed the person in), so TinySesam records `oidc` or `saml` (T-99).
AMR = {"password": ["pwd"], "pin": ["pin"], "totp": ["otp"], "passkey": ["hwk", "user"], "oidc": ["oidc"],
       "saml": ["saml"]}
#: The provider step-ups of an approval: the method word and its one-time grant in the flow table.
PROVIDERS = {"oidc": "apvoidc:", "saml": "apvsaml:"}


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


# ---------- application action types (class b, stage B) ----------

_TYPES_FILE_CACHE: dict = {}


def _types_from_file(path: str) -> Optional[dict]:
    """The types of a `types_file`, read again only when the file changed (size or modification time) — None when it
    cannot be read (fail-closed: no types)."""
    import os
    try:
        st = os.stat(path)
    except (OSError, TypeError, ValueError):
        return None
    key = (path, st.st_mtime_ns, st.st_size)
    hit = _TYPES_FILE_CACHE.get(path)
    if hit is not None and hit[0] == key:
        return hit[1]
    types, _why = config_check.read_approval_types_file(path)
    _TYPES_FILE_CACHE[path] = (key, types)
    return types


def _compile_type(spec: dict) -> dict:
    fields = {}
    for name, schema in spec["fields"].items():
        f = {"type": schema["type"]}
        if schema["type"] == "string":
            f["max"] = schema["max"]
            f["pattern"] = re.compile(schema["pattern"]) if "pattern" in schema else None
        elif schema["type"] == "integer":
            f["min"] = schema.get("min", -_INT_LIMIT)
            f["max"] = schema.get("max", _INT_LIMIT)
        fields[name] = f
    return {"fields": fields, "title": dict(spec["title"]), "summary": dict(spec["summary"]),
            "irreversible": bool(spec.get("irreversible", False))}


def normalize_app_approvals(cfg) -> dict:
    """The applications of `cfg.apps` with an `approvals` block, normalized — `{app_id: {"id", "account", "name",
    "source", "types", "return_urls"}}`; `source` is the id whose types it asks for (its own, or `types_from`).

    Fail-closed for a configuration changed at runtime (construction already refused a broken one,
    `config_check._app_approvals`): an entry with a bad or reserved id, without a service account or with a broken
    block is left out; a type with any finding (`config_check.approval_type_findings`) is left out; a return address
    that is not exact and absolute is dropped."""
    raw = getattr(cfg, "apps", None) or {}
    if not isinstance(raw, dict):
        return {}

    def own_types(app_id: str, block: dict) -> Optional[dict]:
        if "types" in block and "types_file" not in block:
            types = block["types"]
        elif "types_file" in block and "types" not in block:
            types = _types_from_file(block["types_file"])
        else:
            return None
        if not isinstance(types, dict) or len(types) > config_check.APPROVAL_TYPES_MAX:
            return None
        return {name: _compile_type(spec) for name, spec in types.items()
                if not config_check.approval_type_findings(app_id, name, spec)}

    out: dict = {}
    for app_id, entry in raw.items():
        if (not isinstance(app_id, str) or not config_check.APP_ID.match(app_id) or app_id == "tinysesam"
                or not isinstance(entry, dict)):
            continue
        block, account = entry.get("approvals"), entry.get("account")
        if (not isinstance(block, dict) or set(block) - set(config_check.APPROVAL_KEYS)
                or not isinstance(account, str) or not account.strip()):
            continue
        source = app_id
        if "types_from" in block:
            source = block["types_from"]
            target = raw.get(source) if isinstance(source, str) else None
            tblock = target.get("approvals") if isinstance(target, dict) else None
            if ("types" in block or "types_file" in block or source == app_id or not isinstance(tblock, dict)
                    or "types_from" in tblock):
                continue
            types = own_types(source, tblock)
        else:
            types = own_types(app_id, block)
        if types is None:
            continue
        urls = block.get("return_urls", [])
        name = entry.get("name")
        out[app_id] = {"id": app_id, "account": account, "name": name if isinstance(name, (str, dict)) else None,
                       "source": source, "types": types,
                       "return_urls": [u for u in (urls if isinstance(urls, list) else [])
                                       if config_check.approval_return_url_ok(u)]}
    return out


def validate_fields(spec: dict, fields: Any) -> dict:
    """The fields of a request for an application action against its type's schema — returned unchanged, or
    `ApprovalError("invalid_request", 400)` naming the field. Unknown, missing and wrongly typed fields are refused,
    never dropped or converted (`1` is no string, `true` no integer); forbidden characters (`_FORBIDDEN_IN_VALUE`) are
    refused, never removed; a string must match its `pattern` as a whole."""
    if not isinstance(fields, dict):
        raise ApprovalError("invalid_request", 400, "fields")
    unknown = sorted(str(k) for k in set(fields) - set(spec["fields"]))
    if unknown:
        raise ApprovalError("invalid_request", 400, f"unknown field {unknown[0][:40]}")
    out: dict = {}
    for name, schema in spec["fields"].items():
        if name not in fields:
            raise ApprovalError("invalid_request", 400, f"missing field {name}")
        value = fields[name]
        kind = schema["type"]
        if kind == "string":
            good = (isinstance(value, str) and len(value) <= schema["max"] and not _FORBIDDEN_IN_VALUE.search(value)
                    and (schema["pattern"] is None or schema["pattern"].fullmatch(value) is not None))
        elif kind == "integer":
            good = (isinstance(value, int) and not isinstance(value, bool)
                    and schema["min"] <= value <= schema["max"])
        else:
            good = isinstance(value, bool)
        if not good:
            raise ApprovalError("invalid_request", 400, f"field {name}")
        out[name] = value
    return out


def render_summary(template: str, values: dict) -> list:
    """The operator's summary as parts `(text, is_value)` — the values stay data: the page escapes every part and puts
    each value in `<bdi>`. `{{`/`}}` are literal braces; a placeholder without a value stays visible as itself."""
    import string
    parts: list = []
    for literal, name, _spec, _conv in string.Formatter().parse(template):
        if literal:
            parts.append((literal, False))
        if name is not None:
            value = values.get(name, "{" + name + "}")
            parts.append(("true" if value is True else "false" if value is False else str(value), True))
    return parts


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
        u, row, app = self.caller(request)
        if app is not None:
            self._no_approver(request, u, row)
        return u, row

    def caller(self, request: Request) -> tuple[dict, dict, Optional[dict]]:
        """`requester`, but the service account of an application in `apps` with `provisioning` or `approvals` passes
        too — with an automation key, resolved like the account API resolves it (`Provisioning.caller`). Returns
        (account, key row, application or None); any other service account gets `no_approver`.

        The application is one dict: its `provisioning` settings (`Provisioning.apps`, empty scopes without that
        block) and under `"approvals"` its normalized approvals block (`normalize_app_approvals`) or None."""
        u, row = self._key_holder(request)
        if not u.get("is_service"):
            return u, row, None
        app = None
        if self.auth._key_kind(row) == "automation" and u.get("is_service") == 1:
            name = str(u.get("username") or "").lower()
            prov = next((a for a in self.auth._provisioning().apps().values() if a["account"].lower() == name), None)
            mine = next((a for a in self.app_approvals().values() if a["account"].lower() == name), None)
            base: Optional[dict] = None
            if prov is not None:
                base = prov
            elif mine is not None:
                base = {"id": mine["id"], "account": mine["account"], "scopes": [], "provisioning": False}
            if base is not None:
                # One service account, two entries: `config_check` refuses it; at runtime nobody speaks for either.
                if mine is None or mine["id"] == base["id"]:
                    app = dict(base, approvals=mine)
        if app is None:
            self._no_approver(request, u, row)
        return u, row, app

    def app_approvals(self) -> dict:
        """`normalize_app_approvals` of the running configuration — computed again when it changes at runtime."""
        try:
            key = json.dumps(getattr(self.cfg, "apps", None), sort_keys=True, default=repr)
        except (TypeError, ValueError):
            return {}
        cached = getattr(self, "_apv_cache", None)
        if cached is None or cached[0] != key:
            cached = (key, normalize_app_approvals(self.cfg))
            self._apv_cache = cached
        return cached[1]

    def _no_approver(self, request: Request, u: dict, row) -> None:
        self.auth.audit("approval_denied", u["username"], self.auth.client_ip(request),
                        f"reason=no_approver key={row['id']}")
        raise ApprovalError("no_approver", 403, "a service account cannot confirm an approval")

    def _key_holder(self, request: Request) -> tuple[dict, dict]:
        auth = self.auth
        key = auth._extract_api_key(request)
        if not key:
            if (request.headers.get("authorization") or "").strip():
                raise ApprovalError("unsupported_token", 403, "only an API key can request an approval")
            raise ApprovalError("unauthorized", 401)
        auth._remember_request(request)
        u, _scope = auth.verify_api_key(key)
        row = self.store.get_api_key_by_hash(self.store.token_digest(key, "apikey")) if u else None
        if u is None or row is None:
            raise ApprovalError("unauthorized", 401)
        if auth._key_kind(row) == "human":
            s = auth._session_from_request(request)
            if not (s and s["mfa_ok"] and s["user_id"] == u["id"]):
                raise ApprovalError("unauthorized", 401)
        auth._remember_request(request, u)
        return u, row

    # ---------- limits ----------
    def _throttled(self, uid: int, ref: str, type_: str, now: int, kind: str = "apikey") -> Optional[str]:
        cfg = self.cfg
        if self.store.count_approvals_pending(uid, now) >= int(cfg.approval_open_per_account):
            return "open_per_account"
        if self.store.count_approvals_open_by(kind, ref, now) >= int(cfg.approval_open_per_token):
            return "open_per_token"
        if self.store.count_approvals_since(uid, now - 3600) >= int(cfg.approval_requests_per_hour):
            return "per_hour"
        limit = int(cfg.approval_reject_limit)
        times = self.store.approval_rejections(kind, ref, type_, now - 7200)
        for i in range(limit - 1, len(times)):
            if times[i] - times[i - limit + 1] <= 3600 and times[i] > now - 3600:
                return "rejections"
        return None

    # ---------- create / read / withdraw ----------
    def create(self, request: Request, body: Any) -> dict:
        auth = self.auth
        u, key, app = self.caller(request)
        if not isinstance(body, dict):
            raise ApprovalError("invalid_request", 400, "body")
        if app is not None:
            if body.get("type") in APP_TYPES:
                if app.get("provisioning") is False:
                    raise ApprovalError("scope_missing", 403, RESET_SCOPE)
                return self._create_for_app(request, u, app, body)
            return self._create_app_action(request, u, app, body)
        if "subject" in body:
            # Class (a) always concerns the account of the token; naming another one is an application's request
            # (class b, stage B) — refused, not ignored.
            raise ApprovalError("invalid_request", 400, "subject is not allowed for TinySesam actions")
        extra = sorted(set(body) - {"type", "fields"})
        if extra:
            raise ApprovalError("invalid_request", 400, f"unknown member {extra[0]}")
        payload = normalize(body.get("type"), body.get("fields"))
        if payload["type"] in APP_TYPES:
            raise ApprovalError("invalid_type", 400, "only an application's service account requests this type")
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

    def _create_for_app(self, request: Request, u: dict, app: dict, body: dict) -> dict:
        """`POST /auth/api/approvals` by an application's service account: only `APP_TYPES`, with `subject` (the
        person who confirms, a decimal id as a string like the fields). Checked here, in this order, before anything
        is stored: scope `users:reset`; the payload; the subject an active person (an answer `invalid_subject`
        counts against the application's `taken_per_hour`, it would otherwise tell which ids are persons); never the
        account itself (`forbidden`); the account one the application sees and may act on as a whole
        (`Provisioning.target` — 404 `not_found`, 409 `account_shared`); not disabled. Whether the subject holds
        `approver_role` is NOT asked now — that is decided at confirmation time, and asking here would tell the key
        who the approvers are."""
        from .provisioning import ProvisioningError
        auth = self.auth
        prov = auth._provisioning()
        extra = sorted(set(body) - {"type", "subject", "fields"})
        if extra:
            raise ApprovalError("invalid_request", 400, f"unknown member {extra[0]}")
        try:
            prov.claim(request, app, write=False)
            if body.get("type") not in APP_TYPES:
                raise ApprovalError("invalid_type", 400, "an application requests only: " + ", ".join(sorted(APP_TYPES)))
            prov.need(app, RESET_SCOPE)
            payload = normalize(body.get("type"), body.get("fields"))
            subject = body.get("subject")
            if not isinstance(subject, str) or not _STR_ID.match(subject):
                raise ApprovalError("invalid_request", 400, "subject: the id of the person who confirms, as a string")
            person = self.store.get_user(int(subject))
            if person is None or person["disabled"] or person["is_service"]:
                prov._spend_oracle(app)
                raise ApprovalError("invalid_subject", 400, "subject: an active person's id")
            if subject == payload["account"]:
                auth.audit("provision_denied", None, None, f"app={app['id']} reason=own_account")
                raise ApprovalError("forbidden", 403, "the person who confirms cannot reset their own access")
            target = prov.target(app, payload["account"], whole=True)
        except ProvisioningError as e:
            raise ApprovalError(e.code, e.status, e.detail) from None
        if target["disabled"]:
            raise ApprovalError("account_disabled", 409, "the account is disabled")
        now = _now()
        ref = str(int(u["id"]))
        ip = auth.client_ip(request)
        why = self._throttled(int(person["id"]), ref, payload["type"], now, kind="app")
        if why:
            auth.audit("approval_throttled", person["username"], ip, f"type={payload['type']} reason={why}")
            raise ApprovalError("too_many_requests", 429, why)
        text = canonical(payload)
        row = {"id": new_id(), "class": "tinysesam", "type": payload["type"], "app_id": app["id"],
               "subject_id": int(person["id"]), "requester_kind": "app", "requester_ref": ref,
               "payload": text, "payload_hash": payload_hash(text), "match_code": new_match_code(),
               "return_url": None, "state": "pending", "created_at": now,
               "expires_at": now + int(self.cfg.approval_pending_sec), "ip_request": ip}
        self.store.add_approval(row)
        auth.audit("approval_requested", person["username"], ip,
                   f"id={row['id']} type={row['type']} account={payload['account']} hash={row['payload_hash']}")
        return {"id": row["id"], "state": "pending", "match_code": row["match_code"],
                "approve_url": self.approve_url(row["id"]), "expires_at": row["expires_at"]}

    def _create_app_action(self, request: Request, u: dict, app: dict, body: dict) -> dict:
        """`POST /auth/api/approvals` by an application for one of ITS OWN action types (class b, stage B). Checked
        here, in this order, before anything is stored: the members; the application's hourly budget (every request
        counts, so the answer `invalid_subject` cannot be used to map the active persons); the type's prefix — only
        the application's own id, or that of `types_from` (403 `forbidden_type`); the type registered by the operator
        (400 `invalid_type`); the fields against its schema (400 `invalid_request`); `return_url` exactly one of the
        registered addresses and `state` with it (400); the subject an active person (400 `invalid_subject`); the
        limits per account. Nothing about the action itself is checked: whether it is allowed is the application's
        rule, before it asks and again before it acts."""
        auth = self.auth
        ip = auth.client_ip(request)
        mine = app.get("approvals")
        extra = sorted(set(body) - set(APP_ACTION_MEMBERS))
        if extra:
            raise ApprovalError("invalid_request", 400, f"unknown member {str(extra[0])[:40]}")
        if mine is None:
            raise ApprovalError("invalid_type", 400, "the application has no approval types (apps[…].approvals)")
        now = _now()
        hour = now // 3600
        if not self.store.count_up(f"apv:app:{app['id']}:{hour}", int(self.cfg.approval_app_requests_per_hour), 3700):
            auth.audit("approval_throttled", None, ip, f"app={app['id']} reason=per_app_hour")
            raise ApprovalError("too_many_requests", 429, "per_app_hour")
        type_ = body.get("type")
        if not isinstance(type_, str) or type_.split(".", 1)[0] != mine["source"]:
            auth.audit("approval_denied", None, ip, f"app={app['id']} reason=foreign_type type={_detail(type_)}")
            raise ApprovalError("forbidden_type", 403, f"an application asks only for types beginning with "
                                                       f"{mine['source']}.")
        spec = mine["types"].get(type_)
        if spec is None:
            raise ApprovalError("invalid_type", 400, "not a type of apps[…].approvals")
        fields = validate_fields(spec, body.get("fields"))
        return_url, state = body.get("return_url"), body.get("state")
        if return_url is not None and (not isinstance(return_url, str) or return_url not in mine["return_urls"]):
            raise ApprovalError("invalid_return_url", 400, "return_url: exactly one of apps[…].approvals.return_urls")
        if state is not None and (not isinstance(state, str) or not _STATE.match(state)):
            raise ApprovalError("invalid_request", 400, "state: 1 to 128 printable ASCII characters")
        if return_url is not None and state is None:
            raise ApprovalError("invalid_request", 400, "state is required with return_url")
        subject = body.get("subject")
        if not isinstance(subject, str) or not _STR_ID.match(subject):
            raise ApprovalError("invalid_request", 400, "subject: the id of the person who confirms, as a string")
        person = self.store.get_user(int(subject))
        if person is None or person["disabled"] or person["is_service"]:
            raise ApprovalError("invalid_subject", 400, "subject: an active person's id")
        ref = str(int(u["id"]))
        why = self._throttled(int(person["id"]), ref, type_, now, kind="app")
        if why:
            auth.audit("approval_throttled", person["username"], ip, f"type={type_} app={app['id']} reason={why}")
            raise ApprovalError("too_many_requests", 429, why)
        text = canonical({"type": type_, **fields})
        row = {"id": new_id(), "class": "app", "type": type_, "app_id": app["id"],
               "subject_id": int(person["id"]), "requester_kind": "app", "requester_ref": ref,
               "payload": text, "payload_hash": payload_hash(text), "match_code": new_match_code(),
               "return_url": return_url, "nonce": state, "state": "pending", "created_at": now,
               "expires_at": now + int(self.cfg.approval_pending_sec), "ip_request": ip}
        self.store.add_approval(row)
        auth.audit("approval_requested", person["username"], ip,
                   f"id={row['id']} type={type_} app={app['id']} hash={row['payload_hash']}"
                   f"{' entry=browser' if return_url else ''}")
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
        unknown one answer alike). For an application: any automation key of its service account, for its app id."""
        u, key, app = self.caller(request)
        row = self.store.get_approval(approval_id) if valid_id(approval_id) else None
        if app is None:
            mine = row is not None and row["requester_kind"] == "apikey" and row["requester_ref"] == str(key["id"])
        else:
            mine = (row is not None and row["requester_kind"] == "app" and row["requester_ref"] == str(int(u["id"]))
                    and row["app_id"] == app["id"])
        if not mine:
            raise ApprovalError("not_found", 404)
        return self._expire_if_due(row)

    @staticmethod
    def status(row) -> dict:
        out = {"id": row["id"], "state": row["state"], "type": row["type"], "expires_at": row["expires_at"]}
        if row["state"] == "consumed" and (row["class"] == "tinysesam" or row["result"]):
            out["result"] = row["result"]
        if row["decided_at"]:
            out["decided_at"] = row["decided_at"]
        return out

    def pickup(self, row) -> dict:
        """The status for the requester — and, for a confirmed row that waits for its pickup, its output exactly
        once: the access reset's new link (`output`), an application action's signed confirmation (`confirmation`).
        The one atomic transition `approved` → `consumed` decides who gets it (two parallel reads: one output), and
        the output is made only after that transition — so it exists nowhere but in this one answer. Every later read,
        or one that lost the race, sees `consumed` without it."""
        if row["state"] != "approved":
            return self.status(row)
        if row["class"] == "app":
            member = "confirmation"
        elif row["type"] in PICKUP_TYPES and row["result"] == "ok":
            member = "output"
        else:
            return self.status(row)
        if not self.store.approval_transition(row["id"], "approved", "consumed"):
            return self.status(self.store.get_approval(row["id"]))
        output: Any
        output, result = self._confirmation(row) if member == "confirmation" else self._reset_link(row)
        if result != "ok":
            self.store.set_approval_fields(row["id"], "consumed", result=result)
        out = self.status(self.store.get_approval(row["id"]))
        if output:
            out[member] = output
        return out

    def _app_scope(self, row) -> tuple[Optional[dict], Optional[dict], str]:
        """(application, type, "ok") when an application action may still be confirmed or handed out NOW — otherwise
        (None, None, "forbidden"): the application still in the register with an approvals block whose types hold
        this type, the requester still its service account, the subject still an active person."""
        app = self.app_approvals().get(str(row["app_id"] or ""))
        spec = app["types"].get(row["type"]) if app is not None else None
        requester = self.store.get_user(int(row["requester_ref"])) if _STR_ID.match(str(row["requester_ref"])) else None
        person = self.store.get_user(int(row["subject_id"]))
        if (app is None or spec is None or requester is None or requester["is_service"] != 1
                or str(requester["username"]).lower() != app["account"].lower()
                or person is None or person["disabled"] or person["is_service"]):
            return None, None, "forbidden"
        return app, spec, "ok"

    def _confirmation(self, row) -> tuple[Optional[str], str]:
        """The signed one-time confirmation of a confirmed application action — (token, "ok") or (None, "forbidden").
        Made here, after the transition to `consumed`, and returned in the one answer only: it is never stored, never
        in the audit (`approval_issued` names id, type and application), never in a log or a URL."""
        from . import approval_token
        auth = self.auth
        app, _spec, word = self._app_scope(row)
        if word != "ok" or app is None:
            return None, word
        now = _now()
        token = approval_token.issue(
            auth._approval_private(), iss=auth.gate_issuer(), aud=app["id"], sub=str(int(row["subject_id"])),
            jti=row["id"], entry=json.loads(row["payload"]), auth_time=int(row["auth_time"]),
            amr=json.loads(row["stepup_amr"]), act=app["id"], now=now,
            ttl=int(self.cfg.approval_token_ttl_sec), nonce=row["nonce"] or None)
        self.store.set_approval_fields(row["id"], "consumed", issued_at=now)
        auth.audit("approval_issued", auth._account_name(row["subject_id"]), None,
                   f"id={row['id']} type={row['type']} app={app['id']} hash={row['payload_hash']}")
        return token, "ok"

    def _reset_link(self, row) -> tuple[Optional[dict], str]:
        """The new one-time link of a confirmed access reset — (output, "ok") or (None, a word of `RESULTS`). Checked
        again: the application still configured for resets, the account still its own as a whole and not disabled.
        A setup window opens for the link's lifetime plus an hour, so the person may set up the factors the chain
        demands although `first_login_at` stays (`mfa_enrollment`, `magiclink_first_login_only`)."""
        from .errors import ConfigError
        auth = self.auth
        app, target, word = self._reset_scope(row, None)
        if word != "ok" or app is None or target is None:
            return None, word
        uid = int(target["id"])
        ttl = int(app["link_ttl_min"])
        auth.store.set_mfa_enroll_until(uid, _now() + (ttl + 60) * 60)
        try:
            # T-94: the application's `welcome_url` (checked by `normalize_apps`) — where its links lead afterwards.
            link = auth._signin_link(uid, ttl_min=ttl, app_id=app["id"], next=app.get("welcome_url"))
        except (ValueError, ConfigError):
            auth.store.set_mfa_enroll_until(uid, None)
            return None, "conflict"
        return {"account": str(uid), "signin_url": link["url"], "expires_at": link["expires_at"],
                "qr": link["qr"]}, "ok"

    def _reset_scope(self, row, me: Optional[dict]) -> tuple[Optional[dict], Any, str]:
        """(application, target row, "ok") when an access reset may happen NOW — otherwise a word of `RESULTS`.

        The application must still have `users:reset` and an `approver_role`, the requester must still be its service
        account; with `me` (the confirming session) that account must hold the role at this moment and must not be
        the target; the target must still be one of the application's own accounts that it may act on as a whole
        (`app_visible`, `may_manage` — never an admin, owner, service account or delegate) and must not be disabled."""
        from . import config_check
        auth = self.auth
        prov = auth._provisioning()
        app = prov.apps().get(str(row["app_id"] or ""))
        if app is None or RESET_SCOPE not in app["scopes"] or not app["approver_role"]:
            return None, None, "forbidden"
        requester = self.store.get_user(int(row["requester_ref"])) if _STR_ID.match(str(row["requester_ref"])) else None
        if (requester is None or requester["is_service"] != 1
                or str(requester["username"]).lower() != app["account"].lower()):
            return None, None, "forbidden"
        uid = int(json.loads(row["payload"])["account"])
        if me is not None:
            if me.get("is_service") or app["approver_role"] not in [str(r) for r in auth.user_roles(me)]:
                return None, None, "forbidden"
            if int(me["id"]) == uid:
                return None, None, "forbidden"
        target = self.store.get_user(uid)
        roles = auth.user_roles(target) if target is not None else []
        delegates = prov._delegate_roles()
        if not config_check.app_visible(app["id"], target, roles, delegates):
            return None, None, "not_found"
        if not config_check.may_manage(frozenset(app["roles"]), None, target, roles, delegate_roles=delegates,
                                       without_roles=True):
            return None, None, "conflict"
        if target["disabled"]:
            return None, None, "conflict"
        return app, target, "ok"

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
        if auth._confirms_at_oidc(u):       # a fresh sign-in at the provider for THIS approval (`max_age=0`)
            out.append("oidc")
        if auth._confirms_at_saml(u):       # the same at the SAML provider (`ForceAuthn`, `AuthnInstant`; T-99)
            out.append("saml")
        return out

    def view(self, row, viewer: dict) -> dict:
        """What the page shows of an approval — built from the payload AND the current database state, every value
        as data (the templates escape it). A target the viewer may not manage right now is named by its id only:
        the page must not tell a token holder the names of accounts it could not see in the panel."""
        if row["class"] == "app":
            return self._app_view(row)
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
        warning = None
        app_name = None
        if type_ == RESET_ACCESS:
            # The approver is usually neither admin nor delegate: the account is named when the viewer holds the
            # application's approver role right now and the account is one of the application's own.
            app, target, word = self._reset_scope(row, viewer)
            entry = (getattr(self.cfg, "apps", None) or {}).get(row["app_id"]) if isinstance(
                getattr(self.cfg, "apps", None), dict) else None
            app_name = self._app_name(entry, row["app_id"])
            uid_text = json.loads(row["payload"])["account"]
            label = f"{target['username']} (#{uid_text})" if word == "ok" else f"#{uid_text}"
            summary = t("apv.sum.reset_access", account=label, app=app_name)
            rows = [(t("apv.f.account"), label), (t("apv.f.app"), app_name)]
            if word == "ok":
                rows.append((t("apv.f.methods"), self._methods_text(int(target["id"]))))
                rows.append((t("apv.f.ends"), self._ends_text(int(target["id"]))))
            elif word == "forbidden":
                rows.append((t("apv.f.right"), t("apv.no_right")))
            else:
                rows.append((t("apv.f.state"), t("apv.not_visible")))
            warning = t("apv.warn.reset_access")
        elif type_ == "tinysesam.account.set_roles":
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
        if row["requester_kind"] == "app":
            via = t("apv.via_app", app=app_name or str(row["app_id"] or "—"))
        else:
            via = (t("apv.via_key", name=key["name"] or "—", prefix=key["prefix"],
                     date=time.strftime("%Y-%m-%d", time.gmtime(key["created_at"] or 0)))
                   if key is not None else t("apv.via_gone"))
        return {"id": row["id"], "type": type_, "title": t("apv.title." + type_), "summary": summary, "rows": rows,
                "irreversible": type_ in IRREVERSIBLE, "warning": warning, "match_code": row["match_code"], "via": via,
                "state": row["state"], "result": row["result"], "payload_hash": row["payload_hash"],
                "expires_at": row["expires_at"], "minutes_left": max(0, (row["expires_at"] - _now() + 59) // 60)}

    def _app_view(self, row) -> dict:
        """The page of an application action: the application's name and the type's title and summary — the
        operator's fixed texts in the page's language (English when it has none) — with the field values as data
        (`summary_parts`: the page escapes each part and isolates each value in `<bdi>`), below them every field with
        its raw value. Nothing of it comes from the application except the values."""
        auth = self.auth
        t = auth.t
        payload = json.loads(row["payload"])
        values = {k: v for k, v in payload.items() if k != "type"}
        app = self.app_approvals().get(str(row["app_id"] or ""))
        spec = app["types"].get(row["type"]) if app is not None else None
        entry = (getattr(self.cfg, "apps", None) or {}).get(row["app_id"]) if isinstance(
            getattr(self.cfg, "apps", None), dict) else None
        app_name = self._app_name(entry, row["app_id"])
        lang = str(getattr(self.cfg, "lang", "en") or "en")
        if spec is not None:
            title = spec["title"].get(lang) or spec["title"]["en"]
            parts = render_summary(spec["summary"].get(lang) or spec["summary"]["en"], values)
        else:
            # The type is no longer configured: name it by its id only, never guess a text.
            title, parts = row["type"], [(t("apv.app_type_gone"), False)]
        rows = [(t("apv.f.app"), app_name), (t("apv.f.type"), row["type"])]
        rows += [(k, "true" if v is True else "false" if v is False else str(v)) for k, v in sorted(values.items())]
        out = {"id": row["id"], "type": row["type"], "title": title, "app_name": app_name,
               "summary": "".join(text for text, _ in parts), "summary_parts": parts, "rows": rows,
               "irreversible": bool(spec and spec["irreversible"]), "warning": None, "match_code": row["match_code"],
               "via": t("apv.via_app", app=app_name), "state": row["state"],
               "result": row["result"] or ("confirmed" if row["state"] in ("approved", "consumed") else None),
               "payload_hash": row["payload_hash"], "expires_at": row["expires_at"],
               "minutes_left": max(0, (row["expires_at"] - _now() + 59) // 60), "app_action": True,
               "return_to": None, "return_origin": None}
        if row["return_url"] and row["nonce"]:
            word = {"rejected": "rejected", "expired": "expired"}.get(row["state"])
            if row["state"] in ("pending", "approved", "consumed", "rejected", "expired"):
                out["return_to"] = self.return_to(row, word)
            out["return_origin"] = _origin(row["return_url"])
        return out

    @staticmethod
    def return_to(row, result: Optional[str] = None) -> str:
        """Where the browser goes back after the decision (browser entry): the registered `return_url` exactly, with
        `approval` and `state` — and `result=rejected|expired` — never the confirmation (an address ends up in logs
        and in the Referer; the application picks the confirmation up in its back end)."""
        from urllib.parse import urlencode
        query = {"approval": row["id"], "state": row["nonce"]}
        if result:
            query["result"] = result
        return f"{row['return_url']}?{urlencode(query)}"

    def _app_name(self, entry, app_id) -> str:
        """The operator's name of an application in the page's language (`apps[…].name`), else its id."""
        name = entry.get("name") if isinstance(entry, dict) else None
        if isinstance(name, dict):
            lang = str(getattr(self.cfg, "lang", "en") or "en")
            name = name.get(lang) or name.get("en") or next((v for v in name.values() if isinstance(v, str)), None)
        return name.strip() if isinstance(name, str) and name.strip() else str(app_id or "—")

    def _methods_text(self, uid: int) -> str:
        """What the account signs in with now — the list the reset deletes, in words."""
        auth = self.auth
        t = auth.t
        have = []
        if auth.store.get_password_hash(uid):
            have.append(t("apv.m.password"))
        if auth.store.has_pin(uid):
            have.append(t("apv.m.pin"))
        if auth.store.has_confirmed_totp(uid):
            have.append(t("apv.m.totp"))
        n = len(auth.store.list_webauthn(uid))
        if n:
            have.append(t("apv.m.passkeys", n=n))
        return ", ".join(have) or t("apv.m.none")

    def _ends_text(self, uid: int) -> str:
        """What the reset ends besides the factors — sessions, API keys, app passwords, services and connected
        programs the account holds now, in words."""
        store = self.store
        t = self.auth.t
        sessions = int(store._one("SELECT COUNT(*) AS n FROM session WHERE user_id=?", (uid,))["n"])
        keys = sum(1 for k in store.list_api_keys(uid) if not k["revoked"])
        parts = [(sessions, "apv.e.sessions"), (keys, "apv.e.api_keys"),
                 (store.app_passwords_active(uid), "apv.e.app_passwords"),
                 (len(store.oauth_service_ids(uid)), "apv.e.services"),
                 (len(store.oauth_user_grant_ids(uid)), "apv.e.devices")]
        return ", ".join(t(key, n=n) for n, key in parts if n) or t("apv.m.none")

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

    def _provider_ok(self, u: dict, row, method: str = "oidc") -> Optional[int]:
        """The provider's `auth_time` (OIDC) or `AuthnInstant` (SAML) of a fresh sign-in started from THIS approval's
        page for this account, consumed once — or None. Without the time from the provider there is none
        (fail-closed)."""
        grant = self.store.pop_flow(PROVIDERS[method] + row["id"])
        if not grant or int(grant.get("user_id") or 0) != int(u["id"]):
            return None
        at = grant.get("auth_time")
        if not isinstance(at, int) or at < int(row["created_at"]):
            return None
        return at

    def provider_ready(self, u: dict, row, method: str = "oidc") -> bool:
        """Is a provider confirmation (`oidc`, `saml`) for this approval waiting (read only — the POST consumes it)?"""
        r = self.store._one("SELECT data, expires_at FROM flow WHERE key=?", (PROVIDERS[method] + row["id"],))
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
        asker = f"app={row['app_id']}" if row["class"] == "app" else f"key={row['requester_ref']}"
        auth.audit("approval_approved", u["username"], ip,
                   f"id={row['id']} type={row['type']} {asker} amr={','.join(amr)} hash={row['payload_hash']}")
        if row["class"] == "app":
            return self._decided_app_action(u, row, now, ip)
        result = self.execute(request, u, json.loads(row["payload"]), row)
        if result == "ok" and row["type"] in PICKUP_TYPES:
            # Executed; the output waits for the requester (`pickup`), at most `approval_pending_sec` from now.
            self.store.set_approval_fields(row["id"], "approved", result=result,
                                           expires_at=now + int(self.cfg.approval_pending_sec))
        else:
            self.store.approval_transition(row["id"], "approved", "consumed", result=result)
        auth.audit("approval_executed", u["username"], ip, f"id={row['id']} type={row['type']} result={result}")
        auth._security_event("approval_approved", u["id"], approval_id=row["id"], type=row["type"], result=result)
        return 200, "done", self.view(self.store.get_approval(row["id"]), u)

    def _decided_app_action(self, u: dict, row, now: int, ip) -> tuple[int, str, dict]:
        """An application action was confirmed (class b): TinySesam carries nothing out. The application, its type and
        the subject are checked once more; then the row waits in `approved` for the pickup of its confirmation, at
        most `approval_pickup_sec` from now. Otherwise it ends in `consumed` with `result=forbidden`."""
        _app, _spec, word = self._app_scope(row)
        if word != "ok":
            self.store.approval_transition(row["id"], "approved", "consumed", result=word)
            self.auth.audit("approval_denied", u["username"], ip, f"id={row['id']} reason=app_gone")
            return 200, "done", self.view(self.store.get_approval(row["id"]), u)
        self.store.set_approval_fields(row["id"], "approved", expires_at=now + int(self.cfg.approval_pickup_sec))
        return 200, "done", self.view(self.store.get_approval(row["id"]), u)

    def _step_up(self, request: Request, u: dict, row, form: dict):
        """((amr, auth_time), None) for a step-up of THIS approval that succeeded, otherwise (None, refusal)."""
        auth = self.auth
        offered = self.methods(u)
        if form.get("webauthn"):
            if "passkey" in offered and self._passkey_ok(u, row, str(form["webauthn"])):
                return (AMR["passkey"], _now()), None
            return None, None
        if form.get("method") in PROVIDERS:
            method = str(form["method"])
            at = self._provider_ok(u, row, method) if method in offered else None
            return ((AMR[method], at), None) if at is not None else (None, None)
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

    def execute(self, request: Request, me: dict, payload: dict, row=None) -> str:
        """Run a confirmed class (a) action with the admin panel's code, as the confirming session — its rights at
        THIS moment decide (E4): an administrator, a delegate within their scope (T-74), or the holder for their own
        key; for an access reset only a holder of the application's `approver_role` (`_reset_scope`) — not even an
        administrator without it. Returns one word of `RESULTS`."""
        auth = self.auth
        if payload["type"] == RESET_ACCESS:
            if row is None:
                return "forbidden"
            app, target, word = self._reset_scope(row, me)
            if word != "ok" or app is None or target is None:
                return word
            auth._reset_access(int(target["id"]), app_id=app["id"], approved_by=me,
                               detail=f"approval={row['id']}")
            return "ok"
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

def _origin(url: str) -> Optional[str]:
    from urllib.parse import urlsplit
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    return f"{p.scheme}://{p.netloc}" if p.scheme in ("http", "https") and p.netloc else None


def _no_framing(resp: Response, form_origin: Optional[str] = None) -> Response:
    """The approval pages are never framed (clickjacking) — `frame-ancestors 'none'` and `X-Frame-Options: DENY`
    whatever `csp` says: with `csp="off"` (the proxy sets the policy) and with an own policy as well.

    `form_origin`: the origin of a registered return address (browser entry). The decision is a form POST that
    redirects there, and Chrome checks that redirect against the page's `form-action` — so exactly that origin is
    added to an existing `form-action`, nothing else."""
    policy = resp.headers.get("content-security-policy", "")
    parts = [d.strip() for d in policy.split(";") if d.strip()]
    out = [d for d in parts if d.split(None, 1)[0].lower() != "frame-ancestors"]
    if form_origin:
        out = [f"{d} {form_origin}" if d.split(None, 1)[0].lower() == "form-action" else d for d in out]
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

    # --- the applications' side: the public keys of the confirmations (purpose `approval`, never the gate keys) ---
    # Registered before `/auth/approvals/{approval_id}`, which would otherwise take "jwks.json" for an id.
    @r.get("/auth/approvals/jwks.json")
    def approval_jwks():
        return JSONResponse(auth.approval_jwks(), headers={"Cache-Control": "public, max-age=300"})

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
            # `pickup`: a confirmed access reset hands out its one-time link here, exactly once.
            return ok_json(svc.pickup(row))
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
        error_text = {"stale": auth.t("err.oidc_reauth_stale"),
                      "stale-saml": auth.t("err.saml_reauth_stale")}.get(stepup, "")
        return _no_framing(auth.render_page("approval", request=request, outcome="open", approval=view,
                                            methods=svc.methods(u), provider_ready=svc.provider_ready(u, row),
                                            saml_ready=svc.provider_ready(u, row, "saml"),
                                            error=error_text), view.get("return_origin"))

    @r.post("/auth/approvals/{approval_id}")
    async def approval_decide(request: Request, approval_id: str):
        form = {k: v for k, v in (await request.form()).items() if isinstance(v, str)}
        status, outcome, view = svc.decide(request, approval_id, form)
        # Browser entry of an application action: back to exactly the registered address — confirmed, rejected or
        # expired — with the id and the application's state, never the confirmation (it is picked up in the back end).
        back = view.get("return_to") if view.get("app_action") else None
        if back and (outcome in ("done", "rejected") or (outcome == "closed" and view.get("state") == "expired")):
            return _no_framing(RedirectResponse(back, 303))
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
        return _no_framing(auth.render_page("approval", status=status, request=request, **ctx),
                           view.get("return_origin"))

    if auth.webauthn is not None:
        @r.post("/auth/approvals/{approval_id}/passkey")
        def approval_passkey(request: Request, approval_id: str):
            if request.headers.get("authorization") or request.headers.get("x-api-key"):
                raise HTTPException(403, auth.t("apv.token_refused"))
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            return Response(content=svc.passkey_options(request, approval_id), media_type="application/json",
                            headers={"Cache-Control": "no-store"})
