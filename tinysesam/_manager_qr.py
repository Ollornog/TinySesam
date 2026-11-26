"""The building block `qr` of `TinySesam`: cross-device sign-in by QR code (T-33).

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import hmac
import re
import secrets
import sqlite3
from . import totp as _totp
from .store import read_payload
from fastapi import HTTPException
from typing import Optional
from . import manager as _manager


def _qr_hash(self, code) -> str:
    # Prefixed: a short code must never meet a token of another purpose.
    return self._token_hash("qr:" + code)


def _qr_start(self, request, nxt="/") -> dict:
    """Open a cross-device request for the device of this request.
    Returns {code, secret, expires_at, approve_url, qr}; `approve_url`/`qr` are empty
    without `base_url` (never from the Host header), `qr` also without the extra `[qr]`."""
    ip = self.client_ip(request)
    agent = str(request.headers.get("user-agent") or "")[:200]
    secret = secrets.token_urlsafe(32)
    expires = _manager._now() + int(self.cfg.qr_login_ttl_sec)
    # Number matching (T-44, RFC 10027 §6.1): the new device shows a two-digit number that the
    # approving device has to type. Whoever got the approval link sent (consent phishing) does not
    # see the number — it stands only on the screen of the device that asks.
    match = f"{secrets.randbelow(90) + 10}"
    payload = {"device": self.store.token_digests(secret, "qr-device")[0], "ip": ip, "agent": agent, "next": str(nxt or "/"),
               "match": match}
    for _ in range(5):
        code = "".join(secrets.choice(self._QR_ALPHABET) for _ in range(self._QR_LENGTH))
        try:
            self.store.add_magic_token(self._qr_hash(code), "qr_login", expires, None, None, payload)
            break
        except sqlite3.IntegrityError:      # the same code is still open — draw again
            continue
    else:
        raise HTTPException(503, self.t("err.retry"))
    return {"code": code, "secret": secret, "expires_at": expires, "match": match, **self._qr_links(code)}


def _qr_links(self, code) -> dict:
    """{approve_url, qr} for a short code. The address comes only from `base_url` — never from
    the Host header (R4-01); without it both stay empty and the page shows the code alone."""
    if not str(self.cfg.base_url or "").strip():
        return {"approve_url": "", "qr": None}
    url = f"{self._checked_base(self.cfg.base_url)}/auth/qr/approve?code={code}"
    return {"approve_url": url, "qr": _totp.qr_data_uri(url)}


def _qr_peek(self, code) -> Optional[dict]:
    """An open (unused, unexpired) cross-device request — or None."""
    c = self._qr_code_norm(code)
    row = self.store.get_magic_token(self._qr_hash(c)) if c else None
    if not row or row["purpose"] != "qr_login" or row["used_at"] or row["expires_at"] < _manager._now():
        return None
    p = read_payload(row["payload"]) or {}
    return {"code": c, "user_id": row["user_id"], "ip": p.get("ip"), "agent": p.get("agent"),
            "next": p.get("next") or "/", "device": p.get("device") or "", "match": str(p.get("match") or ""),
            "created_at": row["created_at"], "expires_at": row["expires_at"]}


def _qr_own(self, code, secret) -> Optional[dict]:
    """The request, if `secret` is the one of the device that opened it — otherwise None."""
    info = self._qr_peek(code)
    if not info or not secret or not any(hmac.compare_digest(info["device"], d)
                                         for d in self.store.token_digests(secret, "qr-device")):
        return None
    return info


def _qr_may_approve(self, user) -> bool:
    """May this account approve a cross-device sign-in at all? (T-44, `qr_login_require_second_factor`)

    Only an account with a second factor (TOTP or passkey) by default: the new device then has to
    present it too (`magiclink_require_second_factor`), so an approval talked out of the holder
    gives a half sign-in at most. For an account without one the approval is the whole sign-in."""
    if not self.cfg.qr_login_require_second_factor:
        return True
    uid = int(user["id"])
    return bool(self.store.has_confirmed_totp(uid) or self.store.list_webauthn(uid))


def _qr_approve(self, code, user, match=None) -> str:
    """Bind an open request to the approving account — once; a second approval fails.

    Returns `"ok"`, `"invalid"` (no open request, already decided) or `"mismatch"`: the typed
    number is not the one the new device shows (T-44). A mismatch voids the request at once —
    a guess gets exactly one try, and the new device has to start over."""
    info = self._qr_peek(code)
    if not info or info["user_id"] is not None:
        return "invalid"
    expected = info.get("match") or ""
    typed = re.sub(r"\s", "", str(match or ""))
    if not expected or not hmac.compare_digest(typed.encode(), expected.encode()):
        self.store.expire_magic_token(self._qr_hash(info["code"]))
        self.audit("qr_login_mismatch", str(user["username"]), detail=f"device_ip={info['ip']}")
        return "mismatch"
    if not self.store.approve_qr_token(self._qr_hash(info["code"]), int(user["id"])):
        return "invalid"
    self.audit("qr_login_approve", str(user["username"]), detail=f"device_ip={info['ip']}")
    return "ok"


def _qr_deny(self, code, user) -> bool:
    """Refuse an open request: it expires at once, the new device gets nothing."""
    info = self._qr_peek(code)
    if not info or info["user_id"] is not None:
        return False
    self.store.expire_magic_token(self._qr_hash(info["code"]))
    self.audit("qr_login_deny", str(user["username"]), detail=f"device_ip={info['ip']}")
    return True


def _qr_redeem(self, code, secret) -> Optional[dict]:
    """Consume an APPROVED request for the device that opened it — single use."""
    info = self._qr_own(code, secret)
    if not info or info["user_id"] is None:
        return None
    if not self.store.use_magic_token(self._qr_hash(info["code"])):
        return None
    return info
