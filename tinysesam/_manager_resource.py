"""The building block `resource` of `TinySesam`: shared resource secrets (PIN or passphrase without an account).

Methods of `TinySesam`, loaded on first use (the index `manager._PART_METHODS`); each takes the instance as
`self`, exactly as it did inside the class (T-112).
"""
from __future__ import annotations

import secrets
from .errors import ConfigError
from .passwords import hash_password
from .passwords import verify_password
from fastapi import HTTPException
from fastapi import Request
from . import manager as _manager
from .manager import (
    _samesite,
)


# ---------- Shared resource secrets (PIN or passphrase, without a user account) ----------
def set_resource_secret(self, name, secret, kind="pin", label=None):
    """Set/change the secret for a realm. kind='pin' (numeric) | 'password' (passphrase)."""
    if not secret:
        raise ConfigError("empty secret")
    if kind not in ("pin", "password"):
        raise ConfigError("kind must be 'pin' or 'password'")
    self.store.set_resource_secret(name, hash_password(str(secret)), kind, label)


def remove_resource_secret(self, name):
    """Release a locked resource again (remove the lock, not unlock it)."""
    self.store.delete_resource_secret(name)


def list_resource_secrets(self):
    """All locked resources (names and descriptions, no secrets)."""
    return self.store.list_resource_secrets()


def _check_resource(self, name, secret) -> bool:
    """Check the secret of a locked resource (without unlocking it — `_unlock_resource` does that)."""
    row = self.store.get_resource_secret(name)
    return bool(row and verify_password(str(secret or ""), row["hash"]))


def resource_unlocked(self, request: Request, name) -> bool:
    """Is this resource currently unlocked for this browser?"""
    return self.store.is_resource_unlocked(request.cookies.get(self.resource_cookie_name), name)


def _unlock_resource(self, request: Request, response, name):
    """Unlock a resource for this browser and set the cookie.

    Every unlock gets a **new** token (F-01). Before, it took over the token from the
    browser's cookie: whoever had planted their own on the victim beforehand
    (neighbouring subdomain, plaintext HTTP) knew afterwards the token of an unlocked
    browser — session fixation, only for the realm PIN. What this browser already had
    open moves over to the new token."""
    old = request.cookies.get(self.resource_cookie_name)
    token = secrets.token_urlsafe(32)
    if old:
        self.store.move_resource_unlocks(old, token)
    ttl = self.cfg.resource_unlock_ttl_hours * 3600
    self.store.add_resource_unlock(token, name, _manager._now() + ttl)
    kw = dict(httponly=True, secure=self.cfg.cookie_secure, samesite=_samesite(self.cfg.cookie_samesite),
              path=self.cfg.cookie_path, max_age=ttl)
    if self.cfg.cookie_domain:
        kw["domain"] = self.cfg.cookie_domain
    response.set_cookie(self.resource_cookie_name, token, **kw)


def require_resource(self, name: str):
    """FastAPI dependency factory: realm accessible only after entering the resource secret.
    Independent of the user login. `Depends(auth.require_resource('photos'))`."""
    def dep(request: Request):
        if not self.resource_unlocked(request, name):
            if "text/html" in request.headers.get("accept", ""):
                from urllib.parse import quote
                nxt = quote(request.url.path, safe="/")
                raise HTTPException(307, headers={"Location": f"{self.browser_path(request, '/auth/resource/' + name)}?next={nxt}"})
            raise HTTPException(401, self.t("api.resource_locked"))
        return True
    return dep
