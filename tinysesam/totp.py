"""TOTP (time-based 2FA) — pyotp; optional qrcode for the enrollment QR."""
from __future__ import annotations
import io, base64

import pyotp

try:
    import qrcode
    _QR = True
except Exception:
    _QR = False


def new_secret() -> str:
    return pyotp.random_base32()


def provisioning_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer or "TinySesam")


def verify(secret: str, code: str) -> bool:
    if not secret or not code:
        return False
    try:
        return pyotp.TOTP(secret).verify(str(code).strip().replace(" ", ""), valid_window=1)
    except Exception:
        return False


def matching_step(secret: str, code: str, window: int = 1):
    """Which time step matches this code — or None.

    `verify()` only says yes/no. For single use the caller has to know WHICH
    step was hit: `valid_window=1` allows the previous, the current and the
    next one, so a code was valid any number of times for 90 seconds (NIST SP 800-63B requires
    exactly once). Without this information the consumption cannot be booked.
    """
    try:
        import time as _t

        import pyotp
    except ModuleNotFoundError:
        return None
    clean = str(code).strip().replace(" ", "")
    totp = pyotp.TOTP(secret)
    now = int(_t.time())
    for offset in range(-window, window + 1):
        moment = now + offset * totp.interval
        if pyotp.utils.strings_equal(str(totp.at(moment)), clean):
            return moment // totp.interval
    return None


def qr_data_uri(uri: str):
    """PNG QR as data: URI (or None if qrcode is not installed → the UI then shows the secret)."""
    if not _QR:
        return None
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
