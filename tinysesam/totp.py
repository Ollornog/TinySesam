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


#: Which time steps a code may come from, per `totp_window` (T-57): (steps back, steps ahead).
#: RFC 6238 §5.2 recommends at most one step back for the transmission delay; a step ahead only
#: covers a device whose clock runs fast — phones set their clock from the network.
WINDOWS = {"current": (0, 0), "previous": (1, 0), "previous_and_next": (1, 1)}


def verify(secret: str, code: str, window: str = "previous") -> bool:
    """Does the code match one of the steps `window` allows (a key of `WINDOWS`)? Yes/no only, no consumption."""
    if not secret or not code:
        return False
    try:
        back, ahead = WINDOWS[window]
        return matching_step(secret, code, back, ahead) is not None
    except Exception:
        return False


def matching_step(secret: str, code: str, window: int = 1, ahead=None):
    """Which time step matches this code — or None.

    `verify()` only says yes/no. For single use the caller has to know WHICH
    step was hit: a window of a step back and a step ahead allowed three steps, so a code was valid any number
    of times for 90 seconds (NIST SP 800-63B requires exactly once). Without this information the consumption
    cannot be booked.

    `window` is the number of steps back, `ahead` the number of steps ahead (None = as many as back, the
    symmetric window up to T-57). The manager passes the pair from `WINDOWS[cfg.totp_window]`.
    """
    try:
        import time as _t

        import pyotp
    except ModuleNotFoundError:
        return None
    ahead = window if ahead is None else ahead
    clean = str(code).strip().replace(" ", "")
    totp = pyotp.TOTP(secret)
    now = int(_t.time())
    for offset in range(-window, ahead + 1):
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
