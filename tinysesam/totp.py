"""TOTP (Zeit-2FA) — pyotp; optional qrcode für den Enrollment-QR."""
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


def qr_data_uri(uri: str):
    """PNG-QR als data:-URI (oder None, wenn qrcode nicht installiert → UI zeigt dann das Secret)."""
    if not _QR:
        return None
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
