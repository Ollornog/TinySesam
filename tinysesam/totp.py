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


def passender_schritt(secret: str, code: str, fenster: int = 1):
    """Welcher Zeitschritt passt zu diesem Code — oder None.

    `verify()` sagt nur ja/nein. Für die Einmal-Verwendung muss der Aufrufer wissen, WELCHER
    Schritt getroffen wurde: `valid_window=1` erlaubt den vorherigen, den aktuellen und den
    nächsten, ein Code war damit 90 Sekunden lang beliebig oft gültig (NIST SP 800-63B verlangt
    genau einmal). Ohne diese Auskunft lässt sich der Verbrauch nicht buchen.
    """
    try:
        import time as _t

        import pyotp
    except ModuleNotFoundError:
        return None
    sauber = str(code).strip().replace(" ", "")
    totp = pyotp.TOTP(secret)
    jetzt = int(_t.time())
    for versatz in range(-fenster, fenster + 1):
        zeitpunkt = jetzt + versatz * totp.interval
        if pyotp.utils.strings_equal(str(totp.at(zeitpunkt)), sauber):
            return zeitpunkt // totp.interval
    return None


def qr_data_uri(uri: str):
    """PNG-QR als data:-URI (oder None, wenn qrcode nicht installiert → UI zeigt dann das Secret)."""
    if not _QR:
        return None
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return "data:image/png;base64," + base64.b64encode(buf.getvalue()).decode()
