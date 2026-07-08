"""Passwort-Hashing. Bevorzugt argon2 (argon2-cffi); Fallback auf stdlib-scrypt,
damit TinySesam auch ohne argon2-cffi läuft. Beide sind speicher-hart und sicher."""
from __future__ import annotations
import hashlib, os, base64, hmac

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
    _PH = PasswordHasher()
    _ARGON = True
except Exception:
    _ARGON = False

_MAXMEM = 132 * 1024 * 1024  # scrypt n=2^15,r=8 braucht ~32 MiB → OpenSSL-Default-Limit anheben
_SCRYPT = dict(n=2 ** 15, r=8, p=1, dklen=32, maxmem=_MAXMEM)


def hash_password(pw: str) -> str:
    if not pw:
        raise ValueError("leeres Passwort")
    if _ARGON:
        return _PH.hash(pw)
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, **_SCRYPT)
    return "scrypt$" + base64.b64encode(salt).decode() + "$" + base64.b64encode(dk).decode()


def verify_password(pw: str, stored: str) -> bool:
    if not pw or not stored:
        return False
    if stored.startswith("scrypt$"):
        try:
            _, salt_b, dk_b = stored.split("$")
            salt, dk = base64.b64decode(salt_b), base64.b64decode(dk_b)
            calc = hashlib.scrypt(pw.encode(), salt=salt, n=_SCRYPT["n"], r=_SCRYPT["r"],
                                  p=_SCRYPT["p"], dklen=len(dk), maxmem=_MAXMEM)
            return hmac.compare_digest(calc, dk)
        except Exception:
            return False
    if _ARGON:
        try:
            _PH.verify(stored, pw)
            return True
        except (VerifyMismatchError, InvalidHash, VerificationError):
            return False
        except Exception:
            return False
    return False


# Dummy-Hash (mit dem AKTIVEN Verfahren, einmalig erzeugt) für Timing-Ausgleich: bei unbekanntem
# User/fehlendem Hash trotzdem gleich viel Verify-Arbeit leisten → keine User-Enumeration per Zeit.
_DUMMY = hash_password("tinysesam-timing-dummy")


def dummy_verify(pw: str) -> bool:
    """Verify-Arbeit gegen den Dummy-Hash leisten (Rückgabe immer False)."""
    try:
        verify_password(pw or "", _DUMMY)
    except Exception:
        pass
    return False


def needs_rehash(stored: str) -> bool:
    if _ARGON and not stored.startswith("scrypt$"):
        try:
            return _PH.check_needs_rehash(stored)
        except Exception:
            return False
    return False
