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
#: scrypt-Parameter für den Fallback ohne `[argon2]`. `p=3` statt `p=1`: Das OWASP Password
#: Storage Cheat Sheet listet `N=2^15` nur zusammen mit `p=3` als gleichwertige Konfiguration
#: (die übrigen sind `N=2^17/p=1`, `N=2^16/p=2`, `N=2^14/p=5`, `N=2^13/p=10`). `N=2^15, p=1` war
#: keine davon und lag messbar darunter — 52 ms gegen 122 ms auf demselben Rechner.
_SCRYPT = dict(n=2 ** 15, r=8, p=3, dklen=32, maxmem=_MAXMEM)

#: Die Parameter, mit denen bis einschliesslich 0.17.0 gehasht wurde. Das damalige Format
#: `scrypt$salt$dk` trug sie nicht mit — wer einen solchen Hash mit dem heutigen `p=3` nachrechnet,
#: bekommt ein anderes Ergebnis und damit ein falsches "Passwort stimmt nicht". Ohne diese Zeile
#: hätte die Parameter-Anhebung in 0.18.0 jedes Konto ausgesperrt, das ohne `[argon2]` läuft.
_SCRYPT_ALT = dict(n=2 ** 15, r=8, p=1)


def _scrypt_teile(stored: str) -> tuple[int, int, int, str, str]:
    """`scrypt$…` zerlegen → (n, r, p, salt_b64, dk_b64).

    Zwei Formate: das heutige `scrypt$n$r$p$salt$dk` trägt seine Parameter selbst, das alte
    `scrypt$salt$dk` nicht — dort gelten die von damals (`_SCRYPT_ALT`).

    Die Parameter kommen damit aus der Datenbank. Ein absurd grosses `n` rechnet trotzdem niemand:
    `verify_password` gibt `_MAXMEM` mit, `hashlib.scrypt` weist alles darüber ab, und der Aufrufer
    wertet das als „Passwort stimmt nicht". (Wer in die Tabelle schreiben kann, braucht diesen Weg
    ohnehin nicht — er setzt einfach einen eigenen Hash.)
    """
    teile = stored.split("$")
    if len(teile) == 6:
        _, n, r, pp, salt_b, dk_b = teile
        return int(n), int(r), int(pp), salt_b, dk_b
    _, salt_b, dk_b = teile
    return _SCRYPT_ALT["n"], _SCRYPT_ALT["r"], _SCRYPT_ALT["p"], salt_b, dk_b


def hash_password(pw: str) -> str:
    if not pw:
        raise ValueError("leeres Passwort")
    if _ARGON:
        return _PH.hash(pw)
    salt = os.urandom(16)
    dk = hashlib.scrypt(pw.encode(), salt=salt, **_SCRYPT)
    return "scrypt$%d$%d$%d$%s$%s" % (_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"],
                                      base64.b64encode(salt).decode(),
                                      base64.b64encode(dk).decode())


def verify_password(pw: str, stored: str) -> bool:
    if not pw or not stored:
        return False
    if stored.startswith("scrypt$"):
        try:
            n, r, pp, salt_b, dk_b = _scrypt_teile(stored)
            salt, dk = base64.b64decode(salt_b), base64.b64decode(dk_b)
            calc = hashlib.scrypt(pw.encode(), salt=salt, n=n, r=r, p=pp,
                                  dklen=len(dk), maxmem=_MAXMEM)
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
    """Sollte dieser Hash beim nächsten erfolgreichen Login neu gerechnet werden?

    Ein **scrypt**-Hash sagt hier `True`, sobald argon2 verfügbar ist: Wer das Extra `[argon2]`
    nachinstalliert, soll seine Bestandskonten auch wirklich auf das stärkere Verfahren heben.
    Vorher gab diese Funktion für jeden `scrypt$`-Hash `False` zurück — die Login-Pfade riefen
    sie zwar korrekt auf, bekamen aber nie ein `True`, und die Konten blieben für immer auf dem
    Fallback. Zusammen mit den zu schwachen scrypt-Parametern war das doppelt ärgerlich.
    """
    if not stored:
        return False
    if stored.startswith("scrypt$"):
        if _ARGON:
            return True        # argon2 da → beim nächsten Login aufsteigen
        try:                   # sonst: schwächere scrypt-Parameter als heute → neu rechnen
            n, r, pp, _, _ = _scrypt_teile(stored)
        except Exception:
            return False
        return (n, r, pp) != (_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"])
    if _ARGON:
        try:
            return _PH.check_needs_rehash(stored)
        except Exception:
            return False
    return False
