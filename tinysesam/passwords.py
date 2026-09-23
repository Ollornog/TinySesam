"""Passwort-Hashing. Bevorzugt argon2 (argon2-cffi); Fallback auf stdlib-scrypt,
damit TinySesam auch ohne argon2-cffi läuft. Beide sind speicher-hart und sicher."""
from __future__ import annotations
import hashlib, os, base64, hmac
from typing import Optional

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
        pass  # nur die Rechenzeit zählt; das Ergebnis ist immer False
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


# ---------- Passwortregel beim Setzen (Länge, Blockliste, Kontextwörter) ----------
#: Obergrenze für ein neues Passwort. NIST SP 800-63B verlangt, mindestens 64 Zeichen
#: zuzulassen — 256 lässt Passphrasen und Passwortmanagern reichlich Platz. Ohne Grenze
#: (R4-07) nahmen alle drei Setzstellen beliebig lange Eingaben an, und jede davon ging
#: vollständig in den Hash; eine Obergrenze ist die übliche, prüfbare Zusage.
PASSWORT_MAX_LAENGE = 256

#: Eingebaute Blockliste — die Passwörter, die in jeder veröffentlichten Leak-Auswertung ganz
#: oben stehen, plus die deutschsprachigen Klassiker. Bewusst **offline**: Eine Anfrage an
#: einen fremden Dienst (etwa die k-Anonymity-API von HIBP) würde bei jeder Registrierung
#: nach aussen telefonieren; das entscheidet der Betreiber, nicht die Bibliothek (Fund B2-5,
#: Empfehlung H-17). Die Liste ist klein, weil sie mit der Mindestlänge zusammenspielt —
#: länger wird sie über `password_blocklist_file`. Verglichen wird kleingeschrieben.
BLOCKLISTE = frozenset("""
password password1 password12 password123 password1234 passw0rd p@ssw0rd p@ssword
passwort passwort1 passwort12 passwort123 passwort1234 kennwort kennwort1 kennwort123
geheimnis geheimnis1 geheimnis123
123456 1234567 12345678 123456789 1234567890 12345678910 0123456789 987654321 87654321
111111 1111111 11111111 000000 00000000 123123 123123123 123321 654321 666666 121212
112233 159753 147258369 123qwe 1q2w3e 1q2w3e4r 1q2w3e4r5t 1qaz2wsx zaq12wsx
qwerty qwerty1 qwerty12 qwerty123 qwertyuiop qwertz qwertz1 qwertz123 qwertzuiop
asdfgh asdfghjk asdfghjkl yxcvbnm zxcvbnm abc123 abcd1234 abcdef abcdefg abcdefgh
iloveyou iloveyou1 letmein letmein1 welcome welcome1 welcome123 willkommen willkommen1
hallo123 hallohallo admin admin123 admin1234 administrator root1234 changeme changeme1
default secret secret123 test1234 testtest test123456 master master123 superman
football baseball dragon monkey sunshine princess shadow michael jennifer trustno1
starwars whatever freedom computer internet samsung pokemon batman ichliebedich
schatz schatzi schalke04 fussball fußball sommer2024 sommer2025 sommer2026
winter2024 winter2025 winter2026 frühling2026 herbst2026 dezember januar
""".split())

def mit_kernen(eintraege) -> frozenset:
    """Eine Blockliste samt der Wortkerne ihrer Einträge (ab vier Buchstaben).

    Steht `Firmenname2026` auf der Liste, soll `Firmenname!!` nicht durchgehen — verglichen wird
    deshalb auch Kern gegen Kern. Kürzere Kerne (`abc` aus `abc123`) blieben draussen: Sie
    stecken in zu vielen brauchbaren Passwörtern."""
    klein = {str(e).strip().lower() for e in eintraege if str(e).strip()}
    return frozenset(klein | {k for k in map(_kern, klein) if len(k) >= 4})


#: Wörter, die für einen Dienst dieser Art ohnehin jeder zuerst probiert.
KONTEXT_GRUNDWORTE = ("tinysesam", "password", "passwort", "login", "admin")


def _kern(pw: str) -> str:
    """Der Wortkern eines Passworts: kleingeschrieben, ohne Ziffern und Sonderzeichen.

    Daran scheitern die üblichen Aufhübschungen (`Passwort2026!`, `Anna1990`, `admin#1`) —
    sie hängen nur Ziffern und Zeichen an ein Wort, das auf der Liste steht."""
    return "".join(z for z in pw.lower() if z.isalpha())


def _trivial(pw: str) -> bool:
    """Ein Zeichen wiederholt (`aaaaaaaa`) oder eine lückenlose Zeichenfolge (`45678901`)."""
    if len(set(pw)) <= 1:
        return True
    schritte = {ord(b) - ord(a) for a, b in zip(pw, pw[1:])}
    return schritte in ({1}, {-1}) or (pw.isdigit() and schritte <= {1, -9})


def passwort_mangel(pw: str, min_laenge: int, *, kontext=(), blockliste=()) -> "Optional[tuple]":
    """Was stimmt mit diesem neuen Passwort nicht? `None` = in Ordnung.

    Rückgabe `(grund, parameter)` mit `grund` in `"short"`, `"long"`, `"weak"` — die Texte
    macht der Aufrufer, damit dieselbe Regel für Seite, JSON-Antwort und CLI gilt. Geprüft
    wird, was NIST SP 800-63B für ein gewähltes Passwort verlangt: Länge, Abgleich gegen eine
    Liste bekannter Passwörter und gegen **kontextbezogene Wörter** (Dienstname, Benutzername,
    E-Mail-Adresse). Keine Zusammensetzungsregeln (Grossbuchstabe, Sonderzeichen) — die
    verbietet dieselbe Norm, weil sie nur vorhersehbare Muster erzeugen.

    `kontext`: Wörter, die für DIESES Konto naheliegen. `blockliste`: zusätzliche Einträge
    des Betreibers (aufbereitet mit `mit_kernen`).
    """
    pw = pw or ""
    if len(pw) < int(min_laenge):
        return "short", {"n": int(min_laenge)}
    if len(pw) > PASSWORT_MAX_LAENGE:
        return "long", {"n": PASSWORT_MAX_LAENGE}
    klein = pw.lower()
    kern = _kern(pw)
    if klein in _BLOCK or klein in blockliste or _trivial(pw):
        return "weak", {}
    if kern and (kern in _BLOCK or kern in blockliste):
        return "weak", {}
    for wort in tuple(KONTEXT_GRUNDWORTE) + tuple(kontext or ()):
        w = _kern(str(wort or ""))
        # Unter vier Buchstaben trägt ein Kontextwort nichts — `al` stünde in jedem zweiten Wort.
        # Auch verdoppelt (`admin-admin`) ist es nur das eine Wort.
        if kern and len(w) >= 4 and len(kern) % len(w) == 0 and kern == w * (len(kern) // len(w)):
            return "weak", {}
    return None


_BLOCK = mit_kernen(BLOCKLISTE)
