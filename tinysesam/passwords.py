"""Password hashing. Prefers argon2 (argon2-cffi); falls back to stdlib scrypt,
so TinySesam also runs without argon2-cffi. Both are memory-hard and secure.

The direction matters: every installation can verify scrypt hashes, argon2 hashes only one with the extra
`[argon2]`. If it is missing at runtime — new image without the extra, `pip install tinysesam` instead of
`tinysesam[argon2]`, a venv set up anew —, not a single existing password matches any more (B6-8).
That stays so (an argon2 hash cannot be verified without argon2), but it no longer happens
silently: `TinySesam()` counts the affected hashes at startup, and the first failure of this kind
in operation writes a line with the remedy.
"""
from __future__ import annotations
import hashlib, os, base64, hmac, logging
from typing import Optional

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError, InvalidHash, VerificationError
    _PH = PasswordHasher()
    _ARGON = True
except Exception:
    _ARGON = False

_MAXMEM = 132 * 1024 * 1024  # scrypt n=2^15,r=8 needs ~32 MiB → raise the OpenSSL default limit
#: scrypt parameters for the fallback without `[argon2]`. `p=3` instead of `p=1`: the OWASP Password
#: Storage Cheat Sheet lists `N=2^15` only together with `p=3` as an equivalent configuration
#: (the others are `N=2^17/p=1`, `N=2^16/p=2`, `N=2^14/p=5`, `N=2^13/p=10`). `N=2^15, p=1` was
#: none of them and measurably lower — 52 ms against 122 ms on the same machine.
_SCRYPT = dict(n=2 ** 15, r=8, p=3, dklen=32, maxmem=_MAXMEM)

#: The parameters used for hashing up to and including 0.17.0. The format of that time,
#: `scrypt$salt$dk`, did not carry them — recomputing such a hash with today's `p=3`
#: gives a different result and thus a false "password does not match". Without this line
#: the parameter increase in 0.18.0 would have locked out every account that runs without `[argon2]`.
_SCRYPT_OLD = dict(n=2 ** 15, r=8, p=1)


def _scrypt_parts(stored: str) -> tuple[int, int, int, str, str]:
    """Split `scrypt$…` → (n, r, p, salt_b64, dk_b64).

    Two formats: today's `scrypt$n$r$p$salt$dk` carries its parameters itself, the old
    `scrypt$salt$dk` does not — there those of that time apply (`_SCRYPT_OLD`).

    The parameters thus come from the database. An absurdly large `n` is still not computed by anyone:
    `verify_password` passes `_MAXMEM`, `hashlib.scrypt` rejects everything above it, and the caller
    treats that as "password does not match". (Whoever can write to the table does not need this path
    anyway — they simply set a hash of their own.)
    """
    parts = stored.split("$")
    if len(parts) == 6:
        _, n, r, pp, salt_b, dk_b = parts
        return int(n), int(r), int(pp), salt_b, dk_b
    _, salt_b, dk_b = parts
    return _SCRYPT_OLD["n"], _SCRYPT_OLD["r"], _SCRYPT_OLD["p"], salt_b, dk_b


def hash_password(pw: str) -> str:
    if not pw:
        raise ValueError("empty password")
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
            n, r, pp, salt_b, dk_b = _scrypt_parts(stored)
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
    if is_argon2(stored):
        _report_argon2_missing()
    return False


#: Notice when an argon2 hash shows up without the extra — one line, with the remedy.
ARGON2_MISSING = ("The extra [argon2] is missing, but the database contains argon2 hashes: these "
                "passwords/PINs cannot be verified, every sign-in with them fails. "
                "Remedy: pip install 'tinysesam[argon2]' and restart.")
_ARGON2_REPORTED = {"ja": False}


def argon2_available() -> bool:
    """Is the `[argon2]` extra usable in this process?"""
    return _ARGON


def is_argon2(stored) -> bool:
    return isinstance(stored, str) and stored.startswith("$argon2")


def _report_argon2_missing() -> None:
    """Once per process: in operation it would otherwise be one line per sign-in attempt."""
    if _ARGON2_REPORTED["ja"]:
        return
    _ARGON2_REPORTED["ja"] = True
    logging.getLogger("tinysesam").error(ARGON2_MISSING)


# Dummy hash (with the ACTIVE method, created once) for timing equalization: for an unknown
# user/missing hash still do the same amount of verify work → no user enumeration via timing.
_DUMMY = hash_password("tinysesam-timing-dummy")


def dummy_verify(pw: str) -> bool:
    """Do verify work against the dummy hash (always returns False)."""
    try:
        verify_password(pw or "", _DUMMY)
    except Exception:
        pass  # only the compute time counts; the result is always False
    return False


def needs_rehash(stored: str) -> bool:
    """Should this hash be recomputed at the next successful login?

    A **scrypt** hash says `True` here as soon as argon2 is available: whoever installs the
    `[argon2]` extra later should really have their existing accounts lifted to the stronger method.
    Before, this function returned `False` for every `scrypt$` hash — the login paths
    called it correctly but never got a `True`, and the accounts stayed on the
    fallback forever. Together with the too-weak scrypt parameters that was doubly annoying.
    """
    if not stored:
        return False
    if stored.startswith("scrypt$"):
        if _ARGON:
            return True        # argon2 present → upgrade at the next login
        try:                   # otherwise: weaker scrypt parameters than today → recompute
            n, r, pp, _, _ = _scrypt_parts(stored)
        except Exception:
            return False
        return (n, r, pp) != (_SCRYPT["n"], _SCRYPT["r"], _SCRYPT["p"])
    if _ARGON:
        try:
            return _PH.check_needs_rehash(stored)
        except Exception:
            return False
    return False


# ---------- Password policy when setting (length, blocklist, context words) ----------
#: Upper limit for a new password. NIST SP 800-63B requires allowing at least 64 characters
#: — 256 leaves plenty of room for passphrases and password managers. Without a limit
#: (R4-07) all three setting points accepted input of any length, and each of them went
#: completely into the hash; an upper limit is the usual, verifiable commitment.
PASSWORD_MAX_LENGTH = 256

#: Built-in blocklist — the passwords that top every published leak analysis,
#: plus the German-language classics. Deliberately **offline**: a request to
#: a foreign service (such as HIBP's k-anonymity API) would phone outward on every registration;
#: that is for the operator to decide, not the library (finding B2-5,
#: recommendation H-17). The list is small because it interplays with the minimum length —
#: it grows via `password_blocklist_file`. Comparison is lowercase.
BLOCKLIST = frozenset("""
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

def with_cores(entries) -> frozenset:
    """A blocklist together with the word cores of its entries (from four letters).

    If `Firmenname2026` is on the list, `Firmenname!!` should not get through — so core is
    compared against core as well. Shorter cores (`abc` from `abc123`) stay out: they
    occur in too many usable passwords."""
    small = {str(e).strip().lower() for e in entries if str(e).strip()}
    return frozenset(small | {k for k in map(_core, small) if len(k) >= 4})


#: Words that everyone tries first anyway for a service of this kind.
CONTEXT_BASE_WORDS = ("tinysesam", "password", "passwort", "login", "admin")


def _core(pw: str) -> str:
    """The word core of a password: lowercase, without digits and special characters.

    The usual embellishments fail on it (`Passwort2026!`, `Anna1990`, `admin#1`) —
    they only append digits and characters to a word that is on the list."""
    return "".join(z for z in pw.lower() if z.isalpha())


#: Character rows whose segments count as a "sequence" — forwards as well as backwards. Keyboard rows
#: (German and English layout), alphabet, digit row.
_FORWARD = ("1234567890", "qwertyuiop", "qwertzuiop", "asdfghjkl", "yxcvbnm", "zxcvbnm",
              "abcdefghijklmnopqrstuvwxyz")
_ROWS: tuple = _FORWARD + tuple(r[::-1] for r in _FORWARD)


def _from_rows(s: str) -> bool:
    """Can `s` be composed without gaps from row segments of at least three characters each?

    Catches `qwerasdf`, `0987654321`, `7890123`, `Asdf1234` — keyboard paths and counting rows that
    rank high in every leak list but have no constant character distance."""
    n = len(s)
    goes = [True] + [False] * n
    for i in range(n):
        if not goes[i]:
            continue
        for j in range(i + 3, min(n, i + 26) + 1):
            if any(s[i:j] in r for r in _ROWS):
                goes[j] = True
    return goes[n]


def _trivial(pw: str) -> bool:
    """Trivial patterns: a repeated character (`aaaaaaaa`), a gapless sequence (`45678901`),
    a repeated block (`12341234`, `asdfasdf`), doubled sequences (`11112222`,
    `aabbccdd`) and keyboard or counting rows (`qwerasdf`, `0987654321`).

    Until the rework (A-6) the check knew only the constant distance ±1 — everything else
    in this catalog ranks just as high in the leak lists and got through."""
    s = pw.lower()
    if len(set(s)) <= 1:
        return True
    steps = {ord(b) - ord(a) for a, b in zip(s, s[1:])}
    if steps in ({1}, {-1}) or (s.isdigit() and (steps <= {1, -9} or steps <= {-1, 9})):
        return True
    # One block, several times in a row: `s` is contained in itself shifted by less than its
    # length exactly when it is periodic.
    if (s + s).find(s, 1) < len(s):
        return True
    # Fold runs of identical characters: whatever is at most half as long afterwards and itself
    # trivial was only an inflated sequence.
    folded = "".join(z for i, z in enumerate(s) if i == 0 or s[i - 1] != z)
    if len(folded) * 2 <= len(s) and (len(set(folded)) <= 2 or _trivial(folded)):
        return True
    return _from_rows(s)


def _context_parts(word: str) -> set:
    """A context word as a whole AND in its parts (separators, digits, inner capitals).

    `max.mustermann`, `anna_schmidt`, `k.mueller`, `MaxMustermann` — the surname alone is
    the most obvious password word of these accounts, and comparing the whole name let
    it through (A-5)."""
    raw = str(word or "")
    separated = "".join(" " + z if z.isupper() and i and raw[i - 1].islower() else z
                       for i, z in enumerate(raw))
    parts = "".join(z if z.isalpha() else " " for z in separated.lower()).split()
    return {_core(raw), *parts}


def read_blocklist(path) -> frozenset:
    """A blocklist from a file: one password per line, `#` at the line start = comment.

    Lines are read as UTF-8; a line that is not valid UTF-8, as Latin-1.
    Common leak lists (such as `rockyou.txt`) mix both — with strict UTF-8 reading
    the startup aborted on exactly the lists the field is meant for (A-3). An
    `OSError` (file missing, directory, no permissions) goes to the caller."""
    lines = []
    with open(path, "rb") as f:
        for raw in f:
            try:
                z = raw.decode("utf-8")
            except UnicodeDecodeError:
                z = raw.decode("latin-1")
            if z.strip() and not z.lstrip().startswith("#"):
                lines.append(z)
    return with_cores(lines)


def password_defect(pw: str, min_length: int, *, context=(), blocklist=()) -> "Optional[tuple]":
    """What is wrong with this new password? `None` = fine.

    Returns `(reason, parameter)` with `reason` in `"short"`, `"long"`, `"weak"` — the texts
    are made by the caller, so the same rule applies to page, JSON response and CLI. What is
    checked is what NIST SP 800-63B requires for a chosen password: length, comparison against a
    list of known passwords and against **context-related words** (service name, username,
    email address). No composition rules (uppercase letter, special character) — the
    same standard forbids them because they only produce predictable patterns.

    `context`: words that are obvious for THIS account. `blocklist`: additional entries
    of the operator (prepared with `with_cores`).
    """
    pw = pw or ""
    if len(pw) < int(min_length):
        return "short", {"n": int(min_length)}
    if len(pw) > PASSWORD_MAX_LENGTH:
        return "long", {"n": PASSWORD_MAX_LENGTH}
    small = pw.lower()
    core = _core(pw)
    if small in _BLOCK or small in blocklist or _trivial(pw):
        return "weak", {}
    if core and (core in _BLOCK or core in blocklist):
        return "weak", {}
    for word in tuple(CONTEXT_BASE_WORDS) + tuple(context or ()):
        for w in _context_parts(word):
            # Under four letters a context word contributes nothing — `al` would be in every second
            # word. Even doubled (`admin-admin`) it is just the one word.
            if core and len(w) >= 4 and len(core) % len(w) == 0 and core == w * (len(core) // len(w)):
                return "weak", {}
    return None


_BLOCK = with_cores(BLOCKLIST)
