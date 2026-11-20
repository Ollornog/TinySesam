"""App passwords (T-66): a password per device and purpose for HTTP clients without a browser.

WebDAV, CalDAV/CardDAV, Git over HTTPS and simple scripts speak only Basic auth (RFC 7617): a user name and a
password in every request. They cannot follow a redirect to a sign-in page, cannot answer a TOTP prompt and cannot
hold a passkey. The established answer is the app password (Nextcloud, Google, Fastmail, GitHub fine-grained
tokens): a generated secret, shown once, valid for one purpose, revocable on its own — never the account's own
password, which stays behind the full sign-in with its second factor.

This module holds the pure parts: the format, its normalisation, the digest and the parsing of the Basic header.
What is allowed — which account, which application, expiry, lockout — lives in `TinySesam`.

**Format.** Five groups of five characters, joined by hyphens: ``k7qm3-x9tfa-…``. The alphabet is 31 symbols —
lowercase letters and digits without ``0 o 1 l i`` (the pairs that a person copying from a screen to a phone
keyboard confuses). Lowercase only: no shift key on a phone. 25 symbols × log2(31) ≈ 123.9 bits — above the
112 bits that NIST SP 800-63B (§5.1.2.1) asks of a look-up secret that is NOT rate-limited, so the secret holds
even where the lockout does not (a stolen database together with the pepper). Google's app passwords have 16 letters
(≈ 75 bits); Nextcloud's 5 × 5 mixed-case groups ≈ 148 bits, but with a shift key per character. The hyphens and
the case are ignored on input (`normalize`), so a client that drops them or a person who types capitals still gets in.

**Digest.** HMAC-SHA-256 with the pepper keyring of ADR-12 (`keys.PEPPER`) and a label of its own, so a digest
of an app password can never equal the digest of an OAuth token with the same text. A fast keyed hash, not
argon2: the secret has 124 bits of entropy (nothing to stretch), and a client sends it with every request — a
WebDAV sync of a thousand files would otherwise cost a thousand argon2 runs.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
import secrets
from typing import Optional

#: The symbols of an app password: lowercase letters and digits without 0, o, 1, l, i.
ALPHABET = "23456789abcdefghjkmnpqrstuvwxyz"
#: Five groups of five.
GROUPS = 5
GROUP_LENGTH = 5
LENGTH = GROUPS * GROUP_LENGTH

#: Domain separation inside the shared pepper keyring (ADR-12): the OAuth digests use the plain token.
_LABEL = b"tinysesam/app-password/v1\x00"

#: A Basic header longer than this is not looked at (a user name and a 29-character secret need far less).
MAX_HEADER = 1024

#: Default lifetime in days (`app_password_default_days`). A year, not the 90 days of an automation key: an app
#: password sits in a calendar or a file sync on a phone, typed in by hand — breaking it every quarter teaches people
#: to make it last forever. A year still ends what nobody remembers, and the list shows when each one was last used.
DEFAULT_DAYS = 365
#: The longest lifetime one can choose (ten years) — beyond it only "no expiry", and that needs the operator's
#: permission (`app_password_allow_unlimited`).
MAX_DAYS = 3650
#: The longest name of an app password (a label for the person, e.g. "Phone calendar").
MAX_NAME = 80


def generate() -> str:
    """A new app password in its display form: ``xxxxx-xxxxx-xxxxx-xxxxx-xxxxx``."""
    raw = "".join(secrets.choice(ALPHABET) for _ in range(LENGTH))
    return "-".join(raw[i:i + GROUP_LENGTH] for i in range(0, LENGTH, GROUP_LENGTH))


def normalize(text: str) -> Optional[str]:
    """The canonical form of a typed app password — or None if it cannot be one.

    Case, hyphens and spaces are ignored; what remains must be exactly `LENGTH` symbols of `ALPHABET`. Anything
    else — above all the account's own password — is no app password and is never looked up: the main password
    therefore cannot pass at the gate, whatever it is."""
    s = "".join(c for c in str(text or "").lower() if c not in "- ")
    if len(s) != LENGTH or any(c not in ALPHABET for c in s):
        return None
    return s


def digest(pepper: bytes, normalized: str) -> str:
    """HMAC-SHA-256 of a normalised app password with a pepper, hex."""
    return hmac.new(pepper, _LABEL + normalized.encode("ascii"), hashlib.sha256).hexdigest()


def parse_basic(header: str) -> Optional[tuple]:
    """``(user, secret)`` from an ``Authorization: Basic …`` header (RFC 7617) — or None.

    UTF-8 as RFC 7617 §2.1 recommends (`charset="UTF-8"` in the challenge); the user ends at the FIRST colon, the
    password may contain colons. A header that is no valid Basic header (wrong scheme, broken Base64, no colon,
    not UTF-8, control characters in the user name, too long) is None — it is then treated like no header."""
    h = str(header or "")
    if len(h) > MAX_HEADER or h[:6].lower() != "basic ":
        return None
    try:
        text = base64.b64decode(h[6:].strip(), validate=True).decode("utf-8")
    except (binascii.Error, ValueError):
        return None
    user, sep, secret = text.partition(":")
    if not sep or not user or any(c < " " or c == "\x7f" for c in user):
        return None
    return user, secret


def challenge(realm: str) -> str:
    """The `WWW-Authenticate` value for a Basic challenge (RFC 7617 §2): the realm quoted, quotes and backslashes
    escaped, control characters dropped, and `charset="UTF-8"`."""
    clean = "".join(c for c in str(realm or "") if c >= " " and c != "\x7f")
    clean = clean.replace("\\", "\\\\").replace('"', '\\"')
    return f'Basic realm="{clean}", charset="UTF-8"'
