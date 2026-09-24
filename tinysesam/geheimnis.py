"""Umkehrbare Geheimnisse ruhend verschlüsseln (H-14/H-15, PO-Entscheid 2026-09-24: Pflicht).

Das einzige umkehrbare Geheimnis in der Datenbank ist das TOTP-Geheimnis — Passwörter, PINs,
Recovery-Codes, API-Keys und Bereichsgeheimnisse liegen nur als Hash dort. Bis 0.20.x stand es im
Klartext: Wer eine Kopie der Datei hatte (ein Backup, ein Abzug des Volumes), erzeugte für jedes
Konto gültige Codes, der zweite Faktor war damit so stark wie die Aufbewahrung der Sicherungen.

Jetzt: AES-256-GCM, der Schlüssel liegt NICHT in der Datenbank. Woher er kommt, in dieser Reihe:

1. Umgebungsvariable `TINYSESAM_SECRETS_KEY` (32 Byte, Base64) — der Weg für Container-Secrets.
2. `secrets_key_file` in der Konfiguration (Datei mit demselben Inhalt).
3. Sonst eine Schlüsseldatei neben der Datenbank (`<db>.key`, 0600), beim ersten Start erzeugt.
   Laut: Sie schützt gegen eine Datenbankdatei, die ALLEIN abfliesst, nicht gegen eine Sicherung
   des ganzen Verzeichnisses. Für echte Trennung den Schlüssel über 1. oder 2. an einen anderen
   Ort legen.

**Ohne Schlüssel sind die TOTP-Einrichtungen verloren** — er gehört in die Sicherung, getrennt
von der Datenbank. Passt er nicht zu den gespeicherten Geheimnissen, startet TinySesam nicht
(`ConfigError`), statt still jede TOTP-Anmeldung scheitern zu lassen.

Format eines Werts: `v1:` + Base64url(Nonce 12 Byte ‖ Chiffrat ‖ Tag). Ein Wert ohne Präfix ist
Klartext aus der Zeit davor und wird beim Start verschlüsselt (`Store.geheimnisse_heben`).
"""
from __future__ import annotations

import base64
import logging
import os
import secrets
from typing import Optional

from .errors import ConfigError

PRAEFIX = "v1:"
UMGEBUNG = "TINYSESAM_SECRETS_KEY"
log = logging.getLogger("tinysesam")


def _aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as e:   # pragma: no cover — cryptography ist Pflichtabhängigkeit
        raise ConfigError("Das Paket `cryptography` fehlt — es ist seit 0.21.0 Pflicht "
                          "(TOTP-Geheimnisse werden verschlüsselt).") from e
    return AESGCM


def _schluessel_lesen(text: str, herkunft: str) -> bytes:
    try:
        roh = base64.b64decode(text.strip(), validate=True)
    except (ValueError, TypeError):
        raise ConfigError(f"{herkunft}: kein gültiges Base64.") from None
    if len(roh) != 32:
        raise ConfigError(f"{herkunft}: der Schlüssel muss 32 Byte lang sein (Base64 von 32 "
                          f"Zufallsbytes, z. B. `python -c \"import os,base64;"
                          f"print(base64.b64encode(os.urandom(32)).decode())\"`), er hat {len(roh)}.")
    return roh


def schluessel_laden(db_path: str, schluessel_datei: str = "") -> tuple[bytes, str]:
    """Den Schlüssel finden oder (neben der Datenbank) anlegen. Rückgabe `(schlüssel, herkunft)`."""
    wert = os.environ.get(UMGEBUNG, "")
    if wert.strip():
        return _schluessel_lesen(wert, UMGEBUNG), "umgebung"
    if schluessel_datei:
        try:
            with open(schluessel_datei, encoding="ascii") as f:
                return _schluessel_lesen(f.read(), f"secrets_key_file {schluessel_datei!r}"), "datei"
        except OSError as e:
            raise ConfigError(f"secrets_key_file {schluessel_datei!r} lässt sich nicht lesen: {e}") from e
    if not db_path or db_path == ":memory:":
        # Eine Datenbank im Speicher lebt so lange wie der Prozess — ihr Schlüssel auch.
        return secrets.token_bytes(32), "speicher"
    pfad = db_path + ".key"
    try:
        with open(pfad, encoding="ascii") as f:
            return _schluessel_lesen(f.read(), f"Schlüsseldatei {pfad!r}"), "neben_db"
    except FileNotFoundError:
        pass
    # Atomar und exklusiv anlegen: erst eine vollständige Zwischendatei (0600, fsync), dann ein
    # Hardlink auf den Zielnamen — der gelingt genau einem Prozess. Mehrere Worker, die gleichzeitig
    # zum ersten Mal starten, lasen sonst eine halb geschriebene Datei oder scheiterten am
    # O_EXCL (Angriff auf die zweite Runde, Fund 10: 85 von 240 Starts). Wer verliert, liest die
    # Datei des Gewinners.
    roh = secrets.token_bytes(32)
    zwischen = f"{pfad}.{os.getpid()}.{secrets.token_hex(4)}.tmp"
    fd = os.open(zwischen, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="ascii") as f:
            f.write(base64.b64encode(roh).decode("ascii") + "\n")
            f.flush()
            os.fsync(f.fileno())
        try:
            os.link(zwischen, pfad)
        except FileExistsError:
            with open(pfad, encoding="ascii") as f:
                return _schluessel_lesen(f.read(), f"Schlüsseldatei {pfad!r}"), "neben_db"
    finally:
        try:
            os.unlink(zwischen)
        except FileNotFoundError:
            pass
    log.warning(
        "TinySesam: Schlüssel für die TOTP-Geheimnisse neu erzeugt: %s (0600). Er liegt neben der "
        "Datenbank — das schützt gegen eine Datenbankdatei, die allein abfliesst, nicht gegen eine "
        "Sicherung des ganzen Verzeichnisses. Getrennt ablegen: %s oder secrets_key_file. Und: "
        "Ohne diesen Schlüssel sind alle TOTP-Einrichtungen verloren — mitsichern, getrennt von der "
        "Datenbank.", pfad, UMGEBUNG)
    return roh, "neben_db_neu"


class Tresor:
    """Ver- und Entschlüsseln mit EINEM Schlüssel (AES-256-GCM)."""

    def __init__(self, schluessel: bytes):
        self._aead = _aesgcm()(schluessel)

    def verschluesseln(self, klartext: str) -> str:
        nonce = secrets.token_bytes(12)
        chiffrat = self._aead.encrypt(nonce, klartext.encode("utf-8"), PRAEFIX.encode("ascii"))
        return PRAEFIX + base64.urlsafe_b64encode(nonce + chiffrat).decode("ascii")

    def entschluesseln(self, wert: Optional[str]) -> Optional[str]:
        """`None` bleibt `None`; ein Wert ohne Präfix ist Klartext aus der Zeit vor der
        Verschlüsselung und kommt unverändert zurück (bis `geheimnisse_heben` ihn verschlüsselt).
        Ein falscher Schlüssel wirft `cryptography.exceptions.InvalidTag`."""
        if wert is None or not str(wert).startswith(PRAEFIX):
            return wert
        roh = base64.urlsafe_b64decode(str(wert)[len(PRAEFIX):].encode("ascii"))
        return self._aead.decrypt(roh[:12], roh[12:], PRAEFIX.encode("ascii")).decode("utf-8")

    @staticmethod
    def ist_verschluesselt(wert: Optional[str]) -> bool:
        return bool(wert) and str(wert).startswith(PRAEFIX)
