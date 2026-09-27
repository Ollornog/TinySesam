"""Das Ergebnis eines Passwortwechsels: `change_password` (0.22.0).

PO-Entscheid 2026-09-27: Nach dem Login-Baustein (`login_*` → `LoginResult`) bekommt auch der
eigene Passwortwechsel einen Baustein für eigene Seiten. Bis dahin gab es nur die Route
`POST /auth/password`; wer eine eigene Kontoseite baute, setzte ihn aus `set_password` und den
inneren Prüfern zusammen — ohne die eigene Sperre für das alte Passwort (R4-10), ohne das Beenden
der anderen Sitzungen und ohne die Protokollzeilen.

Ein eigener Typ und nicht `LoginResult`: Ein Passwortwechsel meldet niemanden an und dreht kein
Sitzungs-Token — `next_url`, `next_factor`, `done`, `set_cookie()` und `redirect()` hätten hier
keine Bedeutung. Dafür trägt er, was nur er zu sagen hat: wie viele API-Keys des Kontos den
Wechsel überleben (`api_keys_active`). Die Form ist dieselbe wie bei `LoginResult` — `ok`,
`reason`, `status`, `message`, `bool(result)`, eingefroren, fail-closed: Bei einem Misserfolg
hat sich nichts geändert.

Erwartbare Ausgänge — altes Passwort falsch, Sperre, Drossel, neues Passwort zu schwach — sind
**Ergebnisse, keine Ausnahmen**; `status` und `message` sind das, was `POST /auth/password`
antwortet (die Route ruft genau diesen Baustein).
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import ClassVar


@dataclass(frozen=True)
class PasswordChangeResult:
    """Was ein Passwortwechsel ergeben hat: Erfolg oder der Grund dagegen, mit HTTP-Status und Text.

    `if not result:` fragt nach dem Erfolg (`ok`). Bei Erfolg gilt das neue Passwort, die anderen
    Sitzungen des Kontos sind beendet (die eigene läuft weiter, ihr Cookie bleibt gültig), und
    `api_keys_active` sagt, wie viele API-Keys weiter gelten. Bei einem Misserfolg hat sich nichts
    geändert; `status`/`message` sind das, was `POST /auth/password` antworten würde.
    """

    #: Ist das neue Passwort gesetzt? Genau dann, wenn `reason == "ok"`; `bool(result)` ist derselbe Wert.
    ok: bool
    #: Warum (nicht): einer der Werte aus `REASONS`. Für Programme — der Text steht in `message`.
    reason: str
    #: Der HTTP-Status von `POST /auth/password`: 200 bei Erfolg, sonst 400, 401, 403 oder 429.
    status: int
    #: Der übersetzte Text für den Nutzer (Sprache aus `config.lang`); leer bei Erfolg.
    message: str = ""
    #: Wie viele API-Keys des Kontos weiter gelten — sie überleben den Wechsel mit Absicht (sie
    #: gehören Automatiken), verschwiegen wird es nicht. Nur bei Erfolg, sonst 0.
    api_keys_active: int = 0

    #: Jeder Wert, den `reason` annehmen kann: `ok`; `missing` (altes Passwort leer, 400, zählt
    #: nicht als Fehlversuch); `invalid` (altes Passwort falsch, 403); `locked` (Sperre nach
    #: `password_change_max_attempts` Fehlversuchen, 429); `ratelimit` (Drossel je IP, 429);
    #: `policy` (das neue Passwort verletzt die Passwortregel, 400 — der Grund steht in `message`);
    #: `no_session` (keine volle Sitzung, 401; 403, wenn die Anfrage statt einer Sitzung einen
    #: API-Key zeigt).
    REASONS: ClassVar[tuple] = ("ok", "missing", "invalid", "locked", "ratelimit", "policy", "no_session")

    def __post_init__(self) -> None:
        if self.reason not in self.REASONS:
            raise ValueError(f"unbekannter Grund {self.reason!r} (erlaubt: {', '.join(self.REASONS)})")
        if bool(self.ok) != (self.reason == "ok"):
            raise ValueError("ok und reason widersprechen sich")

    def __bool__(self) -> bool:
        return bool(self.ok)
