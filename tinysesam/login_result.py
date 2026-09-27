"""Das Ergebnis eines Anmeldeschritts: `login_password`, `login_pin`, `login_totp` (0.22.0).

PO-Befund 2026-09-26: Die README zeigte als Weg zu einer eigenen Login-Seite `check_password` +
`start_session`. Die inneren Prüfer drosseln aber nicht — Sperre, Fehlversuchszähler, Serie,
IP-Drossel und die Zeilen für fail2ban standen nur in den eingebauten Routen. Wer dem Muster
folgte, liess Passwörter (oder eine vierstellige PIN) so schnell raten, wie der Server antwortet.

Der öffentliche Weg sind seither die drei `login_*`-Methoden. Sie tun genau, was die
eingebauten Routen tun, weil diese sie aufrufen (eine Quelle, kein Drift). Zurück kommt ein
`LoginResult`: Erfolg oder der Grund dagegen, mit dem HTTP-Status und dem Text, den die eingebaute
Seite zeigt.

Die Namen sind englisch (PO-Entscheid 2026-09-27), wie der Rest der Stufe-A-Oberfläche. Die Werte
von `reason` sind kurze englische Kürzel für Programme; die Audit- und Log-Zeilen (fail2ban!)
behalten ihre eigenen Wörter — ein `reason` ist keine Log-Zeile.

Erwartbare Ausgänge — falsches Passwort, Sperre, Drossel, Verzeichnis weg — sind **Ergebnisse,
keine Ausnahmen**: Die eingebaute Route muss sie als Seite mit Status rendern, eine eigene als
Formular oder JSON. Fail-closed durch Bauweise: Bei jedem Misserfolg gibt es keine Sitzung und
kein Cookie. Wer das Ergebnis ignoriert, landet ohne Sitzung auf der Zielseite und wird von dort
zur Anmeldung zurückgeschickt.

Das Sitzungs-Token ist bewusst **kein Feld**: Der Fehler, den die alte README vormachte (das
Tupel aus `start_session` im Cookie), kam genau vom Hantieren mit dem Token. `set_cookie()`
und `redirect()` setzen es richtig — samt neuem CSRF-Token bei einer frischen Anmeldung.
Es hängt am Objekt, aber ausserhalb der Dataclass-Felder: `repr()`, `==` und
`dataclasses.asdict()` sehen es nicht.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Optional


@dataclass(frozen=True)
class LoginResult:
    """Was ein Anmeldeschritt ergeben hat: Erfolg oder der Grund dagegen, mit HTTP-Status und Text.

    `if not result:` fragt nach dem Erfolg (`ok`). Bei Erfolg setzt `result.redirect()` das
    Sitzungs-Cookie und leitet zum nächsten Faktor oder zum Ziel; bei einem Misserfolg gibt es
    keine Sitzung, und `status`/`message` sind das, was die eingebaute Seite zeigen würde.
    """

    #: Hat der Schritt angemeldet? Genau dann, wenn `reason == "ok"`; `bool(result)` ist derselbe Wert.
    ok: bool
    #: Warum (nicht): einer der Werte aus `REASONS`. Für Programme — der Text steht in `message`.
    reason: str
    #: Der HTTP-Status der eingebauten Seite: 303 bei Erfolg, sonst 400, 401, 404, 429 oder 503.
    status: int
    #: Der übersetzte Text für den Nutzer (Sprache aus `config.lang`); leer bei Erfolg.
    message: str = ""
    #: Das geprüfte Ziel (`safe_next`, mit Montage-Präfix): bei Erfolg der nächste Faktor-Schritt
    #: oder `next`, sonst `next` fürs Formular — bei `no_session` die Login-Seite.
    next_url: str = ""
    #: Der offene Faktor nach diesem Schritt (etwa `"totp"`), für eine eigene Seite des nächsten
    #: Schritts. Bei einem Fehlschlag im Folgeschritt derselbe Faktor noch einmal, sonst None.
    next_factor: Optional[str] = None
    #: Ist die Sitzung vollständig angemeldet? Nur bei Erfolg und ohne offenen Faktor True.
    done: bool = False
    #: Das angemeldete Konto (wie `get_user`) — nur bei Erfolg, sonst None.
    user: Optional[dict] = None

    #: Jeder Wert, den `reason` annehmen kann: `ok`; `missing` (Pflichtfeld leer, 400); `invalid`
    #: (Passwort, PIN oder Code falsch, 401); `locked` (Sperre nach Fehlversuchen, 429);
    #: `locked_series` (zu viele Fehlversuche in Folge, läuft nicht ab, 429); `ratelimit` (Drossel
    #: je IP, 429); `directory_down` (LDAP-Verzeichnis nicht erreichbar, 503); `method_disabled`
    #: (Verfahren abgeschaltet oder hier kein Erstfaktor, 404); `no_session` (TOTP ohne Sitzung,
    #: 401 — nur bei `login_totp`). `locked` umfasst auch den Aufschub hinter einer schwebenden
    #: Verzeichnis-Anmeldung (G9) — sonst verriete der Grund, dass gerade jemand anderes unter der
    #: Kennung anmeldet.
    REASONS: ClassVar[tuple] = ("ok", "missing", "invalid", "locked", "locked_series", "ratelimit",
                                "directory_down", "method_disabled", "no_session")

    def __post_init__(self) -> None:
        if self.reason not in self.REASONS:
            raise ValueError(f"unbekannter Grund {self.reason!r} (erlaubt: {', '.join(self.REASONS)})")
        if bool(self.ok) != (self.reason == "ok"):
            raise ValueError("ok und reason widersprechen sich")
        # Ohne Sitzung: Nur `_with_session` hängt Token und TinySesam an — ausserhalb der Felder.
        object.__setattr__(self, "_token", None)
        object.__setattr__(self, "_auth", None)

    @classmethod
    def _with_session(cls, auth: Any, token: Optional[str], **felder) -> "LoginResult":
        """Ein Erfolg, dessen Sitzungs-Token noch ins Cookie muss (None: das Cookie gilt schon)."""
        result = cls(**felder)
        object.__setattr__(result, "_auth", auth)
        object.__setattr__(result, "_token", token)
        return result

    def __bool__(self) -> bool:
        return bool(self.ok)

    def set_cookie(self, response) -> None:
        """Das Sitzungs-Cookie in `response` setzen, falls der Schritt ein neues Token ergeben hat.

        Über `TinySesam.set_cookie`: Die Art des Cookies folgt der Sitzung („Angemeldet bleiben“),
        und eine eben entstandene Anmeldung bekommt dabei ein neues CSRF-Token. Ohne neues Token
        (ein Kettenschritt an einer laufenden Sitzung, jeder Misserfolg) tut es nichts. Für eine
        eigene Antwort — JSON statt Umleitung —, sonst `redirect()`."""
        if self._token and self._auth is not None:     # type: ignore[attr-defined]
            self._auth.set_cookie(response, self._token)   # type: ignore[attr-defined]

    def redirect(self):
        """Eine Umleitung (303) nach `next_url`, mit gesetztem Sitzungs-Cookie, falls es eines gibt.

        Bei Erfolg der übliche Abschluss einer eigenen Route: zum offenen Faktor oder zum Ziel.
        Bei `no_session` führt sie zur Login-Seite; bei jedem anderen Misserfolg auf `next`,
        ohne Sitzung — von dort schickt der Guard zurück zur Anmeldung."""
        from fastapi.responses import RedirectResponse
        antwort = RedirectResponse(self.next_url, 303)
        self.set_cookie(antwort)
        return antwort
