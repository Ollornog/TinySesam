"""Das Ergebnis eines Anmeldeschritts: `anmelden_passwort`, `anmelden_pin`, `anmelden_totp` (0.22.0).

PO-Befund 2026-09-26: Die README zeigte als Weg zu einer eigenen Login-Seite `check_password` +
`start_session`. Die inneren Prüfer drosseln aber nicht — Sperre, Fehlversuchszähler, Serie,
IP-Drossel und die Zeilen für fail2ban standen nur in den eingebauten Routen. Wer dem Muster
folgte, liess Passwörter (oder eine vierstellige PIN) so schnell raten, wie der Server antwortet.

Der öffentliche Weg sind seither die drei `anmelden_*`-Methoden. Sie tun genau, was die
eingebauten Routen tun, weil diese sie aufrufen (eine Quelle, kein Drift). Zurück kommt eine
`Anmeldung`: Erfolg oder der Grund dagegen, mit dem HTTP-Status und dem Text, den die eingebaute
Seite zeigt.

Erwartbare Ausgänge — falsches Passwort, Sperre, Drossel, Verzeichnis weg — sind **Ergebnisse,
keine Ausnahmen**: Die eingebaute Route muss sie als Seite mit Status rendern, eine eigene als
Formular oder JSON. Fail-closed durch Bauweise: Bei jedem Misserfolg gibt es keine Sitzung und
kein Cookie. Wer das Ergebnis ignoriert, landet ohne Sitzung auf der Zielseite und wird von dort
zur Anmeldung zurückgeschickt.

Das Sitzungs-Token ist bewusst **kein Feld**: Der Fehler, den die alte README vormachte (das
Tupel aus `start_session` im Cookie), kam genau vom Hantieren mit dem Token. `cookie_setzen()`
und `weiterleitung()` setzen es richtig — samt neuem CSRF-Token bei einer frischen Anmeldung.
Es hängt am Objekt, aber ausserhalb der Dataclass-Felder: `repr()`, `==` und
`dataclasses.asdict()` sehen es nicht.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, ClassVar, Optional


@dataclass(frozen=True)
class Anmeldung:
    """Was ein Anmeldeschritt ergeben hat: Erfolg oder der Grund dagegen, mit HTTP-Status und Text.

    `if not erg:` fragt nach dem Erfolg (`ok`). Bei Erfolg setzt `erg.weiterleitung()` das
    Sitzungs-Cookie und leitet zum nächsten Faktor oder zum Ziel; bei einem Misserfolg gibt es
    keine Sitzung, und `status`/`meldung` sind das, was die eingebaute Seite zeigen würde.
    """

    #: Hat der Schritt angemeldet? Genau dann, wenn `grund == "ok"`; `bool(erg)` ist derselbe Wert.
    ok: bool
    #: Warum (nicht): einer der Werte aus `GRUENDE`. Für Programme — der Text steht in `meldung`.
    grund: str
    #: Der HTTP-Status der eingebauten Seite: 303 bei Erfolg, sonst 400, 401, 404, 429 oder 503.
    status: int
    #: Der übersetzte Text für den Nutzer (Sprache aus `config.lang`); leer bei Erfolg.
    meldung: str = ""
    #: Das geprüfte Ziel (`safe_next`, mit Montage-Präfix): bei Erfolg der nächste Faktor-Schritt
    #: oder `next`, sonst `next` fürs Formular — bei `keine_sitzung` die Login-Seite.
    weiter: str = ""
    #: Der offene Faktor nach diesem Schritt (etwa `"totp"`), für eine eigene Seite des nächsten
    #: Schritts. Bei einem Fehlschlag im Folgeschritt derselbe Faktor noch einmal, sonst None.
    naechster: Optional[str] = None
    #: Ist die Sitzung vollständig angemeldet? Nur bei Erfolg und ohne offenen Faktor True.
    fertig: bool = False
    #: Das angemeldete Konto (wie `get_user`) — nur bei Erfolg, sonst None.
    user: Optional[dict] = None

    #: Jeder Wert, den `grund` annehmen kann. `gesperrt` umfasst auch den Aufschub hinter einer
    #: schwebenden Verzeichnis-Anmeldung (G9) — sonst verriete der Grund, dass gerade jemand
    #: anderes unter der Kennung anmeldet. `keine_sitzung` gibt es nur bei `anmelden_totp`.
    GRUENDE: ClassVar[tuple] = ("ok", "leer", "falsch", "gesperrt", "gesperrt_serie", "ratelimit",
                                "verzeichnis_weg", "abgeschaltet", "keine_sitzung")

    def __post_init__(self) -> None:
        if self.grund not in self.GRUENDE:
            raise ValueError(f"unbekannter Grund {self.grund!r} (erlaubt: {', '.join(self.GRUENDE)})")
        if bool(self.ok) != (self.grund == "ok"):
            raise ValueError("ok und grund widersprechen sich")
        # Ohne Sitzung: Nur `_mit_sitzung` hängt Token und TinySesam an — ausserhalb der Felder.
        object.__setattr__(self, "_token", None)
        object.__setattr__(self, "_auth", None)

    @classmethod
    def _mit_sitzung(cls, auth: Any, token: Optional[str], **felder) -> "Anmeldung":
        """Ein Erfolg, dessen Sitzungs-Token noch ins Cookie muss (None: das Cookie gilt schon)."""
        erg = cls(**felder)
        object.__setattr__(erg, "_auth", auth)
        object.__setattr__(erg, "_token", token)
        return erg

    def __bool__(self) -> bool:
        return bool(self.ok)

    def cookie_setzen(self, response) -> None:
        """Das Sitzungs-Cookie in `response` setzen, falls der Schritt ein neues Token ergeben hat.

        Über `set_cookie`: Die Art des Cookies folgt der Sitzung („Angemeldet bleiben“), und eine
        eben entstandene Anmeldung bekommt dabei ein neues CSRF-Token. Ohne neues Token (ein
        Kettenschritt an einer laufenden Sitzung, jeder Misserfolg) tut es nichts. Für eine
        eigene Antwort — JSON statt Umleitung —, sonst `weiterleitung()`."""
        if self._token and self._auth is not None:     # type: ignore[attr-defined]
            self._auth.set_cookie(response, self._token)   # type: ignore[attr-defined]

    def weiterleitung(self):
        """Eine Umleitung (303) nach `weiter`, mit gesetztem Sitzungs-Cookie, falls es eines gibt.

        Bei Erfolg der übliche Abschluss einer eigenen Route: zum offenen Faktor oder zum Ziel.
        Bei `keine_sitzung` führt sie zur Login-Seite; bei jedem anderen Misserfolg auf `next`,
        ohne Sitzung — von dort schickt der Guard zurück zur Anmeldung."""
        from fastapi.responses import RedirectResponse
        antwort = RedirectResponse(self.weiter, 303)
        self.cookie_setzen(antwort)
        return antwort
