"""Fehlertypen, auf die eine einbettende App reagieren kann.

Bis 0.18.0 warf TinySesam nur eingebaute Typen: `ValueError` aus den Konstruktor-Wächtern,
`RuntimeError` aus einem fehlenden Extra, `MailNotConfigured` (nicht exportiert). Wer beim
Starten unterscheiden wollte, ob die **Konfiguration** falsch ist oder ob ein **Paket** fehlt,
musste den Meldungstext lesen — die brüchigste Art, ein Programm zu steuern, und beim nächsten
Übersetzungswechsel kaputt.

Jeder Typ hier erbt zusätzlich von dem eingebauten, den er ersetzt. Bestehender Code, der
`except ValueError` schreibt, fängt weiter — nichts bricht, es wird nur unterscheidbar:

    from tinysesam import ConfigError, MissingExtra, TinySesamError

    try:
        auth = TinySesam(config)
    except MissingExtra as e:
        print("Bitte nachinstallieren:", e)      # pip install 'tinysesam[passkey]'
    except ConfigError as e:
        print("Konfiguration prüfen:", e)        # widersprüchliche Schalter
"""
from __future__ import annotations

from typing import Optional


class TinySesamError(Exception):
    """Basis aller eigenen Fehler — `except TinySesamError` fängt alles von hier."""


class ConfigError(TinySesamError, ValueError):
    """Die Konfiguration widerspricht sich oder verspricht etwas, das so nicht wirkt.

    Erbt von `ValueError`, weil die Wächter das bisher warfen.

    Zwei Felder sind gesetzt, wo eine **Kennung** im Spiel ist (`create_user`): `feld` ist
    `"username"` oder `"email"`, `besitzer_id` die ID des Kontos, dem die Kennung gehört.
    Damit muss niemand den Meldungstext lesen, um die beiden Fälle zu trennen — der Text ist
    übersetzt und gehört dem Menschen, die Attribute dem Programm. Sonst leer bzw. `None`."""

    #: "username" | "email" | "" — betroffenes Feld, wo es eines gibt.
    feld: str = ""
    #: ID des Kontos, dem die Kennung schon gehört (sonst None).
    besitzer_id: "Optional[int]" = None


class MissingExtra(TinySesamError, RuntimeError):
    """Ein aktivierter Schalter braucht ein Extra, das nicht installiert ist.

    Trägt den Namen des Extras, damit eine App die Installationszeile bauen kann, statt sie
    aus dem Meldungstext zu fischen."""

    def __init__(self, nachricht: str, extra: str = ""):
        super().__init__(nachricht)
        self.extra = extra


class MailNotConfigured(TinySesamError, RuntimeError):
    """Es sollte eine Mail raus, aber kein Mailer ist eingerichtet."""


class StateError(TinySesamError, RuntimeError):
    """Der Vorgang passt nicht zum Zustand des Kontos — und wird deshalb verweigert.

    Kein Konfigurations- und kein Installationsfehler: Die Anfrage ist für sich in Ordnung,
    nur würde sie etwas überschreiben, das schon gilt. Erster Fall: eine TOTP-Einrichtung
    starten, obwohl bereits ein bestätigter zweiter Faktor existiert (Fund B2-1) — dort war
    der stille Erfolg das Problem, nicht der Abbruch."""
