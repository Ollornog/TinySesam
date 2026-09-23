"""E-Mail-Versand für TinySesam. Standard: stdlib-smtplib (STARTTLS/SSL). Komplett ersetzbar
über auth.set_mailer(fn): fn(to, subject, text, html=None) -> None.

Ohne konfigurierten smtp_host UND ohne gesetzten Mailer ist der Versand deaktiviert: Der Mailer
wird AUFGERUFEN wie eine Funktion (`mailer(to, subject, text, html)`) und wirft dann
MailNotConfigured — die Aufrufer behandeln das als „E-Mail-Feature nicht verfügbar". Eine Methode
`send()` gibt es nicht; wer einen eigenen Mailer baut, schreibt ein `__call__` oder übergibt
gleich eine Funktion.

Die eingebauten Routen verschicken nicht selbst, sondern über den `Postausgang` (unten): Die
Antwort geht hinaus, bevor die Mail den Server verlässt.
"""
from __future__ import annotations
import asyncio
import logging
import smtplib
import ssl
import threading
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from typing import Optional


# Der Typ lebt jetzt in errors.py, damit ihn eine App importieren kann; hier bleibt der Name
# stehen, damit `from .mailer import MailNotConfigured` weiter geht.
from .errors import MailNotConfigured  # noqa: F401

log = logging.getLogger("tinysesam.mail")


def tls_kontext(cfg) -> ssl.SSLContext:
    """Der TLS-Kontext für die SMTP-Verbindung: Zertifikat UND Hostname werden geprüft (B3-1).

    `smtplib.SMTP_SSL()` und `starttls()` ohne `context=` nehmen den stdlib-Kontext, der
    **nichts** prüft — jeder auf dem Weg konnte sich als Mailserver ausgeben und bekam das
    SMTP-Passwort samt jedem Anmelde- und Reset-Link mitgelesen. Ein Relay mit eigener CA gibt
    sie über `smtp_ca_file` an; abschalten lässt sich die Prüfung bewusst nicht.
    """
    return ssl.create_default_context(cafile=(getattr(cfg, "smtp_ca_file", "") or None))


class SMTPMailer:
    """Voreingestellter SMTP-Sender (stdlib). Für den Hetzner-587-Submission-Relay & Co."""
    def __init__(self, cfg):
        self.cfg = cfg

    def __call__(self, to, subject, text, html=None):
        cfg = self.cfg
        if not cfg.smtp_host:
            raise MailNotConfigured("kein smtp_host konfiguriert")
        msg = EmailMessage()
        msg["From"] = cfg.smtp_from or cfg.smtp_user
        msg["To"] = to
        msg["Subject"] = (cfg.mail_subject_prefix or "") + subject
        msg.set_content(text)
        if html:
            msg.add_alternative(html, subtype="html")
        try:
            self._senden(cfg, msg)
        except ssl.SSLCertVerificationError as e:
            # Seit B3-1 wird das Zertifikat geprüft. Wer vorher mit selbstsigniertem Zertifikat
            # oder per IP-Adresse versandt hat, sieht sonst nur `*_send_error` im Audit-Log —
            # hier steht, was zu tun ist (Angriff A4).
            log.error("SMTP: Zertifikat von %s nicht vertrauenswürdig (%s). Eigene CA in "
                      "smtp_ca_file eintragen bzw. smtp_host auf den Namen im Zertifikat setzen.",
                      cfg.smtp_host, getattr(e, "verify_message", None) or e)
            raise

    @staticmethod
    def _senden(cfg, msg):
        if cfg.smtp_ssl:
            with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=cfg.smtp_timeout,
                                  context=tls_kontext(cfg)) as s:
                if cfg.smtp_user:
                    s.login(cfg.smtp_user, cfg.smtp_password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=cfg.smtp_timeout) as s:
                if cfg.smtp_starttls:
                    s.starttls(context=tls_kontext(cfg))
                if cfg.smtp_user:
                    s.login(cfg.smtp_user, cfg.smtp_password)
                s.send_message(msg)


class Postausgang:
    """Versand ausserhalb der Anfrage: eigene, kleine Arbeiterschaft mit gedeckelter Warteschlange.

    Zwei Befunde, eine Ursache — die Route wartete auf den Mailserver:

    * **R4-05 (Timing):** „Passwort vergessen" und der Anmelde-Link antworteten für eine
      existierende Adresse um die Dauer einer SMTP-Sitzung später als für eine unbekannte. Die
      Antwort war wortgleich, die Stoppuhr nicht.
    * **B6-6 (Threadpool):** Jeder Versand hielt einen Platz im Threadpool von FastAPI für bis zu
      `smtp_timeout` Sekunden. Vierzig Anfragen gegen einen hängenden Mailserver belegten alle —
      im Gateway-Betrieb stand damit auch `/auth/forward` und jede dahinter geschützte App.

    `nachher()` liefert deshalb eine **async** Hintergrundaufgabe: Starlette schickt erst die
    Antwort, dann läuft sie; sie wartet auf den eigenen Arbeiter, ohne einen Platz im Threadpool
    zu halten. Die Warteschlange ist gedeckelt — ist sie voll, wird die Mail verworfen und das
    gemeldet, statt den Speicher mit einer Flut von Aufträgen zu füllen. `TestClient` wartet auf
    Hintergrundaufgaben, Tests sehen die Mail also wie bisher direkt nach der Anfrage.
    """

    def __init__(self, arbeiter: int = 2, max_offen: int = 100):
        self.arbeiter = arbeiter
        self.max_offen = max_offen
        self._pool: Optional[ThreadPoolExecutor] = None
        self._offen = 0
        self._lock = threading.Lock()

    def _executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(max_workers=self.arbeiter,
                                                thread_name_prefix="tinysesam-mail")
            return self._pool

    def _reservieren(self) -> bool:
        with self._lock:
            if self._offen >= self.max_offen:
                return False
            self._offen += 1
            return True

    def _freigeben(self):
        with self._lock:
            self._offen -= 1

    def nachher(self, auftrag, bei_ueberlauf=None):
        """Eine async Hintergrundaufgabe, die `auftrag()` im eigenen Arbeiter ausführt.

        `auftrag` fängt seine Fehler selbst (er weiss, was aufzuräumen ist); was trotzdem
        durchschlägt, wird hier geloggt statt still verschluckt. `bei_ueberlauf()` läuft, wenn
        die Warteschlange voll ist — der Auftrag entfällt dann.
        """
        async def _lauf():
            if not self._reservieren():
                log.warning("Mail-Warteschlange voll (%d) — Versand verworfen", self.max_offen)
                if bei_ueberlauf:
                    try:
                        bei_ueberlauf()
                    except Exception:   # noqa: BLE001 — Aufräumen darf den Server nicht reissen
                        log.exception("Aufräumen nach verworfenem Versand gescheitert")
                return
            try:
                await asyncio.wrap_future(self._executor().submit(auftrag))
            except Exception:   # noqa: BLE001
                log.exception("Mail-Auftrag gescheitert")
            finally:
                self._freigeben()
        return _lauf
