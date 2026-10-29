"""Email sending for TinySesam. Default: stdlib smtplib (STARTTLS/SSL). Fully replaceable
via auth.set_mailer(fn): fn(to, subject, text, html=None) -> None.

Without a configured smtp_host AND without a set mailer, sending is disabled: the mailer
is CALLED like a function (`mailer(to, subject, text, html)`) and then raises
MailNotConfigured — the callers treat that as "email feature not available". There is no
`send()` method; whoever builds their own mailer writes a `__call__` or passes
a function directly.

The built-in routes do not send themselves but via the `Postausgang` (below): the
response goes out before the mail leaves the server.
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


# The type now lives in errors.py so an app can import it; the name stays here
# so `from .mailer import MailNotConfigured` keeps working.
from .errors import MailNotConfigured  # noqa: F401

log = logging.getLogger("tinysesam.mail")


def tls_kontext(cfg) -> ssl.SSLContext:
    """The TLS context for the SMTP connection: certificate AND hostname are verified (B3-1).

    `smtplib.SMTP_SSL()` and `starttls()` without `context=` take the stdlib context, which
    verifies **nothing** — anyone on the path could pose as the mail server and got the
    SMTP password along with every sign-in and reset link to read. A relay with its own CA gives
    it via `smtp_ca_file`; the verification deliberately cannot be switched off.
    """
    return ssl.create_default_context(cafile=(getattr(cfg, "smtp_ca_file", "") or None))


class SMTPMailer:
    """Default SMTP sender (stdlib). For the Hetzner 587 submission relay & co."""
    def __init__(self, cfg):
        self.cfg = cfg

    def __call__(self, to, subject, text, html=None):
        cfg = self.cfg
        if not cfg.smtp_host:
            raise MailNotConfigured("no smtp_host configured")
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
            # Since B3-1 the certificate is verified. Whoever sent before with a self-signed certificate
            # or via IP address would otherwise see only `*_send_error` in the audit log —
            # here it says what to do (attack A4).
            log.error("SMTP: certificate of %s not trusted (%s). Enter your own CA in "
                      "smtp_ca_file or set smtp_host to the name in the certificate.",
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
    """Sending outside the request: a small worker pool of its own with a capped queue.

    Two findings, one cause — the route waited for the mail server:

    * **R4-05 (timing):** "Forgot password" and the sign-in link answered for an
      existing address later than for an unknown one by the duration of an SMTP session. The
      response was word for word identical, the stopwatch was not.
    * **B6-6 (thread pool):** Every send held a slot in FastAPI's thread pool for up to
      `smtp_timeout` seconds. Forty requests against a hanging mail server occupied all of them —
      in gateway operation that stalled `/auth/forward` and every app protected behind it.

    `nachher()` therefore returns an **async** background task: Starlette sends the
    response first, then it runs; it waits for its own worker without holding a slot in the thread pool.
    The queue is capped — when it is full, the mail is dropped and this is
    reported, instead of filling memory with a flood of jobs. `TestClient` waits for
    background tasks, so tests see the mail right after the request as before.
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

    def einreihen(self, auftrag) -> bool:
        """Start `auftrag()` in the own worker without waiting for it — for places without a
        response object (the lockout in login, ASVS 6.3.5). False if the queue is full;
        the job is dropped then."""
        if not self._reservieren():
            log.warning("Hinweis-Warteschlange voll (%d) — Versand verworfen", self.max_offen)
            return False

        def _lauf():
            try:
                auftrag()
            except Exception:   # noqa: BLE001
                log.exception("Hinweis-Auftrag gescheitert")
            finally:
                self._freigeben()
        zukunft = self._executor().submit(_lauf)
        with self._lock:
            self._laufend = [z for z in getattr(self, "_laufend", []) if not z.done()] + [zukunft]
        return True

    def abwarten(self, timeout: float = 10.0) -> None:
        """Wait until everything queued has run (for tests and an orderly shutdown)."""
        with self._lock:
            laufend = list(getattr(self, "_laufend", []))
        for z in laufend:
            z.result(timeout=timeout)

    def nachher(self, auftrag, bei_ueberlauf=None):
        """An async background task that runs `auftrag()` in the own worker.

        `auftrag` catches its own errors (it knows what to clean up); whatever still
        gets through is logged here instead of silently swallowed. `bei_ueberlauf()` runs when
        the queue is full — the job is dropped then.
        """
        async def _lauf():
            if not self._reservieren():
                log.warning("Mail-Warteschlange voll (%d) — Versand verworfen", self.max_offen)
                if bei_ueberlauf:
                    try:
                        bei_ueberlauf()
                    except Exception:   # noqa: BLE001 — cleanup must not bring the server down
                        log.exception("Cleanup after a discarded send failed")
                return
            try:
                await asyncio.wrap_future(self._executor().submit(auftrag))
            except Exception:   # noqa: BLE001
                log.exception("Mail-Auftrag gescheitert")
            finally:
                self._freigeben()
        return _lauf
