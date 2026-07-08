"""E-Mail-Versand für TinySesam. Standard: stdlib-smtplib (STARTTLS/SSL). Komplett ersetzbar
über auth.set_mailer(fn): fn(to, subject, text, html=None) -> None.

Ohne konfigurierten smtp_host UND ohne gesetzten Mailer ist der Versand deaktiviert (send() wirft
MailNotConfigured — die Aufrufer behandeln das als „E-Mail-Feature nicht verfügbar").
"""
from __future__ import annotations
import smtplib
from email.message import EmailMessage


class MailNotConfigured(RuntimeError):
    pass


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
        if cfg.smtp_ssl:
            with smtplib.SMTP_SSL(cfg.smtp_host, cfg.smtp_port, timeout=cfg.smtp_timeout) as s:
                if cfg.smtp_user:
                    s.login(cfg.smtp_user, cfg.smtp_password)
                s.send_message(msg)
        else:
            with smtplib.SMTP(cfg.smtp_host, cfg.smtp_port, timeout=cfg.smtp_timeout) as s:
                if cfg.smtp_starttls:
                    s.starttls()
                if cfg.smtp_user:
                    s.login(cfg.smtp_user, cfg.smtp_password)
                s.send_message(msg)
