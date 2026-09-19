---
id: T-4
type: Task
title: E-Mail-Verifikation und Einladung ohne Magic-Link-Endpunkt
status: erledigt
milestone: M-1
tags: [mail, registrierung]
created: 2026-07-10
---

# T-4 — Verifikation/Einladung vom Magic-Link entkoppeln

E-Mail-Verifikation und Einladung nutzen aktuell denselben Endpunkt wie der Magic-Link
(`/auth/magic/{token}`). Wer Magic-Link abschaltet, verliert damit auch Verifikation und Einladung
— zwei Dinge, die nichts miteinander zu tun haben.

**Fertig, wenn:** beide Wege einen eigenen Endpunkt haben und Magic-Link unabhängig abschaltbar ist.

## Erledigt (2026-09-19)

Drei Wege statt der erwarteten zwei — beim Umbau fiel auf, dass der **Passwort-Reset** denselben
Fehler hatte: seine Route verlangte `password_reset_enabled AND magiclink_enabled`, obwohl sie
ihren eigenen Endpunkt längst besaß. Sie hängt jetzt nur noch am eigenen Schalter.

| Zweck | vorher | jetzt |
|---|---|---|
| Anmelde-Link | `/auth/magic/{token}` | unverändert |
| Adresse bestätigen | `/auth/magic/{token}` | `/auth/verify/{token}` (an `signup_verify_email`) |
| Einladung | `/auth/magic/{token}` → Redirect | `/auth/invite/{token}` (an `allow_signup`) |
| Passwort-Reset | `/auth/magic/{token}` → Redirect | `/auth/reset?token=…` direkt im Link |

Die Links entstehen zweckabhängig aus `TinySesam.TOKEN_PATHS` (`magic_url(raw, base, purpose)`).
`/auth/magic/{token}` nimmt nur noch `login`-Token an und weist andere ab, **ohne sie zu
verbrauchen** — ein falsch geratener Endpunkt macht den Token nicht wertlos.

**Harter Schnitt, bewusst** (PO-Entscheidung): bereits verschickte `/auth/magic/…`-Bestätigungs-
und Einladungslinks sind ungültig. Der Verteiler `_magic_dispatch` ist entfallen; geblieben ist
eine gemeinsame Anmelde-Hilfe für die beiden Wege, die tatsächlich dasselbe belegen (Zugriff aufs
Postfach).
