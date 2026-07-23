---
id: T-4
type: Task
title: E-Mail-Verifikation und Einladung ohne Magic-Link-Endpunkt
status: offen
milestone: M-1
tags: [mail, registrierung]
created: 2026-07-10
---

# T-4 — Verifikation/Einladung vom Magic-Link entkoppeln

E-Mail-Verifikation und Einladung nutzen aktuell denselben Endpunkt wie der Magic-Link
(`/auth/magic/{token}`). Wer Magic-Link abschaltet, verliert damit auch Verifikation und Einladung
— zwei Dinge, die nichts miteinander zu tun haben.

**Fertig, wenn:** beide Wege einen eigenen Endpunkt haben und Magic-Link unabhängig abschaltbar ist.
