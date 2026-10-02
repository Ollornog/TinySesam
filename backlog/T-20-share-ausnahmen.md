---
id: T-20
type: Task
title: Share-Ausnahmen je App — exakte Pfadpräfixe vor dem Gate, mit Gegenprobe
status: offen
milestone: M-3
tags: [gateway, caddy, share]
created: 2026-10-03
---

# T-20 — Share-Ausnahmen

Apps mit Share-Links brauchen öffentliche Pfade. Die Ausnahme steht im Proxy **vor** dem Gate.

**Zu tun:** Doku + Beispiel (Caddy `handle @share`), Muster für bekannte Apps als Startpunkt (je App
selbst nachmessen: Share-Seiten laden eigene Assets und API-Aufrufe). Nie Endungs-Matcher.
`Remote-User` auch hier entfernen. Kleines Prüfwerkzeug oder Testmuster: ein Pfad **außerhalb** der
Liste (auch mit `..`, `%2e`, doppeltem Schrägstrich) muss 401 bzw. 307 liefern.

**Fertig, wenn:** Beispiel und Gegenprobe im Repo, Konfigurationsprüfung (T-23) warnt vor Endungen.
