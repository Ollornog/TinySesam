---
id: T-20
type: Task
title: Share-Ausnahmen je App — exakte Pfadpräfixe vor dem Gate, mit Gegenprobe
status: erledigt
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

## Erledigt 2026-10-07

- `@share` in beiden Caddy-Vorlagen, aus bis `TS_SHARE_PRAEFIX` gesetzt ist.
- **Messung vor der Regel** (Caddy 2.11.7): Der `path`-Matcher vergleicht den bereinigten Pfad und
  unterscheidet nicht nach Gross-/Kleinschreibung, reicht der Anwendung aber den rohen weiter.
  `/s/..;/admin`, `/s/..%5cadmin` und `/s/abc%00` kamen durch, `/x/../s/abc` und `/S/abc` ebenso.
  Deshalb prüft die Regel `orig_uri.path` mit einem Ausdruck und weist Tricks gesondert ab.
- Kein „Prüfwerkzeug“ im Paket: Die Gegenprobe gegen eine echte Anwendung ist deren Share-Seite im
  Browser (Anleitung `docs/BETRIEB.md`). Für die Vorlage selbst misst `tests/test_gate_caddy.py`
  16 Tricks und Nachbarpfade sowie 5 offene Pfade.
- Der Punkt aus T-23 („Konfigurationsprüfung warnt vor Endungen“) entfällt: Die Liste steht im Proxy,
  TinySesam sieht sie nicht. Der Wächter in `tests/test_gate.py` hält die Form der Vorlagen fest.
- Mutation: 5 Eingriffe in die Vorlagen, alle rot.
