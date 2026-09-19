---
id: T-3
type: Task
title: Forward-Auth — welche Remote-Header gesetzt werden, konfigurierbar machen
status: erledigt
milestone: M-1
tags: [forward-auth, konfiguration]
created: 2026-07-10
---

# T-3 — Feinsteuerung der `Remote-*`-Header

Im Forward-Auth-Modus ([ADR-3](ADR-3-in-app-statt-proxy.md)) setzt `/auth/verify` einen festen
Satz `Remote-*`-Header. Nicht jede nachgelagerte Anwendung will alle davon, und manche erwarten
andere Namen.

**Fertig, wenn:** die Auswahl über die Konfiguration steuerbar ist und der Standard unverändert
bleibt (keine stille Verhaltensänderung für Bestandsnutzer).

## Erledigt (2026-09-19)

`config.forward_headers` bildet **Feld → Headername** ab (`user` · `name` · `email` · `groups`);
ein Feld darf auf mehrere Namen zeigen. Leer bleibt der Authelia-Satz `Remote-*`, also ändert sich
für Bestandsnutzer nichts.

Die Zuordnung ist die **vollständige** Liste und keine Ergänzung: `{"user": "X-WEBAUTH-USER"}`
verschickt genau diesen einen Header. Damit deckt ein Feld beide Hälften der Aufgabe ab — Umbenennen
*und* Weglassen —, statt einen zweiten Schalter für „welche will ich überhaupt" zu brauchen. Wer der
App die E-Mail-Adresse nicht geben will, lässt `email` weg.

Geprüft wird beim Start, nicht zur Laufzeit: ein unbekanntes Feld (`"mail"` statt `"email"`) liesse
den Header sonst still weg, und ein Name mit Zeilenumbruch wäre Header-Injection. Beides wirft jetzt
`ValueError`. Gebaut wird der Satz in `auth.forward_response_headers(user)` — dieselbe Naht für
eigene Anpassungen.
