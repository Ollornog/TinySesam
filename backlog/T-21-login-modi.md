---
id: T-21
type: Task
title: "Login-Modus je App: unsichtbar (Vorgabe im Gateway) oder fenster"
status: erledigt
milestone: M-3
tags: [gateway, oidc, login]
created: 2026-10-03
---

# T-21 — Login-Modi

Heute schickt das Gate bei 401 immer auf die TinySesam-Login-Seite, dort steht der OIDC-Knopf
(`/auth/oidc/start?next=…`). Das ist der Modus `fenster` ohne App-Bezug.

**Zu tun:**
- `unsichtbar`: die Login-URL des Gates zeigt direkt auf `/auth/oidc/start?next=<Startadresse>` (bzw. den
  Client der App, T-14). **Vorgabe im Gateway-Preset** (PO 2026-10-03); in der Bibliothek bleibt die
  Vorgabe die Login-Seite. Nur zulässig, wenn OIDC die einzige Methode ist.
- `fenster`: Login-Seite mit Name und Icon der App („In *App X* anmelden“), Aussehen über das Theme.
- Je App einstellbar (`oidc_clients`-Eintrag / Gateway-Variable).
- Fehlerfall beim Provider (Absage, Gruppe fehlt) darf nicht in eine Umleitungsschleife laufen:
  sichtbare Fehlerseite.

**Fertig, wenn:** Browser-Test beider Modi, Schleifentest bei Absage, Doku EN/DE, Mutation.

## Erledigt 2026-10-07

Die Werte heissen englisch (Regel der Stufen A/B): `forward_login = "page" | "direct"`, je Host in
`forward_apps` (`name`, `login`) statt im Eintrag von `oidc_clients` — die Einstellung gilt auch für
eine Installation mit nur einem Client.

- `direct` nur für **Seitenaufrufe** (`Sec-Fetch-Mode: navigate`, sonst `Accept: text/html`); jede
  andere Anfrage geht zur Login-Seite. Ohne das hätte jede XHR einer abgelaufenen Sitzung einen
  eigenen OIDC-Flow begonnen (Datenbankzeile, Rate-Limit von `/auth/oidc/start`).
- `direct` nur mit OIDC als einziger Methode — beim Start geprüft und zur Laufzeit noch einmal.
- Absage des Providers: Der Callback antwortet mit einer Fehlerseite, nicht mit einer Umleitung —
  keine Schleife.
- **Icon** der Anwendung auf der Login-Seite: nicht gebaut. Es bräuchte eine Bilddatei, die TinySesam
  selbst ausliefert (keine fremde Quelle) — offen als Wunsch, kein Task.
- Beim Bau gefunden und behoben: [B-2](B-2-schleife-ohne-app-freigabe.md).
- Test: `tests/test_login_modi.py`, 9 Mutationen rot.
