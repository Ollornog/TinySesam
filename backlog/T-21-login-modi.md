---
id: T-21
type: Task
title: "Login-Modus je App: unsichtbar (Vorgabe im Gateway) oder fenster"
status: offen
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
