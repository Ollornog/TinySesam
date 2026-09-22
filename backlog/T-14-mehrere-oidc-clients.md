---
id: T-14
type: Task
title: Mehrere OIDC-Clients in einer Instanz — die Freigabe je App liegt beim Identity Provider
status: offen
milestone: M-1
tags: [oidc, forward-auth, gateway, autorisierung, pocketid]
created: 2026-09-21
---

# T-14 — Mehrere OIDC-Clients in einer Instanz

**Anforderung des Betreibers (2026-09-21, Pflicht):** Eine TinySesam-Installation schützt mehrere
Anwendungen (Hosts). Wer in welche Anwendung darf, wird **im Identity Provider** entschieden — bei
PocketID über die Gruppenfreigabe je OIDC-Client —, nicht in TinySesam und nicht im Proxy. Da diese
Freigabe beim IdP **pro Client** gilt, braucht jede geschützte Anwendung ihren eigenen Client.

TinySesam kennt heute genau ein `oidc_client_id`/`oidc_client_secret`. Die einzige Lösung war
bisher eine Gateway-Instanz je Anwendung — drei Container, drei Datenbanken, drei Audit-Logs,
drei Admin-Panels für dieselben Nutzer. Das ist die Aufgabe, die dieser Eintrag abschafft.

## Was zu tun ist

- [ ] **`oidc_clients`**: Zuordnung geschützter Host → Client (`client_id`, `client_secret`,
      optional `scopes`, `allowed_groups`, `group_role_map`). Der bisherige Einzel-Client bleibt
      als Vorgabe („alle Hosts") — bestehende Konfigurationen laufen unverändert.
- [ ] **Eine Callback-URL für alle Clients** (`base_url` + `oidc_callback_path`): Welcher Client
      gemeint ist, steht im Flow im Store, nicht in der URL. Beim IdP zeigen alle Clients auf
      dieselbe Adresse.
- [ ] **Die Sitzung merkt sich die Freigaben**: je Client, für den der IdP den Nutzer angemeldet
      hat, ein Eintrag mit Zeitstempel. Rollen aus `group_role_map` werden je Client geführt,
      nicht global.
- [ ] **`/auth/forward` für einen Host ohne Freigabe** startet die OIDC-Runde mit dem Client
      dieses Hosts (Ziel-Host aus `X-Forwarded-Host`, nur aus `trusted_redirect_hosts`/
      `protected_hosts`). Der IdP hat seine Sitzung noch, prüft nur die Freigabe — eine
      Weiterleitung, kein neuer Passkey. Lehnt der IdP ab, zeigt er seine Absage; TinySesam
      hinterlässt eine Audit-Zeile mit Client und Grund.
- [ ] **Widerruf folgt dem IdP** (Anforderung aus demselben Gespräch, siehe den PocketID-Bericht
      des dritten Audits): Die Freigabe je Client verfällt nach `oidc_revalidate_minutes`; die
      nächste Anfrage prüft über Refresh-Token oder Introspection beim IdP nach — verweigert er,
      ist die Freigabe für diesen Client weg, die Sitzung für die anderen bleibt. So wird auch
      der Gruppenentzug im IdP binnen Minuten wirksam, und eine Löschung dort trifft alle Clients.
- [ ] **Gateway-Umgebungsvariablen**: `TINYSESAM_OIDC_CLIENTS` als JSON oder je Host
      `TINYSESAM_OIDC_CLIENT_<HOST>_ID/_SECRET`; `deploy/forward-auth/` bekommt ein Beispiel mit
      zwei Hosts und zwei Clients.
- [ ] **Konfigprüfung**: Host ohne Client, Client ohne Secret, Host nicht in `protected_hosts`,
      Vorgabe-Client fehlt bei Hosts ohne Eintrag — alles beim Aufbau melden.
- [ ] **Tests**: zwei Hosts, zwei Clients gegen die OIDC-Attrappe aus `tests/test_oidc_jwks.py`;
      Freigabe für A gilt nicht für B; Absage des IdP für B lässt A unberührt; Widerruf je Client;
      Bestandskonfiguration mit Einzel-Client verhält sich exakt wie vorher (`test_api_surface`).
- [ ] **Doku**: README-Abschnitt „Mehrere Anwendungen, ein TinySesam" in beiden Sprachen,
      `KONFIGURATION.md` (generiert), CHANGELOG.

**Fertig, wenn:** eine Instanz drei Hosts mit drei IdP-Clients schützt, die Freigabe je Host
ausschliesslich vom IdP kommt, ein Gruppenentzug dort innerhalb der eingestellten Frist wirkt, und
eine Konfiguration mit nur einem Client sich um kein Byte anders verhält als in 0.18.0.

## Warum vor 1.0

`oidc_clients` ändert die Form der OIDC-Konfiguration. Das ist nach dem Einfrieren der API
([M-1](M-1-api-stabil-1-0.md)) teurer als davor. Der Einzel-Client bleibt als Sonderfall der
Zuordnung erhalten, damit der Übergang kein Bruch ist.
