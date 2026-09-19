---
id: ADR-5
type: Decision
title: Rollen im Forward-Auth kommen vom Proxy, nicht aus einer Regeltabelle
status: erledigt
tags: [architektur, forward-auth, rollen]
created: 2026-09-19
---

# ADR-5 — Rollen im Forward-Auth kommen vom Proxy

## Kontext

`/auth/forward` war binär: angemeldet oder nicht. Rollen reiste es nur als `Remote-Groups`-Header
mit, und damit kann ein Reverse-Proxy nichts anfangen — nginx wegen der Phasenreihenfolge nicht,
Caddy und Traefik stehen vor demselben Problem. Faktisch existierte `require_role` damit nur im
In-App-Modus ([ADR-3](ADR-3-in-app-statt-proxy.md)), während das README Forward-Auth vor fremde
Anwendungen verspricht. Aus der Praxis gemeldet (Fremd-Deployment, 2026-09).

## Optionen

1. **Regeltabelle in der Konfiguration** (Authelia-Modell): Pfadmuster → Rollen, ausgewertet gegen
   das ohnehin übertragene `X-Original-URL`. Zentral sichtbar, im Panel editierbar.
2. **Der Proxy sagt, was er verlangt**: `?roles=a,b` am Sub-Request bzw. Header
   `X-TinySesam-Roles`.

## Entscheidung

**Option 2.** Die Angabe steht dort, wo der Proxy die Route ohnehin konfiguriert.

## Begründung

Option 1 macht TinySesam von der Pfadstruktur fremder Anwendungen abhängig: es müsste Muster
kennen, sortieren und gegen die URL abgleichen — genau die Doppelpflege, wegen der ADR-3 den
In-App-Schutz zum Grundmodell gemacht hat, nur andersherum. Option 2 hält die Bibliothek
zustandslos gegenüber fremden Pfaden und ändert nichts für Bestandsnutzer: ohne Angabe bleibt
`/auth/forward` binär wie zuvor.

## Konsequenzen

- Mehrere Angaben werden **UND**-verknüpft, Kommas innerhalb einer Angabe ODER. Damit ist die
  Auswertung fail-closed: Hängt ein Client selbst ein `roles=` oder den Header an, kann er die
  Prüfung nur verschärfen, nie aufweichen.
- Fehlt die Rolle, antwortet TinySesam **403, nicht 401**. Ein 401 schickte den bereits
  Angemeldeten zum Login, der ihn mit derselben fehlenden Rolle zurückschickt — eine Schleife.
- Die Abweisung geht ins Audit-Log (`forward_role_denied`): Eine 403 im Proxy-Log sagt nicht, wer
  woran gescheitert ist.
- `admin_implies_roles` gilt wie bei `require_role` — ein Admin erfüllt die Rolle mit, sofern
  nicht global abgeschaltet.
