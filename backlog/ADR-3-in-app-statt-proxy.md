---
id: ADR-3
type: Decision
title: Schutz in der App pro Route, nicht auf Proxy-Ebene
status: erledigt
tags: [architektur, auth, forward-auth]
created: 2026-07-06
---

# ADR-3 — Schutz in der App, nicht auf Proxy-Ebene

## Kontext

Zwei verbreitete Muster: Forward-Auth am Reverse-Proxy (wie Authelia, oauth2-proxy) oder eine
Abhängigkeit an der einzelnen Route in der Anwendung.

## Entscheidung

**In der App, pro Route** (Dependency an der Route oder an einem Sub-Router). Der Webserver
terminiert nur TLS und reicht alle Pfade durch.

## Begründung

Für **eigene** Anwendungen ist das die richtige Naht: Öffentliche Vorschauen bleiben offen,
während einzelne Bereiche eine Anmeldung verlangen — beides im selben Deployment, ohne dass ein
Proxy die Pfadmuster nachbauen muss. Eine Proxy-Lösung hinkt bei jeder neuen Route hinterher.

## Konsequenzen

- Für **fremde** Anwendungen, die man nicht anfassen kann, gibt es zusätzlich den Forward-Auth-Modus
  (`/auth/forward`, `/auth/verify`, Gateway-Preset). Das ist ein **eigener Betriebsmodus**, kein
  Ersatz für das Grundmodell.
- OIDC-`state`/`nonce` und die WebAuthn-Challenge liegen serverseitig im Store, nicht im Client.
