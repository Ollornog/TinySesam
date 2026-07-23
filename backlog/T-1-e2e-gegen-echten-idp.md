---
id: T-1
type: Task
title: End-to-End-Test gegen einen echten Identity Provider
status: offen
milestone: M-1
tags: [testing, passkey, oidc, saml]
created: 2026-07-10
---

# T-1 — End-to-End-Test gegen einen echten IdP

**Der größte verbliebene blinde Fleck.** Passkey/WebAuthn, OIDC und SAML sind bisher nur
**struktur-getestet**: Die Ceremony gegen einen echten Browser auf einer echten HTTPS-Domain,
gegen einen echten IdP, hat nie stattgefunden. Ein Fehler dort fiele erst im Betrieb auf.

## Was fehlt

- Öffentlich erreichbare Domain mit gültigem Zertifikat (WebAuthn verlangt eine echte `rp_id`
  und HTTPS)
- Ein IdP mit registriertem Client
- Ein Passkey-fähiger Browser

## Wie

Dieselbe CDP-Suite wie `tests/test_browser.py`, aber mit `BASE_URL=https://…` gegen die deployte
Instanz — also ein **Smoke-Test nach dem Deploy**, kein CI-Test. WebAuthn lässt sich über CDP mit
`WebAuthn.enable` + `WebAuthn.addVirtualAuthenticator` fahren, ohne echten Sicherheitsschlüssel.

## Warum kein CI-Test

Die CI hat keine Domain, kein Zertifikat und keinen IdP. Ein Test, der das vortäuscht, prüft die
Attrappe — nicht die Ceremony.

**Fertig, wenn:** ein Lauf gegen eine echte Instanz alle drei Wege durchspielt und rot wird, wenn
man ihn absichtlich bricht.
