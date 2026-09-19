---
id: T-1
type: Task
title: End-to-End-Test gegen einen echten Identity Provider
status: erledigt
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

## Erledigt (2026-09-19)

`tests/e2e_stage.py`, gefahren gegen eine ausgerollte Instanz mit echter Domain und echtem
Zertifikat. Alle drei Wege laufen durch: Passkey (Registrierung über die eingebaute Konto-Seite,
danach passwortlose Anmeldung — virtueller Authenticator, aber echte `rp_id`), SAML gegen einen
echten IdP, OIDC gegen einen echten Provider.

Beide Hälften des Kriteriums geprüft:

| Lauf | Exit |
|---|---|
| alles richtig konfiguriert | 0 |
| falsches Passwort am IdP | **1** |
| Credential, das der Provider nicht kennt | **1** |
| ohne Konfiguration (übersprungen) | 0 — nichts geprüft ist kein Fehler |

**Der Lauf hat sofort etwas gefunden**, wofür dieser Eintrag da war: Eine abgelehnte SAML-Assertion
zeigte die *Magic-Link*-Fehlerseite und hinterliess keine Logzeile — die Ursache (`Invalid issuer`,
weil Keycloaks Entity-ID nicht die SSO-URL ist) war nur durch Patchen der Bibliothek zu finden.
Behoben; der Grund geht jetzt an `tinysesam.security`.

Was der Lauf beim Bauen über sich selbst gelernt hat, steht im CHANGELOG: auf Zustände warten statt
auf die Uhr, hinter sich aufräumen, Rate-Limit als Rate-Limit melden.

**Nicht Teil dieses Eintrags:** Die Bühne wurde von Hand aufgebaut. Sie reproduzierbar zu machen
(ein Playbook, das aus einem frischen Wegwerf-CT die Stage baut) steht als eigene Aufgabe.
