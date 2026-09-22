---
id: ADR-7
type: Decision
title: TOTP-Geheimnisse und PINs kommen nie aus dem Identitätsanbieter
status: erledigt
tags: [architektur, oidc, mfa, pocketid]
created: 2026-09-22
---

# ADR-7 — TOTP-Geheimnisse und PINs kommen nie aus dem Identitätsanbieter

## Kontext

Beim Symbiose-Audit mit PocketID (2026-09-22) kam die Frage auf, ob sich der zweite Faktor
zentral im Identitätsanbieter (IdP) pflegen lässt: PocketID kann jedem Benutzer beliebige
**Custom Claims** mitgeben, und diese Claims stehen im ID-Token. Ein `totp_secret` oder eine
`tinysesam_pin` dort einzutragen, wäre auf den ersten Blick bequem — eine Stelle für alle Dienste,
kein zweites Enrollment, und ein Wechsel des Authenticators wäre eine Änderung im IdP-Panel.

Die Frage ist berechtigt, weil TinySesam in dieser Installation hinter PocketID steht und die
Benutzerverwaltung dort liegt. Sie ist trotzdem mit Nein zu beantworten, und zwar aus einem Grund,
der nichts mit PocketID zu tun hat.

## Optionen

1. **Custom Claim im ID-Token.** Der IdP trägt das TOTP-Geheimnis (bzw. die PIN) als Claim ein,
   TinySesam liest es beim Login und prüft den eingegebenen Code dagegen.
2. **Abruf über die IdP-API.** TinySesam holt das Geheimnis bei Bedarf über eine API des IdP,
   statt es im Token zu transportieren.
3. **Faktoren bleiben lokal.** TinySesam verwaltet TOTP und PIN selbst; der IdP liefert
   Identität, Gruppen und Freigabe — nicht Geheimnisse.

## Entscheidung

**Option 3.** TOTP-Geheimnisse und PINs bleiben in TinySesams eigener Datenbank.

## Begründung

**Ein Claim geht an jeden Client, nicht an einen.** Custom Claims hängen in PocketID am Benutzer,
nicht am OIDC-Client. Ein Geheimnis dort steht damit im ID-Token **jeder** Anwendung, bei der sich
dieser Benutzer anmeldet — in dieser Installation sind das dreizehn. Der zweite Faktor wäre nach
einem einzigen Login bei irgendeiner davon bekannt. Was als „eine Stelle für alle" gedacht war,
ist „ein Leck bei jedem".

**Ein zweiter Faktor, den der erste mitliefert, ist keiner.** Das ID-Token ist das Ergebnis des
ersten Faktors. Käme das TOTP-Geheimnis darin mit, hätte wer auch immer diesen Anmeldevorgang
abschließt, damit sofort auch den zweiten. Zwei Faktoren müssen aus zwei Quellen stammen, sonst
sind sie einer mit zwei Eingabefeldern.

**Auch Option 2 löst das nicht.** Ein Abruf über die API verkleinert den Empfängerkreis, aber das
Geheimnis liegt dann in zwei Systemen statt in einem, und die Frage „wem gehört der Faktor" ist
weiter unbeantwortet. Ein TOTP-Geheimnis ist ein *Verifikationsgeheimnis*: Es gehört dorthin, wo
geprüft wird, und nirgendwo sonst. Dieselbe Überlegung schließt aus, es im IdP zu spiegeln.

**Die Arbeitsteilung bleibt sauber.** Der IdP beantwortet: Wer ist das, in welchen Gruppen ist er,
darf er diesen Client benutzen. TinySesam beantwortet: Reicht mir das für diese Route, und welchen
zusätzlichen Beleg verlange ich. Das ist die Trennung, die auch ADR-5 (Rollen im Forward-Auth) und
ADR-3 (In-App statt Proxy) tragen.

## Folgen

- Wer TOTP oder PIN nutzt, richtet sie **in TinySesam** ein. Ein zweites Enrollment ist der Preis,
  und er ist der richtige.
- Aus dem IdP kommen weiter: Identität (`sub`), E-Mail mit `email_verified`, Gruppen, und über die
  Client-Freigabe die Antwort, ob dieser Benutzer diese Anwendung überhaupt benutzen darf
  (→ [T-14](T-14-mehrere-oidc-clients.md)).
- **Nicht betroffen** ist die Frage, ob TinySesam einem im IdP durchgeführten MFA vertraut: Das ist
  eine andere Entscheidung (`amr`/`acr` im Token auswerten) und steht hier nicht zur Debatte.
- Diese ADR beantwortet nur die Herkunft der **Geheimnisse**. Dass ein im IdP gesperrter oder
  gelöschter Benutzer in TinySesam zeitnah nachvollzogen werden muss, ist ein eigener Punkt
  (Widerrufslücke, siehe T-13 und die Symbiose-Untersuchung).
