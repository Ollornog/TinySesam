---
id: ADR-9
type: Decision
title: Gate vor fremden Apps — der Proxy prüft ein kurzlebiges Gate-Token selbst, TinySesam nur beim Ausstellen
status: erledigt
tags: [architektur, forward-auth, gateway, oidc, sso, logout]
created: 2026-10-03
---

# ADR-9 — Gate-Token am Proxy statt Unteranfrage je Request

## Kontext

Für **fremde** Anwendungen, deren Sicherheit man nicht trauen will, steht TinySesam als Gate davor
(Forward-Auth-Modus, [ADR-3](ADR-3-in-app-statt-proxy.md) Konsequenzen). Heute fragt der Proxy für
**jeden** Request `/auth/forward` — auch für jedes Skript, Stylesheet und Icon. TinySesam sucht dabei
die Sitzung im Store, prüft die Freigabe je Anwendung ([T-14](T-14-mehrere-oidc-clients.md)) und die
Rollen ([ADR-5](ADR-5-rollen-im-forward-auth.md)). Aus dem Betrieb vor einer Fremd-App (zuvor mit
einem anderen Forward-Auth-Dienst): **die Prüfung selbst** war der spürbare Preis, nicht der Netzweg.

Zweites Ärgernis: Gate und App verlangen je einen eigenen Login.

## Optionen

1. **Forward-Auth wie bisher, mit Cache in TinySesam** (Sitzungs-Hash → Ergebnis, ~30 s). Billiger,
   aber jede Anfrage bleibt ein Hop durch Python.
2. **Pfad-Ausnahmen für Assets** (`*.js`, `/static/*`). Verworfen: Endungs-Matcher sind das klassische
   Loch — App-Router liefern unter `/admin/x.css` dynamischen Inhalt.
3. **Kurzlebiges, signiertes Gate-Token, das der Proxy selbst prüft.** TinySesam wird nur gefragt,
   wenn das Token fehlt oder abgelaufen ist.

## Entscheidung

**Option 3.**

- **Gate-Token:** JWT, Laufzeit 5–10 min (einstellbar), `aud` = Host der Anwendung, `iss` = Gateway.
  Ed25519 (`EdDSA`), der Proxy kennt nur den öffentlichen Schlüssel. Abgeleitet aus dem Grundschlüssel
  der Installation (HKDF), kein zweites Geheimnis; `tinysesam gate-key` gibt den öffentlichen Teil aus. TinySesam prüft beim
  **Ausstellen** alles, was heute `/auth/forward` prüft (Sitzung, Freigabe je App, Rollen) — das Token
  ist dessen zwischengespeichertes Ergebnis.
- **Cookie:** host-only auf dem App-Host, `HttpOnly`, `Secure`, `SameSite=Lax`, eigener Name.
  Der Proxy **entfernt es aus dem Request**, bevor er ihn an die App reicht.
- **Ausstellen auf dem Rückweg, nicht über eigene Routen** (Stand 2026-10-07, mit T-19 gebaut): Fehlt
  das Token oder ist es ungültig, fällt der Proxy auf die bestehende Forward-Auth zurück
  (`handle_errors 401` → `/auth/forward`). Deren 200 trägt das neue Token im Header
  `X-TinySesam-Gate-Cookie`, und der Proxy hängt es als `Set-Cookie` an die Antwort der Anwendung.
  Die Sitzung sieht TinySesam dabei wie bisher (Cookie über `cookie_domain`, das die Vorlagen vor der
  Anwendung entfernen, B-20).
  *Bis 2026-10-07 stand hier ein eigener Code-Austausch (`/.sesam/refresh` → Einmal-Code →
  `/.sesam/callback`) mit 307-Umleitungen.* Er hätte die Sitzung nur auf dem Gateway-Host gehalten,
  aber eine zweite Anmelde-Strecke neben der bestehenden gebraucht, und ein POST mit abgelaufenem Token
  wäre über mehrere Sprünge doch zum GET geworden. Der Rückweg über `/auth/forward` reicht die Anfrage
  samt Methode und Body an die Anwendung weiter — gemessen mit Caddy 2.11.7 (`tests/test_gate_caddy.py`).
  Die Frage, ob das Sitzungs-Cookie auf der Elterndomain liegen darf, ist damit nicht neu, sondern die
  der bestehenden Forward-Auth.
- **Proxy-Seite:** Caddy mit dem Plugin `ggicci/caddy-jwt` (v1.4.0), `sign_alg EdDSA` mit dem
  öffentlichen Schlüssel als Base64 — dann ignoriert das Plugin das `alg` im Kopf (im Quelltext
  nachgesehen). Vorlage `deploy/forward-auth/Caddyfile.gate`. nginx/Traefik-Gegenstücke gibt es
  noch nicht.
- **Login einmal, beim Provider:** Gate und App sind je ein eigener OIDC-Client beim selben Provider,
  beide auf dieselbe Gruppe beschränkt. Kein geteilter Client: dessen Geheimnis läge sonst in der
  fremden App. Die App meldet sich danach lautlos an (Provider-Sitzung besteht).
- **Login-Modus je App:** `unsichtbar` (**Vorgabe im Gateway**, PO 2026-10-03) leitet direkt zum
  Provider und zurück zur Startadresse; `fenster` zeigt „In *App X* anmelden“.
- **Logout-Modus je App:** `app` · `alle` · `fragen` ([T-22](T-22-logout-modi.md)).
- **Share-Pfade:** exakte Präfixe je App, vor dem Gate, nie nach Dateiendung ([T-20](T-20-share-ausnahmen.md)).

## Konsequenzen

- **Widerruf verzögert:** Sperre oder Logout greifen am Proxy erst mit Ablauf des Tokens. Der eigene
  Logout-Weg (`/.sesam/logout`) löscht das Cookie sofort; andere Apps folgen nach ≤ einer Laufzeit.
- **Abhängigkeit vom Proxy-Plugin.** Wer kein Plugin bauen kann, bleibt bei `/auth/forward` (bleibt
  unverändert bestehen).
- **Header-Auth** (`Remote-User` aus den Claims) wird möglich, aber nur für Apps, die das als Modus
  anbieten; der Proxy entfernt einen mitgeschickten `Remote-User` **immer**, auch auf Share-Pfaden.
- Die Share-Ausnahme bleibt echte Angriffsfläche der fremden App — unvermeidlich, deshalb eng.
- Provider-Befund (PocketID v2.17.0, Code `backend/internal/oidc/end_session_*.go`): RP-initiierter
  Logout mit `id_token_hint`, Ziel aus den je Client hinterlegten **Logout Callback URLs**, `state` wird
  angehängt; der Provider beendet dabei **seine eigene Sitzung**; kein Back-/Front-Channel-Logout.
