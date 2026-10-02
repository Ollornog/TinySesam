---
id: ADR-9
type: Decision
title: Gate vor fremden Apps — der Proxy prüft ein kurzlebiges Gate-Token selbst, TinySesam nur beim Ausstellen
status: offen
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
  Asymmetrisch signiert, der Proxy kennt nur den öffentlichen Schlüssel (JWKS). TinySesam prüft beim
  **Ausstellen** alles, was heute `/auth/forward` prüft (Sitzung, Freigabe je App, Rollen) — das Token
  ist dessen zwischengespeichertes Ergebnis.
- **Cookie:** host-only auf dem App-Host, `HttpOnly`, `Secure`, `SameSite=Lax`, eigener Name.
  Der Proxy **entfernt es aus dem Request**, bevor er ihn an die App reicht.
- **Die TinySesam-Sitzung ist für die geschützte App unsichtbar.** Sie lebt host-only auf dem Host des
  Gateways, nie auf der Elterndomain — sonst bekäme jede nicht vertrauenswürdige App das Master-Cookie.
  Ausstellen deshalb als kleiner Code-Austausch: App-Host `/.sesam/refresh` → Gateway (Sitzung da? sonst
  Login) → Einmal-Code → App-Host `/.sesam/callback` → Gate-Cookie. Der Proxy leitet `/.sesam/*` an
  TinySesam.
- **307, nicht 302**, damit POST/`fetch()` mit abgelaufenem Token Methode und Body behalten.
- **Proxy-Seite:** Caddy mit dem Plugin `ggicci/caddy-jwt` (`from_cookies`, `audience_whitelist`,
  `issuer_whitelist`; laut README HS256/RS256 — EdDSA vor der Wahl prüfen). Ungültig → 401 →
  `handle_errors` → 307 auf `/.sesam/refresh`. nginx/Traefik-Gegenstücke als Beispiele, nicht Pflicht.
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
