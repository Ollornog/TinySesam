# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☐ **[M-1](M-1-api-stabil-1-0.md)** 1.0 — API stabil genug für PyPI — 11/14 erledigt
* ☐ **[M-2](M-2-nach-1-0.md)** Nach 1.0 — das veröffentlichte Paket gepflegt halten — 0/2 erledigt

## Aufgaben

* ☑ **[T-1](T-1-e2e-gegen-echten-idp.md)** End-to-End-Test gegen einen echten Identity Provider · M-1
* ☑ **[T-2](T-2-freien-port-nicht-selbst-suchen.md)** Browser-Test soll den freien Port nicht selbst suchen · M-1
* ☑ **[T-3](T-3-forward-auth-header-feinsteuerung.md)** Forward-Auth — welche Remote-Header gesetzt werden, konfigurierbar machen · M-1
* ☑ **[T-4](T-4-verifikation-ohne-magic-endpoint.md)** E-Mail-Verifikation und Einladung ohne Magic-Link-Endpunkt · M-1
* ☑ **[T-5](T-5-abbild-signatur-pruefen.md)** Abbild-Signatur und SBOM erwägen · M-1
* ☑ **[T-6](T-6-stage-per-playbook.md)** Die E2E-Bühne per Playbook aufbauen statt von Hand · M-1
* ☐ **[T-7](T-7-spdx-lizenzausdruck.md)** Lizenzangabe auf den SPDX-Ausdruck umstellen (Frist: 18.02.2027) · M-2
* ☑ **[T-8](T-8-reifepruefung-restbefunde.md)** Die 35 nicht einzeln nachgestellten Befunde der Reifeprüfung abarbeiten · M-1
* ☑ **[T-9](T-9-audit-2026-09-21-runde-2.md)** Befunde des zweiten Audits (vier Blickwinkel) abarbeiten · M-1
* ☑ **[T-10](T-10-doku-abgleich-2026-09-21.md)** Doku gegen den Code gemessen — 70 Stellen, 10 echte Mängel · M-1
* ☑ **[T-11](T-11-zizmor-excessive-permissions.md)** zizmor excessive-permissions — bei Anlage bereits behoben, Eintrag bleibt als Lehre · M-1
* ◐ **[T-12](T-12-codeql-bestand.md)** CodeQL-Bestand bewerten und die offenen Alerts im Backlog führen · M-1
* ☐ **[T-13](T-13-audit-2026-09-22-runde-3.md)** Befunde des dritten Audits (Red Team, Blue Team, Online-Recherche) abarbeiten · M-1
* ☐ **[T-14](T-14-mehrere-oidc-clients.md)** Mehrere OIDC-Clients in einer Instanz — die Freigabe je App liegt beim Identity Provider · M-1
* ☐ **[T-15](T-15-unterpfad-montage.md)** Eingebaute Seiten unter einem Unterpfad montierbar machen · M-2

## Fehler

* ☑ **[B-1](B-1-admin-panel-rotiert-csrf.md)** Das Admin-Panel würfelt bei jedem Aufruf ein neues CSRF-Token · M-1

## Entscheidungen (ADR)

* ✗ **[ADR-1](ADR-1-pypi-vertagt.md)** PyPI-Veröffentlichung bis 1.0 vertagt · abgelöst durch ADR-6
* ☑ **[ADR-2](ADR-2-kein-selbst-update.md)** Kein Selbst-Update — die Version bestimmt, wer installiert
* ☑ **[ADR-3](ADR-3-in-app-statt-proxy.md)** Schutz in der App pro Route, nicht auf Proxy-Ebene
* ☑ **[ADR-4](ADR-4-keine-self-hosted-runner.md)** CI bleibt auf gehosteten Runnern — self-hosted ausgeschlossen
* ☑ **[ADR-5](ADR-5-rollen-im-forward-auth.md)** Rollen im Forward-Auth kommen vom Proxy, nicht aus einer Regeltabelle
* ☑ **[ADR-6](ADR-6-pypi-veroeffentlichen.md)** TinySesam wird ab 1.0 auf PyPI veröffentlicht
