# Backlog

<!-- GENERIERT von scripts/_backlog.py — nicht von Hand pflegen. Neu bauen: `python3 scripts/_backlog.py index` -->

Die Wahrheit sind die Einzeldateien in diesem Verzeichnis; diese Seite ist ihr Abzug.
Konventionen: [README-KONVENTION.md](README-KONVENTION.md).

## Meilensteine

* ☐ **[M-1](M-1-api-stabil-1-0.md)** 1.0 — API stabil genug für PyPI — 0/5 erledigt

## Aufgaben

* ☐ **[T-1](T-1-e2e-gegen-echten-idp.md)** End-to-End-Test gegen einen echten Identity Provider · M-1
* ☐ **[T-2](T-2-freien-port-nicht-selbst-suchen.md)** Browser-Test soll den freien Port nicht selbst suchen · M-1
* ☐ **[T-3](T-3-forward-auth-header-feinsteuerung.md)** Forward-Auth — welche Remote-Header gesetzt werden, konfigurierbar machen · M-1
* ☐ **[T-4](T-4-verifikation-ohne-magic-endpoint.md)** E-Mail-Verifikation und Einladung ohne Magic-Link-Endpunkt · M-1
* ☐ **[T-5](T-5-abbild-signatur-pruefen.md)** Abbild-Signatur und SBOM erwägen · M-1

## Entscheidungen (ADR)

* ☑ **[ADR-1](ADR-1-pypi-vertagt.md)** PyPI-Veröffentlichung bis 1.0 vertagt
* ☑ **[ADR-2](ADR-2-kein-selbst-update.md)** Kein Selbst-Update — die Version bestimmt, wer installiert
* ☑ **[ADR-3](ADR-3-in-app-statt-proxy.md)** Schutz in der App pro Route, nicht auf Proxy-Ebene
* ☑ **[ADR-4](ADR-4-keine-self-hosted-runner.md)** CI bleibt auf gehosteten Runnern — self-hosted ausgeschlossen
