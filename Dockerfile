# TinySesam als OIDC-Forward-Auth-Gateway.
#
#   docker build -t tinysesam-gateway .
#   docker run --rm -p 8000:8000 -e TINYSESAM_OIDC_ISSUER=… tinysesam-gateway
#
# Fertige Abbilder: ghcr.io/ollornog/tinysesam:<version>  (siehe .github/workflows/release.yml)
#
# Nur das `[gateway]`-Extra (= `[oidc]` plus ASGI-Server). `[all]` zöge `python3-saml` und damit
# die C-Bibliothek `libxmlsec1` nach — die müsste für arm64 unter Emulation kompiliert werden,
# für ein Extra, das das Gateway gar nicht benutzt. Wer SAML will, baut sich TinySesam als
# Bibliothek in eine App.
#
# Bis 0.18.0 stand hier `.[oidc]` plus ein von Hand angehängtes `uvicorn>=0.30`. Dieser Flicken
# war der Grund, warum das Abbild lief und ein `pip install 'tinysesam[oidc]'` nach Anleitung
# nicht: Der Server fehlte im Extra, nicht im Abbild.

# ---------- Bauen ----------
# Per DIGEST gepinnt, nicht per Tag: `python:3.12-slim` zeigt heute hierhin und morgen
# woanders — zwei Bauläufe desselben Commits ergäben verschiedene Abbilder. Anheben:
#   docker manifest inspect python:3.12-slim   (bzw. Dependabot, s. dependabot.yml)
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9 AS build

# Aus dem Build-Kontext installieren, NICHT aus dem Netz: das Abbild soll genau den Stand
# enthalten, der hier daneben liegt — nicht das, was `main` gerade zufällig ist.
WORKDIR /src
COPY pyproject.toml README.md ./
COPY tinysesam ./tinysesam

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir ".[gateway]"

# ---------- Laufen ----------
FROM python:3.12-slim@sha256:2f17fc044b579bab302c2e8054d3a686e2cb9a83de48e70534b94cd8ebbe06a9

RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tinysesam \
    && mkdir -p /data && chown tinysesam:tinysesam /data

COPY --from=build /opt/venv /opt/venv

# Kein git, kein pip im Endabbild: wer hier Code nachladen kann, hat gewonnen. Genau deshalb
# hat TinySesam auch kein Selbst-Update mehr (siehe CHANGELOG 0.12.0).
# Das venv bringt ein EIGENES pip mit — das System-pip zu löschen genügt nicht. Ein Test hat
# das gefunden, nachdem das Abbild bereits „ohne pip" hieß.
RUN rm -rf /usr/local/lib/python3.12/site-packages/pip \
           /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12 \
           /opt/venv/lib/python3.12/site-packages/pip \
           /opt/venv/lib/python3.12/site-packages/pip-*.dist-info

ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    TINYSESAM_DB=/data/gateway.db \
    TINYSESAM_HOST=0.0.0.0 \
    TINYSESAM_PORT=8000

USER tinysesam
WORKDIR /data
VOLUME ["/data"]
EXPOSE 8000

# `/healthz` ist der einzige Pfad ohne Anmeldung und ohne HTTPS-Zwang — der Check spricht den
# Prozess von innen über HTTP an.
#
# Redirects werden NICHT verfolgt — deshalb `http.client` und nicht `urllib.request.urlopen`.
# Letzteres bringt den HTTPRedirectHandler im Standard-Opener mit, folgt einer 302 und meldet
# danach den Status des UMLEITUNGSZIELS. Eine Umleitung auf /healthz — genau der Fall, den
# `_install_https_except_health` abwehrt — ginge damit als "healthy" durch. Bis 2026-09-21
# behauptete der Kommentar hier das Gegenteil dessen, was der Code tat. (Ein eigener Opener
# reicht dafür nicht: `build_opener` lässt Default-Handler nur weg, wenn eine SUBKLASSE genau
# dieses Handlers übergeben wird — ein mitgegebener HTTPHandler ersetzt den Redirect-Handler
# nicht.) `http.client` leitet von sich aus nie um.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,http.client,sys;\
c=http.client.HTTPConnection('127.0.0.1',int(os.environ.get('TINYSESAM_PORT','8000')),timeout=4);\
c.request('GET','/healthz');\
sys.exit(0 if c.getresponse().status==200 else 1)"]

ENTRYPOINT ["python", "-m", "tinysesam.gateway"]
