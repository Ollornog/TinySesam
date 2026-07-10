# TinySesam als OIDC-Forward-Auth-Gateway.
#
#   docker build -t tinysesam-gateway .
#   docker run --rm -p 8000:8000 -e TINYSESAM_OIDC_ISSUER=… tinysesam-gateway
#
# Fertige Abbilder: ghcr.io/ollornog/tinysesam:<version>  (siehe .github/workflows/release.yml)
#
# Nur das `[oidc]`-Extra. `[all]` zöge `python3-saml` und damit die C-Bibliothek `libxmlsec1`
# nach — die müsste für arm64 unter Emulation kompiliert werden, für ein Extra, das das
# Gateway gar nicht benutzt. Wer SAML will, baut sich TinySesam als Bibliothek in eine App.

# ---------- Bauen ----------
FROM python:3.12-slim AS build

# Aus dem Build-Kontext installieren, NICHT aus dem Netz: das Abbild soll genau den Stand
# enthalten, der hier daneben liegt — nicht das, was `main` gerade zufällig ist.
WORKDIR /src
COPY pyproject.toml README.md ./
COPY tinysesam ./tinysesam

RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip \
    && /opt/venv/bin/pip install --no-cache-dir ".[oidc]" "uvicorn>=0.30"

# ---------- Laufen ----------
FROM python:3.12-slim

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
# Prozess von innen über HTTP an. Redirects werden bewusst NICHT verfolgt.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,urllib.request,sys;\
u=f\"http://127.0.0.1:{os.environ.get('TINYSESAM_PORT','8000')}/healthz\";\
sys.exit(0 if urllib.request.urlopen(u,timeout=4).status==200 else 1)"]

ENTRYPOINT ["python", "-m", "tinysesam.gateway"]
