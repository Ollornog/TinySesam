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
# Per DIGEST gepinnt, nicht per Tag: `python:3.14-slim` zeigt heute hierhin und morgen
# woanders — zwei Bauläufe desselben Commits ergäben verschiedene Abbilder. Anheben:
#   docker manifest inspect python:3.14-slim   (bzw. Dependabot, s. dependabot.yml)
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2 AS build

# Aus dem Build-Kontext installieren, NICHT aus dem Netz: das Abbild soll genau den Stand
# enthalten, der hier daneben liegt — nicht das, was `main` gerade zufällig ist.
WORKDIR /src
COPY pyproject.toml README.md ./
COPY deploy/gateway/requirements.txt ./requirements.txt
COPY tinysesam ./tinysesam

# Der Digest oben hält nur das Basis-Abbild fest — die andere Hälfte der Frage ist, was pip
# hineinlegt. Deshalb zwei Schritte statt eines `pip install ".[gateway]"`:
#   1. die Abhängigkeiten aus der gehashten Sperrliste, nichts sonst (`--require-hashes`); dort
#      steht auch setuptools, das Bau-Backend für Schritt 2;
#   2. TinySesam selbst ohne Netz (`--no-index`), ohne Bau-Isolierung (die holte sich setuptools
#      sonst ungeprüft aus dem Index) und ohne Abhängigkeitsauflösung.
# Kein `pip install --upgrade pip` mehr: Das zog bei jedem Bau die gerade neueste Fassung. Das pip
# des Basis-Abbilds ist durch den Digest festgelegt und wird am Ende ohnehin entfernt.
# `SOURCE_DATE_EPOCH` (setzt der Release-Workflow) macht die .pyc-Dateien zeitstempelfrei.
#
# `--no-deps` heisst auch: Fehlt in der Sperrliste eine transitive Abhängigkeit, installiert pip
# trotzdem ohne Murren. Dependabot hebt in einer gehashten Liste nur einzelne Zeilen und trägt
# keine neue Abhängigkeit nach — ein Bump, der eine mitbringt, ergäbe ein Abbild, das erst beim
# Start mit ModuleNotFoundError abbricht. `pip check` und der Import fangen das beim BAU ab;
# audit.yml fährt dieselben Schritte bei jedem PR, damit es gar nicht erst bis zum Release kommt.
ARG SOURCE_DATE_EPOCH
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-hashes --no-deps -r requirements.txt \
    && /opt/venv/bin/pip install --no-cache-dir --no-deps --no-index --no-build-isolation . \
    && /opt/venv/bin/pip check \
    && /opt/venv/bin/python -c "import tinysesam.gateway" \
    && /opt/venv/bin/pip uninstall --yes setuptools

# ---------- Laufen ----------
FROM python:3.14-slim@sha256:caaf356f40667c496d405780745b9ac25771c189a51dfcc42430d531ea09f8a2

# `useradd` schreibt das Datum der letzten Passwortänderung nach /etc/shadow — ohne diese Zeile
# den Tag des Baus, mit ihr den Tag des Commits (shadow ab 4.14 liest SOURCE_DATE_EPOCH).
ARG SOURCE_DATE_EPOCH
RUN useradd --uid 1000 --create-home --shell /usr/sbin/nologin tinysesam \
    && mkdir -p /data && chown tinysesam:tinysesam /data

COPY --from=build /opt/venv /opt/venv

# Kein git, kein pip im Endabbild: wer hier Code nachladen kann, hat gewonnen. Genau deshalb
# hat TinySesam auch kein Selbst-Update mehr (siehe CHANGELOG 0.12.0).
# Das venv bringt ein EIGENES pip mit — das System-pip zu löschen genügt nicht. Ein Test hat
# das gefunden, nachdem das Abbild bereits „ohne pip" hieß.
# Die Pfade per Muster statt mit fester Python-Reihe: Bis 2026-09-23 stand hier `python3.12` —
# nach dem Sprung auf 3.14 (#74) griff davon nichts mehr, pip lag wieder im venv.
RUN rm -rf /usr/local/lib/python3.*/site-packages/pip \
           /usr/local/lib/python3.*/site-packages/pip-*.dist-info \
           /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.* \
           /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.* \
           /opt/venv/lib/python3.*/site-packages/pip \
           /opt/venv/lib/python3.*/site-packages/pip-*.dist-info

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
#
# Die Fristen liegen über `Store.BUSY_TIMEOUT_MS` (10 s): `/healthz` schreibt (B6-4) und wartet
# dabei wie jede Anmeldung hinter einem fremden Schreiber (Checkpoint, Sicherung, zweiter Worker).
# Mit 4 s brach der Check ab, während Anmeldungen nur warteten und dann gelangen; erst was länger
# als 10 s sperrt, ist ein Ausfall — und dann antwortet der Dienst selbst mit 503.
HEALTHCHECK --interval=30s --timeout=15s --start-period=10s --retries=3 \
    CMD ["python", "-c", "import os,http.client,sys;\
c=http.client.HTTPConnection('127.0.0.1',int(os.environ.get('TINYSESAM_PORT','8000')),timeout=12);\
c.request('GET','/healthz');\
sys.exit(0 if c.getresponse().status==200 else 1)"]

ENTRYPOINT ["python", "-m", "tinysesam.gateway"]
