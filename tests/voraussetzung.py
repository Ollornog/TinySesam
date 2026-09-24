"""Eine Suite sagt selbst, wenn ihr eine Voraussetzung fehlt.

Liegt bewusst NEBEN `_kit/` und nicht darin: `_kit/` ist die geteilte Testbasis aus repokit und
wird von `repokit sync` überschrieben — eine eigene Datei dort wäre beim nächsten Sync weg.

Warum das nicht der Runner entscheidet: Er sähe nur einen ImportError im stderr und könnte zwei
völlig verschiedene Fälle nicht trennen — „diesem TEST fehlt ein Extra" (überspringen ist richtig)
und „die BIBLIOTHEK stürzt ohne ein Extra ab" (das ist ein Fehler). Genau daran blieb monatelang
unsichtbar, dass `pip install tinysesam` mit Vorgabe-Konfiguration gar nicht startet.

Benutzung, ganz oben in der Suite:

    from voraussetzung import braucht_modul, braucht
    braucht_modul("onelogin", extra="saml")
    braucht(shutil.which("chrome"), "kein Chrome gefunden")

Beides beendet den Prozess mit Exit 77; `run_all.py` wertet das als „übersprungen" und nennt den
Grund. Ist die Voraussetzung da, passiert nichts.
"""
import importlib.util
import os
import shutil
import sys

SKIP_EXIT = 77


def braucht(bedingung, grund):
    """Abwinken, wenn `bedingung` falsch ist — mit einem Grund, den der Runner anzeigt."""
    if not bedingung:
        print(f"uebersprungen: {grund}")
        sys.exit(SKIP_EXIT)


def braucht_modul(name, extra=None):
    """Abwinken, wenn ein Modul nicht installiert ist.

    Prüft über `find_spec` statt über einen echten Import: Ein Import könnte selbst scheitern
    (fehlende Systembibliothek, kaputte Installation), und DAS wäre ein Fehler, kein Grund zum
    Überspringen. Hier geht es nur um „ist es da".
    """
    try:
        da = importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        da = False
    hinweis = f"Modul '{name}' fehlt"
    if extra:
        hinweis += f" — pip install 'tinysesam[{extra}]'"
    braucht(da, hinweis)


def pflicht_werkzeug(name, zweck):
    """Den Pfad eines Werkzeugs, ohne das ein TEIL einer Suite nicht prüft — oder rot.

    Anders als `braucht()`: Die Suite läuft weiter, nur dieser Teil hängt am Werkzeug. Bis
    2026-09-24 stand an solchen Stellen `if shutil.which("node"):` — fehlte node, fiel die Probe
    stumm weg, und die Suite meldete grün. Genau so prüfte `ci-local` (Abbild ohne node) weniger
    als das Gate auf GitHub (`ubuntu-latest` bringt node mit), und niemand sah es: Eine Mutation
    im Panel-JS blieb lokal grün. Fehlt das Werkzeug, ist das jetzt ein Fehler.

    Wer bewusst ohne arbeitet, setzt `TINYSESAM_OHNE_<NAME>=1` (z. B. `TINYSESAM_OHNE_NODE=1`):
    Dann läuft die Suite weiter, und die Zeile sagt ausdrücklich, dass dieser Teil NICHT geprüft
    hat. Die CI setzt das nie.
    """
    pfad = shutil.which(name)
    if pfad:
        return pfad
    schalter = f"TINYSESAM_OHNE_{name.upper()}"
    if os.environ.get(schalter) == "1":
        print(f"  ⚠ {zweck}: `{name}` fehlt, per {schalter}=1 erlaubt — dieser Teil hat NICHT geprüft")
        return None
    raise AssertionError(f"`{name}` fehlt — ohne es prüft „{zweck}“ nichts und wäre stumm grün. "
                         f"Installieren, oder bewusst {schalter}=1 setzen (dann steht es als ungeprüft da).")
