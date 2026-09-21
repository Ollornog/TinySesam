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
