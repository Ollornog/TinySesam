"""`Typing :: Typed` ist eine Zusage — hier wird sie gemessen.

Das Paket trägt den Classifier und eine `py.typed`. Damit sagt es jedem Nutzer zu: Die
Annotationen stimmen, dein Typprüfer darf sich darauf verlassen. Geprüft hat das nie jemand —
und bei der ersten Messung standen **30 Fehler** in 6 Dateien, darunter sechs nutzerseitige
Methoden, die `Optional[dict]` versprachen und eine `sqlite3.Row` lieferten. Wer der Zusage
glaubte und `user.get("email")` schrieb, bekam einen `AttributeError` aus einer Zeile, die laut
Typ nicht falsch sein konnte.

Diese Suite ist das Gegenmittel. Zusätzlich misst sie die Zusage dort, wo sie ankommt: am
tatsächlichen Rückgabewert — eine Annotation kann stimmen und die Umsetzung trotzdem nicht.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from voraussetzung import braucht_modul  # noqa: E402

braucht_modul("mypy")

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from _kit.report import Report  # noqa: E402

r = Report("Typen — die Zusage `Typing :: Typed`")

# ---------- 1) Der Typprüfer selbst ----------
lauf = subprocess.run([sys.executable, "-m", "mypy", "tinysesam/", "--ignore-missing-imports"],
                      cwd=ROOT, capture_output=True, text=True)
fehler = [z for z in lauf.stdout.splitlines() if ": error:" in z]
r.check("mypy findet keinen Fehler in tinysesam/", not fehler,
        "\n        " + "\n        ".join(fehler[:6]) +
        (f"\n        … und {len(fehler) - 6} weitere" if len(fehler) > 6 else ""))

# Und die Prüfung muss überhaupt etwas gesehen haben — ein Lauf über null Dateien wäre
# immer grün und würde nichts aussagen.
r.check("und hat dabei die ganze Bibliothek gesehen",
        "source file" in lauf.stdout and " 0 source files" not in lauf.stdout,
        f"Ausgabe: {lauf.stdout.strip()[:120]!r}")

# ---------- 2) Die Zusage dort, wo sie ankommt ----------
# `py.typed` muss mitgeliefert werden, sonst ignoriert jeder Typprüfer die Annotationen.
r.check("py.typed liegt im Paket", (ROOT / "tinysesam" / "py.typed").exists(),
        "ohne diese Datei wertet kein Typprüfer die Annotationen aus (PEP 561)")

auth = TinySesam(TinySesamConfig(db_path=str(Path(tempfile.mkdtemp()) / "t.db"),
                                 cookie_secure=False))
uid = auth.create_user("wer", password="geheim12345", email="wer@example.com")

# Die sechs Methoden, die `Optional[dict]` versprechen — gemessen am echten Rückgabewert.
for name, wert in (("get_user", auth.get_user(uid)),
                   ("find_user", auth.find_user("wer")),
                   ("check_password", auth.check_password("wer", "geheim12345")),
                   ("current_user", None),
                   ("redeem_magic (leer)", auth.redeem_magic("gibtsnicht")),
                   ("find_user (leer)", auth.find_user("niemand"))):
    if name == "current_user":
        continue
    erwartet_leer = "leer" in name
    if erwartet_leer:
        r.check(f"{name} liefert None, nicht etwas Falsches", wert is None, f"{type(wert).__name__}")
    else:
        r.check(f"{name} liefert wirklich ein dict, keine sqlite3.Row",
                isinstance(wert, dict), f"liefert {type(wert).__name__}")

# Der Test, an dem ein Nutzer scheiterte: `.get()` gibt es auf einer Row nicht.
u = auth.check_password("wer", "geheim12345")
r.check("und ein dict-Zugriff wie .get() funktioniert",
        u is not None and u.get("email") == "wer@example.com",
        "genau hier scheiterte, wer der Annotation glaubte")

sys.exit(r.done())
