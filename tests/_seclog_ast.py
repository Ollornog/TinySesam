"""Static reading of the security-log call sites (`seclog.<level>(...)`) — shared by two guards.

`tests/test_fail2ban_reason.py` measures that every line a fail2ban filter reads carries its cause under
`reason=`; `tests/test_api_surface.py` pins the line shapes, event words and logger names that the operator
promise (M-1, PO decision 2026-10-29) covers. Both need the same thing: which texts can a `seclog` call
produce, with the event word substituted? It lives here once, so the two cannot drift apart.

Nothing in this module runs at import beyond reading `tinysesam/security.py` (the event-word constants).
"""
import ast
import itertools
import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PAKET = os.path.join(ROOT, "tinysesam")

LEVEL = {"debug", "info", "warning", "error", "critical", "exception"}


def lies(pfad):
    with open(pfad, encoding="utf-8") as fh:
        return fh.read()


def sicherheit_konstanten():
    """Module-level string constants of security.py and the possible results of `log_ereignis`."""
    baum = ast.parse(lies(os.path.join(PAKET, "security.py")))
    konst = {}
    for k in baum.body:
        if (isinstance(k, ast.Assign) and len(k.targets) == 1 and isinstance(k.targets[0], ast.Name)
                and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)):
            konst[k.targets[0].id] = k.value.value
    ereignis = set()
    for k in baum.body:
        if isinstance(k, ast.FunctionDef) and k.name == "log_ereignis":
            for r in ast.walk(k):
                if isinstance(r, ast.Return):
                    ereignis |= werte(r.value, konst, set()) or set()
    return konst, ereignis


def werte(knoten, konst, ereignis, lokal=None):
    """The strings an expression can evaluate to — or None if unknown.

    `lokal`: simple `name = expr` assignments of the enclosing function (`wort = A if login else B`)."""
    lokal = lokal or {}
    if isinstance(knoten, ast.Constant) and isinstance(knoten.value, str):
        return {knoten.value}
    if isinstance(knoten, ast.Attribute) and knoten.attr in konst:
        return {konst[knoten.attr]}
    if isinstance(knoten, ast.Name) and knoten.id in lokal:
        rest = {k: v for k, v in lokal.items() if k != knoten.id}      # no cycles
        return werte(lokal[knoten.id], konst, ereignis, rest)
    if isinstance(knoten, ast.Name) and knoten.id in konst:
        return {konst[knoten.id]}
    if isinstance(knoten, ast.IfExp):
        a = werte(knoten.body, konst, ereignis, lokal)
        b = werte(knoten.orelse, konst, ereignis, lokal)
        return (a | b) if a is not None and b is not None else None
    if isinstance(knoten, ast.Call):
        name = knoten.func.attr if isinstance(knoten.func, ast.Attribute) else getattr(knoten.func, "id", "")
        if name == "log_ereignis" and ereignis:
            return set(ereignis)
    return None


KONST, EREIGNIS = sicherheit_konstanten()

SPEZIFIKATION = re.compile(r"(%%|%(?:\([^)]*\))?[-#0 +]*\d*(?:\.\d+)?[a-zA-Z])")


def formatvarianten(aufruf, lokal=None):
    """All texts a `seclog.<level>(fmt, *args)` call can produce, with the event word substituted."""
    if not aufruf.args or not (isinstance(aufruf.args[0], ast.Constant) and isinstance(aufruf.args[0].value, str)):
        return []
    teile = SPEZIFIKATION.split(aufruf.args[0].value)
    argumente = list(aufruf.args[1:])
    optionen, i = [], 0
    for t in teile:
        if t == "%%":
            optionen.append(["%"])
        elif t.startswith("%") and len(t) > 1:
            wert = werte(argumente[i], KONST, EREIGNIS, lokal) if i < len(argumente) else None
            optionen.append(sorted(wert) if wert else ["<?>"])
            i += 1
        else:
            optionen.append([t])
    return ["".join(p) for p in itertools.product(*optionen)]


def seclog_aufrufe(quelle):
    """-> (call, local assignments of the enclosing function)."""
    baum = ast.parse(quelle)
    bereiche = [(baum, {})]
    for f in ast.walk(baum):
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
            lokal = {}
            for z in ast.walk(f):
                if (isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)):
                    lokal[z.targets[0].id] = z.value
            bereiche.append((f, lokal))
    gesehen = set()
    for bereich, lokal in reversed(bereiche):          # innermost scopes first
        for k in ast.walk(bereich):
            if id(k) in gesehen:
                continue
            if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in LEVEL):
                w = k.func.value
                if (isinstance(w, ast.Name) and w.id == "seclog") or \
                   (isinstance(w, ast.Attribute) and w.attr == "seclog"):
                    gesehen.add(id(k))
                    yield k, lokal
