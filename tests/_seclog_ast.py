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
PACKAGE = os.path.join(ROOT, "tinysesam")

LEVEL = {"debug", "info", "warning", "error", "critical", "exception"}


def read(path):
    with open(path, encoding="utf-8") as fh:
        return fh.read()


def security_constants():
    """Module-level string constants of security.py and the possible results of `log_event`."""
    tree = ast.parse(read(os.path.join(PACKAGE, "security.py")))
    const = {}
    for k in tree.body:
        if (isinstance(k, ast.Assign) and len(k.targets) == 1 and isinstance(k.targets[0], ast.Name)
                and isinstance(k.value, ast.Constant) and isinstance(k.value.value, str)):
            const[k.targets[0].id] = k.value.value
    event = set()
    for k in tree.body:
        if isinstance(k, ast.FunctionDef) and k.name == "log_event":
            for r in ast.walk(k):
                if isinstance(r, ast.Return):
                    event |= values(r.value, const, set()) or set()
    return const, event


def values(node, const, event, local=None):
    """The strings an expression can evaluate to — or None if unknown.

    `local`: simple `name = expr` assignments of the enclosing function (`word = A if login else B`)."""
    local = local or {}
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Attribute) and node.attr in const:
        return {const[node.attr]}
    if isinstance(node, ast.Name) and node.id in local:
        rest = {k: v for k, v in local.items() if k != node.id}      # no cycles
        return values(local[node.id], const, event, rest)
    if isinstance(node, ast.Name) and node.id in const:
        return {const[node.id]}
    if isinstance(node, ast.IfExp):
        a = values(node.body, const, event, local)
        b = values(node.orelse, const, event, local)
        return (a | b) if a is not None and b is not None else None
    if isinstance(node, ast.Call):
        name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
        if name == "log_event" and event:
            return set(event)
    return None


CONST, EVENT = security_constants()

SPECIFICATION = re.compile(r"(%%|%(?:\([^)]*\))?[-#0 +]*\d*(?:\.\d+)?[a-zA-Z])")


def format_variants(call, local=None):
    """All texts a `seclog.<level>(fmt, *args)` call can produce, with the event word substituted."""
    if not call.args or not (isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
        return []
    parts = SPECIFICATION.split(call.args[0].value)
    arguments = list(call.args[1:])
    options, i = [], 0
    for t in parts:
        if t == "%%":
            options.append(["%"])
        elif t.startswith("%") and len(t) > 1:
            value = values(arguments[i], CONST, EVENT, local) if i < len(arguments) else None
            options.append(sorted(value) if value else ["<?>"])
            i += 1
        else:
            options.append([t])
    return ["".join(p) for p in itertools.product(*options)]


def seclog_calls(source):
    """-> (call, local assignments of the enclosing function)."""
    tree = ast.parse(source)
    areas = [(tree, {})]
    for f in ast.walk(tree):
        if isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)):
            local = {}
            for z in ast.walk(f):
                if (isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)):
                    local[z.targets[0].id] = z.value
            areas.append((f, local))
    seen = set()
    for area, local in reversed(areas):          # innermost scopes first
        for k in ast.walk(area):
            if id(k) in seen:
                continue
            if (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in LEVEL):
                w = k.func.value
                if (isinstance(w, ast.Name) and w.id == "seclog") or \
                   (isinstance(w, ast.Attribute) and w.attr == "seclog"):
                    seen.add(id(k))
                    yield k, local
