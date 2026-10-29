"""Measurement of the HTTP and log contract — what `tests/test_api_surface.py` pins beyond the Python names.

PO decision 2026-10-29 (M-1, "what belongs in the stability promise"): besides the Python surface the promise
covers the attributes `auth.cfg` and `auth.on_security_event`, the HTTP routes (the forward/gate contract that
proxies use in tier A, the HTML pages in tier B) and the logger names plus the security-log lines that fail2ban
filters read (tier A). This module only MEASURES; the tiers are decisions and live in `tests/api_surface.json`.

Everything here is read from the source with the `ast` module or from a probe instance, never from the
installed extras: the route scan sees the OIDC, passkey and SAML routes even where the extra is missing, so the
baseline is the same on every machine. A live router is compared against the scan (`routes_live`), so a route
registered in a way the scan cannot see turns the guard red instead of staying unmeasured.

Areas it delivers (see `measure()`):

    TinySesam.attributes        `cfg`, `on_security_event` — type, default, call contract
    TinySesam.event_payload     event name -> keys of the `details` dict handed to `on_security_event`
    http.routes                 "METHOD /path" -> query/form parameter names (sorted list)
    http.forward                scenario -> status and contract headers, measured against a probe instance
    http.contract               atoms: X-TinySesam-* headers, reason values, request headers/params, cookie names
    log.loggers                 atoms: the names passed to `logging.getLogger`
    log.lines                   atoms: format of the log file, shapes and literal values of the filter lines
"""
import ast
import os
import re
import tempfile

import _seclog_ast as S

ROOT = S.ROOT
PAKET = S.PAKET

#: Modules with routes and the prefix their paths get ("<admin>" = wherever the admin router is mounted,
#: by default `cfg.admin_path`).
ROUTE_MODULES = {"router.py": "", "oidc.py": "", "webauthn_.py": "", "admin.py": "<admin>", "gateway.py": ""}
#: Names a router or app has in those modules (`r = APIRouter(...)`, `ar = ...`, `@router.get`, `@app.get`).
ROUTE_RECEIVERS = {"r", "router", "ar", "app"}
HTTP_METHODS = {"get", "post", "put", "delete", "patch"}
#: Registering a route in any other way would be invisible to the scan — the scan refuses it.
ROUTE_ESCAPES = {"add_api_route", "add_route", "add_websocket_route", "api_route", "route", "websocket",
                 "mount", "add_api_websocket_route"}
#: Python types of a handler parameter that are not part of the HTTP interface.
FRAMEWORK_TYPES = {"Request", "Response", "BackgroundTasks", "HTTPConnection"}

#: Functions whose reads of request headers and query parameters are the INPUT of the forward/gate contract.
#: (file, function) — and the whole `if cfg.forward_auth_enabled:` block of `router.py`.
INPUT_READERS = (("manager.py", "_forwarded_url"), ("manager.py", "_gate_host"),
                 ("manager.py", "_ist_seitenaufruf"), ("manager.py", "_extract_api_key"),
                 ("security.py", "client_ip"), ("router.py", "_required_roles"))


class MeasurementError(AssertionError):
    """The source has a form the measurement does not understand — fix the measurement, do not skip it."""


def read_sources(root: str = ROOT) -> dict:
    paket = os.path.join(root, "tinysesam")
    quellen = {}
    for n in sorted(os.listdir(paket)):
        if n.endswith(".py"):
            quellen[n] = S.lies(os.path.join(paket, n))
    return quellen


def _docstring_nodes(baum) -> set:
    ids = set()
    for k in ast.walk(baum):
        if isinstance(k, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and k.body:
            erst = k.body[0]
            if isinstance(erst, ast.Expr) and isinstance(erst.value, ast.Constant) \
                    and isinstance(erst.value.value, str):
                ids.add(id(erst.value))
    return ids


def _strings(baum):
    """Every string constant that is code (docstrings excluded — they talk about things, they do not do them)."""
    doc = _docstring_nodes(baum)
    for k in ast.walk(baum):
        if isinstance(k, ast.Constant) and isinstance(k.value, str) and id(k) not in doc:
            yield k


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------
def _route_path(arg, datei: str, zeile: int, konst: dict) -> str:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name) and arg.id in konst:       # `HEALTH_PATH = "/healthz"` at module level
        return konst[arg.id]
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == "cfg":
        return f"<{arg.attr}>"                      # a path taken from a configuration field
    raise MeasurementError(f"{datei}:{zeile}: route path is neither a literal nor `cfg.<field>`")


def _handler_params(fn, pfad: str) -> list:
    """The HTTP parameters of a handler as `query:x`, `form:x` — FastAPI's reading of the signature."""
    inpath = set(re.findall(r"\{(\w+)\}", pfad))
    args = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    defaults = ([None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
                + list(fn.args.defaults) + list(fn.args.kw_defaults))
    ergebnis = []
    for arg, vorgabe in zip(args, defaults):
        ann = arg.annotation
        ann_name = (ann.id if isinstance(ann, ast.Name) else (ann.attr if isinstance(ann, ast.Attribute) else "")
                    ).lstrip("_")
        if arg.arg in inpath or ann_name in FRAMEWORK_TYPES:
            continue
        art, name = "query", arg.arg
        if isinstance(vorgabe, ast.Call):
            fname = vorgabe.func.id if isinstance(vorgabe.func, ast.Name) else getattr(vorgabe.func, "attr", "")
            if fname == "Depends":
                continue
            if fname in ("Form", "File", "Body", "Query", "Header", "Cookie"):
                art = "query" if fname == "Query" else fname.lower()
                for kw in vorgabe.keywords:
                    if kw.arg == "alias" and isinstance(kw.value, ast.Constant):
                        name = kw.value.value
        ergebnis.append(f"{art}:{name}")
    return ergebnis


def routes_static(quellen: dict) -> dict:
    """{"METHOD /path": sorted parameter list} from the decorators of the route modules."""
    for datei, text in sorted(quellen.items()):
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in ROUTE_ESCAPES:
                raise MeasurementError(
                    f"{datei}:{k.lineno}: `.{k.func.attr}(...)` registers a route the scan cannot see — "
                    "use the decorators, or teach tests/_contract.py")
    routen = {}
    for datei, praefix in ROUTE_MODULES.items():
        if datei not in quellen:
            raise MeasurementError(f"{datei} is missing from the sources")
        baum = ast.parse(quellen[datei])
        konst = {z.targets[0].id: z.value.value for z in baum.body
                 if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)
                 and isinstance(z.value, ast.Constant) and isinstance(z.value.value, str)}
        for fn in ast.walk(baum):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in fn.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in HTTP_METHODS and isinstance(dec.func.value, ast.Name)
                        and dec.func.value.id in ROUTE_RECEIVERS and dec.args):
                    continue
                pfad = praefix + _route_path(dec.args[0], datei, dec.lineno, konst)
                schluessel = f"{dec.func.attr.upper()} {pfad}"
                routen.setdefault(schluessel, set()).update(_handler_params(fn, pfad))
    return {k: sorted(v) for k, v in sorted(routen.items())}


def routes_live(cfg_vorgaben: "dict | None" = None) -> dict:
    """{"METHOD /path": parameter list} as FastAPI itself reads the routers of a probe instance (the OpenAPI
    schema) — with as many features on as the base install allows. Extras that are not installed (OIDC,
    passkeys, SAML) simply contribute no routes here; the static scan has them anyway."""
    from fastapi import FastAPI
    from tinysesam import TinySesam, TinySesamConfig
    werte = dict(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-routes-"), "r.db"),
                 passkey_enabled=False, oidc_enabled=False, forward_auth_enabled=True,
                 gate_link_enabled=True, gate_token_enabled=True, base_url="https://auth.example.com",
                 trusted_redirect_hosts=["app.example.com"], allow_signup=True, pin_enabled=True,
                 resource_locks_enabled=True, magiclink_enabled=True, signup_verify_email=True,
                 password_reset_enabled=True, apikey_enabled=True, account_enabled=True,
                 self_service_username_change=True, self_service_email_change=True, admin_enabled=True)
    werte.update(cfg_vorgaben or {})
    cfg = TinySesamConfig(**werte)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    schema = app.openapi()
    komponenten = schema.get("components", {}).get("schemas", {})
    gefunden = {}
    for pfad, operationen in schema["paths"].items():
        if pfad == cfg.admin_path or pfad.startswith(cfg.admin_path + "/"):
            pfad = "<admin>" + pfad[len(cfg.admin_path):]
        for methode, op in operationen.items():
            if methode.lower() not in HTTP_METHODS:
                continue
            params = {f"query:{p['name']}" for p in op.get("parameters", []) if p.get("in") == "query"}
            inhalt = (op.get("requestBody") or {}).get("content", {})
            formular = inhalt.get("application/x-www-form-urlencoded") or inhalt.get("multipart/form-data") or {}
            ref = (formular.get("schema") or {}).get("$ref", "")
            eigenschaften = komponenten.get(ref.rsplit("/", 1)[-1], {}).get("properties", {}) if ref else {}
            params |= {f"form:{n}" for n in eigenschaften}
            gefunden[f"{methode.upper()} {pfad}"] = sorted(params)
    return gefunden


def routes_differences(statisch: dict, live: dict) -> list:
    """Where the live routers (OpenAPI) and the static scan disagree: a route the scan misses, or other
    parameters. Placeholders of the scan (`<oidc_callback_path>`) are resolved with the configuration default."""
    from tinysesam import TinySesamConfig
    vorgaben = {f.name: f.default for f in TinySesamConfig.__dataclass_fields__.values()}

    def aufloesen(schluessel):
        return re.sub(r"<(\w+)>", lambda m: m.group(0) if m.group(1) == "admin"
                      else str(vorgaben.get(m.group(1), m.group(0))), schluessel)
    bekannt = {aufloesen(k): v for k, v in statisch.items()}
    befunde = []
    for k, v in sorted(live.items()):
        k2 = aufloesen(k)
        if k2 not in bekannt:
            befunde.append(f"live route {k!r} is not in the static scan")
        elif sorted(bekannt[k2]) != sorted(v):
            befunde.append(f"{k!r}: scan reads parameters {bekannt[k2]}, FastAPI reads {v}")
    return befunde


# ---------------------------------------------------------------------------
# Contract atoms (headers, reasons, request inputs, cookies)
# ---------------------------------------------------------------------------
def canonical_header(name: str) -> str:
    """`x-forwarded-uri` -> `X-Forwarded-Uri`; the project's own headers keep their `TinySesam` spelling."""
    teile = [t.capitalize() for t in name.split("-")]
    kanon = "-".join(teile)
    return kanon.replace("X-Tinysesam-", "X-TinySesam-", 1) if kanon.startswith("X-Tinysesam-") else kanon


def _funktionen(baum, name: str) -> list:
    return [k for k in ast.walk(baum) if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef)) and k.name == name]


def _header_reads(wurzel) -> tuple:
    """(header names, query parameter names) read with `.get("name")` / `.getlist("name")` below `wurzel`."""
    aliase = {"headers": "header", "query_params": "param"}
    for z in ast.walk(wurzel):
        if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name) \
                and isinstance(z.value, ast.Attribute) and z.value.attr in ("headers", "query_params"):
            aliase[z.targets[0].id] = "header" if z.value.attr == "headers" else "param"
    header, params = set(), set()
    for k in ast.walk(wurzel):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr in ("get", "getlist") and k.args
                and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
            continue
        w = k.func.value
        art = aliase.get(w.attr if isinstance(w, ast.Attribute) else getattr(w, "id", ""))
        if art == "header":
            header.add(canonical_header(k.args[0].value))
        elif art == "param":
            params.add(k.args[0].value)
    return header, params


def _forward_block(baum):
    """The `if cfg.forward_auth_enabled:` block of the router (the proxy-facing endpoints)."""
    for k in ast.walk(baum):
        if isinstance(k, ast.If) and ast.unparse(k.test) == "cfg.forward_auth_enabled":
            return k
    raise MeasurementError("router.py: the block `if cfg.forward_auth_enabled:` was not found")


def _reason_values(quellen: dict) -> set:
    """Values of the response header `X-TinySesam-Reason` (dict literals in the router)."""
    baum = ast.parse(quellen["router.py"])
    manager = ast.parse(quellen["manager.py"])
    approval = set()
    for fn in _funktionen(manager, "_oidc_approval_valid"):
        for r in ast.walk(fn):
            if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple) and len(r.value.elts) == 2:
                z = r.value.elts[1]
                if isinstance(z, ast.Constant) and isinstance(z.value, str) and z.value:
                    approval.add(z.value)
    if not approval:
        raise MeasurementError("manager.py: `_oidc_approval_valid` returns no reason string — form changed?")
    werte = set()
    for k in ast.walk(baum):
        if not isinstance(k, ast.Dict):
            continue
        for kk, vv in zip(k.keys, k.values):
            if not (isinstance(kk, ast.Constant) and kk.value == "X-TinySesam-Reason"):
                continue
            if isinstance(vv, ast.Constant) and isinstance(vv.value, str):
                werte.add(vv.value)
            elif isinstance(vv, ast.BinOp) and isinstance(vv.op, ast.Add) \
                    and isinstance(vv.left, ast.Constant) and isinstance(vv.left.value, str):
                werte |= {vv.left.value + a for a in approval}
            else:
                raise MeasurementError(f"router.py:{vv.lineno}: value of X-TinySesam-Reason is not a literal "
                                       "or 'prefix' + <approval reason> — teach tests/_contract.py")
    return werte


def contract_atoms(quellen: dict) -> list:
    """The atoms of the forward/gate contract that are not a route: headers, reasons, inputs, cookies."""
    atome = set()
    # 1. Every `X-TinySesam-*` header name that appears in code (docstrings excluded), in any spelling.
    for datei, text in quellen.items():
        for k in _strings(ast.parse(text)):
            for roh in re.findall(r"(?i)x-tinysesam-[a-z]+(?:-[a-z]+)*", k.value):
                atome.add(f"header:{canonical_header(roh)}")
    # 2. The values of X-TinySesam-Reason.
    atome |= {f"reason:{v}" for v in _reason_values(quellen)}
    # 3. What the forward endpoint and the gate paths read from the request.
    header, params = set(), set()
    router = ast.parse(quellen["router.py"])
    h, p = _header_reads(_forward_block(router))
    header |= h
    params |= p
    for datei, funktion in INPUT_READERS:
        funde = _funktionen(ast.parse(quellen[datei]), funktion)
        if not funde:
            raise MeasurementError(f"{datei}: function {funktion} not found — the reader list is out of date")
        for fn in funde:
            h, p = _header_reads(fn)
            header |= h
            params |= p
    atome |= {f"request-header:{n}" for n in header}
    atome |= {f"request-param:{n}" for n in params}
    # 4. Cookie names the gate sets itself (host-only, fixed): string class attributes starting with `__Host-`.
    for k in ast.walk(ast.parse(quellen["manager.py"])):
        if isinstance(k, ast.ClassDef) and k.name == "TinySesam":
            for z in k.body:
                if isinstance(z, ast.Assign) and isinstance(z.value, ast.Constant) \
                        and isinstance(z.value.value, str) and z.value.value.startswith("__Host-"):
                    atome.add(f"cookie:{z.value.value}")
    return sorted(atome)


# ---------------------------------------------------------------------------
# Loggers and security-log lines
# ---------------------------------------------------------------------------
def loggers_static(quellen: dict) -> list:
    """The names passed to `logging.getLogger(...)` in the package. A name that is not a literal is refused."""
    namen = set()
    for datei, text in quellen.items():
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "getLogger":
                if not k.args:
                    raise MeasurementError(f"{datei}:{k.lineno}: getLogger() without a name = the root logger")
                a = k.args[0]
                if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
                    raise MeasurementError(f"{datei}:{k.lineno}: logger name is not a literal")
                namen.add(a.value)
    return sorted(namen)


def _formatter_strings(quellen: dict) -> list:
    out = set()
    for datei, text in quellen.items():
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "Formatter" \
                    and k.args and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str):
                out.add(k.args[0].value)
    return sorted(out)


def _filter_words(root: str = ROOT) -> set:
    """Event words that the shipped filter files name (failregex and comments)."""
    ordner = os.path.join(root, "deploy", "fail2ban")
    worte = set()
    for datei in sorted(os.listdir(ordner)):
        if datei.endswith("-filter.conf"):
            text = S.lies(os.path.join(ordner, datei))
            worte.update(re.findall(r"(?:`|WARNING |INFO )((?:failed|deferred|repeated) (?:login|verification)"
                                    r"|login ok)\b", text))
    return worte


def log_event_words(root: str = ROOT) -> set:
    """The event words of the security log that the promise covers: the `LOG_*` constants of security.py
    and the deferral words (`deferred login|verification`, which the filters deliberately do not match)."""
    return {v for k, v in S.KONST.items() if k.startswith("LOG_") and isinstance(v, str) and " " in v}


def log_atoms(quellen: dict, nicht_login_methoden=(), root: str = ROOT) -> list:
    """Atoms of the security log: the file format, one shape per (level, event, key order), and the literal
    values of `method=`, `reason=` and `unban=` in those lines. Free text behind the keys is not measured."""
    atome = {f"format:{f}" for f in _formatter_strings(quellen)}
    worte = log_event_words(root)
    gefunden = set()
    for datei, text in sorted(quellen.items()):
        for call, lokal in S.seclog_aufrufe(text):
            for v in S.formatvarianten(call, lokal):
                wort = next((w for w in sorted(worte, key=len, reverse=True) if v.startswith(w + " ")), None)
                if wort is None and v.startswith("deferred "):
                    wort = " ".join(v.split(" ")[:2])
                if wort is None:
                    continue
                gefunden.add(wort)
                rest = v[len(wort):].split()
                schluessel = [t.split("=", 1)[0] for t in rest if "=" in t]
                atome.add(f"line:{call.func.attr.upper()} {wort} | {' '.join(schluessel)}")
                for t in rest:
                    if "=" not in t:
                        continue
                    k, wert = t.split("=", 1)
                    if k in ("method", "reason", "unban") and wert not in ("<?>", "?", ""):
                        atome.add(f"value:{k}={wert}")
    atome |= {f"value:method={m}" for m in nicht_login_methoden}
    fehlt = _filter_words(root) - gefunden
    if fehlt:
        raise MeasurementError(f"the shipped filters name event words that no log call produces: {sorted(fehlt)}")
    atome |= {f"event:{w}" for w in gefunden}
    return sorted(atome)


# ---------------------------------------------------------------------------
# Event payload
# ---------------------------------------------------------------------------
def event_payload(quellen: dict) -> dict:
    """{event: sorted keys of the `details` handed to `on_security_event`} from the `_security_event` calls."""
    ereignisse = {}
    for datei, text in sorted(quellen.items()):
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "_security_event":
                if not (k.args and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
                    raise MeasurementError(f"{datei}:{k.lineno}: event name of _security_event is not a literal")
                if any(w.arg is None for w in k.keywords):
                    raise MeasurementError(f"{datei}:{k.lineno}: _security_event(**…) hides the payload keys")
                ereignisse.setdefault(k.args[0].value, set()).update(w.arg for w in k.keywords)
    return {e: sorted(s) for e, s in sorted(ereignisse.items())}


def hook_annotation(quellen: dict) -> str:
    """`Optional[Callable[...]] = None` — the declaration of `self.on_security_event` in the constructor."""
    for fn in _funktionen(ast.parse(quellen["manager.py"]), "__init__"):
        for z in ast.walk(fn):
            if isinstance(z, ast.AnnAssign) and ast.unparse(z.target) == "self.on_security_event":
                return f"{ast.unparse(z.annotation)} = {ast.unparse(z.value) if z.value else '<none>'}"
    raise MeasurementError("manager.py: `self.on_security_event: … = …` not found in __init__")
