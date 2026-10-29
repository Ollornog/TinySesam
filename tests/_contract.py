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
PACKAGE = S.PACKAGE

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
                 ("manager.py", "_is_page_view"), ("manager.py", "_extract_api_key"),
                 ("security.py", "client_ip"), ("router.py", "_required_roles"))


class MeasurementError(AssertionError):
    """The source has a form the measurement does not understand — fix the measurement, do not skip it."""


def read_sources(root: str = ROOT) -> dict:
    package = os.path.join(root, "tinysesam")
    sources = {}
    for n in sorted(os.listdir(package)):
        if n.endswith(".py"):
            sources[n] = S.read(os.path.join(package, n))
    return sources


def _docstring_nodes(tree) -> set:
    ids = set()
    for k in ast.walk(tree):
        if isinstance(k, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) and k.body:
            first = k.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) \
                    and isinstance(first.value.value, str):
                ids.add(id(first.value))
    return ids


def _strings(tree):
    """Every string constant that is code (docstrings excluded — they talk about things, they do not do them)."""
    doc = _docstring_nodes(tree)
    for k in ast.walk(tree):
        if isinstance(k, ast.Constant) and isinstance(k.value, str) and id(k) not in doc:
            yield k


# ---------------------------------------------------------------------------
# HTTP routes
# ---------------------------------------------------------------------------
def _route_path(arg, file: str, line: int, const: dict) -> str:
    if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value
    if isinstance(arg, ast.Name) and arg.id in const:       # `HEALTH_PATH = "/healthz"` at module level
        return const[arg.id]
    if isinstance(arg, ast.Attribute) and isinstance(arg.value, ast.Name) and arg.value.id == "cfg":
        return f"<{arg.attr}>"                      # a path taken from a configuration field
    raise MeasurementError(f"{file}:{line}: route path is neither a literal nor `cfg.<field>`")


def _handler_params(fn, path: str) -> list:
    """The HTTP parameters of a handler as `query:x`, `form:x` — FastAPI's reading of the signature."""
    inpath = set(re.findall(r"\{(\w+)\}", path))
    args = fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs
    defaults = ([None] * (len(fn.args.posonlyargs) + len(fn.args.args) - len(fn.args.defaults))
                + list(fn.args.defaults) + list(fn.args.kw_defaults))
    result = []
    for arg, default in zip(args, defaults):
        ann = arg.annotation
        ann_name = (ann.id if isinstance(ann, ast.Name) else (ann.attr if isinstance(ann, ast.Attribute) else "")
                    ).lstrip("_")
        if arg.arg in inpath or ann_name in FRAMEWORK_TYPES:
            continue
        kind, name = "query", arg.arg
        if isinstance(default, ast.Call):
            fname = default.func.id if isinstance(default.func, ast.Name) else getattr(default.func, "attr", "")
            if fname == "Depends":
                continue
            if fname in ("Form", "File", "Body", "Query", "Header", "Cookie"):
                kind = "query" if fname == "Query" else fname.lower()
                for kw in default.keywords:
                    if kw.arg == "alias" and isinstance(kw.value, ast.Constant):
                        name = kw.value.value
        result.append(f"{kind}:{name}")
    return result


def routes_static(sources: dict) -> dict:
    """{"METHOD /path": sorted parameter list} from the decorators of the route modules."""
    for file, text in sorted(sources.items()):
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute) and k.func.attr in ROUTE_ESCAPES:
                raise MeasurementError(
                    f"{file}:{k.lineno}: `.{k.func.attr}(...)` registers a route the scan cannot see — "
                    "use the decorators, or teach tests/_contract.py")
    routes = {}
    for file, prefix in ROUTE_MODULES.items():
        if file not in sources:
            raise MeasurementError(f"{file} is missing from the sources")
        tree = ast.parse(sources[file])
        const = {z.targets[0].id: z.value.value for z in tree.body
                 if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name)
                 and isinstance(z.value, ast.Constant) and isinstance(z.value.value, str)}
        for fn in ast.walk(tree):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for dec in fn.decorator_list:
                if not (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        and dec.func.attr in HTTP_METHODS and isinstance(dec.func.value, ast.Name)
                        and dec.func.value.id in ROUTE_RECEIVERS and dec.args):
                    continue
                path = prefix + _route_path(dec.args[0], file, dec.lineno, const)
                key_name = f"{dec.func.attr.upper()} {path}"
                routes.setdefault(key_name, set()).update(_handler_params(fn, path))
    return {k: sorted(v) for k, v in sorted(routes.items())}


def _schema_properties(schema: dict, components: dict, depth: int = 0) -> set:
    """The property names of an OpenAPI schema — inline, behind a `$ref`, or in an `allOf` (FastAPI versions differ)."""
    if depth > 5:
        return set()
    names = set(schema.get("properties", {}))
    if "$ref" in schema:
        names |= _schema_properties(components.get(schema["$ref"].rsplit("/", 1)[-1], {}), components, depth + 1)
    for part in schema.get("allOf", []):
        names |= _schema_properties(part, components, depth + 1)
    return names


def routes_live(cfg_defaults: "dict | None" = None) -> dict:
    """{"METHOD /path": parameter list} as FastAPI itself reads the routers of a probe instance (the OpenAPI
    schema) — with as many features on as the base install allows. Extras that are not installed (OIDC,
    passkeys, SAML) simply contribute no routes here; the static scan has them anyway."""
    from fastapi import FastAPI
    from tinysesam import TinySesam, TinySesamConfig
    values = dict(db_path=os.path.join(tempfile.mkdtemp(prefix="tinysesam-routes-"), "r.db"),
                 passkey_enabled=False, oidc_enabled=False, forward_auth_enabled=True,
                 gate_link_enabled=True, gate_token_enabled=True, base_url="https://auth.example.com",
                 trusted_redirect_hosts=["app.example.com"], allow_signup=True, pin_enabled=True,
                 resource_locks_enabled=True, magiclink_enabled=True, signup_verify_email=True,
                 password_reset_enabled=True, apikey_enabled=True, account_enabled=True,
                 self_service_username_change=True, self_service_email_change=True, admin_enabled=True)
    values.update(cfg_defaults or {})
    cfg = TinySesamConfig(**values)
    cfg.cookie_secure = False
    auth = TinySesam(cfg)
    app = FastAPI()
    app.include_router(auth.router())
    schema = app.openapi()
    components = schema.get("components", {}).get("schemas", {})
    found = {}
    for path, operations in schema["paths"].items():
        if path == cfg.admin_path or path.startswith(cfg.admin_path + "/"):
            path = "<admin>" + path[len(cfg.admin_path):]
        for method, op in operations.items():
            if method.lower() not in HTTP_METHODS:
                continue
            params = {f"query:{p['name']}" for p in op.get("parameters", []) if p.get("in") == "query"}
            content = (op.get("requestBody") or {}).get("content", {})
            form = content.get("application/x-www-form-urlencoded") or content.get("multipart/form-data") or {}
            params |= {f"form:{n}" for n in _schema_properties(form.get("schema") or {}, components)}
            found[f"{method.upper()} {path}"] = sorted(params)
    return found


def routes_differences(static: dict, live: dict) -> list:
    """Where the live routers (OpenAPI) and the static scan disagree: a route the scan misses, or other
    parameters. Placeholders of the scan (`<oidc_callback_path>`) are resolved with the configuration default."""
    from tinysesam import TinySesamConfig
    defaults = {f.name: f.default for f in TinySesamConfig.__dataclass_fields__.values()}

    def resolve(key_name):
        return re.sub(r"<(\w+)>", lambda m: m.group(0) if m.group(1) == "admin"
                      else str(defaults.get(m.group(1), m.group(0))), key_name)
    known = {resolve(k): v for k, v in static.items()}
    findings = []
    for k, v in sorted(live.items()):
        k2 = resolve(k)
        if k2 not in known:
            findings.append(f"live route {k!r} is not in the static scan")
        elif sorted(known[k2]) != sorted(v):
            findings.append(f"{k!r}: scan reads parameters {known[k2]}, FastAPI reads {v}")
    return findings


# ---------------------------------------------------------------------------
# Contract atoms (headers, reasons, request inputs, cookies)
# ---------------------------------------------------------------------------
def canonical_header(name: str) -> str:
    """`x-forwarded-uri` -> `X-Forwarded-Uri`; the project's own headers keep their `TinySesam` spelling."""
    parts = [t.capitalize() for t in name.split("-")]
    canon = "-".join(parts)
    return canon.replace("X-Tinysesam-", "X-TinySesam-", 1) if canon.startswith("X-Tinysesam-") else canon


def _functions(tree, name: str) -> list:
    return [k for k in ast.walk(tree) if isinstance(k, (ast.FunctionDef, ast.AsyncFunctionDef)) and k.name == name]


def _header_reads(root) -> tuple:
    """(header names, query parameter names) read with `.get("name")` / `.getlist("name")` below `root`."""
    aliases = {"headers": "header", "query_params": "param"}
    for z in ast.walk(root):
        if isinstance(z, ast.Assign) and len(z.targets) == 1 and isinstance(z.targets[0], ast.Name) \
                and isinstance(z.value, ast.Attribute) and z.value.attr in ("headers", "query_params"):
            aliases[z.targets[0].id] = "header" if z.value.attr == "headers" else "param"
    header, params = set(), set()
    for k in ast.walk(root):
        if not (isinstance(k, ast.Call) and isinstance(k.func, ast.Attribute)
                and k.func.attr in ("get", "getlist") and k.args
                and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
            continue
        w = k.func.value
        kind = aliases.get(w.attr if isinstance(w, ast.Attribute) else getattr(w, "id", ""))
        if kind == "header":
            header.add(canonical_header(k.args[0].value))
        elif kind == "param":
            params.add(k.args[0].value)
    return header, params


def _forward_block(tree):
    """The `if cfg.forward_auth_enabled:` block of the router (the proxy-facing endpoints)."""
    for k in ast.walk(tree):
        if isinstance(k, ast.If) and ast.unparse(k.test) == "cfg.forward_auth_enabled":
            return k
    raise MeasurementError("router.py: the block `if cfg.forward_auth_enabled:` was not found")


def _reason_values(sources: dict) -> set:
    """Values of the response header `X-TinySesam-Reason` (dict literals in the router)."""
    tree = ast.parse(sources["router.py"])
    manager = ast.parse(sources["manager.py"])
    approval = set()
    for fn in _functions(manager, "_oidc_approval_valid"):
        for r in ast.walk(fn):
            if isinstance(r, ast.Return) and isinstance(r.value, ast.Tuple) and len(r.value.elts) == 2:
                z = r.value.elts[1]
                if isinstance(z, ast.Constant) and isinstance(z.value, str) and z.value:
                    approval.add(z.value)
    if not approval:
        raise MeasurementError("manager.py: `_oidc_approval_valid` returns no reason string — form changed?")
    values = set()
    for k in ast.walk(tree):
        if not isinstance(k, ast.Dict):
            continue
        for kk, vv in zip(k.keys, k.values):
            if not (isinstance(kk, ast.Constant) and kk.value == "X-TinySesam-Reason"):
                continue
            if isinstance(vv, ast.Constant) and isinstance(vv.value, str):
                values.add(vv.value)
            elif isinstance(vv, ast.BinOp) and isinstance(vv.op, ast.Add) \
                    and isinstance(vv.left, ast.Constant) and isinstance(vv.left.value, str):
                values |= {vv.left.value + a for a in approval}
            else:
                raise MeasurementError(f"router.py:{vv.lineno}: value of X-TinySesam-Reason is not a literal "
                                       "or 'prefix' + <approval reason> — teach tests/_contract.py")
    return values


def contract_atoms(sources: dict) -> list:
    """The atoms of the forward/gate contract that are not a route: headers, reasons, inputs, cookies."""
    atoms = set()
    # 1. Every `X-TinySesam-*` header name that appears in code (docstrings excluded), in any spelling.
    for file, text in sources.items():
        for k in _strings(ast.parse(text)):
            for raw in re.findall(r"(?i)x-tinysesam-[a-z]+(?:-[a-z]+)*", k.value):
                atoms.add(f"header:{canonical_header(raw)}")
    # 2. The values of X-TinySesam-Reason.
    atoms |= {f"reason:{v}" for v in _reason_values(sources)}
    # 3. What the forward endpoint and the gate paths read from the request.
    header, params = set(), set()
    router = ast.parse(sources["router.py"])
    h, p = _header_reads(_forward_block(router))
    header |= h
    params |= p
    for file, function in INPUT_READERS:
        hits = _functions(ast.parse(sources[file]), function)
        if not hits:
            raise MeasurementError(f"{file}: function {function} not found — the reader list is out of date")
        for fn in hits:
            h, p = _header_reads(fn)
            header |= h
            params |= p
    atoms |= {f"request-header:{n}" for n in header}
    atoms |= {f"request-param:{n}" for n in params}
    # 4. Cookie names the gate sets itself (host-only, fixed): string class attributes starting with `__Host-`.
    for k in ast.walk(ast.parse(sources["manager.py"])):
        if isinstance(k, ast.ClassDef) and k.name == "TinySesam":
            for z in k.body:
                if isinstance(z, ast.Assign) and isinstance(z.value, ast.Constant) \
                        and isinstance(z.value.value, str) and z.value.value.startswith("__Host-"):
                    atoms.add(f"cookie:{z.value.value}")
    return sorted(atoms)


# ---------------------------------------------------------------------------
# Loggers and security-log lines
# ---------------------------------------------------------------------------
#: Loggers of OTHER packages the package touches (not its own names, so not part of the promise): the gateway drops
#: uvicorn's upgrade warnings on `uvicorn.error` (B-5). Every other name outside `tinysesam*` is refused — a typo
#: such as `tinysesm.security` must not slip out of the measurement as "foreign".
FOREIGN_LOGGERS = ("uvicorn.error",)


def loggers_static(sources: dict) -> list:
    """The names passed to `logging.getLogger(...)` in the package. A name that is not a literal is refused; a
    foreign logger (`FOREIGN_LOGGERS`) is not measured, any other name outside `tinysesam*` is refused."""
    names = set()
    for file, text in sources.items():
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "getLogger":
                if not k.args:
                    raise MeasurementError(f"{file}:{k.lineno}: getLogger() without a name = the root logger")
                a = k.args[0]
                if not (isinstance(a, ast.Constant) and isinstance(a.value, str)):
                    raise MeasurementError(f"{file}:{k.lineno}: logger name is not a literal")
                if a.value in FOREIGN_LOGGERS:
                    continue
                if a.value != "tinysesam" and not a.value.startswith("tinysesam."):
                    raise MeasurementError(f"{file}:{k.lineno}: logger {a.value!r} is neither tinysesam* nor "
                                           "listed in FOREIGN_LOGGERS")
                names.add(a.value)
    return sorted(names)


def _formatter_strings(sources: dict) -> list:
    out = set()
    for file, text in sources.items():
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "Formatter" \
                    and k.args and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str):
                out.add(k.args[0].value)
    return sorted(out)


def filter_words(root: str = ROOT) -> set:
    """Event words that the shipped filter files name (failregex and comments)."""
    folder = os.path.join(root, "deploy", "fail2ban")
    words = set()
    for file in sorted(os.listdir(folder)):
        if file.endswith("-filter.conf"):
            text = S.read(os.path.join(folder, file))
            words.update(re.findall(r"(?:`|WARNING |INFO )((?:failed|deferred|repeated) (?:login|verification)"
                                    r"|login ok)\b", text))
    return words


def log_event_words(root: str = ROOT) -> set:
    """The event words of the security log that the promise covers: the `LOG_*` constants of security.py
    and the deferral words (`deferred login|verification`, which the filters deliberately do not match)."""
    return {v for k, v in S.CONST.items() if k.startswith("LOG_") and isinstance(v, str) and " " in v}


def log_atoms(sources: dict, not_login_methods=(), root: str = ROOT) -> list:
    """Atoms of the security log: the file format, one shape per (level, event, key order), and the literal
    values of `method=`, `reason=` and `unban=` in those lines. Free text behind the keys is not measured."""
    atoms = {f"format:{f}" for f in _formatter_strings(sources)}
    words = log_event_words(root)
    found = set()
    for file, text in sorted(sources.items()):
        for call, local in S.seclog_calls(text):
            for v in S.format_variants(call, local):
                word = next((w for w in sorted(words, key=len, reverse=True) if v.startswith(w + " ")), None)
                if word is None and v.startswith("deferred "):
                    word = " ".join(v.split(" ")[:2])
                if word is None:
                    continue
                found.add(word)
                rest = v[len(word):].split()
                key_name = [t.split("=", 1)[0] for t in rest if "=" in t]
                atoms.add(f"line:{call.func.attr.upper()} {word} | {' '.join(key_name)}")
                for t in rest:
                    if "=" not in t:
                        continue
                    k, value = t.split("=", 1)
                    if k in ("method", "reason", "unban") and value not in ("<?>", "?", ""):
                        atoms.add(f"value:{k}={value}")
    atoms |= {f"value:method={m}" for m in not_login_methods}
    atoms |= {f"event:{w}" for w in found}
    return sorted(atoms)


# ---------------------------------------------------------------------------
# Event payload
# ---------------------------------------------------------------------------
def event_payload(sources: dict) -> dict:
    """{event: sorted keys of the `details` handed to `on_security_event`} from the `_security_event` calls."""
    events = {}
    for file, text in sorted(sources.items()):
        for k in ast.walk(ast.parse(text)):
            if isinstance(k, ast.Call) and getattr(k.func, "attr", getattr(k.func, "id", "")) == "_security_event":
                if not (k.args and isinstance(k.args[0], ast.Constant) and isinstance(k.args[0].value, str)):
                    raise MeasurementError(f"{file}:{k.lineno}: event name of _security_event is not a literal")
                if any(w.arg is None for w in k.keywords):
                    raise MeasurementError(f"{file}:{k.lineno}: _security_event(**…) hides the payload keys")
                events.setdefault(k.args[0].value, set()).update(w.arg for w in k.keywords)
    return {e: sorted(s) for e, s in sorted(events.items())}


def hook_annotation(sources: dict) -> str:
    """`Optional[Callable[...]] = None` — the declaration of `self.on_security_event` in the constructor."""
    for fn in _functions(ast.parse(sources["manager.py"]), "__init__"):
        for z in ast.walk(fn):
            if isinstance(z, ast.AnnAssign) and ast.unparse(z.target) == "self.on_security_event":
                return f"{ast.unparse(z.annotation)} = {ast.unparse(z.value) if z.value else '<none>'}"
    return "attribute declaration missing"
