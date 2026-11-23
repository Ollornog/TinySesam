"""An application that lets TinySesam confirm a sensitive action — the whole flow of spec/approval-token.md in one
small WSGI app: ask, send the person to TinySesam, come back, pick the confirmation up, check it, remember its `jti`,
run the own rule again, act. Standard library plus `tinysesam.approval_token` (no FastAPI in the application).

    python examples/approvals/app.py --demo

`--demo` starts a real TinySesam on http://127.0.0.1:8000 (throwaway database, the people `anna` and `bert`, password
`demo password 4711`) and this application on http://127.0.0.1:8001. Nothing leaves the machine. Open the application,
pick a person (a stand-in for the identity the gate passes in production), press "Delete permanently" on a collection,
sign in at TinySesam if asked, compare the code, confirm with the password — and you are back, the collection is gone.

Against an installation of your own, TinySesam needs the application in its configuration (`apps.example`: a service
account, the type below, this app's return address) and this app needs that account's automation key:

    TINYSESAM_URL=https://auth.example.com TINYSESAM_API_KEY=tsk_… python examples/approvals/app.py

The rules this file follows (spec/approval-token.md §1, §4, §10):

- the action, its fields, the account and the `state` come from what the application stored when it asked — never
  from the confirmation, never from the return address;
- the confirmation is picked up in the back end and is never in a URL, a log line or an error page;
- `verify` checks against the APPROVAL key set (`/auth/approvals/jwks.json`), and its last step writes the `jti` with
  one INSERT into a table with a unique key — a second use is `replay`;
- the own rule (the collection still exists, the person still owns it) runs before asking AND again before acting.
"""
from __future__ import annotations

import argparse
import html
import json
import os
import secrets
import sqlite3
import sys
import threading
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from http.cookies import SimpleCookie
from typing import Any, Optional
from urllib.parse import parse_qs, quote

from tinysesam import approval_token
from tinysesam.gate_client import GateError

APP_ID = "example"
DELETE = "example.collection.delete_permanently"
#: The registration in TinySesam's configuration (`apps.example.approvals.types`): the texts come from the operator.
TYPES = {DELETE: {
    "fields": {"collection": {"type": "string", "max": 64, "pattern": "^[A-Za-z0-9_-]{1,64}$"},
               "name": {"type": "string", "max": 120}},
    "title": {"en": "Delete collection permanently", "de": "Collection endgültig löschen"},
    "summary": {"en": "Permanently delete the collection {name} ({collection}). This cannot be undone.",
                "de": "Die Collection {name} ({collection}) endgültig löschen. Das lässt sich nicht rückgängig machen."},
    "irreversible": True}}

#: (method, path, JSON body or None) → (status, JSON answer). TinySesam's API with the application's automation key.
Api = Callable[[str, str, Optional[dict]], "tuple[int, dict]"]


def http_api(base_url: str, api_key: str) -> Api:
    """TinySesam's approval API over HTTP (urllib), with the automation key of the application's service account."""
    def call(method: str, path: str, body: Optional[dict] = None) -> tuple[int, dict]:
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(base_url.rstrip("/") + path, data=data, method=method,
                                     headers={"X-Api-Key": api_key, "Accept": "application/json",
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=35) as resp:      # the long poll waits up to 25 s
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as e:
            with e:
                return e.code, json.loads(e.read() or b"{}")
    return call


class ExampleApp:
    """The application: collections with an owner, and one sensitive action — deleting a collection permanently."""

    def __init__(self, *, api: Api, keys: Any, issuer: str, return_url: str, db_path: str,
                 identify: Callable[[dict], Optional[str]], secure_cookies: bool = True):
        self.api, self.keys, self.issuer, self.return_url = api, keys, issuer.rstrip("/"), return_url
        self.identify, self.secure = identify, secure_cookies
        self.db = sqlite3.connect(db_path, check_same_thread=False, isolation_level=None)
        self.lock = threading.Lock()
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS collection (id TEXT PRIMARY KEY, name TEXT NOT NULL, owner TEXT NOT NULL);
            -- What the application stored when it asked, keyed by the state of the person's browser.
            CREATE TABLE IF NOT EXISTS pending (state TEXT PRIMARY KEY, approval_id TEXT NOT NULL, owner TEXT NOT NULL,
                                                fields TEXT NOT NULL, created_at INTEGER NOT NULL);
            -- The jti store of spec/approval-token.md §7: one row per used confirmation, unique.
            CREATE TABLE IF NOT EXISTS approval_jti (jti TEXT PRIMARY KEY, until INTEGER NOT NULL);
        """)

    # ---------- the jti store: one INSERT ----------
    def remember(self, jti: str, until: int) -> bool:
        """True only the first time: the INSERT fails on the unique key for a confirmation used before."""
        with self.lock:
            self.db.execute("DELETE FROM approval_jti WHERE until < ?", (int(time.time()),))
            try:
                self.db.execute("INSERT INTO approval_jti (jti, until) VALUES (?, ?)", (jti, until))
            except sqlite3.IntegrityError:
                return False
        return True

    # ---------- the own rule ----------
    def owned(self, collection: str, user: str) -> Optional[str]:
        """The collection's name when it exists and `user` owns it — checked before asking and again before acting."""
        row = self.db.execute("SELECT name FROM collection WHERE id = ? AND owner = ?", (collection, user)).fetchone()
        return row[0] if row else None

    # ---------- WSGI ----------
    def __call__(self, environ: dict, start_response: Callable) -> list[bytes]:
        method, path = environ["REQUEST_METHOD"], environ.get("PATH_INFO", "/")
        user = self.identify(environ)
        if path == "/" and method == "GET":
            return self.index(start_response, user)
        if path.startswith("/collections/") and path.endswith("/delete") and method == "POST":
            return self.ask(start_response, user, path[len("/collections/"):-len("/delete")])
        if path == "/approvals/return" and method == "GET":
            return self.come_back(environ, start_response, user)
        return page(start_response, "404 Not Found", "Not found.")

    def index(self, start_response, user: Optional[str]) -> list[bytes]:
        if user is None:
            return page(start_response, "401 Unauthorized", "Not signed in.")
        rows = self.db.execute("SELECT id, name FROM collection WHERE owner = ? ORDER BY id", (user,)).fetchall()
        items = "".join(f"<li>{html.escape(name)} <code>{html.escape(cid)}</code> "
                        f"<form method=post action='/collections/{quote(cid)}/delete'>"
                        f"<button>Delete permanently</button></form></li>" for cid, name in rows)
        return page(start_response, "200 OK", f"<ul>{items}</ul>" if items else "No collections.")

    def ask(self, start_response, user: Optional[str], collection: str) -> list[bytes]:
        if user is None:
            return page(start_response, "401 Unauthorized", "Not signed in.")
        name = self.owned(collection, user)
        if name is None:                                        # the own rule, before asking
            return page(start_response, "403 Forbidden", "Not your collection.")
        state = secrets.token_urlsafe(24)
        fields = {"collection": collection, "name": name}
        status, answer = self.api("POST", "/auth/api/approvals", {
            "type": DELETE, "subject": user, "fields": fields, "return_url": self.return_url, "state": state})
        if status != 201:
            return page(start_response, "502 Bad Gateway", "TinySesam did not take the request.")
        with self.lock:
            self.db.execute("INSERT INTO pending VALUES (?, ?, ?, ?, ?)",
                            (state, answer["id"], user, json.dumps(fields), int(time.time())))
        # Browser entry (§1.1): the fields never travel through the browser — only to TinySesam's page and back.
        start_response("303 See Other", [("Location", answer["approve_url"]),
                                         ("Set-Cookie", self.state_cookie(state, 600))])
        return [b""]

    def come_back(self, environ: dict, start_response, user: Optional[str]) -> list[bytes]:
        query = {k: v[0] for k, v in parse_qs(environ.get("QUERY_STRING", "")).items()}
        cookie = SimpleCookie(environ.get("HTTP_COOKIE", ""))
        kept = cookie["example_approval_state"].value if "example_approval_state" in cookie else ""
        state = query.get("state", "")
        if not state or not secrets.compare_digest(state.encode(), kept.encode()):
            return page(start_response, "400 Bad Request", "This confirmation belongs to another browser session.")
        with self.lock:                                         # what we stored when we asked, used once
            row = self.db.execute("SELECT approval_id, owner, fields FROM pending WHERE state = ?",
                                  (state,)).fetchone()
            self.db.execute("DELETE FROM pending WHERE state = ?", (state,))
        if row is None or row[0] != query.get("approval") or row[1] != user:
            return page(start_response, "400 Bad Request", "Nothing waits for this confirmation.")
        approval_id, owner, fields = row[0], row[1], json.loads(row[2])
        if query.get("result"):
            return page(start_response, "200 OK", f"Not confirmed ({html.escape(query['result'])}). Nothing happened.")
        status, answer = self.api("GET", f"/auth/api/approvals/{quote(approval_id)}?wait=25", None)
        token = answer.get("confirmation") if status == 200 else None
        if not token:
            return page(start_response, "409 Conflict", f"No confirmation ({html.escape(str(answer.get('state')))}).")
        try:
            approval_token.verify(token, keys=self.keys, issuer=self.issuer, app_id=APP_ID, expect_type=DELETE,
                                  expect_fields=fields, expect_sub=owner, expect_nonce=state,
                                  jti_store=self.remember)
        except GateError as e:                                  # log the class, never the confirmation
            print(f"approval refused: {e.kind}", file=sys.stderr)
            return page(start_response, "403 Forbidden", "The confirmation does not hold. Nothing happened.")
        with self.lock:                                         # the own rule again, right before acting
            if self.owned(fields["collection"], owner) is None:
                return page(start_response, "409 Conflict", "The collection changed meanwhile. Nothing happened.")
            self.db.execute("DELETE FROM collection WHERE id = ?", (fields["collection"],))
        return page(start_response, "200 OK", f"Deleted {html.escape(fields['name'])}.")

    def state_cookie(self, state: str, max_age: int) -> str:
        # SameSite=Lax: TinySesam sends the browser back with a top-level GET from another site.
        return (f"example_approval_state={state}; Max-Age={max_age}; Path=/approvals/return; HttpOnly; SameSite=Lax"
                + ("; Secure" if self.secure else ""))


def page(start_response, status: str, body: str) -> list[bytes]:
    out = (f"<!doctype html><meta charset=utf-8><title>Example</title><h1>Example</h1><p>{body}</p>"
           "<p><a href='/'>Back</a></p>").encode()
    start_response(status, [("Content-Type", "text/html; charset=utf-8"), ("Cache-Control", "no-store"),
                            ("Content-Security-Policy", "default-src 'none'; form-action 'self'")])
    return [out]


# ---------- the local demo ----------

DEMO_PASSWORD = "demo password 4711"


def demo_identify(environ: dict) -> Optional[str]:
    """DEMO ONLY — a stand-in for the identity of the gate (`Remote-Id` checked by `tinysesam.gate_client`): the account
    id from the query `?as=<id>` or the cookie it sets. Never do this in production."""
    cookie = SimpleCookie(environ.get("HTTP_COOKIE", ""))
    who = parse_qs(environ.get("QUERY_STRING", "")).get("as", [""])[0]
    return who or (cookie["example_demo_user"].value if "example_demo_user" in cookie else None)


def demo() -> None:  # pragma: no cover — started by hand
    import tempfile
    from wsgiref.simple_server import make_server

    import uvicorn
    from fastapi import FastAPI

    from tinysesam import TinySesam, TinySesamConfig

    auth_url, app_url = "http://127.0.0.1:8000", "http://127.0.0.1:8001"
    tmp = tempfile.mkdtemp(prefix="tinysesam-approvals-demo-")
    auth = TinySesam(TinySesamConfig(
        db_path=os.path.join(tmp, "tinysesam.db"), base_url=auth_url, cookie_secure=False, passkey_enabled=False,
        oidc_enabled=False, apikey_enabled=True, approvals_enabled=True, trusted_redirect_hosts=["127.0.0.1"],
        apps={APP_ID: {"account": "svc-example", "name": {"en": "Example"},
                       "approvals": {"types": TYPES, "return_urls": [f"{app_url}/approvals/return"]}}}))
    service = auth.create_service("svc-example")
    key = auth.create_api_key(service, name="example")["key"]
    people = {name: str(auth.create_user(name, password=DEMO_PASSWORD)) for name in ("anna", "bert")}
    fastapi_app = FastAPI()
    fastapi_app.include_router(auth.router())
    threading.Thread(target=uvicorn.run, args=(fastapi_app,), kwargs={"host": "127.0.0.1", "port": 8000,
                                                                     "log_level": "warning"}, daemon=True).start()
    app = ExampleApp(api=http_api(auth_url, key), keys=approval_token.JWKSKeys(f"{auth_url}/auth/approvals/jwks.json"),
                     issuer=auth_url, return_url=f"{app_url}/approvals/return",
                     db_path=os.path.join(tmp, "example.db"), identify=demo_identify, secure_cookies=False)
    app.db.executemany("INSERT INTO collection VALUES (?, ?, ?)",
                       [("c_81f2", "Project Alpha", people["anna"]), ("c_77aa", "Holiday photos", people["anna"]),
                        ("c_0b5e", "Bert's notes", people["bert"])])

    def with_demo_login(environ, start_response):
        asked = parse_qs(environ.get("QUERY_STRING", "")).get("as", [""])[0]
        chosen = next((uid for uid in people.values() if uid == asked), None)   # one of the demo people, nothing else
        if environ.get("PATH_INFO") == "/" and chosen is not None:
            start_response("303 See Other", [("Location", "/"), ("Set-Cookie", f"example_demo_user={chosen}; Path=/")])
            return [b""]
        if environ.get("PATH_INFO") == "/" and demo_identify(environ) is None:
            links = " · ".join(f"<a href='/?as={uid}'>{name}</a>" for name, uid in people.items())
            return page(start_response, "200 OK", f"Demo: continue as {links} (a stand-in for the gate).")
        return app(environ, start_response)

    print(f"TinySesam: {auth_url}   the application: {app_url}   (the password is DEMO_PASSWORD in this file)")
    make_server("127.0.0.1", 8001, with_demo_login).serve_forever()


def main(argv: list[str]) -> int:  # pragma: no cover — started by hand
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--demo", action="store_true", help="start a real TinySesam and this app on 127.0.0.1")
    args = parser.parse_args(argv)
    if args.demo:
        demo()
        return 0
    from wsgiref.simple_server import make_server

    from tinysesam.gate_client import GateClient, WSGIMiddleware, current_identity
    issuer, key = os.environ["TINYSESAM_URL"], os.environ["TINYSESAM_API_KEY"]

    def identify(environ: dict) -> Optional[str]:       # behind the gate: the checked Remote-Id of a browser session
        who = current_identity(environ)
        return who.id if who is not None and who.is_session() else None

    app = ExampleApp(api=http_api(issuer, key), keys=approval_token.JWKSKeys(f"{issuer}/auth/approvals/jwks.json"),
                     issuer=issuer, db_path=os.environ.get("APP_DB", "example.db"), identify=identify,
                     return_url=os.environ.get("APP_RETURN_URL", "https://app.example.com/approvals/return"))
    gate = GateClient(mode="header", trusted_proxies=["127.0.0.1", "::1"])
    make_server("127.0.0.1", 8001, WSGIMiddleware(app, gate)).serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main(sys.argv[1:]))
