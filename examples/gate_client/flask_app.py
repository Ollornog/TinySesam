"""A Flask application behind TinySesam's gate, with `tinysesam.gate_client` (no FastAPI needed).

    pip install tinysesam flask
    python examples/gate_client/flask_app.py       # listens on 127.0.0.1:8081 — only the proxy may reach it

The proxy (deploy/forward-auth/Caddyfile, or Caddyfile.gate) asks TinySesam for every request and passes the identity
as `Remote-*` headers. It must remove those headers from every client request and be the only way to this app
(spec/gate-client.md §2.1). `trusted_proxies` refuses requests from any other address.

Try it without a proxy:

    curl -H 'Remote-User: anna' -H 'Remote-Groups: editors' -H 'Remote-Auth: session' -H 'Remote-Kind: user' http://127.0.0.1:8081/reports
"""
import functools
import html

from flask import Flask, abort

from tinysesam.gate_client import GateClient, WSGIMiddleware, current_identity, guard_status

gate = GateClient(mode="header", trusted_proxies=["127.0.0.1", "::1"])
app = Flask(__name__)
app.wsgi_app = WSGIMiddleware(app.wsgi_app, gate)        # every request: identity or None, never an exception


def require(role=None, session=False):
    """A view decorator: 401 without an identity, 403 without the role or (session=True) for a token request."""
    def wrap(view):
        @functools.wraps(view)
        def guarded(*args, **kwargs):
            status = guard_status(current_identity(), role=role, session=session)
            if status:
                abort(status)
            return view(*args, **kwargs)
        return guarded
    return wrap


@app.get("/")
def home():
    who = current_identity()
    if who is None:
        return "Not signed in."
    # Names may contain any character but controls: escape them, isolate bidirectional text.
    return f"Signed in as <bdi>{html.escape(who.name or who.user)}</bdi> (account {html.escape(who.id)})."


@app.get("/reports")
@require(role="editors")
def reports():
    return "Reports for editors."


@app.post("/settings")
@require(session=True)          # an API key or app password must never change settings
def settings():
    return "Saved."


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8081)
