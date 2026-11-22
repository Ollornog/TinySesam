"""A single-file Django application behind TinySesam's gate, with `tinysesam.gate_client` (no FastAPI needed).

    pip install tinysesam django
    python examples/gate_client/django_app.py        # listens on 127.0.0.1:8082 — only the proxy may reach it

In a regular project the two pieces go to their usual places: the `WSGIMiddleware` line into `wsgi.py`
(`application = WSGIMiddleware(get_wsgi_application(), gate)`), the decorator into a module of your app. Django puts
the WSGI environ into `request.META`, so `current_identity(request)` finds the identity there. Under ASGI
(`asgi.py`) wrap the application with `ASGIMiddleware(get_asgi_application(), gate)` instead.

The proxy must remove the `Remote-*` headers from every client request and be the only way to this app
(spec/gate-client.md §2.1).
"""
import functools
import html
import secrets

from django.conf import settings

settings.configure(DEBUG=False, ALLOWED_HOSTS=["127.0.0.1", "localhost"], ROOT_URLCONF=__name__,
                   SECRET_KEY=secrets.token_urlsafe(32), MIDDLEWARE=[])

from django.core.wsgi import get_wsgi_application  # noqa: E402
from django.http import HttpResponse  # noqa: E402
from django.urls import path  # noqa: E402

from tinysesam.gate_client import GateClient, WSGIMiddleware, current_identity, guard_status  # noqa: E402

gate = GateClient(mode="header", trusted_proxies=["127.0.0.1", "::1"])


def require(role=None, session=False):
    """A view decorator: 401 without an identity, 403 without the role or (session=True) for a token request."""
    def wrap(view):
        @functools.wraps(view)
        def guarded(request, *args, **kwargs):
            status = guard_status(current_identity(request), role=role, session=session)
            if status:
                return HttpResponse(status=status, headers={"Cache-Control": "no-store"})
            return view(request, *args, **kwargs)
        return guarded
    return wrap


def home(request):
    who = current_identity(request)
    if who is None:
        return HttpResponse("Not signed in.")
    return HttpResponse(f"Signed in as <bdi>{html.escape(who.name or who.user)}</bdi> (account {html.escape(who.id)}).")


@require(role="editors")
def reports(request):
    return HttpResponse("Reports for editors.")


urlpatterns = [path("", home), path("reports", reports)]
application = WSGIMiddleware(get_wsgi_application(), gate)

if __name__ == "__main__":
    # `runserver` would serve Django's own handler, not `application`: serve it with the standard library instead.
    from wsgiref.simple_server import make_server
    make_server("127.0.0.1", 8082, application).serve_forever()
