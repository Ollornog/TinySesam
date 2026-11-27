"""T-100 acceptance, example Ex2 (`examples/ex2/app.py`): a Python application with TinySesam as a library — `docs.read`
and `docs.delete`, a role assigned locally, the delete button only with the permission.

Everything an operator does happens through the real admin panel routes (CSRF, a fresh session): the administrator
assigns the permissions to the roles in the permission matrix and the roles to the accounts. The application asks only
`has_permission` / `require_permission`.

 1. The manifest is registered at the start and grants nothing: nobody reads, nobody deletes.
 2. The administrator assigns `docs.read` to both roles and `docs.delete` (dangerous) to `docs-editor`, and the roles to
    two accounts — locally, in the panel.
 3. The reader sees the list without a delete button, and the delete route refuses (403) — a hidden button is no
    protection.
 4. The editor sees the button and deletes.
 5. The administrator withdraws `docs.delete` — at once the button is gone and the route refuses.
 6. An account without a role reads nothing (403).
"""
from __future__ import annotations

import importlib.util
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

from fastapi.testclient import TestClient  # noqa: E402

spec = importlib.util.spec_from_file_location("example_ex2", os.path.join(ROOT, "examples", "ex2", "app.py"))
example = importlib.util.module_from_spec(spec)
spec.loader.exec_module(example)

PW = "a long probe password 4711"


def ok(name):
    print(f"  ✓ {name}")


app, auth = example.build(os.path.join(tempfile.mkdtemp(), "ex2.db"))
ada = int(auth.create_user("ada", password=PW, is_admin=True))
rita = int(auth.create_user("rita", password=PW))
eddi = int(auth.create_user("eddi", password=PW))
nora = int(auth.create_user("nora", password=PW))


def signed_in(name):
    c = TestClient(app, follow_redirects=False)
    c.get("/auth/login")
    r = c.post("/auth/login", data={"username": name, "password": PW, "_csrf": c.cookies.get(auth.csrf_cookie_name)})
    assert r.status_code == 303, (name, r.status_code, r.text[:200])
    return c


def csrf(c):
    return c.cookies.get(auth.csrf_cookie_name) or ""


def panel(c, path, body):
    r = c.post("/auth/admin/api" + path, json=body, headers={"X-CSRF-Token": csrf(c)})
    assert r.status_code == 200, (path, r.status_code, r.text[:300])
    return r.json()


def delete(c, doc):
    return c.post(f"/docs/{doc}/delete", data={"_csrf": csrf(c)})


# 1 ──────────────────────────────────────────────────────────────────────────────────────────────────
names = {r["name"]: r for r in auth.app_permissions("docs")}
assert set(names) == {"docs.read", "docs.delete"} and names["docs.delete"]["danger"], names
assert all(not r["roles"] for r in names.values())
admin = signed_in("ada")
assert admin.get("/", headers={"Accept": "application/json"}).status_code == 403, "the admin flag alone read documents"
ok("1. the manifest is registered at the start and grants nothing — not even the administrator reads")

# 2 ──────────────────────────────────────────────────────────────────────────────────────────────────
matrix = admin.get("/auth/admin/api/permissions").json()
assert [a["id"] for a in matrix["apps"]] == ["docs"] and {"docs-reader", "docs-editor"} <= set(matrix["roles"])
for role in ("docs-reader", "docs-editor"):
    panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.read", "role": role, "granted": True})
panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.delete", "role": "docs-editor", "granted": True})
panel(admin, f"/users/{rita}/roles", {"roles": ["docs-reader"]})
panel(admin, f"/users/{eddi}/roles", {"roles": ["docs-editor"]})
assert auth.user_roles(auth.get_user(eddi)) == ["docs-editor"]
ok("2. the administrator assigns the permissions to the roles and the roles to the accounts, in the panel")

# 3 ──────────────────────────────────────────────────────────────────────────────────────────────────
reader = signed_in("rita")
page = reader.get("/")
assert page.status_code == 200 and "Quarterly report" in page.text and "id=del-" not in page.text, page.text[:400]
r = delete(reader, "d1")
assert r.status_code == 403 and "d1" in app.state.docs, r.status_code
ok("3. the reader sees the list without a delete button, and the delete route refuses (403)")

# 4 ──────────────────────────────────────────────────────────────────────────────────────────────────
editor = signed_in("eddi")
page = editor.get("/")
assert "id=del-d1" in page.text and "id=del-d2" in page.text, page.text[:400]
r = delete(editor, "d1")
assert r.status_code == 303 and "d1" not in app.state.docs, r.status_code
assert "Quarterly report" not in editor.get("/").text
r = editor.post("/docs/d2/delete")
assert r.status_code == 403 and "d2" in app.state.docs, "a delete without the CSRF token"
ok("4. the editor sees the button and deletes (with the CSRF token)")

# 5 ──────────────────────────────────────────────────────────────────────────────────────────────────
panel(admin, "/permissions/assign", {"app": "docs", "permission": "docs.delete", "role": "docs-editor", "granted": False})
assert "id=del-" not in editor.get("/").text
r = delete(editor, "d2")
assert r.status_code == 403 and "d2" in app.state.docs, r.status_code
ok("5. withdrawn in the panel: the button is gone at once and the route refuses")

# 6 ──────────────────────────────────────────────────────────────────────────────────────────────────
assert signed_in("nora").get("/").status_code == 403
assert TestClient(app).get("/", headers={"Accept": "application/json"}).status_code == 401
ok("6. an account without a role reads nothing (403); without a session 401")
