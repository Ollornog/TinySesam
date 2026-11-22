"""Role levels (`role_levels`) and the accounts part of the admin panel (7f).

* `_role_levels`: entries from the known roles, the most specific template wins, a level is offered only when every
  role up to it is known, labels per language, malformed ladders skipped (fail closed).
* `config_check`: shape, at least two levels, templates usable and unique, no comma or control character, no overlap
  between ladders, no equally specific overlap inside one, no role claimed by two entries — errors; a ladder without
  entry, an entry missing a level role, a delegate holding only a part of a level — warnings.
* The panel gets the ladders over the roles its viewer may grant: an administrator `available_roles`, a delegate their
  scope. The server stores exactly the roles sent — a level implies nothing (headers, `has_role`).
* The panel JS (node): the level an account holds, an incomplete entry preselects nothing and keeps its roles when
  saved, a chosen level stores its full set, "—" stores none; roles outside the configuration stay ticked (the old
  editor dropped them on every save); a delegate sees only the levels they may grant; an administrator sees why a
  level is not available, in words.

Mutations in the PR description, each named next to its check.
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
from html.parser import HTMLParser

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from tinysesam import TinySesam, TinySesamConfig  # noqa: E402
from tinysesam import _role_levels as R  # noqa: E402
from tinysesam.admin import render_panel  # noqa: E402
from voraussetzung import pflicht_werkzeug  # noqa: E402


def ok(name):
    print(f"  ✓ {name}")


COLL = {"name": "collections", "label": {"en": "Collections", "de": "Sammlungen"},
        "levels": [{"name": "read", "label": {"en": "read", "de": "lesen"}, "role": "coll:{1}-read"},
                   {"name": "write", "label": {"en": "write", "de": "schreiben"}, "role": "coll:{1}"}]}
ROLES = ["coll:a", "coll:a-read", "coll:b", "coll:b-read", "coll:c-read", "coll:d", "app:wiki", "app:mail", "editor",
         "lead"]

# ---------- the pure functions ----------
assert R.split("coll:{1}-read") == ("coll:", "-read") and R.split("coll:{1}") == ("coll:", "")
assert [R.split(t) for t in ("{1}", "a{1}{1}", "a{2}", "a{1}}", "x", None)] == [None] * 6
assert R.match("coll:{1}-read", "coll:a-read") == "a" and R.match("coll:{1}", "coll:a-read") == "a-read"
assert R.match("coll:{1}", "coll:") is None and R.match("coll:{1}-read", "coll:-read") is None
# The most specific template wins: `coll:a-read` is the read role of `a`, not the write role of `a-read`.
# (Mutation: sort `_templates` by ascending literal length → red.)
assert R.assign([COLL], "coll:a-read") == (0, 0, "a") and R.assign([COLL], "coll:a") == (0, 1, "a")
assert R.assign([COLL], "editor") is None
ok("templates: one {1}, a literal part, the most specific template decides the entry")

rows = R.entries([COLL], ROLES)[0]
assert [r["key"] for r in rows] == ["a", "b", "c", "d"], rows
by = {r["key"]: r for r in rows}
assert by["a"]["own"] == ["coll:a-read", "coll:a"] and by["a"]["offer"] == [True, True]
# A level is offered only when EVERY role up to it is known: `d` has `coll:d` but no `coll:d-read` — neither level.
# (Mutation: `offer` from `own[i] in known` alone → `d` write offered → red.)
assert by["c"]["offer"] == [True, False] and by["d"]["offer"] == [False, False], by
v = R.view([COLL], ROLES, "de")
assert v[0]["label"] == COLL["label"]["de"] and v[0]["levels"] == [x["label"]["de"] for x in COLL["levels"]]
assert R.view([COLL], ROLES, "fr")[0]["levels"] == ["read", "write"]        # unknown language → en
bare = {"name": "x", "levels": [{"name": "lo", "role": "x:{1}-lo"}, {"name": "hi", "role": "x:{1}"}]}
assert R.view([bare], ["x:q"], "de")[0]["levels"] == ["lo", "hi"] and R.view([COLL], ["editor"]) == []
for broken in ({"name": "x", "levels": [{"name": "a", "role": "x:{1}"}]},                         # one level
               {"name": "x", "levels": [{"name": "a", "role": "x:{1}"}, {"name": "b", "role": "x:{1}"}]},  # twice
               {"name": "x", "levels": [{"name": "a", "role": "x:{1}"}, {"name": "a", "role": "y:{1}"}]},  # name twice
               {"name": "x", "levels": [{"name": "a", "role": "{1}"}, {"name": "b", "role": "y:{1}"}]},
               {"name": "x", "levels": [{"name": "a", "role": "x:{1}", "extra": 1}, {"name": "b", "role": "y:{1}"}]},
               {"name": "", "levels": [{"name": "a", "role": "x:{1}"}, {"name": "b", "role": "y:{1}"}]},
               {"name": "x", "label": 3, "levels": [{"name": "a", "role": "x:{1}"}, {"name": "b", "role": "y:{1}"}]},
               "x", None):
    assert R.usable([broken]) == [], broken
assert R.usable([COLL, dict(COLL)]) == [COLL]                                  # a name twice: the first counts
assert R.overlap("coll:{1}", "coll:x{1}") and R.overlap("a{1}", "{1}b") and not R.overlap("a:{1}", "b:{1}")
ok("entries from the known roles, a level offered only with all its roles, labels per language, malformed skipped")


# ---------- config_check ----------
def findings(levels, known=ROLES, delegates=None, lang="en"):
    cfg = TinySesamConfig(db_path=":memory:", lang=lang, role_levels=levels, available_roles=list(known),
                          admin_delegates=delegates or {})
    errors, warnings = cfg._findings()
    return [e for e in errors if "role_levels" in e], [w for w in warnings if "role_levels" in w]


full = ["coll:a", "coll:a-read", "coll:b", "coll:b-read", "editor"]
assert findings([COLL], full) == ([], []), findings([COLL], full)                   # the clean case: no finding
for broken in ("x", [{"name": "x", "levels": [{"name": "a", "role": "x:{1}"}]}],
               [{"name": "x", "levels": [{"name": "a", "role": "x:{1}"}, {"name": "b", "role": "x:{1}"}]}],
               [COLL, COLL]):
    e, _ = findings(broken, full)
    assert e and "at least two levels, names and templates unique" in e[0], (broken, e)
# (Mutation: `len(levels) >= 2` → `>= 1` in `_role_levels.usable` → the one-level ladder passes → red.)
e, _ = findings([{"name": "x", "levels": [{"name": "a", "role": "x:{1}-r"}, {"name": "b", "role": "x,{1}"}]}], full)
assert any("comma or a control character" in x for x in e), e
other = {"name": "teams", "levels": [{"name": "m", "role": "coll:t-{1}-m"}, {"name": "o", "role": "coll:t-{1}"}]}
e, _ = findings([COLL, other], full)
assert any("can match the same role — every role belongs to one ladder" in x for x in e), e
# (Mutation: drop the cross-ladder branch of the overlap check → red.)
e, _ = findings([{"name": "x", "levels": [{"name": "a", "role": "a{1}"}, {"name": "b", "role": "{1}b"}]}], full)
assert any("equally specific" in x for x in e), e
e, _ = findings([COLL], full + ["coll:a-read-read"])          # entry `a-read` would claim `coll:a-read` of `a`
assert any("belongs to the entry 'a-read' and to another one" in x for x in e), e
_, w = findings([COLL], ["editor"])
assert any("has no entry in available_roles" in x for x in w), w
_, w = findings([COLL], ["coll:c-read", "editor"])
assert any("entry 'c': coll:c not in available_roles" in x for x in w), w
_, w = findings([COLL], full + ["lead"], {"lead": {"roles": ["coll:a"]}})
assert any("'lead' manages coll:a but not every role below" in x for x in w), w
_, w_en = findings([COLL], ["coll:c-read", "editor"])
_, w = findings([COLL], ["coll:c-read", "editor"], lang="de")
assert len(w) == len(w_en) == 1 and w != w_en and "'c'" in w[0] and "coll:c " in w[0], (w, w_en)   # translated
try:
    TinySesam(TinySesamConfig(db_path=os.path.join(tempfile.mkdtemp(), "x.db"), available_roles=full,
                              role_levels=[{"name": "x", "levels": [{"name": "a", "role": "x:{1}"}]}]))
    raise AssertionError("a one-level ladder must stop the start")
except Exception as exc:                                        # noqa: BLE001 — the type is the library's ConfigError
    assert "role_levels" in str(exc), exc
ok("config_check: shape, two levels, unique templates, no comma, no overlap, no shared role — warnings in en/de")


# ---------- the server: stored roles are exactly the roles sent, the delegate scope as before ----------
def build():
    auth = TinySesam(TinySesamConfig(
        db_path=os.path.join(tempfile.mkdtemp(), "t.db"), csrf_enabled=False, lang="en", cookie_secure=False,
        passkey_enabled=False, base_url="https://auth.example.com", magiclink_enabled=True,
        available_roles=list(ROLES), role_levels=[COLL],
        # `coll:d` without `coll:d-read`: the delegate's page knows entry `d`, but no level of it is grantable.
        admin_delegates={"lead": {"roles": ["coll:a", "coll:a-read", "coll:b-read", "coll:d", "app:wiki"]}}))
    app = FastAPI()
    app.include_router(auth.router())
    return auth, app


def client(auth, app, uid):
    c = TestClient(app, base_url="http://testserver", follow_redirects=False)
    tok = auth.store.create_session(uid, 86400, True, "password", factors=["password"])
    now = int(time.time())
    auth.store._exec("UPDATE session SET mfa_at=?, created_at=? WHERE token_hash=?",
                     (now, now, auth.store.session_hash(tok)))
    c.cookies.set(auth.cfg.session_cookie, tok)
    return c


auth, app = build()
boss = auth.create_user("boss", password="a long probe password 4711", is_admin=True)
lead = auth.create_user("leader", password="a long probe password 4711", roles=["lead"])
member = auth.create_user("member", password="a long probe password 4711", roles=["coll:a-read"])
cb, cl = client(auth, app, boss), client(auth, app, lead)
r = cb.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["coll:b"]})
assert r.status_code == 200, r.text
m = auth.store.get_user(member)
# No implication: `coll:b` alone stays `coll:b` alone — the panel adds the lower roles, the server never does.
assert auth.user_roles(m) == ["coll:b"] and not auth.has_role(m, "coll:b-read"), auth.user_roles(m)
r = cb.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["coll:a-read"]})
assert r.status_code == 200
# A delegate: write of `b` needs `coll:b`, outside the scope → 400, nothing written; read of `b` and write of `a` fit.
r = cl.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["coll:b", "coll:b-read"]})
assert r.status_code == 400 and auth.user_roles(auth.store.get_user(member)) == ["coll:a-read"], (r.status_code, r.text)
r = cl.post(f"/auth/admin/api/users/{member}/roles", json={"roles": ["coll:a", "coll:a-read", "coll:b-read"]})
assert r.status_code == 200 and sorted(auth.user_roles(auth.store.get_user(member))) == \
    ["coll:a", "coll:a-read", "coll:b-read"], r.text


def page_const(html, name):
    return json.loads(re.search(rf"const {name}=(.*?);\s*//", html).group(1))


admin_ladders = page_const(cb.get("/auth/admin").text, "LADDERS")
lead_ladders = page_const(cl.get("/auth/admin").text, "LADDERS")
assert [e["key"] for e in admin_ladders[0]["entries"]] == ["a", "b", "c", "d"], admin_ladders
# The delegate's page knows only its scope: `a` (both levels), `b` (read only), `d` (nothing grantable); `c` is not
# in it. (Mutation: `render_panel` builds the ladders from `available_roles` for everyone → red.)
assert [(e["key"], e["offer"]) for e in lead_ladders[0]["entries"]] == \
    [("a", [True, True]), ("b", [True, False]), ("d", [False, False])], lead_ladders
assert page_const(cl.get("/auth/admin").text, "ME") == {"id": lead, "owner": False}
ok("server: stored roles = roles sent (no implication), delegate scope unchanged, the page gets the viewer's ladders")

# ---------- the panel JS in node ----------
node = pflicht_werkzeug("node", "role levels: the panel JS (stateOf, picker, collect)")


class _Scripts(HTMLParser):
    """The text of every <script> of a page — the browser's own tokenizer rules, no tag regex."""

    def __init__(self):
        super().__init__(convert_charrefs=False)
        self.found, self._open = [], False

    def handle_starttag(self, tag, attrs):
        if tag == "script":
            self._open = True
            self.found.append("")

    def handle_endtag(self, tag):
        if tag == "script":
            self._open = False

    def handle_data(self, data):
        if self._open:
            self.found[-1] += data


def panel_js(viewer, scope):
    parser = _Scripts()
    parser.feed(render_panel(auth, "/auth/admin", viewer=viewer, scope=scope))
    scripts = [s for s in parser.found if "const ACT={" in s]
    assert len(scripts) == 1
    return scripts[0].replace("tabs();users();", "")


STUBS = ("const document={cookie:'',addEventListener(){},querySelectorAll:()=>[],getElementById:i=>BOX[i]||null};\n"
         "const window={addEventListener(){}},location={hash:'',pathname:'',search:''},history={replaceState(){}};\n"
         "const fetch=async()=>({ok:true,status:200,json:async()=>[]});const tsAlert=async()=>{};\n"
         "const BOX={};\n")
# A box built from the picker's own HTML: what is checked there is what `collect` reads — so "save without touching
# anything" is checked through the real markup.
DRIVER = r"""
function boxOf(html){return {tagName:"DIV",
  querySelector:sel=>{const n=sel.match(/name="([^"]+)"/)[1];
    const m=html.match(new RegExp('name="'+n+'" value=(-?\\d+)[^>]*?checked'));return m?{value:m[1]}:null},
  querySelectorAll:()=>[...html.matchAll(/type=checkbox value="([^"]*)" checked/g)].map(m=>({value:m[1]}))}}
function pick(html,name,value){return html.replace(new RegExp('(name="'+name+'" value=)(-?\\d+)([^>]*?) checked','g'),'$1$2$3')
  .replace('name="'+name+'" value='+value+' ','name="'+name+'" value='+value+' checked ')}
const out={};
const L0=LADDERS[0];
const E=k=>L0.entries.find(e=>e.key===k);
out.state=[stateOf(E("a"),new Set(["coll:a","coll:a-read"])),stateOf(E("a"),new Set(["coll:a-read"])),
  stateOf(E("a"),new Set(["coll:a"])),stateOf(E("a"),new Set())];
const held=["coll:a","coll:b-read","app:wiki","legacy-group"];   // a: incomplete (write without read)
let html=picker("pk",held);out.html=html;
BOX.pk=boxOf(html);out.untouched=collect("pk",held).sort();
const ia=L0.entries.indexOf(E("a")),ib=L0.entries.indexOf(E("b"));
html=pick(html,"pk_0_"+ia,1);BOX.pk=boxOf(html);out.a_write=collect("pk",held).sort();
html=pick(html,"pk_0_"+ib,-1);BOX.pk=boxOf(html);out.b_none=collect("pk",held).sort();
html=pick(html,"pk_0_"+ia,0);BOX.pk=boxOf(html);out.a_read=collect("pk",held).sort();
out.chips=chips({roles:held});
process.stdout.write(JSON.stringify(out));
"""


def entry(html, key):
    """The markup of one ladder entry of the picker."""
    start = html.index(f'<div class=ent data-q="{key}">')
    ends = [i for i in (html.find("<div class=ent", start + 1), html.find("</fieldset>", start)) if i > 0]
    return html[start:min(ends)]


def run(js):
    res = subprocess.run([node, "-e", STUBS + js + DRIVER], capture_output=True, text=True, timeout=30)
    assert res.returncode == 0, res.stderr[-800:]
    return json.loads(res.stdout)


if node:
    admin_view = dict(auth.store.get_user(boss))
    out = run(panel_js(admin_view, None))
    # (Mutation: `complete:true` in `stateOf` → the incomplete entry gets a level preselected → red.)
    assert out["state"] == [{"level": 1, "complete": True}, {"level": 0, "complete": True},
                            {"level": 1, "complete": False}, {"level": -1, "complete": True}], out["state"]
    seg_a = entry(out["html"], "a")
    assert "checked" not in seg_a and "incomplete" in seg_a, seg_a         # incomplete: nothing preselected, said so
    # Saved untouched: the incomplete entry keeps `coll:a` (no silent widening), the legacy role stays — the old editor
    # sent only ticked roles of `available_roles` and dropped it. (Mutation: drop the "keep" branch of `collect` → red;
    # drop the group of roles outside the configuration from `picker` → red.)
    assert out["untouched"] == ["app:wiki", "coll:a", "coll:b-read", "legacy-group"], out["untouched"]
    assert out["a_write"] == ["app:wiki", "coll:a", "coll:a-read", "coll:b-read", "legacy-group"], out["a_write"]
    assert out["b_none"] == ["app:wiki", "coll:a", "coll:a-read", "legacy-group"], out["b_none"]
    assert out["a_read"] == ["app:wiki", "coll:a-read", "legacy-group"], out["a_read"]
    # Not available for an administrator: struck through, disabled, the reason in words (title, aria-label, text).
    seg_d = entry(out["html"], "d")
    assert seg_d.count(" disabled") == 2 and "not available: coll:d-read not in the configured roles" in seg_d, seg_d
    assert 'aria-label="d: write — not available: coll:d-read not in the configured roles"' in seg_d, seg_d
    assert "incomplete" in out["chips"] and "legacy-group" in out["chips"], out["chips"]
    ok("panel JS: level per account, incomplete kept until a level is chosen, full set per level, legacy roles stay")

    lead_view = {**dict(auth.store.get_user(lead)), "_via": "session"}
    scope = auth._delegate_scopes(lead_view)
    assert scope, "no delegate scope"
    out = run(panel_js(lead_view, scope))
    html = out["html"]
    # A delegate: only the levels they may grant — `b` shows "—" and read, no write segment at all; an entry without a
    # grantable level is gone; no admin box. (Mutation: drop the delegate branch in `picker` → red.)
    assert 'data-q="b"' in html and 'name="pk_0_1" value=1' not in html and " disabled" not in html, html
    assert 'data-q="c"' not in html and 'data-q="d"' not in html and "not available" not in html, html
    ok("panel JS: a delegate sees only the levels they may grant, no disabled ones, no entry without one")
