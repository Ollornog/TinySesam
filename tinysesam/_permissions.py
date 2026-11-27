"""Permissions of an application (T-100, ADR-17): the name rule and the shape of one declared permission.

Pure functions, shared by the configuration check (`apps[id].permissions`) and `TinySesam.register_permissions`, so a
manifest the configuration accepts is the one the library accepts — and the other way round.

A permission is declared as

    {"name": "docs.delete", "label": {"en": "Delete documents", "de": "Dokumente löschen"},
     "description": {"en": "…", "de": "…"}, "danger": True, "suggested_roles": ["docs-admin"]}

`name` is required; `label` and `description` are a text or a mapping language → text; `danger` marks a permission
whose assignment in the panel needs a fresh confirmation; `suggested_roles` is a hint in the panel, never a grant.
"""
from __future__ import annotations

import re
from typing import Optional

#: The name rule of ADR-17: a lower-case word, then one to three dot-separated segments (`docs.read`, `docs.files.delete`).
NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$")
#: The most permissions one application declares (its manifests together).
MAX_PER_APP = 200
#: The members of one declared permission.
KEYS = ("name", "label", "description", "danger", "suggested_roles")
#: The longest label and description (characters per language) and the most suggested roles.
LABEL_MAX, DESCRIPTION_MAX, SUGGESTED_MAX = 120, 500, 20
_LANG = re.compile(r"^[a-z]{2,3}(-[A-Za-z0-9]{2,8})*$")


def _text(value, limit: int) -> Optional[dict]:
    """A text or {language: text} as {language: text} ({} for None) — or None when it is neither, too long or contains
    a control character."""
    if value is None:
        return {}
    if isinstance(value, str):
        value = {"en": value}
    if not isinstance(value, dict):
        return None
    out = {}
    for lang, text in value.items():
        if not (isinstance(lang, str) and _LANG.match(lang) and isinstance(text, str) and text.strip()
                and len(text) <= limit and not any(ord(z) < 32 or ord(z) == 127 for z in text)):
            return None
        out[lang] = text.strip()
    return out


def spec_error(spec) -> Optional[str]:
    """Why `spec` is no declared permission — None when it is one."""
    if not isinstance(spec, dict) or set(spec) - set(KEYS):
        return f"a mapping with the members {', '.join(KEYS)}"
    name = spec.get("name")
    if not isinstance(name, str) or not NAME.match(name):
        return f"name {name!r} — lower-case letters, digits, _ and -, then one to three dot-separated segments"
    if _text(spec.get("label"), LABEL_MAX) is None:
        return f"{name}: label is a text or a mapping language → text (at most {LABEL_MAX} characters)"
    if _text(spec.get("description"), DESCRIPTION_MAX) is None:
        return f"{name}: description is a text or a mapping language → text (at most {DESCRIPTION_MAX} characters)"
    if not isinstance(spec.get("danger", False), bool):
        return f"{name}: danger is true or false"
    roles = spec.get("suggested_roles", [])
    if not (isinstance(roles, list) and len(roles) <= SUGGESTED_MAX
            and all(isinstance(r, str) and r.strip() and r == r.strip() and "," not in r
                    and not any(ord(z) < 32 or ord(z) == 127 for z in r) for r in roles)):
        return f"{name}: suggested_roles is a list of at most {SUGGESTED_MAX} role names"
    return None


def manifest_error(specs) -> Optional[str]:
    """Why `specs` is no manifest (a list of declared permissions, each name once, at most `MAX_PER_APP`)."""
    if not isinstance(specs, (list, tuple)):
        return "a list of permissions"
    if len(specs) > MAX_PER_APP:
        return f"{len(specs)} permissions — at most {MAX_PER_APP} per application"
    seen = set()
    for spec in specs:
        error = spec_error(spec)
        if error:
            return error
        if spec["name"] in seen:
            return f"{spec['name']} is declared twice"
        seen.add(spec["name"])
    return None


def normalized(spec: dict) -> dict:
    """A checked declaration (`spec_error` is None) in the stored shape."""
    return {"name": spec["name"], "label": _text(spec.get("label"), LABEL_MAX) or {},
            "description": _text(spec.get("description"), DESCRIPTION_MAX) or {},
            "danger": bool(spec.get("danger", False)), "suggested_roles": list(spec.get("suggested_roles", []))}
