"""The shared helpers of the configuration rules: the finding text in the configured language (`_t`, German from
`_config_check_de._DE`), reading a field (`_an`, `_integer`), host and frame checks (T-112).

A leaf for `config_check` and its parts: neither imports back here, so there is no import cycle.
"""
from __future__ import annotations

from ._config_check_de import _DE


def _urlsplit_host(url: str) -> str:
    """The host of an address, without port and without the brackets of an IPv6 literal."""
    from urllib.parse import urlsplit
    return (urlsplit(url).hostname or "").lower()


def _topbar_link_findings(config, f: str, links, hosts: set, roles_known: set, error: list, warnings: list,
                          frame: bool = False) -> None:
    """The checks of one top bar link field (`topbar_links`, `topbar_menu_links`, `forward_apps[host]['links']` —
    named by `f` in the findings): shape, visibility, target. `frame`: the links of an app frame (T-91), whose
    targets lie on exactly the application's host (`hosts` = that one host)."""
    links = links or []
    if not isinstance(links, (list, tuple)):
        links = [links]
    for link in links:
        if (not isinstance(link, (list, tuple)) or len(link) not in (2, 3) or not isinstance(link[0], str)
                or not 1 <= len(link[0].strip()) <= 60 or not isinstance(link[1], str)
                or any(z < " " or z == "\x7f" for z in link[0])):
            error.append(_t(
                config,
                "{f}: {v!r} — each entry is a (title, target) pair with a title of 1–60 characters",
                f=f, v=link))
            continue
        # Visibility (T-76): a third element {"admin": True} or {"role": "…"} — exactly one of them. Anything else
        # would hide the link from everyone (topbar.link_visible is fail-closed) without saying why.
        if len(link) == 3:
            rule = link[2]
            admin_rule = isinstance(rule, dict) and set(rule) == {"admin"} and rule["admin"] is True
            role_rule = (isinstance(rule, dict) and set(rule) == {"role"} and isinstance(rule["role"], str)
                         and bool(rule["role"].strip()))
            # T-103: a permission of one application — the same answer the target's `require_permission` gives.
            permission_rule = (isinstance(rule, dict) and set(rule) == {"permission", "app"}
                               and isinstance(rule["permission"], str) and isinstance(rule["app"], str))
            if not (admin_rule or role_rule or permission_rule):
                error.append(_t(
                    config,
                    "{f}: {v!r} — the visibility is {{\"admin\": True}}, {{\"role\": \"name\"}} or "
                    "{{\"permission\": \"app.name\", \"app\": \"id\"}}",
                    f=f, v=link))
                continue
            if permission_rule:
                from ._permissions import NAME as _permission_name
                apps = getattr(config, "apps", None)
                if not _permission_name.match(rule["permission"]) or not (
                        isinstance(apps, dict) and rule["app"] in apps):
                    error.append(_t(
                        config,
                        "{f}: the link {title!r} names the permission {perm!r} of the application {app!r} — the "
                        "name must follow the permission rule and the application must stand in apps, or nobody "
                        "would ever see the link",
                        f=f, title=link[0], perm=rule["permission"], app=rule["app"]))
                    continue
            if role_rule and rule["role"] not in roles_known:
                warnings.append(_t(
                    config,
                    "{f}: the link {title!r} is shown only to the role {role!r}, which is not in "
                    "available_roles — a typo hides it from everyone. List the role in available_roles.",
                    f=f, title=link[0], role=rule["role"]))
        href = link[1]
        if not _frame_target_ok(href, hosts):
            if frame:
                error.append(_t(
                    config,
                    "{f}: {h!r} — a target of the app frame is a path (\"/spaces\", on this host) or an https "
                    "address on exactly this host, without quotation marks, angle brackets, backslash and spaces",
                    f=f, h=href))
                continue
            error.append(_t(
                config,
                "{f}: {h!r} — a target is a path on the own origin (\"/wiki\") or an https address on "
                "the host of base_url or of trusted_redirect_hosts, without quotation marks, angle brackets, "
                "backslash and spaces",
                f=f, h=href))


def _frame_target_ok(href, hosts: set) -> bool:
    """A link target of the top bar or the app frame: a path (not `//`) or an https address on one of `hosts`, without
    quotation marks, angle brackets, backslash and white space (the bar writes it into a single-quoted attribute)."""
    if not isinstance(href, str):
        return False
    bad = not href or any(z in href for z in "'\"<>\\ \t\n\r")
    if bad:
        return False
    if href.startswith("/") and not href.startswith("//"):
        return True
    if href.startswith("https://"):
        try:
            return _urlsplit_host(href) in hosts and "@" not in href.split("/", 3)[2]
        except ValueError:
            return False
    return False


def _t(config, template: str, **values) -> str:
    """Finding text in the language of `config.lang`: English (default) or German.

    `template` is the English text with named placeholders (`str.format`); for `lang == "de"` the
    German template with the same key is taken from `_DE` (fallback: English if the key is missing).
    Literal braces in a template are written doubled (`{{` / `}}`)."""
    if getattr(config, "lang", "en") == "de":
        template = _DE.get(template, template)
    return template.format(**values)


def _an(config, slot: str) -> bool:
    return bool(getattr(config, slot, False))


def _integer(config, slot: str, missing: int | None = 0):
    """Read a number field for a combination check — or None if it is not an integer.

    Type and range are reported by `_number_limits` (including `True`, text, `inf`, `nan`); the combination
    is then not evaluated. An `int()` on the raw value crashed the whole check
    before the type message came, and `TinySesam(cfg)` raised ValueError/OverflowError instead of a
    collected ConfigError (second attack round, config)."""
    value = getattr(config, slot, missing)
    if value is None:
        return missing
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return value
