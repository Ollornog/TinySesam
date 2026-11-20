"""Design tokens of the built-in pages — the only place with color values.

All built-in pages (login, PIN, TOTP, account, admin panel, error pages) style themselves
exclusively through these CSS variables. Whoever wants to change the look overrides them in
`config.brand_css` — one set of variables re-skins *every* page, without a
selector having to be rebuilt anywhere:

    TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-accent:#b0566f;…}")

The defaults here are the dark standard theme.
"""
import html
from importlib import resources

TOKENS = """
:root{
  color-scheme:light dark;
  --ts-bg:#0f1115;            /* page background */
  --ts-surface:#161a22;       /* cards, header, sections */
  --ts-surface-2:#1b2130;     /* active tab */
  --ts-ink:#e6e6e6;           /* Text */
  --ts-muted:#9aa4b2;         /* secondary text, labels */
  --ts-line:#262b36;          /* border */
  --ts-line-soft:#20252f;     /* dividers in lists/tables */
  --ts-link:#7dd3fc;
  --ts-field-bg:#0f1115;      /* input fields */
  --ts-field-line:#303643;
  --ts-accent:#2563eb;        /* primary button */
  --ts-accent-ink:#fff;
  --ts-neutral:#374151;       /* secondary button */
  --ts-neutral-ink:#fff;
  --ts-danger:#b91c1c;        /* destructive button */
  --ts-danger-ink:#fff;
  --ts-success:#15803d;
  --ts-success-ink:#fff;
  --ts-chip:#22262e;          /* badges */
  --ts-err-bg:#3a1520;   --ts-err-ink:#f87171;
  --ts-ok-bg:#12331f;    --ts-ok-ink:#4ade80;
  --ts-warn-bg:#442006;  --ts-warn-ink:#fdba74;  --ts-warn-line:#7c2d12;
  --ts-info-bg:#12283a;  --ts-info-ink:#60a5fa;
  --ts-image-base:#050608;    /* behind the background images (brand_backgrounds) */
  --ts-image-overlay:rgba(5,6,8,.45);   --ts-image-overlay-edge:rgba(5,6,8,.75);   /* darkening on top */
  --ts-image-strength:.6;       /* opacity of the background images */
  --ts-image-brightness:.8;          /* brightness of the background images (CSS brightness) */
  --ts-radius:12px;
  --ts-font:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --ts-mono:ui-monospace,Menlo,Consolas,monospace;
}
"""


#: Optional adapter: derives every --ts-* token from the C22 design system's tokens, falling back to
#: the defaults above (tinysesam/c22.css). Inlined when `c22_stylesheet` is set; paste it into
#: `brand_css` yourself if you load C22 another way.
C22_ADAPTER = (resources.files(__package__) / "c22.css").read_text("utf-8")

# C22's own light/dark mechanism (Basecoat theme API): the class `dark` on <html>, the choice kept in
# localStorage `themeMode`, without one the system setting. C22 leaves restoring it on page load to
# the app's head script — TinySesam's pages do the same here. No C22 code runs on them.
_C22_THEME_JS = ("(function(){var m=null;try{m=localStorage.getItem('themeMode')}catch(e){}"
                 "document.documentElement.classList.toggle('dark',m?m==='dark':"
                 "matchMedia('(prefers-color-scheme: dark)').matches)})()")


def c22_css(cfg) -> str:
    """The adapter CSS for `brand_css` position (after TOKENS, before the app's own brand_css)."""
    if not getattr(cfg, "c22_stylesheet", ""):
        return ""
    # Native controls (scrollbars, date pickers) follow the C22 mode, not the dark default.
    # The C22 stylesheet is a whole component library: two of its global class rules share a name with
    # TinySesam's (`.card`, `.tabs` set flex columns), and its reset takes the underline off links — which
    # would leave a link recognisable by colour alone. Put back what TinySesam's pages rely on.
    return (C22_ADAPTER + "html:not(.dark){color-scheme:light}html.dark{color-scheme:dark}"
            ".tsmain .card{display:block}.tsadmin .tabs{flex-direction:row}.tsmain a{text-decoration:underline}")


def c22_head(cfg) -> str:
    """`<head>` additions for `c22_stylesheet`: the app's C22 stylesheet (same origin, nonce like every
    own tag) and the light/dark restore. Empty without the setting."""
    sheet = getattr(cfg, "c22_stylesheet", "") or ""
    if not sheet:
        return ""
    return f'<script>{_C22_THEME_JS}</script><link rel=stylesheet href="{html.escape(sheet)}">'
