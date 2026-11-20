"""Design tokens of the built-in pages — the only place with color values.

All built-in pages (login, PIN, TOTP, account, admin panel, error pages) style themselves
exclusively through these CSS variables. Whoever wants to change the look overrides them in
`config.brand_css` — one set of variables re-skins *every* page, without a
selector having to be rebuilt anywhere:

    TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-accent:#b0566f;…}")

Light and dark (T-64): the class `dark` on `<html>` switches between the two sets below — the same switch the
C22 design system uses (`THEME_JS` sets it before the first paint from `localStorage.themeMode`, without a stored
choice from the system setting; the account menu of the top bar changes it). The defaults sit in the cascade
layer `tinysesam`, so every `brand_css` rule wins over them whatever its selector: a plain `:root{…}` there
holds in both modes, `html.dark{…}` / `html:not(.dark){…}` give a brand its own light and dark values.
"""
import html
from importlib import resources

#: The first `:root{…}` block is the dark standard set (the reference the C22 adapter falls back to), the second
#: the light values that differ from it. Image tokens stay the same in both: the background images are dark.
TOKENS = """
@layer tinysesam{
:root{
  color-scheme:dark;
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
:root:not(.dark){
  color-scheme:light;
  --ts-bg:#f6f7f9;
  --ts-surface:#ffffff;
  --ts-surface-2:#eef1f5;
  --ts-ink:#1b1f27;
  --ts-muted:#5a6372;
  --ts-line:#dde1e8;
  --ts-line-soft:#eceff3;
  --ts-link:#1d4ed8;
  --ts-field-bg:#ffffff;
  --ts-field-line:#c9d0da;
  --ts-neutral:#e6e9ef;
  --ts-neutral-ink:#1b1f27;
  --ts-chip:#eef1f5;
  --ts-err-bg:#fdecec;   --ts-err-ink:#b42318;
  --ts-ok-bg:#e7f5ec;    --ts-ok-ink:#166534;
  --ts-warn-bg:#fff3e2;  --ts-warn-ink:#9a3412;  --ts-warn-line:#f1c48f;
  --ts-info-bg:#e8effd;  --ts-info-ink:#1e40af;
}
}
"""


#: The built-in favicon (T-64): a rounded tile with a keyhole, the shape of the top bar's logo. A favicon cannot read the
#: page's tokens, so its two colours live here: the light accent on a light tab, a lighter blue on a dark one.
FAVICON_SVG = ("<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><style>rect{fill:#2563eb}"
               "@media(prefers-color-scheme:dark){rect{fill:#60a5fa}g{fill:#0f1115}}</style>"
               "<rect width='32' height='32' rx='8'/><g fill='#fff'><circle cx='16' cy='13' r='4.5'/>"
               "<path d='M14 15.5h4l1.4 8.5h-6.8z'/></g></svg>")

#: Optional adapter: derives every --ts-* token from the C22 design system's tokens, falling back to
#: the defaults above (tinysesam/c22.css). Inlined when `c22_stylesheet` is set; paste it into
#: `brand_css` yourself if you load C22 another way.
C22_ADAPTER = (resources.files(__package__) / "c22.css").read_text("utf-8")

# C22's own light/dark mechanism (Basecoat theme API): the class `dark` on <html>, the choice kept in
# localStorage `themeMode` ("light" | "dark"; no entry = the system setting). C22 leaves restoring it on page load
# to the app's head script — TinySesam's pages do the same, with or without C22 (T-64). No C22 code runs on them.
#: The light/dark restore for `<head>`: runs before the first paint, so nothing flashes.
THEME_JS = ("(function(){var m=null;try{m=localStorage.getItem('themeMode')}catch(e){}"
            "document.documentElement.classList.toggle('dark',m?m==='dark':"
            "matchMedia('(prefers-color-scheme: dark)').matches)})()")


def theme_head() -> str:
    """`<script>` with `THEME_JS` — first thing in every built-in page's `<head>` (the nonce comes centrally)."""
    return f"<script>{THEME_JS}</script>"


def c22_css(cfg) -> str:
    """The adapter CSS for `brand_css` position (after TOKENS, before the app's own brand_css)."""
    if not getattr(cfg, "c22_stylesheet", ""):
        return ""
    # The C22 stylesheet is a whole component library: two of its global class rules share a name with
    # TinySesam's (`.card`, `.tabs` set flex columns), and its reset takes the underline off links — which
    # would leave a link recognisable by colour alone. Put back what TinySesam's pages rely on.
    return (C22_ADAPTER + ".tsmain .card{display:block}.tsadmin .tabs{flex-direction:row}.tsmain a{text-decoration:underline}")


def c22_head(cfg) -> str:
    """`<head>` addition for `c22_stylesheet`: the app's C22 stylesheet (same origin, nonce like every own tag).
    Empty without the setting. The light/dark restore is on every page anyway (`theme_head`)."""
    sheet = getattr(cfg, "c22_stylesheet", "") or ""
    if not sheet:
        return ""
    return f'<link rel=stylesheet href="{html.escape(sheet)}">'
