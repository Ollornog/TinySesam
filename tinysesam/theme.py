"""Design tokens of the built-in pages — the only place with color values.

All built-in pages (login, PIN, TOTP, account, admin panel, error pages) style themselves
exclusively through these CSS variables. Whoever wants to change the look overrides them in
`config.brand_css` — one set of variables re-skins *every* page, without a
selector having to be rebuilt anywhere:

    TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-accent:#b0566f;…}")

The defaults here are the dark standard theme.
"""

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
  --ts-success:#15803d;
  --ts-chip:#22262e;          /* badges */
  --ts-err-bg:#3a1520;   --ts-err-ink:#f87171;
  --ts-ok-bg:#12331f;    --ts-ok-ink:#4ade80;
  --ts-warn-bg:#442006;  --ts-warn-ink:#fdba74;  --ts-warn-line:#7c2d12;
  --ts-info-bg:#12283a;  --ts-info-ink:#60a5fa;
  --ts-bild-grund:#050608;    /* behind the background images (brand_backgrounds) */
  --ts-bild-decke:rgba(5,6,8,.45);   --ts-bild-decke-rand:rgba(5,6,8,.75);   /* darkening on top */
  --ts-bild-staerke:.6;       /* opacity of the background images */
  --ts-bild-hell:.8;          /* brightness of the background images (CSS brightness) */
  --ts-radius:12px;
  --ts-font:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --ts-mono:ui-monospace,Menlo,Consolas,monospace;
}
"""
