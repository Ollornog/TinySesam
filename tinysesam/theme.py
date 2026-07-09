"""Design-Tokens der eingebauten Seiten — die einzige Stelle mit Farbwerten.

Alle eingebauten Seiten (Login, PIN, TOTP, Konto, Admin-Panel, Fehlerseiten) stylen sich
ausschließlich über diese CSS-Variablen. Wer das Aussehen ändern will, überschreibt sie in
`config.brand_css` — ein Satz Variablen re-skinnt damit *jede* Seite, ohne dass irgendwo ein
Selektor nachgebaut werden muss:

    TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-accent:#b0566f;…}")

Die Defaults hier sind das dunkle Standard-Theme.
"""

TOKENS = """
:root{
  color-scheme:light dark;
  --ts-bg:#0f1115;            /* Seitenhintergrund */
  --ts-surface:#161a22;       /* Karten, Kopfzeile, Abschnitte */
  --ts-surface-2:#1b2130;     /* aktiver Reiter */
  --ts-ink:#e6e6e6;           /* Text */
  --ts-muted:#9aa4b2;         /* Sekundärtext, Labels */
  --ts-line:#262b36;          /* Rahmen */
  --ts-line-soft:#20252f;     /* Trennlinien in Listen/Tabellen */
  --ts-link:#7dd3fc;
  --ts-field-bg:#0f1115;      /* Eingabefelder */
  --ts-field-line:#303643;
  --ts-accent:#2563eb;        /* Primärknopf */
  --ts-accent-ink:#fff;
  --ts-neutral:#374151;       /* Sekundärknopf */
  --ts-neutral-ink:#fff;
  --ts-danger:#b91c1c;        /* destruktiver Knopf */
  --ts-success:#15803d;
  --ts-chip:#22262e;          /* Badges */
  --ts-err-bg:#3a1520;   --ts-err-ink:#f87171;
  --ts-ok-bg:#12331f;    --ts-ok-ink:#4ade80;
  --ts-warn-bg:#442006;  --ts-warn-ink:#fdba74;  --ts-warn-line:#7c2d12;
  --ts-info-bg:#12283a;  --ts-info-ink:#60a5fa;
  --ts-radius:12px;
  --ts-font:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;
  --ts-mono:ui-monospace,Menlo,Consolas,monospace;
}
"""
