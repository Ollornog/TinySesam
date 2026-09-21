---
id: B-1
type: Bug
title: Das Admin-Panel würfelt bei jedem Aufruf ein neues CSRF-Token
status: erledigt
milestone: M-1
tags: [csrf, admin, sicherheit]
created: 2026-09-21
---

# B-1 — Das Admin-Panel würfelt bei jedem Aufruf ein neues CSRF-Token

Es gibt drei Stellen, die das CSRF-Cookie setzen: `manager.render_page`, `manager.issue_csrf` und
`admin.py`. Für die ersten beiden wurde genau dieser Fehler schon einmal behoben (Commit `b6204bf`):
`render_page` würfelte bei **jedem** Rendern ein neues Token und überschrieb das Cookie — offene
Formulare wurden damit ungültig und antworteten mit **403 ohne Fehlermeldung**. Seitdem übernimmt
`render_page(..., request=request)` ein vorhandenes Cookie.

`admin.py` ist die dritte Stelle. Sie setzt bei jedem `GET` der Panel-Seite unbedingt ein frisches
Token, ohne das vorhandene anzusehen.

## Nachgestellt

Mit einer Instanz, die Login-Seite und Admin-Panel montiert hat:

1. `GET /auth/login` → Cookie `tinysesam_csrf` = **A**. Zweiter Aufruf: weiterhin **A** (richtig).
2. `GET /auth/admin` → Cookie ist jetzt **B**.
3. `POST /auth/login` mit dem Token **A** aus dem noch offenen Formular → **403**.

Gegen den Angreifer schützt das Verfahren weiterhin; getroffen wird der eigene Nutzer. In der Praxis:
zwei Reiter offen, einer davon das Panel — das Formular im anderen scheitert stumm.

## Fertig, wenn

- Das Panel ein vorhandenes, gültiges CSRF-Cookie übernimmt, statt es zu ersetzen (dieselbe
  Behandlung wie in `render_page`).
- Eine Suite deckt den dritten Setzer ab. `tests/test_cookies.py` nennt die Lücke bereits und
  verweist auf `tests/test_adminmount.py` als richtigen Ort. Steht seit 2026-09-21 in
  `tests/test_bestandsdaten.py` statt dort: `test_adminmount.py` fährt durchgehend
  `csrf_enabled=False` — eine CSRF-Prüfung darin hätte entweder die ganze Suite umgestellt oder
  als einzelner Fremdkörper mit eigener Config dagestanden.
- Der Regressionstest prüft den **rohen** `Set-Cookie`-Header, nicht den Cookie-Jar: Der verschluckt
  Attribute und legt Secure-Cookies über `http://` gar nicht erst ab.

## Erledigt (2026-09-21, mit [T-9](T-9-audit-2026-09-21-runde-2.md))

Vorgezogen von M-2 nach M-1: Der Eintrag trägt `tags: [csrf, admin, sicherheit]`, und M-1
verlangt seit der Reifeprüfung ausdrücklich *keine offenen Sicherheitsbefunde*. Ein
Sicherheitsbefund auf „nach 1.0" zu legen, während 1.0 keine offenen verlangt, widerspricht sich.

Dazu war die Lage inzwischen schlechter als bei der Meldung: Die Sicherheitsfixes von T-8 haben
vier weitere Routen und **jede** nicht-lesende Methode des Panels unter CSRF gestellt — die
Token-Rotation traf damit mehr Wege als vorher.

`admin.py` übernimmt jetzt ein vorhandenes Cookie, statt bei jedem Aufruf eines zu würfeln —
dieselbe Behandlung wie in `render_page`. Gemessen: Login-Seite setzt Token A, Panel-Aufruf
setzt **kein** neues Cookie mehr, und der POST aus dem anderen Reiter antwortet wieder mit 200
statt 403.
