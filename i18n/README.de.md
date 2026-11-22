<p align="center"><img src="../docs/wizard.png" alt="TinySesam" width="250" height="250"></p>

<h1 align="center">TinySesam</h1>

<p align="center"><a href="../README.md">English</a> · <b>Deutsch</b></p>

<p align="right">
<a href="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml"><img src="https://github.com/Ollornog/TinySesam/actions/workflows/ci.yml/badge.svg" alt="tests"></a>
<a href="../LICENSE"><img src="https://img.shields.io/badge/License-MIT-informational.svg" alt="License: MIT"></a>
<img src="https://img.shields.io/badge/python-3.13%2B-blue.svg" alt="Python">
</p>

### Der Login-Mechanismus für deine selbstgebauten Apps.

Ein **super-leichtes Auth für FastAPI**, bei dem du **nur nutzt, was du brauchst** — und das mit dir mitwächst.
Eine Klasse davorhängen, fertig: Login-Seite, Sessions und Route-Guards inklusive.

- **Nur eine Seite mit einer PIN sichern?** → geht. (`require_resource("photos")`, ganz ohne Benutzerkonto)
- **Forward-Auth vor fremde Apps hängen, wie TinyAuth?** → kann er. (`/auth/forward` bzw. OIDC-Gateway)
- **Ein Admin-Panel?** → eingebaut. **Lieber in dein eigenes einbauen?** → auch das (nur JSON-API).
- **Von „Passwort reicht" bis „OIDC → Passwort → TOTP"?** → wächst mit — jedes Stück **optional, an/aus per Config**.
- **Eigenes Look & Feel?** → das komplette **Frontend ist austauschbar** (`auth.set_template(...)`), inkl. Sprache (en/de).

> **Kurz zur Einordnung:** TinySesam sichert **deine eigenen (selbstgebauten) Apps** und **nutzt** dabei vorhandene
> IdProvider (OIDC, SAML, LDAP/AD) als *Client / Relying Party*. Es ist **selbst kein Identity Provider** — also
> **kein Ersatz** für Keycloak/Authentik/PocketID, sondern die schlanke Auth-Schicht **davor bzw. in** deiner App.

**Anmelde-Methoden — beliebig kombinierbar:**
- 🔑 **Passkey / WebAuthn** (passwortlos, phishing-resistent)
- 🔐 **Passwort** (argon2, mit stdlib-scrypt-Fallback)
- 🔢 **PIN** (persönliche PIN pro User, eigener strenger Lockout)
- 🌐 **OIDC** (generischer IdProvider: PocketID, Keycloak, Entra/Azure AD, …)
- 🪪 **SAML 2.0** (SP-Login gegen ADFS, Okta, Keycloak, …)
- 🗂️ **LDAP / Active Directory** (Passwort gegen Verzeichnis-Bind)
- ✉️ **Magic-Link** (Einmal-Login per E-Mail — oder vom Admin ausgegeben, ohne Mailer)
- 📱 **Geräteübergreifende Anmeldung** (QR-Code oder Kurzcode, bestätigt auf einem schon angemeldeten Gerät)
- 📱 **TOTP** als 2. Faktor *on-top* (+ **Recovery-Codes**; Passkeys gelten schon als vollwertig)

**Kombinierbar in Reihenfolge:**
beliebige **Faktor-Ketten** (`login_chain=["oidc","password"]`),
global oder per Route (`Depends(auth.require(factors=[...], strict=...))`).

**Rollen sind optional:**
die meisten Apps brauchen nur „eingeloggt / nicht" (`require_user`).
Wer differenzieren will: `is_admin` + frei definierbare `roles` (`require_admin`, `require_role("editor")`).

**Mehr:**
„Angemeldet bleiben",
**Step-up** pro Route (`require(mfa=True)`),
**Selbst-Registrierung** + **Einladungen**,
**Passwort-vergessen**,
geteiltes **Ressourcen-Geheimnis** (PIN/Passphrase ohne Konto),
eingebaute **Konto-Seite** (inkl. eigener Sitzungen + Recovery-Codes),
**Forward-Auth** für fremde Apps

jedes Feature optional, per Config an/aus,
und das komplette **Frontend austauschbar** (`auth.set_template(...)`).

---

## Installation

TinySesam liegt auf **PyPI** (seit 0.19.0). Pinne die Version:

```bash
pip install "tinysesam==0.27.1"
# Kern: Passwort + TOTP. Alles: [all] — + argon2, QR, OIDC, Passkey
pip install "tinysesam[all]==0.27.1"
# gezielt: [argon2] [qr] [oidc] [saml] [ldap] [passkey] [redis] [gateway]
```

Jedes Release geht aus seinem Git-Tag nach PyPI, per Trusted Publishing (ohne Token), und jede
Datei trägt eine PEP-740-Beglaubigung des Commits, aus dem sie gebaut ist. Dieselbe Fassung
installiert sich auch direkt vom Tag:

```bash
pip install "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@v0.27.1"
```

Ohne `@v…` kommt statt einer freigegebenen Fassung der bewegliche Hauptzweig — das gehört in ein
Experiment, nicht in einen Betrieb.

**Einen Commit zwischen zwei Releases testen** (`@<sha>`): Er trägt die Version des letzten Releases, pip meldet also
„already satisfied“ und behält den installierten Code. Erzwingen — mit den Abhängigkeiten, damit ein Commit, der ein
Extra oder eine Abhängigkeit hinzufügt oder ändert (oder ein Wechsel auf `[all]`), mitbringt, was er braucht:

```bash
pip install --force-reinstall "tinysesam[all] @ git+https://github.com/Ollornog/TinySesam.git@<sha>"
```

Schneller, wenn sich weder Extras noch Abhängigkeiten ändern: `--no-deps` anhängen (nur das Paket wird ersetzt).

## Quickstart

```python
from fastapi import FastAPI, Depends
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(
    db_path="app.db",
    # Öffentliche Adresse dieser App. Pflicht, sobald ein Link sie verlässt —
    # die OIDC-Redirect-URI unten ist so einer. Sonst bliebe als Quelle nur der
    # Host-Header der Anfrage, und den setzt der Anfragende: Der Konstruktor
    # bricht lieber ab, als zu raten.
    base_url="https://app.example.com",
    rp_id="app.example.com",           # Domain (WebAuthn), ohne Schema/Port
    origin="https://app.example.com",  # exaktes Browser-Origin
    passkey_enabled=True,
    oidc_enabled=True,
    oidc_issuer="https://id.example.com",
    oidc_client_id="…", oidc_client_secret="…",
))
auth.ensure_admin("admin", "startpasswort")   # legt Admin an, NUR wenn der Store leer ist

app = FastAPI(lifespan=auth.lifespan)           # geordnetes Herunterfahren, siehe unten
app.include_router(auth.router())              # /auth/* + Login-UI

@app.get("/")
def home(user = Depends(auth.require_user)):    # geschützt: eingeloggt (inkl. 2FA)
    return {"hi": user["username"]}
```

Nicht-eingeloggte Browser werden auf `/auth/login` umgeleitet; API-Clients (Accept ≠ HTML) bekommen `401`.

**Herunterfahren.** TinySesam verschickt Mails und Hinweise aus Hintergrund-Workern, die in seine Datenbank schreiben.
`auth.close()` nimmt keine neuen Hintergrundjobs mehr an, lässt die wartenden zu Ende laufen (Frist `timeout`, 10 s)
und schließt dann die Datenbank — idempotent, `False`, wenn bei Fristende noch ein Job lief (die Datenbank bleibt dann
offen). `auth.lifespan` ruft es beim Herunterfahren von FastAPI auf; mit eigenem Lifespan verschachteln
(`async with auth.lifespan(app): yield`); in einem Skript oder Test `with TinySesam(cfg) as auth:`. Nie
`auth.store.db` selbst schließen: Ein Worker, der gerade in SQLite steckt, bringt den Prozess zum Absturz.

## Login-Kennung

Womit man sich anmeldet, ist ein Config-Feld — `login_identifier`:

```python
TinySesamConfig(login_identifier="both")      # Benutzername ODER E-Mail im selben Feld (Default)
TinySesamConfig(login_identifier="username")  # nur Benutzername
TinySesamConfig(login_identifier="email")     # nur E-Mail
```

Die Beschriftung des Feldes zieht automatisch nach, Passwort- **und** PIN-Login halten sich daran.
Weil die E-Mail eine Login-Kennung ist, wird sie kanonisch gespeichert (getrimmt, klein) und ist
**eindeutig** — über Benutzernamen *und* Adressen (eine Kennung gehört nie zwei Konten, auch nicht als
`Alice`/`alice`), von der Datenbank erzwungen; Konten ohne Adresse bleiben erlaubt. Bei der Registrierung
ist sie standardmäßig Pflicht — `signup_require_email=False` schaltet das ab. Im Modus `"email"`
fällt das Benutzernamen-Feld ganz weg: die Adresse *ist* die Kennung. `signup_verify_email=True`
aktiviert das Konto erst nach Klick auf den Bestätigungslink; das braucht einen Mailer (`set_mailer`
oder SMTP-Config) und verweigert sonst die Registrierung, statt die Prüfung still zu überspringen.

## Guards

```python
Depends(auth.require_user)             # eingeloggt — mehr braucht der einfachste Fall nicht
Depends(auth.require_admin)            # eingeloggt + is_admin
Depends(auth.require_role("editor"))   # eingeloggt + Rolle (Admin hat implizit alle)
Depends(auth.require_role("a", "b"))   # eine der beiden genügt
```

Ohne Guard liefert `auth.current_user(request)` das angemeldete Konto — aus einer Sitzung
**oder** einem API-Key — oder `None`, und leitet nie um: für eine Seite, die angemeldet nur
anders aussieht. Eine Route, die *auf die Sitzung wirkt* (einen Faktor anwendet, sie auffrischt
oder beendet), nimmt das Konto stattdessen aus `auth.session_user(request)`, das für einen Key
nie antwortet ([Stufe B](#öffentliche-api-drei-stufen)).

## Rollen & Gruppen

**Rollen sind die Gruppen** — pro User eine Liste (`roles`) + `is_admin`; Guard `require_role("…")`.
Mehrere nennen und **eine davon genügt** — `require_role("redaktion", "lektorat")`, oder aus der Config
`require_role(cfg.erlaubte_rollen)`. Das ist dasselbe ODER wie `?roles=a,b` im Forward-Auth; die Frage
„wer darf durch?" bedeutet damit in beiden Betriebsmodi dasselbe. Wer **alle** verlangt, stapelt die
Guards: `@app.get(…, dependencies=[Depends(auth.require_role("a")), Depends(auth.require_role("b"))])`.
Ein Admin erfüllt dabei **jede** Rolle. Wer das nicht will (z.B. weil die Rechte an einer IdP-Gruppe
hängen): `admin_implies_roles=False` global oder `require_role("editor", admin_implies=False)` je Route.
Innerhalb einer Route stellt `auth.has_role(user, "editor")` dieselbe Frage als `bool` — dieselbe
Admin-Regel, derselbe Schalter `admin_implies=False`.
- **Lokale User/Passwort:** Rollen im **Admin-Panel** je User zuweisen. `available_roles=[…]` definiert bekannte
  Rollen → das Panel zeigt sie als **Checkboxen** (leer = Freitext-Eingabe).
- **IdP-User (OIDC/SAML/LDAP/AD):** externe Gruppen automatisch auf lokale Rollen mappen —
  `oidc_group_role_map` / `saml_group_role_map` / `ldap_group_role_map`, z.B.
  `{"editors": "editor", "cn=admins,ou=g": "__admin__"}` (Ziel `__admin__` = Admin-Flag). Beim Login gesetzt;
  gemappte Rollen werden synchronisiert, manuell vergebene bleiben. Überall dieselben `require_role(...)`-Guards.
  **PocketID** (und andere Provider, die Claims an Scopes binden) schickt den Claim `groups` nur,
  wenn der Scope `groups` angefordert wird — also aufnehmen: `oidc_scopes="openid profile email groups"`
  (Gateway: `TINYSESAM_OIDC_SCOPES`). Ohne ihn weist `oidc_allowed_groups` jeden ab, und das
  Rollen-Mapping vergibt nichts; der Start warnt. TinySesam fordert den Scope nicht selbst an
  (Entra ID etwa lehnt ihn ab und schickt Gruppen als „optional claim").

## Konten im Code

`auth.create_user(…)` legt ein Konto an und gibt seine ID zurück. Es prüft dasselbe wie jeder
andere Weg — die Kennung muss über Benutzernamen *und* Adressen hinweg frei sein, sonst
`ConfigError` (`e.field`, `e.owner_id` sagen, was kollidierte):

```python
uid = auth.create_user("alice", email="alice@example.com", roles=["editor"])  # ohne Passwort: OIDC, Link, …
auth.create_user("bob", password=os.environ["BOB_START"], display_name="Bob")
```

`ensure_admin(…)` ist für den ersten Admin, `create_service(…)` für Maschinenkonten
([API-Keys](#api-keys--service-daemon-accounts)).

**Ein Konto als Betreiber sperren** — dasselbe wie „Sperren“ im Panel, das diese Methode ruft:

```python
auth.set_disabled(uid, True)     # beendet die Sitzungen, widerruft die API-Keys, verwirft offene Links
auth.set_disabled(uid, False)    # entsperrt; widerrufene Keys bleiben widerrufen
```

Die Sperre trägt den Betreiber-Vermerk: Kein Bestätigungslink hebt sie auf, auch keiner, der erst
danach entsteht. Ein Owner lässt sich nicht sperren (`StateError`); eine unbekannte ID gibt `False`.
Bis 0.21.x zeigte die Doku dafür `auth.store.set_disabled(uid, True, durch_betreiber=True)` — das
setzte nur den Vermerk, Sitzungen, Keys und Links blieben gültig.

**In den Tests deiner App** brauchst du einen angemeldeten Client ohne den Umweg über den Login.
`start_session` legt eine Sitzung an, **ohne irgendetwas zu prüfen** — genau deshalb gehört es in
Tests (oder hinter einen Faktor, den du selbst geprüft hast), nie in eine Login-Route (die nimmt
[`login_password`](#eigene-login-seite)):

```python
token, _ = auth.start_session(uid, "oidc")
client.cookies.set(auth.session_cookie_name, token)
```

`session_cookie_name`, `csrf_cookie_name` und `resource_cookie_name` tragen das Präfix `__Host-`,
wo der Browser es erlaubt — auslesen, nicht ausschreiben.

## Routen (vom Router bereitgestellt)

| Route | Zweck |
|---|---|
| `GET/POST /auth/login` | Passwort-Login + Login-Seite (zeigt aktive Methoden) |
| `GET/POST /auth/totp` | 2. Faktor nach Passwort/OIDC |
| `GET/POST /auth/totp/setup` · `POST /auth/totp/setup/start` · `POST /auth/totp/disable` | TOTP einrichten/abschalten (das Geheimnis entsteht erst im `…/start`-POST) |
| `GET /auth/oidc/start` · `/auth/oidc/callback` | OIDC-Flow *(wenn aktiviert)* |
| `POST /auth/passkey/{register,login}/{begin,finish}` | WebAuthn *(wenn aktiviert)* |
| `GET /auth/passkey/list` · `POST /auth/passkey/delete` | Passkeys verwalten |
| `GET /auth/magic/{token}` | Anmelde-Link einlösen *(wenn Magic-Link aktiv)* |
| `GET/POST /auth/magic/request` | Anmelde-Link per E-Mail anfordern *(Magic-Link aktiv und `magiclink_self_request`)* |
| `POST /auth/qr/start` · `/auth/qr/status` · `/auth/qr/finish` | neues Gerät: geräteübergreifende Anmeldung öffnen, abfragen, abholen *(`qr_login_enabled`)* |
| `GET/POST /auth/qr/approve` · `POST /auth/qr/deny` | angemeldetes Gerät: bestätigen oder ablehnen *(`qr_login_enabled`)* |
| `GET /auth/setup` | Einrichtungsdurchgang nach einem Anmeldelink: einrichten, was die `login_chain` verlangt; fragt auch nach einem eigenen Passwort, wenn mit einem vom Admin gesetzten angemeldet wurde (T-46) *(`magiclink_enabled`, `qr_login_enabled` oder `password_enabled`)* |
| `GET /auth/verify/{token}` · `GET /auth/invite/{token}` | Adresse bestätigen · Einladung annehmen |
| `GET /auth/logout` · `GET /auth/me` | Abmelden · aktueller User (JSON) |

**Wer einen Faktor verwaltet, muss gerade einen erbracht haben.** `POST /auth/totp/disable`,
`/auth/totp/recovery`, `/auth/pin/set`, `/auth/pin/disable` und `/auth/passkey/delete` verlangen
eine Step-up-Bestätigung, die nicht älter ist als `stepup_max_age_sec` — sonst 403 samt
`X-TinySesam-Reauth: /auth/reauth` (Browser werden dorthin geschickt). Ein **API-Key erfüllt das
nie**: Ein maschinelles Credential erbringt keinen interaktiven Faktor und kann folglich auch
keinen abbauen. Auch `/auth/reauth` selbst antwortet einem Key mit 403 (`api.stepup_session`): Er
hat dort nichts zu bestätigen, und Key plus Passwort dürfen nicht den zweiten Faktor einer halb
fertigen Anmeldung ersetzen (behoben in 0.20.1).

**Das Einrichten von TOTP gibt die Recovery-Codes aus.** Die Bestätigung (`POST /auth/totp/setup`)
erzeugt `recovery_code_count` Codes und gibt sie einmal zurück (`recovery_codes`), zusammen mit dem
Ziel (`next` — das übergebene, sonst die Kontoseite); die eingebaute Seite zeigt sie und leitet erst
nach *Notiert — weiter* weiter. `/auth/totp/recovery` ersetzt sie später (mit Step-up).

**Wer einen Faktor ANLEGT, braucht eine interaktive Sitzung.** `GET/POST /auth/totp/setup` und
`POST /auth/passkey/register/{begin,finish}` verlangen ebenfalls eine Sitzung — ein API-Key
bekommt 403 (der Wächter ist `auth.require_session()`). Sonst richtet ein abgeflossener CI-Key
einen Faktor ein, den **er** kontrolliert: Das TOTP-Geheimnis steht im Rumpf von
`GET /auth/totp/setup`, und ein selbst registrierter Passkey ist ein vollwertiger Login — darüber
hätte der Key eine frische interaktive Sitzung und damit doch die Routen von oben.

**Der ERSTE Faktor ist ein Sonderfall.** Ein Konto ohne Passwort, PIN und TOTP (rein föderiert)
hat nichts, womit es bestätigen könnte — `stepup_options()` ist leer und die Reauth-Seite hat
kein einziges Feld. Für genau diesen Fall genügt `POST /auth/pin/set` eine **frische Anmeldung**
(nicht älter als `stepup_max_age_sec`, gemessen ab Login, `auth.login_fresh()`); das *Ersetzen*
einer PIN und das Abbauen jedes Faktors bleiben hinter `require_mfa()`.

**Kein API-Key-Weg auf diese Routen — und kein Ersatz über HTTP.** Automatik, die mit eigenem
Schlüssel eine PIN rotiert oder TOTP abschaltet, bekommt 403 mit übersetzter Begründung
(`api.needs_session` / `api.stepup_session`). Es gibt dafür weder eine Admin-Route noch ein
CLI-Kommando: im eigenen Dienst über die Python-API tun (`auth.set_pin(uid, …)`,
`auth.totp_disable(uid)`) — derselbe Code-Pfad wie in den Routen, nur ohne HTTP-Fläche.

## Anmeldung per Link und per QR-Code

Drei Wege hinein ohne Passworteingabe, alle auf demselben Einmal-Token (`magic_token`, Zweck
`login`) — also überall dieselben Regeln: einmalig, kurz gültig, und **der zweite Faktor bleibt
Pflicht**: Ein Konto mit TOTP oder Passkey muss ihn nach dem Link noch bestehen
(`magiclink_require_second_factor`, Vorgabe an). Die Anmeldung per Link zählt als Faktor `magic`.

- **Link per E-Mail** (`magiclink_enabled=True`, `magiclink_self_request=True`, ein Mailer): Die
  Login-Seite bietet „Login-Link per E-Mail“ an. Unverändert.
- **Link vom Admin, ohne Mail** (`magiclink_enabled=True`): Das Admin-Panel hat je Benutzer einen
  Knopf *Anmeldelink* (JSON: `POST <admin>/api/users/{id}/signin-link`, Body `{"ttl_min": 60}`,
  1 Minute bis `signin_link_max_ttl_min` — Vorgabe 24 h, NIST SP 800-63B-4 §4.2.2; höchstens eine Woche, bewusst
  gesetzt —, Vorgabe `magiclink_ttl_min`). Der Link wird **einmal** angezeigt, als Link
  und als QR-Code (Extra `[qr]`), zur Übergabe auf beliebigem Weg; er braucht keinen Mailer. Er
  verfällt mit den anderen offenen Links des Kontos, wenn es gesperrt oder sein Passwort
  zurückgesetzt wird. Audit `signin_link_issue` mit dem Admin als `actor=`. Im Code:
  `auth.create_signin_link(user_id, ttl_min=None, next="/")` → `{url, expires_at, qr}`.
  Die Adresse kommt **nur** aus `base_url`, nie aus dem `Host`-Header der Anfrage.
- **Links nur vom Admin:** `magiclink_self_request=False`. Dann antwortet `/auth/magic/request`
  mit 404, und die Login-Seite hat keinen Knopf „Link senden“ — Links, die der Admin oder dein Code
  ausgestellt hat, lösen weiter ein. Kein Mailer nötig (`config_check` verlangt ihn nur mit der
  Selbstanforderung).
- **Geräteübergreifend (QR-Code)** (`qr_login_enabled=True`): Das neue Gerät zeigt einen QR-Code
  und einen Kurzcode (*Mit anderem Gerät anmelden*). Auf einem Gerät, auf dem man angemeldet ist,
  scannen oder `/auth/qr/approve` öffnen und den Code eintippen: Die Seite nennt das anfragende
  Gerät (User-Agent, IP, Alter), bevor man bestätigt. Das neue Gerät bekommt dann **eine eigene**
  Sitzung. Gültig `qr_login_ttl_sec` (Vorgabe 120 s), einmalig, gedrosselt, im Audit
  (`qr_login_approve`, `qr_login_deny`, `qr_login`). Bestätigen kann nur eine volle interaktive
  Sitzung — kein API-Key, keine halbe Anmeldung. Wer nur den Code auf dem Bildschirm sieht, bekommt
  nichts: Die Sitzung geht an das Gerät, das die Anfrage geöffnet hat (es hält ein Geheimnis, das
  nie angezeigt wird). Der QR-Code braucht `base_url` und das Extra `[qr]`; ohne beides erscheint
  nur der Kurzcode. Kein Mailer nötig.
  **Gegen Consent-Phishing (H2, T-44):** Das neue Gerät zeigt zusätzlich eine zweistellige Zahl, die das
  bestätigende Gerät eintippen muss (eine falsche macht die Anfrage ungültig); die Bestätigungsseite warnt,
  verlangt eine frische Bestätigung und — mit `qr_login_require_second_factor=True` (Vorgabe) — ein Konto mit
  TOTP oder Passkey, den das neue Gerät dann ebenfalls vorlegen muss. `/auth/qr/status` ist gedrosselt.

### Rezept: Der Admin legt Konten an, ein Link meldet an

Registrierung aus, der Admin legt das Konto an (ohne Passwort), gibt einen Anmeldelink heraus, und bei
der ersten Anmeldung richtet die Person genau das ein, was deine Kette verlangt — erst dann ist sie voll
angemeldet. Danach meldet sie sich über die Kette an, der Link war nur die Tür.

```python
auth = TinySesam(TinySesamConfig(
    base_url="https://auth.example.com",
    allow_signup=False,                          # niemand registriert sich selbst
    magiclink_enabled=True,
    magiclink_self_request=False,                # Links nur vom Admin (oder deinem Code), kein Mailer
    magiclink_first_login_only=True,             # ein Link meldet nur zur ersten Anmeldung an
    login_chain=["password", "totp"],            # was jede Anmeldung braucht — und was eingerichtet wird
))
uid = auth.create_user("dana", email="dana@example.com")     # ohne Passwort
link = auth.create_signin_link(uid)["url"]                    # oder der Panel-Knopf „Anmeldelink“
```

Dana öffnet den Link → `/auth/setup`: Passwort festlegen → Authenticator-App einrichten
(Recovery-Codes einmal angezeigt) → angemeldet. Später: Passwort + TOTP, wie die Kette sagt.

**Alternativen je Kettenglied** mit `|`: `login_chain=["password|passkey"]` lässt den
Einrichtungsdurchgang Passwort *oder* Passkey anbieten; `["password|passkey", "totp|passkey"]` verlangt
zwei verschiedene Faktoren (ein Passkey zählt nie für zwei Glieder). Faktornamen: `password`, `pin`,
`passkey`, `totp`, `oidc`, `saml`, `magic`.

Die Regeln des Einrichtungsdurchgangs:

- Er öffnet sich nur bei einer Link-Anmeldung (Mail, Admin, App-Code, geräteübergreifend) eines Kontos,
  das die Kette mit seinen Faktoren nicht erfüllen kann, nur mit `login_chain` und nur, wo
  Selbsteinrichtung erlaubt ist (`mfa_enrollment`; bei `"strict"` öffnet der Betreiber ein Fenster mit
  `grant_mfa_enrollment`).
- Die halbe Sitzung kann nichts außer dem Faktor einrichten, den die Seite gerade anbietet — keine
  geschützte Route, keine Kontoseite, kein Admin, kein API-Key. Sie verfällt mit `stepup_max_age_sec`
  (gemessen ab dem Link); Sperren des Kontos oder ein Passwort-Reset beenden sie.
- Der Link ersetzt keinen Faktor, den das Konto **hat**: Ein vorhandenes Passwort (oder PIN, Passkey,
  TOTP) wird zuerst eingegeben wie bei jeder Anmeldung; der Durchgang bietet nur fehlende Faktoren an
  und ersetzt nie einen.
- Ein Konto mit TOTP oder Passkey zeigt ihn vor jeder Einrichtung (dieselbe Regel wie
  `magiclink_require_second_factor`), außer der Betreiber hat ein Einrichtungsfenster geöffnet.
- `magiclink_first_login_only=True`: Ein Link meldet nur ein Konto an, das noch nie voll angemeldet
  war, oder eines, dem ein Faktor fehlt und das ihn selbst einrichten darf. Ein fertiges Konto bekommt
  „nur für die erste Anmeldung“ — auch vom Admin. Faktor verloren? Im Panel entfernen, ein
  Einrichtungsfenster öffnen (`grant_mfa_enrollment`), dann einen Link herausgeben: Die Person gibt
  ein, was sie noch hat, und richtet den Rest ein. Die geräteübergreifende Anmeldung betrifft das
  nicht (ihre Bestätigung kommt aus einer vollen Sitzung).
- Innerhalb des Durchgangs gilt die Reihenfolge der Kette nicht (der Server gibt die Schritte vor);
  die reguläre Anmeldung danach behält `login_chain_strict`. Ohne `login_chain` ändert sich nichts:
  Der Link meldet an wie bisher.

## Konfiguration (`TinySesamConfig`, Auszug)

| Feld | Default | |
|---|---|---|
| `db_path` | `tinysesam.db` | SQLite-Store |
| `password_enabled` / `passkey_enabled` / `oidc_enabled` | `True/False/False` | aktive Methoden (Passkey ab Werk aus: `webauthn` steckt im Extra `[passkey]`) |
| `totp_enabled` | `True` | 2FA erlauben (verlangt, sobald ein Nutzer es eingerichtet hat) |
| `totp_window` | `"previous"` | aus welchen 30-Sekunden-Schritten ein Code stammen darf: laufender + voriger (RFC 6238 §5.2); `"current"`; `"previous_and_next"` = bis 0.25.x |
| `login_chain` · `stepup_strict` | `[]` · `False` | `["password","totp"]` **erzwingt** 2FA über die Faktor-Kette; Alternativen je Glied mit `\|` (`["password\|passkey"]`). Leer = klassisch: ein Erstfaktor, dazu TOTP, wo eingerichtet |
| `session_ttl_hours` · `cookie_secure` · `cookie_samesite` | `168` · `True` · `lax` | Sessions/Cookie |
| `rp_id` · `origin` | `localhost` · … | WebAuthn (echte Domain nötig, HTTPS) |
| `oidc_issuer/_client_id/_client_secret/_scopes` | – | OIDC-Provider |
| `oidc_auto_create` · `oidc_allowed_groups` · `oidc_group_claim` | `True` · `[]` · `groups` | Auto-Anlage + Gruppen-Gate |
| `base_url` · `login_redirect` · `logout_redirect` | – · `/` · … | App-Integration (`base_url` bei Mail-Wegen/OIDC/SAML **Pflicht**) |
| `cookie_domain` · `trusted_redirect_hosts` | `""` · `[]` | SSO über Subdomains · erlaubte absolute `?next=`-Ziele |
| `security_log` | `""` | Datei für den fail2ban-Logger (leer = nur an den Logger) |
| `forward_auth_enabled` · `forward_headers` | `False` · `{}` | Forward-Auth-Endpunkt · welche Header er setzt (leer = `Remote-*`) |
| `magiclink_enabled` · `magiclink_self_request` · `magiclink_ttl_min` | `False` · `True` · `10` | Anmelde-Links lösen ein · jeder darf einen per E-Mail anfordern (braucht einen Mailer; `False` = Links nur vom Admin oder App-Code) · Gültigkeit in Minuten (auch Reset-Links; bis 0.25.x `15`) |
| `signin_link_max_ttl_min` | `1440` | Obergrenze für einen Anmeldelink oder eine Einladung, die der Admin oder App-Code ausstellt (bis 0.25.x eine Woche, `10080`) |
| `invite_ttl_min` | `1440` | Gültigkeit einer Einladung ohne eigenes `ttl_min` (bis 0.25.x `magiclink_ttl_min`) |
| `magiclink_first_login_only` | `False` | ein Link meldet nur zur ersten Anmeldung an (oder um einen fehlenden Faktor einzurichten) |
| `qr_login_enabled` · `qr_login_ttl_sec` | `False` · `120` | geräteübergreifende Anmeldung (QR-Code braucht `base_url` und das Extra `[qr]`) · Gültigkeit einer Anfrage |

`TinySesamConfig` ist eine Dataclass, und das gehört zur Zusage: `dataclasses.fields(TinySesamConfig)`
zählt jedes Feld auf — praktisch, um aus eigenen Einstellungen nur die bekannten Schlüssel
weiterzureichen. Jedes Feld mit Bedeutung: [`CONFIGURATION.md`](../CONFIGURATION.md).

## Sprache (i18n)

Die eingebauten Texte sind **standardmäßig Englisch** (`lang="en"`); mitgeliefert ist auch **Deutsch**:

```python
TinySesamConfig(lang="de")                       # eingebaute Seiten + Meldungen auf Deutsch
auth.add_messages("fr", {"login.submit": "Se connecter", ...})   # eigene Sprache/Überschreibung
```
Einzelne Texte oder ganze Seiten lassen sich zusätzlich per `auth.set_template(...)` frei ersetzen.

## Eigene Login-Seite

Zwei Wege, je nachdem, was sich ändern soll:

- **Nur das Aussehen** — die Seite ersetzen, die Route behalten: `auth.set_template("login", fn)`
  ([Look & Feel](#look--feel)). Das Formular geht weiter an `POST /auth/login`, und jeder Schutz
  bleibt, wo er ist. Das ist die erste Wahl.
- **Eine eigene Route** (Single-Page-App, JSON, andere Felder) — den Baustein rufen, den die
  eingebaute Route selbst ruft: `auth.login_password(…)`. Er drosselt, zählt und sperrt genau
  wie `POST /auth/login`, denn diese Route ist nichts anderes als dieser Aufruf: CSRF-Prüfung,
  Drossel je IP, der vorab gebuchte Versuch (Fehlversuche je Kennung, je Adresse und je Paar,
  die Serien-Sperre), der LDAP-Rückfall („eine Kennung, ein Konto“; ein Ausfall ist kein
  Fehlversuch), Audit- und Sicherheits-Log (die Zeilen, die fail2ban liest), dann die Sitzung.

```python
from html import escape

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db", lang="de"))
app = FastAPI()
app.include_router(auth.router())


@app.post("/login")          # ein schlichtes `def`: FastAPI führt es im Threadpool aus
def login(request: Request, username: str = Form(""), password: str = Form(""),
          next: str = Form(""), csrf: str = Form("", alias="_csrf")):
    result = auth.login_password(request, username, password, next=next, csrf=csrf)
    if not result:           # falsch, gesperrt, gedrosselt, Verzeichnis weg …: keine Sitzung, kein Cookie
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # dein Formular
    return result.redirect()     # zum offenen Faktor (result.next_factor) oder nach next, Cookie gesetzt
```

Das Ergebnis, ein `tinysesam.LoginResult`, trägt `ok` (auch sein Wahrheitswert), `reason`
(einer aus `LoginResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `locked_series`,
`ratelimit`, `directory_down`, `method_disabled`, `no_session`), `status` (was die eingebaute
Seite antwortet: 303, 400, 401, 404, 429, 503), `message` (der übersetzte Text), `next_url` (das
geprüfte Ziel), `next_factor` (der offene Faktor, etwa `"totp"`), `done` (Sitzung vollständig)
und `user` (nur bei Erfolg). `reason` ist für Programme gedacht; mit dem Audit- und
Sicherheits-Log hat es nichts zu tun (deren Ereignisnamen, Schlüssel und Tokens sind seit Schema 15
ebenfalls englisch, aber ein eigenes Vokabular). Ein Misserfolg hat
keine Sitzung und setzt kein Cookie — wer das Ergebnis ignoriert, meldet niemanden an. Eine
JSON-Route, die lieber wirft, schreibt `if not result: raise HTTPException(result.status,
result.message)`, lässt `csrf` weg (dann zählt der Header `X-CSRF-Token`) und setzt das Cookie
mit `result.set_cookie(response)` an ihrer eigenen Antwort.
Das Sitzungs-Token ist bewusst kein Feld. Geworfen wird nur `HTTPException(403)` (CSRF, oder ein
Konto, das eben gesperrt wurde), dazu Unerwartetes — der Versuch zählt dann als Fehlversuch.

Die Schritte nach dem ersten Faktor gehen genauso: `auth.login_totp(request, code, next=…)`
nimmt einen TOTP-Code oder einen Einmal-Code, wie `POST /auth/totp`, und
`auth.login_pin(request, pin, username, next=…)` arbeitet wie `POST /auth/pin` (im
Kettenschritt oder auf einer angemeldeten Sitzung ohne `username`). `result.next_factor` sagt
deiner Seite, welcher Schritt als nächster kommt. Alle drei sind synchron (ein Passwort-Hash,
vielleicht das Verzeichnis): aus einer `def`-Route rufen, in einer `async def`-Route über
`run_in_threadpool`.

> **Ohne diese Bausteine gibt es keinen Schutz gegen Raten.** Die inneren Prüfer
> `check_password`, `check_pin`, `check_ldap`, `verify_totp` und `verify_recovery_code`
> vergleichen nur: keine Sperre, kein Zähler, keine Serien-Sperre, keine Drossel, keine Zeile für
> fail2ban. Bis 0.21.0 zeigte dieser Abschnitt `check_password` + `start_session` — eine Route
> danach lässt jeden Passwörter (oder eine vierstellige PIN, oder einen sechsstelligen Code) so
> schnell raten, wie der Server antwortet. Sie sind seit 0.22.0 [Stufe C](#öffentliche-api-drei-stufen),
> warnen beim Aufruf und fallen mit 1.0 weg; ersetzen durch `login_password`, `login_pin` und
> `login_totp`.

`start_session` bleibt, für Tests und für einen Faktor, den du selbst geprüft hast — es prüft
nichts ([Konten im Code](#konten-im-code)). Es gibt `(token, session_ok)` zurück: auspacken und das
Token mit `auth.set_cookie(response, token, remember=None)` ins Session-Cookie legen (`remember=None`
folgt der Wahl „angemeldet bleiben“ der Sitzung selbst) — wer das Tupel direkt in `set_cookie` reicht,
schreibt den String `"('abc…', True)"` ins Cookie, und es fliegt keine Ausnahme. Das von `complete_totp` zurückgegebene Token ersetzt das alte, auch
beim Step-up — es gehört ins Cookie, sonst hält das Cookie eine tote Sitzung. Die Bausteine
`login_*` erledigen beides.

Dasselbe Muster gibt es für einen eigenen Step-up ([Eigene Step-up-Seite](#eigene-step-up-seite),
`confirm_*`) und für den Passwortwechsel ([Eigene Passwortwechsel-Seite](#eigene-passwortwechsel-seite),
`change_password`).

### CSRF auf eigenen Seiten

Jedes Formular, das die App selbst rendert, braucht das Token in einem versteckten Feld `_csrf`
(bei `fetch` im Header `X-CSRF-Token`), und der Browser braucht das passende Cookie.
Das CSRF-Cookie ist absichtlich **nicht** `HttpOnly` (Double-Submit: Das JavaScript der Seite liest es und sendet
`X-CSRF-Token`). Das ist keine Schwäche: Es ist kein Zugangsnachweis, sondern ein Wert, den eine fremde Herkunft nicht
lesen kann. Das Sitzungs-Cookie bleibt `HttpOnly`. Meldet ein Scanner „Cookie ohne HttpOnly“ für dieses Cookie, ist das
erwartet.
`auth.ensure_csrf(request, response)` erledigt beides: Ein gültiges Token, das der Browser schon
hat, bleibt — die Formulare in anderen Reitern gelten weiter, und die Antwort bekommt kein
`Set-Cookie` —, sonst setzt es ein neues, mit denselben Attributen wie `issue_csrf()`. Zurück kommt
das Token fürs Formular.

```python
@app.get("/einstellungen", response_class=HTMLResponse)
def einstellungen(request: Request, response: Response, user=Depends(auth.require_user)):
    csrf = auth.ensure_csrf(request, response)          # FastAPI übernimmt das Cookie
    return templates.get_template("einstellungen.html").render(
        csrf=csrf, csrf_cookie=auth.csrf_cookie_name)
```

Bei einer fertigen Antwort (Jinjas `TemplateResponse`) das Token vor dem Rendern holen und das
Cookie danach an die Antwort geben — in derselben Anfrage liefern beide Aufrufe dasselbe Token:

```python
csrf = auth.csrf_token(request)
resp = templates.TemplateResponse(request, "einstellungen.html",
                                  {"csrf": csrf, "csrf_cookie": auth.csrf_cookie_name})
auth.ensure_csrf(request, resp)
return resp
```

Im Template — JavaScript kann keine Python-Property lesen, also reicht die Seite den Cookie-Namen
mit (oder das Skript nimmt den Wert aus dem Feld `_csrf`):

```html
<meta name="csrf-cookie" content="{{ csrf_cookie }}">
<form method="post" action="/einstellungen">
  <input type="hidden" name="_csrf" value="{{ csrf }}">
</form>
<script>
  function csrf() {            // beim Senden lesen: eine Anmeldung in einem anderen Reiter ändert das Cookie
    const name = document.querySelector('meta[name="csrf-cookie"]').content;
    const paar = document.cookie.split("; ").find(c => c.startsWith(name + "="));
    return paar ? paar.slice(name.length + 1) : "";
  }
  fetch("/einstellungen", {method: "POST", headers: {"X-CSRF-Token": csrf()}});
</script>
```

Die empfangende Route prüft mit `auth.require_csrf(request, wert)` — Formularfeld oder Header:
403, wenn der Wert nicht zum Cookie passt oder die Anfrage von fremder Herkunft kommt.

Das Cookie heisst `__Host-tinysesam_csrf`, wo der Browser das Präfix zulässt, sonst
`tinysesam_csrf` — nie fest eintragen. Ein Cookie-Wert, der nicht wie ein Token aussieht (fremde
Zeichen, zu kurz, zu lang), wird ersetzt statt in ein Formular übernommen. `issue_csrf(response)`
würfelt immer ein **neues** Token und entwertet damit die Formulare in allen anderen Reitern — es
ist zum bewussten Erneuern da, nicht zum Rendern einer Seite.

**Anmelden und Abmelden wechseln das Token.** Jede Anmeldung — jeder eingebaute Weg und eine eigene
Route mit `login_*` (oder `start_session` + `set_cookie`) — setzt in derselben Antwort ein
frisches Token, `auth.logout()` löscht es. Ein Formular, das in derselben Antwort entsteht, geht nur
mit dem Antwortparameter (erstes Beispiel): Es holt sein Token *nach* `set_cookie`/`logout` aus
`ensure_csrf(request, response)`. Eine fertige Antwort (zweites Beispiel) ist gerendert, bevor
`set_cookie`/`logout` das Token wechselt — ihr Formular trägt das alte, jedes Absenden endet mit
403. Eine Antwort, die an- oder abmeldet, rendert deshalb so kein Formular, sondern leitet um (303);
die Folgeanfrage rendert mit dem neuen Cookie, wie bei den eingebauten Anmeldungen. Ein Step-up
(`/auth/reauth`, `rotate_session`) behält das Token.

## Look & Feel

Jede eingebaute Seite (Login, PIN, TOTP, Konto, Admin-Panel, Fehlerseiten) stylt sich über **einen Satz
CSS-Variablen** — kein Selektor muss je Seite nachgebaut werden. In `brand_css` überschreiben, fertig:

```python
TinySesamConfig(brand_css=":root{--ts-bg:#f6f1ec;--ts-surface:#fbf8f4;--ts-ink:#2b2a3a;--ts-accent:#b0566f}")
```

Die Tokens (und ihre Defaults) stehen in [`tinysesam/theme.py`](../tinysesam/theme.py); `brand_head` hängt
zusätzliches `<head>`-Markup ein, `brand_icon` setzt das Favicon (und das Logo der Kopfleiste) auf jeder eingebauten
Seite.

**Hell und Dunkel.** Die Seiten haben einen hellen und einen dunklen Satz und schalten über die Klasse `dark` am
`<html>` um — derselbe Schalter wie in C22: Die Wahl steht in `localStorage.themeMode` (`light`/`dark`; keine = die
Systemeinstellung) und wird im `<head>` vor dem ersten Zeichnen gesetzt, nichts blitzt auf. Die Defaults liegen in
der Kaskadenebene `tinysesam`, dein `brand_css` gewinnt also immer: ein schlichtes `:root{…}` gilt in beiden Modi,
`html.dark{…}` / `html:not(.dark){…}` geben deiner Marke eigene helle und dunkle Werte.

**Kopfleiste.** Kontoseite, Admin-Panel sowie Einrichtungs-, Reauth- und Zustimmungsseiten tragen eine Leiste: links
das Anwendungslogo (`brand_icon`, wenn es ein Pfad auf dem eigenen Ursprung oder eine `data:image/…`-Adresse ist,
sonst ein eingebautes Zeichen in `--ts-accent`), der Name (`gate_brand` oder `rp_name`) und deine Links; rechts das
Kontomenü — Kontoname, deine Menü-Links, *Konto*, *Admin-Panel* (nur für Admins), *Hell / Dunkel / System* und
*Abmelden* (ein POST mit CSRF-Feld). Anmelde- und Fehlerseiten zeigen nur Logo und Name. Auf dem Handy (unter 640 px)
wandern die Links ins Menü (vor die Menü-Links); jede Tippfläche ist mindestens 44 px hoch; das Menü folgt der Tastatur
(Escape schließt und gibt den Fokus zurück, `aria-expanded`). `brand_icon_title` gibt dem Logo-Bild einen Tooltip
(`title`, maskiert, höchstens 200 Zeichen) — etwa eine Nennung `"Logo: Example Icons, CC BY 4.0"`; das wirkt nur mit
einem Bild in `brand_icon`. Ein Tooltip ist keine sichtbare Namensnennung: Verlangt eine Lizenz eine, gehört sie auf
eine Seite deiner Anwendung.

```python
TinySesamConfig(topbar_links=[("Wiki", "/wiki"), ("Dateien", "https://files.example.com/")],
                trusted_redirect_hosts=["files.example.com"])
```

Ein Link ist ein Pfad auf dem eigenen Ursprung oder eine https-Adresse auf einem Host, den auch ein `next=` erreichen
darf (`base_url`, `trusted_redirect_hosts`) — alles andere ist ein `ConfigError`. `topbar_enabled=False` nimmt die
Leiste weg (die Kontoseite trägt ihre Admin- und Abmelde-Links dann selbst), etwa wenn `brand_header` die Seiten schon
mit deiner Navigation umrahmt. Eigene Seiten bekommen dieselbe Leiste mit zwei Aufrufen:

```python
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, response: Response):
    nonce = secrets.token_urlsafe(16)          # die Nonce der CSP deiner Seite, falls du eine nutzt
    auth.ensure_csrf(request, response)        # das Abmeldeformular im Menü braucht das CSRF-Cookie
    return (f"<!doctype html><html><head>{auth.topbar_head(nonce=nonce)}</head><body>"
            f"{auth.topbar(request, nonce=nonce, current='/dashboard')}<main>…</main></body></html>")
```

`auth.topbar_head()` bringt die Hell/Dunkel-Wiederherstellung, die `--ts-*`-Tokens (mit `c22_stylesheet` auch Adapter
und C22-Stylesheet) und das CSS der Leiste — alles auf `.tsbar` begrenzt, der Rest deiner Seite bleibt unberührt;
`brand_css` bleibt draußen, deine `--ts-*`-Werte setzt du im eigenen Stylesheet. `auth.topbar(request)` zeichnet die
Leiste für die Sitzung dieses Requests, mit dem Mount-Präfix in jedem TinySesam-Pfad; `current` markiert den Eintrag
der gezeigten Seite.

**Wer einen Link sieht.** Ein drittes Element beschränkt einen Link auf Admins oder eine Rolle:

```python
TinySesamConfig(topbar_links=[("Doku", "/"),
                              ("Admin-App", "https://app.example.com/admin", {"admin": True}),
                              ("Team", "/team", {"role": "teamadmin"})],
                trusted_redirect_hosts=["app.example.com"], available_roles=["teamadmin", "editors"])
```

`{"admin": True}` zeigt den Link Konten mit Admin-Flag, `{"role": "…"}` Konten mit der Rolle — entschieden von
`has_role`, mit `admin_implies_roles` (Vorgabe an) sieht ein Admin also auch Rollen-Links, genau wie ihn das
`require(role=…)` des Ziels hineinlässt. Ein einfaches Paar sehen alle. Leiste, Handy-Menü und `auth.topbar(request)`
filtern gleich; Seiten ohne Kontomenü (Anmeldung, Fehler) tragen gar keinen Link, auch nicht im HTML-Quelltext. Eine
Rolle, die nicht in `available_roles` steht, ist beim Start eine Warnung (ein Tippfehler versteckte den Link vor
allen), jedes andere dritte Element ein `ConfigError`. Sichtbarkeit ist Komfort, kein Schutz: Das Ziel prüft den
Zugang selbst.

**Links im Kontomenü.** `topbar_menu_links` hat dieselbe Form, dieselben Ziele und dieselben Sichtbarkeitsregeln (eine
Prüfung, ein Filter) und setzt seine Einträge ins Kontomenü — nach *Angemeldet als …*, vor *Konto*, mit eigenem
Trenner:

```python
TinySesamConfig(topbar_menu_links=[("Meine Sammlungen", "/collections"),
                                   ("Moderation", "/mod", {"role": "moderators"}),
                                   ("App-Verwaltung", "https://app.example.com/admin", {"admin": True})],
                trusted_redirect_hosts=["app.example.com"], available_roles=["moderators"])
```

Ohne angemeldetes Konto gibt es kein Menü und damit keinen Menü-Link. Mehr als 10 Einträge sind beim Start eine
Warnung (das Menü liefe über den Rand); das Gateway liest sie aus `TINYSESAM_TOPBAR_MENU_LINKS` (dieselbe JSON-Form wie
`TINYSESAM_TOPBAR_LINKS`).

**Die Leiste als Daten.** Eine Anwendung, die ihre Leiste selbst zeichnet (nicht Python oder eigenes Design), fragt
`GET /auth/topbar.json` mit dem Sitzungs-Cookie der Anfrage und bekommt, was die Leiste diesem Konto zeigen würde:

```json
{"brand": "Example", "signed_in": true, "name": "Tara Lead",
 "links": [{"title": "Doku", "href": "/"}, {"title": "Team", "href": "/team"}],
 "menu_links": [{"title": "Meine Sammlungen", "href": "/collections"}],
 "account": {"shown": true, "href": "https://auth.example.com/auth/account"},
 "admin_panel": {"shown": false, "href": null},
 "logout": {"href": "https://auth.example.com/auth/logout"}}
```

TinySesams eigene Pfade sind absolut auf `base_url` (ohne sie relativ zum Mount-Präfix). Ohne Sitzung — auch mit
einem API-Schlüssel, der kein Kontomenü bekommt — ist `signed_in` false und es gibt keine Links (`menu_links` steht
immer da, dann `[]`). Die Antwort trägt
`Cache-Control: no-store` und `Vary: Cookie` und keinen CORS-Header: Die Seite eines anderen Ursprungs kann sie nicht
lesen. Hinter dem Gate entfernen die Proxy-Vorlagen TinySesams Cookies vor der Anwendung; eine Anwendung dort holt die
Daten deshalb vom eigenen Host, `GET /.tinysesam/topbar.json` (jede Proxy-Vorlage reicht `/.tinysesam/*` mit den
Cookies des Browsers an TinySesam) — aus dem Skript der Seite,
gleicher Ursprung. Das fertige Gateway liest die Sichtbarkeit auch
aus `TINYSESAM_TOPBAR_LINKS`: `[["Doku", "/"], ["Admin", "/admin", {"admin": true}]]`.

Eine Anwendung, die TinySesam als Bibliothek nutzt, ihre Oberfläche aber anderswo zeichnet (eine Single-Page-App, eine
Template-Engine einer anderen Sprache), bekommt dasselbe Dict von `auth.topbar_data(account)` — für
`session_user(request)` oder das Konto hinter `Remote-Id`; ein gesperrtes oder unbekanntes Konto bekommt kein Menü.
TinySesams Pfade darin sind absolut auf `base_url`; `base=` setzt ein anderes Präfix davor.

**Rezept: den Admin deiner App aus TinySesam verlinken — und zurück.** TinySesams Admin-Panel bekommt keine Reiter der
Anwendung (T-77 wurde dafür verworfen); die beiden Verwaltungen verlinken einander.
[`examples/app_admin.py`](https://github.com/Ollornog/TinySesam/blob/main/examples/app_admin.py) ist das ganze Rezept
als lauffähige App:

```python
TinySesamConfig(topbar_links=[("Start", "/"),
                              ("App-Admin", "/app-admin", {"admin": True}),          # hin: nur für Admins
                              ("Team", "/team", {"role": "teamadmin"})],             # oder die Leitung eines Teams
                available_roles=["teamadmin"])
```

1. **Hin:** Die Kopfleiste von Admin-Panel, Kontoseite und den eigenen Seiten der Anwendung (`auth.topbar(request)`)
   zeigt *App-Admin* nur Admins.
2. **Zurück:** Die Admin-Seite der Anwendung verlinkt das Panel mit der Adresse aus den Leistendaten —
   `auth.topbar_data(user)["admin_panel"]["href"]`, absolut auf `base_url`, also auch von einem anderen Host aus.
3. **Nicht in Python gezeichnet:**
   - *Serverseitig:* Die Host-Anwendung gibt `auth.topbar_data(auth.get_user(remote_id))` über einen internen Endpunkt
     an ihr Frontend — eine eigene App auf 127.0.0.1, die der Proxy nie weiterleitet (`internal` im Beispiel). Eine
     Prüfung der Client-Adresse reicht nicht: Hinter einem Proxy auf demselben Host kommt jede Anfrage von 127.0.0.1.
   - *Im Browser:* Eine Anwendung, die nur hinter dem Gate sitzt (kein TinySesam im Prozess), lässt ihre Seite
     `/.tinysesam/topbar.json` vom eigenen Host holen.

Die Ziele prüfen den Zugang selbst (`require(admin=True)`, `require(role=…)`): Ein versteckter Link ist Komfort, kein
Schloss.

**Gleicher Look wie deine App (C22).** Ist deine App mit dem Designsystem [C22](https://github.com/Ollornog/C22)
gebaut, zeig TinySesam das C22-Stylesheet, das deine App ohnehin ausliefert — Login, Kontoseite, Admin-Panel und
Fehlerseiten leiten ihre Tokens dann aus C22 ab und folgen dessen Pack und Hell/Dunkel-Umschaltung:

```python
TinySesamConfig(c22_stylesheet="/static/css/c22-vega.css")   # ein Pfad auf dem eigenen Ursprung, nichts von Dritten
```

Auf den Auth-Seiten läuft kein C22-Code, und TinySesam hängt nicht von C22 ab: Die Zuordnung ist eine optionale
CSS-Datei ([`tinysesam/c22.css`](../tinysesam/c22.css)), jeder Eintrag fällt auf TinySesams eigenen Standard zurück,
und die strenge CSP bleibt, wie sie ist (das Stylesheet trägt die Nonce der Antwort). Hell/Dunkel folgt C22s eigener
Mechanik: Klasse `dark` am `<html>`, aus `localStorage.themeMode`, sonst die Systemeinstellung. C22 anders
eingebunden? Die Datei in `brand_css` übernehmen (`tinysesam.theme.C22_ADAPTER`).

**Eigene Navigation und Fußzeile drumherum?** `brand_header` und `brand_footer` umschließen *jede*
eingebaute Seite — Login, PIN, TOTP, Konto, Admin-Panel und die Fehlerseiten. Beide nehmen HTML oder
`fn(auth) -> str`, wenn der Rumpf vom Request abhängt (Login-Status, Sprache). `auth.install_error_pages(app)` liefert Browsern gebrandete 403/404/500-Seiten,
API-Clients weiterhin JSON. Mehr als Farben nötig? Ganze Seite per `auth.set_template(...)` ersetzen.

**Dialoge.** Die eingebauten Seiten öffnen nie die Systemfenster des Browsers (`alert`/`confirm`/`prompt`). Fragen,
Hinweise und einmalig gezeigte Geheimnisse (ein neuer API-Key, neue Recovery-Codes) erscheinen in einem eigenen
Dialog — ein natives `<dialog>`, gestylt über dieselben Tokens, mit Tastatur bedienbar (Escape bricht ab, Enter
bestätigt, Tab bleibt im Dialog, der Fokus kehrt zum auslösenden Knopf zurück) und bei Geheimnissen mit einem
**Kopieren**-Knopf; fehlt die Clipboard-API (reines HTTP), ist der Text zum Kopieren mit Strg+C vorselektiert. Eine
eigene Seite (`set_template`) bekommt denselben Baustein als `ctx["dialog"]` — einmal in die Seite setzen und aus dem
eigenen Skript aufrufen:

```python
def my_account(auth, ctx):
    return f"""<!doctype html><title>Konto</title>{ctx['dialog']}
<button id=go>Key erzeugen</button>
<script>document.getElementById('go').addEventListener('click', async () => {{
  if (await tsConfirm('Neuen Key erzeugen?')) await tsSecret('Neuer API-Key', 'tsk_…', 'Nur einmal sichtbar.');
}});</script>"""

auth.set_template("account", my_account)
```

`tsAlert(text)`, `tsConfirm(text, {danger})` → `true`/`false`, `tsPrompt(text, value, {type})` → Text oder `null`,
`tsSecret(title, value, note)` und `tsCopy(value, field)` liefern jeweils ein Promise; die Nonce der strikten CSP
deckt den Block wie jeden anderen ([`tinysesam/dialog.py`](../tinysesam/dialog.py)).

## PIN und Step-up für sensible Routen

Eine PIN muss kein Weg hinein sein. `pin_login=False` hält sie von der Login-Seite fern und lässt sie
als *zusätzlichen* Faktor stehen:

```python
TinySesamConfig.local_accounts(          # nur Benutzername + Passwort, nirgends eine E-Mail
    pin_enabled=True, pin_login=False,   # eine PIN gibt es, anmelden kann man sich damit nicht
    stepup_methods=["pin"],              # sensible Routen fragen danach, auch wenn man schon drin ist
)
```

- `Depends(auth.require(mfa=True))` → die Route verlangt eine *frische* Bestätigung. `/auth/reauth`
  bietet TOTP, PIN oder Passwort an — eingeschränkt durch `stepup_methods`, sonst das, was der Nutzer
  eingerichtet hat (`auth.stepup_options(user)`). Die Frische verfällt nach `stepup_max_age_sec`.
- `Depends(auth.require(factors=["password", "pin"]))` → eine geordnete Kette pro Route. Wer schon
  eingeloggt ist, bekommt nur das fehlende Feld, nicht noch einmal die ganze Login-Seite.

**Die PIN als Weg hinein ist eine bewusste Option.** Mit `pin_enabled=True` ist die PIN in der Vorgabe
ein Erstfaktor (`pin_login=True`) — ausser eine strikte `login_chain` verlangt sie hinter einem anderen
Faktor, dann ist sie immer nur der nächste Schritt. Praktisch für eine allgemeine Seite, während eine
Detailseite mehr verlangt:

```python
@app.get("/uebersicht")                                 # die PIN genügt
def uebersicht(user=Depends(auth.require())): ...

@app.get("/details")                                    # PIN, danach das Passwort
def details(user=Depends(auth.require(factors=["pin", "password"]))): ...
```

Eine vierstellige PIN hat 10.000 Werte. Das Raten bremsen ihr eigener Zähler (`pin_max_attempts` je
Konto, die Adress-Schwelle beim `ip_attempt_factor`-fachen) und die Sperre nach Fehlversuchen in
Folge (`account_max_consecutive_failures`, siehe *Härtung*) — beide stehen im Admin-Panel direkt bei
der Login-Sperre. Nicht gewollt? `pin_login=False`.

## Eigene Step-up-Seite

`Depends(auth.require(mfa=True))` schickt Browser auf die eingebaute Seite `/auth/reauth` und
antwortet anderen Clients mit 403 samt `X-TinySesam-Reauth` ([oben](#pin-und-step-up-für-sensible-routen)).
Wer nur ihr Aussehen ändern will, ersetzt die Seite: `auth.set_template("reauth", fn)`. Eine eigene
Seite — der Dialog einer Single-Page-App, ein Formular vor einem gefährlichen Knopf — ruft den
Baustein, den die eingebaute Route selbst ruft: `auth.confirm_password(…)`, `auth.confirm_pin(…)`
oder `auth.confirm_totp(…)`. Sie drosseln, zählen und sperren genau wie `POST /auth/reauth`, denn
diese Route ist nichts anderes als dieser Aufruf: CSRF-Prüfung, eine volle Sitzung (ein API-Key
zählt nicht), nur ein Verfahren, das `stepup_options()` diesem Konto anbietet (`stepup_methods`,
`stepup_strict`), die Drossel je IP, der vorab gebuchte Versuch im eigenen Topf
(`reauth_max_attempts` — Tippfehler hier sperren nicht die Anmeldung), Audit- und Sicherheits-Log,
dann die frische Bestätigung mit neuem Sitzungs-Token.

```python
from html import escape

from fastapi import Depends, FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db", lang="de"))
app = FastAPI()
app.include_router(auth.router())


@app.get("/gefaehrlich")         # eine sensible Route: nur mit frischer Bestätigung
def gefaehrlich(user=Depends(auth.require(mfa=True))):
    return {"user": user["username"]}


@app.post("/bestaetigen")        # ein schlichtes `def`: FastAPI führt es im Threadpool aus
def bestaetigen(request: Request, password: str = Form(""), next: str = Form(""),
                csrf: str = Form("", alias="_csrf")):
    result = auth.confirm_password(request, password, next=next, csrf=csrf)
    if not result:               # falsch, gesperrt, keine Sitzung, nicht angeboten …: nichts ist frisch
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # dein Formular
    return result.redirect()     # nach next, mit dem erneuerten Sitzungs-Cookie
```

Das Ergebnis ist dasselbe `tinysesam.LoginResult` wie beim Anmelden: Bei Erfolg ist `done` wahr, und
`redirect()` bzw. `set_cookie(response)` legt das erneuerte Token ins Cookie — das alte gilt noch
`session_rotation_grace_sec` lang weiter, ohne die Frische. Bei einem Misserfolg ist nichts frisch
geworden, und `reason` sagt, warum: `missing` (leer, 400, zählt nicht), `invalid` (401), `locked`
oder `ratelimit` (429), `method_disabled` (403: diesem Konto nicht angeboten; bei leerem
`stepup_options()` hat es nichts, womit es bestätigen könnte), `no_session` (401 mit der Login-Seite
als `next_url`; 403, wenn die Anfrage statt einer Sitzung einen API-Key zeigt). `confirm_totp` nimmt
nur einen TOTP-Code, keinen Einmal-Code — wie die eingebaute Seite. Synchron, wie `login_*`.

## Eigene Passwortwechsel-Seite

Die eingebaute Route ist `POST /auth/password` (JSON mit `current` und `new`; die Konto-Seite
benutzt sie). Eine eigene Seite ruft den Baustein, den diese Route ruft:
`auth.change_password(request, current, new, csrf=…)`. Das alte Passwort ist ein Geheimnis wie am
Login, also gilt derselbe Dreiklang: die Drossel je IP, der vorab gebuchte Versuch im eigenen Topf
(`password_change_max_attempts`, je Konto — ein Tippfehler hier sperrt nicht die Anmeldung), Audit-
und Sicherheits-Log. Geprüft wird gegen das Konto der Sitzung, nie gegen einen Namen, der auf jemand
anderen auflösen könnte; danach das neue gegen die Passwortregel (`password_policy_error`). Bei
Erfolg enden die anderen Sitzungen des Kontos (die eigene bleibt), offene Adresswechsel-Links fallen
weg, und API-Keys und App-Passwörter bleiben mit Absicht gültig — `result.api_keys_active` und
`result.app_passwords_active` sagen, wie viele, damit deine Seite es auch sagen kann.

```python
from html import escape

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse
from tinysesam import TinySesam, TinySesamConfig

auth = TinySesam(TinySesamConfig(db_path="app.db", lang="de"))
app = FastAPI()
app.include_router(auth.router())


@app.post("/passwort")           # ein schlichtes `def`: FastAPI führt es im Threadpool aus
def passwort(request: Request, current: str = Form(""), new: str = Form(""),
             csrf: str = Form("", alias="_csrf")):
    result = auth.change_password(request, current, new, csrf=csrf)
    if not result:               # falsch, gesperrt, zu schwach, keine Sitzung …: nichts geändert
        return HTMLResponse(f"<p>{escape(result.message)}</p>", status_code=result.status)  # dein Formular
    keys = f" {result.api_keys_active} API-Key(s) gelten weiter." if result.api_keys_active else ""
    return HTMLResponse(f"<p>Passwort geändert, deine anderen Sitzungen sind abgemeldet.{keys}</p>")
```

Das Ergebnis ist ein `tinysesam.PasswordChangeResult`: `ok` (auch sein Wahrheitswert), `reason`
(einer aus `PasswordChangeResult.REASONS`: `ok`, `missing`, `invalid`, `locked`, `ratelimit`,
`policy`, `no_session`), `status` (was `POST /auth/password` antwortet: 200, 400, 401, 403, 429),
`message` (der übersetzte Text; bei `policy` die verletzte Regel), `api_keys_active` und `app_passwords_active`. Es braucht
eine volle Sitzung — ein API-Key zählt nicht (`no_session`, 403): Ein Maschinen-Zugang ändert nicht
das Passwort eines Menschen. Ein leeres altes Passwort ist `missing` (400) und zählt nicht als
Fehlversuch. Synchron, wie `login_*`.

**Ein Konto ohne Passwort** (per Anmelde-Link, OIDC oder Passkey angelegt) hat kein aktuelles, das es
eintippen könnte. Die Kontoseite bietet dann *Passwort setzen* ohne dieses Feld an; die Route ist
`POST /auth/password/set` (JSON mit `new`), der Baustein `auth.set_initial_password(request, new,
csrf=…)`. Statt des alten Passworts verlangt er Frische — dieselbe Regel wie beim Anlegen jedes
anderen Faktors: einen frischen Step-up, wenn das Konto schon etwas zum Bestätigen hat (TOTP, PIN;
sonst `stepup`, 403 mit `X-TinySesam-Reauth`), das Alter der Anmeldung, wenn es nichts hat
(`stepup_max_age_sec`; sonst `relogin`, 403 — neu anmelden). Dazu CSRF, die Drossel je IP, die
Passwortregel und die Audit-Zeile `password_set`. Er lehnt ab, wenn das Konto schon ein Passwort hat
(`has_password`, 409 — dafür ist `change_password` da), wenn der Passwort-Login aus ist
(`method_disabled`, 404) und bei `ldap_enabled` (`directory`, 409: ein lokales Passwort neben dem
des Verzeichnisses gälte weiter, nachdem das Verzeichnis das Konto gesperrt hat). Andere Sitzungen
enden nicht — die Antwort trägt `other_sessions`, die Seite bietet es an, wie nach einem neuen Faktor.

## Den ersten Admin bestimmen

Offene Registrierung plus „der erste Account wird Admin" ist ein Wettlauf: wer die frische Instanz
zuerst findet, gewinnt sie. TinySesam bietet deshalb zwei ausdrückliche Wege, **beide nur, solange es
keinen Admin gibt**:

```python
TinySesamConfig(admin_identifiers=["ich@example.com"])   # Allowlist, jede Login-Methode
```

- **Allowlist** — der genannte Benutzername bzw. die E-Mail wird beim nächsten erfolgreichen Login
  befördert, egal über welche Methode. Eine **Adresse** zählt dabei nur mit einem Beleg, dass sie
  dem Anmeldenden gehört; über SAML und LDAP gibt es keinen, dort befördert sie nie (s. unten).
  Danach nie wieder — auch nicht, nachdem ein Identity Provider dem letzten Admin der Instanz das
  Recht entzogen hat; TinySesam gibt dann sofort das Einmal-Token unten aus (oder `tinysesam owner`).
- **Einmal-Token** — gibt es keinen Admin, schreibt TinySesam beim Start eine Claim-URL auf
  **stderr**, wenn stderr eine Konsole ist (das Terminal des Betreibers). Anmelden,
  `/auth/claim-admin?token=…` öffnen, fertig. Das Token gilt einmal und läuft nach
  `admin_claim_ttl_min` ab; sobald ein Admin existiert, antwortet die Route mit 404. Der Wert bleibt
  bewusst aus dem Security-Log heraus — das liest fail2ban, und logrotate hebt es auf. **Ist stderr
  keine Konsole** (Container, journal, Pipe — dort *ist* stderr das Log), schreibt TinySesam das
  Token stattdessen nach `<db_path>.claim` mit `0600` und nennt im Log nur den Pfad
  (`docker exec … python -c "print(open('/data/app.db.claim').read())"` — das Gateway-Abbild hat kein `cat`); nach
  dem Einlösen verschwindet die Datei. Ohne
  Datenbank-Datei (`:memory:`) bleibt nur stderr, und die Log-Zeile sagt das. Mit
  `admin_claim_token_file` wählt man die Datei selbst (sie geht vor, auch an einer Konsole).
  **Bekannte Grenze:** Eingelöst wird der Token über eine URL (`?token=…`, bei nicht angemeldetem
  Aufruf zusätzlich im `Location` des Login-Redirects) — er läuft damit durch Proxy-Access-Logs,
  `Referer` und die Browser-History, bevor er verbraucht ist. Also `admin_claim_ttl_min` kurz
  halten und sofort einlösen. Wo überhaupt kein Token in einer URL stehen soll: den ersten Admin
  über `auth.ensure_admin(...)` oder die Allowlist setzen. Siehe [SECURITY](SECURITY.de.md).

Die Allowlist sagt, **welcher Name** Admin wird — nicht, **wer** diesen Namen bekommt. Mit
`allow_signup=True` registriert sich ein Fremder einfach darunter und ist beim ersten Login Admin;
diese Kombination weist der Konstruktor deshalb ab. Erlaubt ist sie wieder, sobald die Identität
aus der Registrierung selbst belegt ist: eine E-Mail-Adresse (kein blosser Benutzername, den
niemand bestätigt), Pflicht und bestätigt (`signup_require_email=True`,
`signup_verify_email=True`). Sonst die Registrierung **geschlossen lassen** — oder den
Einmal-Token nehmen, der verlässt die Konsole des Betreibers nie.

Dasselbe gilt, wenn ein IdP die Konten anlegt (`oidc_auto_create`, `saml_auto_create`,
`ldap_auto_create`): Auch dort kommt der Benutzername aus fremder Hand, ein Allowlist-**Name**
wird in dieser Lage abgewiesen. Eine Allowlist-**Adresse** bleibt erlaubt, zählt bei OIDC aber
nur mit dem Claim `email_verified`. Fehlt er, wird die Adresse trotzdem ins Konto übernommen und
geht weiter als `Remote-Email` hinaus — sie ist nur als unbestätigt vermerkt
(`users.email_verified`) und trägt keine Rechte, auch nicht über einen späteren Anmeldeweg
desselben Kontos. Für IdPs ohne diesen Claim (Entra ID): der Einmal-Token ist der belegte Weg —
oder, wer die Adressen selbst verantwortet, setzt `oidc_email_verified_default=True`. Ein Claim,
der ausdrücklich `false` sagt, bleibt in beiden Fällen ein Nein.

**SAML und LDAP kennen keinen solchen Beleg**: Kein Standardattribut sagt, dass die Adresse
geprüft wurde, und ein `mail`-Eintrag im Verzeichnis pflegt vielerorts der Nutzer selbst. Über
diese beiden Wege wird eine Allowlist-Adresse deshalb per Vorgabe **nie** zum Erst-Admin — auch
nicht bei einem Bestandskonto, das sie schon führt. Die Konfigurationsprüfung sagt das beim Aufbau,
und der abgewehrte Versuch steht im Sicherheits-Log und im Audit (`admin_bootstrap_denied`). Mit
Mailer bestätigt der Inhaber eine solche Adresse nach der Anmeldung per Link
(`federation_email_confirm`) — eine Allowlist-Adresse bekommt diesen Link nie. Als belegt gilt die
Adresse nur, wo der Betreiber für die Quelle einsteht, wie `email_verified=true` bei OIDC:
`ldap_email_trusted`/`saml_email_trusted` für ein gepflegtes Verzeichnis oder einen Firmen-IdP
ohne Selbstregistrierung, oder ein Beleg-Attribut (`ldap_attr_email_verified`/
`saml_attr_email_verified`) für einen IdP, der eines führt. Sonst ist der belegte Weg der
**Einmal-Token**; wer Rechte fortlaufend aus dem IdP steuern will, nimmt danach
`saml_group_role_map`/`ldap_group_role_map` (Ziel `__admin__`) — das entscheidet der Betreiber in
der Konfiguration, nicht ein Attribut in der Anmeldung.

Alternativ legt `auth.ensure_admin("admin", os.environ["INITIAL_PW"])` den Admin an, bevor die App
den ersten Request beantwortet — am saubersten, wenn du per Skript deployst.

### Admin-Passwort weg, und kein Mailer da?

Ein Preset für interne Werkzeuge (`local_accounts()`) hat bewusst kein „Passwort vergessen" und keinen
Magic-Link — beides bräuchte einen Mailserver. Und die beiden Bootstrap-Wege oben greifen nur,
**solange kein Admin existiert**. Mit genau einem Admin-Konto und ohne zweites, das aushelfen könnte,
ist das eine Sackgasse. Der Weg zurück führt über die Datenbankdatei, die dir ohnehin gehört:

```bash
python -m tinysesam passwd --db auth.db admin     # fragt zweimal, dann ist es gesetzt
```

Das Kommando beendet die offenen Sitzungen des Kontos und widerruft seine API-Keys, App-Passwörter, Dienste und
verbundenen Programme, wie ein Admin-Reset im Panel (`--keep-sessions` lässt all das stehen), und schreibt einen
Audit-Eintrag mit den Zahlen. `--stdin` liest das Passwort von der Standardeingabe, für Skripte.
Dasselbe aus Python:

```python
auth = TinySesam(TinySesamConfig(db_path="auth.db"))
auth.set_password(auth.find_user("admin")["id"], "neues-passwort")
```

## Sicherungen und Aufräumen

```bash
python -m tinysesam backup --db auth.db auth-2026-09-21.db   # konsistente Kopie, im Betrieb
python -m tinysesam gc     --db auth.db                      # Abgelaufenes wegräumen
```

> **Die Datenbank nicht durch Kopieren der Datei sichern.** Sie läuft im WAL-Modus: Alles seit
> dem letzten Checkpoint steht in `auth.db-wal`, nicht in `auth.db`. Ein `cp`/`rsync` der `.db`
> allein liefert einen Torso — gemessen an einer frischen Instanz mit fünf Konten enthielt die
> Kopie nicht einmal die Tabelle `users`, und das merkt man erst beim Zurückspielen. `backup`
> nutzt SQLites Online-Backup: Es nimmt die nötigen Sperren, zieht das WAL mit und schreibt eine
> Datei, die für sich allein stimmt — mit denselben engen Rechten wie die Quelle. Der zugesagte
> Weg ist dieses Kommando; `auth.store.backup(pfad)` tut aus Python dasselbe, aber `auth.store` ist
> Innenleben (Stufe C, keine Zusage — s. [Öffentliche API](#öffentliche-api-drei-stufen)).

`gc` löscht abgelaufene Sitzungen, Flows, Einmal-Token und alte Login-Versuche; das Audit-Log
bleibt bewusst unangetastet. **Von selbst läuft das nicht** — fertige Unit-Dateien liegen in
[`deploy/systemd/`](../deploy/systemd/). Aus Python: `auth.gc()` liefert dieselben Zahlen als
Dict. `gc` gibt allerdings keinen Plattenplatz an das Dateisystem zurück; nach einem grossen
Aufräumen einmalig `sqlite3 auth.db 'VACUUM;'` bei gestopptem Dienst.

### Eine Sicherung zurückspielen

```bash
systemctl stop tinysesam                                  # der Dienst muss stehen
python -m tinysesam restore --db auth.db sicherung-2026-09-21.db
systemctl start tinysesam
```

> **Auch zurück nicht einfach kopieren.** Nach einem Absturz liegen `auth.db-wal` und
> `auth.db-shm` neben der Datenbank. SQLite spielt sie beim Start auf die eben zurückgespielte
> Datei — der alte Stand ist wieder da, ohne Fehlermeldung, und `PRAGMA integrity_check` sagt
> `ok`. `restore` räumt beide vorher weg, prüft die Sicherung, bevor es irgendetwas überschreibt
> (Integrität, Kontenzahl, Schema-Version), und setzt danach `0600`.

> **Ein Rückschritt braucht eine Sicherung im alten Schema.** Jede Fassung, die Spalten
> hinzufügt, migriert die Datenbank beim ersten Start — 0.18.0 tat es einmal (Schema 5), 0.19.0
> hob sie auf **Schema 8** (Freigaben je Anwendung, Key-Art, Erst-Login und
> Einrichtungsfenster), 0.20.0 hebt sie auf **Schema 10** (9: stabile
> Verzeichnis-Kennungen für LDAP/SAML; 10: Zähl-Töpfe und die Suche nach Name und Adresse mit
> Index, Sperren aus dem Panel früherer Fassungen tragen danach den Betreiber-Vermerk). Älterer Code öffnet die Datei danach klaglos, `/healthz` bleibt grün und
> Konten sind lesbar — aber jede Sitzungsoperation wirft. Die Sicherung also **vor** dem Update
> ziehen (`tinysesam backup` lässt die Quelle unangetastet) und im Ernstfall die zurückspielen.
> Lief älterer Code doch auf der neuen Datei, holt der nächste Start der neuen Fassung zweierlei
> nach: Sperren aus dem Panel der älteren tragen danach den Betreiber-Vermerk (erkannt an ihren
> Audit-Zeilen), und Adressen ihrer offenen Registrierungen gelten bis zur Bestätigung als
> unbelegt; im Log steht dann eine Warnung. Mehr gleicht er nicht ab — der sichere Rückweg ist die Sicherung.

**Von 0.17.x oder älter?** `tinysesam backup` gibt es erst seit 0.18.0, und schon der erste Start
der neuen Fassung migriert. Die Sicherung also mit der *neuen* Fassung ziehen, bevor sie startet —
`backup` öffnet die Quelle nur lesend und lässt sie im alten Schema:

```bash
# Container: neues Tag ziehen, sichern, erst dann starten (Dienstname wie in der eigenen compose-Datei)
docker compose pull
docker compose run --rm --no-deps --entrypoint tinysesam tinysesam \
    backup --db /data/gateway.db /data/gateway-vor-update.db
docker compose up -d

# Bibliothek: nach dem Installieren der neuen Fassung, vor dem Neustart des Dienstes
python -m tinysesam backup --db auth.db auth-vor-update.db
```

Oder den Dienst anhalten und `auth.db` zusammen mit `auth.db-wal` und `auth.db-shm` (soweit
vorhanden) in ein eigenes Verzeichnis kopieren; zurück geht es mit allen dreien, bei angehaltenem
Dienst.

### „Ich komme nicht rein" — nachsehen

```bash
python -m tinysesam audit  --db auth.db --user alice    # ins Protokoll, von der Kommandozeile
python -m tinysesam unlock --db auth.db alice           # eine Brute-Force-Sperre aufheben
```

Das Audit-Log hält fest, *warum* eine Anmeldung scheiterte (`no_account`, `account_locked`,
`wrong_secret`) — die HTTP-Antwort tut das bewusst nicht, sonst liesse sich damit nach
Konten suchen. Im Protokoll liest nur der Betreiber mit.

### Ein Konto entfernen

```bash
python -m tinysesam delete --db auth.db alice           # fragt vorher nach; --yes für Skripte
```

Für Instanzen ohne Admin-Panel — etwa nur OIDC, wo ein Abnahmetest mit einem Testkonto ein lokales
Konto hinterlässt. Es nimmt denselben Weg und dieselben Schutzregeln wie „Löschen" im Panel:
Zugangsdaten, Sitzungen und Identitätsverknüpfungen verschwinden, die Anmeldeversuche unter Name und
Adresse ebenfalls, und der Name im Audit-Log wird zu `deleted#<id>` (die Zeilen selbst bleiben). Ein
Owner und der letzte Admin werden nicht gelöscht. Das Kommando nennt, was es entfernt hat (Name, Zahl
der Sitzungen und Identitätsverknüpfungen), nie ein Geheimnis. Ohne `--yes` fragt es nach, ohne
Terminal verweigert es; ein unbekanntes Konto endet mit Exit 1. `#<id>` statt des Namens geht wie bei
`rename`. Ein rohes `DELETE` in der Datenbank ist der falsche Weg — es lässt den Namen in jeder
Audit-Zeile stehen.

### Schlüssel: auflisten, rotieren, neu verschlüsseln, ausmustern (T-48)

```bash
python -m tinysesam keys list      --db auth.db                    # jeder Schlüssel: Zweck, ID, Stand — nie der Schlüssel
python -m tinysesam keys rotate    --db auth.db --purpose vault    # oder gate, oauth-pepper
python -m tinysesam keys reencrypt --db auth.db                    # gespeicherte Geheimnisse auf den aktiven Tresor-Schlüssel
python -m tinysesam keys retire    --db auth.db --purpose vault    # verweigert, solange etwas den alten noch braucht
```

Drei Zwecke, je ein Schlüsselbund (aktiver Schlüssel + ältere, die noch entschlüsseln oder prüfen): `vault` (die
ruhenden Geheimnisse), `gate` (die Signatur des Gate-Tokens) und `oauth-pepper` (die Digests der OAuth-Tokens). Eine
Rotation verliert nichts und meldet niemanden ab; die Schritte, die Quellen (Umgebung, Datei, Datenbank) und der
Rückweg zu einer älteren Version stehen in `docs/OPERATIONS.md`, „Keys".
## Einen Fehler melden

TinySesam schickt nichts nach Hause — keine Telemetrie, auch nicht als Opt-in: Eine Anmeldekomponente, die von sich
aus nach draußen spricht, verlöre das Vertrauen, von dem sie lebt. Stattdessen schreibt ein Befehl einen Bericht, den
du liest, prüfst und selbst abschickst:

```bash
python -m tinysesam diagnose --config yourapp.settings:config --log /var/log/tinysesam/security.log   # Bibliothek
docker exec <container> python -m tinysesam.gateway diagnose                                          # Gateway-Abbild
```

- **Was drinsteht:** Version, Python, Betriebssystem-Familie, Modus, installierte Extras; die *Form* der
  Konfiguration (welche Felder von der Vorgabe abweichen — Schalter und Zahlen wie sie sind, alles andere als
  Platzhalter wie `<url-1>` oder `<host-2>`, Geheimnisse nur als `<set>`); die eingebauten Prüfungen (Fehler und
  Warnungen von `config_check`, Proxy-Header und uvicorns `--no-proxy-headers`, die Uhr, das Datenbankschema, ob der
  Tresor-Schlüssel neben der Datenbank liegt, Gate-Token und JWKS); die letzten Warnungen und Fehler des
  Security-Logs, geschwärzt.
- **Was er nicht tut:** keine Netzwerkanfrage, kein Schreiben (die Datenbank wird nur lesend geöffnet, kein Schlüssel
  entsteht), keine `TinySesam`-Instanz. `--config` nimmt `modul:attr` oder `datei.py:attr` — eine `TinySesamConfig`,
  ein `TinySesam` oder eine Funktion, die eines davon liefert — und importiert dafür dein Modul. `--db` und `--log`
  fallen auf `db_path` und `security_log` zurück; `--no-link` lässt den Link weg.
- **Am Ende** öffnet ein Link das [Fehlerformular](https://github.com/Ollornog/TinySesam/issues/new?template=bug.yml)
  vorausgefüllt. Du prüfst und schickst es selbst ab. Ein Bericht, der für einen Link zu lang ist, lässt Abschnitte
  weg und nennt sie; die fügst du aus dem Terminal ein.
- Hostnamen, Adressen, URLs, Benutzernamen, Pfade und Geheimnisse werden ersetzt, aber du kennst dein Setup am
  besten: Lies den Bericht, bevor du ihn teilst. Eine **Sicherheitslücke** gehört nie in ein öffentliches Issue —
  siehe [`SECURITY.md`](https://github.com/Ollornog/TinySesam/blob/main/i18n/SECURITY.de.md).

## Demo-Modus

`demo_mode=True` legt die Konten `demo` und `demoadmin` an, zeigt ihre Zugangsdaten auf der
Anmeldeseite (und die PIN auf der PIN-Seite) und sagt unmissverständlich, dass er produktiv aus
gehört. Beim Abschalten werden genau diese Konten beim nächsten Start gelöscht. Niemals auf einer
öffentlichen Instanz einschalten.

## Sicherheit

- Passwörter: **argon2id** (Fallback **scrypt**, n=2¹⁵). Sessions **server-side** (in SQLite, jederzeit revozierbar).
- Session-Cookie: `HttpOnly`, `Secure` (Default), `SameSite=Lax`.
- OIDC: `state` + `nonce` im Store (nicht im Client), ID-Token gegen **JWKS** + `iss`/`aud`/`exp` verifiziert.
- WebAuthn: Challenge im Store, an httponly-Cookie gebunden; `sign_count`-Klon-Erkennung.
- **Produktiv immer hinter HTTPS.** `rp_id`/`origin` müssen exakt zur Domain passen.

## Härtung

Nach dem Vorbild von Authelia/Fail2Ban — die Schwellen sind **im Admin-Panel / zur Laufzeit** änderbar
(`auth.set_security(key, wert)`, Defaults in `security.SECURITY_DEFAULTS`):

- **Brute-Force-Regulation:** Fehlversuche pro **User *und* IP** werden gezählt; nach `max_login_attempts`
  im `lockout_window_sec`-Fenster ist der Login gesperrt — blockt auch das *korrekte* Passwort.
  Gilt für Passwort- und TOTP-Login (IP-Schwelle höher wg. NAT: `ip_attempt_factor`).
- **Owner, Inaktivität, verschlüsselte TOTP-Geheimnisse, Widerruf über den IdP:** Owner sind Admins,
  die sich nicht löschen, sperren oder entmachten lassen (mindestens einer, weitergebbar, Notweg
  `tinysesam owner`); Sitzungen ohne „Angemeldet bleiben" enden nach 8 h Inaktivität
  (`session_idle_minutes`); TOTP-Geheimnisse liegen AES-256-GCM-verschlüsselt — **den Schlüssel
  getrennt sichern** (`TINYSESAM_SECRETS_KEY`, `secrets_key_file` oder `<db>.key`), rotieren mit
  `tinysesam keys rotate` (unten); eine
  OIDC-Sitzung prüft ihr Refresh-Token alle `oidc_session_refresh_minutes` nach und endet, wenn der
  Provider Nein sagt. Einzelheiten: `docs/OPERATIONS.md`.
- **Sperr-Hinweis** (ASVS 6.3.5): Mit konfiguriertem Versand bekommt die belegte Adresse eines
  gesperrten Kontos einen Hinweis je Sperrfenster (Opt-out `notify_login_failures=False`).
- **Fehlversuche in Folge, ohne Fenster** (`account_max_consecutive_failures`, Vorgabe 100): Jeder
  gescheiterte Anmeldeversuch unter einem Namen verlängert eine Serie; an der Grenze ist die Anmeldung
  gesperrt — und anders als bei den Fenster-Schwellen läuft diese Sperre nicht ab. Sie endet mit einer
  vollständigen Anmeldung über einen anderen Weg (Passkey, Anmelde-Link, OIDC), einem Passwort-Reset
  (nur der Anteil der Erstfaktoren — TOTP-Fehlgriffe und die einer PIN hinter einem anderen Faktor
  bleiben), einem neuen Passwort aus dem Admin-Panel oder `tinysesam unlock`. Gezählt wird je Name, ob es das
  Konto gibt oder nicht — die Sperre verrät also nichts. NIST SP 800-63B begrenzt Fehlversuche in
  Folge auf 100: Langsames Raten unter jeder Fenster-Schwelle läuft nicht mehr ewig.
- **Passwortlänge nach Faktor-Lage:** Ein neues Passwort braucht `password_min_length_single_factor`
  (Vorgabe 15, NIST SP 800-63B), wenn es allein anmelden kann — keine `login_chain`, eine, die nur
  `password` verlangt, oder eine, deren zweiten Faktor Konten selbst einrichten dürfen
  (`mfa_enrollment` `first_login`/`grace`) —, und `password_min_length` (Vorgabe 8) nur, wenn die
  Kette einen zweiten Faktor erzwingt, den der Betreiber vergibt (`mfa_enrollment="strict"`). Bestehende Passwörter bleiben gültig; die Regel gilt, wo eines gesetzt wird. Das CLI
  (`tinysesam passwd`) liest keine Konfiguration und nimmt die strengere.
- **Methodengebundene Zähler neben dem Login-Lockout:** Die PIN (kurzer Keyspace,
  `pin_max_attempts`), die Alt-Passwort-Abfrage der Kontoseite (`password_change_max_attempts`),
  die Step-up-Bestätigung (`reauth_max_attempts`) und die Bereichs-PIN (`resource_max_attempts`)
  haben je einen **eigenen** Topf. Alles davon ist gedrosselt und protokolliert, aber ein
  Fehlgriff dort sperrt die **Anmeldung** nicht: Sonst hätten ein paar Tippfehler auf der
  eigenen Kontoseite den Nutzer ausgeschlossen — hinter NAT auch Kollegen, die nichts damit zu
  tun hatten, und bei der Bereichs-PIN sogar fremde Besucher, die gar kein Konto haben.
  Welche Methode kein Anmeldeversuch ist, steht in `security.NOT_LOGIN_METHODS` — abgeleitet
  aus `security.OWN_LOCK`, damit keine Methode ohne Bremse dastehen kann.
  Die Töpfe der **angemeldeten** Wege (Passwortwechsel, Step-up) zählen bewusst nur pro Konto,
  nicht pro IP: Wer dort rät, braucht bereits eine Sitzung genau dieses Kontos. Die Bereichs-PIN
  behält die IP-Schwelle, denn dort rät ein Unangemeldeter.
- **Rate-Limiting:** Token-Bucket pro IP auf Login-/2FA-Endpoints (`rate_limit_max` / `rate_limit_window_sec`); eine
  IPv6-Adresse zählt als ihr /64, ein /48 teilt sich das Fünffache (`security.RATE_NET48_FACTOR`).
- **fail2ban:** jeder Fehlversuch wird über den Logger `tinysesam.security` mit echter Client-IP geloggt
  (`failed login … ip=…`; der Grund, falls es einen gibt, steht zuletzt als `reason=…` — seit Schema 15
  auch in den OIDC- und Passkey-Zeilen, die Filterdateien aus `deploy/fail2ban/` also mit dem Release aktualisieren). Filter + Jail in [`deploy/fail2ban/`](../deploy/fail2ban/) → IP-Ban auf Firewall-Ebene.
  **Nur echte Anmeldeversuche tragen `failed login`.** Ein Fehlgriff, der keine Anmeldung war
  (Passwortwechsel, Step-up-Bestätigung, Bereichs-PIN), wird als `failed verification …`
  protokolliert und von der mitgelieferten Jail bewusst **nicht** gebannt: Diese Zeilen kommen
  von jemandem, der bereits angemeldet ist — mit `maxretry = 6` sperrte sich ein legitimer
  Nutzer nach ein paar Tippfehlern auf der eigenen Kontoseite selbst aus, und zwar für die ganze
  Instanz. Wer sie trotzdem bannen will (etwa bei öffentlich angebotenen Bereichs-PINs), nimmt
  `tinysesam-verify-filter.conf` und die zweite, mildere Jail `[tinysesam-verify]` dazu; sie
  liegt abgeschaltet bei.
  Mit `security_log="/var/log/tinysesam/security.log"` schreibt TinySesam die Datei selbst — die
  mitgelieferte Jail zeigt darauf und bewachte sonst eine Datei, die nie entsteht. Leer lassen, wer sein
  Logging selbst einrichtet; ein nicht schreibbarer Pfad warnt beim Start, statt ihn zu verhindern.
  Angelegt wird die Datei mit **0640** — auch die nach einer Rotation neu entstandene —, denn darin
  stehen Benutzernamen und IP-Adressen; eine schon vorhandene welt-lesbare Datei wird gemeldet, aber
  nicht umgeschrieben. Soll ein **dritter** Benutzer mitlesen (Log-Versand, weder Eigentümer noch in
  der Gruppe), geht das über die Gruppe: logrotate-Zeile `create 0640 tinysesam adm` — ohne sie
  entsteht die Datei bei der nächsten Rotation wieder mit der Gruppe des TinySesam-Prozesses, und der
  Versand verliert den Lesezugriff. Nicht beim Update, sondern erst bei der Rotation.
- **Echte Client-IP hinter Proxy:** `X-Forwarded-For` gilt nur, wenn der direkte Peer in
  `trusted_proxies` steht — sonst ist die IP fälschbar. **uvicorn mit `--no-proxy-headers` starten**
  (`uvicorn.run(..., proxy_headers=False)`): uvicorn wertet `X-Forwarded-For` **standardmäßig** aus und ersetzt
  `request.client.host` durch die geforwardete IP; TinySesams Prüfung läuft dann ins Leere, und Rate-Limit,
  Lockout und fail2ban hängen an uvicorns `forwarded_allow_ips` statt an `trusted_proxies`. Das Gateway
  (`python -m tinysesam.gateway`) startet uvicorn selbst so; kommt die Adresse schon umgeschrieben an, sagt es
  das Sicherheitsprotokoll und nennt den Schalter.
- **Rollen und Admins:** standardmäßig erfüllt ein Admin **jede** `require_role(...)`-Prüfung. Hängen
  die Rechte einer App allein an einer IdP-Gruppe, ist das eine stille Rechteausweitung — dann
  `admin_implies_roles=False` setzen (oder je Guard `require_role(..., admin_implies=False)`).
- **IdP-Gruppen** werden **exakt** gegen die Schlüssel von `*_group_role_map` verglichen
  (`group_match="exact"`). Teilstring-Vergleich (nötig für LDAP-`memberOf`-DNs, dort automatisch)
  würde den Schlüssel `admin` auch auf eine Gruppe `nicht-admin` passen lassen.
- **Audit-Log:** Login / Logout / Fehlversuche in der DB (`store.recent_audit()`), fürs Admin-Panel.
- **Antwort-Header:** Jede eingebaute Seite läuft unter einer strengen Nonce-CSP (`csp="strict"`) mit
  `X-Frame-Options: SAMEORIGIN` und `Cross-Origin-Opener-Policy: same-origin`; jede Antwort trägt `nosniff`,
  `Referrer-Policy: same-origin` und `no-store`; die Abmeldung schickt `Clear-Site-Data: "cache"`. Mit
  `csp_report=True` melden Browser Verstöße an `/auth/csp-report`, je eine gedrosselte Zeile im Sicherheitslog —
  an Dritte geht nichts.
- **CSRF:** Double-Submit-Token (`csrf_enabled`, Default an) auf allen state-ändernden POSTs — die
  eingebauten Formulare/JS erledigen das automatisch (`_csrf`-Feld bzw. `X-CSRF-Token`-Header);
  API-Key-Requests sind ausgenommen (kein Cookie-Risiko). Zusätzlich zu `SameSite=Lax`.
  Jede Anmeldung setzt ein frisches Token, das Abmelden löscht es; ein Step-up behält es.
  Wer eigene Seiten rendert: `csrf = auth.ensure_csrf(request, response)` übernimmt das Token des
  Browsers oder setzt eins — siehe „CSRF auf eigenen Seiten" oben.
- **Rate-Limit prozessübergreifend:** optional Redis (`redis_url`, Extra `[redis]`) für Multi-Worker; sonst In-Memory.
- **User-Enumeration:** Login/PIN prüfen auch bei unbekanntem Benutzer gegen einen Dummy-Hash (kein Timing-Leak).
- **Nach Passwortwechsel** werden die übrigen Sitzungen des Users beendet (Admin-Reset: alle).
- **Housekeeping:** `auth.gc()` löscht abgelaufene Sessions/Flows/Magic-Tokens/Ressourcen-Unlocks + alte
  Login-Versuche (Audit-Log bleibt). Regelmäßig aufrufen (Cron/Startup/Scheduler) — sonst wachsen die Tabellen.

## Installation und Updates

**TinySesam aktualisiert sich nicht selbst.** Die Version bestimmst du, und zwar an genau einer
Stelle: dort, wo du die Bibliothek installierst. Ein Auth-Modul, das zur Laufzeit Code aus dem
Internet nachlädt, ist eine Hintertür mit Bedienungsanleitung — wer das Admin-Panel übernimmt,
könnte auf eine alte Version mit bekannter Lücke zurückschalten. Etablierte Auth-Projekte haben
so einen Knopf nicht, und seit `v0.12.0` hat TinySesam ihn auch nicht mehr.

### Als Bibliothek (in deiner eigenen App)

Schreibe eine **feste Version** in die Abhängigkeiten deiner App — nie einen Branch:

```
tinysesam[oidc]==0.27.1
```

Eine veröffentlichte Version auf PyPI ändert sich nicht mehr: Dieselbe Zeile installiert morgen
denselben Code. Aktualisieren heißt dann: Version in der Zeile hochziehen, neu installieren,
Dienst neu starten. Python lädt Code nicht zur Laufzeit nach.

Derselbe Pin über Git, wenn du so installierst — beachte, dass sich ein **Tag umhängen lässt**;
für echte Unveränderlichkeit pinne den Commit (`@a1b2c3d…`):

```
tinysesam[oidc] @ git+https://github.com/Ollornog/TinySesam.git@v0.27.1
```

Jedes Release hängt zusätzlich ein **Wheel** und ein **sdist** an, mit `SHA256SUMS`. Wer ohne Git
und ohne Paketindex installieren will, nimmt die Datei direkt:

```
pip install https://github.com/Ollornog/TinySesam/releases/download/v0.27.1/tinysesam-0.27.1-py3-none-any.whl
```

### Als Gateway (eigener Container)

Jedes Release baut ein Abbild für `linux/amd64` und `linux/arm64`:

```
ghcr.io/ollornog/tinysesam:v0.27.1
```

**Prüfen, woher es kommt.** Ein Digest belegt, dass sich ein Artefakt seit dem Bau nicht verändert
hat — nicht, wer es gebaut hat. Jedes Release trägt deshalb eine über Sigstore signierte
Herkunfts-Attestation und eine SBOM; beide liegen auch neben dem Abbild in der Registry:

```bash
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.27.1 --owner Ollornog
gh attestation verify oci://ghcr.io/ollornog/tinysesam:v0.27.1 --owner Ollornog \
    --predicate-type https://spdx.dev/Document                             # die SBOM
# Wheel und sdist (von PyPI oder der Release-Seite): der isolierte Builder, der Tag und ihre SBOM
gh attestation verify tinysesam-0.27.1-py3-none-any.whl --owner Ollornog \
    --signer-workflow Ollornog/TinySesam/.github/workflows/build-provenance.yml --source-ref refs/tags/v0.27.1
gh attestation verify tinysesam-0.27.1.tar.gz --owner Ollornog \
    --signer-workflow Ollornog/TinySesam/.github/workflows/build-provenance.yml \
    --predicate-type https://spdx.dev/Document
```

Geht das durch, heisst das: gebaut vom Release-Workflow dieses Repos, aus dem Commit, den die
Attestation nennt. Wheel und sdist kommen aus einem eigenen Builder (SLSA Build L3, seit 0.26.0): Der
wiederverwendbare Workflow `build-provenance.yml` baut den Tag neu, hält seine Bytes gegen die, die das Release
ausliefert, und signiert unter eigenem Namen — `--signer-workflow` nagelt ihn fest. Ihre SBOM (auch als
`tinysesam-sbom.spdx.json` am GitHub-Release) nennt TinySesam und die Abhängigkeiten, die pip am Release-Tag dafür
aufgelöst hat (Linux, Python 3.13, ohne Extras). Kein Schlüssel, den man herausgeben — und keiner, den man verlieren kann: Die
Signatur hängt an der Identität des Workflows.

Es läuft als **Nicht-root** (uid 1000), bringt einen `HEALTHCHECK` auf `/healthz` mit und startet direkt das
Gateway — kein `command:` nötig. Die Laufzeit-Basis ist **distroless** (`gcr.io/distroless/base-debian13`, per Digest
gepinnt) mit dem Python-Interpreter der Build-Stufe `python:3.x-slim` darauf: keine Shell, kein Paketmanager, kein
`pip`, kein `git` — wer im Container Code ausführen kann, findet kein Werkzeug, um mehr nachzuladen. Die
Betriebsbefehle gehen wie bisher (`docker exec <c> tinysesam backup …`); zum Umsehen gibt es `docker exec -it <c> python`
oder einen Beiwagen-Container mit Shell in den Namespaces des Containers — beides in `docs/OPERATIONS.md`, „The gateway
image: no shell inside“.
Der Proxy kommt mit: `ghcr.io/ollornog/tinysesam-caddy-gate:v0.27.1` ist Caddy mit dem Plugin caddy-jwt, gebaut,
geprüft und attestiert vom selben Release (Prüfung wie oben). In fünf Minuten am Laufen: „Gateway und Caddy in
5 Minuten“ weiter unten; der Referenz-Stack mit allen Optionen liegt in `deploy/forward-auth/docker-compose.yml`.

**Heimnetz ohne Domain?** Außerhalb von `localhost` ist HTTPS Pflicht; eine nackte IP-Adresse braucht deshalb eine
eigene CA auf jedem Gerät — und Passkeys funktionieren auf einer IP gar nicht. `docs/HOME-NETWORK.md`
(Englisch) empfiehlt eine Domain (DNS-01 klappt auch für Namen, die nur zu Hause auflösen) und beschreibt den
IP-Notweg mit der Vorlage in `deploy/home-network/`.

Update: Tag hochziehen, `docker compose pull && docker compose up -d` — migriert die Fassung die
Datenbank, dazwischen sichern (siehe „Eine Sicherung zurückspielen"; von 0.17.x oder älter mit
dem neuen Abbild). Rollback: alten Tag zurückschreiben, nach einer Migration zusammen mit dieser
Sicherung. **Ein `latest` gibt es bewusst nicht** — ein wandernder Tag macht jeden
Neustart zum Glücksspiel. Wer es ernst meint, pinnt den Digest
(`ghcr.io/ollornog/tinysesam@sha256:…`, steht im Log des Release-Workflows): ein Tag lässt
sich umhängen, ein Digest nicht.

### Woher weißt du, dass es etwas Neues gibt?

Aus dem [Releases-Feed](https://github.com/Ollornog/TinySesam/releases) — per Watch, RSS
(`releases.atom`) oder einem Bot wie Renovate/Dependabot, der den Pin in einem Pull Request
hochzieht. Dann läuft deine CI gegen die neue Version, und du entscheidest, ob du mergst.
Die laufende Version zeigt `python -m tinysesam version` und das Admin-Panel unter „Härtung".

## Mehrere Anwendungen, ein TinySesam

Eine Installation kann mehrere Anwendungen schützen — und **wer in welche darf, entscheidet der
Identity Provider**. Das ist deshalb wichtig, weil die Freigabe bei PocketID (und bei jedem
Provider, der so arbeitet) am *OIDC-Client* hängt, nicht am Benutzer. Mit einem einzigen Client
gibt es für alle Anwendungen nur eine Antwort: Wer in eine darf, darf in alle.

Also bekommt jede Anwendung beim Provider ihren eigenen Client, und die Zuordnung Host → Client
steht in der Konfiguration:

```python
cfg = TinySesamConfig.oidc_gateway(
    issuer="https://id.example.com",
    client_id="gateway", client_secret=os.environ["GATEWAY_SECRET"],   # Rückfall für nicht genannte Hosts
    base_url="https://auth.example.com",
    trusted_redirect_hosts=["app.example.com", "wiki.example.com"],
    clients={
        "app.example.com":  {"client_id": "app",  "client_secret": os.environ["APP_SECRET"]},
        "wiki.example.com": {"client_id": "wiki", "client_secret": os.environ["WIKI_SECRET"],
                             "group_role_map": {"redaktion": "redakteur"}},
    },
    revalidate_minutes=60,
)
```

Alle Clients zeigen auf **eine** Redirect-URI (`base_url` + `/auth/oidc/callback`) — welcher
Client gemeint ist, steht serverseitig im Vorgang, nicht in der Adresse. Beim Provider trägt man
deshalb überall dieselbe Adresse ein.

**Der Widerruf folgt dem Provider.** `revalidate_minutes` sagt, wie lange eine Freigabe gilt,
bevor TinySesam erneut fragt. Läuft die Frist ab, geht die nächste Anfrage über den Provider;
dessen Sitzung besteht in aller Regel weiter, der Mensch sieht also ein Flackern und keine
Anmeldemaske. Wurde die Gruppe inzwischen entzogen, sagt der Provider Nein — und zeigt **seine**
Absage, denn dort wird die Freigabe gepflegt. Die Sitzung selbst bleibt: Die anderen Anwendungen
laufen weiter. `0` schaltet die Nachprüfung ab, dann wirkt ein Entzug erst, wenn die Sitzung
abläuft (in der Vorgabe nach sieben Tagen).

Gibt der Provider Refresh-Tokens aus, fallen die meisten dieser Umwege weg: Jeder erfolgreiche
Refresh-Tausch für eine Anwendung (`oidc_session_refresh_minutes`, Vorgabe 15) erneuert ihre
Freigabe, denn dieser Tausch ist das Ja des Providers für genau diesen Client. Der Umweg bleibt für
Anwendungen ohne Refresh-Token, einen unerreichbaren Provider und einen Client mit `allowed_groups`,
dessen Refresh-Antwort den Gruppen-Claim nicht enthält. Das zählt, wenn die eigene Sitzung des
Providers kürzer ist als die Freigabefrist — sonst endete der Umweg in dessen Anmeldemaske.

Als Umgebungsvariablen (Gateway-Container):

```
TINYSESAM_OIDC_CLIENTS='{"app.example.com": {"client_id": "app", "client_secret": "..."}}'
TINYSESAM_OIDC_REVALIDATE_MINUTES=60
```

Eine Konfiguration mit einem einzigen Client verhält sich unverändert — keine Zuordnung, keine
Freigabe, die ablaufen könnte.

**Für welche Anwendung eine Anfrage ist, sagt allein der Proxy.** `/auth/forward` liest das Ziel aus
`X-Forwarded-Host`/`-Proto`/`-Uri` (Caddy, Traefik) und aus `X-Original-URL` nur, wenn kein `X-Forwarded-Host` da ist
(nginx). Eine Anfrage, die beide mit verschiedenen Zielen trägt, bekommt die Anmeldeseite (`X-TinySesam-Reason:
forwarded-conflict`): Eins der beiden kam vom Browser. An diesem Ziel hängt jede Entscheidung je Anwendung — Freigabe
je Client, App-Passwörter, OAuth-Audience, „nur hier abmelden“ —, also die Proxy-Vorlagen in `deploy/` so übernehmen,
wie sie sind: Sie streichen `X-Original-URL` (Caddy), setzen alle vier Header (nginx) oder vertrauen den
Weiterleitungs-Headern des Browsers weder noch kopieren sie sie (Traefik).

**`Remote-Groups: admin` ist keine frische Bestätigung.** Forward-Auth antwortet für jede gültige Sitzung, egal wie
lange ihre letzte Bestätigung her ist; `admin_require_mfa` und `stepup_max_age_sec` schützen TinySesams eigenes
Admin-Panel und die Routen, die Zugang anlegen, nicht die Anwendungen hinter dem Proxy. Eine Anwendung, die
Admin-Rechte aus dem Header ableitet, sollte eine heikle Aktion (alles löschen, ändern, wer hinein darf) nicht allein
darauf stützen, sondern dort selbst nachfragen.

## API-Keys & Service-/Daemon-Accounts

Für **maschinellen Zugang** (Skripte, andere Dienste, System-Daemons) — parallel zum interaktiven Login:

- Ein API-Key gehört einem User, liegt **gehasht** (sha256) in der DB, optional mit **Ablauf** und **Rollen-Scope**.
- Gesendet als `Authorization: Bearer tsk_…` **oder** `X-API-Key: tsk_…`.
- **`require_user` akzeptiert Session ODER gültigen Key** — geschützte Routen sind ohne Änderung auch per Key erreichbar; `require_role(...)` respektiert den Key-Scope.
- **System-Daemons** = **Service-Account** (`auth.create_service("backup-daemon", roles=["reader"])`, kein Login/MFA) + Key (`auth.create_api_key(uid, name=…, expires_days=…)` → Klartext **einmalig**). Least-Privilege über die Rollen.
- **Sperren statt löschen:** `auth.revoke_api_key(id)` (Key gesperrt, bleibt in der Liste). Self-Service-Routen: `GET/POST /auth/apikeys`, `POST /auth/apikeys/{id}/revoke`.
- **Zwei Arten Key, und keine davon ist eine Admin-API.** `kind="automation"` (Vorgabe) arbeitet
  allein, trägt aber **nie das Admin-Flag** seines Besitzers und erfüllt keine Route, die Admin
  verlangt — der Weg für Dienste, Skripte und CI. `kind="human"` gilt nur **zusammen mit einer
  gültigen Sitzung desselben Kontos** und trägt dafür die vollen Rechte — der Weg für ein
  Werkzeug, das ein Mensch selbst bedient. Allein abgeflossen ist so einer wertlos. Bis 0.18.x
  gab es eine Art, und der Key eines Admins war eine vollständige Schreib-API: Nutzer anlegen,
  `is_admin` setzen, Passwörter zurücksetzen — ohne zweiten Faktor, ohne CSRF-Schicht. Ein
  abgeflossener CI-Key war die Instanz. (Bis 0.21.x hiessen die Arten `automat` und `mensch`; seit
  0.22.0 sind diese Namen ein Eingabefehler, der den neuen nennt, und die Migration schreibt
  gespeicherte Keys um — Rückschritt: `docs/OPERATIONS.md`.)
- **Ein Key läuft von selbst ab.** Ohne `expires_days` galt er bisher unbefristet, und das war
  der häufigste Fall. Jetzt greift `apikey_default_days` (90); `expires_days=0` heisst weiter
  „unbefristet", braucht aber `apikey_allow_unlimited=True` und steht dann im Audit-Eintrag.
- **Ein Key ist eine zweite Haustür — Aussperren nimmt ihn mit.** Der Admin-Passwort-Reset und
  das Sperren eines Kontos widerrufen dessen Keys, ebenso „**alle** Sitzungen beenden"
  (`scope=all`) durch den Nutzer selbst. Der **eigene** Passwortwechsel tut es bewusst nicht —
  ein Routine-Wechsel soll die Automatiken nicht reihenweise stilllegen —, nennt aber in der
  Antwort und im Protokoll, wie viele Keys weiter gelten (`api_keys_active`). Keys eines
  deaktivierten Kontos haben ohnehin nie angemeldet.

## OAuth für MCP-Clients

TinySesam kann der **OAuth-2.1-Autorisierungsserver** für Werkzeuge sein, die ein Mensch auf seinem eigenen Rechner
startet — allen voran **Claude Code** als MCP-Client (T-36, ADR-11). Die Anwendung hinter dem Proxy (ein MCP-Server,
jede HTTP-App) enthält **keinen OAuth-Code**: Die Forward-Auth nimmt das Access-Token an und reicht `Remote-*` weiter,
genau wie bei einer Sitzung. Die Anmeldung ist TinySesams eigene — Kette, TOTP, Passkey, Einrichtungsdurchgang —,
danach kommt eine Zustimmungsseite, die das Programm nennt, wohin die Antwort geht (`localhost:<Port>`) und was es
wie lange darf.

```python
TinySesamConfig(
    base_url="https://auth.example.com",            # der Aussteller — fest, nie aus der Anfrage
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/mcp"],  # Tokens gelten nur hier und darunter
)
```

**TinySesam braucht einen eigenen Ursprung** — einen eigenen Host (`auth.example.com`) oder, wenn alles auf einem Host
liegt, wenigstens einen eigenen Port (`https://app.example.com:8443` neben der Anwendung auf `:443`), nie einen Pfad in
der Anwendung. Drei Gründe: Der Aussteller ist der Ursprung von `base_url`; der Client findet die Metadaten des Servers
unter `/.well-known/oauth-authorization-server` auf genau diesem Ursprung (RFC 8414) und prüft `iss` dagegen
(RFC 9207); Anmelde- und Zustimmungsseite tragen eine eigene strenge CSP, die auf einem geteilten Ursprung die Seiten der
Anwendung bestimmen oder von ihnen aufgeweicht würde; und die Forward-Auth bewacht den Ursprung der Anwendung, während
TinySesams eigene Routen (`/auth/*`, die Metadaten) ohne sie antworten müssen. Für Aussteller und CSP reicht ein Port —
Browser sehen darin einen anderen Ursprung —, aber **Cookies trennen nicht nach Port** (RFC 6265, 8.5): Die
Forward-Auth-Vorlagen streichen jedes `tinysesam_*`-Cookie vor der Anwendung, und eine Anwendung mit eigenen Cookies
sollte diese Namen nicht verwenden.

Am Proxy zwei Ergänzungen auf dem Host der Anwendung (beide in `deploy/forward-auth/Caddyfile`):
`/.well-known/oauth-protected-resource*` geht an TinySesam (RFC 9728 — der Client erfährt, wo er sich anmeldet), und
ein 401, das TinySesam mit `X-TinySesam-Reason: oauth` kennzeichnet, wird mit seinem `WWW-Authenticate: Bearer
resource_metadata=…` durchgereicht statt in eine Weiterleitung zur Anmeldeseite verwandelt. Dann, auf dem Rechner mit
Claude Code:

```bash
claude mcp add --transport http myapp https://app.example.com/mcp
claude mcp login myapp          # oder /mcp in Claude Code — der Browser öffnet sich, anmelden, erlauben
```

Mit einem Zertifikat der eigenen CA (Heimnetz, IP-Adresse — siehe `docs/HOME-NETWORK.md`) braucht Claude Code die
Wurzel: `export NODE_EXTRA_CA_CERTS=/pfad/zu/root.crt` (oder derselbe Schlüssel unter `env` in Claude Codes
`settings.json`); eine IP-Adresse muss als Subject Alternative Name im Zertifikat stehen.

Was passiert und was es schützt:

- **Registrierung** (RFC 7591) ist offen, weil Claude Code sich selbst registriert — und nach jedem Abmelden oder
  Port-Konflikt neu. Nur öffentliche Clients (`token_endpoint_auth_method=none`) mit Loopback-Rückleitung
  (`http://localhost`, `127.0.0.1` oder `[::1]`, beliebiger Port); nichts, was der Client nennt, wird abgerufen, sein
  Name steht als „nicht geprüft“ da, 20 Registrierungen je Adresse und Stunde (eine IPv6-Adresse zählt als ihr /64),
  100 je IPv6-/48. Registrierungen, aus denen nie eine Verbindung wurde, räumt `gc()` ab; an der Obergrenze von 1000
  solcher Registrierungen weicht die am längsten unbenutzte, die älter als zehn Minuten ist — eine Flut sperrt also
  nicht bis dahin alle aus.
- **Autorisierungscode nur mit PKCE S256**, der Code lebt 60 s und gilt einmal — eine zweite Verwendung widerruft,
  was die erste erzeugt hat. Die Rückleitungsadresse wird exakt verglichen, nur ein Loopback-Port darf abweichen
  (RFC 8252 §7.3). Die Antwort trägt `iss` (RFC 9207). CIMD wird nicht beworben: Dafür müsste der Server ein
  Dokument aus dem Internet holen.
- **Tokens sind opak** (`tsat_…` Access, `tsrt_…` Refresh; 256 Zufallsbits plus eine Prüfsumme, die Secret-Scanner
  kennen), die Datenbank hält nur einen HMAC-Digest mit **Pepper** — `TINYSESAM_OAUTH_PEPPER` oder
  `oauth_pepper_file`; ohne beides wird er aus dem Hauptschlüssel abgeleitet (`config_check` sagt es).
- **Access-Token 1 h** (`oauth_access_token_ttl_sec`), bei jeder Anfrage gegen die Datenbank geprüft: Gerät trennen,
  Konto sperren oder Rolle entziehen wirkt sofort. Ein Token trägt nie das Admin-Merkmal.
- **Refresh-Tokens rotieren bei jeder Nutzung.** Kommt ein benutztes zurück, wurde es kopiert: Die ganze Verbindung
  wird widerrufen, Audit-Log und `on_security_event` (`oauth_token_reuse`) melden es. Sie laufen nach
  `oauth_refresh_idle_days` (90) ohne Nutzung ab und spätestens nach `oauth_refresh_max_days` (180) — dann meldet
  sich die Person neu an. `0` schaltet das Höchstalter bewusst ab; `config_check` verweist dann auf ASVS 5.0 V10.4.8.
  `oauth_refresh_grace_sec` (0) erlaubt zwei Prozessen eines Clients gleichzeitiges Erneuern; Claude Code serialisiert.
- **Geräte:** Die Kontoseite listet die verbundenen Programme (Name, Client, verbunden, zuletzt genutzt, Adresse,
  Ressource) mit „Trennen“; das Admin-Panel hat einen Reiter mit allen. `claude mcp logout` widerruft am Server
  (RFC 7009, ohne Client-Geheimnis). Konto sperren, ein Passwort-Reset (selbst, durch einen Admin oder
  `tinysesam passwd`) und „alle Sitzungen beenden“ trennen jedes Programm des Kontos, wie seine API-Keys.
- **Grenzen:** Die Connectors von Claude Desktop und Claude im Web rufen aus Anthropics Netz an und erreichen keinen
  Server, der nur in deinem LAN steht; Claude Code schon. Claude Code kann kein DPoP — Rotation ist der Schutz der
  Refresh-Tokens. Dienste ohne Mensch (`client_credentials`): nächster Abschnitt.

Die Ende-zu-Ende-Prüfung gegen das echte Claude-Code-CLI ist `tools/oauth-e2e/e2e.py` (von Hand: braucht `claude`,
Docker und Chrome).

## Ein Dienst ruft eine geschützte App auf

Ein Daemon, ein Backup-Job oder ein Skript auf einem Server — ein **Dienst ohne Mensch** — erreicht eine Anwendung
hinter TinySesam mit einem kurzlebigen Access-Token vom selben Server (T-60, ADR-13). Er weist sich mit **seinem
eigenen Schlüsselpaar** aus: Der private Schlüssel verlässt den Dienst nie, TinySesam behält nur die öffentliche
Hälfte. Nichts in der Datenbank, im Proxy-Log oder in einer Sicherung verschafft jemand anderem ein Token — anders als
ein API-Key, der eine kopierbare Zeichenkette ist. Gebaut wird nichts: Der Referenz-Client `tinysesam-client`
erledigt Kopplung, Tokens und Schlüsselwechsel.

```python
TinySesamConfig(
    base_url="https://auth.example.com",
    forward_auth_enabled=True,
    oauth_enabled=True,
    oauth_resources=["https://app.example.com/api"],
    oauth_service_clients=True,              # braucht: pip install 'tinysesam[services]'
)
```

**1. Einmal koppeln.** Im Admin-Panel bei den Schlüsseln eines Dienstkontos „Dienst koppeln“ (z. B. eines mit
`auth.create_service("backup", roles=["backup"])` angelegten), oder — für ein Skript, das als du selbst handelt — im
Abschnitt „Dienste“ der Kontoseite. Es gibt einen einmaligen **Kopplungscode** (`ABCD-EFGH-JKMN-PQRS`, gültig
`oauth_pairing_minutes`, 10 min). Aus eigenem Code: `auth.create_service_pairing(uid, name="backup",
resources=["https://app.example.com/api"], roles=["backup"])`. Das fertige Gateway hat weder Panel noch Kontoseite:
Dort schaltet `TINYSESAM_OAUTH_SERVICE_CLIENTS=1` die Dienste ein, und der Code kommt von der Kommandozeile, mit der
Umgebung des Dienstes — `docker exec <gateway> python -m tinysesam.gateway pair backup --create-service`
(`--resource`, `--roles`, `--name` wie oben). Auf dem Rechner des Dienstes:

```bash
pip install "tinysesam[services]==0.27.1"
tinysesam-client pair https://auth.example.com ABCD-EFGH-JKMN-PQRS
#   erzeugt ein Ed25519-Schlüsselpaar, schickt den öffentlichen Schlüssel mit einem Besitznachweis,
#   schreibt $XDG_CONFIG_HOME/tinysesam/client.json (Modus 0600; wählbar mit --key-file oder TINYSESAM_CLIENT_KEY_FILE)
```

**2. Die App aufrufen.** Aus der Shell oder aus Python mit `httpx` oder `requests`:

```bash
curl -H "Authorization: Bearer $(tinysesam-client token)" https://app.example.com/api/things
tinysesam-client request GET https://app.example.com/api/things
```

```python
from tinysesam.client import ServiceClient
sc = ServiceClient("/etc/backup/tinysesam.json")
httpx.get("https://app.example.com/api/things", auth=sc.httpx_auth())
requests.get("https://app.example.com/api/things", auth=sc.requests_auth())
```

Am Proxy ändert sich nichts: Forward-Auth nimmt das Token an und gibt `Remote-User` (das Dienstkonto),
`Remote-Groups` (seine Rollen) und `Remote-Kind: service` weiter — die Anwendung sieht ein angemeldetes Konto und
erkennt, dass es ein Dienst ist.

Was passiert und was es schützt:

- **Token-Anfrage** `grant_type=client_credentials` mit `private_key_jwt` (RFC 7523): ein JWT, signiert mit dem
  Schlüssel des Dienstes, `iss` = `sub` = Client-ID, **`aud` = der Aussteller** (`base_url`, als einziger Wert —
  RFC 10070; die Adresse des Token-Endpunkts wird abgelehnt), `exp` höchstens 5 min voraus, eine `jti`, die einmal
  gilt. Algorithmen `Ed25519`, `ES256` (und `EdDSA` für einen Ed25519-Schlüssel); nie `none` oder HMAC und nie ein
  Schlüssel, den das JWT mitbringt (`jwk`/`jku`/`x5u`). Jede OAuth-Client-Bibliothek mit `private_key_jwt` geht nach
  der Kopplung genauso.
- **Access-Token** opak, `oauth_service_token_ttl_sec` (15 min), **kein Refresh-Token** — der Dienst fragt einfach
  neu (der Client hält es vor und erneuert es). Gültig nur für die gekoppelte(n) Ressource(n) (sonst
  `invalid_target`), bei jeder Anfrage gegen die Datenbank geprüft.
- **Nie Admin.** Der Dienst handelt als sein Konto ohne Admin-Merkmal, mit optionalem Rollenumfang (auf die Rollen
  des Kontos gekürzt). Ein gesperrtes Konto, ein widerrufener Dienst oder eine entzogene Rolle wirkt bei der nächsten
  Anfrage.
- **Koppeln** geht nur aus einer interaktiven, frisch bestätigten Sitzung (nie mit einem API-Key); der Code liegt nur
  als Digest vor, gilt einmal, 20 Versuche je Adresse und Stunde, und jede Ablehnung steht im Audit-Log.
- **Schlüssel laufen ab** nach `oauth_service_key_days` (90); der Client **wechselt selbst** zur halben Laufzeit:
  Er schreibt den neuen Schlüssel zuerst als *pending*, meldet ihn an (signiert mit dem alten, belegt mit dem neuen)
  und schaltet dann um. Der alte gilt am Token-Endpunkt noch eine Stunde — Tokens unterwegs und andere Prozesse
  laufen weiter —, wechseln darf er aber nie mehr: das darf nur der aktuelle (ein kopierter alter Schlüssel übernimmt
  den Dienst nicht). `tinysesam-client rotate` wechselt sofort.
- **Widerruf:** Kontoseite und Admin-Panel (Reiter „Verbundene Programme“) listen jeden Dienst mit letzter
  Token-Anfrage, Adresse und Schlüsselablauf, mit „Widerrufen“; `auth.list_service_clients()`,
  `auth.revoke_service_client(client_id)`. Konto sperren, Admin-Passwort-Reset und „alle Sitzungen beenden“
  widerrufen seine Dienste wie seine API-Keys. Ereignisse: `oauth_service_paired`, `oauth_service_revoked`.

Andere Sprache? Koppeln ist eine JSON-Anfrage — `POST /auth/oauth/pair` mit `{"code", "jwk", "proof"}`, wobei
`proof` ein JWS des neuen Schlüssels ist mit `typ: tinysesam-pairing+jwt`, `aud` = Aussteller, `nonce` =
Base64url(SHA-256(Code ohne Bindestriche)) — und die Antwort (`client_id`, `token_endpoint`) ist alles, was ein
gewöhnlicher `private_key_jwt`-Client braucht. Schlüsselwechsel: `POST /auth/oauth/service/keys` (Formular: eine
Client-Assertion, `jwk`, `proof` mit `typ: tinysesam-key+jwt` und `sub` = Client-ID).

## App-Passwörter: WebDAV, CalDAV, Git hinter TinySesam

Manche Clients können keine Anmeldeseite öffnen: ein Datei-Sync über **WebDAV**, Kalender und Kontakte eines
Handys (**CalDAV/CardDAV**), **Git über HTTPS**, ein Backup-Skript. Sie sprechen nur Basic-Auth — Benutzername und
Passwort in jeder Anfrage. Für sie legt ein Konto auf seiner Kontoseite ein **App-Passwort** an (T-66): erzeugt,
einmal angezeigt mit Kopieren-Knopf, gültig nur für die gewählten Anwendungen, einzeln widerrufbar. Das eigene
Passwort des Kontos geht auf diesem Weg nie, der zweite Faktor lässt sich also nicht umgehen. (Samba und andere
Protokolle ohne HTTP sind nicht dabei — sie kommen nie am Proxy vorbei.)

Eingeschaltet wird je Anwendung — Vorgabe aus:

```python
TinySesamConfig(
    forward_auth_enabled=True,
    base_url="https://auth.example.com",
    trusted_redirect_hosts=["dav.example.com"],
    forward_apps={"dav.example.com": {"name": "Dateien", "app_passwords": True}},
    # app_password_default_days=365, app_password_allow_unlimited=False
)
```

Gateway: derselbe Schlüssel in `TINYSESAM_FORWARD_APPS='{"dav.example.com": {"name": "Dateien", "app_passwords": true}}'`;
`oidc_gateway()` schaltet dann die Kontoseite ein (im Gateway sonst aus), auf der die App-Passwörter entstehen. Der
Schnellstart-Stack hat das ganze Beispiel: `COMPOSE_PROFILES=webdav` fügt einen WebDAV-Server als Anwendung hinzu
(`deploy/quickstart/example.env`, „WebDAV behind the gate“).

**Am Proxy** ein Zweig mehr im Forward-Auth-Block der Anwendung (Caddy, wie in `deploy/forward-auth/Caddyfile`),
**vor** `@denied`: TinySesam antwortet einem Client ohne Browser mit `401`, `WWW-Authenticate: Basic
realm="Dateien"` und `X-TinySesam-Reason: basic`, und genau dieses 401 braucht der Client — eine Umleitung auf die
Anmeldeseite beendete seinen Sync. Und die Anwendung soll das Passwort nicht sehen:

```caddyfile
dav.example.com {
	route {
		reverse_proxy {$TS_AUTH_UPSTREAM:127.0.0.1:8000} {
			method GET
			rewrite /auth/forward
			header_up X-Forwarded-Method {method}
			header_up X-Forwarded-Uri {uri}
			header_up -X-Original-URL
			header_up -X-Original-URI
			@ok status 200
			handle_response @ok {
				request_header Remote-User {rp.header.Remote-User}
				request_header Remote-Groups {rp.header.Remote-Groups}
			}
			@basic {
				status 401
				header X-Tinysesam-Reason basic
			}
			handle_response @basic {
				header WWW-Authenticate {rp.header.Www-Authenticate}
				respond 401
			}
			@denied status 401
			handle_response @denied {
				redir {rp.header.X-Tinysesam-Location} 302
			}
		}
		# Die Anwendung vertraut Remote-User — das Passwort braucht sie nicht (und keine andere Zugangsangabe).
		reverse_proxy {$TS_APP_UPSTREAM:127.0.0.1:9000} {
			header_up -Authorization
			header_up -X-Api-Key
		}
	}
}
```

Dann auf dem Gerät: Benutzername wie bei der Anmeldung, das App-Passwort als Passwort — etwa
`rclone lsf :webdav: --webdav-url https://dav.example.com/ --webdav-user alice --webdav-pass "$(rclone obscure …)"`,
`git clone https://alice@git.example.com/repo.git` oder die Kontoeinstellungen des Handy-Kalenders. Ein Browser,
der dieselbe Anwendung öffnet, geht weiter zur Anmeldeseite (Anfragen mit `Sec-Fetch-*` oder `Accept: text/html`
bekommen keine Basic-Aufforderung — sie öffnete das browsereigene Passwortfenster). Die Vorlagen in `deploy/`
(`forward-auth`, `quickstart`, `home-network`) tragen den Zweig `@basic`; an einem Host ohne App-Passwörter tut er
nichts.

Was es schützt:

- **Format:** fünf Gruppen à fünf Kleinbuchstaben und Ziffern ohne `0 o 1 l i` (`k7qm3-x9tfa-…`), ≈ 124 Bit —
  am Handy gut zu tippen, Groß-/Kleinschreibung und Bindestriche zählen nicht. Gespeichert wird nur ein HMAC-Digest
  mit dem Pepper-Schlüsselbund (ADR-12, `tinysesam keys rotate --purpose oauth-pepper` lässt sie gültig).
- **Gebunden:** an sein Konto (der Benutzername muss passen), an die gewählten Anwendungen (Vorgabe: eine) und nur
  an `/auth/forward` — nie an TinySesams eigene Routen. Es trägt die Rollen des Kontos, aber **nie das Admin-Flag**,
  wie ein Automation-Key; ein Gate-Cookie gibt es nicht, ein Widerruf wirkt also bei der nächsten Anfrage. Ein Konto
  von einem Identity Provider behält sie nur, solange der Provider es noch bestätigt (`oidc_apikey_confirm_days`,
  wie bei API-Keys).
- **Laufzeit:** `app_password_default_days` (365 — von Hand ins Handy getippt, soll es nicht jedes Quartal
  brechen); wählbar sind 30, 90 oder 365 Tage, „nie“ nur mit `app_password_allow_unlimited=True`.
- **Anlegen nur mit frischer Bestätigung** (wie Passkey oder API-Key); der Inhaber bekommt das Ereignis
  `app_password_created` und, mit Mailer, einen Hinweis. Widerrufen mit den API-Keys, wenn das Konto gesperrt wird,
  ein Admin sein Passwort zurücksetzt oder der Inhaber sich überall abmeldet; der eigene Passwortwechsel lässt sie
  stehen und nennt die Zahl (`app_passwords_active`).
- **Raten:** ein falsches ist ein Fehlversuch in einem eigenen Topf (Paar, Konto, Adresse — die Anmeldung im Browser
  sperrt es nicht) und eine Zeile `failed login … method=app_password` für fail2ban. Ein bekanntes App-Passwort,
  das widerrufen oder abgelaufen ist, wird abgewiesen, ohne zu zählen — ein altes Handy sperrt seinen Besitzer nicht
  aus.
- **Sichtbar:** die Kontoseite listet Name, Anwendungen, erstellt, zuletzt genutzt und Adresse; das Admin-Panel hat
  einen Reiter mit allen. Audit `app_password_create`, `app_password_use` (einmal je Stunde und Adresse),
  `app_password_denied`, `app_password_revoke`, `app_passwords_revoked`.

Im Code: `auth.create_app_password(user_id, name, hosts=[…], expires_days=…)` (der Klartext einmal, unter
`secret`), `auth.list_app_passwords(user_id)` (`None`: alle Konten), `auth.revoke_app_password(id, user_id)`,
`auth.app_password_hosts()` (die Anwendungen, die sie annehmen). Die Ende-zu-Ende-Prüfung mit einem echten
WebDAV-Client hinter einem echten Caddy ist `tests/e2e_app_passwords.py` (von Hand: braucht Docker).

## Admin-Panel

Eingebautes Panel unter **`/auth/admin`** (Administratoren; Delegierte sehen ihren Teil — siehe
[Delegierte Verwaltung](#delegierte-verwaltung)), einbindbar ohne Extra-Setup:

- **Benutzer & Service-Accounts:** eine schlanke Liste (Name, Typ, Rollen, Status) mit Suche; ein Klick öffnet die
  eigene Seite des Kontos (Adresse `#user/<id>`) mit den Abschnitten *Profil*, *Zugriff* (Rollen,
  [Rollenstufen](#rollenstufen), Admin), *Anmeldung* (Passwort, Passkeys, API-Keys, Anmeldelink) und *Gefahrenzone*
  (sperren/entsperren — das Konto bleibt, Login blockiert, Sitzungen enden sofort; im Code: `auth.set_disabled` —,
  Owner, löschen). Die Rollen aus `available_roles` stehen nach Präfix gruppiert (`app:`, `ops:` …) mit Filter; eine
  Rolle, die ein Konto hat, die aber nicht konfiguriert ist, bleibt unter eigener Überschrift angehakt, statt beim
  Speichern zu verschwinden.
- **API-Keys** je User: erzeugen (einmalige Anzeige) / widerrufen.
- **Anmeldelink** je User (mit `magiclink_enabled`): Einmal-Link plus QR-Code, einmal angezeigt,
  ohne Mailer — siehe [Anmeldung per Link und per QR-Code](#anmeldung-per-link-und-per-qr-code).
- **Sitzungen:** aktive einsehen + beenden.
- **App-Passwörter** (wenn eine Anwendung sie annimmt): die aller Konten, mit Anwendungen, letzter Nutzung und
  Adresse; widerrufen — siehe [App-Passwörter](#app-passwörter-webdav-caldav-git-hinter-tinysesam).
- **Härtung:** Schwellen (Versuche/Sperrzeit/Rate-Limit) live einstellen.
- **Version:** die laufende Version plus ein Hinweis, wie Updates laufen — es gibt **keinen
  „jetzt aktualisieren"-Knopf**, und zwar mit Absicht ([ADR-2](../backlog/ADR-2-no-self-update.md)):
  Ein Auth-Modul, das zur Laufzeit Code nachlädt, ist eine Hintertür mit Bedienungsanleitung.
  Aktualisiert wird dort, wo installiert wurde. (Hier stand bis 0.18.0 ein Knopf, ein
  manual/auto-Modus und ein Version-Pin — nichts davon gibt es seit 0.12.0.)
- **Audit-Log** einsehen.

JSON-API unter `<mount>/api/*` (dieselben Aktionen — für eigene UIs / Automation).

### Rollenstufen

Manche Rollen haben Stufen: `coll:photos-read` lässt ein Konto eine Sammlung lesen, `coll:photos` schreiben. Je
Sammlung zwei Kästchen anzuhaken ist fehleranfällig; `role_levels` macht aus solchen Rollen im Panel **eine Wahl je
Eintrag** — „— / lesen / schreiben“:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    available_roles=["coll:photos", "coll:photos-read", "coll:recipes", "coll:recipes-read", "editor"],
    role_levels=[{
        "name": "collections",
        "label": {"en": "Collections", "de": "Sammlungen"},
        "levels": [  # niedrigste zuerst
            {"name": "read", "label": {"en": "read", "de": "lesen"}, "role": "coll:{1}-read"},
            {"name": "write", "label": {"en": "write", "de": "schreiben"}, "role": "coll:{1}"},
        ],
    }],
)
```

- **Jede Stufe fügt eine Rollenvorlage** mit `{1}` hinzu; eine Stufe steht für ihre Rolle und alle Rollen darunter.
  *schreiben* für `photos` speichert `coll:photos-read` **und** `coll:photos`; *—* speichert keine.
- **Die Einträge** (`photos`, `recipes`) kommen aus `available_roles`. Passt eine Rolle auf mehrere Vorlagen, gewinnt
  die spezifischste: `coll:photos-read` ist die Leserolle von `photos`.
- **Eine Auswahlhilfe, keine Hierarchie.** Ein Konto hat weiter einfache Rollen: `Remote-Groups`, das Gate-Token,
  Key-Scopes und `has_role` tragen genau die gespeicherten Rollen — `coll:photos` allein schließt
  `coll:photos-read` nicht ein.
- **Bestehende Konten werden nie still erweitert.** Ein Konto mit `coll:photos` ohne `coll:photos-read` erscheint als
  *unvollständig*; nichts ist vorausgewählt, und Speichern behält diese Rollen, bis ein Administrator eine Stufe wählt.
- **Eine Stufe wird nur angeboten, wenn alle ihre Rollen bekannt sind**: in `available_roles` für Administratoren
  (sonst durchgestrichen, die fehlende Rolle genannt), im Bereich für [Delegierte](#delegierte-verwaltung) (sonst
  ausgeblendet; ein Eintrag ohne vergebbare Stufe entfällt). Der Server prüft den Bereich wie bisher.
- **Beim Start geprüft:** mindestens zwei Stufen, jede Vorlage mit genau einem `{1}` und einem festen Teil, keine
  Vorlage doppelt, kein Komma, keine zwei Leitern, deren Vorlagen dieselbe Rolle treffen können, keine gleich
  spezifische Überschneidung in einer — Fehler; eine Leiter ohne Eintrag, ein Eintrag ohne die Rolle einer Stufe,
  ein Delegierter mit nur einem Teil einer Stufe — Warnungen.

**Montieren / einbetten / HTTPS:**
- **Standard:** automatisch unter `config.admin_path` (Default `/auth/admin`) — frei änderbar.
- **Woanders montieren:** `app.include_router(auth.admin_router(), prefix="/admin")` — beliebiger Pfad,
  Sub-App/**Subdomain** (Host-Routing der App) oder **eigener Port** (separate ASGI-App). Die UI ermittelt
  ihre Basis-URL selbst. `admin_enabled=False` schaltet den Auto-Mount ab.
- **In bestehendes Panel einbetten:** `admin_ui_enabled=False` → nur die JSON-API, eigene UI davor.
- **HTTPS** (`config.https_mode` + `auth.install_https(app)`): `force` = HTTP→HTTPS-Redirect;
  `warn` = läuft auch **ohne Zertifikat**, zeigt aber einen Warnhinweis im Panel; `off` = aus.
  Ein Tippfehler fliegt beim Bau auf — alles außer `force` heißt stillschweigend „kein Redirect",
  `https_mode="forse"` hätte den HTTPS-Zwang also wortlos abgeschaltet.
- **`https_mode="force"` verlangt `cookie_secure=True`.** Die Kombination mit `cookie_secure=False`
  wird beim Bau abgelehnt: Eine App, die jeden Request auf HTTPS umleitet, das Session-Cookie aber
  ohne `Secure`-Flag herausgibt, widerspricht sich — ein einziger HTTP-Aufruf reicht, damit es im
  Klartext mitgeht. `cookie_secure=False` bleibt für lokale Aufbauten ohne Zertifikat richtig
  (`https_mode="warn"`).
- **HSTS** (`config.hsts`, ASVS 3.4.1): Mit `https_mode="force"` setzt `install_https` zusätzlich
  `Strict-Transport-Security: max-age=31536000` auf jede HTTPS-Antwort der App, auch auf die eigenen Routen —
  nie über reines HTTP. Ab Werk ohne `includeSubDomains`: Auf einer Elterndomain bände es jede Subdomain an
  HTTPS; `; includeSubDomains` anhängen, sobald alle HTTPS sprechen (ASVS L2). `""` = kein Header (der Proxy
  setzt ihn; die Vorlagen unter `deploy/` tun das).
- **Keine API-Doku im Betrieb:** FastAPI liefert `/docs`, `/redoc` und `/openapi.json` ohne Anmeldung aus — das
  Schema nennt auch die Routen von TinySesam, und Swagger lädt von einem fremden CDN. Das Gateway schaltet sie
  ab; in der eigenen App `FastAPI(docs_url=None, redoc_url=None, openapi_url=None)` (ASVS 13.4.5).
- **Content-Security-Policy** (`config.csp`): Die eingebauten Seiten (Login, Konto, TOTP-Einrichtung,
  Fehlerseiten) tragen eine **strikte, nonce-basierte CSP** — ohne `unsafe-inline`. Je Antwort
  entsteht ein frischer Nonce und wandert in jedes `<script>`/`<style>` und in den Header; die Seiten
  sind inline-frei gebaut (kein `onclick`/`onsubmit`, kein `style=`), deshalb deckt der Nonce alles
  ab. `"strict"` (Vorgabe), `"off"` (kein Header — z.B. weil ein Proxy die CSP setzt) oder eine
  eigene Policy (ein `{nonce}` darin wird je Antwort ersetzt). Ein Template-Override, das ein
  `Response` zurückgibt, bleibt unangetastet und bekommt `ctx["nonce"]` für seine eigene.

## Delegierte Verwaltung

Teamleitungen verwalten die Konten ihres Teams im eingebauten Panel, ohne Administratoren zu werden (T-74). Das Modell
sind rollenbasierte Rechte mit Wirkungsbereich — wie Organisationseinheiten in einem Verzeichnis oder Administrative
Units in Entra ID: Eine **Delegiertenrolle** nennt die Rollen, die sie verwaltet, und wer sie trägt, handelt nur an
Konten in diesem Bereich. Eine Delegiertenrolle kann weitere Delegiertenrollen unter sich verwalten (`manages`); eine
zweistufige Hierarchie sieht so aus:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    available_roles=["X", "A", "A-read", "B", "B-read", "area-admin", "team-a-admin", "team-b-admin"],
    admin_delegates={
        "area-admin":   {"roles": ["X"], "manages": ["team-a-admin", "team-b-admin"]},
        "team-a-admin": {"roles": ["A", "A-read"]},
        "team-b-admin": {"roles": ["B", "B-read"], "can": ["create", "disable", "roles"]},
    },
)
```

- **Was ein Delegierter tut:** Konten und Einladungen anlegen, einen Anmeldelink ausstellen, sperren und entsperren,
  verwaltete Rollen setzen oder entfernen — nur an Konten, deren Rollen **alle** in den verwalteten Rollen liegen
  (mindestens eine). Nie an einem Admin-, Owner- oder Dienstkonto, nie am eigenen. Bewusst streng: Ein Konto in zwei
  Teams gehört dem, der über beiden steht.
- **Verwaltete Rollen:** die eigenen `roles` einer Delegiertenrolle, die Delegiertenrollen darunter (sie ernennt und
  setzt sie ab) und deren Rollen. Oben verwaltet `area-admin` X, A, A-read, B und B-read und ernennt `team-a-admin`
  und `team-b-admin`; `team-a-admin` verwaltet A und A-read. `manages` ist eine Hierarchie ohne Zyklen; eine Rolle
  darf mehrere Eltern haben.
- **Nie seitwärts oder nach oben:** Ein `team-a-admin` sieht weder Team B noch andere `team-a-admin`-Konten noch den
  `area-admin`. Ein Delegierter vergibt nie die eigene Delegiertenrolle oder eine darüber. Ein Konto mit mehreren
  Delegiertenrollen darf, was eine davon erlaubt, an den Konten dieser Rolle.
- **`can`** schränkt die Aktionen einer Delegiertenrolle ein (`create`, `invite`, `disable`, `roles`, `signin_link`;
  ohne Angabe alle). Es vererbt sich weder nach oben noch nach unten.
- **Der Rest des Panels bleibt bei Administratoren** — Passwort-Reset, Umbenennen, Löschen, Keys, Passkeys, Sitzungen,
  verbundene Programme, App-Passwörter, Härtung, Audit. Jede Grenze erzwingt der Server Route für Route; das Panel
  zeigt einem Delegierten nur seinen Reiter, seine Konten, seine Rollen und seine Schaltflächen. Kopfleiste und
  Kontoseite bieten ihm „Admin-Panel“ an. `require_admin` und eigene Admin-Routen ändern sich nicht: Ein Delegierter
  ist kein Admin.
- **Nur eine Browser-Sitzung:** Ein API-Key, ein OAuth-Token oder ein App-Passwort öffnet weder das Panel noch trägt
  es eine Delegiertenrolle (auch nicht in `Remote-Groups`) — wie das Admin-Flag. Die Sitzung behält sie, eine
  Anwendung kann also eine eigene Teamseite zeigen (`topbar_links` mit `{"role": "team-a-admin"}`). Eine App, die
  Profile aus `Remote-Groups` pflegt, frischt sie nur auf, wenn `Remote-Auth` `session` ist (leer gilt wie ein
  Token): Einer Token-Anfrage fehlen `admin` und die Delegiertenrollen absichtlich, sie darf das Profil nicht
  herabstufen.
- **Step-up und Audit:** dieselbe Bestätigung wie für Administratoren (`admin_require_mfa`); Anlegen, Einladen und ein
  Anmeldelink verlangen immer eine frische. Das Audit-Log nennt das handelnde Konto (`actor=`), die eigenen Zeilen des
  Panels auch `as=<Delegiertenrolle>`. Delegierte haben keine Audit-Ansicht: Die Zeilen tragen Adressen anderer.
- **Beim Start geprüft:** jede Rolle in `available_roles`, eine Delegiertenrolle nie in einer `roles`-Liste (ernannt
  wird nur über `manages`), `manages` nennt Delegiertenrollen, kein Zyklus, `can` nur bekannte Aktionen, keine
  Delegiertenrolle namens `admin`.
- **Rollen vom Identitätsanbieter** (`*_group_role_map`) setzt die nächste Anmeldung neu — die Änderung eines
  Delegierten an so einer Rolle hält nicht.

Was ein Delegierter übernehmen kann (ein Anmeldelink meldet im Konto an), steht in
[`SECURITY.de.md`](https://github.com/Ollornog/TinySesam/blob/main/i18n/SECURITY.de.md).

## Freigaben: Ein Token fragt, der Mensch bestätigt

Ein API-Key trägt nie die Admin-Flag oder eine Delegiertenrolle (R6-5, T-74) — ein Skript oder Claude mit Key kann also
keine Rollen setzen, keinen fremden Key widerrufen und kein Konto sperren. Mit Freigaben kann es **anfragen**, und der
Mensch bestätigt im Browser mit einem Step-up für genau diese Aktion:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(approvals_enabled=True, base_url="https://auth.example.com")
```

```http
POST /auth/api/approvals
X-Api-Key: tsk_…

{"type": "tinysesam.account.set_roles", "fields": {"account": "17", "add": ["editors"], "remove": ["viewers"]}}
```

```json
{"id": "apv_q4m7…", "state": "pending", "match_code": "418 207",
 "approve_url": "https://auth.example.com/auth/approvals/apv_q4m7…", "expires_at": 1767226200}
```

- **Typen (Etappe A):** `tinysesam.account.set_roles` (`account`, `add`, `remove` — nur Rollen, nie die Admin-Flag),
  `tinysesam.apikey.revoke` (`key`), `tinysesam.account.disable` (`account`). IDs sind Dezimal-Strings. Unbekannte,
  fehlende oder falsch typisierte Felder geben `400`.
- **Link und Code zeigen** (Claude gibt beides aus; bei MCP ist es eine URL-Elicitation). Die Seite zeigt denselben
  Code, was angefragt ist (aus TinySesams eigenen Texten und der Datenbank, nie freier Text des Anfragers), welcher Key
  gefragt hat und die Restzeit. Im Konto-Menü führt der Eintrag **Freigaben (n)** zu den offenen; `topbar_data()`
  trägt `"approvals": {"pending": n, "href": …}` für eine Anwendung mit eigener Leiste.
- **Der Mensch entscheidet** in einer Browser-Sitzung desselben Kontos — nie mit einem Token — und bestätigt für diese
  Freigabe noch einmal: Passwort, PIN oder TOTP (soweit `stepup_methods` es zulässt), ein an die Freigabe gebundener
  Passkey oder eine frische Anmeldung beim Anbieter. Dann führt TinySesam die Aktion mit dem Code des Admin-Panels und
  den Rechten aus, die die Sitzung in diesem Moment hat: ein Admin, ein Delegierter in seinem Bereich, die Inhaberin
  für ihren eigenen Key.
- **Der Token liest das Ergebnis:** `GET /auth/api/approvals/{id}` (`?wait=25` wartet bis zu 25 s) liefert `state` —
  `pending`, `consumed` mit `result` (`ok`, `forbidden`, `not_found`, `invalid`, `conflict`), `rejected`, `expired`,
  `withdrawn`. `DELETE` zieht eine offene Anfrage zurück. Nur der anfragende Key sieht seine Anfragen.
- **Limits** (`approval_open_per_account`, `approval_open_per_token`, `approval_requests_per_hour`,
  `approval_reject_limit`) antworten mit `429`; eine Anfrage wartet `approval_pending_sec` (Standard 10 min).
  `tinysesam gc` lässt die Zeilen ablaufen und löscht sie später.

Warum das „Admin- und Delegiertenrechte nie über Tokens“ nicht aufweicht:
[`SECURITY.de.md`, „Freigaben“](https://github.com/Ollornog/TinySesam/blob/main/i18n/SECURITY.de.md). Freigaben für eigene Aktionen einer Anwendung (signierte
Einmal-Bestätigungen) kommen mit Etappe B.

## Konten für Anwendungen: die Konten-API

Eine Anwendung hinter TinySesam braucht oft eigene Konten — ein Teamadmin in der Anwendung lädt eine Kollegin ein. Mit
der Konten-API legt die Anwendung **die Konten, die sie selbst anlegt**, über ihr Dienstkonto an und verwaltet sie, in
engen Grenzen: kein Passwort, Passkey oder TOTP, keine Adressänderung, kein Konto, das sie nicht angelegt hat, nie ein
Admin.

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    base_url="https://auth.example.com", magiclink_enabled=True,
    available_roles=["example-member", "example-editor", "staff"],
    apps={"example": {
        "account": "svc-example",                    # Dienstkonto (is_service); seine Automation-Keys sprechen für die App
        "name": {"en": "Example", "de": "Example"},
        "provisioning": {
            "roles": ["example-member", "example-editor"],                       # Allowlist
            "scopes": ["users:read", "users:invite", "users:update", "users:disable"],
            "link_ttl_min": 60, "max_accounts": 1000,
            "limits": {"create_per_hour": 60, "disable_per_hour": 60, "link_per_hour": 30, "taken_per_hour": 30},
        },
    }},
)
```

```http
POST /auth/api/users
X-Api-Key: tsk_…  (ein Automation-Key von svc-example)
TinySesam-On-Behalf-Of: 17

{"username": "lena", "display_name": "Lena M.", "email": "lena@example.org", "roles": ["example-member"]}
```

```json
{"id": 42, "username": "lena", "signin_url": "https://auth.example.com/auth/magic/…", "expires_at": 1767229800,
 "qr": "data:image/png;base64,…", "user": {"id": 42, "state": "active", "roles": ["example-member"], "…": "…"}}
```

| Route | Scope | Was |
|---|---|---|
| `POST /auth/api/users` | `users:invite` | eine Person mit Allowlist-Rollen anlegen (mindestens eine); den Einmal-Link gibt es nur in dieser Antwort |
| `GET /auth/api/users/{id}`, `GET /auth/api/users` | `users:read` | ein Konto oder eine Seite (`?limit=` ≤ 200, `&after=<id>`, `?role=`, `?state=`) → `{"users": […], "next": <id>\|null}` |
| `PATCH /auth/api/users/{id}` | `users:update` | `display_name` und `roles` (die ganze gewünschte Menge innerhalb der Allowlist; andere Rollen bleiben) |
| `POST /auth/api/users/{id}/disable`, `/enable` | `users:disable` | die eigene Sperre der Anwendung; `enable` hebt nur diese auf |
| `POST /auth/api/users/{id}/signin-link` | `users:invite` | ein neuer Einmal-Link, nur vor der ersten Anmeldung; ältere Links verfallen |
| `GET /auth/api/provisioning` | — | was der Key darf: App, Scopes, Rollen, Kontingent, Grenzen und was davon übrig ist |

- **Aufrufe gehen direkt an TinySesam**, mit einem Automation-Key des Dienstkontos (`X-Api-Key` oder
  `Authorization: Bearer tsk_…`). Ein Sitzungs-Cookie zählt nicht. Schreibaufrufe tragen `TinySesam-On-Behalf-Of`: die
  ID der Person, für die die Anwendung handelt, oder `-` für einen Job — das Audit hält sie als Behauptung neben dem
  Dienstkonto fest.
- **Ein Konto gehört der Anwendung,** wenn sie es angelegt hat (`managed_by`). Jedes andere Konto — und ein
  Administrator, Eigentümer, Dienstkonto oder Delegierter — antwortet mit `404` wie eines, das es nicht gibt. Hat der
  Betreiber einem Konto der Anwendung eine Rolle außerhalb der Allowlist gegeben, liest die Anwendung es weiter
  (`"other_roles": true`), aber Anzeigename, Sperre und Link antworten `409 account_shared`.
- **Was die Anwendung von einem Konto liest:** `id`, `username`, `display_name`, `email`, `email_verified`, `roles`
  (nur aus der Allowlist), `other_roles`, `state`, `created_at`, `first_login_at`, `last_login_at`, `delete_after`;
  `state` ist `active`, `disabled` (durch die Anwendung), `disabled_operator` (hebt nur der Betreiber auf) oder
  `deleting`.
- **Fehler** sind `{"error": <code>, "error_description": …}`: `401 unauthenticated`, `403 not_a_provisioning_app`,
  `403 scope_missing`, `404 not_found`, `400 invalid|actor_required|actor_invalid|role_not_allowed|name_invalid|
  email_invalid`, `409 username_taken|email_taken|quota_reached|account_shared|already_signed_in|account_disabled|
  disabled_by_operator`, `429 limit` mit `Retry-After`. Schreibrouten dürfen später `202` antworten (Freigaben); das
  heißt „noch nicht ausgeführt“.
- Die erste Anmeldung über den Link führt ein Konto ohne Faktoren durch den Einrichtungsgang (`/auth/setup`). Danach
  hilft sich die Person selbst (Anmeldelink an ihre Adresse, Passwort zurücksetzen), der Betreiber hilft — oder der
  Teamadmin der Anwendung setzt den Zugang zurück (unten).

### Zugang eines Kontos zurücksetzen: neues Handy, Passwort vergessen

Nach der ersten Anmeldung setzt ein Key allein nie etwas zurück (das wäre eine Übernahme). Die Anwendung fragt
stattdessen an, und ein Mensch bestätigt: ihr Teamadmin mit der Rolle `approver_role`, die nur der Betreiber (oder ein
dazu berechtigter Delegierter) vergibt. Konfiguration — `approvals_enabled=True`, der Scope `users:reset` und die Rolle:

```python
from tinysesam import TinySesamConfig

cfg = TinySesamConfig(
    base_url="https://auth.example.com", magiclink_enabled=True, approvals_enabled=True,
    available_roles=["example-member", "example-editor", "teamadmin"],
    apps={"example": {"account": "svc-example", "name": "Example", "provisioning": {
        "roles": ["example-member", "example-editor"],
        "scopes": ["users:read", "users:invite", "users:reset"],
        "approver_role": "teamadmin",               # nie in der Allowlist einer Anwendung (config_check lehnt das ab)
    }}},
)
```

```http
POST /auth/api/approvals
X-Api-Key: tsk_…  (ein Automation-Key von svc-example)

{"type": "tinysesam.account.reset_access", "subject": "17", "fields": {"account": "42"}}
```

`subject` ist die Konto-ID des Teamadmins, `account` das zurückzusetzende Konto (beide als Zeichenkette). Die Antwort
enthält `approve_url` und einen `match_code`; der Teamadmin öffnet den Link, vergleicht den Code und bestätigt mit einem
Step-up. Dann werden Passwort, PIN, TOTP und Passkeys von Konto 42 gelöscht, seine Sitzungen, Keys und App-Passwörter
enden — und die Anwendung holt den neuen Einmal-Link **einmal** ab: `GET /auth/api/approvals/{id}?wait=25` antwortet
`{"state": "consumed", "result": "ok", "output": {"signin_url": …, "expires_at": …, "qr": …}}`, jeder spätere Abruf
ohne `output`. Wer die Rolle beim Bestätigen nicht hat, bekommt `result: "forbidden"`, und nichts ändert sich.
Einzelheiten und Fehlercodes: [`spec/provisioning-api.md`](https://github.com/Ollornog/TinySesam/blob/main/spec/provisioning-api.md) §5; warum die Rolle nie von der
Anwendung kommt: `SECURITY.de.md`.

Was ein geleakter Anwendungs-Key höchstens kann und was nicht:
[`SECURITY.de.md`, „Konten-API“](https://github.com/Ollornog/TinySesam/blob/main/i18n/SECURITY.de.md).
Löschen mit Frist, die Übernahme bestehender Konten und die Kennzeichen im Panel kommen mit Etappe B.

## Neu in 0.5 — Kurzreferenz

Alles optional (per Config an/aus), einzeln und kombiniert nutzbar, Frontend überall ersetzbar.

- **Frontend austauschbar:** `auth.set_template(name, fn)` — `fn(auth, ctx)` gibt HTML-String **oder**
  eine eigene `Response` zurück. Alle 13 Namen: `login`, `pin`, `totp`, `totp_setup`, `reauth`,
  `account`, `register`, `forgot`, `reset`, `magic_request`, `magic_invalid`, `resource_unlock`,
  `error`. Eingebaute Renderer sind Fallback; `tinysesam.templates.DEFAULTS` führt die aktuelle Liste.
  Eine dieser Seiten aus einer eigenen Route zeigen: `auth.render_page(name, status=200, request=request,
  **ctx)` rendert sie — deinen Ersatz, wenn einer gesetzt ist, sonst die eingebaute Seite — mit CSP-Nonce,
  CSRF-Token und Mount-Präfix im `ctx` und gibt die `Response` zurück. `request` mitgeben: ohne entsteht ein
  neues CSRF-Token, und andere offene Formulare des Nutzers laufen ab.
- **Angemeldet bleiben:** `remember_me_enabled` — Checkbox → persistentes Cookie; ohne Haken reines
  Session-Cookie + kurze `session_ttl_transient_hours`.
- **Step-up / per-Route-MFA:** `Depends(auth.require(mfa=True))` (Sudo-Frische `stepup_max_age_sec`,
  → `/auth/reauth`). `admin_require_mfa=True` (seit H2 die Vorgabe) schützt das Panel zusätzlich mit frischer
  Bestätigung. **Neue Zugänge verlangen immer eine frische Bestätigung (H2, B-12):** Passkey anlegen, TOTP oder PIN
  einrichten, API-Key erstellen, geräteübergreifende Anmeldung bestätigen und ein OAuth-Programm zulassen — eine
  frische Anmeldung zählt, eine ältere Sitzung geht über `/auth/reauth`; der Einrichtungsdurchgang nach einem Link
  fragt nicht doppelt.
- **Startgeheimnis vom Admin (H2, T-46):** Ein Passwort, das der Admin im Panel setzt (neues Konto, Reset), gilt
  für eine Anmeldung — danach fragt `/auth/setup` nach einem eigenen (`admin_password_must_change`).
- **Der Inhaber erfährt von neuen Zugängen (H2, T-47):** `on_security_event` und, mit Mailer, eine Mail ohne Link
  (`notify_new_access`) bei neuem Faktor, API-Key, per QR angemeldetem Gerät, ausgestelltem Anmeldelink, vom Admin
  gesetztem Passwort, verbundenem Programm und Token-Wiederverwendung; die Kontoseite zeigt sie unter „Letzte
  Ereignisse“.
- **Faktor-Ketten (geordnet):** `login_chain=["oidc","password"]` + `login_chain_strict`; pro Route
  `require(factors=[...], strict=...)`. Faktoren: `password, pin, oidc, passkey, totp, magic`.
- **PIN pro User:** `pin_enabled` — Benutzer+PIN, eigener strenger Lockout, mit TOTP kombinierbar.
- **Geteiltes Ressourcen-Geheimnis:** `resource_locks_enabled` — `auth.set_resource_secret(name, secret,
  kind="pin"|"password")`, Guard `Depends(auth.require_resource(name))`, ganz ohne Benutzerkonto.
- **Magic-Link:** `magiclink_enabled` + SMTP-Config **oder** `auth.set_mailer(fn)`; `/auth/magic/request`,
  eingelöst unter `/auth/magic/{token}` — **dieser Endpunkt ist der Anmelde-Link und sonst nichts.**
- **`base_url` ist Pflicht**, sobald ein Mail-Weg (`magiclink_enabled`,
  `password_reset_enabled`, `signup_verify_email`), `oidc_enabled` oder `saml_enabled` an ist —
  sonst wirft der Konstruktor `ConfigError` und nennt, was einzutragen ist. Sie ist die einzige
  Quelle für die Adresse in Reset-, Magic-, Bestätigungs- und Einladungsmails, für die
  OIDC-Redirect-URI und für die SAML-Entity-ID. Ohne sie bliebe nur der `Host`-Header der
  Anfrage — den setzt der *Anfragende*, und wer einen Reset für ein fremdes Postfach anstößt,
  könnte den Link so auf seinen eigenen Server zeigen lassen. `trusted_redirect_hosts` ist dafür
  kein Ersatz: Steht dort mehr als ein Host, bestimmte weiterhin der `Host`-Header, welcher davon
  in den Link kommt. **Unter einem Unterpfad montiert** (`root_path`) gehört das Präfix in
  `base_url`: `base_url="https://example.com/sso"` — und es gilt für die **verschickten Links**,
  die es genau einmal tragen. Die eingebauten Seiten und ihre Umleitungen nehmen denselben Präfix
  aus dem Pfad der `base_url` (ohne `base_url`: aus dem `root_path` der Anfrage — `uvicorn
  --root-path /sso` hinter einem Proxy, der `/sso` abschneidet, oder `Mount("/sso", app)`).
  `login_path`, `login_redirect`, `logout_redirect` und `admin_path` sind Pfade der App *ohne*
  den Präfix.
  (Nicht `FastAPI(root_path=...)` an der App selbst: Damit fehlt der Präfix im Pfad der Anfrage,
  und daraus gebildete `next=`-Ziele zeigten aus der Montage heraus.) Dieselbe eine Regel gilt für die
  Methoden selbst, nicht nur für die eingebauten Routen: `magic_url`, `send_password_reset`,
  `send_login_link`, `send_verify_email` und `create_invite` gehen alle durch `public_base()`.
  Steht `base_url`, gewinnt sie — auch gegen einen zweiten eigenen Host aus
  `trusted_redirect_hosts`. Ohne sie wird eine fremde Basis mit `ConfigError` abgewiesen (kein
  Token, keine Mail). Wer ein eigenes Formular baut, holt die Basis aus
  `auth.public_base(request)` — leer heißt „keine vertrauenswürdige Adresse, abbrechen" — und
  nie aus `str(request.base_url)`.
- **Registrierung + Einladung:** `allow_signup` (+ `signup_verify_email`, `signup_invite_only`);
  Admin-Einladung `auth.create_invite(email, base_url, roles=…)`.
  Jeder verschickte Link hat **seinen eigenen Endpunkt**: `/auth/verify/{token}` (Adresse bestätigen),
  `/auth/invite/{token}` (Einladung), `/auth/reset?token=…` (Passwort zurücksetzen). Sie hängen an
  ihrer eigenen Funktion, nicht am Magic-Link — `magiclink_enabled=False` nimmt Bestätigung und
  Einladung nicht mehr mit.
- **Konto-Seite:** eingebaut unter `/auth/account` (`account_enabled`) — Passwort/PIN/2FA/Passkeys/Keys.
- **Forward-Auth:** `forward_auth_enabled` → `GET /auth/forward` (200 + `Remote-User/Groups/Email/…/Kind` bzw.
  401 + `X-TinySesam-Location`). Beispiele: [`deploy/forward-auth/`](../deploy/forward-auth/) (Caddy/nginx/Traefik;
  `nginx-path.conf` deckt den anderen häufigen Zuschnitt ab — ein Host, nur einzelne Pfade geschützt,
  dahinter statische Dateien und PHP).
  **Welcher Proxy:** Empfohlen ist Caddy — mit dem Gate-Token (ADR-9) prüft er die meisten Anfragen selbst, ohne
  TinySesam zu fragen. nginx (auch mit PHP über FastCGI) und Traefik werden unterstützt und gegen die echten Proxys
  getestet (`tests/test_proxies.py`, wie Caddy in `tests/test_gate_caddy.py`); bei ihnen geht jede Anfrage über
  `/auth/forward`. Traefik braucht `aliasHeadersStrategy: delete` in der statischen Konfiguration, sonst erreicht ein
  vom Browser gesendetes `Remote_User` ein CGI-/WSGI-/PHP-Backend als `HTTP_REMOTE_USER` (siehe Kopf von `traefik.yml`).
  **Rollen am Proxy:** der Proxy sagt, was er verlangt — `GET /auth/forward?roles=redaktion,admin` oder
  Header `X-TinySesam-Roles`. Eine der genannten Rollen genügt; angemeldet, aber Rolle fehlt → **403**
  (kein 401, der schickte den Benutzer zum Login und von dort sofort zurück). Ohne die Angabe bleibt
  der Endpunkt binär wie bisher. Mehrere Angaben werden UND-verknüpft: ein Client, der selbst eine
  anhängt, kann die Prüfung nur verschärfen, nie aufweichen.
  **Welche Header hinausgehen**, steuert `forward_headers` — Vorgabe `Remote-User/-Name/-Email/-Groups`
  (der Authelia-Satz) und `Remote-Id`, die Konto-ID: Nutzer ändern Benutzername und Adresse selbst,
  eine App ordnet deshalb über `Remote-Id` zu. `Remote-Auth` sagt, wie sich die Anfrage angemeldet hat —
  `session`, `oauth`, `apikey` oder `app-password`; eine Anfrage mit gültigem Gate-Token ist eine `session` (das
  Token trägt den Wert als signierten Claim). Daran sieht die App, warum `Remote-Groups` abweichen: Token, Schlüssel
  und App-Passwort tragen nie `admin`. **Die Gruppen einer Token-Anfrage sind absichtlich unvollständig:** Sobald
  `Remote-Auth` nicht `session` ist, fehlen `admin` und alle Delegiertenrollen. Eine App, die ein Profil aus
  `Remote-Groups` pflegt, aktualisiert es nur bei einer `session`-Anfrage und stuft es bei einer Token-Anfrage nie
  herab — sonst kippt das Konto mit jedem API-Aufruf zwischen Admin und Nicht-Admin. Ein leeres oder fehlendes
  `Remote-Auth` gilt wie ein Token. `Remote-Kind` sagt, was das Konto ist — `service` für ein Dienstkonto, sonst
  `user` — und geht **immer** mit (ein Gate-Token trägt es als Claim `ts_kind`): `Remote-Auth` sagt, wie eine Anfrage
  hereinkam, `Remote-Kind`, ob ein Mensch oder ein Dienst dahintersteht (ein gepaarter Dienst, der als Mensch handelt,
  ist `oauth` + `user`). Ein Konto, dessen `is_service` weder 0 noch 1 ist, bekommt 403, nie ein geratenes `user`.
  **Rechte nie an `Remote-User` oder `Remote-Email`
  binden:** Ein Name oder eine Adresse, die frei wird (Konto gelöscht oder umbenannt), kann ein
  anderes Konto übernehmen und trägt sie dann in die App. Der Proxy muss jeden dieser Header selbst setzen (die
  Beispiele unter `deploy/forward-auth/` tun das), sonst reicht er einen gefälschten durch. Eine Zuordnung benennt sie um oder lässt sie weg: `{"user": "X-WEBAUTH-USER"}`
  verschickt genau diesen einen Header (Grafana-Stil), eine Liste denselben Wert unter mehreren Namen.
  Die Zuordnung ist die **vollständige** Liste — `email` wegzulassen ist der Weg, der App die Adresse
  nicht mehr zu geben. Die Vorgabe-Zuordnung ist `TinySesam.FORWARD_HEADERS_DEFAULT`; wer einen Header
  ändern und die übrigen behalten will, geht von einer Kopie aus:
  `forward_headers={**TinySesam.FORWARD_HEADERS_DEFAULT, "user": ["Remote-User", "X-WEBAUTH-USER"]}`.
  Beim Umbenennen den neuen Namen in der Proxy-Konfiguration mitziehen. **Eine Ausnahme von „vollständig“:** Die Felder
  in `TinySesam.FORWARD_HEADERS_MANDATORY` (`kind`) gehen auch dann mit, wenn die Zuordnung sie weglässt — unter ihrem
  Vorgabenamen; `{"kind": "X-Account-Kind"}` benennt um, `{"kind": []}` ist ein `ConfigError`. Gate-Clients nach
  Spezifikation v2 weisen eine Anfrage ohne es ab, also erst TinySesam und die Proxy-Vorlage aktualisieren, dann die
  Anwendungen (`SECURITY.md`).
- **Open-Redirect-Schutz:** alle `?next=` laufen über `safe_next` (nur relative Pfade bzw.
  `trusted_redirect_hosts`; der Host der eigenen `base_url` zählt immer mit und muss dort nicht
  wiederholt werden). **`cookie_domain` für SSO über Subdomains** — und ohne das Feld gilt: Das
  Session-Cookie ist host-only, deshalb wird die Login-Seite **auf dem angefragten Host** gebaut
  statt auf `base_url`. Sonst setzte TinySesam das Cookie auf Host A und schickte den Browser nach
  Host B, wo es nicht mitgeschickt wird — eine Endlosschleife ohne Fehlermeldung. Dafür kommen nur
  Hosts aus `trusted_redirect_hosts` infrage, ein gefälschter `X-Forwarded-Host` biegt also
  niemanden um. `base_url` selbst bleibt unangetastet: OIDC-/SAML-Callbacks behalten ihre feste Adresse.

Vollständige Demo: [`examples/showcase.py`](../examples/showcase.py) — `/` ist die Projekt-Website selbst,
`/demo` ein Frontend, dessen Login-/Konto-/Admin-Panels **read-only Live-Vorschauen** der echten Seiten sind (`uvicorn examples.showcase:app`).

**Die Live-Demo ist ein Beispiel-Frontend, das mitgeliefert wird** — kein Bestandteil der Bibliothek
und keine Vorgabe. Sie zeigt einen Weg, die eingebauten Seiten einzubinden; Aussehen und Aufbau sind
frei ersetzbar. Wer TinySesam einbaut, bringt sein eigenes Frontend mit oder nimmt dieses als Vorlage.

## LDAP / lldap

Passwort-Login kann gegen ein Verzeichnis (lldap, OpenLDAP, AD) geprüft werden — als Backend hinter dem
normalen Passwort-Formular (Faktor `password`). `pip install 'tinysesam[ldap]'`:

```python
TinySesamConfig(
    ldap_enabled=True, ldap_url="ldaps://lldap:6360",   # oder ldap:// + ldap_start_tls=True
    ldap_user_dn_template="uid={username},ou=people,dc=example,dc=com",   # Direkt-Bind (lldap)
    # ODER Search-then-Bind: ldap_bind_dn=…, ldap_bind_password=…, ldap_user_base=…, ldap_user_filter="(uid={username})"
    ldap_allowed_groups=["staff"],   # optionales Gate (memberOf), leer = alle
    ldap_auto_create=True,           # unbekannten LDAP-User lokal anlegen
    # ldap_tls_ca_file="/etc/ssl/eigene-ca.pem",   # interne CA; leer = Systemspeicher
)
```
Lokale Passwörter und LDAP koexistieren (erst lokal, dann LDAP). Rollen/2FA/Ketten gelten wie sonst.

> **Klartext muss man sagen.** `ldap://` ohne StartTLS schickt das Passwort des Dienstkontos
> **und** jedes Benutzerpasswort bei jeder Anmeldung offen über das Netz. Seit 0.20.0 ist das ein
> **Aufbaufehler**; `ldap_allow_plaintext=True` sagt ausdrücklich, dass es so gewollt ist (ein
> Verzeichnis auf demselben Host). Das Zertifikat wird per Vorgabe geprüft (`ldap_tls_verify`),
> und das Dienstkonto bindet **nach** dem TLS-Upgrade, nicht davor.

> **Identitäten hängen an einer stabilen Kennung, nicht an einem Namen.** Ein Benutzername ist
> nicht fälschungssicher: Wer im Verzeichnis umbenennt oder ein gelöschtes Konto unter demselben
> Namen neu anlegt, landete bis 0.19.0 im selben lokalen Konto mitsamt seinen Rollen. LDAP bindet
> jetzt `entryUUID`/`objectGUID` (`ldap_attr_id`), SAML die `NameID` (`saml_attr_id` für IdPs mit
> transienten NameIDs). Ein Konto, das schon an eine **andere** Kennung gebunden ist, wird nie
> übernommen — dieser Fall wird abgewiesen und protokolliert. Konten von vor dieser Fassung
> binden sich beim nächsten Login über den Namen selbst nach, einmal, ebenfalls protokolliert —
> aber nur in `federation_name_binding_days` (Vorgabe 30) Tagen ab dem ersten Start mit
> eingeschalteter Quelle bzw. ab der Anlage des Kontos; danach fiele ein ruhendes Konto an die
> nächste Person, die im Verzeichnis denselben Namen bekommt. Den Rest bindet man ausdrücklich:
> `auth.federation_bind_existing("ldap")` (Vorgabe Trockenlauf, `apply=True` schreibt; SAML
> mit `mapping={name: nameid}`), oder man öffnet ein einzelnes Konto mit
> `auth.federation_unbind(source, user_id)`. Ein selbst gewählter Name (Registrierung,
> Umbenennen in der Selbstbedienung) bindet nie über den Namen, ebenso wenig ein Name, den eine
> andere Quelle beim Anlegen mitgebracht hat (ein über OIDC angelegtes Konto bindet sich nie über
> den Namen an LDAP oder SAML — beim IdP kann der Name selbst gewählt sein). Liefert das Verzeichnis keine
> Kennung, entscheidet weiter der Name und eine Logzeile sagt das;
> `federation_require_stable_id=True` macht daraus eine Abweisung.

> **Verweisen (Referrals) folgt TinySesam nie** — und das steht jetzt im Log. ldap3 verfolgt einen
> `SearchResultDone resultCode=10` von sich aus und bindet auf dem Host, den die *Antwort* nennt,
> mit denselben Zugangsdaten (Fund F-28: DN und Klartext-Passwort des Dienstkontos kamen bei einem
> fremden Server an). Deshalb steht `auto_referrals=False` auf jeder Verbindung, ohne Schalter
> zurück. Der Preis: Eine Suche, die ein Verzeichnis per Verweis beantwortet, endet ergebnislos —
> die Anmeldung scheitert und sieht wie ein falsches Passwort aus. Dieser Fall schreibt jetzt eine
> Zeile über den Logger `tinysesam.security` und nennt den verwiesenen Host. **Steht sie für jeden
> Nutzer einer Domäne da, den Global Catalog abfragen** (Port 3268/3269) und `ldap_user_base` auf
> die Forest-Wurzel setzen, statt einen Domain-Controller zu fragen, der weiterverweist.

## SAML 2.0

SP-Login gegen einen SAML-IdP (ADFS, Okta, Keycloak, …). `pip install 'tinysesam[saml]'` (braucht System-`libxmlsec1`):

```python
TinySesamConfig(
    saml_enabled=True, base_url="https://app.example.com",
    saml_idp_sso_url="https://idp.example.com/sso",
    saml_idp_x509cert="MIID…",                 # IdP-Signaturzertifikat (PEM-Body)
    saml_attr_email="email", saml_attr_groups="groups", saml_allowed_groups=["staff"],
)
```
Routen: `/auth/saml/login` (→ IdP), `/auth/saml/acs` (Assertion, signaturgeprüft — von CSRF ausgenommen),
`/auth/saml/metadata` (SP-Metadaten für den IdP). Faktor `saml`, in Ketten kombinierbar.


> **`saml_idp_entity_id` setzen**, solange nicht sicher ist, dass sie der SSO-URL entspricht.
> Leer nimmt TinySesam an, der IdP nenne sich bei seiner SSO-URL. Keycloak (und andere) tun das
> nicht: dort ist sie `https://…/realms/<realm>`, während die SSO-URL auf `/protocol/saml` endet.
> Passt es nicht, wird **jede** Assertion mit `Invalid issuer` abgelehnt. Aus den IdP-Metadaten
> abschreiben (`entityID=`). Der Grund einer Ablehnung geht immer an den Logger
> `tinysesam.security` — nie an den Browser.

> **Nur SP-initiiert, und dafür braucht es `cookie_secure=True`.** Jede Assertion muss einen
> `AuthnRequest` beantworten, den diese App auch geschickt hat: `/auth/saml/login` legt die
> Request-ID in ein kurzlebiges Cookie, die ACS weist alles ab, dessen `InResponseTo` nicht dazu
> passt. Das schliesst Login-CSRF — ohne die Bindung konnte jeder mit einer gültigen Assertion
> sie in den Browser eines Fremden POSTen. Zwei Folgen: **IdP-initiierte Logins gibt es nicht
> mehr** (Einstieg ist `/auth/saml/login`), und das Cookie übersteht den Cross-Site-POST des IdP
> nur als `SameSite=None; Secure`. Mit `cookie_secure=False` bleibt es beim Wert aus
> `cookie_samesite`, den ein Browser bei diesem POST nicht mitschickt — für lokale Läufe und den
> TestClient in Ordnung, gegen einen echten IdP nicht. Der Grund steht im Log
> `tinysesam.security`.

> **Alle Felder auf einen Blick:** [`CONFIGURATION.md`](../CONFIGURATION.md) führt alle 120
> Config-Felder mit Typ, Vorgabe und Bedeutung — erzeugt aus `config.py`, kann also nicht
> auseinanderlaufen. Diese README erklärt die *Wege*; jene Seite beantwortet *„es gibt da ein
> Feld — was tut es?"*

## Presets

Fertige Config-Presets für gängige Fälle (Rest via `**overrides`, z. B. `db_path=`):

```python
# Active Directory (on-prem, via LDAP) — Direkt-Bind per UPN oder Search-then-Bind
TinySesamConfig.active_directory(ldap_url="ldaps://dc.corp:636", upn_suffix="corp.example.com", db_path="app.db")

# Entra ID / Azure AD (Cloud-AD, via OIDC)
TinySesamConfig.entra_id(tenant_id="…", client_id="…", client_secret="…", db_path="app.db")

# Reines OIDC-Forward-Auth-Gateway (siehe unten)
TinySesamConfig.oidc_gateway(issuer="…", client_id="…", client_secret="…", base_url="…")
```

## Als reines OIDC-Gateway (Preset)

Wer nur **OIDC-SSO vor beliebige Apps** will (Authelia-/oauth2-proxy-Stil), betreibt TinySesam als
Forward-Auth-**Gateway** — ohne eigene App, nur `pip install 'tinysesam[gateway]'`:
(`[gateway]` = `[oidc]` **plus ASGI-Server**. Mit `[oidc]` allein endet der Startbefehl unten
in `ModuleNotFoundError: uvicorn` — genau diese Kombination stand hier vorher.)

```bash
export TINYSESAM_OIDC_ISSUER=https://id.example.com \
       TINYSESAM_OIDC_CLIENT_ID=gateway TINYSESAM_OIDC_CLIENT_SECRET=… \
       TINYSESAM_BASE_URL=https://auth.example.com \
       TINYSESAM_COOKIE_DOMAIN=.example.com \
       TINYSESAM_PROTECTED_HOSTS=app.example.com,wiki.example.com
python -m tinysesam.gateway          # oder: uvicorn tinysesam.gateway:app --ws none --no-proxy-headers
```

Mit eigenem `uvicorn`-Aufruf `--ws none` mitgeben: Ist eine WebSocket-Bibliothek installiert, beantwortet uvicorn
sonst die Forward-Auth-Prüfung einer WebSocket-App (sie trägt das `Upgrade: websocket` des Clients) mit 403 (B-5).
`python -m tinysesam.gateway` setzt das selbst.

Der Reverse-Proxy ruft je Request `GET /auth/forward`. Der Gateway hängt den vollen
`/auth/*`-Router ein — mit `password_enabled=False` und OIDC als einziger Methode bleiben davon
der OIDC-Login, der Forward-Auth-Endpunkt, Logout und `/me`. Eine schmale Konfiguration also,
keine Ein-Routen-App.
Programmatisch: `TinySesamConfig.oidc_gateway(issuer=…, client_id=…, client_secret=…, base_url=…)`.
Fertiges [`deploy/forward-auth/docker-compose.yml`](../deploy/forward-auth/) (Gateway + Caddy) liegt bei.

### Gateway und Caddy in 5 Minuten

[`deploy/quickstart/`](../deploy/quickstart/) ist ein Stack: das Gateway, Caddy mit caddy-jwt und eine
Beispielanwendung hinter dem Tor — nichts zu bauen, jedes Abbild aus einem Release oder per Digest gepinnt.

```bash
git clone https://github.com/Ollornog/TinySesam && cd TinySesam
cp deploy/quickstart/example.env deploy/quickstart/.env && chmod 600 deploy/quickstart/.env
$EDITOR deploy/quickstart/.env        # OIDC-Anbieter, zwei Hostnamen, TLS-Modus
docker compose -f deploy/quickstart/docker-compose.yml up -d
```

Beim Anbieter `https://<TS_AUTH_HOST>/auth/oidc/callback` als Weiterleitungs-URL eintragen, `https://<TS_APP_HOST>`
öffnen: Nach der Anmeldung zeigt die Beispielanwendung die `Remote-*`-Header, die TinySesam gesetzt hat. Danach den
eigenen Dienst an die Stelle von `app` setzen.

- **TLS-Modus** `TS_TLS`: `acme` (öffentliche Domain, Let's Encrypt), `dns` (Domain, die nur zu Hause auflöst, DNS-01 —
  braucht ein Caddy mit dem Modul des DNS-Anbieters: `docker build --build-arg
  CADDY_EXTRA_MODULES=github.com/caddy-dns/<anbieter> deploy/forward-auth/caddy-gate`), `internal` (Domainnamen mit
  Caddys eigener CA) oder `ip` (nackte IP-Adresse — vorher [`docs/HOME-NETWORK.md`](../docs/HOME-NETWORK.md) lesen,
  Englisch).
- **Enthalten:** Identitäts-Header aus dem Browser werden entfernt, HSTS überall, wo eine Domain ist, Abmelden an der
  Anwendung, OAuth für MCP-Clients (`TS_OAUTH_RESOURCES`). **Nicht enthalten:** der fail2ban-Zulauf, mehrere
  Anwendungen mit je eigenem Client, Freigabepfade, das Gate-Token — die kommen aus
  [`deploy/forward-auth/`](../deploy/forward-auth/).
- Jeder Pull-Request fährt diesen Stack in den Modi `ip` und `internal` (`tests/test_quickstart.py`).

### Gate-Token: der Proxy prüft selbst (ADR-9)

Vor einer fremden Anwendung fragt der Proxy ohne Weiteres für **jede** Anfrage `/auth/forward` —
auch für jedes Skript, Stylesheet und Icon. Mit `gate_token_enabled=True` (im Gateway
`TINYSESAM_GATE=1`) liefert eine erfolgreiche Prüfung zusätzlich ein kurzlebiges, mit Ed25519
signiertes Token. Der Proxy legt es als Cookie `__Host-tinysesam_gate` auf den Host der Anwendung
und prüft es danach **selbst**; TinySesam wird erst wieder gefragt, wenn es fehlt oder abläuft.
Der Rückweg ist die bestehende Forward-Auth, eine Anfrage samt Body geht also nicht verloren.

- **Proxy:** Caddy mit dem Plugin [caddy-jwt](https://github.com/ggicci/caddy-jwt) — Vorlage
  [`deploy/forward-auth/Caddyfile.gate`](../deploy/forward-auth/Caddyfile.gate), Abbild
  `ghcr.io/ollornog/tinysesam-caddy-gate:v0.27.1` (gebaut aus
  [`deploy/forward-auth/caddy-gate/`](../deploy/forward-auth/caddy-gate/)).
- **Schlüssel:** ein eigener, zufälliger Ed25519-Schlüssel (seit T-48, ADR-12 — bis 0.25.x aus dem
  Tresor-Schlüssel abgeleitet): `TINYSESAM_GATE_KEY`, `gate_key_file`, sonst mit dem Tresor-Schlüssel verschlüsselt
  in der Datenbank. Der Proxy nimmt `tinysesam gate-key --db …` als `sign_key` (`TS_GATE_PUBKEY`; nach einer
  Gate-Rotation neu, bis dahin gehen die neuen Tokens den Rückweg). **Nicht `jwk_url`** mit caddy-jwt 1.4.0, obwohl
  TinySesam `/auth/gate/jwks.json` veröffentlicht: Ein einziger gescheiterter erster Abruf lässt danach jede Anfrage
  mit Gate-Token hängen. Jedes Token trägt `typ: tinysesam-gate+jwt` und seine `kid`.
- **`caddy reload` unter systemd:** Der Reload liest das Caddyfile im *aufrufenden* Prozess, `{$TS_GATE_PUBKEY}` und
  jeder andere `{$…}`-Platzhalter (auch `{$CREDENTIALS_DIRECTORY}`) wird also dort aufgelöst. Ein `ExecReload=` ohne
  die Umgebung lässt sie leer; der Reload scheitert (z. B. `open /tls.crt`), und Caddy läuft still mit der alten
  Konfiguration weiter. Die Variablen gehören in `EnvironmentFile=` auf Unit-Ebene — das gilt auch für `ExecReload=` —,
  und `CREDENTIALS_DIRECTORY=/run/credentials/<unit>` steht in `ExecReload=` ausdrücklich. Mit Docker
  (`docker compose exec caddy caddy reload`) erbt der Reload die Umgebung des Containers; dort ist nichts zu tun.
- **Rollen:** Verlangt der Proxy Rollen (`X-TinySesam-Roles`), stehen sie in der Zielgruppe des
  Tokens (`app.example.com|roles=admin`); ein Token ohne Rollenangabe gilt dort nicht.
- **Preis:** Abmelden, Sperren oder eine entzogene Freigabe greifen am Proxy erst, wenn das Token
  abläuft — `gate_token_ttl_sec`, Vorgabe 300 Sekunden.
- **Gate-Clients in anderen Sprachen:** Eine Anwendung hinter dem Gate, die die `Remote-*`-Header liest oder das
  Gate-Token selbst prüft, folgt der [Gate-Client-Spezifikation](../spec/gate-client.md) (englisch: Token-Format,
  Prüfreihenfolge, Gruppen, JWKS-Regeln, die nie hängen). Ihre sprachneutralen Test- und Angriffsvektoren in
  [`spec/vectors/`](../spec/vectors/) werden aus TinySesams eigenem Code erzeugt. Der **Go-Client** liegt in
  [`clients/go/`](../clients/go/) (`net/http`-Middleware, Header- und Token-Modus, nur Standardbibliothek; noch nicht
  veröffentlicht, Nutzung per Commit), der **Rust-Client** in [`clients/rust/`](../clients/rust/) (Crate
  `tinysesam-gate`: Header- und Token-Modus, der Abruf des Schlüsselsatzes hinter dem Feature `jwks`, unabhängig vom
  Web-Framework über die Crate `http`, ein axum-Beispiel; nicht in der Rust-Crate-Registry veröffentlicht, Nutzung als
  Git-Abhängigkeit), der **JS/TS-Client** in [`clients/js/`](../clients/js/) (TypeScript, ESM, ohne
  Laufzeit-Abhängigkeit: WebCrypto `Ed25519` und `fetch`, läuft daher unter Node, Deno, Bun und Edge-Runtimes;
  Node/Express-Middleware und ein Fetch-Adapter für Hono und Edge-Handler; nicht bei npm veröffentlicht, Nutzung aus dem
  Repository), der **PHP-Client** in [`clients/php/`](../clients/php/) (Paket `tinysesam/gate`, PHP 8.4+: nur ext-sodium
  und PSR-Schnittstellen, eine PSR-15-Middleware, `$_SERVER` für PHP-FPM, ein Schlüsselsatz-Cache in einer Datei, den
  die Prozesse eines Hosts teilen; nicht bei Packagist veröffentlicht, Nutzung aus dem Repository). Der
  **Python-Client** gehört zum Paket: `tinysesam.gate_client` (WSGI/ASGI, ohne FastAPI), nächster Abschnitt.

### Gate-Client für Flask, Django und andere Python-Apps (T-86)

Eine Anwendung hinter dem Gate, die nicht auf FastAPI baut, nutzt `tinysesam.gate_client`: die
[Gate-Client-Spezifikation](../spec/gate-client.md) in Python, geprüft gegen jeden Vektor in `spec/vectors/`. Er prüft
nur; er meldet niemanden an und stellt kein Token aus. Der Import zieht weder FastAPI noch den Rest von TinySesam nach —
nur die Standardbibliothek und `cryptography`, das `pip install tinysesam` ohnehin mitbringt.

```python
from tinysesam import gate_client

gate = gate_client.GateClient(mode="header", trusted_proxies=["127.0.0.1"])
who = gate.identify({"Remote-User": "anna", "Remote-Groups": "editors", "Remote-Auth": "session", "Remote-Id": "7",
                     "Remote-Kind": "user"}, peer="127.0.0.1")
assert who.id == "7" and who.has_role("editors") and who.is_session() and not who.is_service()

try:
    gate.identify({"Remote-User": "anna"}, peer="192.0.2.10")        # nicht vom Proxy
except gate_client.UntrustedPeer:
    pass
```

- **Header-Modus** (`GateClient(mode="header")`, den die Proxy-Vorlagen heute tragen) liest `Remote-User`, `-Name`, `-Email`,
  `-Groups`, `-Id`, `-Auth` und `-Kind` streng: ein doppeltes Feld, ungültiges UTF-8, ein Steuerzeichen, eine
  `Remote-Id` aus anderem als ASCII-Ziffern oder ein `Remote-Kind`, das fehlt, nicht genau `user`/`service` ist oder
  `service` zusammen mit `Remote-Auth: session`, wird abgewiesen, nie bereinigt oder geraten (Spezifikation Version 2 —
  sie braucht TinySesam und die Proxy-Vorlagen desselben Release). Sicher ist das nur, wenn der Proxy diese Header aus
  jeder Client-Anfrage entfernt, auf jedem Pfad, und der einzige Weg zur Anwendung ist (Spezifikation §2.1);
  `trusted_proxies` weist Anfragen von jeder anderen Gegenstelle ab. `header_names` folgt umbenannten
  `forward_headers`.
- **Token-Modus** (`GateClient(mode="token", issuer=…, audience=…, gate_keys=[…])` oder `jwks_url=…`) prüft das Gate-Token selbst
  in der Reihenfolge von §4.4 und ignoriert jeden `Remote-*`-Header. Der Algorithmus ist fest EdDSA; `alg`, `jwk`,
  `jku`, `x5u` und `x5c` im Token gelten nie. Schlüssel: die Ausgabe von `tinysesam gate-key` oder die JWKS-URL —
  geholt mit `urllib` aus der Standardbibliothek (keine zusätzliche Abhängigkeit) binnen 5 s und 64 KiB, höchstens
  einmal je 10 s, zwischengespeichert für `max-age` (begrenzt auf 60–3600 s), nach einem Fehler gilt der letzte gute
  Satz noch eine Stunde; Anfragen teilen einen laufenden Abruf, keine wartet über die Frist. Das Token kommt aus dem
  Gate-Cookie (`DEFAULT_GATE_COOKIE` oder `cookie_name`) oder `token_header`. Mit dem heutigen `Caddyfile.gate` sieht die Anwendung das Token nie (T-84); der
  Modus wartet auf einen Zustellweg.
- `gate.verify(jws)` prüft ein Token ohne Anfrage und liefert Identität und Claims.
- **Die Identität**: `Identity` mit `user`, `name`, `email`, `groups`, `id`, `auth`, `kind`, `account_kind`. Eigene
  Datensätze an `id` hängen. `has_role` vergleicht exakt (`admin` schließt nichts ein). `is_session()` ist nur bei
  `Remote-Auth: session` wahr; ein leerer oder unbekannter Wert ist ein Token, dessen Gruppen absichtlich unvollständig
  sind. `is_service()` ist nur für ein Dienstkonto wahr (`account_kind == "service"`, aus `Remote-Kind` oder
  `ts_kind`). Namen dürfen jedes Zeichen außer Steuerzeichen enthalten: maskieren.
- **Fehler**: `gate.identify` wirft einen `GateError`, dessen `kind` die Klasse der Spezifikation ist —
  `Unauthenticated`, `UntrustedPeer`, `HeaderError`, `InternalError` und unter `TokenError`: `MalformedToken`,
  `KidError`, `SignatureError`, `KeyUnavailable`, `ClaimsError`, `IssuerError`, `AudienceError`, `LifetimeError`,
  `NotYetValid`, `Expired`. Jeder heißt *nicht angemeldet*. Eine falsche Konfiguration wirft beim Erzeugen
  `ConfigError`.
- **Middleware**: `WSGIMiddleware(app, gate)` (Flask: `app.wsgi_app = WSGIMiddleware(app.wsgi_app, gate)`; Django: die
  Anwendung in `wsgi.py` einwickeln) und `ASGIMiddleware(app, gate=gate)` (Starlette:
  `app.add_middleware(ASGIMiddleware, gate=gate)`) erkennen jede Anfrage und lassen sie durch. Die Identität steht in
  `environ["tinysesam.identity"]` / `scope["tinysesam.identity"]`, `current_identity()` liefert sie — auch aus einem
  Request-Objekt (`current_identity(request)` liest `.environ`, `.META` oder `.scope`). Eine Abweisung wird auf
  `tinysesam.gate_client` mit Klasse und `kid` protokolliert, nie mit Token oder Header-Wert. Mit `jwks_url` prüft die
  ASGI-Middleware in einem Worker-Thread, ein Schlüsselabruf blockiert die Ereignisschleife also nie. WSGI-Server
  fügen doppelte Header-Felder zusammen, bevor die Anwendung sie sieht; die ASGI-Middleware weist sie ab.
- **Wächter**: `require_auth(app)`, `require_role("editors")(app)`, `require_session(app)` und
  `require_account_kind("user")(app)` umhüllen eine WSGI- oder ASGI-Anwendung und antworten 401/403 mit
  `Cache-Control: no-store` und ohne Grund. Für View-Dekoratoren in jedem Framework liefert
  `guard_status(identity, role=…, session=…, account_kind=…)` `None`, 401 oder 403.
- **Kopfleiste** (optional): `parse_topbar(data)` reduziert TinySesams `/.tinysesam/topbar.json` auf das, was
  angezeigt werden darf (`Topbar`, `TopbarLink`, mit `links` und `menu_links`; unsichere Links fallen weg, im Zweifel
  abgemeldet);
  `fetch_topbar(url, cookie_header)` holt sie serverseitig nur mit TinySesams Cookies; `Topbar.to_dict()` liefert die
  normalisierte Form aus §8.

Flask, mit einem View-Dekorator auf `guard_status`:

```python
import functools

from flask import Flask, abort
from tinysesam.gate_client import GateClient, WSGIMiddleware, current_identity, guard_status

app = Flask(__name__)
app.wsgi_app = WSGIMiddleware(app.wsgi_app, GateClient(mode="header", trusted_proxies=["127.0.0.1"]))


def require(role=None, session=False):
    def wrap(view):
        @functools.wraps(view)
        def guarded(*args, **kwargs):
            status = guard_status(current_identity(), role=role, session=session)
            if status:
                abort(status)
            return view(*args, **kwargs)
        return guarded
    return wrap


@app.get("/reports")
@require(role="editors")
def reports():
    return f"Hello {current_identity().name or current_identity().user}"
```

Vollständige Programme für Flask und Django liegen in [`examples/gate_client/`](../examples/gate_client/).

### Anmelden vor dem Gate: unsichtbar oder mit Seite (T-21)

`forward_login="direct"` — **die Vorgabe des Gateways** — schickt einen nicht Angemeldeten beim
Seitenaufruf gleich zum Identity Provider und danach zurück zur aufgerufenen Adresse; besteht dort
schon eine Sitzung, sieht er davon nur eine Umleitung. `"page"` (Vorgabe der Bibliothek) zeigt
erst die Login-Seite. Je Anwendung einstellbar, samt Namen auf der Login-Seite:

```python
forward_apps={"wiki.example.com": {"name": "Wiki", "login": "page"}}   # „Anmelden bei Wiki"
```

Gateway: `TINYSESAM_FORWARD_LOGIN`, `TINYSESAM_FORWARD_APPS` (JSON). `direct` verlangt OIDC als einzige
Methode. Hintergrund-Anfragen (XHR, Skripte) gehen auch dann zur Login-Seite: Eine Umleitung zum
Provider könnten sie nicht anzeigen, und jede begänne einen eigenen OIDC-Flow.

### Ein Gateway für viele Apps, ohne geteiltes Sitzungs-Cookie (T-26)

Mit `gate_link_enabled=True` (Gateway: `TINYSESAM_GATE_LINK=1`) bleibt die Sitzung auf dem Host des Gateways
(`base_url`, ohne `cookie_domain`). Ein App-Host bekommt über einen Code-Austausch nur ein eigenes
Verbindungs-Cookie, das ausschliesslich für ihn gilt:
`/.tinysesam/start` (App-Host) → `/auth/gate/authorize` (Gateway, ggf. Anmeldung) → `/.tinysesam/callback`
(App-Host, Einmal-Code, an den Browser gebunden). Keine App sieht die Sitzung, mit der man in die anderen
käme. Abmelden „überall“ an einer App beendet die Sitzung beim Gateway und damit jede Verbindung — auch wenn
die App zuvor schon „nur hier“ abgemeldet war (dann über `/auth/gate/logout` am Gateway). Die Sprache der
Gateway-Seiten wählt `TINYSESAM_LANG` (`en`, `de`).

### Öffentliche Pfade: Share-Links (T-20)

Beide Caddy-Vorlagen lassen mit `TS_SHARE_PREFIX='^/(s|public/share)/'` Pfade ohne Anmeldung
durch, ohne Identität. Geprüft wird der rohe Pfad; `.`/`..`-Segmente (auch mit Pfadparameter: `..;`), Backslash, NUL
und ihre kodierten Formen weist die Regel ab (`/s/..;/admin` lesen Tomcat und Spring als `/admin`); ein `;` oder `%3B`
anderswo, etwa in einem Dateinamen, lässt sie durch. Von sich aus aus. Wie man die
Pfade einer Anwendung nachmisst: `docs/OPERATIONS.md`.

### Abmelden an der Anwendung: nur hier oder überall (T-22)

Der Abmelde-Link der Anwendung zeigt auf `https://app.example.com/.tinysesam/logout` — der Proxy reicht
`/.tinysesam/*` an TinySesam, am Gate vorbei (beide Caddy-Vorlagen tun das). Was dort passiert, sagt
`forward_logout` bzw. `forward_apps[host].logout` (oder `?scope=app|all` im Link):

- **`all`** (Vorgabe): Die Sitzung endet — sie trägt jede Anwendung hinter derselben Anmeldung — und
  mit `oidc_rp_logout` (im Gateway an) auch die beim Provider, mit dem ID-Token als `id_token_hint`.
  Zurück kommt man über `https://app.example.com/.tinysesam/after-logout`: diese Adresse beim Provider
  als **Logout Callback URL** eintragen.
- **`app`**: Nur diese Anwendung. Die Sitzung bleibt; die Anwendung lässt sie erst wieder durch, wenn
  man auf der Login-Seite „Weiter als …“ wählt oder sich neu anmeldet.
- **`ask`**: Eine Seite fragt „Nur von Wiki abmelden oder überall?“.

Meldet sich die Anwendung selbst beim Provider ab (ihr eigener RP-Logout), trägt man dort ebenfalls
`…/.tinysesam/after-logout` als Logout Callback URL ein: Der Provider schickt dann hierher, und die Sitzung
bei TinySesam endet mit. Andere Anwendungen im selben Browser halten ihr Gate-Token höchstens noch
`gate_token_ttl_sec` lang.

Nach `all` erscheint die Seite „Abgemeldet“. Mit `forward_login="direct"` führt sie nach
`forward_logged_out_sec` Sekunden von selbst zurück zur Anwendung (Vorgabe 10, Gateway
`TINYSESAM_FORWARD_LOGGED_OUT_SEC`, 0 = stehen lassen): Das Gate schickt weiter zum Provider, der ebenfalls
abgemeldet ist, dort beginnt also eine **neue** Anmeldung. Die Seite nutzt ein `meta refresh`, kein Skript.
Im Modus `page` sagt die Anmeldeseite selbst „Du wurdest abgemeldet“.

## Öffentliche API: drei Stufen

Nicht alles ohne führenden Unterstrich ist eine Zusage. Seit 0.22.0 hat jeder öffentliche Name
eine **Stufe**, festgehalten in `tests/api_surface.json` und mit Signatur und Beschreibung
aufgeführt in [`API.md`](../API.md):

| Stufe | Was | Zusage |
|---|---|---|
| **A — öffentlich, stabil ab 1.0** | was diese README zeigt, und was einbettende Apps nutzen | Kein Bruch über zwei Minor-Versionen — die Bedingung für 1.0. Gezählt wird ab 0.22.0. |
| **B — für Fortgeschrittene** | Bausteine für eigene Konto- und Admin-Seiten (unten) | Bleibt. Entfernen oder umbauen erst nach einer `DeprecationWarning` über zwei Minor-Versionen. Eine Route kann nicht warnen: ein Pfad der Stufe B wird mindestens zwei Minor-Versionen vor dem Entfernen im CHANGELOG unter „Deprecated“ angekündigt. |
| **C — intern** | die Verdrahtung der eingebauten Routen | Keine. Seit 0.22.0 trägt die Implementierung einen führenden Unterstrich; der alte Name bleibt bis 1.0 als Alias, der beim Aufruf warnt, dann fällt er weg. Nicht neu verwenden. |

**Öffentlich ist, was die von Hand geschriebene Doku beschreibt** (entschieden vor 1.0): diese README,
`CONFIGURATION.md`, `SECURITY.md` und `docs/OPERATIONS.md`. `API.md` wird aus dem Code erzeugt und führt
jeden Namen mit seiner Stufe; dort aufgeführt zu sein, ist allein keine Zusage. Der Wächter schlägt an,
wenn ein Python-Name der Stufe A oder B (Methode, Konstante, Property, Preset, Export, Feld eines
Ergebnistyps) in keinem dieser Dokumente genannt ist.

Ein neuer öffentlicher Name hat keine Stufe, bis jemand entscheidet; so lange ist der Wächter
`tests/test_api_surface.py` rot — nichts wird aus Versehen zur Zusage. Die Konfigurationsfelder
sind Stufe A (bis auf einen Grabstein, markiert in `CONFIGURATION.md`), ebenso die Fehlertypen
(`TinySesamError`, `ConfigError`, `StateError`, `MissingExtra`, `MailNotConfigured`).

**Stufen A und B heissen englisch.** Bis 0.21.x waren einige dieser Namen deutsch
(`foederation_nachbinden`, `kennung_vergeben`, `SICHERHEITSEREIGNISSE`, Parameter wie
`durch_betreiber`, `ConfigError.besitzer_id` …). 0.22.0 benennt sie **ohne Alias** um — die
Zusagen der Stufen beginnen erst mit diesem Release; die ganze Liste alt → neu steht im
[CHANGELOG](../CHANGELOG.md). Der Wächter wird rot, sobald ein Name, Parameter,
Konfigurationsfeld oder Attribut eines Fehlertyps der Stufen A/B ein deutsches Wort trägt.

**Ebenso die Schlüssel und Werte** (0.22.0, ebenfalls ohne Alias): was die Methoden der Stufen A/B
zurückgeben oder annehmen (der Bericht von `federation_bind_existing`, `gc()`, `create_api_key`, die
Grund-Kürzel), die `details` an `on_security_event`, der Kontext eigener Seiten (`ctx["prefix"]`,
`ctx["purpose"]`), das JSON der Konto- und Admin-Routen und die Arten der API-Keys `automation`/
`human`. Die zwei Werte, die in der Datenbank stehen (die Art eines Keys, die bisherige Adresse
`old` in einem offenen Adresswechsel-Link), schreibt der Start um (Schema 12), gelesen werden sie
auch in alter Form richtig; der Rückschritt auf 0.21.x braucht einen SQL-Block aus
`docs/OPERATIONS.md`. Derselbe Wächter misst sie an einer Probeinstanz und im Quelltext. **Audit- und
Log-Zeilen sind seit Schema 15 ebenfalls englisch** (einmaliges Umbenennen, PO-Entscheidung 2026-10-29):
Ereignisnamen (`oidc_widerruf` → `oidc_revoked`), Schlüssel (`grund=` → `reason=`) und Tokens
(`kein_konto` → `no_account`), der Ersatzname eines gelöschten Kontos (`gelöscht#<id>` → `deleted#<id>`)
und die Meldung der Kennungs-Trigger. Der erste Start schreibt eine bestehende Datenbank um (vorher sichern);
eigene Filter, die auf die alten Wörter passen, müssen angepasst werden. Die ganze Liste alt → neu steht im
CHANGELOG, der Rückweg in `docs/OPERATIONS.md` („Rollback to 0.24.x").

**Über die Python-Namen hinaus** (PO-Entscheidung 2026-10-29). Die Stufen decken auch ab, was kein
Python-Name ist; gemessen in `tests/api_surface.json`, aufgeführt in [`API.md`](../API.md):

- **Stufe A:** `auth.cfg` — das *Lesen* (das Attribut und sein Typ; es ist die Instanz, die du übergeben hast).
  **Das Schreiben ist nicht zugesagt:** es ist eine einfache, veränderliche Dataclass, und welches Feld einmal
  und welches je Anfrage gelesen wird, gehört nicht zur Zusage. Und `auth.on_security_event` — das Attribut,
  der Aufruf `hook(event, account, details)`, dass er synchron nach dem Schreiben der Änderung läuft, dass ein
  fehlschlagender Hook den Vorgang nicht abbricht, und die Schlüssel von `details` je Ereignis. Die
  Ereignisnamen stehen in `TinySesam.SECURITY_EVENTS` (die Liste mit den Schlüsseln von `details` in
  `SECURITY.md`).
- **Stufe A — der Forward- und Gate-Vertrag**, auf den sich Reverse-Proxys verlassen: `/auth/forward`,
  `/auth/verify`, `/.tinysesam/*`, `/auth/gate/*`, ihre Statuscodes, die `X-TinySesam-*`-Header und die Werte
  von `X-TinySesam-Reason`, die Eingangs-Header, die ein Proxy setzen oder weiterreichen muss
  (`X-Forwarded-Uri`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `Cookie`, `Authorization` …), `?roles=` und
  die Namen der Cookies, die das Gate setzt. Ebenfalls Stufe A, weil andere Systeme sie von Hand eingetragen
  haben oder abfragen: der OIDC-Callback, die SAML-ACS- und Metadaten-Pfade und `/healthz`. Header, die ein
  Browser von sich aus schickt (`X-Csrf-Token`, `Sec-Fetch-Site`, `Referer` …), sind Stufe B.
- **Stufe B — Seiten und API-Routen:** die HTML-Seiten (Anmeldung, Registrierung, Konto, Admin-Panel …) und die
  JSON-Routen — **Pfad und Methode** sind zugesagt, das HTML und das Aussehen nicht. Ein Pfad der Stufe B wird
  mindestens zwei Minor-Versionen vor dem Entfernen oder Umbenennen im CHANGELOG unter „Deprecated“ angekündigt
  (eine Route kann keine `DeprecationWarning` auslösen).
- **Stufe A — das Sicherheitslog**, das fail2ban-Filter lesen: die Logger-Namen (`tinysesam.security`), das
  Format der Logdatei, die Ereigniswörter (`failed login`, `failed verification`, `deferred login`,
  `repeated login`, `login ok`) und ihre Schlüssel in der Reihenfolge (`user= ip= method= reason= unban=`).
  Freitext hinter den Schlüsseln ist nicht zugesagt. Siehe `docs/OPERATIONS.md`, „Security log contract“.

Für diese neuen Einträge beginnt die Uhr der Stufe A mit dem Release, das sie einführt (dem nach 0.24.13),
nicht mit 0.22.0; die Namen oben behalten ihre.

**`auth.store` ist Innenleben (Stufe C).** Das ist die Speicherschicht der eingebauten Routen; ihre
Methoden haben keine Stufe, keine Zusage und keine Übergangsfrist und können sich mit jedem Release
ändern. Was eine App braucht, hat eine öffentliche Methode (`set_disabled`, `find_user`,
`list_api_keys`, `lift_lockout` …); wo die Doku doch einen Aufruf von `auth.store` nennt (eine
Gesundheitsprobe, das Entziehen von OIDC-Freigaben), sagt sie es dazu.

**Stufe C warnt.** Wer einen alten C-Namen aufruft (bei den Konstanten: liest), bekommt eine
`DeprecationWarning` mit dem Ersatz; [`API.md`](../API.md) führt jeden auf. Python zeigt diese
Warnungen ausserhalb von `__main__` nicht an — um sie in der eigenen App zu finden, deren Tests
einmal mit `python -W error::DeprecationWarning` laufen lassen. Eine Unterklasse, die einen dieser
Namen überschreibt, bekommt beim Definieren eine `RuntimeWarning`: Die eingebauten Routen rufen seit
0.22.0 `_name`, die Überschreibung wirkt nicht mehr. Dasselbe gilt für einen **Test-Fake** auf einen
alten Namen — `auth.check_password = fake` oder `mock.patch.object(auth, "rate_ok", …)` wird nie
gerufen; die Zuweisung löst eine `RuntimeWarning` aus, die das Ziel nennt. Den Fake auf den neuen
Namen setzen (`auth._check_password = fake`). Ein Patch an der Klasse
(`mock.patch.object(TinySesam, …)`) warnt nicht und wirkt ebenso wenig.

### Für Fortgeschrittene (Stufe B)

Bausteine für Seiten, die du selbst baust — Signaturen und Beschreibungen in
[`API.md`](../API.md), Abschnitte „B“.

- **Eigene Konto-Seite:** `count_other_sessions` (weitere Sitzungen beenden?), `own_events`,
  `has_pin`, `disable_pin`, `generate_recovery_codes`, `recovery_codes_remaining`,
  `remove_passkey`, `totp_begin` → `totp_confirm`, `totp_enrollment_user`, `mfa_enrollment_allowed`,
  `federated_only` (reines SSO-Konto: kein Passwort zu ändern), `password_policy_error` (die Regel für
  ein neues Passwort; den Wechsel selbst macht `change_password`, Stufe A), `identifier_taken` und
  `NAME_MAX` (ist ein Name oder eine Adresse frei, wie lang darf er sein), `request_email_change`
  (Ergebnis an `after_response` geben) → `confirm_email_change`, `stepup_fresh` (den Step-up selbst
  machen `confirm_*`, Stufe A), `pending_user`, `session_user`.
- **Eigenes Admin-Panel oder Betreiber-Werkzeuge:** `get_user`, `find_user`, `user_roles`,
  `set_roles`, `delete_user`, `lift_lockout` (wie `tinysesam unlock`), `list_api_keys`,
  `api_key_kind`, `verify_api_key`, `create_app_password`, `list_app_passwords`, `revoke_app_password`,
  `app_password_hosts` ([App-Passwörter](#app-passwörter-webdav-caldav-git-hinter-tinysesam)),
  `create_service_pairing`, `list_service_clients`, `revoke_service_client`
  ([Dienste](#ein-dienst-ruft-eine-geschützte-app-auf)),
  `revoke_mfa_enrollment`, `list_resource_secrets`,
  `remove_resource_secret`, `resource_unlocked`, `all_security`, `admin_exists`,
  `admin_claim_token`, `audit`, `FEDERATED_SOURCES`, `NAME_BINDING_REFUSALS`.
- **Mail- und Token-Abläufe:** `mail_configured`, `send_mail`, `create_magic_token` → `magic_url`
  → `peek_magic` / `redeem_magic`, `TOKEN_PATHS`, `require_public_base`, `create_signin_link`
  (Einmal-Anmeldelink ohne Mail, Adresse aus `base_url`).
- **Proxy-Konfiguration für das Gate-Token:** `gate_public_key` (`sign_key` für caddy-jwt, wie
  `tinysesam gate-key`), `gate_jwks` (die Schlüsselmenge hinter `/auth/gate/jwks.json` für `jwk_url`),
  `gate_issuer` (`issuer_whitelist`).
- **Eigene Routen und Erweiterungspunkte:** `client_ip` (die echte Client-Adresse hinter
  `trusted_proxies`), `json_body` (JSON-Body mit CSRF-Prüfung für Cookie-Clients), `browser_path` (Links
  auf TinySesam-Seiten unter einem Montage-Präfix), `flow_cookie_name`, `t` (übersetzter Text in
  `config.lang`), `set_rate_limiter`, `apply_idp_groups`, `version` und
  `tinysesam.current_version()`, `PAGES` (die Seitennamen, die `set_template` annimmt),
  `MFA_ENROLLMENT_MODES`, `TinySesamConfig.validate()` (Nachprüfung, nachdem du ein Config-Objekt zur Laufzeit geändert hast;
  das Schreiben von `auth.cfg` selbst ist nicht zugesagt), `TinySesamConfig.enabled_methods()`, `TinySesamConfig.pin_as_first_factor()`.
- **Die Kopfleiste auf eigenen Seiten:** `topbar_head` (Tokens, CSS der Leiste und die Hell/Dunkel-Wiederherstellung
  für den `<head>`) und `topbar` (die Leiste mit dem Kontomenü für die Sitzung dieses Requests); `topbar_data`
  (dieselbe Leiste als Daten für ein Konto, für eine Oberfläche, die nicht in Python gezeichnet wird) — siehe
  [Look & Feel](#look--feel).
- **Der Gate-Client für Apps ohne FastAPI:** `tinysesam.gate_client` — jeder Name im eigenen Abschnitt,
  [Gate-Client für Flask, Django und andere Python-Apps](#gate-client-für-flask-django-und-andere-python-apps-t-86).
- **`apply_factor`** hängt einen Faktor an die Sitzung, **ohne ihn zu prüfen**. Nur rufen, wenn du
  den Faktor selbst geprüft hast, und mit dem Konto aus `session_user()` — der mächtigste Baustein
  hier; ein Fehler davor ist ein Weg hinein. Für Passwort, PIN und TOTP nicht nötig: Die
  Bausteine `login_*` ([Eigene Login-Seite](#eigene-login-seite), Stufe A) prüfen, drosseln
  und rufen ihn dann selbst.

## Tests & CI

```bash
pip install -e '.[all]' setuptools         # + httpx für den FastAPI-TestClient (in [all] enthalten)
python tests/run_all.py                    # alle Suiten; Exit 0 = grün, 1 = Fehlschlag
python tests/run_all.py core pin chain     # gezielt einzelne
CI_TEST_JOBS=1 python tests/run_all.py   # eine Suite nach der anderen
```

Die Suiten laufen **parallel**: `CI_TEST_JOBS` legt fest, wie viele gleichzeitig (sonst
`CI_KERNE`, das der CI-Runner setzt, sonst 2 — keine Erkennung der Kerne; alles außer einer ganzen Zahl
≥ 1 ist ein Fehler). Jede Suite
bekommt ihr eigenes Wegwerf-Verzeichnis, und das Protokoll nennt die Suiten in der Reihenfolge der
Dateien, nicht in der, in der sie fertig werden — `CI_TEST_JOBS=1` ist der serielle Lauf. Der
Sammellauf startet jede Suite über `tests/_starter.py`, der die Kosten des Passwort-Hashings **nur in
diesem Testprozess** absenkt. Eine direkt gestartete Suite (`python tests/test_core.py`) und das
Paket selbst hashen immer mit den Produktionswerten — dafür gibt es keine Einstellung und keine
Umgebungsvariable. Im selben Prozess wartet das Schließen einer `sqlite3`-Verbindung erst die
Hintergrund-Benachrichtigungen von TinySesam ab, die sie sonst noch benutzen könnten. Eine rote Suite
steht mit ihrem Ende im Protokoll (`exit 1`, `killed by signal SIGSEGV`); die Suiten laufen ungepuffert
und mit faulthandler, ein Absturz hinterlässt also seine Ausgabe und den Python-Stack im Protokoll.

Die Suiten sind eigenständige assert-Skripte (kein pytest). Drei davon beantworten die Frage
„ist etwas kaputt?", ohne dass du hinschauen musst:

- **`tests/test_browser.py`** fährt einen headless Chrome über das DevTools-Protokoll gegen das laufende
  Showcase und prüft, was ein Nutzer wirklich sieht: keine Konsolenfehler, keine fehlschlagenden Anfragen,
  Kopf/Nav/Fußzeile auf jeder Seite, gleiche Breiten, `?lang=`-Umschaltung, Dunkelmodus bis in die
  Vorschau-iframes, den Login (samt simuliertem Passwort-Autofill) und dass ein leeres Formular eine
  Meldung liefert statt einer 422-JSON-Wand. Wird übersprungen, wenn Chrome oder `websockets` fehlen.
- **`tests/test_repo.py`** bewacht die Hygiene: Versionen in `pyproject.toml`, `__init__.py` und Changelog
  stimmen überein; kein generiertes HTML, keine Geheimnisse, kein vergessenes `print()` in der Bibliothek;
  Farbwerte nur in `theme.py`/`theme.css`; jede Suite läuft im Sammellauf mit.
- **`tests/test_site.py`** prüft die erzeugte Website: beide Sprachen je Datei, ein `?lang=`-Mechanismus,
  überall derselbe Rumpf, Impressum vollständig.
- **`tests/test_packaging.py`** baut Wheel und sdist und sieht hinein: Alles, was das Paket braucht,
  ist wirklich drin, die Metadaten sind die, die PyPI erwartet, und veröffentlicht wird ohne Geheimnis.
  (`setuptools` muss installiert sein — ohne Bau-Backend prüfte die Suite nichts.)

**Vor jedem Push** — ein Tor, lokal:

```bash
git config core.hooksPath .githooks   # einmal pro Klon: der pre-push-Hook fährt das Tor
scripts/check.sh                      # Suiten + Browser + Hygiene + Website-Build
scripts/check.sh --fast               # ohne Browser-Test (nur wenn es eilt)
gh run watch --exit-status            # nach dem Push: CI-Ergebnis abholen, Exit != 0 bei Rot
```

**GitHub Actions** fährt das bei **Push auf `main`, bei Pull Requests und auf Zuruf**
(`workflow_dispatch`) — ein Push auf einen Feature-Branch löst bewusst nichts aus; dafür ist
`scripts/check.sh` da. Die CI fährt den vollen Lauf (Python 3.13–3.15 mit `[all]`), einen
Minimal-Lauf ohne Extras (sichert den stdlib-scrypt-Fallback) und einen Browser-Job, der
zusätzlich die Website baut.

## Für KI-Assistenten

Zwei Einstiege, damit ein Assistent sich zurechtfindet, ohne das ganze README zu lesen:

- **Eine App mit TinySesam bauen:** der Skill
  [`skills/tinysesam/SKILL.md`](https://github.com/Ollornog/TinySesam/blob/main/skills/tinysesam/SKILL.md) (Englisch) —
  Rezepte (FastAPI mit TOTP-Pflicht, Step-up, Konten vom Admin mit Anmeldelink, API-Schlüssel, Gate vor beliebigen
  Apps, OAuth für Claude Code, Heimnetz, C22-Optik), die Schalter und die Fallen, mit Verweisen in diese Doku. In
  Claude Code: `/plugin marketplace add Ollornog/TinySesam`, dann `/plugin install tinysesam@tinysesam` (ab Claude
  Code 2.1.275 in einem Schritt: `/plugin install tinysesam --marketplace Ollornog/TinySesam`). Andere Agenten lesen
  die Datei direkt; sie folgt dem verbreiteten `SKILL.md`-Format.
- **An TinySesam selbst arbeiten:** [`AGENTS.md`](https://github.com/Ollornog/TinySesam/blob/main/AGENTS.md)
  (Englisch) — Aufbau, Tests, generierte Dateien, Backlog, Sicherheitsregeln des Repos. `CLAUDE.md` bindet sie für
  Claude Code ein.

Jeder Python-Block beider Dateien läuft in der Testsuite, und jeder genannte Name wird gegen den Code geprüft.

## Status

**123 Testdateien, alle grün** — eine je Funktion, dazu eine Kombinations-Matrix
(`tests/test_matrix.py`).

Gebaut und getestet: Passwort/TOTP/Sitzungen/Rollen, Remember-me, Step-up und per-Route-MFA,
Faktor-Ketten, persönliche PIN, geteilte Ressourcen-Geheimnisse, Magic-Links + Mailer-Hook,
Registrierung und Einladung, Konto-Seite, Passwort-vergessen und TOTP-Recovery-Codes,
Sitzungsverwaltung, API-Keys und Service-Konten, Admin-Panel (oder nur dessen JSON-API),
Forward-Auth samt OIDC-Gateway, eine nonce-basierte CSP und die Kommandozeile (`backup`,
`restore`, `gc`, `audit`, `unlock`, `diagnose`).

Externe Identitätsanbieter — OIDC, SAML 2.0, LDAP/AD — und Passkeys sind gebaut und gegen einen
echten Provider auf einer Bühne geprüft (`tests/e2e_stage.py`); die mitgelieferten Tests decken
sie strukturell ab, weil sie nicht nach draussen telefonieren können.

Zwei Sicherheitsaudits sind im September 2026 durch den Code gegangen (siehe `CHANGELOG`). Die
Version ist bewusst noch **nicht** 1.0: Die Oberfläche der Stufe A
([Öffentliche API](#öffentliche-api-drei-stufen)) muss dafür zwei Minor-Versionen stillhalten,
gezählt ab 0.22.0.

MIT-Lizenz.

## Credits

Icon: <a href="https://www.flaticon.com/authors/maxicons" target="_blank" rel="noopener">Wizard PNG Image by max.icons - flaticon.com</a>
