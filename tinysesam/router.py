"""FastAPI-Router: /auth/* — Login (Passwort), TOTP-2FA + -Einrichtung, Logout, /me.

Der Router ist **durchgehend bedingt**: Fast jede Route hängt an einem Config-Schalter — PIN,
Ressourcen-Sperren, Magic-Link, Registrierung und E-Mail-Bestätigung, Passwort-Reset,
Forward-Auth, Konto-Seite, API-Keys, Admin-Panel und die Verfahren OIDC/Passkey/SAML. Was eine
konkrete Konfiguration daraus macht, sagt `[r.path for r in app.routes]` verlässlicher als jede
Aufzählung hier.

Die Verfahrens-Routen hängen dabei nicht am Schalter, sondern am fertig **aufgebauten** Verfahren
(`auth.oidc`, `auth.webauthn`, `auth.saml`): Ein gesetzter Schalter, dessen Extra oder Pflichtfeld
fehlt, lässt den Aufbau schon im Konstruktor scheitern — hier kommt er nie an."""
from __future__ import annotations
import secrets
from fastapi import APIRouter, Request, Form, HTTPException
from starlette.exceptions import HTTPException as _StarletteHTTPException
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse

from .errors import ConfigError
from . import security
from .store import ersatzname, name_ungueltig, norm_email, valid_email
from . import security


async def _antwort_des_handlers(request: Request, exc: Exception):
    """Die Antwort, die der Exception-Handler der App für `exc` bauen würde — oder None.

    Dieselbe Suche wie Starlettes `ExceptionMiddleware` (entlang der MRO in der Tabelle, die sie
    in den Scope legt), damit ein eigener Handler des Gastgebers gewinnt wie ohne TinySesam.
    """
    from starlette.concurrency import run_in_threadpool
    import inspect
    tabellen = request.scope.get("starlette.exception_handlers")
    if not tabellen:
        return None
    h = next((tabellen[0][k] for k in type(exc).__mro__ if k in tabellen[0]), None)
    if h is None:
        return None
    if inspect.iscoroutinefunction(h):
        return await h(request, exc)
    return await run_in_threadpool(h, request, exc)


def gehaertete_route(auth) -> type[APIRoute]:
    """Eine Routen-Klasse, die jede Antwort durch `auth._kopfzeilen` schickt.

    Als Routen-Klasse und nicht als Middleware: TinySesam ist ein Router in einer fremden App.
    Eine Middleware träfe jede Route des Gastgebers mit — dessen Cache-Regeln für statische
    Dateien eingeschlossen. `include_router` übernimmt die Klasse je Route, deshalb gilt sie
    auch für das Admin-Panel unter einem frei gewählten Präfix.
    """
    class _GehaerteteRoute(APIRoute):
        def get_route_handler(self):
            innen = super().get_route_handler()

            async def handler(request: Request):
                try:
                    antwort = await innen(request)
                except _StarletteHTTPException as exc:   # FastAPIs HTTPException erbt davon
                    auth._kopfzeilen_fehler(exc)
                    raise
                except RequestValidationError as exc:
                    # Das 422 gibt die Eingabe zurück, trägt aber keine `headers`, in die man die
                    # Kopfzeilen legen könnte (A2). Also die Antwort hier bauen — mit genau dem
                    # Handler, den die App dafür registriert hat (der des Gastgebers oder FastAPIs
                    # Vorgabe), damit sich an ihrem Inhalt nichts ändert.
                    antwort = await _antwort_des_handlers(request, exc)
                    if antwort is None:
                        raise
                # Schreibt die Antwort die Sitzung (Anmelden auf jedem Weg, Abmelden, Step-up),
                # gehen die Cookies unter den Namen von vor `__Host-` mit (H-1). Hier zentral,
                # damit kein Anmeldeweg es vergessen kann.
                auth._altnamen_loeschen(request, antwort)
                return auth._kopfzeilen(antwort)
            return handler
    return _GehaerteteRoute


def build_router(auth) -> APIRouter:
    cfg = auth.cfg
    r = APIRouter(tags=["auth"], route_class=gehaertete_route(auth))

    # ---------- Login (Passwort) ----------
    @r.get("/auth/login", response_class=HTMLResponse)
    def login_page(request: Request, next: str = "", error: str = ""):
        nxt = auth.safe_next(next, request)
        if auth.current_user(request):
            return RedirectResponse(nxt, 303)
        return auth.render_page("login", request=request, next=nxt, error=error)

    @r.post("/auth/login")
    def login_submit(request: Request, username: str = Form(""), password: str = Form(""),
                     next: str = Form(""), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        if not cfg.password_enabled:
            raise HTTPException(404, auth.t("api.password_off"))
        nxt = auth.safe_next(next, request)
        if not username or not password:
            # Kein 422-JSON ins Gesicht: die Seite noch einmal, mit Hinweis.
            return auth.render_page("login", status=400, request=request, next=nxt,
                                    error=auth.t("err.required"))
        remember_me = _remember(cfg, remember)
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip):
            return auth.render_page("login", request=request, status=429, next=nxt, error=auth.t("err.rate"))
        # Prüfen und Verbuchen in EINEM Schritt (R7-2): Mit `is_locked()` vorab und
        # `record_login()` danach lag die ganze Passwortprüfung dazwischen, und eine parallele
        # Salve las N-mal „noch nicht gesperrt". Der Versuch steht ab hier schon als
        # Fehlversuch in der Tabelle; `record_login(..., versuch=…)` macht ihn zum Erfolg.
        versuch = auth.versuch_beginnen(username, ip, "password")
        if versuch is None:
            # Eine Serien-Sperre (B2-6) läuft nicht ab — „vorübergehend" wäre gelogen, und der
            # Nutzer braucht den Weg hinaus. Die Meldung verrät nichts über die Existenz des
            # Kontos: gezählt wird je Kennung, ob es sie gibt oder nicht.
            text = auth.t("err.locked_serie" if auth._serie_voll(username) else "err.locked")
            return auth.render_page("login", request=request, status=429, next=nxt, error=text)
        u = auth.check_password(username, password)
        aus_verzeichnis = False
        if not u and cfg.ldap_enabled:
            from .ldap_ import VerzeichnisNichtErreichbar
            try:
                u = auth.check_ldap(username, password)   # LDAP/lldap-Backend (Faktor 'password')
            except VerzeichnisNichtErreichbar as e:
                # Ein Ausfall ist kein Fehlversuch (F-23): nichts gegen Konto oder IP verbuchen
                # und kein `failed login` ins Sicherheits-Log — sonst sperrte ein paar Minuten
                # Verzeichnis-Ausfall die Nutzer aus, und fail2ban bannte sie obendrein. Die
                # Antwort ist für jedes Konto dieselbe 503, verrät also nichts über dessen
                # Existenz (lokal falsches Passwort und unbekannter Name kommen beide hier an).
                auth.audit("ldap_unavailable", username, ip, security.fuer_log(str(e))[:300])
                security.seclog.error("LDAP nicht erreichbar user=%s ip=%s grund=%s",
                                      security.fuer_log(username), security.fuer_log(ip),
                                      security.fuer_log(str(e)))
                # …aber nur der Anteil des VERZEICHNISSES ist entschuldigt (A-1). Hat das Konto
                # ein lokales Passwort und war es falsch, ist das ein Fehlversuch wie immer —
                # sonst wäre jeder Ausfall eine Rate-Pause ohne Kontosperre gegen genau das
                # Notfallkonto (lokaler Admin), das man in dem Moment braucht; verteilt über viele
                # IPs griffe nur noch das IP-Ratelimit. Die Antwort bleibt 503. Ein lokales Konto
                # MIT Passwort lässt sich so während eines Ausfalls an der späteren 429 erkennen —
                # dieselbe Sperre, die es im Normalbetrieb auch trifft; das ist der kleinere Preis.
                # Der Versuch steht seit `versuch_beginnen` schon als Fehlversuch in der Tabelle
                # (R7-2) — ohne lokales Passwort wird er also zurückgenommen, nicht nur nicht
                # zusätzlich verbucht. Bis dahin zählt er mit; damit das nicht bei jedem Anlauf
                # bis zum Timeout dauert, fragt `check_ldap` nach einem Ausfall eine Pause lang
                # gar nicht erst (`ldap_.AusfallMerker`) und wirft sofort.
                lokal = auth.find_user(username)
                if lokal and auth.store.get_password_hash(lokal["id"]):
                    auth.record_login(username, ip, False, "password", versuch=versuch, quelle="lokal")
                else:
                    auth._versuch_zuruecknehmen(versuch)
                return auth.render_page("login", request=request, status=503, next=nxt,
                                        error=auth.t("err.directory_down"))
            aus_verzeichnis = u is not None
        # Welcher Weg entschieden hat, steht im Audit-Log (F-29): Vorher war eine
        # Verzeichnis-Anmeldung von einer lokalen nicht zu unterscheiden — beide schrieben
        # Faktor `password`, und bei einem Fehlversuch hiess es `grund=kein_konto`, obwohl das
        # Verzeichnis gefragt worden war und abgelehnt hatte.
        auth.record_login(username, ip, bool(u), "password", versuch=versuch,
                          quelle=("" if not cfg.ldap_enabled else "ldap" if aus_verzeichnis
                                  else "lokal" if u else "lokal+ldap"))
        if not u:
            return auth.render_page("login", request=request, status=401, next=nxt, error=auth.t("err.credentials"))
        # Kam das Konto aus dem Verzeichnis, ist die E-Mail ein LDAP-Attribut — in vielen
        # Verzeichnissen von dem gepflegt, dem es gehört, und von niemandem bestätigt. Traut der
        # Betreiber dem Verzeichnis (`ldap_email_trusted`, Vorgabe), entscheidet der Beleg am
        # Konto (None); sonst reist hier ausdrücklich „kein Beleg" mit: Eine
        # Allowlist-ADRESSE darf über LDAP nicht zum Erst-Admin führen (F-14). Am Faktornamen
        # ist der Weg nicht zu erkennen — LDAP zählt bewusst als `password`.
        token, ok, is_new = auth.apply_factor(request, u["id"], "password", ip,
                                              request.headers.get("user-agent"), remember_me,
                                              email_bestaetigt=(None if cfg.ldap_email_trusted else False)
                                              if aus_verzeichnis else None)
        if cfg.remember_me_enabled and remember_me:
            auth.store.set_session_bleiben(auth.store.session_hash(token))     # F-05: ausdrücklich gewählt
        resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
        if is_new:
            auth.set_cookie(resp, token)   # Art des Cookies folgt der Sitzung (A-2)
        return resp

    # ---------- TOTP als Faktor (2. Schritt oder Ketten-/Route-Faktor) ----------
    @r.get("/auth/totp", response_class=HTMLResponse)
    def totp_page(request: Request, next: str = "", error: str = ""):
        nxt = auth.safe_next(next, request)
        # Das Konto aus dem Cookie, wie beim Absenden (0.20.1, `session_user`): Ein API-Key hat
        # hier keinen TOTP-Schritt.
        voll = auth.session_user(request)
        user = auth.pending_user(request) or voll
        if not user:
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        if not auth.store.has_confirmed_totp(user["id"]):
            # Faktor totp verlangt, aber nicht eingerichtet → zur Einrichtung. Erlaubt ist das
            # für voll Angemeldete und für den Ketten-Fall (siehe totp_enrollment_user) — sonst
            # wäre login_chain=["password","totp"] für jedes Konto ohne TOTP eine Sackgasse.
            if voll or auth.totp_enrollment_user(request):
                return RedirectResponse(f"{auth.pfad(request, '/auth/totp/setup')}?next={_q(nxt)}", 303)
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        return auth.render_page("totp", request=request, next=nxt, error=error)

    @r.post("/auth/totp")
    def totp_submit(request: Request, code: str = Form(""), next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        nxt = auth.safe_next(next, request)
        if not code:
            return auth.render_page("totp", status=400, request=request, next=nxt,
                                    error=auth.t("err.required"))
        s = auth.session_from_request(request)
        # Geprüft wird der Code des Kontos, dessen Sitzung danach weiterkommt — beide aus dem
        # Cookie (0.20.1, `session_user`). `current_user()` fiel hier auf einen API-Key zurück,
        # wenn das Konto der Sitzung gesperrt war; dann hätte der Code des Key-Kontos gezählt.
        pu = auth.pending_user(request) or auth.session_user(request)
        if not s or not pu:
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        ip = auth.client_ip(request)
        # Atomar wie am Login (R3-2): Die Prüfung liegt sonst zwischen Sperre und Zählung.
        versuch = auth.versuch_beginnen(pu["username"], ip, "totp") if auth.rate_ok(ip) else None
        if versuch is None:
            text = auth.t("err.locked_serie" if auth._serie_voll(pu["username"]) else "err.retry")
            return auth.render_page("totp", request=request, status=429, next=nxt, error=text)
        # TOTP-Code ODER Einmal-Recovery-Code akzeptieren
        if not auth.verify_totp(pu["id"], code) and not auth.verify_recovery_code(pu["id"], code):
            auth.record_login(pu["username"], ip, False, "totp", versuch=versuch)
            return auth.render_page("totp", request=request, status=401, next=nxt, error=auth.t("err.code"))
        auth.record_login(pu["username"], ip, True, "totp", versuch=versuch)
        sitzungs_token = request.cookies.get(auth.session_cookie_name)   # Klartext nur hier, im Cookie
        # Wird die Sitzung durch diesen Faktor vollwertig, bekommt sie ein neues Token — der
        # Rechtewechsel. Ebenso beim Step-up auf einer schon vollen Sitzung (F-06). In beiden
        # Fällen muss das Cookie mit.
        erneuert = auth.complete_totp(sitzungs_token)
        weiter = erneuert or sitzungs_token
        antwort = RedirectResponse(auth.login_redirect_after(request, weiter, pu["id"], nxt), 303)
        if erneuert:
            # Wird die Sitzung hier voll (Login), dreht `set_cookie` auch das CSRF-Token; beim
            # Step-up nicht — es würde nur die Formulare der anderen offenen Reiter entwerten.
            auth.set_cookie(antwort, erneuert)
        return antwort

    # ---------- TOTP einrichten (eingeloggter User) ----------
    @r.get("/auth/totp/setup", response_class=HTMLResponse)
    def totp_setup(request: Request, next: str = ""):
        u = auth.current_user(request) or auth.totp_enrollment_user(request)
        if not u:
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        # Faktor-ANLAGE ist Selbstverwaltung — eine Sitzung, kein API-Key. Der Abbau war seit
        # R3-3 gesperrt, die Anlage nicht: Ein abgeflossener CI-Key richtete sich ein eigenes
        # TOTP ein und kam über den vollwertigen Login damit zurück an die Abbau-Routen.
        auth.require_session(request, u)
        # Wer schon einen bestätigten zweiten Faktor hat, darf ihn hier nicht verlieren — ein
        # Klick auf einen fremden Link reichte sonst, um TOTP auf „unbestätigt" zurückzusetzen
        # (Fund B2-1). Der Weg zum Wechsel führt über das reguläre Abschalten
        # (POST /auth/totp/disable, CSRF-geschützt). `totp_begin` verweigert das ebenfalls —
        # der Wächter hier liefert nur die lesbare Antwort statt eines Serverfehlers.
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        # Dieser GET schreibt NICHTS mehr. Bis zur Nacharbeit rief er `totp_begin()` unbedingt:
        # Für ein Konto ohne bestätigtes TOTP erzeugte damit jeder Aufruf ein neues Geheimnis
        # und ersetzte einen laufenden Einrichtungsversuch — ein fremder Link entwertete das
        # eben gescannte QR-Bild und stiess Audit-Zeilen von aussen an. Der Fundtext zu B2-1
        # verlangte beides: bei bestätigtem TOTP verweigern UND nur auf ausdrückliche
        # Anforderung (POST mit CSRF-Token) beginnen. Das Geheimnis entsteht deshalb erst in
        # `POST /auth/totp/setup/start`; diese Seite zeigt bloss den Knopf dafür.
        return auth.render_page("totp_setup", request=request, data=None, next=auth.safe_next(next, request))

    @r.post("/auth/totp/setup/start", response_class=HTMLResponse)
    def totp_setup_start(request: Request, next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        """Die Einrichtung ausdrücklich starten — hier (und nur hier) entsteht das Geheimnis."""
        auth.require_csrf(request, csrf_tok)
        u = auth.current_user(request) or auth.totp_enrollment_user(request)
        if not u:
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        # Dasselbe Schloss wie am GET, und hier das wichtigere: Diese Antwort trägt das
        # TOTP-Geheimnis im Klartext. Ein API-Key darf es nicht zu sehen bekommen — er käme
        # sonst über den selbst registrierten Faktor an eine frische Sitzung.
        auth.require_session(request, u)
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        return auth.render_page("totp_setup", request=request, data=auth.totp_begin(u["id"]),
                                next=auth.safe_next(next, request))

    @r.post("/auth/totp/setup")
    def totp_setup_confirm(request: Request, code: str = Form(...), next: str = Form("")):
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # Beide Konten aus dem Cookie (0.20.1, `session_user`): Der Einschreibungs-Zweig unten
        # schliesst mit `complete_totp` die Sitzung ab.
        voll = auth.session_user(request)
        # Vor der Bestätigung fragen — danach hat das Konto ein bestätigtes TOTP, und
        # `totp_enrollment_user` sagt None.
        einschreibung = None if voll else auth.totp_enrollment_user(request)
        # Ohne beides: ein API-Key bekommt die Absage mit Grund (403 `api.needs_session`, wie
        # beim GET), wer gar nichts vorzeigt, die übliche Absage von `require_session` (401;
        # nur ein Aufruf mit `Accept: text/html` wird zur Anmeldung geleitet — das Formular
        # der Seite schickt per `fetch`, also ohne).
        u = auth.require_session(request, voll or einschreibung)
        # Wie GET und /start (A-4): Ein aktives TOTP wird hier nicht „noch einmal bestätigt".
        # Sonst meldete die Stelle `totp_enabled` für nichts und prüfte nebenbei Codes des
        # aktiven Faktors mit eigenem Versuchstopf.
        if auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(409, auth.t("api.totp_active"))
        # Drossel, eigener Topf und Protokoll wie an jeder anderen OTP-Prüfstelle (B2-12/R3-6).
        # Eigener Topf, weil Einrichten keine Anmeldung ist: Tippfehler hier dürfen den
        # Login-Lockout nicht füllen. Prüfen und Verbuchen in EINEM Schritt wie überall sonst
        # (R7-2): Mit `is_totp_setup_locked()` vorab und `record_login()` danach lag die
        # Codeprüfung dazwischen, und eine parallele Salve kam an der Grenze vorbei.
        ip = auth.client_ip(request)
        versuch = (auth.versuch_beginnen(u["username"], ip, "totp_setup")
                   if auth.rate_ok(ip, login=False) else None)
        if versuch is None:
            raise HTTPException(429, auth.t("api.too_many"))
        ok = auth.totp_confirm(u["id"], code)
        auth.record_login(u["username"], ip, ok, "totp_setup", versuch=versuch)
        if not (ok and einschreibung):
            # B1-7: Nach einem neuen Faktor das Beenden der übrigen Sitzungen anbieten — die Zahl
            # sagt der Oberfläche, ob es etwas anzubieten gibt.
            return JSONResponse({"ok": ok, "other_sessions": auth.andere_sitzungen(request, u) if ok else 0})
        # Pflicht-Einrichtung unter der Kette (A-1): Der Bestätigungscode IST der TOTP-Schritt.
        # Er ist jetzt verbraucht; hätte der Nutzer ihn an /auth/totp noch einmal getippt, wäre
        # das ein Fehlversuch gewesen — fünfmal, und der Login-Lockout samt fail2ban-Zeilen
        # sperrte das Konto, das sich gerade korrekt eingerichtet hat.
        auth.record_login(u["username"], ip, True, "totp")
        sitzungs_token = request.cookies.get(auth.session_cookie_name)
        erneuert = auth.complete_totp(sitzungs_token)
        weiter = erneuert or sitzungs_token
        # B1-7 auch hier: Gerade die Einschreibung ist der Fall mit alten Sitzungen (Gerät
        # verloren, Betreiber-Fenster). Gezählt an der NEUEN Sitzung — die alte, halbe hat
        # `complete_totp` eben gelöscht (sonst liefe die neue als „andere" mit).
        # Nur wenn die Sitzung damit voll ist (`erneuert`): Folgt in der Kette noch ein Schritt
        # (password → totp → pin), bleibt sie halb, und das Beenden der übrigen Sitzungen
        # scheiterte mit 401 — die Seite hätte gefragt, der Nutzer zugestimmt, und das verlorene
        # Gerät bliebe angemeldet. Dann lieber kein Angebot; die Kontoseite listet die Sitzungen.
        antwort = JSONResponse({"ok": True, "next": auth.login_redirect_after(
            request, weiter, u["id"], auth.safe_next(next, request)),
            "other_sessions": auth.andere_sitzungen(request, u, token=erneuert) if erneuert else 0,
            # Grenze d: Bleibt die Sitzung halb, fragt die Seite trotzdem — eingelöst wird beim
            # Abschluss der Kette (`/auth/sessions/revoke-after-login`).
            "other_sessions_after": 0 if erneuert else auth.andere_sitzungen(request, u)})
        if erneuert:
            auth.set_cookie(antwort, erneuert)   # dreht beim Login auch das CSRF-Token
        return antwort

    @r.post("/auth/totp/disable")
    def totp_off(request: Request):
        # Ohne diese Zeile genügte ein <form method=POST> ohne Body von einer fremden Seite,
        # um TOTP UND alle Recovery-Codes zu löschen — der zweite Faktor spurlos weg.
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        # **Faktor-Verwaltung verlangt Frische** (Befund R3-3). `current_user()` genügte hier
        # bisher — mit zwei Folgen: (1) Eine Sitzung, deren Step-up längst abgelaufen war
        # (jeder `require(mfa=True)`-Guard gab ihr 403), durfte den zweiten Faktor trotzdem
        # abbauen. (2) `current_user()` akzeptiert auch einen **API-Key**: ein abgeflossenes
        # Maschinen-Credential, das nie einen interaktiven Faktor erbracht hat, löschte TOTP und
        # PIN seines Besitzers lautlos. `require_mfa()` schliesst beides — für einen API-Key ist
        # Step-up-Frische konstruktiv unerreichbar (403, `api.stepup_session`).
        u = auth.require_mfa(request)
        auth.totp_disable(u["id"])
        return {"ok": True, "other_sessions": auth.andere_sitzungen(request, u)}   # B1-7

    @r.post("/auth/totp/recovery")
    def totp_recovery(request: Request):
        """Neue Einmal-Recovery-Codes erzeugen (nur mit eingerichtetem TOTP). Klartext NUR EINMAL."""
        auth.require_csrf(request, request.headers.get("x-csrf-token"))
        u = auth.require_mfa(request)   # R3-3: frische Faktor-Bestätigung, kein API-Key
        if not auth.store.has_confirmed_totp(u["id"]):
            raise HTTPException(400, auth.t("api.totp_first"))
        return {"codes": auth.generate_recovery_codes(u["id"])}

    # ---------- PIN-Login (persönliche PIN, nur wenn aktiviert) ----------
    if cfg.pin_enabled:
        @r.get("/auth/pin", response_class=HTMLResponse)
        def pin_page(request: Request, next: str = "", error: str = ""):
            """PIN-Eingabe. Für Eingeloggte (PIN als Zusatzfaktor einer Route) ohne Benutzerfeld;
            für Gäste als eigenständige Seite — die Login-Seite bietet die PIN ohnehin an."""
            nxt = auth.safe_next(next, request)
            u = auth.session_user(request)    # wie beim Absenden: ein API-Key ist ein Gast
            if u:
                return auth.render_page("pin", request=request, next=nxt, error=error, username=u["username"])
            if not cfg.pin_login:
                # PIN ist kein Erstfaktor → Gäste haben hier nichts verloren
                return RedirectResponse(f"{auth.pfad(request, cfg.login_path)}?next={_q(nxt)}", 303)
            return auth.render_page("pin", request=request, next=nxt, error=error)

        @r.post("/auth/pin")
        def pin_submit(request: Request, pin: str = Form(""), username: str = Form(""),
                       next: str = Form(""), remember: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            remember_me = _remember(cfg, remember)
            ip = auth.client_ip(request)
            # Schon eingeloggt → die PIN gehört zur laufenden Sitzung, kein Benutzerfeld nötig.
            # „Eingeloggt" heisst hier: eine volle SITZUNG (0.20.1, `session_user`). Mit
            # `current_user()` galt eine reine API-Key-Anfrage als eingeloggt — der Riegel
            # `pin_login=False` unten griff nicht, geprüft wurde die PIN des Key-Kontos, und
            # `apply_factor` legte mangels Sitzung eine neue, volle an: Automaten-Key + PIN
            # ergaben eine interaktive Sitzung samt Admin-Flag, das der Key allein nie trägt.
            # Ein Key kommt hier nur als Gast an, und für den gilt `pin_login`.
            me = auth.session_user(request)
            page = "pin" if me else "login"

            def fail(msg, status):
                ctx = {"next": nxt, "error": msg}
                if me:
                    ctx["username"] = me["username"]
                return auth.render_page(page, status=status, request=request, **ctx)

            if not me and not cfg.pin_login:
                raise HTTPException(404)          # PIN ist kein Erstfaktor
            if not pin or (not me and not username):
                return fail(auth.t("err.required"), 400)
            if not auth.rate_ok(ip):
                return fail(auth.t("err.rate"), 429)
            ident = me["username"] if me else username
            if not ident:
                return fail(auth.t("err.credentials"), 401)
            # Login- und PIN-Topf in einem atomaren Schritt (R3-7): Eine vierstellige PIN
            # ist das dankbarste Ziel einer parallelen Salve.
            versuch = auth.versuch_beginnen(ident, ip, "pin")
            if versuch is None:
                return fail(auth.t("err.locked_serie" if auth._serie_voll(ident) else "err.locked"), 429)
            if me:
                u = auth.get_user(me["id"]) if auth.verify_user_pin(me["id"], pin) else None
            else:
                u = auth.check_pin(ident, pin)
            auth.record_login(ident, ip, bool(u), "pin", versuch=versuch)
            if not u:
                return fail(auth.t("err.credentials"), 401)
            token, ok, is_new = auth.apply_factor(request, u["id"], "pin", ip,
                                                  request.headers.get("user-agent"), remember_me)
            if cfg.remember_me_enabled and remember_me:
                auth.store.set_session_bleiben(auth.store.session_hash(token))  # F-05: ausdrücklich gewählt
            resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            return resp

        @r.post("/auth/pin/set")
        async def pin_set(request: Request):
            # R3-3: Eine PIN zu ERSETZEN heisst, einen Anmeldefaktor auszutauschen — das darf
            # nur eine interaktive Sitzung mit frischer Bestätigung. Ein API-Key kommt hier in
            # keinem Fall durch, auch nicht beim Anlegen (sonst setzt der Key-Inhaber den
            # Faktor seines Besitzers): der Riegel steht deshalb VOR der Fallunterscheidung
            # und liefert die klare Meldung statt der Frische-Ausrede.
            u = auth.require_session(request)
            # Die Regel, genau: `require_mfa()` gilt für das Ersetzen UND für das Anlegen,
            # sobald das Konto überhaupt etwas hat, womit es bestätigen kann — auch wenn das
            # nur sein Passwort ist. Denn mit `pin_login` ist eine PIN ein vollwertiger
            # Erstfaktor: Wer ein frisches Sitzungscookie stiehlt, richtete sich sonst einen
            # eigenen Zugang ein, der den Diebstahl überdauert. Das Passwort noch einmal zu
            # tippen ist die Hürde, die genau das verhindert; die Kontoseite führt über
            # `X-TinySesam-Reauth` von selbst dorthin. Nur ein Konto, das gar nichts hat
            # (rein föderiert), hängt am Alter der Anmeldung — sonst wäre die Einrichtung
            # für es eine Sackgasse.
            if auth.has_pin(u["id"]) or auth.stepup_options(u):
                u = auth.require_mfa(request)
            elif not auth.login_fresh(request, u):
                # Die ERSTE PIN eines Kontos, das nichts hat, womit es bestätigen könnte
                # (kein Passwort, keine PIN, kein TOTP — rein föderiert): `require_mfa()`
                # wäre hier eine Sackgasse, `stepup_options()` ist leer und die Reauth-Seite
                # hätte kein Feld. Das Anlegen hängt darum am Alter der Anmeldung. Kein
                # `X-TinySesam-Reauth`: Die Reauth-Seite kann diesem Konto nicht helfen, ein
                # neuer Login schon.
                raise HTTPException(403, auth.t("api.stepup_relogin"))
            b = await auth.json_body(request)
            try:
                auth.set_pin(u["id"], b.get("pin"))
            except ValueError as e:
                raise HTTPException(400, str(e))
            auth.audit("pin_set", u["username"])
            return {"ok": True, "other_sessions": auth.andere_sitzungen(request, u)}   # B1-7

        @r.post("/auth/pin/disable")
        def pin_off(request: Request):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            u = auth.require_mfa(request)   # R3-3: frische Faktor-Bestätigung, kein API-Key
            # Die Zeile schreibt `disable_pin` selbst — mit Konto und IP (B5-02). Hier stand eine
            # zweite, die denselben Vorgang doppelt ins Log schrieb.
            auth.disable_pin(u["id"])
            return {"ok": True, "other_sessions": auth.andere_sitzungen(request, u)}   # B1-7

    # ---------- Geteiltes Ressourcen-Geheimnis (PIN/Passphrase ohne User-Konto) ----------
    if cfg.resource_locks_enabled:
        def _res_ctx(row, name, nxt, error=""):
            return dict(name=name, kind=row["kind"], label=row["label"] or name, next=nxt, error=error)

        @r.get("/auth/resource/{name}", response_class=HTMLResponse)
        def resource_page(request: Request, name: str, next: str = "", error: str = ""):
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, auth.t("api.resource_unknown"))
            nxt = auth.safe_next(next, request)
            if auth.resource_unlocked(request, name):
                return RedirectResponse(nxt, 303)
            return auth.render_page("resource_unlock", request=request, **_res_ctx(row, name, nxt, error))

        @r.post("/auth/resource/{name}")
        def resource_submit(request: Request, name: str, secret: str = Form(""), next: str = Form(""),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            row = auth.store.get_resource_secret(name)
            if not row:
                raise HTTPException(404, auth.t("api.resource_unknown"))
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            pseudo = f"res:{name}"
            # Eigener Topf (`is_resource_locked`): Die Bereichs-PIN darf JEDER Besucher
            # probieren, und über den Login-Zähler verriegelten diese Fehlgriffe via
            # `ip_attempt_factor` die Anmeldung von Konten, die damit nichts zu tun hatten
            # (drei Bereiche à fünf Fehlgriffe reichten). Gesperrt wird jetzt der Bereich —
            # je Bereich und, weil hier Unangemeldete raten, weiterhin auch je Adresse.
            versuch = auth.versuch_beginnen(pseudo, ip, "resource") if auth.rate_ok(ip, login=False) else None
            if versuch is None:
                return auth.render_page("resource_unlock", request=request, status=429,
                                        **_res_ctx(row, name, nxt, "Zu viele Versuche — bitte warten."))
            if not auth.check_resource(name, secret):
                auth.record_login(pseudo, ip, False, "resource", versuch=versuch)
                return auth.render_page("resource_unlock", request=request, status=401, **_res_ctx(row, name, nxt, "Falsch"))
            auth.record_login(pseudo, ip, True, "resource", versuch=versuch)
            resp = RedirectResponse(nxt, 303)
            auth.unlock_resource(request, resp, name)
            auth.audit("resource_unlock", ip=ip, detail=name)
            return resp

    # ---------- Magic-Link (Einmal-Login per E-Mail) ----------
    if cfg.magiclink_enabled:
        @r.get("/auth/magic/request", response_class=HTMLResponse)
        def magic_request_page(request: Request, next: str = ""):
            return auth.render_page("magic_request", request=request, next=auth.safe_next(next, request), sent=False, error="")

        @r.post("/auth/magic/request", response_class=HTMLResponse)
        def magic_request(request: Request, email: str = Form(""), next: str = Form(""),
                          csrf_tok: str = Form("", alias="_csrf")):
            # Ohne diese Prüfung konnte eine fremde Seite über den Browser des Opfers
            # Anmeldelinks an beliebige Adressen verschicken lassen — die einzige
            # zustandsändernde Route, die ohne Token durchkam.
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("magic_request", request=request, status=429, next=nxt, sent=False,
                                        error=auth.t("err.rate"))
            # Ohne vertrauenswürdige öffentliche Adresse geht KEINE Mail hinaus: der Link
            # käme aus dem Host-Header des Anfragenden, und den setzt bei einer Mail an ein
            # fremdes Postfach der Angreifer (R4-01).
            #
            # `require_public_base` und nicht `public_base`: Hier stand die Prüfung schon, aber
            # der leere Fall schrieb nur eine Audit-Zeile und fiel unten in die Erfolgsseite —
            # HTTP 200, „Mail ist unterwegs", keine Mail. Die generische Antwort ist gegen die
            # Benutzer-Enumeration richtig und verdeckte hier einen Totalausfall. Ein fehlender
            # `base_url` ist nicht adressbezogen: Der Abbruch verrät nichts über das Postfach,
            # und `konfigpruefung` verhindert diesen Zustand ohnehin beim Aufbau.
            base = _mail_basis(auth, request)
            adresse = email.strip()

            def _versand():
                try:
                    auth.send_login_link(adresse, base, nxt)
                except Exception:
                    auth.audit("magic_send_error", detail=adresse)   # Fehler nicht nach außen leaken
            # immer dieselbe Antwort (keine User-Enumeration) — und zur selben Zeit: versandt
            # wird erst nach der Antwort (R4-05), im eigenen Mail-Arbeiter (B6-6).
            return auth.nach_der_antwort(
                auth.render_page("magic_request", request=request, next=nxt, sent=True, error=""), _versand)

        # R4-02: Der Link aus der Mail führt auf eine Bestätigungsseite, erst deren POST löst ein.
        # Mail-Scanner (Safe Links, Virenprüfer, Vorschau-Bots) rufen jeden Link per GET auf —
        # bisher verbrauchte schon dieser Abruf den Token, und der Nutzer landete auf „Link
        # ungültig". Ein GET, der anmeldet, meldet ausserdem jeden an, der den Link öffnet,
        # auch den Scanner. Die Seite prüft nur (`peek_magic`), eingelöst wird mit CSRF-Token.
        @r.get("/auth/magic/{token}", response_class=HTMLResponse)
        def magic_confirm(request: Request, token: str):
            """Nur noch der Anmelde-Link. E-Mail-Bestätigung und Einladung haben seit 0.16 eigene
            Endpunkte — sonst nahm das Abschalten des Magic-Links beides mit."""
            if not auth.peek_magic(token, purpose="login"):
                auth.token_abgewiesen("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, zweck="login",
                                    action=auth.pfad(request, f"/auth/magic/{_q(token)}"))

        @r.post("/auth/magic/{token}")
        def magic_redeem(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            data = auth.redeem_magic(token, purpose="login")
            if not data or not data.get("user_id"):
                auth.token_abgewiesen("login", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return _login_nach_token(auth, request, data["user_id"],
                                     auth.safe_next((data.get("payload") or {}).get("next") or "", request))

    # ---------- E-Mail-Bestätigung (eigener Endpunkt, unabhängig vom Magic-Link) ----------
    if cfg.signup_verify_email:
        @r.get("/auth/verify/{token}", response_class=HTMLResponse)
        def verify_confirm(request: Request, token: str):
            """Bestätigungsseite statt Einlösen per GET — Begründung bei `/auth/magic/{token}` (R4-02)."""
            if not auth.peek_magic(token, purpose="verify_email"):
                auth.token_abgewiesen("verify_email", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, zweck="verify_email",
                                    action=auth.pfad(request, f"/auth/verify/{_q(token)}"))

        @r.post("/auth/verify/{token}")
        def verify_email(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            data = auth.redeem_magic(token, purpose="verify_email")
            if not data or not data.get("user_id"):
                auth.token_abgewiesen("verify_email", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            uid = data["user_id"]
            # Nur die Sperre der AUSSTEHENDEN Bestätigung aufheben, nie die des Betreibers (H-18,
            # zweite Angriffsrunde). Bis dahin setzte diese Route `disabled` bedingungslos auf 0:
            # Entstand der Token erst nach einer Sperre im Panel — eine App schiebt
            # `send_verify_email` in den Postausgang —, fand die Sperre nichts zu verwerfen, und
            # der Link schaltete das Konto wieder frei und meldete an.
            if not auth.store.bestaetigung_freischalten(uid):
                konto = auth._kontoname(uid)
                if konto is None:                        # Konto inzwischen gelöscht
                    auth.token_abgewiesen("verify_email", request)
                    return auth.render_page("magic_invalid", request=request, status=400)
                auth.audit("verify_blocked", konto, auth.client_ip(request),
                           "Konto vom Betreiber gesperrt")
                return auth.render_page("magic_invalid", request=request, status=403)
            # Der eingelöste Link belegt die Adresse, an die er ging — solange sie noch die des
            # Kontos ist (eine inzwischen geänderte Adresse hat er nicht belegt). Vor der Anmeldung
            # unten: Dort entscheidet `maybe_promote_admin` über den Vermerk am Konto.
            konto_zeile = auth.store.get_user(uid)
            if (konto_zeile is not None and konto_zeile["email"] and data.get("email")
                    and norm_email(data.get("email")) == konto_zeile["email"]):
                auth.store.set_email_verified(uid, True)
            # Konto und IP gehören in die Zeile (B5-02): Hier wird ein Konto freigeschaltet, und
            # ohne Namen fand `tinysesam audit --user X` den Vorgang nicht.
            auth.audit("email_verified", auth._kontoname(uid), auth.client_ip(request),
                       data.get("email"))
            return _login_nach_token(auth, request, uid, auth.safe_next("", request))

    # ---------- Einladung (eigener Endpunkt; verbraucht wird der Token erst bei der Registrierung) ----------
    if cfg.allow_signup:
        @r.get("/auth/invite/{token}")
        def invite_redeem(request: Request, token: str):
            if not auth.peek_magic(token, purpose="invite"):
                auth.token_abgewiesen("invite", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return RedirectResponse(f"{auth.pfad(request, '/auth/register')}?invite={_q(token)}", 303)

    # ---------- Erst-Admin per Einmal-Token (nur solange es keinen Admin gibt) ----------
    @r.get("/auth/claim-admin", response_class=HTMLResponse)
    def claim_admin(request: Request, token: str = ""):
        u = auth.current_user(request)
        if not u:
            return RedirectResponse(f"{auth.pfad(request, cfg.login_path)}?next={auth.pfad(request, '/auth/claim-admin')}?token={_q(token)}", 303)
        if auth.admin_exists():
            raise HTTPException(404)          # kein Hinweis darauf, dass es die Route mal gab
        # Gedrosselt und protokolliert (B5-16): Bis T-13 durfte ein angemeldetes Konto hier
        # beliebig oft raten, und kein Fehlgriff hinterliess eine Spur. Das Token hat 192 Bit,
        # Raten ist also aussichtslos — aber wer es versucht, soll im Log stehen, und zwar
        # als `failed verification` (kein Anmeldeversuch, siehe `security.LOG_PRUEFUNG`).
        ip = auth.client_ip(request)
        if not auth.rate_ok(ip, login=False):
            raise HTTPException(429, auth.t("api.too_many"))
        if not auth.consume_admin_claim(token, u):
            auth.admin_claim_fehlgriff(u["username"], ip)
            raise HTTPException(403, auth.t("err.claim"))
        return RedirectResponse(auth.pfad(request, cfg.admin_path), 303)

    # ---------- Step-up / Reauth (Sudo-Frische für mfa=True-Guards) ----------
    def _nur_sitzung(request: Request):
        """Das Konto, dessen Sitzung hier bestätigt wird — aus der Sitzung, nie aus einem API-Key (0.20.1).

        Die Route prüfte den Faktor des Kontos aus `current_user()` und frischte danach die
        Sitzung aus dem Cookie auf. Bei einer HALBEN Sitzung (erster Faktor ja, TOTP offen) fällt
        `current_user()` auf den API-Key zurück — geprüft wurde dann das Konto des Keys, voll
        gemacht die Sitzung aus dem Cookie: Die halbe Sitzung eines anderen wurde mit dem eigenen
        Key und dem eigenen Passwort voll, und im eigenen Konto ersetzten Automaten-Key und Passwort
        den zweiten Faktor (samt dem Admin-Flag, das der Key allein nicht trägt). Jetzt kommt das
        Konto aus `session_user()` — der VOLLEN Sitzung eben dieses Cookies, derselben, die unten
        auffrischt. Frische kann ein Key ohnehin nie erreichen (`stepup_fresh`); zeigt die Anfrage
        ohne Sitzung einen vor, sagt die Antwort das (403) statt auf die Login-Seite zu leiten.
        """
        u = auth.session_user(request)
        if u is None and cfg.apikey_enabled and auth._extract_api_key(request):
            raise HTTPException(403, auth.t("api.stepup_session"))
        return u

    @r.get("/auth/reauth", response_class=HTMLResponse)
    def reauth_page(request: Request, next: str = "", error: str = ""):
        u = _nur_sitzung(request)
        if not u:
            return RedirectResponse(f"{auth.pfad(request, cfg.login_path)}?next={_q(auth.safe_next(next, request))}", 303)
        methods = auth.stepup_options(u)
        # Leere Liste heisst `stepup_strict=True` und nichts Passendes eingerichtet. Ohne eigene
        # Meldung stünde hier eine Seite ohne einziges Eingabefeld — der Nutzer sähe nicht, was
        # von ihm erwartet wird.
        return auth.render_page("reauth", request=request, next=auth.safe_next(next, request),
                                error=error or ("" if methods else auth.t("err.stepup_none")),
                                username=u["username"], methods=methods)

    @r.post("/auth/reauth")
    def reauth_submit(request: Request, code: str = Form(""), password: str = Form(""), pin: str = Form(""),
                      next: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
        auth.require_csrf(request, csrf_tok)
        u = _nur_sitzung(request)
        if not u:
            return RedirectResponse(auth.pfad(request, cfg.login_path), 303)
        nxt = auth.safe_next(next, request)
        ip = auth.client_ip(request)
        methods = auth.stepup_options(u)
        if not methods:
            # Dieses Konto hat kein Verfahren, mit dem es hier bestätigen könnte
            # (`stepup_strict`, oder noch gar kein Faktor eingerichtet). Der Versuch KANN
            # nicht gelingen — er wird deshalb nicht als Fehlversuch protokolliert, sonst
            # füttert die aussichtslose Seite die Brute-Force-Sperre desselben Kontos.
            return auth.render_page("reauth", request=request, status=403, next=nxt,
                                    username=u["username"], methods=methods,
                                    error=auth.t("err.stepup_none"))
        # Eigener Topf (`is_reauth_locked`), nicht der des Logins: Eine Step-up-Bestätigung
        # ist keine Anmeldung — wer hier steht, ist bereits angemeldet. Mit dem geteilten
        # Zähler sperrten fünf Tippfehler auf dieser Seite die **Anmeldung** desselben
        # Kontos für `lockout_window_sec`, samt dem korrekten Passwort. Gedrosselt und
        # protokolliert bleibt der Weg, nur eben in seinem eigenen Topf.
        versuch = (auth.versuch_beginnen(u["username"], ip, "reauth", auch_pin="pin" in methods)
                   if auth.rate_ok(ip, login=False) else None)
        if versuch is None:
            return auth.render_page("reauth", request=request, status=429, next=nxt, username=u["username"],
                                    methods=methods, error=auth.t("err.retry"))
        # Nur ein angebotenes Verfahren zählt — was der Nutzer ausgefüllt hat, entscheidet.
        ok = False
        if "totp" in methods and code:
            ok = auth.verify_totp(u["id"], code)
        elif "pin" in methods and pin:
            ok = auth.verify_user_pin(u["id"], pin)
        elif "password" in methods and password:
            ok = auth.verify_user_password(u["id"], password)
        auth.record_login(u["username"], ip, ok, "reauth", versuch=versuch)
        if not ok:
            return auth.render_page("reauth", request=request, status=401, next=nxt, username=u["username"],
                                    methods=methods, error=auth.t("err.reauth"))
        s = auth.session_from_request(request)
        resp = RedirectResponse(nxt, 303)
        if s:
            auth.store.set_session_mfa(s["token_hash"], True)   # setzt mfa_at=now → wieder frisch
            # Frisch bestätigt heisst neues Token (F-06): Ein mitgelesenes altes Cookie hielte
            # sonst genau die Sitzung, die eben Sudo-Rechte bekommen hat.
            auth.rotate_session(request, resp)
        auth.audit("stepup", u["username"], ip)
        return resp

    # ---------- Passwort vergessen / zurücksetzen (braucht einen Mailer, NICHT den Magic-Link) ----------
    if cfg.password_reset_enabled:
        @r.get("/auth/forgot", response_class=HTMLResponse)
        def forgot_page(request: Request):
            return auth.render_page("forgot", request=request, sent=False, error="")

        @r.post("/auth/forgot", response_class=HTMLResponse)
        def forgot_submit(request: Request, email: str = Form(""), csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("forgot", request=request, status=429, sent=False, error=auth.t("err.rate"))
            base = _mail_basis(auth, request)   # fail closed, siehe /auth/magic/request
            adresse = email.strip()

            def _versand():
                try:
                    auth.send_password_reset(adresse, base)
                except Exception:
                    auth.audit("reset_send_error", detail=adresse)
            # generisch (keine Enumeration), Versand nach der Antwort (R4-05/B6-6)
            return auth.nach_der_antwort(auth.render_page("forgot", request=request, sent=True, error=""),
                                         _versand)

        @r.get("/auth/reset", response_class=HTMLResponse)
        def reset_page(request: Request, token: str = ""):
            if not auth.peek_magic(token, purpose="reset_password"):
                # Ohne Token (Lesezeichen, Crawler) ist das kein vorgelegter Link — kein Eintrag,
                # sonst meldete das Sicherheits-Log einen Fehlgriff, den es nie gab (A3).
                if token:
                    auth.token_abgewiesen("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("reset", request=request, token=token, error="")

        @r.post("/auth/reset", response_class=HTMLResponse)
        def reset_submit(request: Request, token: str = Form(""), password: str = Form(""),
                         csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            # Die Regel braucht das Konto (Kontextwörter) — also erst nachsehen, OHNE den Token
            # zu verbrauchen: Ein abgelehntes Passwort soll den Link nicht entwerten.
            vorab = auth.peek_magic(token, purpose="reset_password") or {}
            if not vorab.get("user_id"):
                # Ein toter Link zuerst (A-8): Sonst hiess es bei abgelaufenem Link und schwachem
                # Passwort „zu leicht", und erst der zweite Versuch verriet, dass der Link nicht
                # mehr gilt. Verraten wird damit nichts Neues — der GET sagt dasselbe.
                # Und dieselbe Spur wie der GET (B5-18, Integrationsfund 4): Hier kehrt JEDER tote
                # Token zurück — geraten, abgelaufen, schon eingelöst. Der Aufruf hinter
                # `redeem_magic` unten erreicht nur noch den Wettlauf zwischen peek und redeem;
                # stand er allein, liessen sich Reset-Token per POST ohne Audit- und
                # fail2ban-Zeile durchprobieren. Ohne Token kein vorgelegter Link (A3).
                if token:
                    auth.token_abgewiesen("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            konto = auth.store.get_user(vorab["user_id"])
            mangel = auth.passwort_mangel(password, username=konto["username"] if konto else None,
                                          email=konto["email"] if konto else None)
            if mangel:
                return auth.render_page("reset", request=request, status=400, token=token, error=mangel)
            data = auth.redeem_magic(token, purpose="reset_password")   # jetzt verbrauchen
            if not data or not data.get("user_id"):
                auth.token_abgewiesen("reset_password", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            uid = data["user_id"]
            auth.set_password(uid, password)
            auth.store.delete_user_sessions(uid)   # alle alten Sitzungen beenden
            # Der Reset hebt die Passwort-Sperre auf (R4-13). Vorher setzte er das Passwort
            # und liess die Fehlversuche stehen: Wer sich ausgesperrt hatte und den
            # vorgesehenen Weg ging, stand danach mit dem NEUEN Passwort vor derselben 429.
            # Damit ist der Reset der Weg aus der Sperre, der nicht an ihr hängt (H-10).
            weg = auth.sperre_aufheben(uid, methoden=("password",))
            # Und die API-Keys (R4-14). Wer sein Passwort über „vergessen" zurücksetzt, hat sein
            # Konto verloren oder fürchtet, dass es übernommen ist — derselbe Fall wie der
            # Admin-Reset, der die Keys seit 0.18.0 widerruft. Ein Key ist eine zweite,
            # gleichwertige Anmeldung; blieb er gültig, hätte der Reset nur die Haustür
            # geschlossen. (Der Wechsel auf der Kontoseite lässt sie mit Absicht stehen — dort
            # meldet sich der Inhaber mit dem alten Passwort an, das ist ein Routine-Wechsel.)
            keys = auth._keys_widerrufen(uid, "passwort_reset")
            auth.audit("password_reset", auth._kontoname(uid), auth.client_ip(request),
                       f"uid={uid} fehlversuche_verworfen={weg}"
                       + (f" api_keys_revoked={keys}" if keys else ""))
            return RedirectResponse(f"{auth.pfad(request, cfg.login_path)}?next={_q(auth.pfad(request, '/'))}", 303)

    # ---------- Registrierung (nur wenn allow_signup) ----------
    if cfg.allow_signup:
        def _reg_ctx(nxt, invite="", email="", error="", **extra):
            return dict(next=nxt, invite=invite, email=email, error=error,
                        invite_only=cfg.signup_invite_only, **extra)

        @r.get("/auth/register", response_class=HTMLResponse)
        def register_page(request: Request, next: str = "", invite: str = ""):
            nxt = auth.safe_next(next, request)
            if auth.current_user(request):
                return RedirectResponse(nxt, 303)
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if invite and not inv:
                # Dieselbe Spur wie /auth/invite/<t> und der POST (B5-18): Die Seite antwortet
                # je nach Token anders (403 oder die vorausgefüllte Adresse) — ohne diese Zeile
                # liessen sich Einladungs-Token hier still durchprobieren.
                auth.token_abgewiesen("invite", request)
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", request=request, status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            return auth.render_page("register", request=request, **_reg_ctx(nxt, invite=invite, email=(inv or {}).get("email") or ""))

        @r.post("/auth/register", response_class=HTMLResponse)
        def register_submit(request: Request, password: str = Form(""), username: str = Form(""),
                            email: str = Form(""), next: str = Form(""), invite: str = Form(""),
                            csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            nxt = auth.safe_next(next, request)
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                return auth.render_page("register", request=request, status=429, **_reg_ctx(nxt, invite=invite, email=email,
                                        error=auth.t("err.rate")))
            inv = auth.peek_magic(invite, purpose="invite") if invite else None
            if invite and not inv:
                auth.token_abgewiesen("invite", request)
            if cfg.signup_invite_only and not inv:
                return auth.render_page("register", request=request, status=403,
                                        **_reg_ctx(nxt, error=auth.t("err.invite_required")))
            username = username.strip()
            def err(msg, status=400):
                return auth.render_page("register", request=request, status=status,
                                        **_reg_ctx(nxt, invite=invite, email=email, error=msg))
            if not password:
                return err(auth.t("err.required"))
            mangel = auth.passwort_mangel(password, username=username, email=email)
            if mangel:
                return err(mangel)
            roles, is_admin = list(cfg.signup_default_roles), False
            email_final = norm_email(email)
            if inv:
                roles = (inv.get("payload") or {}).get("roles") or []
                is_admin = bool((inv.get("payload") or {}).get("is_admin"))
                email_final = norm_email(inv.get("email")) or email_final
            # E-Mail ist Login-Kennung → Pflicht, plausibel und eindeutig
            if (cfg.signup_require_email or cfg.login_identifier == "email") and not email_final:
                return err(auth.t("err.email_required"))
            if email_final and not valid_email(email_final):
                return err(auth.t("err.email_invalid"))
            # Bestätigung verlangt, aber kein Mailer? Dann NICHT stillschweigend durchwinken.
            # Steht vor der Vergeben-Prüfung: Sie hängt nicht an der Adresse und verrät nichts.
            verify = cfg.signup_verify_email and not inv
            if verify and not auth.mail_configured():
                return err(auth.t("err.verify_no_mailer"), 500)
            # Vor dem Anlegen prüfen, nicht danach: sonst entstünde ein deaktiviertes Konto,
            # das mangels Bestätigungsmail nie freigeschaltet werden kann.
            verify_base = _mail_basis(auth, request) if verify else ""
            # Im E-Mail-Modus gibt es kein Benutzernamen-Feld — die Adresse IST die Kennung.
            if cfg.login_identifier == "email":
                username = email_final or ""
            if not username:
                return err(auth.t("err.username_required"))
            if name_ungueltig(username):
                return err(auth.t("err.username_invalid"))
            # Benutzername = die eigene Adresse? Dann prüft die Adress-Prüfung unten beides.
            name_ist_adresse = bool(email_final) and norm_email(username) == email_final
            # Mit Bestätigung darf ein Benutzername keine FREMDE Adresse sein (Angriff A1): Die
            # Namensprüfung sucht kreuzweise auch in den Adressen und hätte mit 409 verraten,
            # dass es die Adresse gibt — R4-03 wäre über das Namensfeld umgangen.
            if verify and "@" in username and not name_ist_adresse:
                return err(auth.t("err.username_is_address"))
            # Kreuzweise prüfen: Benutzername und E-Mail sind EIN Kennungs-Raum (Fund R4-12).
            # Eine Adresse, die schon als Benutzername eines anderen Kontos dient, ist vergeben —
            # sonst besetzt die Registrierung dessen Login-Kennung und sperrt ihn aus.
            # Der Name kommt VOR der Adresse (Angriff A1): Andersherum war ein bekannter,
            # vergebener Name (`admin`) plus Zieladresse ein Orakel — vergebene Adresse 200,
            # freie Adresse 409 username_taken. Ein vergebener Name ist ohnehin sichtbar (der
            # Nutzer muss einen anderen wählen); jetzt hängt die Antwort darauf nicht mehr an der Adresse.
            if not name_ist_adresse and auth.kennung_vergeben(username):
                return err(auth.t("err.username_taken"), 409)
            if email_final and auth.kennung_vergeben(email_final):
                if verify:
                    # R4-03: Mit Bestätigung antwortet eine vergebene Adresse wie eine freie —
                    # 409 und „E-Mail vergeben" verrieten jedem, welche Adressen ein Konto
                    # haben. Der Inhaber bekommt stattdessen einen Hinweis. Ohne Bestätigung
                    # geht das nicht: Dort meldet der Erfolgsfall sofort an, die Antwort
                    # unterscheidet sich also zwangsläufig.
                    #
                    # Der Benutzername wird dabei genauso belegt wie beim echten Anlegen (A1,
                    # zweite Variante): ein gesperrter Platzhalter ohne Adresse, mit einem nie
                    # verschickten Bestätigungstoken. Sonst verriet die zweite Registrierung
                    # desselben Namens per 409, ob die erste ein Konto angelegt hatte — also ob
                    # die Adresse frei war. `gc()` entfernt den Platzhalter mit Ablauf des
                    # Tokens, genau wie ein nie bestätigtes echtes Konto (R4-09). Das Anlegen
                    # samt Passwort-Hash gleicht zugleich die Laufzeit an.
                    # Ist der Name die Adresse (immer bei login_identifier='email'), ist der Name
                    # selbst vergeben — der Platzhalter bekommt dann einen Zufallsnamen. Bis
                    # 2026-09-24 schrieb dieser Zweig nur die Audit-Zeile, der freie dagegen Konto,
                    # Sperre und Token: messbar an der Antwortzeit, ein Orakel „Adresse vergeben?"
                    # (T-13, B1-12 / ASVS 6.3.8). Jetzt dieselbe Arbeit in beiden Zweigen; `gc()`
                    # räumt den Platzhalter mit dem Ablauf seines Tokens (R4-09).
                    platzhalter = auth.create_user(
                        f"reserviert-{secrets.token_hex(6)}" if name_ist_adresse else username,
                        password=password, roles=[])
                    auth.store.set_disabled(platzhalter, True)
                    auth.create_magic_token("verify_email", user_id=platzhalter)
                    adresse = email_final

                    def _hinweis():
                        try:
                            auth.send_signup_notice(adresse, verify_base)
                        except Exception:
                            auth.audit("signup_notice_error", detail=adresse)
                    auth.audit("signup_taken", username, ip, detail=adresse)
                    return auth.nach_der_antwort(
                        auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True)),
                        _hinweis)
                return err(auth.t("err.email_taken"), 409)
            # Belegt ist die Adresse hier nur, wenn sie aus der Einladung stammt — die hat der
            # Admin an genau dieses Postfach geschickt. Eingetippt ist sie eine Behauptung: Mit
            # Bestätigungspflicht setzt den Beleg erst der eingelöste Link (`/auth/verify`), ohne
            # sie nie. Bis Schema 10 stand hier die Vorgabe „belegt", und die Löschung durch
            # einen Admin nahm die fremd eingetippte Adresse deshalb auch aus Zeilen von vor der
            # Anlage — die Einladung des Admins, die Fehlversuche der echten Inhaberin
            # (`Store.konto_entfernen`). Rechte hängen daran nicht: Eine Allowlist-Adresse
            # verlangt bei offener Registrierung ohnehin die Bestätigung (Konstruktor-Wächter).
            uid = auth.create_user(username, password=password, is_admin=is_admin, roles=roles,
                                   email=email_final or None,
                                   email_verified=bool(inv and norm_email(inv.get("email"))))
            if inv:
                auth.redeem_magic(invite, purpose="invite")   # Einladung jetzt verbrauchen
            auth.audit("signup", username, ip)
            # E-Mail-Bestätigung nötig? (nicht bei Einladung — die gilt als bestätigt)
            if verify and email_final:
                auth.store.set_disabled(uid, True)

                def _zuruecknehmen(grund):
                    # B6-5: Ohne zugestellte Bestätigung ist das Konto eine Leiche — gesperrt,
                    # nie freischaltbar, und es hält Namen und Adresse besetzt. Bis 0.19 kam
                    # dazu eine HTTP-500. Es wird deshalb wieder entfernt; die Registrierung
                    # lässt sich danach einfach wiederholen.
                    # Über den einen Löschweg (H-13, Integrationsfunde 12/18): Sonst stünden
                    # `signup` und diese Zeile samt IP weiter unter dem Namen, und wer ihn später
                    # registriert, sähe sie auf seiner Kontoseite als eigene Ereignisse (H-7).
                    auth.store.konto_entfernen(uid)
                    auth.audit("verify_send_error", ersatzname(uid), ip,
                               detail=f"{grund}, Konto entfernt")

                seite = auth.render_page("register", request=request, **_reg_ctx(nxt, sent_verify=True))
                # Der Token entsteht HIER, in der Anfrage; nur der Versand wartet auf den
                # Postausgang. Eine Sperre durch den Betreiber verwirft offene Token (H-18) —
                # entstand er erst im Mail-Arbeiter, fand eine Sperre im Wartefenster nichts, und
                # der verspätete Link hob sie danach auf. Zeitlich neutral nur gegenüber dem
                # Platzhalter-Zweig einer vergebenen Adresse (R4-03, Name ≠ Adresse), der seinen
                # Token ebenfalls in der Anfrage anlegt. Ist der Name die Adresse (immer bei
                # login_identifier='email'), schreibt der Vergeben-Zweig nur die Audit-Zeile —
                # dieses Zeitorakel bestand schon vorher und steht im Backlog (T-13).
                try:
                    senden = auth._verify_mail(uid, email_final, verify_base)
                except Exception:
                    senden = None
                if senden is None:
                    _zuruecknehmen("versand")
                    return seite

                def _versand():
                    try:
                        senden()
                    except Exception:
                        _zuruecknehmen("versand")
                return auth.nach_der_antwort(
                    seite, _versand, bei_ueberlauf=lambda: _zuruecknehmen("warteschlange_voll"))
            token, ok, is_new = auth.apply_factor(request, uid, "password", ip,
                                                  request.headers.get("user-agent"), True)
            resp = RedirectResponse(auth.login_redirect_after(request, token, uid, nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            return resp

    # ---------- Forward-Auth (Reverse-Proxy: Caddy forward_auth / nginx auth_request / Traefik) ----------
    if cfg.forward_auth_enabled:
        from fastapi.responses import Response

        def _required_roles(request: Request) -> list:
            """Rollen, die der **Proxy** für diese Route verlangt: `?roles=a,b` (mehrfach erlaubt)
            oder Header `X-TinySesam-Roles`. Ohne Angabe bleibt /auth/forward binär wie bisher.

            Gelesen wird die Angabe aus dem Sub-Request, den der Proxy stellt — sie steht in
            dessen Konfiguration, nicht beim Client. Trotzdem ist die Auswertung absichtlich
            **fail-closed**: mehrere Angaben werden UND-verknüpft, Kommas innerhalb einer Angabe
            ODER. Hängt ein Client also selbst ein `roles=` oder den Header an (weil ein Setup den
            Client-Query durchreicht), kann er die Prüfung nur verschärfen — nie aufweichen.
            """
            groups = []
            for raw in list(request.query_params.getlist("roles")) + \
                       [request.headers.get("x-tinysesam-roles") or ""]:
                rs = [r.strip() for r in str(raw).split(",") if r.strip()]
                if rs:
                    groups.append(rs)
            return groups

        def _forward_abweisung_protokollieren(request: Request, orig: str) -> None:
            """Eine 401 der Forward-Auth ins Audit-Log — wenn ein Nachweis vorlag (B5-17).

            Bisher schrieb diese Antwort nichts. Protokolliert wird, wenn die Anfrage etwas
            MITBRACHTE, das nicht (mehr) gilt: ein Sitzungscookie ohne gültige Sitzung, eine
            Sitzung mitten im Faktor-Schritt, einen API-Key. Das ist der Anlass zum Nachsehen —
            ein abgelaufener, gestohlener oder erratener Nachweis. Ein Aufruf ganz OHNE Nachweis
            ist der gewöhnliche erste Besuch vor dem Login; ihn zu protokollieren begrübe das Log
            unter Seitenaufrufen, und das Zugriffslog des Proxys hat ihn ohnehin. Gedrosselt je
            IP und Grund, weil ein Browser mit abgelaufenem Cookie jede Teilanfrage einer Seite
            (Bilder, Skripte) einzeln abweisen lässt.
            """
            if request.cookies.get(auth.session_cookie_name):
                grund = "mfa_offen" if auth.pending_user(request) else "sitzung_ungueltig"
            elif cfg.apikey_enabled and auth._extract_api_key(request):
                grund = "api_key_ungueltig"
            else:
                return
            ip = auth.client_ip(request)
            if auth._einmal_je(("forward401", ip, grund), 300):
                auth.audit("forward_denied", None, ip,
                           f"grund={grund} url={security.url_fuer_log(orig)}")

        def _forward(request: Request):
            u = auth.current_user(request)   # Session ODER API-Key
            orig = auth.forwarded_url(request)
            if u:
                # Schützt diese Installation mehrere Anwendungen, reicht „angemeldet" nicht:
                # Wer in welche darf, hat der Provider je Client entschieden (T-14). Der Vermerk
                # dazu hängt an der SITZUNG — ein API-Key hat keinen und ist hier auch nicht
                # gemeint; für ihn bleibt es bei der bisherigen Antwort.
                anwendung = auth.oidc_anwendung(orig)
                sitzung = request.cookies.get(auth.session_cookie_name) or ""
                if anwendung and sitzung:
                    ja, grund = auth.oidc_freigabe_gueltig(auth.store.session_hash(sitzung), anwendung)
                    if not ja:
                        # Kein 403: Der Provider soll gefragt werden, nicht der Mensch abgewiesen.
                        # Er hat dort meist noch eine Sitzung, der Sprung ist für ihn ein Flackern.
                        # Erst wenn der Provider ablehnt, sieht der Mensch dessen eigene Absage —
                        # und zwar die des Providers, denn dort wird die Freigabe gepflegt.
                        auth.audit("oidc_app_revalidate", u["username"], auth.client_ip(request),
                                   f"app={anwendung} grund={grund}")
                        login = auth.forward_login_url(orig, request)
                        return Response(status_code=401,
                                        headers={"X-TinySesam-Location": login,
                                                 "X-TinySesam-Reason": "app-" + grund,
                                                 "WWW-Authenticate": 'FormBased realm="TinySesam"'})
                # Rollenprüfung im Proxy-Modus. Fehlt die Rolle, ist das **403, nicht 401**:
                # ein 401 schickte den bereits Angemeldeten zurück zum Login, der ihn sofort
                # wieder hierher schickt — eine Schleife, an deren Ende dieselbe Rolle fehlt.
                fehlend = [g for g in _required_roles(request)
                           if not any(auth.has_role(u, r) for r in g)]
                if fehlend:
                    # Eine 403 im Proxy-Log sagt nicht, wer woran gescheitert ist. Das Panel hat
                    # das Audit-Log ohnehin — also dorthin, wo man später nachsieht.
                    auth.audit("forward_role_denied", u["username"], auth.client_ip(request),
                               f"url={security.url_fuer_log(orig)} fehlt={';'.join(','.join(g) for g in fehlend)}")
                    return Response(status_code=403, headers={"X-TinySesam-Reason": "role"})
                # Welche Header das sind, steuert config.forward_headers (Vorgabe: Remote-*).
                return Response(status_code=200, headers=auth.forward_response_headers(u))
            login = auth.forward_login_url(orig, request)
            _forward_abweisung_protokollieren(request, orig)
            # Caddys forward_auth-Shortcut reicht nur die 401 durch → handle_response/redir nötig
            return Response(status_code=401, headers={"X-TinySesam-Location": login,
                                                      "WWW-Authenticate": 'FormBased realm="TinySesam"'})

        @r.get("/auth/forward")
        def forward_auth(request: Request):
            return _forward(request)

        @r.get("/auth/verify")
        def verify_auth(request: Request):
            return _forward(request)

    # ---------- Eigenes Konto (Selbstverwaltung) ----------
    @r.post("/auth/password")
    async def change_own_password(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        b = await auth.json_body(request)
        ip = auth.client_ip(request)
        # Das alte Passwort ist ein Geheimnis wie am Login — also derselbe Dreiklang aus
        # Drossel, Sperre und Protokoll. Ohne ihn war diese Route ein stilles, unbegrenztes
        # Passwort-Orakel: beliebig viele Versuche, nie eine 429, keine Zeile im Sicherheits-
        # Log, kein Fehlversuch in `login_attempt` — während derselbe Fehlversuch am Login
        # nach wenigen Anläufen sperrt (R4-10; die Login-Schwelle ist `max_login_attempts`,
        # Vorgabe 5 und im Panel einstellbar).
        #
        # Die Sperre ist ein EIGENER Topf (`is_password_change_locked`, eigene Schwelle
        # `password_change_max_attempts`), nicht der des Logins: Mit dem geteilten Zähler
        # sperrten fünf Tippfehler hier die Anmeldung für 15 Minuten — samt dieser Route, über
        # die der Nutzer die Sperre hätte abtragen können. Hinter NAT traf es über
        # `ip_attempt_factor` sogar unbeteiligte Kollegen. Gedrosselt bleibt es (`rate_ok`),
        # protokolliert auch.
        versuch = (auth.versuch_beginnen(u["username"], ip, "password_change")
                   if auth.rate_ok(ip, login=False) else None)
        if versuch is None:
            raise HTTPException(429, auth.t("api.too_many"))
        # Geprüft wird gegen die **ID** der eigenen Sitzung, nicht gegen die Login-Kennung:
        # `check_password(u["username"], …)` lief durch `find_user()` und konnte damit auf ein
        # FREMDES Konto auflösen (Benutzername des Angreifers = E-Mail des Opfers, R4-12).
        # Dann riet man hier nicht sein eigenes Passwort, sondern dessen — und der Treffer
        # setzte still das eigene Passwort, blieb also unsichtbar.
        richtig = auth.verify_user_password(u["id"], b.get("current") or "")
        # Eigene Methode: Ein Treffer hier räumt die Fehlversuche des Login-Pfads NICHT weg
        # (`record_login` löscht nur die derselben Methode) — die Sperre bleibt, wo sie gilt.
        auth.record_login(u["username"], ip, richtig, "password_change", versuch=versuch)
        if not richtig:
            raise HTTPException(403, auth.t("api.password_wrong"))
        new = b.get("new") or ""
        mangel = auth.passwort_mangel(new, username=u["username"], email=u.get("email"), api=True)
        if mangel:
            raise HTTPException(400, mangel)
        auth.set_password(u["id"], new)
        # andere Sitzungen des Users beenden (aktuelle behalten) — Standard nach Credential-Wechsel
        s = auth.session_from_request(request)
        auth.store.delete_user_sessions_except(u["id"], s["token_hash"] if s else None)
        # API-Keys überleben den eigenen Passwortwechsel mit Absicht: Sie sind für Automatiken
        # da, und ein Routine-Wechsel soll die nicht reihenweise stilllegen (ein Konto = oft ein
        # Key = mehrere Integrationen). Verschwiegen wird es trotzdem nicht — wer nach einem
        # Einbruch das Passwort ändert, muss wissen, dass da noch eine Tür offen ist.
        aktiv = auth.store.count_active_api_keys(u["id"])
        auth.audit("password_change", u["username"], auth.client_ip(request),
                   f"api_keys_active={aktiv}" if aktiv else None)
        return {"ok": True, "api_keys_active": aktiv}

    if cfg.account_enabled:
        @r.get("/auth/account", response_class=HTMLResponse)
        def account_page(request: Request):
            u = auth.current_user(request)
            if not u:
                return RedirectResponse(f"{auth.pfad(request, cfg.login_path)}?next={_q(auth.pfad(request, '/auth/account'))}", 303)
            return auth.render_page("account", request=request, user=u, methods=cfg.enabled_methods(),
                                    has_totp=auth.store.has_confirmed_totp(u["id"]),
                                    recovery_left=auth.recovery_codes_remaining(u["id"]),
                                    recovery_warn=auth.RECOVERY_WARNSCHWELLE,
                                    has_pin=(cfg.pin_enabled and auth.has_pin(u["id"])),
                                    is_admin=bool(u["is_admin"]), admin_path=cfg.admin_path,
                                    events=auth.own_events(u["id"]),
                                    username_change=(cfg.self_service_username_change
                                                     and cfg.login_identifier != "email"),
                                    email_change=(cfg.self_service_email_change and auth.mail_configured()))

    # ---------- Selbstbedienung: Benutzername und Adresse (PO-Entscheid 2026-09-25) ----------
    def _frisch_fuer_kennung(request: Request) -> dict:
        """Wer seine Kennung ändert, bestätigt vorher frisch — wie beim Einrichten eines Faktors:
        Mit einem gestohlenen Sitzungscookie liesse sich sonst der Name oder die Adresse umbiegen,
        und der Reset-Link ginge danach an den Dieb. Ein Konto ohne jeden Faktor (rein föderiert)
        hängt am Alter der Anmeldung. Kein API-Key (`require_session`)."""
        u = auth.require_session(request)
        if auth.stepup_options(u):
            return auth.require_mfa(request)
        if not auth.login_fresh(request, u):
            raise HTTPException(403, auth.t("api.stepup_relogin"))
        return u

    if cfg.self_service_username_change:
        @r.post("/auth/account/username")
        async def own_username(request: Request):
            b = await auth.json_body(request)
            u = _frisch_fuer_kennung(request)
            if not auth.rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                neu = auth.change_username(u["id"], b.get("username"), auth.client_ip(request))
            except ValueError as e:
                raise HTTPException(400, str(e))
            return {"ok": True, "username": neu}

    if cfg.self_service_email_change:
        @r.post("/auth/account/email")
        async def own_email(request: Request):
            b = await auth.json_body(request)
            u = _frisch_fuer_kennung(request)
            if not auth.rate_ok(auth.client_ip(request), login=False):
                raise HTTPException(429, auth.t("api.too_many"))
            try:
                senden = auth.request_email_change(u["id"], b.get("email"), auth.public_base(request))
            except ValueError as e:
                raise HTTPException(400, str(e))
            except ConfigError:
                raise HTTPException(400, auth.t("api.no_mail"))
            # Dieselbe Antwort, ob ein Link hinausgeht oder nicht (vergebene Adresse, Drossel) —
            # und der Versand erst nach der Antwort (R4-05): keine Laufzeit als Orakel.
            antwort = JSONResponse({"ok": True, "sent": True})
            return auth.nach_der_antwort(antwort, senden) if senden else antwort

        @r.get("/auth/email/{token}", response_class=HTMLResponse)
        def email_confirm_page(request: Request, token: str):
            """Bestätigungsseite statt Einlösen per GET — Link-Scanner lösen nichts ein (R4-02)."""
            if not auth.peek_magic(token, purpose="email_change"):
                auth.token_abgewiesen("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            return auth.render_page("magic_confirm", request=request, zweck="email_change",
                                    action=auth.pfad(request, f"/auth/email/{_q(token)}"))

        @r.post("/auth/email/{token}")
        def email_confirm(request: Request, token: str, csrf_tok: str = Form("", alias="_csrf")):
            auth.require_csrf(request, csrf_tok)
            ergebnis = auth.confirm_email_change(token, auth.client_ip(request))
            if ergebnis is None:
                auth.token_abgewiesen("email_change", request)
                return auth.render_page("magic_invalid", request=request, status=400)
            if ergebnis == "vergeben":
                return auth.render_page("magic_invalid", request=request, status=409)
            ziel = auth.pfad(request, "/auth/account" if cfg.account_enabled else cfg.login_redirect)
            return RedirectResponse(ziel, 303)

    # ---------- Eigene Sitzungen verwalten ----------
    @r.get("/auth/sessions")
    def own_sessions(request: Request):
        u = auth.current_user(request)
        if not u:
            raise HTTPException(401)
        # Die Liste nennt IP und Browser jeder Sitzung — das ist die Sicht eines Menschen auf sein
        # Konto, nicht die eines Automaten (F-09). Ansehen braucht keine frische Bestätigung
        # (ASVS 5.0 7.5.2 verlangt sie nur fürs Beenden), wohl aber eine echte Sitzung.
        auth.require_session(request, u)
        cur = auth.session_from_request(request)
        cur_tok = cur["token_hash"] if cur else None
        out = []
        for s in auth.store.list_sessions(u["id"]):
            out.append({"created_at": s["created_at"], "ip": s["ip"], "method": s["method"],
                        "user_agent": (s["user_agent"] or "")[:120], "current": s["token_hash"] == cur_tok})
        return out

    @r.post("/auth/sessions/revoke-after-login")
    async def sessions_revoke_after_login(request: Request):
        """Die übrigen Sitzungen beenden, SOBALD diese halbe Anmeldung vollständig ist (Grenze d).

        Nur für eine halbe Sitzung: Eine volle nimmt `/auth/sessions/revoke`. Beendet wird hier
        nichts — vermerkt wird die Zustimmung, eingelöst erst nach dem letzten Faktor. Wer nur den
        ersten Faktor hat, kann damit also nichts beenden, was er nicht ohnehin voll könnte."""
        await auth.json_body(request)                     # CSRF wie jede Schreib-Route
        s = auth.session_from_request(request)
        if not s or s["mfa_ok"]:
            raise HTTPException(400, auth.t("api.invalid", grund="keine halbe Anmeldung"))
        auth.store.set_session_andere_beenden(s["token_hash"])
        return {"ok": True}

    @r.post("/auth/sessions/revoke")
    async def own_sessions_revoke(request: Request):
        # Sitzungen beenden verlangt eine frische Bestätigung (F-09, ASVS 5.0 7.5.2: „having
        # authenticated again with at least one factor"). Vorher genügte jede Sitzung und jeder
        # API-Key: Ein gestohlenes Cookie warf den rechtmässigen Inhaber auf allen anderen
        # Geräten hinaus, und „alle beenden" widerrief dabei auch noch seine API-Keys. Die
        # Kontoseite folgt dem `X-TinySesam-Reauth`-Hinweis von selbst.
        if not auth.current_user(request):
            raise HTTPException(401)
        u = auth.require_mfa(request)
        scope = (await auth.json_body(request)).get("scope", "others")
        # Ein API-Key ist eine zweite, gleichwertige Anmeldung — er hängt an keiner Sitzung.
        # „alle beenden" ist die Panik-Taste (Konto vermutlich übernommen): da gehört er dazu.
        # „andere beenden" ist Aufräumen: da bleibt er, und die Antwort sagt, wie viele weiter
        # gelten. Stillschweigend weiterlaufen lassen ist das Einzige, was nicht geht.
        keys_widerrufen = 0
        if scope == "all":
            auth.store.delete_user_sessions(u["id"])          # inkl. aktueller → ausgeloggt
            keys_widerrufen = auth._keys_widerrufen(u["id"], "sitzungen_beendet")
        else:
            cur = auth.session_from_request(request)
            auth.store.delete_user_sessions_except(u["id"], cur["token_hash"] if cur else None)
        auth.audit("sessions_revoke", u["username"], auth.client_ip(request),
                   scope + (f" api_keys_revoked={keys_widerrufen}" if keys_widerrufen else ""))
        return {"ok": True, "api_keys_revoked": keys_widerrufen,
                "api_keys_active": auth.store.count_active_api_keys(u["id"])}

    # ---------- Logout / me ----------
    def _abmelden(request: Request):
        # Protokolliert wird das Konto, dessen Sitzung hier endet — aus dem Cookie (0.20.1,
        # `session_user`), nicht das eines mitgeschickten API-Keys.
        u = auth.session_user(request) or auth.pending_user(request)
        # OIDC-Provider-Logout (optional): vor dem lokalen Logout prüfen, ob die Sitzung via OIDC lief
        oidc_logout_url = None
        if cfg.oidc_rp_logout and auth.oidc:
            s = auth.session_from_request(request)
            factors: list = []
            try:
                factors = __import__("json").loads(s["factors_done"] or "[]") if s else []
            except Exception:
                factors = []
            if s and (s["method"] == "oidc" or "oidc" in factors):
                # Ohne vertrauenswürdige Basis KEIN post_logout_redirect_uri: sonst schickte
                # der IdP das Opfer nach dem Logout auf den Host aus dem Host-Header. Der
                # lokale Logout unten läuft trotzdem, nur eben ohne Provider-Umweg.
                base = auth.public_base(request)
                if base:
                    oidc_logout_url = auth.oidc.end_session_url(base + cfg.logout_redirect)
        if u:
            auth.audit("logout", u["username"], auth.client_ip(request))
        resp = RedirectResponse(oidc_logout_url or auth.pfad(request, cfg.logout_redirect), 303)
        auth.logout(request, resp)
        return resp

    @r.get("/auth/logout")
    def logout(request: Request):
        # Logout-CSRF (F-07): Ein GET, der abmeldet, lässt sich von jeder fremden Seite mit einem
        # <img src> auslösen. Der Browser sagt aber, woher die Navigation kommt. Von der eigenen
        # Seite, einer Nachbar-Subdomain (die Abmelden-Schaltfläche einer geschützten App) oder
        # aus der Adresszeile gilt der Link weiter; von einer FREMDEN Seite kommt statt des
        # Abmeldens eine Rückfrage mit POST-Formular. Ohne den Header (alter Browser, Skript)
        # bleibt es beim alten Verhalten — sonst bräche jeder bestehende Abmelde-Link.
        if (request.headers.get("sec-fetch-site") or "").strip().lower() == "cross-site":
            return auth.render_page("logout", request=request)
        return _abmelden(request)

    @r.post("/auth/logout")
    def logout_post(request: Request, csrf_tok: str = Form("", alias="_csrf")):
        """Abmelden per Formular — mit CSRF-Prüfung, der Weg für eigene Oberflächen."""
        auth.require_csrf(request, csrf_tok or request.headers.get("x-csrf-token"))
        return _abmelden(request)

    @r.get("/auth/me")
    def me(request: Request):
        u = auth.current_user(request)
        if not u:
            return JSONResponse({"authenticated": False}, 401)
        return {"authenticated": True, "id": u["id"], "username": u["username"],
                "display_name": u["display_name"], "is_admin": bool(u["is_admin"]),
                "roles": auth.user_roles(u)}

    # ---------- OIDC (nur wenn aktiviert) ----------
    if auth.oidc:
        from .oidc import register_oidc_routes
        register_oidc_routes(r, auth)

    # ---------- Passkey / WebAuthn (nur wenn aktiviert) ----------
    if auth.webauthn:
        from .webauthn_ import register_passkey_routes
        try:
            register_passkey_routes(r, auth)
        except ModuleNotFoundError as e:
            # Wer passkey_enabled bewusst einschaltet, soll lesen koennen, was fehlt — statt
            # einen ModuleNotFoundError aus dem Innern der Bibliothek zu bekommen.
            #
            # `MissingExtra`, nicht `RuntimeError`: Die Doku zeigt `except MissingExtra as e:
            # … e.extra` als Muster, und für den Passkey-Fall griff das ins Leere — als
            # einziges Verfahren warf er einen anderen Typ. (`MissingExtra` erbt von
            # `RuntimeError`, bestehender Code fängt also weiter.)
            from .errors import MissingExtra
            raise MissingExtra(
                "passkey_enabled=True, aber das Extra [passkey] ist nicht installiert "
                "(pip install 'tinysesam[passkey]'). Ohne es gibt es keine Passkey-Routen; "
                "passkey_enabled=False schaltet sie ab.", extra="passkey") from e

    # ---------- SAML 2.0 SP (nur wenn aktiviert) ----------
    if auth.saml:
        from fastapi.responses import Response as _Resp

        def _saml_base(request: Request):
            proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
            host = (request.headers.get("x-forwarded-host") or request.headers.get("host")
                    or request.url.netloc).split(",")[0].strip()
            return f"{proto}://{host}"

        def _saml_req(request: Request, form=None):
            """Der `req`-Satz für python3-saml — gebaut aus der GEPRÜFTEN Basis (F-16).

            Vorher standen hier Schema und Host aus `X-Forwarded-Proto`/`Host`. python3-saml
            berechnet daraus die Adresse, die es für die eigene hält, und vergleicht sie mit der
            `Destination` der Assertion — der Anfragende bestimmte diesen Vergleich also mit.
            """
            from .saml_ import request_kontext
            return request_kontext(_saml_basis(request), request.url.path,
                                   form=form, query=request.query_params)

        # Anker gegen untergeschobene Assertions: Die ID des AuthnRequests liegt bis zur ACS in
        # einem eigenen, kurzlebigen Cookie.
        #
        # SameSite ist hier NICHT aus der Config: Die ACS ist ein Cross-Site-POST (der IdP lässt
        # den Browser ein Formular abschicken), und dabei sendet der Browser ein Lax-Cookie
        # nicht mit — der Vorgabewert `cookie_samesite="lax"` würde den Anker also bei jedem
        # echten Login verlieren. Mitkommen kann nur `SameSite=None`, und das verlangt `Secure`.
        # Ohne `cookie_secure` bleibt es deshalb beim Config-Wert: lokal/im TestClient ist der
        # POST same-site und kommt durch, für einen echten IdP ist dieser Aufbau ohnehin keiner.
        _SAMLFLOW = "tinysesam_saml_flow"

        # SAML baut aus der Basis die eigene Entity-ID und die ACS-URL. Kommt sie aus dem
        # Host-Header, wandert ein fremder Name in den AuthnRequest und in die Metadaten —
        # deshalb hier kein Weiterarbeiten ohne geprüfte Basis (R4-01).
        def _saml_basis(request: Request) -> str:
            return auth.require_public_base(request, _saml_base(request))

        @r.get("/auth/saml/login")
        def saml_login(request: Request, next: str = ""):
            base = _saml_basis(request)
            url, rid = auth.saml.login_url(_saml_req(request), base, return_to=auth.safe_next(next, request))
            resp = RedirectResponse(url, 303)
            # `__Host-` davor, wo möglich (A-1) — sonst setzt eine Nachbar-Subdomain den Anker.
            auth._flow_cookie_setzen(resp, _SAMLFLOW, rid or "", max_age=600,
                                    samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
            return resp

        @r.post("/auth/saml/acs")            # POST vom IdP → von CSRF ausgenommen (Signatur schützt)
        async def saml_acs(request: Request):
            # Ratenbegrenzt wie jeder andere Anmelde-Einstieg (F-22). Die ACS nimmt ohne CSRF und
            # ohne Sitzung einen POST an und wirft ihn durch die XML-Signaturprüfung — die
            # teuerste Arbeit, die ein Unangemeldeter hier auslösen kann, und bis 0.19.x die
            # einzige Anmelderoute ohne Drossel.
            ip = auth.client_ip(request)
            if not auth.rate_ok(ip):
                raise HTTPException(429, auth.t("err.rate"))
            form = await request.form()
            base = _saml_basis(request)
            data = auth.saml.process(_saml_req(request, form), base,
                                     request_id=request.cookies.get(auth.flow_cookie_name(_SAMLFLOW)) or "")
            if not data:
                # NICHT die Magic-Link-Seite („dieser Link ist ungültig, abgelaufen oder schon
                # benutzt") — hier ging es um keinen Link, und die Meldung schickte beim ersten
                # Lauf gegen einen echten IdP in die falsche Richtung. Der Grund steht im Log.
                auth.audit("saml_invalid", None, ip, "Assertion abgelehnt (Grund im Sicherheits-Log)")
                raise HTTPException(400, auth.t("err.saml"))
            u = auth.check_saml(data.get("nameid"), data.get("attrs") or {}, ip=ip)
            if not u:
                # Den Grund (Gruppe, kein Konto, gesperrt, Kennung vergeben) schreibt
                # `check_saml` selbst ins Audit-Log — hier nur die Antwort an den Browser.
                raise HTTPException(403, auth.t("api.saml_denied"))
            nxt = auth.safe_next(form.get("RelayState") or "", request)
            # SAML kennt kein `email_verified`: Kein Standard-Attribut sagt, dass der IdP die
            # Adresse geprüft hat. Ohne `saml_email_trusted` (Vorgabe) reist hier deshalb „kein
            # Beleg" mit — eine Allowlist-ADRESSE wird über SAML nie zum Erst-Admin (F-14). Mit
            # dem Schalter zählt der Beleg am Konto, den `check_saml` gesetzt hat. Der Faktor `saml`
            # steht zusätzlich in `FOEDERIERTE_FAKTOREN`, das Weglassen wäre also kein Loch.
            token, ok, is_new = auth.apply_factor(request, u["id"], "saml",
                                                  auth.client_ip(request),
                                                  request.headers.get("user-agent"),
                                                  email_bestaetigt=bool(
                                                      cfg.saml_email_trusted and u.get("email")
                                                      and u.get("email_verified")))
            resp = RedirectResponse(auth.login_redirect_after(request, token, u["id"], nxt), 303)
            if is_new:
                auth.set_cookie(resp, token)
            # einmal angefordert, einmal eingelöst
            auth._flow_cookie_loeschen(resp, _SAMLFLOW,
                                      samesite="none" if cfg.cookie_secure else cfg.cookie_samesite)
            return resp

        @r.get("/auth/saml/metadata")
        def saml_metadata(request: Request):
            base = _saml_basis(request)
            return _Resp(content=auth.saml.metadata(base), media_type="application/xml")

    # ---------- API-Keys: Self-Service für den eingeloggten User ----------
    if cfg.apikey_enabled:
        @r.get("/auth/apikeys")
        def apikeys_list(request: Request):
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            return [key_view(k) for k in auth.list_api_keys(u["id"])]

        def _nur_mit_sitzung(request: Request):
            """Verwaltung von Schlüsseln setzt eine interaktive Sitzung voraus.

            `create_api_key` schneidet den Scope gegen die **Konto**-Rollen — nicht gegen die
            des Aufrufers. Ein auf `["lager"]` beschränkter Key konnte sich damit selbst einen
            Key mit allen Rollen des Kontos ausstellen und so seine eigene Begrenzung aufheben.
            Statt die Schnittmenge durch den ganzen Aufrufpfad zu fädeln, gilt die einfachere
            Regel: Schlüssel gibt ein Mensch aus, kein Schlüssel.
            """
            u = auth.current_user(request)
            if not u:
                raise HTTPException(401)
            if u.get("_via") != "session":
                raise HTTPException(403, auth.t("api.key_needs_session"))
            return u

        @r.post("/auth/apikeys")
        async def apikeys_create(request: Request):
            u = _nur_mit_sitzung(request)
            b = await auth.json_body(request)
            # `kind` entscheidet, was der Key kann (R6-5): "automat" arbeitet allein, trägt
            # aber nie das Admin-Flag; "mensch" gilt nur zusammen mit einer Sitzung desselben
            # Kontos. Die Vorgabe ist die engere der beiden.
            # Ein unbrauchbarer Scope, „unbefristet" ohne Erlaubnis oder eine unbekannte Art
            # sind Eingabefehler, kein Serverfehler — dieselbe Klasse wie R6-8 im Panel.
            try:
                return auth.create_api_key(u["id"], name=b.get("name"),
                                           expires_days=b.get("expires_days"), roles=b.get("roles"),
                                           kind=str(b.get("kind") or "automat"))
            except (ConfigError, ValueError, TypeError) as e:
                raise HTTPException(400, auth.t("api.invalid", grund=str(e)))

        @r.post("/auth/apikeys/{key_id}/revoke")
        def apikeys_revoke(request: Request, key_id: int):
            auth.require_csrf(request, request.headers.get("x-csrf-token"))
            u = _nur_mit_sitzung(request)
            auth.revoke_api_key(key_id, u["id"])   # sperren, nicht löschen
            return {"ok": True}

    # ---------- Admin-Panel — an config.admin_path; via auth.admin_router() auch woanders montierbar ----------
    if cfg.admin_enabled:
        r.include_router(auth.admin_router(), prefix=cfg.admin_path)

    return r


def _mail_basis(auth, request) -> str:
    """Die Basis für einen verschickten Link — oder HTTP 503, nie ein 500 und nie ein stiller 200.

    `konfigpruefung` lässt eine Mail-Funktion ohne `base_url` gar nicht erst starten. Wird die
    Config NACH dem Konstruktor geändert (`auth.cfg.base_url = ""`), wirft
    `require_public_base()` zur Request-Zeit `ConfigError` — und den fing keine Route: Der
    Nutzer bekam „internal server error", der Betreiber einen Stacktrace ohne Hinweis, dass es
    an der Konfiguration liegt. 503 sagt, was es ist: Der Dienst ist so nicht einsatzbereit.
    Der Grund steht einmal im Sicherheits-Log (nicht je Anfrage), die Antwort verrät nichts
    über das Postfach und nichts über den Aufbau.
    """
    from . import security
    try:
        return auth.require_public_base(request)
    except ConfigError as e:
        if security.einmal_melden("mail_basis"):
            security.seclog.error("Verschickter Link nicht möglich, Anfrage mit 503 beantwortet: %s", e)
        raise HTTPException(503, auth.t("api.base_missing"))


def _key_art(k) -> str:
    """Die Art eines Key-Datensatzes, verträglich mit Dateien vor Schema 7."""
    try:
        return str(k["kind"] or "automat")
    except (IndexError, KeyError):
        return "automat"


def key_view(k) -> dict:
    return {"id": k["id"], "name": k["name"], "prefix": k["prefix"], "created_at": k["created_at"],
            "last_used": k["last_used"], "expires_at": k["expires_at"], "revoked": bool(k["revoked"]),
            "kind": _key_art(k)}


def _login_nach_token(auth, request, uid, nxt):
    """Nach einem eingelösten E-Mail-Token anmelden (Faktor `magic`) und weiterleiten.

    Gemeinsam für Anmelde-Link und E-Mail-Bestätigung: Beide belegen dasselbe — der Empfänger
    hat Zugriff auf das Postfach. Eine globale Faktor-Kette kann trotzdem einen weiteren Schritt
    verlangen; darum geht der Weg über `apply_factor`/`login_redirect_after` statt direkt in
    eine Sitzung.
    """
    from fastapi.responses import RedirectResponse
    token, ok, is_new = auth.apply_factor(request, uid, "magic",
                                          auth.client_ip(request), request.headers.get("user-agent"))
    resp = RedirectResponse(auth.login_redirect_after(request, token, uid, nxt), 303)
    if is_new:
        auth.set_cookie(resp, token)
    return resp


def _remember(cfg, val) -> bool:
    """Remember-me aus dem Formular auswerten. Ist die Checkbox global aus, gilt immer persistent."""
    if not cfg.remember_me_enabled:
        return True
    return str(val) in ("1", "true", "on", "yes")


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s or "/", safe="/")
