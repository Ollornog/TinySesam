"""OIDC (Authorization Code Flow) für einen generischen Provider (PocketID, Keycloak, …).

httpx für Discovery/Token, authlib.jose für die ID-Token-Verifikation (Signatur gegen JWKS +
iss/aud/exp). state & nonce liegen kurzlebig im Store (flow), nicht im Client → CSRF-/Replay-fest.
Beide Libs sind optional-Extra `[oidc]`.
"""
from __future__ import annotations

import time
import secrets
from urllib.parse import urlencode

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from . import security
from .messages import translate


from . import errors


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Aus einem nackten Importfehler eine Meldung machen, die sagt, was zu tun ist.

    Die Extras werden hier bewusst LAZY importiert (erst beim Benutzen). Der Preis dafür war
    bis 0.18.0 ein `ModuleNotFoundError: authlib` mitten im Anmeldevorgang — für den Betreiber
    ein Defekt, dabei fehlte nur eine Zeile im Install-Befehl."""
    return errors.MissingExtra(
        "Das Extra [oidc] ist nicht installiert (pip install 'tinysesam[oidc]') — "
        f"es fehlt: {e.name or 'authlib'}.", extra="oidc")


def _hash(wert: str) -> str:
    """Flow-Geheimnisse liegen nur als Hash im Speicher — wie Sitzungs-Token auch."""
    import hashlib
    return hashlib.sha256((wert or "").encode()).hexdigest()


def _flag_wahr(wert) -> bool:
    """`email_verified` als Ja/Nein. Manche Provider schicken den Wert als Zeichenkette
    ("true"), deshalb beide Schreibweisen — alles andere, auch ein fehlender Wert, ist Nein."""
    if isinstance(wert, bool):
        return wert
    if wert is None:
        return False
    return str(wert).strip().lower() in ("true", "1")


def _email_mit_beleg(claims, nutzerinfo) -> tuple:
    """Adresse UND Beleg immer aus demselben Dokument.

    OpenID Connect Core 5.1 kennt für die Adresse den Claim `email_verified` („True if the
    End-User's e-mail address has been verified"). **Fehlt er, lautet die Antwort Nein** —
    nicht „vielleicht": Ohne Beleg ist `email` ein Textfeld, das der Anmeldende beim IdP
    selbst gefüllt hat (Selbstregistrierung, zweiter Mandant, öffentlicher Provider).

    Entscheidend ist das Wort *derselben*: Der Callback legt userinfo-Dokument und ID-Token
    zu einem Wörterbuch zusammen, und beim Mischen kann der Beleg des einen an die Adresse
    des anderen geraten — liefert das ID-Token nur `email` und das userinfo-Dokument eine
    ANDERE Adresse mit `email_verified=true`, trüge die ungeprüfte Adresse den fremden Beleg.
    Darum wird das Paar hier an der Quelle gebildet, mit Vorrang für das signierte ID-Token
    (das gewinnt auch beim Mischen).
    """
    for quelle in (claims, nutzerinfo):
        mail = (quelle or {}).get("email")
        if mail:
            return mail, _flag_wahr((quelle or {}).get("email_verified"))
    return None, False


class OIDCClient:
    def __init__(self, issuer, client_id, client_secret, scopes):
        self.issuer = issuer.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.scopes = scopes
        self._meta = None
        self._meta_zeit = 0.0
        self._jwks = None
        self._jwks_zeit = 0.0

    #: Höchstalter der gecachten Metadaten. Ein Provider verschiebt gelegentlich Endpunkte;
    #: ein Tag ist lange genug, um nicht bei jedem Login zu fragen, und kurz genug, um eine
    #: Änderung nicht bis zum nächsten Neustart auszusitzen.
    META_TTL = 24 * 3600
    #: Höchstalter des JWKS. Provider rotieren ihre Signaturschlüssel regelmässig (Keycloak,
    #: Entra, Auth0); bis 0.18.0 wurde das Set EINMAL geholt und nie wieder — nach einer
    #: Rotation scheiterte jeder Login an der Signatur, bis jemand den Prozess neu startete.
    JWKS_TTL = 3600
    #: Kürzester Abstand zwischen zwei ausserplanmässigen JWKS-Abrufen. Ohne diese Bremse löst
    #: jedes kaputte id_token einen Abruf beim Provider aus — ein bequemer Weg, ihn von hier aus
    #: zu belasten.
    JWKS_MIN_ABSTAND = 60
    #: Signaturverfahren, die für ein ID-Token gelten — bewusst NUR asymmetrische.
    #: Geprüft wird gegen das **öffentliche** JWKS des Providers; ein HMAC-Verfahren ergäbe hier
    #: nie einen Sinn, denn das Geheimnis wäre ein öffentlicher Schlüssel. Genau darauf zielt die
    #: Algorithmen-Konfusion: Der Angreifer setzt `alg: HS256`, signiert mit dem öffentlichen
    #: Schlüssel aus dem JWKS als HMAC-Geheimnis und schreibt sich ins `sub`, das er will.
    #: Wer die Liste erweitert, muss beim asymmetrischen Verfahren bleiben — `_dekoder()` weist
    #: alles andere ab.
    ID_TOKEN_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                     "ES256", "ES384", "ES512", "EdDSA")

    def meta(self, erzwingen: bool = False):
        # `self._meta_zeit and …`: Wer die Metadaten von aussen setzt (Tests ohne Netz, oder ein
        # Aufbau, der sie aus einer Datei nimmt), hinterlässt keinen Zeitstempel. Ohne diese
        # Bedingung wäre so ein Satz sofort „älter als die Lebensdauer" und würde beim ersten
        # Zugriff überschrieben — inklusive des Netzzugriffs, den man gerade vermeiden wollte.
        veraltet = self._meta_zeit and (time.time() - self._meta_zeit) > self.META_TTL
        if self._meta is None or erzwingen or veraltet:
            try:
                import httpx
            except ModuleNotFoundError as e:
                raise _fehlt_extra(e) from e
            # Kein Redirect: Ein 3xx auf dem Well-Known-Pfad würde das Dokument von woanders holen —
            # und aus diesem Dokument kommen token_endpoint, jwks_uri und der Issuer, gegen den jedes
            # ID-Token geprüft wird. Wer den Pfad umleiten kann, hätte damit den ganzen Login.
            antwort = httpx.get(self.issuer + "/.well-known/openid-configuration",
                                timeout=10, follow_redirects=False)
            if antwort.status_code != 200:
                raise errors.ConfigError(
                    f"OIDC-Discovery unter {self.issuer}/.well-known/openid-configuration antwortet mit "
                    f"{antwort.status_code} statt 200 (Umleitungen werden nicht gefolgt — oidc_issuer muss "
                    "die endgültige Adresse sein, z.B. https statt http, ohne Pfadumleitung).")
            meta = antwort.json()
            self._pruefe_issuer(meta)
            self._meta = meta
            self._meta_zeit = time.time()
        return self._meta

    def _pruefe_issuer(self, meta: dict) -> None:
        """Das Discovery-Dokument muss den konfigurierten Issuer nennen (RFC 8414 §3.3, OIDC
        Discovery §4.3). Alles Weitere — Token-Endpunkt, JWKS, der Schlüssel, unter dem Konten in
        der Datenbank liegen — kommt aus diesem Dokument; stimmt der Issuer nicht, ist nichts davon
        vertrauenswürdig. Bis 0.18.0 wurde das nie verglichen."""
        gefunden = str(meta.get("issuer") or "").rstrip("/")
        if gefunden != self.issuer:
            raise errors.ConfigError(
                f"OIDC-Discovery: das Dokument nennt issuer={gefunden or '?'}, konfiguriert ist "
                f"oidc_issuer={self.issuer}. Beides muss übereinstimmen — sonst prüft TinySesam Tokens "
                "gegen einen Provider, den niemand konfiguriert hat.")

    def _jwkset(self, erzwingen: bool = False):
        alt_genug = self._jwks_zeit and (time.time() - self._jwks_zeit) > self.JWKS_TTL
        if self._jwks is None or alt_genug or erzwingen:
            try:
                import httpx
                from authlib.jose import JsonWebKey
            except ModuleNotFoundError as e:
                raise _fehlt_extra(e) from e
            self._jwks = JsonWebKey.import_key_set(httpx.get(self.meta()["jwks_uri"], timeout=10).json())
            self._jwks_zeit = time.time()
        return self._jwks

    def _dekoder(self):
        """Der JWT-Dekoder für das ID-Token — mit **fester** Algorithmenliste.

        `authlib.jose.jwt` ist ein fertiger Dekoder mit Vorgabesatz, und dieser Satz enthält
        HS256. Wird kein Verfahren genannt, sucht sich der **Header des Tokens** aus, wie geprüft
        wird — die Entscheidung liegt damit beim Absender. Bis authlib 1.3.0 liess sich so mit dem
        öffentlichen Schlüssel als HMAC-Geheimnis ein gültiges ID-Token fälschen
        (GHSA-5357-c2jx-v7qh); die Gegenmassnahme dort deckt nur einige Schlüsselformate ab.
        Die installierte Fassung darf nicht die Frage sein: Hier wird der Satz selbst gesetzt.
        """
        try:
            from authlib.jose import JsonWebToken
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        # Fail-closed gegen eine spätere Erweiterung (auch aus einer Unterklasse heraus): Alles,
        # was kein RSA-, PSS-, ECDSA- oder EdDSA-Verfahren ist, käme ohne privaten Schlüssel aus.
        fremd = [a for a in self.ID_TOKEN_ALGS if not str(a).startswith(("RS", "PS", "ES", "Ed"))]
        if fremd:
            raise errors.ConfigError(
                f"OIDC: ID_TOKEN_ALGS nennt {fremd}. Das ID-Token wird gegen das öffentliche JWKS "
                "des Providers geprüft — ein HMAC-Verfahren (HS*) oder 'none' macht damit den "
                "öffentlichen Schlüssel zum Signaturgeheimnis. Nur asymmetrische Verfahren.")
        return JsonWebToken(list(self.ID_TOKEN_ALGS))

    def _jwks_auffrischbar(self) -> bool:
        """Darf jetzt ausserplanmässig neu geholt werden? (Drosselung gegen Fremdlast.)"""
        return (time.time() - self._jwks_zeit) > self.JWKS_MIN_ABSTAND

    def auth_url(self, redirect_uri, state, nonce):
        q = urlencode({"response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
                       "scope": self.scopes, "state": state, "nonce": nonce})
        return self.meta()["authorization_endpoint"] + "?" + q

    def exchange(self, code, redirect_uri, nonce, t=None):
        """Code gegen Tokens tauschen und das ID-Token verifizieren.

        `t` ist die Übersetzungsfunktion des Aufrufers (`auth.t`). Der Client selbst kennt keine
        Sprache — er spricht das Protokoll, nicht mit dem Nutzer. Ohne `t` bleiben die beiden
        Meldungen englisch, statt einem Aufrufer mit `lang="en"` Deutsch unterzuschieben.
        """
        t = t or (lambda schluessel, **fmt: translate("en", schluessel, None, **fmt))
        try:
            import httpx
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        dekoder = self._dekoder()
        tok = httpx.post(self.meta()["token_endpoint"], timeout=15, data={
            "grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
            "client_id": self.client_id, "client_secret": self.client_secret}).json()
        if "id_token" not in tok:
            raise HTTPException(502, t("api.oidc_token", grund=tok.get("error", "?")))
        optionen = {"iss": {"essential": True, "value": self.meta()["issuer"]},
                    "aud": {"essential": True, "value": self.client_id}}
        try:
            claims = dekoder.decode(tok["id_token"], self._jwkset(), claims_options=optionen)
        except Exception:
            # Scheitert die Signatur, ist der wahrscheinlichste Grund eine Schlüsselrotation
            # beim Provider: Das Token nennt eine `kid`, die unser Set noch nicht kennt. Einmal
            # neu holen und erneut versuchen — gedrosselt, damit ein Strom gefälschter Tokens
            # den Provider nicht über uns belastet. Klappt es wieder nicht, gilt der Fehler.
            if not self._jwks_auffrischbar():
                raise
            security.seclog.warning(
                "OIDC: ID-Token nicht verifizierbar — JWKS wird neu geholt (Schlüsselrotation?).")
            claims = dekoder.decode(tok["id_token"], self._jwkset(erzwingen=True),
                                    claims_options=optionen)
        claims.validate()  # exp/iat/nbf
        if nonce and claims.get("nonce") != nonce:
            raise HTTPException(400, t("api.oidc_nonce"))
        return claims, tok

    def end_session_url(self, post_logout_redirect_uri=None):
        """RP-initiated-Logout-URL beim Provider (oder None, wenn nicht unterstützt).
        Ohne id_token_hint (wird nicht gespeichert) — best effort; manche Provider verlangen es."""
        try:
            ep = self.meta().get("end_session_endpoint")
        except Exception:
            ep = None
        if not ep:
            return None
        params = {"client_id": self.client_id}
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return ep + ("&" if "?" in ep else "?") + urlencode(params)

    def userinfo(self, access_token):
        try:
            import httpx
            ep = self.meta().get("userinfo_endpoint")
            if not ep or not access_token:
                return {}
            return httpx.get(ep, headers={"Authorization": f"Bearer {access_token}"}, timeout=10).json()
        except Exception:
            return {}


def register_oidc_routes(router, auth):
    cfg = auth.cfg
    oidc: OIDCClient = auth.oidc
    if cfg.base_url:
        # Sichtbar machen, was der IdP als Redirect-URI kennen muss. Stimmt es nicht überein,
        # meldet den Fehler sonst erst der Provider — nach dem Login, ohne Hinweis auf die Ursache.
        security.seclog.info("OIDC-Redirect-URI: %s", cfg.base_url.rstrip("/") + cfg.oidc_callback_path)

    def _redirect_uri(request: Request):
        # Die Redirect-URI entscheidet, wohin der IdP den Autorisierungs-Code schickt. Aus dem
        # Host-Header abgeleitet wäre sie durch den Anfragenden bestimmbar; ein IdP mit locker
        # gepflegten Redirect-URIs würde den Code dann an einen fremden Host ausliefern
        # (R4-01). Ohne geprüfte Basis bricht der Flow ab, statt sie zu raten.
        base = auth.public_base(request)
        if not base:
            raise HTTPException(500, auth.t("api.no_public_base"))
        return base + cfg.oidc_callback_path

    # Der Flow wird an den BROWSER gebunden, nicht nur an den `state`. Ohne das kann ein
    # Angreifer den Flow bei sich starten, sich beim IdP als er selbst anmelden und das Opfer
    # dann auf die Callback-URL locken — das Opfer landet still im Konto des Angreifers und
    # arbeitet dort weiter. Ein gewöhnlicher Top-Level-GET genügt dafür; SameSite hilft nicht,
    # weil gar kein Cookie gebraucht wird. Dasselbe Muster nutzt webauthn_.py schon
    # (`_set_flow_cookie`) — hier fehlte es.
    _OIDCFLOW = "tinysesam_oidc_flow"

    def _flow_cookie_setzen(resp, wert):
        resp.set_cookie(_OIDCFLOW, wert, max_age=600, httponly=True, secure=cfg.cookie_secure,
                        samesite=cfg.cookie_samesite, path=cfg.cookie_path)

    @router.get("/auth/oidc/start")
    def oidc_start(request: Request, next: str = "/"):
        # Jeder Aufruf hinterlässt eine `flow`-Zeile (600 s), gelöscht wird sie nur beim
        # erfolgreichen Rückweg oder von `gc`. Im Gateway-Betrieb ist das genau der Einstieg,
        # auf den der Proxy jeden nicht angemeldeten Besucher schickt — jeder Abbruch, jeder
        # Scanner, jeder Bot liess die Datenbank wachsen, und als einzige flow-erzeugende Route
        # war sie nicht ratenbegrenzt.
        if not auth.rate_ok(auth.client_ip(request)):
            raise HTTPException(429, auth.t("err.rate"))
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        # Das Geheimnis geht als httponly-Cookie an den Browser, nur sein Hash in den Flow-Satz.
        # Wer den `state` aus der Redirect-URL abliest, hat damit noch nichts.
        flow_key = secrets.token_urlsafe(24)
        auth.store.put_flow("oidc:" + state,
                            {"nonce": nonce, "next": next, "fk": _hash(flow_key)}, ttl=600)
        resp = RedirectResponse(oidc.auth_url(_redirect_uri(request), state, nonce), 303)
        _flow_cookie_setzen(resp, flow_key)
        return resp

    @router.get(cfg.oidc_callback_path)
    def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if error:
            raise HTTPException(400, auth.t("api.oidc_error", grund=error))
        flow = auth.store.pop_flow("oidc:" + state)
        if not flow:
            raise HTTPException(400, auth.t("api.oidc_state"))
        # Der Rückweg muss aus DEMSELBEN Browser kommen, der den Flow begonnen hat.
        erwartet = flow.get("fk")
        mitgebracht = request.cookies.get(_OIDCFLOW) or ""
        if not erwartet or not secrets.compare_digest(_hash(mitgebracht), erwartet):
            security.seclog.warning("OIDC-Callback ohne passendes Flow-Cookie — abgewiesen")
            raise HTTPException(400, auth.t("api.oidc_browser"))
        claims, tok = oidc.exchange(code, _redirect_uri(request), flow["nonce"], t=auth.t)
        nutzerinfo = oidc.userinfo(tok.get("access_token")) or {}
        info = {**nutzerinfo, **dict(claims)}

        if cfg.oidc_allowed_groups:
            groups = info.get(cfg.oidc_group_claim) or []
            if not (set(cfg.oidc_allowed_groups) & set(groups if isinstance(groups, list) else [groups])):
                # Ins Protokoll, nicht nur an den Browser: „ich komme nicht rein" ist im
                # Gateway-Betrieb der häufigste Supportfall, und ohne diese Zeile hinterliess
                # er serverseitig gar nichts. Das Muster gibt es im Projekt schon
                # (`forward_role_denied` in router.py).
                auth.audit("oidc_group_denied", str(info.get("email") or info.get("sub") or "?"),
                           auth.client_ip(request),
                           f"verlangt={sorted(cfg.oidc_allowed_groups)}")
                raise HTTPException(403, auth.t("api.oidc_group"))

        issuer, sub = oidc.meta()["issuer"], claims["sub"]

        # Die E-Mail aus dem ID-Token trägt in TinySesam Entscheidungen: `admin_identifiers`
        # macht ihren Träger beim ersten Login zum Admin, und `Remote-Email` reicht sie an die
        # geschützte App weiter, die daran ihrerseits Rechte hängt. Beides setzt voraus, dass
        # die Adresse dem Anmeldenden wirklich gehört — belegt ist das allein durch
        # `email_verified`. Wer sich bei einem IdP mit Selbstregistrierung eine beliebige
        # Adresse einträgt, wurde sonst mit ihr zum Erst-Admin.
        mail, mail_bestaetigt = _email_mit_beleg(claims, nutzerinfo)
        if mail and not mail_bestaetigt:
            security.seclog.warning(
                "OIDC: Der Provider meldet %s ohne email_verified — die Adresse gilt als "
                "unbestätigt%s. Das Admin-Recht aus admin_identifiers hängt in keinem Fall "
                "daran; der belegte Bootstrap-Weg ist /auth/claim-admin.",
                mail, " und wird nicht ins Konto übernommen"
                if cfg.oidc_require_verified_email else "")
            auth.audit("oidc_email_unverified", str(mail), auth.client_ip(request),
                       "übernommen=%s" % (not cfg.oidc_require_verified_email))
            if cfg.oidc_require_verified_email:
                mail = None

        uid = auth.store.get_oidc_user(issuer, sub)
        if not uid:
            if not cfg.oidc_auto_create:
                auth.audit("oidc_no_account", str(info.get("email") or sub or "?"),
                           auth.client_ip(request), "oidc_auto_create=False")
                raise HTTPException(403, auth.t("api.oidc_nolink"))
            # Ersatzname aus der geprüften Adresse, nicht aus der rohen: Sonst hiesse das
            # Konto wie eine Adresse, die niemand bestätigt hat.
            username = info.get("preferred_username") or mail or ("oidc-" + sub[:8])
            base_un, i = username, 1
            while auth.store.get_user_by_name(username):
                i += 1
                username = f"{base_un}{i}"
            uid = auth.create_user(username, display_name=info.get("name") or username, email=mail)
            auth.store.link_oidc(issuer, sub, uid)

        # OIDC-Gruppen → lokale Rollen (falls gemappt)
        _grp = info.get(cfg.oidc_group_claim) or []
        auth.apply_idp_groups(uid, _grp if isinstance(_grp, list) else [_grp], cfg.oidc_group_role_map)

        # client_ip statt der rohen Peer-IP — hinter einem Proxy ist der Peer der Proxy.
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, uid, "oidc", ip, ua,
                                              email_bestaetigt=mail_bestaetigt)
        target = auth.login_redirect_after(request, token, uid,
                                           auth.safe_next(flow.get("next") or cfg.login_redirect))
        resp = RedirectResponse(target, 303)
        if is_new:
            auth.set_cookie(resp, token)
        # Das Flow-Cookie hat seinen Zweck erfüllt — es liegen zu lassen wäre ein Rest,
        # der nichts mehr schützt und nur noch verrät, dass hier ein Flow lief.
        resp.delete_cookie(_OIDCFLOW, path=cfg.cookie_path)
        return resp
