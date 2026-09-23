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
    """`email_verified` als Ja/Nein — für einen Wert, der **da ist**. Ob er fehlt, entscheidet
    der Aufrufer (`_email_mit_beleg`): Ein fehlender Claim heisst etwas anderes als ein Claim,
    der `false` sagt.

    Gemessen an dem, was echte Provider senden: `True` (JSON-Boolean, der Standard),
    `"true"`/`"True"` (als Zeichenkette — verbreitete Abweichung) und `1`/`"1"`. Alles andere
    ist **Nein**, ausdrücklich auch `"false"` als Zeichenkette: Sie ist nicht leer und wäre für
    jede Wahrheitsprüfung auf dem rohen Wert (`bool("false")`) ein Ja — genau die Verwechslung,
    mit der eine unbestätigte Adresse wieder Erst-Admin-fähig würde."""
    if isinstance(wert, bool):
        return wert
    if wert is None:
        return False
    return str(wert).strip().lower() in ("true", "1")


def _email_mit_beleg(claims, nutzerinfo, vorgabe_wenn_claim_fehlt: bool = False) -> tuple:
    """Adresse UND Beleg immer aus demselben Dokument. Gibt
    `(adresse, bestaetigt, ausdruecklich)` — `ausdruecklich` sagt, ob der Provider sich zur
    Adresse **geäussert** hat oder ob nur die Vorgabe des Betreibers gilt (Schweigen).

    OpenID Connect Core 5.1 kennt für die Adresse den Claim `email_verified` („True if the
    End-User's e-mail address has been verified"). **Fehlt er, lautet die Antwort Nein** —
    nicht „vielleicht": Ohne Beleg ist `email` ein Textfeld, das der Anmeldende beim IdP
    selbst gefüllt hat (Selbstregistrierung, zweiter Mandant, öffentlicher Provider).

    Weil der Claim optional ist, darf der Betreiber dieses Nein für seinen IdP umdrehen
    (`oidc_email_verified_default`, hier `vorgabe_wenn_claim_fehlt`) — er verantwortet die
    Adressen dann selbst. Das gilt nur für den **fehlenden** Claim: Steht er da und sagt
    `false`, bleibt die Antwort Nein, sonst wäre der Schalter eine Umgehung der Aussage des
    Providers.

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
            # `in` statt `.get()`: Der fehlende Claim ist ein eigener Fall (dann gilt die
            # Vorgabe des Betreibers), ein vorhandener wird immer gemessen — auch `"false"`.
            if "email_verified" in (quelle or {}):
                return mail, _flag_wahr((quelle or {}).get("email_verified")), True
            return mail, bool(vorgabe_wenn_claim_fehlt), False
    return None, False, False


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
        self._pruefe_publikum(claims, t)
        if nonce and claims.get("nonce") != nonce:
            raise HTTPException(400, t("api.oidc_nonce"))
        return claims, tok

    def _pruefe_publikum(self, claims, t) -> None:
        """`aud` und `azp` nach OIDC Core 3.1.3.7, Punkt 3 bis 5 (F-15).

        Der Dekoder prüft nur, dass die eigene `client_id` in `aud` **vorkommt**. Ein Token darf
        aber mehrere Empfänger nennen, und dann sagt erst `azp` (authorized party), für wen es
        ausgestellt wurde. Ohne diese Prüfung nimmt TinySesam ein Token an, das für eine **andere**
        Anwendung desselben Providers gemacht wurde und uns nur mitnennt — Token-Substitution.
        Wer bei irgendeinem Client dieses Providers ein Token bekommt, käme damit auch hier herein.

        Genau drei Regeln, und alle drei fehlten:
        * mehrere `aud` → `azp` ist Pflicht,
        * `azp` vorhanden → es muss die eigene `client_id` sein,
        * die eigene `client_id` muss in `aud` stehen (das deckt der Dekoder ab, hier noch einmal
          als Boden — `claims_options` lässt sich von aussen setzen).

        Seit T-14 wiegt das schwerer: Bei mehreren Clients **derselben** Installation wäre sonst
        das Token von App A auch an App B gut, und die Freigabe je Client wäre umgangen.
        """
        aud = claims.get("aud")
        publikum = [str(a) for a in (aud if isinstance(aud, (list, tuple)) else [aud] if aud else [])]
        azp = claims.get("azp")
        if self.client_id not in publikum:
            security.seclog.warning("OIDC: ID-Token nennt aud=%s, erwartet wurde %s",
                                    security.fuer_log(",".join(publikum)),
                                    security.fuer_log(self.client_id))
            raise HTTPException(400, t("api.oidc_audience"))
        if len(publikum) > 1 and not azp:
            security.seclog.warning(
                "OIDC: ID-Token nennt %d Empfänger, aber kein azp — nicht entscheidbar, für wen "
                "es ausgestellt wurde (OIDC Core 3.1.3.7).", len(publikum))
            raise HTTPException(400, t("api.oidc_audience"))
        if azp and str(azp) != self.client_id:
            security.seclog.warning(
                "OIDC: ID-Token ist für azp=%s ausgestellt, nicht für %s — abgewiesen.",
                security.fuer_log(str(azp)), security.fuer_log(self.client_id))
            raise HTTPException(400, t("api.oidc_audience"))

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

    def userinfo(self, access_token, erwartetes_sub: str = ""):
        """Die UserInfo-Antwort des Providers — **nur**, wenn ihr `sub` zum ID-Token passt (F-18).

        OIDC Core 5.3.2 verlangt den Abgleich ausdrücklich: „The sub Claim in the UserInfo
        Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not
        match, the UserInfo Response values MUST NOT be used."

        Warum das zählt: Die Antwort wird im Callback **über** die Claims des ID-Tokens gelegt und
        liefert Gruppen, E-Mail und damit mittelbar Rollen und das Admin-Flag. Das ID-Token ist
        signiert, die UserInfo-Antwort ist es nicht — sie ist eine gewöhnliche HTTPS-Antwort auf
        einen Bearer-Token. Wer einen Access-Token eines **anderen** Kontos vorlegt (oder der
        Provider bei mehreren Mandanten verwechselt), schob so die Merkmale einer fremden Person
        in die eigene Sitzung.

        `erwartetes_sub` leer zu lassen ist der Bestandsaufruf und **verwirft dann jede Antwort**
        mit `sub`, die nicht leer ist — der Aufrufer, der den Abgleich nicht machen kann, soll
        die Daten nicht bekommen. Fail-closed statt „besser als nichts".
        """
        try:
            import httpx
            ep = self.meta().get("userinfo_endpoint")
            if not ep or not access_token:
                return {}
            antwort = httpx.get(ep, headers={"Authorization": f"Bearer {access_token}"},
                                timeout=10).json()
        except Exception:
            return {}
        return self.userinfo_pruefen(antwort, erwartetes_sub)

    @staticmethod
    def userinfo_pruefen(antwort, erwartetes_sub: str = "") -> dict:
        """Der `sub`-Abgleich aus OIDC Core 5.3.2 — als eigene Funktion, damit ihn auch messen
        kann, wer den HTTP-Teil durch eine Attrappe ersetzt. Eine Attrappe, die den Abgleich
        nachbaut, prüft sonst nur den Nachbau."""
        if not isinstance(antwort, dict):
            return {}
        gemeldet = str(antwort.get("sub") or "")
        if gemeldet != str(erwartetes_sub or ""):
            security.seclog.warning(
                "OIDC: UserInfo meldet sub=%s, das ID-Token nennt sub=%s — Antwort verworfen "
                "(OIDC Core 5.3.2). Gruppen, E-Mail und Admin-Flag stammen damit allein aus dem "
                "signierten Token.",
                security.fuer_log(gemeldet or "<leer>"), security.fuer_log(str(erwartetes_sub or "<leer>")))
            return {}
        return antwort


#: Schlüssel des Einzel-Clients in `oidc_grant` und im Flow. Ein Stern, weil er für **jeden**
#: Host gilt, für den `oidc_clients` nichts Eigenes sagt — und weil kein Hostname so heissen kann.
VORGABE_CLIENT = "*"


class OIDCClients:
    """Alle OIDC-Clients einer Installation: Host → Client beim selben Provider (T-14).

    Warum eine Registry und nicht einfach ein zweites Feld: Wer in welche Anwendung darf,
    entscheidet der Provider je **Client** (bei PocketID über die Gruppenfreigabe). Mit einem
    einzigen Client gibt es deshalb nur eine Antwort für alle Anwendungen. Die Registry hält
    die Zuordnung an genau einer Stelle, damit Flow, Callback und Forward-Auth dieselbe Frage
    gleich beantworten.

    **Ein Issuer für alle.** Discovery-Dokument und JWKS hängen am Provider, nicht am Client;
    sie werden deshalb geteilt statt je Client neu geholt. Mehrere Provider in einer Instanz
    sind nicht vorgesehen — `konfigpruefung` weist einen `issuer` im Client-Eintrag ab.
    """

    def __init__(self, cfg):
        self.cfg = cfg
        self._clients: dict = {}
        vorgabe = OIDCClient(cfg.oidc_issuer, cfg.oidc_client_id, cfg.oidc_client_secret,
                             cfg.oidc_scopes)
        self._clients[VORGABE_CLIENT] = vorgabe
        for host, eintrag in (cfg.oidc_clients or {}).items():
            e = dict(eintrag or {})
            c = OIDCClient(cfg.oidc_issuer, e.get("client_id", ""), e.get("client_secret", ""),
                           e.get("scopes") or cfg.oidc_scopes)
            # Metadaten und JWKS kommen vom selben Provider — einmal holen reicht. Ohne das
            # fragte jeder Client einzeln nach demselben Dokument, bei drei Anwendungen also
            # dreifach, und eine Schlüsselrotation wäre dreimal zu bemerken statt einmal.
            c._meta, c._meta_zeit = vorgabe._meta, vorgabe._meta_zeit
            self._clients[str(host).strip().lower()] = c
        self._teile_meta()

    def _teile_meta(self):
        """Den Metadaten-Cache des Vorgabe-Clients an alle anderen weiterreichen.

        Aufgerufen nach jedem Abruf: `meta()` setzt `_meta` auf dem Client, der gerade fragt.
        Ohne dieses Nachziehen hätte jeder Client seinen eigenen Stand, und ein Test, der die
        Metadaten von aussen setzt (die OIDC-Attrappe tut das), erreichte nur einen davon.
        """
        vorgabe = self._clients[VORGABE_CLIENT]
        for schluessel, c in self._clients.items():
            if schluessel == VORGABE_CLIENT:
                continue
            c._meta, c._meta_zeit = vorgabe._meta, vorgabe._meta_zeit
            c._jwks, c._jwks_zeit = vorgabe._jwks, vorgabe._jwks_zeit

    @property
    def mehrere(self) -> bool:
        return len(self._clients) > 1

    def schluessel_fuer_host(self, host: str) -> str:
        """Welcher Client-Schlüssel gilt für diesen Host? Unbekannt → der Vorgabe-Client.

        Ein unbekannter Host bekommt bewusst den Vorgabe-Client und keine Absage: Genau so
        verhält sich eine Installation ohne `oidc_clients`, und der Übergang soll keiner sein.
        Welche Hosts überhaupt geschützt sind, entscheidet der Proxy — nicht diese Zuordnung.
        """
        h = str(host or "").strip().lower()
        if h and ":" in h and not h.startswith("["):
            h = h.split(":", 1)[0]          # Port gehört nicht zum Namen der Anwendung
        return h if h in self._clients else VORGABE_CLIENT

    def __getitem__(self, schluessel: str) -> OIDCClient:
        return self._clients.get(schluessel) or self._clients[VORGABE_CLIENT]

    def fuer_host(self, host: str) -> OIDCClient:
        return self[self.schluessel_fuer_host(host)]

    def eintrag(self, schluessel: str) -> dict:
        """Die Zusatzangaben eines Clients (`allowed_groups`, `group_role_map`) — mit den
        Werten des Einzel-Clients als Rückfall. So gilt eine global gesetzte Gruppenregel auch
        für eine Anwendung, die selbst keine nennt."""
        e = dict((self.cfg.oidc_clients or {}).get(schluessel) or {})
        return {
            "allowed_groups": list(e.get("allowed_groups") or self.cfg.oidc_allowed_groups or []),
            "group_role_map": dict(e.get("group_role_map") or self.cfg.oidc_group_role_map or {}),
        }

    def namen(self) -> list:
        return [k for k in self._clients if k != VORGABE_CLIENT]


def register_oidc_routes(router, auth):
    cfg = auth.cfg
    oidc: OIDCClient = auth.oidc
    clients: OIDCClients = auth.oidc_clients
    if cfg.base_url:
        # Sichtbar machen, was der IdP als Redirect-URI kennen muss. Stimmt es nicht überein,
        # meldet den Fehler sonst erst der Provider — nach dem Login, ohne Hinweis auf die Ursache.
        security.seclog.info("OIDC-Redirect-URI: %s", cfg.base_url.rstrip("/") + cfg.oidc_callback_path)

    def _redirect_uri(request: Request):
        # Die Redirect-URI entscheidet, wohin der IdP den Autorisierungs-Code schickt. Aus dem
        # Host-Header abgeleitet wäre sie durch den Anfragenden bestimmbar; ein IdP mit locker
        # gepflegten Redirect-URIs würde den Code dann an einen fremden Host ausliefern
        # (R4-01). Ohne geprüfte Basis bricht der Flow ab, statt sie zu raten.
        # `require_public_base`: Ein 500 mitten im Anmeldeversuch war der falsche Ort für
        # eine Konfigurationslücke — `/auth/oidc/start` ist der Einstieg, auf den ein Gateway
        # jeden Besucher schickt. Seit dieser Fassung verlangt `konfigpruefung` bei
        # `oidc_enabled` ein `base_url` und der Aufbau scheitert vorher.
        return auth.require_public_base(request) + cfg.oidc_callback_path

    # Der Flow wird an den BROWSER gebunden, nicht nur an den `state`. Ohne das kann ein
    # Angreifer den Flow bei sich starten, sich beim IdP als er selbst anmelden und das Opfer
    # dann auf die Callback-URL locken — das Opfer landet still im Konto des Angreifers und
    # arbeitet dort weiter. Ein gewöhnlicher Top-Level-GET genügt dafür; SameSite hilft nicht,
    # weil gar kein Cookie gebraucht wird. Dasselbe Muster nutzt webauthn_.py schon
    # (`_set_flow_cookie`) — hier fehlte es.
    # Der tatsächliche Name trägt `__Host-`, wo möglich (A-1): Sonst setzt eine
    # Nachbar-Subdomain per `Domain=.example.com` ihr eigenes Flow-Cookie, und die Bindung
    # an den Browser hält nichts mehr.
    _OIDCFLOW = "tinysesam_oidc_flow"

    def _flow_cookie_setzen(resp, wert):
        auth._flow_cookie_setzen(resp, _OIDCFLOW, wert, max_age=600)

    @router.get("/auth/oidc/start")
    def oidc_start(request: Request, next: str = "/", app: str = ""):
        # Jeder Aufruf hinterlässt eine `flow`-Zeile (600 s), gelöscht wird sie nur beim
        # erfolgreichen Rückweg oder von `gc`. Im Gateway-Betrieb ist das genau der Einstieg,
        # auf den der Proxy jeden nicht angemeldeten Besucher schickt — jeder Abbruch, jeder
        # Scanner, jeder Bot liess die Datenbank wachsen, und als einzige flow-erzeugende Route
        # war sie nicht ratenbegrenzt.
        if not auth.rate_ok(auth.client_ip(request)):
            raise HTTPException(429, auth.t("err.rate"))
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        # Welche Anwendung gemeint ist, entscheidet sich HIER und wandert in den Flow-Satz —
        # nicht in die Redirect-URI (die ist für alle Clients dieselbe, damit beim Provider
        # eine einzige Adresse eingetragen werden muss) und nicht in den `state` (den liest
        # jeder aus der Adresszeile). `?app=` kommt vom Forward-Auth oder von der Anwendung
        # selbst; ein unbekannter Name landet beim Vorgabe-Client, genau wie bisher (T-14).
        ziel = clients.schluessel_fuer_host(app)
        client = clients[ziel]
        # Das Geheimnis geht als httponly-Cookie an den Browser, nur sein Hash in den Flow-Satz.
        # Wer den `state` aus der Redirect-URL abliest, hat damit noch nichts.
        flow_key = secrets.token_urlsafe(24)
        auth.store.put_flow("oidc:" + state,
                            {"nonce": nonce, "next": next, "fk": _hash(flow_key), "app": ziel},
                            ttl=600)
        resp = RedirectResponse(client.auth_url(_redirect_uri(request), state, nonce), 303)
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
        mitgebracht = request.cookies.get(auth.flow_cookie_name(_OIDCFLOW)) or ""
        if not erwartet or not secrets.compare_digest(_hash(mitgebracht), erwartet):
            security.seclog.warning("OIDC-Callback ohne passendes Flow-Cookie — abgewiesen")
            raise HTTPException(400, auth.t("api.oidc_browser"))
        # Getauscht wird mit dem Client, mit dem der Flow begonnen hat. Ein anderer Client hätte
        # ein anderes Geheimnis — der Tausch scheitert dann beim Provider, und zwar zu Recht.
        ziel = str(flow.get("app") or VORGABE_CLIENT)
        client = clients[ziel]
        claims, tok = client.exchange(code, _redirect_uri(request), flow["nonce"], t=auth.t)
        # Das `sub` aus dem **signierten** Token ist der Massstab für die UserInfo-Antwort, die
        # selbst nicht signiert ist (F-18). Deshalb steht es vor dem Abruf, nicht danach.
        sub_im_token = str(claims.get("sub") or "")
        nutzerinfo = client.userinfo(tok.get("access_token"), erwartetes_sub=sub_im_token) or {}
        info = {**nutzerinfo, **dict(claims)}

        # Gruppenregel je Anwendung: `oidc_clients[host]["allowed_groups"]`, sonst die globale.
        # Die eigentliche Freigabe trifft ohnehin der Provider (er gibt einem nicht freigegebenen
        # Benutzer gar keinen Code) — das hier ist die zweite Schranke für den Fall, dass beim
        # Provider grosszügiger freigegeben ist als gewollt.
        eintrag = clients.eintrag(ziel)
        erlaubte = eintrag["allowed_groups"]
        if erlaubte:
            groups = info.get(cfg.oidc_group_claim) or []
            if not (set(erlaubte) & set(groups if isinstance(groups, list) else [groups])):
                # Ins Protokoll, nicht nur an den Browser: „ich komme nicht rein" ist im
                # Gateway-Betrieb der häufigste Supportfall, und ohne diese Zeile hinterliess
                # er serverseitig gar nichts. Das Muster gibt es im Projekt schon
                # (`forward_role_denied` in router.py).
                auth.audit("oidc_group_denied", str(info.get("email") or info.get("sub") or "?"),
                           auth.client_ip(request),
                           f"app={ziel} verlangt={sorted(erlaubte)}")
                raise HTTPException(403, auth.t("api.oidc_group"))

        issuer, sub = client.meta()["issuer"], claims["sub"]

        # Die E-Mail aus dem ID-Token trägt in TinySesam Entscheidungen: `admin_identifiers`
        # macht ihren Träger beim ersten Login zum Admin. Das setzt voraus, dass die Adresse dem
        # Anmeldenden wirklich gehört — belegt ist das allein durch `email_verified`. Wer sich
        # bei einem IdP mit Selbstregistrierung eine beliebige Adresse einträgt, wurde sonst mit
        # ihr zum Erst-Admin. Adresse und Beleg werden deshalb als Paar geführt: die Adresse wie
        # bisher ins Konto und in `Remote-Email`, der Beleg als Vermerk daneben.
        mail, mail_bestaetigt, beleg_ausdruecklich = _email_mit_beleg(
            claims, nutzerinfo, cfg.oidc_email_verified_default)
        if mail and not mail_bestaetigt:
            # Die Adresse wird trotzdem geführt. Sie zu verwerfen war die erste Fassung dieses
            # Fixes, und sie kostete mehr, als sie schützte: Ein IdP ohne den optionalen Claim
            # (Entra ID) liess damit jedes neu angelegte Konto `oidc-<sub>` heissen statt wie die
            # Adresse, und `Remote-Email` ging leer an die geschützte App — dieselbe Person
            # landete nach dem Update in einem anderen Konto der App. Was die Adresse nicht mehr
            # darf, ist Rechte tragen: Der fehlende Beleg wird am Konto vermerkt
            # (`email_verified=0`) und gilt von dort für jeden Anmeldeweg dieses Kontos.
            security.seclog.warning(
                "OIDC: Der Provider meldet %s ohne Beleg (email_verified fehlt oder ist nicht "
                "wahr) — die Adresse wird als unbestätigt übernommen und trägt keine Rechte. "
                "Das Admin-Recht aus admin_identifiers hängt in keinem Fall daran; der belegte "
                "Bootstrap-Weg ist /auth/claim-admin. Schickt dieser IdP den Claim nie und "
                "verantwortet der Betreiber die Adressen selbst: "
                "oidc_email_verified_default=True.", mail)
            auth.audit("oidc_email_unverified", str(mail), auth.client_ip(request),
                       "übernommen=1 rechte=0")

        uid = auth.store.get_oidc_user(issuer, sub)
        if not uid:
            if not cfg.oidc_auto_create:
                auth.audit("oidc_no_account", str(info.get("email") or sub or "?"),
                           auth.client_ip(request), "oidc_auto_create=False")
                raise HTTPException(403, auth.t("api.oidc_nolink"))
            # Ersatzname notfalls aus der Adresse — auch aus einer unbestätigten: **ein Name ist
            # keine Berechtigung.** Ein Allowlist-Name aus fremder Hand ist hier ohnehin
            # unmöglich, den verbietet der Konstruktor-Wächter, sobald ein IdP Konten anlegt.
            username = info.get("preferred_username") or mail or ("oidc-" + sub[:8])
            base_un, i = username, 1
            # Der Ausweichname muss in BEIDEN Namensräumen frei sein (Fund R4-12) — ein Name,
            # der die E-Mail eines bestehenden Kontos ist, besetzt dessen Login-Kennung.
            while auth.kennung_vergeben(username):
                i += 1
                username = f"{base_un}{i}"
            try:
                # Adresse UND Beleg gehen zusammen ins Konto (F-14): Der Vermerk entscheidet
                # später über Erst-Admin/Allowlist — unabhängig davon, über welchen Weg dieses
                # Konto sich das nächste Mal anmeldet.
                uid = auth.create_user(username, display_name=info.get("name") or username,
                                       email=mail, email_verified=mail_bestaetigt)
            except errors.ConfigError:
                # Die Kennung der Identität gehört lokal schon jemandem. Fail-closed: kein Konto,
                # das eine fremde Kennung überschreibt — der Betreiber verknüpft von Hand.
                auth.audit("oidc_ident_taken", str(mail or username or sub or "?"),
                           auth.client_ip(request))
                raise HTTPException(409, auth.t("api.idp_ident_taken"))
            auth.store.link_oidc(issuer, sub, uid)
        elif mail and beleg_ausdruecklich:
            # Bestandskonto: Was der Provider HEUTE über SEINE Adresse SAGT, ersetzt den Vermerk.
            # Sonst bliebe ein „unbestätigt" von früher stehen, nachdem der IdP die Adresse
            # geprüft hat — und umgekehrt bliebe ein alter Beleg gültig, obwohl der Provider ihn
            # zurückgenommen hat.
            #
            # Zwei Grenzen: nur bei DERSELBEN Adresse (über eine andere sagt der Claim nichts —
            # dieselbe Regel wie in `_email_mit_beleg`), und nur bei einer ausdrücklichen
            # Aussage. **Schweigen überschreibt nichts:** Ein Konto, dessen Adresse der Betreiber
            # selbst gesetzt hat (Admin, CLI, Registrierung mit Bestätigungsmail), verlöre sonst
            # seinen Beleg, nur weil ein IdP den optionalen Claim nicht mitschickt.
            konto = auth.store.get_user(uid)
            if konto and str(konto["email"] or "").lower() == str(mail).strip().lower() \
                    and bool(konto["email_verified"]) is not bool(mail_bestaetigt):
                auth.store.set_email_verified(uid, mail_bestaetigt)

        # Ein gesperrtes Konto bekommt hier gar nichts mehr (F-17). Bis 0.18.x lief der
        # Callback für ein `disabled=1`-Konto vollständig durch: Gruppen wurden übernommen, das
        # Admin-Flag konnte gesetzt werden, ein Login-Eintrag entstand — nur die Sitzung blieb am
        # Ende aus. Das Sperren eines Kontos ist aber die Antwort auf „diese Person soll nichts
        # mehr können"; dass ihre Rollen sich dabei noch ändern, ist das Gegenteil davon. Und im
        # Protokoll sah es aus wie eine erfolgreiche Anmeldung.
        #
        # Die Prüfung steht VOR `apply_idp_groups`, `apply_factor` und jedem Schreibzugriff —
        # jede Zeile danach wäre eine Änderung an einem Konto, das nicht mehr anmelden darf.
        # Lokaler Passwort-Login und Panel prüfen dasselbe seit jeher; die föderierte Seite war
        # die Lücke.
        _konto = auth.store.get_user(uid)
        if _konto and _konto["disabled"]:
            auth.audit("oidc_disabled", str(_konto["username"]), auth.client_ip(request),
                       f"app={ziel} sub={security.fuer_log(sub)}")
            security.seclog.warning("%s user=%s ip=%s method=oidc grund=konto_gesperrt",
                                    security.log_ereignis("oidc"),
                                    security.fuer_log(str(_konto["username"])),
                                    security.fuer_log(auth.client_ip(request)))
            raise HTTPException(403, auth.t("api.oidc_disabled"))

        # OIDC-Gruppen → lokale Rollen (falls gemappt). Die Zuordnung darf je Anwendung eine
        # andere sein: Dieselbe Verzeichnisgruppe kann in App A „Redakteur" heissen und in App B
        # gar nichts. Ohne Eintrag gilt die globale Zuordnung, also das Verhalten von 0.18.0.
        _grp = info.get(cfg.oidc_group_claim) or []
        _gruppen = _grp if isinstance(_grp, list) else [_grp]
        auth.apply_idp_groups(uid, _gruppen, eintrag["group_role_map"])

        # client_ip statt der rohen Peer-IP — hinter einem Proxy ist der Peer der Proxy.
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, uid, "oidc", ip, ua,
                                              email_bestaetigt=mail_bestaetigt)
        # Der Provider hat für DIESE Anwendung zugestimmt — das wird an der Sitzung vermerkt.
        # Für jede andere Anwendung sagt dieser Vermerk nichts; dort fragt `/auth/forward`
        # erneut. Genau das ist der Unterschied zu „angemeldet ja/nein" (T-14).
        auth.vermerke_oidc_freigabe(token, ziel, rollen=_gruppen)
        target = auth.login_redirect_after(request, token, uid,
                                           auth.safe_next(flow.get("next") or cfg.login_redirect))
        resp = RedirectResponse(target, 303)
        if is_new:
            auth.set_cookie(resp, token)
        # Das Flow-Cookie hat seinen Zweck erfüllt — es liegen zu lassen wäre ein Rest,
        # der nichts mehr schützt und nur noch verrät, dass hier ein Flow lief.
        auth._flow_cookie_loeschen(resp, _OIDCFLOW)
        return resp
