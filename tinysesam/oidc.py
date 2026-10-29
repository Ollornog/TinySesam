"""OIDC (authorization code flow) for a generic provider (PocketID, Keycloak, …).

httpx for discovery/token, authlib.jose for ID-token verification (signature against JWKS +
iss/aud/exp). state, nonce and the PKCE verifier (S256) are kept short-lived in the store (flow),
not in the client → CSRF/replay-proof, an intercepted code cannot be redeemed without the verifier.
Both libs are the optional extra `[oidc]`.
"""
from __future__ import annotations

import hashlib
import sqlite3
import time
import secrets
from urllib.parse import urlencode

from fastapi import Request, HTTPException
from fastapi.responses import RedirectResponse

from . import security
from .messages import translate


from . import errors
from .store import jetzt, name_ungueltig, norm_email, norm_kennung


def _fehlt_extra(e: ModuleNotFoundError) -> "errors.MissingExtra":
    """Turn a bare import error into a message that says what to do.

    The extras are deliberately imported LAZILY here (only on use). The price for that was,
    until 0.18.0, a `ModuleNotFoundError: authlib` in the middle of the sign-in process — for the
    operator a defect, although only one line was missing in the install command."""
    return errors.MissingExtra(
        "The extra [oidc] is not installed (pip install 'tinysesam[oidc]') — "
        f"missing: {e.name or 'authlib'}.", extra="oidc")


def _hash(wert: str) -> str:
    """Flow secrets are kept in memory only as a hash — like session tokens."""
    import hashlib
    return hashlib.sha256((wert or "").encode()).hexdigest()


def pkce_paar() -> tuple[str, str]:
    """(code_verifier, code_challenge) per RFC 7636 with S256.

    PKCE binds the authorization code to THE flow that requested it (F-20/H-12): whoever
    intercepts a code (referer, proxy log, browser history, an eavesdropper on the redirect URI)
    cannot exchange it without the verifier — that one lives only in the flow record on the server.
    RFC 9700 (OAuth 2.0 Security BCP, 2.1.1) expressly recommends it also for confidential
    clients with a client secret, because it additionally catches code injection into a
    foreign flow. 48 random bytes yield 64 characters, RFC 7636 requires 43 to 128."""
    import base64
    import hashlib
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


def _flag_wahr(wert) -> bool:
    """`email_verified` as yes/no — for a value that **is there**. Whether it is missing is decided
    by the caller (`_email_mit_beleg`): a missing claim means something different from a claim
    that says `false`.

    Measured against what real providers send: `True` (JSON boolean, the standard),
    `"true"`/`"True"` (as a string — a common deviation) and `1`/`"1"`. Everything else
    is **no**, explicitly also `"false"` as a string: it is not empty and would be a yes for
    any truthiness check on the raw value (`bool("false")`) — exactly the mix-up
    with which an unconfirmed address would become first-admin-capable again."""
    if isinstance(wert, bool):
        return wert
    if wert is None:
        return False
    return str(wert).strip().lower() in ("true", "1")


def _email_mit_beleg(claims, nutzerinfo, vorgabe_wenn_claim_fehlt: bool = False) -> tuple:
    """Address AND evidence always from the same document. Returns
    `(address, confirmed, explicit)` — `explicit` says whether the provider **spoke** about
    the address or whether only the operator's default applies (silence).

    OpenID Connect Core 5.1 knows the claim `email_verified` for the address ("True if the
    End-User's e-mail address has been verified"). **If it is missing, the answer is no** —
    not "maybe": without evidence, `email` is a text field that the person signing in filled
    at the IdP themselves (self-registration, second tenant, public provider).

    Because the claim is optional, the operator may flip this no for their IdP
    (`oidc_email_verified_default`, here `vorgabe_wenn_claim_fehlt`) — they then answer for the
    addresses themselves. This applies only to the **missing** claim: if it is there and says
    `false`, the answer stays no, otherwise the switch would be a circumvention of the
    provider's statement.

    The decisive word is *same*: the callback merges the userinfo document and the ID token
    into one dictionary, and when mixing, the evidence of one can end up with the address
    of the other — if the ID token supplies only `email` and the userinfo document a
    DIFFERENT address with `email_verified=true`, the unchecked address would carry the foreign evidence.
    That is why the pair is formed here at the source, with priority for the signed ID token
    (which also wins when mixing).
    """
    for quelle in (claims, nutzerinfo):
        mail = (quelle or {}).get("email")
        if mail:
            # `in` instead of `.get()`: the missing claim is a case of its own (then the
            # operator's default applies), an existing one is always measured — also `"false"`.
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

    #: Maximum age of the cached metadata. A provider occasionally moves endpoints;
    #: a day is long enough not to ask on every login, and short enough not to sit out a
    #: change until the next restart.
    META_TTL = 24 * 3600
    #: Maximum age of the JWKS. Providers rotate their signing keys regularly (Keycloak,
    #: Entra, Auth0); until 0.18.0 the set was fetched ONCE and never again — after a
    #: rotation every login failed on the signature until someone restarted the process.
    JWKS_TTL = 3600
    #: Shortest interval between two unscheduled JWKS fetches. Without this brake
    #: every broken id_token triggers a fetch at the provider — a convenient way to put load
    #: on it from here.
    JWKS_MIN_ABSTAND = 60
    #: Signature algorithms valid for an ID token — deliberately ONLY asymmetric ones.
    #: Verification is against the provider's **public** JWKS; an HMAC algorithm would never
    #: make sense here, since the secret would be a public key. This is exactly what the
    #: algorithm confusion aims at: the attacker sets `alg: HS256`, signs with the public
    #: key from the JWKS as the HMAC secret and writes whatever `sub` they want.
    #: Whoever extends the list must stay with asymmetric algorithms — `_dekoder()` rejects
    #: everything else.
    ID_TOKEN_ALGS = ("RS256", "RS384", "RS512", "PS256", "PS384", "PS512",
                     "ES256", "ES384", "ES512", "EdDSA")

    def meta(self, erzwingen: bool = False):
        # `self._meta_zeit and …`: whoever sets the metadata from outside (tests without network, or a
        # setup that takes it from a file) leaves no timestamp. Without this
        # condition such a set would be "older than the lifetime" at once and would be overwritten on first
        # access — including the network access that one wanted to avoid in the first place.
        veraltet = self._meta_zeit and (time.time() - self._meta_zeit) > self.META_TTL
        if self._meta is None or erzwingen or veraltet:
            try:
                import httpx
            except ModuleNotFoundError as e:
                raise _fehlt_extra(e) from e
            # No redirect: a 3xx on the well-known path would fetch the document from elsewhere —
            # and this document supplies token_endpoint, jwks_uri and the issuer against which every
            # ID token is checked. Whoever can redirect the path would thereby own the whole login.
            antwort = httpx.get(self.issuer + "/.well-known/openid-configuration",
                                timeout=10, follow_redirects=False)
            if antwort.status_code != 200:
                raise errors.ConfigError(
                    f"OIDC discovery at {self.issuer}/.well-known/openid-configuration answers with "
                    f"{antwort.status_code} instead of 200 (redirects are not followed — oidc_issuer must be "
                    "the final address, e.g. https instead of http, without a path redirect).")
            meta = antwort.json()
            self._pruefe_issuer(meta)
            self._meta = meta
            self._meta_zeit = time.time()
        return self._meta

    def _pruefe_issuer(self, meta: dict) -> None:
        """The discovery document must name the configured issuer (RFC 8414 §3.3, OIDC
        Discovery §4.3). Everything else — token endpoint, JWKS, the key under which accounts are
        stored in the database — comes from this document; if the issuer does not match, none of it
        is trustworthy. Until 0.18.0 this was never compared."""
        gefunden = str(meta.get("issuer") or "").rstrip("/")
        if gefunden != self.issuer:
            raise errors.ConfigError(
                f"OIDC discovery: the document names issuer={gefunden or '?'}, configured is "
                f"oidc_issuer={self.issuer}. The two must match — otherwise TinySesam checks tokens "
                "against a provider nobody configured.")

    def _jwkset(self, erzwingen: bool = False):
        alt_genug = self._jwks_zeit and (time.time() - self._jwks_zeit) > self.JWKS_TTL
        if self._jwks is None or alt_genug or erzwingen:
            try:
                import httpx
                from authlib.jose import JsonWebKey
            except ModuleNotFoundError as e:
                raise _fehlt_extra(e) from e
            antwort = httpx.get(self.meta()["jwks_uri"], timeout=10)
            # An error response is not a key set. Without this check a
            # `{"keys": []}` behind a 5xx (or a maintenance proxy) landed in the cache for JWKS_TTL,
            # and until then every login failed on the signature (F-24, the same rule as for
            # the discovery above: only a 200 is remembered).
            status = getattr(antwort, "status_code", 200)
            if status != 200:
                raise errors.ConfigError(
                    f"OIDC: JWKS at {self.meta()['jwks_uri']} answers with {status} instead of 200 "
                    "— nothing cached, the next login asks again.")
            self._jwks = JsonWebKey.import_key_set(antwort.json())
            self._jwks_zeit = time.time()
        return self._jwks

    def _dekoder(self):
        """The JWT decoder for the ID token — with a **fixed** algorithm list.

        `authlib.jose.jwt` is a ready-made decoder with a default set, and this set contains
        HS256. If no algorithm is named, the **token's header** picks how verification is done —
        the decision thus lies with the sender. Up to authlib 1.3.0 a valid ID token could be
        forged this way with the public key as HMAC secret
        (GHSA-5357-c2jx-v7qh); the countermeasure there covers only some key formats.
        The installed version must not be the question: here the set is set explicitly.
        """
        try:
            from authlib.jose import JsonWebToken
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        # Fail-closed against a later extension (also from a subclass): anything
        # that is not an RSA, PSS, ECDSA or EdDSA algorithm would manage without a private key.
        fremd = [a for a in self.ID_TOKEN_ALGS if not str(a).startswith(("RS", "PS", "ES", "Ed"))]
        if fremd:
            raise errors.ConfigError(
                f"OIDC: ID_TOKEN_ALGS names {fremd}. The ID token is checked against the provider's "
                "public JWKS — an HMAC algorithm (HS*) or 'none' would thereby turn the "
                "public key into the signing secret. Asymmetric algorithms only.")
        return JsonWebToken(list(self.ID_TOKEN_ALGS))

    def _jwks_auffrischbar(self) -> bool:
        """May an unscheduled re-fetch happen now? (Throttling against foreign load.)"""
        return (time.time() - self._jwks_zeit) > self.JWKS_MIN_ABSTAND

    #: How many seconds the clocks of provider and TinySesam may differ when
    #: `exp`, `iat` and `nbf` are checked (F-26). Without tolerance, EVERY login failed as soon as
    #: the provider's clock ran a few seconds ahead: the fresh token carried an `iat` in the
    #: future. 60 s is the usual value (Keycloak adapter, Spring Security, PyJWT examples) —
    #: well below any sensible token lifetime.
    UHR_TOLERANZ = 60

    def auth_url(self, redirect_uri, state, nonce, code_challenge: str = ""):
        """The address of the authorization request. With `code_challenge` (from `pkce_paar()`)
        it requires PKCE with S256; the caller must then pass the same verifier to
        `exchange()`."""
        felder = {"response_type": "code", "client_id": self.client_id, "redirect_uri": redirect_uri,
                  "scope": self.scopes, "state": state, "nonce": nonce}
        if code_challenge:
            felder.update(code_challenge=code_challenge, code_challenge_method="S256")
        return self.meta()["authorization_endpoint"] + "?" + urlencode(felder)

    def exchange(self, code, redirect_uri, nonce, t=None, code_verifier: str = ""):
        """Exchange the code for tokens and verify the ID token.

        `t` is the caller's translation function (`auth.t`). The client itself knows no
        language — it speaks the protocol, not to the user. Without `t` the two
        messages stay English, instead of foisting German on a caller with `lang="en"`.

        `code_verifier` belongs to the `code_challenge` from `auth_url()` (PKCE, F-20). The
        own callback always passes it along.
        """
        t = t or (lambda schluessel, **fmt: translate("en", schluessel, None, **fmt))
        try:
            import httpx
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        dekoder = self._dekoder()
        daten = {"grant_type": "authorization_code", "code": code, "redirect_uri": redirect_uri,
                 "client_id": self.client_id, "client_secret": self.client_secret}
        if code_verifier:
            daten["code_verifier"] = code_verifier
        tok = httpx.post(self.meta()["token_endpoint"], timeout=15, data=daten).json()
        if "id_token" not in tok:
            raise HTTPException(502, t("api.oidc_token", reason=tok.get("error", "?")))
        # `exp` is mandatory (F-25). authlib checks expiry only if the claim is THERE — an
        # ID token without `exp` was thus valid forever. OIDC Core 2 requires it ("REQUIRED"), a
        # provider that omits it is defective or the token is not from it.
        optionen = {"iss": {"essential": True, "value": self.meta()["issuer"]},
                    "aud": {"essential": True, "value": self.client_id},
                    "exp": {"essential": True}}
        try:
            claims = dekoder.decode(tok["id_token"], self._jwkset(), claims_options=optionen)
        except Exception:
            # If the signature fails, the most likely reason is a key rotation
            # at the provider: the token names a `kid` that our set does not know yet. Fetch
            # anew once and try again — throttled, so that a stream of forged tokens
            # does not load the provider via us. If it fails again, the error stands.
            if not self._jwks_auffrischbar():
                raise
            security.seclog.warning(
                "OIDC: ID token not verifiable — fetching JWKS again (key rotation?).")
            claims = dekoder.decode(tok["id_token"], self._jwkset(erzwingen=True),
                                    claims_options=optionen)
        claims.validate(leeway=self.UHR_TOLERANZ)  # exp/iat/nbf, with clock tolerance (F-26)
        self._pruefe_publikum(claims, t)
        if nonce and claims.get("nonce") != nonce:
            raise HTTPException(400, t("api.oidc_nonce"))
        return claims, tok

    def refresh(self, refresh_token: str, erwartetes_sub: str) -> tuple:
        """Exchange a refresh token at the provider (4a, "revocation follows the IdP").

        Returns `(status, info, tok)`: `"ok"` with the fresh data (ID-token claims, otherwise
        UserInfo) · `"abgelehnt"` — the provider refuses (RFC 6749 5.2: `invalid_grant` etc.;
        the user is blocked, deleted, withdrawn from the application or the token was revoked) ·
        `"fehler"` — the provider is unreachable or answers nonsense. Only `"abgelehnt"`
        ends the session; an outage of the provider must not sign anybody out."""
        try:
            import httpx
        except ModuleNotFoundError as e:
            raise _fehlt_extra(e) from e
        daten = {"grant_type": "refresh_token", "refresh_token": refresh_token,
                 "client_id": self.client_id, "client_secret": self.client_secret}
        try:
            antwort = httpx.post(self.meta()["token_endpoint"], timeout=10, data=daten)
            tok = antwort.json()
        except Exception as e:   # noqa: BLE001 — network, JSON: the provider does not answer usably
            return "fehler", {}, {"error": type(e).__name__}
        if not isinstance(tok, dict):
            return "fehler", {}, {"error": "antwort"}
        # An error of the CLIENT says nothing about the person: `invalid_client` after a
        # secret rotation (RFC 6749 5.2: the 401 stands for that, too), `unauthorized_client`, a
        # disabled grant. It counts like an unreachable provider — otherwise
        # a misconfiguration ended all sessions and, since finding 8, silenced the API keys of all
        # those affected (attack on the third round). Every other 4xx is a no: the
        # request is well-formed, so the provider means the token — Dex reports a revoked
        # or expired one as `400 invalid_request` (counter-check of the fixes), others send
        # no code at all. A list of the no-codes would let every such provider through.
        fehler_code = str(tok.get("error") or "")
        if antwort.status_code >= 500 or antwort.status_code == 401 or fehler_code in (
                "invalid_client", "unauthorized_client", "unsupported_grant_type"):
            return "fehler", {}, {**tok, "error": fehler_code or f"http_{antwort.status_code}"}
        if 400 <= antwort.status_code < 500:
            return "abgelehnt", {}, {**tok, "error": fehler_code or f"http_{antwort.status_code}"}
        if antwort.status_code >= 300 or "error" in tok:
            return "fehler", {}, {**tok, "error": fehler_code or f"http_{antwort.status_code}"}
        claims: dict = {}
        if tok.get("id_token"):
            optionen = {"iss": {"essential": True, "value": self.meta()["issuer"]},
                        "aud": {"essential": True, "value": self.client_id},
                        "exp": {"essential": True}}
            try:
                geprueft = self._dekoder().decode(tok["id_token"], self._jwkset(), claims_options=optionen)
                geprueft.validate(leeway=self.UHR_TOLERANZ)
                self._pruefe_publikum(geprueft, lambda schluessel, **fmt: schluessel)
            except Exception:   # noqa: BLE001 — a token we cannot verify does not count
                return "fehler", {}, {"error": "id_token"}
            claims = dict(geprueft)
            if str(claims.get("sub") or "") != str(erwartetes_sub):
                # A different subject than at sign-in: not the same person.
                return "abgelehnt", {}, {"error": "sub"}
        info: dict = {}
        if tok.get("access_token"):
            try:
                info = self.userinfo(tok["access_token"], erwartetes_sub=erwartetes_sub) or {}
            except Exception:   # noqa: BLE001 — without UserInfo the ID token alone counts
                info = {}
        return "ok", {**info, **claims}, tok

    def _pruefe_publikum(self, claims, t) -> None:
        """`aud` and `azp` per OIDC Core 3.1.3.7, points 3 to 5 (F-15).

        The decoder only checks that the own `client_id` **occurs** in `aud`. A token may,
        however, name several recipients, and then only `azp` (authorized party) says whom it was
        issued for. Without this check TinySesam accepts a token made for a **different**
        application of the same provider that merely names us as well — token substitution.
        Whoever gets a token at any client of this provider would thereby get in here, too.

        Exactly three rules, and all three were missing:
        * several `aud` → `azp` is mandatory,
        * `azp` present → it must be the own `client_id`,
        * the own `client_id` must be in `aud` (the decoder covers that, here once more
          as a floor — `claims_options` can be set from outside).

        Since T-14 this weighs heavier: with several clients of the **same** installation, the
        token of app A would otherwise also be good for app B, and the approval per client would be bypassed.
        """
        aud = claims.get("aud")
        publikum = [str(a) for a in (aud if isinstance(aud, (list, tuple)) else [aud] if aud else [])]
        azp = claims.get("azp")
        if self.client_id not in publikum:
            security.seclog.warning("OIDC: ID token names aud=%s, expected %s",
                                    security.fuer_log(",".join(publikum)),
                                    security.fuer_log(self.client_id))
            raise HTTPException(400, t("api.oidc_audience"))
        if len(publikum) > 1 and not azp:
            security.seclog.warning(
                "OIDC: ID token names %d audiences but no azp — cannot be decided for whom "
                "it was issued (OIDC Core 3.1.3.7).", len(publikum))
            raise HTTPException(400, t("api.oidc_audience"))
        if azp and str(azp) != self.client_id:
            security.seclog.warning(
                "OIDC: ID token was issued for azp=%s, not for %s — rejected.",
                security.fuer_log(str(azp)), security.fuer_log(self.client_id))
            raise HTTPException(400, t("api.oidc_audience"))

    def end_session_url(self, post_logout_redirect_uri=None, id_token_hint=None):
        """RP-initiated logout URL at the provider (or None if not supported).

        `id_token_hint` (stored since T-22, `Store.get_oidc_id_token`): PocketID does not end its
        session without it, but shows a confirmation prompt and does not redirect back afterwards.
        An expired ID token is valid for this (OIDC RP-Initiated Logout 1.0, section 2)."""
        try:
            ep = self.meta().get("end_session_endpoint")
        except Exception:
            ep = None
        if not ep:
            return None
        params = {"client_id": self.client_id}
        if id_token_hint:
            params["id_token_hint"] = id_token_hint
        if post_logout_redirect_uri:
            params["post_logout_redirect_uri"] = post_logout_redirect_uri
        return ep + ("&" if "?" in ep else "?") + urlencode(params)

    def userinfo(self, access_token, erwartetes_sub: str = ""):
        """The provider's UserInfo response — **only** if its `sub` matches the ID token (F-18).

        OIDC Core 5.3.2 expressly requires the comparison: "The sub Claim in the UserInfo
        Response MUST be verified to exactly match the sub Claim in the ID Token; if they do not
        match, the UserInfo Response values MUST NOT be used."

        Why it matters: in the callback the response is laid **over** the claims of the ID token and
        supplies groups, e-mail and thereby indirectly roles and the admin flag. The ID token is
        signed, the UserInfo response is not — it is an ordinary HTTPS response to
        a bearer token. Whoever presents an access token of a **different** account (or whoever the
        provider confuses with several tenants) thus pushed the attributes of a foreign person
        into their own session.

        Leaving `erwartetes_sub` empty is the legacy call and **then discards every response**
        with a non-empty `sub` — a caller that cannot do the comparison should not
        get the data. Fail-closed instead of "better than nothing".
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
        """The `sub` comparison from OIDC Core 5.3.2 — as a function of its own, so that whoever
        replaces the HTTP part with a dummy can measure it too. A dummy that
        rebuilds the comparison otherwise tests only the rebuild."""
        if not isinstance(antwort, dict):
            return {}
        gemeldet = str(antwort.get("sub") or "")
        if gemeldet != str(erwartetes_sub or ""):
            security.seclog.warning(
                "OIDC: UserInfo reports sub=%s, the ID token names sub=%s — response discarded "
                "(OIDC Core 5.3.2). Groups, e-mail and admin flag thus come solely from the "
                "signed token.",
                security.fuer_log(gemeldet or "<leer>"), security.fuer_log(str(erwartetes_sub or "<leer>")))
            return {}
        return antwort


#: Key of the single client in `oidc_grant` and in the flow. A star, because it applies to **every**
#: host for which `oidc_clients` says nothing of its own — and because no hostname can be called that.
VORGABE_CLIENT = "*"


class OIDCClients:
    """All OIDC clients of an installation: host → client at the same provider (T-14).

    Why a registry and not simply a second field: who may enter which application is
    decided by the provider per **client** (with PocketID via the group approval). With a
    single client there is therefore only one answer for all applications. The registry holds
    the mapping at exactly one place, so that flow, callback and forward-auth answer the same question
    the same way.

    **One issuer for all.** Discovery document and JWKS hang on the provider, not on the client;
    they are therefore shared instead of being fetched anew per client. Several providers in one instance
    are not intended — `config_check` rejects an `issuer` in the client entry.
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
            # Metadata and JWKS come from the same provider — fetching once is enough. Without that
            # every client asked separately for the same document, i.e. three times with three applications,
            # and a key rotation would have to be noticed three times instead of once.
            c._meta, c._meta_zeit = vorgabe._meta, vorgabe._meta_zeit
            self._clients[str(host).strip().lower()] = c
        self._teile_meta()

    def _teile_meta(self):
        """Pass the metadata cache of the default client on to all the others.

        Called after every fetch: `meta()` sets `_meta` on the client that is currently asking.
        Without this catching up, every client would have its own state, and a test that sets the
        metadata from outside (the OIDC dummy does) would reach only one of them.
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
        """Which client key applies to this host? Unknown → the default client.

        An unknown host deliberately gets the default client and no rejection: that is exactly how
        an installation without `oidc_clients` behaves, and the transition should not be one.
        Which hosts are protected at all is decided by the proxy — not by this mapping.
        """
        h = str(host or "").strip().lower()
        if h and ":" in h and not h.startswith("["):
            h = h.split(":", 1)[0]          # the port is not part of the application's name
        return h if h in self._clients else VORGABE_CLIENT

    def __getitem__(self, schluessel: str) -> OIDCClient:
        return self._clients.get(schluessel) or self._clients[VORGABE_CLIENT]

    def fuer_host(self, host: str) -> OIDCClient:
        return self[self.schluessel_fuer_host(host)]

    def bekannt(self, schluessel: str) -> bool:
        """Is this client (still) set up? `__getitem__` otherwise falls back to the default client
        — for a row from `oidc_sitzung` that would mean exchanging a foreign refresh token with
        the wrong credentials."""
        return schluessel in self._clients

    def eintrag(self, schluessel: str) -> dict:
        """The additional settings of a client (`allowed_groups`, `group_role_map`) — with the
        values of the single client as fallback. This way a globally set group rule also applies
        to an application that names none itself."""
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
        # Make visible what the IdP must know as redirect URI. If it does not match,
        # the provider reports the error only later — after the login, with no hint at the cause.
        security.seclog.info("OIDC-Redirect-URI: %s", cfg.base_url.rstrip("/") + cfg.oidc_callback_path)

    def _redirect_uri(request: Request):
        # The redirect URI decides where the IdP sends the authorization code. Derived from the
        # host header, it would be determinable by the requester; an IdP with loosely
        # maintained redirect URIs would then deliver the code to a foreign host
        # (R4-01). Without a checked base the flow aborts instead of guessing.
        # `require_public_base`: a 500 in the middle of a sign-in attempt was the wrong place for
        # a configuration gap — `/auth/oidc/start` is the entry point to which a gateway sends
        # every visitor. Since this version `config_check` requires a `base_url` when
        # `oidc_enabled` is set, and setup fails beforehand.
        return auth.require_public_base(request) + cfg.oidc_callback_path

    # The flow is bound to the BROWSER, not only to the `state`. Without that an
    # attacker can start the flow at their side, sign in at the IdP as themselves and then lure
    # the victim onto the callback URL — the victim silently lands in the attacker's account and
    # keeps working there. An ordinary top-level GET suffices for that; SameSite does not help,
    # because no cookie is needed at all. webauthn_.py already uses the same pattern
    # (`_set_flow_cookie`) — it was missing here.
    # The actual name carries `__Host-` where possible (A-1): otherwise a
    # neighboring subdomain sets its own flow cookie via `Domain=.example.com`, and the binding
    # to the browser holds nothing any more.
    _OIDCFLOW = "tinysesam_oidc_flow"

    def _flow_cookie_setzen(resp, wert):
        auth._flow_cookie_setzen(resp, _OIDCFLOW, wert, max_age=600)

    @router.get("/auth/oidc/start")
    def oidc_start(request: Request, next: str = "", app: str = ""):
        # Every call leaves a `flow` row (600 s), which is deleted only on the
        # successful return path or by `gc`. In gateway operation this is exactly the entry point
        # to which the proxy sends every non-signed-in visitor — every abort, every
        # scanner, every bot made the database grow, and as the only flow-creating route
        # it was not rate-limited.
        if not auth._rate_ok(auth.client_ip(request)):
            raise HTTPException(429, auth.t("err.rate"))
        state, nonce = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        # Which application is meant is decided HERE and travels into the flow record —
        # not into the redirect URI (which is the same for all clients, so that a single
        # address must be registered at the provider) and not into the `state` (which everyone
        # reads from the address bar). `?app=` comes from forward-auth or from the application
        # itself; an unknown name ends up at the default client, exactly as before (T-14).
        # Without `app` the host of `next` decides (B-2): an entry that loses the information
        # (a bookmark, a login page of its own) would otherwise begin with the default client, and the
        # approval for the application it returns to would never come about.
        if not app and "://" in str(next or ""):
            from urllib.parse import urlsplit
            app = urlsplit(str(next)).hostname or ""
        ziel = clients.schluessel_fuer_host(app)
        client = clients[ziel]
        # The secret goes to the browser as an httponly cookie, only its hash into the flow record.
        # Whoever reads the `state` from the redirect URL has gained nothing with that.
        flow_key = secrets.token_urlsafe(24)
        # PKCE (F-20): the verifier stays in the flow record on the server, only the challenge goes
        # into the address bar. An intercepted code is worthless without it.
        verifier, challenge = pkce_paar()
        auth.store.put_flow("oidc:" + state,
                            {"nonce": nonce, "next": next, "fk": _hash(flow_key), "app": ziel,
                             "pkce": verifier},
                            ttl=600)
        resp = RedirectResponse(client.auth_url(_redirect_uri(request), state, nonce,
                                                code_challenge=challenge), 303)
        _flow_cookie_setzen(resp, flow_key)
        return resp

    @router.get(cfg.oidc_callback_path)
    def oidc_callback(request: Request, code: str = "", state: str = "", error: str = ""):
        if error:
            raise HTTPException(400, auth.t("api.oidc_error", reason=error))
        flow = auth.store.pop_flow("oidc:" + state)
        if not flow:
            raise HTTPException(400, auth.t("api.oidc_state"))
        # The return path must come from THE SAME browser that began the flow.
        erwartet = flow.get("fk")
        mitgebracht = request.cookies.get(auth.flow_cookie_name(_OIDCFLOW)) or ""
        if not erwartet or not secrets.compare_digest(_hash(mitgebracht), erwartet):
            security.seclog.warning("OIDC callback without a matching flow cookie — rejected")
            raise HTTPException(400, auth.t("api.oidc_browser"))
        # The exchange is done with the client with which the flow began. A different client would have
        # a different secret — the exchange then fails at the provider, rightly so.
        ziel = str(flow.get("app") or VORGABE_CLIENT)
        client = clients[ziel]
        _gefragt = jetzt()          # finding 8: a no that comes afterwards stays
        claims, tok = client.exchange(code, _redirect_uri(request), flow["nonce"], t=auth.t,
                                      code_verifier=str(flow.get("pkce") or ""))
        # The `sub` from the **signed** token is the yardstick for the UserInfo response, which
        # itself is not signed (F-18). That is why it stands before the fetch, not after.
        sub_im_token = str(claims.get("sub") or "")
        nutzerinfo = client.userinfo(tok.get("access_token"), erwartetes_sub=sub_im_token) or {}
        info = {**nutzerinfo, **dict(claims)}

        # Group rule per application: `oidc_clients[host]["allowed_groups"]`, otherwise the global one.
        # The actual approval is made by the provider anyway (it gives a user who is not approved
        # no code at all) — this is the second barrier for the case that the provider
        # approves more generously than intended.
        eintrag = clients.eintrag(ziel)
        erlaubte = eintrag["allowed_groups"]
        if erlaubte:
            groups = info.get(cfg.oidc_group_claim) or []
            if not (set(erlaubte) & set(groups if isinstance(groups, list) else [groups])):
                # Into the log, not only to the browser: "I cannot get in" is the most common
                # support case in gateway operation, and without this line it left
                # nothing at all on the server side. The pattern already exists in the project
                # (`forward_role_denied` in router.py).
                auth.audit("oidc_group_denied", str(info.get("email") or info.get("sub") or "?"),
                           auth.client_ip(request),
                           f"app={ziel} required={sorted(erlaubte)}")
                raise HTTPException(403, auth.t("api.oidc_group"))

        issuer, sub = client.meta()["issuer"], claims["sub"]

        # The e-mail from the ID token carries decisions in TinySesam: `admin_identifiers`
        # makes its bearer admin on the first login. That presupposes that the address really belongs
        # to the person signing in — which is proven solely by `email_verified`. Whoever enters an arbitrary address
        # at an IdP with self-registration would otherwise become first admin with
        # it. Address and evidence are therefore kept as a pair: the address as
        # before into the account and into `Remote-Email`, the evidence as a note next to it.
        mail, mail_bestaetigt, beleg_ausdruecklich = _email_mit_beleg(
            claims, nutzerinfo, cfg.oidc_email_verified_default)
        if mail and not mail_bestaetigt:
            # An address WITHOUT evidence is not used (H-3, PO decision 2026-09-24): no
            # account name from it, no address in the new account, hence also no `Remote-Email` to the
            # protected app. Until then it was adopted and merely noted as unconfirmed —
            # but a downstream app that assigns users by address never saw the note:
            # whoever entered a foreign address at the provider arrived there as its owner.
            #
            # The price: a provider that never sends the optional claim (Entra ID) then
            # supplies no addresses any more. For it there is the operator's explicit statement
            # `oidc_email_verified_default=True` — "this provider verifies every address" —, which
            # `_email_mit_beleg` treats like evidence. An explicit `false` always stays
            # unconfirmed.
            security.seclog.warning(
                "OIDC: The provider reports %s without proof (email_verified missing or not "
                "true) — the address is NOT used (no account name, no Remote-Email). "
                "If this provider verifies every address but does not send the claim: "
                "oidc_email_verified_default=True.", security.fuer_log(mail))
            auth.audit("oidc_email_unverified", str(mail), auth.client_ip(request),
                       "used=0")

        uid = auth.store.get_oidc_user(issuer, sub)
        if not uid:
            if not cfg.oidc_auto_create:
                auth.audit("oidc_no_account", str(info.get("email") or sub or "?"),
                           auth.client_ip(request), "oidc_auto_create=False")
                raise HTTPException(403, auth.t("api.oidc_nolink"))
            # Fallback name if need be from the address — but only from one with evidence (H-3). Until
            # 2026-09-24 also from an unconfirmed one ("a name is not an authorization"); but an
            # app behind forward-auth that assigns via `Remote-User` saw in it exactly the
            # foreign address that is not to be used here.
            belegte_mail = mail if mail_bestaetigt else None
            # `preferred_username` can also be an address (Keycloak "Email as username", Entra
            # with the UPN, Zitadel) — and is then the same unverified address under another name.
            # Let through, it became account name and `Remote-User`, and the identifier was taken
            # for the real owner (attack on H-3). A name with `@` therefore counts only if it
            # is the address with evidence; otherwise the fallback name.
            # The FOLDED identifier is checked: `victim＠example.com` (full-width, U+FF20) or
            # `﹫` (U+FE6B) become `@` in `norm_kennung` — checked literally they slipped through
            # and occupied the address after all (attack on the fixes, R2-1).
            wunsch = str(info.get("preferred_username") or "").strip()
            if name_ungueltig(wunsch):
                wunsch = ""          # control characters: a different name in `Remote-User`
            if "@" in norm_kennung(wunsch) and not (
                    belegte_mail and norm_email(wunsch) == norm_email(belegte_mail)):
                wunsch = ""
            username = wunsch or belegte_mail or ("oidc-" + sub[:8])
            if name_ungueltig(username):
                username = "oidc-" + hashlib.sha256(sub.encode()).hexdigest()[:8]
            base_un, i = username, 1
            # The alternative name must be free in BOTH namespaces (finding R4-12) — a name
            # that is the e-mail of an existing account occupies its login identifier.
            while auth.identifier_taken(username):
                i += 1
                username = f"{base_un}{i}"
            try:
                # Address AND evidence go into the account together (F-14): the note decides
                # later about first admin/allowlist — regardless of by which route this
                # account signs in the next time.
                # The name comes from the provider (`name_quelle`): a sign-in via LDAP/SAML never binds
                # this account via it (attack round 2026-09-26, `_konto_anlegen`).
                uid = auth._konto_anlegen(username, display_name=info.get("name") or username,
                                          email=belegte_mail, email_verified=bool(belegte_mail),
                                          name_quelle="oidc")
            except errors.ConfigError:
                # The identifier of the identity already belongs to someone locally. Fail-closed: no account
                # that overwrites a foreign identifier — the operator links by hand.
                auth.audit("oidc_ident_taken", str(mail or username or sub or "?"),
                           auth.client_ip(request))
                raise HTTPException(409, auth.t("api.idp_ident_taken"))
            auth.store.link_oidc(issuer, sub, uid)
        elif mail and beleg_ausdruecklich:
            # Existing account: what the provider SAYS TODAY about ITS address replaces the note.
            # Otherwise an "unconfirmed" from earlier would remain after the IdP has
            # verified the address — and conversely an old evidence would remain valid although the provider
            # has withdrawn it.
            #
            # Two limits: only for the SAME address (about a different one the claim says nothing —
            # the same rule as in `_email_mit_beleg`), and only for an explicit
            # statement. **Silence overwrites nothing:** an account whose address the operator
            # set themselves (admin, CLI, registration with confirmation mail) would otherwise lose
            # its evidence merely because an IdP does not send the optional claim.
            konto = auth.store.get_user(uid)
            if konto and not str(konto["email"] or "").strip() and mail_bestaetigt:
                # The counterpart to H-3: an account created without an address because the
                # provider did not verify it gets it as soon as it does — provided it is free.
                # If it already belongs to another account, the account stays without (fail-closed, as with
                # creation); the operator sees the line.
                if auth.identifier_taken(mail, exclude_id=uid):
                    auth.audit("oidc_email_taken", str(konto["username"]), auth.client_ip(request),
                               "backfilled=0")
                else:
                    try:
                        auth.store.set_email(uid, mail, verified=True)
                        auth.audit("oidc_email_added", str(konto["username"]), auth.client_ip(request),
                                   "proof=1")
                    except sqlite3.IntegrityError:
                        # Race (G12c): assigned between check and write — the database
                        # decides, the account stays without an address as above.
                        auth.audit("oidc_email_taken", str(konto["username"]), auth.client_ip(request),
                                   "backfilled=0 race=1")
            elif konto and str(konto["email"] or "").lower() == str(mail).strip().lower() \
                    and bool(konto["email_verified"]) is not bool(mail_bestaetigt):
                auth.store.set_email_verified(uid, mail_bestaetigt)

        # A blocked account gets nothing at all here any more (F-17). Until 0.18.x the
        # callback ran through completely for a `disabled=1` account: groups were adopted, the
        # admin flag could be set, a login entry was created — only the session stayed
        # out at the end. But blocking an account is the answer to "this person should be able to do
        # nothing any more"; that their roles still change in the process is the opposite. And in the
        # log it looked like a successful sign-in.
        #
        # The check stands BEFORE `apply_idp_groups`, `apply_factor` and any write access —
        # every line after it would be a change to an account that may no longer sign in.
        # Local password login and panel have always checked the same; the federated side was
        # the gap.
        _konto = auth.store.get_user(uid)
        if _konto and _konto["disabled"]:
            auth.audit("oidc_disabled", str(_konto["username"]), auth.client_ip(request),
                       f"app={ziel} sub={security.fuer_log(sub)}")
            security.seclog.warning("%s user=%s ip=%s method=oidc reason=account_locked",
                                    security.log_ereignis("oidc"),
                                    security.fuer_log(str(_konto["username"])),
                                    security.fuer_log(auth.client_ip(request)))
            raise HTTPException(403, auth.t("api.oidc_disabled"))
        # The provider has just confirmed the account — that wakes dormant API keys (finding 8). Only
        # here, after all rejections (group gate, identifier taken, blocked): a login that
        # fails confirms nothing.
        auth.store.idp_bestaetigen(uid, _gefragt)

        # OIDC groups → local roles (if mapped). The mapping may differ per application:
        # the same directory group can be called "editor" in app A and
        # nothing at all in app B. Without an entry the global mapping applies, i.e. the behavior of 0.18.0.
        _grp = info.get(cfg.oidc_group_claim) or []
        _gruppen = _grp if isinstance(_grp, list) else [_grp]
        auth.apply_idp_groups(uid, _gruppen, eintrag["group_role_map"])

        # client_ip instead of the raw peer IP — behind a proxy the peer is the proxy.
        ip, ua = auth.client_ip(request), request.headers.get("user-agent")
        token, ok, is_new = auth.apply_factor(request, uid, "oidc", ip, ua,
                                              email_verified=mail_bestaetigt)
        # 4a: remember the refresh token — with it TinySesam regularly asks the provider whether the
        # person is still allowed (`oidc_session_refresh_minutes`). Without a refresh token this does not work.
        if tok.get("refresh_token"):
            auth._oidc_sitzung_merken(token, ziel, str(sub), str(tok["refresh_token"]))
        # The ID token as a sign-out hint (T-22): PocketID ends its session only with
        # `id_token_hint`; without it the person is left standing at its confirmation prompt.
        if tok.get("id_token"):
            auth.store.set_oidc_id_token(auth.store.session_hash(token), ziel, str(tok["id_token"]))
        # The provider has agreed for THIS application — this is noted on the session.
        # For every other application this note says nothing; there `/auth/forward` asks
        # again. Exactly that is the difference to "signed in yes/no" (T-14).
        auth._record_oidc_approval(token, ziel, rollen=_gruppen)
        target = auth._login_redirect_after(request, token, uid,
                                            auth.safe_next(flow.get("next") or "", request))
        resp = RedirectResponse(target, 303)
        if is_new:
            auth.set_cookie(resp, token)
        # The flow cookie has served its purpose — leaving it would be a remnant
        # that protects nothing any more and only reveals that a flow ran here.
        auth._flow_cookie_loeschen(resp, _OIDCFLOW)
        return resp
