package tinysesam

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

// Mode is the operating mode of a [Gate]. It must be chosen explicitly; the zero value is a configuration error.
type Mode int

// Operating modes (spec section 1).
const (
	// HeaderMode trusts the Remote-* headers the proxy sets. Only safe when the proxy fulfils spec section 2.1.
	HeaderMode Mode = iota + 1
	// TokenMode verifies the gate token itself and ignores every Remote-* header.
	TokenMode
)

// DefaultGateCookie is the default name of the gate cookie (TinySesam's gate_cookie_name).
const DefaultGateCookie = "__Host-tinysesam_gate"

// Config configures a [Gate]. New refuses a contradictory or incomplete configuration, so the application stops at
// start-up instead of failing open later.
type Config struct {
	// Mode is HeaderMode or TokenMode. Required.
	Mode Mode

	// TrustedProxies (header mode, recommended): the peer addresses the proxy connects from. When set, a request
	// from any other peer is refused with ClassUntrustedPeer. RemoteAddr is used as it is — do not let another
	// middleware rewrite it from X-Forwarded-For.
	TrustedProxies []netip.Prefix
	// HeaderNames (header mode): renamed headers when TinySesam's forward_headers renames them.
	HeaderNames HeaderNames

	// Issuer (token mode, required): TinySesam's base_url without a trailing slash, exactly.
	Issuer string
	// Audience (token mode, required): the exact string the proxy names in audience_whitelist, including
	// "|roles=..." when the route requires roles. Never derived from the request.
	Audience string
	// GateKeys (token mode): fixed public keys, each the output of `tinysesam gate-key` (standard Base64).
	GateKeys []string
	// JWKSURL (token mode): the key set address, normally https://<auth host>/auth/gate/jwks.json. https, or http
	// to a loopback address only. Exactly one of GateKeys and JWKSURL is required.
	JWKSURL string
	// HTTPClient (token mode with JWKSURL, optional): the client for fetching the key set. Its timeout is capped at
	// FetchTimeout and redirects never leave the host.
	HTTPClient *http.Client
	// LeewaySeconds (token mode): clock leeway, 0 (the default) to MaxLeeway.
	LeewaySeconds int
	// CookieName (token mode): the gate cookie; DefaultGateCookie when empty.
	CookieName string
	// TokenHeader (token mode, optional): read the token from this request header instead of the cookie.
	TokenHeader string

	// Logger (optional) receives one line per refused request with the error class and, if well-formed, the kid —
	// never the token, a claim or a header value. Nil logs nothing.
	Logger *slog.Logger
}

// Gate identifies requests in one configured mode.
type Gate struct {
	mode    Mode
	names   HeaderNames
	proxies []netip.Prefix

	rules       tokenRules
	static      *KeySet
	jwks        *jwksCache
	cookie      string
	tokenHeader string
	now         func() int64

	log *slog.Logger
}

// New checks the configuration and builds a Gate.
func New(cfg Config) (*Gate, error) {
	g := &Gate{mode: cfg.Mode, log: cfg.Logger, now: func() int64 { return time.Now().Unix() }}
	tokenSettings := cfg.Issuer != "" || cfg.Audience != "" || len(cfg.GateKeys) > 0 || cfg.JWKSURL != "" ||
		cfg.HTTPClient != nil || cfg.LeewaySeconds != 0 || cfg.CookieName != "" || cfg.TokenHeader != ""
	switch cfg.Mode {
	case HeaderMode:
		if tokenSettings {
			return nil, configError("token settings given in header mode")
		}
		g.names = cfg.HeaderNames.withDefaults()
		seen := map[string]bool{}
		for _, n := range g.names.list() {
			if !validFieldName(n) {
				return nil, configError("invalid header name")
			}
			if seen[strings.ToLower(n)] {
				return nil, configError("two header names are equal")
			}
			seen[strings.ToLower(n)] = true
		}
		for _, p := range cfg.TrustedProxies {
			if !p.IsValid() {
				return nil, configError("invalid trusted proxy prefix")
			}
		}
		g.proxies = append([]netip.Prefix(nil), cfg.TrustedProxies...)
	case TokenMode:
		if len(cfg.TrustedProxies) > 0 || cfg.HeaderNames != (HeaderNames{}) {
			return nil, configError("header settings given in token mode")
		}
		if cfg.Issuer == "" || cfg.Audience == "" {
			return nil, configError("token mode needs Issuer and Audience")
		}
		if cfg.LeewaySeconds < 0 || cfg.LeewaySeconds > MaxLeeway {
			return nil, configError(fmt.Sprintf("LeewaySeconds must be 0 to %d", MaxLeeway))
		}
		g.rules = tokenRules{issuer: cfg.Issuer, audience: cfg.Audience, leeway: int64(cfg.LeewaySeconds)}
		switch {
		case len(cfg.GateKeys) > 0 && cfg.JWKSURL != "":
			return nil, configError("give either GateKeys or JWKSURL, not both")
		case len(cfg.GateKeys) > 0:
			if cfg.HTTPClient != nil {
				return nil, configError("HTTPClient without JWKSURL")
			}
			ks, err := NewStaticKeySet(cfg.GateKeys...)
			if err != nil {
				return nil, configError("a gate key is not 32 bytes in standard Base64")
			}
			g.static = ks
		case cfg.JWKSURL != "":
			if err := checkJWKSURL(cfg.JWKSURL); err != nil {
				return nil, err
			}
			g.jwks = newJWKSCache(httpFetcher(cfg.HTTPClient, cfg.JWKSURL))
		default:
			return nil, configError("token mode needs GateKeys or JWKSURL")
		}
		g.cookie = cfg.CookieName
		if g.cookie == "" {
			g.cookie = DefaultGateCookie
		}
		if cfg.TokenHeader != "" {
			if cfg.CookieName != "" {
				return nil, configError("give either CookieName or TokenHeader, not both")
			}
			if !validFieldName(cfg.TokenHeader) {
				return nil, configError("invalid TokenHeader")
			}
			g.tokenHeader = cfg.TokenHeader
		}
	default:
		return nil, configError("Mode must be HeaderMode or TokenMode")
	}
	return g, nil
}

func configError(msg string) error {
	return errors.New("tinysesam: configuration: " + msg)
}

func checkJWKSURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil || u.Fragment != "" {
		return configError("JWKSURL is not an absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" {
			return nil
		}
		if ip, err := netip.ParseAddr(host); err == nil && ip.Unmap().IsLoopback() {
			return nil
		}
		return configError("JWKSURL over plain http is allowed to a loopback address only")
	}
	return configError("JWKSURL must use https")
}

func validFieldName(n string) bool {
	if n == "" {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("!#$%&'*+-.^_`|~", c) >= 0) {
			return false
		}
	}
	return true
}

// Identify returns the identity of r, or an *Error whose class says why not. Every error — a panic inside the client
// included — means not authenticated.
func (g *Gate) Identify(r *http.Request) (id *Identity, err error) {
	defer func() {
		if recover() != nil {
			id, err = nil, refuse(ClassInternal, "unexpected failure")
		}
	}()
	switch g.mode {
	case HeaderMode:
		if len(g.proxies) > 0 && !g.trustedPeer(r.RemoteAddr) {
			return nil, refuse(ClassUntrustedPeer, "")
		}
		return identityFromHeaders(r.Header, g.names)
	case TokenMode:
		jws, err := g.token(r)
		if err != nil {
			return nil, err
		}
		id, _, err := g.Verify(r.Context(), jws)
		return id, err
	}
	return nil, refuse(ClassInternal, "gate not built by New")
}

func (g *Gate) trustedPeer(remote string) bool {
	host := remote
	if h, _, err := net.SplitHostPort(remote); err == nil {
		host = h
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	for _, p := range g.proxies {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// token reads the gate token from the one configured source.
func (g *Gate) token(r *http.Request) (string, error) {
	if g.tokenHeader != "" {
		vals := r.Header.Values(g.tokenHeader)
		if len(vals) > 1 {
			return "", refuse(ClassMalformed, "more than one token header")
		}
		if len(vals) == 0 || vals[0] == "" {
			return "", refuse(ClassUnauthenticated, "no token")
		}
		return vals[0], nil
	}
	cookies := r.CookiesNamed(g.cookie)
	if len(cookies) > 1 {
		return "", refuse(ClassMalformed, "more than one gate cookie")
	}
	if len(cookies) == 0 || cookies[0].Value == "" {
		return "", refuse(ClassUnauthenticated, "no token")
	}
	return cookies[0].Value, nil
}

// Verify checks a gate token in the order of spec section 4.4 and returns the identity and the claims. Only for a
// Gate in token mode.
func (g *Gate) Verify(ctx context.Context, jws string) (*Identity, *Claims, error) {
	if g.mode != TokenMode {
		return nil, nil, refuse(ClassInternal, "Verify needs token mode")
	}
	now := g.now()
	p, err := parseToken(jws)
	if err != nil {
		return nil, nil, err
	}
	var key ed25519.PublicKey
	if g.jwks != nil {
		key, err = g.jwks.lookup(ctx, p.kid, now)
		if err != nil {
			return nil, nil, err
		}
	} else {
		key = g.static.lookup(p.kid)
		if key == nil {
			return nil, nil, refuseKid(ClassKid, p.kid, "kid not in the key set")
		}
	}
	c, err := finishToken(p, key, g.rules, now)
	if err != nil {
		return nil, nil, err
	}
	return identityFromClaims(c), c, nil
}

type ctxKey struct{}

// FromContext returns the identity [Gate.Middleware] stored, or nil and false.
func FromContext(ctx context.Context) (*Identity, bool) {
	id, _ := ctx.Value(ctxKey{}).(*Identity)
	return id, id != nil
}

// Middleware identifies every request and stores the identity in its context (read it with [FromContext]). It
// lets every request through; guard handlers with [RequireAuth], [RequireRole] or [RequireSession].
func (g *Gate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := g.Identify(r)
		if err != nil {
			id = nil
			g.logRefusal(r, err)
		}
		// Always set the value, so an identity from an outer layer never survives a failed check here.
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
	})
}

func (g *Gate) logRefusal(r *http.Request, err error) {
	if g.log == nil {
		return
	}
	var e *Error
	if !errors.As(err, &e) || e.Class == ClassUnauthenticated {
		return
	}
	attrs := []any{"class", string(e.Class)}
	if e.Kid != "" {
		attrs = append(attrs, "kid", e.Kid)
	}
	g.log.WarnContext(r.Context(), "tinysesam gate refused a request", attrs...)
}

// RequireAuth answers 401 unless the request carries an identity.
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := FromContext(r.Context()); !ok {
			deny(w, http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole answers 401 without an identity and 403 when the role is not one of its groups (compared exactly).
func RequireRole(role string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok {
			deny(w, http.StatusUnauthorized)
			return
		}
		if !id.HasRole(role) {
			deny(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireSession answers 401 without an identity and 403 unless the request came from a browser session — for
// actions a token must never perform, and for decisions that need the complete groups.
func RequireSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, ok := FromContext(r.Context())
		if !ok {
			deny(w, http.StatusUnauthorized)
			return
		}
		if !id.IsSession() {
			deny(w, http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// deny answers without the token, the claims or the reason (spec section 6).
func deny(w http.ResponseWriter, status int) {
	w.Header().Set("Cache-Control", "no-store")
	http.Error(w, http.StatusText(status), status)
}
