package tinysesam

import (
	"bytes"
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
)

func TestConfigErrorsStopTheStart(t *testing.T) {
	key := testGateKey(t, "A")
	token := func(c Config) Config {
		c.Mode = TokenMode
		if c.Issuer == "" {
			c.Issuer = testIssuer
		}
		if c.Audience == "" {
			c.Audience = testAudience
		}
		return c
	}
	bad := map[string]Config{
		"no mode":                    {},
		"unknown mode":               {Mode: 7},
		"token without issuer":       {Mode: TokenMode, Audience: testAudience, GateKeys: []string{key}},
		"token without audience":     {Mode: TokenMode, Issuer: testIssuer, GateKeys: []string{key}},
		"token without key":          token(Config{}),
		"keys and JWKS":              token(Config{GateKeys: []string{key}, JWKSURL: "https://auth.example.com/j"}),
		"leeway above 60":            token(Config{GateKeys: []string{key}, LeewaySeconds: 61}),
		"negative leeway":            token(Config{GateKeys: []string{key}, LeewaySeconds: -1}),
		"short key":                  token(Config{GateKeys: []string{"AAAA"}}),
		"url-safe key":               token(Config{GateKeys: []string{"ecc3yanysDDBsjOxE03UuR3bhBJmVjsRPkXuVsCwVCY"}}),
		"http JWKS to another host":  token(Config{JWKSURL: "http://auth.example.com/auth/gate/jwks.json"}),
		"JWKS without scheme":        token(Config{JWKSURL: "auth.example.com/auth/gate/jwks.json"}),
		"JWKS ftp":                   token(Config{JWKSURL: "ftp://auth.example.com/jwks.json"}),
		"cookie and header":          token(Config{GateKeys: []string{key}, CookieName: "c", TokenHeader: "X-Gate"}),
		"bad token header":           token(Config{GateKeys: []string{key}, TokenHeader: "X Gate"}),
		"header settings in token":   token(Config{GateKeys: []string{key}, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}}),
		"token settings in header":   {Mode: HeaderMode, Issuer: testIssuer},
		"keys in header mode":        {Mode: HeaderMode, GateKeys: []string{key}},
		"equal header names":         {Mode: HeaderMode, HeaderNames: HeaderNames{Name: "remote-user"}},
		"invalid header name":        {Mode: HeaderMode, HeaderNames: HeaderNames{User: "Remote User"}},
		"HTTP client without JWKS":   token(Config{GateKeys: []string{key}, HTTPClient: &http.Client{}}),
		"invalid trusted proxy":      {Mode: HeaderMode, TrustedProxies: []netip.Prefix{{}}},
		"JWKS with user info":        token(Config{JWKSURL: "https://u:p@auth.example.com/jwks.json"}),
		"http JWKS to a public addr": token(Config{JWKSURL: "http://192.0.2.1/jwks.json"}),
		"approval key set":           token(Config{JWKSURL: "https://auth.example.com/auth/approvals/jwks.json"}),
		"approval key set /":         token(Config{JWKSURL: "https://auth.example.com/auth/approvals/jwks.json/"}),
	}
	for name, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	good := map[string]Config{
		"header":             {Mode: HeaderMode},
		"header with peers":  {Mode: HeaderMode, TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}},
		"fixed keys":         token(Config{GateKeys: []string{key, testGateKey(t, "B")}, LeewaySeconds: 60}),
		"JWKS https":         token(Config{JWKSURL: "https://auth.example.com/auth/gate/jwks.json"}),
		"JWKS http loopback": token(Config{JWKSURL: "http://127.0.0.1:8080/auth/gate/jwks.json"}),
		"JWKS http ::1":      token(Config{JWKSURL: "http://[::1]:8080/auth/gate/jwks.json"}),
		"token header":       token(Config{GateKeys: []string{key}, TokenHeader: "X-Gate-Token"}),
	}
	for name, cfg := range good {
		if _, err := New(cfg); err != nil {
			t.Errorf("%s: refused: %v", name, err)
		}
	}
}

func fixedGate(t testing.TB, logger *slog.Logger) *Gate {
	t.Helper()
	g, err := New(Config{Mode: TokenMode, Issuer: testIssuer, Audience: testAudience,
		GateKeys: []string{testGateKey(t, "A")}, Logger: logger})
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() int64 { return testNow }
	return g
}

// app is a small router with the three guards behind a gate.
func app(g *Gate) http.Handler {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := FromContext(r.Context())
		_, _ = io.WriteString(w, "hello "+id.ID)
	})
	mux := http.NewServeMux()
	mux.Handle("/", RequireAuth(ok))
	mux.Handle("/admin", RequireRole("admin", ok))
	mux.Handle("/settings", RequireSession(ok))
	mux.Handle("/public", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, signed := FromContext(r.Context()); signed {
			_, _ = io.WriteString(w, "signed in")
			return
		}
		_, _ = io.WriteString(w, "anonymous")
	}))
	return g.Middleware(mux)
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestTokenModeGuards(t *testing.T) {
	var logs bytes.Buffer
	h := app(fixedGate(t, slog.New(slog.NewTextHandler(&logs, nil))))
	session := mint(t, "A", sessionClaims("editors"))
	adminTok := mint(t, "A", sessionClaims("editors,admin"))
	oauth := sessionClaims("admin")
	oauth["ts_auth"] = "oauth"
	oauthTok := mint(t, "A", oauth)
	forged := mint(t, "X", sessionClaims("admin"))
	cases := []struct {
		name, path, token string
		want              int
	}{
		{"no token", "/", "", 401},
		{"session", "/", session, 200},
		{"session, role missing", "/admin", session, 403},
		{"admin", "/admin", adminTok, 200},
		{"session route", "/settings", session, 200},
		{"oauth on session route", "/settings", oauthTok, 403},
		{"oauth with role", "/admin", oauthTok, 200},
		{"forged key", "/", forged, 401},
		{"forged key on public route", "/public", forged, 200},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodGet, c.path, nil)
		if c.token != "" {
			r.AddCookie(&http.Cookie{Name: DefaultGateCookie, Value: c.token})
		}
		rec := serve(h, r)
		if rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
		if c.want >= 400 && c.token != "" && strings.Contains(rec.Body.String(), strings.Split(c.token, ".")[1]) {
			t.Errorf("%s: the answer contains the token", c.name)
		}
		if c.want >= 400 && rec.Header().Get("Cache-Control") != "no-store" {
			t.Errorf("%s: refusal without no-store", c.name)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/public", nil)
	r.AddCookie(&http.Cookie{Name: DefaultGateCookie, Value: forged})
	if body := serve(h, r).Body.String(); body != "anonymous" {
		t.Errorf("a refused token left an identity: %q", body)
	}
	// The log names the class and the kid, never the token or a claim.
	if !strings.Contains(logs.String(), "class=kid") {
		t.Errorf("refusal not logged with its class: %q", logs.String())
	}
	for _, secret := range []string{forged, strings.Split(forged, ".")[1], "anna"} {
		if strings.Contains(logs.String(), secret) {
			t.Errorf("the log contains credential material: %q", logs.String())
		}
	}
}

// Token mode ignores every Remote-* header and never falls back to header mode.
func TestTokenModeIgnoresRemoteHeaders(t *testing.T) {
	h := app(fixedGate(t, nil))
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.Header.Set("Remote-User", "admin")
	r.Header.Set("Remote-Groups", "admin")
	r.Header.Set("Remote-Id", "2")
	r.Header.Set("Remote-Auth", "session")
	if rec := serve(h, r); rec.Code != 401 {
		t.Errorf("Remote-* headers in token mode: status %d, want 401", rec.Code)
	}
	r.AddCookie(&http.Cookie{Name: DefaultGateCookie, Value: mint(t, "A", sessionClaims("editors"))})
	if rec := serve(h, r); rec.Code != 403 {
		t.Errorf("token plus forged Remote-Groups: status %d, want 403", rec.Code)
	}
}

func TestTokenSources(t *testing.T) {
	g := fixedGate(t, nil)
	tok := mint(t, "A", sessionClaims("editors"))
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Add("Cookie", DefaultGateCookie+"="+tok)
	r.Header.Add("Cookie", DefaultGateCookie+"="+tok)
	if _, err := g.Identify(r); ClassOf(err) != ClassMalformed {
		t.Errorf("two gate cookies: class %v, want malformed", ClassOf(err))
	}
	// Not from Authorization, a query parameter or another cookie unless configured.
	r = httptest.NewRequest(http.MethodGet, "/?token="+tok, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	r.AddCookie(&http.Cookie{Name: "tinysesam_gate", Value: tok})
	if _, err := g.Identify(r); ClassOf(err) != ClassUnauthenticated {
		t.Errorf("token only in unconfigured places: class %v, want unauthenticated", ClassOf(err))
	}
	hg, err := New(Config{Mode: TokenMode, Issuer: testIssuer, Audience: testAudience,
		GateKeys: []string{testGateKey(t, "A")}, TokenHeader: "X-Gate-Token"})
	if err != nil {
		t.Fatal(err)
	}
	hg.now = g.now
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("X-Gate-Token", tok)
	if id, err := hg.Identify(r); err != nil || id.ID != "1" {
		t.Errorf("token header: %v", err)
	}
	r.Header.Add("X-Gate-Token", tok)
	if _, err := hg.Identify(r); ClassOf(err) != ClassMalformed {
		t.Errorf("two token headers: class %v, want malformed", ClassOf(err))
	}
	r = httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: DefaultGateCookie, Value: tok})
	if _, err := hg.Identify(r); ClassOf(err) != ClassUnauthenticated {
		t.Errorf("cookie while a header is configured: class %v, want unauthenticated", ClassOf(err))
	}
}

func TestLeeway(t *testing.T) {
	g, err := New(Config{Mode: TokenMode, Issuer: testIssuer, Audience: testAudience,
		GateKeys: []string{testGateKey(t, "A")}, LeewaySeconds: 30})
	if err != nil {
		t.Fatal(err)
	}
	tok := mint(t, "A", sessionClaims("editors")) // valid from testNow to testNow+300
	for _, c := range []struct {
		now  int64
		want ErrorClass
	}{{testNow - 30, ""}, {testNow - 31, ClassNotYetValid}, {testNow + 329, ""}, {testNow + 330, ClassExpired}} {
		g.now = func() int64 { return c.now }
		_, _, err := g.Verify(t.Context(), tok)
		if (c.want == "" && err != nil) || (c.want != "" && ClassOf(err) != c.want) {
			t.Errorf("now %+d: %v, want %q", c.now-testNow, err, c.want)
		}
	}
}

func TestHeaderMode(t *testing.T) {
	peer := netip.MustParsePrefix("192.0.2.0/24")
	g, err := New(Config{Mode: HeaderMode, TrustedProxies: []netip.Prefix{peer}})
	if err != nil {
		t.Fatal(err)
	}
	h := app(g)
	req := func(remote, path string, headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.RemoteAddr = remote
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	session := map[string]string{"Remote-User": "anna", "Remote-Id": "1", "Remote-Groups": "editors",
		"Remote-Auth": "session", "Remote-Kind": "user"}
	token := map[string]string{"Remote-User": "anna", "Remote-Id": "1", "Remote-Groups": "admin", "Remote-Kind": "user"}
	cases := []struct {
		name, remote, path string
		headers            map[string]string
		want               int
	}{
		{"trusted session", "192.0.2.10:4000", "/settings", session, 200},
		{"untrusted peer", "198.51.100.7:4000", "/", session, 401},
		{"mapped IPv4 peer", "[::ffff:192.0.2.10]:4000", "/", session, 200},
		{"no Remote-Auth is a token", "192.0.2.10:4000", "/settings", token, 403},
		{"token with role", "192.0.2.10:4000", "/admin", token, 200},
		{"role missing", "192.0.2.10:4000", "/admin", session, 403},
		{"no user", "192.0.2.10:4000", "/", map[string]string{"Remote-Groups": "admin"}, 401},
		{"control character", "192.0.2.10:4000", "/", map[string]string{"Remote-User": "boss\x01"}, 401},
		{"other identity header", "192.0.2.10:4000", "/", map[string]string{"X-Forwarded-User": "admin"}, 401},
	}
	for _, c := range cases {
		if rec := serve(h, req(c.remote, c.path, c.headers)); rec.Code != c.want {
			t.Errorf("%s: status %d, want %d", c.name, rec.Code, c.want)
		}
	}
	if _, err := g.Identify(req("198.51.100.7:4000", "/", session)); !errors.Is(err, ErrUntrustedPeer) {
		t.Errorf("untrusted peer: %v", err)
	}
	// Renamed headers: the default names no longer count.
	rg, err := New(Config{Mode: HeaderMode, HeaderNames: HeaderNames{User: "X-Ts-User", Groups: "X-Ts-Groups"}})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := rg.Identify(req("192.0.2.10:1", "/", map[string]string{"X-Ts-User": "anna", "X-Ts-Groups": "a", "Remote-Kind": "user"})); err != nil || id.User != "anna" || !id.HasRole("a") {
		t.Errorf("renamed headers: %v", err)
	}
	if _, err := rg.Identify(req("192.0.2.10:1", "/", map[string]string{"Remote-User": "anna"})); ClassOf(err) != ClassUnauthenticated {
		t.Errorf("default name after renaming: class %v", ClassOf(err))
	}
}

// Spec v2: the account kind — renamed header, missing value, unauthenticated first, guard, token claim.
func TestAccountKind(t *testing.T) {
	g, err := New(Config{Mode: HeaderMode, HeaderNames: HeaderNames{Kind: "X-Account-Kind"}})
	if err != nil {
		t.Fatal(err)
	}
	req := func(headers map[string]string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return r
	}
	id, err := g.Identify(req(map[string]string{"Remote-User": "bot", "Remote-Auth": "apikey",
		"X-Account-Kind": "service", "Remote-Kind": "user"}))
	if err != nil || id.AccountKind != AccountService || !id.IsService() || id.IsSession() {
		t.Fatalf("renamed kind header: %v %+v", err, id)
	}
	_, err = g.Identify(req(map[string]string{"Remote-User": "anna", "Remote-Kind": "user"}))
	if ClassOf(err) != ClassHeader || !strings.Contains(err.Error(), "older than spec v2") ||
		strings.Contains(err.Error(), "anna") {
		t.Errorf("default kind name after renaming: %v", err)
	}
	if _, err := IdentityFromHeaders(http.Header{"Remote-Groups": {"admin"}}); ClassOf(err) != ClassUnauthenticated {
		t.Errorf("no user and no kind: %v, want unauthenticated", err)
	}
	person, err := IdentityFromHeaders(http.Header{"Remote-User": {"anna"}, "Remote-Auth": {"oauth"},
		"Remote-Kind": {"user"}})
	if err != nil || person.IsService() || person.Kind != KindToken || person.AccountKind != AccountUser {
		t.Fatalf("a paired service acting as a person: %v %+v", err, person)
	}
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for _, c := range []struct {
		kind AccountKind
		who  *Identity
		want int
	}{{AccountUser, person, 200}, {AccountUser, id, 403}, {AccountService, id, 200}, {AccountService, person, 403},
		{AccountUser, nil, 401}} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if c.who != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, c.who))
		}
		if rec := serve(RequireAccountKind(c.kind, ok), r); rec.Code != c.want {
			t.Errorf("RequireAccountKind(%s) for %+v: %d, want %d", c.kind, c.who, rec.Code, c.want)
		}
	}
	// Token mode: ts_kind is mandatory and exact.
	ks, err := NewStaticKeySet(testGateKey(t, "A"))
	if err != nil {
		t.Fatal(err)
	}
	tg := &Gate{mode: TokenMode, static: ks, rules: tokenRules{issuer: testIssuer, audience: testAudience},
		now: func() int64 { return testNow }}
	for name, change := range map[string]any{"missing": nil, "case": "User", "number": 1, "unknown": "admin"} {
		c := sessionClaims("editors")
		if change == nil {
			delete(c, "ts_kind")
		} else {
			c["ts_kind"] = change
		}
		if _, _, err := tg.Verify(context.Background(), mint(t, "A", c)); ClassOf(err) != ClassClaims {
			t.Errorf("ts_kind %s: %v, want claims", name, err)
		}
	}
	c := sessionClaims("editors")
	c["ts_kind"], c["ts_auth"] = "service", "apikey"
	if id, _, err := tg.Verify(context.Background(), mint(t, "A", c)); err != nil || !id.IsService() {
		t.Errorf("a service token: %v %+v", err, id)
	}
}

func TestGuardsWithoutMiddlewareFailClosed(t *testing.T) {
	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	for name, h := range map[string]http.Handler{
		"auth": RequireAuth(ok), "role": RequireRole("admin", ok), "session": RequireSession(ok),
	} {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.Header.Set("Remote-User", "admin")
		if rec := serve(h, r); rec.Code != 401 {
			t.Errorf("%s without middleware: %d, want 401", name, rec.Code)
		}
	}
	var zero Gate
	if _, err := zero.Identify(httptest.NewRequest(http.MethodGet, "/", nil)); err == nil {
		t.Error("a Gate not built by New identified a request")
	}
}

func TestErrorsIs(t *testing.T) {
	err := error(refuseKid(ClassExpired, "a033507ca61ad979", "detail"))
	if !errors.Is(err, ErrExpired) || errors.Is(err, ErrIssuer) {
		t.Error("errors.Is does not follow the class")
	}
	if ClassOf(errors.New("other")) != ClassInternal {
		t.Error("a foreign error is not internal")
	}
	if ParseGroups("") == nil {
		t.Error("ParseGroups returns nil")
	}
	var nilID *Identity
	if nilID.HasRole("x") || nilID.IsSession() {
		t.Error("a nil identity has a role or a session")
	}
}

func TestTopbarFetch(t *testing.T) {
	var gotCookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, c := range r.Cookies() {
			gotCookies = append(gotCookies, c.Name)
		}
		_, _ = io.WriteString(w, `{"brand":"B","signed_in":true,"name":"Anna","links":[{"title":"x","href":"javascript:alert(1)"}],"logout":{"href":"/auth/logout"}}`)
	}))
	defer srv.Close()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "__Host-tinysesam_session", Value: "s"})
	r.AddCookie(&http.Cookie{Name: "app_session", Value: "private"})
	tb, err := FetchTopbar(t.Context(), srv.Client(), srv.URL+"/auth/topbar.json", r)
	if err != nil || !tb.SignedIn || *tb.Name != "Anna" || len(tb.Links) != 0 || *tb.Logout != "/auth/logout" {
		t.Errorf("top bar %+v, %v", tb, err)
	}
	if len(gotCookies) != 1 || gotCookies[0] != "__Host-tinysesam_session" {
		t.Errorf("forwarded cookies %v, want only TinySesam's", gotCookies)
	}
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusBadGateway)
	}))
	defer bad.Close()
	if tb, err := FetchTopbar(t.Context(), nil, bad.URL, r); err == nil || tb.SignedIn {
		t.Errorf("a failed fetch counts as signed in: %+v", tb)
	}
}

// Only U+0020 is trimmed from a group (spec section 3.3): a no-break space or another Unicode space stays part of the
// name, so " admin" with U+00A0 is not admin.
func TestGroupsTrimOnlySpace(t *testing.T) {
	got := ParseGroups(" admin, admin  ,　")
	want := []string{" admin", "admin  ", "　"}
	if len(got) != len(want) {
		t.Fatalf("groups %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("groups %q, want %q", got, want)
		}
	}
}

// An identity an outer layer stored never survives a failed check of the gate.
func TestMiddlewareClearsOuterIdentity(t *testing.T) {
	outer := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := &Identity{User: "admin", ID: "2", Groups: []string{"admin"}, Kind: KindSession}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
		})
	}
	h := outer(app(fixedGate(t, nil)))
	r := httptest.NewRequest(http.MethodGet, "/admin", nil)
	r.AddCookie(&http.Cookie{Name: DefaultGateCookie, Value: mint(t, "X", sessionClaims("admin"))})
	if rec := serve(h, r); rec.Code != 401 {
		t.Errorf("refused token behind an outer identity: status %d, want 401", rec.Code)
	}
}
