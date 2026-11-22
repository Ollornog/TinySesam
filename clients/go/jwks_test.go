package tinysesam

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func jwksBody(t testing.TB, names ...string) []byte {
	t.Helper()
	var keys []any
	for _, n := range names {
		pub := testPrivateKey(t, n).Public().(ed25519.PublicKey)
		keys = append(keys, map[string]any{"kty": "OKP", "crv": "Ed25519", "kid": KeyID(pub),
			"x": base64.RawURLEncoding.EncodeToString(pub), "alg": "EdDSA", "use": "sig"})
	}
	b, err := json.Marshal(map[string]any{"keys": keys})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func jwksGate(t testing.TB, url string) *Gate {
	t.Helper()
	g, err := New(Config{Mode: TokenMode, Issuer: testIssuer, Audience: testAudience, JWKSURL: url})
	if err != nil {
		t.Fatal(err)
	}
	g.now = func() int64 { return testNow }
	return g
}

// A server that accepts the connection and never answers: the request returns within the fetch deadline,
// key_unavailable, and a second request meanwhile does not wait longer either (spec section 5, rule 2).
func TestJWKSServerNeverAnswers(t *testing.T) {
	t.Parallel()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var held []net.Conn
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			held = append(held, c)
			mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		for _, c := range held {
			_ = c.Close()
		}
		mu.Unlock()
	})
	g := jwksGate(t, "http://"+ln.Addr().String()+"/auth/gate/jwks.json")
	tok := mint(t, "A", sessionClaims("editors"))
	limit := FetchTimeout + 2*time.Second
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(delay time.Duration) {
			defer wg.Done()
			time.Sleep(delay)
			start := time.Now()
			_, _, err := g.Verify(context.Background(), tok)
			if took := time.Since(start); took > limit {
				t.Errorf("request waited %v for keys, limit %v", took, limit)
			}
			if ClassOf(err) != ClassKeyUnavailable {
				t.Errorf("class %v, want key_unavailable", ClassOf(err))
			}
		}(time.Duration(i) * time.Second)
	}
	wg.Wait()
}

// A body above 64 KiB is a failed fetch; the same document below the limit is accepted (the control).
func TestJWKSBodyLimit(t *testing.T) {
	t.Parallel()
	doc := jwksBody(t, "A")
	pad := func(n int) []byte {
		return append(append([]byte{}, doc...), []byte(strings.Repeat(" ", n-len(doc)))...)
	}
	for _, tc := range []struct {
		size int
		want ErrorClass
	}{{MaxJWKSBytes, ""}, {MaxJWKSBytes + 1, ClassKeyUnavailable}} {
		body := pad(tc.size)
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(body)
		}))
		g := jwksGate(t, srv.URL)
		_, _, err := g.Verify(context.Background(), mint(t, "A", sessionClaims("editors")))
		srv.Close()
		if tc.want == "" && err != nil {
			t.Errorf("body of %d bytes refused: %v", tc.size, err)
		}
		if tc.want != "" && ClassOf(err) != tc.want {
			t.Errorf("body of %d bytes: class %v, want %v", tc.size, ClassOf(err), tc.want)
		}
	}
}

// Concurrent requests on a cold cache share one fetch and all succeed.
func TestJWKSConcurrentRequestsShareOneFetch(t *testing.T) {
	t.Parallel()
	doc := jwksBody(t, "A")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		time.Sleep(300 * time.Millisecond)
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(doc)
	}))
	defer srv.Close()
	g := jwksGate(t, srv.URL)
	tok := mint(t, "A", sessionClaims("editors"))
	var wg sync.WaitGroup
	var refused atomic.Int32
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := g.Verify(context.Background(), tok); err != nil {
				refused.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := hits.Load(); n != 1 {
		t.Errorf("%d fetches, want 1", n)
	}
	if n := refused.Load(); n != 0 {
		t.Errorf("%d of 32 concurrent requests refused", n)
	}
}

// A redirect to another host is not followed: the fetch fails.
func TestJWKSRedirectToAnotherHostRefused(t *testing.T) {
	t.Parallel()
	doc := jwksBody(t, "A")
	var foreignHits atomic.Int32
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		_, _ = w.Write(doc)
	}))
	defer foreign.Close()
	// 127.0.0.1 and localhost are two hosts for the redirect rule.
	foreignURL := strings.Replace(foreign.URL, "127.0.0.1", "localhost", 1)
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreignURL+"/jwks.json", http.StatusFound)
	}))
	defer origin.Close()
	g := jwksGate(t, origin.URL)
	_, _, err := g.Verify(context.Background(), mint(t, "A", sessionClaims("editors")))
	if ClassOf(err) != ClassKeyUnavailable {
		t.Errorf("class %v, want key_unavailable", ClassOf(err))
	}
	if foreignHits.Load() != 0 {
		t.Error("the redirect to another host was followed")
	}
}

// The token's own key material is never used: a token signed by the attacker key X with a jwk header is refused
// even though the JWKS server is reachable.
func TestJWKSKeyRotationAndForeignKey(t *testing.T) {
	t.Parallel()
	doc := jwksBody(t, "A", "B")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(doc) }))
	defer srv.Close()
	g := jwksGate(t, srv.URL)
	for _, name := range []string{"A", "B"} {
		if _, _, err := g.Verify(context.Background(), mint(t, name, sessionClaims("editors"))); err != nil {
			t.Errorf("key %s refused: %v", name, err)
		}
	}
	if _, _, err := g.Verify(context.Background(), mint(t, "X", sessionClaims("editors"))); ClassOf(err) != ClassKid {
		t.Errorf("attacker key: class %v, want kid", ClassOf(err))
	}
}

func TestFreshness(t *testing.T) {
	for cc, want := range map[string]int64{
		"": 300, "max-age=120": 120, "no-cache, max-age=0": 60, "public, max-age=86400": 3600,
		"MAX-AGE=90": 90, `max-age="90"`: 300, "max-age=99999999999999999999999": 3600, "s-maxage=10": 300,
	} {
		if got := freshness(cc); got != want {
			t.Errorf("freshness(%q) = %d, want %d", cc, got, want)
		}
	}
}
