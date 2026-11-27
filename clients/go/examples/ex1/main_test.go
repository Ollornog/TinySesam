package main

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	tinysesam "github.com/Ollornog/TinySesam/clients/go"
)

// T-101 acceptance of Ex1: it registers its manifest at start and checks the permissions by the client.
func TestRegisterAtStart(t *testing.T) {
	var path, key string
	var body map[string][]map[string]any
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, key = r.Method+" "+r.URL.Path, r.Header.Get("X-Api-Key")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"added":["ex1.members.read","ex1.members.invite"],"updated":[],"returned":[],"orphaned":[]}`))
	}))
	defer ts.Close()
	register(context.Background(), slog.New(slog.NewTextHandler(io.Discard, nil)),
		&accountAPI{base: ts.URL, key: "tsk_ex1", client: ts.Client()})
	if path != "PUT /auth/api/apps/ex1/permissions" || key != "tsk_ex1" || len(body["permissions"]) != 2 {
		t.Fatalf("register sent %q key %q body %v", path, key, body)
	}
}

func TestMembersNeedThePermissions(t *testing.T) {
	gate, err := tinysesam.New(tinysesam.Config{Mode: tinysesam.HeaderMode,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}})
	if err != nil {
		t.Fatal(err)
	}
	h := gate.Middleware(newMux(slog.New(slog.NewTextHandler(io.Discard, nil)), nil, "https://auth.example.com"))
	call := func(method, perms string) int {
		r := httptest.NewRequest(method, "/members", nil)
		r.RemoteAddr = "192.0.2.1:4711"
		r.Header.Set("Remote-User", "anna")
		r.Header.Set("Remote-Id", "7")
		r.Header.Set("Remote-Auth", "session")
		r.Header.Set("Remote-Kind", "user")
		if perms != "" {
			r.Header.Set("Remote-Permissions", perms)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	// Without the account API (api nil) a permitted request reaches the handler's 503; a refused one stops at 403.
	for _, c := range []struct {
		method, perms string
		want          int
	}{
		{http.MethodGet, "", http.StatusForbidden},
		{http.MethodGet, "ex1.members.invite", http.StatusForbidden},
		{http.MethodGet, "EX1.MEMBERS.READ", http.StatusForbidden},
		{http.MethodGet, "ex1.members.read", http.StatusServiceUnavailable},
		{http.MethodPost, "ex1.members.read", http.StatusForbidden},
		{http.MethodPost, "ex1.members.read,ex1.members.invite", http.StatusServiceUnavailable},
	} {
		if got := call(c.method, c.perms); got != c.want {
			t.Errorf("%s with %q: %d, want %d", c.method, c.perms, got, c.want)
		}
	}
}
