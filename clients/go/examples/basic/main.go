// Command basic is a minimal application behind TinySesam's gate in header mode.
//
// It listens on the loopback address only, so the proxy on the same machine is the only way in, and accepts the
// Remote-* headers from that proxy only. Run it behind a proxy that fulfils spec section 2.1 (for example the
// Caddyfile templates in deploy/forward-auth):
//
//	go run ./examples/basic
//
// Token mode instead (fixed key from `tinysesam gate-key`):
//
//	tinysesam.Config{Mode: tinysesam.TokenMode, Issuer: "https://auth.example.com",
//		Audience: "app.example.com", GateKeys: []string{os.Getenv("GATE_KEY")}}
package main

import (
	"fmt"
	"html"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"time"

	tinysesam "github.com/Ollornog/TinySesam/clients/go"
)

func main() {
	gate, err := tinysesam.New(tinysesam.Config{
		Mode:           tinysesam.HeaderMode,
		TrustedProxies: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")},
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		log.Fatal(err) // a configuration error stops the start
	}

	mux := http.NewServeMux()
	mux.Handle("/", tinysesam.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := tinysesam.FromContext(r.Context())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Names may hold any character but controls: escape them, and isolate them as bidi text.
		_, _ = fmt.Fprintf(w, "<p>Hello <bdi>%s</bdi> (account %s)</p>", html.EscapeString(id.Name),
			html.EscapeString(id.ID))
	})))
	mux.Handle("/reports", tinysesam.RequireRole("editors", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "reports for editors")
	})))
	// Changing the account needs a browser session: a token (OAuth, API key, app password) never passes.
	mux.Handle("/settings", tinysesam.RequireSession(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "settings")
	})))

	srv := &http.Server{Addr: "127.0.0.1:8080", Handler: gate.Middleware(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
