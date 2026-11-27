// Command ex1 is example Ex1 (T-97): a Go application behind the TinySesam server with local accounts — sign-in,
// admin panel and account API without a line of Python in the application.
//
// TinySesam does everything around the people: the proxy asks it on every request (forward auth), its sign-in page
// signs them in, its admin panel and account page manage them. The application only reads the identity from the
// Remote-* headers the proxy sets (spec section 2.1, header mode) and creates its own accounts through the account
// API with an automation key of its service account. The stack is in deploy/ex1 (docker-compose.yml, tinysesam.toml).
//
//	TS_AUTH_URL=https://auth.example.com TS_API_KEY=tsk_… go run ./examples/ex1
//
// Optional: TS_API_URL (the account API server to server, default TS_AUTH_URL), TS_LISTEN (default 127.0.0.1:9000),
// TS_TRUSTED_PROXY (one more network the Remote-* headers may come from, besides loopback).
//
// TS_API_KEY is an automation key of the service account `svc-ex1` (panel → the account → API keys). Without it the
// account API part is switched off and the page says so.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"

	tinysesam "github.com/Ollornog/TinySesam/clients/go"
)

// accountAPI talks to TinySesam's account API (spec/provisioning-api.md) with the service account's key.
type accountAPI struct {
	base   string
	key    string
	client *http.Client
}

// account is the part of an account the application shows (spec/provisioning-api.md section 3).
type account struct {
	ID       int64    `json:"id"`
	Username string   `json:"username"`
	State    string   `json:"state"`
	Roles    []string `json:"roles"`
	Source   []string `json:"source"`
}

func (a *accountAPI) do(ctx context.Context, method, path, onBehalfOf string, body any) ([]byte, int, error) {
	var payload io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return nil, 0, err
		}
		payload = bytes.NewReader(raw)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, payload)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("X-Api-Key", a.key)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if onBehalfOf != "" {
		// The person in the application who asked for it (spec/provisioning-api.md section 1): TinySesam logs the
		// action under that account and checks it may act.
		req.Header.Set("TinySesam-On-Behalf-Of", onBehalfOf)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return out, resp.StatusCode, err
}

// list returns the first page of the accounts the application created.
func (a *accountAPI) list(ctx context.Context) ([]account, error) {
	body, status, err := a.do(ctx, http.MethodGet, "/auth/api/users?limit=50", "", nil)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("account API answered %d", status)
	}
	var page struct {
		Users []account `json:"users"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return nil, err
	}
	return page.Users, nil
}

// invite creates a person with the role ex1-member and returns the one-time sign-in link (only in this answer).
func (a *accountAPI) invite(ctx context.Context, actor, username string) (string, error) {
	body, status, err := a.do(ctx, http.MethodPost, "/auth/api/users", actor,
		map[string]any{"username": username, "roles": []string{"ex1-member"}})
	if err != nil {
		return "", err
	}
	if status != http.StatusCreated && status != http.StatusOK {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(body, &e)
		return "", fmt.Errorf("account API answered %d %s", status, e.Error)
	}
	var created struct {
		SigninURL string `json:"signin_url"`
	}
	if err := json.Unmarshal(body, &created); err != nil {
		return "", err
	}
	return created.SigninURL, nil
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	authURL := strings.TrimRight(os.Getenv("TS_AUTH_URL"), "/")
	if authURL == "" {
		log.Fatal("TS_AUTH_URL is not set (the address of TinySesam, e.g. https://auth.example.com)")
	}
	// The proxy of deploy/ex1 reaches the application over the compose network; only it may set Remote-* headers.
	proxies := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32"), netip.MustParsePrefix("::1/128")}
	if extra := os.Getenv("TS_TRUSTED_PROXY"); extra != "" {
		proxies = append(proxies, netip.MustParsePrefix(extra))
	}
	gate, err := tinysesam.New(tinysesam.Config{Mode: tinysesam.HeaderMode, TrustedProxies: proxies, Logger: logger})
	if err != nil {
		log.Fatal(err) // a configuration error stops the start
	}
	var api *accountAPI
	if key := os.Getenv("TS_API_KEY"); key != "" {
		// Server to server the application may talk to TinySesam directly (TS_API_URL, e.g. http://tinysesam:8000 in
		// the compose network); the links for the browser always use TS_AUTH_URL.
		base := strings.TrimRight(os.Getenv("TS_API_URL"), "/")
		if base == "" {
			base = authURL
		}
		api = &accountAPI{base: base, key: key, client: &http.Client{Timeout: 10 * time.Second}}
	}

	mux := http.NewServeMux()
	mux.Handle("/", tinysesam.RequireAuth(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, _ := tinysesam.FromContext(r.Context())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		// Names may hold any character but controls: escape them, and isolate them as bidi text.
		_, _ = fmt.Fprintf(w, "<h1>Ex1</h1><p>Signed in as <bdi>%s</bdi> (account %s).</p>"+
			"<p><a href=\"%s/auth/account\">Your account</a> · <a href=\"%s/auth/admin\">Admin panel</a> · "+
			"<a href=\"/members\">Members (account API)</a></p>",
			html.EscapeString(id.Name), html.EscapeString(id.ID), html.EscapeString(authURL), html.EscapeString(authURL))
	})))
	// The application's own accounts, through the account API. Changing them needs a browser session of a person
	// with the role ex1-staff (a token never passes).
	mux.Handle("/members", tinysesam.RequireRole("ex1-staff", tinysesam.RequireSession(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			if api == nil {
				http.Error(w, "TS_API_KEY is not set: the account API part of the example is off", http.StatusServiceUnavailable)
				return
			}
			id, _ := tinysesam.FromContext(r.Context())
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			if r.Method == http.MethodPost {
				link, err := api.invite(r.Context(), id.ID, r.FormValue("username"))
				if err != nil {
					logger.Warn("invite failed", "err", err)
					http.Error(w, "the account could not be created", http.StatusBadGateway)
					return
				}
				// Hand the link over by any channel; it works once and expires.
				_, _ = fmt.Fprintf(w, "<p>Created. One-time sign-in link: <code>%s</code></p>", html.EscapeString(link))
				return
			}
			users, err := api.list(r.Context())
			if err != nil {
				var timeout interface{ Timeout() bool }
				if errors.As(err, &timeout) && timeout.Timeout() {
					http.Error(w, "TinySesam did not answer in time", http.StatusGatewayTimeout)
					return
				}
				logger.Warn("list failed", "err", err)
				http.Error(w, "the accounts could not be read", http.StatusBadGateway)
				return
			}
			var b strings.Builder
			b.WriteString("<h1>Members</h1><ul>")
			for _, u := range users {
				fmt.Fprintf(&b, "<li><bdi>%s</bdi> — %s, %s, origin %s</li>", html.EscapeString(u.Username),
					html.EscapeString(u.State), html.EscapeString(strings.Join(u.Roles, ", ")),
					html.EscapeString(strings.Join(u.Source, " + ")))
			}
			// No CSRF token here: the form posts to the application itself; a real application adds its own.
			b.WriteString("</ul><form method=post><input name=username required><button>Invite</button></form>")
			_, _ = io.WriteString(w, b.String())
		}))))

	addr := os.Getenv("TS_LISTEN")
	if addr == "" {
		addr = "127.0.0.1:9000"
	}
	srv := &http.Server{Addr: addr, Handler: gate.Middleware(mux), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
