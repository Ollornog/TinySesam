package tinysesam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"unicode"
)

// TopbarLink is one link of the top bar. Title is text, never markup.
type TopbarLink struct {
	Title string `json:"title"`
	Href  string `json:"href"`
}

// Topbar is TinySesam's top bar data reduced to what an application may render (spec section 8). Every href is an
// absolute http(s) URL or a path starting with exactly one slash; titles and the name are text, never markup.
type Topbar struct {
	Brand      string       `json:"brand"`
	SignedIn   bool         `json:"signed_in"`
	Name       *string      `json:"name"`
	Links      []TopbarLink `json:"links"`
	Account    *string      `json:"account"`
	AdminPanel *string      `json:"admin_panel"`
	Logout     *string      `json:"logout"`
}

// ParseTopbar normalizes the body of /.tinysesam/topbar.json or /auth/topbar.json. Anything but a JSON object with
// signed_in true (the boolean) and a string name counts as signed out; unsafe links are dropped.
func ParseTopbar(body []byte) Topbar {
	out := Topbar{Links: []TopbarLink{}}
	v, err := decodeStrictJSON(body)
	if err != nil {
		return out
	}
	data, ok := v.(map[string]any)
	if !ok {
		return out
	}
	if b, ok := data["brand"].(string); ok {
		out.Brand = b
	}
	name, ok := data["name"].(string)
	if signed, _ := data["signed_in"].(bool); !signed || !ok {
		return out
	}
	out.SignedIn, out.Name = true, &name
	links, _ := data["links"].([]any)
	for _, l := range links {
		m, ok := l.(map[string]any)
		if !ok {
			continue
		}
		title, ok1 := m["title"].(string)
		href, ok2 := m["href"].(string)
		if ok1 && ok2 && safeHref(href) {
			out.Links = append(out.Links, TopbarLink{Title: title, Href: href})
		}
	}
	shown := func(slot string) *string {
		m, ok := data[slot].(map[string]any)
		if !ok {
			return nil
		}
		if s, _ := m["shown"].(bool); !s {
			return nil
		}
		if href, ok := m["href"].(string); ok && safeHref(href) {
			return &href
		}
		return nil
	}
	out.Account, out.AdminPanel = shown("account"), shown("admin_panel")
	if m, ok := data["logout"].(map[string]any); ok {
		if href, ok := m["href"].(string); ok && safeHref(href) {
			out.Logout = &href
		}
	}
	return out
}

// safeHref accepts an absolute http/https URL or a path that starts with exactly one slash (not // or /\), without
// whitespace or control characters.
func safeHref(href string) bool {
	if hasControl(href) || strings.ContainsFunc(href, unicode.IsSpace) {
		return false
	}
	if hasPrefixFold(href, "https://") || hasPrefixFold(href, "http://") {
		return true
	}
	return strings.HasPrefix(href, "/") && !strings.HasPrefix(href, "//") && !strings.HasPrefix(href, "/\\")
}

func hasPrefixFold(s, lowerPrefix string) bool {
	return len(s) >= len(lowerPrefix) && asciiEqualFold(s[:len(lowerPrefix)], lowerPrefix)
}

var errTopbarStatus = errors.New("tinysesam: top bar answered with a status other than 200")

// FetchTopbar fetches the top bar data server-side for the request r: a GET to topbarURL (normally
// https://<auth host>/auth/topbar.json) carrying only TinySesam's cookies of r (tinysesam_* and __Host-tinysesam_*),
// with a deadline of FetchTimeout and a body limit of 64 KiB. On any failure it returns the signed-out top bar and
// the error. Do not cache the result across sessions.
func FetchTopbar(ctx context.Context, client *http.Client, topbarURL string, r *http.Request) (Topbar, error) {
	signedOut := Topbar{Links: []TopbarLink{}}
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, topbarURL, nil)
	if err != nil {
		return signedOut, err
	}
	req.Header.Set("Accept", "application/json")
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, "tinysesam_") || strings.HasPrefix(c.Name, "__Host-tinysesam_") {
			req.AddCookie(c)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return signedOut, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return signedOut, errTopbarStatus
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return signedOut, err
	}
	if len(body) > MaxJWKSBytes {
		return signedOut, errBodyTooLarge
	}
	return ParseTopbar(body), nil
}
