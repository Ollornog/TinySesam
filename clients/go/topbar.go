package tinysesam

import (
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
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
	MenuLinks  []TopbarLink `json:"menu_links"` // the entries of the account menu (spec v2); [] when there are none
	Account    *string      `json:"account"`
	AdminPanel *string      `json:"admin_panel"`
	Logout     *string      `json:"logout"`
	// Approvals is set when TinySesam has approvals switched on and the answer carries a count of at least 0 and a
	// safe link (spec section 8). Show the number with a word ("Approvals (2)"), never as a coloured dot alone.
	Approvals *TopbarApprovals `json:"approvals"`
	// Frame is what the shell draws on the application's host (spec section 8d); always set.
	Frame TopbarFrame `json:"frame"`
}

// TopbarFrame is the part frame of the top bar (spec section 8d): Layout "top" or "side", the application's Name and
// Icon (an image address: http(s), a path or a data:image/...; draw it as an image) in its app frame (nil without
// one), Home the way back and Links the frame's links the person may see (both only signed in; Links is never nil).
// Without an app frame: the bar on top, nothing else.
type TopbarFrame struct {
	Layout string       `json:"layout"`
	Name   *string      `json:"name"`
	Icon   *string      `json:"icon"`
	Home   *string      `json:"home"`
	Links  []TopbarLink `json:"links"`
}

// dataIconRE is frame.icon as a data: address: one of the image types apps[id].icon takes, then printable ASCII
// without a quote, < > or a backslash.
var dataIconRE = regexp.MustCompile(`^data:image/(?:png|gif|jpeg|webp|svg\+xml)[;,][!#-&(-;=?-\[\]-~]+$`)

// frameIcon keeps an href of spec section 8 or a data:image/ address of the five types; anything else is nil.
func frameIcon(v any) *string {
	if s, ok := v.(string); ok && (safeHref(s) || dataIconRE.MatchString(s)) {
		return &s
	}
	return nil
}

// emptyTopbar is the signed-out bar without brand and without a frame.
func emptyTopbar() Topbar {
	return Topbar{Links: []TopbarLink{}, MenuLinks: []TopbarLink{}, Frame: topbarFrame(nil, false)}
}

// topbarFrame normalizes the member frame: layout exactly "side" or else "top", name text or nil; home and links only
// signed in (a safe href, the safe {title, href} entries). Anything that is no object reads as no frame.
func topbarFrame(raw any, signedIn bool) TopbarFrame {
	out := TopbarFrame{Layout: "top", Links: []TopbarLink{}}
	m, ok := raw.(map[string]any)
	if !ok {
		return out
	}
	if l, _ := m["layout"].(string); l == "side" {
		out.Layout = "side"
	}
	out.Name, out.Icon = text(m["name"]), frameIcon(m["icon"])
	if signedIn {
		out.Home, out.Links = href(m["home"]), topbarLinks(m["links"])
	}
	return out
}

// TopbarApprovals is how many approvals wait for this account and where to decide them.
type TopbarApprovals struct {
	Pending int64  `json:"pending"`
	Href    string `json:"href"`
}

// ParseTopbar normalizes the body of /.tinysesam/topbar.json or /auth/topbar.json. Anything but a JSON object with
// signed_in true (the boolean) and a string name counts as signed out; unsafe links are dropped.
func ParseTopbar(body []byte) Topbar {
	out := emptyTopbar()
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
		out.Frame = topbarFrame(data["frame"], false)
		return out
	}
	out.Frame = topbarFrame(data["frame"], true)
	out.SignedIn, out.Name = true, &name
	out.Links, out.MenuLinks = topbarLinks(data["links"]), topbarLinks(data["menu_links"])
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
	if m, ok := data["approvals"].(map[string]any); ok {
		pending, ok1 := intClaim(m["pending"])
		href, ok2 := m["href"].(string)
		if ok1 && ok2 && safeHref(href) {
			out.Approvals = &TopbarApprovals{Pending: pending, Href: href}
		}
	}
	return out
}

// topbarLinks keeps the safe {title, href} entries of a link list; anything that is no list counts as none.
func topbarLinks(raw any) []TopbarLink {
	out := []TopbarLink{}
	list, _ := raw.([]any)
	for _, l := range list {
		m, ok := l.(map[string]any)
		if !ok {
			continue
		}
		title, ok1 := m["title"].(string)
		href, ok2 := m["href"].(string)
		if ok1 && ok2 && safeHref(href) {
			out = append(out, TopbarLink{Title: title, Href: href})
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

var errTopbarStatus = errors.New("tinysesam: TinySesam answered with a status other than 200")

// FetchTopbar fetches the top bar data server-side for the request r: a GET to topbarURL (normally
// https://<auth host>/auth/topbar.json) carrying only TinySesam's cookies of r (tinysesam_* and __Host-tinysesam_*),
// with a deadline of FetchTimeout and a body limit of 64 KiB. On any failure it returns the signed-out top bar and
// the error. Do not cache the result across sessions.
func FetchTopbar(ctx context.Context, client *http.Client, topbarURL string, r *http.Request) (Topbar, error) {
	body, err := fetchTinySesamJSON(ctx, client, topbarURL, r)
	if err != nil {
		return emptyTopbar(), err
	}
	return ParseTopbar(body), nil
}

// fetchTinySesamJSON is the server-side GET of the top bar and the account overview: only TinySesam's cookies of r,
// a deadline of FetchTimeout, a body limit of 64 KiB, status 200 only.
func fetchTinySesamJSON(ctx context.Context, client *http.Client, target string, r *http.Request) ([]byte, error) {
	if client == nil {
		client = http.DefaultClient
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	for _, c := range r.Cookies() {
		if strings.HasPrefix(c.Name, "tinysesam_") || strings.HasPrefix(c.Name, "__Host-tinysesam_") {
			req.AddCookie(c)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, errTopbarStatus
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > MaxJWKSBytes {
		return nil, errBodyTooLarge
	}
	return body, nil
}
