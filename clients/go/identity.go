package tinysesam

import (
	"net/http"
	"strings"
	"unicode/utf8"
)

// Kind says whether a request came from a browser session or from a token (OAuth, API key, app password).
type Kind string

// Kinds of a request (spec section 2.3).
const (
	KindSession Kind = "session"
	KindToken   Kind = "token"
)

// Identity is who made the request, the same in both modes (spec section 1). Key your own records by ID: it is the
// only value that survives a rename. Name, User and Email may hold any character except controls — bidirectional
// overrides and zero-width characters included — so escape them for HTML and isolate them as bidi text.
type Identity struct {
	User   string   `json:"user"`   // the account name (sign-in identifier)
	Name   string   `json:"name"`   // the display name, may be empty
	Email  string   `json:"email"`  // may be empty
	Groups []string `json:"groups"` // the roles; never nil
	ID     string   `json:"id"`     // the account ID, decimal digits
	Auth   string   `json:"auth"`   // session, oauth, apikey, app-password, or empty
	Kind   Kind     `json:"kind"`   // KindSession only when Auth is exactly "session"
}

// HasRole reports whether role is one of the groups, compared exactly: no case folding, no normalization, and no
// role implied by "admin". Whether an admin passes every role check is the application's decision.
func (i *Identity) HasRole(role string) bool {
	if i == nil {
		return false
	}
	for _, g := range i.Groups {
		if g == role {
			return true
		}
	}
	return false
}

// IsSession reports whether the request came from a browser session. The groups of a token request are incomplete
// on purpose (a token never carries admin): never conclude from a missing group that the account lacks it.
func (i *Identity) IsSession() bool {
	return i != nil && i.Kind == KindSession
}

var authKinds = map[string]bool{"session": true, "oauth": true, "apikey": true, "app-password": true}

// kindOf maps the value of Remote-Auth or ts_auth to the reported auth and the kind: session only for exactly
// "session"; an empty, missing or unknown value counts as a token and is reported empty.
func kindOf(auth string) (string, Kind) {
	if !authKinds[auth] {
		return "", KindToken
	}
	if auth == "session" {
		return auth, KindSession
	}
	return auth, KindToken
}

// ParseGroups reads Remote-Groups or ts_groups (spec section 3.3): split at every comma, remove leading and trailing
// spaces (U+0020 only), drop empty and repeated entries, keep the order. There is no escape mechanism.
func ParseGroups(s string) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, part := range strings.Split(s, ",") {
		g := strings.Trim(part, " ")
		if g == "" || seen[g] {
			continue
		}
		seen[g] = true
		out = append(out, g)
	}
	return out
}

// HeaderNames are the six headers of header mode. TinySesam's forward_headers can rename them; an empty field keeps
// the default name.
type HeaderNames struct {
	User, Name, Email, Groups, ID, Auth string
}

// DefaultHeaderNames are the names TinySesam sends unless forward_headers renames them.
var DefaultHeaderNames = HeaderNames{
	User: "Remote-User", Name: "Remote-Name", Email: "Remote-Email",
	Groups: "Remote-Groups", ID: "Remote-Id", Auth: "Remote-Auth",
}

func (n HeaderNames) withDefaults() HeaderNames {
	pick := func(v, d string) string {
		if v == "" {
			return d
		}
		return v
	}
	d := DefaultHeaderNames
	return HeaderNames{
		User: pick(n.User, d.User), Name: pick(n.Name, d.Name), Email: pick(n.Email, d.Email),
		Groups: pick(n.Groups, d.Groups), ID: pick(n.ID, d.ID), Auth: pick(n.Auth, d.Auth),
	}
}

func (n HeaderNames) list() []string {
	return []string{n.User, n.Name, n.Email, n.Groups, n.ID, n.Auth}
}

// IdentityFromHeaders reads the identity from the Remote-* headers with the default names (spec section 2.2). It
// does not check where the request came from: use it only behind a proxy that fulfils the duties of spec section
// 2.1, or use a [Gate] in header mode with TrustedProxies.
func IdentityFromHeaders(h http.Header) (*Identity, error) {
	return identityFromHeaders(h, DefaultHeaderNames)
}

func identityFromHeaders(h http.Header, names HeaderNames) (*Identity, error) {
	order := names.list()
	values := make([]string, len(order))
	for i, name := range order {
		var found []string
		// Field names are case-insensitive; a hand-built http.Header can hold two spellings as two keys.
		for key, vs := range h {
			if asciiEqualFoldBoth(key, name) {
				found = append(found, vs...)
			}
		}
		if len(found) == 0 {
			continue
		}
		if len(found) > 1 {
			return nil, refuse(ClassHeader, "a header occurs more than once")
		}
		v := found[0]
		if !utf8.ValidString(v) {
			return nil, refuse(ClassHeader, "a header is not UTF-8")
		}
		if hasControl(v) {
			return nil, refuse(ClassHeader, "control character in a header")
		}
		values[i] = v
	}
	user, name, email, groups, id, auth := values[0], values[1], values[2], values[3], values[4], values[5]
	if user == "" {
		return nil, refuse(ClassUnauthenticated, "no user header")
	}
	if id != "" && !allASCIIDigits(id) {
		return nil, refuse(ClassHeader, "the id header is not a number")
	}
	a, k := kindOf(auth)
	return &Identity{User: user, Name: name, Email: email, Groups: ParseGroups(groups), ID: id, Auth: a, Kind: k}, nil
}

func allASCIIDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// asciiEqualFoldBoth compares two header field names ignoring ASCII case only.
func asciiEqualFoldBoth(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if x >= 'A' && x <= 'Z' {
			x += 'a' - 'A'
		}
		if y >= 'A' && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
