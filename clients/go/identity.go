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

// AccountKind says what the account is (spec version 2): a person or a service account. It is independent of
// Kind — a paired service acting as a person is KindToken and AccountUser.
type AccountKind string

// Account kinds (Remote-Kind, ts_kind).
const (
	AccountUser    AccountKind = "user"
	AccountService AccountKind = "service"
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
	// AccountKind is AccountUser or AccountService, never empty: a request without it is refused (spec v2).
	AccountKind AccountKind `json:"account_kind"`
	// Permissions are the account's permissions for this application (spec section 3.4, Remote-Permissions or
	// ts_perms); never nil, empty when TinySesam sends none — which means "holds none", never "unknown".
	Permissions []string `json:"permissions"`
}

// HasPermission reports whether permission is one of the permissions, compared exactly (spec section 3.4): no case
// folding, no wildcard, and neither "admin" nor a role implies one.
func (i *Identity) HasPermission(permission string) bool {
	if i == nil {
		return false
	}
	for _, p := range i.Permissions {
		if p == permission {
			return true
		}
	}
	return false
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

// IsService reports whether the account is a service account (Remote-Kind or ts_kind exactly "service").
func (i *Identity) IsService() bool {
	return i != nil && i.AccountKind == AccountService
}

// checkAccountKind applies the account-kind rules of spec version 2 (section 2.2 rules 6–8, section 4.4 step 9) to the
// value of Remote-Kind or ts_kind ("" when missing) and of Remote-Auth or ts_auth. It returns the kind, or the reason
// for the refusal — never a value, and never a guessed "user".
func checkAccountKind(kind, auth string) (AccountKind, string) {
	if kind == "" {
		return "", "Remote-Kind/ts_kind missing (TinySesam or proxy older than spec v2?)"
	}
	if kind != string(AccountUser) && kind != string(AccountService) {
		return "", "Remote-Kind/ts_kind is not exactly user or service"
	}
	if kind == string(AccountService) && auth == "session" {
		return "", "a service account has no session"
	}
	return AccountKind(kind), ""
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

// HeaderNames are the eight headers of header mode. TinySesam's forward_headers can rename them; an empty field keeps
// the default name. Permissions is optional on the wire: missing or empty means none (spec section 3.4).
type HeaderNames struct {
	User, Name, Email, Groups, ID, Auth, Kind, Permissions string
}

// DefaultHeaderNames are the names TinySesam sends unless forward_headers renames them.
var DefaultHeaderNames = HeaderNames{
	User: "Remote-User", Name: "Remote-Name", Email: "Remote-Email",
	Groups: "Remote-Groups", ID: "Remote-Id", Auth: "Remote-Auth", Kind: "Remote-Kind",
	Permissions: "Remote-Permissions",
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
		Kind: pick(n.Kind, d.Kind), Permissions: pick(n.Permissions, d.Permissions),
	}
}

func (n HeaderNames) list() []string {
	return []string{n.User, n.Name, n.Email, n.Groups, n.ID, n.Auth, n.Kind, n.Permissions}
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
	user, name, email, groups, id, auth, kind, perms := values[0], values[1], values[2], values[3], values[4],
		values[5], values[6], values[7]
	if user == "" {
		return nil, refuse(ClassUnauthenticated, "no user header")
	}
	if id != "" && !allASCIIDigits(id) {
		return nil, refuse(ClassHeader, "the id header is not a number")
	}
	ak, why := checkAccountKind(kind, auth)
	if why != "" {
		return nil, refuse(ClassHeader, why)
	}
	a, k := kindOf(auth)
	return &Identity{User: user, Name: name, Email: email, Groups: ParseGroups(groups), ID: id, Auth: a, Kind: k,
		AccountKind: ak, Permissions: ParseGroups(perms)}, nil
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
