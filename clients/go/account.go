package tinysesam

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// Account is the person's own security state as TinySesam's account page shows it, reduced to what an application
// may render on its own settings page (spec section 8a). Signed out, every pointer is nil. Signed in, Account, SignIn,
// Sessions, Programs and Links are always set; a nil pointer inside them means "missing or of the wrong type" — for
// TOTP, Passkeys, OAuth, Services, AppPasswords "not offered by this installation". Every string is text, never markup;
// every href is an absolute http(s) URL or a path starting with exactly one slash. Changes happen on TinySesam's
// account page, which the links lead to. Do not cache it across sessions.
type Account struct {
	SignedIn  bool              `json:"signed_in"`
	Account   *AccountName      `json:"account"`
	SignIn    *AccountSignIn    `json:"sign_in"`
	Sessions  *AccountSessions  `json:"sessions"`
	Programs  *AccountPrograms  `json:"programs"`
	Approvals *AccountApprovals `json:"approvals"` // nil when approvals are off (or the count is unusable)
	// Permissions are the account's permissions for the application of the host (spec section 8a); nil on a host of
	// no application.
	Permissions *AccountPermissions `json:"permissions"`
	Links       *AccountLinks       `json:"links"`
	// Actions are the addresses of the own action pages (spec section 8c); build the address to send the person to
	// with ActionURL.
	Actions *AccountActions `json:"actions"`
}

// AccountPermissions names the application (nil when missing or no text) and the account's permissions for it
// (never nil; an entry that is no string is dropped).
type AccountPermissions struct {
	App   *string  `json:"app"`
	Names []string `json:"names"`
}

// AccountName names the account. Source says where it comes from: "local", "oidc", "saml", "ldap" (two or more =
// a mixed account; an unknown text is for the application to ignore); nil when missing or no list.
type AccountName struct {
	Username    *string  `json:"username"`
	DisplayName *string  `json:"display_name"`
	Source      []string `json:"source"`
}

// AccountSignIn are the sign-in methods.
type AccountSignIn struct {
	Password *string          `json:"password"` // "set", "unset", "directory"; nil when passwords are off
	TOTP     *AccountTOTP     `json:"totp"`
	Passkeys *AccountPasskeys `json:"passkeys"`
	PIN      *bool            `json:"pin"`
}

// AccountTOTP is the state of the authenticator app.
type AccountTOTP struct {
	Enabled      *bool  `json:"enabled"`
	RecoveryLeft *int64 `json:"recovery_left"`
	RecoveryLow  *bool  `json:"recovery_low"`
}

// AccountPasskeys are the passkeys; Items is never nil.
type AccountPasskeys struct {
	Count *int64       `json:"count"`
	Items []AccountUse `json:"items"`
}

// AccountUse is a named thing with its creation and last use (Unix seconds; nil = never used).
type AccountUse struct {
	Name      *string `json:"name"`
	CreatedAt *int64  `json:"created_at"`
	LastUsed  *int64  `json:"last_used"`
}

// AccountAppPassword is a live app password.
type AccountAppPassword struct {
	Name      *string `json:"name"`
	CreatedAt *int64  `json:"created_at"`
	LastUsed  *int64  `json:"last_used"`
	ExpiresAt *int64  `json:"expires_at"`
}

// AccountSessions are the browser sessions; Items is never nil.
type AccountSessions struct {
	Count *int64           `json:"count"`
	Items []AccountSession `json:"items"`
}

// AccountSession is one session. Device is a coarse "browser · system" or nil; Current is true for the session of
// this request, false for the others, nil when the answer does not know. Handle is the session handle (opaque text,
// never the token); End is the action page that ends exactly this session (nil for the session of the request):
// ActionURL(*s.End, returnTo, state) is the address to send the person to.
type AccountSession struct {
	CreatedAt *int64  `json:"created_at"`
	LastSeen  *int64  `json:"last_seen"`
	Method    *string `json:"method"`
	Device    *string `json:"device"`
	Current   *bool   `json:"current"`
	Handle    *string `json:"handle"`
	End       *string `json:"end"`
}

// AccountPrograms are the connected programs. A nil list means "not offered here", an empty one "offered, none".
type AccountPrograms struct {
	OAuth         []AccountUse         `json:"oauth"`
	Services      []AccountUse         `json:"services"`
	AppPasswords  []AccountAppPassword `json:"app_passwords"`
	APIKeysActive *int64               `json:"api_keys_active"`
}

// AccountApprovals is how many approvals wait for this account.
type AccountApprovals struct {
	Pending int64 `json:"pending"`
}

// AccountLinks lead to TinySesam's account page and its sections; nil when not offered (or not a safe link).
type AccountLinks struct {
	Account      *string `json:"account"`
	Sessions     *string `json:"sessions"`
	TOTP         *string `json:"totp"`
	Passkeys     *string `json:"passkeys"`
	Devices      *string `json:"devices"`
	AppPasswords *string `json:"app_passwords"`
	Services     *string `json:"services"`
	Approvals    *string `json:"approvals"`
}

// AccountActions are the own action pages of spec section 8c; nil when not offered to this account (or not a safe
// link).
type AccountActions struct {
	Username      *string `json:"username"`
	Email         *string `json:"email"`
	Password      *string `json:"password"`
	PIN           *string `json:"pin"`
	TOTP          *string `json:"totp"`
	RecoveryCodes *string `json:"recovery_codes"`
	Passkeys      *string `json:"passkeys"`
	APIKeys       *string `json:"api_keys"`
	AppPasswords  *string `json:"app_passwords"`
	Sessions      *string `json:"sessions"`
	Programs      *string `json:"programs"`
	Services      *string `json:"services"`
}

// ParseAccount normalizes the body of a 200 answer of /.tinysesam/account.json or /auth/account.json (spec section
// 8a). Anything but a JSON object with signed_in true (the boolean) counts as signed out; a member of the wrong type
// reads as missing, an unsafe href as nil, unknown members are dropped.
func ParseAccount(body []byte) Account {
	v, err := decodeStrictJSON(body)
	if err != nil {
		return Account{}
	}
	data, ok := v.(map[string]any)
	if !ok {
		return Account{}
	}
	if signed, _ := data["signed_in"].(bool); !signed {
		return Account{}
	}
	account, signIn := group(data["account"]), group(data["sign_in"])
	sessions, programs, links := group(data["sessions"]), group(data["programs"]), group(data["links"])
	actions := group(data["actions"])
	out := Account{
		SignedIn: true,
		Account: &AccountName{Username: text(account["username"]), DisplayName: text(account["display_name"]),
			Source: texts(account["source"])},
		SignIn:   &AccountSignIn{Password: text(signIn["password"]), PIN: flag(signIn["pin"])},
		Sessions: &AccountSessions{Count: count(sessions["count"]), Items: []AccountSession{}},
		Programs: &AccountPrograms{OAuth: offeredUses(programs["oauth"]), Services: offeredUses(programs["services"]),
			APIKeysActive: count(programs["api_keys_active"])},
		Links: &AccountLinks{Account: href(links["account"]), Sessions: href(links["sessions"]),
			TOTP: href(links["totp"]), Passkeys: href(links["passkeys"]), Devices: href(links["devices"]),
			AppPasswords: href(links["app_passwords"]), Services: href(links["services"]),
			Approvals: href(links["approvals"])},
		Actions: &AccountActions{Username: href(actions["username"]), Email: href(actions["email"]),
			Password: href(actions["password"]), PIN: href(actions["pin"]), TOTP: href(actions["totp"]),
			RecoveryCodes: href(actions["recovery_codes"]), Passkeys: href(actions["passkeys"]),
			APIKeys: href(actions["api_keys"]), AppPasswords: href(actions["app_passwords"]),
			Sessions: href(actions["sessions"]), Programs: href(actions["programs"]),
			Services: href(actions["services"])},
	}
	if t, ok := signIn["totp"].(map[string]any); ok {
		out.SignIn.TOTP = &AccountTOTP{Enabled: flag(t["enabled"]), RecoveryLeft: count(t["recovery_left"]),
			RecoveryLow: flag(t["recovery_low"])}
	}
	if p, ok := signIn["passkeys"].(map[string]any); ok {
		out.SignIn.Passkeys = &AccountPasskeys{Count: count(p["count"]), Items: uses(p["items"])}
	}
	for _, e := range objects(sessions["items"]) {
		out.Sessions.Items = append(out.Sessions.Items, AccountSession{CreatedAt: count(e["created_at"]),
			LastSeen: count(e["last_seen"]), Method: text(e["method"]), Device: text(e["device"]),
			Current: flag(e["current"]), Handle: text(e["handle"]), End: href(e["end"])})
	}
	if list, ok := programs["app_passwords"].([]any); ok {
		out.Programs.AppPasswords = []AccountAppPassword{}
		for _, e := range objects(list) {
			out.Programs.AppPasswords = append(out.Programs.AppPasswords, AccountAppPassword{Name: text(e["name"]),
				CreatedAt: count(e["created_at"]), LastUsed: count(e["last_used"]), ExpiresAt: count(e["expires_at"])})
		}
	}
	if a, ok := data["approvals"].(map[string]any); ok {
		if n := count(a["pending"]); n != nil {
			out.Approvals = &AccountApprovals{Pending: *n}
		}
	}
	if p, ok := data["permissions"].(map[string]any); ok {
		names := []string{}
		if list, ok := p["names"].([]any); ok {
			for _, n := range list {
				if s, ok := n.(string); ok {
					names = append(names, s)
				}
			}
		}
		out.Permissions = &AccountPermissions{App: text(p["app"]), Names: names}
	}
	return out
}

// FetchAccount fetches the own account overview server-side for the request r: a GET to accountURL (normally
// https://<auth host>/auth/account.json, or /.tinysesam/account.json on the application's host) carrying only
// TinySesam's cookies of r, with a deadline of FetchTimeout and a body limit of 64 KiB. On any failure — a 401 (no
// full browser session), a 404 or a 429 included — it returns the signed-out Account and the error. Do not cache the
// result across sessions.
func FetchAccount(ctx context.Context, client *http.Client, accountURL string, r *http.Request) (Account, error) {
	body, err := fetchTinySesamJSON(ctx, client, accountURL, r)
	if err != nil {
		return Account{}, err
	}
	return ParseAccount(body), nil
}

// group is a member that is always an object in the answer: anything else reads as an empty one.
func group(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func text(v any) *string {
	if s, ok := v.(string); ok {
		return &s
	}
	return nil
}

// texts keeps the string entries of a list, in order; anything that is no list is nil, an empty list stays empty.
func texts(v any) []string {
	list, ok := v.([]any)
	if !ok {
		return nil
	}
	out := []string{}
	for _, e := range list {
		if s, ok := e.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func flag(v any) *bool {
	if b, ok := v.(bool); ok {
		return &b
	}
	return nil
}

// count is a count or a time: a JSON integer from 0 to 2^53 - 1.
func count(v any) *int64 {
	if n, ok := intClaim(v); ok {
		return &n
	}
	return nil
}

func href(v any) *string {
	if s, ok := v.(string); ok && safeHref(s) {
		return &s
	}
	return nil
}

// objects keeps the object entries of a list; anything that is no list counts as none.
func objects(v any) []map[string]any {
	list, _ := v.([]any)
	var out []map[string]any
	for _, e := range list {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

// uses is a list of named things that is always a list.
func uses(v any) []AccountUse {
	out := []AccountUse{}
	for _, e := range objects(v) {
		out = append(out, AccountUse{Name: text(e["name"]), CreatedAt: count(e["created_at"]),
			LastUsed: count(e["last_used"])})
	}
	return out
}

// offeredUses is nil when the answer has no list (not offered), otherwise the list.
func offeredUses(v any) []AccountUse {
	if _, ok := v.([]any); !ok {
		return nil
	}
	return uses(v)
}

// ErrActionURL wraps every refusal of ActionURL.
var ErrActionURL = errors.New("tinysesam: action page address refused")

// ActionStateMax is the longest state an action page carries back (spec section 8c).
const ActionStateMax = 128

// ActionURL builds the address of an action page with the way back (spec section 8c): href is a member of
// Account.Actions or a session's End (ending exactly that session), returnTo the absolute http(s) URL on the
// application's own host to come back to, state an optional value of the application ("" for none; printable ASCII,
// at most ActionStateMax characters). Send the person there by navigation; the page leads back with ts_action,
// ts_result and state. It refuses (an error wrapping ErrActionURL) an href that fails the rule of spec section 8 or
// carries a fragment, a returnTo that is no absolute http(s) URL of printable ASCII, and a state outside the rule.
func ActionURL(href, returnTo, state string) (string, error) {
	refuse := func(why string) (string, error) {
		return "", fmt.Errorf("%w: %s", ErrActionURL, why)
	}
	if !safeHref(href) || strings.Contains(href, "#") {
		return refuse("the href is no action page address")
	}
	lower := strings.ToLower(returnTo)
	if !strings.HasPrefix(lower, "https://") && !strings.HasPrefix(lower, "http://") || !printableASCII(returnTo) {
		return refuse("returnTo must be an absolute http(s) URL in printable ASCII")
	}
	if len(state) > ActionStateMax || !printableASCII(state) {
		return refuse(fmt.Sprintf("state is printable ASCII of at most %d characters", ActionStateMax))
	}
	sep := "?"
	if strings.Contains(href, "?") {
		sep = "&"
	}
	out := href + sep + "return=" + queryEscape(returnTo)
	if state != "" {
		out += "&state=" + queryEscape(state)
	}
	return out, nil
}

// printableASCII is true when every byte lies in 0x21-0x7e (true for "").
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x21 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// queryEscape writes every byte but A-Z a-z 0-9 - . _ ~ as %XX with upper-case hex digits.
func queryEscape(s string) string {
	const hex = "0123456789ABCDEF"
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '.' || c == '_' ||
			c == '~' {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hex[c>>4])
			b.WriteByte(hex[c&15])
		}
	}
	return b.String()
}
