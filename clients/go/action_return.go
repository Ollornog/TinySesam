package tinysesam

import (
	"crypto/subtle"
	"errors"
	"strings"
)

// The refusals of ParseActionReturn.
var (
	// ErrActionReturnInvalid: not a way back an action page gives — an unknown action or result, one of the three
	// names twice or missing, a value outside printable ASCII, a broken escape, a state outside the rule.
	ErrActionReturnInvalid = errors.New("tinysesam: action page way back refused: invalid")
	// ErrActionReturnState: the state that came back is not the one the application issued.
	ErrActionReturnState = errors.New("tinysesam: action page way back refused: state")
)

// ActionReturn is the way back an action page gave (spec section 8c): which action and how it ended — a hint for a
// message, never a proof. The application reads the account overview again.
type ActionReturn struct {
	// Action is one of the 21 action names of the register: the own actions and the administration's (admin_*).
	Action string `json:"action"`
	// Result is "done", "cancelled" or "unavailable".
	Result string `json:"result"`
}

// actionNames are the names an action page hands back in ts_action; actionResults the results in ts_result.
var (
	actionNames = map[string]bool{"username": true, "email": true, "password": true, "pin": true, "totp": true,
		"recovery_codes": true, "passkeys": true, "api_keys": true, "app_passwords": true, "sessions": true,
		"session_end": true, "programs": true, "services": true, "admin_totp_reset": true, "admin_lock": true,
		"admin_unlock": true, "admin_roles": true, "admin_key_revoke": true, "admin_program_revoke": true,
		"admin_session_end": true, "admin_signin_link": true}
	actionResults = map[string]bool{"done": true, "cancelled": true, "unavailable": true}
)

// ParseActionReturn reads the way back of an action page (spec section 8c) from the address the person came back on —
// an absolute URL, a path with its query (r.URL.RequestURI()) or the query alone with its "?"; the query is what lies
// between the first "?" and the first "#". state is the value the application issued with ActionURL ("" for none).
//
// It returns the way back, or nil and no error when the address carries neither ts_action nor ts_result (an ordinary
// visit). It refuses with an error wrapping ErrActionReturnInvalid a way back no action page gives, and with
// ErrActionReturnState when the state that came back is not the one issued (compared in constant time). Only the
// names ts_action, ts_result and state exactly as written count; every other parameter is the application's.
func ParseActionReturn(address, state string) (*ActionReturn, error) {
	if i := strings.IndexByte(address, '#'); i >= 0 {
		address = address[:i]
	}
	query := ""
	if i := strings.IndexByte(address, '?'); i >= 0 {
		query = address[i+1:]
	}
	found := map[string][]string{}
	for _, pair := range strings.Split(query, "&") {
		name, value, _ := strings.Cut(pair, "=")
		if name == "ts_action" || name == "ts_result" || name == "state" {
			found[name] = append(found[name], value)
		}
	}
	if len(found["ts_action"]) == 0 && len(found["ts_result"]) == 0 {
		return nil, nil
	}
	if len(found["ts_action"]) != 1 || len(found["ts_result"]) != 1 || len(found["state"]) > 1 {
		return nil, ErrActionReturnInvalid
	}
	action, okAction := formDecode(found["ts_action"][0])
	result, okResult := formDecode(found["ts_result"][0])
	back, okState := "", true
	if len(found["state"]) == 1 {
		back, okState = formDecode(found["state"][0])
	}
	if !okAction || !okResult || !okState || !actionNames[action] || !actionResults[result] ||
		len(back) > ActionStateMax || !printableASCII(back) {
		return nil, ErrActionReturnInvalid
	}
	if subtle.ConstantTimeCompare([]byte(back), []byte(state)) != 1 {
		return nil, ErrActionReturnState
	}
	return &ActionReturn{Action: action, Result: result}, nil
}

// formDecode decodes a query value as written: printable ASCII only, "+" a space, "%XX" an octet (either case).
func formDecode(raw string) (string, bool) {
	if !printableASCII(raw) {
		return "", false
	}
	var b strings.Builder
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; c {
		case '%':
			if i+2 >= len(raw) || !isHex(raw[i+1]) || !isHex(raw[i+2]) {
				return "", false
			}
			b.WriteByte(unhex(raw[i+1])<<4 | unhex(raw[i+2]))
			i += 2
		case '+':
			b.WriteByte(' ')
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= 'a':
		return c - 'a' + 10
	case c >= 'A':
		return c - 'A' + 10
	default:
		return c - '0'
	}
}
