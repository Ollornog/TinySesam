package tinysesam

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Limits of an approval confirmation (spec/approval-token.md).
const (
	ApprovalTokenType   = "tinysesam-approval+jwt" // the typ of a confirmation, never tinysesam-gate+jwt
	MaxApprovalLifetime = 300                      // the largest exp - nbf in seconds
	MaxApprovalLeeway   = 30                       // the largest configurable clock leeway in seconds

	maxApprovalText = 128 // the longest jti, nonce, act.sub
	maxApprovalSub  = 1000
	maxApprovalAMR  = 32
	maxApprovalType = 100
)

// Error classes of the approval check beyond those of the gate client (spec/approval-token.md section 5). Every class
// means the same to the application: do not carry the action out.
const (
	ClassApprovalType   ErrorClass = "approval_type"   // another action
	ClassApprovalFields ErrorClass = "approval_fields" // other fields: a name, a JSON type or a value
	ClassSubject        ErrorClass = "subject"         // another account
	ClassNonce          ErrorClass = "nonce"           // another browser session (browser entry)
	ClassReplay         ErrorClass = "replay"          // the confirmation was used before
)

// Sentinels of the approval classes for errors.Is.
var (
	ErrApprovalType   = &Error{Class: ClassApprovalType}
	ErrApprovalFields = &Error{Class: ClassApprovalFields}
	ErrSubject        = &Error{Class: ClassSubject}
	ErrNonce          = &Error{Class: ClassNonce}
	ErrReplay         = &Error{Class: ClassReplay}
)

// approvalClaimNames are the claims every confirmation carries (step 9); nonce is optional.
var approvalClaimNames = []string{"iss", "aud", "sub", "iat", "nbf", "exp", "jti", "auth_time", "amr", "act",
	"authorization_details", "ts_payload_sha256"}

// JTIStore remembers the jti of every confirmation the application accepted (spec/approval-token.md section 7).
// Remember stores jti atomically and reports true only the first time; it may forget the entry after until (Unix
// seconds). It must be shared by every process of the application: a database table with a unique key, written with
// one INSERT — not process memory when several workers run. An error refuses the confirmation (fails closed).
type JTIStore interface {
	Remember(ctx context.Context, jti string, until int64) (bool, error)
}

// JTIStoreFunc adapts a function to JTIStore.
type JTIStoreFunc func(ctx context.Context, jti string, until int64) (bool, error)

// Remember calls f.
func (f JTIStoreFunc) Remember(ctx context.Context, jti string, until int64) (bool, error) {
	return f(ctx, jti, until)
}

// ApprovalConfig configures the check of approval confirmations. Issuer and AppID come from configuration, never from
// the request. Exactly one key source: KeySet (a fixed approval key set, from ParseJWKS) or JWKSURL (normally
// https://<auth host>/auth/approvals/jwks.json, fetched under the rules of spec/gate-client.md section 5). Never the
// gate key set: a JWKSURL ending in /gate/jwks.json is refused.
type ApprovalConfig struct {
	// Issuer is TinySesam's base_url without a trailing slash.
	Issuer string
	// AppID is the application's own id (apps.<id> in TinySesam's configuration).
	AppID string
	// KeySet is a fixed approval key set.
	KeySet *KeySet
	// JWKSURL is the approval key set to fetch; https, plain http only to a loopback address.
	JWKSURL string
	// HTTPClient fetches JWKSURL; nil means a client of its own. Redirects to another host are not followed.
	HTTPClient *http.Client
	// LeewaySeconds is the clock leeway, 0 to MaxApprovalLeeway (default 0).
	LeewaySeconds int
}

// ApprovalVerifier checks approval confirmations (spec/approval-token.md section 4). Create one at start-up and share
// it; it is safe for concurrent use.
type ApprovalVerifier struct {
	issuer string
	appID  string
	leeway int64
	static *KeySet
	jwks   *jwksCache
	now    func() int64
}

// NewApprovalVerifier checks the configuration; an error here must stop the start.
func NewApprovalVerifier(cfg ApprovalConfig) (*ApprovalVerifier, error) {
	if cfg.Issuer == "" || cfg.AppID == "" {
		return nil, configError("approvals need Issuer and AppID")
	}
	if cfg.LeewaySeconds < 0 || cfg.LeewaySeconds > MaxApprovalLeeway {
		return nil, configError(fmt.Sprintf("LeewaySeconds must be 0 to %d for approvals", MaxApprovalLeeway))
	}
	v := &ApprovalVerifier{issuer: cfg.Issuer, appID: cfg.AppID, leeway: int64(cfg.LeewaySeconds),
		now: func() int64 { return time.Now().Unix() }}
	switch {
	case cfg.KeySet != nil && cfg.JWKSURL != "":
		return nil, configError("give either KeySet or JWKSURL, not both")
	case cfg.KeySet != nil:
		if cfg.HTTPClient != nil {
			return nil, configError("HTTPClient without JWKSURL")
		}
		if len(cfg.KeySet.Kids()) == 0 {
			return nil, configError("the approval key set has no usable key")
		}
		v.static = cfg.KeySet
	case cfg.JWKSURL != "":
		if err := checkJWKSURL(cfg.JWKSURL); err != nil {
			return nil, err
		}
		if u, _ := url.Parse(cfg.JWKSURL); strings.HasSuffix(strings.TrimRight(u.Path, "/"), "/gate/jwks.json") {
			return nil, configError("JWKSURL is the GATE key set; confirmations have their own " +
				"(https://<auth host>/auth/approvals/jwks.json)")
		}
		v.jwks = newJWKSCache(httpFetcher(cfg.HTTPClient, cfg.JWKSURL))
	default:
		return nil, configError("approvals need KeySet or JWKSURL")
	}
	return v, nil
}

// ApprovalExpect is the action the application stored when it asked — never taken from the confirmation.
type ApprovalExpect struct {
	// Type is the action type (authorization_details[0].type).
	Type string
	// Fields are the field values exactly as sent: string, bool or an integer type (json.Number with an integer value
	// too). Names, JSON types and values must match: 1, "1" and true are three different values.
	Fields map[string]any
	// Subject is the account the application acts for (a decimal id as a string, for example Remote-Id).
	Subject string
	// Nonce is the state kept in the person's session for a browser entry; "" when the application sent none.
	Nonce string
}

// ApprovalClaims are the claims of a valid confirmation. Fields hold string, int64 or bool values; Raw holds every
// claim as decoded (numbers as json.Number), unknown claims included.
type ApprovalClaims struct {
	Issuer    string
	Audience  string
	Subject   string
	IssuedAt  int64
	NotBefore int64
	Expiry    int64
	AuthTime  int64
	JTI       string
	AMR       []string
	Actor     string // act.sub, "app:<application id>"
	Type      string
	Fields    map[string]any
	Nonce     string
	Raw       map[string]any
}

// Verify checks a confirmation in the order of spec/approval-token.md section 4 and, as the last step, writes its jti
// into store. Any error means: do not carry the action out; ClassOf names the class for the log (never log the
// token). After a nil error run the application's own rules again (still the owner? does the thing still exist?),
// then carry the action out.
func (v *ApprovalVerifier) Verify(ctx context.Context, token string, want ApprovalExpect, store JTIStore) (claims *ApprovalClaims, err error) {
	defer func() {
		if r := recover(); r != nil {
			claims, err = nil, refuse(ClassInternal, "unexpected failure")
		}
	}()
	if store == nil {
		return nil, refuse(ClassInternal, "no jti store")
	}
	now := v.now()
	p, err := parseJWS(token, ApprovalTokenType)
	if err != nil {
		return nil, err
	}
	var key ed25519.PublicKey
	if v.jwks != nil {
		key, err = v.jwks.lookup(ctx, p.kid, now)
		if err != nil {
			return nil, err
		}
	} else if key = v.static.lookup(p.kid); key == nil {
		return nil, refuseKid(ClassKid, p.kid, "kid not in the approval key set")
	}
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, p.signingInput, p.signature) {
		return nil, refuseKid(ClassSignature, p.kid, "verification failed")
	}
	pv, jerr := decodeStrictJSON(p.payload)
	m, ok := pv.(map[string]any)
	if jerr != nil || !ok {
		return nil, refuseKid(ClassMalformed, p.kid, "payload is not a strict JSON object")
	}
	c, cerr := v.checkApproval(ctx, m, want, store, now)
	if cerr != nil {
		cerr.Kid = p.kid
		return nil, cerr
	}
	return c, nil
}

func (v *ApprovalVerifier) checkApproval(ctx context.Context, m map[string]any, want ApprovalExpect, store JTIStore, now int64) (*ApprovalClaims, *Error) {
	c, e := approvalClaims(m)
	if e != nil {
		return nil, e
	}
	// Step 10: values.
	if c.Issuer != v.issuer {
		return nil, refuse(ClassIssuer, "")
	}
	if c.Audience != v.appID {
		return nil, refuse(ClassAudience, "")
	}
	if c.Expiry <= c.NotBefore || c.Expiry-c.NotBefore > MaxApprovalLifetime {
		return nil, refuse(ClassLifetime, "")
	}
	if c.NotBefore > now+v.leeway {
		return nil, refuse(ClassNotYetValid, "")
	}
	if c.Expiry+v.leeway <= now {
		return nil, refuse(ClassExpired, "")
	}
	// Step 11: the binding to the stored action.
	if c.Type != want.Type {
		return nil, refuse(ClassApprovalType, "")
	}
	if !sameFields(c.Fields, want.Fields) {
		return nil, refuse(ClassApprovalFields, "")
	}
	if c.Subject != want.Subject {
		return nil, refuse(ClassSubject, "")
	}
	if want.Nonce != "" && c.Nonce != want.Nonce {
		return nil, refuse(ClassNonce, "")
	}
	// Step 12, last: once.
	first, err := store.Remember(ctx, c.JTI, c.Expiry+v.leeway)
	if err != nil {
		return nil, refuse(ClassInternal, "the jti store failed")
	}
	if !first {
		return nil, refuse(ClassReplay, "")
	}
	return c, nil
}

// approvalText is a non-empty string of at most limit code points without a C0 control character or DEL.
func approvalText(v any, limit int) (string, bool) {
	s, ok := v.(string)
	if !ok || s == "" || utf8.RuneCountInString(s) > limit || hasControl(s) {
		return "", false
	}
	return s, true
}

// approvalClaims is step 9: presence, types, aud as one string, exactly one entry, the digest, the order of the times.
func approvalClaims(m map[string]any) (*ApprovalClaims, *Error) {
	bad := func(detail string) (*ApprovalClaims, *Error) { return nil, refuse(ClassClaims, detail) }
	for _, name := range approvalClaimNames {
		if _, ok := m[name]; !ok {
			return bad(name + " missing")
		}
	}
	c := &ApprovalClaims{Raw: m}
	var ok bool
	if c.Issuer, ok = m["iss"].(string); !ok {
		return bad("iss")
	}
	if c.Subject, ok = approvalText(m["sub"], maxApprovalSub); !ok {
		return bad("sub")
	}
	for name, dst := range map[string]*int64{"iat": &c.IssuedAt, "nbf": &c.NotBefore, "exp": &c.Expiry,
		"auth_time": &c.AuthTime} {
		if *dst, ok = intClaim(m[name]); !ok {
			return bad(name)
		}
	}
	if c.JTI, ok = approvalText(m["jti"], maxApprovalText); !ok {
		return bad("jti")
	}
	amr, ok := m["amr"].([]any)
	if !ok || len(amr) == 0 {
		return bad("amr")
	}
	for _, a := range amr {
		s, ok := approvalText(a, maxApprovalAMR)
		if !ok {
			return bad("amr")
		}
		c.AMR = append(c.AMR, s)
	}
	act, ok := m["act"].(map[string]any)
	if !ok {
		return bad("act")
	}
	if c.Actor, ok = approvalText(act["sub"], maxApprovalText); !ok {
		return bad("act")
	}
	digest, ok := m["ts_payload_sha256"].(string)
	if !ok {
		return bad("ts_payload_sha256")
	}
	if n, present := m["nonce"]; present {
		if c.Nonce, ok = approvalText(n, maxApprovalText); !ok {
			return bad("nonce")
		}
	}
	// aud is ONE string, the application's id — never an array, which could name several applications.
	if c.Audience, ok = m["aud"].(string); !ok {
		return bad("aud is not a string")
	}
	details, ok := m["authorization_details"].([]any)
	if !ok || len(details) != 1 {
		return bad("authorization_details is not one entry")
	}
	entry, ok := details[0].(map[string]any)
	if !ok {
		return bad("authorization_details[0]")
	}
	if c.Type, ok = approvalText(entry["type"], maxApprovalType); !ok {
		return bad("authorization_details[0].type")
	}
	c.Fields = map[string]any{}
	for name, raw := range entry {
		val, ok := fieldValue(raw)
		if !ok {
			return bad("a field value of an unsupported type")
		}
		if name != "type" {
			c.Fields[name] = val
		}
	}
	if digest != PayloadDigest(entry) {
		return bad("ts_payload_sha256 does not match the entry")
	}
	if c.IssuedAt > c.NotBefore || c.AuthTime > c.IssuedAt {
		return bad("iat, nbf and auth_time out of order")
	}
	return c, nil
}

// fieldValue accepts a field value of an entry: a string, a boolean or an integer within ±(2^53 - 1) — nothing else.
// Integers come back as int64.
func fieldValue(v any) (any, bool) {
	switch t := v.(type) {
	case string, bool:
		return t, true
	case json.Number:
		return signedInt(string(t))
	}
	return nil, false
}

func signedInt(s string) (any, bool) {
	if strings.ContainsAny(s, ".eE") {
		return nil, false
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil || i < -maxSafeInteger || i > maxSafeInteger {
		return nil, false
	}
	return i, true
}

// expectedValue converts a field value of ApprovalExpect to the form of ApprovalClaims.Fields; false for a type a
// confirmation can never carry (it then matches nothing).
func expectedValue(v any) (any, bool) {
	switch t := v.(type) {
	case string, bool:
		return t, true
	case int:
		return int64(t), true
	case int8:
		return int64(t), true
	case int16:
		return int64(t), true
	case int32:
		return int64(t), true
	case int64:
		return t, true
	case uint8:
		return int64(t), true
	case uint16:
		return int64(t), true
	case uint32:
		return int64(t), true
	case json.Number:
		return signedInt(string(t))
	}
	return nil, false
}

// sameFields compares names, JSON types and values exactly: 1, "1" and true are three different values.
func sameFields(got, want map[string]any) bool {
	if len(got) != len(want) {
		return false
	}
	for name, w := range want {
		g, present := got[name]
		ev, ok := expectedValue(w)
		if !present || !ok || g != ev {
			return false
		}
	}
	return true
}

// PayloadDigest is ts_payload_sha256 of an authorization_details entry: SHA-256 over its canonical form (RFC 8785
// for string, integer and boolean values, spec/approval-token.md section 6), base64url without padding.
func PayloadDigest(entry map[string]any) string {
	sum := sha256.Sum256([]byte(canonicalEntry(entry)))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// canonicalEntry writes the members sorted by name (code point order, which is byte order in UTF-8), no whitespace,
// strings with only the escapes of RFC 8785, integers in plain decimal, true and false.
func canonicalEntry(entry map[string]any) string {
	names := make([]string, 0, len(entry))
	for k := range entry {
		names = append(names, k)
	}
	sort.Strings(names)
	var b strings.Builder
	b.WriteByte('{')
	for i, k := range names {
		if i > 0 {
			b.WriteByte(',')
		}
		canonicalString(&b, k)
		b.WriteByte(':')
		switch t := entry[k].(type) {
		case string:
			canonicalString(&b, t)
		case bool:
			b.WriteString(strconv.FormatBool(t))
		case json.Number:
			if i, ok := signedInt(string(t)); ok {
				b.WriteString(strconv.FormatInt(i.(int64), 10))
			} else {
				b.WriteString(string(t))
			}
		case int64:
			b.WriteString(strconv.FormatInt(t, 10))
		}
	}
	b.WriteByte('}')
	return b.String()
}

func canonicalString(b *strings.Builder, s string) {
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\b':
			b.WriteString(`\b`)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\f':
			b.WriteString(`\f`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20:
			fmt.Fprintf(b, `\u%04x`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
}
