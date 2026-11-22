package tinysesam

import (
	"crypto/ed25519"
	"encoding/json"
	"strconv"
	"strings"
)

// Limits of token mode (spec section 4).
const (
	MaxTokenBytes  = 4096 // a larger token is malformed
	MaxLeeway      = 60   // the largest configurable clock leeway in seconds
	MaxLifetime    = 3600 // the largest exp - nbf in seconds
	maxSafeInteger = 1<<53 - 1

	tokenAlgorithm = "EdDSA"
	tokenType      = "tinysesam-gate+jwt"
)

var identityClaims = []string{"ts_user", "ts_name", "ts_email", "ts_groups", "ts_id", "ts_auth"}

// Claims of a valid gate token. Raw holds every claim as decoded (numbers as json.Number); unknown claims are
// ignored by the checks but kept there.
type Claims struct {
	Issuer    string
	Audience  []string
	Subject   string
	IssuedAt  int64
	NotBefore int64
	Expiry    int64
	JTI       string
	Raw       map[string]any
}

// parsedToken is what steps 1-5 of the checking order decide before a key is chosen.
type parsedToken struct {
	signingInput []byte
	payload      []byte
	signature    []byte
	kid          string
}

// parseToken runs steps 1-5 of spec section 4.4: size, structure, header JSON, header members, signature length.
func parseToken(jws string) (*parsedToken, error) {
	if len(jws) > MaxTokenBytes {
		return nil, refuse(ClassMalformed, "token too large")
	}
	parts := strings.Split(jws, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" {
		return nil, refuse(ClassMalformed, "not three segments")
	}
	head, ok1 := decodeSegment(parts[0])
	payload, ok2 := decodeSegment(parts[1])
	sig, ok3 := decodeSegment(parts[2])
	if !ok1 || !ok2 || !ok3 {
		return nil, refuse(ClassMalformed, "not strict base64url")
	}
	hv, err := decodeStrictJSON(head)
	if err != nil {
		return nil, refuse(ClassMalformed, "header is not strict JSON")
	}
	hdr, ok := hv.(map[string]any)
	if !ok {
		return nil, refuse(ClassMalformed, "header is not a JSON object")
	}
	for name := range hdr {
		if name != "alg" && name != "typ" && name != "kid" {
			return nil, refuse(ClassHeader, "forbidden header member")
		}
	}
	// The algorithm is this client's constant; the header may only confirm it.
	if alg, ok := hdr["alg"].(string); !ok || alg != tokenAlgorithm {
		return nil, refuse(ClassHeader, "alg is not EdDSA")
	}
	if typ, ok := hdr["typ"].(string); !ok || !asciiEqualFold(typ, tokenType) {
		return nil, refuse(ClassHeader, "wrong typ")
	}
	kid, ok := hdr["kid"].(string)
	if !ok || !validKid(kid) {
		return nil, refuse(ClassKid, "kid missing or not 16 lowercase hex digits")
	}
	if len(sig) != ed25519.SignatureSize {
		return nil, refuseKid(ClassSignature, kid, "signature is not 64 bytes")
	}
	return &parsedToken{
		signingInput: []byte(parts[0] + "." + parts[1]),
		payload:      payload,
		signature:    sig,
		kid:          kid,
	}, nil
}

func validKid(kid string) bool {
	if len(kid) != 16 {
		return false
	}
	for i := 0; i < len(kid); i++ {
		c := kid[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// tokenRules are the values the claims are checked against; all come from configuration, never from the request.
type tokenRules struct {
	issuer   string
	audience string
	leeway   int64
}

// finishToken runs steps 7-10: the signature, then (only then) the payload, its claims and their values.
func finishToken(p *parsedToken, key ed25519.PublicKey, rules tokenRules, now int64) (*Claims, error) {
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, p.signingInput, p.signature) {
		return nil, refuseKid(ClassSignature, p.kid, "verification failed")
	}
	pv, err := decodeStrictJSON(p.payload)
	if err != nil {
		return nil, refuseKid(ClassMalformed, p.kid, "payload is not strict JSON")
	}
	m, ok := pv.(map[string]any)
	if !ok {
		return nil, refuseKid(ClassMalformed, p.kid, "payload is not a JSON object")
	}
	c, cerr := checkClaims(m, rules, now)
	if cerr != nil {
		cerr.Kid = p.kid
		return nil, cerr
	}
	return c, nil
}

func checkClaims(m map[string]any, rules tokenRules, now int64) (*Claims, *Error) {
	bad := func(detail string) (*Claims, *Error) { return nil, refuse(ClassClaims, detail) }
	iss, ok := m["iss"].(string)
	if !ok {
		return bad("iss")
	}
	sub, ok := m["sub"].(string)
	if !ok {
		return bad("sub")
	}
	var aud []string
	switch v := m["aud"].(type) {
	case string:
		aud = []string{v}
	case []any:
		if len(v) == 0 {
			return bad("aud")
		}
		for _, a := range v {
			s, ok := a.(string)
			if !ok {
				return bad("aud")
			}
			aud = append(aud, s)
		}
	default:
		return bad("aud")
	}
	iat, ok1 := intClaim(m["iat"])
	nbf, ok2 := intClaim(m["nbf"])
	exp, ok3 := intClaim(m["exp"])
	if !ok1 || !ok2 || !ok3 {
		return bad("iat, nbf or exp")
	}
	jti := ""
	if v, present := m["jti"]; present {
		s, ok := v.(string)
		if !ok {
			return bad("jti")
		}
		jti = s
	}
	for _, name := range identityClaims {
		if v, present := m[name]; present {
			s, ok := v.(string)
			if !ok {
				return bad("identity claim type")
			}
			if hasControl(s) {
				return bad("control character in an identity claim")
			}
		}
	}
	if sub == "" || hasControl(sub) {
		return bad("sub")
	}
	if v, present := m["ts_id"]; present && v.(string) != sub {
		return bad("ts_id differs from sub")
	}
	if iat > nbf {
		return bad("iat later than nbf")
	}
	if iss != rules.issuer {
		return nil, refuse(ClassIssuer, "")
	}
	hit := false
	for _, a := range aud {
		if a == rules.audience {
			hit = true
			break
		}
	}
	if !hit {
		return nil, refuse(ClassAudience, "")
	}
	if exp <= nbf || exp-nbf > MaxLifetime {
		return nil, refuse(ClassLifetime, "")
	}
	if nbf > now+rules.leeway {
		return nil, refuse(ClassNotYetValid, "")
	}
	if exp+rules.leeway <= now {
		return nil, refuse(ClassExpired, "")
	}
	return &Claims{Issuer: iss, Audience: aud, Subject: sub, IssuedAt: iat, NotBefore: nbf, Expiry: exp, JTI: jti,
		Raw: m}, nil
}

// intClaim accepts a JSON number without fraction or exponent from 0 to 2^53 - 1; not a boolean, not a string.
func intClaim(v any) (int64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	s := string(n)
	if strings.ContainsAny(s, ".eE") {
		return 0, false
	}
	i, err := strconv.ParseInt(s, 10, 64)
	if err != nil || i < 0 || i > maxSafeInteger {
		return 0, false
	}
	return i, true
}

// identityFromClaims maps the claims of a valid token to the identity (spec section 4.1); a missing claim gives an
// empty value.
func identityFromClaims(c *Claims) *Identity {
	str := func(name string) string {
		s, _ := c.Raw[name].(string)
		return s
	}
	a, k := kindOf(str("ts_auth"))
	return &Identity{User: str("ts_user"), Name: str("ts_name"), Email: str("ts_email"),
		Groups: ParseGroups(str("ts_groups")), ID: c.Subject, Auth: a, Kind: k}
}
