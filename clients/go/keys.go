package tinysesam

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
)

// MaxJWKSKeys is the largest number of entries a key set document may have.
const MaxJWKSKeys = 32

// KeyID is the kid of a public key: the first 16 hex digits of SHA-256 over its 32 raw bytes.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// KeySet maps kid to an Ed25519 public key. It comes from configuration (fixed keys or a JWKS URL), never from a
// token.
type KeySet struct {
	kids []string
	keys map[string]ed25519.PublicKey
}

// Kids returns the kids in the order of the source.
func (s *KeySet) Kids() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.kids...)
}

func (s *KeySet) lookup(kid string) ed25519.PublicKey {
	if s == nil {
		return nil
	}
	return s.keys[kid]
}

// ParseGateKey reads the output of `tinysesam gate-key`: 32 raw bytes in standard Base64 (the proxy's sign_key).
func ParseGateKey(b64 string) (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, refuse(ClassKeyUnavailable, "a gate key must be 32 bytes in standard Base64")
	}
	return ed25519.PublicKey(raw), nil
}

// NewStaticKeySet builds a key set from one or more gate keys (before and after a rotation).
func NewStaticKeySet(gateKeys ...string) (*KeySet, error) {
	if len(gateKeys) == 0 {
		return nil, refuse(ClassKeyUnavailable, "no gate key")
	}
	s := &KeySet{keys: map[string]ed25519.PublicKey{}}
	for _, k := range gateKeys {
		pub, err := ParseGateKey(k)
		if err != nil {
			return nil, err
		}
		kid := KeyID(pub)
		if _, dup := s.keys[kid]; dup {
			continue
		}
		s.kids = append(s.kids, kid)
		s.keys[kid] = pub
	}
	return s, nil
}

// ParseJWKS reads a key set document (spec section 4.3). Unusable entries are skipped, two usable entries with the
// same kid make that kid unusable; a document that is not strict JSON, not an object, has no keys array or more than
// MaxJWKSKeys entries is ErrJWKSInvalid. The result may be empty.
func ParseJWKS(doc []byte) (*KeySet, error) {
	v, err := decodeStrictJSON(doc)
	if err != nil {
		return nil, refuse(ClassJWKSInvalid, "not strict JSON")
	}
	obj, ok := v.(map[string]any)
	if !ok {
		return nil, refuse(ClassJWKSInvalid, "not an object")
	}
	entries, ok := obj["keys"].([]any)
	if !ok || len(entries) > MaxJWKSKeys {
		return nil, refuse(ClassJWKSInvalid, "no keys array or too many entries")
	}
	type usable struct {
		kid string
		pub ed25519.PublicKey
	}
	var found []usable
	count := map[string]int{}
	for _, e := range entries {
		if kid, pub, ok := jwkEntry(e); ok {
			found = append(found, usable{kid, pub})
			count[kid]++
		}
	}
	s := &KeySet{keys: map[string]ed25519.PublicKey{}}
	for _, u := range found {
		if count[u.kid] == 1 {
			s.kids = append(s.kids, u.kid)
			s.keys[u.kid] = u.pub
		}
	}
	return s, nil
}

// jwkEntry returns the kid and key of a usable JWKS entry.
func jwkEntry(e any) (string, ed25519.PublicKey, bool) {
	m, ok := e.(map[string]any)
	if !ok {
		return "", nil, false
	}
	if kty, _ := m["kty"].(string); kty != "OKP" {
		return "", nil, false
	}
	if crv, _ := m["crv"].(string); crv != "Ed25519" {
		return "", nil, false
	}
	for _, forbidden := range []string{"d", "x5u", "x5c", "x5t", "x5t#S256", "jku"} {
		if _, present := m[forbidden]; present {
			return "", nil, false
		}
	}
	if v, present := m["alg"]; present {
		if s, _ := v.(string); s != tokenAlgorithm {
			return "", nil, false
		}
	}
	if v, present := m["use"]; present {
		if s, _ := v.(string); s != "sig" {
			return "", nil, false
		}
	}
	if v, present := m["key_ops"]; present {
		ops, ok := v.([]any)
		if !ok || !containsString(ops, "verify") {
			return "", nil, false
		}
	}
	x, ok1 := m["x"].(string)
	kid, ok2 := m["kid"].(string)
	if !ok1 || !ok2 {
		return "", nil, false
	}
	raw, ok := decodeSegment(x)
	if !ok || len(raw) != ed25519.PublicKeySize {
		return "", nil, false
	}
	pub := ed25519.PublicKey(raw)
	if kid != KeyID(pub) {
		return "", nil, false
	}
	return kid, pub, true
}

func containsString(list []any, want string) bool {
	for _, v := range list {
		if s, ok := v.(string); ok && s == want {
			return true
		}
	}
	return false
}
