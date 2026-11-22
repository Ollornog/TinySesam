package tinysesam

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// Test material only: the public test keys of spec/vectors/keys.json.
const (
	testIssuer   = "https://auth.example.com"
	testAudience = "app.example.com"
	testNow      = int64(1767225600)
)

// testPrivateKey derives the private test key A, B or X from its published seed.
func testPrivateKey(t testing.TB, name string) ed25519.PrivateKey {
	t.Helper()
	keys := loadVectors(t, "keys.json")["keys"].(map[string]any)
	k, ok := keys[name].(map[string]any)
	if !ok {
		t.Fatalf("no test key %s", name)
	}
	seed, err := base64.RawURLEncoding.DecodeString(k["d"].(string))
	if err != nil || len(seed) != ed25519.SeedSize {
		t.Fatalf("test key %s: bad seed", name)
	}
	return ed25519.NewKeyFromSeed(seed)
}

func testGateKey(t testing.TB, name string) string {
	t.Helper()
	return base64.StdEncoding.EncodeToString(testPrivateKey(t, name).Public().(ed25519.PublicKey))
}

// mint signs a token with test key name. Clients never mint tokens; this exists for the tests only.
func mint(t testing.TB, name string, claims map[string]any) string {
	t.Helper()
	priv := testPrivateKey(t, name)
	head := map[string]any{"alg": "EdDSA", "typ": "tinysesam-gate+jwt", "kid": KeyID(priv.Public().(ed25519.PublicKey))}
	enc := func(v any) string {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := enc(head) + "." + enc(claims)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
}

// sessionClaims are the claims /auth/forward issues for a browser session at testNow.
func sessionClaims(groups string) map[string]any {
	return map[string]any{
		"iss": testIssuer, "aud": testAudience, "sub": "1", "iat": testNow, "nbf": testNow, "exp": testNow + 300,
		"jti": "test", "ts_user": "anna", "ts_name": "Anna Berg", "ts_email": "anna@example.com",
		"ts_groups": groups, "ts_id": "1", "ts_auth": "session", "ts_kind": "user",
	}
}

func splitToken(tok string) []string { return strings.Split(tok, ".") }

func replaceOnce(b []byte, old, repl string) []byte {
	return []byte(strings.Replace(string(b), old, repl, 1))
}

// resign signs a header segment and raw payload bytes with priv (test helper for payloads json.Marshal cannot make).
func resign(priv ed25519.PrivateKey, headSeg string, payload []byte) string {
	input := headSeg + "." + base64.RawURLEncoding.EncodeToString(payload)
	return input + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(priv, []byte(input)))
}
