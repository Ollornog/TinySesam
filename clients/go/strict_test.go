package tinysesam

import "testing"

// Strict JSON cases beyond the vectors. encoding/json accepts invalid UTF-8 inside strings (and replaces it), so the
// UTF-8 check also has its own test here (the vector attack-payload-invalid-utf8 carries that one defect since the
// generator dropped its repeated member).
func TestStrictJSON(t *testing.T) {
	refused := []string{
		"{\"a\":\"\xff\"}",
		"{\"a\":\"\xc0\xaf\"}",
		"{\"\xed\xa0\x80\":1}",
		"\xef\xbb\xbf{}",
		`{"a":1,"a":1}`,
		`{"a":{"b":1,"b":2}}`,
		`[{"a":1,"a":2}]`,
		`{"a":NaN}`,
		`{"a":Infinity}`,
		`{"a":1} {}`,
		`{"a":1}x`,
		``,
	}
	for _, s := range refused {
		if _, err := decodeStrictJSON([]byte(s)); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
	accepted := []string{`{}`, " {\"a\":[1,{\"b\":null}]} \n", `{"a":"ü","b":"ü"}`, `[]`, `"x"`, `1e400`}
	for _, s := range accepted {
		if _, err := decodeStrictJSON([]byte(s)); err != nil {
			t.Errorf("refused %q: %v", s, err)
		}
	}
}

// A token whose payload holds invalid UTF-8 (and nothing else wrong) is malformed.
func TestTokenPayloadInvalidUTF8(t *testing.T) {
	g := fixedGate(t, nil)
	claims := sessionClaims("editors")
	claims["ts_name"] = "PLACEHOLDER"
	tok := mint(t, "A", claims)
	// Re-sign a payload with a raw 0xFF byte in place of the placeholder.
	priv := testPrivateKey(t, "A")
	parts := splitToken(tok)
	payload, _ := decodeSegment(parts[1])
	payload = replaceOnce(payload, "PLACEHOLDER", "\xff")
	tok = resign(priv, parts[0], payload)
	if _, _, err := g.Verify(t.Context(), tok); ClassOf(err) != ClassMalformed {
		t.Errorf("payload with invalid UTF-8: class %v, want malformed", ClassOf(err))
	}
}
