package tinysesam

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
	"unicode/utf8"
)

// seedTokens adds every token of the vectors to a fuzz corpus.
func seedTokens(f *testing.F) {
	for _, raw := range loadVectors(f, "token.json")["vectors"].([]any) {
		f.Add(raw.(map[string]any)["input"].(map[string]any)["jws"].(string))
	}
}

// FuzzVerify: no input panics, and nothing is accepted that the key did not sign or that breaks a rule of the
// specification.
func FuzzVerify(f *testing.F) {
	seedTokens(f)
	g := &Gate{mode: TokenMode, now: func() int64 { return testNow },
		rules: tokenRules{issuer: testIssuer, audience: testAudience}}
	ks, err := NewStaticKeySet(testGateKey(f, "A"), testGateKey(f, "B"))
	if err != nil {
		f.Fatal(err)
	}
	g.static = ks
	f.Fuzz(func(t *testing.T, jws string) {
		id, c, err := g.Verify(t.Context(), jws)
		if err != nil {
			if id != nil || c != nil {
				t.Fatal("a refusal returned an identity")
			}
			if ClassOf(err) == ClassInternal {
				t.Fatalf("unexpected internal error: %v", err)
			}
			return
		}
		parts := strings.Split(jws, ".")
		if len(jws) > MaxTokenBytes || len(parts) != 3 {
			t.Fatal("accepted a token of the wrong size or shape")
		}
		p, err := parseToken(jws)
		if err != nil || !ed25519.Verify(ks.lookup(p.kid), []byte(parts[0]+"."+parts[1]), p.signature) {
			t.Fatal("accepted a token without a valid signature")
		}
		if c.Issuer != testIssuer || c.Expiry <= testNow || c.NotBefore > testNow || hasControl(id.User) {
			t.Fatal("accepted a token that breaks a claim rule")
		}
	})
}

// FuzzParseToken: the structural checks never panic, and what passes them has a well-formed kid and a 64-byte
// signature.
func FuzzParseToken(f *testing.F) {
	seedTokens(f)
	f.Fuzz(func(t *testing.T, jws string) {
		p, err := parseToken(jws)
		if err != nil {
			return
		}
		if !validKid(p.kid) || len(p.signature) != ed25519.SignatureSize {
			t.Fatalf("parse let through kid %q, signature of %d bytes", p.kid, len(p.signature))
		}
	})
}

// FuzzParseGroups: no empty entry, no surrounding spaces, no comma, no repeat; every entry comes from the input.
func FuzzParseGroups(f *testing.F) {
	for _, s := range []string{"", "editors", "editors, admin", ",,a,,", "a,a", "team a", `a\,b`, " ", "Admin,admin"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		seen := map[string]bool{}
		for _, g := range ParseGroups(s) {
			if g == "" || strings.HasPrefix(g, " ") || strings.HasSuffix(g, " ") || strings.Contains(g, ",") {
				t.Fatalf("entry %q", g)
			}
			if seen[g] {
				t.Fatalf("repeated entry %q", g)
			}
			seen[g] = true
			if !strings.Contains(s, g) {
				t.Fatalf("entry %q not in the input", g)
			}
		}
	})
}

// FuzzHeaders: an accepted identity never holds a control character or invalid UTF-8, its ID is ASCII digits, and its
// account kind is exactly the Remote-Kind sent — user or service, never service with a session.
func FuzzHeaders(f *testing.F) {
	f.Add("anna", "Anna Berg", "editors,admin", "1", "session", "user")
	f.Add("boss\x01", "", "", "", "", "")
	f.Add("a\xc0\xafb", "x", "y", "١", "Session", "User")
	f.Add("bot", "", "editors", "7", "session", "service")
	f.Fuzz(func(t *testing.T, user, name, groups, id, auth, kind string) {
		h := http.Header{"Remote-User": {user}, "Remote-Name": {name}, "Remote-Groups": {groups},
			"Remote-Id": {id}, "Remote-Auth": {auth}, "Remote-Kind": {kind}}
		ident, err := IdentityFromHeaders(h)
		if err != nil {
			return
		}
		for _, v := range append([]string{ident.User, ident.Name, ident.ID, ident.Auth}, ident.Groups...) {
			if hasControl(v) || !utf8.ValidString(v) {
				t.Fatalf("accepted %q", v)
			}
		}
		if ident.User == "" || (ident.ID != "" && !allASCIIDigits(ident.ID)) {
			t.Fatalf("accepted user %q, id %q", ident.User, ident.ID)
		}
		if ident.IsSession() != (auth == "session") {
			t.Fatalf("Remote-Auth %q gave kind %q", auth, ident.Kind)
		}
		if string(ident.AccountKind) != kind || (kind != "user" && kind != "service") ||
			(ident.IsService() && ident.IsSession()) {
			t.Fatalf("Remote-Kind %q (auth %q) gave account kind %q", kind, auth, ident.AccountKind)
		}
	})
}

// FuzzStrictJSON: what the strict parser accepts is valid JSON for encoding/json too, and an object never loses a
// member (a repeated name is refused, not merged).
func FuzzStrictJSON(f *testing.F) {
	for _, s := range []string{`{}`, `{"a":1}`, `{"a":1,"a":2}`, `{"a":{"b":1,"b":2}}`, `[1,2]`, `NaN`, "\xef\xbb\xbf{}",
		`{"a":1} {}`, `{"a":"\u0000"}`, `{"a":1e400}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, raw []byte) {
		v, err := decodeStrictJSON(raw)
		if err != nil {
			return
		}
		if !json.Valid(raw) || !utf8.Valid(raw) {
			t.Fatal("accepted invalid JSON")
		}
		if m, ok := v.(map[string]any); ok {
			var loose map[string]json.RawMessage
			if err := json.Unmarshal(raw, &loose); err != nil || len(loose) != len(m) {
				t.Fatalf("object members differ: strict %d, loose %d", len(m), len(loose))
			}
		}
	})
}

// FuzzParseActionReturn: the way back of an action page (spec section 8c) never panics; what it accepts is a known
// action and result, and only with exactly the state given.
func FuzzParseActionReturn(f *testing.F) {
	for _, s := range []string{"", "/settings", "?ts_action=password&ts_result=done&state=s", "?ts_action=%", "#?",
		"?ts_action=admin_lock&ts_result=unavailable", "?ts_action=pin&ts_action=pin&ts_result=done", "?state=%zz"} {
		f.Add(s, "s")
	}
	f.Fuzz(func(t *testing.T, address, state string) {
		back, err := ParseActionReturn(address, state)
		if err != nil && back != nil {
			t.Fatalf("a refusal with a result: %v", err)
		}
		if back == nil {
			return
		}
		if !actionNames[back.Action] || !actionResults[back.Result] {
			t.Fatalf("accepted %q / %q", back.Action, back.Result)
		}
		if _, err := ParseActionReturn(address, state+"x"); !errors.Is(err, ErrActionReturnState) {
			t.Fatalf("another state was accepted too: %v", err)
		}
	})
}
