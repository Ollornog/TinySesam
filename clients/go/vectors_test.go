package tinysesam

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// The vectors live in the repository, never as a copy: spec/vectors/ relative to this module.
const vectorDir = "../../spec/vectors"

// Every file in spec/vectors/ must be run by one of these; a new file without a runner fails the suite.
var vectorFiles = []string{"account.json", "approval.json", "headers.json", "jwks.json", "keys.json",
	"permissions.json", "token.json", "topbar.json"}

// The format each file must declare: approval.json belongs to spec/approval-token.md (version 1), the others to
// spec/gate-client.md (version 2).
var vectorFormats = map[string]string{"approval.json": "1"}

func loadVectors(t testing.TB, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(vectorDir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	// Spec version 2 (Remote-Kind, ts_kind, menu_links), approval version 1: vectors of another version must not pass
	// unseen.
	want := vectorFormats[name]
	if want == "" {
		want = "2"
	}
	if doc["format"] != json.Number(want) {
		t.Fatalf("%s: unknown vector format %v", name, doc["format"])
	}
	return doc
}

func mustJSON(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// normalize turns a value into the generic form encoding/json produces (numbers as json.Number), so a typed result
// can be compared with an expected value of the vectors.
func normalize(t testing.TB, v any) any {
	t.Helper()
	dec := json.NewDecoder(bytes.NewReader(mustJSON(t, v)))
	dec.UseNumber()
	var out any
	if err := dec.Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func num(t testing.TB, v any) int64 {
	t.Helper()
	n, err := v.(json.Number).Int64()
	if err != nil {
		t.Fatalf("not an integer: %v", v)
	}
	return n
}

func TestVectorFilesAllCovered(t *testing.T) {
	entries, err := os.ReadDir(vectorDir)
	if err != nil {
		t.Fatalf("spec/vectors is missing: %v", err)
	}
	var found []string
	for _, e := range entries {
		if filepath.Ext(e.Name()) == ".json" {
			found = append(found, e.Name())
		}
	}
	sort.Strings(found)
	want := append([]string{}, vectorFiles...)
	sort.Strings(want)
	if !reflect.DeepEqual(found, want) {
		t.Fatalf("vector files %v, runner knows %v — add a runner for the new file", found, want)
	}
}

// tokenGate builds a token-mode gate with a fixed key set and a fixed clock, as the vectors describe.
func tokenGate(t testing.TB, jwks any, issuer, audience string, leeway, now int64) *Gate {
	t.Helper()
	ks, err := ParseJWKS(mustJSON(t, jwks))
	if err != nil {
		t.Fatalf("vector key set: %v", err)
	}
	return &Gate{mode: TokenMode, static: ks, rules: tokenRules{issuer: issuer, audience: audience, leeway: leeway},
		now: func() int64 { return now }}
}

func checkIdentity(t *testing.T, id string, got *Identity, expected map[string]any) {
	t.Helper()
	if want, ok := expected["identity"]; ok {
		// token.json and headers.json list the identity without permissions; permissions.json checks those.
		have := normalize(t, got).(map[string]any)
		delete(have, "permissions")
		if !reflect.DeepEqual(have, want) {
			t.Errorf("%s: identity %v, want %v", id, have, want)
		}
	}
	if roles, ok := expected["has_role"].(map[string]any); ok {
		for role, want := range roles {
			if got.HasRole(role) != want.(bool) {
				t.Errorf("%s: HasRole(%q) = %v, want %v", id, role, got.HasRole(role), want)
			}
		}
	}
}

func TestTokenVectors(t *testing.T) {
	doc := loadVectors(t, "token.json")
	vectors := doc["vectors"].([]any)
	if len(vectors) == 0 {
		t.Fatal("no token vectors")
	}
	for _, raw := range vectors {
		v := raw.(map[string]any)
		id := v["id"].(string)
		in := v["input"].(map[string]any)
		want := v["expected"].(map[string]any)
		g := tokenGate(t, in["jwks"], in["issuer"].(string), in["audience"].(string), num(t, in["leeway"]),
			num(t, in["now"]))
		ident, claims, err := g.Verify(context.Background(), in["jws"].(string))
		if want["ok"] != true {
			if err == nil {
				t.Errorf("%s: accepted, want %v", id, want["error"])
				continue
			}
			if got := ClassOf(err); string(got) != want["error"] {
				t.Errorf("%s: class %q, want %q", id, got, want["error"])
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: refused (%v), want ok", id, err)
			continue
		}
		if !reflect.DeepEqual(any(claims.Raw), want["claims"]) {
			t.Errorf("%s: claims %v, want %v", id, claims.Raw, want["claims"])
		}
		checkIdentity(t, id, ident, want)
	}
	t.Logf("%d token vectors", len(vectors))
}

// latin1 turns a vector header value (one code point U+0000-U+00FF per octet) into the octets on the wire.
func latin1(t testing.TB, s string) string {
	t.Helper()
	out := make([]byte, 0, len(s))
	for _, r := range s {
		if r > 0xff {
			t.Fatalf("header value outside Latin-1: %q", s)
		}
		out = append(out, byte(r))
	}
	return string(out)
}

func TestHeaderVectors(t *testing.T) {
	doc := loadVectors(t, "headers.json")
	vectors := doc["vectors"].([]any)
	if len(vectors) == 0 {
		t.Fatal("no header vectors")
	}
	for _, raw := range vectors {
		v := raw.(map[string]any)
		id := v["id"].(string)
		want := v["expected"].(map[string]any)
		// Keys stay as spelled in the vector: two spellings of one field are two map keys here.
		h := http.Header{}
		for name, val := range v["input"].(map[string]any)["headers"].(map[string]any) {
			switch x := val.(type) {
			case string:
				h[name] = []string{latin1(t, x)}
			case []any:
				for _, item := range x {
					h[name] = append(h[name], latin1(t, item.(string)))
				}
			default:
				t.Fatalf("%s: header value %T", id, val)
			}
		}
		ident, err := IdentityFromHeaders(h)
		if want["ok"] != true {
			if err == nil {
				t.Errorf("%s: accepted, want %v", id, want["error"])
			} else if got := ClassOf(err); string(got) != want["error"] {
				t.Errorf("%s: class %q, want %q", id, got, want["error"])
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: refused (%v), want ok", id, err)
			continue
		}
		checkIdentity(t, id, ident, want)
	}
	t.Logf("%d header vectors", len(vectors))
}

func TestJWKSSetVectors(t *testing.T) {
	doc := loadVectors(t, "jwks.json")
	sets := doc["sets"].([]any)
	if len(sets) == 0 {
		t.Fatal("no key set vectors")
	}
	for _, raw := range sets {
		v := raw.(map[string]any)
		id := v["id"].(string)
		want := v["expected"].(map[string]any)
		ks, err := ParseJWKS(mustJSON(t, v["input"].(map[string]any)["jwks"]))
		if want["ok"] != true {
			if err == nil {
				t.Errorf("%s: accepted, want %v", id, want["error"])
			} else if got := ClassOf(err); string(got) != want["error"] {
				t.Errorf("%s: class %q, want %q", id, got, want["error"])
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: refused (%v)", id, err)
			continue
		}
		var wantKids []string
		for _, k := range want["kids"].([]any) {
			wantKids = append(wantKids, k.(string))
		}
		if !reflect.DeepEqual(ks.Kids(), wantKids) {
			t.Errorf("%s: kids %v, want %v", id, ks.Kids(), wantKids)
		}
	}
	t.Logf("%d key set vectors", len(sets))
}

// scenarioFetcher answers with the simulated fetch of the current step; a fetch where the step gives none fails it.
type scenarioFetcher struct {
	answer     map[string]any
	calls      int
	unexpected bool
	t          testing.TB
}

func (f *scenarioFetcher) fetch(context.Context) fetchResult {
	f.calls++
	if f.answer == nil {
		f.unexpected = true
		return fetchResult{err: errBodyTooLarge}
	}
	if _, failed := f.answer["error"]; failed {
		return fetchResult{err: errBodyTooLarge}
	}
	r := fetchResult{status: int(num(f.t, f.answer["status"]))}
	if cc, ok := f.answer["cache_control"].(string); ok {
		r.cacheControl = cc
	}
	if body, ok := f.answer["body"]; ok {
		r.body = mustJSON(f.t, body)
	} else if text, ok := f.answer["body_text"].(string); ok {
		r.body = []byte(text)
	}
	return r
}

func TestJWKSScenarioVectors(t *testing.T) {
	doc := loadVectors(t, "jwks.json")
	defaults := doc["defaults"].(map[string]any)
	scenarios := doc["scenarios"].([]any)
	if len(scenarios) == 0 {
		t.Fatal("no cache scenarios")
	}
	steps := 0
	for _, raw := range scenarios {
		sc := raw.(map[string]any)
		id := sc["id"].(string)
		f := &scenarioFetcher{t: t}
		var now int64
		g := &Gate{mode: TokenMode, jwks: newJWKSCache(f.fetch),
			rules: tokenRules{issuer: defaults["issuer"].(string), audience: defaults["audience"].(string)},
			now:   func() int64 { return now }}
		for i, rawStep := range sc["steps"].([]any) {
			st := rawStep.(map[string]any)
			want := st["expect"].(map[string]any)
			now = num(t, st["now"])
			f.answer, _ = st["fetch"].(map[string]any)
			f.calls, f.unexpected = 0, false
			_, _, err := g.Verify(context.Background(), st["jws"].(string))
			steps++
			if f.unexpected {
				t.Errorf("%s step %d: fetched although the step gives no answer", id, i)
			}
			if f.calls > 1 {
				t.Errorf("%s step %d: %d fetches in one request", id, i, f.calls)
			}
			if (f.calls == 1) != want["fetched"].(bool) {
				t.Errorf("%s step %d: fetched %v, want %v", id, i, f.calls == 1, want["fetched"])
			}
			if want["ok"] == true {
				if err != nil {
					t.Errorf("%s step %d: refused (%v), want ok", id, i, err)
				}
			} else if err == nil {
				t.Errorf("%s step %d: accepted, want %v", id, i, want["error"])
			} else if got := ClassOf(err); string(got) != want["error"] {
				t.Errorf("%s step %d: class %q, want %q", id, i, got, want["error"])
			}
		}
	}
	t.Logf("%d cache scenarios, %d steps", len(scenarios), steps)
}

func TestTopbarVectors(t *testing.T) {
	doc := loadVectors(t, "topbar.json")
	vectors := doc["vectors"].([]any)
	if len(vectors) == 0 {
		t.Fatal("no top bar vectors")
	}
	for _, raw := range vectors {
		v := raw.(map[string]any)
		id := v["id"].(string)
		got := ParseTopbar(mustJSON(t, v["input"].(map[string]any)["topbar"]))
		want := v["expected"].(map[string]any)["topbar"]
		if !reflect.DeepEqual(normalize(t, got), want) {
			t.Errorf("%s: top bar %v, want %v", id, normalize(t, got), want)
		}
	}
	t.Logf("%d top bar vectors", len(vectors))
}

func TestAccountVectors(t *testing.T) {
	doc := loadVectors(t, "account.json")
	vectors := doc["vectors"].([]any)
	if len(vectors) == 0 {
		t.Fatal("no account vectors")
	}
	for _, raw := range vectors {
		v := raw.(map[string]any)
		id := v["id"].(string)
		got := ParseAccount(mustJSON(t, v["input"].(map[string]any)["account"]))
		want := v["expected"].(map[string]any)["account"]
		if !reflect.DeepEqual(normalize(t, got), want) {
			t.Errorf("%s: account %s, want %s", id, mustJSON(t, got), mustJSON(t, want))
		}
	}
	t.Logf("%d account vectors", len(vectors))
	urls := doc["action_urls"].([]any)
	if len(urls) == 0 {
		t.Fatal("no action address vectors")
	}
	for _, raw := range urls {
		v := raw.(map[string]any)
		id := "action_urls/" + v["id"].(string)
		in, exp := v["input"].(map[string]any), v["expected"].(map[string]any)
		state, _ := in["state"].(string)
		got, err := ActionURL(in["href"].(string), in["return"].(string), state)
		switch {
		case exp["ok"] == true && (err != nil || got != exp["url"]):
			t.Errorf("%s: %q, %v; want %q", id, got, err, exp["url"])
		case exp["ok"] != true && (!errors.Is(err, ErrActionURL) || got != ""):
			t.Errorf("%s: %q, %v; want a refusal", id, got, err)
		}
	}
	t.Logf("%d action address vectors", len(urls))
	returns := doc["action_returns"].([]any)
	if len(returns) == 0 {
		t.Fatal("no action return vectors")
	}
	for _, raw := range returns {
		v := raw.(map[string]any)
		id := "action_returns/" + v["id"].(string)
		in, exp := v["input"].(map[string]any), v["expected"].(map[string]any)
		state, _ := in["state"].(string)
		back, err := ParseActionReturn(in["url"].(string), state)
		var got map[string]any
		switch {
		case errors.Is(err, ErrActionReturnInvalid) && back == nil:
			got = map[string]any{"ok": false, "error": "invalid"}
		case errors.Is(err, ErrActionReturnState) && back == nil:
			got = map[string]any{"ok": false, "error": "state"}
		case err != nil:
			got = map[string]any{"ok": false, "error": err.Error()}
		default:
			got = map[string]any{"ok": true, "return": normalize(t, back)}
		}
		if !reflect.DeepEqual(got, exp) {
			t.Errorf("%s: %v, want %v", id, got, exp)
		}
	}
	t.Logf("%d action return vectors", len(returns))
	admin := doc["admin_accounts"].([]any)
	if len(admin) == 0 {
		t.Fatal("no administration vectors")
	}
	for _, raw := range admin {
		v := raw.(map[string]any)
		id := "admin_accounts/" + v["id"].(string)
		got := ParseAdminAccounts(mustJSON(t, v["input"].(map[string]any)["answer"]))
		want := v["expected"].(map[string]any)["admin"]
		if !reflect.DeepEqual(normalize(t, got), want) {
			t.Errorf("%s: %s, want %s", id, mustJSON(t, got), mustJSON(t, want))
		}
	}
	t.Logf("%d administration vectors", len(admin))
}

// memoryStore is the jti store of a vector: the ids in input.seen are already in it.
type memoryStore struct{ seen map[string]bool }

func (m *memoryStore) Remember(_ context.Context, jti string, _ int64) (bool, error) {
	if m.seen[jti] {
		return false, nil
	}
	m.seen[jti] = true
	return true, nil
}

// runApprovalVector checks one vector of approval.json; it returns the claims or the error class.
func runApprovalVector(t testing.TB, in map[string]any) (*ApprovalClaims, error) {
	t.Helper()
	ks, err := ParseJWKS(mustJSON(t, in["jwks"]))
	if err != nil {
		t.Fatalf("vector key set: %v", err)
	}
	now := num(t, in["now"])
	v := &ApprovalVerifier{issuer: in["issuer"].(string), appID: in["app_id"].(string),
		leeway: num(t, in["leeway"]), static: ks, now: func() int64 { return now }}
	e := in["expect"].(map[string]any)
	want := ApprovalExpect{Type: e["type"].(string), Fields: e["fields"].(map[string]any), Subject: e["sub"].(string)}
	if n, ok := e["nonce"].(string); ok {
		want.Nonce = n
	}
	store := &memoryStore{seen: map[string]bool{}}
	for _, s := range in["seen"].([]any) {
		store.seen[s.(string)] = true
	}
	return v.Verify(context.Background(), in["jws"].(string), want, store)
}

func TestApprovalVectors(t *testing.T) {
	doc := loadVectors(t, "approval.json")
	if doc["spec"] != "spec/approval-token.md" {
		t.Fatalf("approval.json belongs to %v", doc["spec"])
	}
	vectors := doc["vectors"].([]any)
	if len(vectors) < 40 {
		t.Fatalf("only %d approval vectors", len(vectors))
	}
	valid := 0
	for _, raw := range vectors {
		v := raw.(map[string]any)
		id := v["id"].(string)
		exp := v["expected"].(map[string]any)
		c, err := runApprovalVector(t, v["input"].(map[string]any))
		if exp["ok"] == true {
			valid++
			if err != nil {
				t.Errorf("%s: refused with %v", id, err)
				continue
			}
			if !reflect.DeepEqual(normalize(t, c.Raw), exp["claims"]) {
				t.Errorf("%s: claims %v, want %v", id, normalize(t, c.Raw), exp["claims"])
			}
			continue
		}
		if err == nil {
			t.Errorf("%s: accepted, want %v", id, exp["error"])
		} else if got := ClassOf(err); string(got) != exp["error"] {
			t.Errorf("%s: class %q, want %q", id, got, exp["error"])
		}
	}
	t.Logf("%d approval vectors, %d valid", len(vectors), valid)
}

// The test keys: each public JWK matches its sign_key form, and the seed signs for that key.
func TestKeyVectors(t *testing.T) {
	doc := loadVectors(t, "keys.json")
	keys := doc["keys"].(map[string]any)
	if len(keys) < 3 {
		t.Fatalf("expected the test keys A, B and X, got %d", len(keys))
	}
	for name, raw := range keys {
		k := raw.(map[string]any)
		pub, err := ParseGateKey(k["sign_key_base64"].(string))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		jwk := k["public_jwk"].(map[string]any)
		if KeyID(pub) != jwk["kid"] {
			t.Errorf("%s: kid %s, JWK says %v", name, KeyID(pub), jwk["kid"])
		}
		ks, err := ParseJWKS(mustJSON(t, map[string]any{"keys": []any{jwk}}))
		if err != nil || !reflect.DeepEqual(ks.Kids(), []string{KeyID(pub)}) {
			t.Errorf("%s: public JWK not usable: %v", name, err)
		}
		if !bytes.Equal(testPrivateKey(t, name).Public().(ed25519.PublicKey), pub) {
			t.Errorf("%s: seed does not belong to the public key", name)
		}
	}
}

func checkPermissions(t *testing.T, id string, ident *Identity, err error, want map[string]any) {
	t.Helper()
	if want["ok"] != true {
		if err == nil {
			t.Errorf("%s: accepted, want %v", id, want["error"])
		} else if got := ClassOf(err); string(got) != want["error"] {
			t.Errorf("%s: class %q, want %q", id, got, want["error"])
		}
		return
	}
	if err != nil {
		t.Errorf("%s: refused (%v), want ok", id, err)
		return
	}
	if !reflect.DeepEqual(normalize(t, ident.Permissions), want["permissions"]) {
		t.Errorf("%s: permissions %v, want %v", id, ident.Permissions, want["permissions"])
	}
	if checks, ok := want["has_permission"].(map[string]any); ok {
		for p, w := range checks {
			if ident.HasPermission(p) != w.(bool) {
				t.Errorf("%s: HasPermission(%q) = %v, want %v", id, p, ident.HasPermission(p), w)
			}
		}
	}
}

func TestPermissionVectors(t *testing.T) {
	doc := loadVectors(t, "permissions.json")
	count := 0
	for _, raw := range doc["headers"].([]any) {
		v := raw.(map[string]any)
		h := http.Header{}
		for name, val := range v["input"].(map[string]any)["headers"].(map[string]any) {
			switch x := val.(type) {
			case string:
				h[name] = []string{latin1(t, x)}
			case []any:
				for _, item := range x {
					h[name] = append(h[name], latin1(t, item.(string)))
				}
			}
		}
		ident, err := IdentityFromHeaders(h)
		checkPermissions(t, "headers/"+v["id"].(string), ident, err, v["expected"].(map[string]any))
		count++
	}
	for _, raw := range doc["tokens"].([]any) {
		v := raw.(map[string]any)
		in := v["input"].(map[string]any)
		g := tokenGate(t, in["jwks"], in["issuer"].(string), in["audience"].(string), num(t, in["leeway"]),
			num(t, in["now"]))
		ident, _, err := g.Verify(context.Background(), in["jws"].(string))
		checkPermissions(t, "tokens/"+v["id"].(string), ident, err, v["expected"].(map[string]any))
		count++
	}
	for _, raw := range doc["register"].([]any) {
		v := raw.(map[string]any)
		id := "register/" + v["id"].(string)
		in, want := v["input"].(map[string]any), v["expected"].(map[string]any)
		list, isList := in["permissions"].([]any)
		if !isList {
			// A manifest that is no list cannot even be passed in Go: refused by the type.
			if want["ok"] != false || want["error"] != "invalid" {
				t.Errorf("%s: a manifest that is no list must be invalid", id)
			}
			count++
			continue
		}
		req, err := RegisterRequest(in["base_url"].(string), in["app"].(string), list)
		if want["ok"] != true {
			if !errors.Is(err, ErrManifest) {
				t.Errorf("%s: accepted (%v), want invalid", id, err)
			}
		} else if err != nil {
			t.Errorf("%s: refused (%v), want ok", id, err)
		} else {
			got := map[string]any{"method": req.Method, "url": req.URL, "body": req.Body}
			if !reflect.DeepEqual(normalize(t, got), normalize(t, want["request"])) {
				t.Errorf("%s: request %v, want %v", id, got, want["request"])
			}
		}
		count++
	}
	if count == 0 {
		t.Fatal("no permission vectors")
	}
	t.Logf("%d permission vectors", count)
}
