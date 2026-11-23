package tinysesam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// approvalVector returns the input of one vector of approval.json.
func approvalVector(t testing.TB, id string) map[string]any {
	t.Helper()
	for _, raw := range loadVectors(t, "approval.json")["vectors"].([]any) {
		v := raw.(map[string]any)
		if v["id"] == id {
			return v["input"].(map[string]any)
		}
	}
	t.Fatalf("no approval vector %s", id)
	return nil
}

func expectOf(in map[string]any) ApprovalExpect {
	e := in["expect"].(map[string]any)
	return ApprovalExpect{Type: e["type"].(string), Fields: e["fields"].(map[string]any), Subject: e["sub"].(string)}
}

func TestApprovalConfigErrors(t *testing.T) {
	ks, err := ParseJWKS(mustJSON(t, approvalVector(t, "valid-basic")["jwks"]))
	if err != nil {
		t.Fatal(err)
	}
	empty, _ := ParseJWKS([]byte(`{"keys":[]}`))
	good := ApprovalConfig{Issuer: testIssuer, AppID: "example", KeySet: ks}
	if _, err := NewApprovalVerifier(good); err != nil {
		t.Fatalf("a good configuration was refused: %v", err)
	}
	for name, cfg := range map[string]ApprovalConfig{
		"no issuer":       {AppID: "example", KeySet: ks},
		"no app id":       {Issuer: testIssuer, KeySet: ks},
		"no keys":         {Issuer: testIssuer, AppID: "example"},
		"empty key set":   {Issuer: testIssuer, AppID: "example", KeySet: empty},
		"both sources":    {Issuer: testIssuer, AppID: "example", KeySet: ks, JWKSURL: "https://auth.example.com/auth/approvals/jwks.json"},
		"leeway 31":       {Issuer: testIssuer, AppID: "example", KeySet: ks, LeewaySeconds: 31},
		"negative leeway": {Issuer: testIssuer, AppID: "example", KeySet: ks, LeewaySeconds: -1},
		"client, no URL":  {Issuer: testIssuer, AppID: "example", KeySet: ks, HTTPClient: http.DefaultClient},
		"gate key set":    {Issuer: testIssuer, AppID: "example", JWKSURL: "https://auth.example.com/auth/gate/jwks.json"},
		"gate key set /":  {Issuer: testIssuer, AppID: "example", JWKSURL: "https://auth.example.com/auth/gate/jwks.json/"},
		"plain http":      {Issuer: testIssuer, AppID: "example", JWKSURL: "http://auth.example.com/auth/approvals/jwks.json"},
	} {
		if _, err := NewApprovalVerifier(cfg); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := NewApprovalVerifier(ApprovalConfig{Issuer: testIssuer, AppID: "example", LeewaySeconds: MaxApprovalLeeway,
		JWKSURL: "https://auth.example.com/auth/approvals/jwks.json"}); err != nil {
		t.Errorf("the approval key set URL with the largest leeway was refused: %v", err)
	}
}

// One store for two checks: the first use passes, the second is a replay; a failing store refuses (fails closed).
func TestApprovalStore(t *testing.T) {
	in := approvalVector(t, "valid-basic")
	ks, _ := ParseJWKS(mustJSON(t, in["jwks"]))
	v, err := NewApprovalVerifier(ApprovalConfig{Issuer: testIssuer, AppID: "example", KeySet: ks})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() int64 { return testNow }
	var until int64
	seen := map[string]bool{}
	store := JTIStoreFunc(func(_ context.Context, jti string, u int64) (bool, error) {
		until = u
		if seen[jti] {
			return false, nil
		}
		seen[jti] = true
		return true, nil
	})
	c, err := v.Verify(t.Context(), in["jws"].(string), expectOf(in), store)
	if err != nil {
		t.Fatalf("first use refused: %v", err)
	}
	if until != c.Expiry || c.JTI == "" || c.Actor != "app:example" || c.Type != "example.collection.delete_permanently" ||
		c.Fields["collection"] != "c_81f2" || len(c.AMR) != 2 || c.AuthTime > c.IssuedAt {
		t.Errorf("claims %+v, store until %d", c, until)
	}
	if _, err := v.Verify(t.Context(), in["jws"].(string), expectOf(in), store); !errors.Is(err, ErrReplay) {
		t.Errorf("second use: %v, want replay", err)
	}
	failing := JTIStoreFunc(func(context.Context, string, int64) (bool, error) { return false, errors.New("db down") })
	if _, err := v.Verify(t.Context(), in["jws"].(string), expectOf(in), failing); ClassOf(err) != ClassInternal {
		t.Errorf("a failing store: %v, want internal", err)
	}
	if _, err := v.Verify(t.Context(), in["jws"].(string), expectOf(in), nil); ClassOf(err) != ClassInternal {
		t.Errorf("no store: %v, want internal", err)
	}
	// A confirmation refused for another reason does not use up its id.
	fresh := map[string]bool{}
	counting := JTIStoreFunc(func(_ context.Context, jti string, _ int64) (bool, error) { fresh[jti] = true; return true, nil })
	other := expectOf(in)
	other.Subject = "1002"
	if _, err := v.Verify(t.Context(), in["jws"].(string), other, counting); !errors.Is(err, ErrSubject) || len(fresh) != 0 {
		t.Errorf("another subject: %v, store written %v", err, fresh)
	}
}

// The expected fields may come in any integer type of Go; a float, a nil or a nested value never matches.
func TestApprovalExpectedFieldTypes(t *testing.T) {
	in := approvalVector(t, "valid-escapes-int-bool")
	ks, _ := ParseJWKS(mustJSON(t, in["jwks"]))
	v, _ := NewApprovalVerifier(ApprovalConfig{Issuer: testIssuer, AppID: "example", KeySet: ks})
	v.now = func() int64 { return testNow }
	member := expectOf(in).Fields["member"]
	always := JTIStoreFunc(func(context.Context, string, int64) (bool, error) { return true, nil })
	for _, quota := range []any{-1, int8(-1), int16(-1), int32(-1), int64(-1), json.Number("-1")} {
		want := ApprovalExpect{Type: "example.member.set_quota", Subject: "2",
			Fields: map[string]any{"member": member, "quota": quota, "notify": false}}
		if _, err := v.Verify(t.Context(), in["jws"].(string), want, always); err != nil {
			t.Errorf("quota %T: %v", quota, err)
		}
	}
	for _, quota := range []any{-1.0, float32(-1), nil, "-1", true, []any{-1}, json.Number("-1.0")} {
		want := ApprovalExpect{Type: "example.member.set_quota", Subject: "2",
			Fields: map[string]any{"member": member, "quota": quota, "notify": false}}
		if _, err := v.Verify(t.Context(), in["jws"].(string), want, always); !errors.Is(err, ErrApprovalFields) {
			t.Errorf("quota %T %v: %v, want approval_fields", quota, quota, err)
		}
	}
}

// The approval key set fetched from TinySesam: once, then from the cache; never a request on a malformed token.
func TestApprovalJWKSURL(t *testing.T) {
	in := approvalVector(t, "valid-basic")
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/auth/approvals/jwks.json" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Cache-Control", "max-age=300")
		_, _ = w.Write(mustJSON(t, in["jwks"]))
	}))
	defer srv.Close()
	v, err := NewApprovalVerifier(ApprovalConfig{Issuer: testIssuer, AppID: "example",
		JWKSURL: srv.URL + "/auth/approvals/jwks.json", HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	v.now = func() int64 { return testNow }
	always := JTIStoreFunc(func(context.Context, string, int64) (bool, error) { return true, nil })
	for range 2 {
		if _, err := v.Verify(t.Context(), in["jws"].(string), expectOf(in), always); err != nil {
			t.Fatalf("refused: %v", err)
		}
	}
	if _, err := v.Verify(t.Context(), "not.a.token", expectOf(in), always); !errors.Is(err, ErrMalformed) {
		t.Errorf("malformed token: %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("fetched %d times, want once", hits.Load())
	}
	missing, _ := NewApprovalVerifier(ApprovalConfig{Issuer: testIssuer, AppID: "example",
		JWKSURL: srv.URL + "/auth/approvals/missing.json", HTTPClient: srv.Client()})
	missing.now = func() int64 { return testNow }
	if _, err := missing.Verify(t.Context(), in["jws"].(string), expectOf(in), always); !errors.Is(err, ErrKeyUnavailable) {
		t.Errorf("no key set: %v, want key_unavailable", err)
	}
}

// The canonical form of spec/approval-token.md section 6: sorted members, only the escapes of RFC 8785.
func TestApprovalCanonicalForm(t *testing.T) {
	entry := map[string]any{"type": "t", "b": true, "a": json.Number("-12"), "s": "q\"\\é\n\x01"}
	if got, want := canonicalEntry(entry), `{"a":-12,"b":true,"s":"q\"\\é\n\u0001","type":"t"}`; got != want {
		t.Errorf("canonical form %s, want %s", got, want)
	}
}

func TestAccountFetch(t *testing.T) {
	full := loadVectors(t, "account.json")["vectors"].([]any)[0].(map[string]any)["input"].(map[string]any)["account"]
	var gotCookies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookies = gotCookies[:0]
		for _, c := range r.Cookies() {
			gotCookies = append(gotCookies, c.Name)
		}
		switch r.URL.Path {
		case "/auth/account.json":
			_, _ = w.Write(mustJSON(t, full))
		case "/big":
			_, _ = io.WriteString(w, `{"signed_in":true,"pad":"`+strings.Repeat("x", MaxJWKSBytes)+`"}`)
		case "/401":
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = io.WriteString(w, `{"authenticated":false,"signed_in":false}`)
		case "/429":
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = io.WriteString(w, `{"signed_in":true}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&http.Cookie{Name: "tinysesam_session", Value: "s"})
	r.AddCookie(&http.Cookie{Name: "app_session", Value: "private"})
	a, err := FetchAccount(t.Context(), srv.Client(), srv.URL+"/auth/account.json", r)
	if err != nil || !a.SignedIn || *a.Account.Username != "anna" || a.Approvals.Pending != 1 || *a.Links.Approvals == "" {
		t.Errorf("account %s, %v", mustJSON(t, a), err)
	}
	if len(gotCookies) != 1 || gotCookies[0] != "tinysesam_session" {
		t.Errorf("forwarded cookies %v, want only TinySesam's", gotCookies)
	}
	for _, path := range []string{"/401", "/429", "/404", "/big"} {
		if a, err := FetchAccount(t.Context(), srv.Client(), srv.URL+path, r); err == nil || a.SignedIn || a.Links != nil {
			t.Errorf("%s: counts as signed in: %s, %v", path, mustJSON(t, a), err)
		}
	}
}
