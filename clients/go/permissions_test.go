package tinysesam

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterPermissions(t *testing.T) {
	var gotPath, gotKey string
	var gotBody map[string]any
	status := http.StatusOK
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut {
			t.Errorf("method %s", r.Method)
		}
		gotPath, gotKey = r.URL.Path, r.Header.Get("X-Api-Key")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"added":["docs.read"],"updated":[],"returned":[],"orphaned":[]}`))
	}))
	defer srv.Close()
	manifest := []any{map[string]any{"name": "docs.read", "label": map[string]any{"en": "Read"}}}
	out, err := RegisterPermissions(context.Background(), srv.Client(), srv.URL+"/", "docs", manifest, "tsk_probe")
	if err != nil {
		t.Fatalf("refused: %v", err)
	}
	if gotPath != "/auth/api/apps/docs/permissions" || gotKey != "tsk_probe" || out["added"].([]any)[0] != "docs.read" {
		t.Fatalf("path %q key %q answer %v", gotPath, gotKey, out)
	}
	if list, _ := gotBody["permissions"].([]any); len(list) != 1 {
		t.Fatalf("body %v", gotBody)
	}
	status = http.StatusForbidden
	_, err = RegisterPermissions(context.Background(), srv.Client(), srv.URL, "docs", manifest, "tsk_probe")
	var re *RegistrationError
	if !errors.As(err, &re) || re.Status != http.StatusForbidden {
		t.Fatalf("a 403 answer: %v", err)
	}
	gotPath = ""
	for _, bad := range []struct {
		appID, key string
		list       []any
	}{{"Docs", "k", manifest}, {"docs", "", manifest}, {"docs", "k", []any{map[string]any{"name": "Docs"}}}} {
		if _, err := RegisterPermissions(context.Background(), srv.Client(), srv.URL, bad.appID, bad.list,
			bad.key); !errors.Is(err, ErrManifest) {
			t.Errorf("%v accepted: %v", bad, err)
		}
	}
	if gotPath != "" {
		t.Fatal("a refused manifest was sent")
	}
}
