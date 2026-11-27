package tinysesam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
)

// The application id rule of TinySesam's apps and the permission name rule (ADR-17); at most MaxPermissions entries.
var (
	appIDRE          = regexp.MustCompile(`^[a-z][a-z0-9_]{0,31}$`)
	permissionNameRE = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,31}(\.[a-z0-9_-]{1,32}){1,3}$`)
)

// MaxPermissions is the largest manifest TinySesam takes per application.
const MaxPermissions = 200

// ErrManifest wraps every refusal of RegisterRequest: nothing was sent.
var ErrManifest = errors.New("tinysesam: permission manifest refused")

// PermissionRequest is the request RegisterPermissions sends (spec section 3.4): PUT <base>/auth/api/apps/<app>/permissions
// with Body as JSON.
type PermissionRequest struct {
	Method string
	URL    string
	Body   map[string]any
}

// RegisterRequest checks a manifest the way spec section 3.4 asks and builds the request, without sending it. It refuses
// (an error wrapping ErrManifest) a base URL that is not https (plain http only to a loopback address), an application
// id outside the rule, a manifest of more than MaxPermissions entries, an entry that is no object or whose name breaks
// the rule, and a name twice. TinySesam checks labels and descriptions itself.
func RegisterRequest(baseURL, app string, permissions []any) (PermissionRequest, error) {
	refuse := func(why string) (PermissionRequest, error) {
		return PermissionRequest{}, fmt.Errorf("%w: %s", ErrManifest, why)
	}
	if err := checkBaseURL(baseURL); err != nil {
		return refuse(err.Error())
	}
	if !appIDRE.MatchString(app) {
		return refuse("the application id must match ^[a-z][a-z0-9_]{0,31}$")
	}
	if permissions == nil || len(permissions) > MaxPermissions {
		return refuse(fmt.Sprintf("the manifest is a list of at most %d permissions", MaxPermissions))
	}
	seen := map[string]bool{}
	for _, entry := range permissions {
		obj, ok := entry.(map[string]any)
		name, _ := obj["name"].(string)
		if !ok || !permissionNameRE.MatchString(name) {
			return refuse("every permission is an object whose name matches the rule of spec section 3.4")
		}
		if seen[name] {
			return refuse("a permission name twice")
		}
		seen[name] = true
	}
	return PermissionRequest{Method: http.MethodPut,
		URL:  strings.TrimRight(baseURL, "/") + "/auth/api/apps/" + app + "/permissions",
		Body: map[string]any{"permissions": permissions}}, nil
}

func checkBaseURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("the base URL is no absolute URL")
	}
	switch u.Scheme {
	case "https":
		return nil
	case "http":
		host := u.Hostname()
		if ip, err := netip.ParseAddr(host); (err == nil && ip.Unmap().IsLoopback()) || host == "localhost" {
			return nil
		}
	}
	return errors.New("the base URL must be https (plain http only to a loopback address)")
}

// RegistrationError is a refusal by TinySesam (Status, 0 without an answer).
type RegistrationError struct {
	Status int
	Reason string
}

func (e *RegistrationError) Error() string {
	return fmt.Sprintf("tinysesam: permission registration failed (%d): %s", e.Status, e.Reason)
}

// RegisterPermissions registers the application's whole manifest with TinySesam (PUT /auth/api/apps/{id}/permissions)
// with an automation key of the application's service account (scope permissions:register), straight to TinySesam,
// never through the proxy. Registering grants nothing. It returns TinySesam's answer (added, updated, returned,
// orphaned). A manifest RegisterRequest refuses is never sent; any answer but 200 is a *RegistrationError. The
// deadline is FetchTimeout unless ctx ends earlier; the key goes in X-Api-Key and never into an error.
func RegisterPermissions(ctx context.Context, client *http.Client, baseURL, app string, permissions []any,
	apiKey string) (map[string]any, error) {
	req, err := RegisterRequest(baseURL, app, permissions)
	if err != nil {
		return nil, err
	}
	if apiKey == "" || hasControl(apiKey) {
		return nil, fmt.Errorf("%w: an API key is required", ErrManifest)
	}
	body, err := json.Marshal(req.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	ctx, cancel := context.WithTimeout(ctx, FetchTimeout)
	defer cancel()
	hr, err := http.NewRequestWithContext(ctx, req.Method, req.URL, bytes.NewReader(body))
	if err != nil {
		return nil, &RegistrationError{Reason: "request"}
	}
	hr.Header.Set("Content-Type", "application/json")
	hr.Header.Set("Accept", "application/json")
	hr.Header.Set("X-Api-Key", apiKey)
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(hr)
	if err != nil {
		return nil, &RegistrationError{Reason: "not reachable"}
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxJWKSBytes+1))
	if err != nil || len(raw) > MaxJWKSBytes {
		return nil, &RegistrationError{Status: resp.StatusCode, Reason: "unreadable answer"}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &RegistrationError{Status: resp.StatusCode, Reason: "refused"}
	}
	v, err := decodeStrictJSON(raw)
	out, ok := v.(map[string]any)
	if err != nil || !ok {
		return nil, &RegistrationError{Status: resp.StatusCode, Reason: "an answer that is no JSON object"}
	}
	return out, nil
}
