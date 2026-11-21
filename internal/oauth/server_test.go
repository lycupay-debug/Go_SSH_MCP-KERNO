package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestValidRedirectURI(t *testing.T) {
	cases := []struct {
		uri  string
		want bool
	}{
		{"https://client.example/callback", true},
		{"http://127.0.0.1:3456/callback", true},
		{"http://localhost/callback", true},
		{"http://example.com/callback", false},
		{"https://client.example/callback#fragment", false},
		{"javascript:alert(1)", false},
		{"https://user:pass@client.example/callback", false},
		{"/relative/callback", false},
	}
	for _, tc := range cases {
		if got := validRedirectURI(tc.uri); got != tc.want {
			t.Errorf("validRedirectURI(%q)=%v want %v", tc.uri, got, tc.want)
		}
	}
}
func TestScopeSubset(t *testing.T) {
	if !scopeSubset([]string{"go-ssh-mcp"}, []string{"go-ssh-mcp"}) {
		t.Fatal("expected supported scope")
	}
	if scopeSubset([]string{"admin"}, []string{"go-ssh-mcp"}) {
		t.Fatal("unsupported scope accepted")
	}
}
func TestSignedAuthorizationRequest(t *testing.T) {
	s := New(nil, "https://issuer.example", "https://issuer.example/mcp", []byte(strings.Repeat("x", 64)))
	in := signedRequest{ClientID: "client", RedirectURI: "https://client.example/callback", Challenge: strings.Repeat("a", 43), State: "state", Scopes: []string{scopeName}, Resource: s.Resource, Expires: time.Now().Add(time.Minute).Unix()}
	token, err := s.sign(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := s.verify(token)
	if err != nil {
		t.Fatal(err)
	}
	if out.ClientID != in.ClientID || out.RedirectURI != in.RedirectURI || out.State != in.State {
		t.Fatalf("round trip mismatch: %#v", out)
	}
	in.Expires = time.Now().Add(-time.Minute).Unix()
	token, err = s.sign(in)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = s.verify(token); err == nil {
		t.Fatal("expired request was accepted")
	}
}
func TestTokenHashIsFixedLengthAndOneWayShape(t *testing.T) {
	h := hashToken("opaque-secret")
	if len(h) != 64 {
		t.Fatalf("hash length=%d", len(h))
	}
	if h == "opaque-secret" {
		t.Fatal("token hash equals token")
	}
}

func TestOAuthMetadataAdvertisesRefreshScope(t *testing.T) {
	s := New(nil, "https://issuer.example", "https://issuer.example/mcp", []byte(strings.Repeat("x", 64)))
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	for _, path := range []string{"/.well-known/oauth-protected-resource/mcp", "/.well-known/oauth-authorization-server"} {
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, httptest.NewRequest("GET", path, nil))
		if rr.Code != 200 {
			t.Fatalf("%s status=%d body=%s", path, rr.Code, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		scopes, ok := body["scopes_supported"].([]any)
		if !ok {
			t.Fatalf("%s missing scopes_supported: %#v", path, body)
		}
		foundOffline, foundRemote := false, false
		for _, scope := range scopes {
			if scope == "offline_access" {
				foundOffline = true
			}
			if scope == remoteSSHScope {
				foundRemote = true
			}
		}
		if !foundOffline || !foundRemote {
			t.Fatalf("%s missing expected scopes: %#v", path, scopes)
		}
	}
	if !scopeSubset([]string{scopeName, "offline_access", remoteSSHScope}, []string{scopeName, "offline_access", remoteSSHScope}) {
		t.Fatal("go-ssh-mcp, offline_access and remote SSH scope should be accepted")
	}
}

func TestAuthorizationScopes(t *testing.T) {
	registered := []string{scopeName, remoteSSHScope}

	got := authorizationScopes("", registered)
	if len(got) != 2 || got[0] != scopeName || got[1] != remoteSSHScope {
		t.Fatalf("omitted scope should inherit registered scopes: %#v", got)
	}

	got = authorizationScopes("   ", registered)
	if len(got) != 2 || got[0] != scopeName || got[1] != remoteSSHScope {
		t.Fatalf("blank scope should inherit registered scopes: %#v", got)
	}

	got = authorizationScopes(scopeName, registered)
	if len(got) != 1 || got[0] != scopeName {
		t.Fatalf("explicit scope must not be expanded: %#v", got)
	}

	got = authorizationScopes(scopeName+" "+remoteSSHScope, registered)
	if len(got) != 2 || got[0] != scopeName || got[1] != remoteSSHScope {
		t.Fatalf("explicit multiple scopes were not preserved: %#v", got)
	}
}

func TestAuthorizationErrorRedirectIncludesStateAndIssuer(t *testing.T) {
	rr := httptest.NewRecorder()
	redirectURI := "https://chatgpt.com/connector/oauth/test-callback?existing=preserved"
	redirectWithError(rr, redirectURI, "invalid_scope", "state-123", "https://issuer.example")
	if rr.Code != http.StatusFound {
		t.Fatalf("status=%d, want %d", rr.Code, http.StatusFound)
	}
	target, err := url.Parse(rr.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	q := target.Query()
	if q.Get("error") != "invalid_scope" || q.Get("state") != "state-123" || q.Get("iss") != "https://issuer.example" {
		t.Fatalf("authorization error response missing OAuth parameters: %s", target.Redacted())
	}
	if q.Get("existing") != "preserved" {
		t.Fatalf("existing redirect query parameter was lost: %s", target.Redacted())
	}
}

func TestAuthorizationServerMetadataDoesNotSwitchExistingDCRRedirectMode(t *testing.T) {
	s := New(nil, "https://issuer.example", "https://issuer.example/mcp", []byte(strings.Repeat("x", 64)))
	rr := httptest.NewRecorder()
	s.authorizationServerMetadata(rr, httptest.NewRequest(http.MethodGet, "/.well-known/oauth-authorization-server", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("metadata status=%d", rr.Code)
	}
	var body map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if _, advertised := body["authorization_response_iss_parameter_supported"]; advertised {
		t.Fatal("do not advertise RFC 9207 stable-redirect mode until existing DCR redirect URIs are migrated")
	}
}

func TestAccessTokenTTLIs24Hours(t *testing.T) {
	if got := int(accessTokenTTL.Seconds()); got != 86400 {
		t.Fatalf("access token TTL=%d seconds, want 86400", got)
	}
}
