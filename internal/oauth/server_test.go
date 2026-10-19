package oauth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		found := false
		for _, scope := range scopes {
			if scope == "offline_access" {
				found = true
			}
		}
		if !found {
			t.Fatalf("%s does not advertise offline_access: %#v", path, scopes)
		}
	}
	if !scopeSubset([]string{scopeName, "offline_access"}, []string{scopeName, "offline_access"}) {
		t.Fatal("go-ssh-mcp plus offline_access should be accepted")
	}
}
