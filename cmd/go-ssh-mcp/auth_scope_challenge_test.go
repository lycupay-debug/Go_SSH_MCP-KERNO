package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/auth"
)

func TestInitialOAuthScopeChallengeIncludesRemoteWithoutChangingBaseGate(t *testing.T) {
	verifier := func(_ context.Context, token string, _ *http.Request) (*auth.TokenInfo, error) {
		scopesByToken := map[string][]string{
			"base-token":   {"go-ssh-mcp"},
			"remote-token": {"remote:ssh:manage"},
			"full-token":   {"go-ssh-mcp", "remote:ssh:manage"},
		}
		scopes, ok := scopesByToken[token]
		if !ok {
			return nil, auth.ErrInvalidToken
		}
		return &auth.TokenInfo{UserID: "test-user", Scopes: scopes, Expiration: time.Now().Add(time.Hour)}, nil
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.TokenInfoFromContext(r.Context()) == nil {
			t.Fatal("authenticated token context missing")
		}
		w.WriteHeader(http.StatusNoContent)
	})
	protected := initialOAuthScopeChallenge(auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{
		ResourceMetadataURL: "https://mcp.example/.well-known/oauth-protected-resource",
		Scopes:              []string{"go-ssh-mcp"},
	})(handler))

	assertBothScopes := func(t *testing.T, response *httptest.ResponseRecorder) {
		t.Helper()
		challenge := response.Header().Get("WWW-Authenticate")
		for _, expected := range []string{
			"resource_metadata=",
			`scope="go-ssh-mcp remote:ssh:manage"`,
		} {
			if !strings.Contains(challenge, expected) {
				t.Fatalf("challenge %q does not contain %q", challenge, expected)
			}
		}
	}

	t.Run("initial unauthenticated request advertises both scopes", func(t *testing.T) {
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil))
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("status=%d want=%d", response.Code, http.StatusUnauthorized)
		}
		assertBothScopes(t, response)
	})

	t.Run("legacy base-scope token remains valid for base tools", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil)
		request.Header.Set("Authorization", "Bearer base-token")
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status=%d want=%d", response.Code, http.StatusNoContent)
		}
	})

	t.Run("token without base scope remains rejected", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil)
		request.Header.Set("Authorization", "Bearer remote-token")
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		if response.Code != http.StatusForbidden {
			t.Fatalf("status=%d want=%d", response.Code, http.StatusForbidden)
		}
		assertBothScopes(t, response)
	})

	t.Run("full-scope token is valid", func(t *testing.T) {
		request := httptest.NewRequest(http.MethodPost, "https://mcp.example/mcp", nil)
		request.Header.Set("Authorization", "Bearer full-token")
		response := httptest.NewRecorder()
		protected.ServeHTTP(response, request)
		if response.Code != http.StatusNoContent {
			t.Fatalf("status=%d want=%d", response.Code, http.StatusNoContent)
		}
	})
}
