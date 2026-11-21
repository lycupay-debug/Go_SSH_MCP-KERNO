package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestRegisterClientPersistsBothRequiredScopesIntegration(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	server := New(pool, "https://issuer.example", "https://issuer.example/mcp", []byte(strings.Repeat("R", 64)))
	mux := http.NewServeMux()
	server.RegisterRoutes(mux)

	cases := []struct {
		name  string
		scope string
		want  string
	}{
		{name: "scope omitted", scope: "", want: scopeName + " " + remoteSSHScope},
		{name: "base scope only", scope: scopeName, want: scopeName + " " + remoteSSHScope},
		{name: "both scopes", scope: scopeName + " " + remoteSSHScope, want: scopeName + " " + remoteSSHScope},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := map[string]any{
				"client_name":      "OAuth scope policy integration test",
				"application_type": "web",
				"redirect_uris":    []string{"https://client.example/callback"},
			}
			if tc.scope != "" {
				metadata["scope"] = tc.scope
			}
			body, err := json.Marshal(metadata)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()
			mux.ServeHTTP(rr, req)
			if rr.Code != http.StatusCreated {
				t.Fatalf("registration status=%d body=%s", rr.Code, rr.Body.String())
			}

			var response map[string]any
			if err := json.Unmarshal(rr.Body.Bytes(), &response); err != nil {
				t.Fatal(err)
			}
			clientID, _ := response["client_id"].(string)
			if clientID == "" {
				t.Fatalf("registration response missing client_id: %#v", response)
			}
			t.Cleanup(func() {
				_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1`, clientID)
				_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
			})
			if got, _ := response["scope"].(string); got != tc.want {
				t.Fatalf("response scope=%q want %q", got, tc.want)
			}

			var stored string
			if err := pool.QueryRow(ctx, `SELECT metadata->>'scope' FROM oauth.clients WHERE client_id=$1`, clientID).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			if stored != tc.want {
				t.Fatalf("stored scope=%q want %q", stored, tc.want)
			}

			var auditDetailsRaw []byte
			if err := pool.QueryRow(ctx, `SELECT details FROM oauth.audit_log WHERE client_id=$1 AND event_type='client.registered' ORDER BY created_at DESC LIMIT 1`, clientID).Scan(&auditDetailsRaw); err != nil {
				t.Fatal(err)
			}
			var auditDetails map[string]any
			if err := json.Unmarshal(auditDetailsRaw, &auditDetails); err != nil {
				t.Fatal(err)
			}
			effectiveScopes, ok := auditDetails["effective_scopes"].([]any)
			if !ok || len(effectiveScopes) < 2 || effectiveScopes[0] != scopeName || effectiveScopes[1] != remoteSSHScope {
				t.Fatalf("audit effective_scopes=%#v want both required scopes", auditDetails["effective_scopes"])
			}
		})
	}
}
