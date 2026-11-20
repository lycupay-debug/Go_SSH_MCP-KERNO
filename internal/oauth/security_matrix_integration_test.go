package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestOAuthAuthorizationAndGrantRejectionMatrixIntegration(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}

	userID := uuid.NewString()
	clientID := "oauth-matrix-" + uuid.NewString()
	username := "oauth-matrix-" + uuid.NewString()
	redirectURI := "https://client.example/callback"
	issuer := "https://issuer.example"
	resource := issuer + "/mcp"
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,'test-only',TRUE)`, userID, username); err != nil {
		t.Fatal(err)
	}
	metadata, _ := json.Marshal(map[string]any{
		"client_name":   "OAuth rejection matrix",
		"redirect_uris": []string{redirectURI},
		"scope":         scopeName + " offline_access " + remoteSSHScope,
	})
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,$2::jsonb,TRUE)`, clientID, string(metadata)); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_tokens WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_token_families WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.access_tokens WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.authorization_codes WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})

	s := New(pool, issuer, resource, []byte(strings.Repeat("M", 64)))
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	client := ts.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authorizeURL := func(scope, requestedResource string) string {
		values := url.Values{
			"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {redirectURI},
			"code_challenge_method": {"S256"}, "code_challenge": {challenge}, "state": {"matrix-state"},
		}
		if scope != "" {
			values.Set("scope", scope)
		}
		if requestedResource != "" {
			values.Set("resource", requestedResource)
		}
		return ts.URL + "/authorize?" + values.Encode()
	}
	request := func(method, endpoint string, form url.Values) (*http.Response, string) {
		t.Helper()
		var resp *http.Response
		var requestErr error
		if method == http.MethodGet {
			resp, requestErr = client.Get(endpoint)
		} else {
			resp, requestErr = client.PostForm(endpoint, form)
		}
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		return resp, string(body)
	}
	assertOAuthError := func(resp *http.Response, body, want string) {
		t.Helper()
		var payload map[string]string
		if err := json.Unmarshal([]byte(body), &payload); err != nil {
			t.Fatalf("invalid OAuth error response: status=%d body=%s err=%v", resp.StatusCode, body, err)
		}
		if resp.StatusCode != http.StatusBadRequest || payload["error"] != want {
			t.Fatalf("OAuth error status=%d error=%q want=%q body=%s", resp.StatusCode, payload["error"], want, body)
		}
	}

	// A missing resource defaults to the configured resource; invalid resource and scope are rejected before login.
	resp, body := request(http.MethodGet, authorizeURL(scopeName, ""), nil)
	if resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login?request=") {
		t.Fatalf("default resource authorization was not accepted: status=%d location=%q body=%s", resp.StatusCode, resp.Header.Get("Location"), body)
	}
	resp, _ = request(http.MethodGet, authorizeURL(scopeName, "https://wrong.example/mcp"), nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("wrong resource authorization status=%d want redirect error", resp.StatusCode)
	}
	wrongResourceRedirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || wrongResourceRedirect.Query().Get("error") != "invalid_target" || wrongResourceRedirect.Query().Get("state") != "matrix-state" {
		t.Fatalf("wrong resource was not rejected with state: location=%q err=%v", resp.Header.Get("Location"), err)
	}
	resp, _ = request(http.MethodGet, authorizeURL("unsupported:scope", resource), nil)
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("unsupported scope authorization status=%d want redirect error", resp.StatusCode)
	}
	unsupportedScopeRedirect, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || unsupportedScopeRedirect.Query().Get("error") != "invalid_scope" {
		t.Fatalf("unsupported scope was not rejected: location=%q err=%v", resp.Header.Get("Location"), err)
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=FALSE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}
	resp, body = request(http.MethodGet, authorizeURL(scopeName, resource), nil)
	assertOAuthError(resp, body, "invalid_client")
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=TRUE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}

	insertCode := func(code, storedResource string, expires time.Time) {
		t.Helper()
		_, insertErr := pool.Exec(ctx, `INSERT INTO oauth.authorization_codes(id,code_hash,client_id,user_id,redirect_uri,code_challenge,scopes,resource,expires_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.NewString(), hashToken(code), clientID, userID, redirectURI, challenge, []string{scopeName}, storedResource, expires)
		if insertErr != nil {
			t.Fatal(insertErr)
		}
	}
	postCode := func(code, redirect, codeVerifier, requestedResource string) (*http.Response, string) {
		form := url.Values{
			"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code},
			"redirect_uri": {redirect}, "code_verifier": {codeVerifier},
		}
		if requestedResource != "" {
			form.Set("resource", requestedResource)
		}
		return request(http.MethodPost, ts.URL+"/token", form)
	}
	validUntil := time.Now().Add(5 * time.Minute)

	wrongRedirectCode := "matrix-wrong-redirect-" + uuid.NewString()
	insertCode(wrongRedirectCode, resource, validUntil)
	resp, body = postCode(wrongRedirectCode, "https://attacker.example/callback", verifier, "")
	assertOAuthError(resp, body, "invalid_grant")

	wrongVerifierCode := "matrix-wrong-verifier-" + uuid.NewString()
	insertCode(wrongVerifierCode, resource, validUntil)
	resp, body = postCode(wrongVerifierCode, redirectURI, strings.Repeat("x", 43), "")
	assertOAuthError(resp, body, "invalid_grant")

	expiredCode := "matrix-expired-code-" + uuid.NewString()
	insertCode(expiredCode, resource, time.Now().Add(-time.Minute))
	resp, body = postCode(expiredCode, redirectURI, verifier, "")
	assertOAuthError(resp, body, "invalid_grant")

	wrongStoredResourceCode := "matrix-wrong-stored-resource-" + uuid.NewString()
	insertCode(wrongStoredResourceCode, "https://wrong.example/mcp", validUntil)
	resp, body = postCode(wrongStoredResourceCode, redirectURI, verifier, "")
	assertOAuthError(resp, body, "invalid_grant")

	wrongRequestedResourceCode := "matrix-wrong-request-resource-" + uuid.NewString()
	insertCode(wrongRequestedResourceCode, resource, validUntil)
	resp, body = postCode(wrongRequestedResourceCode, redirectURI, verifier, "https://wrong.example/mcp")
	assertOAuthError(resp, body, "invalid_target")

	disabledClientCode := "matrix-disabled-client-code-" + uuid.NewString()
	insertCode(disabledClientCode, resource, validUntil)
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=FALSE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}
	resp, body = postCode(disabledClientCode, redirectURI, verifier, "")
	assertOAuthError(resp, body, "invalid_grant")
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=TRUE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}

	disabledUserCode := "matrix-disabled-user-code-" + uuid.NewString()
	insertCode(disabledUserCode, resource, validUntil)
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=FALSE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	resp, body = postCode(disabledUserCode, redirectURI, verifier, "")
	assertOAuthError(resp, body, "invalid_grant")
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=TRUE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}

	insertRefresh := func(token, storedResource string, expires time.Time, revoked bool) string {
		t.Helper()
		familyID := uuid.NewString()
		if _, insertErr := pool.Exec(ctx, `INSERT INTO oauth.refresh_token_families(id,client_id,user_id) VALUES($1,$2,$3)`, familyID, clientID, userID); insertErr != nil {
			t.Fatal(insertErr)
		}
		var revokedAt *time.Time
		if revoked {
			now := time.Now()
			revokedAt = &now
		}
		if _, insertErr := pool.Exec(ctx, `INSERT INTO oauth.refresh_tokens(id,token_hash,family_id,client_id,user_id,scopes,resource,expires_at,revoked_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, uuid.NewString(), hashToken(token), familyID, clientID, userID, []string{scopeName}, storedResource, expires, revokedAt); insertErr != nil {
			t.Fatal(insertErr)
		}
		return familyID
	}
	postRefresh := func(token, requestedResource string) (*http.Response, string) {
		form := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {token}}
		if requestedResource != "" {
			form.Set("resource", requestedResource)
		}
		return request(http.MethodPost, ts.URL+"/token", form)
	}

	for _, tc := range []struct {
		name     string
		resource string
		expires  time.Time
		revoked  bool
		want     string
	}{
		{name: "expired", resource: resource, expires: time.Now().Add(-time.Minute), want: "invalid_grant"},
		{name: "revoked", resource: resource, expires: validUntil, revoked: true, want: "invalid_grant"},
		{name: "wrong stored resource", resource: "https://wrong.example/mcp", expires: validUntil, want: "invalid_grant"},
	} {
		t.Run("refresh_"+tc.name, func(t *testing.T) {
			token := "matrix-refresh-" + uuid.NewString()
			insertRefresh(token, tc.resource, tc.expires, tc.revoked)
			resp, body := postRefresh(token, "")
			assertOAuthError(resp, body, tc.want)
		})
	}

	disabledClientRefresh := "matrix-disabled-client-refresh-" + uuid.NewString()
	insertRefresh(disabledClientRefresh, resource, validUntil, false)
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=FALSE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}
	resp, body = postRefresh(disabledClientRefresh, "")
	assertOAuthError(resp, body, "invalid_grant")
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=TRUE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}

	disabledUserRefresh := "matrix-disabled-user-refresh-" + uuid.NewString()
	insertRefresh(disabledUserRefresh, resource, validUntil, false)
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=FALSE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	resp, body = postRefresh(disabledUserRefresh, "")
	assertOAuthError(resp, body, "invalid_grant")
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=TRUE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}

	wrongResourceRefresh := "matrix-request-resource-refresh-" + uuid.NewString()
	insertRefresh(wrongResourceRefresh, resource, validUntil, false)
	resp, body = postRefresh(wrongResourceRefresh, "https://wrong.example/mcp")
	assertOAuthError(resp, body, "invalid_target")
}

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	if dsn := strings.TrimSpace(os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")); dsn != "" {
		return dsn
	}
	t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL-backed OAuth rejection matrix")
	return ""
}

func TestOAuthAuditRedactsSecretFieldsIntegration(t *testing.T) {
	dsn := testDatabaseURL(t)
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	userID := uuid.NewString()
	clientID := "oauth-audit-redaction-" + uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,'unused',TRUE)`, userID, "oauth-audit-redaction-"+uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,'{}'::jsonb,TRUE)`, clientID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	}()
	server := New(pool, "https://oauth-audit.example", "https://oauth-audit.example/mcp", []byte(strings.Repeat("A", 64)))
	server.audit(ctx, "redaction.test", "success", userID, clientID, map[string]any{
		"password":           "OAUTH_PASSWORD_SENTINEL",
		"private_key":        "OAUTH_PRIVATE_KEY_SENTINEL",
		"passphrase":         "OAUTH_PASSPHRASE_SENTINEL",
		"access_token":       "OAUTH_ACCESS_TOKEN_SENTINEL",
		"refresh_token":      "OAUTH_REFRESH_TOKEN_SENTINEL",
		"authorization_code": "OAUTH_CODE_SENTINEL",
		"code_verifier":      "OAUTH_VERIFIER_SENTINEL",
		"scopes":             []string{scopeName},
		"resource":           "https://oauth-audit.example/mcp",
	})
	var details string
	if err = pool.QueryRow(ctx, `SELECT details::text FROM oauth.audit_log WHERE client_id=$1 AND event_type='redaction.test' ORDER BY id DESC LIMIT 1`, clientID).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{"OAUTH_PASSWORD_SENTINEL", "OAUTH_PRIVATE_KEY_SENTINEL", "OAUTH_PASSPHRASE_SENTINEL", "OAUTH_ACCESS_TOKEN_SENTINEL", "OAUTH_REFRESH_TOKEN_SENTINEL", "OAUTH_CODE_SENTINEL", "OAUTH_VERIFIER_SENTINEL"} {
		if strings.Contains(details, sentinel) {
			t.Errorf("OAuth audit persisted secret sentinel %s: %s", sentinel, details)
		}
	}
	if !strings.Contains(details, scopeName) || !strings.Contains(details, "resource") {
		t.Fatalf("OAuth audit lost allowed metadata: %s", details)
	}
}
