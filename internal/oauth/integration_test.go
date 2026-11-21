package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

func TestOAuthAuthorizationCodeRefreshRotationIntegration(t *testing.T) {
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL-backed OAuth integration tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err = pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	userID := uuid.NewString()
	username := "oauth-test-" + strings.ReplaceAll(uuid.NewString(), "-", "")
	password := "IntegrationTestPassword-Only-For-This-Run"
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,$3,TRUE)`, userID, username, string(hash)); err != nil {
		t.Fatal(err)
	}
	var clientID string
	t.Cleanup(func() {
		if clientID != "" {
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_tokens WHERE client_id=$1`, clientID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.access_tokens WHERE client_id=$1`, clientID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.authorization_codes WHERE client_id=$1`, clientID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.consents WHERE user_id=$1`, userID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_token_families WHERE client_id=$1`, clientID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.sessions WHERE user_id=$1`, userID)
			_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		}
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})

	issuer := "https://mcp-test.example/go-ssh-mcp"
	resource := issuer + "/mcp"
	server := New(pool, issuer, resource, []byte(strings.Repeat("K", 64)))
	rootMux := http.NewServeMux()
	server.RegisterRoutes(rootMux)
	mux := http.NewServeMux()
	mux.Handle("/go-ssh-mcp/", http.StripPrefix("/go-ssh-mcp", rootMux))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/go-ssh-mcp/mcp", func(w http.ResponseWriter, r *http.Request) {
		cloned := r.Clone(r.Context())
		cloned.URL.Path = "/.well-known/oauth-protected-resource/mcp"
		rootMux.ServeHTTP(w, cloned)
	})
	mux.HandleFunc("GET /.well-known/oauth-authorization-server/go-ssh-mcp", func(w http.ResponseWriter, r *http.Request) {
		cloned := r.Clone(r.Context())
		cloned.URL.Path = "/.well-known/oauth-authorization-server"
		rootMux.ServeHTTP(w, cloned)
	})
	ts := newTLSServer(t, mux)
	defer ts.Close()
	base := ts.URL + "/go-ssh-mcp"
	metaResp, metaErr := ts.Client().Get(ts.URL + "/.well-known/oauth-protected-resource/go-ssh-mcp/mcp")
	if metaErr != nil {
		t.Fatal(metaErr)
	}
	var resourceMeta map[string]any
	metaBody, _ := io.ReadAll(metaResp.Body)
	metaResp.Body.Close()
	if metaResp.StatusCode != http.StatusOK || json.Unmarshal(metaBody, &resourceMeta) != nil {
		t.Fatalf("resource metadata failed: %d %s", metaResp.StatusCode, metaBody)
	}
	if resourceMeta["resource"] != resource || metaResp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Fatalf("incorrect path-aware resource metadata: %s", metaBody)
	}
	asResp, asErr := ts.Client().Get(ts.URL + "/.well-known/oauth-authorization-server/go-ssh-mcp")
	if asErr != nil {
		t.Fatal(asErr)
	}
	var asMeta map[string]any
	asBody, _ := io.ReadAll(asResp.Body)
	asResp.Body.Close()
	if asResp.StatusCode != http.StatusOK || json.Unmarshal(asBody, &asMeta) != nil || asMeta["issuer"] != issuer || asMeta["authorization_endpoint"] != issuer+"/authorize" {
		t.Fatalf("authorization metadata failed: %d %s", asResp.StatusCode, asBody)
	}
	jar, _ := cookiejar.New(nil)
	client := ts.Client()
	client.Jar = jar
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }

	regBody := map[string]any{"client_name": "Integration Test Client", "application_type": "web", "redirect_uris": []string{"https://client.example/callback"}, "token_endpoint_auth_method": "none", "grant_types": []string{"authorization_code", "refresh_token"}, "response_types": []string{"code"}, "scope": scopeName}
	raw, _ := json.Marshal(regBody)
	resp, err := client.Post(base+"/register", "application/json", strings.NewReader(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	regRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("DCR status %d: %s", resp.StatusCode, regRaw)
	}
	var reg map[string]any
	if err = json.Unmarshal(regRaw, &reg); err != nil {
		t.Fatal(err)
	}
	clientID, _ = reg["client_id"].(string)
	if clientID == "" {
		t.Fatalf("missing client_id: %s", regRaw)
	}

	verifier := strings.Repeat("v", 43)
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	state := "state-" + uuid.NewString()
	badRedirectURL := base + "/authorize?" + url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://attacker.example/callback"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "state": {"bad-redirect"}, "scope": {scopeName}, "resource": {resource}}.Encode()
	badRedirectResp, badRedirectErr := client.Get(badRedirectURL)
	if badRedirectErr != nil {
		t.Fatal(badRedirectErr)
	}
	if badRedirectResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(badRedirectResp.Body)
		badRedirectResp.Body.Close()
		t.Fatalf("redirect URI mismatch was not rejected: %d %s", badRedirectResp.StatusCode, body)
	}
	badRedirectResp.Body.Close()
	authURL := base + "/authorize?" + url.Values{"response_type": {"code"}, "client_id": {clientID}, "redirect_uri": {"https://client.example/callback"}, "code_challenge_method": {"S256"}, "code_challenge": {challenge}, "state": {state}, "scope": {scopeName}, "resource": {resource}}.Encode()
	resp, err = client.Get(authURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("authorize status %d: %s", resp.StatusCode, b)
	}
	loginURL := ts.URL + resp.Header.Get("Location")
	resp.Body.Close()
	resp, err = client.Get(loginURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login page status %d: %s", resp.StatusCode, b)
	}
	resp.Body.Close()
	loginCSRF := cookieValue(t, jar, ts.URL, "go_ssh_mcp_login_csrf")
	loginForm := url.Values{"request": {queryValue(t, loginURL, "request")}, "login_csrf": {loginCSRF}, "username": {username}, "password": {password}}
	badLoginForm := cloneValues(loginForm)
	badLoginForm.Set("login_csrf", "invalid-csrf")
	badLoginResp, badLoginErr := client.PostForm(base+"/login", badLoginForm)
	if badLoginErr != nil {
		t.Fatal(badLoginErr)
	}
	if badLoginResp.StatusCode != http.StatusBadRequest {
		body, _ := io.ReadAll(badLoginResp.Body)
		badLoginResp.Body.Close()
		t.Fatalf("invalid login CSRF was not rejected: %d %s", badLoginResp.StatusCode, body)
	}
	badLoginResp.Body.Close()
	resp, err = client.PostForm(base+"/login", loginForm)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSeeOther {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("login status %d: %s", resp.StatusCode, b)
	}
	csrfCookieFound := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "go_ssh_mcp_csrf" {
			csrfCookieFound = true
			if cookie.SameSite != http.SameSiteLaxMode {
				t.Fatalf("CSRF cookie SameSite=%v; want Lax to survive cross-site OAuth entry redirects", cookie.SameSite)
			}
		}
	}
	if !csrfCookieFound {
		t.Fatal("login response did not set CSRF cookie")
	}
	consentURL := ts.URL + resp.Header.Get("Location")
	resp.Body.Close()
	resp, err = client.Get(consentURL)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("consent page status %d: %s", resp.StatusCode, b)
	}
	resp.Body.Close()
	csrf := cookieValue(t, jar, ts.URL, "go_ssh_mcp_csrf")
	consentForm := url.Values{"request": {queryValue(t, consentURL, "request")}, "csrf_token": {csrf}, "decision": {"approve"}}
	badConsentForm := cloneValues(consentForm)
	badConsentForm.Set("csrf_token", "invalid-csrf")
	badConsentResp, badConsentErr := client.PostForm(base+"/consent", badConsentForm)
	if badConsentErr != nil {
		t.Fatal(badConsentErr)
	}
	if badConsentResp.StatusCode != http.StatusForbidden {
		body, _ := io.ReadAll(badConsentResp.Body)
		badConsentResp.Body.Close()
		t.Fatalf("invalid consent CSRF was not rejected: %d %s", badConsentResp.StatusCode, body)
	}
	badConsentResp.Body.Close()
	resp, err = client.PostForm(base+"/consent", consentForm)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusFound {
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		t.Fatalf("consent status %d: %s", resp.StatusCode, b)
	}
	callback, err := url.Parse(resp.Header.Get("Location"))
	resp.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	code := callback.Query().Get("code")
	if code == "" || callback.Query().Get("state") != state || callback.Query().Get("iss") != issuer {
		t.Fatalf("invalid authorization redirect: %s", callback)
	}
	// A bad PKCE verifier must not consume the authorization code.
	badForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {strings.Repeat("x", 43)}, "resource": {resource}}
	resp, err = client.PostForm(base+"/token", badForm)
	if err != nil {
		t.Fatal(err)
	}
	badRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(badRaw), "invalid_grant") {
		t.Fatalf("bad PKCE was not rejected: %d %s", resp.StatusCode, badRaw)
	}
	goodForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {code}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}, "resource": {resource}}
	resp, err = client.PostForm(base+"/token", goodForm)
	if err != nil {
		t.Fatal(err)
	}
	tokenRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("token exchange failed: %d %s", resp.StatusCode, tokenRaw)
	}
	var first map[string]any
	if err = json.Unmarshal(tokenRaw, &first); err != nil {
		t.Fatal(err)
	}
	refresh1, _ := first["refresh_token"].(string)
	access1, _ := first["access_token"].(string)
	if refresh1 == "" || access1 == "" {
		t.Fatalf("missing tokens: %s", tokenRaw)
	}
	codeReuseResp, codeReuseErr := client.PostForm(base+"/token", goodForm)
	if codeReuseErr != nil {
		t.Fatal(codeReuseErr)
	}
	codeReuseBody, _ := io.ReadAll(codeReuseResp.Body)
	codeReuseResp.Body.Close()
	if codeReuseResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(codeReuseBody), "invalid_grant") {
		t.Fatalf("authorization code reuse was not rejected: %d %s", codeReuseResp.StatusCode, codeReuseBody)
	}
	expiredCode := "expired-code-" + uuid.NewString()
	_, err = pool.Exec(ctx, `INSERT INTO oauth.authorization_codes(id,code_hash,client_id,user_id,redirect_uri,code_challenge,scopes,resource,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,$7,now()-interval '1 minute')`, hashToken(expiredCode), clientID, userID, "https://client.example/callback", challenge, []string{scopeName}, resource)
	if err != nil {
		t.Fatal(err)
	}
	expiredForm := url.Values{"grant_type": {"authorization_code"}, "client_id": {clientID}, "code": {expiredCode}, "redirect_uri": {"https://client.example/callback"}, "code_verifier": {verifier}, "resource": {resource}}
	expiredResp, expiredErr := client.PostForm(base+"/token", expiredForm)
	if expiredErr != nil {
		t.Fatal(expiredErr)
	}
	expiredBody, _ := io.ReadAll(expiredResp.Body)
	expiredResp.Body.Close()
	if expiredResp.StatusCode != http.StatusBadRequest || !strings.Contains(string(expiredBody), "invalid_grant") {
		t.Fatalf("expired authorization code was not rejected: %d %s", expiredResp.StatusCode, expiredBody)
	}

	refreshForm := url.Values{"grant_type": {"refresh_token"}, "client_id": {clientID}, "refresh_token": {refresh1}, "resource": {resource}}
	resp, err = client.PostForm(base+"/token", refreshForm)
	if err != nil {
		t.Fatal(err)
	}
	refreshRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("refresh failed: %d %s", resp.StatusCode, refreshRaw)
	}
	var second map[string]any
	if err = json.Unmarshal(refreshRaw, &second); err != nil {
		t.Fatal(err)
	}
	refresh2, _ := second["refresh_token"].(string)
	access2, _ := second["access_token"].(string)
	if refresh2 == "" || refresh2 == refresh1 || access2 == "" {
		t.Fatalf("refresh rotation failed: %s", refreshRaw)
	}

	// Reuse of the old refresh token revokes the entire family.
	resp, err = client.PostForm(base+"/token", refreshForm)
	if err != nil {
		t.Fatal(err)
	}
	reuseRaw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(string(reuseRaw), "reuse detected") {
		t.Fatalf("refresh reuse not blocked: %d %s", resp.StatusCode, reuseRaw)
	}
	var revoked int
	if err = pool.QueryRow(ctx, `SELECT count(*) FROM oauth.access_tokens WHERE token_hash=ANY($1) AND revoked_at IS NOT NULL`, []string{hashToken(access1), hashToken(access2)}).Scan(&revoked); err != nil {
		t.Fatal(err)
	}
	if revoked != 2 {
		t.Fatalf("expected both family access tokens revoked after reuse, got %d", revoked)
	}
}

func newTLSServer(t *testing.T, h http.Handler) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(h)
}
func cookieValue(t *testing.T, jar http.CookieJar, rawURL, name string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range jar.Cookies(u) {
		if c.Name == name {
			return c.Value
		}
	}
	t.Fatalf("cookie %s not found", name)
	return ""
}
func cloneValues(v url.Values) url.Values {
	out := url.Values{}
	for k, values := range v {
		out[k] = append([]string(nil), values...)
	}
	return out
}

func queryValue(t *testing.T, rawURL, key string) string {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatal(err)
	}
	v := u.Query().Get(key)
	if v == "" {
		t.Fatalf("query parameter %s missing from %s", key, rawURL)
	}
	return v
}
