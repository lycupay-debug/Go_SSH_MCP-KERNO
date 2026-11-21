package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/config"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/executor"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/remote"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/crypto/bcrypt"
)

func TestBearerTokenVerifierAndChallengeIntegration(t *testing.T) {
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL-backed auth tests")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	if err = pool.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	userID, clientID := uuid.NewString(), "token-test-"+uuid.NewString()
	username := "token-test-" + uuid.NewString()
	hash, err := bcrypt.GenerateFromPassword([]byte("IntegrationOnly-Password"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,$3,TRUE)`, userID, username, string(hash)); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,jsonb_build_object('client_name','token test'),TRUE)`, clientID); err != nil {
		t.Fatal(err)
	}
	token := "test-access-token-" + uuid.NewString()
	tokenHash := sha256.Sum256([]byte(token))
	tokenHashHex := hex.EncodeToString(tokenHash[:])
	resource := "https://example.invalid/mcp"
	_, err = pool.Exec(ctx, `INSERT INTO oauth.access_tokens(id,token_hash,client_id,user_id,scopes,resource,expires_at)
		VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,now()+interval '5 minutes')`, tokenHashHex, clientID, userID, []string{"go-ssh-mcp"}, resource)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.access_tokens WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})
	verifier := tokenVerifier(pool, resource)
	info, err := verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil))
	if err != nil || info == nil || info.UserID != userID {
		t.Fatalf("valid token rejected: info=%#v err=%v", info, err)
	}
	if got, _ := info.Extra["client_id"].(string); got != clientID {
		t.Fatalf("client id context=%q want %q", got, clientID)
	}
	if _, err = verifier(ctx, "not-a-valid-token", httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("invalid token accepted")
	}

	metadataURL := "https://example.invalid/.well-known/oauth-protected-resource/mcp"
	protected := auth.RequireBearerToken(verifier, &auth.RequireBearerTokenOptions{ResourceMetadataURL: metadataURL, Scopes: []string{"go-ssh-mcp"}})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.TokenInfoFromContext(r.Context()) == nil {
			http.Error(w, "missing token context", 500)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	noAuth := httptest.NewRecorder()
	protected.ServeHTTP(noAuth, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil))
	if noAuth.Code != http.StatusUnauthorized || !strings.Contains(noAuth.Header().Get("WWW-Authenticate"), metadataURL) {
		t.Fatalf("missing/incorrect OAuth challenge: %d %q", noAuth.Code, noAuth.Header().Get("WWW-Authenticate"))
	}
	validReq := httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)
	validReq.Header.Set("Authorization", "Bearer "+token)
	validResp := httptest.NewRecorder()
	protected.ServeHTTP(validResp, validReq)
	if validResp.Code != http.StatusNoContent {
		t.Fatalf("valid bearer request returned %d", validResp.Code)
	}

	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET scopes=$2 WHERE token_hash=$1`, tokenHashHex, []string{"other"}); err != nil {
		t.Fatal(err)
	}
	wrongScopeReq := httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)
	wrongScopeReq.Header.Set("Authorization", "Bearer "+token)
	wrongScopeResp := httptest.NewRecorder()
	protected.ServeHTTP(wrongScopeResp, wrongScopeReq)
	if wrongScopeResp.Code != http.StatusForbidden {
		t.Fatalf("wrong-scope token returned %d, want 403", wrongScopeResp.Code)
	}

	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET scopes=$2 WHERE token_hash=$1`, tokenHashHex, []string{}); err != nil {
		t.Fatal(err)
	}
	emptyScopeReq := httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)
	emptyScopeReq.Header.Set("Authorization", "Bearer "+token)
	emptyScopeResp := httptest.NewRecorder()
	protected.ServeHTTP(emptyScopeResp, emptyScopeReq)
	if emptyScopeResp.Code != http.StatusForbidden {
		t.Fatalf("empty-scope token returned %d, want 403", emptyScopeResp.Code)
	}

	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET scopes=$2,expires_at=now()-interval '1 second' WHERE token_hash=$1`, tokenHashHex, []string{"go-ssh-mcp"}); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("expired token accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET expires_at=now() WHERE token_hash=$1`, tokenHashHex); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("token at the expiry boundary was accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET expires_at=now()+interval '5 minutes',revoked_at=now() WHERE token_hash=$1`, tokenHashHex); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("revoked token accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET revoked_at=NULL,resource='https://wrong.example/mcp' WHERE token_hash=$1`, tokenHashHex); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("wrong-resource token accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET resource=$2 WHERE token_hash=$1`, tokenHashHex, resource); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=FALSE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("disabled user token accepted")
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.users SET is_enabled=TRUE WHERE id=$1`, userID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `UPDATE oauth.clients SET is_enabled=FALSE WHERE client_id=$1`, clientID); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("disabled client token accepted")
	}
}

func TestHTTPSReverseProxyMCPToolCallIntegration(t *testing.T) {
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL-backed HTTPS reverse-proxy integration")
	}
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
	clientID := "https-proxy-" + uuid.NewString()
	username := "https-proxy-" + uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,'unused-test-hash',TRUE)`, userID, username); err != nil {
		t.Fatal(err)
	}
	metadata := map[string]any{"client_name": "HTTPS reverse-proxy integration", "redirect_uris": []string{"http://127.0.0.1:18767/callback"}, "scope": "go-ssh-mcp"}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,$2::jsonb,TRUE)`, clientID, string(metadataJSON)); err != nil {
		t.Fatal(err)
	}
	validToken := "https-proxy-valid-" + uuid.NewString()
	wrongResourceToken := "https-proxy-wrong-resource-" + uuid.NewString()
	wrongScopeToken := "https-proxy-wrong-scope-" + uuid.NewString()
	tokenHash := func(value string) string {
		sum := sha256.Sum256([]byte(value))
		return hex.EncodeToString(sum[:])
	}

	edge := httptest.NewUnstartedServer(http.NotFoundHandler())
	edge.StartTLS()
	t.Cleanup(edge.Close)
	issuer := edge.URL
	resource := issuer + "/mcp"
	for _, item := range []struct {
		token    string
		scopes   []string
		resource string
	}{
		{validToken, []string{"go-ssh-mcp"}, resource},
		{wrongResourceToken, []string{"go-ssh-mcp"}, "https://wrong.example/mcp"},
		{wrongScopeToken, []string{"remote:ssh:manage"}, resource},
	} {
		if _, err = pool.Exec(ctx, `INSERT INTO oauth.access_tokens(id,token_hash,client_id,user_id,scopes,resource,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,now()+interval '5 minutes')`, tokenHash(item.token), clientID, userID, item.scopes, item.resource); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.access_tokens WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.authorization_codes WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_tokens WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_token_families WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.consents WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.sessions WHERE user_id=$1`, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})

	application := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	mcpServer := mcp.NewServer(&mcp.Implementation{Name: "HTTPS reverse-proxy test", Version: "1.0.0"}, nil)
	mcp.AddTool(mcpServer, &mcp.Tool{Name: "get_system_info", Description: "Read system information for the HTTPS proxy integration test."}, func(callCtx context.Context, req *mcp.CallToolRequest, in emptyInput) (*mcp.CallToolResult, map[string]any, error) {
		out, callErr := application.call(callCtx, "system.info", map[string]any{}, 15, "https-proxy-test")
		return nil, out, callErr
	})
	handler := mcp.NewStreamableHTTPHandler(func(r *http.Request) *mcp.Server { return mcpServer }, &mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true, DisableLocalhostProtection: true})
	resourceMetadataURL, err := protectedResourceMetadataURL(resource)
	if err != nil {
		t.Fatal(err)
	}
	authHandler := auth.RequireBearerToken(tokenVerifier(pool, resource), &auth.RequireBearerTokenOptions{ResourceMetadataURL: resourceMetadataURL, Scopes: []string{"go-ssh-mcp"}})
	mux := http.NewServeMux()
	mux.Handle("/mcp", authHandler(handler))
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"resource":"` + resource + `","authorization_servers":["` + issuer + `"]}`))
	})
	upstream := httptest.NewTLSServer(securityHeaders(mux))
	t.Cleanup(upstream.Close)
	target, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.Transport = upstream.Client().Transport
	edge.Config.Handler = proxy

	client := edge.Client()
	metadataResp, err := client.Get(edge.URL + "/.well-known/oauth-protected-resource/mcp")
	if err != nil {
		t.Fatal(err)
	}
	metadataBody, _ := io.ReadAll(metadataResp.Body)
	metadataResp.Body.Close()
	if metadataResp.StatusCode != http.StatusOK || !strings.Contains(string(metadataBody), resource) || !strings.Contains(string(metadataBody), issuer) {
		t.Fatalf("protected resource metadata did not survive HTTPS proxy: status=%d body=%s", metadataResp.StatusCode, metadataBody)
	}

	postMCP := func(token string, id int, method string, params map[string]any) (*http.Response, string) {
		t.Helper()
		payload, marshalErr := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		req, requestErr := http.NewRequest(http.MethodPost, edge.URL+"/mcp", bytes.NewReader(payload))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		if id != 1 {
			req.Header.Set("MCP-Protocol-Version", "2025-03-26")
		}
		resp, requestErr := client.Do(req)
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

	initResp, initBody := postMCP(validToken, 1, "initialize", map[string]any{"protocolVersion": "2025-03-26", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "https-proxy-test", "version": "1.0"}})
	if initResp.StatusCode != http.StatusOK || !strings.Contains(initBody, "protocolVersion") {
		t.Fatalf("HTTPS MCP initialize failed: status=%d body=%s", initResp.StatusCode, initBody)
	}
	callResp, callBody := postMCP(validToken, 2, "tools/call", map[string]any{"name": "get_system_info", "arguments": map[string]any{}})
	if callResp.StatusCode != http.StatusOK || !strings.Contains(callBody, "FreeBSD") {
		t.Fatalf("HTTPS authenticated MCP tool call failed: status=%d body=%s", callResp.StatusCode, callBody)
	}
	wrongResourceResp, wrongResourceBody := postMCP(wrongResourceToken, 3, "tools/call", map[string]any{"name": "get_system_info", "arguments": map[string]any{}})
	if wrongResourceResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("wrong-resource bearer token returned %d, want 401: %s", wrongResourceResp.StatusCode, wrongResourceBody)
	}
	wrongScopeResp, wrongScopeBody := postMCP(wrongScopeToken, 4, "tools/call", map[string]any{"name": "get_system_info", "arguments": map[string]any{}})
	if wrongScopeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("wrong-scope bearer token returned %d, want 403: %s", wrongScopeResp.StatusCode, wrongScopeBody)
	}
}

func testCExecutorPath(t *testing.T) string {
	t.Helper()
	p := os.Getenv("C_EXECUTOR_TEST_PATH")
	if p == "" {
		p = filepath.Join("..", "..", "bin", "host-executor")
	}
	if _, err := os.Stat(p); err != nil {
		t.Skip("build C executor first: " + err.Error())
	}
	return p
}
func TestSynchronousToolOutputParity(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	ctx := context.Background()
	info, err := a.call(ctx, "system.info", map[string]any{}, 15, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if info["runtime"] != "Go SDK + C executor" {
		t.Fatalf("runtime field mismatch: %#v", info)
	}
	if _, ok := info["python"]; ok {
		t.Fatalf("Python runtime field should not be advertised after port: %#v", info)
	}
	path := filepath.Join(t.TempDir(), "parity.txt")
	written, err := a.call(ctx, "file.write", map[string]any{"path": path, "content": "alpha\nbeta\nalpha\n"}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if written["success"] != true || written["previously_existed"] != false {
		t.Fatalf("unexpected write result: %#v", written)
	}
	read, err := a.call(ctx, "file.read", map[string]any{"path": path, "max_bytes": 5}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if read["content"] != "alpha" || read["truncated"] != true {
		t.Fatalf("unexpected read result: %#v", read)
	}
	if _, ok := read["bytes_read"]; ok {
		t.Fatalf("Python-compatible response must omit bytes_read: %#v", read)
	}
	replaced, err := a.call(ctx, "file.replace", map[string]any{"path": path, "old_text": "alpha", "new_text": "omega", "replace_all": false}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if replaced["matches"] != float64(2) || replaced["replacements"] != float64(1) {
		t.Fatalf("unexpected replace result: %#v", replaced)
	}
	afterReplace, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterReplace) != "omega\nbeta\nalpha\n" {
		t.Fatalf("replace_all=false must replace only the first match: %q", afterReplace)
	}
	shell, err := a.call(ctx, "shell.exec", map[string]any{"command": "printf out; printf err >&2; exit 7"}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if shell["returncode"] != float64(7) || shell["stdout"] != "out" || shell["stderr"] != "err" || shell["timed_out"] != false {
		t.Fatalf("unexpected shell result: %#v", shell)
	}
}
func TestSynchronousShellTimeoutReturnsStructuredResult(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	start := time.Now()
	out, err := a.call(context.Background(), "shell.exec", map[string]any{"command": "printf before; sleep 10", "timeout_seconds": 1}, 1, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["timed_out"] != true {
		t.Fatalf("expected timed_out result: %#v", out)
	}
	if out["stdout"] != "before" || out["cleanup_complete"] != true {
		t.Fatalf("timeout must preserve partial output and clean up process group: %#v", out)
	}
	if time.Since(start) > 4*time.Second {
		t.Fatalf("timeout cleanup took too long: %s", time.Since(start))
	}
}
func TestDirectoryToolReturnsPythonListShape(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := t.TempDir()
	if err := os.WriteFile(filepath.Join(path, "z.txt"), []byte("z"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "A.txt"), []byte("a"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "directory.list", map[string]any{"path": path}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(out["entries"])
	if err != nil {
		t.Fatal(err)
	}
	var entries []map[string]any
	if err = json.Unmarshal(raw, &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 || entries[0]["name"] != "A.txt" || entries[1]["name"] != "z.txt" {
		t.Fatalf("directory entries not sorted like Python: %#v", entries)
	}
	if entries[0]["path"] != filepath.Join(path, "A.txt") {
		t.Fatalf("entry path mismatch: %#v", entries[0])
	}
}

func TestShellOutputReturnsTailLikePython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	out, err := a.call(context.Background(), "shell.exec", map[string]any{"command": "yes x | head -c 1100000; printf END", "timeout_seconds": 10}, 10, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	stdout, ok := out["stdout"].(string)
	if !ok {
		t.Fatalf("stdout missing: %#v", out)
	}
	if len([]rune(stdout)) > 30000 {
		t.Fatalf("stdout exceeds Python's 30000-character tail limit: %d", len([]rune(stdout)))
	}
	if !strings.HasSuffix(stdout, "END") {
		t.Fatalf("stdout should preserve the tail, got suffix %q", stdout[max(0, len(stdout)-20):])
	}
}

func TestProcessFileWritePreservesUnicodeAndNUL(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "unicode.bin")
	content := "A\x00中"
	out, err := a.call(context.Background(), "file.write", map[string]any{"path": path, "content": content}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["characters_written"] != float64(3) || out["previously_existed"] != false {
		t.Fatalf("unexpected Unicode write result: %#v", out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatalf("write changed UTF-8/NUL bytes: %q", got)
	}
	read, err := a.call(context.Background(), "file.read", map[string]any{"path": path, "max_bytes": 32}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if read["content"] != content || read["truncated"] != false {
		t.Fatalf("unexpected Unicode read result: %#v", read)
	}
}
func TestProcessFileWriteFollowsSymlinkLikePython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "file.write", map[string]any{"path": link, "content": "new"}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["previously_existed"] != true {
		t.Fatalf("symlink target should count as existing: %#v", out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("write should follow symlink, got %q", got)
	}
	st, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode()&os.ModeSymlink == 0 {
		t.Fatal("write replaced the symlink instead of following it")
	}
}

func TestAtomicWriteFollowsSymlinkAndBreaksHardlink(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	root := t.TempDir()

	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "file.write", map[string]any{"path": link, "content": "symlink-new", "atomic": true}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["previously_existed"] != true {
		t.Fatalf("unexpected atomic symlink write result: %#v", out)
	}
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "symlink-new" {
		t.Fatalf("atomic write did not update symlink target: %q", got)
	}
	linkInfo, err := os.Lstat(link)
	if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("atomic write replaced the symlink itself: info=%v err=%v", linkInfo, err)
	}

	hardTarget := filepath.Join(root, "hard-target.txt")
	hardAlias := filepath.Join(root, "hard-alias.txt")
	if err := os.WriteFile(hardTarget, []byte("hard-old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(hardTarget, hardAlias); err != nil {
		t.Fatal(err)
	}
	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": hardTarget, "content": "hard-new", "atomic": true}, 5, "test-actor"); err != nil {
		t.Fatal(err)
	}
	targetBytes, err := os.ReadFile(hardTarget)
	if err != nil {
		t.Fatal(err)
	}
	aliasBytes, err := os.ReadFile(hardAlias)
	if err != nil {
		t.Fatal(err)
	}
	if string(targetBytes) != "hard-new" || string(aliasBytes) != "hard-old" {
		t.Fatalf("atomic write hardlink semantics mismatch: target=%q alias=%q", targetBytes, aliasBytes)
	}
	targetInfo, err := os.Stat(hardTarget)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(hardAlias)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(targetInfo, aliasInfo) {
		t.Fatal("atomic write should detach the replaced path from the old hardlink inode")
	}

	newPath := filepath.Join(root, "created", "nested.txt")
	created, err := a.call(context.Background(), "file.write", map[string]any{"path": newPath, "content": "created", "create_parents": true, "atomic": true}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if created["previously_existed"] != false {
		t.Fatalf("new atomic file should report previously_existed=false: %#v", created)
	}
	createdBytes, err := os.ReadFile(newPath)
	if err != nil || string(createdBytes) != "created" {
		t.Fatalf("atomic create_parents failed: content=%q err=%v", createdBytes, err)
	}

	oldUmask := syscall.Umask(0077)
	umaskPath := filepath.Join(root, "umask-created.txt")
	_, umaskErr := a.call(context.Background(), "file.write", map[string]any{"path": umaskPath, "content": "mode", "atomic": true}, 5, "test-actor")
	syscall.Umask(oldUmask)
	if umaskErr != nil {
		t.Fatalf("atomic create with restrictive umask failed: %v", umaskErr)
	}
	umaskInfo, err := os.Stat(umaskPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := umaskInfo.Mode().Perm(); got != 0600 {
		t.Fatalf("atomic new-file mode ignored umask: got %o want 600", got)
	}

	dangling := filepath.Join(root, "dangling-link")
	if err := os.Symlink(filepath.Join(root, "missing-target"), dangling); err != nil {
		t.Fatal(err)
	}
	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": dangling, "content": "must-not-create", "atomic": true}, 5, "test-actor"); err == nil {
		t.Fatal("atomic write should reject a dangling symlink rather than replace the link")
	}
	if _, err := os.Lstat(dangling); err != nil {
		t.Fatalf("dangling symlink should remain after rejected atomic write: %v", err)
	}
}

func TestAtomicOperationsRejectConcurrentMetadataMutation(t *testing.T) {
	for _, operation := range []string{"file.write", "file.replace"} {
		for _, metadataKind := range []string{"user-extattr", "system-extattr", "posix-acl", "nfs4-acl"} {
			for _, checkpoint := range []string{"after-copy", "after-fsync", "before-rename"} {
				t.Run(operation+"/"+metadataKind+"/"+checkpoint, func(t *testing.T) {
					root := os.Getenv("KERNO_METADATA_RACE_TEST_DIR")
					if root == "" {
						root = t.TempDir()
					}
					path := filepath.Join(root, "metadata-race-"+strings.ReplaceAll(operation, ".", "-")+"-"+metadataKind+".txt")
					if err := os.WriteFile(path, []byte("needle-original-content"), 0600); err != nil {
						t.Fatal(err)
					}
					switch metadataKind {
					case "user-extattr", "system-extattr":
						namespace := strings.TrimSuffix(metadataKind, "-extattr")
						if output, err := exec.Command("setextattr", namespace, "kerno.race", "baseline", path).CombinedOutput(); err != nil {
							t.Skipf("filesystem does not support %s extattrs: %v: %s", namespace, err, output)
						}
					case "posix-acl":
						if output, err := exec.Command("setfacl", "-m", "u:12345:r--", path).CombinedOutput(); err != nil {
							t.Skipf("filesystem does not support POSIX ACLs: %v: %s", err, output)
						}
					case "nfs4-acl":
						if output, err := exec.Command("setfacl", "-m", "user:12345:r:allow", path).CombinedOutput(); err != nil {
							t.Skipf("filesystem does not support NFSv4 ACLs: %v: %s", err, output)
						}
					}

					readyPath := filepath.Join(root, "ready-"+metadataKind+"-"+checkpoint+"-"+strings.ReplaceAll(operation, ".", "-"))
					resumePath := filepath.Join(root, "resume-"+metadataKind+"-"+checkpoint+"-"+strings.ReplaceAll(operation, ".", "-"))
					_ = os.Remove(readyPath)
					_ = os.Remove(resumePath)
					t.Setenv("KERNO_TEST_METADATA_BARRIER", checkpoint)
					t.Setenv("KERNO_TEST_METADATA_COPY_READY", readyPath)
					t.Setenv("KERNO_TEST_METADATA_COPY_RESUME", resumePath)

					a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(root, "audit-"+metadataKind+".log")}
					type callResult struct {
						out map[string]any
						err error
					}
					ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
					defer cancel()
					resultCh := make(chan callResult, 1)
					go func() {
						var out map[string]any
						var callErr error
						if operation == "file.write" {
							out, callErr = a.call(ctx, operation, map[string]any{"path": path, "content": "replacement-content", "atomic": true}, 30, "test-actor")
						} else {
							out, callErr = a.call(ctx, operation, map[string]any{"path": path, "old_text": "needle", "new_text": "changed"}, 30, "test-actor")
						}
						resultCh <- callResult{out: out, err: callErr}
					}()

					deadline := time.Now().Add(10 * time.Second)
					for {
						if _, err := os.Stat(readyPath); err == nil {
							break
						}
						select {
						case result := <-resultCh:
							t.Fatalf("operation completed before metadata-copy barrier: out=%#v err=%v", result.out, result.err)
						default:
						}
						if time.Now().After(deadline) {
							t.Fatal("timed out waiting for C executor metadata-copy barrier")
						}
						time.Sleep(time.Millisecond)
					}

					switch metadataKind {
					case "user-extattr", "system-extattr":
						namespace := strings.TrimSuffix(metadataKind, "-extattr")
						if output, err := exec.Command("setextattr", namespace, "kerno.race", "concurrent-writer", path).CombinedOutput(); err != nil {
							t.Fatalf("concurrent %s extattr mutation failed: %v: %s", namespace, err, output)
						}
					case "posix-acl":
						if output, err := exec.Command("setfacl", "-m", "u:12345:rw-", path).CombinedOutput(); err != nil {
							t.Fatalf("concurrent POSIX ACL mutation failed: %v: %s", err, output)
						}
					case "nfs4-acl":
						if output, err := exec.Command("setfacl", "-m", "user:12345:rw:allow", path).CombinedOutput(); err != nil {
							t.Fatalf("concurrent NFSv4 ACL mutation failed: %v: %s", err, output)
						}
					}
					if err := os.WriteFile(resumePath, []byte("continue"), 0600); err != nil {
						t.Fatal(err)
					}
					result := <-resultCh
					if result.err == nil || !strings.Contains(result.err.Error(), "ATOMIC_TARGET_CHANGED") {
						t.Fatalf("metadata-only concurrent mutation should reject atomic commit, out=%#v err=%v", result.out, result.err)
					}
					content, err := os.ReadFile(path)
					if err != nil || string(content) != "needle-original-content" {
						t.Fatalf("source content changed despite rejected operation: content=%q err=%v", content, err)
					}
					switch metadataKind {
					case "user-extattr", "system-extattr":
						namespace := strings.TrimSuffix(metadataKind, "-extattr")
						output, err := exec.Command("getextattr", namespace, "kerno.race", path).CombinedOutput()
						if err != nil || !strings.Contains(string(output), "concurrent-writer") {
							t.Fatalf("concurrent %s extattr value was not preserved: output=%s err=%v", namespace, output, err)
						}
					case "posix-acl":
						output, err := exec.Command("getfacl", "-n", path).CombinedOutput()
						if err != nil || !strings.Contains(string(output), "user:12345:rw-") {
							t.Fatalf("concurrent POSIX ACL was not preserved: output=%s err=%v", output, err)
						}
					case "nfs4-acl":
						output, err := exec.Command("getfacl", "-n", path).CombinedOutput()
						found := false
						for _, line := range strings.Split(string(output), "\n") {
							line = strings.TrimSpace(line)
							if strings.HasPrefix(line, "user:12345:") && strings.HasSuffix(line, ":allow") && strings.Contains(line, ":rw") {
								found = true
								break
							}
						}
						if err != nil || !found {
							t.Fatalf("concurrent NFSv4 ACL was not preserved: output=%s err=%v", output, err)
						}
					}
					entries, err := os.ReadDir(root)
					if err != nil {
						t.Fatal(err)
					}
					for _, entry := range entries {
						if strings.HasPrefix(entry.Name(), filepath.Base(path)+".tmp.") {
							t.Errorf("rejected metadata mutation left temporary file %q", entry.Name())
						}
					}
				})
			}
		}
	}
}

func TestAtomicOperationsPreserveExtendedAttributesAndFileFlags(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "metadata.txt")
	if err := os.WriteFile(path, []byte("old-value"), 0640); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("setextattr", "user", "kerno.test", "metadata-value", path).CombinedOutput(); err != nil {
		t.Fatalf("setextattr failed: %v: %s", err, output)
	}
	if output, err := exec.Command("chflags", "nodump", path).CombinedOutput(); err != nil {
		t.Fatalf("chflags nodump failed: %v: %s", err, output)
	}

	aclSupported := true
	if output, err := exec.Command("setfacl", "-m", "u:12345:r--", path).CombinedOutput(); err != nil {
		if strings.Contains(string(output), "Operation not supported") {
			aclSupported = false
			t.Log("filesystem does not support ACLs; ACL preservation assertion skipped")
		} else {
			t.Fatalf("setfacl failed: %v: %s", err, output)
		}
	}

	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": path, "content": "new-value", "atomic": true}, 5, "test-actor"); err != nil {
		t.Fatalf("atomic write failed: %v", err)
	}
	verifyMetadata := func(stage string) {
		t.Helper()
		extattr, err := exec.Command("getextattr", "user", "kerno.test", path).CombinedOutput()
		if err != nil || !strings.Contains(string(extattr), "metadata-value") {
			t.Fatalf("%s: extended attribute lost: output=%s err=%v", stage, extattr, err)
		}
		flags, err := exec.Command("stat", "-f", "%Sf", path).CombinedOutput()
		if err != nil || !strings.Contains(string(flags), "nodump") {
			t.Fatalf("%s: nodump flag lost: output=%s err=%v", stage, flags, err)
		}
		if aclSupported {
			acl, err := exec.Command("getfacl", "-n", path).CombinedOutput()
			if err != nil || !strings.Contains(string(acl), "user:12345:r--") {
				t.Fatalf("%s: access ACL lost: output=%s err=%v", stage, acl, err)
			}
		}
	}
	verifyMetadata("after atomic write")

	if _, err := a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "new", "new_text": "replace"}, 5, "test-actor"); err != nil {
		t.Fatalf("streaming atomic replace failed: %v", err)
	}
	verifyMetadata("after atomic replace")

	immutablePath := filepath.Join(t.TempDir(), "immutable.txt")
	if err := os.WriteFile(immutablePath, []byte("immutable-original"), 0600); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("chflags", "uchg", immutablePath).CombinedOutput(); err != nil {
		t.Fatalf("set user immutable flag failed: %v: %s", err, output)
	}
	_, operationErr := a.call(context.Background(), "file.write", map[string]any{"path": immutablePath, "content": "must-not-replace", "atomic": true}, 5, "test-actor")
	if operationErr == nil || !strings.Contains(operationErr.Error(), "ATOMIC_FILE_FLAGS_UNSUPPORTED") {
		_ = exec.Command("chflags", "nouchg", immutablePath).Run()
		t.Fatalf("atomic write should reject immutable target flags, got %v", operationErr)
	}
	if output, err := exec.Command("chflags", "nouchg", immutablePath).CombinedOutput(); err != nil {
		t.Fatalf("clear user immutable flag failed: %v: %s", err, output)
	}
	original, err := os.ReadFile(immutablePath)
	if err != nil || string(original) != "immutable-original" {
		t.Fatalf("immutable target changed despite rejected atomic write: content=%q err=%v", original, err)
	}
}

func TestAtomicOperationsPreservePOSIXACLOnMountedFilesystem(t *testing.T) {
	aclRoot := os.Getenv("KERNO_ACL_TEST_DIR")
	if aclRoot == "" {
		t.Skip("set KERNO_ACL_TEST_DIR to a mounted ACL-capable filesystem")
	}
	root, err := os.MkdirTemp(aclRoot, "kerno-acl-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(root, "audit.log")}
	path := filepath.Join(root, "acl-file.txt")
	if err := os.WriteFile(path, []byte("before"), 0640); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("setfacl", "-m", "u:12345:r--", path).CombinedOutput(); err != nil {
		t.Fatalf("set POSIX ACL failed: %v: %s", err, output)
	}
	verifyACL := func(stage string) {
		t.Helper()
		output, err := exec.Command("getfacl", "-n", path).CombinedOutput()
		if err != nil || !strings.Contains(string(output), "user:12345:r--") {
			t.Fatalf("%s: POSIX ACL missing after atomic operation: output=%s err=%v", stage, output, err)
		}
	}
	verifyACL("before")
	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": path, "content": "after-write", "atomic": true}, 5, "test-actor"); err != nil {
		t.Fatalf("atomic write with POSIX ACL failed: %v", err)
	}
	verifyACL("after atomic write")
	if _, err := a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "after", "new_text": "replaced"}, 5, "test-actor"); err != nil {
		t.Fatalf("atomic replace with POSIX ACL failed: %v", err)
	}
	verifyACL("after atomic replace")
}

func TestAtomicOperationsPreserveNFSv4ACLOnMountedFilesystem(t *testing.T) {
	aclRoot := os.Getenv("KERNO_NFS4_ACL_TEST_DIR")
	if aclRoot == "" {
		t.Skip("set KERNO_NFS4_ACL_TEST_DIR to a mounted NFSv4-ACL filesystem")
	}
	root, err := os.MkdirTemp(aclRoot, "kerno-nfs4-acl-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(root, "audit.log")}
	path := filepath.Join(root, "nfs4-acl-file.txt")
	if err := os.WriteFile(path, []byte("before"), 0640); err != nil {
		t.Fatal(err)
	}
	if output, err := exec.Command("setfacl", "-m", "user:12345:r:allow", path).CombinedOutput(); err != nil {
		t.Fatalf("set NFSv4 ACL failed: %v: %s", err, output)
	}
	verifyACL := func(stage string) {
		t.Helper()
		output, err := exec.Command("getfacl", "-n", path).CombinedOutput()
		found := false
		for _, line := range strings.Split(string(output), "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "user:12345:") && strings.HasSuffix(line, ":allow") {
				found = true
				break
			}
		}
		if err != nil || !found {
			t.Fatalf("%s: NFSv4 ACL missing after atomic operation: output=%s err=%v", stage, output, err)
		}
	}
	verifyACL("before")
	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": path, "content": "after-write", "atomic": true}, 5, "test-actor"); err != nil {
		t.Fatalf("atomic write with NFSv4 ACL failed: %v", err)
	}
	verifyACL("after atomic write")
	if _, err := a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "after", "new_text": "replaced"}, 5, "test-actor"); err != nil {
		t.Fatalf("atomic replace with NFSv4 ACL failed: %v", err)
	}
	verifyACL("after atomic replace")
}

func TestRepeatedAtomicWriteToSameFile(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "repeated-atomic.txt")
	if err := os.WriteFile(path, []byte("initial"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		content := fmt.Sprintf("iteration-%03d", i)
		if _, err := a.call(context.Background(), "file.write", map[string]any{"path": path, "content": content, "atomic": true}, 5, "test-actor"); err != nil {
			t.Fatalf("atomic write iteration %d failed: %v", i, err)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != content {
			t.Fatalf("atomic write iteration %d content=%q want=%q", i, got, content)
		}
	}
}

func TestRepeatedAtomicReplaceToSameFile(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "repeated-replace.txt")
	if err := os.WriteFile(path, []byte("needle"), 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		oldText, newText := "needle", "changed"
		if i%2 == 1 {
			oldText, newText = newText, oldText
		}
		out, err := a.call(context.Background(), "file.replace", map[string]any{
			"path": path, "old_text": oldText, "new_text": newText, "replace_all": true,
		}, 5, "test-actor")
		if err != nil {
			t.Fatalf("atomic replace iteration %d failed: %v", i, err)
		}
		if out["success"] != true || out["matches"] != float64(1) || out["replacements"] != float64(1) {
			t.Fatalf("atomic replace iteration %d returned unexpected result: %#v", i, out)
		}
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != newText {
			t.Fatalf("atomic replace iteration %d content=%q want=%q", i, got, newText)
		}
	}
}

func TestStreamingAtomicReplaceRejectsConcurrentSourceWrite(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	root := t.TempDir()
	path := filepath.Join(root, "concurrent-source.bin")
	const originalSize int64 = 512 * 1024 * 1024
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(originalSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("needle"), originalSize-6); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	type callResult struct {
		out map[string]any
		err error
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	resultCh := make(chan callResult, 1)
	go func() {
		out, callErr := a.call(ctx, "file.replace", map[string]any{
			"path": path, "old_text": "needle", "new_text": "change", "replace_all": true,
		}, 60, "test-actor")
		resultCh <- callResult{out: out, err: callErr}
	}()

	// Wait until the temporary destination has received its first output chunk.
	// At this point the source baseline has already been captured and staging is active.
	deadline := time.Now().Add(30 * time.Second)
	stagingObserved := false
	for time.Now().Before(deadline) {
		entries, readErr := os.ReadDir(root)
		if readErr != nil {
			t.Fatal(readErr)
		}
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), filepath.Base(path)+".tmp.") {
				continue
			}
			info, statErr := entry.Info()
			if statErr == nil && info.Size() >= 64*1024 {
				stagingObserved = true
				break
			}
		}
		if stagingObserved {
			break
		}
		select {
		case result := <-resultCh:
			t.Fatalf("replace completed before staging observation: out=%#v err=%v", result.out, result.err)
		default:
			time.Sleep(time.Millisecond)
		}
	}
	if !stagingObserved {
		t.Fatal("timed out waiting for atomic replacement staging output")
	}

	writer, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = writer.WriteAt([]byte{0x7f}, 0); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err = writer.Sync(); err != nil {
		writer.Close()
		t.Fatal(err)
	}
	if err = writer.Close(); err != nil {
		t.Fatal(err)
	}

	result := <-resultCh
	if result.err == nil || !strings.Contains(result.err.Error(), "ATOMIC_TARGET_CHANGED") {
		t.Fatalf("concurrent source write should reject atomic commit, out=%#v err=%v", result.out, result.err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != originalSize {
		t.Fatalf("source size changed after rejected commit: got %d want %d", info.Size(), originalSize)
	}
	first := make([]byte, 1)
	check, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = check.ReadAt(first, 0); err != nil {
		check.Close()
		t.Fatal(err)
	}
	tail := make([]byte, 6)
	if _, err = check.ReadAt(tail, originalSize-6); err != nil {
		check.Close()
		t.Fatal(err)
	}
	if err = check.Close(); err != nil {
		t.Fatal(err)
	}
	if first[0] != 0x7f || string(tail) != "needle" {
		t.Fatalf("source writer's change or original tail was lost: first=%x tail=%q", first[0], tail)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filepath.Base(path)+".tmp.") {
			t.Errorf("rejected concurrent write left temporary file %q", entry.Name())
		}
	}
}

func TestStreamingAtomicReplaceAcrossChunkBoundaryAndLinkSemantics(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	root := t.TempDir()
	target := filepath.Join(root, "target.bin")
	link := filepath.Join(root, "link.bin")
	alias := filepath.Join(root, "hard-alias.bin")

	prefix := strings.Repeat("p", 64*1024-2)
	original := prefix + "XYZ" + "\x00middleXYZ"
	if err := os.WriteFile(target, []byte(original), 0640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(target, alias); err != nil {
		t.Fatal(err)
	}

	out, err := a.call(context.Background(), "file.replace", map[string]any{"path": link, "old_text": "XYZ", "new_text": "Q\x00R", "replace_all": true}, 10, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["success"] != true || out["matches"] != float64(2) || out["replacements"] != float64(2) {
		t.Fatalf("unexpected streaming replace result: %#v", out)
	}
	want := prefix + "Q\x00R" + "\x00middleQ\x00R"
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Fatalf("streaming replace content mismatch: got length=%d want length=%d", len(got), len(want))
	}
	targetMode, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if targetMode.Mode().Perm() != 0640 {
		t.Fatalf("atomic replace did not preserve mode: got %o want 640", targetMode.Mode().Perm())
	}
	aliasBytes, err := os.ReadFile(alias)
	if err != nil {
		t.Fatal(err)
	}
	if string(aliasBytes) != original {
		t.Fatalf("atomic replace should leave the other hardlink on the original inode: alias_len=%d original_len=%d alias_prefix=%q original_prefix=%q", len(aliasBytes), len(original), aliasBytes[:min(len(aliasBytes), 24)], original[:min(len(original), 24)])
	}
	linkInfo, err := os.Lstat(link)
	if err != nil || linkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("atomic replace replaced the symlink itself: info=%v err=%v", linkInfo, err)
	}
	targetInfo, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Stat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(targetInfo, aliasInfo) {
		t.Fatal("atomic replace should detach the target path from the old hardlink inode")
	}
}

func TestStreamingReplaceBeyondLegacyINTMAX(t *testing.T) {
	if os.Getenv("KERNO_LARGE_FILE_TEST") != "1" {
		t.Skip("set KERNO_LARGE_FILE_TEST=1 to run the >2 GiB streaming replacement test")
	}
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "sparse-over-intmax.bin")
	const originalSize int64 = 2*1024*1024*1024 + 4096
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(originalSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("TARGET"), originalSize-6); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	out, err := a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "TARGET", "new_text": "DONE"}, 120, "test-actor")
	if err != nil {
		t.Fatalf("streaming replacement of >2 GiB file failed: %v", err)
	}
	if out["matches"] != float64(1) || out["replacements"] != float64(1) {
		t.Fatalf("unexpected large-file replacement counts: %#v", out)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != originalSize-2 {
		t.Fatalf("large-file size = %d, want %d", info.Size(), originalSize-2)
	}
	result, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	tail := make([]byte, 4)
	if _, err = result.ReadAt(tail, info.Size()-int64(len(tail))); err != nil {
		t.Fatal(err)
	}
	if string(tail) != "DONE" {
		t.Fatalf("large-file tail = %q, want DONE", tail)
	}
}

func TestStreamingAtomicReplaceTimeoutLeavesOriginalUnchanged(t *testing.T) {
	if os.Getenv("KERNO_LARGE_FILE_TEST") != "1" {
		t.Skip("set KERNO_LARGE_FILE_TEST=1 to run the forced-termination atomicity test")
	}
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "replace-timeout.bin")
	const originalSize int64 = 2*1024*1024*1024 + 4096
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = file.Truncate(originalSize); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if _, err = file.WriteAt([]byte("TARGET"), originalSize-6); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err = file.Close(); err != nil {
		t.Fatal(err)
	}

	_, err = a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "TARGET", "new_text": "DONE"}, 1, "test-actor")
	if err == nil {
		t.Fatal("large streaming replace unexpectedly completed before timeout")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != originalSize {
		t.Fatalf("source file size changed after forced termination: got %d want %d", info.Size(), originalSize)
	}
	result, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	tail := make([]byte, 6)
	if _, err = result.ReadAt(tail, originalSize-int64(len(tail))); err != nil {
		t.Fatal(err)
	}
	if string(tail) != "TARGET" {
		t.Fatalf("source file was modified before atomic commit: tail=%q", tail)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filepath.Base(path)+".tmp.") {
			t.Errorf("SIGTERM cleanup left temporary file %q", entry.Name())
		}
	}
}

func TestAtomicOperationsPreserveOriginalOnFilesystemFull(t *testing.T) {
	fullRoot := os.Getenv("KERNO_FULL_TEST_DIR")
	if fullRoot == "" {
		t.Skip("set KERNO_FULL_TEST_DIR to a disposable small filesystem")
	}
	root, err := os.MkdirTemp(fullRoot, "kerno-enospc-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)

	writePath := filepath.Join(root, "write-target.txt")
	if err := os.WriteFile(writePath, []byte("preserve-write-original"), 0600); err != nil {
		t.Fatal(err)
	}
	replacePath := filepath.Join(root, "replace-target.bin")
	replaceOriginal := strings.Repeat("needle", 4*1024*1024/6)
	if err := os.WriteFile(replacePath, []byte(replaceOriginal), 0600); err != nil {
		t.Fatal(err)
	}

	fillerPath := filepath.Join(root, "filler.bin")
	filler, err := os.OpenFile(fillerPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer filler.Close()
	chunk := bytes.Repeat([]byte{0xA5}, 256*1024)
	for {
		var stat syscall.Statfs_t
		if err := syscall.Statfs(root, &stat); err != nil {
			t.Fatal(err)
		}
		freeBytes := uint64(stat.Bfree) * uint64(stat.Bsize)
		if freeBytes <= 1024*1024 {
			break
		}
		if _, err := filler.Write(chunk); err != nil {
			if errors.Is(err, syscall.ENOSPC) {
				break
			}
			t.Fatal(err)
		}
	}

	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(root, "audit.log")}
	payload := strings.Repeat("x", 4*1024*1024)
	if _, err := a.call(context.Background(), "file.write", map[string]any{"path": writePath, "content": payload, "atomic": true}, 30, "test-actor"); err == nil {
		t.Fatal("atomic write unexpectedly succeeded on a full filesystem")
	}
	writeContent, err := os.ReadFile(writePath)
	if err != nil || string(writeContent) != "preserve-write-original" {
		t.Fatalf("atomic write damaged original on ENOSPC: content=%q err=%v", writeContent, err)
	}

	if _, err := a.call(context.Background(), "file.replace", map[string]any{"path": replacePath, "old_text": "needle", "new_text": "change", "replace_all": true}, 30, "test-actor"); err == nil {
		t.Fatal("atomic replace unexpectedly succeeded on a full filesystem")
	}
	replaceInfo, err := os.Stat(replacePath)
	if err != nil {
		t.Fatal(err)
	}
	if replaceInfo.Size() != int64(len(replaceOriginal)) {
		t.Fatalf("atomic replace changed source size on ENOSPC: got %d want %d", replaceInfo.Size(), len(replaceOriginal))
	}
	replaceFile, err := os.Open(replacePath)
	if err != nil {
		t.Fatal(err)
	}
	tail := make([]byte, len("needle"))
	if _, err := replaceFile.ReadAt(tail, replaceInfo.Size()-int64(len(tail))); err != nil {
		replaceFile.Close()
		t.Fatal(err)
	}
	replaceFile.Close()
	if string(tail) != "needle" {
		t.Fatalf("atomic replace changed source tail on ENOSPC: %q", tail)
	}

	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp.") {
			t.Errorf("failed atomic operation left temporary file %q", entry.Name())
		}
	}
}

func TestReadFileDefaultLimitMatchesPython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "large.txt")
	if err := os.WriteFile(path, []byte(strings.Repeat("x", 200001)), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "file.read", map[string]any{"path": path}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if len(out["content"].(string)) != 200000 || out["truncated"] != true {
		t.Fatalf("Python default max_bytes=200000 not preserved: content length=%d result=%#v", len(out["content"].(string)), out)
	}
}

func TestProcessReplacePreservesEmbeddedNUL(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	path := filepath.Join(t.TempDir(), "nul.txt")
	original := "a\x00b a\x00b"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "file.replace", map[string]any{"path": path, "old_text": "a\x00b", "new_text": "x\x00y", "replace_all": true}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["matches"] != float64(2) || out["replacements"] != float64(2) {
		t.Fatalf("unexpected NUL replacement result: %#v", out)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "x\x00y x\x00y" {
		t.Fatalf("embedded NUL replacement mismatch: %q", got)
	}
}

func TestMovePathOverwritesExistingFileLikePython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
	root := t.TempDir()
	src := filepath.Join(root, "source.txt")
	dst := filepath.Join(root, "destination.txt")
	if err := os.WriteFile(src, []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dst, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	out, err := a.call(context.Background(), "file.move", map[string]any{"source": src, "destination": dst, "overwrite": true}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if out["success"] != true {
		t.Fatalf("unexpected move result: %#v", out)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "new" {
		t.Fatalf("destination not overwritten: %q", got)
	}
	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatalf("source should be moved, stat err=%v", err)
	}
}

func TestRuntimeToolRegistryExposesAllTwentyToolsAndSchemas(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	application := &app{remote: &remote.Store{}}
	server := mcp.NewServer(&mcp.Implementation{Name: "registry-test", Version: "test"}, nil)
	registerLocalTools(server, application, nil, config.Config{})
	registerRemoteTools(server, application, "https://mcp.example/.well-known/oauth-protected-resource/mcp")

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	client := mcp.NewClient(&mcp.Implementation{Name: "registry-test-client"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	result, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.NextCursor != "" {
		t.Fatalf("unexpected paginated tool registry cursor: %q", result.NextCursor)
	}
	if len(result.Tools) != 20 {
		t.Fatalf("runtime registry exposes %d tools, want 20", len(result.Tools))
	}

	expectedProperties := map[string]map[string]string{
		"get_system_info":               {},
		"list_directory":                {"path": "string"},
		"read_file":                     {"path": "string", "max_bytes": "integer"},
		"write_file":                    {"path": "string", "content": "string", "create_parents": "boolean", "atomic": "boolean"},
		"replace_in_file":               {"path": "string", "old_text": "string", "new_text": "string", "replace_all": "boolean"},
		"move_path":                     {"source": "string", "destination": "string"},
		"delete_path":                   {"path": "string", "recursive": "boolean"},
		"get_service_status":            {"service": "string"},
		"get_service_logs":              {"path": "string", "lines": "integer"},
		"execute_shell":                 {"command": "string", "timeout_seconds": "integer"},
		"execute_parallel":              {"tasks": "array", "max_parallel": "integer"},
		"database_query":                {"database": "string", "sql": "string", "max_rows": "integer"},
		"remote_target_create":          {"name": "string", "host": "string", "port": "integer", "username": "string", "host_key": "string"},
		"remote_target_list":            {},
		"remote_target_delete":          {"target_id": "string"},
		"remote_credential_create":      {"target_id": "string", "name": "string", "private_key": "string", "passphrase": "string"},
		"remote_credential_list":        {"target_id": "string"},
		"remote_credential_set_default": {"target_id": "string", "credential_id": "string"},
		"remote_credential_read":        {"credential_id": "string"},
		"remote_ssh_exec":               {"target_id": "string", "credential_id": "string", "command": "string", "timeout_seconds": "integer"},
	}
	expectedRequired := map[string][]string{
		"get_system_info":               {},
		"list_directory":                {"path"},
		"read_file":                     {"path"},
		"write_file":                    {"path", "content"},
		"replace_in_file":               {"path", "old_text", "new_text"},
		"move_path":                     {"source", "destination"},
		"delete_path":                   {"path"},
		"get_service_status":            {"service"},
		"get_service_logs":              {"path"},
		"execute_shell":                 {"command"},
		"execute_parallel":              {"tasks"},
		"database_query":                {"sql"},
		"remote_target_create":          {"name", "host", "port", "username", "host_key"},
		"remote_target_list":            {},
		"remote_target_delete":          {"target_id"},
		"remote_credential_create":      {"target_id", "name", "private_key"},
		"remote_credential_list":        {"target_id"},
		"remote_credential_set_default": {"target_id", "credential_id"},
		"remote_credential_read":        {"credential_id"},
		"remote_ssh_exec":               {"target_id", "command"},
	}
	seen := make(map[string]bool, len(result.Tools))
	for _, tool := range result.Tools {
		if tool == nil || tool.Name == "" {
			t.Fatal("runtime registry contains a nil tool or empty name")
		}
		if seen[tool.Name] {
			t.Fatalf("duplicate runtime tool name %q", tool.Name)
		}
		seen[tool.Name] = true

		wantProperties, ok := expectedProperties[tool.Name]
		if !ok {
			t.Fatalf("unexpected runtime tool %q", tool.Name)
		}
		schemaBytes, err := json.Marshal(tool.InputSchema)
		if err != nil {
			t.Fatalf("%s input schema marshal: %v", tool.Name, err)
		}
		var schema map[string]any
		if err := json.Unmarshal(schemaBytes, &schema); err != nil {
			t.Fatalf("%s input schema decode: %v; schema=%s", tool.Name, err, schemaBytes)
		}
		if schema["type"] != "object" {
			t.Errorf("%s input schema type = %v, want object", tool.Name, schema["type"])
		}
		properties, _ := schema["properties"].(map[string]any)
		if len(properties) != len(wantProperties) {
			t.Errorf("%s property count = %d, want %d; properties=%v", tool.Name, len(properties), len(wantProperties), properties)
		}
		for field, wantType := range wantProperties {
			property, ok := properties[field].(map[string]any)
			if !ok {
				t.Errorf("%s property %q missing or malformed", tool.Name, field)
				continue
			}
			gotType := fmt.Sprint(property["type"])
			if gotType != wantType && !(wantType == "array" && gotType == "[null array]") {
				t.Errorf("%s property %q type = %q, want %q", tool.Name, field, gotType, wantType)
			}
		}

		requiredRaw, _ := schema["required"].([]any)
		gotRequired := make([]string, 0, len(requiredRaw))
		for _, value := range requiredRaw {
			gotRequired = append(gotRequired, fmt.Sprint(value))
		}
		wantRequired := append([]string{}, expectedRequired[tool.Name]...)
		sort.Strings(gotRequired)
		sort.Strings(wantRequired)
		if !reflect.DeepEqual(gotRequired, wantRequired) {
			t.Errorf("%s required fields = %v, want %v", tool.Name, gotRequired, wantRequired)
		}
		if strings.HasPrefix(tool.Name, "remote_") {
			metaBytes, _ := json.Marshal(tool.Meta)
			if !strings.Contains(string(metaBytes), "remote:ssh:manage") {
				t.Errorf("%s runtime metadata lacks remote:ssh:manage: %s", tool.Name, metaBytes)
			}
		}
	}
	for name := range expectedProperties {
		if !seen[name] {
			t.Errorf("runtime registry is missing tool %q", name)
		}
	}
}

func TestAuditErrorSummariesDoNotExposeRawMessages(t *testing.T) {
	rawSecret := "password=private-value bearer=token-value"
	genericErr := errors.New(rawSecret)
	if got := auditErrorType(genericErr); got == "" || strings.Contains(got, rawSecret) || strings.Contains(got, "private-value") {
		t.Fatalf("audit error type leaked raw error content: %q", got)
	}

	postgresErr := &pgconn.PgError{Code: "23505", Message: "duplicate key includes private-value"}
	fields := databaseAuditErrorFields(postgresErr)
	encoded, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	if fields["sqlstate"] != "23505" {
		t.Fatalf("database audit omitted SQLSTATE: %#v", fields)
	}
	if strings.Contains(string(encoded), "private-value") || strings.Contains(string(encoded), "duplicate key") {
		t.Fatalf("database audit leaked PostgreSQL error message: %s", encoded)
	}
}

func TestWriteAuditPersistsFieldsWithoutRedaction(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	entry := map[string]any{
		"actor": "user-1", "operation": "audit.persistence.test",
		"password": "PASSWORD_SENTINEL", "private_key": "PRIVATE_KEY_SENTINEL",
		"passphrase": "PASSPHRASE_SENTINEL", "bearer_token": "BEARER_SENTINEL",
		"authorization_code": "AUTH_CODE_SENTINEL", "command": "COMMAND_SENTINEL",
		"stdout": "OUTPUT_SENTINEL", "content": "FILE_CONTENT_SENTINEL", "sql": "SQL_SENTINEL",
		"command_sha256": "command-hash-retained", "path": "/tmp/safe-path",
	}
	if err := writeAudit(path, entry); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"PASSWORD_SENTINEL", "PRIVATE_KEY_SENTINEL", "PASSPHRASE_SENTINEL", "BEARER_SENTINEL", "AUTH_CODE_SENTINEL", "COMMAND_SENTINEL", "OUTPUT_SENTINEL", "FILE_CONTENT_SENTINEL", "SQL_SENTINEL"} {
		if !strings.Contains(string(raw), field) {
			t.Errorf("audit file omitted unredacted field %s: %s", field, raw)
		}
	}
	if !strings.Contains(string(raw), "command-hash-retained") || !strings.Contains(string(raw), "/tmp/safe-path") {
		t.Fatalf("audit file omitted supplied metadata: %s", raw)
	}
}

func TestRemoteToolSecurityMetadata(t *testing.T) {
	meta := remoteToolSecurityMeta()
	schemes, ok := meta["securitySchemes"].([]any)
	if !ok || len(schemes) != 1 {
		t.Fatalf("securitySchemes metadata has wrong shape: %#v", meta)
	}
	scheme, ok := schemes[0].(map[string]any)
	if !ok || scheme["type"] != "oauth2" {
		t.Fatalf("OAuth security scheme missing: %#v", schemes[0])
	}
	scopes, ok := scheme["scopes"].([]string)
	if !ok || len(scopes) != 2 || scopes[0] != "go-ssh-mcp" || scopes[1] != "remote:ssh:manage" {
		t.Fatalf("remote tool scopes = %#v", scheme["scopes"])
	}
	encoded, err := json.Marshal(&struct {
		mcp.Meta `json:"_meta,omitempty"`
	}{Meta: meta})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"_meta":{"securitySchemes"`) {
		t.Fatalf("security metadata did not serialize under _meta: %s", encoded)
	}
}

func TestRemoteScopeChallengeResult(t *testing.T) {
	metadataURL := "https://example.invalid/.well-known/oauth-protected-resource/mcp"
	result := remoteScopeChallengeResult(metadataURL)
	if result == nil || !result.IsError {
		t.Fatalf("expected error tool result: %#v", result)
	}
	challenges, ok := result.Meta["mcp/www_authenticate"].([]string)
	if !ok || len(challenges) != 1 {
		t.Fatalf("missing MCP WWW-Authenticate metadata: %#v", result.Meta)
	}
	for _, expected := range []string{metadataURL, `error="insufficient_scope"`, `scope="go-ssh-mcp remote:ssh:manage"`} {
		if !strings.Contains(challenges[0], expected) {
			t.Fatalf("challenge %q missing %q", challenges[0], expected)
		}
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err = json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	meta, ok := decoded["_meta"].(map[string]any)
	if !ok || meta["mcp/www_authenticate"] == nil {
		t.Fatalf("challenge metadata not serialized: %s", encoded)
	}
}

func TestRemoteActorScopeGate(t *testing.T) {
	if _, err := remoteActorFromTokenInfo(nil); err == nil {
		t.Fatal("missing token info must be rejected")
	}
	baseOnly := &auth.TokenInfo{UserID: "user-1", Scopes: []string{"go-ssh-mcp"}}
	if _, err := remoteActorFromTokenInfo(baseOnly); !errors.Is(err, errRemoteScopeRequired) {
		t.Fatalf("base-only token error = %v, want remote scope challenge sentinel", err)
	}
	full := &auth.TokenInfo{UserID: "user-1", Scopes: []string{"go-ssh-mcp", "remote:ssh:manage"}, Extra: map[string]any{"client_id": "client-1"}}
	actor, err := remoteActorFromTokenInfo(full)
	if err != nil {
		t.Fatal(err)
	}
	if actor.UserID != "user-1" || actor.ClientID != "client-1" {
		t.Fatalf("unexpected actor: %#v", actor)
	}
}

func TestProtectedResourceMetadataURL(t *testing.T) {
	got, err := protectedResourceMetadataURL("https://example.invalid/mcp/v1/")
	if err != nil {
		t.Fatal(err)
	}
	want := "https://example.invalid/.well-known/oauth-protected-resource/mcp/v1"
	if got != want {
		t.Fatalf("metadata URL = %q, want %q", got, want)
	}
	if _, err = protectedResourceMetadataURL("/relative/path"); err == nil {
		t.Fatal("relative resource URL must be rejected")
	}
}

func TestSDKToolLevelOAuthStepUpRoundTrip(t *testing.T) {
	ctx := context.Background()
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "1"}, nil)
	mcp.AddTool(server, &mcp.Tool{Meta: remoteToolSecurityMeta(), Name: "remote_target_list"}, func(context.Context, *mcp.CallToolRequest, emptyInput) (*mcp.CallToolResult, *remote.Target, error) {
		return remoteScopeChallengeResult("https://example.invalid/.well-known/oauth-protected-resource/mcp"), nil, nil
	})
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer serverSession.Close()
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer clientSession.Close()

	listed, err := clientSession.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed.Tools) != 1 || listed.Tools[0].Meta["securitySchemes"] == nil {
		t.Fatalf("tool security scheme missing from tools/list: %#v", listed.Tools)
	}
	result, err := clientSession.CallTool(ctx, &mcp.CallToolParams{Name: "remote_target_list"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatalf("scope challenge must be an MCP tool error: %#v", result)
	}
	if result.Meta["mcp/www_authenticate"] == nil {
		t.Fatalf("scope challenge metadata lost by SDK wrapper: %#v", result)
	}
}
