package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/executor"
	"github.com/modelcontextprotocol/go-sdk/auth"
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
	defer pool.Close()
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

	if _, err = pool.Exec(ctx, `UPDATE oauth.access_tokens SET scopes=$2,expires_at=now()-interval '1 second' WHERE token_hash=$1`, tokenHashHex, []string{"go-ssh-mcp"}); err != nil {
		t.Fatal(err)
	}
	if _, err = verifier(ctx, token, httptest.NewRequest(http.MethodGet, "https://example.invalid/mcp", nil)); err == nil {
		t.Fatal("expired token accepted")
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
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
	shell, err := a.call(ctx, "shell.exec", map[string]any{"command": "printf out; printf err >&2; exit 7"}, 5, "test-actor")
	if err != nil {
		t.Fatal(err)
	}
	if shell["returncode"] != float64(7) || shell["stdout"] != "out" || shell["stderr"] != "err" || shell["timed_out"] != false {
		t.Fatalf("unexpected shell result: %#v", shell)
	}
}
func TestSynchronousShellTimeoutReturnsStructuredResult(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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

func TestNativeFileWritePreservesUnicodeAndNUL(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
func TestNativeFileWriteFollowsSymlinkLikePython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
func TestReadFileDefaultLimitMatchesPython(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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

func TestNativeReplacePreservesEmbeddedNUL(t *testing.T) {
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
	a := &app{runner: &executor.Executor{Path: testCExecutorPath(t), Native: true, MaxOutputBytes: 6 * 1024 * 1024}, logger: slog.New(slog.NewTextHandler(io.Discard, nil)), auditPath: filepath.Join(t.TempDir(), "audit.log")}
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
