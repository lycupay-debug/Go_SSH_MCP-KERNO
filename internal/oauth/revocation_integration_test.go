package oauth

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestTokenRevocationIntegration(t *testing.T) {
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL-backed revocation tests")
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
	userID, clientID, familyID := uuid.NewString(), "revoke-test-"+uuid.NewString(), uuid.NewString()
	username := "revoke-test-" + uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES($1,$2,'not-used-by-this-test',TRUE)`, userID, username); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.clients(client_id,metadata,is_enabled) VALUES($1,'{"client_name":"revoke test"}'::jsonb,TRUE)`, clientID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.refresh_token_families(id,client_id,user_id) VALUES($1,$2,$3)`, familyID, clientID, userID); err != nil {
		t.Fatal(err)
	}
	access, refresh := "access-"+uuid.NewString(), "refresh-"+uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.access_tokens(id,token_hash,client_id,user_id,scopes,resource,family_id,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,now()+interval '5 minutes')`, hashToken(access), clientID, userID, []string{scopeName}, "https://revoke.example/mcp", familyID); err != nil {
		t.Fatal(err)
	}
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.refresh_tokens(id,token_hash,family_id,client_id,user_id,scopes,resource,expires_at) VALUES(gen_random_uuid(),$1,$2,$3,$4,$5,$6,now()+interval '30 days')`, hashToken(refresh), familyID, clientID, userID, []string{scopeName}, "https://revoke.example/mcp"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.audit_log WHERE client_id=$1 OR user_id=$2`, clientID, userID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_tokens WHERE family_id=$1`, familyID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.access_tokens WHERE family_id=$1`, familyID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.refresh_token_families WHERE id=$1`, familyID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.clients WHERE client_id=$1`, clientID)
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})
	s := New(pool, "https://revoke.example", "https://revoke.example/mcp", []byte(strings.Repeat("r", 64)))
	mux := http.NewServeMux()
	s.RegisterRoutes(mux)
	server := httptest.NewServer(mux)
	defer server.Close()
	form := url.Values{"token": {refresh}}
	resp, err := http.PostForm(server.URL+"/revoke", form)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke status %d: %s", resp.StatusCode, body)
	}
	var familyRevoked, accessRevoked, refreshRevoked bool
	if err = pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM oauth.refresh_token_families WHERE id=$1`, familyID).Scan(&familyRevoked); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM oauth.access_tokens WHERE token_hash=$1`, hashToken(access)).Scan(&accessRevoked); err != nil {
		t.Fatal(err)
	}
	if err = pool.QueryRow(ctx, `SELECT revoked_at IS NOT NULL FROM oauth.refresh_tokens WHERE token_hash=$1`, hashToken(refresh)).Scan(&refreshRevoked); err != nil {
		t.Fatal(err)
	}
	if !familyRevoked || !accessRevoked || !refreshRevoked {
		t.Fatalf("family revocation incomplete: family=%v access=%v refresh=%v", familyRevoked, accessRevoked, refreshRevoked)
	}
}
