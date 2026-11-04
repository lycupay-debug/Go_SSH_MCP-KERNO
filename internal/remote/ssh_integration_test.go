// Package remote integration tests exercise PostgreSQL ownership, concurrency, and SSH behavior.
package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// integrationStore uses only the disposable database explicitly supplied by CI.
// It never falls back to the service's production DATABASE_URL.
func integrationStore(t *testing.T) (*Store, Actor, func()) {
	t.Helper()
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("GO_SSH_MCP_TEST_DATABASE_URL is not configured; refusing to use a non-test database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect disposable integration database: %v", err)
	}
	if err = pool.Ping(ctx); err != nil {
		pool.Close()
		t.Fatalf("ping disposable integration database: %v", err)
	}
	userID := uuid.NewString()
	username := "remote-it-" + uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash) VALUES($1,$2,'integration-test')`, userID, username); err != nil {
		pool.Close()
		t.Fatalf("create isolated integration user: %v", err)
	}
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = pool.Exec(cleanupCtx, `DELETE FROM oauth.users WHERE id=$1`, userID)
		pool.Close()
	}
	return &Store{Pool: pool}, Actor{UserID: userID, ClientID: "remote-integration-test"}, cleanup
}

func TestCredentialDefaultsOwnershipAndConcurrentRotation(t *testing.T) {
	store, actor, cleanup := integrationStore(t)
	defer cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	_, hostKey, _ := testSSHKey(t)
	target, err := store.CreateTarget(ctx, actor, TargetInput{
		Name: "integration-target-" + uuid.NewString(), Host: "127.0.0.1", Port: 22,
		Username: "root", HostKey: hostKey,
	})
	if err != nil {
		t.Fatalf("create target: %v", err)
	}

	privateKey, _, _ := testSSHKey(t)
	const credentialCount = 8
	created := make([]CredentialInfo, credentialCount)
	errs := make(chan error, credentialCount)
	var wg sync.WaitGroup
	for i := 0; i < credentialCount; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			item, saveErr := store.SaveCredential(ctx, actor, target.ID, fmt.Sprintf("rotation-%02d", index), privateKey, "unit-test")
			if saveErr != nil {
				errs <- saveErr
				return
			}
			created[index] = item
		}(i)
	}
	wg.Wait()
	close(errs)
	for saveErr := range errs {
		t.Fatalf("concurrent credential creation: %v", saveErr)
	}
	for _, item := range created {
		encoded, marshalErr := json.Marshal(item)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if containsSecretField(string(encoded)) {
			t.Fatalf("credential create response exposed secret material: %s", encoded)
		}
	}

	items, err := store.ListCredentials(ctx, actor, target.ID)
	if err != nil {
		t.Fatalf("list credentials: %v", err)
	}
	if len(items) != credentialCount {
		t.Fatalf("listed %d credentials, want %d", len(items), credentialCount)
	}
	defaults := 0
	for _, item := range items {
		if item.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("concurrent creation left %d default credentials, want exactly one", defaults)
	}

	// Concurrent rotations serialize on the target row; the partial unique index
	// provides a second line of defense against duplicate defaults.
	errs = make(chan error, credentialCount)
	for _, item := range items {
		item := item
		wg.Add(1)
		go func() {
			defer wg.Done()
			if setErr := store.SetDefaultCredential(ctx, actor, target.ID, item.ID); setErr != nil {
				errs <- setErr
			}
		}()
	}
	wg.Wait()
	close(errs)
	for setErr := range errs {
		t.Fatalf("concurrent default rotation: %v", setErr)
	}
	items, err = store.ListCredentials(ctx, actor, target.ID)
	if err != nil {
		t.Fatalf("list credentials after rotation: %v", err)
	}
	defaults = 0
	for _, item := range items {
		if item.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("concurrent rotation left %d default credentials, want exactly one", defaults)
	}

	encoded, err := json.Marshal(items[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) == "" || containsSecretField(string(encoded)) {
		t.Fatalf("credential list exposed secret material: %s", encoded)
	}

	otherID := uuid.NewString()
	if _, err = store.Pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash) VALUES($1,$2,'integration-test')`, otherID, "remote-it-"+uuid.NewString()); err != nil {
		t.Fatalf("create second integration user: %v", err)
	}
	other := Actor{UserID: otherID, ClientID: "other-client"}
	defer func() { _, _ = store.Pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, otherID) }()
	if got, listErr := store.ListCredentials(ctx, other, target.ID); listErr != nil || len(got) != 0 {
		t.Fatalf("cross-owner credential list = %#v, err=%v; want empty", got, listErr)
	}
	if err = store.SetDefaultCredential(ctx, other, target.ID, items[0].ID); err == nil {
		t.Fatal("cross-owner default credential change was accepted")
	}
	if _, err = store.ReadCredential(ctx, other, items[0].ID); err == nil {
		t.Fatal("cross-owner secret read was accepted")
	}
	if err = store.DeleteTarget(ctx, actor, target.ID); err != nil {
		t.Fatalf("delete isolated integration target: %v", err)
	}
}

func containsSecretField(encoded string) bool {
	return strings.Contains(encoded, "private_key") || strings.Contains(encoded, "passphrase")
}
