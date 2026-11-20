package remote

import (
	"context"
	"strings"
	"testing"
)

func TestRemoteAuditRedactsSecretFieldsIntegration(t *testing.T) {
	store, actor, cleanup := integrationStore(t)
	defer cleanup()
	ctx := context.Background()
	if err := store.Audit(ctx, actor, "", "", "ssh.exec", "success", map[string]any{
		"command":        "REMOTE_COMMAND_SENTINEL",
		"private_key":    "REMOTE_PRIVATE_KEY_SENTINEL",
		"passphrase":     "REMOTE_PASSPHRASE_SENTINEL",
		"bearer_token":   "REMOTE_BEARER_SENTINEL",
		"command_sha256": "remote-command-hash",
		"exit_code":      0,
	}); err != nil {
		t.Fatal(err)
	}
	var details string
	if err := store.Pool.QueryRow(ctx, `SELECT details::text FROM remote.audit_log WHERE owner_user_id=$1 AND operation='ssh.exec' ORDER BY id DESC LIMIT 1`, actor.UserID).Scan(&details); err != nil {
		t.Fatal(err)
	}
	for _, sentinel := range []string{"REMOTE_COMMAND_SENTINEL", "REMOTE_PRIVATE_KEY_SENTINEL", "REMOTE_PASSPHRASE_SENTINEL", "REMOTE_BEARER_SENTINEL"} {
		if strings.Contains(details, sentinel) {
			t.Errorf("remote audit persisted secret sentinel %s: %s", sentinel, details)
		}
	}
	if !strings.Contains(details, "remote-command-hash") || !strings.Contains(details, "exit_code") {
		t.Fatalf("remote audit lost allowed metadata: %s", details)
	}
}
