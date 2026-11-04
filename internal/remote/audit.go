// Package remote records auditable metadata for remote SSH operations.
// This file stores operation outcomes and non-secret details; callers must hash commands.
package remote

// Audit writes structured metadata for remote SSH operations. Callers must pass hashes
// rather than raw commands and must never include private keys, passphrases, or tokens.

import (
	"context"
	"encoding/json"

	"github.com/google/uuid"
)

// Audit persists operation metadata; callers must not pass secrets or raw command text.
func (s *Store) Audit(ctx context.Context, actor Actor, targetID, credentialID, operation, outcome string, details map[string]any) error {
	raw, err := json.Marshal(details)
	if err != nil {
		return err
	}
	var tid, cid any
	if targetID != "" {
		v, e := uuid.Parse(targetID)
		if e != nil {
			return e
		}
		tid = v
	}
	if credentialID != "" {
		v, e := uuid.Parse(credentialID)
		if e != nil {
			return e
		}
		cid = v
	}
	_, err = s.Pool.Exec(ctx, `INSERT INTO remote.audit_log(owner_user_id,client_id,target_id,credential_id,operation,outcome,details) VALUES($1,NULLIF($2,''),$3,$4,$5,$6,$7::jsonb)`, actor.UserID, actor.ClientID, tid, cid, operation, outcome, string(raw))
	return err
}
