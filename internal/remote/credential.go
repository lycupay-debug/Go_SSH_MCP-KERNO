// Credential operations validate, persist, list, and select SSH authentication keys.
// Dependencies: PostgreSQL transactions through Store, UUID parsing, and x/crypto/ssh key parsing.
// Collaboration: remote_tools.go exposes metadata-only create/list and explicit secret-read handlers.
// Side effects: PostgreSQL reads/writes; private keys and optional passphrases are stored as configured.
package remote

// Credential operations validate SSH private keys, persist them for an owned target,
// and maintain one deterministic default key per target. Secret material is returned
// only by ReadCredential; SaveCredential and ListCredentials return metadata contracts.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/ssh"
)

// SaveCredential validates and persists a key, selecting it as default only when needed.
func (s *Store) SaveCredential(ctx context.Context, actor Actor, targetID, name, privateKey, passphrase string) (CredentialInfo, error) {
	var out CredentialInfo
	tid, err := uuid.Parse(targetID)
	if err != nil {
		return out, errors.New("target_id 必须是 UUID")
	}
	name, privateKey = strings.TrimSpace(name), strings.TrimSpace(privateKey)
	if name == "" || len(name) > 128 || privateKey == "" || len(privateKey) > 128*1024 || len(passphrase) > 4096 {
		return out, errors.New("credential name 或 private_key 无效")
	}
	signer, err := parseSigner(privateKey, passphrase)
	if err != nil {
		return out, fmt.Errorf("invalid or passphrase-protected SSH private key: %w", err)
	}
	pub := signer.PublicKey()
	pubText := string(ssh.MarshalAuthorizedKey(pub))
	fingerprint := ssh.FingerprintSHA256(pub)
	// Serialize credential creation per target. The first enabled credential
	// becomes default; adding a rotation key never silently replaces it.
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return out, fmt.Errorf("begin credential transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var ownedTarget uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM remote.targets WHERE id=$1 AND owner_user_id=$2 AND is_enabled=TRUE FOR UPDATE`, tid, actor.UserID).Scan(&ownedTarget); err != nil {
		return out, errors.New("enabled target not found or inaccessible")
	}
	var hasDefault bool
	if err = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM remote.credentials WHERE target_id=$1 AND owner_user_id=$2 AND is_enabled=TRUE AND is_default=TRUE)`, tid, actor.UserID).Scan(&hasDefault); err != nil {
		return out, fmt.Errorf("check default SSH credential: %w", err)
	}
	if !hasDefault {
		if _, err = tx.Exec(ctx, `UPDATE remote.credentials SET is_default=FALSE WHERE target_id=$1 AND owner_user_id=$2 AND is_default=TRUE`, tid, actor.UserID); err != nil {
			return out, fmt.Errorf("clear disabled default SSH credential: %w", err)
		}
	}
	err = tx.QueryRow(ctx, `INSERT INTO remote.credentials(target_id,owner_user_id,name,private_key,passphrase,public_key,fingerprint,is_default,created_by_client_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')) RETURNING id::text,created_at`, tid, actor.UserID, name, privateKey, passphrase, strings.TrimSpace(pubText), fingerprint, !hasDefault, actor.ClientID).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return out, fmt.Errorf("save SSH credential: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return CredentialInfo{}, fmt.Errorf("commit SSH credential: %w", err)
	}
	out.TargetID, out.Name, out.Fingerprint, out.Enabled, out.Default = tid.String(), name, fingerprint, true, !hasDefault
	return out, nil
}

// ListCredentials returns metadata only; secret key material is never included.
func (s *Store) ListCredentials(ctx context.Context, actor Actor, targetID string) ([]CredentialInfo, error) {
	tid, err := uuid.Parse(targetID)
	if err != nil {
		return nil, errors.New("target_id 必须是 UUID")
	}
	rows, err := s.Pool.Query(ctx, `SELECT c.id::text,c.target_id::text,c.name,c.fingerprint,c.is_enabled,c.is_default,c.created_at
		FROM remote.credentials AS c
		JOIN remote.targets AS t ON t.id=c.target_id AND t.owner_user_id=c.owner_user_id
		WHERE c.target_id=$1 AND c.owner_user_id=$2
		ORDER BY c.is_default DESC,c.created_at DESC,c.id`, tid, actor.UserID)
	if err != nil {
		return nil, fmt.Errorf("list SSH credentials: %w", err)
	}
	defer rows.Close()
	out := make([]CredentialInfo, 0)
	for rows.Next() {
		var item CredentialInfo
		if err = rows.Scan(&item.ID, &item.TargetID, &item.Name, &item.Fingerprint, &item.Enabled, &item.Default, &item.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// SetDefaultCredential changes the default key atomically and verifies ownership.
func (s *Store) SetDefaultCredential(ctx context.Context, actor Actor, targetID, credentialID string) error {
	tid, err := uuid.Parse(targetID)
	if err != nil {
		return errors.New("target_id 必须是 UUID")
	}
	cid, err := uuid.Parse(credentialID)
	if err != nil {
		return errors.New("credential_id 必须是 UUID")
	}
	tx, err := s.Pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin default credential transaction: %w", err)
	}
	defer tx.Rollback(ctx)
	var ownedTarget uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM remote.targets WHERE id=$1 AND owner_user_id=$2 AND is_enabled=TRUE FOR UPDATE`, tid, actor.UserID).Scan(&ownedTarget); err != nil {
		return errors.New("enabled target not found or inaccessible")
	}
	var selected uuid.UUID
	if err = tx.QueryRow(ctx, `SELECT id FROM remote.credentials WHERE id=$1 AND target_id=$2 AND owner_user_id=$3 AND is_enabled=TRUE FOR UPDATE`, cid, tid, actor.UserID).Scan(&selected); err != nil {
		return errors.New("enabled credential not found for this target")
	}
	if _, err = tx.Exec(ctx, `UPDATE remote.credentials SET is_default=FALSE WHERE target_id=$1 AND owner_user_id=$2 AND is_default=TRUE`, tid, actor.UserID); err != nil {
		return fmt.Errorf("clear previous default credential: %w", err)
	}
	if _, err = tx.Exec(ctx, `UPDATE remote.credentials SET is_default=TRUE WHERE id=$1 AND target_id=$2 AND owner_user_id=$3`, cid, tid, actor.UserID); err != nil {
		return fmt.Errorf("set default credential: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit default credential: %w", err)
	}
	return nil
}

// ReadCredential returns secret key material only for a credential owned by the actor.
func (s *Store) ReadCredential(ctx context.Context, actor Actor, credentialID string) (Credential, error) {
	id, err := uuid.Parse(credentialID)
	if err != nil {
		return Credential{}, errors.New("credential_id 必须是 UUID")
	}
	var out Credential
	err = s.Pool.QueryRow(ctx, `SELECT c.id::text,c.target_id::text,c.name,c.private_key,c.passphrase,c.public_key,c.fingerprint,c.is_enabled,c.created_at
		FROM remote.credentials AS c
		JOIN remote.targets AS t ON t.id=c.target_id AND t.owner_user_id=c.owner_user_id
		WHERE c.id=$1 AND c.owner_user_id=$2`, id, actor.UserID).Scan(&out.ID, &out.TargetID, &out.Name, &out.PrivateKey, &out.Passphrase, &out.PublicKey, &out.Fingerprint, &out.Enabled, &out.CreatedAt)
	if err != nil {
		return out, errors.New("credential not found or inaccessible")
	}
	return out, nil
}

func parseSigner(privateKey, passphrase string) (ssh.Signer, error) {
	if passphrase != "" {
		return ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase))
	}
	return ssh.ParsePrivateKey([]byte(privateKey))
}
