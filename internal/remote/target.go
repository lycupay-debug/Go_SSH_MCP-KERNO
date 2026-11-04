// Package remote persists and validates operator-managed SSH targets.
// This file owns target input validation, pinned host identity, and owner-scoped CRUD.
package remote

// Target operations validate operator-supplied host identity and persist user-owned
// endpoints. The host key is pinned at registration and is never discovered implicitly.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func validateTarget(in TargetInput) (ssh.PublicKey, string, error) {
	in.Name = strings.TrimSpace(in.Name)
	in.Host = strings.TrimSpace(in.Host)
	in.Username = strings.TrimSpace(in.Username)
	if in.Name == "" || len(in.Name) > 128 || in.Host == "" || len(in.Host) > 253 || in.Username == "" || len(in.Username) > 128 {
		return nil, "", errors.New("name、host、username 不能为空且长度必须在限制内")
	}
	if in.Port < 1 || in.Port > 65535 {
		return nil, "", errors.New("port 必须在 1 至 65535 之间")
	}
	if strings.ContainsAny(in.Host, " \t\r\n/@") {
		return nil, "", errors.New("host 必须是主机名或 IP 地址，不得包含路径、用户信息或空白字符")
	}
	key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(in.HostKey)))
	if err != nil {
		return nil, "", fmt.Errorf("invalid SSH host public key: %w", err)
	}
	if len(strings.TrimSpace(string(rest))) != 0 {
		return nil, "", errors.New("SSH host public key must contain exactly one authorized_keys entry")
	}
	return key, ssh.FingerprintSHA256(key), nil
}

// CreateTarget registers a user-owned endpoint with a verified, pinned SSH host key.
func (s *Store) CreateTarget(ctx context.Context, actor Actor, in TargetInput) (Target, error) {
	var out Target
	if _, err := uuid.Parse(actor.UserID); err != nil {
		return out, errors.New("authenticated user id is invalid")
	}
	key, fingerprint, err := validateTarget(in)
	if err != nil {
		return out, err
	}
	var id uuid.UUID
	err = s.Pool.QueryRow(ctx, `INSERT INTO remote.targets(owner_user_id,name,host,port,username,host_key_type,host_key_data,host_key_fingerprint,created_by_client_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,'')) RETURNING id,created_at`, actor.UserID, strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), in.Port, strings.TrimSpace(in.Username), key.Type(), strings.TrimSpace(in.HostKey), fingerprint, actor.ClientID).Scan(&id, &out.CreatedAt)
	if err != nil {
		return out, fmt.Errorf("create remote target: %w", err)
	}
	out.ID, out.Name, out.Host, out.Port, out.Username = id.String(), strings.TrimSpace(in.Name), strings.TrimSpace(in.Host), in.Port, strings.TrimSpace(in.Username)
	out.HostKeyType, out.HostKeyFingerprint, out.Enabled = key.Type(), fingerprint, true
	return out, nil
}

// ListTargets returns only endpoints owned by the authenticated actor.
func (s *Store) ListTargets(ctx context.Context, actor Actor) ([]Target, error) {
	rows, err := s.Pool.Query(ctx, `SELECT id::text,name,host,port,username,host_key_type,host_key_fingerprint,is_enabled,created_at FROM remote.targets WHERE owner_user_id=$1 ORDER BY created_at DESC`, actor.UserID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]Target, 0)
	for rows.Next() {
		var v Target
		if err = rows.Scan(&v.ID, &v.Name, &v.Host, &v.Port, &v.Username, &v.HostKeyType, &v.HostKeyFingerprint, &v.Enabled, &v.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// DeleteTarget removes an owned endpoint and cascades to its credentials.
func (s *Store) DeleteTarget(ctx context.Context, actor Actor, targetID string) error {
	id, err := uuid.Parse(targetID)
	if err != nil {
		return errors.New("target_id 必须是 UUID")
	}
	tag, err := s.Pool.Exec(ctx, `DELETE FROM remote.targets WHERE id=$1 AND owner_user_id=$2`, id, actor.UserID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return errors.New("target not found")
	}
	return nil
}
