// Package remote manages user-owned SSH targets and credentials.
// Private keys are intentionally stored as plaintext per the product requirement;
// callers must restrict database access and never include key material in logs.
package remote

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

const (
	MaxCommandBytes = 16 * 1024
	MaxOutputBytes  = 1 << 20
)

type Store struct{ Pool *pgxpool.Pool }

type Target struct {
	ID                 string    `json:"id"`
	Name               string    `json:"name"`
	Host               string    `json:"host"`
	Port               int       `json:"port"`
	Username           string    `json:"username"`
	HostKeyType        string    `json:"host_key_type"`
	HostKeyFingerprint string    `json:"host_key_fingerprint"`
	Enabled            bool      `json:"enabled"`
	CreatedAt          time.Time `json:"created_at"`
}

type Credential struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	Name        string    `json:"name"`
	PrivateKey  string    `json:"private_key"`
	Passphrase  string    `json:"passphrase,omitempty"`
	PublicKey   string    `json:"public_key,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Enabled     bool      `json:"enabled"`
	CreatedAt   time.Time `json:"created_at"`
}

type Actor struct{ UserID, ClientID string }

type TargetInput struct {
	Name, Host, Username, HostKey string
	Port                          int
}

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

func (s *Store) SaveCredential(ctx context.Context, actor Actor, targetID, name, privateKey, passphrase string) (Credential, error) {
	var out Credential
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
	err = s.Pool.QueryRow(ctx, `INSERT INTO remote.credentials(target_id,owner_user_id,name,private_key,passphrase,public_key,fingerprint,created_by_client_id) SELECT t.id,t.owner_user_id,$3,$4,$5,$6,$7,NULLIF($8,'') FROM remote.targets t WHERE t.id=$1 AND t.owner_user_id=$2 RETURNING id::text,created_at`, tid, actor.UserID, name, privateKey, passphrase, strings.TrimSpace(pubText), fingerprint, actor.ClientID).Scan(&out.ID, &out.CreatedAt)
	if err != nil {
		return out, fmt.Errorf("save SSH credential: %w", err)
	}
	out.TargetID, out.Name, out.PrivateKey, out.Passphrase, out.PublicKey, out.Fingerprint, out.Enabled = tid.String(), name, privateKey, passphrase, strings.TrimSpace(pubText), fingerprint, true
	return out, nil
}

func (s *Store) ReadCredential(ctx context.Context, actor Actor, credentialID string) (Credential, error) {
	id, err := uuid.Parse(credentialID)
	if err != nil {
		return Credential{}, errors.New("credential_id 必须是 UUID")
	}
	var out Credential
	err = s.Pool.QueryRow(ctx, `SELECT id::text,target_id::text,name,private_key,passphrase,public_key,fingerprint,is_enabled,created_at FROM remote.credentials WHERE id=$1 AND owner_user_id=$2`, id, actor.UserID).Scan(&out.ID, &out.TargetID, &out.Name, &out.PrivateKey, &out.Passphrase, &out.PublicKey, &out.Fingerprint, &out.Enabled, &out.CreatedAt)
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

func pinnedHostKeyCallback(expected ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, presented ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(presented.Marshal(), expected.Marshal()) != 1 {
			return errors.New("SSH host key mismatch")
		}
		return nil
	}
}

type ExecResult struct {
	TargetID     string `json:"target_id"`
	CredentialID string `json:"credential_id"`
	ExitCode     int    `json:"exit_code"`
	Stdout       string `json:"stdout"`
	Stderr       string `json:"stderr"`
	Truncated    bool   `json:"truncated"`
	DurationMS   int64  `json:"duration_ms"`
}

type cappedBuffer struct {
	b         bytes.Buffer
	limit     int
	truncated bool
}

func (w *cappedBuffer) Write(p []byte) (int, error) {
	original := len(p)
	remaining := w.limit - w.b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = w.b.Write(p[:remaining])
			w.truncated = true
		} else {
			_, _ = w.b.Write(p)
		}
	} else if len(p) > 0 {
		w.truncated = true
	}
	return original, nil
}
func (w *cappedBuffer) String() string { return w.b.String() }

func (s *Store) Execute(ctx context.Context, actor Actor, targetID, credentialID, command string, timeout time.Duration) (ExecResult, error) {
	var out ExecResult
	if strings.TrimSpace(command) == "" || len(command) > MaxCommandBytes {
		return out, errors.New("command 不能为空且不得超过 16384 字节")
	}
	if timeout < time.Second || timeout > 300*time.Second {
		return out, errors.New("timeout_seconds 必须在 1 至 300 之间")
	}
	tid, err := uuid.Parse(targetID)
	if err != nil {
		return out, errors.New("target_id 必须是 UUID")
	}
	cid, err := uuid.Parse(credentialID)
	if err != nil {
		return out, errors.New("credential_id 必须是 UUID")
	}
	var host, username, hostKeyData, privateKey, passphrase string
	var port int
	err = s.Pool.QueryRow(ctx, `SELECT t.host,t.port,t.username,t.host_key_data,c.private_key,c.passphrase FROM remote.targets t JOIN remote.credentials c ON c.target_id=t.id AND c.owner_user_id=t.owner_user_id WHERE t.id=$1 AND t.owner_user_id=$2 AND t.is_enabled=TRUE AND c.id=$3 AND c.is_enabled=TRUE`, tid, actor.UserID, cid).Scan(&host, &port, &username, &hostKeyData, &privateKey, &passphrase)
	if err != nil {
		return out, errors.New("target or credential not found, disabled, or inaccessible")
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(hostKeyData))
	if err != nil {
		return out, errors.New("stored SSH host key is invalid")
	}
	signer, err := parseSigner(privateKey, passphrase)
	if err != nil {
		return out, fmt.Errorf("stored SSH private key is invalid: %w", err)
	}
	deadlineCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	dialer := net.Dialer{Timeout: 8 * time.Second, KeepAlive: 30 * time.Second}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, err := dialer.DialContext(deadlineCtx, "tcp", address)
	if err != nil {
		return out, fmt.Errorf("SSH connect: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	watchDone := make(chan struct{})
	go func() {
		select {
		case <-deadlineCtx.Done():
			_ = conn.Close()
		case <-watchDone:
		}
	}()
	defer close(watchDone)
	cfg := &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: pinnedHostKeyCallback(key), Timeout: 8 * time.Second}
	started := time.Now()
	cc, chans, reqs, err := ssh.NewClientConn(conn, address, cfg)
	if err != nil {
		return out, fmt.Errorf("SSH handshake/authentication: %w", err)
	}
	client := ssh.NewClient(cc, chans, reqs)
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return out, err
	}
	defer session.Close()
	var stdout, stderr cappedBuffer
	stdout.limit, stderr.limit = MaxOutputBytes, MaxOutputBytes
	session.Stdout = &stdout
	session.Stderr = &stderr
	done := make(chan error, 1)
	go func() { done <- session.Run(command) }()
	select {
	case err = <-done:
	case <-deadlineCtx.Done():
		_ = session.Close()
		return out, deadlineCtx.Err()
	}
	out = ExecResult{TargetID: tid.String(), CredentialID: cid.String(), ExitCode: 0, Stdout: stdout.String(), Stderr: stderr.String(), Truncated: stdout.truncated || stderr.truncated, DurationMS: time.Since(started).Milliseconds()}
	if err != nil {
		var exit *ssh.ExitError
		if errors.As(err, &exit) {
			out.ExitCode = exit.ExitStatus()
		} else {
			return out, err
		}
	}
	return out, nil
}

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

var _ io.Writer = (*cappedBuffer)(nil)
