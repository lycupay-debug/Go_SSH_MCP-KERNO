// SSH execution connects to registered targets using owner-scoped credentials and pinned host keys.
// Dependencies: PostgreSQL through Store, context/net deadlines, and x/crypto/ssh transport.
// Collaboration: remote_tools.go validates OAuth scope and delegates command execution here.
// Side effects: outbound SSH connections and remote command execution; output and duration are bounded.
package remote

// SSH execution applies strict input/time/output bounds and a pinned host-key callback.
// It resolves credentials only after checking target ownership and enabled state; omitted
// credential IDs select the single enabled default key. Network and process side effects
// are bounded by the caller context and the configured command timeout.

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

func pinnedHostKeyCallback(expected ssh.PublicKey) ssh.HostKeyCallback {
	return func(_ string, _ net.Addr, presented ssh.PublicKey) error {
		if subtle.ConstantTimeCompare(presented.Marshal(), expected.Marshal()) != 1 {
			return errors.New("SSH host key mismatch")
		}
		return nil
	}
}

// pinnedHostKeyAlgorithms prevents SSH negotiation from selecting a different
// host-key type before the pinned-key callback can verify the expected key.
func pinnedHostKeyAlgorithms(key ssh.PublicKey) []string {
	if key.Type() == ssh.KeyAlgoRSA {
		return []string{ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256}
	}
	return []string{key.Type()}
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

// Execute runs a bounded command over pinned-host-key SSH using an owned enabled credential.
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
	var credentialFilter any
	if strings.TrimSpace(credentialID) != "" {
		parsed, parseErr := uuid.Parse(credentialID)
		if parseErr != nil {
			return out, errors.New("credential_id 必须是 UUID")
		}
		credentialFilter = parsed
	}
	var host, username, hostKeyData, privateKey, passphrase, selectedCredentialID string
	var port int
	query := `SELECT t.host,t.port,t.username,t.host_key_data,c.private_key,c.passphrase,c.id::text FROM remote.targets t JOIN remote.credentials c ON c.target_id=t.id AND c.owner_user_id=t.owner_user_id WHERE t.id=$1 AND t.owner_user_id=$2 AND t.is_enabled=TRUE AND c.is_enabled=TRUE AND c.is_default=TRUE`
	args := []any{tid, actor.UserID}
	if credentialFilter != nil {
		query = `SELECT t.host,t.port,t.username,t.host_key_data,c.private_key,c.passphrase,c.id::text FROM remote.targets t JOIN remote.credentials c ON c.target_id=t.id AND c.owner_user_id=t.owner_user_id WHERE t.id=$1 AND t.owner_user_id=$2 AND t.is_enabled=TRUE AND c.is_enabled=TRUE AND c.id=$3`
		args = append(args, credentialFilter)
	}
	err = s.Pool.QueryRow(ctx, query, args...).Scan(&host, &port, &username, &hostKeyData, &privateKey, &passphrase, &selectedCredentialID)
	if err != nil {
		if credentialFilter == nil {
			return out, errors.New("no enabled default SSH credential for this target; list credentials and select a default")
		}
		return out, errors.New("target or credential not found, disabled, or inaccessible")
	}
	out.TargetID, out.CredentialID = tid.String(), selectedCredentialID
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
	cfg := &ssh.ClientConfig{User: username, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: pinnedHostKeyCallback(key), HostKeyAlgorithms: pinnedHostKeyAlgorithms(key), Timeout: 8 * time.Second}
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
	out = ExecResult{TargetID: tid.String(), CredentialID: selectedCredentialID, ExitCode: 0, Stdout: stdout.String(), Stderr: stderr.String(), Truncated: stdout.truncated || stderr.truncated, DurationMS: time.Since(started).Milliseconds()}
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

// Compile-time contract: cappedBuffer satisfies the SSH session writer interface.
var _ io.Writer = (*cappedBuffer)(nil)
