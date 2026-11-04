// Package remote contains persistence and execution for operator-managed SSH targets.
// Store owns PostgreSQL access; Actor carries the authenticated OAuth principal used for
// ownership checks and audit attribution. Secret-bearing Credential is reserved for the
// explicit credential-read operation; list/create responses use CredentialInfo.
package remote

import (
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	MaxCommandBytes = 16 * 1024
	MaxOutputBytes  = 1 << 20
)

type Store struct{ Pool *pgxpool.Pool }

type Actor struct{ UserID, ClientID string }

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

type TargetInput struct {
	Name, Host, Username, HostKey string
	Port                          int
}

// Credential contains the secret material returned only by the explicit read operation.
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

// CredentialInfo is the non-secret metadata shape used by create and list responses.
type CredentialInfo struct {
	ID          string    `json:"id"`
	TargetID    string    `json:"target_id"`
	Name        string    `json:"name"`
	Fingerprint string    `json:"fingerprint"`
	Enabled     bool      `json:"enabled"`
	Default     bool      `json:"default"`
	CreatedAt   time.Time `json:"created_at"`
}
