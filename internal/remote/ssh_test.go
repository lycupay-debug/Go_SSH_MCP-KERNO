// Package remote unit tests cover host-key pinning, key parsing, and bounded output.
package remote

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
)

func testSSHKey(t *testing.T) (string, string, ssh.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "unit-test", []byte("unit-test"))
	if err != nil {
		t.Fatal(err)
	}
	privateText := string(pem.EncodeToMemory(block))
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return privateText, string(ssh.MarshalAuthorizedKey(sshPub)), sshPub
}

func TestValidateTargetRequiresPinnedAuthorizedKey(t *testing.T) {
	_, hostKey, parsed := testSSHKey(t)
	key, fingerprint, err := validateTarget(TargetInput{Name: "laptop", Host: "laptop.example.test", Port: 22, Username: "admin", HostKey: hostKey})
	if err != nil {
		t.Fatal(err)
	}
	if key.Type() != parsed.Type() || fingerprint != ssh.FingerprintSHA256(parsed) {
		t.Fatalf("unexpected host key metadata: %s %s", key.Type(), fingerprint)
	}
	for _, in := range []TargetInput{
		{Name: "", Host: "host", Port: 22, Username: "u", HostKey: hostKey},
		{Name: "x", Host: "host", Port: 0, Username: "u", HostKey: hostKey},
		{Name: "x", Host: "host name", Port: 22, Username: "u", HostKey: hostKey},
		{Name: "x", Host: "host", Port: 22, Username: "u", HostKey: "not-a-key"},
	} {
		if _, _, err := validateTarget(in); err == nil {
			t.Fatalf("invalid target accepted: %#v", in)
		}
	}
}

func TestParseSignerSupportsPassphraseAndRejectsWrongPassphrase(t *testing.T) {
	privateText, _, _ := testSSHKey(t)
	if _, err := parseSigner(privateText, "unit-test"); err != nil {
		t.Fatalf("valid encrypted key rejected: %v", err)
	}
	if _, err := parseSigner(privateText, "wrong"); err == nil {
		t.Fatal("wrong passphrase accepted")
	}
}

func TestPinnedHostKeyCallback(t *testing.T) {
	_, _, expected := testSSHKey(t)
	_, _, other := testSSHKey(t)
	cb := pinnedHostKeyCallback(expected)
	if err := cb("host", nil, expected); err != nil {
		t.Fatalf("pinned host key rejected: %v", err)
	}
	if err := cb("host", nil, other); err == nil {
		t.Fatal("mismatched host key accepted")
	}
}

func TestPinnedHostKeyAlgorithms(t *testing.T) {
	_, _, expected := testSSHKey(t)
	got := pinnedHostKeyAlgorithms(expected)
	if len(got) != 1 || got[0] != expected.Type() {
		t.Fatalf("expected only pinned key algorithm %q, got %v", expected.Type(), got)
	}
}

func TestCappedBuffer(t *testing.T) {
	w := &cappedBuffer{limit: 4}
	if n, err := w.Write([]byte("abcdef")); err != nil || n != 6 {
		t.Fatalf("write=(%d,%v)", n, err)
	}
	if w.String() != "abcd" || !w.truncated {
		t.Fatalf("unexpected capped output: %q truncated=%v", w.String(), w.truncated)
	}
}

func TestCredentialInfoSerializationExcludesSecrets(t *testing.T) {
	encoded, err := json.Marshal(CredentialInfo{
		ID: "credential-id", TargetID: "target-id", Name: "primary",
		Fingerprint: "SHA256:test", Enabled: true, Default: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	text := string(encoded)
	if strings.Contains(text, "private_key") || strings.Contains(text, "passphrase") {
		t.Fatalf("credential metadata response must not expose secret fields: %s", text)
	}
	if !strings.Contains(text, `"default":true`) {
		t.Fatalf("default credential state missing from metadata response: %s", text)
	}
}
