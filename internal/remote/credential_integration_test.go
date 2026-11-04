// Package remote integration tests verify credential default selection and SSH execution.
package remote

import (
	"context"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/ssh"
)

func TestCredentialDefaultLifecycleIntegration(t *testing.T) {
	dsn := os.Getenv("GO_SSH_MCP_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("set GO_SSH_MCP_TEST_DATABASE_URL to run PostgreSQL remote credential tests")
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

	userID := uuid.NewString()
	if _, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash) VALUES($1,$2,'test')`, userID, "remote-test-"+userID); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM oauth.users WHERE id=$1`, userID)
	})

	store := &Store{Pool: pool}
	actor := Actor{UserID: userID, ClientID: "remote-credential-integration-test"}
	hostPrivate, hostKey, _ := testSSHKey(t)
	privateOne, _, _ := testSSHKey(t)
	privateTwo, _, _ := testSSHKey(t)
	hostSigner, err := parseSigner(hostPrivate, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	firstSigner, err := parseSigner(privateOne, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	secondSigner, err := parseSigner(privateTwo, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	port := startTestSSHServer(t, hostSigner, firstSigner.PublicKey(), secondSigner.PublicKey())
	target, err := store.CreateTarget(ctx, actor, TargetInput{
		Name: "credential-test", Host: "127.0.0.1", Port: port, Username: "root", HostKey: hostKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	first, err := store.SaveCredential(ctx, actor, target.ID, "primary", privateOne, "unit-test")
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.SaveCredential(ctx, actor, target.ID, "rotation", privateTwo, "unit-test")
	if err != nil {
		t.Fatal(err)
	}

	listed, err := store.ListCredentials(ctx, actor, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 2 || !listed[0].Default || listed[0].ID != first.ID || listed[1].Default {
		t.Fatalf("first credential should remain default after rotation: %#v", listed)
	}
	result, err := store.Execute(ctx, actor, target.ID, "", "true", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialID != first.ID || result.Stdout != "remote-default-ok\n" {
		t.Fatalf("default execution did not use the first key: %#v", result)
	}

	if err = store.SetDefaultCredential(ctx, actor, target.ID, second.ID); err != nil {
		t.Fatal(err)
	}
	listed, err = store.ListCredentials(ctx, actor, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	defaults := 0
	for _, item := range listed {
		if item.Default {
			defaults++
			if item.ID != second.ID {
				t.Fatalf("unexpected default credential: %#v", item)
			}
		}
	}
	if defaults != 1 {
		t.Fatalf("expected exactly one default credential, got %d", defaults)
	}
	result, err = store.Execute(ctx, actor, target.ID, "", "true", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialID != second.ID || result.Stdout != "remote-default-ok\n" {
		t.Fatalf("default execution did not use the selected key: %#v", result)
	}
	result, err = store.Execute(ctx, actor, target.ID, first.ID, "true", 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialID != first.ID {
		t.Fatalf("explicit credential override ignored: %#v", result)
	}

	setErrors := make(chan error, 2)
	go func() { setErrors <- store.SetDefaultCredential(ctx, actor, target.ID, first.ID) }()
	go func() { setErrors <- store.SetDefaultCredential(ctx, actor, target.ID, second.ID) }()
	for range 2 {
		if err = <-setErrors; err != nil {
			t.Fatal(err)
		}
	}
	listed, err = store.ListCredentials(ctx, actor, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	defaults = 0
	for _, item := range listed {
		if item.Default {
			defaults++
		}
	}
	if defaults != 1 {
		t.Fatalf("concurrent default changes broke uniqueness: %#v", listed)
	}

	other := Actor{UserID: uuid.NewString(), ClientID: actor.ClientID}
	otherList, err := store.ListCredentials(ctx, other, target.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(otherList) != 0 {
		t.Fatalf("another owner can list credentials: %#v", otherList)
	}
	if err = store.SetDefaultCredential(ctx, other, target.ID, first.ID); err == nil {
		t.Fatal("another owner changed the default credential")
	}
}

func startTestSSHServer(t *testing.T, hostKey ssh.Signer, allowedKeys ...ssh.PublicKey) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		for _, allowed := range allowedKeys {
			if string(key.Marshal()) == string(allowed.Marshal()) {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("unexpected client key")
	}}
	config.AddHostKey(hostKey)
	go func() {
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			go func(conn net.Conn) {
				serverConn, channels, requests, handshakeErr := ssh.NewServerConn(conn, config)
				if handshakeErr != nil {
					_ = conn.Close()
					return
				}
				defer serverConn.Close()
				go ssh.DiscardRequests(requests)
				for incoming := range channels {
					if incoming.ChannelType() != "session" {
						_ = incoming.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					channel, channelRequests, channelErr := incoming.Accept()
					if channelErr != nil {
						continue
					}
					go func(channel ssh.Channel, requests <-chan *ssh.Request) {
						defer channel.Close()
						for request := range requests {
							if request.Type == "exec" {
								_ = request.Reply(true, nil)
								_, _ = channel.Write([]byte("remote-default-ok\n"))
								_, _ = channel.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{Status: 0}))
								return
							}
							_ = request.Reply(false, nil)
						}
					}(channel, channelRequests)
				}
			}(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port
}
