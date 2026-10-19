package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/lycupay-debug/Go_SSH_MCP-KERNO/internal/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./cmd/admin-user <username>")
		os.Exit(2)
	}
	username := strings.TrimSpace(os.Args[1])
	if username == "" || len(username) > 128 {
		log.Fatal("username must be 1..128 characters")
	}
	path := os.Getenv("GO_SSH_MCP_CONFIG")
	if path == "" {
		path = "/usr/local/etc/kerno.conf"
	}
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprint(os.Stderr, "New password: ")
	password, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		log.Fatal("could not read password securely")
	}
	fmt.Fprint(os.Stderr, "Confirm password: ")
	confirm, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		log.Fatal("could not read password securely")
	}
	if len(password) < 14 {
		log.Fatal("password must be at least 14 bytes")
	}
	if string(password) != string(confirm) {
		log.Fatal("passwords do not match")
	}
	hash, err := bcrypt.GenerateFromPassword(password, bcrypt.DefaultCost)
	for i := range password {
		password[i] = 0
	}
	for i := range confirm {
		confirm[i] = 0
	}
	if err != nil {
		log.Fatal(err)
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()
	_, err = pool.Exec(ctx, `INSERT INTO oauth.users(id,username,password_hash,is_enabled) VALUES(gen_random_uuid(),$1,$2,TRUE)
		ON CONFLICT(username) DO UPDATE SET password_hash=EXCLUDED.password_hash,is_enabled=TRUE`, username, string(hash))
	if err != nil {
		log.Fatal(err)
	}
	fmt.Fprintln(os.Stderr, "OAuth user created or updated. Password was not logged.")
}
