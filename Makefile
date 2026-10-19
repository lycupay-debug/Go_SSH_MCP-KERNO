GO ?= go

.PHONY: build build-candidate build-production build-c build-c-candidate test test-integration vet migrate clean clean-production

# Safe default for the development branch: never replace executables used by the live service.
build: build-candidate

build-candidate: build-c-candidate
	$(GO) build -o bin/go-ssh-mcp-parallel-candidate ./cmd/go-ssh-mcp
	$(GO) build -o bin/go-ssh-mcp-admin-user-candidate ./cmd/admin-user

# Explicit production-named outputs; run only during an approved deployment.
build-production: build-c
	$(GO) build -o bin/go-ssh-mcp ./cmd/go-ssh-mcp
	$(GO) build -o bin/go-ssh-mcp-admin-user ./cmd/admin-user

# Legacy target writes the production C executor path; avoid it during branch development.
build-c:
	$(MAKE) -C executor/c all OUT=../../bin/host-executor

build-c-candidate:
	$(MAKE) -C executor/c all OUT=../../bin/host-executor-candidate

test: build-c-candidate
	C_EXECUTOR_TEST_PATH="$$(pwd)/bin/host-executor-candidate" $(GO) test -count=1 ./...

# Requires a disposable PostgreSQL database initialized with migrations/001_oauth.sql.
test-integration: build-c-candidate
	@test -n "$(GO_SSH_MCP_TEST_DATABASE_URL)" || (echo "GO_SSH_MCP_TEST_DATABASE_URL is required" >&2; exit 2)
	C_EXECUTOR_TEST_PATH="$$(pwd)/bin/host-executor-candidate" $(GO) test -count=1 -v ./...

vet:
	$(GO) vet ./...

# Supply PGHOST, PGDATABASE, PGUSER, PGPASSWORD and PGSSLMODE via environment.
migrate:
	@test -n "$(PGDATABASE)" -a -n "$(PGUSER)" || (echo "PGDATABASE and PGUSER are required" >&2; exit 2)
	@for migration in migrations/*.sql; do echo "Applying $$migration"; psql -X -v ON_ERROR_STOP=1 -f "$$migration"; done

# Default clean only removes branch candidate artifacts; live service binaries are preserved.
clean:
	rm -f bin/go-ssh-mcp-parallel-candidate bin/go-ssh-mcp-admin-user-candidate bin/host-executor-candidate

clean-production:
	rm -f bin/go-ssh-mcp bin/go-ssh-mcp-admin-user bin/host-executor
