# Acceptance checklist

A passing compile is necessary but not sufficient for deployment.

## 1. OAuth and authentication

- [ ] Issuer, resource URL and authorization/token/revocation/registration endpoints match the private deployment configuration.
- [ ] Signing-key file is root-owned, regular and mode `0600`.
- [ ] Access-token expiry, revocation, user/client enablement, scope and resource checks work.
- [ ] Unauthenticated requests return the expected protected-resource metadata challenge.
- [ ] PKCE, redirect-URI matching, state validation, refresh rotation/reuse detection and CSRF protections pass.
- [ ] End-to-end authorization and an authenticated tool call succeed through the intended HTTPS reverse proxy.

## 2. Tool surface

- [ ] `tools/list` exposes all tools documented in the root README.
- [ ] `execute_parallel` validates 2–32 tasks, enforces a concurrency cap of 8, rejects duplicate task IDs/directories, and requires separate Git worktrees for work in the same repository.
- [ ] Independent tasks can run concurrently without exceeding the server-wide limit.
- [ ] Per-task timeout (1–300 seconds), output cap, process-group cleanup, restricted task logs and audit records are verified.
- [ ] Required/optional arguments, defaults, schema bounds, result shapes and errors are verified.
- [ ] `get_system_info` identifies the Go/C runtime.
- [ ] File write, move and delete tests cover symlinks, permissions, overwrite behavior, recursive deletion and failure cases.

## 3. Runtime and platform

- [ ] Warning-enabled C build passes.
- [ ] `make test`, `go mod verify` and `go vet ./...` pass.
- [ ] Integration tests use only a disposable test database.
- [ ] Service startup, restart, logs, health endpoint and reverse-proxy routing are verified.
- [ ] Linux must not be advertised as supported until Linux build, integration, systemd and OAuth/MCP tests pass.

## 4. Security review

- [ ] Public repository scan finds no credentials, private keys, production URLs, server IPs or private deployment configuration.
- [ ] Configuration and signing-key permissions are verified.
- [ ] The service's root-equivalent execution and the database privileges available to `database_query` are explicitly accepted by the operator.
- [ ] Audit logs do not record passwords, bearer tokens, authorization codes, cookies, file contents or full database URLs.
- [ ] Backups and rollback procedures are tested; no destructive migration is run against production during validation.

## 5. Performance and release

- [ ] Benchmarks use repeatable inputs and report median, P95, failures and output equivalence.
- [ ] Source archive SHA-256 is published and verified by the installer.
- [ ] Third-party license report is reviewed for the exact release dependencies.
- [ ] The release tag points to the tested commit and the release notes identify platform limitations.
