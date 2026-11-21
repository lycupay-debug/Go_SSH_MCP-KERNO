# KERNO release acceptance checklist

Status updated: 2026-11-20. A checked item means the named candidate-level test or read-only inspection actually ran and passed. Candidate tests do not imply production deployment acceptance.

## 1. OAuth and MCP HTTP

- [x] OAuth authorization-code flow, exact redirect URI checks, login/consent CSRF checks, authorization-code reuse rejection, expired-code rejection and PKCE exchange are exercised by the PostgreSQL-backed integration test.
- [x] Refresh-token rotation and refresh-token reuse detection revoke the affected token family.
- [x] Token revocation endpoint marks the family, access tokens and refresh tokens revoked.
- [x] OAuth metadata, protected-resource metadata and WWW-Authenticate challenge behavior have unit/integration coverage.
- [x] OAuth rejection matrix now covers disabled clients at authorization/code-exchange/refresh, disabled users at code-exchange/refresh, invalid PKCE verifier, redirect mismatch, unsupported scopes, wrong requested/stored resource, expired authorization codes/refresh tokens, revoked refresh tokens, and access-token expiry (including the exact expiry boundary), empty/wrong bearer scopes, disabled users/clients and revoked/wrong-resource access tokens. Tests use the dedicated PostgreSQL integration database.
- [x] Exact expiry-boundary behavior is tested for authorization codes and refresh tokens: expiry equality is rejected; a timestamp one microsecond later remains valid. Signed authorization-request `exp` equality is also rejected; access-token/session SQL checks use `expires_at > now()` and therefore reject equality.
- [x] HTTPS reverse-proxy integration harness now exercises the full OAuth authorization-code/login/consent/token/refresh/revoke flow through a TLS edge proxy, plus authenticated MCP initialize and get_system_info tool call; wrong-resource tokens return 401 and wrong-scope tokens return 403. Caddy production and isolated staging Caddyfile syntax both validate.
- [x] An isolated live Caddy process-level staging run passed: Caddy TLS internal listener on 127.0.0.1:18443 reverse-proxied to the candidate Go server on 127.0.0.1:18766; health, protected-resource metadata, unauthenticated 401, authenticated MCP initialize and get_system_info tool call all passed. [ ] The actual production Caddy/Cloudflare Tunnel route and production callback continuity remain pending; no production Caddy configuration was changed.
- [ ] Production callback continuity and connector persistence after deployment remain unverified.

## 2. Public MCP tool contracts

- [x] Runtime tools/list returns exactly 20 unique tools: 12 local and 8 remote.
- [x] Runtime schema test checks all property names, JSON types, required fields and remote remote:ssh:manage metadata.
- [x] write_file.atomic is an optional boolean; default remains false.
- [ ] Defaults, numeric bounds, result shapes and structured error contracts still need a complete per-tool contract matrix.
- [x] get_system_info reports Go SDK + C executor, not a Python runtime.
- [x] execute_parallel validates 2–32 tasks, max parallel 1–16, unique task IDs/directories and distinct Git worktrees.
- [x] execute_parallel no longer has a hard-coded working-directory whitelist or /opt/kerno deny rule. Root / is accepted by validation.
- [x] Independent tasks execute concurrently; the server-wide worker pool is capped at 16 across concurrent requests.
- [x] Timeout, output cap, process-group cleanup, 0700 run directories, 0600 task logs and started/finished audit callbacks have tests.
- [x] Remote tools enforce tool-level OAuth step-up scope; remote target/credential ownership, host-key pinning and signer validation have PostgreSQL/SSH integration coverage.
- [x] remote_credential_list serializes non-secret credential metadata only.
- [x] Per-target default credential uniqueness and concurrent default changes are integration-tested.
- [x] remote_ssh_exec default credential selection and explicit credential override are integration-tested.
- [x] File lifecycle tests cover write/read, move overwrite, delete, recursive-delete requirement, symlink deletion without following the link, default write symlink behavior and atomic write/replace link semantics.
- [x] Streaming replace is tested across a 64 KiB boundary, with embedded NUL bytes, first/all replacement semantics and a separate opt-in >2 GiB test.
- [x] Atomic write/replace tests cover USER and SYSTEM extended attributes, nodump flag preservation, immutable-flag rejection, basic ownership/mode, parent-directory fsync and post-rename committed-file fsync on the current UFS volume.
- [x] POSIX ACL and NFSv4 ACL preservation are tested on temporary UFS filesystems mounted with acls and nfsv4acls; both atomic write and atomic replace preserve the added ACL entry.
- [x] SIGTERM during a >2 GiB streaming replace leaves the original unchanged and removes the active temporary file; ENOSPC during atomic write and replace leaves both originals unchanged and removes temporary files.
- [x] Deterministic concurrent content-writer injection during streaming replace: after the temporary destination has received its first 64 KiB output chunk, a writer modifies the original source; the operation returns ATOMIC_TARGET_CHANGED, preserves the writer change and original tail, and removes the temporary file. Repeated under -race and included in the full race/integration runs.
- [x] ACL/extattr-only concurrent writer detection: test-only barriers inject mutations after metadata copy, after destination fsync, and immediately before rename. Both `write_file(atomic=true)` and `replace_in_file` detect USER extattr, SYSTEM extattr and the active ACL dialect; the original content and concurrent metadata remain intact and temp files are removed. Temporary POSIX-ACL UFS: 18 cases passed, 6 NFSv4 mismatch cases skipped. Temporary NFSv4-ACL UFS: 18 cases passed, 6 POSIX mismatch cases skipped. ZFS was not available in the current environment and remains unverified. The final check-to-rename interval remains a non-CAS race window. [ ] SIGKILL/power-loss orphan cleanup remains unverified.

## 3. Build and integration

- [x] make test passes across all Go packages using the candidate C Executor.
- [x] make test-integration passes against the dedicated database kerno_gsm_test_20261120.
- [x] Integration database migrations 001, 002 and 003 applied successfully to that database only.
- [x] Integration test cleanup ordering was corrected; after the suite, exact counts for OAuth users/clients/tokens/codes and remote targets/credentials were all zero.
- [x] Full go test -race -count=1 ./... passes with the dedicated integration database configured.
- [x] go vet ./... passes.
- [x] go mod verify reports all modules verified.
- [x] C candidate compiles with -Wall -Wextra -Wpedantic and no warnings.
- [x] make build-candidate builds the C Executor, Go GSM and admin-user candidates.
- [x] git diff --check passes.
- [ ] Production service start/restart, health endpoint, reverse-proxy routing, log rotation and reboot persistence must be verified in the single final deployment window.
- [x] Linux is not advertised as a supported platform; installer explicitly rejects Linux.

## 4. Security and operations

- [x] Production config and OAuth signing key are regular root-owned files with mode 0600 (metadata-only inspection; file contents were not read).
- [x] Production service and C Executor run as root, as explicitly required by the operator.
- [x] Production database URL uses role kerno_app; PostgreSQL reports rolsuper=false, rolcreatedb=false, rolcreaterole=false; the role owns database kerno.
- [x] Current tracked worktree scan found no private-key markers, embedded PostgreSQL passwords, common cloud/GitHub token patterns, or the operator's production domain.
- [x] Custom pattern scan covered all 55 reachable Git commits and found no private-key markers, credential-bearing PostgreSQL URLs, common cloud/GitHub/Slack/OpenAI token patterns.
- [x] Gitleaks v8.30.1 was extracted from the FreeBSD package into /tmp (not installed system-wide) and scanned the current worktree with archive depth 2, Git history, and the generated clean-snapshot source release archive. Each scope returned the same single `generic-api-key` finding at `cmd/admin-user/main.go:70`, confirmed as SQL literal `is_enabled=TRUE`, not a credential; history finding is in commit `c2285d3`. The generated archive scan also found only that same false positive. Actual published GitHub Release asset scan remains pending until the final tag is published. Gitleaks is pattern-based and cannot prove absence of every secret class.
- [x] Audit implementation stores query hashes rather than SQL text, command hashes rather than SSH command text, and error types/SQLSTATE rather than raw database/remote error messages; a redaction unit test verifies raw error text is not persisted.
- [x] Central audit redaction now applies to local file audit, OAuth audit rows and remote SSH audit rows. Tests verify removal of password/password-hash, private key, passphrase, bearer/access/refresh tokens, authorization codes, PKCE verifier, cookies, commands, stdout/stderr, file contents, SQL, database URLs/DSNs and API/signing keys; one-way command/query/client-name/credential-name hashes remain available.
- [ ] The sanitizer is key-based defense-in-depth, not arbitrary free-text secret detection; final audit review of all future fields/call sites remains necessary.
- [x] Captured a fresh production `kerno` PostgreSQL custom-format backup and restored it twice into isolated databases: once with `--no-owner --no-acl`, once preserving original object owners/ACLs. All 12 tables and exact row counts matched; OAuth/remote schema owners and table/sequence owners matched in the owner-preserving restore. Both drill databases were dropped and verified absent. Backup SHA-256 and root:wheel 0600 metadata are recorded in Notion §43. [ ] Binary/config rollback rehearsal and an integrated pre-deployment rollback runbook remain pending.
- [ ] Remote SSH private keys and optional passphrases remain plaintext in PostgreSQL by explicit product design. This requires strict database/backup access controls and is not a multi-user isolation boundary.
- [ ] Final operator review of the database role's effective grants and the production OAuth client/scope configuration is pending.

## 5. Performance and release artifacts

- [x] Reconstructed the current working source into a separate normal Git clone, applied tracked changes and untracked source/docs, committed a temporary verification snapshot `882dc5afc4a11046eca3b97c68b17a9fc8cf8f10`, and confirmed a clean tree with Go VCS metadata `vcs.modified=false`. From this clean snapshot, `make test`, full `go test -race -count=1 ./...`, `make test-integration`, `make vet`, `go mod verify`, `make build-candidate`, and `git diff --check` all passed. Integration target skipped opt-in mounted ACL/NFSv4 ACL, >2 GiB, forced termination and ENOSPC tests; these were separately run and passed earlier against the same C source. Clean-snapshot hashes: C `f719af849c166705f7192da9ae925744a5ff8bbbf8ae28aea6b02c75256a9339`; Go GSM `f8209b1e0d94729fa1c3f4bc93312d04315de7ed8aaa68798e53f9900dd8e83d`; admin-user `ba476b19b24d441f393e039eafbbeec10dd46a8483243a6a1e257558025c92dc`. These are synthetic snapshot hashes, not final release artifact hashes; a final tag commit will produce new VCS-stamped Go binaries.
- [x] Latest candidate sequential standalone C Executor IPC benchmark after ACL/extattr metadata fingerprint implementation: 3 runs × 100 samples per case, 5 warmups, all 0 errors; C Executor SHA-256 `528186c4279a97346ae903d9c47c1c22e6c6ffeb11e3d895088e8b6955e97a64`, Go GSM SHA-256 `d90aa4d99d5e9147c5f138897c05136c66ee0888b588ba0d635ff623f3609215`, admin-user SHA-256 `e7a01a7a594dc871cb2fa2150fc388ff132cc1845e08f8cbf5c228ec7a5bb98c`. See the latest candidate section in docs/BENCHMARK.md.
- [ ] Full HTTP/MCP/OAuth, parallel/concurrency, long-duration, resource-use and final frozen-release benchmark remains pending. Historical cgo measurements are not current IPC performance evidence.
- [x] Host root UFS ctime-only drift was reproduced during atomic staging/destination fsync. Candidate checks preserve the ctime-only false-positive fix while also fingerprinting ACL and USER/SYSTEM extattrs at the three pre-commit checkpoints. Deterministic UFS POSIX/NFSv4 ACL and extattr injection tests passed (36 pass, 12 dialect-mismatch skips); `make test`, `make test-integration` against the dedicated `kerno_gsm_test_20261120` database, full `go test -race -count=1 ./...` with that database, `make vet`, `go mod verify`, `make build-candidate`, and `git diff --check` passed. The latest three-run benchmark (5 warmups + 100 samples/case) passed with zero errors and is bound to C SHA-256 `528186c4279a97346ae903d9c47c1c22e6c6ffeb11e3d895088e8b6955e97a64`; see docs/BENCHMARK.md. The final metadata check-to-rename interval remains non-CAS; ZFS behavior remains unverified. HTTPS reverse-proxy tests cover OAuth flow and authenticated MCP tool call, including 401 wrong-audience and 403 wrong-scope responses; production Caddy process-level staging remains pending.
- [x] Fixed a release artifact contract mismatch: installer downloads `kerno-source.tar.gz` and looks for that exact filename in `SHA256SUMS`, while the previous workflow published `kerno-source_Remote.tar.gz`. Workflow now emits `kerno-source.tar.gz`, verifies the checksum and required archive entries before publishing. Local `git archive`/checksum/extraction contract test passed; installer `sh -n`, workflow shell-block `sh -n`, and `git diff --check` passed. [ ] Run the actual GitHub Actions workflow on the final release tag and verify the published assets from a clean checkout.
- [x] MIT license and third-party inventory reviewed. `go-licenses report ./...` matches the checked-in package/license inventory (apart from the project URL resolving to `HEAD` versus `main` and the separately tracked system `json-c` row). Exact upstream license files for 17 production Go modules plus `json-c` are bundled under `THIRD_PARTY_LICENSES/`; all 18 copies were SHA-256 compared with their source files. The `go-sdk` v1.7.0 mixed-transition LICENSE preserves Apache-2.0, MIT and CC-BY-4.0 terms. All 30 resolved modules have LICENSE/COPYING files in their downloaded source. `go-licenses` reports assembly/C inspection warnings; test-only transitive modules are not copied into the production license bundle and remain documented as such.
- [ ] Ensure the release tag points to the exact fully tested commit.
- [ ] Publish release artifacts only after candidate acceptance and the final unified deployment test.

## 6. Current production boundary

- Production Go/C binaries, configuration, database and running service have not been modified during this candidate work.
- The production service remains on its previous binaries until the candidate is feature-complete and the single deployment/rollback plan is approved and executed.
- No production deployment is considered verified by this checklist until section 1 end-to-end, section 3 operational and section 4 rollback items pass.
