# Architecture: Go control plane and standalone C Executor

## Request path

1. The Go HTTP server exposes MCP Streamable HTTP at /mcp.
2. The OAuth provider handles registration, authorization, login/consent, refresh and revocation. Bearer validation checks token hash, user/client enablement, expiry, scope and resource.
3. The official Go MCP SDK validates JSON arguments against typed tool definitions. Local and remote tool registration is separated into testable registration functions.
4. Go routes local filesystem, system-information, service-status and log operations to the standalone C Executor process.
5. execute_shell uses Go os/exec; execute_parallel uses the bounded Go worker pool; database_query uses Go pgx/PostgreSQL; remote SSH uses the Go SSH client and pinned host keys.
6. Go maps results to the public MCP response contract and writes audit records.

## Execution and privilege model

- The Go GSM service and C Executor run as root. The C Executor is a separate process for request lifecycle and fault containment, not a privilege boundary.
- No component automatically drops privileges or switches to an unprivileged user.
- The C Executor does not receive OAuth signing keys, bearer tokens or the database connection string.
- The configured PostgreSQL role's privileges determine what database_query can do. The tool does not independently grant PostgreSQL superuser privileges.
- Root-level filesystem and shell tools are intentionally high privilege. There is no tool-level protected-path blacklist or working-directory whitelist. Parameter validation, path parsing, symlink semantics, task isolation, timeouts, output limits and audit remain in force.

## Bounded parallel execution

- execute_parallel accepts 2–32 independent tasks and has a process-wide maximum of 8 concurrent workers.
- Each task must use an existing, independently resolved working directory; duplicate task IDs/directories and tasks in the same Git worktree are rejected.
- Working directories are not restricted to a hard-coded list of system paths.
- Per-task timeout, output cap, process-group cleanup, restricted task logs and audit records are enforced.
- Execution is request-scoped; no durable job queue, DAG scheduler, cross-request task state or resource lease mechanism is provided.

## C Executor process protocol

The Go control plane starts the C Executor as a child process for each C operation. Go sends one JSON request to stdin:
- protocol_version
- task_id
- operation
- input

C returns one JSON response to stdout with ok and either result or a structured error. task_id must match the request. stderr is reserved for diagnostics. The process handles one request and exits. Input and output are bounded.

This internal Go/C protocol is distinct from the external MCP Streamable HTTP transport used by MCP clients.

## File operation semantics

- write_file defaults to the original truncate-in-place behavior (atomic=false), including following symlinks and preserving shared hard-link inode behavior.
- write_file atomic=true opens and identity-checks an existing source, captures its ACL/extattr snapshot, fsyncs the source and rechecks descriptor/path basic metadata, then stages data and metadata in a same-directory temporary file, fsyncs that temporary file and renames it over the resolved target. It follows symlinks but replaces the target directory entry, so other hard links continue to reference the old inode.
- replace_in_file performs byte-oriented streaming replacement in 64 KiB chunks, retains cross-chunk match overlap, supports embedded NUL bytes, preserves first/all replacement semantics, and commits through a same-directory temporary file plus rename.
- Atomic operations require a regular-file target. Symlink targets are resolved; dangling symlinks are rejected. The destination path becomes a new inode and other hard links are not updated.
- Atomic replacement preserves owner, group and mode; it copies ACLs when the filesystem supports the relevant ACL type, copies user/system extended attributes, and copies non-blocking file flags. Immutable, append-only, no-unlink and snapshot flags are rejected rather than cleared.
- New atomic files use the same 0666-and-umask creation semantics as the original direct-write implementation.
- The temporary file is fsynced before rename. After rename, the parent directory is fsynced and then the committed target file is fsynced. If either post-rename fsync fails, the operation reports that the rename may already have committed but durability is unconfirmed. The C Executor catches SIGTERM/SIGINT while an atomic temp file is active and unlinks that temp file before exiting; SIGKILL or power loss cannot run this cleanup handler.
- Existing source files are opened and identity-checked before the metadata baseline is captured. The baseline retains the ACL selected by the existing copy policy (NFSv4 first, POSIX access ACL fallback) and compares ACLs with FreeBSD `acl_cmp_np`. USER and SYSTEM extattrs are normalized by sorting names; a `libmd` SHA-256 digest covers namespace tags, name/value lengths and bytes. Each extattr value is read and hashed one at a time; the implementation does not retain all attribute values simultaneously.
- Both `write_file(atomic=true)` and `replace_in_file` compare the source metadata baseline after metadata copy, after destination-file fsync, and immediately before rename. A detected ACL/extattr difference returns `ATOMIC_TARGET_CHANGED`; the staged temporary file is removed, while the original source inode and the concurrent writer's metadata remain. Metadata snapshot read/compare failures use `ATOMIC_METADATA_SNAPSHOT_FAILED` rather than being misreported as a concurrent change.
- Basic source checks continue to compare device/inode, size, mtime, mode, owner, group and file flags. ctime-only drift is intentionally ignored because it was observed on FreeBSD UFS without content/basic-metadata changes. Metadata fingerprints supplement rather than replace these stat checks. This remains best-effort, not a compare-and-swap guarantee: a non-cooperating writer can still race in the interval after the final metadata/stat check and before rename.
- Validation note (2026-11-20): deterministic barriers injected concurrent changes at all three checkpoints for both atomic write and streaming replace. On temporary UFS mounted with POSIX ACLs, USER/SYSTEM extattrs and POSIX ACL mutations were detected; on UFS mounted with NFSv4 ACLs, USER/SYSTEM extattrs and NFSv4 ACL mutations were detected. Across both filesystem configurations, 36 checkpoint cases passed and 12 cases skipped only because the requested ACL dialect did not match the mount. Tests verified `ATOMIC_TARGET_CHANGED`, original file content preservation, concurrent metadata preservation and temporary-file cleanup. The current server filesystem is UFS; ZFS behavior has not been tested in this iteration.
- POSIX ACL and NFSv4 ACL copy paths were both exercised on temporary UFS filesystems mounted with acls and nfsv4acls. User extended attributes, nodump flag preservation, immutable-flag rejection, parent-directory fsync and post-rename committed-file fsync also succeeded on the current UFS volume.
- move_path retains its established overwrite behavior. delete_path requires recursive=true for non-empty directories and does not follow a symlink when deleting it. No protected path denylist or working-directory whitelist is applied.

## Tool registry

The local and remote tool registrations are exercised through the MCP SDK in-memory transport. The runtime tools/list test asserts all 20 names, property names/types, required fields, and remote OAuth scope metadata. get_system_info identifies the Go/C runtime rather than claiming Python is running.

## OAuth and remote SSH

- OAuth authorization-code, refresh-token and signed authorization-request expiry boundaries are exclusive: when current time equals `expires_at`/`exp`, the credential is expired. Access-token and session SQL lookups use `expires_at > now()` with the same boundary semantics.
- The HTTP MCP middleware requires the base go-ssh-mcp scope.
- Remote SSH tools additionally advertise and enforce remote:ssh:manage at tool level.
- Remote target and credential ownership is checked in the remote store.
- SSH host keys are pinned; credentials are selected by the target default unless an explicit credential override is supplied.
- Remote private keys and optional passphrases are stored in PostgreSQL as plaintext by explicit product requirement. Restrict database, backup and audit access; this is not a multi-user security boundary.

## Deployment boundary

The accepted platform is FreeBSD 15.x amd64. Linux remains unsupported until its build, service management, installation, OAuth and MCP integration tests pass. Production deployment is performed only after candidate acceptance, with a verified backup and rollback plan.
