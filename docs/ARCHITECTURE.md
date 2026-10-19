# Architecture: Go/C MCP server with bounded parallel execution

## Request path

1. The Go HTTP server exposes MCP Streamable HTTP at `/mcp`.
2. The OAuth provider handles registration, authorization-code + PKCE, login/consent, refresh and revocation routes. Bearer validation checks token hash, user/client enablement, expiry, scope and resource.
3. The official Go MCP SDK validates JSON arguments against typed tool definitions.
4. Go routes local filesystem operations (directory listing, file read/write/replace/delete) through typed cgo calls into C.
5. Shell execution, service/log queries, system information and file moves use the C executor process through a versioned JSON request/response protocol.
6. Go maps results to the tool response contract and writes audit records.

## Execution model

- No durable job queue, DAG scheduler, cross-request task state or resource lease mechanism is provided.
- `execute_parallel` uses a bounded Go worker pool (maximum 8 workers), isolated working directories, per-task timeout/output caps, process-group cleanup and restricted task logs.
- Parallel execution is request-scoped; it does not create durable job rows or background schedules.
- The C process does not receive OAuth signing keys, bearer tokens or the database connection string.

## Tool registry

The typed registrations in `cmd/go-ssh-mcp/main.go` are authoritative. Available tools are listed in the root README. `get_system_info` identifies the Go/C runtime rather than claiming Python is running.

## C protocol

Process-backed operations use one JSON object with `protocol_version`, `task_id`, `operation` and `input`; C returns one JSON object with `ok` and either `result` or a structured `error`. Shell operations use bounded output, explicit timeouts and process-group cleanup. Local file operations call C directly through cgo and do not spawn an executor process.

## OAuth and data safety

The OAuth provider and token verifier are responsible for token validation and authorization state. Audit logs are designed to omit shell command contents and file contents to reduce accidental secret capture. File writes preserve `Path.write_text`-style truncate-in-place behavior and follow symlinks; they are not atomic writes. Operators must account for this when choosing paths and permissions.

## Deployment boundary

The current release is tested on FreeBSD. Linux support remains unaccepted until the C executor, service-management operations, installation flow and end-to-end OAuth/MCP behavior pass dedicated Linux tests.
