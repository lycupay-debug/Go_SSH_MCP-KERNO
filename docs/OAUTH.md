# OAuth design and acceptance

KERNO exposes an OAuth-protected MCP Streamable HTTP endpoint. Deployment-specific URLs are intentionally not committed; configure the issuer and resource URL in the private runtime configuration.

## Required deployment properties

- HTTPS-only public issuer and MCP resource URL.
- Protected Resource Metadata and Authorization Server Metadata discovery.
- Dynamic Client Registration for public clients using `token_endpoint_auth_method=none` where required by the client.
- Authorization Code grant with PKCE S256, state validation, exact redirect-URI matching and resource/audience binding.
- Login and explicit consent screens with CSRF protection and secure, HttpOnly session cookies.
- Short-lived opaque access tokens stored as hashes, refresh-token rotation and reuse detection.
- Token revocation, user/client disablement, expiry and scope checks.
- Audit events must not include passwords, bearer tokens, authorization codes, cookies or full database URLs.
- Unauthenticated MCP requests should return the expected protected-resource metadata challenge.

## Database and signing key

The `oauth` schema stores users, sessions, clients, authorization codes, access tokens, refresh-token families, refresh tokens, consents and audit records. The signing key must be a regular root-owned file with mode `0600` and at least 32 bytes. Back it up securely; do not regenerate it as part of an ordinary service restart.

`migrations/001_oauth.sql` creates the OAuth schema and tables with `CREATE ... IF NOT EXISTS`. It does not drop existing objects. Run it only against the intended KERNO database and never point development or integration tests at production data.

## Acceptance tests

Before production use, verify:

- PKCE success and failure, expired/reused codes, redirect URI mismatch and state validation.
- Invalid, expired and revoked access tokens; disabled users/clients; scope and resource checks.
- Refresh-token rotation/reuse detection and CSRF protection.
- Correct OAuth metadata and `WWW-Authenticate` behavior.
- An end-to-end authorization flow and authenticated MCP tool call through the intended HTTPS reverse proxy.

A passing unit test or metadata response alone is not end-to-end OAuth acceptance. Account and plan restrictions imposed by an external client cannot be overridden by server-side changes.
