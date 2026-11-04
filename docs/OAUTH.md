# OAuth design and acceptance

KERNO exposes an OAuth-protected MCP Streamable HTTP endpoint. Deployment-specific URLs are intentionally not committed; configure the issuer and resource URL in the private runtime configuration.

## Required deployment properties

- HTTPS-only public issuer and MCP resource URL.
- Protected Resource Metadata and Authorization Server Metadata discovery.
- Dynamic Client Registration for public clients using `token_endpoint_auth_method=none` where required by the client.
- Authorization Code grant with PKCE S256, state validation, exact redirect-URI matching and resource/audience binding.
- Login and explicit consent screens with CSRF protection and secure, HttpOnly session cookies.
- 24-hour opaque access tokens stored as hashes, refresh-token rotation and reuse detection.
- Token revocation, user/client disablement, expiry and scope checks.
- Audit events must not include passwords, bearer tokens, authorization codes, cookies or full database URLs.
- Unauthenticated MCP requests should return the expected protected-resource metadata challenge.
- Successful authorization responses and OAuth errors redirected after exact redirect-URI validation must include both the original `state` and the authorization server `iss`.

## Authorization callback compatibility

KERNO adds `iss` to successful authorization-code redirects and to redirectable authorization errors (`invalid_scope`, `invalid_target`, and user denial). Errors raised before a client and its exact `redirect_uri` have been validated remain local HTTP errors and are not redirected.

The authorization-server metadata intentionally does not advertise `authorization_response_iss_parameter_supported: true` yet. Existing ChatGPT DCR records use callback-ID-specific redirect URIs and KERNO enforces exact redirect-URI matching. Advertising RFC 9207 support changes the callback mode used by compatible clients; enable it only as part of a coordinated DCR redirect-URI migration after every success and redirectable error response is verified to include `iss`. Do not toggle this metadata flag independently of registered redirect URIs.

The authorization-code exchange additionally validates the exact registered redirect URI, PKCE verifier, and resource indicator. A server-side `token.issued` audit event proves that the callback reached the token endpoint and the code exchange completed; it does not prove that the client subsequently persisted the connector or that its later MCP request succeeded.

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

## Remote SSH tool-level OAuth step-up

The `/mcp` HTTP middleware continues to require only the base `go-ssh-mcp` scope so existing local host-management tools and existing base-scope tokens remain usable. Each remote SSH tool separately advertises an OAuth 2.0 `securitySchemes` entry in its MCP tool `_meta`, requiring `go-ssh-mcp` and `remote:ssh:manage`. If a valid base-scope token calls one of those tools without the additional scope, the handler returns an MCP error result with `isError: true` and `_meta["mcp/www_authenticate"]` containing an `insufficient_scope` challenge, the protected-resource metadata URL, and both required scopes. This is a tool-level OAuth step-up response; it does not broaden the HTTP middleware requirements or change the behavior of local tools.

## Remote SSH scope and trust model

The `remote:ssh:manage` scope enables the remote SSH target, credential and execution tools. Clients must allow this scope in their registration metadata. At authorization, an explicitly supplied `scope` parameter is honored as-is; when the parameter is omitted or blank, KERNO now uses the client's registered scope allow-list (including `remote:ssh:manage` when registered). The resulting scope list is still shown on the consent page and is granted only after the user explicitly approves it. This preserves least privilege when a client explicitly asks for only `go-ssh-mcp`, while allowing clients that omit `scope` to receive the scopes they registered as eligible for consent. It is independent of the existing `go-ssh-mcp` scope; the local host-management tools retain their existing behavior.

KERNO is intended by default for a self-hosted instance operated by one trusted user. The `user_id` ownership checks organize targets and credentials and provide audit attribution; they are not a strong isolation boundary against another caller who can use the instance's existing root-level host tools or database access. Multi-user deployments require a separate authorization design and security review.

Remote SSH private keys and optional passphrases are stored as plaintext in PostgreSQL by explicit product choice. Restrict database and backup access. Remote targets accept operator-supplied hostnames and IP addresses, so outbound SSH reachability follows the KERNO host's network access policy. Apply `migrations/002_remote_ssh.sql` and `migrations/003_remote_ssh_default_credential.sql` in order before using the remote SSH tools. Each target has at most one default credential, enforced by a partial unique index. The first credential created becomes default; later credential creation does not silently change it. `remote_credential_list` returns non-secret metadata, `remote_credential_set_default` changes the default in a transaction, and `remote_ssh_exec` uses that default when `credential_id` is omitted. An explicit credential ID can still be supplied for a one-off override.
