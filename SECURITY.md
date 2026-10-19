# Security Policy

## Scope

KERNO exposes host-level file, shell, parallel execution and PostgreSQL tools. Treat any report affecting authentication, authorization, command execution, file access, secret handling, SQL execution or audit integrity as security-sensitive.

## Reporting

Do not publish exploit details or real credentials in public issues. Contact the repository maintainers privately through the GitHub security reporting mechanism if enabled; otherwise request a private channel from the maintainers before sharing details. Include affected commit/version, reproduction steps, impact and relevant sanitized logs.

## Deployment baseline

- Use HTTPS and keep the MCP listener bound to loopback behind a trusted reverse proxy.
- Restrict OAuth users and client registrations; do not expose the service to untrusted users.
- Treat the service as root-equivalent remote execution, not as a sandbox.
- Keep configuration and signing-key files private; never commit credentials or logs.
- Use a dedicated PostgreSQL database and carefully evaluate the broad privileges required by `database_query`.
- Report suspected credential exposure immediately and rotate affected credentials.
