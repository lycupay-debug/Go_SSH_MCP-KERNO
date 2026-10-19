# Deployment guide (FreeBSD)

This guide applies to the currently tested platform only: FreeBSD 15.x amd64. Debian/Ubuntu support is not accepted yet; the installer intentionally refuses Linux.

## Before installation

1. Use a clean host or a dedicated VM; the service requires root-equivalent host authority.
2. Configure a DNS hostname and a trusted TLS reverse proxy. Keep the KERNO listener on `127.0.0.1` and forward HTTPS requests to the configured local port.
3. Create a dedicated PostgreSQL database. Review the role permissions carefully: the `database_query` tool permits SQL data changes, DDL and administrative statements. If the configured role is a PostgreSQL superuser, tool calls can affect the cluster, not only KERNO's OAuth tables.
4. Ensure outbound network access to the configured Go module source and FreeBSD package repository.
5. Read `scripts/install.sh` before running it as root.

## Install from a source checkout

```sh
git clone --branch v0.1.0 --depth 1 https://github.com/lycupay-debug/Go_SSH_MCP-KERNO.git
cd Go_SSH_MCP-KERNO
sudo sh scripts/install.sh
```

Use a real release tag that exists in the repository. Do not install a floating development branch on a production host.

The installer asks for the hostname, local port, PostgreSQL connection string (hidden input), and initial OAuth username. It runs build/tests before installing, refuses to overwrite existing `/opt/kerno` or config/key files, creates the OAuth schema with `CREATE IF NOT EXISTS`, and asks for the OAuth user's password without terminal echo. The password must be at least 14 bytes.

When run as a standalone script without a source checkout, it downloads the versioned release archive and `SHA256SUMS` asset, and verifies the SHA-256 before extraction. Release packaging must provide these two assets.

## Reverse proxy and OAuth URLs

The issuer is `https://YOUR_HOSTNAME` and the resource URL is `https://YOUR_HOSTNAME/mcp`. The reverse proxy must preserve the `/mcp` path and the OAuth discovery/authorization routes used by this version. Configure TLS, request-size limits, timeouts, and access logging at the proxy. Do not log authorization headers, cookies, authorization codes, or database URLs.

## Operations

```sh
service kerno status
service kerno restart
tail -n 100 /var/log/kerno.log
tail -n 100 /var/log/kerno-audit.log
```

Configuration is `/usr/local/etc/kerno.conf` (mode `0600`); the OAuth signing key is `/usr/local/etc/kerno.secret` (mode `0600`, root-owned). Back them up securely. Never regenerate the signing key during a routine restart; doing so may invalidate existing OAuth state/tokens.

## Uninstall

There is no automatic uninstall command yet. Before removing files, disable and stop the service, preserve the configuration/key if OAuth continuity matters, and review whether the database contains other applications' data. Do not drop the PostgreSQL database or schema automatically.

## Linux status

Linux is not currently supported by this release. The project still has FreeBSD service assumptions and has not passed Debian/Ubuntu build, runtime, service-management and integration tests. The installer exits without modifying the host when it detects Linux.
