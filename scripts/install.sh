#!/bin/sh
# KERNO installer. Supports FreeBSD 15.x only until Linux acceptance tests pass.
set -eu

REPO="lycupay-debug/Go_SSH_MCP-KERNO"
VERSION="${KERNO_VERSION:-}"
TMP_ROOT=""
STTY_STATE=""
cleanup() {
  if [ -n "$STTY_STATE" ]; then stty "$STTY_STATE" 2>/dev/null || true; printf "\n"; fi
  [ -z "$TMP_ROOT" ] || rm -rf "$TMP_ROOT"
}
trap cleanup EXIT HUP INT TERM

say() { printf '%s\n' "$*"; }
fail() { say "ERROR: $*" >&2; exit 1; }
ask() { printf '%s' "$1"; IFS= read -r REPLY; }

case "$(uname -s)" in
  FreeBSD) ;;
  Linux) fail "Debian/Ubuntu/Linux is not yet an accepted platform. Do not install this version there." ;;
  *) fail "Unsupported operating system: $(uname -s)" ;;
esac
[ "$(uname -m)" = "amd64" ] || fail "This installer currently targets FreeBSD amd64."
[ "$(id -u)" -eq 0 ] || fail "Run as root after reviewing this script."

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." 2>/dev/null && pwd || true)
if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/go.mod" ]; then
  [ -n "$VERSION" ] || { ask "Release tag to install (example: v0.1.0): "; VERSION=$REPLY; }
  case "$VERSION" in v[0-9]*.[0-9]*.[0-9]*) ;; *) fail "Use an explicit release tag such as v0.1.0; floating branch installs are disabled." ;; esac
  TMP_ROOT=$(mktemp -d /tmp/kerno-install.XXXXXX)
  ARCHIVE="$TMP_ROOT/kerno-source.tar.gz"
  SUMS="$TMP_ROOT/SHA256SUMS"
  BASE="https://github.com/$REPO/releases/download/$VERSION"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$BASE/kerno-source.tar.gz" -o "$ARCHIVE"
    curl -fsSL "$BASE/SHA256SUMS" -o "$SUMS"
  elif command -v fetch >/dev/null 2>&1; then
    fetch -qo "$ARCHIVE" "$BASE/kerno-source.tar.gz"
    fetch -qo "$SUMS" "$BASE/SHA256SUMS"
  else
    fail "curl or fetch is required to download the release."
  fi
  EXPECTED=$(awk '$2 == "kerno-source.tar.gz" {print $1}' "$SUMS")
  [ -n "$EXPECTED" ] || fail "SHA256SUMS does not include kerno-source.tar.gz."
  ACTUAL=$(sha256 -q "$ARCHIVE")
  [ "$ACTUAL" = "$EXPECTED" ] || fail "Source archive SHA-256 mismatch."
  mkdir "$TMP_ROOT/source"
  tar -xzf "$ARCHIVE" -C "$TMP_ROOT/source"
  SCRIPT_DIR=$(find "$TMP_ROOT/source" -mindepth 2 -maxdepth 3 -name go.mod -print -quit | sed 's#/go.mod$##')
  [ -n "$SCRIPT_DIR" ] || fail "Downloaded archive does not contain go.mod."
fi

cd "$SCRIPT_DIR"
command -v pkg >/dev/null 2>&1 || fail "pkg is required on FreeBSD."
if ! command -v go >/dev/null 2>&1 || ! pkg info -e json-c >/dev/null 2>&1 || ! command -v psql >/dev/null 2>&1 || ! command -v python3 >/dev/null 2>&1; then
  say "The installer needs Go, json-c and PostgreSQL client packages."
  ask "Install missing packages using pkg? [y/N] "
  case "$REPLY" in y|Y|yes|YES) pkg install -y go json-c postgresql17-client python3 ;; *) fail "Required build/runtime dependencies are missing." ;; esac
fi
command -v cc >/dev/null 2>&1 || fail "A C compiler is required."

say "KERNO requires root-equivalent host access and database_query can execute administrative SQL."
say "Use a dedicated database, keep the listener on loopback, and expose it only through a trusted HTTPS reverse proxy."
ask "Public hostname (without scheme or path): "
DOMAIN=$REPLY
case "$DOMAIN" in ''|*://*|*/*|*' '*|*example.com*|*example.net*) fail "Enter a real hostname you control, not a placeholder." ;; esac
case "$DOMAIN" in *[!A-Za-z0-9.-]*|.*|*.) fail "Hostname may contain only letters, digits, dots and hyphens." ;; esac
case "$DOMAIN" in *.*) ;; *) fail "Use a fully qualified hostname." ;; esac
case "$DOMAIN" in *..*) fail "Hostname cannot contain consecutive dots." ;; esac
ask "HTTPS issuer/resource hostname is https://$DOMAIN; confirm MCP path /mcp? [Y/n] "
case "$REPLY" in n|N|no|NO) fail "Installer cancelled." ;; esac
ask "Local listener port [8766]: "
PORT=${REPLY:-8766}
case "$PORT" in *[!0-9]*|'') fail "Port must be numeric." ;; esac
[ "$PORT" -ge 1024 ] && [ "$PORT" -le 65535 ] || fail "Port must be between 1024 and 65535."
printf "%s" "PostgreSQL URL (input hidden; role privileges will govern database_query): "
STTY_STATE=$(stty -g) || fail "An interactive terminal is required for hidden database input."
stty -echo
if ! IFS= read -r DATABASE_URL; then fail "Could not read DATABASE_URL."; fi
stty "$STTY_STATE"
STTY_STATE=""
printf '\n'
[ -n "$DATABASE_URL" ] || fail "DATABASE_URL is required."
case "$DATABASE_URL" in postgres://*|postgresql://*) ;; *) fail "DATABASE_URL must start with postgres:// or postgresql://." ;; esac
ask "Initial OAuth username [admin]: "
OAUTH_USER=${REPLY:-admin}
case "$OAUTH_USER" in *[!a-zA-Z0-9_.@+-]*|'') fail "Username contains unsupported characters." ;; esac

say "\nPlanned changes:"
say "  - install candidate under /opt/kerno"
say "  - create /usr/local/etc/kerno.conf (0600) and /usr/local/etc/kerno.secret (0600)"
say "  - initialize oauth tables in the selected database (CREATE IF NOT EXISTS only)"
say "  - register and start the FreeBSD kerno service"
say "  - interactively set the password for OAuth user '$OAUTH_USER'"
say "  - set issuer to https://$DOMAIN and resource to https://$DOMAIN/mcp"
[ ! -e /opt/kerno ] || fail "/opt/kerno already exists; refusing to overwrite an existing installation."
[ ! -e /usr/local/etc/kerno.conf ] || fail "/usr/local/etc/kerno.conf already exists; refusing to overwrite it."
[ ! -e /usr/local/etc/kerno.secret ] || fail "/usr/local/etc/kerno.secret already exists; refusing to overwrite it."
ask "Continue with installation? [y/N] "
case "$REPLY" in y|Y|yes|YES) ;; *) fail "Installation cancelled." ;; esac

export GOMODCACHE="$SCRIPT_DIR/.install-gomodcache"
export GOCACHE="$SCRIPT_DIR/.install-gocache"
mkdir -p "$GOMODCACHE" "$GOCACHE"
make test
go mod verify
go vet ./...
make build-production

install -d -o root -g wheel -m 0755 /opt/kerno/bin
install -o root -g wheel -m 0555 bin/go-ssh-mcp /opt/kerno/bin/go-ssh-mcp
install -o root -g wheel -m 0555 bin/go-ssh-mcp-admin-user /opt/kerno/bin/go-ssh-mcp-admin-user
install -o root -g wheel -m 0555 bin/host-executor /opt/kerno/bin/host-executor
install -o root -g wheel -m 0555 deploy/freebsd/rc.d/kerno /usr/local/etc/rc.d/kerno
install -d -o root -g wheel -m 0755 /usr/local/etc
umask 077
openssl rand -out /usr/local/etc/kerno.secret 64
chmod 0600 /usr/local/etc/kerno.secret
cat > /usr/local/etc/kerno.conf <<CONFIG
LISTEN_ADDR=127.0.0.1:$PORT
PUBLIC_ISSUER_URL=https://$DOMAIN
RESOURCE_URL=https://$DOMAIN/mcp
DATABASE_URL=$DATABASE_URL
C_EXECUTOR_PATH=/opt/kerno/bin/host-executor
MAX_OUTPUT_BYTES=1048576
OAUTH_SIGNING_KEY_FILE=/usr/local/etc/kerno.secret
AUDIT_LOG_PATH=/var/log/kerno-audit.log
CONFIG
chown root:wheel /usr/local/etc/kerno.conf
chmod 0600 /usr/local/etc/kerno.conf
unset DATABASE_URL

# Parse the connection string in Python and pass credentials through environment variables,
# not the psql command line. The migration itself is additive (CREATE IF NOT EXISTS).
GO_SSH_MCP_CONFIG=/usr/local/etc/kerno.conf python3 - <<'PY'
import os, subprocess, urllib.parse
url=os.environ.get('DATABASE_URL')
if not url:
    # Read the value only inside this process; never print it.
    for line in open('/usr/local/etc/kerno.conf', encoding='utf-8'):
        if line.startswith('DATABASE_URL='):
            url=line.rstrip('\n').split('=',1)[1]
            break
if not url:
    raise SystemExit('DATABASE_URL missing from config')
u=urllib.parse.urlsplit(url)
if u.scheme not in ('postgres','postgresql'):
    raise SystemExit('Unsupported PostgreSQL URL scheme')
env=os.environ.copy()
env['PGHOST']=u.hostname or 'localhost'
env['PGPORT']=str(u.port or 5432)
env['PGDATABASE']=urllib.parse.unquote((u.path or '/').lstrip('/'))
env['PGUSER']=urllib.parse.unquote(u.username or '')
if u.password is not None: env['PGPASSWORD']=urllib.parse.unquote(u.password)
for k,v in urllib.parse.parse_qsl(u.query,keep_blank_values=True):
    if k=='sslmode': env['PGSSLMODE']=v
subprocess.run(['psql','-X','-v','ON_ERROR_STOP=1','-f','migrations/001_oauth.sql'],env=env,check=True)
PY

GO_SSH_MCP_CONFIG=/usr/local/etc/kerno.conf /opt/kerno/bin/go-ssh-mcp-admin-user "$OAUTH_USER"
sysrc kerno_enable=YES
service kerno start
say "KERNO installed. Verify the reverse proxy, HTTPS issuer metadata, and an authenticated tool call before exposing it to clients."
say "Config: /usr/local/etc/kerno.conf; key: /usr/local/etc/kerno.secret; service: service kerno status"
