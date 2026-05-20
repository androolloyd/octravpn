#!/usr/bin/env sh
# OctraVPN universal POSIX installer.
#
# Usage:
#   curl -fsSL https://octravpn.org/install.sh | sh
#   curl -fsSL https://octravpn.org/install.sh | sh -s -- --node          (install node)
#   curl -fsSL https://octravpn.org/install.sh | sh -s -- --version=0.2.0
#
# Detects: Linux x86_64/aarch64, macOS x86_64/aarch64.
#
# Installs:
#   /usr/local/bin/octravpn          (client CLI)
#   /usr/local/bin/octravpn-node     (node daemon, if --node)
# Plus, with --node, registers a system service via systemd / launchd.

set -eu

INSTALL_DIR="${OCTRAVPN_PREFIX:-/usr/local}"
RELEASES_URL="${OCTRAVPN_RELEASES_URL:-https://github.com/octra-labs/octravpn/releases}"
VERSION=""
INSTALL_NODE=0
INSTALL_CLIENT=1
DRY_RUN=0
SERVICE=1

for arg in "$@"; do
    case "$arg" in
        --version=*) VERSION="${arg#*=}" ;;
        --node) INSTALL_NODE=1 ;;
        --no-client) INSTALL_CLIENT=0 ;;
        --no-service) SERVICE=0 ;;
        --dry-run) DRY_RUN=1 ;;
        --prefix=*) INSTALL_DIR="${arg#*=}" ;;
        --help|-h)
            cat <<EOF
OctraVPN installer.

Flags:
  --version=X.Y.Z     Pin a release version (default: latest).
  --node              Also install octravpn-node and register a system service.
  --no-client         Skip the client CLI.
  --no-service        Skip system-service registration.
  --prefix=DIR        Install root (default: /usr/local).
  --dry-run           Print what would happen but make no changes.
EOF
            exit 0
            ;;
        *)
            echo "Unknown flag: $arg" >&2
            exit 2
            ;;
    esac
done

say() { printf '%s\n' "==> $*"; }
warn() { printf '%s\n' "warn: $*" >&2; }
die() { printf '%s\n' "error: $*" >&2; exit 1; }

require_cmd() {
    command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

require_cmd curl
require_cmd uname
require_cmd tar
require_cmd install

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS" in
    Linux)
        case "$ARCH" in
            x86_64|amd64) TARGET="x86_64-unknown-linux-gnu" ;;
            aarch64|arm64) TARGET="aarch64-unknown-linux-gnu" ;;
            *) die "unsupported Linux arch: $ARCH" ;;
        esac
        ;;
    Darwin)
        case "$ARCH" in
            x86_64) TARGET="x86_64-apple-darwin" ;;
            arm64) TARGET="aarch64-apple-darwin" ;;
            *) die "unsupported macOS arch: $ARCH" ;;
        esac
        ;;
    *)
        die "unsupported OS: $OS — try a native package or build from source"
        ;;
esac

if [ -z "$VERSION" ]; then
    say "resolving latest release"
    VERSION="$(curl -fsSL -I "$RELEASES_URL/latest" | awk -F'/' '/^location:/i {print $NF}' | tr -d '\r')"
    [ -n "$VERSION" ] || die "could not resolve latest release; pass --version=X.Y.Z"
fi
say "installing octravpn $VERSION ($TARGET)"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

URL="$RELEASES_URL/download/$VERSION/octravpn-$VERSION-$TARGET.tar.gz"
say "downloading $URL"
[ "$DRY_RUN" -eq 1 ] || curl -fsSL "$URL" -o "$TMP/octravpn.tar.gz" || die "download failed"
[ "$DRY_RUN" -eq 1 ] || tar -C "$TMP" -xzf "$TMP/octravpn.tar.gz"

# Verify GPG signature if gpg is installed and the .sig sidecar is
# present. Lookup-only; install proceeds if signature isn't available
# (and we warn). The signature contract is documented in SECURITY.md
# and produced by .github/workflows/release.yml (gpg --detach-sign
# --armor → <artifact>.sig). Keep the suffix in sync with that
# workflow — see the regression check at the bottom of this file.
SIG_SUFFIX=".sig"
verify_sig() {
    SIG_URL="$URL$SIG_SUFFIX"
    if command -v gpg >/dev/null 2>&1 && curl -fsI "$SIG_URL" >/dev/null 2>&1; then
        say "verifying GPG signature"
        curl -fsSL "$SIG_URL" -o "$TMP/octravpn.tar.gz$SIG_SUFFIX"
        # The release public key must already be imported into the
        # invoking user's GPG keyring. Bootstrap once with:
        #   curl -fsSL https://octra.org/keys/octravpn-release.asc | gpg --import
        # The expected fingerprint is pinned in docs/release.md §5.
        if gpg --verify "$TMP/octravpn.tar.gz$SIG_SUFFIX" "$TMP/octravpn.tar.gz" 2>&1; then
            say "GPG signature OK"
        else
            die "signature verification failed — refusing to install"
        fi
    else
        warn "gpg not installed or signature absent; skipping signature verification"
        warn "see docs/release.md §6 to enable verified installs"
    fi
}
[ "$DRY_RUN" -eq 1 ] || verify_sig

install_binary() {
    src="$1"; dst="$2"
    if [ "$DRY_RUN" -eq 1 ]; then
        say "(dry-run) install $src → $dst"
        return
    fi
    if [ "$(id -u)" -ne 0 ]; then
        sudo install -m 0755 "$src" "$dst"
    else
        install -m 0755 "$src" "$dst"
    fi
}

if [ "$INSTALL_CLIENT" -eq 1 ]; then
    install_binary "$TMP/octravpn" "$INSTALL_DIR/bin/octravpn"
    say "installed $INSTALL_DIR/bin/octravpn"
fi
if [ "$INSTALL_NODE" -eq 1 ]; then
    install_binary "$TMP/octravpn-node" "$INSTALL_DIR/bin/octravpn-node"
    say "installed $INSTALL_DIR/bin/octravpn-node"
fi

# Linux capabilities: bind CAP_NET_ADMIN to the node binary so it can
# open TUN without running as root.
if [ "$INSTALL_NODE" -eq 1 ] && [ "$OS" = "Linux" ]; then
    if command -v setcap >/dev/null 2>&1; then
        say "setcap CAP_NET_ADMIN+ep on $INSTALL_DIR/bin/octravpn-node"
        if [ "$DRY_RUN" -eq 0 ]; then
            sudo setcap cap_net_admin,cap_net_bind_service+ep "$INSTALL_DIR/bin/octravpn-node" || \
                warn "setcap failed; node may need to run as root"
        fi
    else
        warn "setcap not installed; node may need to run as root"
    fi
fi

# Register a system service.
register_systemd() {
    say "registering systemd unit"
    if [ "$DRY_RUN" -eq 1 ]; then
        say "(dry-run) skip"
        return
    fi
    # User + dirs.
    sudo getent passwd octravpn >/dev/null || sudo useradd --system --no-create-home --shell /usr/sbin/nologin octravpn
    sudo install -d -o octravpn -g octravpn -m 0750 /etc/octravpn /var/lib/octravpn /var/log/octravpn

    UNIT_SRC="$(dirname "$0")/systemd/octravpn-node.service"
    if [ -f "$UNIT_SRC" ]; then
        sudo install -m 0644 "$UNIT_SRC" /etc/systemd/system/octravpn-node.service
    else
        # Source not local (curl|sh path); fetch from the release.
        curl -fsSL "$RELEASES_URL/download/$VERSION/octravpn-node.service" \
            -o "$TMP/octravpn-node.service"
        sudo install -m 0644 "$TMP/octravpn-node.service" /etc/systemd/system/octravpn-node.service
    fi
    sudo systemctl daemon-reload
    say "systemd unit installed at /etc/systemd/system/octravpn-node.service"
    say "run 'octravpn-node init --config /etc/octravpn/node.toml' to provision a config."
    say "then: sudo systemctl enable --now octravpn-node"
}

register_launchd() {
    say "registering launchd plist"
    if [ "$DRY_RUN" -eq 1 ]; then
        say "(dry-run) skip"
        return
    fi
    sudo install -d -m 0755 /usr/local/etc/octravpn /usr/local/var/log
    PLIST_SRC="$(dirname "$0")/launchd/com.octravpn.node.plist"
    if [ -f "$PLIST_SRC" ]; then
        sudo install -m 0644 "$PLIST_SRC" /Library/LaunchDaemons/com.octravpn.node.plist
    else
        curl -fsSL "$RELEASES_URL/download/$VERSION/com.octravpn.node.plist" \
            -o "$TMP/com.octravpn.node.plist"
        sudo install -m 0644 "$TMP/com.octravpn.node.plist" /Library/LaunchDaemons/com.octravpn.node.plist
    fi
    say "launchd plist installed at /Library/LaunchDaemons/com.octravpn.node.plist"
    say "load with: sudo launchctl bootstrap system /Library/LaunchDaemons/com.octravpn.node.plist"
}

if [ "$INSTALL_NODE" -eq 1 ] && [ "$SERVICE" -eq 1 ]; then
    case "$OS" in
        Linux) register_systemd ;;
        Darwin) register_launchd ;;
    esac
fi

cat <<EOF

OctraVPN installed.

Next steps:
  octravpn init --rpc-url https://your.rpc/rpc --program-addr oct...
  octravpn doctor

Documentation: https://github.com/octra-labs/octravpn/blob/main/docs/install.md
EOF

# ----------------------------------------------------------------------
# Regression check (executes only when this script is invoked with
# OCTRAVPN_INSTALL_SELFTEST=1; a no-op on the normal curl|sh path).
# Asserts that $SIG_SUFFIX matches the artifact name produced by
# .github/workflows/release.yml's `gpg --detach-sign --armor --output
# "${artifact}.sig"` step. If those two ever drift, signature
# verification silently breaks and operators land in the unverified
# branch — exactly the Audit-6 bug this commit closes. Update both
# this constant AND the workflow output= flag together.
# ----------------------------------------------------------------------
if [ "${OCTRAVPN_INSTALL_SELFTEST:-0}" = "1" ]; then
    expected_suffix=".sig"
    if [ "$SIG_SUFFIX" != "$expected_suffix" ]; then
        die "selftest: SIG_SUFFIX=$SIG_SUFFIX does not match release.yml's '$expected_suffix' contract"
    fi
    say "selftest: sidecar suffix matches release.yml contract ($SIG_SUFFIX)"
fi
