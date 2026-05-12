#!/usr/bin/env bash
# Build a signed + notarized macOS .pkg installer.
#
# Inputs (env):
#   VERSION                    — release version (e.g. 0.2.0)
#   DEVELOPER_ID_INSTALLER     — "Developer ID Installer: <name> (<team>)"
#   NOTARY_APPLE_ID            — apple id with notarization access
#   NOTARY_PASSWORD            — app-specific password (or use --keychain-profile)
#
# Outputs:
#   dist/octravpn-${VERSION}.pkg            (signed + notarized)
#
# Assumes `cargo build --release` has been run for both x86_64-apple-darwin
# and aarch64-apple-darwin, and that the binaries live at
#   target/<triple>/release/octravpn
#   target/<triple>/release/octravpn-node

set -euo pipefail

VERSION="${VERSION:?VERSION required (e.g. 0.2.0)}"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
STAGING="$(mktemp -d)"
DIST="$ROOT/dist"
mkdir -p "$DIST"

# Make a universal binary so the .pkg works on Intel + Apple Silicon.
lipo_universal() {
    name="$1"
    if [ -f "$ROOT/target/x86_64-apple-darwin/release/$name" ] && \
       [ -f "$ROOT/target/aarch64-apple-darwin/release/$name" ]; then
        lipo -create \
            -output "$STAGING/usr/local/bin/$name" \
            "$ROOT/target/x86_64-apple-darwin/release/$name" \
            "$ROOT/target/aarch64-apple-darwin/release/$name"
    elif [ -f "$ROOT/target/release/$name" ]; then
        # Fallback: single-arch build.
        install -m 0755 "$ROOT/target/release/$name" "$STAGING/usr/local/bin/$name"
    else
        echo "missing $name; build with cargo first" >&2
        exit 2
    fi
    chmod 0755 "$STAGING/usr/local/bin/$name"
}

mkdir -p "$STAGING/usr/local/bin"
mkdir -p "$STAGING/Library/LaunchDaemons"
mkdir -p "$STAGING/usr/local/etc/octravpn"

lipo_universal octravpn
lipo_universal octravpn-node

install -m 0644 "$ROOT/deploy/launchd/com.octravpn.node.plist" \
    "$STAGING/Library/LaunchDaemons/com.octravpn.node.plist"

PKGROOT="$STAGING"
IDENT="org.octra.octravpn"
PKG_UNSIGNED="$DIST/octravpn-${VERSION}-unsigned.pkg"
PKG_SIGNED="$DIST/octravpn-${VERSION}.pkg"

pkgbuild \
    --root "$PKGROOT" \
    --identifier "$IDENT" \
    --version "$VERSION" \
    --install-location / \
    "$PKG_UNSIGNED"

if [ -n "${DEVELOPER_ID_INSTALLER:-}" ]; then
    productsign --sign "$DEVELOPER_ID_INSTALLER" "$PKG_UNSIGNED" "$PKG_SIGNED"
    if [ -n "${NOTARY_APPLE_ID:-}" ] && [ -n "${NOTARY_PASSWORD:-}" ]; then
        xcrun notarytool submit "$PKG_SIGNED" \
            --apple-id "$NOTARY_APPLE_ID" \
            --password "$NOTARY_PASSWORD" \
            --team-id "${NOTARY_TEAM_ID:-}" \
            --wait
        xcrun stapler staple "$PKG_SIGNED"
    fi
    rm -f "$PKG_UNSIGNED"
else
    mv "$PKG_UNSIGNED" "$PKG_SIGNED"
    echo "warning: DEVELOPER_ID_INSTALLER not set; produced unsigned .pkg"
fi

echo "built $PKG_SIGNED"
