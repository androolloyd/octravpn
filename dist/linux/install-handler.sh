#!/usr/bin/env bash
#
# Register `octravpn open-url` as the Linux handler for `oct://` URLs.
#
# Usage:
#   bash dist/linux/install-handler.sh           # install (default)
#   bash dist/linux/install-handler.sh status    # show current binding
#
# Uninstall lives in the sibling script `dist/linux/uninstall-handler.sh`
# so this file stays focused on the install path (mirroring the macOS
# layout in `dist/macos/`).
#
# This script writes a single `.desktop` file under
# `~/.local/share/applications/octravpn-oct-handler.desktop` and
# registers it with `xdg-mime` as the default for `x-scheme-handler/oct`.
# Nothing is written outside `~/.local/share/applications/`. Nothing
# touches `/usr/` or `/etc/`.
#
# Not run during scaffolding. To test manually:
#
#   1.  cargo build --release -p octravpn-client
#   2.  bash dist/linux/install-handler.sh
#   3.  xdg-open 'oct://octdeadbeef00000000000000000000000000000000/policy.json'
#   4.  Expect a terminal-style invocation that prints
#       "would open oct://..." (stub behaviour; see open_url.rs).
#
# Read the design doc before changing anything here:
#   docs/oct-url-handler.md
#
# Idempotent: re-running rewrites the desktop file in place and
# re-applies the xdg-mime default.

set -euo pipefail

ACTION="${1:-install}"

# Hard refuse on non-Linux. The macOS path lives in
# `dist/macos/install-handler.sh`; the Windows path in
# `dist/windows/install-handler.ps1`. Running this on either is wrong.
UNAME_S="$(uname -s)"
if [ "$UNAME_S" != "Linux" ]; then
    echo "error: this script targets Linux; got uname=$UNAME_S" >&2
    echo "       macOS:   dist/macos/install-handler.sh" >&2
    echo "       Windows: dist/windows/install-handler.ps1" >&2
    exit 1
fi

# Resolve the workspace root from this script's location. The script
# lives at `<repo>/dist/linux/install-handler.sh`; the binary lands at
# `<repo>/target/release/octravpn` after `cargo build --release`.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Locate the `octravpn` binary. Precedence:
#   1. $OCTRAVPN_BIN env override (absolute path).
#   2. `octravpn` on $PATH (e.g. /usr/local/bin/octravpn after install).
#   3. <repo>/target/release/octravpn (cargo build artifact).
#
# We embed an absolute path in the `.desktop` file because XDG
# `Exec=` lookups go through the desktop's exec parser, NOT through
# the user's shell — `$PATH` may not be set the same way the GUI
# session sees it.
locate_binary() {
    if [ -n "${OCTRAVPN_BIN:-}" ]; then
        if [ -x "$OCTRAVPN_BIN" ]; then
            echo "$OCTRAVPN_BIN"
            return 0
        fi
        echo "error: \$OCTRAVPN_BIN=$OCTRAVPN_BIN is not executable" >&2
        return 1
    fi
    if command -v octravpn >/dev/null 2>&1; then
        command -v octravpn
        return 0
    fi
    local fallback="$REPO_ROOT/target/release/octravpn"
    if [ -x "$fallback" ]; then
        echo "$fallback"
        return 0
    fi
    echo "error: octravpn binary not found." >&2
    echo "       set \$OCTRAVPN_BIN, install to PATH, or run:" >&2
    echo "       cargo build --release -p octravpn-client" >&2
    return 1
}

TEMPLATE="$SCRIPT_DIR/octravpn-oct-handler.desktop"
DESKTOP_NAME="octravpn-oct-handler.desktop"
APPS_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$APPS_DIR/$DESKTOP_NAME"

case "$ACTION" in
    install)
        if [ ! -f "$TEMPLATE" ]; then
            echo "error: desktop template not found at $TEMPLATE" >&2
            exit 1
        fi

        OCTRAVPN_BIN="$(locate_binary)"
        echo "using octravpn binary: $OCTRAVPN_BIN"

        echo "writing desktop file to $DESKTOP_FILE"
        mkdir -p "$APPS_DIR"
        # Substitute the placeholder with the absolute binary path. We
        # use `|` as the sed delimiter because the binary path may
        # contain `/`.
        sed "s|__OCTRAVPN_BIN__|$OCTRAVPN_BIN|g" "$TEMPLATE" > "$DESKTOP_FILE"
        chmod 0644 "$DESKTOP_FILE"

        # `update-desktop-database` refreshes the MIME cache that
        # GNOME-style sessions consult. KDE additionally rebuilds via
        # `kbuildsycoca5`/`kbuildsycoca6` on its own when a `.desktop`
        # changes under `~/.local/share/applications`; we don't poke
        # it here.
        if command -v update-desktop-database >/dev/null 2>&1; then
            echo "running update-desktop-database $APPS_DIR"
            update-desktop-database "$APPS_DIR"
        else
            echo "note: update-desktop-database not installed; skipping cache refresh" >&2
            echo "      (binding will still work on most session types)" >&2
        fi

        echo "registering $DESKTOP_NAME as default for x-scheme-handler/oct"
        xdg-mime default "$DESKTOP_NAME" x-scheme-handler/oct

        echo "verifying registration"
        BOUND="$(xdg-mime query default x-scheme-handler/oct || true)"
        if [ "$BOUND" = "$DESKTOP_NAME" ]; then
            echo "ok: oct: scheme bound to $DESKTOP_NAME"
            echo
            echo "test with:"
            echo "  xdg-open 'oct://octdeadbeef00000000000000000000000000000000/policy.json'"
        else
            echo "error: registration did not stick." >&2
            echo "       xdg-mime query returned: '$BOUND'" >&2
            echo "       expected:                '$DESKTOP_NAME'" >&2
            exit 1
        fi
        ;;

    status)
        if [ -f "$DESKTOP_FILE" ]; then
            echo "desktop file present: $DESKTOP_FILE"
        else
            echo "desktop file absent (expected at $DESKTOP_FILE)"
        fi
        echo
        echo "current x-scheme-handler/oct binding:"
        xdg-mime query default x-scheme-handler/oct || \
            echo "  (none / xdg-mime unavailable)"
        ;;

    *)
        echo "usage: $0 [install|status]" >&2
        echo "       (uninstall lives in dist/linux/uninstall-handler.sh)" >&2
        exit 64
        ;;
esac
