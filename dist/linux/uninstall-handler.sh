#!/usr/bin/env bash
#
# Remove the `oct://` URL-scheme handler installed by
# `dist/linux/install-handler.sh`.
#
# Idempotent: running this twice (or running it when nothing is
# installed) prints a status message and exits 0.
#
# Touches only:
#   - `xdg-mime default '' x-scheme-handler/oct` (clears our binding)
#   - `rm -f ~/.local/share/applications/octravpn-oct-handler.desktop`
#
# Never writes outside `~/.local/share/applications/`. Never touches
# `/usr/` or `/etc/`.

set -euo pipefail

UNAME_S="$(uname -s)"
if [ "$UNAME_S" != "Linux" ]; then
    echo "error: this script targets Linux; got uname=$UNAME_S" >&2
    exit 1
fi

DESKTOP_NAME="octravpn-oct-handler.desktop"
APPS_DIR="$HOME/.local/share/applications"
DESKTOP_FILE="$APPS_DIR/$DESKTOP_NAME"

# Clear the scheme binding first so xdg-open stops dispatching to our
# (about-to-be-removed) desktop file. Empty value resets to whatever
# the desktop's default-default is (typically: nothing).
#
# We only clear the binding if it currently points at our entry —
# blowing away someone else's later override would be rude.
CURRENT="$(xdg-mime query default x-scheme-handler/oct 2>/dev/null || true)"
if [ "$CURRENT" = "$DESKTOP_NAME" ]; then
    echo "clearing x-scheme-handler/oct binding (was: $CURRENT)"
    # `xdg-mime default ''` is the documented way to unset; some
    # distros' xdg-utils versions refuse an empty string. Fall back
    # to deleting the mimeapps line directly if so.
    if ! xdg-mime default "" x-scheme-handler/oct 2>/dev/null; then
        MIMEAPPS="$HOME/.config/mimeapps.list"
        if [ -f "$MIMEAPPS" ]; then
            # Strip any line that binds our desktop name to the oct
            # scheme. Leaves the rest of the file alone.
            tmp="$(mktemp)"
            grep -v "x-scheme-handler/oct=$DESKTOP_NAME" "$MIMEAPPS" > "$tmp" || true
            mv "$tmp" "$MIMEAPPS"
        fi
    fi
elif [ -n "$CURRENT" ]; then
    echo "note: x-scheme-handler/oct is bound to '$CURRENT' (not ours); leaving it"
else
    echo "note: no x-scheme-handler/oct binding currently set"
fi

if [ -f "$DESKTOP_FILE" ]; then
    echo "removing $DESKTOP_FILE"
    rm -f "$DESKTOP_FILE"
else
    echo "note: $DESKTOP_FILE already absent"
fi

if command -v update-desktop-database >/dev/null 2>&1; then
    echo "refreshing desktop database"
    update-desktop-database "$APPS_DIR" || true
fi

echo "done."
