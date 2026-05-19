# `dist/` — OS-level packaging assets

Per-platform glue for registering `octravpn` as the system handler for
`oct://` URLs. Design + security model: `docs/oct-url-handler.md`.

Prerequisite for any platform:

```
cargo build --release -p octravpn-client
```

## macOS

```
bash dist/macos/install-handler.sh
open "oct://octdeadbeef.../policy.json"        # manual test
bash dist/macos/install-handler.sh uninstall   # remove
```

Writes `~/Library/Application Support/octravpn/handler/OctravpnUrlHandler.app`
and registers it with LaunchServices.

## Linux

```
bash dist/linux/install-handler.sh
xdg-open 'oct://octdeadbeef.../policy.json'    # manual test
bash dist/linux/uninstall-handler.sh           # remove
```

Writes `~/.local/share/applications/octravpn-oct-handler.desktop` and
binds it via `xdg-mime`.

## Windows

```
powershell -ExecutionPolicy Bypass -File dist\windows\install-handler.ps1
cmd /c start "" "oct://octdeadbeef.../policy.json"    # manual test
powershell -ExecutionPolicy Bypass -File dist\windows\uninstall-handler.ps1
```

Writes the per-user `HKCU\Software\Classes\oct` registry subtree (no
admin, no HKLM).

## Safety boundaries

Every install script writes only to user-scoped locations
(`~/Library/...`, `~/.local/share/applications/`,
`HKCU\Software\Classes\oct`). Nothing touches `/etc/`, `/usr/`, or
`HKLM\`. Every action is reversible by the matching uninstall script.

## Optional: `oct-curl` shim

For shell users who want `oct://` to work from `curl`-style pipelines
without typing the portal `/raw` + token dance every time. Not
installed automatically.

- `dist/macos/oct-curl` — bash; pure POSIX + `jq` (falls back to
  `sed` if `jq` is absent).
- `dist/linux/oct-curl` — identical to the macOS copy.
- `dist/windows/oct-curl.ps1` — PowerShell shim around `curl.exe`.

Drop wherever your `$PATH` resolves it. Requires `octravpn portal`
running. Override the loopback bind with
`OCTRAVPN_PORTAL=http://127.0.0.1:NNNN`.
