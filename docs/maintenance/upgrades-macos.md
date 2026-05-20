# OctraVPN — macOS upgrade runbook

In-place upgrade of `octravpn-node` on a macOS host running under
`launchd`. The shipped service uses
[`deploy/launchd/com.octravpn.node.plist`](../../deploy/launchd/com.octravpn.node.plist)
which runs the daemon as root (utun needs it) and reads config from
`/usr/local/etc/octravpn/node.toml`.

Two install paths are supported today; pick the one you originally
used and stay on it:

1. **Homebrew** — `brew install octravpn-node` (when the tap ships
   the formula). Upgrade with `brew upgrade octravpn-node`.
2. **Manual tarball / .pkg** — download from the GitHub Releases
   page, swap binaries, reload launchd.

Cross-major migrations (v1 → v2 → v3) follow the same redeploy path
as Linux — see
[`upgrades-linux.md §Major-version migrations`](upgrades-linux.md#major-version-migrations).

## 0. Background

> macOS artifacts are not currently produced by the
> [`docs/release.md`](../release.md) CI lane (it's Linux-only). The
> Homebrew + .pkg paths below are operator-supported only — the
> formula skeleton at `deploy/homebrew/` is a starting point, not
> a published tap. <!-- UNVERIFIED -->

The state-on-disk layout differs from Linux:

| Surface | macOS path |
|---|---|
| Binary | `/usr/local/bin/octravpn-node` |
| Config | `/usr/local/etc/octravpn/node.toml` |
| State (audit dir, journal, sealed keys) | `/usr/local/var/octravpn/` (operator-chosen — set in `node.toml`) |
| Service unit | `/Library/LaunchDaemons/com.octravpn.node.plist` |
| Stdout / stderr logs | `/usr/local/var/log/octravpn-node.out.log` / `.err.log` |

The same `node.toml` shape works on macOS as on Linux; only the
absolute paths in `[control].audit_dir`, `[control].receipt_journal_path`,
`[chain].wallet_secret_path`, `[tunnel].wg_secret_path` differ.

## 1. Pre-flight checks (on the OLD binary)

Same four checks as Linux — see
[`upgrades-linux.md §1`](upgrades-linux.md#1-pre-flight-on-the-old-binary).
Run them as root (launchd-launched daemon runs as root; the files it
writes are root-owned):

```sh
sudo /usr/local/bin/octravpn-node \
    --config /usr/local/etc/octravpn/node.toml \
    config validate

sudo /usr/local/bin/octravpn-node \
    --config /usr/local/etc/octravpn/node.toml \
    audit verify \
    --audit-path /usr/local/var/octravpn/audit/ \
    --journal-path /usr/local/var/octravpn/receipts.bin

sudo /usr/local/bin/octravpn-node \
    --config /usr/local/etc/octravpn/node.toml \
    health \
    --remote http://localhost:51821

/usr/local/bin/octravpn-node --version
```

Each must exit 0 before continuing. Audit chain non-zero is the
high-stakes one — see [audit-verify.md](audit-verify.md) before
proceeding.

## 2. Stop the daemon

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.octravpn.node.plist
# Confirm:
sudo launchctl print system/com.octravpn.node 2>&1 | head -5
```

`bootout` removes the daemon from the launchd graph and stops it; an
equivalent `unload` form (deprecated but still works) is `sudo
launchctl unload /Library/LaunchDaemons/com.octravpn.node.plist`.

Verify the process is gone:

```sh
pgrep -fl octravpn-node
# (no output = stopped)
```

## 3. Install the new version

### 3.1 Homebrew (when the tap is published)

```sh
brew update
brew upgrade octravpn-node
```

Brew handles the binary swap atomically (downloads to a staging dir,
flips the `/usr/local/Cellar/` symlink). The launchd plist is left
in place — Homebrew installs the formula's plist to
`/usr/local/opt/octravpn-node/*.plist` but the load-bearing copy is
the system one at `/Library/LaunchDaemons/com.octravpn.node.plist`.
**Do not let brew overwrite the system plist** — your custom
EnvironmentVariables (`OCTRAVPN_KEY_PASSPHRASE`) live there.

> The published formula path is not finalized. If `brew upgrade`
> tries to relink the system plist, abort with
> `brew unlink octravpn-node && brew link --overwrite octravpn-node`
> AFTER you have backed the system plist up. <!-- UNVERIFIED -->

### 3.2 Manual tarball swap

```sh
VERSION=<new-version>
TARGET=x86_64-apple-darwin   # or aarch64-apple-darwin
BASE=https://github.com/octra-labs/octravpn/releases/download/v${VERSION}

curl -fsSL ${BASE}/octravpn-${VERSION}-${TARGET}.tar.gz     -o /tmp/octravpn.tar.gz
curl -fsSL ${BASE}/octravpn-${VERSION}-${TARGET}.tar.gz.sig -o /tmp/octravpn.tar.gz.sig

# Verify with minisign if you have the public key wired up.
minisign -V -p ~/.minisign/octravpn.pub \
    -m /tmp/octravpn.tar.gz -x /tmp/octravpn.tar.gz.sig

# Stash the previous binary for rollback.
sudo cp /usr/local/bin/octravpn-node /usr/local/bin/octravpn-node.previous

# Extract + swap.
tar -tzf /tmp/octravpn.tar.gz   # sanity-check the contents first
sudo tar -xzf /tmp/octravpn.tar.gz -C /usr/local/bin \
    --include='octravpn-node' --strip-components=1
sudo chmod 0755 /usr/local/bin/octravpn-node
```

> macOS Gatekeeper will quarantine binaries downloaded via `curl`.
> If launchd refuses to start the new binary with
> `posix_spawn: Operation not permitted`, clear the quarantine bit:
> ```sh
> sudo xattr -d com.apple.quarantine /usr/local/bin/octravpn-node
> ```
> Signed + notarized .pkg installs (when shipped) do not have this
> issue. <!-- UNVERIFIED for current release -->

## 4. Post-install verification

### 4.1 Schema validates against the new binary

```sh
sudo /usr/local/bin/octravpn-node \
    --config /usr/local/etc/octravpn/node.toml \
    config validate
```

Same schema-break canary as Linux.

### 4.2 Reload launchd

```sh
sudo launchctl bootstrap system /Library/LaunchDaemons/com.octravpn.node.plist
# Confirm:
sudo launchctl print system/com.octravpn.node | head -20
```

If you ever see "Service already loaded" reload as
`bootout` + `bootstrap`:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.octravpn.node.plist
sudo launchctl bootstrap system /Library/LaunchDaemons/com.octravpn.node.plist
```

### 4.3 Confirm it's actually running

```sh
# launchd-reported state:
sudo launchctl print system/com.octravpn.node | grep -E "state|last exit"

# Process visible in Activity Monitor — or, in the shell:
pgrep -fl octravpn-node

# Stdout log carries the boot phases — chain ctx, sealed keys, audit
# dir, receipt journal, control plane, tunnel.
tail -n 100 /usr/local/var/log/octravpn-node.out.log
tail -n 50  /usr/local/var/log/octravpn-node.err.log
```

If the daemon flaps (KeepAlive=true means launchd restarts it on
exit; the `last exit` field on `launchctl print` shows the most
recent non-zero), check `octravpn-node.err.log` for the boot-phase
the daemon was in. See [recovery.md](recovery.md) for phase-by-phase
diagnostics.

### 4.4 Audit chain still clean

```sh
sudo /usr/local/bin/octravpn-node \
    audit verify \
    --audit-path /usr/local/var/octravpn/audit/ \
    --journal-path /usr/local/var/octravpn/receipts.bin
```

Exit 0 expected.

### 4.5 Version

```sh
/usr/local/bin/octravpn-node --version
```

## 5. Sealed-keys + the macOS Keychain

The daemon's sealed-key envelope (wallet + WG static) decrypts at
boot via `OCTRAVPN_KEY_PASSPHRASE`. On Linux that comes from an
`EnvironmentFile=` drop-in; on macOS the source-of-truth is the
launchd plist's `EnvironmentVariables` dict OR a Keychain entry the
launchd plist reads via a wrapper script.

### 5.1 Plist-embedded (simplest, less secure)

Edit `/Library/LaunchDaemons/com.octravpn.node.plist`:

```xml
<key>EnvironmentVariables</key>
<dict>
    <key>RUST_LOG</key>
    <string>info</string>
    <key>OCTRAVPN_KEY_PASSPHRASE</key>
    <string>...paste here, chmod the plist to 0600...</string>
</dict>
```

Then `chmod 0600 /Library/LaunchDaemons/com.octravpn.node.plist` so
non-root users can't read the passphrase via `cat`. The plist is
otherwise root-readable by default.

### 5.2 Keychain-backed (recommended)

Stash the passphrase in the system keychain once:

```sh
sudo security add-generic-password \
    -a octravpn -s octravpn-key-passphrase \
    -T /usr/local/bin/octravpn-node \
    -w 'paste-the-passphrase-here'
```

Then wrap the daemon launch so launchd executes:

```sh
#!/bin/sh
# /usr/local/libexec/octravpn-node-launch.sh
export OCTRAVPN_KEY_PASSPHRASE=$(security find-generic-password \
    -a octravpn -s octravpn-key-passphrase -w)
exec /usr/local/bin/octravpn-node --config /usr/local/etc/octravpn/node.toml run
```

Update the plist's `ProgramArguments` to point at the wrapper.
Keychain ACLs (`-T <binary>`) restrict who can read; the binary is
the only authorized caller. `security` writes to the system keychain
when run as root.

> Keychain integration requires the operator to manually edit the
> shipped plist + create the wrapper script. The release artifacts
> do not ship the wrapper. <!-- UNVERIFIED -->

## 6. Rolling back

If §4 fails, restore the previous binary:

```sh
sudo launchctl bootout system /Library/LaunchDaemons/com.octravpn.node.plist
sudo mv /usr/local/bin/octravpn-node.previous /usr/local/bin/octravpn-node
sudo launchctl bootstrap system /Library/LaunchDaemons/com.octravpn.node.plist
```

For a Homebrew install:

```sh
brew uninstall octravpn-node
brew install octravpn-node@<previous-version>    # if the formula exposes pinned versions
```

> `brew install foo@version` only works when the formula explicitly
> publishes the older version. If the tap doesn't, you have to fall
> back to the manual tarball flow. <!-- UNVERIFIED -->

## 7. Verifying via Activity Monitor

For operators who want a GUI cross-check:

1. Open **Activity Monitor** (Cmd+Space → "Activity Monitor").
2. Filter on `octravpn-node`. The process should be present, running
   as **root**, and not flapping (PID stable for >60 seconds).
3. CPU should idle <5% on a quiet network; brief spikes during a
   policy poll or settle are normal.

If the process keeps respawning under a new PID, launchd's KeepAlive
is restarting it after a crash. Stop the GUI inspection and read
`/usr/local/var/log/octravpn-node.err.log` for the crash reason.

## 8. Common macOS-specific upgrade mistakes

1. **Quarantine bit blocks the new binary.** `curl`-downloaded
   tarballs land with `com.apple.quarantine` set. launchd refuses
   to exec quarantined binaries. Surfaced as `posix_spawn:
   Operation not permitted` in `octravpn-node.err.log`. Fix with
   `sudo xattr -d com.apple.quarantine /usr/local/bin/octravpn-node`.
2. **Brew overwrote the system plist.** When the formula relinks,
   it may overwrite `/Library/LaunchDaemons/com.octravpn.node.plist`
   if `--overwrite` was passed, wiping out custom
   `EnvironmentVariables`. Always back the plist up before
   `brew upgrade`. <!-- UNVERIFIED for production formula -->
3. **utun not granted.** A re-installed binary loses its
   network-extension entitlement on the first launch; the daemon
   boots fine but `tunnel up` fails. macOS surfaces this as a
   prompt the first time; if the prompt was dismissed, re-grant
   via System Settings → Privacy & Security → Network Extensions.
   <!-- UNVERIFIED — depends on whether the build is notarized + signed -->

## References

- [Linux upgrade runbook](upgrades-linux.md) — analogous flow with
  more detail on the pre-flight + post-flight checks.
- [Sealed key hygiene](../v2-operator-key-hygiene.md) — passphrase
  storage patterns per OS.
- [Recovery runbook](recovery.md) — when boot wedges, walk the
  phases here.
- [Install guide](../install.md) — first-time install for macOS.
- [launchd plist source](../../deploy/launchd/com.octravpn.node.plist).
