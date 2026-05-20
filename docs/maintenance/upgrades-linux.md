# OctraVPN — Linux upgrade runbook

In-place upgrade of `octravpn-node` on a Linux host running the
shipped `.deb` / `.rpm` package + systemd unit. Same schema, same
program, same circle — for *retired* major releases (v1, v2) jump
to [§Major-version migrations](#major-version-migrations).

The upgrade has four phases: **pre-flight**, **stop**, **install**,
**verify**. Each phase is reversible up to the stop. After the new
binary boots and `audit verify` is clean, the previous package can
be deleted.

> Audit chain integrity is the load-bearing invariant across an
> upgrade: a clean chain before AND after the swap is the
> only evidence that no records were lost or rewritten by an
> install-time crash. Do not skip the pre-flight verify.

## 0. Background

The release pipeline lives at
[`.github/workflows/release.yml`](../../.github/workflows/release.yml)
and the package metadata is in
[`crates/octravpn-node/Cargo.toml`](../../crates/octravpn-node/Cargo.toml).
Each tagged release publishes per-architecture artifacts:

| Distro | Artifact |
|---|---|
| Debian / Ubuntu | `octravpn-node_<version>-1_<arch>.deb` |
| Fedora / RHEL / Rocky / Alma | `octravpn-node-<version>-1.<arch>.rpm` |
| Any (manual install) | `octravpn-<version>-<target>.tar.gz` |

All three carry detached `.sig` signatures plus a consolidated
`SHA256SUMS` line set (see [`docs/release.md`](../release.md) §2).

The `postinst` / `post_install_script` hook creates the `octravpn`
system user, lays out `/etc/octravpn` (0750), `/var/lib/octravpn`
(0700), `/var/log/octravpn` (0750), `setcap`s `CAP_NET_ADMIN +
CAP_NET_BIND_SERVICE` onto the binary, and `systemctl enable`s the
unit *without* starting it. **An in-place upgrade preserves the
existing config + state**; the postinst is idempotent in that regard.

## 1. Pre-flight (on the OLD binary)

Run these four checks **before** stopping the daemon. They all
exercise the currently-running version, so a failure here is an
"abort the upgrade" signal.

### 1.1 Config validates

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
    --config /etc/octravpn/node.toml \
    config validate
```

Exit 0 means schema parses, keys load, RPC reaches the chain, the
program responds. Non-zero blocks the upgrade — fix the surfaced
failure first.

### 1.2 Audit chain is clean

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
    --config /etc/octravpn/node.toml \
    audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin
```

This must exit 0. Non-zero exits mean either tampering, disk
corruption, or a partial write — see [audit-verify.md](audit-verify.md)
§Recovering from a chain break before continuing.

### 1.3 Health probe (chain + local files + daemon HTTP)

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
    --config /etc/octravpn/node.toml \
    health \
    --remote http://localhost:51821
```

Confirms the daemon is alive *now* and the chain reads correspond.
Capture this output — you will compare it against the post-upgrade
run.

### 1.4 Note the current version

```sh
/usr/local/bin/octravpn-node --version
```

The output is `octravpn-node <semver>`. Keep this for the rollback
step.

## 2. Stop the daemon

```sh
sudo systemctl stop octravpn-node.service
sudo systemctl status octravpn-node.service     # confirm inactive
```

Open sessions terminate cleanly: the daemon flushes the audit log
and closes the receipt journal on `SIGTERM`. There is no graceful
"drain new sessions only" mode; if you need that, set
`accept_new_sessions = false` in the circle policy first (see
[rotation-master.md §Coordinated rotations](rotation-master.md#coordinated-rotations))
and wait for active sessions to settle before stopping.

## 3. Install the new package

### 3.1 .deb (Debian / Ubuntu)

```sh
ARCH=$(dpkg --print-architecture)
VERSION=<new-version>
BASE=https://github.com/octra-labs/octravpn/releases/download/v${VERSION}

curl -fsSL ${BASE}/octravpn-node_${VERSION}-1_${ARCH}.deb     -o /tmp/octravpn-node.deb
curl -fsSL ${BASE}/octravpn-node_${VERSION}-1_${ARCH}.deb.sig -o /tmp/octravpn-node.deb.sig

# Verify before installing — the signing key was imported on first
# install per `docs/operators/mainnet-deployment.md §1.1`.
gpg --verify /tmp/octravpn-node.deb.sig /tmp/octravpn-node.deb

# Keep the previous package on disk so step 5 can roll back.
sudo cp /var/cache/apt/archives/octravpn-node_*.deb /var/cache/apt/archives/octravpn-node.previous.deb

sudo dpkg -i /tmp/octravpn-node.deb
```

### 3.2 .rpm (Fedora / RHEL / Rocky / Alma)

```sh
sudo rpm -Uvh octravpn-node-<version>-1.<arch>.rpm
```

`rpm -U` upgrades in place and runs the postinst. The previous
RPM stays in `/var/cache/dnf/` (Fedora) or `/var/cache/yum/` (RHEL)
until cleaned — useful for step 5.

## 4. Post-install verification

### 4.1 Schema still validates against the new binary

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
    --config /etc/octravpn/node.toml \
    config validate
```

This is the **schema-break canary**. If the new binary added a
required field or renamed one, `config validate` exits 1 here and
the daemon will not boot. Fix `node.toml` per the release notes
*before* starting the service.

### 4.2 Start the service

```sh
sudo systemctl start octravpn-node.service
sudo systemctl status octravpn-node.service
journalctl -u octravpn-node.service -e --no-pager -n 50
```

The boot log walks (in order): chain context load → sealed keys
unlock → audit dir open → receipt journal open → control plane bind
→ tunnel up. Each phase is named in the log; if boot wedges, the
phase the daemon was in is the failure point — see
[recovery.md §Operator daemon won't boot](recovery.md#operator-daemon-wont-boot).

### 4.3 Health probe (same as §1.3, expect identical chain state)

```sh
sudo -u octravpn /usr/local/bin/octravpn-node health \
    --remote http://localhost:51821
```

Compare against the pre-upgrade capture from §1.3. Stake / slashed /
unbonding state must be identical. Local-file checks (`audit log`
openable, `receipt journal` openable) must all be `OK`.

### 4.4 Audit chain still clean

```sh
sudo -u octravpn /usr/local/bin/octravpn-node \
    audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin
```

Must exit 0. A chain break introduced by the upgrade is a
high-severity bug — capture `journalctl -u octravpn-node` since the
stop and file an issue tagged `upgrade audit-break`.

### 4.5 Version reflects the new binary

```sh
/usr/local/bin/octravpn-node --version
```

Should print the new semver.

## 5. Rolling back

If §4 fails, roll back to the previous package. The state on disk
(audit log, receipt journal, sealed keys, `node.toml`) is forward
compatible — same schema — so the old binary boots cleanly against
the post-upgrade state.

### 5.1 .deb rollback

```sh
sudo systemctl stop octravpn-node.service
sudo dpkg -i /var/cache/apt/archives/octravpn-node.previous.deb
sudo systemctl start octravpn-node.service
```

### 5.2 .rpm rollback

```sh
sudo systemctl stop octravpn-node.service
sudo dnf downgrade octravpn-node    # uses the cached prior version
sudo systemctl start octravpn-node.service
```

(On older RHEL: `sudo yum downgrade octravpn-node`.)

### 5.3 Re-pinning a known-good version

To prevent unattended upgrades from re-rolling you forward:

```sh
# Debian / Ubuntu
sudo apt-mark hold octravpn-node

# Fedora / RHEL
sudo dnf versionlock add octravpn-node    # if versionlock plugin installed
```

Remove the hold with `apt-mark unhold` / `dnf versionlock delete`
once the upstream fix lands.

## Major-version migrations

In-place upgrades work within a major release line (`v0.1.x` →
`v0.1.y`, `v1.x.y` → `v1.x.z`). **They do NOT work across major
program versions.**

The history so far:

- **v1 → v2** was a redeploy: new circle id, new program address,
  new node config. The v1 circles + program contracts are
  effectively retired; no in-place path exists.
- **v2 → v3** was the same shape: v3 uses a different program
  (`program/main-v3.aml` vs `program/main-v2.aml`), a different
  on-chain data layout (flat maps, no struct types — see
  [`docs/v3/v3-vs-v2.md`](../v3/v3-vs-v2.md)), and a different
  circle. An operator running v2 must (a) deploy a v3 circle from
  scratch, (b) drain the v2 circle, (c) update `node.toml` to point
  at the new program + circle, (d) re-bond + re-register against
  v3.

[`docs/v3/v3-vs-v2.md`](../v3/v3-vs-v2.md) has the per-entrypoint
delta and the per-data-type delta. Read it before starting a v2 → v3
migration — every entrypoint changed name, shape, or default.

> No clean **down**grade across major versions. v3 receipts cannot
> be settled against a v2 program; sessions opened under v3 are
> not visible to v2 binaries.

## Per-systemd-target tweaks

### `octravpn-attest.timer` (known no-op)

The package ships
[`deploy/systemd/octravpn-attest.timer`](../../deploy/systemd/octravpn-attest.timer)
and
[`deploy/systemd/octravpn-attest.service`](../../deploy/systemd/octravpn-attest.service)
which call `octravpn-node attest`. That subcommand **does not
exist on the current binary** — see
[`docs/audit/known-limitations.md`](../audit/known-limitations.md)
for the long-form. The timer is harmless (it fires, the oneshot
fails, journald logs the failure) but **the load-bearing
attestation refresh is the daemon's in-process loop, not the
timer**.

Working-loop replacement (no operator action needed in normal
operation):

- The long-running `octravpn-node run` service has an in-process
  attestation refresh that fires on the same cadence the timer was
  meant to. As long as `octravpn-node.service` is `active
  (running)`, attestations stay fresh.
- If you choose to silence the timer, mask it:
  ```sh
  sudo systemctl mask octravpn-attest.timer
  ```
  Do NOT also mask `octravpn-node.service` — the in-process refresh
  lives there.
- If a future release ships `octravpn-node attest`, unmask the
  timer + re-enable it: `sudo systemctl unmask octravpn-attest.timer
  && sudo systemctl enable --now octravpn-attest.timer`.

### `octravpn-node.service` runtime hardening

The shipped unit
[`deploy/systemd/octravpn-node.service`](../../deploy/systemd/octravpn-node.service)
runs with `NoNewPrivileges`, `ProtectSystem=strict`,
`MemoryDenyWriteExecute`, and the bounding set restricted to
`CAP_NET_ADMIN + CAP_NET_BIND_SERVICE`. Do not relax these to
"make a flag work" — if a new binary needs more, the *release notes*
will say so and we will ship an updated unit. Operator overrides
belong in `/etc/systemd/system/octravpn-node.service.d/*.conf`
drop-ins, not in edits to the shipped file (which the package
manager will overwrite at the next install).

A common safe override is environment loading:

```ini
# /etc/systemd/system/octravpn-node.service.d/passphrase.conf
[Service]
EnvironmentFile=/etc/octravpn/keys.env
```

with `/etc/octravpn/keys.env` chmod 0600 carrying
`OCTRAVPN_KEY_PASSPHRASE=<paste>`. See
[`docs/v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage)
for the full sealed-keys flow.

## Common upgrade mistakes

These are the three failure modes observed most often during pre-v0.1
upgrades. None of them surface a clean error message; each one
manifests as "the daemon won't start" or "settle is failing" and
chews half a day. The pre-flight checks above catch each one *if
you run them*.

1. **Schema break missed because `config validate` was skipped after
   install.** A new required field in `node.toml` means
   `Hub::new` panics during boot, *after* the audit dir is touched,
   leaving stale lockfiles. Always run §4.1 before §4.2.
2. **Sealed-keys passphrase not in the new service environment.**
   If you re-installed the systemd unit (postinst doesn't, but
   manual `cp deploy/systemd/octravpn-node.service` does), the
   `EnvironmentFile=` drop-in disappears and the daemon fails
   sealed-key unseal at boot. The error names
   `OCTRAVPN_KEY_PASSPHRASE` explicitly; reinstate the drop-in.
3. **Audit chain break introduced by an unclean stop.** A `kill -9`
   or OOM during the *previous* daemon's lifetime can leave a
   torn-tail line in the audit log. `audit verify` catches this
   pre-upgrade — but if you skip §1.2 you only learn after §4.4,
   by which point the new binary has appended its own lines and
   you can't tell whose stop wrote the bad line. Always verify
   before AND after.

## References

- [Release runbook](../release.md) — how the artifacts are produced.
- [Mainnet deployment runbook](../operators/mainnet-deployment.md) —
  first-install path.
- [Rotation master](rotation-master.md) — when key rotation needs
  to interleave with an upgrade.
- [Audit verify](audit-verify.md) — the recurring "chain clean?"
  cron + recovery on a break.
- [v3 vs v2 delta](../v3/v3-vs-v2.md) — for major-version migrations.
- [Known limitations](../audit/known-limitations.md) —
  `octravpn-attest.timer` and other audit-flagged caveats.
