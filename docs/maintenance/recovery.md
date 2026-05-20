# OctraVPN — Disaster recovery runbook

When the node won't boot, a key is lost, a file is corrupt, or the
audit log is screaming. This runbook covers the failure modes that
*aren't* rotations — those go through
[rotation-master.md](rotation-master.md). The cases here are
**irrecoverable** on their own (lost passphrase, lost WG key) or
**recoverable with surgery** (corrupted journal, partial boot).

Each section names: what's actually broken, what state survives,
what state doesn't, and what the operator can do.

If you're in the middle of an incident: skip to
[§Operator daemon won't boot](#operator-daemon-wont-boot) and walk
the boot phases backwards from the last log line.

## Lost wallet passphrase

You sealed `wallet.hex.sealed` with `OCTRAVPN_KEY_PASSPHRASE` and
the passphrase is now gone (forgotten, deleted from the keyring,
the env file was wiped). The sealed envelope is at
`[chain].wallet_secret_path`.

**What survives:**
- The sealed-envelope bytes on disk. The wallet secret is inside,
  encrypted with ChaCha20-Poly1305 under a PBKDF2-HMAC-SHA256 KEK
  (200k iters) derived from the passphrase.
- The on-chain history of the wallet. Anyone can see what the
  wallet did; nobody can sign new txs without the secret.

**What does NOT survive:**
- The wallet itself. The KEK is unrecoverable without the
  passphrase; brute-forcing 200k-iter PBKDF2 over a strong
  passphrase (≥64 bits entropy per
  [`docs/v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage))
  is computationally infeasible.
- Any earnings sitting unclaimed in the wallet. Without the
  secret, you cannot call `claim_earnings` or sweep the balance.

**Special case — unseal to tmpfs first.** The
`unseal-keys` CLI explicitly enforces a memory-volatile filesystem
for the output path (Linux: tmpfs/ramfs/devtmpfs; macOS: under
`/private/tmp`). That means even if you DID know the passphrase,
the unsealed material lives only as long as the tmpfs is mounted.
The intent is: unseal, immediately copy the secret into a new
sealing flow, blow away the tmpfs.

**What the operator can do:**

1. **If the passphrase is gone**: the wallet is unrecoverable.
   Mint a fresh wallet via
   [`v2-operator-key-hygiene.md §2`](../v2-operator-key-hygiene.md#2-generate-a-fresh-wallet),
   accept the loss, redeploy the circle from a new wallet. The
   old wallet's earnings stay on chain forever.
2. **If the passphrase env var is gone but the sealed file remains AND the operator can re-derive the passphrase from a paper backup / KMS / co-signer**: re-set
   `OCTRAVPN_KEY_PASSPHRASE`, restart the daemon (`systemctl
   restart octravpn-node` on Linux; analogues per OS). The daemon
   unseals on boot and resumes.

> The unseal env path is the **only** way to drive the daemon's
> passphrase intake. There is no on-disk fallback, no recovery
> question, no support email that can reset it. The threat model
> explicitly chose this — see
> [`docs/v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage).

## Lost WG static key

Same shape as the wallet. The sealed key is at
`[tunnel].wg_secret_path`; the on-chain `wg_pubkey_hash` was
committed when `register` ran.

**What survives:**
- The sealed bytes (if you have them).
- The on-chain registration of the **pubkey hash**.

**What does NOT survive:**
- The secret key itself. The pubkey hash on chain is a one-way
  function of the public key, which is itself derived from the
  secret. No recovery path.
- The ability to handshake with peers — the WG handshake requires
  the secret to sign the Noise IK init.

**What the operator can do:**

1. **Rotate**: mint a new WG static key, seal under
   `OCTRAVPN_KEY_PASSPHRASE`, point `[tunnel].wg_secret_path` at
   the new sealed file, restart the daemon, re-run
   `octravpn-node register` so the new pubkey hash binds on chain.
2. Existing client sessions break — they had the old pubkey
   pinned, the new pubkey doesn't match. Clients fall back to the
   operator's other endpoints (if listed) or surface a connection
   error.

The runbook is identical to "scheduled hygiene" in
[`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage)
— the difference is only that you have no choice about whether
to rotate.

## Corrupted receipt journal

The receipt journal at `[control].receipt_journal_path` is the
floor against forced-restart double-signing. Its format is:

- 8-byte magic: `OCRJ1\0\0\0`.
- 4-byte record count.
- Per-record: 32-byte session_id, 8-byte seq, 4-byte CRC32 (in v1).

The journal is append-only with per-record checksums. Two failure
modes:

### Torn-tail (clean failure mode)

The daemon was writing a record when power dropped. The on-disk
file ends with a partially-written record whose CRC doesn't match.

**What survives:** every record before the torn tail.
**Daemon behavior:** `ReceiptJournal::open` detects torn-tail
specifically and truncates back to the last good record. The
daemon boots cleanly and continues. No operator action needed.

### CRC fail on a middle record (unsalvageable shape)

A bit flip in the middle of the file. CRC32 catches it; the
journal is unparseable from the corrupt record onward.

**What survives:**
- Records before the corrupt one (in memory if the daemon was
  running; on disk if you can read past the corrupt record
  manually — but the public `open()` API refuses).

**What does NOT survive cleanly:**
- The journal as a whole. There is no "skip bad record" mode.

**What the operator can do:**

1. **Stop the daemon.** The current process holds the journal
   open; if it's running, you can't safely truncate.
2. **Back up the corrupt file** for forensic analysis:
   ```sh
   sudo systemctl stop octravpn-node
   sudo cp /var/lib/octravpn/receipts.bin \
           /var/lib/octravpn/receipts.bin.corrupt.$(date +%s)
   ```
3. **Rebuild from the audit log.** Every `receipt_signed` row in
   the audit log carries a `(session_id, seq)` pair. Reconstruct
   the per-session max-seq from the audit log; that's the floor.
   ```sh
   octravpn-node audit replay \
       --audit-path /var/lib/octravpn/audit/ \
       --format json \
   | jq -c 'select(.kind == "receipt_signed") | {sid: .session_id, seq: .seq}' \
   | sort -u
   ```
   Use the per-session max as the floor to rebuild a clean
   `receipts.bin`. This currently requires hand-writing the
   binary file in the format above — there is no shipped CLI
   for "rebuild journal from audit". <!-- UNVERIFIED — no such
   CLI exists on the current binary; the audit-replay output is
   the input you'd feed to a manual rebuild. -->
4. **Worst case**: delete the journal and accept the rollback
   risk. The daemon recreates an empty journal at boot. Any
   session whose floor was the truncated/lost record can be
   double-signed in principle — the operator MUST submit the
   same `bytes_used` for any subsequent `settle_claim`, or
   equivocation slashing fires. The audit log is the only
   source of "what bytes_used did I last sign for this
   session"; cross-reference before acting.

> The journal's job is to defend against the operator's OWN
> daemon getting double-signed; the chain-side equivocation
> check is the load-bearing defense, not the journal. The
> journal makes the equivocation impossible on the happy path;
> if it's gone, the equivocation is still detectable on chain.
> Lose-the-journal is not lose-the-bond.

## Operator daemon won't boot

The most common incident shape. Walk the boot sequence phase by
phase; the daemon names each phase in its log output, so the
"last log line" tells you where to look.

### Phase 1 — Chain context load

The daemon resolves the chain RPC endpoint, loads
`[chain].pinned_root_paths`, opens an RPC client.

**Failure shapes:**
- "RPC endpoint unreachable" → network issue, or chain
  endpoint operator changed the URL. Verify with `curl
  https://<rpc>/?method=node_status`. If the endpoint moved,
  update `[chain].rpc_url` in `node.toml`.
- "TLS handshake failed: certificate signed by unknown
  authority" → the chain operator rotated their CA, your
  pinned bundle is stale. Get the new bundle from their
  announcement channel, drop it at the `pinned_root_paths`
  location, restart. See
  [`tls-rotation.md §Chain RPC roots`](../operators/tls-rotation.md#chain-rpc-roots).
- "RPC body too large" → devnet-only, 1 MiB cap on POST
  bodies (memory note `octra_devnet_rpc_body_cap.md`). Affects
  PVAC pubkey registration (~4 MB). Use mainnet for production.

### Phase 2 — Sealed keys unlock

The daemon reads `[chain].wallet_secret_path` and
`[tunnel].wg_secret_path`, unseals each with
`OCTRAVPN_KEY_PASSPHRASE`.

**Failure shapes:**
- "missing passphrase: OCTRAVPN_KEY_PASSPHRASE unset" → env
  var didn't reach the daemon. On Linux check the
  `EnvironmentFile=` drop-in; on macOS check the launchd plist;
  on Windows check the service env config.
- "wrong passphrase: AEAD authentication failed" → passphrase
  is wrong. See [§Lost wallet passphrase](#lost-wallet-passphrase)
  if the original is unrecoverable.
- "require_sealed_keys = true but file is plaintext" →
  config strict-mode enabled but the key file is still raw
  hex. Run `octravpn-node seal-keys` to wrap, then re-point
  the path at `<original>.sealed`. See
  [`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#cross-platform-the-octravpn-node-seal-keys-subcommand-recommended).

### Phase 3 — Audit dir open

The daemon opens `[control].audit_dir`, ensures the dir exists +
the HMAC key is present (creates it on first boot, mode 0600).

**Failure shapes:**
- "permission denied creating .audit.key" → the audit dir
  exists but the daemon user (`octravpn` on Linux, root on
  macOS) can't write. Check ownership: `ls -la
  /var/lib/octravpn/audit/`. Fix: `chown -R octravpn:octravpn
  /var/lib/octravpn/audit/`.
- "audit log MAC chain broken at boot" → the daemon
  pre-verifies before appending; if a prior day's file is
  broken, it refuses to start (refusing-to-extend is the
  conservative choice). Repair per
  [audit-verify.md §Recovering from a chain break](audit-verify.md#recovering-from-a-chain-break).

### Phase 4 — Receipt journal open

The daemon calls
`octravpn_core::receipt_journal::ReceiptJournal::open`.

**Failure shapes:**
- "bad magic" → file at the path is not a journal (wrong
  path, or a stray file). Move it aside, restart.
- "CRC fail at record N" → see [§Corrupted receipt journal](#corrupted-receipt-journal).
- "journal locked by another process" → a previous daemon
  crashed without releasing the lock. Kill any stale
  `octravpn-node` process; the journal opens a process-local
  advisory lock that releases on exit.

### Phase 5 — Control plane bind

The daemon binds the HTTPS listener (`mesh serve --https-listen`)
and the plain-HTTP listener (`--listen`).

**Failure shapes:**
- "address already in use" → another process holds the port,
  or a previous daemon didn't release. Check with `ss -ltnp |
  grep 51821`. Kill the stale process; restart.
- "permission denied: bind to :443" → on Linux the daemon
  needs `CAP_NET_BIND_SERVICE`. The shipped package's postinst
  `setcap`s this; a manual binary install doesn't. Apply with
  `sudo setcap 'cap_net_admin,cap_net_bind_service=ep'
  /usr/local/bin/octravpn-node`.
- "TLS cert load failed: private key does not match public
  key" → partial cert swap (cert from one mint, key from
  another). Restore from
  `${state_dir}/tls/backup/<latest>` and re-run
  `rotate-tls.sh`. See
  [`tls-rotation.md §Failure modes`](../operators/tls-rotation.md#failure-modes-and-recovery).

### Phase 6 — Tunnel up

The daemon opens the TUN device, configures the WG peer, and
brings the data plane online.

**Failure shapes:**
- "could not open /dev/net/tun" → on Linux the daemon needs
  `CAP_NET_ADMIN`. Same fix as Phase 5's bind perm.
- "wintun: device not found" (Windows) → WinTUN driver not
  installed or version mismatch. See
  [`upgrades-windows.md §WinTUN driver compatibility`](upgrades-windows.md#wintun-driver-compatibility).
- "utun: operation not permitted" (macOS) → launchd plist
  isn't running as root. Verify `UserName=root` in
  `/Library/LaunchDaemons/com.octravpn.node.plist`.

## Common recovery mistakes

1. **Restoring the wallet from a passphrase-less backup.** If you
   backed up `wallet.hex.sealed` to off-site storage and the
   passphrase to a *different* off-site, then lose access to one
   of them, the wallet is gone. Treat the backup pair as
   inseparable.
2. **Deleting the receipt journal "to fix a boot crash".** A
   missing journal lets the daemon boot, BUT means the operator
   has no local floor against forced-restart double-signing. The
   chain-side equivocation check fires; the bond is slashed.
   Always rebuild via §Corrupted receipt journal before
   considering deletion.
3. **Running `audit verify` against a partially-restored audit
   dir.** If you restored some JSONL files from backup but not
   the `.audit.key`, every line fails MAC. Always restore the
   key alongside the JSONL files; the key is the chain anchor.

## References

- [Audit verify](audit-verify.md) — the recurring verification
  runbook + chain-break recovery flow.
- [Rotation master](rotation-master.md) — when the recovery
  path is rotation rather than restoration.
- [Sealed-keys hygiene](../v2-operator-key-hygiene.md) — the
  sealed-envelope format and passphrase resolution order.
- [TLS rotation](../operators/tls-rotation.md) — for control-plane
  cert failures during Phase 5.
- [Linux upgrade runbook](upgrades-linux.md) — the pre-flight
  checks here are exactly the recovery surface.
- [Known limitations](../audit/known-limitations.md) — the
  audited-known caveats (attest.timer, fhe_load_pk, etc.).
