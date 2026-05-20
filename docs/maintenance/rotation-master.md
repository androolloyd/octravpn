# OctraVPN — Rotation master runbook

The unified decision tree + ordering contract across every key,
secret, and cert an OctraVPN operator rotates. This document is the
**entry point**; the per-key procedures live in three pre-existing
runbooks under [`docs/operators/`](../operators/) and the dedicated
sealed-keys section of
[`docs/v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md).
This doc does NOT duplicate those — it links to them.

If you have time to read three sentences, read these:

1. Rotation order matters: **PVAC → TLS → sealed-policy**, so a
   client never sees a TLS swap before it knows about the PVAC swap
   that needs it.
2. Every rotation MUST appear as a discrete event in the audit log
   (`audit-YYYY-MM-DD.jsonl`) so a post-mortem can reconstruct
   exactly when each key changed.
3. The PVAC rotation has a 24h **dual-decrypt window** during which
   the old secret stays warm — do not archive it before T+24h, do
   not skip the window even if you think no traffic is in flight.

## Decision tree — when to rotate which

The four scheduled rotations and their compromise-triggered
counterparts. Pick the row that matches the trigger you actually
saw; each row links to the runbook step you execute.

### Wallet key (the bond-stake-signing keypair)

| Trigger | Action | Runbook |
|---|---|---|
| Suspected compromise (sealed envelope leak + passphrase leak, or wallet.hex.sealed copied off-host) | Rotate to a fresh wallet, sweep the old wallet's claimable earnings, retire the circle if the address is also the deployer | [`v2-operator-key-hygiene.md §2-§3`](../v2-operator-key-hygiene.md#2-generate-a-fresh-wallet) |
| Quarterly hygiene (every 90 days) | Mint a fresh wallet, seal under a new passphrase, swap the `[chain].wallet_secret_path` to the new sealed file, restart the daemon | [`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage) — same flow, wallet path |
| Operator role hand-off (new human) | Same as quarterly; the passphrase is rotated alongside the wallet | [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence) |

> The wallet key is sealed via `octravpn_core::wallet_enc`. Once
> sealed, the only loss path is "passphrase forgotten". See
> [recovery.md §Lost wallet passphrase](recovery.md#lost-wallet-passphrase)
> for the (limited) recovery.

### WG static key (the WireGuard data-plane identity)

| Trigger | Action | Runbook |
|---|---|---|
| Suspected compromise (host backup leak with sealed wg.key.sealed + passphrase) | Rotate; the WG pubkey hash is bound on chain via the operator-circle endpoint registration; rotation requires re-registering | [`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage) |
| Annual hygiene (every 365 days) | Mint new, seal, swap, restart | [`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage) |
| Switching to AmneziaWG params | New static key required; same flow | [`v2-operator-key-hygiene.md §4`](../v2-operator-key-hygiene.md#4-wg-static-key-storage) |

> The on-chain `wg_pubkey_hash` is committed when you ran
> `register` (`octravpn-node register`). Rotation = re-running
> `register` with the new sealed key so the on-chain hash matches
> the new on-disk material.

### PVAC pubkey (the lattice keypair that gates encrypted receipts)

| Trigger | Action | Runbook |
|---|---|---|
| Suspected secret-key compromise | Drain new sessions → mint + seal → broadcast `octra_registerPvacPubkey` → 24h dual-decrypt → archive old SK | [`pvac-rotation.md §When to rotate (1)`](../operators/pvac-rotation.md#when-to-rotate) + the rotation procedure §Step 1-5 |
| Lattice parameter upgrade (sidecar bumps `pvac_default_params`) | Same drain-mint-swap, keep old sidecar binary on disk under a versioned path through the 24h window | [`pvac-rotation.md §When to rotate (2)`](../operators/pvac-rotation.md#when-to-rotate) |
| Adding / re-keying a region (multi-region operator) | Per-region rotation against per-region wallet; no shared key | [`pvac-rotation.md §When to rotate (3)`](../operators/pvac-rotation.md#when-to-rotate) |
| Scheduled hygiene (every 180 days) | Drain + mint + swap + 24h window | [`pvac-rotation.md §Rotation procedure`](../operators/pvac-rotation.md#rotation-procedure) |

### TLS cert (the `mesh serve` HTTPS listener)

| Trigger | Action | Runbook |
|---|---|---|
| Suspected private-key compromise | Run `rotate-tls.sh --rekey`; publish the new `oct://` URL with the new SPKI fingerprint | [`tls-rotation.md §Recovering from a compromised key`](../operators/tls-rotation.md#recovering-from-a-compromised-key) |
| Scheduled hygiene (every 90 days for self-signed; 30 days for CA-chained) | Run `rotate-tls.sh` (no `--rekey` — preserves the SPKI fingerprint so pinned URLs keep working) | [`tls-rotation.md §Without-downtime rotation`](../operators/tls-rotation.md#without-downtime-rotation-the-common-path) |
| DERP cert expiry approaching | Rotate the DERP material via the harness's `gen-derp-cert.sh` step | [`tls-rotation.md §Calendar`](../operators/tls-rotation.md#calendar) |
| Chain RPC pinned root bundle updated by chain operator | Drop the new PEM in `pinned_root_paths`, restart the daemon | [`tls-rotation.md §Chain RPC roots`](../operators/tls-rotation.md#chain-rpc-roots) |
| Knock PSK suspected leaked or rotated | Rotate the PSK; clients carrying the old one start seeing nginx-404 within one window (~60s) | [`tls-rotation.md §Rotating the PSK`](../operators/tls-rotation.md#rotating-the-psk) |

### Tailnet sealed-policy passphrase (`/policy.json`, `/wg.pub`, `/acl.root`)

| Trigger | Action | Runbook |
|---|---|---|
| Member revoke (`revoke_member` on chain) | Immediately re-encrypt the sealed assets under a new passphrase; redistribute via the same out-of-band channel | [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence) |
| Suspected env-var leak | Same as member revoke; surface ASAP | [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence) |
| Quarterly hygiene (every 90 days) | Re-encrypt + atomic anchor flip via `octravpn-node circle update` | [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence) |

## Coordinated rotations

When more than one rotation needs to happen at the same time (e.g.
quarterly hygiene that lands at the same week as a PVAC parameter
upgrade), order matters. Clients fail closed on a state mismatch;
ordering wrong = mass client errors for the window.

### The PVAC → TLS → sealed-policy ordering

Concrete order of operations when rotating multiple keys at once:

1. **PVAC pubkey first.**
   - Why: the `octra_registerPvacPubkey` registration is a one-shot
     chain write with no overlap window of its own. Doing PVAC first
     puts you into the 24h dual-decrypt phase early; the rest of
     the rotations can complete inside that window.
   - Runbook: [`pvac-rotation.md §Rotation procedure`](../operators/pvac-rotation.md#rotation-procedure).
   - Wait for `octra_pvacPubkey(<wallet>)` to return the new hash
     before continuing.
2. **TLS cert second.**
   - Why: a TLS rotation either preserves the SPKI fingerprint (no
     `--rekey`, no client impact) or changes it (`--rekey`,
     requires a published new `oct://` URL). Doing TLS after PVAC
     lets the new `oct://` URL carry both the new PVAC pubkey hash
     reference AND the new TLS fingerprint atomically — the client
     sees a single coherent update.
   - Runbook: [`tls-rotation.md §Without-downtime rotation`](../operators/tls-rotation.md#without-downtime-rotation-the-common-path).
   - Wait for `/health` to report the new `tls_cert_not_before`
     before continuing.
3. **Sealed-policy passphrase last.**
   - Why: the policy blob in the circle is the layer clients poll
     for "what's the current price, who's an authorized member,
     where do I send receipts." A rotation here flips the
     readability of `/policy.json` for every member who hasn't
     received the new passphrase. Putting it last means the
     out-of-band passphrase distribution has had the longest
     possible head-start.
   - Runbook: [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence).
   - Use `octravpn-node circle update` with the new passphrase via
     `OCTRAVPN_SEALED_PASSPHRASE`.

### The dual-decrypt window (24h after PVAC rotation)

The single most important window in OctraVPN rotation. From PVAC
HFHE-5:

- **T+0**: `octra_registerPvacPubkey` confirms. The chain map now
  returns the new pubkey hash for your wallet. New receipts mint
  ciphertexts under the new pubkey.
- **T+0 to T+24h**: the daemon runs two sidecar instances. The new
  one serves all post-rotation decrypt requests. The old one
  (`octra-pvac-sidecar-prev` on disk) opens any receipt whose
  `pvac_pk_hash` field matches the pre-rotation pubkey. The
  dispatcher routes by hash.
- **T+24h**: the operator runs `rotate-pvac.sh --archive-old`,
  moves the backed-up `sk.enc` to cold storage, the warm copy is
  gone. Any receipt arriving after this point whose hash matches
  the old pubkey is unredeemable under this operator and the
  client must escalate via the v3 dispute path.

**Do not skip the 24h window even if you think the network is
idle.** Battery-saving mobile clients delay receipt redemption by
hours; the 24h calibration is empirical, not arbitrary. See
[`pvac-rotation.md §Step 4`](../operators/pvac-rotation.md#step-4--dual-decrypt-window-t0-to-t24h).

### The asymmetric rotation case (just one key)

If you're only rotating one thing:

- **PVAC alone**: still 24h dual-decrypt. Order is PVAC →
  observation period, no TLS, no policy.
- **TLS alone**: drain-then-swap (no `--rekey`) is zero-downtime
  and zero-client-impact. With `--rekey` it is a hard cutover and
  every pinned `oct://` URL has to be republished.
- **Policy passphrase alone**: every member must have the new
  passphrase before the anchor flips, otherwise they see decrypt
  failures on next poll.
- **Wallet alone**: rotate fresh wallet, sweep balance via stealth
  send. No coordinated impact on TLS / PVAC / policy.

## Audit-trail: every rotation is a discrete event

Each rotation event MUST appear in the audit log so post-mortem
reconstruction works. The daemon's `AuditLog` emits an event
automatically for:

- TLS rotation: the `rotate-tls.sh` script touches the cert/key
  files; the daemon's on-restart emit logs the new cert
  not-before timestamp.
- PVAC rotation: the `octra_registerPvacPubkey` confirmation is
  picked up by the chain-watcher and emitted as a chain-side
  event row.
- Sealed-key rotation: the `seal-keys` / `unseal-keys` CLI emits
  a `key_sealed` / `key_unsealed` row before exiting.
- Policy rotation: the `circle update` CLI emits a
  `circle_anchor_flipped` row when the chain confirmation lands.

To list every rotation event in the last 30 days:

```sh
octravpn-node audit replay \
    --audit-path /var/lib/octravpn/audit/ \
    --since $(date -d '30 days ago' +%s) \
    --until $(date +%s) \
    --format json \
| jq -c 'select(.kind | test("rotat|seal|anchor_flipped"))'
```

> The exact `kind` strings emitted by the daemon are stable in
> v0.1 but the set may grow; the regex `rotat|seal|anchor_flipped`
> captures the current set. If a future release adds a new
> rotation surface, this regex needs an update.

If your rotation does NOT show up in the replay, that's a bug — file
it tagged `audit rotation-event missing` and capture the exact
command you ran. The audit log is the operator's only post-mortem
artifact; gaps in it are blocking issues for production deployments.

## Pre-rotation safety checks

Before any rotation, run the same pre-flight as for an upgrade:

```sh
octravpn-node config validate
octravpn-node audit verify \
    --audit-path /var/lib/octravpn/audit/ \
    --journal-path /var/lib/octravpn/receipts.bin
octravpn-node health --remote http://localhost:51821
```

A failing audit chain BEFORE rotation means the post-rotation
verify might fail for reasons unrelated to the rotation. Fix the
chain first — see [audit-verify.md](audit-verify.md).

## Common rotation mistakes

1. **Skipping PVAC drain.** Rotating PVAC while sessions are still
   minting receipts under the old pubkey leaves orphan
   commitments. Recovery is per-session via the v3 dispute path —
   slow, reputational. Always set `accept_new_sessions = false`
   and wait for active sessions to settle, then rotate. See
   [`pvac-rotation.md §Step 1`](../operators/pvac-rotation.md#step-1--drain-new-sessions-t-5-min).
2. **Re-keying TLS without re-publishing the `oct://` URL.** Every
   pinned client refuses the new fingerprint and falls back to
   the operator's other endpoints — if none are listed, the user
   sees a hard error. Either re-publish the URL before the rekey,
   or restore from the cert backup. See
   [`tls-rotation.md §Failure modes and recovery`](../operators/tls-rotation.md#failure-modes-and-recovery).
3. **Distributing a new sealed-policy passphrase out-of-band but
   forgetting to atomic-flip the anchor.** Members carrying the
   new passphrase decrypt successfully against the OLD blob (the
   blob was re-encrypted but the on-chain anchor still names the
   old version). Always use `octravpn-node circle update
   --commit` — the CLI enforces blob-first-anchor-second
   ordering atomically. The legacy `octra cast circle
   put-encrypted` path could leave chain state on the wrong
   anchor. See
   [`v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md#5-sealed-passphrase-rotation-cadence).

## References

- [`tls-rotation.md`](../operators/tls-rotation.md) — full TLS
  runbook (mesh serve HTTPS, DERP, chain RPC pinned roots,
  knock PSK).
- [`pvac-rotation.md`](../operators/pvac-rotation.md) — full PVAC
  runbook (mint, seal, validate, swap, dual-decrypt, archive).
- [`v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md) —
  wallet, WG static, sealed-policy passphrase, fresh-wallet pattern.
- [audit-verify.md](audit-verify.md) — the recurring chain-clean
  check that gates every rotation.
- [recovery.md](recovery.md) — when a rotation goes wrong and the
  daemon won't boot or a journal break shows up.
