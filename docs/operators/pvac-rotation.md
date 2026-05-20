# PVAC pubkey rotation runbook

This runbook covers rotation of an operator's **lattice PVAC pubkey** —
the ~4 MB blob registered against the operator's wallet via the
off-chain RPC `octra_registerPvacPubkey`. The PVAC pubkey is the
public half of a PVAC (Plaintext-Verified-Against-Ciphertext) lattice
keypair produced by the GPL-isolated sidecar at
[`pvac-sidecar/`](../../pvac-sidecar/) and consumed by every
ciphertext-bearing receipt produced by a v3 session.

> **Separate from `rotate_receipt_pubkey`.** The v3 program
> (`program/main-v3.aml:329`) exposes
> `rotate_receipt_pubkey(circle, new_pubkey)` which bumps the
> **ed25519 receipt-signing pubkey** stored in `circle_receipt_pk`.
> That is a different key on a different curve serving a different
> purpose (non-repudiation of receipts, not encryption). PVAC pubkey
> rotation lives in the off-chain `octra_pvacPubkey` map keyed by
> wallet address and has no v3-program-side hook. The two rotations
> are independent and can run on their own schedules.

See [`docs/operators/tls-rotation.md`](tls-rotation.md) for the
operator UX pattern this runbook follows (back-up → mint → validate →
swap → observe). PVAC differs in two ways: the new pubkey blob is
~4 MB rather than ~2 KB, and chain-side registration is an
overwrite-in-place — there is no `pinned_root_paths`-style OR list
that lets you trust two pubkeys at once during a cutover.

## When to rotate

Four real-world scenarios. Three are reactive; one is hygiene.

1. **Suspected secret-key compromise.** The sealed secret-key envelope
   at `${state_dir}/pvac/sk.enc` leaked, an operator container image
   ran with the passphrase in `argv`, or a backup of the host wallet
   leaked along with the passphrase. Treat as urgent — clients holding
   sealed receipts encrypted under the old pubkey can be decrypted by
   anyone with the leaked secret. Rotation is part of the response;
   the other parts are session draining (so no new receipts are minted
   under the compromised pubkey) and an audit pass over the receipt
   journal (`crates/octravpn-core/src/receipt.rs`).
2. **Lattice parameter upgrade.** When the sidecar bumps
   `pvac_default_params` (typically: ring degree or modulus chain) in
   a new release, every existing pubkey becomes incompatible with
   ciphertexts produced by the new sidecar. Operators must mint a new
   keypair under the new params and rotate on-chain before the upgrade
   window closes. This is the only rotation scenario where the
   **sidecar binary itself changes** — keep the old binary on disk
   under a versioned path during the dual-decrypt window so receipts
   minted before the swap can still be opened.
3. **Multi-region operator.** An operator running exit nodes in
   multiple regions (e.g. EU + US + APAC) may want a region-pinned
   PVAC pubkey per region so that compromise of one region does not
   cross-contaminate. Each region rotates on its own schedule against
   its own wallet (each region runs as a separate Octra wallet by
   design — region IDs are baked into the operator's circle policy).
   This is a "no shared key" pattern, not a single-key rotation.
4. **Scheduled hygiene.** Rotate every **180 days** under normal
   operating conditions. The PVAC keypair lives in a sealed envelope
   on the operator host filesystem; rotating bounds the blast radius
   of a slow-leak compromise (e.g. a long-lived host backup that
   eventually surfaces). 180 days matches the TLS calendar in
   [`tls-rotation.md`](tls-rotation.md) doubled, because PVAC pubkey
   rotation has higher operator cost (the 24h dual-decrypt window;
   see "Rotation procedure" below) and lower marginal risk reduction
   per cycle (the sealed-envelope at-rest protection means the secret
   does not leave the host on TLS errors the way a TLS private key
   would).

## Material layout

| Surface | Path | Owner | Format |
|---------|------|-------|--------|
| Sealed PVAC secret key | `${state_dir}/pvac/sk.enc` | operator (0600) | `octra_core::wallet_enc` envelope wrapping `hfhe_v1\|<base64-pvac-sk>` |
| PVAC pubkey blob | `${state_dir}/pvac/pk.bin` | operator (0644) | `hfhe_v1\|<base64-pvac-pk>` (the line the sidecar's `keygen` returns under `pk`) |
| AES KAT vector | `${state_dir}/pvac/kat.json` | operator (0644) | Reference plaintext + expected ciphertext under the new pubkey; used by step 3 of the script |
| Registered pubkey hash | `${state_dir}/pvac/registered.sha256` | operator (0644) | sha256 of the last blob submitted to `octra_registerPvacPubkey`, kept so the operator can detect drift between on-chain state and local files |

`state_dir` is the operator's node state dir
(`[control].tailscale_wire_state_dir` in `node.toml`); the `pvac/`
subdirectory is created by `rotate-pvac.sh` if absent.

## Pre-rotation: mint, seal, validate

The new material is produced via the sidecar's `keygen` IPC op
(`pvac-sidecar/src/main.cpp:263`) over JSON-over-stdio (see
`pvac-sidecar/ipc-tests/src/lib.rs` for the protocol). The script
below automates the full sequence, but the manual shape is:

```bash
# 1. Mint a fresh 32-byte seed and ask the sidecar for a keypair.
SEED_HEX=$(openssl rand -hex 32)
RESP=$(printf '{"op":"keygen","seed":"%s"}\n' "$SEED_HEX" \
  | "$PVAC_SIDECAR_BIN")
PK=$(jq -r '.pk' <<<"$RESP")   # "hfhe_v1|<base64>"
SK=$(jq -r '.sk' <<<"$RESP")   # "hfhe_v1|<base64>"

# 2. Seal the secret under the wallet passphrase envelope.
# (in production this happens via the `octravpn-node pvac seal` CLI
#  which calls octra_core::wallet_enc::seal_with_passphrase; manual
#  invocation requires the same KDF + AEAD wire that wallet.json uses.)

# 3. Compute the pubkey blob hash; this is what we will compare against
# the on-chain blob after registration.
printf '%s' "$PK" | sha256sum > pk.sha256

# 4. Validate the new keypair end-to-end via the AES KAT — encrypt a
# known plaintext under the new pubkey and assert the ciphertext
# decrypts under the new secret to the same plaintext, byte for byte.
# This catches mint corruption before any chain-side traffic.
```

The AES KAT step is non-negotiable. A keypair that round-trips a known
plaintext is the only proof that the bytes coming out of `keygen` are
internally consistent — every other check (`size`, `magic`, `prefix`)
verifies framing, not cryptographic structure. The KAT runs entirely
on the operator host and takes <100 ms.

## Rotation procedure

The honest rotation path is a **drain-mint-swap-dual-decrypt-archive**
sequence. Each step is reversible up until the chain-side registration.

### Step 1 — drain new sessions (T-5 min)

Stop accepting new sessions. The operator's circle policy is the
control surface: bump `policy.json` to set
`accept_new_sessions = false`, re-seal it into the operator circle,
and let the v3 program observe the policy update (the next session
open will be rejected on-chain). Existing sessions remain open and
continue producing receipts under the **old** PVAC pubkey.

Drain takes as long as the longest open session — typical p99 is ~10
minutes. The script does **not** auto-drain; the operator confirms
drain externally and then re-runs the script with `--post-drain`.

> If you skip drain and rotate anyway: every in-flight session whose
> client minted a receipt commitment under the old pubkey but has not
> yet redeemed it will see redemption failures. Recovery is a per-
> session settle through the v3 dispute path, which is slow and
> reputational. Do not skip drain.

### Step 2 — mint, seal, KAT (T-0)

Run `scripts/operators/rotate-pvac.sh --state-dir <dir>` (dry-run by
default). The script:

1. Spawns the sidecar and runs `op=keygen` against a fresh seed.
2. Seals the returned secret key under the wallet passphrase envelope
   (`octra_core::wallet_enc::seal_with_passphrase`).
3. Computes the sha256 of the new pubkey blob.
4. Runs the AES KAT.
5. Prints the `octra_registerPvacPubkey` tx envelope to stdout.

This is dry-run by default — nothing is written to chain, nothing on
disk is overwritten. The new sealed-sk lives at
`${state_dir}/pvac/sk.enc.new` and the new pubkey lives at
`${state_dir}/pvac/pk.bin.new` so the operator can inspect them.

### Step 3 — submit `octra_registerPvacPubkey` (T+0)

Re-run the script with `--broadcast`. This:

1. Submits `octra_registerPvacPubkey(<wallet>, <new_pk>, <sig>)` to the
   configured RPC endpoint.
2. Polls `octra_pvacPubkey(<wallet>)` until it returns the new blob
   hash (matches `pk.sha256`).
3. Atomically renames `sk.enc.new` → `sk.enc` and `pk.bin.new` →
   `pk.bin`. The old `sk.enc` is moved to
   `${state_dir}/pvac/backup/<ts>/sk.enc` and kept for the dual-
   decrypt window.

**Important:** `octra_registerPvacPubkey` **overwrites** the previous
pubkey under the wallet's address. There is no on-chain
"deprecated-but-still-trusted" state — only the current registration
is queryable. This means:

- Receipts emitted **before** rotation embed ciphertexts under the old
  pubkey. Their decryption requires the **old** secret key.
- Receipts emitted **after** rotation embed ciphertexts under the new
  pubkey. Their decryption requires the **new** secret key.
- The chain's `octra_pvacPubkey` map only knows about the new key.
  Anyone validating a pre-rotation receipt against the on-chain pubkey
  will see a mismatch — this is expected, and the validator must use
  the receipt's `pvac_pk_hash` field (the hash committed at receipt
  mint time) to know which pubkey to fetch.

### Step 4 — dual-decrypt window (T+0 to T+24h)

For 24 hours after rotation, the operator keeps **both** sidecar
instances warm:

- The new sidecar serves all post-rotation decrypt requests.
- The old sidecar (`octra-pvac-sidecar-prev` on disk) serves any
  decrypt request for a receipt whose `pvac_pk_hash` matches the
  pre-rotation pubkey. The receipt journal at
  `[control].receipt_journal_path` (default `./state/receipts.bin`)
  carries the `pvac_pk_hash` per receipt so the dispatcher can route.

24 hours is calibrated to (a) the v3 settlement window — receipts
settle within hours, not days — plus (b) the longest plausible client
delay before redeeming a receipt under standard battery-saving
mobile-client behavior.

After 24h, the dual-decrypt window closes. The operator runs:

```bash
scripts/operators/rotate-pvac.sh --state-dir <dir> --archive-old
```

which moves `${state_dir}/pvac/backup/<rotation-ts>/sk.enc` to cold
storage (operator chooses — air-gapped HSM, paper backup, etc.) and
removes it from the warm filesystem. Any receipt that arrives after
T+24h without having been redeemed earlier is unredeemable under this
operator and the client must escalate via the v3 dispute path.

### Step 5 — post-rotation verification

```bash
# 1. On-chain pubkey matches local pk.bin
LOCAL=$(sha256sum "${state_dir}/pvac/pk.bin" | cut -d' ' -f1)
CHAIN=$(curl -s "$RPC/?method=octra_pvacPubkey&wallet=$WALLET" \
        | sha256sum | cut -d' ' -f1)
[[ "$LOCAL" == "$CHAIN" ]]

# 2. A fresh receipt encrypts/decrypts under the new key
octravpn-node pvac self-test --state-dir "${state_dir}"

# 3. The old sidecar still opens a pre-rotation receipt (during the
# 24h window).
octravpn-node pvac decrypt-test --state-dir "${state_dir}" \
    --sidecar-bin "${state_dir}/pvac/octra-pvac-sidecar-prev" \
    --receipt-hash <pre-rotation-receipt-hash>
```

## Failure modes

| Symptom | Likely cause | Recovery |
|---------|--------------|----------|
| `octra_registerPvacPubkey` returns "tx already in mempool" | duplicate broadcast | wait for the first to confirm; the script's poll loop handles this |
| `octra_registerPvacPubkey` confirms, but `octra_pvacPubkey` still returns the old blob | RPC node lag | wait 1-2 blocks and re-query; if persistent after 60 s, file an RPC bug — the script exits 50 in this case |
| KAT fails after a successful `keygen` | sidecar param drift between mint and decrypt | confirm `PVAC_SIDECAR_BIN` points at the same binary across mint + KAT; rebuild if the binary changed mid-flight |
| Forgot to drain; receipts already in flight under old key | step 1 was skipped | enter the v3 dispute path per-session; the operator's circle policy must be backed off to `accept_new_sessions = false` to stop the bleed |
| Sealed-sk envelope decrypt fails after rotation | wrong passphrase staged | restore from `${state_dir}/pvac/backup/<latest>/sk.enc` and reseal with the correct passphrase before re-running |
| 24h window closed with un-redeemed receipts under the old key | client failed to redeem in time | operator keeps the archived old `sk.enc` in cold storage for the v3 dispute window (≥7d); only escalate to cold archive after 7d settlement-final |

## Calendar

- Scheduled hygiene rotation every **180 days**.
- On-demand rotation: immediate, no calendar.
- Multi-region: each region rotates on its own schedule; coordinate so
  that no two regions are in their 24h dual-decrypt window
  simultaneously (a single operator helpdesk can only walk one
  drain-rotate at a time).

## Constraints

- DO NOT run rotation while a v3 dispute window is open against the
  operator — the dispute path needs a stable PVAC pubkey to verify the
  contested receipt against.
- DO NOT submit `octra_registerPvacPubkey` without having first sealed
  the new secret. A registration without a recoverable secret means
  every subsequent receipt is unredeemable.
- DO NOT skip the AES KAT. A keypair that mints cleanly but fails KAT
  is a corrupt mint; the on-chain registration is wasted gas and the
  operator has to rotate again.
- DO NOT archive the old `sk.enc` before T+24h. Receipts minted
  immediately before the swap may still need to be opened in the
  window.

## References

- Sidecar IPC protocol — `pvac-sidecar/ipc-tests/src/lib.rs`,
  `pvac-sidecar/src/main.cpp:263` (`op_keygen`).
- v3 program receipt-pubkey rotation (separate concept) —
  `program/main-v3.aml:329` (`rotate_receipt_pubkey`).
- Wallet passphrase envelope — `octra_core::wallet_enc`.
- TLS rotation UX pattern this runbook mirrors —
  [`docs/operators/tls-rotation.md`](tls-rotation.md).
- AML host-call bridge status (PVAC pubkey is registered but
  `fhe_load_pk` reverts) —
  [`docs/audit/fhe-load-pk-status.json`](../audit/fhe-load-pk-status.json),
  re-verified daily by
  `.github/workflows/fhe-load-pk-probe.yml`.
