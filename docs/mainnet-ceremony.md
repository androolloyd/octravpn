# OctraVPN v3 Mainnet Deploy + Owner-Wallet Ceremony

Operator-facing runbook for taking `program/main-v3.aml` from a
clean checkout to a live mainnet contract under a cold-storage
m-of-n multisig owner.

This is task #224 from `docs/production-readiness.md` — one of the
P0 items that gate "first paying operator on mainnet." Sibling docs:

- `docs/deployment-runbook.md` — operator-facing node bring-up.
- `docs/production-readiness.md` — the gap list this closes.
- `docs/v3-circle-resident-architecture.md` — the contract this
  ceremony deploys.

## Scripts referenced

All paths repo-relative:

| Artefact                                        | Role                                                                 |
| ----------------------------------------------- | -------------------------------------------------------------------- |
| `scripts/ceremony/mainnet-deploy.sh`            | Driver — reads params, walks signing, emits broadcast plan           |
| `scripts/ceremony/verify-deploy.sh`             | Anyone-runs verifier; PASS/FAIL on `vm_contract` + source-hash gates |
| `ceremony/mainnet-params.toml.example`          | Parameter template with rationale per value                          |
| `ceremony/signers/<name>.pub`                   | ed25519 pubkey per signer (committed once known)                     |
| `ceremony/signers/<name>.key.sealed`            | Passphrase-sealed secret key — NEVER committed                       |
| `ceremony/signers/<name>.sig`                   | Detached ed25519 sig over the tx digest                              |
| `ceremony/build/unsigned-deploy-tx.json`        | Canonical-JSON unsigned deploy envelope                              |
| `ceremony/build/unsigned-deploy-tx.digest`      | SHA256(unsigned tx) — the bytes signers attest to                    |
| `ceremony/build/unsigned-transfer-tx.json`      | Unsigned `transfer_ownership(multisig_addr)`                         |
| `ceremony/build/unsigned-setparams-tx.json`     | Unsigned `set_params(...)` with all 10 ints                          |
| `ceremony/build/broadcast-plan.json`            | Machine-readable shopping list for the broadcast phase               |

## 1. Pre-ceremony checklist

Before scheduling the ceremony, every box must be green. If any
single box drifts red between now and the signing day, the ceremony
is cancelled and re-scheduled.

### 1.1 Substrate

- [ ] Contract source `program/main-v3.aml` has cleared an external
      audit. Audit report attached to the ceremony attestation.
- [ ] Audit findings closed OR explicitly accepted in writing by
      the owner-wallet quorum (≥ M of N signers).
- [ ] Devnet smoke (`bash docker/devnet/v3-smoke.sh`) green on the
      identical source.
- [ ] Devnet adversarial drill (`bash docker/devnet/e2e-adversarial-v3.sh`)
      green on the identical source.
- [ ] `git status --porcelain` is empty (tree clean).
- [ ] The commit hash to be deployed is signed (`git verify-commit HEAD`).

### 1.2 Signers — offline preparation

Default quorum is **3-of-5** (see `ceremony/mainnet-params.toml.example`
for the rationale). Each of N signers:

- [ ] Operates from an air-gapped machine — no network during keygen
      or signing.
- [ ] Generates an ed25519 keypair using a tool whose source they
      can read end-to-end (`octra cast wallet new` from
      octra-foundry is the canonical path; a vanilla
      `openssl genpkey -algorithm ed25519` works for the v1 text
      flow).
- [ ] Seals the secret with a passphrase only they know. The seal
      format is the `octra-core::wallet_enc` envelope (argon2id KDF
      + AES-256-GCM); filename:
      `ceremony/signers/<name>.key.sealed`.
- [ ] Writes the **passphrase** on paper, stored in a physical safe
      separate from the laptop holding the sealed file.
- [ ] Publishes only the base64 public key as
      `ceremony/signers/<name>.pub`. Pubkeys are committed to git;
      sealed secrets are NEVER committed.
- [ ] Documents the recovery path: the n-1 other signers' pubkeys,
      this runbook URL, and the passphrase-safe location.

### 1.3 Hardware-wallet variant (OPTIONAL for v1)

The v1 driver script is text-mode multisig. The HW slot is marked
in `scripts/ceremony/mainnet-deploy.sh` (search for `HW TODO`):

- Steps 1.2 keygen/seal become "register the device pubkey under
  `<name>.pub`."
- Step 5 (signing) becomes "render the digest as a QR/HW prompt and
  read back the signature."
- The driver script's signature-file consumption (step 5) is
  identical between modes — the HW wallet emits the same base64
  ed25519 sig that `openssl pkeyutl -sign` would.

A future v2 of this runbook will replace text-mode with HW-only;
text-mode is preserved as a fallback for the case where an HW
device fails during the ceremony.

### 1.4 Witnesses

- [ ] At least one independent witness per signer attests, in
      writing, that the signer's machine was air-gapped during
      keygen + signing.
- [ ] One external observer (not a signer, not a witness) records
      the ceremony — minimum: signed transcript of the digest each
      signer attested to and the timestamp.

### 1.5 Reference values

- [ ] `ceremony/mainnet-params.toml` (NOT `.example`) is staged
      with every numeric default reviewed by the quorum. Specifically:
  - `slash_burn_bps + slash_bounty_bps == 10000`
  - `min_circle_stake >= 100_000_000` (AML floor)
  - `unbond_grace_epochs >= 1000` (AML floor)
  - `multisig_threshold` and `multisig_signer_count` match the
    actual signer set in `ceremony/signers/*.pub`.
- [ ] `contract_source_sha256_expected` is filled with the SHA256
      of the audited source.

## 2. Step-by-step

### 2.1 Dry-run the driver (anyone, any machine)

```sh
bash scripts/ceremony/mainnet-deploy.sh \
  --dry-run \
  --params ceremony/mainnet-params.toml
```

Expected output (truncated):

```
=== 0. Loading params from ceremony/mainnet-params.toml ===
  [ok]   rpc_url=https://octra.network/rpc
  [ok]   chain_id=octra-mainnet
  [ok]   contract=program/main-v3.aml
  [ok]   multisig=3-of-5

=== 1. Source-hash integrity gate ===
  [ok]   live  source SHA256: <hex>
  [ok]   param source SHA256: <hex>
  [ok]   source hash matches param

=== 2. Deploy bundle ===
  [ok]   constructor args: [1000000000,10000000000,10000000000,100,1000]
  [ok]   bundle hash:      <hex>

=== 3. Unsigned tx materialisation ===
  [ok]   unsigned tx:      ceremony/build/unsigned-deploy-tx.json
  [ok]   tx digest:        <hex>
  ...

DRY RUN — stopping before broadcast
```

The driver exits 0 on success. Any non-zero exit aborts the
ceremony — debug, fix, restart.

### 2.2 Signer key generation

Each signer, on their air-gapped machine, runs the keygen step
described in 1.2 above. The output is two files:

- `<name>.pub` — committed to the repo immediately (low sensitivity)
- `<name>.key.sealed` — NEVER committed; lives encrypted on the
  signer's machine + a backup-passphrase-protected copy in cold
  storage.

When all N signers have submitted their `<name>.pub`, the driver
prints a "multisig canonical hash" — a SHA256 over the sorted
pubkey list + the threshold — that every signer cross-checks
against `octra cast wallet multisig` output.

### 2.3 Multisig address derivation

The on-chain owner address is the address that `octra cast wallet
multisig --m <M> --pubkeys ceremony/signers/*.pub` produces. The
driver does NOT compute this itself; the foundry tooling owns the
ed25519-MuSig (or whatever scheme Octra mainnet ships) primitive.

Record the multisig address back into
`ceremony/mainnet-params.toml::expected_owner_addr` before the
broadcast phase.

### 2.4 Contract bundle hash verification

After every signer has dry-run the driver on their own machine,
they should each independently report:

- The SHA256 of `program/main-v3.aml`
- The bundle hash from step 2 of the driver output
- The tx digest from step 3 of the driver output

ALL signers must report identical hashes. Any mismatch indicates
divergent source trees and aborts the ceremony.

### 2.5 Signing party

Schedule a coordinated session (video call with cameras on the
air-gapped machines; physical room if possible). The flow is:

1. The ceremony coordinator runs the driver one more time and
   distributes the resulting `unsigned-deploy-tx.json` +
   `unsigned-deploy-tx.digest` to every signer.
2. Each signer verifies, on their air-gapped machine, that the
   digest is the SHA256 of the JSON they received.
3. Each signer signs the digest using their sealed key + passphrase.
   For text-mode: `octra cast sign --key <name>.key.sealed
   --digest <hex>` emits a base64 ed25519 sig. For HW: the device
   renders the digest, the signer approves, the sig comes back.
4. Each signer drops their `<name>.sig` file into the shared
   `ceremony/signers/` directory (network-permitted at this point —
   we are publishing public signatures, not secrets).
5. The coordinator re-runs the driver. If ≥ M sigs are present,
   step 5 reports "threshold met" and step 7 prints the foundry
   broadcast command line.

### 2.6 Broadcast

The driver does NOT itself POST to the mainnet RPC. Broadcast is
delegated to the foundry CLI because that tool knows how to encode
multisig ed25519 sigs into the on-wire OctraTx envelope:

```sh
octra forge create \
  --aml program/main-v3.aml \
  --constructor-args 1000000000,10000000000,10000000000,100,1000 \
  --rpc-url https://octra.network/rpc \
  --multisig-sig-dir ceremony/signers \
  --multisig-threshold 3
```

Capture the program address from the output.

### 2.7 Post-deploy verification

Immediately after broadcast confirms (poll `vm_contract <addr>`
until `code_hash` is non-empty):

```sh
bash scripts/ceremony/verify-deploy.sh <program-addr> \
  --rpc-url https://octra.network/rpc \
  --params ceremony/mainnet-params.toml \
  --refresh
```

The `--refresh` flag prints the live `code_hash` for pasting into
the params file as `expected_code_hash`. Commit that change to
the repo in the same PR as the post-ceremony attestation.

Then run without `--refresh` to confirm PASS:

```sh
bash scripts/ceremony/verify-deploy.sh <program-addr>
```

Expected output ends with:

```
PASS — oct... verified on https://octra.network/rpc
```

### 2.8 Initial owner transfer + set_params

Two more multisig-signed transactions complete the ceremony:

1. `transfer_ownership(multisig_addr)` — moves the program owner
   from the ad-hoc deploy signer to the cold-storage multisig
   address. Without this, the multisig has no governance authority
   over the deployed contract.
2. `set_params(...)` — installs the 10-int parameter vector that
   was reviewed in 1.5. The constructor already set 5 of these,
   but `set_params` covers all 10 including slash/treasury/fee bps.

Both transactions use the templates in
`ceremony/build/unsigned-transfer-tx.json` and
`ceremony/build/unsigned-setparams-tx.json`. The signing flow is
identical to 2.5; broadcast is via the foundry CLI's `cast send
--multisig-sig-dir` subcommand.

Re-run `verify-deploy.sh` after each transaction.

## 3. Post-ceremony attestation

Commit the following to the repo in a single PR:

```
ceremony/attestation-<date>.md     — runbook below
ceremony/mainnet-params.toml       — with expected_code_hash,
                                     expected_owner_addr,
                                     program_addr populated
ceremony/signers/*.pub             — committed
ceremony/signers/*.sig             — committed (PUBLIC by design)
ceremony/build/*.json              — committed (audit trail)
```

Attestation template:

```markdown
# OctraVPN v3 Mainnet Deploy Attestation — <YYYY-MM-DD>

## Result

- Program address: oct...
- Chain: octra-mainnet
- code_hash:       <hex>
- bundle_hash:     <hex>
- source SHA256:   <hex>
- Deploy tx hash:  <hex>
- transfer_ownership tx hash: <hex>
- set_params tx hash:         <hex>

## Quorum

- Threshold: M-of-N (default 3-of-5)
- Signers (alphabetical):
  - <name1> — pubkey <base64>, sig <base64>
  - <name2> — pubkey <base64>, sig <base64>
  - <nameM> — pubkey <base64>, sig <base64>

## Witnesses

- <witness1> attests for <signer1>: <signed statement>
- ...

## External observer

- <observer>: signed transcript at <URL>

## Parameters installed

| Key                   | Value          | Rationale          |
| --------------------- | -------------- | ------------------ |
| min_session_deposit   | 1_000_000_000  | 1 OCT, anti-spam   |
| ...                   | ...            | ...                |

## Verification command

```
bash scripts/ceremony/verify-deploy.sh <addr>
# → PASS
```

## Open items

- <e.g. expected_owner_addr to be cross-checked against foundry
  multisig derivation in PR #NNNN>
```

The attestation lands on `main` only after the verify-deploy
command actually returns PASS — that is the gate that flips
`production-readiness.md` row "v3 AML deployed on mainnet" from
🔴 to 🟢.

## 4. Rollback plan

The deploy is a single on-chain transaction; either it confirms or
it does not. The interesting failure modes are:

### 4.1 Deploy tx rejected at submit

Symptom: foundry CLI prints a rejection, no contract appears.

Action: re-check signer set, re-collect signatures if any expired
(devnet has no concept of sig expiry but the foundry tool may add
a freshness window). No on-chain state has changed; restart the
signing party.

### 4.2 Deploy tx confirms but transfer_ownership fails

Symptom: `verify-deploy.sh` PASS on code_hash, FAIL or warn on
owner. The program exists on chain with the deployer wallet (the
ad-hoc multisig coordinator) as owner.

Action: the deployer wallet is the only key that can call
`transfer_ownership` until it succeeds. Either:

- Re-sign + re-submit `transfer_ownership(multisig_addr)` until it
  confirms; OR
- If the deployer key is compromised in this window, **STOP**. The
  program is unowned-by-multisig and any actor with the deployer
  key can `transfer_ownership` to themselves. Triage:
  - Check `vm_contract <addr>` for any state changes since deploy.
  - If clean: rotate to a fresh multisig immediately (new ceremony,
    new params file, same contract source). The deploy tx + initial
    state still cost OCT but the program is rescued.
  - If the deployer key has already moved ownership elsewhere:
    coordinate with Octra protocol governance for an emergency
    revert. There is no on-chain rescue without Octra cooperation.

### 4.3 set_params fails after transfer_ownership

Symptom: contract is owned by the multisig but the parameter
vector is the constructor defaults (not the full 10-int set).

Action: re-sign + re-submit `set_params(...)` until it confirms.
No emergency posture — the constructor defaults are safe
(see `program/main-v3.aml::constructor`); set_params only tightens
or adjusts.

### 4.4 Mid-ceremony abort

Symptom: any signer reports a hash mismatch, a witness reports
network activity on an air-gapped machine, or a deadline slips.

Action:
1. Stop. No keys leave the air-gapped machines.
2. Coordinator publishes a "ceremony aborted" notice to the same
   channel that announced the ceremony.
3. Investigate the divergence — likely a stale checkout, an editor
   touching the contract file, or a witness misobservation.
4. Re-schedule.

The cost of an aborted ceremony is operator time. The cost of a
ceremony that confirms with the wrong source or the wrong signers
is permanent. Bias hard toward aborting.

## 5. After the ceremony

The `production-readiness.md` items that flip to ✅:

- Row "v3 AML deployed on mainnet" — green when verify-deploy
  passes against the published mainnet program addr.
- Row "Owner-wallet ceremony" — green when this runbook's
  attestation lands on `main`.

The remaining P0 from `production-readiness.md` — Wall 5, operator
CLI consolidation, audit CLI, mainnet runbook (this doc partially
satisfies the runbook item) — proceed in parallel.

## 6. Glossary

- **Bundle hash** — SHA256 of (source-hash || constructor-args ||
  chain_id || protocol_version "v3"). Stable across rebuilds; the
  scriptable witness that all signers attest to the same input.
- **Code hash** — the on-chain `vm_contract.code_hash` — computed
  by the chain over the compiled bytecode. Distinct from the
  bundle hash because the latter is over the source text.
- **m-of-n** — threshold signature scheme; M valid signatures from
  N possible signers authorise a transaction. Default here is 3-of-5.
- **Sealed key** — secret key encrypted with a passphrase-derived
  AES key (argon2id + AES-256-GCM, the `octra-core::wallet_enc`
  format). Storing the sealed file alone is harmless; recovery
  requires the passphrase.
- **Air-gapped machine** — machine with no network interface
  enabled (wifi off, Bluetooth off, ethernet unplugged) for the
  duration of keygen + signing.
