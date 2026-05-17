# OctraVPN v2 — Operator Key Hygiene

> Companion to `docs/v2-threat-model.md`. Read that first for the threat
> model. This doc tells operators *what to do* to avoid the publicly-known
> linkability leaks introduced by the on-chain `deploy_circle` /
> `register_circle` tx envelope.

## 0. TL;DR

1. Generate a **brand-new wallet** for every operator circle you deploy.
   The wallet must have **zero prior chain history** — no faucet, no
   transfers, no contract calls.
2. Fund it via the **public Octra faucet** directly, *or* via a stealth
   output from another wallet (`octra cast stealth send`), *or* via a
   third-party mixer once one ships.
3. Store the wallet secret encrypted on disk (`octra cast wallet
   encrypt`). The `OCTRA_WALLET_PASSPHRASE` lives in your keyring (macOS
   Keychain / Linux kernel keyring / GNOME secret-service / KeepassXC),
   never in a plaintext `.env`.
4. Store the WG static private key encrypted with the same scheme. The
   `wallet_enc` envelope is in `octra-foundry/crates/octra-core/src/wallet_enc.rs`.
5. Rotate the sealed `/policy.json` passphrase every quarter, or
   immediately on any suspected member compromise.

## 1. Why the fresh wallet matters

The known leak: `deploy_circle` is a normal Octra tx with `from =
deployer_wallet`, `to_ = circle_id`. octrascan and any chain scraper
records this forever. `register_circle` on `main-v2.aml:455-498` then
binds `owner = caller`, re-stating the connection. `bond_endpoint`,
`finalize_unbond`, `gov_slash_operator`, every Circle-owner action
re-binds.

→ Whatever wallet you used to deploy IS public-record the operator of the
circle. If that wallet is also the wallet you use for your DEX trades,
your salary, or anything else, everything that wallet ever does is now
publicly linked to your VPN operation.

**The threat model declares this acceptable iff the deploy wallet is
fresh, single-purpose, and never touches anything else.**

## 2. Generate a fresh wallet

```bash
# Generate a new wallet — outputs the address + secret hex
octra cast wallet new
# Example output:
#   address: oct8Tdgu4RLbSGah1fVoVHW4T4cLFDmsoKhTyVD8gCndNFm
#   secret : f14173ec...   (HEX, 32 bytes)

# Write the secret to a passphrase-encrypted file
octra cast wallet encrypt \
    --secret-hex f14173ec...60252b3 \
    --out ~/.octra/op-2026-Q2.wallet
# Will prompt for a passphrase; envelope written as OCTRA-WALLET-V1.
```

Verify the file is encrypted (no plaintext hex visible):

```bash
file ~/.octra/op-2026-Q2.wallet
# Should NOT contain `XXX has ASCII text` with hex inside
xxd ~/.octra/op-2026-Q2.wallet | head -1
# First 16 bytes must read "OCTRA-WALLET-V1\0"
```

Audit: `octra-foundry/crates/octra-core/src/wallet_enc.rs:22` defines
the magic. The KEK is PBKDF2-HMAC-SHA256 over the passphrase with 200k
iterations (default; configurable per the constant
`DEFAULT_PBKDF2_ITERS`). Inner cipher is ChaCha20-Poly1305.

## 3. Fund the fresh wallet WITHOUT revealing your main wallet

Three options, ordered by privacy:

### Option A — public faucet (devnet only, no privacy beyond IP)

```bash
# Devnet faucet drops you the minimum stake (1 OCT today)
curl https://devnet.octrascan.io/faucet -d '{"to":"oct8Tdgu..."}'
# The faucet logs the request IP. Use Tor / a VPN of last resort to
# anonymize the source. The chain tx itself is `from=FAUCET, to=YOU`,
# which is the least linkable shape.
```

### Option B — stealth send from your funding wallet

```bash
# Read the target wallet's view pubkey (derived from its secret).
octra cast wallet view-pubkey --key ~/.octra/op-2026-Q2.wallet
# Returns: viewpk_hex = ...

# Send via octra_privateTransfer from your funding wallet. The recipient's
# wallet address NEVER appears in the tx; only a 16-byte stealth tag does.
octra cast send-stealth \
    --from-key ~/.octra/funder.wallet \
    --to-view-pubkey <viewpk_hex> \
    --amount 1000000  # 1 OCT
```

Audit: `crates/octravpn-core/src/stealth.rs:87` builds the output; the
chain stores only `(ephemeral_pubkey, tag16)` per
`stealth.rs:152`. Recipient scans via `scan_with_view_secret`
(`stealth.rs:131`).

**Caveat:** the funding wallet's *outflow pattern* (amount + timing) can
still correlate to your new wallet's first stake-bond tx if amounts are
unique. Round the deposit to a common stake amount; delay between fund
and bond by hours/days.

### Option C — mixer (when one ships)

Out of scope; OctraVPN does not provide one. Track issue.

## 4. WG static-key storage

The WG static private key today sits as plaintext hex in
`docker/devnet/state/node*/wg.key` (see `state/node1/wg.key:1`). For
production:

### Linux (kernel keyring)

```bash
# Read the existing plain hex
WG_HEX=$(cat /etc/octravpn/wg.key)

# Stash it in the user keyring; survives login session but not reboot
echo -n "$WG_HEX" | keyctl padd user wg-static-2026-Q2 @u
keyctl list @u   # confirm

# Remove the plaintext file
shred -u /etc/octravpn/wg.key
```

Modify the node to read from the keyring (`crates/octravpn-node/src/hub.rs`
loads from disk; needs a `--wg-key-source kernel-keyring` flag).

### macOS (Keychain)

```bash
security add-generic-password \
    -a octravpn -s wg-static-2026-Q2 \
    -w "$(cat /etc/octravpn/wg.key)"

shred -u /etc/octravpn/wg.key  # then read back via
# security find-generic-password -a octravpn -s wg-static-2026-Q2 -w
```

### Cross-platform: the `octravpn-node seal-keys` subcommand (recommended)

P1-6 ships an in-daemon sealing path. The flow:

```bash
# 1. Pick a strong passphrase (≥ 64 bits of entropy; the threat model's
#    Tree B brute-force estimate against PBKDF2-200k assumes this).
export OCTRAVPN_KEY_PASSPHRASE="$(openssl rand -base64 24)"

# 2. Seal the configured keys in one shot. `seal-keys` reads the
#    *.key paths the operator's TOML points at and writes parallel
#    `*.sealed` files atomically; the plaintext sources are kept
#    until --remove-plaintext is passed.
octravpn-node --config /etc/octravpn/node.toml seal-keys

# 3. Confirm the sealed file starts with the OCTRA-WALLET-V1 magic.
xxd /etc/octravpn/wg.key.sealed | head -1

# 4. Point the TOML at the sealed files and enable strict mode:
#       [chain]
#       wallet_secret_path = "/etc/octravpn/wallet.key.sealed"
#       require_sealed_keys = true
#       [tunnel]
#       wg_secret_path     = "/etc/octravpn/wg.key.sealed"
#
#    The daemon now refuses to boot if any configured secret is
#    plaintext-on-disk; the error message names the same seal-keys CLI
#    so an operator who mis-set the paths gets a copy-paste fix.

# 5. Once you've verified the sealed daemon boots cleanly:
octravpn-node --config /etc/octravpn/node.toml seal-keys --remove-plaintext
```

Passphrase resolution order on `seal-keys` / `unseal-keys`:
`--passphrase` > `--passphrase-file` > `--passphrase-stdin` >
`OCTRAVPN_KEY_PASSPHRASE` > TTY prompt (only if stdin is a terminal,
which a systemd-launched daemon isn't). For systemd:

```ini
# /etc/systemd/system/octravpn-node.service.d/passphrase.conf
[Service]
EnvironmentFile=/etc/octravpn/keys.env
```

with `/etc/octravpn/keys.env` chmod 0600 containing one line:

```
OCTRAVPN_KEY_PASSPHRASE=<paste-from-secret-manager>
```

Audit refs:
`crates/octravpn-node/src/seal.rs` (CLI + atomic write),
`octra-foundry/crates/octra-core/src/util.rs::read_secret_32_or_sealed`
(strict-mode loader),
`octra-foundry/crates/octra-core/src/wallet_enc.rs` (envelope itself —
untouched in this commit).

## 5. Sealed-passphrase rotation cadence

The per-tailnet passphrase that decrypts `/policy.json`,
`/wg.pub`, and `/acl.root` (per `discover_v2.rs:40`) should rotate:

- **Quarterly by default.** Match it to a calendar event so no operator
  forgets.
- **Immediately** when a member is removed via `revoke_member`
  (`operator-circle.aml:176`). Today `revoke_member` is silent — the
  ex-member still has the passphrase and can decrypt next-poll's
  `/policy.json`. Rotation = re-encrypt and re-upload (`circle_asset_put_encrypted`).
- **Immediately** on any suspicion the passphrase has leaked via env-var
  exposure (see threat model §3 P1-10).

### Rotation procedure

```bash
# 1. Pick a new passphrase (≥ 12 random chars, see threat model §3 P1-4)
NEW_PP=$(openssl rand -base64 16)
echo "$NEW_PP" | gpg --encrypt -r alice@example.com > new-pp-2026-Q3.gpg
# Distribute the GPG-encrypted file to each member out-of-band.

# 2. Re-encrypt /policy.json with the new passphrase, same key_id
octra cast circle put-encrypted \
    octE5x8WvhXB1FStpDmmfxkMmFKdnx5cL1Fr4gnry6aUdqA \
    /policy.json \
    /etc/octravpn/policy.json \
    --key-id default \
    --passphrase "$NEW_PP" \
    --padding-class 4k \
    --key ~/.octra/op-2026-Q2.wallet

# 3. After confirm, retire the old passphrase from secret stores.
```

## 6. Don't do these

- **Don't commit `wg.key` or `wallet.key` to git.** `state/node1/wg.key:1`
  is in the repo for devnet only. Production deployments must `.gitignore`
  the keys dir, even if encrypted; an encrypted-file leak still helps an
  offline PBKDF2 brute-force on the passphrase.
- **Don't pass the passphrase via `--passphrase 'foo'` on the CLI** —
  shell history captures it. Use the env var
  `OCTRA_SEALED_PASSPHRASE` (still imperfect; see threat-model
  Tree B.3.a) or, better, prompt at runtime.
- **Don't share the SAME deploy wallet across multiple circles.** Each
  circle should have its own one-shot wallet. Cross-circle wallet reuse
  creates an "operator portfolio" graph an analyst can mine.
- **Don't keep the deploy wallet alive long-term.** Once the circle is
  registered and bonded, the deploy wallet's only remaining job is
  `bond_endpoint` / `unbond_endpoint` / `claim_earnings`. After
  `claim_earnings`, sweep any residual to a different fresh wallet,
  destroy the secret, and never reuse the address.

## 7. References

- Threat model: `docs/v2-threat-model.md` §1B, §2 Tree D, §3 P1-3.
- Wallet envelope: `octra-foundry/crates/octra-core/src/wallet_enc.rs`.
- Stealth send: `crates/octravpn-core/src/stealth.rs`.
- Sealed assets: `octra-foundry/crates/octra-core/src/circle.rs`.
- v2 program: `program/main-v2.aml`, `program/operator-circle.aml`.
