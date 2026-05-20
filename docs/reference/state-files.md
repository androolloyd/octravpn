<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# On-disk state files

Every artifact `octravpn-node` (and `octravpn`) reads or writes. All
paths are configurable; the defaults listed are the in-code defaults
from `crates/octravpn-node/src/config.rs`.

## Quick index

| Path | Owner | Format | Section |
|---|---|---|---|
| `state/receipts.bin` | node | binary, v1 framed | [receipts.bin](#receiptsbin) |
| `state/circle.toml` | node (v2) | TOML | [circle.toml](#circletoml) |
| `state/circle-v3.toml` | node (v3) | TOML | [circle-v3.toml](#circle-v3toml) |
| `state/tailscale-wire/noise_static.key` | node | 32 raw bytes mode 0600 | [Noise static key](#noise-static-key) |
| `state/tailscale-wire/tls.crt` + `tls.key` | node | PEM | [Wire TLS material](#wire-tls-material) |
| `audit/audit-YYYY-MM-DD.jsonl` | node | append-only NDJSON | [Audit log](#audit-log) |
| `audit/.audit.key` | node | 32 raw bytes mode 0600 | [Audit HMAC key](#audit-hmac-key) |
| `state/derp-map.json` | node | JSON | [DERP map](#derp-map) |
| `state/extra_records.json` | node | JSON | [MagicDNS extra records](#magicdns-extra-records) |
| Wallet secrets (`*.key`, `*.key.sealed`) | node + client | raw 32 bytes / OCRS1-sealed | [Key material](#key-material) |
| `~/.octravpn/tailnets/<name>.toml` | client | TOML | [Client tailnet cache](#client-tailnet-cache) |
| `~/.cache/octravpn/v2/<circle>.bin` | client | sealed JSON | [Client v2 cache](#client-v2-cache) |

---

## `receipts.bin`

The P1-8/9 **persistent receipt-seq journal**. The daemon consults this
file before signing any receipt and refuses to sign at any seq that
does not strictly exceed the on-disk floor. Survives daemon restarts —
an attacker cannot force the node to double-sign at a seq it previously
committed to.

* **Default path.** `./state/receipts.bin` (override via
  `[control].receipt_journal_path`).
* **Recommended path (production).** `/var/lib/octravpn/receipts.bin`.
* **Owner.** Created and exclusively written by `octravpn-node` at boot.
* **Format.** v1 framed. Header is 8-byte magic `OCRJ2\0\0\0`, then a
  stream of fixed 44-byte records. Per-record:
  | Offset | Size | Field | Encoding |
  |---|---|---|---|
  | 0 | 32 | `session_id` | raw bytes |
  | 32 | 8 | `seq` | u64 big-endian |
  | 40 | 4 | `crc32` | u32 big-endian, IEEE poly over bytes 0..40 |
* **Atomicity.** Append-only in steady state; compaction snapshots
  rewrite the file atomically via a tempfile suffix (`.compacting`)
  followed by `rename` + parent-dir fsync. Watermark
  `DEFAULT_COMPACTION_WATERMARK = 10 MiB`.
* **Backward compat.** v0 (`OCRJ1`) is auto-migrated to v1 on first
  open. See `crates/octravpn-core/src/receipt_journal/migration.rs`.
* **Verifier.** `octravpn-node audit verify --journal-path …` (also
  `receipt-verify`).
* **Permissions.** Whatever the daemon's process umask produces. Mode
  0600 recommended; the file contains session ids the operator handled.
* **Backup.** A cold copy is harmless. Restoring an OLDER copy is
  catastrophic — the floor would regress. Restore only as part of a
  full host rebuild and only if no receipts have been signed since.
* **Source.** Spec at
  `crates/octravpn-core/src/receipt_journal/README.md`.
  Implementation in the sibling files (`mod.rs`, `inner.rs`, `codec.rs`,
  `compact.rs`, `migration.rs`).
* **Threat model.** docs/v2-threat-model.md §3 P1-8 + P1-9.

---

## `circle.toml`

v2-only. Caches the predicted/deployed circle id so the operator
doesn't re-derive it on every restart.

* **Default path.** `./state/circle.toml` (override via
  `[chain].circle_state_path`).
* **Owner.** `octravpn-node` v2 boot path.
* **Format.** TOML — single `circle_id = "oct…"` field plus the boot
  tx hash. The exact shape is in `crates/octravpn-node/src/chain_v2.rs`.
* **Atomicity.** Tempfile + rename.
* **Recovery if missing.** Boot re-derives the circle id and re-writes
  the file. No on-chain effect — re-derivation is deterministic.

---

## `circle-v3.toml`

v3-only. Caches the v3 boot anchor + tx hashes so subsequent restarts
can detect whether the circle is already registered without round-
tripping the chain for every detail.

* **Default path.** `./state/circle-v3.toml` (override via
  `[chain].circle_v3_state_path`).
* **Owner.** `octravpn-node` v3 boot path (`v3_boot.rs`).
* **Format.** TOML. Fields include `state_root` (hex64), `tx_hash`,
  `receipt_pubkey_b64`.
* **Recovery if missing.** The daemon re-runs `register_circle` (which
  is idempotent: the chain returns the existing record if already
  registered) and re-writes the file.

---

## Noise static key

`state/tailscale-wire/noise_static.key` — 32 raw bytes, mode 0600. The
Tailscale-wire long-term static identity. Determines the node's `mkey:`
identity advertised on `/key`.

* **Default path.** `./state/tailscale-wire/noise_static.key` (override
  via `[control].tailscale_wire_state_dir` or `mesh serve --state-dir`).
* **Owner.** `octravpn-node` (the `mesh serve` arm and the hub's
  Tailscale-wire bridge).
* **Format.** 32 raw bytes. Mode 0600.
* **Generation.** Generated on first boot if absent; written atomically.
* **Persistence requirement.** Must survive across restarts or the
  node's `mkey:` identity churns, forcing every peer to re-register.
* **Source.** `crates/octravpn-mesh/src/tailscale_wire/noise.rs`.

---

## Wire TLS material

`state/tailscale-wire/tls.crt` + `tls.key` — self-signed cert for the
rustls-terminated HTTPS listener (`mesh serve --https-listen …`).

* **Generation.** Self-signed at startup using `--cert-hostname` as the
  SAN. Stored in the same `state_dir`.
* **Use.** Stock `tailscale up` v1.78+ requires HTTPS on :443; this
  cert satisfies the dial without needing a public CA.
* **Recovery.** Delete to regenerate with a fresh keypair (operators
  doing this must redistribute the pinned cert hash to clients
  pinning via `--login-server-cert`).

---

## Audit log

`audit/audit-YYYY-MM-DD.jsonl` — append-only NDJSON, one file per UTC
day. Daemon writes every operator-relevant event here.

* **Default directory.** `./audit/` (override via
  `[control].audit_dir`).
* **Recommended path (production).** `/var/lib/octravpn/audit`.
* **Owner.** `octravpn-node` boot creates the dir + key (if missing);
  the audit task is the only writer.
* **Format.** NDJSON. Each line is `{ts_unix, kind, session_id?,
  extra?, prev_hash, hmac}` where `hmac = HMAC_SHA256(audit_key,
  prev_hash || record_json)`. Chain head HMAC is the verifiable suffix.
  Field reference: [audit-events.md](./audit-events.md).
* **Daily rotation.** New filename at UTC midnight; the HMAC chain
  resets per file but the first record links to the prior file's
  terminal HMAC (forward integrity).
* **Verifier.** `octravpn-node audit verify --audit-path <dir>` walks
  the chain across files. `octravpn-node audit-tail` tails with
  per-line verification.
* **Atomicity.** Per-line writes through `BufWriter` + periodic fsync
  (configurable via `AuditLog::open_batched`). Default fsync after every
  write for paranoia.

---

## Audit HMAC key

`audit/.audit.key` — 32 raw bytes mode 0600. The HMAC key used by every
record in the audit log.

* **Owner.** `octravpn-node` boot generates it via `AuditLog::open` if
  absent.
* **Backup.** Take a cold copy after first generation. Without this key
  the audit log is unverifiable (a future verifier can still parse the
  JSON but cannot cryptographically validate the chain).
* **Recovery if missing.** Generate a new one; the existing audit logs
  become unverifiable forward. Don't delete it casually.

---

## DERP map

`state/derp-map.json` — optional DERP map override for the
Tailscale-wire bridge. Currently surfaced only via the
`OCTRAVPN_DERP_MAP_PATH` env var (no `[derp]` block in the schema yet).

* **Format.** Tailscale DERP-map JSON. See upstream
  `tailscale/derp/derpmap` for the shape.
* **Owner.** Operator-managed; the daemon only reads.
* **Hot reload.** Not yet wired; restart required.

---

## MagicDNS extra records

`state/extra_records.json` — optional set of hostname → IP overrides
the MagicDNS resolver serves. Hot-reload target.

* **Format.** JSON array of `{name, type, value}` records.
* **Hot reload.** The DNS task watches the file with `notify` and
  reloads on change (atomic rewrites only — full replace, no partial
  updates).
* **Owner.** Operator-managed.

---

## Key material

Two key files per node, two locations:

* `wallet.key` — 32-byte ed25519 secret. Signs chain transactions.
  Configured via `[chain].wallet_secret_path`.
* `wg.key` — 32-byte WireGuard secret + (post-derivation) receipt
  signing material. Configured via `[tunnel].wg_secret_path`.

Both files may be:

* **Plaintext.** 32 raw bytes, mode 0600. Auto-detected.
* **Sealed.** ChaCha20-Poly1305 envelope under
  `octra_core::wallet_enc` (magic `OCRS1`). Wraps the same 32 raw bytes.
  Produced by `octravpn-node seal-keys`. Pass-phrase resolution: see
  [env-vars.md § `OCTRAVPN_KEY_PASSPHRASE`](./env-vars.md).

With `[chain].require_sealed_keys = true`, the daemon refuses to boot
when a configured key file is plaintext on disk.

**Backup.** Treat both like SSH host keys — back up to encrypted
storage, never email/Slack. Loss of `wallet.key` means loss of the
operator stake (recovery requires social attestation through the
governance multisig).

---

## Client tailnet cache

`~/.octravpn/tailnets/<name>.toml` — friendly-name → tailnet id mapping
written by `octravpn tailnet create --name …`.

* **Owner.** `octravpn` (client).
* **Format.** TOML; minimal — `tailnet_id`, owner address, ACL hash.
* **Honours.** `$HOME` (Unix) + `$USERPROFILE` (Windows-like).

---

## Client v2 cache

`<cache>/octravpn/v2/<circle>.bin` — sealed JSON cache of decrypted
operator policies so `octravpn discover v2` doesn't refetch every time.

* **Owner.** `octravpn`.
* **Format.** AES-GCM over the decoded `OperatorPolicy` JSON; key is
  derived from the per-tailnet passphrase + a static "v2-cache" domain
  separator.
* **Cache root precedence.** `OCTRAVPN_CACHE_DIR` env > `$XDG_CACHE_HOME/octravpn` >
  `$HOME/.cache/octravpn`. Source:
  `crates/octravpn-client/src/v2_cache.rs:140-160`.
* **Invalidation.** `octravpn discover invalidate --circle …`.

---

## Permissions, ownership, recovery summary

| File | Mode | If missing | If restored stale |
|---|---|---|---|
| `receipts.bin` | 0600 | Re-created empty; daemon may double-sign if you also re-used the same WG key without bumping seq. Don't lose it. | **CATASTROPHIC** — operator may now sign at seqs already used. Force a key rotation if you restored a stale copy. |
| `circle.toml` / `circle-v3.toml` | 0644 | Re-derived deterministically on boot. | Safe — daemon cross-checks chain state. |
| `noise_static.key` | 0600 | Regenerated; clients re-register. | Safe — but client peer caches now point at wrong mkey for a window. |
| `audit/*.jsonl` | 0644 | Started fresh — gaps in history. | Mostly safe — but the chain HMAC across days breaks; re-verify with `audit verify`. |
| `.audit.key` | 0600 | Regenerated; old logs become unverifiable. | Safe — restores chain HMAC continuity. |
| `wallet.key`, `wg.key` (sealed or plain) | 0600 | Boot fails. | Safe if the restore is the canonical key. |

---

## Cross-references

* Receipt journal byte spec: `crates/octravpn-core/src/receipt_journal/README.md`.
* Audit-event kinds emitted to JSONL: [audit-events.md](./audit-events.md).
* Sealed-keys workflow: `docs/v2-operator-key-hygiene.md`.
* Config fields controlling these paths: [config.md](./config.md).
