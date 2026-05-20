<!-- captured from source at SHA 2ffead7 (2026-05-20) -->

# Error codes

Every `thiserror::Error` enum variant in the OctraVPN workspace plus
every documented process-exit code. Each variant lists what triggers
it, where it surfaces (HTTP code / exit code), and the operator's
recovery path.

## Process-exit code summary

| Binary | Code | Variant / Meaning |
|---|---|---|
| `octravpn-node` | 0 | Success |
| `octravpn-node` | 1 | Generic `anyhow::Error` |
| `octravpn-node` | 2 | clap usage error |
| `octravpn-node headscale …` | 3 | `AdminError::Connection` (DNS/TCP/TLS) |
| `octravpn-node headscale …` | 4 | `AdminError::Auth` (401/403) |
| `octravpn-node headscale …` | 5 | `AdminError::NotFound` (404) |
| `octravpn-node headscale …` | 6 | `AdminError::{BadRequest,Server,Decode,Local}` |
| `octravpn fetch` | 0 | Success |
| `octravpn fetch` | 2 | URL parse / bad output path |
| `octravpn fetch` | 3 | `FetchAssetError::Rpc` |
| `octravpn fetch` | 4 | `FetchAssetError::NotPublished` |
| `octravpn fetch` | 5 | `FetchAssetError::MissingPassphrase` (or 3 wrong attempts in `-i`) |
| `octravpn fetch` | 6 | `FetchAssetError::DecryptFailed` |
| `octravpn` (other) | 0/1/2 | Standard |

## Error enums

| Enum | Source | Section |
|---|---|---|
| `JournalError` | `crates/octravpn-core/src/receipt_journal/errors.rs:7` | [JournalError](#journalerror) |
| `ReceiptError` | `crates/octravpn-core/src/receipt.rs:185` | [ReceiptError](#receipterror) |
| `OnionError` | `crates/octravpn-core/src/onion.rs:45` | [OnionError](#onionerror) |
| `V3PolicyError` | `crates/octravpn-core/src/v3_policy.rs:101` | [V3PolicyError](#v3policyerror) |
| `V3MembersError` | `crates/octravpn-core/src/v3_members.rs:119` | [V3MembersError](#v3memberserror) |
| `StateRootError` | `crates/octravpn-core/src/v3_state_root.rs:71` | [StateRootError](#staterooterror) |
| `MeshError` | `crates/octravpn-mesh/src/lib.rs:61` | [MeshError](#mesherror) |
| `KnockPskError` | `crates/octravpn-mesh/src/knock.rs:153` | [KnockPskError](#knockpskerror) |
| `RedeemError` | `crates/octravpn-mesh/src/headscale_bridge/preauth.rs:341` | [RedeemError](#redeemerror) |
| `AdminError` | `headscale-rs/headscale-cli/src/admin/mod.rs:45` | [AdminError](#adminerror) |
| `UpdateError` | `crates/octravpn-node/src/circle_update.rs:229` | [UpdateError](#updateerror) |
| `PvacError` | `crates/octravpn-node/src/pvac.rs:126` | [PvacError](#pvacerror) |
| `FetchAssetError` | `crates/octravpn-client/src/portal/chain/errors.rs:12` | [FetchAssetError](#fetchasseterror) |
| `StunError` | `crates/octravpn-mesh/src/stun.rs` (`use thiserror::Error`) | [StunError](#stunerror) |
| `obfs4 HandshakeError` | `crates/octravpn-obfs4/src/handshake.rs:72` | [obfs4 errors](#obfs4-errors) |
| `obfs4 FrameError` | `crates/octravpn-obfs4/src/frame.rs:46` | [obfs4 errors](#obfs4-errors) |

Total error enums: **16**.

---

## `JournalError`

The receipt journal (P1-8/9). Variants:

| Variant | Trigger | Recovery |
|---|---|---|
| `Io(std::io::Error)` | Underlying I/O failed (disk full, permission denied). | Inspect stderr; restore from backup if disk is gone. |
| `BadMagic { path }` | File at `path` doesn't start with `OCRJ2` (or v0 `OCRJ1`). Daemon refuses to clobber an unrelated file. | Verify the path is the right journal; move the file aside if it isn't. |
| `Truncated { path, detail }` | Last record cut off mid-write (power loss). | Compaction on next open should drop the torn tail. Verify with `audit verify`. |
| `ChecksumMismatch { path, offset }` | CRC32 over a record doesn't match. | Suggests on-disk corruption. Audit the storage substrate; restore from backup if confirmed. |
| `SeqNotMonotonic { session, floor, proposed }` | The daemon (or a test) proposed `seq <= floor`. | Hard refusal; the alternative is silent double-signing. Indicates a control-plane bug or a tampered `receipts.bin`. Page on this. |

Result alias: `JournalResult<T> = Result<T, JournalError>`.

---

## `ReceiptError`

The on-the-wire receipt struct. Variants:

| Variant | Trigger |
|---|---|
| `NonMonotonicSeq { prev, next }` | Receipt verifier saw a `seq` that did not strictly exceed the previous. |
| `BadClientSig` | The client's ed25519 sig over the receipt payload failed verification. |
| `BadNodeSig` | The operator's signature failed. |
| `Core(CoreError)` | Wraps a generic `octravpn_core::CoreError` (encoding, etc.). |

These surface as HTTP 422 from `POST /session/{id}/receipt` and as
`receipt rejected` warnings in the client log.

---

## `OnionError`

The onion-routing builder/peeler.

| Variant | Trigger |
|---|---|
| `EmptyRoute` | Caller passed zero hops to `build_onion`. |
| `TooManyHops` | More than `MAX_HOPS` (3) hops. |
| `Aead(String)` | AEAD encrypt/decrypt failed (most often a wrong key in test setups). |
| `Io(String)` | Internal `serde_json` encoding failure. |
| `Malformed` | Inner packet header didn't decode. |

---

## `V3PolicyError`

Validates `OperatorPolicy` (the canonical operator-circle policy
sealed into `policy.json`).

| Variant | Trigger |
|---|---|
| `UnsupportedVersion { got, supported }` | Schema version mismatch. |
| `BadWgPubkeyLength { len }` | `wg_pubkey_b64` not the expected base64 length. |
| `BadWgPubkeyEncoding(String)` | Not valid base64. |
| `BadWgPubkeyDecodedLength { got }` | Decodes to wrong number of bytes (≠32). |
| `EmptyEndpoint` | Required dial target missing. |
| `EmptyRegion` | Required region missing. |
| `BadHashLength { field, len }` | Hex hash field has wrong length (≠64). |
| `BadHashEncoding { field }` | Non-hex character or uppercase letter. |
| `Serde(serde_json::Error)` | Deserialize error. |

---

## `V3MembersError`

Validates `members.json` (the canonical tailnet member roster).

| Variant | Trigger |
|---|---|
| `UnsupportedVersion { got, supported }` | Schema version mismatch. |
| `BadIpSaltLength { len }` | `ip_salt` hex length wrong. |
| `BadIpSaltEncoding` | `ip_salt` has non-hex character or uppercase. |
| `EmptyWallet { index }` | Member at index has empty wallet. |
| `BadWalletPrefix { index, wallet, prefix }` | Wallet missing the `oct…` prefix. |
| `BadWgPubkeyLength { index, len }` | Per-member WG pubkey wrong length. |
| `BadWgPubkeyEncoding { index, reason }` | Per-member WG pubkey not base64. |
| `BadWgPubkeyDecodedLength { index, got }` | Decodes to wrong byte count. |
| `DuplicateWallet { wallet, first, second }` | Same wallet appears twice in the roster. |
| `Serde(serde_json::Error)` | Deserialize error. |

---

## `StateRootError`

Validates `state-root.json` (the canonical v3 anchor target).

| Variant | Trigger |
|---|---|
| `UnsupportedVersion { got, supported }` | Schema version mismatch. |
| `BadHashLength { field, len }` | Hex hash field wrong length (≠64). |
| `BadHashEncoding { field }` | Non-hex character. |
| `EmptyCircleId` | `circle_id` missing. |
| `EmptyRegion` | `region` missing. |
| `Serde(serde_json::Error)` | Deserialize error. |

---

## `MeshError`

The mesh / peer-snapshot layer.

| Variant | Trigger |
|---|---|
| `Stun(StunError)` | STUN binding-request failed. See `StunError` below. |
| `Io(std::io::Error)` | Underlying I/O. |
| `InvalidPeer(String)` | Peer snapshot record didn't decode. |
| `InvalidSubnet(String)` | CIDR string didn't parse. |
| `SnapshotExpired { age_secs }` | Peer snapshot older than allowed window. |
| `SignatureMismatch` | Snapshot ed25519 sig failed. |
| `OldPeerSnapshotFormat` | Pre-v2 unframed encoding. Upgrade the publisher. |

Result alias: `MeshResult<T>`.

---

## `KnockPskError`

The optional knock-layer PSK parser (env var
`OCTRAVPN_KNOCK_PSK`).

| Variant | Trigger |
|---|---|
| `Base64` | Base64 decode of the PSK failed. |
| `BadLength(usize)` | Decoded length wasn't 32. |
| `Duplicate` | `knock_psk` appeared twice in a query string. |

The `mesh serve` arm logs the error and disables the knock layer (does
NOT fail boot — defense in depth).

---

## `RedeemError`

The preauth-key minter. Variants:

| Variant | Trigger | HTTP code |
|---|---|---|
| `Unknown` | Token doesn't match any minted key, or was already consumed once for a non-reusable key. Also returned when an expired key has been evicted from the store. | 401 |
| `Expired` | Token was valid at some point but its TTL has passed. | 401 |

Note: future PRs may introduce `Used` / `Unauthorized` variants for
distinct error pages. Today the surface is intentionally narrow so a
scanner can't distinguish "wrong key" from "already used" from
"expired".

---

## `AdminError`

The embedded `headscale_cli` admin surface (see
[cli-headscale-embedded.md](./cli-headscale-embedded.md)).

| Variant | Trigger | Exit code |
|---|---|---|
| `Connection(String)` | DNS / TCP / TLS / handshake failure. | 3 |
| `Auth(String)` | HTTP 401 / 403. | 4 |
| `NotFound(String)` | HTTP 404. | 5 |
| `BadRequest { status, body }` | HTTP 4xx other than 401/403/404. | 6 |
| `Server { status, body }` | HTTP 5xx. | 6 |
| `Decode(String)` | JSON / response-decoding failure. | 6 |
| `Local(String)` | Local file IO, validation. | 6 |

Source: `headscale-rs/headscale-cli/src/admin/mod.rs:45-94`.

---

## `UpdateError`

The atomic circle-asset update primitive. Source:
`crates/octravpn-node/src/circle_update.rs:229`.

| Variant | Trigger | Recovery |
|---|---|---|
| `BlobPutFailed { asset_path, index, committed_so_far, source }` | A `circle_asset_put_encrypted` tx failed mid-bundle. | None — daemon left chain on OLD anchor. Re-run `circle update` after fixing the underlying issue; the already-committed blobs are tracked in `committed_so_far`. |
| `AnchorUpdateFailed { target_anchor_hex, blob_tx_hashes, source }` | All blobs committed but the final `update_circle_state` tx failed. | `octravpn-node circle retry-anchor --circle … --anchor <target_anchor_hex>` will re-submit just the anchor flip. |
| `BundleInvalid(String)` | Local validation rejected the request (empty circle_id, bad asset_path, members-root override not supported on operator circles, etc.). | Fix the inputs and re-run. |
| `AnchorFetch(anyhow::Error)` | Couldn't read the current state-root from chain for inheritance. | Check `[chain].rpc_url` + `octra_isValidator` ping. |

Operator note: the daemon emits an `audit` record for the partial
failure with `kind="circle_update_partial"` so operators can audit
recovery.

---

## `PvacError`

The managed PVAC (HFHE) sidecar client. Source:
`crates/octravpn-node/src/pvac.rs:126`.

| Variant | Trigger |
|---|---|
| `Spawn { path, source }` | The sidecar binary couldn't be located or spawned. |
| `Timeout(Duration)` | Request did not complete within `request_timeout`. |
| `SubprocessCrashed` | Supervised subprocess crashed mid-request; supervisor will respawn. |
| `Sidecar(String)` | The sidecar returned `{"error": "…"}` instead of a normal response. |
| `BadResponse(String)` | Response JSON didn't match the documented shape. Indicates version skew or a sidecar bug. |
| `Shutdown` | `PvacClient` was dropped. |

The boot-time check for sidecar absence does NOT fail boot — when
`[pvac].enabled = true` but the binary is missing, the daemon logs a
warning and runs without HFHE.

---

## `FetchAssetError`

The portal / `octravpn fetch` chain-asset fetcher. Source:
`crates/octravpn-client/src/portal/chain/errors.rs:12`.

| Variant | Trigger | `octravpn fetch` exit | Portal HTTP |
|---|---|---|---|
| `Rpc { circle_id, path, source }` | JSON-RPC transport / response-shape failure. | 3 | 502 |
| `NotPublished { circle_id, path, resource_key }` | The RPC returned `null` for `(circle_id, resource_key)`. | 4 | 404 |
| `MissingPassphrase { circle_id, path }` | Bytes look sealed but no passphrase available. | 5 | 412 |
| `DecryptFailed { circle_id, path }` | Wrong passphrase / key_id / corrupt envelope. | 6 | 412 |

The `Display` impl on `DecryptFailed` deliberately discards the
underlying error string to prevent the passphrase or ciphertext bytes
from leaking through logs.

---

## `StunError`

STUN client errors. Source: `crates/octravpn-mesh/src/stun.rs:22`.
Variants are timeout, bad response, or transport failure; they wrap
underlying `std::io::Error` where applicable. Wrapped by
`MeshError::Stun`.

---

## obfs4 errors

`HandshakeError` (`crates/octravpn-obfs4/src/handshake.rs:72`) and
`FrameError` (`crates/octravpn-obfs4/src/frame.rs:46`).

* `HandshakeError` variants cover NTOR handshake failures: bad node_id
  length, bad pubkey, replay detected, etc.
* `FrameError` variants cover framing-layer failures: short read, MAC
  mismatch, decompression error.

Both surface as a closed peer connection; the operator log carries the
specific variant.

---

## Mapping table: error → operator action

| Error | Severity | Action |
|---|---|---|
| `JournalError::SeqNotMonotonic` | **PAGE** | Page the operator; daemon refuses to sign. |
| `ReceiptError::*` (any) | warn | Investigate; usually a misconfigured client. |
| `UpdateError::AnchorUpdateFailed` | warn | Run `circle retry-anchor`. |
| `PvacError::SubprocessCrashed` | info | Supervisor will respawn; retry the request. |
| `PvacError::Spawn` | warn | Fix `[pvac].binary_path` and restart. |
| `AdminError::Auth` | warn | Refresh `HEADSCALE_ADMIN_TOKEN`. |
| `RedeemError::*` | info | Mint a fresh preauth key. |
| `MeshError::SnapshotExpired` | info | Bump publish cadence. |
| `KnockPskError::*` | warn (boot) | Reconfigure `OCTRAVPN_KNOCK_PSK`. |
| `FetchAssetError::DecryptFailed` | info | Wrong passphrase; check `OCTRAVPN_SEALED_PASSPHRASE`. |

---

## Cross-references

* Audit-event records emitted for some of these errors:
  [audit-events.md](./audit-events.md).
* Subcommand exit codes: [cli-octravpn-node.md](./cli-octravpn-node.md),
  [cli-octravpn-client.md](./cli-octravpn-client.md),
  [cli-headscale-embedded.md](./cli-headscale-embedded.md).
* The receipt journal byte spec:
  `crates/octravpn-core/src/receipt_journal/README.md`.
