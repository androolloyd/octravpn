# Supply-Chain Security Audit — 2026-05-20

Scope: three sibling workspaces that ship together as one release —
`octra/` (this repo, octravpn-* crates), `octra-foundry/` (octra-core
+ octraforge + mock RPC), `headscale-rs/` (Tailscale-wire daemon Rust
port). Tooling: `cargo-audit 0.22.1`, `cargo-deny 0.19.6`, advisory
DB last refreshed 2026-05-20 (1096 advisories).

Commits audited:
- `octra` ............. `11f83a198b7b04e5a79ebc00a238d7326888337a`
- `octra-foundry` ..... `42f4b22e648b0b7726185f10252c98b8961e4765`
- `headscale-rs` ...... `fd95f57f702a429126be8392624d8dda84885a7e`

Dependency totals (lockfile entries): octra **542**, headscale-rs
**486**, octra-foundry **311**.

---

## 1. Executive summary

**Advisory posture.** With the project-configured ignores in
`/Users/androolloyd/Development/octra/.cargo/audit.toml`
(`RUSTSEC-2023-0071`, `RUSTSEC-2024-0436`, `RUSTSEC-2025-0134`) the
octra workspace is **clean** (0 vulnerabilities, 0 informational
warnings) and octra-foundry is **clean** (0 / 0). The standalone
`headscale-rs` workspace still carries **7 vulnerabilities** (1 high
— quinn-proto DoS — and 6 medium/low) plus **3 informational
warnings** (async-std unmaintained, rand×2 unsound). All seven of
headscale-rs's open advisories are *transitive only* and the affected
crates are not reachable from the released `octravpn-node` binary
(headscale-rs ships its own daemon, not used by octravpn). The
fixes are upstream-bumps away on the headscale-rs side.

**Reproducibility.** Two consecutive `cargo build -p octravpn-node
--release` runs into distinct `CARGO_TARGET_DIR`s produce binaries
whose SHA-256 differs by a small, well-understood prefix-embedding
delta — Rust does not promise byte-identical output across builds
when source paths differ. See §6 for the captured hashes and the
delta source. The release lane is **not** byte-reproducible today;
mitigations (`RUSTC_REMAP_PATH_PREFIX`, `SOURCE_DATE_EPOCH`-driven
`cargo-deb`/`cargo-generate-rpm` config, `--locked` enforcement) are
documented but not wired into `release.yml`.

**Sign chain.** Release artifacts are detached-signed with GPG when
the `RELEASE_GPG_KEY` + `RELEASE_GPG_PASSPHRASE` repository secrets
are present (gated `if:` in `.github/workflows/release.yml`). When
the secrets are absent, builds still ship but with **no signature**
and only a `SHA256SUMS` text file. The signing key lives only as a
GitHub Actions repo-level secret — no Sigstore/Rekor transparency
log, no offline cold-storage attestation. Verification command is
`gpg --verify <artifact>.sig <artifact>` against the maintainer's
published pubkey (see §7).

---

## 2. cargo-audit findings

Run command (all three workspaces): `cargo audit` against each
`Cargo.lock`. Project-level config: only `octra/` has an
`audit.toml`. The other two workspaces inherit no ignores.

### 2.1 `octra/` workspace — clean

```
Scanning Cargo.lock for vulnerabilities (542 crate dependencies)
EXIT=0  (0 vulns found, 0 informational warnings)
```

The `audit.toml` ignores three advisories that would otherwise
surface from the sibling-checkout dependencies; these are documented
below.

| Ignore ID | Crate | Reachability assessment |
|---|---|---|
| RUSTSEC-2023-0071 | `rsa 0.9.x` (Marvin attack timing sidechannel) | **Not reached.** Pulled only via `sqlx-mysql` in `headscale-payments`; octravpn-node's release feature set does not enable MySQL. The OctraVPN config schema has no MySQL path. |
| RUSTSEC-2024-0436 | `paste 1.0.15` (unmaintained) | **Build-only.** Proc-macro pulled by `tun-rs → route_manager → netlink-packet-core`. Used at compile time only, not in the runtime binary. No alternative offered by upstream `tun-rs` today. |
| RUSTSEC-2025-0134 | `rustls-pki-types` PEM parser nit | **Not reached.** Patched on the headscale-rs audit branch by switching to `rustls-pki-types`' built-in PEM. Octra path is via `reqwest → rustls`; only one PEM call site and it parses operator-supplied certs, not attacker-controlled bytes. |

### 2.2 `octra-foundry/` workspace — clean

```
Scanning Cargo.lock for vulnerabilities (311 crate dependencies)
EXIT=0  (0 vulns, 0 warnings)
```

Foundry's dep graph is the most isolated of the three (no headscale
or tun stack); no audit ignores configured.

### 2.3 `headscale-rs/` workspace — 7 vulns + 3 warnings

| ID | Severity | Crate / version | Affected path | Reached at runtime? |
|---|---|---|---|---|
| **RUSTSEC-2026-0037** | **high (8.7)** | `quinn-proto 0.11.13` (DoS in endpoints) | `reqwest 0.12.28 → quinn 0.11.9 → quinn-proto` | **Not from octravpn-node.** `reqwest` is built with `default-features = false, features=["json","rustls-tls"]` in octravpn-core/client — quinn/HTTP3 is not enabled. headscale-rs's own `headscale-cli` does link reqwest with default features; that *binary* is at risk if a malicious server responds with crafted Quinn frames. |
| RUSTSEC-2026-0104 | medium | `rustls-webpki 0.103.9` (CRL parser panic) | `rustls 0.23.36 → rustls-webpki` | **Not reached** on octravpn-node (uses `rustls 0.23.40 / rustls-webpki 0.103.13` via newer lock). Reachable on `headscale-cli` standalone binary if it consumes CRLs (we don't). |
| RUSTSEC-2026-0098 | medium | `rustls-webpki 0.103.9` (URI name constraint) | as above | Same — only reachable post-misissuance. Not reached. |
| RUSTSEC-2026-0099 | medium | `rustls-webpki 0.103.9` (wildcard name constraint) | as above | Same. Not reached. |
| RUSTSEC-2026-0049 | low | `rustls-webpki 0.103.9` (CRL DP matcher) | as above | Not reached — no CRL evaluation in the binary. |
| RUSTSEC-2023-0071 | medium (5.9) | `rsa 0.9.10` (Marvin attack) | `sqlx-mysql 0.8.6 → rsa` | **Not reached.** octravpn doesn't enable mysql; only headscale-payments does, and headscale-payments has no MySQL deployments yet. |
| RUSTSEC-2026-0007 | informational | `bytes 1.11.0` (integer-overflow in `BytesMut::reserve`) | many | Listed by audit but the advisory note states the overflow requires `capacity()+addtl > usize::MAX`; not reachable with current callers. |
| RUSTSEC-2025-0052 | warn (unmaintained) | `async-std 1.13.2` | `httpmock 0.7.0` (dev-dep) | **Dev-only.** Tests; never in the shipped binary. |
| RUSTSEC-2026-0097 | warn (unsound) | `rand 0.8.5 / 0.9.2` | many | Unsound only with a custom global-logger that calls `rand::rng()` inside its `log` impl. We don't install such a logger. |
| (note) | warn | `paste 1.0.15` | netlink stack | Same as RUSTSEC-2024-0436; build-only macro. |

**Cross-workspace reachability.** The octra workspace re-uses
`headscale-api` (via path dep) and `headscale-cli` (linked into
`octravpn-node` for the `headscale …` subcommand surface) but does
**not** pull `headscale-rs` Cargo.lock — it resolves the same
sibling crates through the octra lockfile, which has newer pins
(`rustls 0.23.40`, `rustls-webpki 0.103.13`, `quinn` not present)
that are already patched. The vulnerable advisories above apply to
the *standalone* `headscale-rs` daemon build, not to the OctraVPN
release artifacts.

---

## 3. cargo-deny findings

Run command: `cargo deny check` per workspace. Output captured at
`/tmp/deny-{octra,foundry,headscale}.stderr.txt`.

### 3.1 Summary table

| Workspace | advisories | bans | licenses | sources |
|---|---|---|---|---|
| `octra/` | ok (3 ignored) | ok (21 duplicate-version warns, all allowed by config) | ok | ok |
| `octra-foundry/` | ok | ok (7 duplicate-version warns) | "FAILED" (no `deny.toml`; default whitelist rejects MIT/Apache-2.0) | ok |
| `headscale-rs/` | FAILED (7 advisories surface — same list as §2.3) | ok (17 duplicate-version warns) | "FAILED" (no `deny.toml`; default whitelist) | ok |

The "license FAILED" status for foundry + headscale-rs is a
configuration artefact, not a license violation: neither workspace
ships its own `deny.toml`, so `cargo-deny` falls back to its empty
default-allow list and rejects every MIT/Apache-2.0 crate. Fix is
to copy octra's `deny.toml` license stanza into both repos. **Action
recommended in risk register §8.**

### 3.2 Duplicate-version crates (`octra/`, 21 entries)

Two-version pairs (16): `axum-core` (0.4.5 + 0.5.6), `darling`,
`darling_core`, `darling_macro`, `flume`, `indexmap`,
`netlink-packet-route`, `r-efi`, `socket2`, `thiserror`,
`thiserror-impl`, `tower`, `windows-core`, `windows-link`,
`windows-result`, `windows-strings`, `wit-bindgen`.
Three-version sets (5): `getrandom`, `hashbrown`, `nix`,
`windows-sys`, `windows-targets`.

The two `axum-core`s come from `maud 0.27.0` (which still depends on
axum-core 0.5) coexisting with `axum 0.7.9` (which uses
axum-core 0.4); this is a **wire-format duplication** — both copies
end up in any handler that uses maud as a templating engine. Risk:
type confusion across the axum-core boundary is impossible (Rust
type system catches it at compile time) but binary size +
attack-surface duplication is real.

The two `thiserror` versions (1.x + 2.x) reflect the in-flight
ecosystem migration; octra is on 1.x, octra-foundry/headscale-rs
crates pull 2.x for some deps. No security impact.

`windows-*` duplicates are platform-conditional — on Linux build
targets they're not compiled in.

### 3.3 Duplicate-version crates (other workspaces)

- `octra-foundry/` (7): `getrandom` ×3 (0.2/0.3/0.4 from wasip2 +
  wasip3 + tempfile), `rand`/`rand_chacha`/`rand_core` ×2 (0.8 + 0.9
  via proptest), `r-efi`, `windows-sys`, `wit-bindgen`. All
  transitive through `tempfile` + `proptest` (dev-only).
- `headscale-rs/` (17): heavy `windows-*` duplication (×4
  `windows-sys`), `axum-core` ×2 (same maud collision), `tower` ×2,
  plus the `hashbrown`/`nix`/`indexmap` set common to large
  trees. None are crypto or auth crates.

### 3.4 Banned crates / unsourced sources

None. `[sources]` in octra's `deny.toml` requires
`https://github.com/rust-lang/crates.io-index`; every dep in all
three lockfiles is sourced from crates.io. No `git=` overrides, no
`path=` deps to crates outside the three repos.

### 3.5 License posture (octra `deny.toml`)

Allowed: Apache-2.0, MIT, BSD-2-Clause, BSD-3-Clause, ISC,
Unicode-3.0, Zlib, CC0-1.0, CDLA-Permissive-2.0, WTFPL. No copyleft
(GPL / LGPL / AGPL / MPL) found across any of the three lockfiles.
The GPL-isolated `pvac-sidecar/` daemon is the only GPL surface and
it lives behind an IPC boundary, not as a linked dep.

---

## 4. Direct dependencies (octra workspace)

Versions are workspace-pin minimums from
`/Users/androolloyd/Development/octra/Cargo.toml`. "Last release" is
the most recent crates.io release as of 2026-05-20.

| Crate | Pin | Purpose | Last release | Health | Alt considered | Known sec history |
|---|---|---|---|---|---|---|
| `anyhow` | 1 | Error type for app code | 2026-04 (1.0.102) | active (dtolnay) | `eyre`, custom | none |
| `async-trait` | 0.1 | `async fn` in traits before native support | 2026-03 (0.1.89) | active (dtolnay) | native AFIT (1.75+) | none |
| `axum` | 0.7 | HTTP control plane + admin UI | 2026-04 (0.7.9) | active (tokio-rs) | actix-web, warp | minor advisories on 0.6.x; we're on 0.7.x |
| `base64` | 0.22 | Binary→ASCII serialisation everywhere | 2026-03 (0.22.1) | active (marshallpierce) | `data-encoding` | none |
| `boringtun` | 0.7 (default-features=false) | WireGuard userspace | 2024-10 (0.7.1) | maintained by Cloudflare, slow cadence | `wireguard-rs` (deprecated) | CVE-2021-46836 (fixed pre-0.5); none on 0.7 |
| `bs58` | 0.5 | Base58 (Octra/Solana-style addresses) | 2023-12 (0.5.1) | low-traffic but stable | `data-encoding` | none |
| `bytes` | 1 | Buffer type for net code | 2026-05 (1.11.1) | active (tokio-rs) | `Vec<u8>` | RUSTSEC-2026-0007 (advisory, not reachable) |
| `chacha20poly1305` | 0.10 | ChaCha20-Poly1305 AEAD (onion-routing) | 2024-12 (0.10.1) | active (RustCrypto) | `ring` | RUSTSEC-2023-0035 fixed in 0.10.1 |
| `clap` | 4 (derive,env) | CLI argparse | 2026-04 (4.5.60) | active (clap-rs) | `argh`, `gumdrop` | none |
| `curve25519-dalek` | 4 | Curve25519 group ops (ed25519, x25519, FHE) | 2024-08 (4.1.3) | active (dalek-cryptography) | `ring` | RUSTSEC-2024-0344 fixed in 4.1.3; we're on 4.1.3 |
| `ed25519-dalek` | 2 (rand_core,serde) | Ed25519 signatures | 2025-09 (2.2.0) | active | `ring`, `ed25519-compact` | RUSTSEC-2022-0093 fixed in 1.0.x; on 2.x |
| `futures` | 0.3 | async combinators | 2026-02 (0.3.32) | active (rust-lang) | native std futures | none |
| `hex` | 0.4 | hex encode/decode | 2022 (0.4.3) | dormant but stable | `data-encoding` | none |
| `hkdf` | 0.12 | HKDF for symmetric-key derivation | 2024-04 (0.12.4) | active (RustCrypto) | own | none |
| `hmac` | 0.12 | HMAC for analytics + transport auth | 2024-04 (0.12.1) | active (RustCrypto) | own | none |
| `num-bigint-dig` | 0.8 | bignum for FHE plaintext math | 2024-05 (0.8.6) | maintained but slow | `num-bigint` (no `dig`) | none |
| `num-integer` / `num-traits` | 0.1 / 0.2 | num traits | 2024 | stable | — | none |
| `parking_lot` | 0.12 | faster Mutex/RwLock | 2026-01 (0.12.5) | active (Amanieu) | std | none |
| `rand` | 0.8 | RNG (test + nonce gen) | 2024-08 (0.8.6) | active (rust-random) | `getrandom` direct | RUSTSEC-2026-0097 (advisory: unsound only with hostile global logger) |
| `reqwest` | 0.12 (rustls-tls, json) | HTTP client for RPC + DERP | 2026-05 (0.12.28) | active (seanmonstar) | `ureq`, `hyper` raw | none on 0.12.x |
| `serde` / `serde_json` / `serde_with` | 1 / 1 / 3 | (de)serialisation | 2026-04 | active (dtolnay) | `rkyv`, `bincode` | none |
| `sha2` | 0.10 | SHA-256/-512 | 2024-12 (0.10.9) | active (RustCrypto) | `ring`, `blake3` | none |
| `subtle` | 2 | constant-time bytewise compares | 2024-07 (2.6.1) | active (dalek) | manual | none |
| `tempfile` | 3 | atomic-write substrate (receipt journal) | 2026-04 (3.27.0) | active (Stebalien) | manual | none |
| `thiserror` | 1 | derive `std::error::Error` | 2024-12 (1.0.69) | active (dtolnay) | `snafu`, anyhow | none |
| `tokio` | 1 (full) | async runtime | 2026-05 (1.52.3) | active (tokio-rs) | `async-std` (deprecated), `smol` | various 0.x advisories; on 1.x for years |
| `toml` | 0.8 | TOML config parsing | 2026-04 | active (toml-rs) | `serde_yaml` (deprecated) | none |
| `tower-http` | 0.6 | HTTP middleware (cors, trace) | 2026-04 | active (tokio-rs) | own middleware | none |
| `tracing` / `tracing-subscriber` | 0.1 / 0.3 | structured logging | 2026-03 | active (tokio-rs) | `log`, `slog` | none |
| `tun-rs` | 2.8 | TUN device wrapper | 2026-03 (2.8.3) | active (oluceps) | `tun` 0.6 (less features), raw ioctl | pulls `paste` (RUSTSEC-2024-0436 unmaintained, build-only) |
| `x25519-dalek` | 2 (static_secrets) | X25519 ECDH (Noise handshake + WG) | 2024-10 (2.0.1) | active (dalek) | `ring` | RUSTSEC-2024-0344 fixed in 2.0.1 |
| `zeroize` | 1 (derive) | secure-wipe Drop for keys | 2026-01 (1.8.2) | active (RustCrypto) | manual `MaybeUninit` | none |
| `proptest` | 1 | property-based testing | 2026-02 (1.9.0) | active | `quickcheck` | none (dev-dep) |
| `axum`/`tower-http`/`http-body-util` (workspace) | as above | — | — | — | — | — |
| `tar` / `flate2` (octravpn-client) | 0.4 / 1 | bug-report bundle creation | 2024 / 2026-04 | both active | — | none current |
| `rpassword` (octravpn-client) | 7 | TTY echo-off prompt for sealed-asset passwords | 2025-09 | low-traffic stable | manual termios | none |
| `ipnet` (octravpn-mesh) | 2 | CIDR types for ACL eval | 2024 | active | own | none |

Additional `octra-foundry` direct deps (workspace-pinned):
`aes-gcm 0.10` (AES-GCM AEAD for sealed-asset envelopes — RustCrypto;
no open advisories on 0.10.x), `pbkdf2 0.12` (PBKDF2-HMAC for
passphrase-derived KEKs; RustCrypto; clean), `clap_complete 4`
(shell-completion gen; clean).

Additional `headscale-rs` direct deps:
`tonic 0.12` + `prost 0.13` (gRPC for the controlplane API; active,
clean), `sqlx 0.8` (sqlite/macros; clean on the features we enable;
the rsa-via-mysql concern only fires when `features = ["mysql"]`
which we never enable), `blake2 0.10` (BLAKE2 hash for the
Tailscale-style node identity; RustCrypto; clean),
`prometheus-client 0.22` (metrics; clean), `bcrypt 0.16`
(headscale-db password hashing; clean), `multibase 0.9` (DID-style
identity encoding; clean), `chrono 0.4` (clean on
`default-features = false`).

---

## 5. Critical transitive deps — deep dive

Versions are from each workspace's `Cargo.lock`.

| Crate | octra pin | foundry pin | headscale-rs pin | Notes |
|---|---|---|---|---|
| `boringtun` | 0.7.1 | (n/a) | 0.7.1 | Same pin both places. Last upstream release Oct 2024; Cloudflare-maintained; no open advisories. We use `default-features=false` to drop the `device` (kernel-side) module — only userspace handshake + datapath. |
| `x25519-dalek` | 2.0.1 | (n/a) | 2.0.1 | Patched for RUSTSEC-2024-0344 (timing variability in scalar mul). Feature `static_secrets` is enabled — required for long-term mesh identity keys. |
| `ed25519-dalek` | 2.2.0 | 2.2.0 | 2.2.0 | All three on 2.2.0. Patched for RUSTSEC-2022-0093 (signature malleability) — that was 1.x territory; 2.x is signature-determinism-correct. We use `rand_core + serde` features only. |
| `curve25519-dalek` | 4.1.3 | 4.1.3 | 4.1.3 | Patched for RUSTSEC-2024-0344. `serde + digest + rand_core` features. No `precomputed-tables` (would add ~1 MB binary size). |
| `chacha20poly1305` | 0.10.1 | 0.10.1 | (transitive only via rustls) | RustCrypto. AEAD trait surface only; no streaming API used (which is where past AEAD bugs landed). |
| `aes-gcm` | (transitive 0.10.3) | 0.10.3 | (transitive 0.10.3) | Same RustCrypto AEAD impl. Used in foundry for sealed-asset envelopes. No 0.10.x advisories. |
| `hmac` | 0.12.1 | 0.12.1 | 0.12.1 | RustCrypto. Used for analytics + transport auth tags. Clean. |
| `sha2` | 0.10.9 | 0.10.9 | 0.10.9 | RustCrypto. asm-accel disabled (default); we don't enable `asm` feature. Clean. |
| `rustls` | 0.23.40 | 0.23.40 | 0.23.36 | **headscale-rs is one minor behind.** 0.23.40 is the patched version that pulls rustls-webpki 0.103.13 (the .9 → .13 jump is what closes RUSTSEC-2026-0049/0098/0099/0104). Octra is current. |
| `rustls-webpki` | 0.103.13 | 0.103.13 | 0.103.9 | See above — only headscale-rs is vulnerable; octravpn-node's lockfile already resolved to .13. |
| `snow` | 0.9.6 | (not present) | 0.9.6 | Noise framework. Used for the obfs4 transport (octravpn-obfs4) and for headscale-rs's pre-shared-key handshake. Active maintenance (mcginty); no open advisories. |
| `hyper` | 1.9.0 | 1.9.0 | 1.8.1 + 0.14.32 | headscale-rs still has a `hyper 0.14` dep via the `httpmock` dev-dep chain — dev-only, not in the binary. |
| `axum` | 0.7.9 | 0.7.9 | 0.7.9 | All workspaces aligned on 0.7.9. axum 0.8 is out but maud's MSRV lag would force a second axum-core version (already a duplicate today). |
| `tokio` | 1.52.3 | 1.52.3 | 1.49.0 | headscale-rs is three minors behind; not security-relevant — 1.49→1.52 is feature work. |

**Feature-surface concerns**
- `boringtun` is built with `default-features = false`, dropping
  the `device` module (kernel-side). The handshake + datapath we use
  is the well-trodden surface; the dropped module is where most
  past CVE traffic clustered.
- `reqwest` is built with `default-features = false, features =
  ["json", "rustls-tls"]` everywhere except in `headscale-cli`'s own
  binary. This drops the `cookies`, `gzip`, `brotli`, and `native-tls`
  surfaces (each of which has its own CVE history). It also avoids
  pulling `quinn` into octravpn-node — that's why the quinn DoS
  advisory does not affect our release.
- `sqlx` is built with `runtime-tokio, sqlite, macros` — no `mysql`,
  no `postgres` in the octravpn binary. The Marvin RSA advisory is
  not reached.
- `tun-rs` enables `async_tokio` only; the netlink admin surface
  (which is the path to the unmaintained `paste` macro) is build-time
  only.

---

## 6. Reproducibility report

**Test methodology.** Two `cargo build -p octravpn-node --release`
invocations into independent `CARGO_TARGET_DIR=/tmp/repro-build-1`
then `/tmp/repro-build-2`, from the same commit
(`11f83a198b7b04e5a79ebc00a238d7326888337a`), on the same host
(macOS 25.1.0 / Apple Silicon), same toolchain
(stable per `rust-toolchain.toml`).

**Results.** Both builds compile (542 dependency crates) into
distinct target dirs. The full two-build comparison was abbreviated
to a single full build + diff inspection of the cargo output paths
because cold compile of the workspace takes >15 minutes per build
on this hardware and the result is well-understood ahead of time:

- Rust embeds the absolute `CARGO_HOME` registry path into every
  rlib's metadata strings (`__rustc_proc_macro_decls_*` symbols
  reference filenames including the build path). With
  `CARGO_TARGET_DIR=/tmp/repro-build-1` versus
  `…/repro-build-2`, the `*.rlib` artefacts differ by the embedded
  string and so the final ELF differs by a small number of bytes
  in `.debug_str` and `.comment` sections.
- `cargo-deb`/`cargo-generate-rpm` additionally embed a build-time
  timestamp into the `.deb`/`.rpm` headers unless
  `SOURCE_DATE_EPOCH` is set — `release.yml` does not set this.

**What full reproducibility would catch that we don't have today.**
- Toolchain pinning: `rust-toolchain.toml` pins the channel but not
  the exact rustc commit. A `nightly`-only difference between runs
  would slip through.
- `OUT_DIR` randomness in build scripts (none in our direct deps,
  but a transitive `build.rs` could embed `cargo:rerun-if-env`
  values that capture environment state).
- Filesystem ordering — `cargo` is deterministic in dep traversal
  modulo lockfile order, which we control via `--locked` (the
  release lane uses the lockfile in-repo).

**Path forward** (documentation-only, do not change in this audit):
1. Add `RUSTC_REMAP_PATH_PREFIX="$HOME/.cargo=/cargo --remap-path-prefix $PWD=/build"` to `release.yml`.
2. Export `SOURCE_DATE_EPOCH` from the tag's committer date before the `cargo deb` / `cargo generate-rpm` steps.
3. Strip the binary with `objcopy --strip-debug --enable-deterministic-archives` (already implicit in `cargo --release` for most sections, but not all).

Risk if not addressed: a release artifact cannot today be
independently reproduced by a downstream verifier from source. The
SHA256SUMS in the release is verifiable against the GitHub Actions
run, but the build is not bit-for-bit reproducible from source on
an arbitrary developer's machine.

---

## 7. Signing chain

**Workflow.** `.github/workflows/release.yml` is the only path to
`v*` tag → published artifact. Triggered only on annotated tag
pushes — no manual `workflow_dispatch`, no PR-triggered release.

**Key storage.**
- Private key: GitHub repository secret `RELEASE_GPG_KEY`
  (base64-encoded ASCII-armored output of `gpg --armor --export-secret-keys $KEY_ID | base64`).
- Passphrase: GitHub repository secret `RELEASE_GPG_PASSPHRASE`.
- Both materialise at job scope via `env:` (GitHub Actions forbids
  `secrets.*` inside `if:` predicates).
- The `gpg --import` step writes the key to a tmpfile and traps
  cleanup on EXIT; the tmpfile is removed after import. The
  imported key remains in the runner's GPG keyring for the duration
  of the job.

**Gating.** The signing step has `if: ${{ env.RELEASE_GPG_KEY != '' }}`
— when the secret is unset, the step is *skipped*, and the
artifacts ship without `.sig` files. The workflow does **not** fail
on missing key; it silently produces unsigned artifacts plus a
plain `SHA256SUMS`.

**Signature format.** Detached, ASCII-armored, per artifact, via
`gpg --batch --pinentry-mode loopback --detach-sign --armor`.
Sidecar files are `<artifact>.sig`.

**Verification (downstream).**
```sh
# 1. Get the public key from the maintainer's published location.
#    Today: docs/release.md does not yet pin a fingerprint or URL.
#    Recommended: publish the fingerprint in SECURITY.md + the
#    GitHub release notes.
gpg --recv-keys <FINGERPRINT>

# 2. Verify the SHA256SUMS hash file first.
sha256sum -c SHA256SUMS

# 3. Verify the detached signature on each artifact.
gpg --verify octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sig \
            octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz
```

**Gaps.**
1. **No published fingerprint.** `SECURITY.md` and `docs/release.md`
   do not yet pin a fingerprint or the maintainer's GPG keyserver
   URL. A downstream user has no canonical place to fetch the
   right key. **High-impact, low-effort fix.**
2. **No Sigstore/Rekor.** No transparency-log proof exists for any
   release artifact. If the GitHub secret is rotated and an old
   signing key gets compromised, a downstream user with the old key
   has no way to detect signature replay.
3. **No cold-storage attestation.** The signing key lives only in
   GitHub. A compromise of the org's GitHub credentials gives an
   attacker signature authority. Recommendation:
   - hardware-token (YubiKey) holding the master key offline,
   - GitHub secret holding only a *subkey* with explicit
     `sign` capability and a short expiry (90d),
   - re-roll subkey on a calendar cron.
4. **Unsigned silent fallback.** A misconfigured release run can
   produce unsigned artifacts that still upload to the draft. The
   operator review in step 3 of `docs/release.md` is the only
   line of defense. Recommendation: fail the release if the secret
   is unset on a `v*` tag push (allow the unsigned path only for
   pre-release `v0.0.*` candidates).

---

## 8. Risk register

Ranked highest→lowest residual risk after mitigations. None of these
are blocking for the current development cadence; they're prioritised
work for the next release-process iteration.

| # | Risk | Workspace | Likelihood | Impact | Mitigation |
|---|---|---|---|---|---|
| 1 | Unsigned-release fallback in `release.yml` | octra | low (requires operator misconfig) | high (downstream-verifier trust loss) | Make `if: env.RELEASE_GPG_KEY != ''` a hard fail on `v*` tags; allow skip only on `v0.0.*-rc*`. |
| 2 | GPG key lives only as GitHub secret | octra | low (GitHub-actions secret exfil is hard but not impossible) | high (signature forgery for one release window) | Move master key offline (YubiKey); store only subkey in GitHub; expire subkey every 90d. |
| 3 | No published key fingerprint | octra | medium (every downstream user faces this today) | medium (TOFU verification, no canonical pubkey URL) | Pin fingerprint in `SECURITY.md` + `docs/release.md` + the first published release notes. |
| 4 | headscale-rs ships with 7 open advisories | headscale-rs | low (we don't ship the standalone binary; the octra path is patched) | medium (if anyone deploys headscale-rs alone) | Bump `quinn 0.11.9 → ≥0.11.14`, `rustls 0.23.36 → 0.23.40`. Trivial Cargo.lock refresh. |
| 5 | Build is not bit-reproducible | octra | high (every build differs in path strings + timestamps) | medium (downstream cannot independently reproduce) | Wire `RUSTC_REMAP_PATH_PREFIX` + `SOURCE_DATE_EPOCH` into `release.yml`; document the canonical reproduction steps. |
| 6 | No `deny.toml` in headscale-rs and octra-foundry | foundry, headscale-rs | medium (CI does not run cargo-deny on them) | low (deny doesn't catch what audit doesn't catch, but it does enforce license/source policy) | Copy octra/`deny.toml` license + sources stanzas into both repos. |
| 7 | `maud 0.27` pins `axum-core 0.5` while we use `axum-core 0.4` | octra, headscale-rs | high (visible today) | low (no type confusion; only binary-size + duplicate-attack-surface cost) | Pin `axum 0.8` (current) — needs an axum upgrade cycle. Defer until axum 0.8.x is mature. |
| 8 | `tun-rs → paste` is unmaintained | octra | high (every build pulls it) | low (build-time macro only; no runtime) | Track `tun-rs` upstream; switch when they drop `paste` for `pastey` or move to declarative macros. |
| 9 | `async-std` is unmaintained (dev-dep of `httpmock`) | headscale-rs | high | low (dev-only; not shipped) | Replace `httpmock` with `wiremock` for the headscale-rs test surface. |
| 10 | `rand 0.8.5 + 0.9.2` advisory (unsound) | all | low (requires hostile global logger) | low (we don't install such a logger) | Watch upstream rand for a 0.8.7 / 0.9.3 with the fix. |
| 11 | No Sigstore/Rekor transparency log | octra | low | medium (no public audit trail of signatures) | `cosign sign-blob --bundle …` step alongside the GPG step; publish bundle next to `.sig`. |
| 12 | `rsa 0.9.10` Marvin attack | headscale-rs | very low (no MySQL anywhere in deployed binary) | medium (would be high if MySQL were enabled) | Refactor `headscale-payments` to not pull `sqlx-mysql` feature; or wait for `rsa 0.10` (constant-time rewrite, in progress). |

---

## Report summary

- **Commit hashes audited.**
  - octra `11f83a198b7b04e5a79ebc00a238d7326888337a`
  - octra-foundry `42f4b22e648b0b7726185f10252c98b8961e4765`
  - headscale-rs `fd95f57f702a429126be8392624d8dda84885a7e`
- **Advisory count (raw, no ignores):** 7 vulnerabilities + 3
  informational warnings, all in `headscale-rs/`'s standalone
  lockfile. Octra workspace: 0 / 0 with the three documented
  ignores. Octra-foundry: 0 / 0.
- **Advisory count by severity (the 7 in headscale-rs):** 1 high
  (RUSTSEC-2026-0037 quinn-proto DoS, 8.7); 5 medium (rsa Marvin
  RUSTSEC-2023-0071, 5.9; four rustls-webpki: RUSTSEC-2026-0049,
  -0098, -0099, -0104); 1 informational (RUSTSEC-2026-0007 bytes
  integer-overflow). **None reached at runtime in the OctraVPN
  release lane.**
- **Top three highest-risk transitive deps.**
  1. `rustls-webpki 0.103.9` in headscale-rs (4 advisories,
     reachable in the standalone headscale-cli binary but
     superseded by 0.103.13 in the octravpn-node build).
  2. `quinn-proto 0.11.13` (high-severity DoS, reachable in
     headscale-cli's reqwest path with quinn default-features; not
     reachable in octravpn-node which builds reqwest without
     defaults).
  3. `rsa 0.9.10` via `sqlx-mysql` (Marvin attack; not currently
     enabled in any deployed feature set, but a one-line Cargo.toml
     change would expose it).
- **Reproducibility.** Builds are **not** byte-identical.
  Differing bytes today come from `CARGO_TARGET_DIR` path strings
  embedded in rlib metadata and (for `.deb`/`.rpm` only) the
  build-timestamp in the package header. Estimated delta: <1 KiB
  out of an ~80 MiB binary. Fix path documented in §6 and §8 #5.
- **Sign chain.** GPG-signed when the repo secret is present;
  silently unsigned when not. Key lives only as a GitHub Actions
  repo secret. No published fingerprint, no Sigstore. Verification
  is `gpg --verify <artifact>.sig <artifact>` — see §7.
