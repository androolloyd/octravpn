# Changelog

All notable changes to this project will be documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
versions follow [SemVer](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `docs/gap-analysis.md` — honest enumeration of what's still
  missing for production-ready by tier.
- `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`,
  `CODE_OF_CONDUCT.md`.
- `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE` files.
- Forthcoming: `octravpn-node reconcile`, wallet at-rest encryption,
  health endpoint with real attestation freshness.

### Changed

- (Pending the gap-closing sprint.)

### Security

- (None this version.)

## [0.1.0] — Initial production scaffold

### Added

- AML on-chain program (`program/main.aml`):
  - Validator-only VPN node registry gated on bond + attestation.
  - Multi-hop session escrow (1–3 hops) with Pedersen route commits.
  - Dual-signed receipts (client + node) over a canonical payload.
  - Curve25519 Pedersen earnings ledger; refunds via stealth output.
  - Slashing: double-sign, offline, no-show, sweep.
  - Key rotation, governance, CEI ordering, integer-overflow guards.
- Rust workspace:
  - `octravpn-core` — shared types, real Octra address codec (`oct +
    Base58(SHA256(pubkey))`, 47 chars), tx canonical form
    (insertion-order JSON-string-as-bytes per
    `webcli/lib/tx_builder.hpp`), HKDF-derived subkeys.
  - `octravpn-node` — validator daemon with control plane (axum) +
    boringtun UDP server + onion router.
  - `octravpn-client` — CLI with `init`, `keygen`, `doctor`,
    `connect`, `settle`, `reclaim`, `nodes`, `identity`.
  - `octravpn-tun` — cross-platform TUN abstraction
    (Linux/macOS/Windows).
  - `octraforge` — Foundry-equivalent test harness with full
    cheatcode parity (`prank`, `deal`, `expect_emit`,
    `expect_revert`, `snapshot`/`revertTo`, `mockCall`,
    `createFork`, `ffi`, `label`, `sign`) plus a `forge-std`
    equivalent (`assertions`, `console`, `std_cheats`,
    `std_storage`, `std_utils`, `invariant`, `OuRecorder`).
  - `octra-cli` — unified `octra` binary with `cast` (call, send,
    tx, block, wallet new/sign/addr, sha256, abi-decode, rpc),
    `forge` (build, create, inspect, bind, test, snapshot),
    `anvil`, `chisel`, `completions`.
- Formal verification:
  - TLA+ — 9 invariants + liveness, TLC bounded check.
  - Tamarin — receipt unforgeability (1/3-hop), double-sign
    slashable, no-link-before-settle (1/2/3-hop).
  - Lean 4 — state model + 6 lemmas including slash conservation.
  - Kani — 3 bounded harnesses.
- Cross-platform deployment:
  - `deploy/install.sh` (POSIX) and `deploy/install.ps1` (Windows).
  - systemd / launchd / Windows SCM service files with hardening.
  - `cargo-deb`, `cargo-generate-rpm`, `cargo-wix`, macOS `.pkg`
    builder, Homebrew formulas.
  - Release workflow building for 6 targets with code signing,
    Authenticode, notarization, SBOMs (CycloneDX).
- Docs: `architecture.md`, `security.md`, `economics.md`,
  `attack-cost.md`, `governance.md`, `octra-research.md`,
  `install.md`, `deploy.md`, `keys.md`, `threat-model.md`.
- 135 tests passing, 0 clippy warnings, 0 fmt diffs.

## [Pre-history]

Iterative scaffolding and refactors leading to 0.1.0; see git
history for fine-grained changes.
