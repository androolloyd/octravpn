# Contributing to OctraVPN

Thanks for your interest in OctraVPN. This document covers the bare
minimum you need to get from `git clone` to a green PR.

## Quick start

```sh
git clone https://github.com/octra-labs/octravpn
cd octravpn

# Build everything (uses the pinned toolchain in rust-toolchain.toml).
cargo build --workspace --release

# Run the full test suite (~10s on a recent laptop).
cargo test --workspace

# Lint at the workspace's pedantic level.
cargo clippy --workspace --all-targets -- -D warnings

# Format.
cargo fmt --all
```

## Project layout

| Path | What lives there |
| --- | --- |
| `program/` | On-chain AML program (the OctraVPN smart contract) |
| `crates/octravpn-core/` | Shared crypto, RPC client, types |
| `crates/octravpn-node/` | Validator-side node daemon |
| `crates/octravpn-client/` | Client CLI |
| `crates/octravpn-tun/` | Cross-platform TUN abstraction |
| `crates/octraforge/` | Foundry-style test harness |
| `crates/octra-cli/` | Unified `octra` CLI (cast, forge, anvil, chisel) |
| `tests/mocks/` | In-process Octra RPC mock |
| `tests/e2e/` | End-to-end integration tests |
| `proofs/` | TLA+ / Tamarin / Lean / Kani formal specs |
| `deploy/` | install scripts, service files, packaging |
| `docs/` | Architecture, economics, security, governance |
| `fuzz/` | cargo-fuzz harnesses |

## What to work on

1. **Open issues** — anything tagged `good-first-issue` is curated for
   contributors who are new.
2. **The gap analysis** — `docs/gap-analysis.md` lists what's missing
   from production-ready by tier. Tier A (data-plane wiring,
   `reconcile`) is the highest-impact open work.
3. **Property tests** — if you find a property the existing tests
   don't cover, add it to one of the `prop_*.rs` files under
   `crates/octravpn-core/tests/`.
4. **Documentation** — keep `docs/architecture.md`, `security.md`,
   `economics.md` accurate when you change the protocol.

## Coding conventions

- **Lints**: pedantic clippy is on workspace-wide. PRs must produce
  zero warnings under `cargo clippy --all-targets`.
- **Format**: `cargo fmt --all`. CI checks this.
- **No `unsafe`** outside of explicit, narrow exceptions (`fs::set_env`
  is the only current carve-out, with `#[allow(unsafe_code)]`).
- **Comments**: keep narrow. Don't narrate the diff, don't describe
  what the code does, only the *why* when it's non-obvious.
- **Errors**: production code returns `Result` and uses `anyhow` for
  application-level errors. Library crates (`octravpn-core`) use a
  typed `CoreError`.

## Tests

Every PR that changes behaviour ships tests. Three flavours:

- **Unit tests** in `#[cfg(test)] mod tests` next to the code.
- **Property tests** in `crates/octravpn-core/tests/prop_*.rs` using
  `proptest`.
- **End-to-end tests** in `tests/e2e/src/lib.rs` exercising the full
  RPC mock + control plane.

If you're adding a new cheatcode to `octraforge`, also add a test in
`crates/octraforge/tests/cheatcodes.rs`.

## Cryptographic changes

Touching any of `commit.rs`, `earnings.rs`, `onion.rs`, `tx.rs`,
`receipt.rs`, `stealth.rs`, `sig.rs`, `util.rs::derive_subkey`,
or `program/main.aml` requires:

1. A property test demonstrating the new behaviour.
2. An update to the corresponding formal spec (TLA+ for state
   transitions, Tamarin for crypto protocols, Lean for entrypoint
   semantics).
3. A note in the PR description about what threat model changes (if
   any) and how the new code preserves the existing guarantees.

## Pull request flow

1. Branch from `main`. One topic per PR.
2. Run `cargo fmt && cargo clippy --workspace --all-targets -- -D warnings && cargo test --workspace`. All four must pass.
3. Push. CI will run the full matrix (fmt, clippy, test, TLA, Tamarin,
   Lean, Kani, docker-e2e).
4. Open the PR. Add a description with:
   - What changed and why.
   - Threat-model impact (or "none").
   - How to verify the change locally.
5. A maintainer reviews. Two approvals required for protocol changes
   (anything in `program/` or under `crates/octravpn-core/src/`).

## Releasing

Tag-based. Push a `v*` tag and the release workflow does the rest:
cross-compile to six targets, build `.deb` / `.rpm` / `.pkg` /
`.msi`, sign macOS via Developer ID, sign Windows via Authenticode,
generate SBOMs, publish to GitHub Releases, update Homebrew tap.

Maintainers tag releases.

## Security

Don't open public issues for vulnerabilities. See `SECURITY.md`.

## Code of conduct

See `CODE_OF_CONDUCT.md`. TL;DR: be kind, be specific, focus on the
code and the protocol.
