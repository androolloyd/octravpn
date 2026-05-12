# OctraVPN — Honest Gap Analysis

Current state (counted at the time of writing):

- **11** workspace crates · **10,599** LOC Rust
- **740** lines AML · **16** markdown docs
- **135** tests passing · **0** clippy warnings · **0** fmt diffs
- Formal proofs: TLA+ 308, Tamarin 220, Lean ~460, Kani 87

The system has shipped scope across the protocol, off-chain libraries,
test harness, Foundry-equivalent tooling, formal verification, install
scripts and CI, and deployment packaging. What follows is what is
**still missing for production**, sorted by blocking impact.

## Tier A — blocks real-world use

### A1. Data plane is not wired end-to-end (the big one)

The `octravpn-tun` crate, `octravpn-core::onion`, the boringtun
integration in `octravpn-node::tunnel`, and the client's `connect`
flow all exist as separate pieces. None are connected:

- **Node side**: `tunnel.rs` reads UDP, runs boringtun decap, and
  *would* onion-peel + dispatch the resulting payload — but there's no
  TUN open, so an `Egress` action drops the packet on the floor instead
  of writing it to a virtual interface for kernel routing to the
  public internet. Bytes are never actually forwarded.
- **Client side**: `octravpn connect` opens an on-chain session,
  announces to the exit, and prints WireGuard config. It does not
  open a TUN device, does not capture system traffic, does not wrap
  packets in onion, does not send anything to the entry hop. To
  "actually VPN" today a user has to configure their OS WireGuard
  client manually and accept that the multi-hop onion + bandwidth
  metering never runs.

This is the single biggest gap and needs ~500-800 lines of careful
packet-pump code split between client and node, plus per-OS routing
configuration (Linux `ip route`, macOS `route`, Windows `netsh`).

### A2. `reconcile` is missing

`docs/deploy.md` references `octravpn-node reconcile` to rebuild the
local Pedersen-accumulator file from chain events. The subcommand
doesn't exist. Validators have no automated way to know what to claim
beyond manually invoking `accumulator-add` after each settlement.

### A3. `octravpn connect` doesn't establish a tunnel

Same root cause as A1 from the client perspective. The session
opens on chain, the announce happens, then it just blocks on
`ctrl-c`. There's no traffic flowing.

### A4. Health endpoint is a placeholder

`/health` reports "warming up" based on process uptime > 5s, not on
attestation freshness. Operators can't actually monitor whether the
node is healthy from this endpoint.

## Tier B — production-critical hardening

### B1. Wallet at-rest encryption

`wallet.key` is a 32-byte hex file with mode 0600. Anyone with disk
access (offline analysis, backup tape, container image leak) reads
the bond-signing key directly. Should support passphrase-protected
storage via age / age-plugin-yubikey / or a simple PBKDF2 +
ChaCha20Poly1305 envelope.

### B2. No LICENSE files

`Cargo.toml` declares `MIT OR Apache-2.0` but the repo has no
`LICENSE`, `LICENSE-MIT`, or `LICENSE-APACHE` files. Downstream
consumers can't verify the license.

### B3. Per-validator receipt audit log

Operators have no record of every receipt their node signed. If a
double-sign accusation arrives, they can't prove their innocence by
showing the canonical log. Need an append-only audit log keyed by
`(session_id, seq)` with periodic disk-sync.

### B4. Rate limiting on control plane is in the doc but not in code

`docs/security.md` mentions `tower-http` rate limit; the actual axum
router doesn't apply one. Easy to wire.

## Tier C — community / community-readiness

### C1. Missing project docs

No `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `CODE_OF_CONDUCT.md`,
or `FAQ.md`. A potential contributor can't onboard, a security
researcher can't report a vuln responsibly, downstream consumers
can't track changes.

### C2. No tutorial docs

`docs/install.md` covers install; `docs/deploy.md` covers operations.
Missing:
- "Your first session as a client (5 min)" tutorial.
- "Your first validator-VPN node (10 min)" tutorial.
- "Troubleshooting" guide.

### C3. No comparison docs

No comparison with adjacent dVPN projects (Mysterium, Sentinel,
Orchid) to position OctraVPN. Operators evaluating options can't
quickly see what's different.

## Tier D — observability / dev-experience

### D1. No performance benchmarks

No `criterion` benches. Receipt-sign/verify, Pedersen commit/verify,
onion peel, tx canonicalization — all candidates for regression
benchmarks tied into CI.

### D2. No code coverage report

No `cargo-tarpaulin` (or grcov) integration. CI doesn't surface
coverage drops.

### D3. No tracing spans on the hot paths

`tracing` is imported but most handlers emit a single `info!` and
don't open spans. Distributed tracing (OpenTelemetry export) would
make multi-hop debugging much easier.

### D4. Structured JSON logging not configurable

Logs are plain text. Production deploys want JSON-line output for
log aggregation. `tracing-subscriber::fmt::json` is a one-liner.

## Tier E — release engineering

### E1. No container images

Release workflow produces binaries, .deb, .rpm, .pkg, .msi, SBOMs.
It does NOT build + push signed OCI/Docker images. Most cloud
deployments expect `docker pull octravpn/node:v0.2.0` to work.

### E2. No Helm chart

K8s operators need a chart. Even a minimal one (StatefulSet + ConfigMap +
Service) saves them rolling their own.

### E3. No Nix flake

Reproducible builds across machines / CI / contributor laptops would
benefit from a flake. Not strictly required but a nice-to-have for
security-conscious deployments.

## Tier F — protocol refinements (post-v1)

### F1. Dispute mechanism beyond double-sign / no-show

A client who suspects metering fraud (node claimed more bytes than
served) has no on-chain path. Needs an arbitration protocol with
adverse-witness evidence (third-party attestation, traffic-pattern
matching).

### F2. Pricing tiers / regional floors

`update_validator` accepts any `price_per_mb`. A node could dump
prices to attack the market. Governance-set per-region floors would
defend against this.

### F3. Top-up running sessions

Clients can't extend a running session past their initial deposit.
They have to close and reopen, losing route continuity.

### F4. Reputation decay

`reputation` increments on settlement and never decays. A
historically-good validator can rest on past success. Add a half-life.

### F5. Treasury withdrawal entrypoint

`treasury` accumulates but has no withdrawal path. Documented as
intentional in `governance.md`; will eventually need a governance-
gated `treasury_withdraw` for grants / bug bounty.

## What's deliberately out of scope for now

These were considered and shelved:

- Mobile clients (iOS/Android). Add later.
- GUI client. CLI is the v1.
- HSM / YubiKey wallet signing. Operator-level addition.
- IPv6 throughout. Most paths take SocketAddr already; egress format
  is IPv4-only. Easy when needed.
- TCP fallback transport (for censored networks). Pluggable transports
  is a v2 milestone.
- Network Extension on macOS (proper user-space VPN). Requires
  Apple Developer Program; out of scope for an open-source project.

## Action plan for next sprint

Working through Tier A (data plane) properly is large enough that
it's its own multi-week milestone. For this immediate push the
plan is:

1. **`reconcile` subcommand** — closes A2 cleanly.
2. **Health endpoint reports real attestation freshness** — A4.
3. **Wallet at-rest encryption** — B1.
4. **LICENSE files** — B2.
5. **Audit-log skeleton** — B3.
6. **Rate limit wiring** — B4.
7. **Project docs**: CONTRIBUTING / SECURITY / CHANGELOG / CODE_OF_CONDUCT — C1.
8. **Tutorials + troubleshooting + FAQ + comparison** — C2 / C3.
9. **Criterion benchmarks** — D1.
10. **Coverage CI job** — D2.
11. **Structured JSON logging option** — D4.
12. **OCI image build** in release workflow — E1.

Tier A data-plane wiring is committed as its own next milestone
because it deserves a focused sprint with multi-machine integration
tests rather than being squeezed in alongside paperwork.
