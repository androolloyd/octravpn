# OctraVPN canary security review — 2026-10-11

The v5 canary is prepared for a **zero-escrow mainnet qualification**. No public
transaction has been submitted. A funded relayer and successful stateful proof
execution on the target network remain required. This is an agent-led source
review and regression campaign, not an independent audit or a proof of the whole
VPN, compiler, consensus engine or cryptographic stack.

## Findings and disposition

| Finding | Impact | Change / remaining scope |
| --- | --- | --- |
| WireGuard identity was not bound to the packet's funded session | An admitted peer could choose a different session ID | Authorization stores the signed announce, session ID and absolute 120-second lease; dispatch checks identity, session and expiry before routing |
| Established peers survived revocation; traffic refreshed idle TTL | Service could continue after authorization was removed | Every packet rechecks the lease; revoked/expired established peers are removed; a bounded concurrent sweeper refreshes against current chain admission and fails closed on unavailable RPC |
| Reannounce reset receipt state and retained old WG bindings | Receipt discontinuity and old-key access | Preserve receipt sequence/blinding; remove replaced WG key; reject client identity changes and rebinding a live WG key to another session |
| Anonymous handshakes scanned every allowlisted key | CPU work increased with the session table | Verify MAC/cookie, recover the authenticated static key once, then perform one allowlist lookup; share and refresh WG rate-limit state |
| Route/key caches were unbounded | Long-lived memory growth | Hard route/key capacity; idle key eviction and zeroization after the last reader; expired control entries remove their associated route |
| UDP egress accepted operator LAN / metadata destinations | An admitted peer could target internal services | Reject private, loopback, link-local, CGNAT, multicast, benchmark, documentation and reserved IPv4 ranges, plus port zero |
| Inter-hop forwarding sent raw UDP; client command does not start an onion transport | The claimed encrypted multi-hop service is incomplete | Raw forwarding now drops packets. Custom onion framing, authenticated inter-hop funding/transport and bidirectional client traffic remain implementation blockers for that service; native Tailscale evidence from the earlier review does not certify this path |
| A former admin credential could be accepted again | A compromised former holder could regain authority | Record accepted commitments; reject reuse. Cancellation does not consume an unused recipient commitment |
| Pause blocked existing fund recovery | Lost admin access could immobilize user/operator balances | Allow existing settlement, refunds, retirement, unbonding and earnings/treasury exits while admission remains paused |
| No canary funding ceiling | An RC could accumulate unrestricted escrow | Immutable ninth constructor argument: 200,000,000 OU for this canary; all six payable funding methods check native balance including attached value. Boundary and rollback verified in the native host |
| Credential/key/request file reads had separate metadata/read steps and incomplete bounds | File replacement, symlinks or oversized input could bypass intended checks | Open one regular file without following symlinks, check its permissions/size, bound growth during read; wipe credential buffers |
| h2, rustls, tracing-subscriber and event-listener advisories | Network DoS, log injection and concurrency unsoundness | Pin patched releases in Cargo.lock. Vendor ark-relations 0.5.1 with only the tracing dependency/callback update; no R1CS or algebra changes |
| Native receipts omit factory return values | The deployed child address could not be recovered reliably | Factory emits VPNDeployed(child); the native host verifies the emitted address equals the returned child |
| CLI parity could accept two killed children | A timeout could falsely look like matching behavior | Bounded worker pools, a realistic child timeout, and explicit rejection of missing exit codes; all 16 comparisons passed |

The funding ceiling covers value admitted by contract methods. Native transfers
sent directly to any program address cannot be rejected by AML and may push the
actual balance above the ceiling. Do not fund the address directly. Keep wallet
budgets bounded and inspect live balance; this change is not a consensus-level
receiver restriction. The ceiling is immutable and cannot be raised by set_params.

## Current verification

- **1,682 Rust tests passed, 0 failed**, across the completed non-node workspace,
  final node unit suite and all final node integration suites. Four tests remain
  explicitly ignored: three long sidecar stress cases and the privileged Linux
  kernel-WireGuard lifecycle.
- Strict workspace all-target/all-feature Clippy passed; the final node fixture
  revision also passed its all-target/all-feature check.
- **127 native security checks passed** with real Groth16 proofs, the native AML
  compiler/VM/worker, journal rollback and Irmin restart. The finalized factory's
  child-address event is also asserted at each deployment. Latest rehearsal uses
  the retained development CRS and fresh, temporary actor credentials.
- **23 v5 + 18 v4 AML tests passed** using real production method bodies, alongside
  three failing negative controls and empty-selection rejection.
- Seven deployment-state/metadata mutations and missing factory evidence were
  rejected by the read-only verifier; v5 requires an explicit expected fund cap.
- Six hermetic canary-runner controls passed: normal qualification, unfunded
  relayer, wrong child code, ambiguous child event, accepted replay, wrong cap.
  These tests verify orchestration, not public-chain execution.
- cargo audit reports **zero known vulnerabilities** against the local RustSec
  database refreshed 2026-10-09. cargo deny advisory/license checks passed.
  derivative and proc-macro-error2 still have documented build-only maintenance
  exceptions; their notices are not suppressed as runtime vulnerability fixes.

An initial workspace run timed out 13 standalone CLI comparison children.
Direct reproduction matched, the isolated rerun passed, and the final integration
run passed after tightening timeout handling. That initial failed run is not
counted as passing evidence.

Existing bounded TLA/Kani/Tamarin/Lean results remain scoped to their models and
previous source assumptions. No new end-to-end formal proof of AML execution,
the circuit, the new lease policy or the transport is claimed here.

## Mainnet target and RC limits

The [official wallet source](https://github.com/octra-labs/webcli/blob/main/wallet.hpp)
selects https://octra.network/rpc. Read-only probes found a responding
v3.0.0-irmin node. The endpoint compiled the finalized v5 and factory with **zero
safety-verifier errors and zero duplicate branch labels**. Its ten v5 warnings
concern allowed zero-valued identifiers, the initial nonce, zero fee and the
unbounded-cap sentinel; the canary uses a nonzero cap. The endpoint does not expose
octra_runtimeVersion, so chain/genesis/profile identity and public finality have
not been independently pinned. Compilation is not evidence that stateful proof
operations are active across validating nodes.

Proposed native SIX-decimal economics:

| Parameter | Canary |
| --- | --- |
| Minimum session / tailnet deposit | 1 OCT each |
| Minimum operator stake | 100 OCT |
| Funding-method balance ceiling | 200 OCT including stake |
| Session / unbond grace | 100 / 1,000 epochs |
| Qualification escrow | 0 OCT |
| Qualification calls | Factory creation, child spawn, private pause, replay rejection, private unpause |
| Default declared qualification fees | 5 × 1,000 OU = 0.005 OCT |

The fresh relayer is `oct8qxdTZc4Tk8ZDkLHXm1HjNXmytRnCMzhxEBnCVtJJ69Q`.
The official RPC returned sender-not-found for it; it is unfunded. Its key and a
fresh admin credential are in the ignored mode-0700
`out/canary-local-secrets-20261011/` directory; each secret file is mode 0600.
The retained setup is explicitly single-party **development-only**. It is suitable
for the requested disposable RC exercise under these limits, and does not qualify
an unrestricted release. No secret is included in the public candidate/evidence.

## Runbook

The 2026-10-12 zero-commission candidate supersedes the earlier fee-charging
candidate. The runner rejects that older candidate. The public candidate is in `out/mainnet-canary-no-fee-candidate-20261012/`; target compiler
responses are in `out/mainnet-canary-no-fee-preflight-20261012/`.

```sh
python3 scripts/ceremony/deploy-canary.py \
  --candidate out/mainnet-canary-no-fee-candidate-20261012 \
  --preflight out/mainnet-canary-no-fee-preflight-20261012
```

After the relayer is funded, the explicit broadcast mode performs qualification
with zero attached value, bounds declared fees, verifies code/metadata/private
initialization and records each submitted transaction before waiting:

```sh
python3 scripts/ceremony/deploy-canary.py \
  --candidate out/mainnet-canary-no-fee-candidate-20261012 \
  --preflight out/mainnet-canary-no-fee-preflight-20261012 \
  --key out/canary-local-secrets-20261011/relayer.key \
  --credential out/canary-local-secrets-20261011/admin.credential \
  --setup out/canary-local-secrets-20261011/setup \
  --out out/mainnet-canary-live-qualification-no-fee-20261012 \
  --broadcast
```

Stop on a failed/unknown outcome. Inspect journal.json, in_flight and recorded
transaction hashes before any retry; use a fresh output directory only after
resolving prior submissions. The runner does not register a circle, deposit stake,
fund a tailnet or activate VPN service. Fund/operate a single controlled canary
only after qualification and the native circle-owner/onboarding checks pass.
Keep all native transfers explicit, remain below the funding-method ceiling,
and rehearse pause, user recovery and private handoff before expanding activity.

Unrestricted deployment still needs independent circuit/security review, a
verified multiparty setup, credentials backup and operator procedures, selected
network/finality evidence, and tested production transport. **No consensus rule
was changed during this review.**
