# P2P upgrade wiring review

Public startup previously discarded the adopted upgrade/rollback schedule by
passing `upgrade: None` to the swarm. It now captures the trusted native inputs
and passes the parsed schedule to the existing transport implementation.
Private Single has an optional JSON adapter using the same parser; existing
configuration defaults are preserved.

The BFT validator also restores the adopted readiness check before new votes,
proposals and pending-vote broadcasts. The cached value binds the selected
canonical parent, next epoch, actual validator selection, pending schedule,
captured program trust, crypto engine and runtime profile. Relief retains the
pending commitment before activation; matching activation clears it. Schedule
inputs cannot come from peers. A mismatch logs its reason when it changes and
blocks voting while authenticated finality following remains available.

Adversarial review caught an intermediate implementation comparing the target
with the active **transport** hash. Native voting readiness instead compares
the **consensus** configuration hash. The corrected adapter keeps those domains
separate and never substitutes a target hash for the locally resolved value.
Review also traced signing, proposal, pending-vote and finalized-vote persistence
paths. Signed round-sync requests and persistence of already emitted finalized
votes retain the adopted behavior.

The [machine-readable checkpoint](p2p-upgrades.json) records exact source and
log hashes, commands and validation boundaries. The combined release run passed
236 tests across 14 targets, including the four-validator executable restart,
observer recovery, private Single crash/restart, canonical VPN/ExEx services
and all 14 compiled payment AML tests. A final focused run checks the affected
libraries, TCP upgrade tests, native differential cases and AML after lint fixes.
Strict Clippy includes `octra-node/test-helpers`; shared test fixtures are loaded
once and large test setup futures are boxed. No lint is suppressed for the new
code.

The new differential fixture contains 496 cases: absent/disabled/orphan inputs,
partial pairs, native signed-64-bit epochs and trimming, hash representations,
validation priority, independent configuration defaults, and activation and
rollback boundaries. All 1,158 adopted source hashes were verified at
`7f9be4489870645cfcc95439638cde40f5da9f50`. Because the earlier native Docker
builder was unavailable, the recorded host OCaml 4.14.2 toolchain compiled the
exact native dependency sources. Only a recorded environment-getter prefix
supplies per-case inputs; original parser bodies remain unchanged. Compiler,
package artifacts and executable hashes are retained. This verifies the parser
and its observations, with no hermetic-build or process-environment-acquisition
claim.

Operator unstake remains fixed at seven days from the first request; payer exit
remains 24 hours. The compiled AML boundary test passed again, and the 19-theorem
abstract accounting/deadline Lean model builds. Those proofs do not establish
compiler/VM refinement or seven elapsed days on a public deployment.

The binary identity is trusted operator configuration, without executable
attestation or automatic installation. Public upgrade deployment, sustained
public sync/recovery, constrained stock-client relay/admission and the paid
stock-client adapter remain release gates. This batch leaves the running public
observer in place and deploys no Mainnet contract.
