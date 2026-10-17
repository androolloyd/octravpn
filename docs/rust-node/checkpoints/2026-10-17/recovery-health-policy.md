# Native health admission and connected recovery

This batch separates native health admission from weighted finality. The active
set determines the distinct-peer requirement; historical stake still determines
certificate and consensus-proof weight. One heavy signer cannot replace the
configured count, and matching low-weight peers are not rejected merely for
lacking weighted source agreement. Root ties follow adopted seed-zero OCaml
table traversal.

Public startup now holds the retained node closed before peer attestation.
Constructing its initial driver grants no service or signing admission, and the
supervisor discards that generation before admitting and rebuilding it. A lone
peer hello or signed high-head hint cannot establish a persistent target. Native
ahead grace, drift, streak and soft-lag settings come from captured trusted
configuration. The initial matching one-epoch soft lag can admit before successor
data arrives; this does not promise stable service while sources withhold data.

HTTP recovery probes the consecutive signed range even if its advertised head
is stale or unavailable. It persists only the first locally QC-verified successor,
so a valid prefix cannot lend authority to an invalid suffix.

The real supervisor regression uses native execution, signed TCP replies,
canonical publication, a durable vote journal, VPN admission, Circle HTTP and
ExEx. Observer and voting cases refuse initial admission without roots, admit
matching evidence, ignore a lone exaggerated head, revoke services and stop the
driver on a conflict, then rebuild from fresh matching evidence. Canonical
history, certificates and ExEx stay intact; quarantine does not add votes.
Separate cases enforce a configured three-peer requirement and initial soft-lag
admission with no successor record available.

The payment AML already fixes operator unstake at 604,800,000 canonical
milliseconds from the first request. Retry cannot change that deadline; new
paid admission stops immediately. Payer exit and stopped-generation settlement
retain their separate 86,400,000-millisecond window. This batch rechecks the
compiled AML boundaries and the existing abstract Lean model.

Validation results and exact source hashes are recorded in
[the machine-readable checkpoint](recovery-health-policy.json).
The final target set passes 265 tests with four intentional helper/fixture
ignores. The affected node library passes all 94 tests after the corrections
below; the other 16 unchanged targets pass 171. Strict Clippy, formatting,
all 14 compiled payment AML tests and 19 abstract Lean theorems pass.

The initial combined run failed one new fixture assertion: it expected the
Circle document body in the viewer shell. The corrected test follows the
actual iframe to `/document`, verifies canonical content and checks that same
document URL is denied during quarantine. Its node rerun passes. Strict lint
then identified duplicate test modules, large constructor futures and implicit
defaults. Peer fixtures now share one module, constructor futures are boxed,
and the final affected library rerun and strict lint pass on identical source
snapshots. Initial logs and every source stage are retained in the checkpoint.

The native oracle executes unchanged adopted health_probe, Env and
Startup_runtime_limits function bodies against 1,898 inputs. Its recorded
adapters supply a root record type, controlled environment acquisition and an
unused proposal dependency; this is a host OCaml run, not a hermetic full-node
execution. The cases cover count thresholds, native hash-table ties, Int63
configuration, retries, ahead and lag policy.

This remains bounded local qualification. It does not establish complete native
health-loop orchestration, legacy nonjournaled repair, public-network recovery,
seven elapsed deployment days, AML/compiler/VM refinement or Mainnet readiness.
The public observer and its relay were not restarted by these local checks.
