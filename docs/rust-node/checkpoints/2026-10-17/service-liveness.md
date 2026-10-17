# Automatic native recovery through the full Service

The previous liveness checkpoint matched native policy and exercised the real
actor with a controlled host. This follow-up exercises `recovery::Service`, the
actual Node driver host and its captured release settings together. Signed TCP
peers attest a genuine committed current root before the voting actor starts.

Only the trusted health wall clock is injectable, matching the native health
wiring's `now` dependency. The executable explicitly uses system time. Proposal
timestamps, monotonic timers, proposal grace, canonical payment timestamps and
all attestation/quarantine/finalization checks retain their production paths.
There is no network, RPC or serialized configuration option for this callback.

The regression never calls `poll_health`. Two automatic Service samples establish
a stable zero-time baseline. Advancing only that health clock to 151 seconds
makes the original live actor advance one round before its actual 120-second
protocol timer can fire. Keeping the original handle alive distinguishes this
from reconstructing a driver. Canonical history, signing floor and ExEx stay
unchanged; the actual Circle document and funded VPN permit remain available.
A real hard Node quarantine then revokes those services, closes the actor,
freezes durable votes and cannot be cleared by further matching signed peer
probes or another clock advance.

The [checkpoint](service-liveness.json) records **287 passing tests across 12
composed targets**, four standalone ignores, strict lint, explicit-file
formatting and the unchanged 19-theorem abstract payment model. The same Service
test also runs without `test-helpers`. Tests bind both the primary source scope
and all local path-dependency source snapshots. The primary docs directory and
README are excluded from the latter, except the source-map/upstream pins. The build records
its own exact source inputs and effective Cargo features. This is bounded local
Service qualification, not whole-native health-loop or public-network parity.

Independent review found no material defect in the final Service test or local
clock boundary. Initial lint rejected a redundant fixture trait-object cast;
the final code uses ordinary coercion. Deployment preparation review also found
missing local-dependency and normal-feature-test provenance, an incomplete
archive-prefix recheck, and missing child cleanup after a supervisor exception.
The prepared scripts bind all those evidence paths, rehash retained archive
prefixes even without checkpoint growth, and gracefully stop/reap a child on
supervisor failure. Their source and actual adoption results are recorded
separately; read-only review is not a deployment test.

Operator unstaking remains 604,800,000 canonical milliseconds from the first
request, payer exit remains 86,400,000 milliseconds and protocol commission is
zero. The compiled AML tests and Lean accounting/deadline model are separate
from this recovery regression; they do not prove the full VM or networking.

Public observer adoption and retained-prefix continuity require a separate
frozen normal release and supervised runtime evidence. Actual legacy
unjournaled IrminPack repair and staged crash recovery, sustained public
resource/sync qualification, stable public Circle assets, stock Tailscale paid
binding, bounded portal/funding onboarding, DNS/TLS, macOS paid routing, public
paid settlement and Mainnet remain open.
