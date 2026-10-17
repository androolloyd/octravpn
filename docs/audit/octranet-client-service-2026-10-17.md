# Reusable paid client review

The Rust `octravpn-client` library now owns the paid service used by the CLI.
Callers supply an accepted plan, receipt key, original journal, interface name
and shutdown future. The service exposes the actual interface and local
accounting summary. Host routing and process signals remain caller-owned.
The [qualification record](octranet-client-service-status.json) pins the source,
dependencies, executables, images and check results.

## Findings addressed

- Shutdown previously depended on returning to the packet loop's outer select.
  The supervisor now races the entire driver, including blocked handoff awaits,
  against shutdown and control failure. Interrupted reservations retain their
  exposure; cancellation cannot turn an uncertain send into free capacity.
- A detached control task could outlive its embedding caller. Owned task sets
  now abort control and receipt waits on cancellation. Graceful shutdown joins
  producers before waiting for actual blocking journal writes. An in-flight
  write retains its journal owner and writer lease even if its async waiter is
  cancelled.
- Recreating freshness when an opened handle starts running could renew an old
  operator status window. The initial observation now carries its original
  monotonic deadline from the authenticated response through startup and run.
- Moving the CLI's modules into a library changes the unit-test executable.
  Active Docker selectors now target the library, including the real transport
  test artifact. Demo builds use Cargo's dependency checks instead of treating
  an unchanged `main.rs` timestamp as proof of a fresh executable.

The lifecycle regressions use real durable journals and local HTTP fixtures.
They cover cancellation during open, original-journal resume with an increasing
connection watermark, blocked handoffs, control failure, retained receipts and
delayed startup. The public API is also compiled and exercised from a separate
integration-test crate. These fixtures do not open a privileged TUN. The CLI
uses the same library service in the isolated paid kernel gate.

The combined release suite passed 1,585 tests across 20 Cargo targets, with zero
failures and three designated ignored helpers. The actual Linux library test
executable passed seven migration, handshake, credit and UDP/TUN transport
checks. Strict lint, the public Rust example, formatting and the abstract Lean
build passed. A test-only lock-scope cleanup was separately rechecked after
the combined source freeze; the record lists that delta explicitly. Production
inputs remained unchanged.

The first connected attempt timed out on a one-shot UDP echo after credit
recovery. The identical runtime image subsequently passed that original oracle
with additional pre-cleanup diagnostics. The pending-nonce warnings and later
HTTP closure did not establish its cause. Source review confirms that canonical
publication deliberately suspends forwarding and can drop a datagram. The
revised gate records bounded application retries and preserves the failed run;
it makes no lossless UDP claim. Review also strengthened two independent
oracles: canonical payment must be reflected in the durable meter before the
next phase, and each later phase must add fresh authorized traffic above its
preceding counter baseline. Six focused regressions cover retry exhaustion,
duplicate matching, unrecognized responses, delayed meter credit and diagnostic
data boundaries. One-sided delivery remains held against credit; readiness
requires room for a further full-MTU round trip. Credit ceilings and revocation
probes still require no target delivery while blocked.

The final strengthened connected gate passed with five canonical claims and
626 OU of operator earnings, identical across all four ExEx sinks. The meter
restored its 32,164-byte authorization after the credit-recovery crash, and both
fresh UDP phases completed eight unique echoes. Canonical exit blocked an
established live WireGuard client. Early payer and operator withdrawals failed;
retrying operator unstake preserved its original seven-day deadline. Source and
all six runtime executables were checked against the frozen image inputs.

## Qualification boundaries

The payment application still uses a fixed seven-day operator unstake hold,
separate from the payer's 24-hour settlement window. The first request fixes
each deadline; retries preserve it. Requesting unstake immediately closes paid
admission. Actual compiled-AML tests check the maturity boundaries and claim
accounting. The 19 Lean theorems prove an abstract accounting/deadline model;
they do not establish AML/compiler/VM refinement or elapsed wall-clock maturity.

Confirmed client bytes describe local IO, signed usage describes authorization,
and remaining OU describes local capacity. None independently proves delivery,
canonical payment or chain finality. Accepted plans require independently
confirmed state. The service never deletes the original journal on cancellation.

Stock Tailscale onboarding and priced exits still need a canonical admission
adapter. The node's mesh launcher currently starts its control service
independently of payment authority. Stock packets and keys also differ from
the paid service's signed connections and packet framing. Route advertisement
alone cannot connect those paths or produce payer-signed class receipts.

When native DERP is enabled, its current loader supplies no client verifier;
the pinned backend defaults to admitting any key. Membership verification and
per-peer forwarding policy are required before that relay can enforce the
bounded unpaid portal rule. The mesh client snapshot/action helpers also still
log their intent without publishing snapshots or installing peer transport.
The existing macOS automatic paid route guard remains unavailable. These are
explicit remaining integration gates, not capabilities established by the
isolated client checks. This candidate was not deployed to public devnet or
Mainnet.
