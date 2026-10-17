# Prepaid Octranet revision and adversarial boundary

This revision replaces postpaid credit with an explicit advance purchase of
per-class bytes. It is a new candidate; earlier payment checkpoints retain their
own source pins and do not qualify it. The
[frozen-source checkpoint](octranet-prepaid-status.json) records 1,719 passing
tests across 20 targets, four intentional helper ignores, strict lint,
formatting, six qualification-oracle tests and all 39 bounded Lean theorems.
The normal-feature release build and Service regression also pass.

The final isolated Linux gate passes with four validators and two endpoint
kernels. It checks canonical purchases before forwarding, zero unpaid traffic,
client/operator crash recovery, TCP/UDP/ICMP, finite class exhaustion with a
still-funded positive control, partial-withdrawal revocation, immediate full
withdrawal, reuse of exit earnings and matching canonical ExEx records.
Exact 24-hour rate activation and seven-day unstake boundaries use separate
compiled AML and canonical-state tests; the kernel clock was not fast-forwarded.
All final checks bind unchanged source and local dependency snapshots.

The payer accepts finite immutable class targets within an original budget.
The client persists exact purchase signatures before sending them. The native
operator waits for exact authenticated canonical purchased bytes before any
packet reservation. Delivery, pending handoffs and uncertainty consume that
allowance separately. There are no credit limits, unlimited fallback or
operator-triggered top-ups. Old postpaid signatures and journals are rejected.

Independent adversarial review identified and addressed these boundaries:

- A fully purchased monetary budget must not revoke remaining bought bytes.
- A zero-rate or same-rounded-price class still needs its exact canonical byte
  authorization; paid OU alone cannot manufacture further capacity.
- One exhausted class must drop its packets without stopping still-funded
  classes. Lease/persistence failures remain fatal.
- Restart and lost HTTP responses must reuse exact purchase authorizations and
  retained consumed/uncertain capacity, without repurchasing or resetting it.
- Held signatures must not buy unusable bytes after payer exit or operator stop.
  Those transitions revoke new purchases immediately. Available channel OCT is
  withdrawable immediately; the operator's seven-day stake hold remains separate.
- Full withdrawal closes the account; partial withdrawal advances its generation
  and clears old reservations. Canonical purchase/withdrawal ordering prevents
  held signatures from spending the remaining or subsequently funded balance.
- Exit earnings are available for outgoing purchases without leaving contract
  custody. Internal balance netting must conserve all liabilities, including
  same-account purchases and withdrawals after incoming earnings.
- Replacement quote activation is delayed by a full 24 hours. A cancelled or
  superseded pending quote cannot later activate; old purchases keep their price.
- The kernel test must prove depleted durable class capacity and a successful
  other-class positive control before negative exhaustion/revocation assertions.

## Delivery claims are separate from prepaid settlement

A signed purchase establishes spending consent, not packet delivery. Dropping a
packet and forwarding it before a downstream failure can leave identical chain
evidence. Withholding a payer acknowledgment is indistinguishable from missing
service. The current application cannot slash selectively for those cases.

Purchases credit operator earnings that can be withdrawn or spent on traffic.
Payer withdrawal returns only OCT still in the channel, not unused bought bytes;
settled purchases are final. The seven-day bond hold
has no predicate for outstanding delivery obligations or compensation. The model
is not delivery insurance: a malicious operator can accept a valid purchase
without fulfilling it.

Narrower objective faults could be specified, such as conflicting signed
obligations or missing a valid on-chain challenge response deadline. Such a
promise proves its own breach, not arbitrary Internet availability. No trusted
arbiter/witness fallback, invented delivery proof or non-delivery slash was added.
A product promising trustless non-delivery protection would require a verifiable
service obligation, its expiry and collateral rules, and actual enforcement.

The Lean model covers abstract accounting, deadlines and separate prepaid
capacity transitions. Compiled AML tests and real packet tests provide distinct
implementation evidence. No compiler/VM refinement or destination delivery proof
is claimed. Public paid service, stock Tailscale, onboarding, DNS/TLS and Mainnet
remain separate open gates.

The local release package contains unsigned Legacy builds of the application
and deployment-only factory. The application bytecode SHA-256 is
`2e3931d07ff53c27fe472ec06b3a3e9ff9f1ac21bb2f4f1d9b697031484604aa`;
the macOS coordinator and isolated Linux compiler emitted the same bytes.
No source was submitted to a public compiler, no public funds were spent,
and the running public observer was not restarted for this candidate.

Initial failures remain in the local evidence: private helper-directory
permissions, premature kernel admission before canonical Serving, a duplicate
test match arm, and Lean record syntax/proof witnesses. The final runs repair
those failures without weakening admission or proof assertions. The first
channel kernel run passed functionally but preceded the test-only lint fix;
`connected-4` binds the final complete source snapshot.
