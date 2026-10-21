# Prepaid custody in a Circle

The Circle-first payment candidate uses the unchanged adopted native OCTB Circle interpreter.
It adds no consensus rule, opcode or WASM clock import. OCTB Circle calls already
receive the admitted epoch timestamp in milliseconds, and native value effects
are available only with active ProofExecution rules and matching code admission.
Existing configurations retain the Program default for compatibility; new
Octranet deployments explicitly select `application: "circle"`.

`octra-node compile-circle-payments --config network.json --custody-cap 200000000
--minimum-stake 100000000` derives source from `program/octranet-payments.aml`.
The CLI derives the distinct Circle receipt domain from the configured full
chain origin. `--domain` remains available for offline fixtures.
Strict constructor/declaration markers and parsed public method names fail closed
on source drift. All original method bodies remain unchanged behind an added
initialization guard. The generated source and original/template hashes accompany
the raw OCTB build. Program source syntax does not confer typed Program authority.

The generated code pins domain, custody cap and minimum stake as constants.
The native Circle factory emits `PaymentsCircleDeployed(child)` after requesting
parent-owned spawn. Native spawn installs the child only after that parent call
succeeds. It does **not** execute a constructor or permit a same-call child init.
Deploy and initialize therefore require **two finalized transactions**. Call the
child's no-argument `initialize` before offering custody; another caller may do
this first, but can install only the identical code-pinned terms. The call is
idempotent. All other public methods, including financial methods and views,
refuse until initialization. An ordinary OCT transfer to the address is a donation,
not an account deposit or purchased allowance.

A Circle service configuration explicitly selects the application kind inside
its existing `payments.application` object:

```json
{
  "application": "circle",
  "program": "CONFIRMED_PAYMENT_CIRCLE",
  "code_hash": "EXACT_DECODED_OCTB_SHA256",
  "factory": "CONFIRMED_FACTORY_CIRCLE",
  "factory_code_hash": "EXACT_FACTORY_OCTB_SHA256",
  "domain": "CIRCLE_KIND_FULL_CHAIN_ORIGIN_DOMAIN",
  "operator_circle": "PUBLIC_TARIFF_CIRCLE",
  "offer": 0
}
```

Use `payments::application_domain(chain, Application::Circle)` for the domain;
its distinct tag prevents Program receipts/journals from becoming Circle authority.
The `program` wire field remains the deployment address for client compatibility.
Omitting the kind retains the original Program semantics and serialized identity.
The adapter checks the actual Circle runtime, bytecode hash, parent factory owner,
current call-code marker, stable root and canonically encoded keyed stable fields.
Its Node-owned rule graph independently checks active value capabilities against
retained authenticated history. Claims use and durably bind `CircleCall`; legacy
claims retain `ContractCall`. Neither an RPC response nor an operator assertion
can substitute for a canonical prepaid byte floor.

The custody Circle runs bonding, funded channels, offers, purchases, claims,
withdrawals and operator earnings. An operator-owned Circle publishes the
hash-pinned tariff, public site assets and any sealed endpoint policy. A portal
Circle publishes the exact allowlisted unpaid onboarding assets. The native
gateway reads those committed assets; the Rust transport worker owns WireGuard,
TUN, packet classification and metering. Circle WASM can provide bounded query,
update and HTTP-handler logic, but its host has no socket or TUN import; the
current gateway uses committed assets, not a dynamic WASM portal handler.
Keep the factory-owned custody Circle separate from operator-editable content
so an operator cannot replace the code holding payer funds.

Seven-day operator unstaking, instant channel withdrawals, immutable purchases,
24-hour replacement-rate notice and zero protocol commission are retained from
the common custody implementation. Native fixed Circle size limits still apply.
Purchased service is not an insured-delivery promise; no arbitrary Internet
non-delivery proof is introduced. Every new offer requires a bond-generation
operator receipt key. Two different operator-signed byte totals for the same
plan, class and sequence are an objective equivocation proof: anyone can submit
both signatures while that generation's bond is still locked. The entire bond
becomes an award for the affected payer, locked until the original unstake
deadline or seven days after a slash that preceded unstaking. The operator
stops serving, and that generation cannot be slashed again. A purchase
signature or failed connectivity probe is not such proof. The seven-day unstake
is the evidence-submission window; after stake withdrawal there is no bonded
recourse for a late proof. Delaying award withdrawal prevents an operator from
self-slashing through a second payer wallet to escape the seven-day lock.

Qualification sources include real Circle transaction/ledger regressions, a
signed-QC canonical Node fixture and an unchanged-native compiler/epoch oracle.
The oracle retains one native store and Ledger across independent admitted epochs
for exact day/week boundaries, first-request unstake retries, replacement-rate
activation, rescheduling and cancellation; it grants no QC/finality authority.
Generate the latter with `scripts/node-port/circle-prepaid-fixtures.py` using the
exact candidate's build JSON, then retain the actual result as
`crates/octra-node-runtime/tests/fixtures/circle-prepaid.json`. Ordinary CI replays
that source-bound artifact; `OCTRA_CIRCLE_PREPAID_ORACLE` explicitly selects an
alternative artifact for regeneration checks. These sources are not results;
public activation, paid stock-client transport and deployment remain separate gates.
A future atomic Circle constructor would be a distinct experimental capability,
not a reason to alter the adopted native baseline for this application.
