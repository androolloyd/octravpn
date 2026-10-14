# Tamarin protocol verification

Run `scripts/run-tamarin.sh` with Tamarin 1.12.0 and Maude installed. The script
requires the exact six lemma results, all verified, including reachable honest
traces to check that the models are not vacuous. Installation, execution, an
unknown result, a counterexample or a missing lemma fails CI.

`octravpn.spthy` checks dual-signature receipt authentication with explicit node
and client compromise exceptions. `relay_receipt_ack.spthy` checks persistence
before acknowledgement and recovery after a crash, under an explicit durable
storage assumption. These are symbolic specifications, not proofs of the Rust,
OS persistence implementation or compiled AML.

The former `octravpn-legacy-target.spthy` is archived for research. Its restrictions
assumed some properties it purported to prove, its spontaneous-slashing liveness
claim was invalid, and its anonymity claim conflicts with public registration.
It is not included in the release gate. Opaque on-chain slashing is disabled in
the candidate; no current model certifies permissionless slashing.
