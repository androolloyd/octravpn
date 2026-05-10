# Tamarin model for OctraVPN

`octravpn.spthy` models the OctraVPN crypto-protocol surface under a
Dolev-Yao adversary. Tamarin checks unforgeability and slashing properties
mechanically.

## Properties

- **ReceiptUnforgeability** — settled receipts always trace back to a real
  client signature or a compromised session key.
- **DoubleSignSlashable** — two distinct validator signatures for the same
  `(session, seq)` always yield a slash trace.
- **NoLinkBeforeSettle** — no observation by the network adversary
  reveals the validator address for an open session without compromising
  the long-term key (the route commitment hides it).

## Running

```
tamarin-prover --prove octravpn.spthy
```

The model intentionally simplifies the multi-hop case to single-hop. The
extension to N hops is structural: each hop adds an independent commitment
and an independent receipt sig path; the unforgeability lemma generalizes
unchanged.

## Adversary capabilities

- Network read/write (Dolev-Yao) — `In` and `Out` facts.
- Static-key compromise — `Reveal_Validator` reveals a chosen validator's
  long-term key.
- Session-key compromise — `Reveal_Session` reveals a chosen session's
  ephemeral key.

This matches the real-world threat model: an attacker can break into a
node OS or steal an ephemeral key from a client; the lemmas characterize
exactly what must hold *unless* such a compromise occurs.
