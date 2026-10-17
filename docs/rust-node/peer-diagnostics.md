# Local peer connection diagnostics

`GET /operator/peers` includes an additive `connections` snapshot. The native
`octra_consensusPeerStates` result and all admission, retry and handshake rules
retain their existing shape and behavior.

The snapshot contains the current swarm generation, running/proxy state,
bootstrap and peer-record dial counts, and nonzero outcome counters. Each row
has a direction, phase, outcome and saturating `u64` count. Counters reset at
run startup; late completions from an earlier generation are ignored.

Phases distinguish transport establishment, authenticated handshake, local peer
admission and an established session. Fixed labels distinguish TCP refusal,
SOCKS refusal/denial/unreachable/TTL/protocol replies, handshake identity,
signature, configuration, membership and frame failures, local capacity and
duplicate decisions, and session closure, timeout, reset, frame budget and
cancellation. A successful transport alone does not establish peer admission.
Counters describe events at each phase; they are not a count of unique peers
or a traffic/payment meter.

Diagnostic storage is bounded by the direction/phase/outcome enum product.
The connection snapshot contains no endpoint, identity, key, frame payload or
remote error text. Classification inspects bounded known reasons with the
outer handshake reason taking precedence over peer-controlled text. SOCKS REP
capture is internal: the public connector returns its existing errors and has
no direct fallback. A session completion guard is created before enqueueing,
so cancellation of an unpolled task is counted once.

Checkpoint reopening also releases a fully authenticated floor tree before
restoring a different current head. It retains the existing certificate,
history/outbox, floor-object and current-object checks. This removes avoidable
simultaneous tree retention; it is not a measured production memory bound.

The [checkpoint](checkpoints/2026-10-17/peer-recovery-diagnostics.json) records
exact source stages, combined validation and the separately adopted public
observer image. The new diagnostics require that image to be installed before
they can explain live connection churn. Positive legacy nonjournaled fork
repair still needs a real legacy storage adapter and staged restart lifecycle;
canonical history, certificates, signing floors and ExEx cannot be rewound.
