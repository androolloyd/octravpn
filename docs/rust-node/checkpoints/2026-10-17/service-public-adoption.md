# Guarded normal release on the public devnet observer

The frozen normal node release `2516b7c` replaced the
previous nonvoting observer after its supervised child exited cleanly with code 0.
The [record](service-public-adoption.json) binds the binary SHA256,
Cargo artifacts without test helpers, exact source/dependency snapshots and the
[passing local qualification](service-liveness.md).

The old observer stopped at epoch 1,708,032, canonical sequence
10,272. The existing canonical and ExEx outbox prefix, every retained
archive in the captured checkpoint prefix, imported authority and consumer
checkpoint bindings were checked across that shutdown. The new observer uses
the same key, configuration, environment, databases, ports and SSH relay. There
was no database reset, forced kill, second writer or transaction spending.

The new supervised child is PID 84816. Its process identity and frozen
executable were observed alive. Startup restoration is still in progress at
this checkpoint; connection refusal during restore is not a terminal process
failure. The configured startup budget is 1800 seconds. No restart should be
triggered solely by an observation timeout. A subsequent checkpoint must show
authenticated canonical growth, matching ExEx/outbox/archive/checkpoints and
actual health admission before this release is called publicly serving.

The supervisor forwards termination signals and reaps its child on exceptions;
it has no automatic restart loop. Failed startup remains visible in its exit
record and logs. Rollback is not automatic after any new canonical commit.

Payments and VPN settlement remain unconfigured on this public observer.
This launch is not public paid-traffic, Circle asset, stock-client or Mainnet
qualification. Operator stake remains seven days, payer exit 24 hours and
protocol commission zero in the separately tested staged payment application.
