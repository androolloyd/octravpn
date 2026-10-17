# Public observer progress after guarded adoption

At 2026-10-17 12:22 UTC the existing frozen normal release `2516b7c`, PID84816,
remained alive and had advanced from epoch1,708,032/sequence10,272 to
epoch1,708,351/sequence10,591. The 319 new epochs contained 2,816 archived
transaction events. The read-only audit checked the retained
canonical/outbox/archive prefix and matching ExEx consumer checkpoint.
It does not independently reverify QCs; cryptographic admission belongs to the
running canonical publisher.

The observer returned `/status`503 while auditing canonical history, with two
peers reported by `/operator/status`. An intermediate sample at11:48:56 UTC
reported epoch1,708,208, eight peers and serving admission enabled, while its
separate `/status` request timed out. These samples establish retained progress,
not sustained public HTTP availability.

No restart, reset, identity/configuration change or transaction spending
accompanied these observations. Payments remained unconfigured. The
[record](service-public-progress.json) binds the latest audit and earlier
samples; the [adoption checkpoint](service-public-adoption.md) binds its
unchanged executable.

The prepaid and offline legacy-repair candidate is separately qualified locally
and is not installed in this observer. Public paid traffic, stable Circle
assets, stock-client onboarding/DNS/TLS and Mainnet remain unqualified.
