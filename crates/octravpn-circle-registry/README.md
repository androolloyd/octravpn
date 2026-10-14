# VPN registry Circle app

Builds as a WASM Circle app and a native Rust library. The guest uses the
existing Circle ABI. `publish` and `retire` bind records to the authenticated
caller and require the current revision. `operator` is read-only.

The `host` feature adds a durable ExEx discovery index. It pins chain identity,
Circle address, code hash and replay anchor, and commits each event batch with
its index cursor. Identical replay is harmless; changed replay, gaps and invalid
revisions stop delivery. The node still needs to supply finalized Circle events.

Advertisements confer no funding or tunnel access. Confirm stake and session
eligibility through the settlement app before serving traffic. There is no VPN
protocol commission.

See [inclusion design](../../docs/octra-vpn-inclusion.md) for build and qualification.
