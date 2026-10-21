# Private composite routes

`octravpn_client::MultiPrivatePaymentClient` is the experimental Linux transport
for two or three independently funded private operator hops. It shares the
public composite client's route blockers, ordered startup, MTU calculation and
owned worker shutdown. It has no payment submission path and cannot fall back
to public custody. The public route format's `shielded_required` refusal remains
in place; public plans cannot become private by changing a flag.

Provision each hop through the native private payer service first. Accept that
operator's exact private pool/directory, tariff, generation, byte cap, TLS CA and
SPKI keys independently. Use separate receipt keys and client journals at each
hop. Hops use the same chain and distinct endpoint IPs; each independently
accepted Octranet may have its own directory Circle and private pool. A provider
may operate several endpoints, so signing keys alone do not establish separate
ownership. Funding remains explicit finite consent; the route client cannot
replenish it or choose another tariff.

This API does not route the native payer's earlier purchase requests. Funding
downstream operators directly can expose the payer node's network address to
them. Fully coordinated onboarding must carry those requests through the paid
prefix while preserving the local node's authenticated chain access; see the
[coordination boundary](private-route-coordination.md). Pre-funded transport
tests alone cannot establish that onboarding privacy.

The host provides a `MultiPrivatePaymentOptions` with an absolute aggregate
journal path, `Vec<PrivatePaymentOptions>`, one `MultiRoutePins` per hop, and the
same `JournalMode` everywhere. `MultiPrivateRoutePlan::load` supports the file
adapter: each hop has `plan`, `journal`, `receipt_key`, `interface_name` and
mandatory `pins` containing `wireguard` and `control` IPv4 socket addresses.
Relative file paths resolve against that configuration file. Protect the
accepted configuration and key files; the configuration itself is ordinary JSON.

```rust,no_run
use octravpn_client::{MultiPrivatePaymentClient, MultiPrivatePaymentOptions};

async fn connect(options: MultiPrivatePaymentOptions) -> anyhow::Result<()> {
    let client = MultiPrivatePaymentClient::open(options).await?;
    client.run(async { tokio::signal::ctrl_c().await?; Ok(()) }).await?;
    Ok(())
}
```

Every control origin requires HTTPS and explicit CA/SPKI trust. Both socket
addresses are pinned before startup; operator DNS is not consulted. TLS still
authenticates the accepted hostname. Only the entry's management endpoints get
direct host exceptions. Each downstream control and WireGuard connection uses
its preceding paid interface, with a blocking fallback until that hop is ready.
All encrypted per-hop journals are prepared before the first control request.
Admission must confirm the accepted purchased floor before each TUN opens.

The aggregate identity is encrypted and binds hop order, plans, public receipt
keys, paths, names, pins and MTUs. Its key is derived from the entry receipt
secret with a separate storage domain. Preserve that key and every journal on
restart; changed terms or missing state refuse resume. The underlying storage
checks remain active while connected. This does not authenticate an adversarial
rollback of the entire host's keys and storage.

Only successful caller-requested shutdown restores ordinary host routes.
Cancellation and errors retain blockers for deliberate recovery as described
in the native VPN route guide. The conservative IPv4 profile uses MTUs 1280,
1075 and 867; it refuses oversized unfragmented payloads. Encrypted carriage
hides downstream payload from preceding operators; the final Internet exit
necessarily forwards the destination traffic and application TLS remains the
end-to-end protection beyond that exit.

The [funded two-hop checkpoint](checkpoints/2026-10-21/private-funded-multihop.json)
records both entry- and exit-limited scenarios: actual native private purchases,
nested TCP/UDP/ICMP, native chain access through the entry, original-journal
crash/restart, provider outage, finite exhaustion, ExEx agreement and independent
payer/provider accounting. Both isolated cases pass and their owned resources
were removed. Client handoffs, pending writes and retained uncertainty remain
part of the finite budget even when a provider did not observe a lost packet.

Three-hop and public multi-operator deployment remain unqualified. The
[private alpha guide](../operators/devnet-private-alpha.md) describes the
separately gated public single-operator profile. The public plan format's
`shielded_required` refusal remains unchanged.
