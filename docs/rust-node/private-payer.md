# Experimental private payer service

This service runs inside the Rust node against its own canonical publication.
It resumes finite deposits and purchases from an encrypted wallet. It does not
replenish automatically, choose prices for the user, or treat an operator reply
as finality. The `private-payments-experimental` feature supports the isolated BFT application
profile and the adopted public-devnet graph. [Public-devnet service wiring](checkpoints/2026-10-20/private-public-startup.json)
is implemented and host-qualified; public stateful deployment remains
unqualified. Native Circle value rules must authenticate
their activation anchors; unsupported networks, including Mainnet, refuse.
Released shielded multihop routing and public activation remain gated.

The operator runs the existing `shielded` service. The payer adds a `payer`
object to its node configuration. That object uses
`vpn::payments::shielded::payer::startup::Config` and contains:

| Field | Meaning |
| --- | --- |
| `application`, `pool` | Independently accepted directory, immutable pool, network and verification-key pins |
| `operator_public` | Accepted 32-byte operator public key |
| `wallet`, `index` | Separate encrypted recovery directories |
| `master_key`, `relayer_key` | Existing private 32-byte files, kept outside both recovery directories |
| `proving_key` | Local Arkworks 0.5 compressed BN254 proving key for the accepted pool VK |
| `index_limits` | Finite public-index note/update resource bounds |
| `control_url`, `control_ca_pem`, `control_spki` | Accepted HTTPS origin, one CA and SPKI pins |

A nonvoting node must explicitly enable `OCTRA_OBSERVER_RELAY_SUBMITS=1`
before running a payer or route scheduler. Public startup reads this from its
captured network environment file; isolated startup reads its local environment.
The launcher refuses a private payer on a read-only observer before opening
custody or reserving a native fee. Operator-only private services can stay
read-only. This opt-in permits native transaction intake and does not grant
voting, signing authority beyond saved consent, or weaker finality.

Paths resolve relative to the node configuration. Keep a dedicated relayer for
this payer book. Its accepted fee policy is a lifetime cap, not a periodic
allowance. Test setup keys are unsuitable for real funds; production requires
an accepted ceremony and independent cryptographic review.

Build the feature explicitly:

```sh
cargo build --release -p octra-node --features private-payments-experimental
```

After deploying and initializing the accepted pool, stop the payer's node.
Initialize its new books once:

```sh
target/release/octra-node init-private-payer --config /absolute/path/node.json
```

Initialization needs an authenticated retained empty pool baseline. It creates
no listeners, submits no transactions and refuses existing stores. If a partial
initialization fails, preserve both directories and investigate; ordinary
startup never recreates a missing book.

Node startup uses `Config::prepare_with_income` and the shared `index::Handle`.
It validates existing custody, finite jobs, fee consent and proving material
before peers start, then waits for fresh canonical admission before opening the
index. A cancelled wait preserves the same books and sends no purchase request
or native transaction. Embedders already holding a fresh publication can use
`resume_with_income` directly. Offline CLI actions dispatch strictly between
public network trust and isolated genesis; both use their ordinary launcher's
captured execution graph and open no peer or HTTP services.

Prepare a private JSON array of finite requests, then import it explicitly:

```sh
chmod 600 /absolute/path/consent.json
target/release/octra-node private-payer-consent \
  --config /absolute/path/node.json --requests /absolute/path/consent.json
target/release/octra-node run-network --config /absolute/path/node.json
```

Use `run-network` for a public-devnet configuration containing `network` trust;
use `run` for an isolated configuration containing `genesis`. The offline
commands accept either supported shape and reject mixed documents.

Each request has `kind: "Deposit"` or `kind: "Purchase"`, a caller-generated
nonzero random 32-byte `id` encoded as a JSON byte array, and `terms` matching
`payer::funding::Terms` or `payer::runner::Terms`. Deposit consent fixes the OCT
amount, validity window, relayer public key and fee policy. Purchase consent
additionally fixes the target, canonical offer generation and tariff hash,
traffic class, byte count, maximum cost, channel ceiling and invoice lifetime.
No request contains a spend key or witness. Protect the input because it reveals
private relationships and amounts; retain IDs when migrating older books.

The same ID and exact terms are idempotent. Changed terms refuse. Batch entries
commit individually, so an interrupted batch must be retried with the original
IDs. Normal startup reads existing encrypted consent only; it never imports
the file again or creates replacement IDs.

A deposit has exactly one durable native signature. If its nonce is consumed or
the transaction expires, the service cannot silently sign another deposit.
Reconcile the original or explicitly authorize another ID. Spendable notes appear
only after the exact successful native exchange is canonically confirmed.
Purchases similarly recover recorded requests, signatures, receipts and change
before attempting further work.

A signed invoice may start at a newer canonical block than the payer has
imported. The runner waits for its own authenticated clock and retries the
original saved request without reserving notes or transaction fees. This wait
applies only after both signatures, offer facts, price limits and rate notice
have verified. Expired, malformed or altered quotes still fail; catch-up never
extends an invoice's expiry or grants packet capacity.

The reusable `payer::service::Service` exposes a bounded status observation and
single-pass `step` or supervised `run`. Job errors pause that job without
terminating the consensus node. Shutdown releases the index and wallet leases.
Legacy purchase records without their ID refuse automatic discovery until
`Purchase::resume` is called with the original ID; no IDs are guessed.

Transport remains a separate capability: `PreparedPrivateClient` and
`PrivatePaymentClient` hold a receipt key, authenticate funded admission, and
maintain encrypted transport recovery. The payer daemon does not automatically
install host routes or start per-hop tunnels. Funded private kernel transport,
route restart/ExEx and production privacy qualification are separate gates.
