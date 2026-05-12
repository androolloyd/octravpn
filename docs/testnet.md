# Testnet Readiness

This document describes what OctraVPN needs from a live Octra testnet to
run end-to-end against real chain state instead of the in-process mock,
and the dry-run procedure to verify the setup before going broader.

## Status today

| Path                                | In docker / mock | On testnet today | Why the gap                                       |
| ----------------------------------- | ---------------- | ---------------- | ------------------------------------------------- |
| Deploy `OctraVPN` AML program       | n/a (mocked)     | ⚠ blocked        | Needs `octra_compileAml` and program deploy flow  |
| `register_endpoint` (validator-gated) | ✅              | ⚠ pending        | Needs `octra_isValidator` exposed by Octra RPC    |
| `create_tailnet`, `add_member`, ACL | ✅              | ✅               | Pure-AML state; no external dependencies          |
| `open_session` → `settle_session`   | ✅              | ✅               | Pure-AML state; Pedersen primitives are local     |
| Encrypted-earnings claim            | ✅              | ⚠ partial        | Needs Octra's real stealth derivation             |
| Validator-equivocation slashing     | ✅ (protocol-level) | ⚠ partial    | Needs Octra slash-evidence submission API         |
| Multi-device registry               | ✅              | ✅               | Pure-AML state                                    |
| Pre-auth join tokens                | ✅              | ✅               | Pure-AML state                                    |
| WireGuard data plane (boringtun)    | ✅              | ✅               | Independent of chain                              |
| STUN / magic DNS / mesh             | ✅              | ✅               | Independent of chain                              |
| `octravpn-admin` web UI             | ✅              | ✅               | Read-only paths work; writes need a wallet        |

The features marked ⚠ are blocked on Octra exposing specific helpers.
Everything not marked ⚠ runs unchanged against a real Octra testnet.

## Privacy analysis of the missing helpers

A reasonable concern: if `octra_publicKey` and `octra_viewPubkey` are
publicly queryable, do they leak something the protocol meant to hide?

| Helper                  | Risk?  | Why                                                                                                                                      |
| ----------------------- | ------ | ---------------------------------------------------------------------------------------------------------------------------------------- |
| `octra_isValidator`     | No     | Validator set is already public on chain (you bond publicly to join). Endpoint registration is also a public event. No new linkage.       |
| `octra_publicKey(addr)` | No     | Every signed tx already discloses the pubkey to anyone watching chain traffic. We can additionally avoid this by carrying the pubkey in the tx envelope and having AML verify `addr == derive_addr(pubkey)`. |
| `octra_viewPubkey(addr)`| No, **iff** our stealth scheme is real ECDH | The view *pubkey* is exactly analogous to a Monero public view key — by design publishable. Tag computation requires the recipient's view *secret* (or, on the sender side, the ephemeral X25519 scalar that's deleted post-send). |
| `octra_compileAml`      | No     | Compiler is account-independent.                                                                                                          |

There **was** a privacy bug in the stealth derivation that made the
third row a real problem: the implementation computed
`tag = SHA256(view_pubkey || nonce)`, which anyone with the public view
key could recompute for any `nonce` they saw on chain. That has been
fixed: `crates/octravpn-core/src/stealth.rs` now implements the
documented `shared = SHA256(X25519(eph_sk, view_pubkey))` scheme.
Property test `observer_with_only_view_pubkey_cannot_recompute_tag`
guards against regression.

The view-pubkey-derivation path was also broken: it derived from the
wallet *public* key, so the view key wasn't actually secret. That has
been fixed too — `view_pubkey = view_secret · G` where `view_secret =
HKDF(wallet_secret, "view-secret-v1")`.

## What Octra must expose for full operation

These are the missing RPC methods OctraVPN reaches for. Each has a clean
seam in the code so swapping in a real implementation is a one-line
change once the upstream method exists.

1. **`octra_isValidator(addr) -> bool`** — gates `register_endpoint`.
   The mock at `tests/mocks/src/lib.rs` implements it directly; the
   real Octra RPC must answer authoritatively. Consumer:
   `crates/octravpn-core/src/rpc.rs::RpcClient::is_octra_validator`.

2. **`octra_publicKey(addr) -> hex pubkey`** — needed for
   `verify_ed25519_acct` host helper inside AML and for the `RpcBackend`
   to verify account signatures. Current placeholder assumes the first
   32 bytes of the address ARE the pubkey; production needs the chain
   to publish the canonical mapping.

3. **`octra_viewPubkey(addr) -> hex view-pubkey`** — needed for stealth
   output derivation. Current placeholder uses HKDF over the account
   pubkey; the chain may use a different scheme.

4. **`octra_compileAml`** — already mocked. Production deployment of
   the OctraVPN program needs the real compiler. The forge tool
   `crates/octra-cli/src/forge/build.rs` already routes through this.

5. **`octra_submit` with real signature verification** — the chain
   must reject transactions whose `from` address didn't sign. Our mock
   doesn't verify signatures, but the AML program calls
   `verify_ed25519_acct` for tail-critical operations (attestations,
   ACL updates).

All consumers go through `octravpn_core::backend::OctraBackend`
(see `crates/octravpn-core/src/backend.rs`):

- `PlaceholderBackend` — refuses `is_octra_validator` with a clear
  error so production deployments using the placeholder fail fast.
- `RpcBackend` — wraps `RpcClient`; routes `is_octra_validator`
  through `octra_isValidator` as soon as the chain provides it.

## Pre-flight: running the daemons against a real Octra node

The node and client take a `rpc_url` in their TOML config. Point that
at your testnet endpoint:

```toml
# /etc/octravpn/node.toml
[chain]
rpc_url             = "https://testnet.octra.network/rpc"
program_addr        = "oct<deployed-OctraVPN-program-addr>"
validator_addr      = "oct<your-Octra-validator-addr>"
wallet_secret_path  = "/etc/octravpn/wallet.key"
```

```toml
# /etc/octravpn/client.toml
[chain]
rpc_url      = "https://testnet.octra.network/rpc"
program_addr = "oct<deployed-OctraVPN-program-addr>"

[wallet]
addr        = "oct<your-wallet-addr>"
secret_path = "/etc/octravpn/wallet.key"
```

Verify reachability first with `cast`:

```sh
octra cast rpc node_status --rpc-url https://testnet.octra.network/rpc
octra cast call <program_addr> get_params --rpc-url https://testnet.octra.network/rpc
```

If both succeed, the AML program is deployed and the RPC is healthy.

## Dry-run procedure (single device)

```sh
# 1. Verify your wallet has funds.
octra cast balance --addr oct<your-wallet-addr> --rpc-url <RPC>

# 2. Create a tailnet (read-only sanity first via list_tailnets).
octravpn tailnet list

# 3. Create one, with a tiny ACL doc + minimum treasury.
cat > /tmp/acl.toml <<'EOF'
version = 1
[[rules]]
action = "accept"
src = ["*"]
dst = ["*"]
EOF
octravpn tailnet create --treasury 1000 --acl /tmp/acl.toml --name dry-run

# 4. Inspect on-chain state.
octravpn tailnet info --tailnet dry-run

# 5. (Owner) Register a device address for this wallet.
octravpn tailnet register-device --device oct<phone-addr>

# 6. (Owner) Issue a pre-auth join token for another device.
octravpn tailnet issue-token --tailnet dry-run --hours 1
# → prints `octravpn-join-token: <base58 blob>`

# 7. (Other device, using a separate wallet) Redeem it.
octravpn tailnet redeem-token --token <base58 blob>
# → joins the tailnet without owner mediation.

# 8. Bring this device online inside the tailnet.
sudo octravpn tailnet up --tailnet dry-run
# → STUN-probes, publishes peer snapshot, listens on the tailnet IP,
#   runs magic DNS.
```

If step 3 succeeds, the chain accepted `create_tailnet`. If steps 5–7
succeed, the chain accepted device + pre-auth flows. Step 8 doesn't
need chain at all once the tailnet exists.

## What the Docker harness proves

The `docker/e2e.sh` and `docker/e2e-tailnet.sh` scripts run the same
flows against the in-process mock chain. Concretely the tailnet e2e:

1. Boots `mock-rpc + node1`.
2. Grants `node1`'s validator address Octra-validator status (mock-only
   helper standing in for the production `octra_isValidator` answer).
3. Calls `register_endpoint`, `create_tailnet`, `add_member`,
   `configure_tailnet_exit`, `open_session`, `settle_session` over
   HTTP-JSON-RPC.
4. Asserts: total_paid = 200 OU, refund = 800 OU, tailnet treasury
   ends at 4800 OU (5000 – 1000 + 800), encrypted earnings is a
   non-identity Ristretto point.

This is the bit that gives us confidence the AML semantics are
correct end-to-end. Swapping `mock-rpc` for a real Octra RPC is the
only protocol-level difference between dev and testnet.

Run with:

```sh
./docker/e2e.sh           # 3-node registration smoke
./docker/e2e-tailnet.sh   # full tailnet happy-path
```

## Test parity matrix (what we don't yet test)

These are real-Octra–only behaviors we can't exercise inside the
mock. They're explicitly listed so the testnet bring-up runbook
covers them:

| Behavior                                | Where to test            |
| --------------------------------------- | ------------------------ |
| Tx fee accounting                       | First testnet `cast send` |
| Signature verification rejecting bad sigs | Mutate the signed envelope |
| Validator jail → endpoint becomes inactive | Wait through a jail event |
| Real stealth output scanning            | `octravpn-node claim-earnings` |
| Real Pedersen `pedersen_verify_eq` host  | `claim_earnings` end-to-end |

Each line above is a discrete test the operator should run on the
first testnet bring-up.

## Quick health-check script (testnet)

Drop this in `docker/testnet-readiness.sh` and run from a workstation
with a configured Octra wallet:

```sh
#!/usr/bin/env bash
set -e
RPC=${OCTRAVPN_RPC:?set OCTRAVPN_RPC=https://...}
PROG=${OCTRAVPN_PROG:?set OCTRAVPN_PROG=oct...}

ok() { printf "  %-35s OK\n" "$1"; }
fail() { printf "  %-35s FAIL\n" "$1"; exit 1; }

echo "Probing $RPC"

octra cast rpc node_status --rpc-url "$RPC" >/dev/null && ok "node_status reachable" || fail "node_status"

octra cast call "$PROG" get_params --rpc-url "$RPC" >/dev/null && ok "OctraVPN deployed" || fail "OctraVPN not at $PROG"

octra cast call "$PROG" list_tailnets --rpc-url "$RPC" >/dev/null && ok "list_tailnets works" || fail "list_tailnets"

# is_octra_validator is the gate: if the chain answers either true or
# false (not "method not found"), we're production-ready.
if octra cast rpc octra_isValidator --params '["oct0000000000000000000000000000000000000000001"]' --rpc-url "$RPC" >/dev/null 2>&1; then
  ok "octra_isValidator available"
else
  echo "  octra_isValidator                   PENDING (chain hasn't exposed yet)"
fi

echo "Done."
```

Reading the output tells you which production paths are ready and which
require Octra to ship the missing helper.
