# OctraVPN v1.1 testnet harness

> **Network reality, 2026-05.** Octra is in "mainnet alpha" — there's
> no separate testnet RPC anymore (`testnet.octra.network` does not
> resolve as of 2026-05-14). The faucet is still live, so test runs
> use faucet-funded wallets on `octra.network` itself.

This directory holds the docker-compose overlay + scripts to bring up
the three-node + one-client OctraVPN harness against the real Octra
RPC. End state: nodes register on chain, a tailnet exists, the client
opens a session, settlement completes (or you induce equivocation and
verify `slash_double_sign` works end-to-end).

## Pre-flight checklist

1. **Wallets.** Generate four with [octra-labs/wallet-gen](https://github.com/octra-labs/wallet-gen):

   ```sh
   git clone https://github.com/octra-labs/wallet-gen
   cd wallet-gen && bun install && bun run dev
   # Open http://localhost:3000 in a browser. Generate node1, node2,
   # node3, client wallets. Save each .key (32-byte hex) somewhere
   # safe — these are also your validator_addrs.
   ```

   Or via `octravpn keygen ./somefile.key` (which uses the same key
   format).

2. **Fund every wallet.** Visit https://faucet.octra.network/ and
   request faucet drops for all four addresses. Each operator wallet
   needs **≥ MIN_ENDPOINT_STAKE = 1,000 OCT (1e9 OU)** for the bond
   + extra OU for tx fees. The client needs enough OU to fund a
   tailnet treasury (≥ MIN_TAILNET_DEPOSIT = 10 OU) plus session
   deposits.

3. **Deploy `program/main.aml`.** Three options:

   a. **CLI (recommended)** — `octra forge create` now emits a real
      Octra `op_type=deploy` envelope (signature over the bare
      canonical JSON, no domain prefix) and uses
      `octra_computeContractAddress` to predict the deployed program
      address. The deployer wallet must hold at least ~55 OCT (50 OCT
      deploy fee + headroom + tx gas):

      ```sh
      # Bytecode + ABI compile-check (no chain side effect).
      ./scripts/compile-check.sh

      # Deploy: ~50 OCT fee. The caller wallet must be funded.
      octra forge create program/main.aml \
        --constructor-args 100 10 \
        --key   $(pwd)/docker/testnet/state/deployer.key \
        --rpc-url https://octra.network/rpc
      # Output:
      #   {
      #     "address":  "oct…",
      #     "tx_hash":  "…",
      #     "name":     "OctraVPN",
      #     "compiler": "OCTB v1 …"
      #   }
      ```

      The fee can be overridden with `--ou <OU>` (1 OCT = 1_000_000 OU).
      Constructor args become the tx's `message` field as a JSON-encoded
      array. Save the printed `address` for the `PROGRAM_ADDR` setting
      below.

   b. **Octra web client.** Open the wallet web client, import the
      `program/` directory, compile with language = `AppliedML`, enter
      constructor params `[min_session_deposit=100,
      min_tailnet_deposit=10]`, deploy. Copy the deployed program
      address. Equivalent to (a); kept here for users who prefer a GUI.

   c. **Pre-deployed test program.** If someone in your org already
      deployed v1.1 to mainnet alpha, reuse their address. Confirm
      with:

      ```sh
      curl -s -X POST https://octra.network/rpc \
        -H 'Content-Type: application/json' \
        -d '{"jsonrpc":"2.0","id":1,"method":"vm_contract","params":["oct…"]}'
      ```

   Save the resulting program address.

## Config setup

```sh
cd octra
cp docker/testnet/.env.example docker/testnet/.env
cp docker/testnet/hosts.env.example docker/testnet/hosts.env

# Edit both .env files:
$EDITOR docker/testnet/.env       # set PROGRAM_ADDR
$EDITOR docker/testnet/hosts.env  # set the four wallet addresses + public endpoints
```

Drop the 32-byte hex wallet + WG keys into the right state dirs
(create the dirs if they don't exist):

```sh
for n in node1 node2 node3; do
  mkdir -p docker/testnet/state/$n
  cp /path/to/$n-wallet.key docker/testnet/state/$n/wallet.key
  openssl rand -hex 32 > docker/testnet/state/$n/wg.key
  chmod 600 docker/testnet/state/$n/*.key
done
mkdir -p docker/testnet/state/client
cp /path/to/client-wallet.key docker/testnet/state/client/wallet.key
chmod 600 docker/testnet/state/client/wallet.key
```

Render the per-node configs:

```sh
./docker/testnet/render-configs.sh
```

Pre-flight all of the above:

```sh
./docker/testnet/preflight.sh
```

Expected: every check `[ok]`. If anything fails, fix it before
bringing nodes up.

## Bring up

```sh
docker compose \
  -f docker-compose.yml \
  -f docker/testnet/docker-compose.testnet.yml \
  --profile testnet up -d node1 node2 node3
```

Watch the logs:

```sh
docker compose logs -f node1 node2 node3 | grep -E "register|bond|stake|settle"
```

The default startup sequence in `octravpn-node run` is bond → register
→ serve. On first boot, each node will:

1. `bond_endpoint` with `MIN_ENDPOINT_STAKE` from its wallet balance.
2. `register_endpoint` with its receipt_pubkey (HKDF-derived from
   `wg.key`).
3. Begin serving the control-plane HTTP surface and the WireGuard
   listener.

Confirm the three endpoints landed:

```sh
curl -s -X POST $OCTRA_RPC_URL \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$PROGRAM_ADDR\",\"list_active_endpoints\",[0,50]]}" | jq
```

You should see node1/node2/node3 addresses in the result.

## Happy-path session

```sh
# Stand up a tailnet (signed by the client wallet) with 1000 OU treasury.
docker compose --profile testnet run --rm client \
  /usr/local/bin/octravpn tailnet create --treasury 1000 --acl /etc/octravpn/acl.toml --name testnet-1

# Configure one node as the exit.
docker compose --profile testnet run --rm client \
  /usr/local/bin/octravpn tailnet configure-exit --tailnet 1 --exit oct…node1

# Connect (one-shot — settle automatically on ctrl-c).
docker compose --profile testnet run --rm client \
  /usr/local/bin/octravpn connect --hops 1 --deposit 100
```

Inspect the resulting on-chain session:

```sh
curl -s -X POST $OCTRA_RPC_URL \
  -H 'Content-Type: application/json' \
  -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$PROGRAM_ADDR\",\"get_session\",[1]]}" | jq
```

## Equivocation slash (v1.1 — the new path)

The off-chain `slash_double_sign` path needs a third-party "slasher"
who's collected two signed receipts that contradict each other.
Drive the scenario by:

1. **Capture two receipts.** Either:
   - Run a buggy node that signs two contradictory receipts (set
     `OCTRAVPN_SIM_DOUBLESIGN=1` in node env to enable the test-only
     equivocation simulator — see `crates/octravpn-node/src/control.rs`).
   - Or hand-craft two signed payloads using the same node's wg.key.

2. **Build the evidence blob.** From the slasher's machine:

   ```sh
   octravpn slash-evidence build \
     --endpoint-addr   oct…the-bad-node \
     --receipt-pubkey  $(cat node1.wg.pub.hex) \
     --session-id      <32-byte hex session id> \
     --seq 1 \
     --bytes-a 100 --blind-a aa…  --sig-a $sig_a \
     --bytes-b 200 --blind-b bb…  --sig-b $sig_b \
     --out equivocation.json
   ```

3. **Verify + submit.**

   ```sh
   octravpn slash-evidence verify equivocation.json
   octravpn slash-evidence submit equivocation.json
   ```

   The submit step calls `slash_double_sign` on chain. On success
   the slasher wallet receives the 10 % bounty; the operator's bond
   is burned to program treasury; the endpoint is marked inactive.

   Confirm with:

   ```sh
   curl -s -X POST $OCTRA_RPC_URL \
     -H 'Content-Type: application/json' \
     -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"contract_call\",\"params\":[\"$PROGRAM_ADDR\",\"get_endpoint\",[\"oct…bad-node\"]]}"
   # `active` should be 0; `slashed` should be 1.
   ```

## Tear down

```sh
docker compose --profile testnet down
```

Wallet keys and state remain on the host (the volumes are
host-mounted on purpose so a restart resumes).

To reclaim staked OU after testing, each operator runs:

```sh
docker compose --profile testnet exec node1 octravpn-node unbond
# wait for UNBOND_GRACE epochs…
docker compose --profile testnet exec node1 octravpn-node finalize-unbond
```

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `preflight.sh`: RPC unreachable | network or octra.network down | Try the explorer proxy: `OCTRA_RPC_URL=https://octrascan.io/rpc` |
| `register_endpoint` reverts with `must bond_endpoint first` | bond tx hadn't confirmed yet | Wait an epoch, run `octravpn-node register` again |
| `register_endpoint` reverts with `receipt pubkey required` | running a pre-1.1 node binary against a v1.1 program | Rebuild with the current main branch |
| client `tailnet create` reverts with `tailnet deposit below min` | `--treasury` value < MIN_TAILNET_DEPOSIT | Use `--treasury 10` or higher |
| `slash-evidence submit` reverts with `operator has no receipt pubkey` | target was registered against a v1 program (no receipt_pubkey on file) | Targets must be running v1.1; re-register them first |

## What's NOT covered by this harness (v2)

Hidden-operator identities (Circles), per-class ACL routing, encrypted
byte counters, multi-hop session escrow. These are gated on Octra
publishing the Circle DSL — see [`../v2-circles-design.md`](../../docs/v2-circles-design.md).
