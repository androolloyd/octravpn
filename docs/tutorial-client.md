# Your first OctraVPN session (5 minutes)

This tutorial walks a brand-new user from a clean machine to a
3-hop session running through the OctraVPN testnet.

## What you'll need

- Linux / macOS / Windows on x86_64 or aarch64.
- ~50 MB free disk space.
- 0.5 OCT in a wallet for the session deposit (testnet OCT is free
  from the faucet at https://octra.network/faucet).
- About 5 minutes.

## Step 1 — Install

The fastest path is the one-shot install script:

### Linux / macOS

```sh
curl -fsSL https://octravpn.org/install.sh | sh
```

### Windows (elevated PowerShell)

```powershell
iex (irm https://octravpn.org/install.ps1)
```

You should see `octravpn installed.` and `octravpn --help` should
work. If anything is wrong, run `octravpn doctor`.

## Step 2 — Provision

```sh
# Pick a directory for your config + wallet.
mkdir -p ~/.octravpn

# Generate a fresh wallet, write a config skeleton.
octravpn init --dir ~/.octravpn \
              --rpc-url https://octra.network/rpc \
              --program-addr oct1xPLACEHOLDER...
```

This writes two files:

- `~/.octravpn/client.toml` — the config (rpc_url, program_addr,
  wallet addr).
- `~/.octravpn/wallet.key` — a 32-byte hex secret (chmod 0600).

The command also prints your new wallet address — copy it for the
next step.

## Step 3 — Fund the wallet

From the Octra faucet at https://octra.network/faucet, paste the
address printed in Step 2 and request 0.5 OCT (testnet) or
purchase OCT on an exchange (mainnet).

Wait ~10s for the transfer to confirm, then check:

```sh
octravpn --config ~/.octravpn/client.toml identity
```

Identity prints your wallet address and current balance.

## Step 4 — Discover validators

```sh
octravpn --config ~/.octravpn/client.toml nodes
```

You'll see a list like:

```
oct1xa…01  1.2.3.4:51820     eu-west       100 OU/MB  bond=10000000000
oct1xb…02  5.6.7.8:51820     us-east       150 OU/MB  bond=20000000000
oct1xc…03  9.10.11.12:51820  apac          200 OU/MB  bond=15000000000
```

If the list is empty, the testnet has no active validators (Octra
validator onboarding is staged; see `docs/octra-research.md`). You
can still test against the local docker-compose harness:

```sh
git clone https://github.com/octra-labs/octravpn /tmp/octravpn
cd /tmp/octravpn
docker compose up -d mock-rpc node1 node2 node3
octravpn --config docker/conf/client/client.toml nodes
```

## Step 5 — Connect

```sh
octravpn --config ~/.octravpn/client.toml connect \
         --hops 3 \
         --deposit 100000   # 0.1 OCT in OU
```

The client picks 3 active validators, opens a session on chain,
prints the WireGuard config the system tunnel should use, and
holds the session open until you press ctrl-c.

Sample output:

```
2026-05-10T08:24:18  INFO  connecting hops=3 deposit=100000
2026-05-10T08:24:19  INFO  session open submitted hash=ab39…
2026-05-10T08:24:21  INFO  session opened session_id=7f4a…

---- WireGuard client config ----
[Interface]
PrivateKey = <derive from your wallet; see docs/keys.md>
Address    = 10.66.0.2/24
DNS        = 1.1.1.1

[Peer]
PublicKey  = 91a2…
Endpoint   = 1.2.3.4:51820
AllowedIPs = 0.0.0.0/0, ::/0
--------------------------------

tunnel up; press ctrl-c to disconnect & settle
```

Apply that to your OS WireGuard client (System Preferences → Network
on macOS, `wg-quick up` on Linux, the WireGuard app on Windows).
Confirm with `curl ifconfig.me` — you should see the exit hop's IP.

> **What's actually flowing**: today, the client opens the
> on-chain session and metering paths but does not yet
> transparently capture your system traffic — you bring up
> WireGuard via your OS. The transparent-capture path
> (`octravpn connect` actually opens TUN and routes everything)
> is on the roadmap; see `docs/gap-analysis.md` § Tier A.

## Step 6 — Disconnect & settle

Press `ctrl-c` in the `octravpn connect` window. The client:

1. Tears down the local WG config.
2. Fetches the exit node's final signed receipt.
3. Submits `settle_session` on chain with the dual signature.
4. Receives a refund of (deposit − bytes_used × price) via a
   stealth output to your wallet.

Sample output:

```
2026-05-10T08:37:42  WARN  disconnect requested; settling…
2026-05-10T08:37:43  INFO  settle_session submitted hash=88a2…
```

## What to try next

- `octravpn connect --hops 1` — fastest, least private.
- `octravpn connect --region eu-west` — pin the exit region.
- `octravpn doctor` — diagnose any failure.
- `docs/economics.md` § Live mainnet snapshot — see current fee/ou
  parameters.
- `docs/tutorial-validator.md` — run your own node.
