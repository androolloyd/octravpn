# Tailnet User Guide

This guide walks you through everyday use of OctraVPN: creating a
tailnet, adding devices, configuring an exit node, and setting an
access policy.

If you've used Tailscale before, the workflow will feel familiar.
The differences are all on the back end (an Octra-blockchain program
instead of Tailscale's coordination server); the foreground UX is the
same shape.

## Prerequisites

- An Octra wallet with some OU.
- The `octravpn` CLI installed (`cargo install --path crates/octravpn-client`
  or grab the prebuilt binary from the latest release).

## 1. Create a tailnet

```sh
octravpn tailnet create \
    --treasury 10000 \
    --acl ./acl.toml \
    --name "my-personal-tailnet"
```

This:

1. Hashes `acl.toml` (you'll see the hash in the output).
2. Calls `create_tailnet(acl_policy_hash)` on the program with
   `value = 10000 OU`. Those 10000 OU become the tailnet's treasury.
3. Saves the tailnet id to `~/.octravpn/tailnets/my-personal-tailnet.toml`.

The wallet that runs this command becomes the **owner** and the first
member.

A minimal `acl.toml`:

```toml
version = 1

[[rules]]
action = "accept"
src = ["*"]
dst = ["*"]
```

This is the equivalent of "anyone can talk to anyone" — fine for a
single-user tailnet. For multi-user tailnets, see the ACL section
below.

## 2. Add a device

On the device you're adding (assume your laptop):

```sh
octravpn keygen --out ~/.octravpn/wallet.hex
octravpn identity
```

`identity` prints the device's Octra address. Note that address.

Back on the owner machine:

```sh
octravpn tailnet add-member \
    --tailnet my-personal-tailnet \
    --addr octABCDEF...   # the laptop's address
```

The on-chain `add_member` call is gated on the caller being the
tailnet owner.

Now on the laptop, connect:

```sh
octravpn tailnet up --tailnet my-personal-tailnet
```

This starts the mesh manager:

- Publishes the laptop's current candidates (LAN, STUN-discovered
  public address) to the peer registry.
- Pulls the current member set from chain.
- Opens a peer-to-peer WireGuard tunnel to every reachable member.
- Falls back to a paid validator-relay for unreachable peers.
- Starts the magic DNS resolver on the tailnet router IP.

Once `up` is running, you can:

```sh
ping desktop.my-personal-tailnet.octra
ssh phone.my-personal-tailnet.octra
```

Hostnames are whatever each device set with `--hostname` at startup
(default: the machine hostname).

## 3. Configure an exit node

If you want internet traffic from one device to route through another
device's connection (or through an Octra validator), use the exit-node
feature.

To exit through a fellow tailnet member (e.g. your home server):

```sh
# On the home server:
octravpn tailnet advertise-exit --tailnet my-personal-tailnet

# On the laptop:
octravpn tailnet exit-node --tailnet my-personal-tailnet --via desktop
```

To exit through a paid Octra validator (anonymous browsing):

```sh
octravpn nodes              # list available validator endpoints
octravpn tailnet exit-node \
    --tailnet my-personal-tailnet \
    --validator octV1Validator...
```

When routing through a validator, every byte is metered and paid for
from the tailnet treasury. Top up with:

```sh
octravpn tailnet top-up --tailnet my-personal-tailnet --amount 5000
```

## 4. Subnet routing

A device can expose its private LAN to the rest of the tailnet:

```sh
# On the home server:
octravpn tailnet advertise-subnet \
    --tailnet my-personal-tailnet \
    --cidr 192.168.1.0/24
```

After this, any tailnet member can reach `192.168.1.x` addresses
through the home server's tunnel. The mesh manager adds
`192.168.1.0/24` to that peer's WireGuard `AllowedIPs`.

## 5. ACLs

For tailnets with multiple users, `acl.toml` is where you express
who can reach whom. Example for a small team:

```toml
version = 1

[groups]
admins = ["oct1ADMIN..."]
eng    = ["oct2ENG...", "oct3ENG..."]
guests = ["oct4GUEST..."]

[[rules]]
# Admins can talk to anything.
action = "accept"
src = ["group:admins"]
dst = ["*"]

[[rules]]
# Engineers can SSH into anything.
action = "accept"
src = ["group:eng"]
dst = ["*"]
ports = ["tcp/22"]

[[rules]]
# Engineers can reach the prod tag on any port.
action = "accept"
src = ["group:eng"]
dst = ["tag:prod"]

[[rules]]
# Guests can only reach the kiosk.
action = "accept"
src = ["group:guests"]
dst = ["oct5KIOSK..."]
ports = ["tcp/443"]
```

After editing, push the new policy on chain:

```sh
octravpn tailnet set-acl --tailnet my-personal-tailnet --file ./acl.toml
```

This computes the canonical hash and calls `update_acl(tailnet_id,
new_hash)` on the program. Members re-fetch the document from
wherever the tailnet hosts it (HTTPS or IPFS pin) and verify the
hash matches.

## 6. Removing a device

```sh
octravpn tailnet remove-member \
    --tailnet my-personal-tailnet \
    --addr octABCDEF...
```

The removed device's tailnet IP and DNS name are immediately freed.
Active WireGuard tunnels involving the device are torn down on the
next mesh tick.

## 7. Inspecting tailnet state

```sh
octravpn tailnet info --tailnet my-personal-tailnet
```

Shows: owner, member count, treasury balance, configured exits, ACL
hash, recent session activity.

```sh
octravpn tailnet peers --tailnet my-personal-tailnet
```

Shows: per-peer connection state (Direct / Relay / Probing), the
endpoint currently in use, last-seen timestamp.

## 8. Common questions

### How does my device get its tailnet IP?

It's deterministic: every device's IP is computed from
`sha256(tailnet_id || member_address)` projected into the CGNAT
range (100.64.0.0/10). Each tailnet gets its own /22 (1024 hosts),
and the same address always lands on the same IP — no central
allocator, no conflict resolution.

### What happens if I lose my wallet?

You lose access. The tailnet membership is anchored to your wallet
address; without the wallet, the owner has to `remove_member` your
old address and `add_member` a new one for your replacement device.
This is a deliberate trade-off: the chain is your identity store,
and identity recovery is a wallet-level concern, not a tailnet one.

### Is my traffic visible to validators?

WireGuard is end-to-end encrypted. A relay validator can see that
encrypted traffic flowed (and how much) but not the contents. If
two members are talking peer-to-peer, no validator is involved at
all.

### Can I see what other devices are in my tailnet?

Yes — `octravpn tailnet peers` lists them. Tailnet membership is
intentionally public on the chain. The traffic patterns
(who-talks-to-whom) are private; the membership graph is not.

## 9. v2 substrate (circle-native tailnets)

Everything above assumes v1.1 — the original public-registry flow. v2
is the circle-native substrate that's live on devnet (program addr
`oct3fxjrzfqh65ATo31eau8xRFBPiXh2Uzwue56EYkfVSj7`). It's gated on
`[chain].protocol_version = "v2"` in `client.toml`; v1.1 configs are
untouched. The canonical client walkthrough is
[`docs/v2-client-flow.md`](v2-client-flow.md); this section covers the
member-side operational flow.

### 9.1 Provisioning a member (owner-side)

In v2, operators are **circles** (not wallet addresses) and the set of
operators a member can see is per-tailnet. The provisioning flow:

1. Owner pre-commits a **join token** so the member can self-redeem
   without exposing their address in a DM:

   ```sh
   PREIMAGE=$(openssl rand -hex 16)
   HASH=$(printf '%s' "$PREIMAGE" | sha256sum | cut -d' ' -f1)
   octra cast call $PROGRAM precommit_join_token 0 0x$HASH
   ```

2. Owner sends the member, **out-of-band** (PGP, Signal, vault): the
   token preimage and the tailnet's **sealed-policy passphrase** (the
   secret used to encrypt every authorized circle's `/policy.json`).

3. Member redeems on chain (adds them to `tailnets[tid].members[]`):

   ```sh
   octra cast call $PROGRAM redeem_join_token 0 0x$PREIMAGE
   ```

4. Owner authorizes an operator circle for the tailnet:

   ```sh
   octra cast call $PROGRAM authorize_circle 0 octE5x…dqA
   ```

After step 4, `octravpn discover v2 0` shows the operator row
decrypted and `octravpn connect-v2` can open a session against it.

### 9.2 Why one passphrase per tailnet (caveat)

The sealed-policy passphrase is **tailnet-wide today**, not per-member.
Every authorized circle's `/policy.json` is sealed under it, and every
member uses the same secret to decrypt. Trade-offs:

- **Pro**: provisioning a new member is one on-chain call plus an
  out-of-band passphrase share. No re-sealing of any asset.
- **Con**: any current member can defect — leak the passphrase and
  every authorized operator in the tailnet is decryptable by the
  recipient. Removing the leaker on chain doesn't fix this.

See [`docs/v2-threat-model.md`](v2-threat-model.md) §P1-3 for the full
defection analysis. The roadmap entry is **per-member encrypted
wraps** (each member gets their own AES key, owner rotates by reissuing
wraps and bumping `policy_version`); that lands after v2 GA.

### 9.3 Removing a member

```sh
octra cast call $PROGRAM remove_member 0 octABCDEF…
```

What the removed member loses, **going forward**:
- They can no longer call `open_session` against any circle in this
  tailnet — `register_session` rejects non-members.
- The next `policy_version` bump (rotated WG keys / new endpoint) is
  re-sealed; if you also rotate the **passphrase**, the removed member
  can't decrypt new policies.

What they keep, **retroactively**:
- Any sealed policy they already cached locally is still decryptable
  under the old passphrase. If you don't rotate the passphrase, they
  could continue resolving the operator's endpoint + WG pubkey for as
  long as those values don't change.

Practical removal flow: `remove_member` → ask each operator to
re-`circle_asset_put_encrypted /policy.json` under a freshly-picked
passphrase → distribute the new passphrase to the remaining members.

### 9.4 Per-class routing (shared vs internal)

A v2 session is opened with a **class**:

- `shared` — operator routes egress onto the public internet, charges
  `price_per_mb_shared`.
- `internal` — operator only routes intra-tailnet traffic, charges
  `price_per_mb_internal` (often 0).

Class is a member-side choice at `connect-v2 --class shared|internal`.
The operator's policy advertises both prices; the AML enforces that
the class you open under matches the class you pay for at settlement.

### 9.5 Pricing transparency

Prices are **stamped at session-open time** from the on-chain circle
registry, not read fresh on every settle. An operator who calls
`update_circle` mid-session to raise the tariff does **not** affect
any session already open — those settle at the snapshotted price in
`sessions[sid]`. Inspect live registry prices with
`octra cast circle info <circle_id>`. `octravpn discover v2 <tid>`
shows the **sealed policy's** prices; if those drift from the
registry, the registry wins at settlement.

### 9.6 Backwards compat

If `[chain].protocol_version` is `"v1.1"` (the default) the v2 commands
return a clear error and §§1–8 above keep working unchanged. To run
both flows side by side, keep two `client.toml` files and select with
`--config`.
