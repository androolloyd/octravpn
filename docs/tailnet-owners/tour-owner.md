# Tailnet-owner tour

A guided walkthrough for the **tailnet owner** role — the party that
controls a v3 tailnet's member set, policy document, and treasury.
Operators are a *separate* role (see
[`../operators/tour-operator.md`](../operators/tour-operator.md)); an
operator owns the exit circle, a tailnet owner owns the user-facing
mesh on top.

This tour assumes:

- An OctraVPN operator (you or someone else) has already followed
  [`../operators/tour-operator.md`](../operators/tour-operator.md)
  steps 1–9 — there is at least one bonded, active circle on chain.
- You have a separate **owner wallet** with enough OCT for the initial
  tailnet deposit + gas. Same hygiene rule as the operator wallet:
  fresh, single-purpose, never reused. See
  [`../v2-operator-key-hygiene.md`](../v2-operator-key-hygiene.md).
- You can run `octravpn-node …` against the same `node.toml` the
  operator uses, OR you've installed it on a separate admin host with
  its own `node.toml` whose `[chain].wallet_secret_path` points at
  *your* owner wallet.

Cross-references:

- [`../v3/call-flows.md`](../v3/call-flows.md) — every chain method
  this tour invokes, with revert reasons.
- [`../v3/data-model.md`](../v3/data-model.md) — what the on-chain
  `tailnets` table actually stores.
- [`../v3-members-schema.md`](../v3-members-schema.md) — the
  off-chain `members.json` schema anchored by `members_root`.
- [`../v3-policy-schema.md`](../v3-policy-schema.md) — the
  off-chain policy document anchored by `policy_hash`.

---

## What a tailnet owner does that an operator doesn't

| Concern | Operator | Tailnet owner |
| --- | --- | --- |
| Receives session payments | Yes | No |
| Bonds OCT as slashable stake | Yes | No |
| Runs the WireGuard / DERP data plane | Yes | No |
| Controls which **users** can join | No | Yes |
| Controls the ACL / policy document | No | Yes |
| Owns the tailnet treasury (funds sessions) | No | Yes |
| Mints preauth keys for members | No | Yes |

On chain, the operator owns `circle_*[circle]`; the owner owns
`tailnet_*[tailnet_id]`. The two intersect when a session opens —
`open_session(tailnet_id, circle, max_pay)` debits the tailnet treasury
and credits the circle. Settlement then flows from the circle's
earnings ledger back to the operator.

---

## Step 1 — Create the tailnet

The on-chain entrypoint is `payable create_tailnet(members_root)`. The
CLI wraps it:

```bash
# 1a. Compose your initial members.json — JSON shape per the schema
#     at docs/v3-members-schema.md. At minimum:
#
#     {
#       "version": 1,
#       "members": [
#         { "user": "alice", "node_keys": [], "groups": ["users"] }
#       ]
#     }
#
#     Canonicalise + hash:
MEMBERS_ROOT=$(jq -cS . < members.json | sha256sum | cut -d' ' -f1)
echo "members_root = $MEMBERS_ROOT"   # 64-char hex
```

```bash
# 1b. Submit create_tailnet. --deposit funds the treasury that will
#     pay for sessions; size it for ~one billing period.
octravpn-node v3 create-tailnet \
    --members-root "$MEMBERS_ROOT" \
    --deposit 10000000000   # 10000 OCT = 1.0e10 OU
```

The CLI prints the submitted tx hash and best-effort polls
`octra_transaction(hash)` for the assigned `tailnet_id`
(an unsigned 64-bit integer). Note it down — every subsequent command
needs it.

```
tx hash: …
tailnet_id assigned: 7
```

Full call-flow + revert reasons:
[`../v3/call-flows.md` §create_tailnet](../v3/call-flows.md).

The `members_root` is a **hash anchor only** — the chain doesn't read
your JSON. You're responsible for distributing the actual document to
members out-of-band.

---

## Step 2 — Write a `policy.hujson`

The policy document drives the ACL evaluator at the wire layer. It's
hujson — JSON with C-style comments — and the schema is the headscale
admin ACL shape (the canonical types + evaluator live in
[`headscale-api-acl`](../../crates/octravpn-mesh/src/acl.rs)).

Minimal "allow everything for testing":

```hujson
{
  // policy.hujson — tailnet ACL
  "version": 1,
  "rules": []
}
```

A working "engineering team can reach ssh; everyone else can reach the
exits only" example:

```hujson
{
  "version": 1,

  // Group definitions: arbitrary labels you'll reference in rules.
  "groups": {
    "group:eng": ["alice", "bob"]
  },

  // Tag owners gate auto-approval of node tags.
  "tagOwners": {
    "tag:exit": ["group:eng"]
  },

  // Static hostname → IP mapping baked into the policy.
  "hosts": {
    "internal-svc": "100.64.0.10"
  },

  // The actual ACL — array of rules, each {action, src, dst}.
  "rules": [
    {
      "action": "accept",
      "src": ["group:eng"],
      "dst": ["internal-svc:22"]
    },
    {
      "action": "accept",
      "src": ["*"],
      "dst": ["autogroup:internet:*"]
    }
  ]
}
```

For exhaustive examples of every supported field
(`acls`, `groups`, `tagOwners`, `hosts`, `nodeAttrs`, `autoApprovers`,
`ssh`), inspect the parser fixtures in
[`crates/octravpn-node/tests/policy_e2e.rs`](../../crates/octravpn-node/tests/policy_e2e.rs)
and the canonical types in
[`crates/octravpn-mesh/src/acl.rs`](../../crates/octravpn-mesh/src/acl.rs).

Validate the document **before** pushing it live:

```bash
octravpn-node headscale policy check \
    --server  http://localhost:51821 \
    --token   "$HEADSCALE_ADMIN_TOKEN" \
    ./policy.hujson
```

`policy check` takes the FILE as a positional arg. Exit 0 means
parse-only validation passed. Exit non-zero with the line offset of
the first error.

---

## Step 3 — Push the policy live

```bash
octravpn-node headscale policy set \
    --server  http://localhost:51821 \
    --token   "$HEADSCALE_ADMIN_TOKEN" \
    ./policy.hujson
```

This calls `PUT /api/v1/policy` on the operator's mesh-control admin
surface. The policy store (re-exported from `headscale-api` via
[`octravpn-mesh::policy`](../../crates/octravpn-mesh/src/lib.rs))
fires its internal `Notify` so any parked `/map` long-pollers wake
within ~1 ms — clients see the updated ACL on their next poll. No
daemon restart required.

The bytes you push round-trip verbatim through `GET /api/v1/policy`,
including comments — useful for the rotation flow in step 9.

> **Embedded `headscale` admin CLI.** Every subcommand the standalone
> `headscale` binary supports is reachable here verbatim
> (`octravpn-node headscale {users,nodes,preauthkeys,policy,tailnet} …`).
> Same `--server`, `--token`, `--json` flags. See
> [`../operators/cli-migration.md`](../operators/cli-migration.md) for
> the migration from the old `mesh policy` / `mesh status` arms.

---

## Step 4 — Mint a preauth key

A preauth key is what a member exchanges for tailnet membership when
their client does `tailscale up --authkey …` (or our client's
equivalent). The owner mints, the member redeems.

```bash
octravpn-node mesh mint-preauth \
    --user     alice \
    --reusable false \
    --ttl-secs 3600
```

The minted key goes to **stdout** as a single line, with
human-readable info on stderr:

```
stderr: minted preauth: user=alice reusable=false expires_at=1716291600
stdout: tskey-abc123-…
```

Capture in a shell harness:

```bash
KEY=$(octravpn-node mesh mint-preauth --user alice --reusable false)
```

Defaults: `--user default`, `reusable false` (matches Tailscale's safer
single-use default), `--ttl-secs 3600` (1 h via
`DEFAULT_PREAUTH_TTL`). Set a longer TTL for batch onboarding.

**Today's gap** — per the deprecation note in
[`cli/mesh.rs`](../../crates/octravpn-node/src/cli/mesh.rs#L40), the
in-CLI minter generates a key but doesn't bind it cross-process to a
running daemon's coordination plane. For interop tests the surface is
fine; for production tailnet redemption you want the persistent minter
from [`../tailscale-interop-blocker.md`](../tailscale-interop-blocker.md).
Track that work before you onboard real users.

---

## Step 5 — Distribute the key + login-server URL

Out-of-band: encrypted chat, GPG-encrypted email, a temporary 1-time
URL. The two pieces alice needs:

1. **Preauth key** from step 4.
2. **Login-server URL** — the operator's control plane SAN. If
   alice's client is stock `tailscale`, this is `https://<operator>:443`
   (forced HTTPS by Tailscale v1.78+). For our client, it can also be
   the plain-HTTP `http://<operator>:51821` if the network allows.

alice's join command:

```bash
tailscale up \
    --login-server https://<operator-san>:443 \
    --authkey      "tskey-abc123-…"
```

Reusable keys (`--reusable true` at mint time) survive multiple `up`s;
single-use keys redeem once and become void. Use reusable sparingly —
each reusable key is essentially a long-lived credential.

---

## Step 6 — Observe the registration land

The operator sees, in their logs:

```
[INFO] machine registered noise_pubkey=mkey:… user=alice tailnet=7
[INFO] /map long-poll opened for alice
```

You (the owner) see the new member in the roster:

```bash
octravpn-node headscale nodes list \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    --json
```

Each entry carries `noise_pubkey`, `user`, `last_seen`, allocated IP.
If the roster is empty after alice ran `up`, see
[`../operators/troubleshooting.md`](../operators/troubleshooting.md)
"WireGuard handshake timeout."

After registration, you should also bump the on-chain
`members_root` so the anchor matches your evolving `members.json`:

```bash
# Re-canonicalise + re-hash the updated members.json
MEMBERS_ROOT=$(jq -cS . < members.json | sha256sum | cut -d' ' -f1)

octravpn-node v3 update-members-root \
    --tailnet-id       7 \
    --new-members-root "$MEMBERS_ROOT"
```

Per [`../v3/call-flows.md` §update_members_root](../v3/call-flows.md),
this is owner-only and tx-cheap; do it on every roster change.

---

## Step 7 — Top up the treasury

Sessions debit `tailnet_balance[tailnet_id]`. When it runs low, the
next `open_session` reverts with `"insufficient tailnet balance"`. Top
it up:

```bash
octravpn-node v3 deposit-to-tailnet \
    --tailnet-id 7 \
    --amount     5000000000   # 5000 OCT
```

This is `payable deposit_to_tailnet(tailnet_id)` — see
[`../v3/call-flows.md` §deposit_to_tailnet](../v3/call-flows.md).
**Anyone** can call deposit (the chain doesn't gate it on owner) — so a
power user can self-fund their own usage if you set that up. Membership
is enforced off-chain via the policy doc.

Track treasury depletion proactively via the analytics indexer:

```bash
curl -sS "http://<operator>:51823/analytics/series?metric=treasury_bytes&bucket=1d"
```

The `treasury_bytes` time series counts bytes paid out per tailnet (per
the indexer's `octravpn_analytics_treasury_bytes{window="1d"}`
counter). When the slope flattens, your treasury is empty — alert on
it.

---

## Step 8 — Track usage

The owner's read-only view of what's happening on their tailnet:

```bash
# Sessions/sec opened over a rolling 5m window
curl -sS "http://<operator>:51823/analytics/series?metric=sessions_opened&bucket=5m"

# Claims/sec (settled sessions, 5m window)
curl -sS "http://<operator>:51823/analytics/series?metric=claims_settled&bucket=5m"

# Receipts signed (matches the operator's bytes-served signal)
curl -sS "http://<operator>:51823/analytics/series?metric=receipts_signed&bucket=5m"

# Treasury bytes (1d cumulative)
curl -sS "http://<operator>:51823/analytics/series?metric=treasury_bytes&bucket=1d"

# Slash events (anything > 0 is a critical signal)
curl -sS "http://<operator>:51823/analytics/series?metric=slash_events&bucket=1d"
```

All endpoints are gated by the `[analytics].token` bearer if set; pass
`-H "Authorization: Bearer $TOKEN"`. The unauthenticated health probe:

```bash
curl -sS http://<operator>:51823/analytics/health
```

For a GUI view, the operator should have the per-tailnet Grafana
dashboard wired —
[`../operators/dashboards.md`](../operators/dashboards.md) covers
import + provisioning.

---

## Step 9 — Rotate the policy document

ACL changes are not destructive — the policy store hot-reloads on every
PUT, and the `/map` long-pollers' `Notify` wakes parked clients within
~1 ms. So the rotation flow is just:

```bash
# 1. Edit policy.hujson in place.
$EDITOR policy.hujson

# 2. Validate.
octravpn-node headscale policy check \
    --server  http://<operator>:51821 \
    --token   "$HEADSCALE_ADMIN_TOKEN" \
    ./policy.hujson

# 3. PUT.
octravpn-node headscale policy set \
    --server  http://<operator>:51821 \
    --token   "$HEADSCALE_ADMIN_TOKEN" \
    ./policy.hujson
```

Verify by re-GETting:

```bash
octravpn-node headscale policy get \
    --server  http://<operator>:51821 \
    --token   "$HEADSCALE_ADMIN_TOKEN"
```

The response's `raw` field is byte-identical to the document you
pushed, including comments. You should also (manually) update the
on-chain `policy_hash` anchor — if your operator binds `policy_hash`
in `circle_state_root`, they push the new anchor via
`octravpn-node circle update --set-policy-hash <hex>` (operator
action; see [`../v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md)).

The reload is **immediate** for connected members. New rules apply to
the very next packet the wire layer evaluates.

---

## Step 10 — Evicting a member

There are two layers to revoke. Do **both**.

### Layer 1 — revoke the preauth key

If the member's machine is still registered, revoke it via the
embedded headscale CLI:

```bash
# List nodes — find the node id for the member to evict.
octravpn-node headscale nodes list \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    --json

# Force-logout (clears Noise/disco keys + stamps expiry=now). Mirrors
# `headscale nodes logout`. Takes the node id as positional.
octravpn-node headscale nodes logout \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    <node-id>

# Or full delete if you also want to drop the registry entry.
octravpn-node headscale nodes delete \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    <node-id>
```

Then expire any outstanding preauth keys. `preauthkeys expire` takes
the visible PREFIX of the key as a positional arg (you record this at
mint time):

```bash
# List the user's outstanding keys to find the prefix.
octravpn-node headscale preauthkeys list \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    --user   alice

octravpn-node headscale preauthkeys expire \
    --server http://<operator>:51821 \
    --token  "$HEADSCALE_ADMIN_TOKEN" \
    <key-prefix>
```

### Layer 2 — rotate the sealed `/policy.json` passphrase

The ex-member still holds the sealed-asset passphrase from when they
were inside the tailnet. Until you rotate it, they can decrypt the
current `/policy.json` ciphertext and read the in-force ACL. Worse: if
the policy doc references private hostnames or group memberships, the
ex-member sees those too.

The rotation procedure lives in
[`../v2-operator-key-hygiene.md §5`](../v2-operator-key-hygiene.md) —
the operator drives it (since they hold the circle owner key that signs
`circle_asset_put_encrypted` + `update_circle_state`), but you (the
owner) trigger it. Coordinate with your operator:

```bash
# Operator runs this with the new passphrase:
export OCTRAVPN_SEALED_PASSPHRASE="$NEW_PP"
octravpn-node circle update \
    --circle <circle-id> \
    --blob /policy.json:./policy.json:default:4k \
    --commit
```

Then re-canonicalise + push the new members roster to chain:

```bash
MEMBERS_ROOT=$(jq -cS . < members.json | sha256sum | cut -d' ' -f1)
octravpn-node v3 update-members-root \
    --tailnet-id 7 \
    --new-members-root "$MEMBERS_ROOT"
```

Distribute the new sealed passphrase to *remaining* members via your
out-of-band channel. The ex-member, with the old passphrase, gets
ciphertext they can no longer decrypt.

---

## Common failure modes

### Bytes-used dispute between opener and operator

**Symptom.** A session opener (member) reports their `settle_confirm`
reverted. The operator's logs show `settle_claim` submitted with one
`bytes_used`; the opener's logs show a different number.

**Status today.** Per the open audit finding
[**C-1**](../audit/2026-05-20-deep-security-audit.md), a disputed
`settle_confirm` is a permanent stuck-funds state on chain. There is no
chain-side resolver. The session's `max_pay` deposit cannot be
recovered by either party. The audit report recommends adding a
`dispute_resolver(session_id)` AML method gated by
`dispute_grace_epochs`; that work is tracked but not deployed.

**Mitigation as a tailnet owner.**

- Use operators with a clean
  `octravpn_slash_double_sign_total == 0` track record (visible in
  the analytics indexer's `slash_events` series).
- Cap `max_pay` per session — disputes only stick value up to
  `max_pay`. Smaller deposits, more sessions.
- Set `session_grace` short enough that `claim_no_show` is the
  default escape hatch if the operator vanishes mid-session.
- File a dispute affidavit in your incident log: opener's signed
  receipt journal + operator's signed `settle_claim` payload. When
  the dispute resolver lands you'll need both to claim back.

### Treasury depletion

**Symptom.** Members report `open_session` reverting with
`"insufficient tailnet balance"`. Grafana / the analytics indexer
shows `treasury_bytes` flatlined.

**Recovery.** Top up per step 7:

```bash
octravpn-node v3 deposit-to-tailnet --tailnet-id 7 --amount <ou>
```

Prevention: alert on
`octravpn_analytics_treasury_bytes{window="1d"} > <threshold>`. Set
the threshold at ~80% of your monthly burn, with paging on a 4 h
window.

### Retired-circle migration

**Symptom.** Your operator retires their circle (`v3 retire --circle
…`) or gets slashed. New session opens revert with
`"circle not active"` or `"previously slashed"`. Existing sessions
still settle via `claim_no_show` / `sweep_expired_session`.

**Recovery.**

1. Notify members the tailnet is moving operators. (Out-of-band; the
   chain has no broadcast channel.)
2. Find a new operator who has registered a healthy circle. Confirm
   their circle is active:

   ```bash
   octra cast call <program_addr> get_circle <new-circle-id>
   ```

3. Re-canonicalise + re-push your `policy.hujson` against the new
   operator's `mesh-control` admin URL (steps 3 + 9 above, new
   `--server` value).
4. Mint **new** preauth keys per member — the old keys were bound to
   the old operator's mesh-control state and won't redeem against the
   new one.
5. Update `members_root` if anything in the JSON moved (typically it
   doesn't — same users, different operator).

If you want a graceful migration where members keep using the old
operator while you stand up the new one, that requires running both
operators against the same `policy_hash` for a window. The
[`../v3/data-model.md`](../v3/data-model.md) covers the multi-circle
data shape.

---

## Where to next

- Operator side of the same world:
  [`../operators/tour-operator.md`](../operators/tour-operator.md).
- The full v3 call list (every chain method you might ever need):
  [`../v3/call-flows.md`](../v3/call-flows.md).
- The on-chain data model (what `tailnet_*` fields exist + their
  invariants): [`../v3/data-model.md`](../v3/data-model.md).
- The off-chain `members.json` schema:
  [`../v3-members-schema.md`](../v3-members-schema.md).
- The off-chain policy schema:
  [`../v3-policy-schema.md`](../v3-policy-schema.md).
- Per-symptom debugging from your operator's seat:
  [`../operators/troubleshooting.md`](../operators/troubleshooting.md).

If you got here, you own a tailnet. Welcome.
