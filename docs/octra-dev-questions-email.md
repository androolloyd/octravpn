# Subject

OctraVPN — chain-side blockers + open questions

# Body

Hi Octra team,

We're the OctraVPN team. We're building a private-VPN settlement layer
on Octra: operators run mesh nodes, users buy bandwidth, all
session-level OCT settlement happens on chain via an AML contract
(`program/main-v3.aml`, deployed on devnet 2026-05-18 at
`oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3`, commit `04bc252`).
End-to-end lifecycle is exercised by `docker/devnet/v3-smoke.sh` and a
40-case adversarial drill (`docker/devnet/e2e-adversarial-v3.sh`).

We've written down everything we found while building against devnet
that we couldn't resolve from public docs alone. Most of it is now
worked around in our code; four items still gate things we'd like to
ship and need clarification on whether they're chain-side bugs,
intentional design, or roadmap items. Sharing as one structured doc
rather than scattered pings so you have the full picture in one place.

## What we've resolved since posting the long doc

These items in the original `docs/octra-dev-questions.md` are no longer
blocking us — flagging so you don't need to re-read them:

- **Devnet RPC body cap (was §7).** The ~1 MiB nginx wall on
  `devnet.octrascan.io/rpc` was raised; `octra_registerPvacPubkey` now
  confirms with our ~4.1 MB PVAC pubkey. Thank you. Still curious
  about the mainnet ceiling (see below).
- **PVAC AES-GCM KAT path.** We were stuck on a deterministic-AES
  known-answer test that broke against `aes-gcm` defaults. Resolved
  in-house via a GPL-isolated `pvac-sidecar` daemon (commit `9e16868`)
  — no chain-side action needed.
- **`bytes`-as-string at the RPC boundary.** Documented as "no decode
  step, `len()` returns char count" in our v3 header comments
  (`program/main-v3.aml` lines 8–15) and in the architecture writeup
  (`docs/v3-circle-resident-architecture.md`). We work around it by
  treating every `bytes` field as a length-checked hex string and
  seeding map entries explicitly. We'd still appreciate a docs note
  from your side either way (§4 in the long doc), but it isn't gating
  shipping.
- **AML map-value 4 KiB cap (was §3).** We discovered + worked around
  this on our side; the v3 architecture stores sha256 commitments
  inline and keeps real bytes in circle-resident sealed assets. Still
  on our wishlist (a larger inline cap would remove a fetch hop) but
  not blocking.

## What we still need from you (priority order)

Four open items, ordered by impact on what we can ship:

1. **AML → HFHE host-call bridge.** Every `fhe_*` AML host call
   reverts on newly-deployed contracts. We ruled out an authoring
   mistake by cloning `octra-labs/program-examples/private_ml`
   verbatim and deploying it at
   `octHCQv6URtBXKjvAUo4AtDuDAgNjPhfazGiLPJXHwB3gDt`; its
   `private_predict` reverts identically at the first `fhe_load_pk`.
   The caller wallet has a 4.1 MB PVAC pubkey registered via
   `octra_registerPvacPubkey`. Question: when is this expected to
   work on newly-deployed contracts, and is there a chain-side opt-in
   flag or deployer allowlist? Until this lands, our v3 settle/claim
   path stores plaintext OCT running totals where it should be
   storing HFHE-encrypted ones. (Was §1 in the long doc.)

2. **Circle code execution.** `deploy_circle` accepts and persists a
   `code_b64` field; the chain computes a real `code_hash`. But
   `contract_call` against the resulting circle address returns
   `"bytecode not found"`. Reproducer: counter circle at
   `octHXaof7eyQEess39BR3nuRg5k6oVsoVMa192Vo8htPoHT`. Question: is
   `deploy_circle.code_b64` execution scheduled? If there's a
   different entrypoint for invoking circle code we should be using,
   we'd appreciate a pointer. Until this lands, bonds + slash logic
   stay in the main contract rather than living per-operator in a
   `BondEscrow` circle (which is the v3 §6 target). (Was §2.)

3. **AML 4 KiB map-value cap.** `map[address]string` (and `bytes`)
   values silently truncate at 4096 bytes on store; no revert.
   Reproducer: program
   `octHiTZruUMFiBkAjt6EGYojYKAcn1mpiSHbaZn8Tfah5ss`; 56 KB
   ciphertext in, 4096 B out. Question: is this intentional, and is
   there a higher-cap storage class (blob, chunked, per-key-prefix
   sealed asset) we could read from AML at runtime? A larger cap
   (even 64 KiB) would let us hold PVAC ciphertexts inline. (Was §3.)

4. **`circle_id` derivation stability across main-contract
   redeploys.** The v3 redeploy story hinges on `circle_id` being a
   function of the registering wallet only, independent of the main
   contract that references the circle. Empirically we see this
   behaviour across our test deploys. Could you confirm in writing
   that it's the contract of the chain and not an implementation
   detail? If `circle_id` ever becomes CREATE-style (function of the
   calling contract address), our redeploy migration path breaks and
   we'd want to know early. (Was §5.)

Two additional asks that are not blocking us but improve operability:

- **Sealed-asset write events** (was §6). Currently we have no
  chain-side signal that `circle_asset_put_encrypted` happened; we
  poll the resource key. An event would let off-chain auditors
  subscribe instead.
- **Mainnet RPC body cap** (residual from §7). We know the devnet cap
  was raised; what's the production ceiling on `octra.network/rpc`?
  Lets us size our client-side chunking strategy correctly before we
  hit the wall on a live deploy.

## Detail link

Full technical writeup with reproducer scripts, deploy addresses, and
the empirical data behind each item:
`https://github.com/<our-repo>/blob/main/docs/octra-dev-questions.md`

The supporting architecture doc that explains the v3 design we built
around these constraints:
`https://github.com/<our-repo>/blob/main/docs/v3-circle-resident-architecture.md`

## Sign-off

Happy to walk through any of this in more depth, jump on a call, or
write reproducer scripts for additional cases. Best contact for us is
<TBD — fill in: GitHub issues / Discord handle / dev@octravpn.io>.

Thanks for the work on the chain. We've been able to ship a real
substrate against it; the four open items above are the gap between
our current devnet build and a clean mainnet ship.

— The OctraVPN team

# Suggested attachments

Three things to link or attach when sending:

- `docs/octra-dev-questions.md` — the full technical writeup with
  reproducers (referenced above).
- `docs/v3-circle-resident-architecture.md` — the architecture we
  built on top of the empirical constraints; useful context for why
  each of the four open items matters to us.
- The devnet deploy address as live proof of the work:
  `oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3` (commit `04bc252`,
  smoke at `docker/devnet/v3-smoke.sh`).
