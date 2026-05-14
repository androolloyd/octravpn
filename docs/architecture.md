# OctraVPN architecture

This document is the long-form companion to the README. It walks through
each subsystem's responsibilities, the wire formats between them, and
the security argument tying them to the formal specs.

## 1. The on-chain program (`program/main.aml`)

OctraVPN's on-chain program holds:

- **Validator registry**: `validators: map[address]ValidatorRecord`.
  Each record stores bond, endpoint, WG pubkey, FHE pubkey, stealth
  view pubkey, region, price, attestation epoch, jail state.
- **Sessions**: `sessions: map[bytes]Session`. Each session stores the
  client's ephemeral session pubkey, route commitments (1–3), deposit,
  open epoch, last accepted seq, status, and the client-supplied refund
  blob.
- **Encrypted earnings ledger**: `enc_earnings: map[address]bytes`. Each
  validator's running balance is held as an FHE ciphertext under
  *their own* public key, so only they can decrypt.

The constructor sets governance parameters (`min_bond`, deposit,
grace windows, slash split). Owner can `set_params`, `set_paused`, and
transfer ownership. The owner cannot move funds; everything goes
through the explicit transfer/private-transfer paths.

### 1.1 Validator lifecycle

```
register_validator(endpoint, wg_pk, fhe_pk, view_pk, region, price, attest_sig)
    requires:
        caller == origin
        not registered
        value >= min_bond
        verify_ed25519_acct(caller, sha256(self_addr || tag_bond || epoch), attest_sig)
    effects:
        validators[caller] = ValidatorRecord{...}
        enc_earnings[caller] = fhe_zero(fhe_pk)
        active_index.append(caller)

refresh_attestation(attest_sig)
    requires:
        caller == origin
        verify_ed25519_acct(caller, sha256(self_addr || tag_attest || epoch), attest_sig)
    effects:
        validators[caller].last_attest_epoch = epoch
        if validators[caller].bond >= min_bond:
            validators[caller].jailed_at = 0   // un-jail offline jails

add_bond() / request_unbond() / complete_unbond()
    standard timer-based unbonding.
```

### 1.2 Session lifecycle

The v1 AML uses a **two-tx settle**: operator submits `settle_claim`,
client submits `settle_confirm`. Settlement only applies when both
agree on `bytes_used`. Equivocation (operator claims twice with
different values) triggers an in-AML slash; client/operator
disagreement records a public `SettleDispute` event and leaves the
session open for governance.

The earlier signature-aggregated `settle_session` design is gone:
the AML cannot call `verify_ed25519` at compile time, so we couldn't
cryptographically verify a dual-signed receipt inside the program.
Both `settle_claim` and `settle_confirm` are themselves
ed25519-verified at the tx layer by the Octra runtime — the AML
just trusts that `caller` is who they say they are.

```
open_session(tailnet_id, exit_addr, max_pay)
    requires:
        is_member(tailnet_id, caller)
        endpoints[exit_addr].active == 1
        tailnet_exits[tailnet_id][exit_addr] == 1
        max_pay >= min_session_deposit
        tailnets[tailnet_id].treasury >= max_pay
    effects:
        tailnet.treasury -= max_pay
        session_count++
        sessions[session_count] = Session{
            tailnet_id,
            exit: exit_addr,
            opener: caller,
            deposit: max_pay,
            opened_at: epoch,
            status: open
        }
        emit SessionOpened(...)

settle_claim(session_id, bytes_used)
    // Operator-side first half.
    requires:
        sessions[session_id].status == open
        sessions[session_id].exit == caller
        endpoints[caller].active && stake[caller] >= MIN_STAKE
        !slashed[caller]
    effects:
        if operator_claims[session_id].set:
            if same bytes_used: no-op (idempotent retry)
            else: SLASH operator + refund deposit + status=refunded
        else:
            operator_claims[session_id] = {bytes_used, claimed_at}
            emit SettleClaimed(...)

settle_confirm(session_id, bytes_used)
    // Client-side second half. Only opener can call.
    requires:
        sessions[session_id].status == open
        sessions[session_id].opener == caller
        operator_claims[session_id].set
    effects:
        if operator_claims[session_id].bytes_used != bytes_used:
            client_confirms[session_id] = {bytes_used, claimed_at}
            emit SettleDispute(...)   // session stays open
        else:
            total = bytes_used * endpoints[exit].price_per_mb
            require total <= deposit
            protocol_fee = total * fee_bps / 10000
            net_pay = total - protocol_fee
            refund = deposit - total
            enc_earnings[exit] += net_pay   // HFHE add_const
            treasury += protocol_fee
            tailnet.treasury += refund
            sessions[session_id].status = settled
            emit SettleConfirmed(...) ; emit SessionSettled(...)

claim_no_show(session_id)
    requires:
        sessions[session_id].status == open
        epoch >= opened_at + session_grace_epochs
        !operator_claims[session_id].set
    effects:
        tailnet.treasury += deposit
        sessions[session_id].status = refunded

sweep_expired_session(session_id)
    long-tail cleanup if neither side closes the session: 1% bounty
    to the sweeper, rest returned to tailnet treasury.
```

#### Hash-precommit join tokens

Tailnet owners pre-publish `sha256(preimage)` via
`precommit_join_token`; anyone holding the preimage redeems via
`redeem_join_token`, which `sha256`-checks and joins them. No
signature verification needed — the preimage IS the capability.
This replaced the earlier "signed-token" design that needed
`verify_ed25519`.

### 1.3 Earnings claim (validator)

```
claim_earnings(amount_proof, claimed_amount, stealth_output)
    requires:
        validators[caller].bond > 0
        claimed_amount > 0
        fhe_verify_decrypt(enc_earnings[caller], claimed_amount, amount_proof,
                           validators[caller].fhe_pubkey)
    effects:
        enc_earnings[caller] = fhe_zero(fhe_pubkey)
        emit_private_transfer(stealth_output, claimed_amount)
```

The stealth output is a one-time token derived client-side from the
validator's view pubkey + a fresh nonce. Observers cannot link the
payout to the registered validator.

### 1.4 Slashing

```
slash_double_sign(session_id, seq, receipt_a, sig_a, receipt_b, sig_b)
    -> if both verify under same node's wg pubkey for same (session_id, seq)
       and receipts differ: zero bond, jail, distribute slash.

slash_offline(node_addr)
    -> permissionless; slashes 1% of bond if last_attest_epoch is too old.
```

## 2. Off-chain components

### 2.1 `octravpn-core`

Shared crate. Defines `Address`, `KeyPair`, `Receipt`, `SignedReceipt`,
`Commitment`, `Onion`, `SessionId`, `ValidatorRecord`, plus the `RpcClient`
covering every Octra RPC method we touch.

Critical invariants encoded here:

- Receipt canonical signing payload = `sha256(tag || session || seq || len || ct)`.
  Identical Rust↔AML serialization is property-checked by
  `prop_canonicalization.rs`.
- `SignedReceipt::check_monotonic` rejects equal seqs.
- Pedersen commitment is hiding under random blinds and binding by hash.

### 2.2 `octravpn-node`

Validator-side daemon. Subcommands:

- `register` — submit `register_validator` once per validator key.
- `attest` — push a `refresh_attestation`. The long-running daemon
  schedules this every `refresh_every_epochs` (default 5).
- `claim-earnings` — fetch encrypted ledger, decrypt locally via the
  FHE helper, prove decryption, submit `claim_earnings` with a fresh
  stealth output.
- `run` — the main loop: register if needed, schedule attestations, run
  the boringtun server, accept onion-wrapped traffic, sign receipts.

### 2.3 `octravpn-client`

End-user CLI. Subcommands:

- `nodes` — list active validators (`list_active_validators`).
- `connect --hops 3 --deposit 200` — choose a route, build commitments,
  publish FHE equality blob, open the session, bring up the tunnel,
  hold until ctrl-c, then settle.
- `settle <id>` — settle a session that was previously opened.
- `reclaim <id>` — call `claim_no_show` past grace.

### 2.4 `octravpn-fhe-helper`

Standalone binary the node and client shell out to for ciphertext ops.
The v1 shipped here is a deterministic stub (so the system runs end-to-
end against the mock today). Replacing it with the real HFHE SDK is a
single-file change once the bindings are public.

## 3. Wire formats

### 3.1 Receipt

```
Domain tag : "octravpn-receipt"  (16 ASCII bytes)
Payload    : tag || session_id (32B) || seq (u64 BE) || ct_len (u32 BE) || ct
Signing    : ed25519(client_session_secret_key, sha256(payload))
```

### 3.2 Pedersen commitment (v1)

```
Domain tag : "octravpn-commit-v1"  (18 ASCII bytes)
Commit     : sha256(tag || addr_raw (32B) || blind (32B))
Open       : (addr, blind) — verified by recomputing
```

The HFHE-native Pedersen swap-in keeps the same struct; only the
`commit` / `verify_open` functions change.

### 3.3 Equality blob

JSON-encoded for now; binary in v2:

```
{
  per_hop_cts:    [bytes...],   // one ciphertext per hop, each under hop.fhe_pubkey
  equality_proof: bytes,         // proves all encrypt the same plaintext
  claimed_max:    u64,           // upper bound on bytes_used
  le_proof:       bytes,         // proves ct <= claimed_max
  refund_stealth: [u8; 32]       // refund target
}
```

### 3.4 Onion header

```
HopHeader {
  wg_pubkey: [u8; 32],
  next: HopNext::Forward { endpoint, wg_pubkey } | HopNext::Egress,
  mac:  [u8; 16]
}
```

`Onion = { layers: [HopHeader; N], inner: bytes }`. Built client-side:
each hop's symmetric session key is derived via Curve25519 ECDH between
the client session ephemeral and the hop's static WG pubkey.

## 4. Safety and verification arguments

| Property                            | Where it's argued / checked          |
| ----------------------------------- | ------------------------------------ |
| Receipt signatures unforgeable      | Tamarin `ReceiptUnforgeability`      |
| Double-sign always slashable        | Tamarin `DoubleSignSlashable`        |
| Route hidden during open session    | Tamarin `NoLinkBeforeSettle`         |
| No double-settle, monotonic seq     | TLA+ `NoDoubleSettle`, `MonotonicSeq` |
| Bond never negative                 | TLA+ `SlashLeBond`, Lean `slash_double_sign_zeros_bond` |
| Conservation of funds               | TLA+ `ConservationOfFunds`           |
| Settle-or-refund eventually         | TLA+ `Liveness_SettleOrRefund` (under fairness) |
| `register; complete_unbond` returns full bond | Lean `completeUnbond_returns_full_bond` |
| Receipt round-trip is sound         | Kani `round_trip_signed_receipt`, proptest |

The Tamarin model is single-hop; the multi-hop generalization is
structural (each hop adds an independent commit + sig path).

## 5. Operational notes

- Validators MUST keep their attestation refresh well within
  `attest_grace_epochs`. The reference daemon refreshes every 5 epochs
  with a 2-epoch margin.
- Clients SHOULD maintain a local cache of in-flight session bookkeeping
  so the standalone `settle <id>` subcommand can reconstruct a route
  after process death. v1 keeps state in memory only — a SIGKILL
  between `connect` and clean shutdown forfeits the deposit (or
  triggers `claim_no_show` once grace elapses).
- Multi-hop forwarding adds latency. A 3-hop session is best for
  privacy-critical sessions; single-hop suffices for casual use and
  retains payment shielding.
