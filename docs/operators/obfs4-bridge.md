# obfs4 bridge runbook

This runbook covers the obfs4-modelled UDP transport plug-in (layer 2
of the OctraVPN 4-layer shielding pack). It sits between the WG
data plane and the public internet, wrapping every WG datagram in an
NTOR-handshaked ChaCha20-Poly1305 frame with length-randomised
padding. The wrapper is opt-in and defaults to off — stock validator
nodes are unaffected.

Layer 1 (AmneziaWG-style WG handshake obfuscation, see
`docs/security/validator-hardening.md` § "Layer 1") sits *inside* the
WG datagram and is independent of obfs4: the two layers compose.

## What the wrapper provides (and doesn't)

The implementation is `crates/octravpn-obfs4/` — see the crate-level
docs for the full design. Summary:

| Property | Where in the design |
|----------|----------------------|
| Probe-resistance (state-level DPI scanner that doesn't know `node_id` gets no reply) | NTOR `mac1` keyed by `node_id` — `handshake.rs` |
| Random-length frames (fixed-size WG packet → length-randomised wire datagram) | `frame.rs` plaintext padding suffix |
| Per-direction AEAD (tamper / replay defence) | ChaCha20-Poly1305 with 4-byte direction tag + 8-byte counter — `frame.rs` |
| Forward secrecy (per-session ephemeral X25519 on both sides) | `handshake.rs` `ecdh_e` |
| IAT chaff (flow-timing randomisation) | `iat.rs`, `IatMode::Uniform` / `Pareto` |
| Bridge identity rotation | operator regenerates `node_id` + `bridge_pubkey` and re-publishes |

Out of scope today:

- **Wire compatibility with the Tor Project's `obfs4proxy`/`lyrebird`.**
  We borrow the design ideas, not the byte layout. Operators who want
  a Tor-compatible bridge should run `obfs4proxy` separately.
- **Identity-pinned client auth.** OctraVPN authenticates clients
  on a different layer (WG static-key allowlist + chain-bound
  receipts), so the obfs4 layer accepts any client who knows
  `node_id`.
- **Replay cache.** Each handshake derives a fresh per-session key
  from per-side ephemerals; a replayed client handshake produces a
  session under a key the replayer cannot decrypt. We trade off the
  one wasted round trip for state-free operation.

## Where credentials live

| Surface | Path | Owner | Trust |
|---------|------|-------|-------|
| Bridge identity (server-side) | `${state_dir}/obfs4/identity.key` (64-byte file: 20-byte `node_id` ‖ 32-byte X25519 secret ‖ 12 zero pad) | `octravpn-node` (root-owned, 0600) | secret — never leaves the bridge host |
| Published credentials (client-side) | hex-encoded `node_id` (40 chars) + hex-encoded `bridge_pubkey` (64 chars) in client `node.toml` | distributed out of band by the operator | not secret — knowing them does not decrypt traffic, but is required to handshake |

`state_dir` is `[control].tailscale_wire_state_dir` from `node.toml`;
defaults to `./state/tailscale-wire`. Mint the obfs4 directory under
the same root so existing key-rotation tooling reaches both.

## Minting bridge credentials

`octravpn-node` does not yet ship a `mint-obfs4-bridge` subcommand;
the credentials are 20 + 32 random bytes. Generate them once at
bridge bring-up:

```bash
# 20 random bytes → 40 hex chars: the node_id distributed to clients.
NODE_ID=$(openssl rand -hex 20)

# 32 random bytes → 64 hex chars: the X25519 identity *secret*.
# The matching public key is derived by the daemon at boot — log the
# value the daemon prints, or compute it with the helper below.
IDENTITY_SECRET=$(openssl rand -hex 32)

# Derive the public key from the secret. The helper is a one-liner
# `cargo run -p octravpn-obfs4 --example pubkey-from-secret -- <hex>`
# (TODO: ship as a subcommand). Until then, the bridge's first-boot
# log emits the public key; capture it from there.
echo "node_id        = $NODE_ID"
echo "identity_secret = $IDENTITY_SECRET"
```

Hand `node_id` + `bridge_pubkey` (the *public* key) to clients. The
`identity_secret` stays on the bridge host.

## Bridge node configuration

`/etc/octravpn/node.toml` on the bridge:

```toml
[tun.transport]
kind = "obfs4"

[tun.transport.obfs4]
bridge_node_id          = "0102030405060708090a0b0c0d0e0f1011121314"   # 40 hex chars
bridge_pubkey           = "abcd...ef"                                   # 64 hex chars
bridge_identity_secret  = "deadbeef...90"                               # 64 hex chars, bridge-only
iat_mode                = 1                                              # 0 off | 1 uniform | 2 Pareto
```

At boot the daemon validates that:

- `bridge_node_id` decodes to exactly 20 bytes;
- `bridge_pubkey` decodes to exactly 32 bytes;
- `bridge_identity_secret` (when set) derives the configured `bridge_pubkey`;
- `iat_mode` is one of {0, 1, 2}.

Any mismatch surfaces in the daemon's startup log; the node refuses to
bring up the tunnel server. This is intentional: a misconfigured
bridge that silently accepts no traffic is worse than one that fails
fast.

## Client configuration

`/etc/octravpn/node.toml` on the client:

```toml
[tun.transport]
kind = "obfs4"

[tun.transport.obfs4]
bridge_node_id  = "0102030405060708090a0b0c0d0e0f1011121314"
bridge_pubkey   = "abcd...ef"
# bridge_identity_secret is intentionally omitted on clients.
iat_mode        = 1
```

`iat_mode` on the client side controls *client-side* outbound timing.
Bridge and client can run at different IAT modes — the wire format is
independent of the chosen distribution. We recommend matching the
modes when both sides are under the operator's control, so the flow
shape is symmetric.

## Rotating bridge credentials

obfs4 credentials are designed to rotate. Two rotation events:

1. **`node_id` rotation (defeats discovery via scanning).** New
   `node_id` → existing clients can no longer handshake. Coordinate
   distribution of the new `node_id` to active clients before
   rotating.
2. **`bridge_pubkey` rotation (compromise recovery).** New X25519
   keypair invalidates all in-flight session state. After distributing
   the new credentials, restart the bridge; clients dial under their
   updated config.

Both rotations are a config swap + daemon restart. There is no
graceful overlap: an obfs4 bridge serves exactly one credential pair
at a time. Operators who want zero-downtime rotation can run two
bridges on different ports under different credentials and direct
clients via the existing endpoint advertisement.

## IAT mode selection

`iat_mode` trades user-visible latency for flow-shape obfuscation.

- **0 (off).** Default. No injected delay; relies on length
  randomisation alone for traffic-shape obfuscation. Pick this for
  latency-sensitive workloads (real-time voice, low-latency gaming).
- **1 (uniform).** Uniform 0..25 ms added before each outbound frame.
  Median +12 ms latency. Defeats simple "WG burst every N ms"
  heuristics. Recommended default for normal browsing tunnels.
- **2 (Pareto).** Heavy-tailed 0..200 ms. Median +5 ms, long tail. Best
  match to a "human web flow" timing profile. Use for overlay tunnels
  that already tolerate RTT (cross-continent paths).

See `crates/octravpn-obfs4/src/iat.rs` for the exact distribution
parameters.

## Verifying the bridge is active

```bash
# 1. Daemon log on the bridge announces config validation.
sudo journalctl -u octravpn-node --since "5 min ago" | grep "obfs4 transport"
# Expected: "obfs4 transport configured (data-plane swap-in pending; ...) iat_mode=Uniform role=bridge"

# 2. From a client host, a misconfigured bridge_node_id surfaces as a
#    handshake timeout (the probe-resistance drop).
RUST_LOG=octravpn_obfs4=debug octravpn-node run --config /etc/octravpn/node.toml
# A bad node_id appears as "handshake failed: PermissionDenied (TimedOut)".
```

## Threat model — what this layer defeats that layer 1 alone does not

AmneziaWG (layer 1) randomises the WG message-type byte + length
prefix and injects a junk-burst before the handshake. That defeats a
DPI engine that pattern-matches on the canonical WG handshake bytes —
but it still:

- Responds to *any* UDP datagram on the validator's listening port,
  even if the upstream attacker is doing random-port scanning. A
  state-level adversary running a /16-wide probe across the validator
  IP space gets a measurable response distribution.
- Leaves the *flow shape* intact: AmneziaWG packets still have the
  WG-typical "two short handshake datagrams, then a sustained
  steady-rate transport stream" timing signature.
- Tied to a static junk-burst configuration: an attacker who
  characterises one AmneziaWG validator can fingerprint other
  validators using the same junk-burst parameters.

Obfs4 (layer 2) closes the remaining gaps:

- **Probe-resistance.** A scanner that does not know `node_id`
  cannot compute `mac1`. The bridge drops the packet with no reply,
  so the bridge is indistinguishable from a closed UDP port. A
  /16-wide state-level scan returns zero responses.
- **Per-session keying.** Every successful handshake derives fresh
  ChaCha20-Poly1305 keys from per-side ephemeral X25519 plus the
  bridge identity. Two clients of the same bridge see ciphertexts
  under different keys; one client's traffic doesn't help an attacker
  characterise another's.
- **Flow-shape jitter via IAT.** Even if a passive monitor identifies
  the bridge by other means (operator's IP is public, port is fixed),
  the IAT chaff smears the WG-typical timing signature into a Pareto
  / uniform distribution that no longer matches "WG-or-AmneziaWG"
  templates.

The two layers compose: the inner WG handshake (with AmneziaWG
substitution) rides inside the obfs4 frame. A DPI engine that
strips the obfs4 layer (it can't, but if it somehow did) still sees
the AmneziaWG-disguised WG handshake underneath. An engine that
fingerprints flow shape (real today, e.g. Iran's classifier) sees the
Pareto-jittered timing distribution. An engine that does active
probing (real today, e.g. China's GFW) is silent-dropped at `mac1`.

## Calendar

- **Monthly rotation of `node_id`.** Distribute new IDs via the
  existing client provisioning channel. Operators with thousands of
  clients should script the rotation.
- **Quarterly rotation of `bridge_pubkey`.** Bigger blast radius
  (every client must update); coordinate with the broader
  client-config refresh.
- **Immediate rotation on suspected compromise.** If the bridge
  host is suspected of compromise, treat the `identity_secret` as
  burned and mint a fresh pair; the X25519 key has no value to an
  attacker once the bridge no longer accepts the old credential.

## Failure modes and recovery

| Symptom | Likely cause | Fix |
|---------|--------------|-----|
| Client logs `PermissionDenied (TimedOut)` on first send | Wrong `bridge_node_id` on client | Re-verify the hex value from the operator |
| Client connects but every frame fails to decap | `bridge_pubkey` mismatch on client | Re-verify the operator-published `bridge_pubkey` |
| Bridge refuses to boot with "bridge_identity_secret does not derive the configured bridge_pubkey" | Operator regenerated secret without updating `bridge_pubkey` | Re-derive the public half from the secret and update both |
| Clients see intermittent `BadTag` after long idle | Process restart on either side without coordinated session reset | Bounce the other side; obfs4 sessions are not durable across restarts |
| Bridge log shows "dropping packet with bad mac1 (probe?)" continuously | External port scanner. This is the probe-resistance working; no action needed | — |

## See also

- `crates/octravpn-obfs4/src/lib.rs` — full design notes.
- `docs/security/validator-hardening.md` § Layer 1 — AmneziaWG layer.
- `docs/operators/tls-rotation.md` — analogous runbook for HTTPS / DERP cert rotation.
- Tor Project obfs4 spec — `https://gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/-/blob/main/doc/obfs4-spec.txt` — for background; OctraVPN's wire format is *not* compatible.
