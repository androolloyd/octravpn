# Native-format legacy repair

`octra-node legacy-repair` resumes an already staged, locally trusted native
`fork_repair.json` in a stopped native-format data directory. It does not select
a fork, create a repair plan, infer quorum from peer counts, or rewind the Rust
canonical SQLite history.

`octra-node legacy-stage` acquires the missing selection evidence for a stopped
native directory. Its existing public-network configuration supplies the chain,
origin, validator trust, environment, peer endpoints and local identity key.
Authenticated epoch-root responses must satisfy the adopted count-health and
weighted target quorum rules. Current-head agreement, native ahead grace,
activation boundaries, mismatched local target roots and journal-protected
suffixes refuse staging. There is no caller-provided target or quorum flag.

The Rust implementation reads the native plan and HEAD codecs and follows the
adopted finality-finish order. Actual Irmin/chaindata recovery uses a pinned
native compatibility backend built from unchanged lite_node
`7f9be4489870645cfcc95439638cde40f5da9f50`. This is not an all-Rust physical
storage backend. Staging is an explicit maintenance command; normal Rust
canonical service startup does not acquire a rewind capability.

Build and qualify the compatibility backend locally:

```sh
python3 scripts/node-port/build-legacy-repair.py \
  --upstream /path/to/pinned/lite_node --out /path/to/fresh/backend-output
cargo test -p octra-node --test legacy_stage --no-run
python3 scripts/node-port/legacy-repair-qualify.py \
  --node /path/to/octra-node --backend-directory /path/to/backend-output \
  --stage-test-binary /path/to/fresh/legacy_stage-TEST_EXECUTABLE \
  --out /path/to/fresh/private-qualification-output
```

The builder verifies all 1,158 inventoried production sources and two native
fixture helpers. The qualifier uses a pinned, network-disabled Linux ARM64
container bridge and disposable physical stores. The signed selection fixture
uses three actual local TCP peers with deterministic development keys, and
checks absent/invalid/weak quorum, origin/environment mismatch, changed source,
protected journals and invalid target finality before resuming the positive
staged plan. These additions require a fresh run; older checkpoint results do
not cover selection. The bridge is a test adapter;
production use needs a backend executable compatible with the node's host.

For an existing stopped native directory, supply its trusted chain identity and
the independently checked backend SHA-256:

```sh
octra-node legacy-stage --config /path/to/trusted/network.json \
  --backend /path/to/compatible/backend --backend-sha256 VERIFIED_SHA256
octra-node legacy-repair --directory /path/to/stopped/native-data \
  --chain-id TRUSTED_CHAIN_ID --backend /path/to/compatible/backend \
  --backend-sha256 VERIFIED_SHA256
```

The host freezes the verified executable in a private directory before running
it. Bounded requests, deadlines and owned-child shutdown apply to the entire
session. The backend holds the actual native chaindata ownership lock before
opening Irmin. Selection retains both stores through all network awaits and
rechecks the complete captured source, validator metadata, relief evidence and
configuration before the native staging call. Staging only fsyncs the repair
marker; stop the maintenance session and run `legacy-repair` to resume it.
Preflight checks journal protection, source/target bindings,
transaction and epoch-log boundaries, the empty suffix and finality proofs.
Native storage verification follows store/chain recovery. Finality rewind and
trimming happen before marker retirement. Vote floors and retained signing
records remain intact.

The [local checkpoint](checkpoints/2026-10-17/legacy-repair.json) records native
codec parity and physical recovery evidence, including real process death,
signed-certificate corruption and competing ownership. Those certificates use
deterministic fixture validators; they do not establish public membership or
full block-execution validity. The gate does not qualify full node startup,
public fork selection or Mainnet recovery. A failed or
incomplete run must preserve the staged marker for diagnosis and resumption;
never delete journals or signing history to make it proceed.
