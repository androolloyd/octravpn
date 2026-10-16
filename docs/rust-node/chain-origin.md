The local store and ExEx identify a chain by its configured name and a typed
origin. A genesis origin records a known original folded state root. A checkpoint
origin records an independently pinned epoch and folded root without claiming
knowledge of the original genesis. Downloaded state cannot choose either origin.

The adopted public network configuration pins this checkpoint identity:

```json
{
  "chain_id": "octra-devnet-9871-cluster",
  "origin": {
    "kind": "checkpoint",
    "epoch": 1278039,
    "state_root": "ab602f2a1956a9df087106a686ea36e654c819e62321ae6b4ed3cf61107676ee"
  }
}
```

Its provenance is [network-authority.json](network-authority.json), which pins
the adopted `config/network.env` hash. The snapshot authority still independently
checks the configured network/configuration, validator finality, exporters,
freshness, image bytes and retained root window. An imported checkpoint must be
at or above the configured origin and must match its root when epochs coincide.
Later snapshots keep the same configured origin. Reopening rechecks the retained
certificate and the exact persisted origin.

Genesis identities retain their legacy JSON and raw SQL namespace key, preserving
existing ExEx checkpoints and already applied sink effects. Checkpoint identities
use a domain-separated host namespace digest. The legacy SQL column `genesis`
stores that opaque key; it never changes a consensus root. Browser snapshots,
wallet capabilities and VPN reads carry and compare the typed origin. ExEx's
first retained cursor remains the authenticated imported floor, and no events
before that floor are synthesized or replayed.
