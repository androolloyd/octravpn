# Trusted P2P upgrade schedules

The public launcher captures the adopted native upgrade and rollback settings
from its configured network environment. Peer messages cannot supply these
settings. `OCTRA_P2P_REQUIRE_BINARY_HASH=1` enables them; other values preserve
the native behavior of ignoring the entire schedule.

An upgrade requires both `OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH` and
`OCTRA_P2P_UPGRADE_BINARY_HASH`. Its activation must be positive. Optional
`OCTRA_P2P_UPGRADE_CONFIG_HASH` defaults to the startup network hash. A rollback
requires both `OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH` and
`OCTRA_P2P_ROLLBACK_BINARY_HASH`; its activation must be strictly later than
the upgrade. Optional `OCTRA_P2P_ROLLBACK_CONFIG_HASH` independently defaults
to the same startup network hash. Hashes accept the native 32-byte or 64-hex
representation; epochs retain native signed 64-bit parsing and validation.

The schedule does not download, replace or select an executable. Operators
must install and restart with the intended binary, its verified local
`OCTRA_BINARY_HASH`, and captured network configuration. The native check trusts
that configured identity; it does not attest the executable. Before activation,
peers commit to the whole trusted schedule
and may run different binaries. At activation and rollback, peer handshakes
commit to the configured binary identity and active transport profile.

Voting has a separate native readiness check at the next canonical epoch.
It compares the configured target with the local binary identity and the
**consensus configuration hash**, including the selected validator set,
pending schedule, program trust and current runtime profile. This hash differs
from the network hash used for handshakes. A config-hash default can therefore
block voting at activation; operators should provide the intended consensus
hash explicitly. The Rust implementation preserves the adopted default.
Relief retains the pending schedule until its selected activation; canonical
publication invalidates the previous epoch's cached readiness. A mismatch
stops new local votes/proposals and logs the reason when it changes. It does
not prevent following authenticated finality.

Private Single transport accepts the same schedule through its existing
explicit configuration:

```json
{
  "require_binary_hash": true,
  "upgrade": {
    "target": {
      "epoch": 100,
      "binary_hash": "<64 hex characters>",
      "config_hash": "<64 hex characters>"
    },
    "rollback": {
      "epoch": 200,
      "binary_hash": "<64 hex characters>",
      "config_hash": "<64 hex characters>"
    }
  }
}
```

This is the `services.network` fragment; all existing required transport
fields still apply. Omitting `upgrade` preserves existing configurations.
Single remains an explicitly isolated private producer; this optional peer
transport does not turn it into public BFT consensus.
