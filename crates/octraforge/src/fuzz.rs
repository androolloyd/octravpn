//! Fuzz-input convenience strategies.
//!
//! `proptest` strategies for the values OctraVPN tests most often want
//! to vary: addresses, hex blobs, deposits, splits.

use proptest::prelude::*;

/// Strategy producing 32-byte hex strings (lowercase, no `0x`).
pub fn hex32_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 32).prop_map(hex::encode)
}

/// Strategy producing pseudo-realistic Octra addresses (`oct...` prefix).
pub fn oct_addr_strategy() -> impl Strategy<Value = String> {
    proptest::collection::vec(any::<u8>(), 32)
        .prop_map(|bytes| format!("oct{}", hex::encode(bytes)))
}

/// Strategy producing a nonzero deposit amount in a sane range.
pub fn deposit_strategy() -> impl Strategy<Value = u64> {
    1u64..1_000_000u64
}
