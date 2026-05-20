//! Forward-compat enforcement for public `#[non_exhaustive]` error
//! enums in `octravpn-mesh`. See
//! `crates/octravpn-core/tests/non_exhaustive_errors.rs` for the
//! mechanism.

#![allow(clippy::needless_pass_by_value)] // intentional: matching consumes the value

use octravpn_mesh::{
    headscale_bridge::preauth::RedeemError, knock::KnockPskError, MeshError, StunError,
};

#[deny(unreachable_patterns)]
#[test]
fn public_error_enums_are_non_exhaustive() {
    fn check_mesh(e: MeshError) -> &'static str {
        match e {
            MeshError::Stun(_) => "stun",
            MeshError::Io(_) => "io",
            MeshError::InvalidPeer(_) => "peer",
            MeshError::InvalidSubnet(_) => "subnet",
            MeshError::SnapshotExpired { .. } => "expired",
            MeshError::SignatureMismatch => "sig",
            MeshError::OldPeerSnapshotFormat => "old",
            _ => "future",
        }
    }
    assert_eq!(check_mesh(MeshError::SignatureMismatch), "sig");

    fn check_stun(e: StunError) -> &'static str {
        match e {
            StunError::Io(_) => "io",
            StunError::NonSuccess(_) => "ns",
            StunError::TxidMismatch => "txid",
            StunError::MagicMismatch => "magic",
            StunError::Truncated => "trunc",
            StunError::MissingAttribute => "miss",
            StunError::UnsupportedFamily(_) => "fam",
            StunError::Timeout => "to",
            _ => "future",
        }
    }
    assert_eq!(check_stun(StunError::Timeout), "to");

    fn check_knock(e: KnockPskError) -> &'static str {
        match e {
            KnockPskError::Base64 => "b64",
            KnockPskError::BadLength(_) => "len",
            KnockPskError::Duplicate => "dup",
            _ => "future",
        }
    }
    assert_eq!(check_knock(KnockPskError::Base64), "b64");

    fn check_redeem(e: RedeemError) -> &'static str {
        match e {
            RedeemError::Unknown => "unk",
            RedeemError::Expired => "exp",
            _ => "future",
        }
    }
    assert_eq!(check_redeem(RedeemError::Unknown), "unk");
}
