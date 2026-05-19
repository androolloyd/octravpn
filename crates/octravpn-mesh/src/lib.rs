//! Decentralized-tailscale mesh primitives for OctraVPN.
//!
//! The mesh layer answers questions the on-chain program can't:
//!   - "Can I reach peer X directly?" (STUN-discovered candidates)
//!   - "What IP does peer X have inside this tailnet?" (IP allocator)
//!   - "What does the name `phone.tailnet-abc.octra` resolve to?" (magic DNS)
//!   - "Should this connection go peer-to-peer, or via a paid relay?"
//!     (connection state machine)
//!
//! Modules:
//!   - [`stun`]      — minimal RFC 5389 client for public-address discovery
//!   - [`peer`]      — peer registry + candidate exchange
//!   - [`ip_alloc`]  — deterministic CGNAT-range allocation per tailnet
//!   - [`magic_dns`] — embedded UDP DNS resolver mapping peer names to IPs
//!   - [`conn`]      — connection FSM (Probing → Direct | Relay → Upgraded)
//!   - [`subnet`]    — subnet-advertisement bookkeeping
//!   - [`serve`]     — serve/funnel advertisement bookkeeping

pub mod acl;
pub mod conn;
pub mod headscale_bridge;
pub mod ip_alloc;
pub mod magic_dns;
pub mod manager;
pub mod peer;
pub mod serve;
pub mod stun;
pub mod subnet;

// The Tailscale wire-protocol implementation moved into
// `headscale-api::tailscale_wire` on 2026-05-19. octravpn-mesh keeps
// only the bridge (PreauthMinter / TailnetIpAllocator + the trait
// impls that connect them to the wire layer). Re-export the wire
// module's public surface so existing callers that did
// `use octravpn_mesh::tailscale_wire::router` keep working.
pub use headscale_api::tailscale_wire;
pub use headscale_api::tailscale_wire::{
    router as tailscale_wire_router, MachineRecord, MachineRegistry, ServerNoiseKey, WireError,
    WireState,
};

pub use acl::{AclAction, AclDoc, AclRule, PortRef, SignedAclDoc};
pub use conn::{ConnState, Connection, ConnectionManager};
pub use headscale_bridge::{
    MetricsSink, PreauthKey, PreauthMinter, RedeemError, DEFAULT_PREAUTH_TTL,
};
pub use ip_alloc::TailnetIpAllocator;
pub use magic_dns::MagicDns;
pub use manager::{MeshAction, MeshManager};
pub use peer::{
    Peer, PeerCandidate, PeerRegistry, PeerSnapshot, SignedPeerSnapshot, PEER_SNAPSHOT_DOMAIN,
    PEER_SNAPSHOT_FRAME_MAGIC, PEER_SNAPSHOT_MAX_AGE_SECS,
};
pub use serve::{ServeEntry, ServeRegistry};
pub use stun::{stun_binding_request, StunError};
pub use subnet::{SubnetAdvertisement, SubnetRouter};

#[derive(Debug, thiserror::Error)]
pub enum MeshError {
    #[error("stun: {0}")]
    Stun(#[from] StunError),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid peer: {0}")]
    InvalidPeer(String),
    #[error("invalid subnet: {0}")]
    InvalidSubnet(String),
    #[error("snapshot expired: age {age_secs}s exceeds max")]
    SnapshotExpired { age_secs: u64 },
    #[error("snapshot signature did not verify")]
    SignatureMismatch,
    #[error("old peer snapshot format (pre-v2 unframed encoding)")]
    OldPeerSnapshotFormat,
}

pub type MeshResult<T> = std::result::Result<T, MeshError>;
