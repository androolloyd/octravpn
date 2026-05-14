//! `OctraBackend` — the integration boundary with Octra-specific
//! primitives that aren't fully documented at the time of writing.
//!
//! Each method has a placeholder implementation in `PlaceholderBackend`
//! that is *correct semantically but not byte-compatible* with the real
//! Octra runtime. When the official Octra SDK is available, swap in
//! `OctraSdkBackend` (single-file change) and every consumer (node,
//! client, mock, octraforge) gets the real behavior.
//!
//! Contracts:
//!   - `address_from_display` / `address_to_display` — codec for
//!     `oct...` strings.
//!   - `derive_view_pubkey` / `derive_stealth_output` — stealth scheme.
//!   - `verify_account_sig` — verify a signature under an Octra account
//!     address (NOT raw ed25519 — Octra may use multi-sig, hardware,
//!     etc.).
//!   - `tx_chain_id` — chain-id used in canonical signing.
//!   - `is_octra_validator` — chain-level Octra validator membership
//!     check; the dVPN program's `register_endpoint` gates on this.
//!
//! ## Production deployment
//!
//! The `RpcBackend` impl talks to a live Octra node over JSON-RPC. The
//! `is_octra_validator` method specifically goes through `octra_isValidator`
//! — when running against a chain that doesn't expose that method, the
//! call will fail loudly and the operator will know to upgrade to a
//! chain release with the helper. There is no silent fallback.

use crate::{address::Address, sig::Signature, CoreError, CoreResult};

#[async_trait::async_trait]
pub trait OctraBackend: Send + Sync {
    /// Decode an `oct...` display string into the 32-byte canonical form
    /// used inside Pedersen commitments.
    fn address_from_display(&self, display: &str) -> CoreResult<Address>;

    /// Encode the 32-byte canonical form back to `oct...` display.
    fn address_to_display(&self, raw: &[u8; 32]) -> CoreResult<String>;

    /// Derive the X25519 view pubkey from the wallet's **secret** scalar.
    /// The corresponding view secret is what lets the wallet owner
    /// scan the chain for stealth payments addressed to them; the
    /// pubkey itself can be published.
    ///
    /// NOTE: the older API took the wallet *public* key here, which
    /// allowed anyone with the address to recompute stealth tags.
    /// That signature was a privacy bug and has been removed.
    fn derive_view_pubkey(&self, account_secret: &[u8; 32]) -> [u8; 32];

    /// Derive a one-time stealth output tag, given a recipient
    /// view pubkey and a *sender ephemeral* X25519 secret. Internally
    /// runs the documented ECDH scheme — see
    /// [`crate::stealth::build_output`].
    fn derive_stealth_output(&self, view_pubkey: &[u8; 32], eph_secret: &[u8; 32]) -> [u8; 32];

    /// Verify a signature under an Octra account address. The real
    /// scheme may involve more than raw ed25519 (e.g. multi-sig).
    fn verify_account_sig(&self, addr: &Address, msg: &[u8], sig: &Signature) -> CoreResult<()>;

    /// Chain id baked into transaction canonical bytes for replay
    /// protection.
    fn tx_chain_id(&self) -> u32;

    /// Is `addr` currently a registered Octra protocol validator?
    /// Production answer comes from the chain via JSON-RPC; the
    /// placeholder backend errors so a misconfigured deployment fails
    /// fast instead of silently treating everyone as a validator.
    async fn is_octra_validator(&self, addr: &Address) -> CoreResult<bool>;
}

/// Default placeholder backend — semantically correct but not byte-
/// compatible with mainnet Octra. Swap for `OctraSdkBackend` once
/// available.
#[derive(Debug, Default, Clone, Copy)]
pub struct PlaceholderBackend;

#[async_trait::async_trait]
impl OctraBackend for PlaceholderBackend {
    fn address_from_display(&self, display: &str) -> CoreResult<Address> {
        Ok(Address::from_display(display))
    }

    fn address_to_display(&self, raw: &[u8; 32]) -> CoreResult<String> {
        // No reverse codec without Octra's bech-style scheme; emit a
        // hex-prefixed identity that's distinguishable from real `oct...`.
        Ok(format!("octplaceholder{}", hex::encode(raw)))
    }

    fn derive_view_pubkey(&self, account_secret: &[u8; 32]) -> [u8; 32] {
        crate::stealth::view_pubkey_from_wallet(account_secret)
    }

    fn derive_stealth_output(&self, view_pubkey: &[u8; 32], eph_secret: &[u8; 32]) -> [u8; 32] {
        // Routes through the proper X25519 ECDH path defined in
        // `stealth::build_output`. Any error reduces to a zeroed
        // 32-byte slot so the trait method stays infallible — callers
        // who need fallible behaviour use `crate::stealth` directly.
        match crate::stealth::build_output(view_pubkey, eph_secret) {
            Ok((out, _)) => out.tag,
            Err(_) => [0u8; 32],
        }
    }

    fn verify_account_sig(&self, addr: &Address, msg: &[u8], sig: &Signature) -> CoreResult<()> {
        // Placeholder treats the account address's first 32 bytes as the
        // ed25519 public key. Real Octra: derive pubkey from on-chain
        // registry (octra_publicKey RPC) or from the account record.
        let mut pk = [0u8; 32];
        pk.copy_from_slice(addr.as_bytes());
        let pubkey = crate::sig::PublicKey(pk);
        crate::sig::verify(&pubkey, msg, sig)
    }

    fn tx_chain_id(&self) -> u32 {
        crate::tx::CHAIN_ID_MAINNET
    }

    async fn is_octra_validator(&self, _addr: &Address) -> CoreResult<bool> {
        // The placeholder cannot answer authoritatively — it has no
        // chain to ask. Production deployments must use `RpcBackend`.
        // Erroring here surfaces the misconfiguration immediately
        // instead of silently returning false (which would make every
        // `register_endpoint` fail) or true (which would let any
        // unprivileged address register a paid relay).
        Err(CoreError::Rpc(
            "PlaceholderBackend cannot answer is_octra_validator — \
             use RpcBackend for production"
                .into(),
        ))
    }
}

/// JSON-RPC-backed implementation of [`OctraBackend`]. Use this in
/// production: it routes chain-querying methods (`is_octra_validator`,
/// stealth derivations once Octra exposes them) through a live Octra
/// node. Sync primitives (`tx_chain_id`, `derive_view_pubkey`) fall
/// back to the placeholder logic until Octra publishes the
/// authoritative algorithm.
pub struct RpcBackend {
    rpc: crate::rpc::RpcClient,
    chain_id: u32,
}

impl RpcBackend {
    pub fn new(rpc: crate::rpc::RpcClient) -> Self {
        Self {
            rpc,
            chain_id: crate::tx::CHAIN_ID_MAINNET,
        }
    }

    pub fn with_chain_id(mut self, chain_id: u32) -> Self {
        self.chain_id = chain_id;
        self
    }
}

#[async_trait::async_trait]
impl OctraBackend for RpcBackend {
    fn address_from_display(&self, display: &str) -> CoreResult<Address> {
        Ok(Address::from_display(display))
    }

    fn address_to_display(&self, raw: &[u8; 32]) -> CoreResult<String> {
        Ok(format!("oct{}", bs58::encode(raw).into_string()))
    }

    fn derive_view_pubkey(&self, account_secret: &[u8; 32]) -> [u8; 32] {
        crate::stealth::view_pubkey_from_wallet(account_secret)
    }

    fn derive_stealth_output(&self, view_pubkey: &[u8; 32], eph_secret: &[u8; 32]) -> [u8; 32] {
        match crate::stealth::build_output(view_pubkey, eph_secret) {
            Ok((out, _)) => out.tag,
            Err(_) => [0u8; 32],
        }
    }

    fn verify_account_sig(&self, addr: &Address, msg: &[u8], sig: &Signature) -> CoreResult<()> {
        // Same placeholder shape; the real Octra implementation would
        // resolve the account's published pubkey via `octra_publicKey`.
        let mut pk = [0u8; 32];
        pk.copy_from_slice(addr.as_bytes());
        let pubkey = crate::sig::PublicKey(pk);
        crate::sig::verify(&pubkey, msg, sig)
    }

    fn tx_chain_id(&self) -> u32 {
        self.chain_id
    }

    async fn is_octra_validator(&self, addr: &Address) -> CoreResult<bool> {
        self.rpc.is_octra_validator(addr).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sig::KeyPair;

    #[test]
    fn placeholder_round_trip() {
        let b = PlaceholderBackend;
        let a = b.address_from_display("octABC").unwrap();
        // The placeholder doesn't preserve the display through a round
        // trip because we hash; real backend will round-trip exactly.
        let _ = b.address_to_display(a.as_bytes()).unwrap();
    }

    #[test]
    fn placeholder_derives_view_from_secret_not_pubkey() {
        let b = PlaceholderBackend;
        let kp = KeyPair::generate();
        // Critical: derive from SECRET. The pubkey would have let
        // anyone with the on-chain address recompute the view key.
        let secret = kp.secret_bytes();
        let v = b.derive_view_pubkey(&secret);
        // Distinct ephemeral secrets → distinct stealth tags.
        let s = b.derive_stealth_output(&v, &[7u8; 32]);
        let s2 = b.derive_stealth_output(&v, &[8u8; 32]);
        assert_ne!(s, s2);
    }

    #[tokio::test]
    async fn placeholder_is_octra_validator_errors_loudly() {
        let b = PlaceholderBackend;
        let addr = Address::from_display("octABC");
        let r = b.is_octra_validator(&addr).await;
        assert!(
            r.is_err(),
            "placeholder must refuse to answer authoritatively"
        );
    }
}
