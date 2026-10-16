//! Stable local VPN identities derived from the node key. Only the public
//! descriptor crosses the operator CLI boundary.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::SigningKey;
use octravpn_core::{address::Address, sig::KeyPair};
use sha2::{Digest, Sha256};
use std::sync::Arc;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

pub struct Keys {
    pub receipt: Arc<KeyPair>,
    pub wireguard: StaticSecret,
    pub operator: Address,
}
impl Keys {
    pub fn derive(node: &SigningKey) -> Self {
        // These labels preserve the established native client identity across
        // restarts and upgrades, including nodes originally created on devnet.
        let secret = Zeroizing::new(node.to_bytes());
        let derive = |label: &[u8]| {
            let mut hash = Sha256::new();
            hash.update(label);
            hash.update(secret.as_slice());
            Zeroizing::new(<[u8; 32]>::from(hash.finalize()))
        };
        let receipt = derive(b"devnet-vpn-receipts");
        let wireguard = derive(b"devnet-vpn-wireguard");
        Self {
            receipt: Arc::new(KeyPair::from_secret_bytes(&receipt)),
            wireguard: StaticSecret::from(*wireguard),
            operator: Address::from_pubkey(node.verifying_key().as_bytes()),
        }
    }
    pub fn public(&self) -> serde_json::Value {
        serde_json::json!({
            "operator": self.operator.display(),
            "receipt_pubkey_b64": STANDARD.encode(self.receipt.public.0),
            "wg_pubkey_b64": STANDARD.encode(PublicKey::from(&self.wireguard).to_bytes()),
            "transport": { "kind": "wireguard" }
        })
    }
}
