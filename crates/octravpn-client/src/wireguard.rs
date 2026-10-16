//! WireGuard identities derive from secret material, never a published key.
use octravpn_core::{sig::KeyPair, util};
use x25519_dalek::{PublicKey, StaticSecret};

mod forward;
#[cfg(test)]
mod integration_tests;
mod io;
mod ip;
pub(crate) mod recovery;
mod tunnel;

pub(crate) use forward::Forward;
pub(crate) use io::Mode;
pub(crate) use tunnel::{Traffic, Tunnel};

pub(crate) fn validate_peer_key(key: [u8; 32]) -> anyhow::Result<()> {
    tunnel::validate_peer_key(key)
}

pub(crate) fn validate_endpoint(endpoint: &str) -> anyhow::Result<()> {
    tunnel::validate_endpoint(endpoint).map(|_| ())
}

fn secret(keypair: &KeyPair) -> StaticSecret {
    let bytes = keypair.secret_bytes();
    StaticSecret::from(util::derive_subkey(&bytes, util::DOMAIN_NOISE))
}

pub(crate) fn public_key(keypair: &KeyPair) -> [u8; 32] {
    PublicKey::from(&secret(keypair)).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn published_signing_key_cannot_reconstruct_wireguard_identity() {
        let keypair = KeyPair::from_secret_bytes(&[71; 32]);
        let public_derived =
            StaticSecret::from(util::derive_subkey(&keypair.public.0, util::DOMAIN_NOISE));
        assert_ne!(
            public_key(&keypair),
            PublicKey::from(&public_derived).to_bytes()
        );
        let expected = StaticSecret::from(util::derive_subkey(&[71; 32], util::DOMAIN_NOISE));
        assert_eq!(public_key(&keypair), PublicKey::from(&expected).to_bytes());
    }
}
