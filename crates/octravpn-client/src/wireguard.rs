//! WireGuard identities derive from secret material, never a published key.
use octravpn_core::{sig::KeyPair, util};
use x25519_dalek::{PublicKey, StaticSecret};

pub(crate) fn public_key(keypair: &KeyPair) -> [u8; 32] {
    let secret = StaticSecret::from(util::derive_subkey(
        &keypair.secret_bytes(),
        util::DOMAIN_NOISE,
    ));
    PublicKey::from(&secret).to_bytes()
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
