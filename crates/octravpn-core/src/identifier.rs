//! Native application and Circle identifiers also include addresses whose
//! Base58 magnitude exceeds the wallet codec's 32-byte digest range.
use crate::{Address, CoreError, CoreResult};

/// Validate the native `oct` + 44 Base58 identifier grammar, then retain the
/// established Address mapping: wallet digests decode directly; other native
/// identifiers use SHA256 of the exact display text. Wallet ownership checks
/// must continue to use `Address::try_from_display` and public-key derivation.
pub fn parse_native_address(display: &str) -> CoreResult<Address> {
    if display.len() != 47
        || !display.starts_with("oct")
        || !display.as_bytes()[3..].iter().all(|byte| {
            b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(byte)
        })
    {
        return Err(CoreError::InvalidEncoding(
            "invalid native Octra identifier".into(),
        ));
    }
    Ok(Address::from_display(display))
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn native_identifiers_preserve_wallet_and_spawned_receipt_domains() {
        let wallet = Address::from_pubkey(&[7; 32]);
        assert_eq!(parse_native_address(wallet.display()).unwrap(), wallet);
        // Actual factory child emitted by the isolated native qualification.
        let spawned = "octQpqKSqmuxfmWZyyJ4mEtorJm5iaoZAmQDC7DZmWpyv83";
        assert!(Address::try_from_display(spawned).is_err());
        let address = parse_native_address(spawned).unwrap();
        assert_eq!(address.display(), spawned);
        assert_eq!(
            address.as_bytes().as_slice(),
            Sha256::digest(spawned.as_bytes()).as_slice()
        );
        let roundtrip: Address =
            serde_json::from_slice(&serde_json::to_vec(&address).unwrap()).unwrap();
        assert_eq!(roundtrip, address);
        assert_ne!(
            parse_native_address("octRpqKSqmuxfmWZyyJ4mEtorJm5iaoZAmQDC7DZmWpyv83").unwrap(),
            address
        );
    }
    #[test]
    fn native_identifier_validation_rejects_malformed_input() {
        for bad in [
            "oct",
            "xxxQpqKSqmuxfmWZyyJ4mEtorJm5iaoZAmQDC7DZmWpyv83",
            "oct0pqKSqmuxfmWZyyJ4mEtorJm5iaoZAmQDC7DZmWpyv83",
            "octQpqKSqmuxfmWZyyJ4mEtorJm5iaoZAmQDC7DZmWpyv8\n",
        ] {
            assert!(parse_native_address(bad).is_err(), "{bad:?}");
        }
    }
}
