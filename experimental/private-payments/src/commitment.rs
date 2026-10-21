//! Amount-opening verification using the existing source-qualified HFHE port.
//! A matching opening is not proof of a canonical debit or payment finality.
use crate::native_stealth::Amount;
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use octra_hfhe::{proof::generators::pedersen_commit, scalar::Scalar};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

pub fn check_opening(amount: &Amount, encoded_commitment: &str) -> Result<()> {
    ensure!(
        amount.value() <= i64::MAX as u64,
        "native payment amount out of range"
    );
    ensure!(
        encoded_commitment.len() == 44,
        "invalid native amount commitment size"
    );
    let actual: [u8; 32] = STANDARD
        .decode(encoded_commitment)
        .context("invalid native amount commitment encoding")?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid native amount commitment size"))?;
    let value = Zeroizing::new(Scalar::from_u64(amount.value()));
    let blinding = Zeroizing::new(Scalar::from_bytes_raw(amount.blinding()));
    let expected = pedersen_commit(&value, &blinding);
    ensure!(
        bool::from(actual.ct_eq(&expected)),
        "native amount opening differs"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[test]
    fn existing_actual_native_generator_vectors_bind_amount_and_blinding() {
        let fixture: Value =
            serde_json::from_str(include_str!("../tests/native-commitments.json")).unwrap();
        assert_eq!(
            fixture["upstream_commit"],
            "d3e834919bd586e81f947d0dae91becc6c43c756"
        );
        for row in fixture["cases"].as_array().unwrap() {
            let value = row["amount"].as_u64().unwrap();
            let blind: [u8; 32] = hex::decode(row["blind"].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap();
            let encoded =
                STANDARD.encode(hex::decode(row["commitment"].as_str().unwrap()).unwrap());
            assert!(check_opening(&Amount::new(value, blind), &encoded).is_ok());
            assert!(check_opening(&Amount::new(value + 1, blind), &encoded).is_err());
            let mut wrong = blind;
            wrong[0] ^= 1;
            assert!(check_opening(&Amount::new(value, wrong), &encoded).is_err());
            assert!(check_opening(&Amount::new(value, blind), &"?".repeat(44)).is_err());
            assert!(check_opening(&Amount::new(value, blind), &"A".repeat(1_000_000)).is_err());
        }
    }

    #[test]
    fn codec_uint64_does_not_bypass_native_payment_int64_range() {
        assert!(check_opening(&Amount::new(u64::MAX, [0; 32]), &STANDARD.encode([0; 32])).is_err());
    }
}
