//! Operator-signed service statements. Only conflicting statements for the
//! same plan, class and sequence can slash; these do not prove non-delivery.
use serde::{Deserialize, Serialize};

use super::{
    native, native_address, public_key, signature, verify_authorization, Address, Error, KeyPair,
    PublicKey, Result, Signature, Usage,
};
use crate::b64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReceipt {
    pub usage: Usage,
    #[serde(with = "native_address")]
    pub operator: Address,
    pub operator_generation: u64,
}

impl ServiceReceipt {
    pub fn signing_message(&self) -> Result<String> {
        self.usage.validate()?;
        native(&self.operator)?;
        if self.operator_generation == 0 {
            return Err(Error::Invalid("zero operator generation"));
        }
        let usage = &self.usage;
        Ok(format!(
            "Octranet service receipt v1|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            usage.deployment.domain,
            usage.deployment.program,
            self.operator,
            self.operator_generation,
            usage.plan,
            usage.payer,
            usage.generation,
            usage.offer,
            usage.manifest_hash,
            usage.traffic_class,
            usage.sequence,
            usage.total_bytes
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedServiceReceipt {
    pub receipt: ServiceReceipt,
    #[serde(with = "public_key")]
    pub operator_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}

impl SignedServiceReceipt {
    pub fn sign(receipt: ServiceReceipt, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(receipt.signing_message()?.as_bytes());
        let signed = Self {
            receipt,
            operator_key: key.public,
            signature,
        };
        signed.verify()?;
        Ok(signed)
    }

    pub fn verify(&self) -> Result<()> {
        if Address::from_pubkey(&self.operator_key.0) != self.receipt.operator {
            return Err(Error::Invalid("service signer differs from operator"));
        }
        verify_authorization(
            &self.operator_key,
            self.receipt.signing_message()?.as_bytes(),
            &self.signature,
        )
    }

    pub fn slash_params(a: &Self, b: &Self) -> Result<serde_json::Value> {
        a.verify()?;
        b.verify()?;
        let mut same = a.receipt.clone();
        same.usage.total_bytes = b.receipt.usage.total_bytes;
        if same != b.receipt
            || a.receipt.usage.total_bytes == b.receipt.usage.total_bytes
            || a.operator_key != b.operator_key
        {
            return Err(Error::Invalid(
                "service receipts do not conflict in one slot",
            ));
        }
        let usage = &a.receipt.usage;
        Ok(serde_json::json!([
            usage.plan,
            usage.traffic_class,
            usage.sequence,
            usage.total_bytes,
            b64::encode(a.signature.0),
            b.receipt.usage.total_bytes,
            b64::encode(b.signature.0)
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::Deployment;

    #[test]
    fn same_slot_conflict_is_constructible_but_different_slot_is_not() {
        let payer = crate::address::Address::from_pubkey(&[12; 32]);
        let key = KeyPair::from_secret_bytes(&[31; 32]);
        let operator = crate::address::Address::from_pubkey(&key.public.0);
        let receipt = ServiceReceipt {
            usage: Usage {
                deployment: Deployment {
                    domain: "a".repeat(64),
                    program: operator.clone(),
                },
                payer,
                generation: 1,
                plan: 7,
                offer: 3,
                manifest_hash: "b".repeat(64),
                traffic_class: 0,
                sequence: 9,
                total_bytes: 100,
            },
            operator,
            operator_generation: 2,
        };
        let a = SignedServiceReceipt::sign(receipt.clone(), &key).unwrap();
        assert!(SignedServiceReceipt::sign(
            receipt.clone(),
            &KeyPair::from_secret_bytes(&[41; 32])
        )
        .is_err());
        let mut other = receipt;
        other.usage.total_bytes = 101;
        let b = SignedServiceReceipt::sign(other.clone(), &key).unwrap();
        assert!(SignedServiceReceipt::slash_params(&a, &b).is_ok());
        other.usage.sequence += 1;
        let unrelated = SignedServiceReceipt::sign(other, &key).unwrap();
        assert!(SignedServiceReceipt::slash_params(&a, &unrelated).is_err());
        assert!(SignedServiceReceipt::slash_params(&a, &a).is_err());
    }
}
