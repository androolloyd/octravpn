//! Private operator accounting. These signed snapshots authenticate a view,
//! not chain finality or delivery. Carry them over authenticated encryption.
//! A quote ceiling is not a withdrawable native channel balance.
use super::{
    connection::wireguard_key, public_key, signature, verify_authorization, Address, Connect,
    Error, KeyPair, PublicKey, Result, Signature, Tariff,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ShieldedStatus {
    pub connection: Connect,
    #[serde(with = "wireguard_key")]
    pub server_wireguard_key: [u8; 32],
    pub tariff: Tariff,
    pub operator_generation: u64,
    pub quote_ceiling_ou: u64,
    /// OCT represented by the uniquely credited byte purchases, not all income.
    pub paid_ou: u64,
    pub purchased_totals: Vec<u64>,
    pub committed_totals: Vec<u64>,
    /// Uncertain and currently reserved IO both retain prepaid capacity.
    pub held_totals: Vec<u64>,
    pub canonical_ms: u64,
    /// Durable slot for committed counters only. Funding, held bytes and the
    /// canonical clock may change within that slot.
    pub service_sequence: u64,
}
impl ShieldedStatus {
    pub fn validate(&self) -> Result<()> {
        self.connection.validate()?;
        if self.server_wireguard_key == [0; 32]
            || self.operator_generation == 0
            || self.canonical_ms == 0
            || self.service_sequence == 0
            || self.quote_ceiling_ou == 0
            || i64::try_from(self.quote_ceiling_ou).is_err()
            || self.paid_ou > self.quote_ceiling_ou
        {
            return Err(Error::Invalid(
                "invalid shielded status identity or accounting",
            ));
        }
        if self.tariff.hash_hex()? != self.connection.binding.manifest_hash {
            return Err(Error::Invalid("shielded status tariff differs"));
        }
        let classes = self.tariff.classes().len();
        if self.purchased_totals.len() != classes
            || self.committed_totals.len() != classes
            || self.held_totals.len() != classes
        {
            return Err(Error::Invalid("shielded status class shape differs"));
        }
        for ((paid, used), held) in self
            .purchased_totals
            .iter()
            .zip(&self.committed_totals)
            .zip(&self.held_totals)
        {
            if used.checked_add(*held).ok_or(Error::Overflow)? > *paid {
                return Err(Error::Invalid("shielded status exceeds prepaid bytes"));
            }
        }
        if self.tariff.total_charge(&self.purchased_totals)? > self.paid_ou {
            return Err(Error::Invalid("shielded status price differs"));
        }
        Ok(())
    }
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut message = b"Octranet shielded status v1\0".to_vec();
        crate::v3_canonical::canonical_write(&serde_json::to_value(self)?, &mut message);
        Ok(message)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedShieldedStatus {
    pub status: ShieldedStatus,
    #[serde(with = "public_key")]
    pub operator_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}
impl SignedShieldedStatus {
    pub fn sign(status: ShieldedStatus, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(&status.signing_message()?);
        let result = Self {
            status,
            operator_key: key.public,
            signature,
        };
        result.verify()?;
        Ok(result)
    }
    pub fn verify(&self) -> Result<()> {
        if Address::from_pubkey(&self.operator_key.0) != *self.status.tariff.operator() {
            return Err(Error::Invalid("shielded status operator differs"));
        }
        verify_authorization(
            &self.operator_key,
            &self.status.signing_message()?,
            &self.signature,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::{Deployment, PlanBinding, TrafficClass, BYTES_PER_MIB};
    fn fixture() -> (ShieldedStatus, KeyPair) {
        let key = KeyPair::from_secret_bytes(&[7; 32]);
        let tariff = Tariff::new(
            Address::from_pubkey(&key.public.0),
            vec![TrafficClass {
                name: "internet".into(),
                rate_ou_per_mib: 10,
            }],
            vec![],
        )
        .unwrap();
        (
            ShieldedStatus {
                connection: Connect {
                    binding: PlanBinding {
                        deployment: Deployment {
                            domain: "a".repeat(64),
                            program: Address::from_pubkey(&[9; 32]),
                        },
                        payer: Address::from_pubkey(&[8; 32]),
                        generation: 1,
                        plan: 1,
                        offer: 0,
                        manifest_hash: tariff.hash_hex().unwrap(),
                    },
                    sequence: 1,
                    wireguard_key: [11; 32],
                },
                server_wireguard_key: [12; 32],
                tariff,
                operator_generation: 1,
                quote_ceiling_ou: 100,
                paid_ou: 10,
                purchased_totals: vec![BYTES_PER_MIB],
                committed_totals: vec![100],
                held_totals: vec![200],
                canonical_ms: 1_000,
                service_sequence: 1,
            },
            key,
        )
    }
    #[test]
    fn private_status_binds_all_counters_connection_and_accounting_without_public_balance() {
        let (status, key) = fixture();
        let signed = SignedShieldedStatus::sign(status, &key).unwrap();
        let wire = serde_json::to_vec(&signed).unwrap();
        let decoded: SignedShieldedStatus = serde_json::from_slice(&wire).unwrap();
        decoded.verify().unwrap();
        assert!(serde_json::from_slice::<crate::payments::SignedStatus>(&wire).is_err());
        let mutations: [fn(&mut ShieldedStatus); 14] = [
            |s| s.connection.binding.plan += 1,
            |s| s.connection.sequence += 1,
            |s| s.connection.wireguard_key[0] ^= 1,
            |s| s.server_wireguard_key[0] ^= 1,
            |s| s.operator_generation += 1,
            |s| s.quote_ceiling_ou += 1,
            |s| s.paid_ou += 1,
            |s| s.purchased_totals[0] -= 1,
            |s| s.committed_totals[0] += 1,
            |s| s.held_totals[0] += 1,
            |s| s.canonical_ms += 1,
            |s| s.service_sequence += 1,
            |s| s.connection.binding.generation += 1,
            |s| s.connection.binding.deployment.domain = "b".repeat(64),
        ];
        for mutate in mutations {
            let mut copy = signed.clone();
            mutate(&mut copy.status);
            assert!(copy.verify().is_err());
        }
    }
    #[test]
    fn impossible_private_floors_prices_and_pending_counters_refuse_signing() {
        let (base, key) = fixture();
        let mutations: [fn(&mut ShieldedStatus); 8] = [
            |s| s.paid_ou = 9,
            |s| s.paid_ou = 101,
            |s| s.quote_ceiling_ou = 0,
            |s| s.service_sequence = 0,
            |s| s.held_totals[0] = BYTES_PER_MIB,
            |s| s.committed_totals[0] = u64::MAX,
            |s| s.purchased_totals.clear(),
            |s| s.operator_generation = 0,
        ];
        for mutate in mutations {
            let mut copy = base.clone();
            mutate(&mut copy);
            assert!(SignedShieldedStatus::sign(copy, &key).is_err());
        }
    }
}
