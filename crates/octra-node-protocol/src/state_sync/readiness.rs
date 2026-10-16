//! Native observer readiness is a signed local statement, not a validator-set
//! certificate. Serving it requires a separate retained canonical-head check.
use super::{lower_hex, require, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

pub const MAX_BYTES: usize = 16 * 1024;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Marker {
    pub version: String,
    pub status: String,
    pub consensus_role: String,
    pub leader_rpc: String,
    pub chain_id: String,
    pub validator: String,
    pub validator_pubkey: String,
    pub ready_epoch: String,
    pub state_root: String,
    pub catchup_records_verified: i64,
    pub sign_payload: String,
    pub signature: String,
    pub generated_at: f64,
}
impl Marker {
    pub fn payload(chain: &str, validator: &str, epoch: i64, root: &str, records: i64) -> String {
        format!("octra:observer-ready:v1|{chain}|{validator}|{epoch}|{root}|{records}")
    }
    pub fn parse(raw: &[u8]) -> Result<Self> {
        require(
            raw.len() <= MAX_BYTES,
            "readiness marker exceeds byte limit",
        )?;
        serde_json::from_slice(raw).map_err(|e| e.to_string().into())
    }
    /// Identity is supplied by the local launcher; a marker cannot introduce a
    /// signer. Role, source and timestamp are native unsigned diagnostic fields.
    pub fn verify(&self, chain: &[u8], address: &[u8], public_key: &[u8]) -> Result<i64> {
        require(
            self.version == "octra-observer-ready" && self.status == "observer_ready",
            "invalid readiness marker version/status",
        )?;
        require(
            self.chain_id.as_bytes() == chain && self.validator.as_bytes() == address,
            "readiness marker identity differs",
        )?;
        require(
            !chain.contains(&b'|') && !address.contains(&b'|'),
            "ambiguous readiness identity",
        )?;
        require(
            lower_hex(self.state_root.as_bytes(), 64),
            "invalid readiness root",
        )?;
        let epoch = self
            .ready_epoch
            .parse::<i64>()
            .map_err(|_| "invalid readiness epoch")?;
        require(
            (0..(1_i64 << 62)).contains(&epoch) && epoch.to_string() == self.ready_epoch,
            "invalid readiness epoch",
        )?;
        require(
            self.catchup_records_verified > 0 && self.catchup_records_verified < (1_i64 << 62),
            "readiness marker has no verified records",
        )?;
        require(
            self.generated_at.is_finite() && self.generated_at >= 0.,
            "invalid readiness timestamp",
        )?;
        require(
            self.leader_rpc.len() <= 4096 && self.consensus_role.len() <= 64,
            "readiness diagnostics exceed limit",
        )?;
        let key = crate::native_base64::decode(self.validator_pubkey.as_bytes())
            .map_err(|e| e.to_string())?;
        require(
            key == public_key && STANDARD.encode(&key) == self.validator_pubkey,
            "readiness public key differs",
        )?;
        let derived = crate::transaction::address_from_public_key(self.validator_pubkey.as_bytes());
        require(derived == address, "readiness address does not bind signer")?;
        let payload = Self::payload(
            &self.chain_id,
            &self.validator,
            epoch,
            &self.state_root,
            self.catchup_records_verified,
        );
        require(
            payload == self.sign_payload,
            "readiness signing payload differs",
        )?;
        let signature =
            crate::native_base64::decode(self.signature.as_bytes()).map_err(|e| e.to_string())?;
        require(
            STANDARD.encode(&signature) == self.signature,
            "noncanonical readiness signature",
        )?;
        let key: [u8; 32] = key.try_into().map_err(|_| "invalid readiness public key")?;
        let signature = Signature::from_slice(&signature).map_err(|e| e.to_string())?;
        VerifyingKey::from_bytes(&key)
            .map_err(|e| e.to_string())?
            .verify_strict(payload.as_bytes(), &signature)
            .map_err(|_| "readiness signature is invalid")?;
        Ok(epoch)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signed() -> (Marker, Vec<u8>, [u8; 32]) {
        let key = SigningKey::from_bytes(&[23; 32]);
        let public = STANDARD.encode(key.verifying_key().as_bytes());
        let address = crate::transaction::address_from_public_key(public.as_bytes());
        let chain = "join-fixture";
        let root = "ab".repeat(32);
        let payload = Marker::payload(chain, std::str::from_utf8(&address).unwrap(), 27, &root, 4);
        (
            Marker {
                version: "octra-observer-ready".into(),
                status: "observer_ready".into(),
                consensus_role: "observer".into(),
                leader_rpc: "http://127.0.0.1:19870".into(),
                chain_id: chain.into(),
                validator: String::from_utf8(address.clone()).unwrap(),
                validator_pubkey: public,
                ready_epoch: "27".into(),
                state_root: root,
                catchup_records_verified: 4,
                signature: STANDARD.encode(key.sign(payload.as_bytes()).to_bytes()),
                sign_payload: payload,
                generated_at: 1.,
            },
            address,
            key.verifying_key().to_bytes(),
        )
    }
    #[test]
    fn signed_readiness_cannot_change_epoch_root_records_or_identity() {
        let (marker, address, key) = signed();
        assert_eq!(marker.verify(b"join-fixture", &address, &key).unwrap(), 27);
        assert!(marker.verify(b"another-chain", &address, &key).is_err());
        assert!(marker.verify(b"join-fixture", &address, &[42; 32]).is_err());
        for mutate in 0..5 {
            let mut changed = marker.clone();
            match mutate {
                0 => changed.ready_epoch = "28".into(),
                1 => changed.state_root = "cd".repeat(32),
                2 => changed.catchup_records_verified = 5,
                3 => changed.sign_payload.push('|'),
                _ => changed.signature = STANDARD.encode([0; 64]),
            }
            assert!(
                changed.verify(b"join-fixture", &address, &key).is_err(),
                "mutation {mutate}"
            );
        }
    }
    #[test]
    fn readiness_diagnostics_are_explicitly_unsigned_and_parsing_is_bounded() {
        let (mut marker, address, key) = signed();
        marker.leader_rpc = "http://127.0.0.1:12345".into();
        marker.consensus_role = "validator".into();
        marker.generated_at = 2.;
        assert!(marker.verify(b"join-fixture", &address, &key).is_ok());
        let bytes = serde_json::to_vec(&marker).unwrap();
        assert!(Marker::parse(&bytes).is_ok());
        assert!(Marker::parse(&vec![b' '; MAX_BYTES + 1]).is_err());
        let mut duplicate = bytes[..bytes.len() - 1].to_vec();
        duplicate.extend_from_slice(b",\"ready_epoch\":\"27\"}");
        assert!(Marker::parse(&duplicate).is_err());
    }
}
