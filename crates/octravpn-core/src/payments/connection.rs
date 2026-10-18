//! Receipt-key authorization for a plan-bound WireGuard connection.
//! A signature and session ID do not establish funding or canonical admission.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{
    b64, deserialize_hash, deserialize_positive, hash, native, native_address, public_key,
    signature, verify_authorization, Address, Deployment, Error, KeyPair, PublicKey, Result,
    Signature, Tariff,
};
use crate::session::SessionId;

/// Immutable payment identity shared by receipts, metering and transport.
/// Native addresses remain JSON strings, matching existing meter records.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlanBinding {
    pub deployment: Deployment,
    #[serde(with = "native_address")]
    pub payer: Address,
    #[serde(deserialize_with = "deserialize_positive")]
    pub generation: u64,
    pub plan: u64,
    pub offer: u64,
    #[serde(deserialize_with = "deserialize_hash")]
    pub manifest_hash: String,
}

impl PlanBinding {
    pub fn validate(&self) -> Result<()> {
        self.deployment.validate()?;
        native(&self.payer)?;
        hash(&self.manifest_hash)?;
        if self.generation == 0 {
            return Err(Error::Invalid("zero account generation"));
        }
        Ok(())
    }

    fn transcript(&self, domain: &str) -> Result<String> {
        self.validate()?;
        // All fields have canonical alphabets without '|'; decimal integers
        // and fixed-order separators therefore have one unambiguous encoding.
        Ok(format!(
            "{domain}|{}|{}|{}|{}|{}|{}|{}",
            self.deployment.domain,
            self.deployment.program,
            self.payer,
            self.generation,
            self.plan,
            self.offer,
            self.manifest_hash
        ))
    }

    /// Stable transport identity, independent of connection sequence or key.
    /// The host must separately verify current canonical funding and admission.
    pub fn session_id(&self) -> Result<SessionId> {
        let message = self.transcript("Octranet session v1")?;
        Ok(SessionId::new(Sha256::digest(message.as_bytes()).into()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Connect {
    pub binding: PlanBinding,
    #[serde(deserialize_with = "deserialize_positive")]
    pub sequence: u64,
    #[serde(with = "wireguard_key")]
    pub wireguard_key: [u8; 32],
}

impl Connect {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.sequence == 0 {
            return Err(Error::Invalid("zero connection sequence"));
        }
        if self.wireguard_key == [0; 32] {
            return Err(Error::Invalid("zero WireGuard public key"));
        }
        Ok(())
    }

    /// Raw ASCII signed by the account's receipt key, without a prehash or JSON.
    pub fn signing_message(&self) -> Result<String> {
        self.message("Octranet connect v1")
    }
    fn message(&self, domain: &str) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "{}|{}|{}",
            self.binding.transcript(domain)?,
            self.sequence,
            b64::encode(self.wireguard_key)
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedConnect {
    pub request: Connect,
    #[serde(with = "public_key")]
    pub receipt_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}

impl SignedConnect {
    pub fn sign(request: Connect, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(request.signing_message()?.as_bytes());
        Ok(Self {
            request,
            receipt_key: key.public,
            signature,
        })
    }

    /// Stock raw-IP mode has a distinct signing domain. Its signature cannot
    /// be replayed through the framed endpoint before the stock first-use write.
    pub fn sign_stock(request: Connect, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(request.message("Octranet stock connect v1")?.as_bytes());
        Ok(Self {
            request,
            receipt_key: key.public,
            signature,
        })
    }
    pub fn verify_stock(&self) -> Result<()> {
        verify_authorization(
            &self.receipt_key,
            self.request
                .message("Octranet stock connect v1")?
                .as_bytes(),
            &self.signature,
        )
    }
    /// Cryptographic authorization only. The caller also checks the current
    /// canonical receipt key/generation, sequence, tariff, plan and funding.
    pub fn verify(&self) -> Result<()> {
        verify_authorization(
            &self.receipt_key,
            self.request.signing_message()?.as_bytes(),
            &self.signature,
        )
    }
}

/// Operator's authenticated view of one connection and its payment capacity.
/// This carries no promise that the snapshot remains current after signing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Status {
    pub binding: PlanBinding,
    #[serde(deserialize_with = "deserialize_positive")]
    pub connect_sequence: u64,
    #[serde(with = "wireguard_key")]
    pub client_wireguard_key: [u8; 32],
    #[serde(with = "wireguard_key")]
    pub server_wireguard_key: [u8; 32],
    pub tariff: Tariff,
    pub original_budget_ou: u64,
    pub remaining_ou: u64,
    /// Locally confirmed forwarded bytes, separately from purchased capacity.
    pub committed_totals: Vec<u64>,
    /// Cumulative prepaid byte entitlements from canonical application state.
    pub redeemed_totals: Vec<u64>,
    #[serde(deserialize_with = "deserialize_positive")]
    pub canonical_ms: u64,
    #[serde(deserialize_with = "deserialize_positive")]
    pub claim_deadline_ms: u64,
}

impl Status {
    pub fn validate(&self) -> Result<()> {
        self.binding.validate()?;
        if self.connect_sequence == 0 {
            return Err(Error::Invalid("zero connection sequence"));
        }
        if self.client_wireguard_key == [0; 32] || self.server_wireguard_key == [0; 32] {
            return Err(Error::Invalid("zero WireGuard public key"));
        }
        if self.tariff.hash_hex()? != self.binding.manifest_hash {
            return Err(Error::Invalid("status tariff differs from plan manifest"));
        }
        let classes = self.tariff.classes().len();
        if self.committed_totals.len() != classes || self.redeemed_totals.len() != classes {
            return Err(Error::Invalid("status counter/class count mismatch"));
        }
        if self
            .redeemed_totals
            .iter()
            .zip(&self.committed_totals)
            .any(|(redeemed, committed)| committed > redeemed)
        {
            return Err(Error::Invalid("delivery exceeds prepaid bytes"));
        }
        let charge = self.tariff.total_charge(&self.redeemed_totals)?;
        if charge > self.original_budget_ou {
            return Err(Error::BudgetExceeded {
                required: charge,
                budget: self.original_budget_ou,
            });
        }
        // The signed status is an operator view, not a canonical state proof.
        if self.remaining_ou > self.original_budget_ou {
            return Err(Error::Invalid("remaining balance exceeds original budget"));
        }
        if self.canonical_ms == 0 || self.claim_deadline_ms <= self.canonical_ms {
            return Err(Error::Invalid("status canonical clock or claim deadline"));
        }
        Ok(())
    }

    /// Domain-separated canonical JSON bytes, without a prehash.
    pub fn signing_message(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut message = b"Octranet prepaid status v1\0".to_vec();
        crate::v3_canonical::canonical_write(&serde_json::to_value(self)?, &mut message);
        Ok(message)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedStatus {
    pub status: Status,
    #[serde(with = "public_key")]
    pub operator_key: PublicKey,
    #[serde(with = "signature")]
    pub signature: Signature,
}

impl SignedStatus {
    pub fn sign(status: Status, key: &KeyPair) -> Result<Self> {
        let signature = key.sign(&status.signing_message()?);
        let signed = Self {
            status,
            operator_key: key.public,
            signature,
        };
        signed.verify()?;
        Ok(signed)
    }

    /// Authenticates an operator snapshot. The client still matches it to its
    /// requested binding, sequence and key and independently checks freshness.
    pub fn verify(&self) -> Result<()> {
        if Address::from_pubkey(&self.operator_key.0) != *self.status.tariff.operator() {
            return Err(Error::Invalid("status signer differs from tariff operator"));
        }
        verify_authorization(
            &self.operator_key,
            &self.status.signing_message()?,
            &self.signature,
        )
    }
}

mod wireguard_key {
    use serde::{de::Error as _, Deserialize, Deserializer, Serializer};

    use super::b64;

    pub(super) fn serialize<S: Serializer>(
        value: &[u8; 32],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        if *value == [0; 32] {
            return Err(serde::ser::Error::custom("zero WireGuard public key"));
        }
        serializer.serialize_str(&b64::encode(value))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<[u8; 32], D::Error> {
        let text = String::deserialize(deserializer)?;
        let bytes = b64::decode(&text).map_err(D::Error::custom)?;
        let raw = <[u8; 32]>::try_from(bytes)
            .map_err(|_| D::Error::custom("expected 32-byte WireGuard public key"))?;
        if raw == [0; 32] || b64::encode(raw) != text {
            return Err(D::Error::custom(
                "zero or noncanonical WireGuard public key",
            ));
        }
        Ok(raw)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payments::{SignedUsage, TrafficClass, Usage, BYTES_PER_MIB};
    use serde_json::json;

    fn binding() -> PlanBinding {
        PlanBinding {
            deployment: Deployment {
                domain: "a".repeat(64),
                program: Address::from_pubkey(&[1; 32]),
            },
            payer: Address::from_pubkey(&[2; 32]),
            generation: 1,
            plan: 0,
            offer: 3,
            manifest_hash: "b".repeat(64),
        }
    }

    fn request() -> Connect {
        Connect {
            binding: binding(),
            sequence: 7,
            wireguard_key: [8; 32],
        }
    }

    fn status() -> Status {
        let key = KeyPair::from_secret_bytes(&[11; 32]);
        let tariff = Tariff::new(
            Address::from_pubkey(&key.public.0),
            vec![
                TrafficClass {
                    name: "default".to_owned(),
                    rate_ou_per_mib: 2,
                },
                TrafficClass {
                    name: "premium".to_owned(),
                    rate_ou_per_mib: 4,
                },
            ],
            Vec::new(),
        )
        .unwrap();
        let mut binding = binding();
        binding.manifest_hash = tariff.hash_hex().unwrap();
        Status {
            binding,
            connect_sequence: 7,
            client_wireguard_key: [8; 32],
            server_wireguard_key: [9; 32],
            tariff,
            original_budget_ou: 20,
            remaining_ou: 17,
            committed_totals: vec![BYTES_PER_MIB / 2, 0],
            redeemed_totals: vec![BYTES_PER_MIB, BYTES_PER_MIB / 2],
            canonical_ms: 1_000,
            claim_deadline_ms: 86_401_000,
        }
    }

    fn changed_bindings(original: &PlanBinding) -> Vec<PlanBinding> {
        let mut variants = Vec::new();
        let mut changed = original.clone();
        changed.deployment.domain = "c".repeat(64);
        variants.push(changed);
        let mut changed = original.clone();
        changed.deployment.program = Address::from_pubkey(&[3; 32]);
        variants.push(changed);
        let mut changed = original.clone();
        changed.payer = Address::from_pubkey(&[3; 32]);
        variants.push(changed);
        let mut changed = original.clone();
        changed.generation += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.plan += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.offer += 1;
        variants.push(changed);
        let mut changed = original.clone();
        changed.manifest_hash = "c".repeat(64);
        variants.push(changed);
        variants
    }

    #[test]
    fn binding_preserves_meter_json_and_usage_transcript() {
        let binding = binding();
        assert_eq!(
            serde_json::to_value(&binding).unwrap(),
            json!({
                "deployment": {
                    "domain": "a".repeat(64),
                    "program": binding.deployment.program.display(),
                },
                "payer": binding.payer.display(),
                "generation": 1,
                "plan": 0,
                "offer": 3,
                "manifest_hash": "b".repeat(64),
            })
        );
        let raw = serde_json::to_vec(&binding).unwrap();
        assert_eq!(
            serde_json::from_slice::<PlanBinding>(&raw).unwrap(),
            binding
        );
        let usage = Usage::from_binding(binding.clone(), 2, 9, 100).unwrap();
        assert_eq!(usage.binding(), binding);
        assert_eq!(
            usage.signing_message().unwrap(),
            format!(
                "Octranet prepaid v1|{}|{}|{}|1|0|3|{}|2|9|100",
                "a".repeat(64),
                binding.deployment.program,
                binding.payer,
                "b".repeat(64)
            )
        );
        assert!(Usage::from_binding(binding.clone(), 32, 1, 0).is_err());
        assert!(Usage::from_binding(binding, 0, 0, 0).is_err());
    }

    #[test]
    fn connection_ascii_authenticates_every_field_and_is_domain_separated() {
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let signed = SignedConnect::sign(request(), &key).unwrap();
        assert_eq!(
            signed.request.signing_message().unwrap(),
            format!(
                "Octranet connect v1|{}|{}|{}|1|0|3|{}|7|{}",
                "a".repeat(64),
                signed.request.binding.deployment.program,
                signed.request.binding.payer,
                "b".repeat(64),
                b64::encode([8; 32])
            )
        );
        signed.verify().unwrap();
        let raw = serde_json::to_vec(&signed).unwrap();
        let restored: SignedConnect = serde_json::from_slice(&raw).unwrap();
        assert_eq!(restored, signed);
        restored.verify().unwrap();
        for binding in changed_bindings(&signed.request.binding) {
            let mut changed = signed.clone();
            changed.request.binding = binding;
            assert!(changed.verify().is_err());
        }
        let mut changed = signed.clone();
        changed.request.sequence += 1;
        assert!(changed.verify().is_err());
        let mut changed = signed.clone();
        changed.request.wireguard_key[0] ^= 1;
        assert!(changed.verify().is_err());
        let mut changed = signed.clone();
        changed.receipt_key = KeyPair::from_secret_bytes(&[10; 32]).public;
        assert!(changed.verify().is_err());
        let mut changed = signed.clone();
        changed.signature.0[0] ^= 1;
        assert!(changed.verify().is_err());
        let usage = Usage::from_binding(binding(), 0, 7, 0).unwrap();
        let usage = SignedUsage::sign(usage, &key).unwrap();
        let mut changed = signed;
        changed.signature = usage.signature;
        assert!(changed.verify().is_err());
    }

    #[test]
    fn stock_framing_is_signed_and_cannot_steal_the_framed_first_use_sequence() {
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let framed = SignedConnect::sign(request(), &key).unwrap();
        let stock = SignedConnect::sign_stock(request(), &key).unwrap();
        framed.verify().unwrap();
        stock.verify_stock().unwrap();
        assert_ne!(stock.signature, framed.signature);
        assert!(stock.verify().is_err());
        assert!(framed.verify_stock().is_err());
        for binding in changed_bindings(&stock.request.binding) {
            let mut changed = stock.clone();
            changed.request.binding = binding;
            assert!(changed.verify_stock().is_err());
        }
        let mut changed = stock.clone();
        changed.request.sequence += 1;
        assert!(changed.verify_stock().is_err());
        let mut changed = stock.clone();
        changed.request.wireguard_key[0] ^= 1;
        assert!(changed.verify_stock().is_err());
        let mut changed = stock;
        changed.receipt_key = KeyPair::from_secret_bytes(&[10; 32]).public;
        assert!(changed.verify_stock().is_err());
    }

    #[test]
    fn session_identity_covers_all_binding_fields_but_not_connection_keys() {
        let binding = binding();
        let expected = format!(
            "Octranet session v1|{}|{}|{}|1|0|3|{}",
            "a".repeat(64),
            binding.deployment.program,
            binding.payer,
            "b".repeat(64)
        );
        let id = binding.session_id().unwrap();
        let expected: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
        assert_eq!(id.as_bytes(), &expected);
        assert_eq!(binding.session_id().unwrap(), id);
        for changed in changed_bindings(&binding) {
            assert_ne!(changed.session_id().unwrap(), id);
        }
        let mut request = request();
        request.sequence += 1;
        request.wireguard_key = [9; 32];
        assert_eq!(request.binding.session_id().unwrap(), id);
    }

    #[test]
    fn strict_json_refuses_invalid_and_ambiguous_connection_data() {
        for path in ["request", "binding", "deployment", "signed"] {
            let key = KeyPair::from_secret_bytes(&[9; 32]);
            let mut value =
                serde_json::to_value(SignedConnect::sign(request(), &key).unwrap()).unwrap();
            let target = match path {
                "request" => &mut value["request"],
                "binding" => &mut value["request"]["binding"],
                "deployment" => &mut value["request"]["binding"]["deployment"],
                _ => &mut value,
            };
            target["unexpected"] = json!(true);
            assert!(
                serde_json::from_value::<SignedConnect>(value).is_err(),
                "{path}"
            );
        }
        for (field, invalid) in [
            ("payer", json!("bad-address")),
            ("generation", json!(0)),
            ("manifest_hash", json!("A".repeat(64))),
            ("plan", json!(-1)),
            ("offer", json!("3")),
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value["binding"][field] = invalid;
            assert!(serde_json::from_value::<Connect>(value).is_err(), "{field}");
        }
        let mut value = serde_json::to_value(request()).unwrap();
        value["binding"]["deployment"]["domain"] = json!("A".repeat(64));
        assert!(serde_json::from_value::<Connect>(value).is_err());
        let mut value = serde_json::to_value(request()).unwrap();
        value["sequence"] = json!(0);
        assert!(serde_json::from_value::<Connect>(value).is_err());
        for invalid in [
            b64::encode([0; 32]),
            b64::encode([1; 31]),
            b64::encode([1; 33]),
            b64::encode([8; 32]).trim_end_matches('=').to_owned(),
            "not-base64".to_owned(),
        ] {
            let mut value = serde_json::to_value(request()).unwrap();
            value["wireguard_key"] = json!(invalid);
            assert!(serde_json::from_value::<Connect>(value).is_err());
        }
        let raw = serde_json::to_string(&request()).unwrap();
        let duplicate = raw.replacen("\"sequence\":7", "\"sequence\":7,\"sequence\":8", 1);
        assert_ne!(raw, duplicate);
        assert!(serde_json::from_str::<Connect>(&duplicate).is_err());
    }

    #[test]
    fn constructed_invalid_binding_zero_keys_and_unsafe_receipt_keys_are_rejected() {
        let key = KeyPair::from_secret_bytes(&[9; 32]);
        let mut invalid = request();
        invalid.binding.generation = 0;
        assert!(invalid.binding.session_id().is_err());
        assert!(SignedConnect::sign(invalid, &key).is_err());
        let mut invalid = request();
        invalid.binding.payer = Address::from_parts([0; 32], invalid.binding.payer.display());
        assert!(invalid.signing_message().is_err());
        let mut invalid = request();
        invalid.wireguard_key = [0; 32];
        assert!(SignedConnect::sign(invalid.clone(), &key).is_err());
        assert!(serde_json::to_vec(&invalid).is_err());
        let mut invalid = request();
        invalid.sequence = 0;
        assert!(SignedConnect::sign(invalid, &key).is_err());
        let mut signed = SignedConnect::sign(request(), &key).unwrap();
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xed;
        noncanonical[31] = 0x7f;
        for raw in [[0; 32], identity, noncanonical] {
            signed.receipt_key = PublicKey(raw);
            assert!(signed.verify().is_err());
        }
    }

    #[test]
    fn status_uses_canonical_domain_separated_json_and_round_trips() {
        let key = KeyPair::from_secret_bytes(&[11; 32]);
        let signed = SignedStatus::sign(status(), &key).unwrap();
        signed.verify().unwrap();
        let status = &signed.status;
        let expected = format!(
            concat!(
                "Octranet prepaid status v1\0",
                "{{\"binding\":{{\"deployment\":{{\"domain\":\"{}\",\"program\":\"{}\"}},",
                "\"generation\":1,\"manifest_hash\":\"{}\",\"offer\":3,\"payer\":\"{}\",\"plan\":0}},",
                "\"canonical_ms\":1000,\"claim_deadline_ms\":86401000,",
                "\"client_wireguard_key\":\"{}\",\"committed_totals\":[524288,0],",
                "\"connect_sequence\":7,\"original_budget_ou\":20,\"redeemed_totals\":[1048576,524288],",
                "\"remaining_ou\":17,\"server_wireguard_key\":\"{}\",",
                "\"tariff\":{{\"classes\":[{{\"name\":\"default\",\"rate_ou_per_mib\":2}},",
                "{{\"name\":\"premium\",\"rate_ou_per_mib\":4}}],",
                "\"operator\":\"{}\",\"selectors\":[],\"version\":1}}}}"
            ),
            status.binding.deployment.domain,
            status.binding.deployment.program,
            status.binding.manifest_hash,
            status.binding.payer,
            b64::encode(status.client_wireguard_key),
            b64::encode(status.server_wireguard_key),
            status.tariff.operator(),
        );
        assert_eq!(status.signing_message().unwrap(), expected.as_bytes());
        // A remaining canonical balance is not derived from unredeemed bytes.
        assert_ne!(
            status.remaining_ou,
            status.original_budget_ou
                - status
                    .tariff
                    .total_charge(&status.committed_totals)
                    .unwrap()
        );
        let raw = serde_json::to_vec_pretty(&signed).unwrap();
        let restored: SignedStatus = serde_json::from_slice(&raw).unwrap();
        assert_eq!(restored, signed);
        restored.verify().unwrap();
    }

    #[test]
    fn operator_signature_authenticates_every_status_field() {
        let key = KeyPair::from_secret_bytes(&[11; 32]);
        let signed = SignedStatus::sign(status(), &key).unwrap();
        for binding in changed_bindings(&signed.status.binding) {
            let mut changed = signed.clone();
            changed.status.binding = binding;
            if changed.status.binding.manifest_hash == signed.status.binding.manifest_hash {
                changed.status.validate().unwrap();
            }
            assert!(changed.verify().is_err());
        }
        for field in [
            "connect_sequence",
            "client_wireguard_key",
            "server_wireguard_key",
            "tariff",
            "original_budget_ou",
            "remaining_ou",
            "committed_totals",
            "redeemed_totals",
            "canonical_ms",
            "claim_deadline_ms",
        ] {
            let mut changed = signed.clone();
            match field {
                "connect_sequence" => changed.status.connect_sequence += 1,
                "client_wireguard_key" => changed.status.client_wireguard_key[0] ^= 1,
                "server_wireguard_key" => changed.status.server_wireguard_key[0] ^= 1,
                "tariff" => {
                    let mut classes = changed.status.tariff.classes().to_vec();
                    classes[0].rate_ou_per_mib += 1;
                    changed.status.tariff = Tariff::new(
                        changed.status.tariff.operator().clone(),
                        classes,
                        Vec::new(),
                    )
                    .unwrap();
                    changed.status.binding.manifest_hash =
                        changed.status.tariff.hash_hex().unwrap();
                }
                "original_budget_ou" => changed.status.original_budget_ou += 1,
                "remaining_ou" => changed.status.remaining_ou += 1,
                "committed_totals" => changed.status.committed_totals[0] += 1,
                "redeemed_totals" => changed.status.redeemed_totals[0] += 1,
                "canonical_ms" => changed.status.canonical_ms += 1,
                "claim_deadline_ms" => changed.status.claim_deadline_ms += 1,
                _ => unreachable!(),
            }
            changed.status.validate().unwrap();
            assert!(changed.verify().is_err(), "{field}");
        }
        let mut changed = signed.clone();
        changed.operator_key = KeyPair::from_secret_bytes(&[12; 32]).public;
        assert!(changed.verify().is_err());
        let mut changed = signed.clone();
        changed.signature.0[0] ^= 1;
        assert!(changed.verify().is_err());
        let connect = Connect {
            binding: signed.status.binding.clone(),
            sequence: signed.status.connect_sequence,
            wireguard_key: signed.status.client_wireguard_key,
        };
        let mut changed = signed;
        changed.signature = SignedConnect::sign(connect, &key).unwrap().signature;
        assert!(changed.verify().is_err());
    }

    #[test]
    fn status_refuses_wrong_operator_and_unsafe_edwards_keys() {
        let wrong = KeyPair::from_secret_bytes(&[12; 32]);
        assert!(SignedStatus::sign(status(), &wrong).is_err());
        let mut identity = [0; 32];
        identity[0] = 1;
        let mut noncanonical = [0xff; 32];
        noncanonical[0] = 0xed;
        noncanonical[31] = 0x7f;
        for raw in [[0; 32], identity, noncanonical] {
            let mut status = status();
            status.tariff = Tariff::new(
                Address::from_pubkey(&raw),
                status.tariff.classes().to_vec(),
                Vec::new(),
            )
            .unwrap();
            status.binding.manifest_hash = status.tariff.hash_hex().unwrap();
            let signed = SignedStatus {
                status,
                operator_key: PublicKey(raw),
                signature: Signature([0; 64]),
            };
            assert!(matches!(
                signed.verify(),
                Err(Error::Invalid("unsafe receipt public key"))
            ));
        }
    }

    #[test]
    fn status_rejects_invalid_budget_counters_clocks_and_binding() {
        let mut invalid = status();
        invalid.binding.manifest_hash = "c".repeat(64);
        assert!(invalid.validate().is_err());
        let mut invalid = status();
        invalid.connect_sequence = 0;
        assert!(invalid.validate().is_err());
        for client in [true, false] {
            let mut invalid = status();
            if client {
                invalid.client_wireguard_key = [0; 32];
            } else {
                invalid.server_wireguard_key = [0; 32];
            }
            assert!(invalid.validate().is_err());
        }
        for committed in [true, false] {
            let mut invalid = status();
            if committed {
                invalid.committed_totals.pop();
            } else {
                invalid.redeemed_totals.push(0);
            }
            assert!(invalid.validate().is_err());
        }
        let mut invalid = status();
        invalid.committed_totals[1] = invalid.redeemed_totals[1] + 1;
        assert!(invalid.validate().is_err());
        let mut invalid = status();
        invalid.original_budget_ou = 3;
        invalid.remaining_ou = 0;
        assert!(matches!(
            invalid.validate(),
            Err(Error::BudgetExceeded { .. })
        ));
        let mut invalid = status();
        invalid.remaining_ou = invalid.original_budget_ou + 1;
        assert!(invalid.validate().is_err());
        let mut invalid = status();
        invalid.canonical_ms = 0;
        assert!(invalid.validate().is_err());
        let mut invalid = status();
        invalid.claim_deadline_ms = invalid.canonical_ms;
        assert!(invalid.validate().is_err());
        invalid.claim_deadline_ms -= 1;
        assert!(invalid.validate().is_err());
        let mut invalid = status();
        invalid.tariff = Tariff::new(
            invalid.tariff.operator().clone(),
            vec![TrafficClass {
                name: "default".to_owned(),
                rate_ou_per_mib: u64::MAX,
            }],
            Vec::new(),
        )
        .unwrap();
        invalid.binding.manifest_hash = invalid.tariff.hash_hex().unwrap();
        invalid.committed_totals = vec![u64::MAX];
        invalid.redeemed_totals = vec![u64::MAX];
        assert!(matches!(invalid.validate(), Err(Error::Overflow)));
    }

    #[test]
    fn status_json_has_strict_fields_numbers_and_wire_key_encodings() {
        let key = KeyPair::from_secret_bytes(&[11; 32]);
        for nested in [false, true] {
            let mut value =
                serde_json::to_value(SignedStatus::sign(status(), &key).unwrap()).unwrap();
            let target = if nested {
                &mut value["status"]
            } else {
                &mut value
            };
            target["unexpected"] = json!(true);
            assert!(serde_json::from_value::<SignedStatus>(value).is_err());
        }
        for (field, invalid) in [
            ("connect_sequence", json!(0)),
            ("canonical_ms", json!(0)),
            ("claim_deadline_ms", json!(0)),
            ("original_budget_ou", json!(-1)),
            ("remaining_ou", json!("1")),
            ("committed_totals", json!([0, -1])),
            ("redeemed_totals", json!([0, "1"])),
            ("client_wireguard_key", json!(b64::encode([0; 32]))),
            ("server_wireguard_key", json!(b64::encode([1; 31]))),
            (
                "client_wireguard_key",
                json!(b64::encode([8; 32]).trim_end_matches('=')),
            ),
        ] {
            let mut value = serde_json::to_value(status()).unwrap();
            value[field] = invalid;
            assert!(serde_json::from_value::<Status>(value).is_err(), "{field}");
        }
    }
}
