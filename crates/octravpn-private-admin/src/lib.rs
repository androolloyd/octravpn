//! Private administration: SHA256 credential and action binding, Groth16 BN254.
//! No wallet address or private witness belongs in transaction calldata.
use anyhow::{bail, ensure, Result};
use ark_bn254::{Bn254, Fr, G1Affine, G2Affine};
use ark_crypto_primitives::crh::sha256::constraints::Sha256Gadget;
use ark_ec::AffineRepr;
use ark_ff::{BigInteger, PrimeField};
use ark_groth16::{prepare_verifying_key, Groth16, Proof, ProvingKey, VerifyingKey};
use ark_r1cs_std::{
    alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, prelude::ToBitsGadget,
    uint8::UInt8,
};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

pub const CREDENTIAL_DOMAIN: &[u8] = b"OctraVPN admin credential v1\0";
pub const TAG_DOMAIN: &[u8] = b"OctraVPN admin action v1\0";
pub const CONTEXT_DOMAIN: &str = "OctraVPN private admin v1";
pub const CIRCUIT_ID: &str = "sha256-credential-action-bn254-v1";

/// Deliberately has no Debug or serialization implementation.
pub struct Credential(pub Zeroizing<[u8; 32]>);

impl Credential {
    pub fn commitment(&self) -> [u8; 32] {
        hash_parts(&[CREDENTIAL_DOMAIN, self.0.as_ref()])
    }

    pub fn tag(&self, challenge: &[u8; 32]) -> [u8; 32] {
        hash_parts(&[TAG_DOMAIN, self.0.as_ref(), challenge])
    }
}

fn hash_parts(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct AdminCircuit {
    pub secret: [u8; 32],
    pub challenge: [u8; 32],
    pub commitment: [u8; 32],
    pub tag: [u8; 32],
}

pub fn field_inputs(commitment: &[u8; 32], challenge: &[u8; 32], tag: &[u8; 32]) -> Vec<Fr> {
    [commitment, challenge, tag]
        .into_iter()
        .flat_map(|digest| digest.chunks_exact(16).map(Fr::from_be_bytes_mod_order))
        .collect()
}

fn bind_digest(
    cs: &ConstraintSystemRef<Fr>,
    bytes: &[UInt8<Fr>],
    expected: &[u8; 32],
) -> Result<(), SynthesisError> {
    for (chunk, value) in bytes.chunks_exact(16).zip(expected.chunks_exact(16)) {
        let mut bits = Vec::with_capacity(128);
        for byte in chunk.iter().rev() {
            bits.extend(byte.to_bits_le()?);
        }
        let packed = Boolean::le_bits_to_fp(&bits)?;
        let input = FpVar::new_input(cs.clone(), || Ok(Fr::from_be_bytes_mod_order(value)))?;
        packed.enforce_equal(&input)?;
    }
    Ok(())
}

impl ConstraintSynthesizer<Fr> for AdminCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let secret = UInt8::new_witness_vec(cs.clone(), &self.secret)?;
        let challenge = UInt8::new_witness_vec(cs.clone(), &self.challenge)?;
        let mut credential = UInt8::constant_vec(CREDENTIAL_DOMAIN);
        credential.extend(secret.clone());
        let commitment = Sha256Gadget::digest(&credential)?;
        // Public-input order is part of the native OG16 wire protocol.
        bind_digest(&cs, &commitment.0, &self.commitment)?;
        bind_digest(&cs, &challenge, &self.challenge)?;
        let mut action = UInt8::constant_vec(TAG_DOMAIN);
        action.extend(secret);
        action.extend(challenge);
        let tag = Sha256Gadget::digest(&action)?;
        bind_digest(&cs, &tag.0, &self.tag)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub method: String,
    pub params: Vec<Value>,
}

fn digest_arg(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("digest must be a string"))?;
    ensure!(
        text.len() == 64
            && text
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "digest must be lowercase hex SHA256"
    );
    Ok(text.to_owned())
}

fn address_arg(value: &Value) -> Result<String> {
    let text = value
        .as_str()
        .ok_or_else(|| anyhow::anyhow!("address must be a string"))?;
    ensure!(
        text.len() == 47
            && text.starts_with("oct")
            && text[3..].bytes().all(|c| {
                b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&c)
            }),
        "invalid Octra address"
    );
    Ok(text.to_owned())
}

impl Request {
    /// Validate typed public parameters and produce an unambiguous transcript.
    pub fn transcript(&self) -> Result<String> {
        let types: &[u8] = match self.method.as_str() {
            "set_paused" => b"u",
            "set_params" => b"uuuuuuuuuu",
            "withdraw_program_treasury" => b"au",
            "approve_circle_registration" | "gov_slash_operator" => b"aa",
            "propose_admin" => b"du",
            "accept_admin" => b"dd",
            "cancel_admin" => b"d",
            _ => bail!("unsupported administration method"),
        };
        ensure!(
            types.len() == self.params.len(),
            "wrong administration parameter count"
        );
        let mut text = self.method.clone();
        for (kind, value) in types.iter().zip(&self.params) {
            let arg = match kind {
                b'd' => digest_arg(value)?,
                b'a' => address_arg(value)?,
                b'u' => value
                    .as_u64()
                    .ok_or_else(|| anyhow::anyhow!("parameter must be a u64 JSON integer"))?
                    .to_string(),
                _ => unreachable!(),
            };
            text.push('|');
            text.push_str(&arg);
        }
        Ok(text)
    }

    pub fn challenge(&self, domain: &str, program: &str, nonce: u64) -> Result<[u8; 32]> {
        digest_arg(&Value::String(domain.to_owned()))?;
        address_arg(&Value::String(program.to_owned()))?;
        ensure!(nonce < u64::MAX, "administration nonce exhausted");
        let text = format!(
            "{CONTEXT_DOMAIN}|{domain}|{program}|{nonce}|{}",
            self.transcript()?
        );
        Ok(Sha256::digest(text.as_bytes()).into())
    }
}

#[derive(Serialize, Deserialize)]
pub struct Authorization {
    pub method: String,
    /// Exact calldata, including nonce, action tag and proof. Contains no secret.
    pub params: Vec<Value>,
    pub commitment: String,
    pub challenge: String,
    pub circuit: String,
    pub verification_key_sha256: String,
}

pub fn authorize(
    pk: &ProvingKey<Bn254>,
    credential: &Credential,
    request: &Request,
    domain: &str,
    program: &str,
    nonce: u64,
) -> Result<Authorization> {
    let commitment = credential.commitment();
    let challenge = request.challenge(domain, program, nonce)?;
    let tag = credential.tag(&challenge);
    let proof = Groth16::<Bn254>::create_random_proof_with_reduction(
        AdminCircuit {
            secret: *credential.0,
            challenge,
            commitment,
            tag,
        },
        pk,
        &mut OsRng,
    )?;
    ensure!(
        Groth16::<Bn254>::verify_proof(
            &prepare_verifying_key(&pk.vk),
            &proof,
            &field_inputs(&commitment, &challenge, &tag)
        )?,
        "proving key does not match the administration circuit"
    );
    let mut params = request.params.clone();
    params.extend([
        Value::from(nonce),
        Value::from(hex::encode(tag)),
        Value::from(STANDARD.encode(encode_proof(&proof)?)),
    ]);
    Ok(Authorization {
        method: request.method.clone(),
        params,
        commitment: hex::encode(commitment),
        challenge: hex::encode(challenge),
        circuit: CIRCUIT_ID.to_owned(),
        verification_key_sha256: hex::encode(Sha256::digest(encode_vk(&pk.vk)?)),
    })
}

fn append_field<F: PrimeField>(out: &mut Vec<u8>, value: F) {
    let bytes = value.into_bigint().to_bytes_be();
    out.extend(std::iter::repeat_n(0, 32 - bytes.len()));
    out.extend(bytes);
}

fn append_g1(out: &mut Vec<u8>, point: &G1Affine) -> Result<()> {
    ensure!(!point.is_zero(), "native verifier rejects infinity");
    append_field(out, point.x);
    append_field(out, point.y);
    Ok(())
}

fn append_g2(out: &mut Vec<u8>, point: &G2Affine) -> Result<()> {
    ensure!(!point.is_zero(), "native verifier rejects infinity");
    append_field(out, point.x.c0);
    append_field(out, point.x.c1);
    append_field(out, point.y.c0);
    append_field(out, point.y.c1);
    Ok(())
}

pub fn encode_vk(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    ensure!(vk.gamma_abc_g1.len() == 7, "expected six public inputs");
    let mut out = b"OG16V1".to_vec();
    out.extend(6_u32.to_be_bytes());
    append_g1(&mut out, &vk.alpha_g1)?;
    for point in [&vk.beta_g2, &vk.gamma_g2, &vk.delta_g2] {
        append_g2(&mut out, point)?;
    }
    for point in &vk.gamma_abc_g1 {
        append_g1(&mut out, point)?;
    }
    Ok(out)
}

pub fn encode_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    let mut out = b"OG16P1".to_vec();
    append_g1(&mut out, &proof.a)?;
    append_g2(&mut out, &proof.b)?;
    append_g1(&mut out, &proof.c)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    #[test]
    fn circuit_binds_secret_commitment_challenge_and_tag() {
        let credential = Credential(Zeroizing::new([42; 32]));
        let valid = AdminCircuit {
            secret: *credential.0,
            challenge: [7; 32],
            commitment: credential.commitment(),
            tag: credential.tag(&[7; 32]),
        };
        for mutation in 0..5 {
            let mut circuit = valid.clone();
            match mutation {
                1 => circuit.secret[0] ^= 1,
                2 => circuit.commitment[0] ^= 1,
                3 => circuit.challenge[0] ^= 1,
                4 => circuit.tag[0] ^= 1,
                _ => {}
            }
            let cs = ConstraintSystem::new_ref();
            circuit.generate_constraints(cs.clone()).unwrap();
            assert_eq!(cs.is_satisfied().unwrap(), mutation == 0);
            assert_eq!(cs.num_instance_variables(), 7);
        }
    }

    #[test]
    fn transcript_rejects_ambiguous_or_untyped_parameters() {
        for request in [
            Request {
                method: "set_paused".into(),
                params: vec![Value::from("1")],
            },
            Request {
                method: "cancel_admin".into(),
                params: vec![Value::from("a|b")],
            },
            Request {
                method: "transfer_ownership".into(),
                params: vec![],
            },
        ] {
            assert!(request.transcript().is_err());
        }
    }

    #[test]
    fn context_separates_network_program_nonce_action_and_all_parameters() {
        let address = format!("oct{}", "1".repeat(44));
        let domain = "a".repeat(64);
        let request = Request {
            method: "set_paused".into(),
            params: vec![Value::from(1)],
        };
        let base = request.challenge(&domain, &address, 1).unwrap();
        assert_ne!(
            base,
            request.challenge(&"b".repeat(64), &address, 1).unwrap()
        );
        assert_ne!(
            base,
            request
                .challenge(&domain, &format!("oct{}", "2".repeat(44)), 1)
                .unwrap()
        );
        assert_ne!(base, request.challenge(&domain, &address, 2).unwrap());
        let other = Request {
            params: vec![Value::from(0)],
            ..request
        };
        assert_ne!(base, other.challenge(&domain, &address, 1).unwrap());
        assert!(other.challenge(&domain, &address, u64::MAX).is_err());
    }
}
