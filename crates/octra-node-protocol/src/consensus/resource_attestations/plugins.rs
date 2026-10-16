// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    assigned, encoded, hash_encoded, leading_zero_bits, merkle_root_from_evidence,
    proof_payload_hash, sign, storage_challenge_index, storage_leaf_hash, storage_path,
    Attestation, AttestationKind, Error, StorageEvidence, Writer,
};
use crate::network::verify_ed25519;
use num_bigint::BigInt;
use num_traits::ToPrimitive;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsefulPlugin {
    PvacKat,
    FheProofReceipt,
    CircleAssetAvailability,
    SnapshotAvailability,
    DeterministicComputationTrace,
    PerturbedMatrixTrace,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PvacKatEvidence {
    pub key_id: Vec<u8>,
    pub pubkey_hash: Vec<u8>,
    pub kat_input_hash: Vec<u8>,
    pub kat_output: Vec<u8>,
    pub expected_output_hash: Vec<u8>,
    pub work_units: i64,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FheReceiptEvidence {
    pub verifier_pubkey: Vec<u8>,
    pub proof_kind: Vec<u8>,
    pub program_id: Vec<u8>,
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub cost_units: i64,
    pub receipt_signature: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CircleAssetEvidence {
    pub circle_id: Vec<u8>,
    pub resource_path: Vec<u8>,
    pub asset_root: Vec<u8>,
    pub byte_count: i64,
    pub storage: StorageEvidence,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotAvailabilityEvidence {
    pub state_root: Vec<u8>,
    pub range_start: i64,
    pub range_end: i64,
    pub snapshot_root: Vec<u8>,
    pub byte_count: i64,
    pub storage: StorageEvidence,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeterministicTraceEvidence {
    pub runtime_id: Vec<u8>,
    pub source_hash: Vec<u8>,
    pub input_hash: Vec<u8>,
    pub output_hash: Vec<u8>,
    pub step_limit: i64,
    pub trace_root: Vec<u8>,
    pub sampled_step: StorageEvidence,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerturbedMatrixTraceEvidence {
    pub runtime_id: Vec<u8>,
    pub matrix_a_root: Vec<u8>,
    pub matrix_b_root: Vec<u8>,
    pub config_hash: Vec<u8>,
    pub chain_state_hash: Vec<u8>,
    pub tile_row: i64,
    pub tile_col: i64,
    pub tile_depth: i64,
    pub tile_trace_root: Vec<u8>,
    pub sampled_tile: StorageEvidence,
    pub field_modulus: i64,
    pub perturbed_left_values: Vec<i64>,
    pub perturbed_right_values: Vec<i64>,
    pub claimed_value: i64,
    pub opening_nonce: Vec<u8>,
    pub difficulty_bits: i64,
    pub work_units: i64,
}

pub fn useful_plugin_to_u8(plugin: UsefulPlugin) -> u8 {
    match plugin {
        UsefulPlugin::PvacKat => 1,
        UsefulPlugin::FheProofReceipt => 2,
        UsefulPlugin::CircleAssetAvailability => 3,
        UsefulPlugin::SnapshotAvailability => 4,
        UsefulPlugin::DeterministicComputationTrace => 5,
        UsefulPlugin::PerturbedMatrixTrace => 6,
    }
}
pub fn useful_plugin_to_string(plugin: UsefulPlugin) -> &'static str {
    match plugin {
        UsefulPlugin::PvacKat => "pvac_kat",
        UsefulPlugin::FheProofReceipt => "fhe_proof_receipt",
        UsefulPlugin::CircleAssetAvailability => "circle_asset_availability",
        UsefulPlugin::SnapshotAvailability => "snapshot_availability",
        UsefulPlugin::DeterministicComputationTrace => "deterministic_computation_trace",
        UsefulPlugin::PerturbedMatrixTrace => "perturbed_matrix_trace",
    }
}
pub fn useful_plugin_task_id(
    challenge: &[u8],
    plugin: UsefulPlugin,
    subject: &[u8],
    resource_hash: &[u8],
    work_units: i64,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_plugin_task:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_u8(useful_plugin_to_u8(plugin))?;
        w.put_bytes(subject)?;
        w.put_hash32(resource_hash)?;
        w.put_u64(work_units as u64)
    })
}
pub fn nonempty_hash32(value: &[u8]) -> bool {
    value.len() == 32
}
pub fn attestation_weight_fits_resource(a: &Attestation, work_units: i64) -> bool {
    a.weight > 0 && work_units > 0 && a.weight <= work_units
}
pub fn encode_pvac_kat_evidence(e: &PvacKatEvidence) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.key_id)?;
        w.put_hash32(&e.pubkey_hash)?;
        w.put_hash32(&e.kat_input_hash)?;
        w.put_bytes(&e.kat_output)?;
        w.put_hash32(&e.expected_output_hash)?;
        w.put_u64(e.work_units as u64)
    })
}
pub fn pvac_kat_output_hash(e: &PvacKatEvidence) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_pvac_kat_output:v1", |w| {
        w.put_hash32(&e.pubkey_hash)?;
        w.put_hash32(&e.kat_input_hash)?;
        w.put_bytes(&e.kat_output)
    })
}
pub fn pvac_kat_resource_hash(e: &PvacKatEvidence) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_pvac_kat_resource:v1", |w| {
        w.put_hash32(&e.pubkey_hash)?;
        w.put_hash32(&e.kat_input_hash)
    })
}
pub fn pvac_kat_evidence_hash(e: &PvacKatEvidence) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_pvac_kat_evidence(e)?))
}
pub fn verify_pvac_kat_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    output_hash: &[u8],
    a: &Attestation,
    e: &PvacKatEvidence,
) -> Result<bool, Error> {
    Ok(assigned(commitment, max_weight, a)
        && nonempty_hash32(challenge)
        && nonempty_hash32(output_hash)
        && a.kind == AttestationKind::Useful
        && nonempty_hash32(&e.pubkey_hash)
        && nonempty_hash32(&e.kat_input_hash)
        && attestation_weight_fits_resource(a, e.work_units)
        && e.expected_output_hash == output_hash
        && pvac_kat_output_hash(e)? == output_hash
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::PvacKat,
                &e.key_id,
                &pvac_kat_resource_hash(e)?,
                e.work_units,
            )?
        && a.proof_hash == pvac_kat_evidence_hash(e)?)
}
pub fn fhe_receipt_sign_bytes(e: &FheReceiptEvidence) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_fhe_receipt_sign:v1", |w| {
        w.put_bytes(&e.proof_kind)?;
        w.put_bytes(&e.program_id)?;
        w.put_hash32(&e.input_hash)?;
        w.put_hash32(&e.output_hash)?;
        w.put_u64(e.cost_units as u64)
    })
}
pub fn encode_fhe_receipt_evidence(e: &FheReceiptEvidence) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.verifier_pubkey)?;
        w.put_bytes(&e.proof_kind)?;
        w.put_bytes(&e.program_id)?;
        w.put_hash32(&e.input_hash)?;
        w.put_hash32(&e.output_hash)?;
        w.put_u64(e.cost_units as u64)?;
        w.put_sig64(&e.receipt_signature)
    })
}
pub fn fhe_receipt_evidence_hash(e: &FheReceiptEvidence) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_fhe_receipt_evidence(e)?))
}
pub fn sign_fhe_receipt_evidence(
    priv_raw: &[u8],
    e: &FheReceiptEvidence,
) -> Result<Vec<u8>, Error> {
    sign(priv_raw, &fhe_receipt_sign_bytes(e)?)
}
pub fn fhe_receipt_resource_hash(e: &FheReceiptEvidence) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_fhe_receipt_resource:v1", |w| {
        w.put_bytes(&e.proof_kind)?;
        w.put_hash32(&e.input_hash)?;
        w.put_hash32(&e.output_hash)
    })
}
pub fn verify_fhe_receipt_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    pubkey: &[u8],
    a: &Attestation,
    e: &FheReceiptEvidence,
) -> Result<bool, Error> {
    Ok(assigned(commitment, max_weight, a)
        && nonempty_hash32(challenge)
        && a.kind == AttestationKind::Useful
        && nonempty_hash32(&e.input_hash)
        && nonempty_hash32(&e.output_hash)
        && e.verifier_pubkey.len() == 32
        && e.verifier_pubkey == pubkey
        && e.receipt_signature.len() == 64
        && attestation_weight_fits_resource(a, e.cost_units)
        && verify_ed25519(pubkey, &fhe_receipt_sign_bytes(e)?, &e.receipt_signature)
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::FheProofReceipt,
                &e.program_id,
                &fhe_receipt_resource_hash(e)?,
                e.cost_units,
            )?
        && a.proof_hash == fhe_receipt_evidence_hash(e)?)
}
pub fn encode_circle_asset_evidence(e: &CircleAssetEvidence) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.circle_id)?;
        w.put_bytes(&e.resource_path)?;
        w.put_hash32(&e.asset_root)?;
        w.put_u64(e.byte_count as u64)?;
        w.put_bytes(&super::encode_storage_evidence(&e.storage)?)
    })
}
pub fn circle_asset_resource_hash(e: &CircleAssetEvidence) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_circle_asset_resource:v1", |w| {
        w.put_bytes(&e.circle_id)?;
        w.put_bytes(&e.resource_path)?;
        w.put_hash32(&e.asset_root)?;
        w.put_u64(e.byte_count as u64)
    })
}
pub fn circle_asset_evidence_hash(e: &CircleAssetEvidence) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_circle_asset_evidence(e)?))
}
pub fn verify_circle_asset_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    leaf_count: i64,
    a: &Attestation,
    e: &CircleAssetEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a) || e.storage.leaf_count != leaf_count {
        return Ok(false);
    }
    let Some(index) = storage_challenge_index(challenge, leaf_count, a)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Useful
        && !e.circle_id.is_empty()
        && !e.resource_path.is_empty()
        && e.byte_count > 0
        && storage_path(&e.storage)
        && e.storage.leaf_index == index
        && e.asset_root == merkle_root_from_evidence(&e.storage)?
        && attestation_weight_fits_resource(a, e.byte_count)
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::CircleAssetAvailability,
                &e.circle_id,
                &circle_asset_resource_hash(e)?,
                e.byte_count,
            )?
        && a.proof_hash == circle_asset_evidence_hash(e)?)
}
pub fn encode_snapshot_availability_evidence(
    e: &SnapshotAvailabilityEvidence,
) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_hash32(&e.state_root)?;
        w.put_u64(e.range_start as u64)?;
        w.put_u64(e.range_end as u64)?;
        w.put_hash32(&e.snapshot_root)?;
        w.put_u64(e.byte_count as u64)?;
        w.put_bytes(&super::encode_storage_evidence(&e.storage)?)
    })
}
pub fn snapshot_availability_resource_hash(
    e: &SnapshotAvailabilityEvidence,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_snapshot_resource:v1", |w| {
        w.put_hash32(&e.state_root)?;
        w.put_u64(e.range_start as u64)?;
        w.put_u64(e.range_end as u64)?;
        w.put_hash32(&e.snapshot_root)?;
        w.put_u64(e.byte_count as u64)
    })
}
pub fn snapshot_availability_evidence_hash(
    e: &SnapshotAvailabilityEvidence,
) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_snapshot_availability_evidence(
        e,
    )?))
}
pub fn verify_snapshot_availability_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    leaf_count: i64,
    a: &Attestation,
    e: &SnapshotAvailabilityEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a) || e.storage.leaf_count != leaf_count {
        return Ok(false);
    }
    let Some(index) = storage_challenge_index(challenge, leaf_count, a)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Useful
        && nonempty_hash32(&e.state_root)
        && e.range_start <= e.range_end
        && e.byte_count > 0
        && storage_path(&e.storage)
        && e.storage.leaf_index == index
        && e.snapshot_root == merkle_root_from_evidence(&e.storage)?
        && attestation_weight_fits_resource(a, e.byte_count)
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::SnapshotAvailability,
                format!("{}:{}", e.range_start, e.range_end).as_bytes(),
                &snapshot_availability_resource_hash(e)?,
                e.byte_count,
            )?
        && a.proof_hash == snapshot_availability_evidence_hash(e)?)
}
pub fn deterministic_trace_resource_hash(
    e: &DeterministicTraceEvidence,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_deterministic_trace_resource:v1", |w| {
        w.put_bytes(&e.runtime_id)?;
        w.put_hash32(&e.source_hash)?;
        w.put_hash32(&e.input_hash)?;
        w.put_hash32(&e.output_hash)?;
        w.put_hash32(&e.trace_root)?;
        w.put_u64(e.step_limit as u64)
    })
}
pub fn encode_deterministic_trace_evidence(
    e: &DeterministicTraceEvidence,
) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.runtime_id)?;
        w.put_hash32(&e.source_hash)?;
        w.put_hash32(&e.input_hash)?;
        w.put_hash32(&e.output_hash)?;
        w.put_u64(e.step_limit as u64)?;
        w.put_hash32(&e.trace_root)?;
        w.put_bytes(&super::encode_storage_evidence(&e.sampled_step)?)
    })
}
pub fn deterministic_trace_evidence_hash(
    e: &DeterministicTraceEvidence,
) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_deterministic_trace_evidence(e)?))
}
pub fn verify_deterministic_trace_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    leaf_count: i64,
    a: &Attestation,
    e: &DeterministicTraceEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a) || e.sampled_step.leaf_count != leaf_count {
        return Ok(false);
    }
    let Some(index) = storage_challenge_index(challenge, leaf_count, a)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Useful
        && !e.runtime_id.is_empty()
        && nonempty_hash32(&e.source_hash)
        && nonempty_hash32(&e.input_hash)
        && nonempty_hash32(&e.output_hash)
        && e.step_limit > 0
        && storage_path(&e.sampled_step)
        && e.sampled_step.leaf_index == index
        && e.trace_root == merkle_root_from_evidence(&e.sampled_step)?
        && attestation_weight_fits_resource(a, e.step_limit)
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::DeterministicComputationTrace,
                &e.runtime_id,
                &deterministic_trace_resource_hash(e)?,
                e.step_limit,
            )?
        && a.proof_hash == deterministic_trace_evidence_hash(e)?)
}
pub fn int64_of_list_length<T>(values: &[T]) -> Result<i64, Error> {
    i64::try_from(values.len()).map_err(|_| "integer length overflow".into())
}
pub fn field_value_is_valid(modulus: i64, value: i64) -> bool {
    modulus > 1 && value >= 0 && value < modulus
}
pub fn field_dot_mod(modulus: i64, left: &[i64], right: &[i64]) -> Option<i64> {
    if modulus <= 1
        || left.is_empty()
        || left.len() != right.len()
        || left
            .iter()
            .chain(right)
            .any(|v| !field_value_is_valid(modulus, *v))
    {
        return None;
    }
    let mut total = BigInt::from(0);
    for (&a, &b) in left.iter().zip(right) {
        total = (total + BigInt::from(a) * b) % modulus;
    }
    total.to_i64()
}
pub fn perturbed_matrix_noise_seed(
    challenge: &[u8],
    e: &PerturbedMatrixTraceEvidence,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_perturbed_matrix_noise_seed:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_bytes(&e.runtime_id)?;
        w.put_hash32(&e.matrix_a_root)?;
        w.put_hash32(&e.matrix_b_root)?;
        w.put_hash32(&e.config_hash)?;
        w.put_hash32(&e.chain_state_hash)?;
        w.put_u64(e.tile_row as u64)?;
        w.put_u64(e.tile_col as u64)?;
        w.put_u64(e.tile_depth as u64)
    })
}
pub fn perturbed_matrix_trace_resource_hash(
    e: &PerturbedMatrixTraceEvidence,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_perturbed_matrix_trace_resource:v1", |w| {
        w.put_bytes(&e.runtime_id)?;
        w.put_hash32(&e.matrix_a_root)?;
        w.put_hash32(&e.matrix_b_root)?;
        w.put_hash32(&e.config_hash)?;
        w.put_hash32(&e.chain_state_hash)?;
        w.put_u64(e.tile_row as u64)?;
        w.put_u64(e.tile_col as u64)?;
        w.put_u64(e.tile_depth as u64)?;
        w.put_hash32(&e.tile_trace_root)?;
        w.put_u64(e.field_modulus as u64)?;
        w.put_u32(e.difficulty_bits as u32)?;
        w.put_u64(e.work_units as u64)
    })
}
pub fn put_u64_list(w: &mut Writer, values: &[i64]) -> Result<(), Error> {
    w.put_list(values, |w, v| w.put_u64(*v as u64))
}
pub fn perturbed_matrix_cell_chunk(
    challenge: &[u8],
    e: &PerturbedMatrixTraceEvidence,
) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_hash32(&perturbed_matrix_noise_seed(challenge, e)?)?;
        w.put_bytes(&e.runtime_id)?;
        w.put_u64(e.tile_row as u64)?;
        w.put_u64(e.tile_col as u64)?;
        w.put_u64(e.tile_depth as u64)?;
        w.put_u64(e.field_modulus as u64)?;
        put_u64_list(w, &e.perturbed_left_values)?;
        put_u64_list(w, &e.perturbed_right_values)?;
        w.put_u64(e.claimed_value as u64)
    })
}
pub fn perturbed_matrix_opening_hash(
    challenge: &[u8],
    e: &PerturbedMatrixTraceEvidence,
) -> Result<[u8; 32], Error> {
    hash_encoded(b"octra:pouw_perturbed_matrix_opening:v1", |w| {
        w.put_hash32(challenge)?;
        w.put_hash32(&perturbed_matrix_noise_seed(challenge, e)?)?;
        w.put_hash32(&perturbed_matrix_trace_resource_hash(e)?)?;
        w.put_u64(e.sampled_tile.leaf_index as u64)?;
        w.put_u64(e.sampled_tile.leaf_count as u64)?;
        w.put_hash32(&storage_leaf_hash(&e.sampled_tile.chunk))?;
        w.put_bytes(&e.opening_nonce)
    })
}
pub fn encode_perturbed_matrix_trace_evidence(
    e: &PerturbedMatrixTraceEvidence,
) -> Result<Vec<u8>, Error> {
    encoded(|w| {
        w.put_bytes(&e.runtime_id)?;
        w.put_hash32(&e.matrix_a_root)?;
        w.put_hash32(&e.matrix_b_root)?;
        w.put_hash32(&e.config_hash)?;
        w.put_hash32(&e.chain_state_hash)?;
        w.put_u64(e.tile_row as u64)?;
        w.put_u64(e.tile_col as u64)?;
        w.put_u64(e.tile_depth as u64)?;
        w.put_hash32(&e.tile_trace_root)?;
        w.put_bytes(&super::encode_storage_evidence(&e.sampled_tile)?)?;
        w.put_u64(e.field_modulus as u64)?;
        put_u64_list(w, &e.perturbed_left_values)?;
        put_u64_list(w, &e.perturbed_right_values)?;
        w.put_u64(e.claimed_value as u64)?;
        w.put_bytes(&e.opening_nonce)?;
        w.put_u32(e.difficulty_bits as u32)?;
        w.put_u64(e.work_units as u64)
    })
}
pub fn perturbed_matrix_trace_evidence_hash(
    e: &PerturbedMatrixTraceEvidence,
) -> Result<[u8; 32], Error> {
    Ok(proof_payload_hash(&encode_perturbed_matrix_trace_evidence(
        e,
    )?))
}
pub fn verify_perturbed_matrix_trace_attestation(
    challenge: &[u8],
    commitment: &[u8],
    max_weight: i64,
    leaf_count: i64,
    difficulty: i64,
    a: &Attestation,
    e: &PerturbedMatrixTraceEvidence,
) -> Result<bool, Error> {
    if !assigned(commitment, max_weight, a)
        || e.sampled_tile.leaf_count != leaf_count
        || e.difficulty_bits != difficulty
    {
        return Ok(false);
    }
    let Some(index) = storage_challenge_index(challenge, leaf_count, a)? else {
        return Ok(false);
    };
    Ok(a.kind == AttestationKind::Useful
        && !e.runtime_id.is_empty()
        && nonempty_hash32(&e.matrix_a_root)
        && nonempty_hash32(&e.matrix_b_root)
        && nonempty_hash32(&e.config_hash)
        && nonempty_hash32(&e.chain_state_hash)
        && e.tile_row >= 0
        && e.tile_col >= 0
        && e.tile_depth >= 0
        && e.tile_depth == int64_of_list_length(&e.perturbed_left_values)?
        && (0..=256).contains(&e.difficulty_bits)
        && storage_path(&e.sampled_tile)
        && e.sampled_tile.leaf_index == index
        && e.sampled_tile.chunk == perturbed_matrix_cell_chunk(challenge, e)?
        && e.tile_trace_root == merkle_root_from_evidence(&e.sampled_tile)?
        && field_dot_mod(
            e.field_modulus,
            &e.perturbed_left_values,
            &e.perturbed_right_values,
        ) == Some(e.claimed_value)
        && leading_zero_bits(&perturbed_matrix_opening_hash(challenge, e)?) >= e.difficulty_bits
        && attestation_weight_fits_resource(a, e.work_units)
        && a.commitment
            == useful_plugin_task_id(
                challenge,
                UsefulPlugin::PerturbedMatrixTrace,
                &e.runtime_id,
                &perturbed_matrix_trace_resource_hash(e)?,
                e.work_units,
            )?
        && a.proof_hash == perturbed_matrix_trace_evidence_hash(e)?)
}
