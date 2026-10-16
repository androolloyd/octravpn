// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Captured native startup settings and consensus compatibility commitments.
//! Hashes describe the adopted runtime; they do not attest implementation parity.
use super::{
    policy::{self, Protocol},
    Error,
};
use crate::{
    emission, native_integer, network,
    oce1::Writer,
    preverify_commit, resource_lanes,
    rules::{self, Rule},
    transaction::RuleMode,
    transaction_policy::{self, Profile, ReleaseProfile},
    validator::{policy as validator, set_fold},
};
use num_bigint::BigInt;
use std::collections::BTreeMap;
type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug)]
pub struct Settings {
    values: BTreeMap<String, Vec<u8>>,
    pub protocol: Protocol,
    pub transactions: Profile,
    pub validators: validator::Policy,
    pub emission: emission::Schedule,
    pub receipt_activation: i64,
    pub private_result_activation: i64,
    pub proposal_txs: i64,
    pub proposal_bytes: i64,
    pub proposal_ou: BigInt,
    pub stealth_defer: i64,
    pub stealth_slots: i64,
    pub fhe_slots: i64,
    pub multi_exec: i64,
}
fn require(condition: bool, message: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into().into())
    }
}
impl Settings {
    pub fn from_values(values: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let get = |name: &str| values.get(name).map(Vec::as_slice);
        let protocol = Protocol::from_activation_value(get(Protocol::ACTIVATION_ENV))?;
        let validators = validator::Policy::from_value(get(validator::ENV_NAME))
            .map_err(|e| Error::from(e.to_string()))?;
        let private_result_activation = match get("OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH") {
            None | Some(b"") => 0,
            Some(raw) => {
                let epoch = native_integer::parse_int63(raw)
                    .ok_or("OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH must be an integer")?;
                require(
                    epoch >= 0,
                    "OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH must be nonnegative",
                )?;
                epoch
            }
        };
        require(
            get("OCTRA_EMISSION_PROFILE").is_none_or(<[u8]>::is_empty),
            "OCTRA_EMISSION_PROFILE is not supported",
        )?;
        let emission = match get("OCTRA_EMISSION_ACTIVATION_EPOCH") {
            None | Some(b"") => emission::Schedule::Inactive,
            Some(raw) => emission::Schedule::SecurityCurve {
                activation_epoch: emission::parse_epoch("emission activation epoch", raw)
                    .map_err(|e| Error::from(e.to_string()))?,
            },
        };
        if let validator::Policy::Bonded(active) = &validators {
            let emission::Schedule::SecurityCurve { activation_epoch } = emission else {
                return Err("bonded validator admission requires security_curve emission".into());
            };
            require(
                activation_epoch <= active.activation_epoch,
                "validator admission activation precedes emission activation",
            )?;
        }
        let transactions = Profile::from_values(
            get("OCTRA_BFT_RELEASE_PROFILE"),
            get("OCTRA_BFT_CRYPTO_PROFILE"),
            get("OCTRA_BFT_ADMIT_OPS"),
        );
        let receipt_activation =
            preverify_commit::activation(get("OCTRA_PREVERIFY_RECEIPT_ACTIVATION_EPOCH"));
        if let Some(release) = get("OCTRA_BFT_RELEASE_PROFILE").filter(|v| !v.is_empty()) {
            let release = String::from_utf8_lossy(release);
            require(
                transactions.release != ReleaseProfile::Off,
                format!("unknown BFT release profile = {release}"),
            )?;
            require(
                admit_ops(get("OCTRA_BFT_ADMIT_OPS")).is_empty(),
                format!("{release} rejects OCTRA_BFT_ADMIT_OPS"),
            )?;
            let raw = get("OCTRA_PREVERIFY_RECEIPT_ACTIVATION_EPOCH")
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    Error::from(format!(
                        "{release} requires preverify receipt activation epoch"
                    ))
                })?;
            let epoch = native_integer::parse_int63(raw).ok_or_else(|| {
                Error::from(format!(
                    "{release} requires valid preverify receipt activation epoch"
                ))
            })?;
            require(
                epoch >= 0,
                format!("{release} requires nonnegative preverify receipt activation epoch"),
            )?;
            require(
                get("OCTRA_PRIVATE_RESULT_ACTIVATION_EPOCH").is_some_and(|v| !v.is_empty()),
                format!("{release} requires private result activation epoch"),
            )?;
            require(
                get("OCTRA_BFT_CRYPTO_PROFILE").is_none_or(<[u8]>::is_empty),
                format!("{release} rejects OCTRA_BFT_CRYPTO_PROFILE"),
            )?;
            match transactions.release {
                ReleaseProfile::DevnetPrivateV1 => {
                    require(
                        get("OCTRA_EMISSION_GUARD") == Some(b"1"),
                        format!("{release} env = OCTRA_EMISSION_GUARD required_value = 1"),
                    )?;
                    require(
                        matches!(emission, emission::Schedule::Inactive),
                        format!("{release} rejects active emission"),
                    )?;
                }
                ReleaseProfile::DevnetFullV1 => {
                    require(
                        get("OCTRA_EMISSION_GUARD") != Some(b"1"),
                        format!("{release} env = OCTRA_EMISSION_GUARD rejected_value = 1"),
                    )?;
                    let emission::Schedule::SecurityCurve { activation_epoch } = emission else {
                        return Err(format!("{release} requires security_curve emission").into());
                    };
                    require(
                        activation_epoch == receipt_activation,
                        format!(
                            "{release} requires matching emission and preverify activation epochs"
                        ),
                    )?;
                    require(
                        get("OCTRA_PVAC_MIGRATION_ROOT").is_some_and(|v| {
                            v.len() == 64
                                && v.iter()
                                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
                        }),
                        "devnet_full_v1 requires migration admission root",
                    )?;
                }
                ReleaseProfile::Off => unreachable!(),
            }
        }
        let bounded = |name: &str, default: i64, low: i64, high: i64| {
            get(name)
                .and_then(native_integer::parse_int63)
                .filter(|v| (low..=high).contains(v))
                .unwrap_or(default)
        };
        let proposal_txs = bounded("OCTRA_BFT_PROPOSAL_MAX_TXS", 1000, 1, 10000);
        let proposal_bytes = bounded(
            "OCTRA_BFT_PROPOSAL_MAX_BYTES",
            5_000_000,
            1024,
            32 * 1024 * 1024,
        );
        let maximum = BigInt::from(10_000_000_000u64);
        let proposal_ou = get("OCTRA_BFT_PROPOSAL_MAX_OU")
            .and_then(native_integer::parse_integer)
            .filter(|v| v > &BigInt::from(0) && v <= &maximum)
            .unwrap_or(maximum);
        let stealth_defer = bounded("OCTRA_STEALTH_MAX_DEFER", 30, 0, 10000);
        let stealth_slots = bounded("OCTRA_STEALTH_MAX_PER_EPOCH", 4, 0, 128);
        let fhe_slots = bounded("OCTRA_FHE_MAX_PER_EPOCH", 8, 0, 128);
        let multi_exec = bounded("OCTRA_MULTI_EXEC_MAX_CALLS", 8, 1, 64);
        Ok(Self {
            values,
            protocol,
            transactions,
            validators,
            emission,
            receipt_activation,
            private_result_activation,
            proposal_txs,
            proposal_bytes,
            proposal_ou,
            stealth_defer,
            stealth_slots,
            fhe_slots,
            multi_exec,
        })
    }
    pub fn get(&self, name: &str) -> Option<&[u8]> {
        self.values.get(name).map(Vec::as_slice)
    }
    fn emission_id(&self) -> &'static [u8] {
        match self.emission {
            emission::Schedule::Inactive => b"inactive",
            emission::Schedule::SecurityCurve { .. } => b"security_curve:47304000:17:7:10",
        }
    }
    pub fn compatibility_hash(&self, crypto_engine: &[u8]) -> Result<[u8; 32]> {
        let mut w = Writer::new();
        for number in [self.proposal_txs, 10_000, self.proposal_bytes] {
            put_int(&mut w, number)?;
        }
        put_int(&mut w, &self.proposal_ou)?;
        for number in [self.stealth_defer, self.stealth_slots, self.fhe_slots] {
            put_int(&mut w, number)?;
        }
        w.put_bool(matches!(
            self.get("OCTRA_STEALTH_INLINE_VERIFY"),
            Some(b"1" | b"true")
        ))?;
        put_int(
            &mut w,
            transaction_policy::stealth_min_ou(self.get("OCTRA_STEALTH_MIN_OU")),
        )?;
        for number in [
            self.receipt_activation,
            self.private_result_activation,
            self.multi_exec,
        ] {
            put_int(&mut w, number)?;
        }
        w.put_bool(self.get("OCTRA_EMISSION_GUARD") == Some(b"1"))?;
        w.put_bytes(match self.transactions.release {
            ReleaseProfile::Off => b"off",
            ReleaseProfile::DevnetPrivateV1 => b"devnet_private_v1",
            ReleaseProfile::DevnetFullV1 => b"devnet_full_v1",
        })?;
        w.put_bytes(if self.transactions.private_v1 {
            b"private_v1"
        } else {
            b"off"
        })?;
        w.put_bytes(self.emission_id())?;
        w.put_bytes(self.validators.consensus_id().as_bytes())?;
        w.put_bytes(self.get("OCTRA_FEE_RECIPIENT").unwrap_or_default())?;
        w.put_bytes(self.protocol.consensus_id().as_bytes())?;
        w.put_bytes(b"fee_burn:1:5")?;
        w.put_bytes(
            match self.emission {
                emission::Schedule::Inactive => String::new(),
                emission::Schedule::SecurityCurve { activation_epoch } => {
                    activation_epoch.to_string()
                }
            }
            .as_bytes(),
        )?;
        for value in [
            crypto_engine,
            b"bound_range_commitment_v2",
            b"proof_verify_view_only_v1",
            b"finalized_rejection_commitment",
            b"rehovot_1",
            self.get("OCTRA_PVAC_MIGRATION_ROOT").unwrap_or_default(),
        ] {
            w.put_bytes(value)?;
        }
        w.put_list(&admit_ops(self.get("OCTRA_BFT_ADMIT_OPS")), |w, v| {
            w.put_bytes(v)
        })?;
        for lane in resource_lanes::LANES {
            let b = lane.budget();
            w.put_bytes(lane.as_str().as_bytes())?;
            w.put_u32(b.transactions as u32)?;
            w.put_u32(b.bytes as u32)?;
            put_int(&mut w, b.ou)?;
            w.put_u32(b.proofs as u32)?;
        }
        Ok(network::domain_hash(
            b"octra:consensus_profile:v16",
            &w.into_bytes(),
        ))
    }
    pub fn hash(&self, chain: &[u8], epoch: i64, crypto_engine: &[u8]) -> Result<[u8; 32]> {
        if rules::at(chain, Rule::Standard, epoch) == RuleMode::Prior {
            return self.compatibility_hash(crypto_engine);
        }
        self.standard_hash(chain, epoch, crypto_engine)
    }
    pub fn standard_hash(
        &self,
        chain: &[u8],
        epoch: i64,
        crypto_engine: &[u8],
    ) -> Result<[u8; 32]> {
        let compatibility = self.compatibility_hash(crypto_engine)?;
        let mut w = Writer::new();
        w.put_bytes(b"octra_consensus")?;
        w.put_bytes(chain)?;
        component(&mut w, "runtime_compatibility", &compatibility)?;
        component(
            &mut w,
            "activation_graph",
            &rules::consensus_id(chain, epoch),
        )?;
        component(
            &mut w,
            "quorum",
            policy::quorum_consensus_id(chain).as_bytes(),
        )?;
        component(
            &mut w,
            "set_fold_bootstrap",
            set_fold::Config::default().consensus_id().as_bytes(),
        )?;
        component(
            &mut w,
            "set_fold_participating",
            set_fold::Config::participating().consensus_id().as_bytes(),
        )?;
        component(
            &mut w,
            "set_fold_rule",
            b"set_fold:standard_then_participating",
        )?;
        component(
            &mut w,
            "validator_admission",
            self.validators.consensus_id().as_bytes(),
        )?;
        component(&mut w, "emission", self.emission_id())?;
        for (name, value) in STANDARD_COMPONENTS {
            component(&mut w, name, value)?;
        }
        component(
            &mut w,
            "proposal_protocol",
            self.protocol.consensus_id().as_bytes(),
        )?;
        for (rule, name, value) in ACTIVATED_COMPONENTS {
            if rules::at(chain, *rule, epoch) == RuleMode::Active {
                component(&mut w, name, value)?;
            }
        }
        Ok(network::domain_hash(
            b"octra:consensus_standard",
            &w.into_bytes(),
        ))
    }
}
pub fn activation_graph_hash(chain: &[u8]) -> Result<[u8; 32]> {
    let mut w = Writer::new();
    w.put_bytes(b"octra_consensus")?;
    w.put_bytes(chain)?;
    w.put_bytes(&rules::consensus_id(chain, (1i64 << 62) - 1))?;
    Ok(network::domain_hash(
        b"octra:consensus_activations",
        &w.into_bytes(),
    ))
}
fn admit_ops(raw: Option<&[u8]>) -> Vec<Vec<u8>> {
    let mut ops = raw
        .unwrap_or_default()
        .split(|b| *b == b',')
        .map(network::endpoint::native_trim)
        .filter(|v| !v.is_empty())
        .map(<[u8]>::to_vec)
        .collect::<Vec<_>>();
    ops.sort();
    ops.dedup();
    ops
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
fn put_int(w: &mut Writer, value: impl ToString) -> Result<()> {
    w.put_bytes(value.to_string().as_bytes())
}
fn component(w: &mut Writer, name: &str, value: &[u8]) -> Result<()> {
    w.put_bytes(name.as_bytes())?;
    w.put_bytes(value)
}
const STANDARD_COMPONENTS: &[(&str, &[u8])] = &[
    ("reward", b"reward:18198732:10000:7:10"),
    ("reward_source", b"reward_source:finalized_parent"),
    ("fee", b"fee_burn:1:5"),
    (
        "private_receipt",
        b"private_receipt:verify_apply:retry_tx:amount_link_v1",
    ),
    (
        "circle_receipt",
        b"circle_receipt:verify_apply:retry_tx:amount_link_v1",
    ),
    ("circle_storage", b"circle_storage:cell_owner:standard"),
    ("circle_hfhe", b"receipt_mode:amount_link_v1"),
    ("integer_work", b"cells_64_product_cap_1000000"),
    ("program_compiler", b"rehovot_runtime"),
    ("vm_undo", b"nested_commit"),
];
const COMPUTE_BILL:&[u8]=b"signed_reserve_8192:fund_10000:return_1000:signed_pay_expiry:payer:nonce:settle_separate:pay_wire_262144:fuel_5000000:model_67108864:io_16:base_10000:wire_2:state_inputs_65:pin_16:entry_32:fund_lane:paid_refusal:session_replay:paid_epoch:paid_root:record_set:charged_receipt:graph_json";
const ACTIVATED_COMPONENTS:&[(Rule,&str,&[u8])]=&[
    (Rule::SetPlan,"set_plan",b"retain_until_activation"),(Rule::Math,"math",b"scalar65_field_signed_cipher_zero_q16"),
    (Rule::Exit,"validator_exit",b"8192:4096"),(Rule::ReadyExecution,"ready_reference",b"proposal_delay2_inclusion_first"),
    (Rule::ProgramSource,"program_source",b"aml_source:oct_gen_count:source_abi:checked_address:option_values:scalar_equality:shape_limits:overlap_64"),
    (Rule::FheWork,"fhe_work",b"fhe_projected_storage_sampling_traversal_child_budget:65536:4096:1048576:16:8:10000:4:8:32:1024:4096:128:fhe_retained_volume:536870912:16:8:270336:65536:64:key_io:64:500:500:10000:1000:1000:500:500:100:200"),
    (Rule::WasmFloat,"wasm_float",b"wasm_float:arith_nan_7fc00000_7ff8000000000000:operand_calls:metered_helpers:v1"),
    (Rule::TxEnvelope,"transaction_envelope",b"sender_key32_signature64_base64_scalar_unique_nonce"),
    (Rule::FheWork,"program_preview",b"aml_2_preview:certificate_version:stored_version:source_compat"),
    (Rule::ProofExecution,"proof_exec",b"fhe_zero_range_commit:groth16_bn254:journal_undo:resource_abort:pure_loop_index:match_scope:if_scope:while_scope:fhe_key_io_16:fhe_key_load_16:circle_key_effort:circle_read_effort:circle_fhe_proofs:circle_value_calls:circle_storage_kinds:typed_call_args:octb_nested:circle_code_optin:circle_storage_io_16:circle_stream_io_16:call_journal_entries_32:circle_batch:circle_nested_optin:circle_spawn_optin:circle_payload_stack:circle_receipt_abort:circle_json_io_16"),
    (Rule::ProofExecution,"wasm_calls",b"suspend_v1:code_optin:update_policy:journal_storage:exchange_bytes_16:exchange_entries_32:circle_delta_v1:shared_fuel:transfer_50:depth_8"),
    (Rule::ProofExecution,"wasm_limits",b"full_request_v2:receipt_9233:direct_16777216:session_67108864:response_2097152:reply_67108864:guest_refusal:error_utf8_256_v1:hfhe_pairs_v2"),
    (Rule::VmBytes,"vm_bytes",b"bytes_v2:key_16777216:value_4194304:copy_16777216:write_4194304:alloc_134217728:unit_32:receipt_4194304:event_count_256:returns:shared_gross:inspect_isolated"),
    (Rule::VmBytes,"compute_transfers",COMPUTE_BILL),(Rule::Settle,"compute_settle",COMPUTE_BILL),
    (Rule::CipherMigration,"cipher_migration",b"ledger_source:historical_strict:current_range64:shared_commitment:source_sha256:record_recovery:zero_record"),
];
