// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use octra_node_protocol::{
    consensus::ParentCommit,
    transaction::RuleMode,
    validator::set_fold::{CapMode, Config},
};
#[derive(Clone, Debug)]
pub struct Fold {
    pub mode: RuleMode,
    pub ready_mode: RuleMode,
    pub ready_ref_mode: RuleMode,
    pub ready_exec_mode: RuleMode,
    pub live_mode: RuleMode,
    pub standard_mode: RuleMode,
    pub cap_mode: CapMode,
    pub ready_config_hash: Option<Vec<u8>>,
    pub start: i64,
    pub profile_start: i64,
    pub parent: Option<ParentCommit>,
    pub members: Vec<Vec<u8>>,
    pub seat_mode: RuleMode,
    pub open_mode: RuleMode,
    pub plan_mode: RuleMode,
    pub account_mode: RuleMode,
    pub program_mode: RuleMode,
    pub program_overlap: bool,
    pub fhe_work: RuleMode,
    pub proof_exec: RuleMode,
    pub proof_key: RuleMode,
    pub program_records: RuleMode,
    pub program_inputs: RuleMode,
    /// Rule `scalar_work`: VM integer width and numeric text work.
    pub scalar_work: RuleMode,
    pub duty_marks: RuleMode,
    pub tx_network: RuleMode,
    pub vm_bytes: RuleMode,
    pub wasm_float: RuleMode,
    pub math: bool,
    pub exit_mode: RuleMode,
    pub active_addresses: Vec<Vec<u8>>,
}
impl Fold {
    pub fn prior() -> Self {
        Self {
            mode: RuleMode::Prior,
            ready_mode: RuleMode::Prior,
            ready_ref_mode: RuleMode::Prior,
            ready_exec_mode: RuleMode::Prior,
            live_mode: RuleMode::Prior,
            standard_mode: RuleMode::Prior,
            cap_mode: CapMode::Reject,
            ready_config_hash: None,
            start: 0,
            profile_start: 0,
            parent: None,
            members: vec![],
            seat_mode: RuleMode::Prior,
            open_mode: RuleMode::Prior,
            plan_mode: RuleMode::Prior,
            account_mode: RuleMode::Prior,
            program_mode: RuleMode::Prior,
            program_overlap: false,
            fhe_work: RuleMode::Prior,
            proof_exec: RuleMode::Prior,
            proof_key: RuleMode::Prior,
            program_records: RuleMode::Prior,
            program_inputs: RuleMode::Prior,
            scalar_work: RuleMode::Prior,
            duty_marks: RuleMode::Prior,
            tx_network: RuleMode::Prior,
            vm_bytes: RuleMode::Prior,
            wasm_float: RuleMode::Prior,
            math: false,
            exit_mode: RuleMode::Prior,
            active_addresses: vec![],
        }
    }
    pub fn config(&self) -> Config {
        if self.standard_mode == RuleMode::Prior {
            Config::default()
        } else {
            Config::participating()
        }
    }
    pub fn start(&self) -> i64 {
        if self.standard_mode == RuleMode::Prior {
            self.start
        } else {
            self.profile_start
        }
    }
}
