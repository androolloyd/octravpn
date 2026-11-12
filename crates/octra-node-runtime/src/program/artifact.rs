// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Independent OCPS rebuilding and trusted binary admission before execution.
use super::{store, Error, Journal, Result};
use crate::{state_batch::Snapshot, validator_epoch::Fold};
use octra_node_protocol::{
    aml::compiler::{
        self,
        package::{self, CompilerMode},
    },
    octb::{admission::Admitted, program},
    program_trust::Keys,
    transaction::{decode_base64, RuleMode},
};

#[derive(Clone, Copy, Debug)]
pub struct SourceRules {
    pub compiler: CompilerMode,
    pub overlap: bool,
    pub point_ops: bool,
    pub loops: bool,
    pub metered: bool,
    pub records: bool,
}
impl SourceRules {
    pub fn captured(fold: &Fold) -> Self {
        Self {
            // The adopted node selects AML preview with the Fhe_work fold.
            compiler: CompilerMode::for_rules(fold.program_mode, fold.fhe_work),
            overlap: fold.program_overlap,
            point_ops: fold.standard_mode == RuleMode::Active,
            loops: fold.proof_exec == RuleMode::Active,
            metered: fold.program_inputs == RuleMode::Active,
            records: fold.program_records == RuleMode::Active,
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Binary,
    Source,
}
#[derive(Clone, Debug)]
pub struct Artifact {
    raw: Vec<u8>,
    admitted: Admitted,
    mode: Mode,
    record: Option<octra_node_protocol::program_record::Record>,
}
impl Artifact {
    pub fn binary(raw: &[u8], point_ops: bool, trusted: &Keys) -> Result<Self> {
        Ok(Self {
            raw: raw.to_vec(),
            admitted: program::decode_deploy(raw, point_ops, trusted)?,
            mode: Mode::Binary,
            record: None,
        })
    }
    pub fn source(encoded: &[u8], rules: SourceRules) -> Result<Self> {
        let checked = if rules.overlap && rules.compiler == CompilerMode::Source {
            package::admit_transition_rules(
                encoded,
                rules.point_ops,
                rules.loops,
                rules.metered,
                rules.records,
            )
        } else {
            package::admit_with_rules(
                encoded,
                rules.compiler,
                rules.point_ops,
                rules.loops,
                rules.metered,
                rules.records,
            )
        }?;
        if rules.records
            && !rules.loops
            && !octra_node_protocol::program_record::source::scope_matches(
                &checked.main,
                &checked.sources,
                rules.metered,
                &checked.result.bytecode,
            )?
        {
            return Err(Error::rejected("program source scope differs"));
        }
        let record = rules.records.then(|| {
            octra_node_protocol::program_record::source::make(
                &octra_node_protocol::program_record::source::source_text(
                    &checked.main,
                    &checked.sources,
                ),
                checked.envelope(),
                &checked.result,
            )
        });
        let (raw, admitted) = checked.into_parts();
        Ok(Self {
            raw,
            admitted,
            mode: Mode::Source,
            record,
        })
    }
    pub fn record(&self) -> Option<&octra_node_protocol::program_record::Record> {
        self.record.as_ref()
    }
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }
    pub fn admitted(&self) -> &Admitted {
        &self.admitted
    }
    pub fn admission(&self) -> &'static [u8] {
        match self.mode {
            Mode::Binary => b"binary",
            Mode::Source => b"source",
        }
    }
    pub fn version(&self) -> &[u8] {
        match self.mode {
            Mode::Binary => compiler::LANG_VERSION,
            Mode::Source => self
                .admitted
                .compiler_version()
                .unwrap_or(compiler::LANG_VERSION),
        }
    }
    // This path is restricted to metadata from the authenticated state or its
    // host-owned journal. A transaction cannot assert admission="source".
    fn stored(
        encoded: &[u8],
        mode: &[u8],
        point_ops: bool,
        trusted: &Keys,
    ) -> Result<Option<Self>> {
        let Ok(raw) = decode_base64(encoded) else {
            return Ok(None);
        };
        let (mode, checked) = if mode == b"source" {
            (Mode::Source, program::decode_source(&raw, point_ops))
        } else {
            (
                Mode::Binary,
                program::decode_deploy(&raw, point_ops, trusted),
            )
        };
        match checked {
            Ok(admitted) => Ok(Some(Self {
                raw,
                admitted,
                mode,
                record: None,
            })),
            Err(error) if error.is_operational() => Err(Error::from(error)),
            Err(_) => Ok(None),
        }
    }
    pub fn load(
        state: &Snapshot,
        journal: &Journal,
        address: &[u8],
        point_ops: bool,
        trusted: &Keys,
    ) -> Result<Option<Self>> {
        if let Some(upgrade) = journal.find_upgrade(address) {
            return Self::stored(
                &upgrade.bytecode,
                &upgrade.meta.admission,
                point_ops,
                trusted,
            );
        }
        if let Some(deploy) = journal.find_deploy(address) {
            return Self::stored(&deploy.bytecode, &deploy.meta.admission, point_ops, trusted);
        }
        let Some(encoded) = store::bytecode(state, address) else {
            return Ok(None);
        };
        let meta = store::meta(state, address)?;
        Self::stored(
            encoded,
            meta.as_ref()
                .map_or(b"binary".as_slice(), |meta| meta.admission.as_slice()),
            point_ops,
            trusted,
        )
    }
}
