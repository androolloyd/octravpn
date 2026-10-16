// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    rpc, CertificateProgress, CommitteeLease, Evidence, Head, JobHandle, JobStatus, OfferSnapshot,
    Request, Response,
};
use crate::compute_deposits::Funded;
use octra_node_protocol::resource_compute::{
    call::Call,
    message::{CancelAck, CancelRound, Fetch, Output},
    read::Read,
    wire::Message,
    Error, Result,
};
use tokio::sync::oneshot;
pub(super) type Reply<T> = oneshot::Sender<Result<T>>;
pub(super) struct Apply {
    pub wire_key: [u8; 32],
    pub source: Option<Vec<u8>>,
    pub message: Message,
    pub funds: Option<Funded>,
}
pub(super) struct Admit {
    pub request: Request,
    pub resume: bool,
}
pub(super) struct Envelope {
    pub generation: u64,
    pub command: Command,
}
// Keep native owned command/result records inline without changing their API.
#[allow(clippy::large_enum_variant)]
pub(super) enum Command {
    Apply(Apply, Reply<bool>),
    CheckFunding(Call, Reply<Option<Head>>),
    DropFunding(Vec<u8>, Reply<()>),
    FundCall((Call, Funded), Reply<bool>),
    Admit(Admit, Reply<(Vec<u8>, JobHandle)>),
    CompleteJob((Vec<u8>, Vec<u8>), Reply<()>),
    Cancel(rpc::Cancellation, Reply<usize>),
    PollCancel(
        Option<(Vec<u8>, Vec<u8>)>,
        Reply<Option<crate::compute_history::Notice>>,
    ),
    ReadCancels(rpc::Cancellation, Reply<Vec<CancelAck>>),
    CancelKeys(CancelRound, Reply<Option<(Vec<u8>, Vec<u8>)>>),
    CancelPath(CancelRound, Reply<Option<Vec<u8>>>),
    WakeReveals((), Reply<()>),
    SentReveal((Vec<u8>, bool), Reply<()>),
    SaveResult((Call, Output), Reply<bool>),
    IssueCall(Call, Reply<()>),
    SaveJob((Vec<u8>, Response), Reply<()>),
    CompleteBackground(u64, Reply<()>),
    RememberCommittee(CommitteeLease, Reply<()>),
    QueryStatus(Read, Reply<Option<JobStatus>>),
    ActiveJobs((), Reply<usize>),
    QueryOffer(Vec<u8>, Reply<Option<OfferSnapshot>>),
    QueryCertificate(Vec<u8>, Reply<CertificateProgress>),
    RequestReplies(Vec<u8>, Reply<Option<(usize, Vec<Fetch>)>>),
    Evidence((), Reply<Evidence>),
    Stop((), Reply<()>),
}
impl Command {
    pub(super) fn control(&self) -> bool {
        match self {
            Self::Apply(input, _) => matches!(
                input.message,
                Message::Cancel(_) | Message::CancelRound(_) | Message::CancelAck(_)
            ),
            Self::CompleteJob(..)
            | Self::DropFunding(..)
            | Self::FundCall(..)
            | Self::Cancel(..)
            | Self::PollCancel(..)
            | Self::ReadCancels(..)
            | Self::CancelKeys(..)
            | Self::CancelPath(..)
            | Self::SentReveal(..)
            | Self::SaveResult(..)
            | Self::IssueCall(..)
            | Self::SaveJob(..)
            | Self::CompleteBackground(..)
            | Self::RememberCommittee(..)
            | Self::Stop(..) => true,
            _ => false,
        }
    }
    pub(super) fn reject(self, error: Error) {
        macro_rules! reject {($($variant:ident),* $(,)?)=>{match self {$(Self::$variant(_,reply)=>{let _=reply.send(Err(error));},)*}};}
        reject!(
            Apply,
            CheckFunding,
            DropFunding,
            FundCall,
            Admit,
            CompleteJob,
            Cancel,
            PollCancel,
            ReadCancels,
            CancelKeys,
            CancelPath,
            WakeReveals,
            SentReveal,
            SaveResult,
            IssueCall,
            SaveJob,
            CompleteBackground,
            RememberCommittee,
            QueryStatus,
            ActiveJobs,
            QueryOffer,
            QueryCertificate,
            RequestReplies,
            Evidence,
            Stop
        );
    }
}
