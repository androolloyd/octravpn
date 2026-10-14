// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native signed consensus domains, including historical v3/v4 headers.
use super::{
    codec::{self, Wire},
    reward,
    types::{
        BundleResponse, Bytes, CatchupEpochRecord, CatchupResponse, EpochHeader, EpochRootResponse,
        ParentCommit, ProofCertificate, ProofKind, ProofQc, Proposal, RoundSync, ValidatorSet,
        Vote, CURRENT_VERSION, LEGACY_VERSION, NIL,
    },
    Error,
};
use crate::{
    network::{domain_hash, verify_ed25519},
    oce1::Writer,
};
pub type Hash = [u8; 32];
fn encoded(
    domain: &[u8],
    put: impl FnOnce(&mut Writer) -> Result<(), Error>,
) -> Result<Hash, Error> {
    let mut writer = Writer::new();
    put(&mut writer)?;
    Ok(domain_hash(domain, &writer.into_bytes()))
}
pub fn proposal_id(header: &EpochHeader) -> Result<Hash, Error> {
    let domain = match header.proto_version {
        LEGACY_VERSION => b"octra:epoch_proposal_id:v3",
        CURRENT_VERSION => b"octra:epoch_proposal_id:v4",
        _ => return Err("unsupported epoch header protocol".into()),
    };
    encoded(domain, |w| {
        w.put_u16(header.proto_version as u16)?;
        w.put_bytes(&header.chain_id)?;
        w.put_u64(header.epoch_id as u64)?;
        w.put_hash32(&header.prev_state_root)?;
        w.put_hash32(&header.tx_list_hash)?;
        w.put_hash32(&header.receipt_root)?;
        w.put_hash32(&header.proposed_state_root)?;
        if header.proto_version == CURRENT_VERSION {
            w.put_hash32(&header.parent_commit_hash)?;
        }
        w.put_bytes(&header.creator_addr)?;
        w.put_u64(header.txid_hi as u64)?;
        w.put_u64(header.ts.to_bits())
    })
}
pub fn vote_sign_bytes(vote: &Vote) -> Result<Hash, Error> {
    encoded(b"octra:vote:v2", |w| {
        w.put_bytes(&vote.chain_id)?;
        w.put_u64(vote.epoch_id as u64)?;
        w.put_u32(vote.round as u32)?;
        w.put_u8(vote.vote_type as u8)?;
        w.put_hash32(&vote.proposal_id)
    })
}
pub fn round_sync_sign_bytes(sync: &RoundSync) -> Result<Hash, Error> {
    encoded(b"octra:round_sync:v1", |w| {
        w.put_bytes(&sync.chain_id)?;
        w.put_u64(sync.epoch_id as u64)?;
        w.put_u32(sync.round as u32)?;
        w.put_u8(sync.step as u8)?;
        w.put_bool(sync.request)?;
        w.put_bytes(&sync.validator)
    })
}
pub fn propose_sign_bytes(proposal: &Proposal) -> Result<Hash, Error> {
    let pid = proposal_id(&proposal.header)?;
    let domain = match proposal.header.proto_version {
        LEGACY_VERSION => b"octra:propose:v3",
        CURRENT_VERSION => b"octra:propose:v4",
        _ => return Err("unsupported proposal protocol".into()),
    };
    encoded(domain, |w| {
        w.put_bytes(&proposal.chain_id)?;
        w.put_u64(proposal.epoch_id as u64)?;
        w.put_u32(proposal.round as u32)?;
        w.put_option(proposal.valid_round.as_ref(), |w, v| w.put_u32(*v as u32))?;
        w.put_hash32(&pid)
    })
}
pub fn parent_commit_hash(parent: &ParentCommit) -> Result<Hash, Error> {
    Ok(domain_hash(b"octra:parent_commit:v1", &parent.encode()?))
}
pub fn parent_commit_hash_opt(parent: Option<&ParentCommit>) -> Result<Hash, Error> {
    parent.map_or(Ok(NIL), parent_commit_hash)
}
pub fn tx_list_hash(hashes: &[Bytes]) -> Result<Hash, Error> {
    encoded(b"octra:tx_list_hash:v1", |w| {
        w.put_list(hashes, |w, h| w.put_hash32(h))
    })
}
pub fn receipt_root(receipts: &[Bytes]) -> Result<Hash, Error> {
    encoded(b"octra:preverify_receipt_root:v1", |w| {
        w.put_list(receipts, |w, h| w.put_bytes(h))
    })
}
pub fn proof_cert_sign_bytes(
    chain_id: &[u8],
    certificate: &ProofCertificate,
) -> Result<Hash, Error> {
    encoded(b"octra:proof_cert:v1", |w| {
        w.put_bytes(chain_id)?;
        w.put_hash32(&certificate.task_id)?;
        w.put_bool(certificate.result)
    })
}
pub fn proof_task_id(tx_hash: &[u8], kind: ProofKind, inputs_hash: &[u8]) -> Result<Hash, Error> {
    encoded(b"octra:proof_task:v1", |w| {
        w.put_hash32(tx_hash)?;
        w.put_u8(kind as u8)?;
        w.put_hash32(inputs_hash)
    })
}
pub fn proof_qc_hash(qc: &ProofQc) -> Result<Hash, Error> {
    let mut signers: Vec<_> = qc.certs.iter().map(|(addr, _)| addr).collect();
    signers.sort();
    encoded(b"octra:proof_qc_hash:v1", |w| {
        w.put_hash32(&qc.task_id)?;
        w.put_bool(qc.result)?;
        w.put_list(&signers, |w, addr| w.put_bytes(addr))
    })
}
pub fn epoch_root_response_sign_bytes(response: &EpochRootResponse) -> Result<Hash, Error> {
    encoded(b"octra:epoch_root_response:v1", |w| {
        w.put_bytes(&response.chain_id)?;
        w.put_u64(response.epoch_id as u64)?;
        w.put_option(response.state_root.as_ref(), |w, h| w.put_hash32(h))?;
        w.put_bytes(&response.responder_addr)?;
        w.put_u64(response.responder_head_epoch as u64)
    })
}
pub fn bundle_response_sign_bytes(response: &BundleResponse) -> Result<Hash, Error> {
    encoded(b"octra:bundle_response:v1", |w| {
        w.put_bytes(&response.chain_id)?;
        w.put_u64(response.epoch_id as u64)?;
        w.put_hash32(&response.proposal_id)?;
        w.put_bytes(&response.responder_addr)?;
        w.put_list(&response.tx_hashes, |w, h| w.put_hash32(h))?;
        w.put_list(&response.txs_json, |w, j| w.put_bytes(j))?;
        w.put_list(&response.receipts_json, |w, j| w.put_bytes(j))
    })
}
pub fn catchup_response_sign_bytes(
    chain_id: &[u8],
    request_id: &[u8],
    responder: &[u8],
    from_epoch: i64,
    records_root: &[u8],
) -> Result<Hash, Error> {
    encoded(b"octra:catchup_range_response:v1", |w| {
        w.put_bytes(chain_id)?;
        w.put_bytes(request_id)?;
        w.put_bytes(responder)?;
        w.put_u64(from_epoch as u64)?;
        w.put_hash32(records_root)
    })
}
pub fn mark_complete_catchup_request(request_id: &[u8]) -> Result<Bytes, Error> {
    if request_id.len() != 32 {
        return Err("catchup request id must be 32 bytes".into());
    }
    let mut output = request_id.to_vec();
    output[..8].copy_from_slice(b"OCRFULL2");
    Ok(output)
}
pub fn catchup_request_is_complete(request_id: &[u8]) -> bool {
    request_id.len() == 32 && request_id.starts_with(b"OCRFULL2")
}
pub fn catchup_complete_sign_bytes(
    from_epoch: i64,
    response: &CatchupResponse,
) -> Result<Hash, Error> {
    encoded(b"octra:catchup_range_response:complete", |w| {
        w.put_bytes(&response.chain_id)?;
        w.put_hash32(&response.request_id)?;
        w.put_bytes(&response.responder_addr)?;
        w.put_u64(from_epoch as u64)?;
        w.put_bytes(&response.status)?;
        w.put_option(response.error_code.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_list(&response.records, |w, r| {
            codec::put_catchup_record(w, r, true)
        })?;
        w.put_option(response.next_epoch.as_ref(), |w, v| w.put_u64(*v as u64))
    })
}
pub fn catchup_records_root(records: &[CatchupEpochRecord]) -> Result<Hash, Error> {
    encoded(b"octra:catchup_records_root:v5", |w| {
        w.put_list(records, |w, r| {
            w.put_u64(r.epoch_id as u64)?;
            w.put_hash32(&r.prev_state_root)?;
            w.put_hash32(&r.state_root)?;
            w.put_hash32(&r.tx_list_hash)?;
            w.put_list(&r.tx_hashes, |w, h| w.put_hash32(h))?;
            w.put_hash32(&r.receipt_root)?;
            w.put_list(&r.receipts_json, |w, j| w.put_bytes(j))?;
            w.put_u64(r.epoch_ts.to_bits())?;
            w.put_bytes(&r.creator_addr)?;
            w.put_u32(r.commit_round as u32)?;
            reward::put(
                w,
                r.reward_source
                    .as_ref()
                    .ok_or_else(|| Error::from("catchup reward source is missing"))?,
            )?;
            let finality = r
                .finality
                .as_ref()
                .ok_or_else(|| Error::from("catchup finality is missing"))?;
            w.put_hash32(&finality.finalize.proposal_id)?;
            w.put_hash32(&validator_set_hash(&finality.validator_set)?)
        })
    })
}
pub fn catchup_records_root_v1(records: &[CatchupEpochRecord]) -> Result<Hash, Error> {
    encoded(b"octra:catchup_records_root:v2", |w| {
        w.put_list(records, |w, r| {
            w.put_u64(r.epoch_id as u64)?;
            w.put_hash32(&r.prev_state_root)?;
            w.put_hash32(&r.state_root)?;
            w.put_hash32(&r.tx_list_hash)?;
            w.put_list(&r.tx_hashes, |w, h| w.put_hash32(h))?;
            w.put_bytes(&[])?;
            w.put_u32(0)
        })
    })
}
pub fn validator_set_hash(set: &ValidatorSet) -> Result<Hash, Error> {
    let domain = if set.weighted {
        b"octra:consensus_validator_set:v2"
    } else {
        b"octra:consensus_validator_set:v1"
    };
    encoded(domain, |w| {
        w.put_u32(set.n as u32)?;
        w.put_u32(set.f as u32)?;
        w.put_u32(set.quorum as u32)?;
        if set.weighted {
            w.put_bytes(set.total_weight.to_string().as_bytes())?;
            w.put_bytes(set.quorum_weight.to_string().as_bytes())?;
        }
        w.put_list(&set.validators, |w, v| {
            w.put_bytes(&v.address)?;
            w.put_raw(&v.pubkey)?;
            if set.weighted {
                w.put_bytes(
                    set.weight(&v.address)
                        .ok_or_else(|| Error::from("validator weight missing"))?
                        .to_string()
                        .as_bytes(),
                )?;
            }
            Ok(())
        })
    })
}
pub fn network_hash(
    chain_id: &[u8],
    program_trust: Option<&Bytes>,
    runtime_profile: Option<&Bytes>,
) -> Result<Hash, Error> {
    encoded(b"octra:consensus_network", |w| {
        w.put_bytes(chain_id)?;
        w.put_u16(CURRENT_VERSION as u16)?;
        w.put_option(program_trust, |w, h| w.put_hash32(h))?;
        w.put_option(runtime_profile, |w, h| w.put_hash32(h))
    })
}
pub fn config_hash(
    chain_id: &[u8],
    set: &ValidatorSet,
    scheduled: Option<(i64, &ValidatorSet)>,
    program_trust: Option<&Bytes>,
    runtime_profile: Option<&Bytes>,
) -> Result<Hash, Error> {
    let weighted = set.weighted || scheduled.is_some_and(|(_, v)| v.weighted);
    let domain = match (weighted, runtime_profile, program_trust) {
        (true, _, _) => b"octra:consensus_config:v4",
        (false, None, None) => b"octra:consensus_config:v1",
        (false, None, Some(_)) => b"octra:consensus_config:v2",
        (false, Some(_), _) => b"octra:consensus_config:v3",
    };
    encoded(domain, |w| {
        w.put_bytes(chain_id)?;
        w.put_u16(CURRENT_VERSION as u16)?;
        if weighted {
            w.put_option(program_trust, |w, h| w.put_hash32(h))?;
            w.put_option(runtime_profile, |w, h| w.put_hash32(h))?;
        } else if let Some(profile) = runtime_profile {
            w.put_option(program_trust, |w, h| w.put_hash32(h))?;
            w.put_hash32(profile)?;
        } else if let Some(program) = program_trust {
            w.put_hash32(program)?;
        }
        w.put_hash32(&validator_set_hash(set)?)?;
        match scheduled {
            None => w.put_u8(0),
            Some((epoch, set)) => {
                w.put_u8(1)?;
                w.put_u64(epoch as u64)?;
                w.put_hash32(&validator_set_hash(set)?)
            }
        }
    })
}
pub fn verify_vote(public_key: &[u8], vote: &Vote) -> Result<bool, Error> {
    Ok(verify_ed25519(
        public_key,
        &vote_sign_bytes(vote)?,
        &vote.signature,
    ))
}
pub fn verify_round_sync(public_key: &[u8], sync: &RoundSync) -> Result<bool, Error> {
    Ok(verify_ed25519(
        public_key,
        &round_sync_sign_bytes(sync)?,
        &sync.signature,
    ))
}
pub fn verify_proposal(public_key: &[u8], proposal: &Proposal) -> Result<bool, Error> {
    Ok(verify_ed25519(
        public_key,
        &propose_sign_bytes(proposal)?,
        &proposal.signature,
    ))
}
pub fn verify_proof_certificate(
    chain_id: &[u8],
    public_key: &[u8],
    certificate: &ProofCertificate,
) -> Result<bool, Error> {
    Ok(verify_ed25519(
        public_key,
        &proof_cert_sign_bytes(chain_id, certificate)?,
        &certificate.signature,
    ))
}
