//! Native bounded duty evidence selection against one committed duty state.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    consensus::codec::Wire,
    duty::Proof,
    light_rpc::json::{object, string},
    validator::set_fold::{self, Config, MarkClaim, State},
};
pub fn proof_fields(proof: &Proof) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    Ok(vec![
        (
            "duty_vote",
            string(STANDARD.encode(proof.vote.encode().map_err(|e| e.to_string())?)),
        ),
        (
            "duty_commit",
            string(STANDARD.encode(proof.commit.encode().map_err(|e| e.to_string())?)),
        ),
    ])
}
pub fn mark_fields(
    base: &[(&'static str, Vec<u8>)],
    epoch: i64,
    chain: &[u8],
    address: &[u8],
    state: &State,
    proofs: &[Proof],
) -> Result<Vec<(&'static str, Vec<u8>)>, String> {
    let cfg = Config::participating();
    let last = epoch.saturating_add(2);
    let available = |at: i64| at >= 0 && at <= last && last - at <= cfg.challenge;
    let mut proofs: Vec<_> = proofs.iter().collect();
    proofs.sort_by(|left, right| {
        left.vote
            .epoch_id
            .cmp(&right.vote.epoch_id)
            .then(left.vote.signature.cmp(&right.vote.signature))
    });
    let mut claims = Vec::<MarkClaim>::new();
    for proof in &proofs {
        let claim = MarkClaim {
            epoch: proof.vote.epoch_id,
            signature: proof.vote.signature.clone(),
        };
        if !available(claim.epoch) || claims.last().is_some_and(|last| last.epoch == claim.epoch) {
            continue;
        }
        let sets = [(
            claim.epoch,
            chain.to_vec(),
            proof.commit.validator_set.clone(),
        )];
        if state
            .verify_mark_claim(&cfg, chain, epoch, address, &sets, &claim)
            .is_ok()
        {
            claims.push(claim);
        }
    }
    if !claims.is_empty() {
        return Ok(vec![(
            "duty_marks",
            string(set_fold::encode_marks(&claims).map_err(|e| e.to_string())?),
        )]);
    }
    for proof in proofs {
        if available(proof.vote.epoch_id)
            && state
                .find_final(proof.vote.epoch_id)
                .is_some_and(|finality| finality.round.is_none())
        {
            let fields = proof_fields(proof)?;
            let mut complete = base.to_vec();
            complete.extend(fields.clone());
            if object(&complete).len()
                <= octra_node_protocol::transaction_payload::Limits::default().message_validator
            {
                return Ok(fields);
            }
        }
    }
    Err("validator duty saved marks are unavailable".into())
}
