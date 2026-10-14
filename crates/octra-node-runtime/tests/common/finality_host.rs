//! Fixed development keys for local publication tests only.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use octra_exex::{native_history::NativeTransaction, ChainIdentity};
use octra_node_protocol::{
    consensus::{engine, hash, EpochHeader, Finalize, Validator, ValidatorSet, Vote, VoteType},
    epoch_index,
};
use octra_node_runtime::{
    canonical::{Head, ReliefSource},
    finality::{EpochRules, ExecutedEpoch, ReceiptRules, ValidatorHistory},
    state_batch::StateBatch,
};
#[derive(Clone)]
pub(crate) struct Authority {
    pub(crate) seed: u8,
    pub(crate) chain: ChainIdentity,
}
impl Authority {
    pub(crate) fn validators(&self, parent: &Head, epoch: u64) -> Result<ValidatorSet, String> {
        if epoch != parent.cursor.epoch.0 + 1
            || (epoch == 1 && parent.cursor.state_root != self.chain.genesis_root)
        {
            return Err("history binding differs".into());
        }
        Ok(validators(self.seed))
    }
}
#[async_trait::async_trait]
impl ValidatorHistory for Authority {
    async fn resolve(
        &self,
        parent: &Head,
        epoch: u64,
        relief: ReliefSource,
    ) -> Result<EpochRules, String> {
        if matches!(relief, ReliefSource::Committed(Some(_))) {
            return Err("fixed development authority cannot authorize relief".into());
        }
        Ok(EpochRules {
            validators: self.validators(parent, epoch)?,
            // Explicit historical policy for these public development fixtures.
            receipts: ReceiptRules {
                required: false,
                crypto_active: false,
                stealth_minimum: 5000.into(),
            },
            relief: None,
        })
    }
}

fn validators(seed: u8) -> ValidatorSet {
    ValidatorSet::unweighted(
        (0..4)
            .map(|i| Validator {
                address: format!("validator-{i}").into_bytes(),
                pubkey: SigningKey::from_bytes(&[seed + i; 32])
                    .verifying_key()
                    .to_bytes()
                    .to_vec(),
            })
            .collect(),
    )
}
#[allow(dead_code)] // Not every QC-only fixture executes an epoch footer.
pub(crate) fn reward(seed: u8) -> octra_node_protocol::epoch_rewards::Attribution {
    use octra_node_protocol::epoch_rewards::{Attribution, Validator};
    Attribution {
        proposer: b"validator-0".to_vec(),
        proposer_public_key: Some(
            STANDARD
                .encode(
                    SigningKey::from_bytes(&[seed; 32])
                        .verifying_key()
                        .to_bytes(),
                )
                .into_bytes(),
        ),
        validators: (0..4)
            .map(|i| Validator {
                address: format!("validator-{i}").into_bytes(),
                public_key: Some(
                    STANDARD
                        .encode(
                            SigningKey::from_bytes(&[seed + i; 32])
                                .verifying_key()
                                .to_bytes(),
                        )
                        .into_bytes(),
                ),
                weight: 1.into(),
            })
            .collect(),
    }
}
#[allow(dead_code)]
pub(crate) fn reward_source(seed: u8) -> octra_node_protocol::consensus::RewardSource {
    octra_node_protocol::consensus::reward_attribution::to_source(&reward(seed)).unwrap()
}
pub(crate) fn sign(finalized: &mut Finalize, seed: u8) {
    finalized.proposal_id = hash::proposal_id(&finalized.header).unwrap().to_vec();
    finalized.precommits = (0..3)
        .map(|i| {
            let mut vote = Vote {
                chain_id: finalized.chain_id.clone(),
                epoch_id: finalized.epoch_id,
                round: finalized.commit_round,
                vote_type: VoteType::Precommit,
                proposal_id: finalized.proposal_id.clone(),
                validator: format!("validator-{i}").into_bytes(),
                signature: vec![],
            };
            vote.signature = SigningKey::from_bytes(&[seed + i; 32])
                .sign(&hash::vote_sign_bytes(&vote).unwrap())
                .to_bytes()
                .to_vec();
            vote
        })
        .collect();
}
pub(crate) fn root(
    base: Option<&Head>,
    state: &StateBatch,
    transactions: &[NativeTransaction],
) -> [u8; 32] {
    let prior = base.map_or_else(
        || hex::encode(epoch_index::genesis_root()),
        |b| b.index_root.clone(),
    );
    let items = transactions
        .iter()
        .map(|t| epoch_index::Item {
            txid: t.txid,
            hash: t.hash.as_bytes().to_vec(),
        })
        .collect::<Vec<_>>();
    let (_, index) = epoch_index::next_root(
        prior.as_bytes(),
        base.map_or(0, |b| b.cursor.epoch.0 as i64 + 1),
        &items,
    )
    .unwrap();
    epoch_index::folded_state_root(
        hex::encode(state.root().unwrap()).as_bytes(),
        hex::encode(index).as_bytes(),
    )
    .unwrap()
}
pub(crate) fn certificate(
    base: &Head,
    executed: &ExecutedEpoch,
    authority: &Authority,
) -> Finalize {
    let state = StateBatch::from_snapshot(executed.state.clone());
    let epoch = base.cursor.epoch.0 as i64 + 1;
    let mut finalized = Finalize {
        chain_id: authority.chain.chain_id.as_bytes().to_vec(),
        epoch_id: epoch,
        commit_round: 0,
        header: EpochHeader {
            proto_version: 4,
            chain_id: authority.chain.chain_id.as_bytes().to_vec(),
            epoch_id: epoch,
            prev_state_root: base.cursor.state_root.0.to_vec(),
            proposed_state_root: root(Some(base), &state, &executed.transactions).to_vec(),
            tx_list_hash: engine::tx_list_hash_for_header(
                &executed
                    .transactions
                    .iter()
                    .map(|t| t.hash.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            )
            .to_vec(),
            receipt_root: hash::receipt_root(&executed.consensus_receipts)
                .unwrap()
                .to_vec(),
            parent_commit_hash: vec![0; 32],
            creator_addr: b"validator-0".to_vec(),
            txid_hi: base.txid_hi + executed.transactions.len() as i64,
            ts: f64::from(u32::try_from(epoch).unwrap()) * 10.,
        },
        proposal_id: vec![],
        precommits: vec![],
        parent_commit: None,
    };
    sign(&mut finalized, authority.seed);
    finalized
}
