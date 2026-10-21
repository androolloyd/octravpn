//! Process-local successes only. Callers must reread all evidence and resolve
//! authority before lookup, then insert only after authenticating those inputs.
use std::{collections::BTreeMap, sync::Mutex};

use num_bigint::BigInt;
use octra_exex::{
    native_history::{ArchiveProof, NativeTransaction},
    ChainIdentity, ChainOrigin, CommittedEpoch, Cursor, Sequence,
};
use octra_node_protocol::consensus::{
    relief::Mark, RewardMember, RewardSource, RoundStep, RoundSync, Validator, ValidatorSet,
};
use sha2::{Digest as _, Sha256};

use super::{EpochRules, ReceiptRules};
use crate::canonical::Head;

pub(super) type Digest = [u8; 32];
const CAPACITY: usize = 32_768;

pub(super) fn stored_key(
    chain: &ChainIdentity,
    record: &crate::canonical::AuditRecord,
    rules: &EpochRules,
) -> Digest {
    let mut transcript = Transcript(Sha256::new());
    transcript.bytes(b"octra:stored-finality-audit:v1\0");
    transcript.chain(chain);
    transcript.head(&record.base);
    transcript.head(&record.head);
    transcript.bytes(&record.fingerprint());
    transcript.rules(rules);
    transcript.0.finalize().into()
}

pub(super) struct Inputs<'a> {
    pub chain: &'a ChainIdentity,
    pub base: &'a Head,
    pub head: &'a Head,
    pub epoch: &'a CommittedEpoch<NativeTransaction>,
    pub certificate: &'a [u8],
    pub receipts: &'a [Vec<u8>],
    pub proposal: &'a [u8],
    pub reward: &'a RewardSource,
    pub rules: &'a EpochRules,
}

impl Inputs<'_> {
    pub(super) fn key(&self) -> Digest {
        let Self {
            chain,
            base,
            head,
            epoch,
            certificate,
            receipts,
            proposal,
            reward,
            rules,
        } = self;
        let mut transcript = Transcript(Sha256::new());
        transcript.bytes(b"octra:finality-audit:v1\0");
        transcript.chain(chain);
        transcript.head(base);
        transcript.head(head);
        transcript.epoch(epoch);
        transcript.bytes(certificate);
        transcript.length(receipts.len());
        for receipt in *receipts {
            transcript.bytes(receipt);
        }
        transcript.bytes(proposal);
        transcript.reward(reward);
        transcript.rules(rules);
        transcript.0.finalize().into()
    }
}

/// Retain the lowest sequences: a bounded ascending full scan must not evict
/// every useful prefix entry while visiting records beyond the capacity.
/// Poisoning only disables this optimization, never authentication.
#[derive(Default)]
pub(super) struct AuditCache(Mutex<BTreeMap<Sequence, Digest>>);

impl AuditCache {
    pub(super) fn contains(&self, sequence: Sequence, key: &Digest) -> bool {
        self.0
            .lock()
            .is_ok_and(|entries| entries.get(&sequence) == Some(key))
    }

    pub(super) fn insert(&self, sequence: Sequence, key: Digest) {
        let Ok(mut entries) = self.0.lock() else {
            return;
        };
        if let Some(previous) = entries.get_mut(&sequence) {
            *previous = key;
        } else if entries.len() < CAPACITY {
            entries.insert(sequence, key);
        } else if entries
            .last_key_value()
            .is_some_and(|(highest, _)| sequence < *highest)
        {
            entries.pop_last();
            entries.insert(sequence, key);
        }
    }
}

/// Fixed-width scalars, length-prefixed bytes/lists and explicit option/enum
/// tags make this an unambiguous transcript without allocating a serialized
/// copy of the archive. Exhaustive patterns keep new input fields visible.
struct Transcript(Sha256);

impl Transcript {
    fn byte(&mut self, value: u8) {
        self.0.update([value]);
    }

    fn boolean(&mut self, value: bool) {
        self.byte(u8::from(value));
    }

    fn unsigned(&mut self, value: u64) {
        self.0.update(value.to_be_bytes());
    }

    fn signed(&mut self, value: i64) {
        self.0.update(value.to_be_bytes());
    }

    fn length(&mut self, value: usize) {
        self.unsigned(value as u64);
    }

    fn bytes(&mut self, value: &[u8]) {
        self.length(value.len());
        self.0.update(value);
    }

    fn integer(&mut self, value: &BigInt) {
        self.bytes(&value.to_signed_bytes_be());
    }

    fn optional_bytes(&mut self, value: Option<&[u8]>) {
        self.boolean(value.is_some());
        if let Some(bytes) = value {
            self.bytes(bytes);
        }
    }

    fn cursor(&mut self, cursor: &Cursor) {
        let Cursor {
            sequence,
            epoch,
            state_root,
        } = cursor;
        self.unsigned(sequence.0);
        self.unsigned(epoch.0);
        self.bytes(&state_root.0);
    }

    fn chain(&mut self, chain: &ChainIdentity) {
        let ChainIdentity { chain_id, origin } = chain;
        self.bytes(chain_id.as_bytes());
        match origin {
            ChainOrigin::Genesis { state_root } => {
                self.byte(0);
                self.bytes(&state_root.0);
            }
            ChainOrigin::Checkpoint { epoch, state_root } => {
                self.byte(1);
                self.unsigned(*epoch);
                self.bytes(&state_root.0);
            }
        }
    }

    fn head(&mut self, head: &Head) {
        let Head {
            cursor,
            ledger_root,
            irmin_commit,
            parent_commit,
            index_root,
            index_hash,
            txid_hi,
            date,
            message,
        } = head;
        self.cursor(cursor);
        self.bytes(ledger_root.as_bytes());
        self.bytes(irmin_commit.as_bytes());
        self.optional_bytes(parent_commit.as_deref().map(str::as_bytes));
        self.bytes(index_root.as_bytes());
        self.optional_bytes(index_hash.as_deref().map(str::as_bytes));
        self.signed(*txid_hi);
        self.signed(*date);
        self.bytes(message);
    }

    fn epoch(&mut self, epoch: &CommittedEpoch<NativeTransaction>) {
        let CommittedEpoch {
            chain,
            cursor,
            parent_root,
            events,
        } = epoch;
        self.chain(chain);
        self.cursor(cursor);
        self.bytes(&parent_root.0);
        self.length(events.len());
        for event in events {
            let NativeTransaction {
                txid,
                hash,
                proof,
                identity,
                transaction,
                receipt,
            } = event;
            self.signed(*txid);
            self.bytes(hash.as_bytes());
            self.byte(match proof {
                ArchiveProof::Exact => 0,
                ArchiveProof::Signed => 1,
                ArchiveProof::SignedOperation => 2,
            });
            self.bytes(identity);
            self.bytes(transaction);
            self.optional_bytes(receipt.as_deref());
        }
    }

    fn reward(&mut self, reward: &RewardSource) {
        let RewardSource {
            reward_proposer_addr,
            reward_proposer_public_key,
            reward_members,
        } = reward;
        self.bytes(reward_proposer_addr);
        self.optional_bytes(reward_proposer_public_key.as_deref());
        self.length(reward_members.len());
        for member in reward_members {
            let RewardMember {
                reward_address,
                reward_public_key,
                reward_weight,
            } = member;
            self.bytes(reward_address);
            self.optional_bytes(reward_public_key.as_deref());
            self.integer(reward_weight);
        }
    }

    fn rules(&mut self, rules: &EpochRules) {
        let EpochRules {
            validators,
            receipts,
            relief,
        } = rules;
        let ValidatorSet {
            validators,
            weights,
            n,
            f,
            quorum,
            total_weight,
            quorum_weight,
            weighted,
        } = validators;
        self.length(validators.len());
        for validator in validators {
            let Validator { address, pubkey } = validator;
            self.bytes(address);
            self.bytes(pubkey);
        }
        self.length(weights.len());
        for (address, weight) in weights {
            self.bytes(address);
            self.integer(weight);
        }
        self.signed(*n);
        self.signed(*f);
        self.signed(*quorum);
        self.integer(total_weight);
        self.integer(quorum_weight);
        self.boolean(*weighted);
        let ReceiptRules {
            required,
            crypto_active,
            stealth_minimum,
        } = receipts;
        self.boolean(*required);
        self.boolean(*crypto_active);
        self.integer(stealth_minimum);
        self.boolean(relief.is_some());
        if let Some(mark) = relief {
            self.mark(mark);
        }
    }

    fn mark(&mut self, mark: &Mark) {
        let Mark {
            height,
            round,
            activate_epoch,
            source_hash,
            target_hash,
            fingerprint,
            proof,
        } = mark;
        self.signed(*height);
        self.signed(*round);
        self.signed(*activate_epoch);
        self.bytes(source_hash);
        self.bytes(target_hash);
        self.bytes(fingerprint);
        self.length(proof.len());
        for sync in proof {
            let RoundSync {
                chain_id,
                epoch_id,
                round,
                step,
                request,
                validator,
                signature,
            } = sync;
            self.bytes(chain_id);
            self.signed(*epoch_id);
            self.signed(*round);
            self.byte(match step {
                RoundStep::Propose => 0,
                RoundStep::Prevote => 1,
                RoundStep::Precommit => 2,
            });
            self.boolean(*request);
            self.bytes(validator);
            self.bytes(signature);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::{EpochId, StateRoot};
    use octra_node_protocol::consensus::codec::Wire;

    struct Fixture {
        chain: ChainIdentity,
        base: Head,
        head: Head,
        epoch: CommittedEpoch<NativeTransaction>,
        certificate: Vec<u8>,
        receipts: Vec<Vec<u8>>,
        proposal: Vec<u8>,
        reward: RewardSource,
        rules: EpochRules,
    }

    impl Fixture {
        fn new() -> Self {
            let chain = ChainIdentity::genesis("audit-fixture", StateRoot([1; 32]));
            let base = Head {
                cursor: Cursor {
                    sequence: Sequence(0),
                    epoch: EpochId(10),
                    state_root: StateRoot([2; 32]),
                },
                ledger_root: "ledger".into(),
                irmin_commit: "commit".into(),
                parent_commit: Some("parent".into()),
                index_root: "index".into(),
                index_hash: Some("index-hash".into()),
                txid_hi: -1,
                date: 10,
                message: vec![0, 255],
            };
            let mut head = base.clone();
            head.cursor.sequence = Sequence(1);
            head.cursor.epoch = EpochId(11);
            head.cursor.state_root = StateRoot([3; 32]);
            let epoch = CommittedEpoch {
                chain: chain.clone(),
                cursor: head.cursor,
                parent_root: base.cursor.state_root,
                events: vec![
                    NativeTransaction {
                        txid: 0,
                        hash: "hash-0".into(),
                        proof: ArchiveProof::Exact,
                        identity: vec![1, 255],
                        transaction: vec![2, 0],
                        receipt: Some(vec![3, 4]),
                    },
                    NativeTransaction {
                        txid: 1,
                        hash: "hash-1".into(),
                        proof: ArchiveProof::Signed,
                        identity: vec![5],
                        transaction: vec![6],
                        receipt: None,
                    },
                ],
            };
            let validators = ValidatorSet {
                validators: vec![
                    Validator {
                        address: vec![10],
                        pubkey: vec![11; 32],
                    },
                    Validator {
                        address: vec![12],
                        pubkey: vec![13; 32],
                    },
                ],
                weights: vec![(vec![10], 2.into()), (vec![12], 3.into())],
                n: 2,
                f: 0,
                quorum: 2,
                total_weight: 5.into(),
                quorum_weight: 4.into(),
                weighted: true,
            };
            let sync = RoundSync {
                chain_id: b"audit-fixture".to_vec(),
                epoch_id: 11,
                round: 64,
                step: RoundStep::Prevote,
                request: false,
                validator: vec![10],
                signature: vec![14; 64],
            };
            let mut second_sync = sync.clone();
            second_sync.validator = vec![12];
            second_sync.signature = vec![15; 64];
            Self {
                chain,
                base,
                head,
                epoch,
                certificate: vec![1, 0, 255],
                receipts: vec![vec![2, 3], vec![4]],
                proposal: vec![5, 6],
                reward: RewardSource {
                    reward_proposer_addr: vec![10],
                    reward_proposer_public_key: Some(vec![11; 32]),
                    reward_members: vec![
                        RewardMember {
                            reward_address: vec![10],
                            reward_public_key: Some(vec![11; 32]),
                            reward_weight: 2.into(),
                        },
                        RewardMember {
                            reward_address: vec![12],
                            reward_public_key: None,
                            reward_weight: 3.into(),
                        },
                    ],
                },
                rules: EpochRules {
                    validators,
                    receipts: ReceiptRules {
                        required: true,
                        crypto_active: false,
                        stealth_minimum: 5_000.into(),
                    },
                    relief: Some(Mark {
                        height: 11,
                        round: 64,
                        activate_epoch: 20,
                        source_hash: vec![16; 32],
                        target_hash: vec![17; 32],
                        fingerprint: vec![18; 64],
                        proof: vec![sync, second_sync],
                    }),
                },
            }
        }

        fn key(&self) -> Digest {
            Inputs {
                chain: &self.chain,
                base: &self.base,
                head: &self.head,
                epoch: &self.epoch,
                certificate: &self.certificate,
                receipts: &self.receipts,
                proposal: &self.proposal,
                reward: &self.reward,
                rules: &self.rules,
            }
            .key()
        }
    }

    fn changed(name: &str, mutate: impl FnOnce(&mut Fixture)) {
        let mut fixture = Fixture::new();
        let original = fixture.key();
        assert_eq!(original, fixture.key(), "determinism: {name}");
        mutate(&mut fixture);
        assert_ne!(original, fixture.key(), "unbound input: {name}");
    }

    #[test]
    fn stored_key_binds_every_captured_blob_head_and_resolved_rule() {
        let fixture = Fixture::new();
        let record = || crate::canonical::AuditRecord {
            base: fixture.base.clone(),
            head: fixture.head.clone(),
            certificate: vec![1],
            receipts: vec![2],
            proposal: vec![3],
            reward: vec![4],
            events: vec![5],
        };
        let key = |record: &crate::canonical::AuditRecord, rules: &EpochRules| {
            stored_key(&fixture.chain, record, rules)
        };
        let original = key(&record(), &fixture.rules);
        let mutations: [fn(&mut crate::canonical::AuditRecord); 7] = [
            |r| r.certificate.push(0),
            |r| r.receipts.push(0),
            |r| r.proposal.push(0),
            |r| r.reward.push(0),
            |r| r.events.push(0),
            |r| r.base.message.push(0),
            |r| r.head.message.push(0),
        ];
        for mutate in mutations {
            let mut changed = record();
            mutate(&mut changed);
            assert_ne!(original, key(&changed, &fixture.rules));
        }
        let mut rules = Fixture::new().rules;
        rules.validators.quorum_weight += 1;
        assert_ne!(original, key(&record(), &rules));
        let mut left = record();
        left.events = vec![4, 5];
        left.reward = vec![];
        assert_ne!(original, key(&left, &fixture.rules));
    }

    macro_rules! changes {
        ($($change:expr),+ $(,)?) => { $(changed(stringify!($change), $change);)+ };
    }

    #[test]
    fn all_head_and_outbox_fields_are_bound() {
        changes!(
            |f| f.chain.chain_id.push('x'),
            |f| f.chain.origin = ChainOrigin::Genesis {
                state_root: StateRoot([9; 32])
            },
            |f| f.chain.origin = ChainOrigin::Checkpoint {
                epoch: 0,
                state_root: StateRoot([1; 32])
            },
            |f| f.epoch.chain.chain_id.push('x'),
            |f| f.epoch.chain.origin = ChainOrigin::Checkpoint {
                epoch: 10,
                state_root: StateRoot([1; 32])
            },
            |f| f.epoch.cursor.sequence.0 += 1,
            |f| f.epoch.cursor.epoch.0 += 1,
            |f| f.epoch.cursor.state_root.0[0] ^= 1,
            |f| f.epoch.parent_root.0[0] ^= 1,
            |f| f.epoch.events[0].txid += 1,
            |f| f.epoch.events[0].hash.push('x'),
            |f| f.epoch.events[0].proof = ArchiveProof::Signed,
            |f| f.epoch.events[0].proof = ArchiveProof::SignedOperation,
            |f| f.epoch.events[0].identity.push(0),
            |f| f.epoch.events[0].transaction.push(0),
            |f| f.epoch.events[0].receipt.as_mut().unwrap().push(0),
            |f| f.epoch.events[0].receipt = None,
            |f| f.epoch.events.swap(0, 1),
            |f| {
                f.epoch.events.pop();
            },
            |f| f.certificate.push(0),
            |f| f.receipts[0].push(0),
            |f| f.receipts.swap(0, 1),
            |f| {
                f.receipts.pop();
            },
            |f| f.proposal.push(0),
        );
        let mutations: [fn(&mut Head); 12] = [
            |h| h.cursor.sequence.0 += 1,
            |h| h.cursor.epoch.0 += 1,
            |h| h.cursor.state_root.0[0] ^= 1,
            |h| h.ledger_root.push('x'),
            |h| h.irmin_commit.push('x'),
            |h| h.parent_commit.as_mut().unwrap().push('x'),
            |h| h.index_root.push('x'),
            |h| h.index_hash.as_mut().unwrap().push('x'),
            |h| h.txid_hi += 1,
            |h| h.date += 1,
            |h| h.message.push(0),
            |h| h.parent_commit = None,
        ];
        for mutate in mutations {
            changed("base head", |f| mutate(&mut f.base));
            changed("current head", |f| mutate(&mut f.head));
        }
        changed("base index option", |f| f.base.index_hash = None);
        changed("current index option", |f| f.head.index_hash = None);
    }

    #[test]
    fn all_reward_and_resolved_rule_fields_are_bound() {
        changes!(
            |f| f.reward.reward_proposer_addr.push(0),
            |f| f
                .reward
                .reward_proposer_public_key
                .as_mut()
                .unwrap()
                .push(0),
            |f| f.reward.reward_proposer_public_key = None,
            |f| f.reward.reward_members[0].reward_address.push(0),
            |f| f.reward.reward_members[0]
                .reward_public_key
                .as_mut()
                .unwrap()
                .push(0),
            |f| f.reward.reward_members[0].reward_public_key = None,
            |f| f.reward.reward_members[0].reward_weight += 1,
            |f| f.reward.reward_members.swap(0, 1),
            |f| {
                f.reward.reward_members.pop();
            },
            |f| f.rules.validators.validators[0].address.push(0),
            |f| f.rules.validators.validators[0].pubkey.push(0),
            |f| f.rules.validators.validators.swap(0, 1),
            |f| {
                f.rules.validators.validators.pop();
            },
            |f| f.rules.validators.weights[0].0.push(0),
            |f| f.rules.validators.weights[0].1 += 1,
            |f| f.rules.validators.weights.swap(0, 1),
            |f| f.rules.validators.weights.push((vec![99], 0.into())),
            |f| f.rules.validators.n += 1,
            |f| f.rules.validators.f += 1,
            |f| f.rules.validators.quorum += 1,
            |f| f.rules.validators.total_weight += 1,
            |f| f.rules.validators.quorum_weight += 1,
            |f| f.rules.validators.weighted = false,
            |f| f.rules.receipts.required = false,
            |f| f.rules.receipts.crypto_active = true,
            |f| f.rules.receipts.stealth_minimum += 1,
            |f| f.rules.relief = None,
        );
    }

    #[test]
    fn complete_relief_evidence_is_bound() {
        let mutations: [fn(&mut Mark); 17] = [
            |m| m.height += 1,
            |m| m.round += 1,
            |m| m.activate_epoch += 1,
            |m| m.source_hash.push(0),
            |m| m.target_hash.push(0),
            |m| m.fingerprint.push(0),
            |m| m.proof[0].chain_id.push(0),
            |m| m.proof[0].epoch_id += 1,
            |m| m.proof[0].round += 1,
            |m| m.proof[0].step = RoundStep::Propose,
            |m| m.proof[0].step = RoundStep::Precommit,
            |m| m.proof[0].request = true,
            |m| m.proof[0].validator.push(0),
            |m| m.proof[0].signature.push(0),
            |m| m.proof.swap(0, 1),
            |m| {
                m.proof.pop();
            },
            |m| m.proof.clear(),
        ];
        for mutate in mutations {
            changed("relief field", |f| mutate(f.rules.relief.as_mut().unwrap()));
        }
    }

    #[test]
    fn wire_equivalent_validator_sets_have_distinct_full_keys() {
        let baseline = Fixture::new();
        let encoded = baseline.rules.validators.encode().unwrap();
        let mutations: [fn(&mut ValidatorSet); 7] = [
            |s| s.n += 1,
            |s| s.f += 1,
            |s| s.quorum += 1,
            |s| s.total_weight += 1,
            |s| s.quorum_weight += 1,
            |s| s.weights.swap(0, 1),
            |s| s.weights.push((vec![99], 0.into())),
        ];
        for mutate in mutations {
            let mut modified = Fixture::new();
            mutate(&mut modified.rules.validators);
            assert_eq!(encoded, modified.rules.validators.encode().unwrap());
            assert_ne!(baseline.key(), modified.key());
        }
    }

    #[test]
    fn delimiters_options_signed_integers_and_origins_are_distinct() {
        let mut left = Fixture::new();
        let mut right = Fixture::new();
        left.receipts = vec![b"ab".to_vec(), b"c".to_vec()];
        right.receipts = vec![b"a".to_vec(), b"bc".to_vec()];
        assert_ne!(left.key(), right.key());
        right.receipts = vec![b"abc".to_vec()];
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.certificate = b"ab".to_vec();
        left.proposal = b"c".to_vec();
        right.certificate = b"a".to_vec();
        right.proposal = b"bc".to_vec();
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.epoch.events[0].receipt = None;
        right.epoch.events[0].receipt = Some(vec![]);
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.base.parent_commit = None;
        right.base.parent_commit = Some(String::new());
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.head.parent_commit = None;
        right.head.parent_commit = Some(String::new());
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.base.index_hash = None;
        right.base.index_hash = Some(String::new());
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.head.index_hash = None;
        right.head.index_hash = Some(String::new());
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.reward.reward_proposer_public_key = None;
        right.reward.reward_proposer_public_key = Some(vec![]);
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.reward.reward_members[0].reward_public_key = None;
        right.reward.reward_members[0].reward_public_key = Some(vec![]);
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.rules.receipts.stealth_minimum = (-128).into();
        right.rules.receipts.stealth_minimum = 128.into();
        assert_ne!(left.key(), right.key());
        right.rules.receipts.stealth_minimum = 0.into();
        assert_ne!(left.key(), right.key());
        left = Fixture::new();
        right = Fixture::new();
        left.chain.origin = ChainOrigin::Checkpoint {
            epoch: 10,
            state_root: StateRoot([1; 32]),
        };
        right.chain.origin = ChainOrigin::Checkpoint {
            epoch: 11,
            state_root: StateRoot([1; 32]),
        };
        assert_ne!(left.key(), right.key());
        right.chain.origin = ChainOrigin::Checkpoint {
            epoch: 10,
            state_root: StateRoot([2; 32]),
        };
        assert_ne!(left.key(), right.key());
    }

    #[test]
    fn bounded_cache_retains_prefix_across_repeated_full_scans() {
        let cache = AuditCache::default();
        for _ in 0..2 {
            for number in 1..=(CAPACITY as u64 + 100) {
                cache.insert(Sequence(number), [1; 32]);
            }
            assert_eq!(cache.0.lock().unwrap().len(), CAPACITY);
            for number in 1..=CAPACITY as u64 {
                assert!(cache.contains(Sequence(number), &[1; 32]));
            }
            assert!(!cache.contains(Sequence(CAPACITY as u64 + 1), &[1; 32]));
        }
        cache.insert(Sequence(1), [2; 32]);
        assert!(!cache.contains(Sequence(1), &[1; 32]));
        assert!(cache.contains(Sequence(1), &[2; 32]));
        assert!(!cache.contains(Sequence(2), &[2; 32]));
        assert_eq!(cache.0.lock().unwrap().len(), CAPACITY);
        assert!(!AuditCache::default().contains(Sequence(1), &[2; 32]));
    }

    #[test]
    fn lower_sequence_displaces_highest_and_duplicate_replaces_in_place() {
        let cache = AuditCache::default();
        for number in (2..=(CAPACITY as u64 + 1)).rev() {
            cache.insert(Sequence(number), [3; 32]);
        }
        cache.insert(Sequence(1), [4; 32]);
        assert!(cache.contains(Sequence(1), &[4; 32]));
        assert!(cache.contains(Sequence(CAPACITY as u64), &[3; 32]));
        assert!(!cache.contains(Sequence(CAPACITY as u64 + 1), &[3; 32]));
        cache.insert(Sequence(2), [5; 32]);
        assert!(cache.contains(Sequence(2), &[5; 32]));
        assert!(!cache.contains(Sequence(2), &[3; 32]));
        assert_eq!(cache.0.lock().unwrap().len(), CAPACITY);
    }

    #[test]
    fn poisoned_cache_is_a_miss_and_never_restores_a_success() {
        let cache = AuditCache::default();
        cache.insert(Sequence(1), [6; 32]);
        let _ = std::panic::catch_unwind(|| {
            let _guard = cache.0.lock().unwrap();
            panic!("poison optimization only");
        });
        assert!(!cache.contains(Sequence(1), &[6; 32]));
        cache.insert(Sequence(1), [7; 32]);
        assert!(!cache.contains(Sequence(1), &[7; 32]));
    }
}
