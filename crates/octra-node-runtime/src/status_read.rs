//! Status reads bind launch identity to one immutable, authenticated canonical
//! head. The signer is opaque and never formatted or serialized.
use crate::{
    canonical::{Head, Reader},
    validator_history::CanonicalValidators,
};
use octra_node_protocol::{
    consensus::{
        hash,
        profile::{self, Settings},
    },
    light_rpc::{AccountWitness, Root, ValidatorSetProof},
    rpc::Fault,
    rules::{self, Rule},
    status_rpc::{self, Enrollment, Membership, RuntimeVersion},
    transaction::RuleMode,
    validator::{
        policy,
        registry::{self, Registry},
        set_fold, update,
    },
};
use std::sync::Arc;
type Result<T> = std::result::Result<T, Fault>;
fn unavailable(_: impl std::fmt::Display) -> Fault {
    Fault::new(110, b"service unavailable")
}
fn fault(e: impl std::fmt::Display) -> Fault {
    Fault::new(-32000, e.to_string().as_bytes())
}

#[derive(Clone)]
pub struct Release {
    pub settings: Settings,
    pub crypto_engine: Vec<u8>,
    pub program_trust: Option<Vec<u8>>,
    pub source_commit: Option<Vec<u8>>,
    pub binary_hash: Option<Vec<u8>>,
}
pub type Signer = Arc<dyn Fn(&[u8]) -> Vec<u8> + Send + Sync>;
pub trait Consensus: Send + Sync {
    fn snapshot(
        &self,
    ) -> std::result::Result<
        (
            Option<crate::consensus_driver::Diagnostics>,
            Vec<octra_node_protocol::status_rpc::consensus::Peer>,
        ),
        octra_node_protocol::oce1::Error,
    >;
}
pub struct Service {
    reader: Reader,
    membership: CanonicalValidators,
    address: Vec<u8>,
    public_key: Vec<u8>,
    signer: Signer,
    release: Option<Release>,
    view_public_key: Option<Vec<u8>>,
    control: Option<crate::validator_control::Control>,
    consensus: Option<(
        Arc<dyn Consensus>,
        octra_node_protocol::network::swarm::Swarm,
    )>,
}
impl Service {
    pub fn new(
        reader: Reader,
        membership: CanonicalValidators,
        address: Vec<u8>,
        public_key: Vec<u8>,
        signer: Signer,
        release: Option<Release>,
        view_public_key: Option<Vec<u8>>,
    ) -> Self {
        Self {
            reader,
            membership,
            address,
            public_key,
            signer,
            release,
            view_public_key,
            control: None,
            consensus: None,
        }
    }
    pub fn with_control(mut self, data_dir: &std::path::Path) -> Self {
        self.control = Some(crate::validator_control::Control::new(data_dir));
        self
    }
    pub fn with_consensus(
        mut self,
        consensus: Arc<dyn Consensus>,
        swarm: octra_node_protocol::network::swarm::Swarm,
    ) -> Self {
        self.consensus = Some((consensus, swarm));
        self
    }
    pub fn consensus_peer_states(&self, now: f64) -> Result<Vec<u8>> {
        use octra_node_protocol::status_rpc::consensus::View;
        let (snapshot, peers, diag) = match &self.consensus {
            None => (None, vec![], None),
            Some((consensus, swarm)) => {
                let (snapshot, peers) = consensus.snapshot().map_err(unavailable)?;
                (snapshot, peers, Some(swarm.diagnostics()))
            }
        };
        let agreed = snapshot
            .as_ref()
            .map(|s| s.agreed(now))
            .transpose()
            .map_err(unavailable)?
            .unwrap_or(false);
        View {
            enabled: snapshot.is_some(),
            voting: snapshot.as_ref().is_some_and(|s| s.voting),
            voting_reason: snapshot
                .as_ref()
                .and_then(|s| s.issue.as_ref().map(std::string::String::as_bytes))
                .or(if snapshot.is_none() {
                    Some(b"driver_unavailable")
                } else {
                    None
                }),
            round_state: snapshot.as_ref().map(|s| &s.round),
            round_peers: snapshot
                .as_ref()
                .map(|s| s.round_peers.as_slice())
                .unwrap_or_default(),
            round_votes: snapshot.as_ref().map(|s| &s.votes),
            round_agreed: agreed,
            peers: &peers,
            diagnostics: diag.as_ref(),
        }
        .to_json(now)
        .map_err(unavailable)
    }
    pub fn round_witness(&self, validator: &[u8]) -> Result<Vec<u8>> {
        let value = self
            .consensus
            .as_ref()
            .map(|(c, _)| c.snapshot())
            .transpose()
            .map_err(unavailable)?
            .and_then(|(snapshot, _)| snapshot)
            .and_then(|snapshot| snapshot.witnesses.get(validator).cloned())
            .ok_or_else(|| {
                Fault::new(112, b"not found").string_data(b"round witness unavailable")
            })?;
        value.to_json(validator).map_err(unavailable)
    }
    async fn config(
        &self,
        head: &Head,
    ) -> Result<(
        octra_node_protocol::validator::config::Config,
        Option<Vec<u8>>,
        Option<Vec<u8>>,
        [u8; 32],
    )> {
        let config = self.membership.config(head).await.map_err(unavailable)?;
        let epoch = i64::try_from(head.cursor.epoch.0)
            .map_err(unavailable)?
            .checked_add(1)
            .ok_or_else(|| fault("current epoch exhausted"))?;
        let (trust, runtime) = match &self.release {
            Some(release) => (
                release.program_trust.clone(),
                Some(
                    release
                        .settings
                        .hash(
                            self.reader.chain().chain_id.as_bytes(),
                            epoch,
                            &release.crypto_engine,
                        )
                        .map_err(unavailable)?
                        .to_vec(),
                ),
            ),
            None => (config.program_trust.clone(), config.runtime_profile.clone()),
        };
        let config_hash = hash::config_hash(
            self.reader.chain().chain_id.as_bytes(),
            &config.active,
            config
                .light_scheduled
                .as_ref()
                .map(|(epoch, set)| (*epoch, set)),
            trust.as_ref(),
            runtime.as_ref(),
        )
        .map_err(unavailable)?;
        Ok((config, trust, runtime, config_hash))
    }
    pub async fn signed_record(&self, head: &Head) -> Result<Root> {
        // Retention identity is checked before signing any caller-supplied head.
        if self
            .reader
            .head_at(head.cursor.sequence)
            .await
            .map_err(unavailable)?
            != *head
        {
            return Err(fault("historical head differs"));
        }
        let (_, _, _, config_hash) = self.config(head).await?;
        Root {
            chain_id: self.reader.chain().chain_id.as_bytes().to_vec(),
            validator_addr: self.address.clone(),
            head_epoch: i64::try_from(head.cursor.epoch.0).map_err(unavailable)?,
            state_root: head.cursor.state_root.0.to_vec(),
            ledger_state_root: Some(head.ledger_root.as_bytes().to_vec()),
            epoch_index_root: Some(
                hex::decode(&head.index_root).map_err(|_| fault("invalid optional root"))?,
            ),
            txid_hi: head.txid_hi,
            config_hash: config_hash.to_vec(),
            signature: vec![],
        }
        .sign(|bytes| (self.signer)(bytes))
        .map_err(fault)
    }
    pub async fn signed_root(&self, head: &Head) -> Result<Vec<u8>> {
        use base64::Engine;
        Ok(self.signed_record(head).await?.to_json(
            base64::engine::general_purpose::STANDARD
                .encode(&self.public_key)
                .as_bytes(),
        ))
    }
    pub async fn validator_set_proof(&self, head: &Head) -> Result<Vec<u8>> {
        let (config, trust, runtime, hash) = self.config(head).await?;
        let proof = ValidatorSetProof::of_set(
            self.reader.chain().chain_id.as_bytes().to_vec(),
            hash.to_vec(),
            &config.active,
            config.light_scheduled.as_ref().map(|(e, s)| (*e, s)),
            trust,
            runtime,
        )
        .map_err(unavailable)?;
        if !proof.verify().map_err(unavailable)? {
            return Err(fault("invalid validator set proof"));
        }
        Ok(proof.to_json())
    }
    pub async fn runtime_version(&self, head: &Head) -> Result<Vec<u8>> {
        let release = self
            .release
            .as_ref()
            .ok_or_else(|| unavailable("captured release unavailable"))?;
        let (_, _, runtime, config_hash) = self.config(head).await?;
        let epoch = i64::try_from(head.cursor.epoch.0)
            .map_err(unavailable)?
            .checked_add(1)
            .ok_or_else(|| fault("current epoch exhausted"))?;
        let standard = release
            .settings
            .standard_hash(
                self.reader.chain().chain_id.as_bytes(),
                epoch,
                &release.crypto_engine,
            )
            .map_err(unavailable)?;
        let graph = profile::activation_graph_hash(self.reader.chain().chain_id.as_bytes())
            .map_err(unavailable)?;
        Ok(RuntimeVersion {
            source_commit: release.source_commit.as_deref(),
            binary_hash: release.binary_hash.as_deref(),
            consensus_standard: b"octra_consensus",
            consensus_standard_hash: &standard,
            activation_graph_hash: &graph,
            compat_wire_profile: 16,
            compat_wire_rules_id: b"finalized_rejection_commitment",
            runtime_profile_hash: runtime.as_deref(),
            config_hash: &config_hash,
            chain_id: self.reader.chain().chain_id.as_bytes(),
            validator: &self.address,
        }
        .to_json())
    }
    pub fn validator_view_pubkey(&self) -> Result<Vec<u8>> {
        Ok(status_rpc::validator_view_pubkey(
            self.view_public_key
                .as_deref()
                .ok_or_else(|| unavailable("validator view key unavailable"))?,
            &self.address,
        ))
    }
    pub async fn enrollment(&self, head: &Head, proposal_id: Option<&[u8]>) -> Result<Vec<u8>> {
        use base64::Engine;
        let registry_bytes = self
            .reader
            .read_at_bounded(head, &[b"meta", registry::META_KEY], 16 * 1024 * 1024)
            .await
            .map_err(unavailable)?;
        let registry = registry_bytes
            .as_deref()
            .map(Registry::from_bytes)
            .transpose()
            .map_err(|e| fault(format!("committed validator registry invalid: {e}")))?
            .unwrap_or_default();
        let epoch = i64::try_from(head.cursor.epoch.0).map_err(unavailable)?;
        let chain = self.reader.chain().chain_id.as_bytes();
        let next = epoch
            .checked_add(1)
            .ok_or_else(|| fault("invalid committed validator head"))?;
        let automatic = self
            .release
            .as_ref()
            .is_some_and(|r| r.settings.validators.lifecycle_enabled())
            && rules::at(chain, Rule::SetFold, next) == RuleMode::Active;
        let duty = if automatic {
            let raw = self
                .reader
                .read_at_bounded(head, &[b"meta", set_fold::META_KEY], 16 * 1024 * 1024)
                .await
                .map_err(unavailable)?
                .ok_or_else(|| fault("committed validator duty is unavailable"))?;
            Some(
                set_fold::State::from_bytes(&raw)
                    .map_err(fault)?
                    .receipt(&self.address),
            )
        } else {
            None
        };
        let active = self
            .reader
            .read_at_bounded(head, &[b"meta", update::ACTIVE_KEY], 16 * 1024 * 1024)
            .await
            .map_err(unavailable)?;
        let pending = self
            .reader
            .read_at_bounded(head, &[b"meta", update::PENDING_KEY], 16 * 1024 * 1024)
            .await
            .map_err(unavailable)?;
        let pubkey = base64::engine::general_purpose::STANDARD.encode(&self.public_key);
        let member = Membership::of_values(
            epoch,
            &self.address,
            pubkey.as_bytes(),
            active.as_deref(),
            pending.as_deref(),
        )
        .map_err(fault)?;
        let config_hash = self.ready_config_hash(head).await?;
        let candidate = registry.find(&self.address);
        let withdrawal = candidate
            .filter(|c| c.exit_epoch.is_some())
            .map(|c| {
                policy::withdraw_epoch(
                    rules::at(chain, Rule::Exit, epoch),
                    rules::activation(chain, Rule::Exit).map(|v| v.activation_epoch),
                    c,
                )
            })
            .transpose()
            .map_err(fault)?;
        Enrollment {
            chain_id: chain,
            head_epoch: epoch,
            address: &self.address,
            pubkey: pubkey.as_bytes(),
            candidate,
            state_root: hex::encode(head.cursor.state_root.0).as_bytes(),
            config_hash: hex::encode(config_hash).as_bytes(),
            duty: duty.as_ref(),
            membership: member.as_ref(),
            head_proposal_id: proposal_id,
            ready_exec_active: rules::at(chain, Rule::ReadyExecution, next) == RuleMode::Active,
            withdraw_epoch: withdrawal,
            local_control: self.control.as_ref().map(|control| match candidate {
                None => Ok(None),
                Some(candidate) => control
                    .status(&octra_node_protocol::validator::intent::Identity {
                        chain_id: chain.to_vec(),
                        address: self.address.clone(),
                        pubkey: pubkey.as_bytes().to_vec(),
                        bonded_epoch: candidate.bonded_epoch,
                    })
                    .map_err(octra_node_protocol::consensus::Error::into_bytes),
            }),
        }
        .to_json()
    }
    /// Validator-ready payloads bind the native startup network profile, whose
    /// hash remains distinct from the changing committed membership hash.
    pub async fn ready_config_hash(&self, head: &Head) -> Result<[u8; 32]> {
        let (_, _, _, config_hash) = self.config(head).await?;
        match &self.release {
            None => Ok(config_hash),
            Some(release) => {
                let compatibility = release
                    .settings
                    .compatibility_hash(&release.crypto_engine)
                    .map_err(unavailable)?
                    .to_vec();
                hash::network_hash(
                    self.reader.chain().chain_id.as_bytes(),
                    release.program_trust.as_ref(),
                    Some(&compatibility),
                )
                .map_err(unavailable)
            }
        }
    }
    pub async fn account_proof(
        &self,
        head: &Head,
        address: &[u8],
        max_bytes: usize,
    ) -> Result<Vec<u8>> {
        use base64::Engine;
        if max_bytes == 0 {
            return Err(Fault::response_limit());
        }
        let root = self.signed_root(head).await?;
        let prefix: &[&[u8]] = &[b"accounts", address];
        let maximum = max_bytes
            .saturating_mul(8)
            .saturating_add(1024 * 1024)
            .min(32 * 1024 * 1024);
        let selected = self
            .reader
            .read_tree_at(head, prefix, maximum)
            .await
            .map_err(unavailable)?;
        let mut projection = crate::state_batch::StateBatch::default();
        projection.begin().map_err(fault)?;
        if let Some(tree) = &selected.tree {
            projection.graft(prefix, tree).map_err(fault)?;
        }
        let tree = projection.snapshot();
        let loaded = crate::account_store::load(
            &crate::state_batch::StateBatch::from_snapshot(tree.clone()),
            address,
        )
        .map_err(fault)?;
        let packed = tree
            .get(&[b"accounts", address, b"data"])
            .map(octra_node_protocol::account_pack::data)
            .transpose()
            .map_err(fault)?
            .is_some_and(|v| matches!(v, octra_node_protocol::account_pack::Data::Parts(..)));
        let path: Vec<&[u8]> = if packed {
            vec![b"accounts", address]
        } else {
            vec![b"accounts", address, b"data"]
        };
        let proof = if packed {
            let meta = tree
                .get(&[b"accounts", address, b"cipher", b"meta"])
                .ok_or_else(|| fault("account cipher metadata is missing"))?;
            let meta = octra_node_protocol::account_pack::meta(meta).map_err(fault)?;
            let mut paths = vec![
                vec![b"accounts".as_slice(), address, b"data"],
                vec![b"accounts".as_slice(), address, b"cipher", b"meta"],
            ];
            paths.extend(meta.parts.iter().map(|id| {
                vec![
                    b"accounts".as_slice(),
                    address,
                    b"cipher",
                    b"parts",
                    id.as_slice(),
                ]
            }));
            let paths = paths.iter().map(Vec::as_slice).collect::<Vec<_>>();
            let suffixes = paths.iter().map(|path| &path[2..]).collect::<Vec<_>>();
            match &selected.tree {
                Some(account) => self
                    .reader
                    .prove_tree_at(head, prefix, account, &suffixes, maximum)
                    .await
                    .map_err(unavailable)?,
                None => selected.proof,
            }
        } else {
            match &selected.tree {
                Some(account) => self
                    .reader
                    .prove_tree_at(head, prefix, account, &[&path[2..]], maximum)
                    .await
                    .map_err(unavailable)?,
                None => selected.proof,
            }
        };
        if proof.len() > max_bytes {
            return Err(Fault::response_limit());
        }
        let proof = base64::engine::general_purpose::STANDARD.encode(proof);
        let account = octra_node_protocol::irmin::proof::verify_account(
            head.ledger_root.as_bytes(),
            address,
            proof.as_bytes(),
        )
        .map_err(fault)?;
        if account != loaded {
            return Err(fault("account proof value mismatch"));
        }
        let witness = account
            .map(|a| {
                AccountWitness {
                    chain_id: self.reader.chain().chain_id.as_bytes().to_vec(),
                    address: address.to_vec(),
                    head_epoch: head.cursor.epoch.0 as i64,
                    state_root: head.cursor.state_root.0.to_vec(),
                    balance: a.balance.to_string().into_bytes(),
                    nonce: a.nonce.get(),
                    public_key: a.public_key,
                    encrypted_balance: a.encrypted_balance,
                    decrypt_allowance: a.decrypt_allowance.to_string().into_bytes(),
                    account_hash: vec![],
                }
                .make()
                .map_err(fault)
            })
            .transpose()?;
        octra_node_protocol::light_rpc::account_proof_json(
            root,
            witness.as_ref(),
            &path,
            head.ledger_root.as_bytes(),
            proof.as_bytes(),
            if packed {
                b"irmin_account_tree"
            } else {
                b"irmin_account_path_v1"
            },
        )
    }
}
