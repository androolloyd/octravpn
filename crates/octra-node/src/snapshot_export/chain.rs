//! Build native finalized anchors from retained proofs, including a bounded
//! overlapping-quorum bridge when the transition predates the imported floor.
use super::{
    bootstrap, ensure, manifest, read_optional, Config, Context, Digest, Engine, Host, Node,
    Result, Sha256, STANDARD,
};
use octra_node_protocol::{
    consensus::{hash, policy, qc, CatchupFinality, Finalize, ValidatorSet},
    control_payload::ValidatorUpdate,
    state_sync::anchor::{self, Anchor, Source, Step},
    validator::update::{ACTIVE_KEY, PENDING_KEY},
};
use octra_node_runtime::canonical::Head;
use std::collections::BTreeSet;

#[derive(Clone)]
struct Chain {
    steps: Vec<Step>,
    set: ValidatorSet,
    epoch: i64,
}
fn same(left: &ValidatorSet, right: &ValidatorSet) -> Result<bool> {
    Ok(hash::validator_set_hash(left)? == hash::validator_set_hash(right)?)
}
fn update(raw: &[u8], chain: &[u8], head: i64) -> Result<(ValidatorUpdate, ValidatorSet)> {
    let update = ValidatorUpdate::parse(Some(raw))?;
    ensure!(
        update.to_bytes() == raw,
        "state sync validator update is not exact"
    );
    let raw_set = update.validator_set()?;
    let set = if policy::quorum_rule(chain, head) == policy::Rule::Stake {
        raw_set
    } else {
        raw_set.for_epoch(chain, update.activate_epoch)?
    };
    Ok((update, set))
}
pub(super) async fn finality<A: Host>(
    node: &Node<A>,
    authority: &bootstrap::Authority,
    epoch: u64,
) -> Result<Option<CatchupFinality>> {
    let Some(sequence) = node.store.sequence_for_epoch(epoch).await? else {
        return Ok(None);
    };
    if epoch == node.store.anchor().cursor.epoch.0 {
        let Some(certificate) = node.store.checkpoint_certificate().await? else {
            return Ok(None);
        };
        let verified = authority.trust().verify_persisted(&certificate)?;
        let anchor = verified
            .anchor()
            .context("snapshot floor finality missing")?
            .anchor();
        return Ok(Some(CatchupFinality {
            finalize: anchor.finalize.clone(),
            validator_set: anchor.validator_set.clone(),
        }));
    }
    Ok(Some(
        node.publisher
            .record_bounded(
                sequence,
                octra_node_protocol::state_sync::range_part::FULL_MAX,
            )
            .await?
            .context("snapshot finality record exceeds export budget")?
            .finality
            .context("snapshot retained finality missing")?,
    ))
}
async fn proof<A: Host>(
    node: &Node<A>,
    epoch: i64,
    raw: &[u8],
    source: Source,
    finalize: Finalize,
) -> Result<Step> {
    let head = node
        .store
        .reader()
        .head_for_epoch(u64::try_from(epoch)?)
        .await?;
    let state = node.store.reader().snapshot_at(&head).await?;
    let key = match &source {
        Source::Pending | Source::Relief(_) => PENDING_KEY,
        Source::Active => ACTIVE_KEY,
    };
    ensure!(
        state.get(&[b"meta", key]) == Some(raw),
        "state sync validator transition proof value differs"
    );
    Ok(Step {
        source,
        finalize,
        ledger_state_root: head.ledger_root.into_bytes(),
        epoch_index_root: head.index_root.into_bytes(),
        update: raw.to_vec(),
        proof: STANDARD
            .encode(state.read_proof(&[b"meta", key], false)?)
            .into_bytes(),
    })
}
async fn transition<A: Host>(
    node: &Node<A>,
    authority: &bootstrap::Authority,
    raw: &[u8],
    update: &ValidatorUpdate,
) -> Result<Option<Step>> {
    let epoch = update
        .activate_epoch
        .checked_sub(1)
        .context("transition epoch underflow")?;
    ensure!(
        epoch >= 0,
        "state sync validator transition epoch is invalid"
    );
    let Some(record) = finality(node, authority, u64::try_from(epoch)?).await? else {
        return Ok(None);
    };
    Ok(Some(
        proof(node, epoch, raw, Source::Pending, record.finalize).await?,
    ))
}
async fn bridge<A: Host>(
    node: &Node<A>,
    authority: &bootstrap::Authority,
    head: i64,
    before: i64,
    prior: &Chain,
    raw: &[u8],
    update: &ValidatorUpdate,
) -> Result<Option<Step>> {
    let Some(after) = prior.epoch.checked_add(1) else {
        return Ok(None);
    };
    let floor = after
        .max(update.activate_epoch)
        .max(head.saturating_sub(4095))
        .max(i64::try_from(node.store.anchor().cursor.epoch.0)?);
    let ceiling = (before - 1).min(head - 1);
    for epoch in (floor..=ceiling).rev() {
        let Some(record) = finality(node, authority, u64::try_from(epoch)?).await? else {
            continue;
        };
        // The original retained record was reauthenticated by Publisher above;
        // the restricted QC must independently meet the preceding set's quorum.
        if !prior.set.is_author(
            &record.finalize.chain_id,
            epoch,
            &record.finalize.header.creator_addr,
        ) {
            continue;
        }
        let mut restricted = record.finalize;
        restricted
            .precommits
            .retain(|vote| prior.set.is_validator(&vote.validator));
        let effective = prior.set.for_epoch(&restricted.chain_id, epoch)?;
        let signers = restricted
            .precommits
            .iter()
            .map(|vote| vote.validator.clone())
            .collect::<Vec<_>>();
        if !effective.has_quorum(&signers)
            || qc::validate_finalize(
                &restricted.chain_id,
                &prior.set,
                &restricted,
                qc::FinalityMode::StrictPersisted,
            )
            .is_err()
        {
            continue;
        }
        let retained = node
            .store
            .reader()
            .head_for_epoch(u64::try_from(epoch)?)
            .await?;
        let state = node.store.reader().snapshot_at(&retained).await?;
        if state.get(&[b"meta", ACTIVE_KEY]) != Some(raw) {
            continue;
        }
        return Ok(Some(
            proof(node, epoch, raw, Source::Active, restricted).await?,
        ));
    }
    Ok(None)
}
async fn walk<A: Host>(
    node: &Node<A>,
    authority: &bootstrap::Authority,
    head: &Head,
    active: &ValidatorSet,
    stop: Chain,
    base: &Chain,
) -> Result<Vec<Step>> {
    let chain_id = authority.network().identity.chain_id.as_bytes();
    let epoch = i64::try_from(head.cursor.epoch.0)?;
    let state = node.store.reader().snapshot_at(head).await?;
    let mut raw = state
        .get(&[b"meta", ACTIVE_KEY])
        .context("state sync active validator update is missing")?
        .to_vec();
    let mut seen = BTreeSet::new();
    let mut before = epoch;
    let mut pending = Vec::new();
    let mut prior = loop {
        ensure!(
            seen.len() < 1024,
            "state sync validator transition chain is too long"
        );
        ensure!(
            seen.insert(Sha256::digest(&raw).to_vec()),
            "state sync validator transition chain has a cycle"
        );
        let (item, next_set) = update(&raw, chain_id, epoch)?;
        if same(&next_set, &stop.set)? {
            break stop.clone();
        }
        let step = transition(node, authority, &raw, &item).await?;
        if step.is_none() {
            if let Some(step) = bridge(node, authority, epoch, before, &stop, &raw, &item).await? {
                pending.push((raw, item, next_set, Some(step), before));
                break stop.clone();
            }
        }
        let previous_epoch = item
            .activate_epoch
            .checked_sub(1)
            .context("transition epoch underflow")?;
        ensure!(
            previous_epoch >= 0 && previous_epoch < before,
            "state sync validator transition order differs"
        );
        let previous = node
            .store
            .reader()
            .head_for_epoch_opt(u64::try_from(previous_epoch)?)
            .await?;
        let previous_raw = match previous {
            Some(head) => node
                .store
                .reader()
                .snapshot_at(&head)
                .await?
                .get(&[b"meta", ACTIVE_KEY])
                .map(<[u8]>::to_vec),
            None => None,
        };
        pending.push((raw, item, next_set, step, before));
        if let Some(value) = previous_raw {
            raw = value;
            before = previous_epoch;
        } else {
            ensure!(
                same(&base.set, &stop.set)?,
                "state sync stored validator chain does not join history"
            );
            break stop.clone();
        }
    };
    for (raw, item, next_set, step, before) in pending.into_iter().rev() {
        if same(&prior.set, &next_set)? {
            continue;
        }
        let step = match step {
            Some(step) => step,
            None => bridge(node, authority, epoch, before, &prior, &raw, &item)
                .await?
                .context("state sync validator bridge is unavailable")?,
        };
        prior.epoch = if policy::quorum_rule(chain_id, epoch) == policy::Rule::Stake {
            step.finalize.epoch_id
        } else {
            item.activate_epoch.max(step.finalize.epoch_id)
        };
        prior.steps.push(step);
        prior.set = next_set;
    }
    ensure!(
        same(
            &if policy::quorum_rule(chain_id, epoch) == policy::Rule::Stake {
                prior.set.for_epoch(chain_id, epoch)?
            } else {
                prior.set.clone()
            },
            active
        )?,
        "state sync active validator set differs from history"
    );
    ensure!(
        prior.steps.len() <= 1024,
        "state sync validator transition chain is too long"
    );
    Ok(prior.steps)
}
async fn build_plain<A: Host>(node: &Node<A>, config: &Config, head: &Head) -> Result<Anchor> {
    let authority = bootstrap::Authority::new(config.network.clone())?;
    let record = finality(node, &authority, head.cursor.epoch.0)
        .await?
        .context("state sync checkpoint finality is missing")?;
    let base = Chain {
        steps: Vec::new(),
        set: anchor::raw_validator_set(authority.trust().validators)?,
        epoch: -1,
    };
    let mut stops = Vec::new();
    if let Some(raw) = node.store.checkpoint_certificate().await? {
        let verified = authority.trust().verify_persisted(&raw)?;
        let checked = verified
            .anchor()
            .context("snapshot floor finality missing")?;
        let value = checked.anchor();
        let (epoch, mut set) =
            if policy::quorum_rule(&value.finalize.chain_id, head.cursor.epoch.0 as i64)
                == policy::Rule::Stake
            {
                let (epoch, set) = checked.transition_base();
                (epoch, set.clone())
            } else {
                (value.finalize.epoch_id, value.validator_set.clone())
            };
        if set
            .authors
            .as_ref()
            .is_some_and(|(epoch, _)| *epoch != head.cursor.epoch.0 as i64)
        {
            set.authors = None;
        }
        stops.push(Chain {
            steps: value.steps.clone(),
            set,
            epoch,
        });
    }
    let path = config.certificate.clone();
    let raw = tokio::task::spawn_blocking(move || read_optional(&path, manifest::MANIFEST_LIMIT))
        .await??;
    if let Some(raw) = raw {
        // Invalid old publication is only a cache miss; it cannot supply trust.
        if let Ok(verified) = authority.trust().verify_persisted(&raw) {
            if let Some(value) = verified.anchor() {
                let checked = value;
                let value = checked.anchor();
                if value.finalize.epoch_id <= record.finalize.epoch_id {
                    let (epoch, mut set) = if policy::quorum_rule(
                        &value.finalize.chain_id,
                        head.cursor.epoch.0 as i64,
                    ) == policy::Rule::Stake
                    {
                        let (epoch, set) = checked.transition_base();
                        (epoch, set.clone())
                    } else {
                        (value.finalize.epoch_id, value.validator_set.clone())
                    };
                    if set
                        .authors
                        .as_ref()
                        .is_some_and(|(epoch, _)| *epoch != head.cursor.epoch.0 as i64)
                    {
                        set.authors = None;
                    }
                    stops.push(Chain {
                        steps: value.steps.clone(),
                        set,
                        epoch,
                    });
                }
            }
        }
    }
    stops.sort_by_key(|chain| std::cmp::Reverse(chain.epoch));
    stops.push(base.clone());
    let mut steps = if same(&base.set, &record.validator_set)? {
        Some(Vec::new())
    } else {
        None
    };
    let mut errors = Vec::new();
    for stop in stops {
        if steps.is_some() {
            break;
        }
        // An imported checkpoint can contain a relief proof whose parent is
        // below our local history floor. Reauthenticate that exact path against
        // the current finality before requiring an additional transition.
        let retained = Anchor {
            steps: stop.steps.clone(),
            finalize: record.finalize.clone(),
            validator_set: record.validator_set.clone(),
        };
        if let Ok(retained) = retained.compact(authority.trust().validators) {
            steps = Some(retained.steps);
            break;
        }
        match walk(node, &authority, head, &record.validator_set, stop, &base).await {
            Ok(value) => steps = Some(value),
            Err(error) => errors.push(error.to_string()),
        }
    }
    let anchor = Anchor {
        steps: steps.with_context(|| {
            format!(
                "state sync validator chain unavailable: {}",
                errors.join("; ")
            )
        })?,
        finalize: record.finalize,
        validator_set: record.validator_set,
    };
    anchor
        .compact(authority.trust().validators)
        .map_err(Into::into)
}

pub(super) async fn build<A: Host>(node: &Node<A>, config: &Config, head: &Head) -> Result<Anchor> {
    // Relief reconstruction carries several authenticated sets and finalities
    // across reads. Keep that working future off every export caller's stack.
    Box::pin(async {
        use octra_node_protocol::consensus::relief;
        use octra_node_runtime::canonical::ReliefSource;
        let epoch = i64::try_from(head.cursor.epoch.0)?;
        let authority = bootstrap::Authority::new(config.network.clone())?;
        let chain_id = authority.network().identity.chain_id.as_bytes();
        if epoch <= 0 || policy::quorum_rule(chain_id, epoch) != policy::Rule::Stake {
            return build_plain(node, config, head).await;
        }
        let Some(previous) = node
            .store
            .reader()
            .head_for_epoch_opt(head.cursor.epoch.0 - 1)
            .await?
        else {
            return build_plain(node, config, head).await;
        };
        let ReliefSource::Committed(Some(mark)) =
            node.store.reader().relief_after(&previous).await?
        else {
            return build_plain(node, config, head).await;
        };
        if epoch >= mark.activate_epoch {
            return build_plain(node, config, head).await;
        }
        let parent_epoch = mark
            .height
            .checked_sub(1)
            .context("state sync relief epoch underflow")?;
        let Some(parent_head) = node
            .store
            .reader()
            .head_for_epoch_opt(u64::try_from(parent_epoch)?)
            .await?
        else {
            // Canonical history is immutable after import. Only the import floor
            // can hide this parent; the authenticated checkpoint carries its proof.
            return build_plain(node, config, head).await;
        };
        let parent = build_plain(node, config, &parent_head).await?;
        let checked = anchor::verify_path(authority.trust().validators, &parent.encode()?)?;
        let current = checked
            .transition_base()
            .1
            .for_epoch(chain_id, mark.height)?;
        let state = node.store.reader().snapshot_at(&parent_head).await?;
        let raw = state
            .get(&[b"meta", PENDING_KEY])
            .context("state sync relief plan is missing")?;
        let (plan, target) = update(raw, chain_id, epoch)?;
        let selected = relief::Plan {
            chain_id,
            height: epoch,
            current: &current,
            activate_epoch: plan.activate_epoch,
            target: &target,
            fingerprint: plan.fingerprint.as_bytes(),
        }
        .restore_with_authors(&mark)?
        .context("state sync relief is expired")?;
        let record = finality(node, &authority, head.cursor.epoch.0)
            .await?
            .context("state sync checkpoint finality is missing")?;
        ensure!(
            same(&selected, &record.validator_set)?,
            "state sync relief set differs"
        );
        let mut steps = parent.steps;
        steps.push(
            proof(
                node,
                parent_epoch,
                raw,
                Source::Relief(mark),
                parent.finalize,
            )
            .await?,
        );
        Anchor {
            steps,
            finalize: record.finalize,
            validator_set: record.validator_set,
        }
        .compact(authority.trust().validators)
        .map_err(Into::into)
    })
    .await
}
