//! Build native finalized anchors from retained proofs, including a bounded
//! overlapping-quorum bridge when the transition predates the imported floor.
use super::{
    bootstrap, ensure, manifest, read_optional, Config, Context, Digest, Engine, Host, Node,
    Result, Sha256, STANDARD,
};
use octra_node_protocol::{
    consensus::{hash, qc, CatchupFinality, Finalize, ValidatorSet},
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
fn update(raw: &[u8], chain: &[u8]) -> Result<(ValidatorUpdate, ValidatorSet)> {
    let update = ValidatorUpdate::parse(Some(raw))?;
    ensure!(
        update.to_bytes() == raw,
        "state sync validator update is not exact"
    );
    let set = update
        .validator_set()?
        .for_epoch(chain, update.activate_epoch)?;
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
    let key = match source {
        Source::Pending => PENDING_KEY,
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
        if !prior.set.is_validator(&record.finalize.header.creator_addr) {
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
        let (item, next_set) = update(&raw, chain_id)?;
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
        prior.epoch = item.activate_epoch.max(step.finalize.epoch_id);
        prior.steps.push(step);
        prior.set = next_set;
    }
    ensure!(
        same(&prior.set, active)?,
        "state sync active validator set differs from history"
    );
    ensure!(
        prior.steps.len() <= 1024,
        "state sync validator transition chain is too long"
    );
    Ok(prior.steps)
}
pub(super) async fn build<A: Host>(node: &Node<A>, config: &Config, head: &Head) -> Result<Anchor> {
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
        let value = verified
            .anchor()
            .context("snapshot floor finality missing")?
            .anchor();
        stops.push(Chain {
            steps: value.steps.clone(),
            set: value.validator_set.clone(),
            epoch: value.finalize.epoch_id,
        });
    }
    let path = config.certificate.clone();
    let raw = tokio::task::spawn_blocking(move || read_optional(&path, manifest::MANIFEST_LIMIT))
        .await??;
    if let Some(raw) = raw {
        // Invalid old publication is only a cache miss; it cannot supply trust.
        if let Ok(verified) = authority.trust().verify_persisted(&raw) {
            if let Some(value) = verified.anchor() {
                let value = value.anchor();
                if value.finalize.epoch_id <= record.finalize.epoch_id {
                    stops.push(Chain {
                        steps: value.steps.clone(),
                        set: value.validator_set.clone(),
                        epoch: value.finalize.epoch_id,
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
