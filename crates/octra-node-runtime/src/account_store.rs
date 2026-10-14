//! Native account persistence over the canonical state batch. Activated account
//! packing uses the same ciphertext parts and identifiers as Store_irmin.
use crate::state_batch::StateBatch;
use octra_node_protocol::{
    account_pack::{self, Data},
    state::{Account, Ledger},
    transaction::{Error, RuleMode},
};
fn operational(error: impl std::fmt::Display) -> Error {
    Error(error.to_string())
}
/// Load every account from the same captured tree. Loading just transaction
/// participants would lose the native public supply and existing reward accounts.
pub fn ledger(store: &StateBatch) -> Result<Ledger, Error> {
    let snapshot = store.snapshot();
    let mut accounts = std::collections::BTreeMap::new();
    // Native fold prepends its rows, then parses the resulting list.
    for address in snapshot
        .child_names(&[b"accounts"])
        .rev()
        .filter(|a| !a.is_empty())
    {
        if let Some(account) = load(store, address)? {
            accounts.insert(address.to_vec(), account);
        }
    }
    Ledger::from_accounts(accounts)
}
pub fn load(store: &StateBatch, address: &[u8]) -> Result<Option<Account>, Error> {
    let Some(raw) = store.get(&[b"accounts", address, b"data"]) else {
        return Ok(None);
    };
    let data = account_pack::data(raw).map_err(|e| Error(format!("account data rejected: {e}")))?;
    if let Data::Old(account) = data {
        return Ok(Some(account));
    }
    let fail = |e: Error| Error(format!("account storage rejected: {e}"));
    if !store.contains_tree(&[b"accounts", address, b"cipher"]) {
        return Err(fail(Error("account cipher storage is missing".into())));
    }
    let meta = store
        .get(&[b"accounts", address, b"cipher", b"meta"])
        .ok_or_else(|| fail(Error("account cipher metadata is missing".into())))?;
    let parsed = account_pack::meta(meta).map_err(fail)?;
    // Native account_from loads all referenced parts before checking that the
    // metadata key agrees with account data. Preserve that refusal precedence.
    for id in &parsed.parts {
        if store
            .get(&[b"accounts", address, b"cipher", b"parts", id])
            .is_none()
        {
            return Err(fail(Error("account cipher part is missing".into())));
        }
    }
    account_pack::read(data, Some(meta), |id| {
        store
            .get(&[b"accounts", address, b"cipher", b"parts", id])
            .map(<[u8]>::to_vec)
    })
    .map(Some)
    .map_err(fail)
}
pub fn set(
    store: &mut StateBatch,
    address: &[u8],
    account: &Account,
    mode: RuleMode,
) -> Result<(), Error> {
    let head = if mode == RuleMode::Active {
        account_pack::head(account)
    } else {
        None
    };
    let Some((data, next_id)) = head else {
        if store.contains_tree(&[b"accounts", address, b"cipher"]) {
            store
                .remove(&[b"accounts", address, b"cipher"])
                .map_err(operational)?;
        }
        return store
            .set(&[b"accounts", address, b"data"], account.to_json_bytes())
            .map_err(operational);
    };
    let prior = store
        .get(&[b"accounts", address, b"data"])
        .map(account_pack::data)
        .transpose()
        .map_err(|e| Error(format!("account data rejected: {e}")))?;
    if matches!(prior,Some(Data::Parts(_,ref id))if id==&next_id) {
        let valid = store.contains_tree(&[b"accounts", address, b"cipher"])
            && store
                .get(&[b"accounts", address, b"cipher", b"meta"])
                .and_then(|v| account_pack::meta(v).ok())
                .is_some_and(|meta| meta.id == next_id);
        if valid {
            return store
                .set(&[b"accounts", address, b"data"], data)
                .map_err(operational);
        }
        return Err(Error("account cipher reference is invalid".into()));
    }
    let image = account_pack::image(account);
    store
        .remove(&[b"accounts", address, b"cipher"])
        .map_err(operational)?;
    let mut seen = std::collections::BTreeMap::new();
    for part in image.parts {
        match seen.get(&part.id) {
            Some(raw) if raw == &part.raw => continue,
            Some(_) => return Err(Error("account cipher part collision".into())),
            None => (),
        }
        store
            .set(
                &[b"accounts", address, b"cipher", b"parts", &part.id],
                part.raw.clone(),
            )
            .map_err(operational)?;
        seen.insert(part.id, part.raw);
    }
    if let Some(meta) = image.meta {
        store
            .set(&[b"accounts", address, b"cipher", b"meta"], meta)
            .map_err(operational)?;
    }
    store
        .set(&[b"accounts", address, b"data"], image.data)
        .map_err(operational)
}
/// Account flush is atomic in the speculative tree. On storage refusal, retain
/// the dirty ledger and restore the old tree so the host can safely abort/retry.
/// A successful flush is still unpublished until the canonical host commits.
pub fn flush_dirty(
    ledger: &mut Ledger,
    store: &mut StateBatch,
    mode: RuleMode,
) -> Result<(), Error> {
    if ledger.dirty_addresses().is_empty() {
        return Ok(());
    }
    let saved = store.save().map_err(operational)?;
    for address in ledger.dirty_addresses() {
        if let Some(account) = ledger.account(address) {
            if let Err(error) = set(store, address, account, mode) {
                store.restore(saved).map_err(operational)?;
                return Err(error);
            }
        }
    }
    ledger.acknowledge_account_flush();
    Ok(())
}
