//! Auxiliary history locators. Returned transactions are rechecked against the
//! native epoch commitment; rejection consumers must authenticate their epoch's
//! finality record before exposing its consensus receipt.
use super::{
    epoch_records, error, retained_head, CanonicalStore, Digest, Head, NativeTransaction, Reader,
    Result, Row, Sha256, Sqlite, Transaction,
};
use octra_node_protocol::{
    native_json::{Document, Value},
    transaction::{is_valid_address, OpType, Transaction as Native},
    transaction_outcome::{self, Rejection},
};

#[derive(Clone, Default)]
pub struct HistoryQuery {
    pub address: Option<Vec<u8>>,
    pub epoch: Option<i64>,
    pub hash: Option<Vec<u8>>,
    pub token_only: bool,
    pub ascending: bool,
}
pub struct HistoryPage<T = (Head, NativeTransaction)> {
    pub total: u64,
    pub incoming: u64,
    pub outgoing: u64,
    pub rows: Vec<T>,
}
pub struct RejectionRecord {
    pub head: Head,
    pub rejection: Rejection,
    /// A rebuilt index cannot reconstruct the original local observation time.
    pub observed_at: Option<f64>,
}
pub struct RejectionPage<T = RejectionRecord> {
    pub total: u64,
    pub rows: Vec<T>,
}
/// Local projection limits do not constrain accepted transactions or native
/// pagination settings. The caller chooses the exact public row representation.
#[derive(Debug)]
pub enum HistoryReadError<E> {
    Canonical(super::super::Error),
    Projection(E),
    ResponseLimit,
}
impl<E> From<super::super::Error> for HistoryReadError<E> {
    fn from(value: super::super::Error) -> Self {
        Self::Canonical(value)
    }
}
fn raw_error(error: HistoryReadError<super::super::Error>) -> super::super::Error {
    match error {
        HistoryReadError::Canonical(error) | HistoryReadError::Projection(error) => error,
        HistoryReadError::ResponseLimit => super::super::error("history read exceeds byte limit"),
    }
}

pub(super) async fn schema(tx: &mut Transaction<'_, Sqlite>) -> Result<()> {
    for query in [
        "CREATE TABLE IF NOT EXISTS node_history_transactions(txid INTEGER PRIMARY KEY REFERENCES node_transactions(txid),sender BLOB NOT NULL,target BLOB NOT NULL,recipient BLOB,extra BLOB,token INTEGER NOT NULL)",
        "CREATE INDEX IF NOT EXISTS node_history_sender ON node_history_transactions(sender,txid)",
        "CREATE INDEX IF NOT EXISTS node_history_target ON node_history_transactions(target,txid)",
        "CREATE INDEX IF NOT EXISTS node_history_extra ON node_history_transactions(extra,txid)",
        "CREATE TABLE IF NOT EXISTS node_history_rejections(hash TEXT NOT NULL,sequence INTEGER NOT NULL REFERENCES node_epochs(sequence),position INTEGER NOT NULL,sender BLOB NOT NULL,target BLOB NOT NULL,receipt BLOB NOT NULL,digest BLOB NOT NULL,observed_at REAL,PRIMARY KEY(hash,sequence,position))",
        "CREATE INDEX IF NOT EXISTS node_rejection_sender ON node_history_rejections(sender,sequence)",
        "CREATE INDEX IF NOT EXISTS node_rejection_target ON node_history_rejections(target,sequence)",
        "CREATE TABLE IF NOT EXISTS node_history_epochs(sequence INTEGER PRIMARY KEY REFERENCES node_epochs(sequence),outcomes INTEGER NOT NULL)",
        "CREATE TABLE IF NOT EXISTS node_history_index(id INTEGER PRIMARY KEY CHECK(id=0),version INTEGER NOT NULL,sequence INTEGER NOT NULL REFERENCES node_epochs(sequence))",
        "INSERT OR IGNORE INTO node_history_index VALUES(0,1,0)",
    ] {
        sqlx::query(query).execute(&mut **tx).await.map_err(error)?;
    }
    Ok(())
}
fn recipient(tx: &Native) -> Option<Vec<u8>> {
    if tx.op_type != OpType::ContractCall || tx.encrypted_data.as_ref().is_none_or(Vec::is_empty) {
        return None;
    }
    let doc = Document::parse(tx.message.as_deref()?).ok()?;
    let Value::List(values) = doc.root() else {
        return None;
    };
    match doc.get(*values.first()?) {
        Some(Value::String(value)) if is_valid_address(value) => Some(value.clone()),
        _ => None,
    }
}
pub(super) async fn retain_confirmed(
    tx: &mut Transaction<'_, Sqlite>,
    records: &[NativeTransaction],
) -> Result<()> {
    for record in records {
        let parsed = Native::from_document(&Document::parse(&record.transaction).map_err(error)?)
            .map_err(error)?;
        let recipient = recipient(&parsed);
        let extra = recipient
            .as_ref()
            .filter(|value| **value != parsed.from && **value != parsed.to);
        let token = parsed.op_type == OpType::ContractCall
            && parsed.encrypted_data.as_deref() == Some(b"transfer");
        sqlx::query("INSERT OR REPLACE INTO node_history_transactions VALUES(?,?,?,?,?,?)")
            .bind(record.txid)
            .bind(&parsed.from)
            .bind(&parsed.to)
            .bind(recipient.as_deref())
            .bind(extra.map(Vec::as_slice))
            .bind(token)
            .execute(&mut **tx)
            .await
            .map_err(error)?;
    }
    Ok(())
}
async fn outcomes(
    tx: &mut Transaction<'_, Sqlite>,
    head: &Head,
    receipts: &[Vec<u8>],
    observed_at: Option<f64>,
) -> Result<()> {
    let sequence = i64::try_from(head.cursor.sequence.0).map_err(error)?;
    let partition = transaction_outcome::split(receipts, false).map_err(error)?;
    for rejection in partition.rejections {
        let hash = hex::encode(rejection.tx.hash().map_err(error)?);
        let raw = transaction_outcome::encode_rejection(&rejection).map_err(error)?;
        sqlx::query("INSERT INTO node_history_rejections VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(hash,sequence,position) DO UPDATE SET receipt=excluded.receipt,digest=excluded.digest,observed_at=coalesce(node_history_rejections.observed_at,excluded.observed_at)")
            .bind(hash).bind(sequence).bind(rejection.position).bind(&rejection.tx.from).bind(&rejection.tx.to)
            .bind(&raw).bind(Sha256::digest(&raw).to_vec()).bind(observed_at).execute(&mut **tx).await.map_err(error)?;
    }
    sqlx::query("INSERT OR REPLACE INTO node_history_epochs VALUES(?,1)")
        .bind(sequence)
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    Ok(())
}
pub(in crate::canonical) async fn retain_outcomes(
    tx: &mut Transaction<'_, Sqlite>,
    head: &Head,
    receipts: &[Vec<u8>],
) -> Result<()> {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(error)?
        .as_secs_f64();
    outcomes(tx, head, receipts, Some(now)).await?;
    let sequence = i64::try_from(head.cursor.sequence.0).map_err(error)?;
    let changed = sqlx::query(
        "UPDATE node_history_index SET sequence=? WHERE id=0 AND version=1 AND sequence=?",
    )
    .bind(sequence)
    .bind(sequence - 1)
    .execute(&mut **tx)
    .await
    .map_err(error)?;
    if changed.rows_affected() != 1 {
        return Err(error("history index is behind canonical publication"));
    }
    Ok(())
}
pub(super) async fn recover(
    store: &CanonicalStore,
    tx: &mut Transaction<'_, Sqlite>,
    head: i64,
) -> Result<()> {
    let mut after: i64 =
        sqlx::query_scalar("SELECT sequence FROM node_history_index WHERE id=0 AND version=1")
            .fetch_one(&mut **tx)
            .await
            .map_err(error)?;
    if after < 0 || after > head {
        return Err(error("invalid history index boundary"));
    }
    let has_receipts:bool=sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='node_consensus_receipts')")
        .fetch_one(&mut **tx).await.map_err(error)?;
    while after < head {
        let sequence = after + 1;
        let parent = retained_head(tx, after).await?;
        let archived = retained_head(tx, sequence).await?;
        let row=sqlx::query("SELECT sequence AS event_sequence,epoch AS event_epoch,parent_root AS event_parent,root AS event_root,events FROM exex_committed_epoch WHERE chain_id=? AND genesis=? AND sequence=?")
            .bind(&store.chain.chain_id).bind(store.chain.namespace_key().as_slice()).bind(format!("{sequence:016x}"))
            .fetch_one(&mut **tx).await.map_err(error)?;
        let records = epoch_records(&row, &parent, &archived)?;
        retain_confirmed(tx, &records).await?;
        let receipts: Option<Vec<u8>> = if has_receipts {
            sqlx::query_scalar("SELECT receipts FROM node_consensus_receipts WHERE sequence=?")
                .bind(sequence)
                .fetch_optional(&mut **tx)
                .await
                .map_err(error)?
        } else {
            None
        };
        if let Some(raw) = receipts {
            let receipts: Vec<Vec<u8>> = serde_json::from_slice(&raw).map_err(error)?;
            outcomes(tx, &archived, &receipts, None).await?;
        } else {
            sqlx::query("INSERT OR REPLACE INTO node_history_epochs VALUES(?,0)")
                .bind(sequence)
                .execute(&mut **tx)
                .await
                .map_err(error)?;
        }
        after = sequence;
    }
    sqlx::query("UPDATE node_history_index SET sequence=? WHERE id=0 AND version=1")
        .bind(after)
        .execute(&mut **tx)
        .await
        .map_err(error)?;
    Ok(())
}

async fn read_prefix(
    reader: &Reader,
    tx: &mut Transaction<'_, Sqlite>,
    head: &Head,
    complete: bool,
) -> Result<i64> {
    let sequence = i64::try_from(head.cursor.sequence.0).map_err(error)?;
    if retained_head(tx, sequence).await? != *head {
        return Err(error("history read head differs"));
    }
    let indexed: i64 =
        sqlx::query_scalar("SELECT sequence FROM node_history_index WHERE id=0 AND version=1")
            .fetch_one(&mut **tx)
            .await
            .map_err(error)?;
    if indexed < sequence {
        return Err(error("history index is behind the published snapshot"));
    }
    if complete && reader.anchor().epoch.0 != 0 {
        return Err(error("history before snapshot checkpoint is unavailable"));
    }
    Ok(sequence)
}
impl Reader {
    /// Exact counts require history from genesis. An epoch query beyond the
    /// authenticated checkpoint can still serve its retained complete epoch.
    pub async fn transactions(
        &self,
        head: &Head,
        query: &HistoryQuery,
        limit: usize,
        offset: u64,
        max_bytes: usize,
    ) -> Result<HistoryPage> {
        self.transactions_projected(head, query, limit, offset, max_bytes, |head, record| {
            let size = record.transaction.len();
            std::future::ready(Ok::<_, super::super::Error>(((head, record), size)))
        })
        .await
        .map_err(raw_error)
    }
    /// Materialize only bounded locator batches and one authenticated native
    /// epoch at a time. Budget the caller's projected bytes, not private archive
    /// payloads which may be absent from the public response.
    pub async fn transactions_projected<T, E, F, Fut>(
        &self,
        head: &Head,
        query: &HistoryQuery,
        limit: usize,
        offset: u64,
        max_bytes: usize,
        mut project: F,
    ) -> std::result::Result<HistoryPage<T>, HistoryReadError<E>>
    where
        F: FnMut(Head, NativeTransaction) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<(T, usize), E>>,
    {
        if max_bytes == 0 || query.hash.is_some() {
            return Err(error("history read limit refused").into());
        }
        let mut read = self.pool.begin().await.map_err(error)?;
        let complete = query.epoch.is_none();
        let prefix = read_prefix(self, &mut read, head, complete).await?;
        if query
            .epoch
            .is_some_and(|epoch| epoch < 0 || epoch as u64 > head.cursor.epoch.0)
        {
            read.commit().await.map_err(error)?;
            return Ok(HistoryPage {
                total: 0,
                incoming: 0,
                outgoing: 0,
                rows: Vec::new(),
            });
        }
        if query.epoch.is_some_and(|epoch| {
            epoch >= 0 && epoch as u64 <= self.anchor().epoch.0 && self.anchor().epoch.0 != 0
        }) {
            return Err(error("epoch precedes retained transaction history").into());
        }
        let address = query.address.as_deref();
        let stats=sqlx::query("SELECT count(*) AS total,coalesce(sum(p.recipient=?),0) AS incoming,coalesce(sum(p.sender=?),0) AS outgoing FROM node_transactions t JOIN node_history_transactions p ON p.txid=t.txid JOIN node_epochs e ON e.sequence=t.sequence WHERE t.sequence<=? AND (? IS NULL OR json_extract(CAST(e.head AS TEXT),'$.cursor.epoch')=?) AND (? IS NULL OR p.sender=? OR p.target=? OR p.extra=?) AND (?=0 OR p.token=1)")
            .bind(address).bind(address).bind(prefix).bind(query.epoch).bind(query.epoch)
            .bind(address).bind(address).bind(address).bind(address).bind(query.token_only)
            .fetch_one(&mut *read).await.map_err(error)?;
        let total: i64 = stats.try_get("total").map_err(error)?;
        let incoming: i64 = stats.try_get("incoming").map_err(error)?;
        let outgoing: i64 = stats.try_get("outgoing").map_err(error)?;
        read.commit().await.map_err(error)?;
        let mut result = Vec::new();
        let mut remaining = max_bytes;
        while result.len() < limit {
            let batch = (limit - result.len()).min(32);
            let at = offset
                .checked_add(result.len() as u64)
                .ok_or_else(|| error("history offset exhausted"))?;
            let mut read = self.pool.begin().await.map_err(error)?;
            // Release the SQL snapshot before calling a projector which can
            // authenticate receipts using the same bounded connection pool.
            read_prefix(self, &mut read, head, complete).await?;
            let rows=sqlx::query("SELECT t.hash FROM node_transactions t JOIN node_history_transactions p ON p.txid=t.txid JOIN node_epochs e ON e.sequence=t.sequence WHERE t.sequence<=? AND (? IS NULL OR json_extract(CAST(e.head AS TEXT),'$.cursor.epoch')=?) AND (? IS NULL OR p.sender=? OR p.target=? OR p.extra=?) AND (?=0 OR p.token=1) ORDER BY CASE WHEN ? THEN t.txid END ASC,t.txid DESC LIMIT ? OFFSET ?")
                .bind(prefix).bind(query.epoch).bind(query.epoch).bind(address).bind(address).bind(address).bind(address).bind(query.token_only)
                .bind(query.ascending).bind(batch as i64).bind(i64::try_from(at).map_err(error)?).fetch_all(&mut *read).await.map_err(error)?;
            read.commit().await.map_err(error)?;
            let count = rows.len();
            for row in rows {
                let hash: String = row.try_get("hash").map_err(error)?;
                let (epoch, record) = self
                    .transaction(head, hash.as_bytes(), i64::MAX as usize - 1)
                    .await?
                    .ok_or_else(|| error("history transaction locator missing"))?;
                let parsed =
                    Native::from_document(&Document::parse(&record.transaction).map_err(error)?)
                        .map_err(error)?;
                let recipient = recipient(&parsed);
                let matches_address = address.is_none_or(|address| {
                    parsed.from == address
                        || parsed.to == address
                        || recipient.as_deref() == Some(address)
                });
                if !matches_address
                    || query
                        .epoch
                        .is_some_and(|wanted| wanted < 0 || wanted as u64 != epoch.cursor.epoch.0)
                    || (query.token_only
                        && !(parsed.op_type == OpType::ContractCall
                            && parsed.encrypted_data.as_deref() == Some(b"transfer")))
                {
                    return Err(error("history transaction query binding differs").into());
                }
                drop(parsed);
                let (row, size) = project(epoch, record)
                    .await
                    .map_err(HistoryReadError::Projection)?;
                remaining = remaining
                    .checked_sub(size)
                    .ok_or(HistoryReadError::ResponseLimit)?;
                result.push(row);
            }
            if count < batch {
                break;
            }
        }
        Ok(HistoryPage {
            total: u64::try_from(total).map_err(error)?,
            incoming: u64::try_from(incoming).map_err(error)?,
            outgoing: u64::try_from(outgoing).map_err(error)?,
            rows: result,
        })
    }
    /// Rejection rows are locators into consensus receipts. The caller must
    /// compare each returned rejection with an authenticated finality record.
    pub async fn rejections(
        &self,
        head: &Head,
        query: &HistoryQuery,
        limit: usize,
        offset: u64,
        max_bytes: usize,
    ) -> Result<RejectionPage> {
        self.rejections_projected(head, query, limit, offset, max_bytes, |record| {
            let size = transaction_outcome::encode_rejection(&record.rejection)
                .map(|raw| raw.len())
                .map_err(error);
            std::future::ready(size.map(|size| (record, size)))
        })
        .await
        .map_err(raw_error)
    }
    /// The callback authenticates finality and retains only public fields before
    /// the next receipt is loaded. Large configured page limits remain valid
    /// when the actual projected response fits the native response budget.
    pub async fn rejections_projected<T, E, F, Fut>(
        &self,
        head: &Head,
        query: &HistoryQuery,
        limit: usize,
        offset: u64,
        max_bytes: usize,
        mut project: F,
    ) -> std::result::Result<RejectionPage<T>, HistoryReadError<E>>
    where
        F: FnMut(RejectionRecord) -> Fut,
        Fut: std::future::Future<Output = std::result::Result<(T, usize), E>>,
    {
        if max_bytes == 0 {
            return Err(error("rejection read limit refused").into());
        }
        let address = query.address.as_deref();
        let epoch = query.epoch;
        let mut read = self.pool.begin().await.map_err(error)?;
        let complete = epoch.is_none() && query.hash.is_none();
        let prefix = read_prefix(self, &mut read, head, complete).await?;
        if epoch.is_some_and(|epoch| epoch < 0 || epoch as u64 > head.cursor.epoch.0) {
            read.commit().await.map_err(error)?;
            return Ok(RejectionPage {
                total: 0,
                rows: Vec::new(),
            });
        }
        if epoch.is_some_and(|epoch| {
            epoch >= 0 && epoch as u64 <= self.anchor().epoch.0 && self.anchor().epoch.0 != 0
        }) {
            return Err(error("epoch precedes retained rejection history").into());
        }
        let target = epoch.map(|epoch| epoch - self.anchor().epoch.0 as i64);
        let covered:i64=sqlx::query_scalar("SELECT count(*) FROM node_history_epochs WHERE sequence>0 AND sequence<=? AND outcomes=1 AND (? IS NULL OR sequence=?)")
            .bind(prefix).bind(target).bind(target).fetch_one(&mut *read).await.map_err(error)?;
        if covered != target.map_or(prefix, |target| i64::from(target > 0 && target <= prefix)) {
            return Err(error("retained rejection outcomes are unavailable").into());
        }
        let hash = query
            .hash
            .as_deref()
            .map(std::str::from_utf8)
            .transpose()
            .map_err(error)?;
        // Like native rejected storage, the newest rejection for a hash replaces
        // earlier observations before address/epoch pagination is applied.
        let total:i64=sqlx::query_scalar("SELECT count(*) FROM node_history_rejections r JOIN node_epochs e ON e.sequence=r.sequence WHERE r.sequence<=? AND NOT EXISTS(SELECT 1 FROM node_history_rejections newer WHERE newer.hash=r.hash AND newer.sequence<=? AND (newer.sequence>r.sequence OR (newer.sequence=r.sequence AND newer.position>r.position))) AND (? IS NULL OR r.sender=? OR r.target=?) AND (? IS NULL OR json_extract(CAST(e.head AS TEXT),'$.cursor.epoch')=?) AND (? IS NULL OR r.hash=?)")
            .bind(prefix).bind(prefix).bind(address).bind(address).bind(address).bind(epoch).bind(epoch).bind(hash).bind(hash).fetch_one(&mut *read).await.map_err(error)?;
        if total == 0 && query.hash.is_some() && self.anchor().epoch.0 != 0 {
            return Err(
                error("rejection absence before snapshot checkpoint is unavailable").into(),
            );
        }
        read.commit().await.map_err(error)?;
        let mut result = Vec::new();
        let mut remaining = max_bytes;
        while result.len() < limit {
            let at = offset
                .checked_add(result.len() as u64)
                .ok_or_else(|| error("rejection offset exhausted"))?;
            let mut read = self.pool.begin().await.map_err(error)?;
            read_prefix(self, &mut read, head, complete).await?;
            let row=sqlx::query("SELECT r.hash,r.sequence,r.position,r.sender,r.target,r.receipt,r.digest,r.observed_at FROM node_history_rejections r JOIN node_epochs e ON e.sequence=r.sequence WHERE r.sequence<=? AND NOT EXISTS(SELECT 1 FROM node_history_rejections newer WHERE newer.hash=r.hash AND newer.sequence<=? AND (newer.sequence>r.sequence OR (newer.sequence=r.sequence AND newer.position>r.position))) AND (? IS NULL OR r.sender=? OR r.target=?) AND (? IS NULL OR json_extract(CAST(e.head AS TEXT),'$.cursor.epoch')=?) AND (? IS NULL OR r.hash=?) ORDER BY CASE WHEN ? THEN r.sequence END ASC,CASE WHEN ? THEN r.hash END ASC,r.sequence DESC,r.hash DESC LIMIT 1 OFFSET ?")
                .bind(prefix).bind(prefix).bind(address).bind(address).bind(address).bind(epoch).bind(epoch).bind(hash).bind(hash)
                .bind(query.ascending).bind(query.ascending).bind(i64::try_from(at).map_err(error)?).fetch_optional(&mut *read).await.map_err(error)?;
            let Some(row) = row else {
                read.commit().await.map_err(error)?;
                break;
            };
            let raw: Vec<u8> = row.try_get("receipt").map_err(error)?;
            let digest: Vec<u8> = row.try_get("digest").map_err(error)?;
            if Sha256::digest(&raw).as_slice() != digest {
                return Err(error("rejection locator checksum differs").into());
            }
            let transaction_outcome::Item::Rejection(rejection) =
                transaction_outcome::parse(&raw, false).map_err(error)?
            else {
                return Err(error("rejection locator record differs").into());
            };
            let actual = hex::encode(rejection.tx.hash().map_err(error)?);
            if row.try_get::<String, _>("hash").map_err(error)? != actual
                || row.try_get::<i64, _>("position").map_err(error)? != rejection.position
                || row.try_get::<Vec<u8>, _>("sender").map_err(error)? != rejection.tx.from
                || row.try_get::<Vec<u8>, _>("target").map_err(error)? != rejection.tx.to
            {
                return Err(error("rejection locator identity differs").into());
            }
            let sequence: i64 = row.try_get("sequence").map_err(error)?;
            let archived = retained_head(&mut read, sequence).await?;
            let observed_at: Option<f64> = row.try_get("observed_at").map_err(error)?;
            if observed_at.is_some_and(|time| !time.is_finite() || time < 0.) {
                return Err(error("rejection observation time differs").into());
            }
            read.commit().await.map_err(error)?;
            let record = RejectionRecord {
                head: archived,
                rejection: *rejection,
                observed_at,
            };
            let (row, size) = project(record)
                .await
                .map_err(HistoryReadError::Projection)?;
            remaining = remaining
                .checked_sub(size)
                .ok_or(HistoryReadError::ResponseLimit)?;
            result.push(row);
        }
        Ok(RejectionPage {
            total: u64::try_from(total).map_err(error)?,
            rows: result,
        })
    }
}
