//! Resumable native public-address scans. Cache only authenticated projections;
//! private rows never contribute to the public count or pagination offsets.
use octra_exex::native_history::NativeTransaction;
use octra_node_protocol::rpc::{self, Fault};
use octra_node_runtime::canonical::{Head, HistoryPage, HistoryQuery, Reader};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Semaphore},
    time::{timeout_at, Instant},
};

#[derive(Clone)]
pub(crate) struct Row {
    pub epoch: u64,
    pub hash: String,
    pub json: Vec<u8>,
}
#[derive(Clone, Copy, Default)]
struct Mark {
    raw: u64,
    seen: u64,
}
#[derive(Clone)]
struct Page {
    first: u64,
    last: u64,
    cursor: Mark,
    rows: Vec<Row>,
}
struct Index {
    raw_count: u64,
    total: u64,
    stride: u64,
    marks: Vec<Mark>,
    page: Option<Page>,
}
impl Default for Index {
    fn default() -> Self {
        Self {
            raw_count: 0,
            total: 0,
            stride: 64,
            marks: vec![Mark::default()],
            page: None,
        }
    }
}
impl Index {
    fn counted(&mut self, count: u64, visible: u64) {
        let before = self.raw_count;
        self.raw_count += count;
        self.total += visible;
        if self.raw_count / self.stride > before / self.stride {
            self.marks.push(Mark {
                raw: self.raw_count,
                seen: self.total,
            });
        }
        if self.marks.len() > 4096 {
            self.stride = self.stride.saturating_mul(2);
            // Always retain the genesis cursor, even as older marks thin out.
            self.marks = self
                .marks
                .iter()
                .enumerate()
                .filter_map(|(i, m)| (i % 2 == 0).then_some(*m))
                .collect();
        }
        self.page = None;
    }
    fn page(&mut self, limit: usize, offset: u64) -> &mut Page {
        let last = self.total.saturating_sub(offset);
        let first = last.saturating_sub(limit.min(1000) as u64);
        if self
            .page
            .as_ref()
            .is_none_or(|p| p.first != first || p.last != last)
        {
            let cursor = self
                .marks
                .iter()
                .rev()
                .find(|m| m.seen <= first)
                .copied()
                .unwrap_or_default();
            self.page = Some(Page {
                first,
                last,
                cursor,
                rows: vec![],
            });
        }
        self.page.as_mut().expect("public history page")
    }
}
#[derive(Default)]
struct Cache {
    clock: u64,
    indexes: BTreeMap<Vec<u8>, (u64, Arc<AsyncMutex<Index>>)>,
}
pub(crate) struct Service {
    waiters: Semaphore,
    cache: Mutex<Cache>,
}
impl Default for Service {
    fn default() -> Self {
        Self {
            waiters: Semaphore::new(8),
            cache: Mutex::default(),
        }
    }
}
fn fault(reason: &str) -> Fault {
    Fault::new(110, b"service unavailable").string_data(reason.as_bytes())
}
impl Service {
    pub(crate) fn token_work(&self) -> Result<tokio::sync::SemaphorePermit<'_>, Fault> {
        self.waiters
            .try_acquire()
            .map_err(|_| fault("token history busy"))
    }
    fn index(&self, address: &[u8]) -> Result<Arc<AsyncMutex<Index>>, Fault> {
        let mut cache = self
            .cache
            .lock()
            .map_err(|_| fault("address history unavailable"))?;
        cache.clock = cache.clock.saturating_add(1);
        let now = cache.clock;
        if let Some((used, index)) = cache.indexes.get_mut(address) {
            *used = now;
            return Ok(index.clone());
        }
        if cache.indexes.len() >= 64 {
            let oldest = cache
                .indexes
                .iter()
                .filter(|(_, (_, index))| Arc::strong_count(index) == 1)
                .min_by_key(|(_, (used, _))| *used)
                .map(|(key, _)| key.clone());
            if let Some(oldest) = oldest {
                cache.indexes.remove(&oldest);
            }
        }
        let index = Arc::new(AsyncMutex::new(Index::default()));
        cache.indexes.insert(address.to_vec(), (now, index.clone()));
        Ok(index)
    }
    pub(crate) async fn read<F>(
        &self,
        reader: &Reader,
        head: &Head,
        address: &[u8],
        limit: usize,
        offset: u64,
        project: F,
    ) -> Result<HistoryPage<Row>, Fault>
    where
        F: Fn(Head, NativeTransaction) -> Result<Option<Row>, Fault>,
    {
        self.read_bounded(reader, head, address, limit, offset, 1024, project)
            .await
    }
    async fn read_bounded<F>(
        &self,
        reader: &Reader,
        head: &Head,
        address: &[u8],
        limit: usize,
        offset: u64,
        budget: usize,
        project: F,
    ) -> Result<HistoryPage<Row>, Fault>
    where
        F: Fn(Head, NativeTransaction) -> Result<Option<Row>, Fault>,
    {
        let deadline = Instant::now() + Duration::from_secs(15);
        let _waiter = self
            .waiters
            .try_acquire()
            .map_err(|_| fault("address history busy"))?;
        let index = self.index(address)?;
        let mut index = timeout_at(deadline, index.lock())
            .await
            .map_err(|_| fault("address history deadline"))?;
        let query = HistoryQuery {
            address: Some(address.to_vec()),
            ascending: true,
            ..HistoryQuery::default()
        };
        let total = timeout_at(deadline, reader.transactions(head, &query, 0, 0, 1))
            .await
            .map_err(|_| fault("address history deadline"))?
            .map_err(|_| fault("address history unavailable"))?
            .total;
        if total < index.raw_count {
            *index = Index::default();
        }
        let mut remaining = budget.min(1024);
        while index.raw_count < total {
            if remaining == 0 {
                return Err(fault("address history pending"));
            }
            let count = remaining.min(64).min((total - index.raw_count) as usize);
            let rows = chunk(
                reader,
                head,
                &query,
                index.raw_count,
                count,
                deadline,
                &project,
            )
            .await?;
            if rows.len() != count {
                return Err(fault("address history index incomplete"));
            }
            remaining -= count;
            index.counted(
                count as u64,
                rows.iter().filter(|r| r.is_some()).count() as u64,
            );
        }
        let total = index.total;
        let page = index.page(limit, offset);
        while page.cursor.seen < page.last && limit != 0 {
            if remaining == 0 {
                return Err(fault("address history pending"));
            }
            let rows = chunk(
                reader,
                head,
                &query,
                page.cursor.raw,
                remaining.min(64),
                deadline,
                &project,
            )
            .await?;
            if rows.is_empty() {
                return Err(fault("address history index incomplete"));
            }
            remaining -= rows.len();
            for row in rows {
                page.cursor.raw += 1;
                if let Some(row) = row {
                    if page.cursor.seen >= page.first {
                        page.rows.push(row);
                    }
                    page.cursor.seen += 1;
                    if page.cursor.seen >= page.last {
                        break;
                    }
                }
            }
        }
        let bytes = page
            .rows
            .iter()
            .map(|r| r.json.len().saturating_add(1))
            .sum::<usize>();
        if bytes > rpc::MAX_SINGLE {
            return Err(Fault::response_limit());
        }
        let rows = if limit == 0 {
            Vec::new()
        } else {
            page.rows.iter().rev().cloned().collect()
        };
        Ok(HistoryPage {
            total,
            incoming: 0,
            outgoing: 0,
            rows,
        })
    }
}
async fn chunk<F>(
    reader: &Reader,
    head: &Head,
    query: &HistoryQuery,
    offset: u64,
    limit: usize,
    deadline: Instant,
    project: &F,
) -> Result<Vec<Option<Row>>, Fault>
where
    F: Fn(Head, NativeTransaction) -> Result<Option<Row>, Fault>,
{
    timeout_at(
        deadline,
        reader.transactions_projected(head, query, limit, offset, rpc::MAX_SINGLE, |head, tx| {
            std::future::ready(project(head, tx).map(|row| {
                let size = row.as_ref().map_or(0, |r| r.json.len() + 1);
                (row, size)
            }))
        }),
    )
    .await
    .map_err(|_| fault("address history deadline"))?
    .map(|page| page.rows)
    .map_err(|_| fault("address history unavailable"))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn public_offsets_ignore_private_rows_and_resume_counting() {
        let mut index = Index::default();
        index.counted(64, 3);
        index.counted(64, 0);
        index.counted(64, 4);
        assert_eq!((index.raw_count, index.total), (192, 7));
        let page = index.page(3, 1);
        assert_eq!(
            (page.first, page.last, page.cursor.raw, page.cursor.seen),
            (3, 6, 128, 3)
        );
        page.cursor.raw += 1;
        assert_eq!(index.page(3, 1).cursor.raw, 129);
        assert_eq!(index.page(3, 0).cursor.raw, 128);
    }
    #[test]
    fn index_cache_is_bounded_and_admission_precedes_work() {
        let service = Service::default();
        for i in 0u16..128 {
            drop(service.index(&i.to_be_bytes()).unwrap());
        }
        assert_eq!(service.cache.lock().unwrap().indexes.len(), 64);
        let held: Vec<_> = (0..8)
            .map(|_| service.waiters.try_acquire().unwrap())
            .collect();
        assert!(service.waiters.try_acquire().is_err());
        drop(held);
        assert!(service.waiters.try_acquire().is_ok());
    }
    #[tokio::test]
    async fn authenticated_public_pages_resume_without_linking_private_transactions() {
        use octra_exex::{native_history::ArchiveProof, ChainIdentity, StateRoot};
        use octra_node_protocol::{
            epoch_index,
            native_json::Document,
            transaction::{Nonce, OpType, Transaction},
        };
        use octra_node_runtime::{
            canonical::{AppliedEpoch, CanonicalStore},
            state_batch::StateBatch,
        };
        let directory = tempfile::tempdir().unwrap();
        let state = StateBatch::default().snapshot();
        let index =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])
                .unwrap()
                .1;
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index).as_bytes(),
        )
        .unwrap();
        let path = directory.path().join("history.db");
        let chain = ChainIdentity::genesis("public-history-storage-fixture", StateRoot(root));
        let store = CanonicalStore::create(&path, chain.clone(), state, 0)
            .await
            .unwrap();
        let (base, mut state) = store.snapshot().await.unwrap();
        let operations = [
            OpType::Standard,
            OpType::Stealth,
            OpType::Standard,
            OpType::Claim,
        ];
        let records = operations
            .into_iter()
            .enumerate()
            .map(|(id, op_type)| {
                let tx = Transaction {
                    from: b"sender".to_vec(),
                    to: b"recipient".to_vec(),
                    amount: 0.into(),
                    nonce: Nonce::new(id as i64 + 1).unwrap(),
                    ou: 1.into(),
                    timestamp: 1.,
                    signature: vec![],
                    public_key: None,
                    message: None,
                    op_type,
                    encrypted_data: None,
                };
                let identity = tx.identity_bytes().unwrap();
                NativeTransaction {
                    txid: id as i64,
                    hash: hex::encode(tx.hash().unwrap()),
                    proof: ArchiveProof::Exact,
                    identity: identity.clone(),
                    transaction: identity,
                    receipt: None,
                }
            })
            .collect::<Vec<_>>();
        let expected = records[2].hash.clone();
        let first = records[0].hash.clone();
        state.begin().unwrap();
        state.set(&[b"meta", b"last_epoch"], b"1".to_vec()).unwrap();
        // Storage-only history fixture leaves the stealth counter unchanged;
        // canonical publication reconciles its persisted cache internally.
        let state = state.snapshot();
        let items = records
            .iter()
            .map(|r| epoch_index::Item {
                txid: r.txid,
                hash: r.hash.as_bytes().to_vec(),
            })
            .collect::<Vec<_>>();
        let index = epoch_index::next_root(base.index_root.as_bytes(), 1, &items)
            .unwrap()
            .1;
        let root = epoch_index::folded_state_root(
            hex::encode(state.root().unwrap()).as_bytes(),
            hex::encode(index).as_bytes(),
        )
        .unwrap();
        let head = store
            .prepare(
                &base,
                AppliedEpoch {
                    epoch: 1,
                    state,
                    expected_root: StateRoot(root),
                    transactions: records,
                    certificate: b"storage-only fixture".to_vec(),
                    date: 1,
                    message: vec![],
                },
            )
            .await
            .unwrap()
            .commit()
            .await
            .unwrap();
        // Raw storage publication does not retain consensus receipts or advance
        // the public history cursor. Reopen authenticates the archive and
        // reconstructs its history locators through the normal recovery path.
        store.close().await;
        let store = CanonicalStore::open(&path, &chain).await.unwrap();
        assert_eq!(store.head().await.unwrap(), head);
        let project = |head: Head, record: NativeTransaction| {
            let tx =
                Transaction::from_document(&Document::parse(&record.transaction).unwrap()).unwrap();
            Ok(if matches!(tx.op_type, OpType::Stealth | OpType::Claim) {
                None
            } else {
                Some(Row {
                    epoch: head.cursor.epoch.0,
                    json: b"{}".to_vec(),
                    hash: record.hash,
                })
            })
        };
        let service = Service::default();
        for _ in 0..3 {
            let failure = service
                .read_bounded(&store.reader(), &head, b"sender", 1, 0, 2, project)
                .await
                .err()
                .expect("bounded work returns a resumable pending status");
            assert_eq!(failure.data, Some(b"\"address history pending\"".to_vec()));
        }
        let page = service
            .read_bounded(&store.reader(), &head, b"sender", 1, 0, 2, project)
            .await
            .unwrap();
        assert_eq!(page.total, 2);
        assert_eq!(page.rows.len(), 1);
        assert_eq!(page.rows[0].hash, expected);
        let older = service
            .read(&store.reader(), &head, b"sender", 1, 1, project)
            .await
            .unwrap();
        assert_eq!(older.total, 2);
        assert_eq!(older.rows[0].hash, first);
        store.close().await;
    }
}
