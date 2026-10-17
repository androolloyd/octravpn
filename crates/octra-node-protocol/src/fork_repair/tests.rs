use super::*;
use std::collections::BTreeMap;
mod parity;

fn head(epoch: i64) -> Head {
    Head {
        schema_version: 3,
        generation: epoch,
        epoch_id: epoch,
        state_root: vec![b'a'; 64],
        ledger_state_root: Some(b"ledger".to_vec()),
        irmin_commit: Some(b"commit".to_vec()),
        txid_hi: 1,
        txlog_seg: Some(0),
        txlog_off: Some(12),
        epochlog_off: Some(34),
        commit_id: b"native".to_vec(),
        ts: 1.,
        quorum_cert_hash: None,
        epoch_index_hash: Some(b"index".to_vec()),
        epoch_index_root: Some(b"root".to_vec()),
    }
}
fn plan() -> Plan {
    Plan {
        source: head(2),
        target_root: vec![b'a'; 64],
        next_txid: 2,
        head: head(1),
    }
}

#[test]
fn records_preserve_native_bytes_int64_and_outer_field_selection() {
    let mut value = plan();
    value.source.commit_id = b"raw\0\xff\x7f\"\\".to_vec();
    value.head.txid_hi = i64::MAX - 1;
    value.next_txid = i64::MAX;
    let encoded = value.encode().unwrap();
    assert_eq!(Plan::parse(&encoded).unwrap(), value);
    let mut repeated = b"{\"schema\":1,\"schema\":9,\"unknown\":[],".to_vec();
    repeated.extend_from_slice(&encoded[b"{\"schema\":1,".len()..]);
    assert_eq!(Plan::parse(&repeated).unwrap(), value);
    let mut invalid = b"{\"schema\":9,".to_vec();
    invalid.extend_from_slice(&encoded[1..]);
    assert_eq!(
        Plan::parse(&invalid).unwrap_err().to_string(),
        "fork repair log schema mismatch"
    );
    let raw = encode_head(&value.source).unwrap();
    let mut duplicate = b"{\"generation\":2,".to_vec();
    duplicate.extend_from_slice(&raw[1..]);
    assert!(parse_head(&duplicate).is_err());
}

#[test]
fn repair_record_codec_does_not_invent_head_file_reader_limit() {
    let mut value = plan();
    value.source.commit_id = vec![b'x'; crate::state_sync::head::MAX_BYTES + 1];
    let raw = value.encode().unwrap();
    assert_eq!(Plan::parse(&raw).unwrap(), value);
}

#[test]
fn source_rewrite_compatibility_is_not_fresh_full_head_equality() {
    let value = plan();
    let mut rewritten = value.source.clone();
    rewritten.irmin_commit = Some(b"rewritten".to_vec());
    rewritten.commit_id = b"rewritten".to_vec();
    assert_ne!(rewritten, value.source);
    assert!(same_source(&rewritten, &value.source));
    assert!(value.accepts_source(&rewritten));
    assert!(value.accepts_source(&value.head));
    rewritten.epochlog_off = Some(35);
    assert!(!value.accepts_source(&rewritten));
    let mut wrong_target = value.head.clone();
    wrong_target.irmin_commit = Some(b"rewritten".to_vec());
    assert!(!value.accepts_source(&wrong_target));
}

#[derive(Clone)]
struct Entry {
    epoch: i64,
    root: Vec<u8>,
    txid: i64,
}
struct Backend {
    plan: Option<Plan>,
    head: Option<Head>,
    entries: BTreeMap<i64, Entry>,
    trace: Vec<String>,
    fail: Option<String>,
    committed: bool,
}
impl Backend {
    fn new() -> Self {
        let value = plan();
        Self {
            entries: BTreeMap::from([(
                1,
                Entry {
                    epoch: 1,
                    root: value.target_root.clone(),
                    txid: 1,
                },
            )]),
            head: Some(value.head.clone()),
            plan: Some(value),
            trace: Vec::new(),
            fail: None,
            committed: true,
        }
    }
    fn touch(&mut self, name: String) -> Result<()> {
        let result = if self.fail.as_ref() == Some(&name) {
            Err(format!("injected:{name}").into())
        } else {
            Ok(())
        };
        self.trace.push(name);
        result
    }
}
impl Finality for Backend {
    type Entry = Entry;
    fn read_plan(&mut self) -> Result<Option<Plan>> {
        self.touch("read_plan".into())?;
        Ok(self.plan.clone())
    }
    fn head(&mut self) -> Result<Option<Head>> {
        self.touch("head".into())?;
        Ok(self.head.clone())
    }
    fn finality_at(&mut self, epoch: i64) -> Result<Option<Entry>> {
        self.touch(format!("finality:{epoch}"))?;
        Ok(self.entries.get(&epoch).cloned())
    }
    fn entry_root<'a>(&self, entry: &'a Entry) -> &'a [u8] {
        &entry.root
    }
    fn entry_txid_hi(&self, entry: &Entry) -> i64 {
        entry.txid
    }
    fn journal_committed(&mut self) -> Result<bool> {
        self.touch("journal_committed".into())?;
        Ok(self.committed)
    }
    fn committed_for(&mut self, entry: &Entry) -> Result<()> {
        self.touch(format!("committed_for:{}", entry.epoch))
    }
    fn rewind_journal(&mut self, entry: &Entry) -> Result<()> {
        self.touch(format!("rewind:{}", entry.epoch))
    }
    fn drop_after(&mut self, target: i64) -> Result<i64> {
        self.touch(format!("drop_after:{target}"))?;
        Ok(3)
    }
    fn clear(&mut self) -> Result<()> {
        self.touch("clear".into())
    }
}

#[test]
fn finality_clear_follows_durable_rewind_and_trim_and_is_never_early() {
    let mut backend = Backend::new();
    assert_eq!(
        finish(&mut backend).unwrap(),
        Finish::Resumed {
            target: 1,
            head: 1,
            dropped: 3
        }
    );
    assert_eq!(
        backend.trace,
        [
            "read_plan",
            "head",
            "finality:1",
            "journal_committed",
            "rewind:1",
            "drop_after:1",
            "clear"
        ]
    );
    for fail in [
        "read_plan",
        "head",
        "finality:1",
        "journal_committed",
        "rewind:1",
        "drop_after:1",
        "clear",
    ] {
        let mut backend = Backend::new();
        backend.fail = Some(fail.into());
        assert_eq!(
            finish(&mut backend).unwrap_err().to_string(),
            format!("injected:{fail}")
        );
        assert_eq!(backend.trace.last().unwrap(), fail);
        if fail != "clear" {
            assert!(!backend.trace.iter().any(|call| call == "clear"));
        }
    }
}

#[test]
fn advanced_head_requires_its_own_finality_proof_without_rewind() {
    let mut backend = Backend::new();
    backend.head = Some(head(4));
    backend.entries.insert(
        4,
        Entry {
            epoch: 4,
            root: vec![b'a'; 64],
            txid: 1,
        },
    );
    assert_eq!(
        finish(&mut backend).unwrap(),
        Finish::Resumed {
            target: 1,
            head: 4,
            dropped: 0
        }
    );
    assert_eq!(
        backend.trace,
        [
            "read_plan",
            "head",
            "finality:1",
            "finality:4",
            "committed_for:4",
            "clear"
        ]
    );
    let mut backend = Backend::new();
    backend.head = Some(head(4));
    assert_eq!(
        finish(&mut backend).unwrap_err().to_string(),
        "current finality entry is missing"
    );
    assert!(!backend.trace.iter().any(|call| call == "clear"));
}
