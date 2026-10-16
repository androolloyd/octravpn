// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
use super::{
    guard::Score,
    peer_record::{self, Record},
};
use crate::light_rpc::json::{array, number, object, string};
use std::collections::BTreeMap;
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Relayed {
    pub accepted: i64,
    pub unchanged: i64,
    pub rejected: i64,
    pub rejections: BTreeMap<Vec<u8>, i64>,
}
impl Relayed {
    pub fn accept(&mut self, new: bool) {
        let value = if new {
            &mut self.accepted
        } else {
            &mut self.unchanged
        };
        *value = value.wrapping_add(1).wrapping_shl(1) >> 1;
    }
    pub fn reject(&mut self, reason: &[u8]) {
        self.rejected = self.rejected.wrapping_add(1).wrapping_shl(1) >> 1;
        let count = self.rejections.entry(reason.to_vec()).or_default();
        *count = count.wrapping_add(1).wrapping_shl(1) >> 1;
    }
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Source {
    pub bucket: Vec<u8>,
    pub records: i64,
    pub connected: i64,
}
#[derive(Clone, Debug)]
pub struct Diagnostics {
    pub connected: i64,
    pub known: i64,
    pub public_sources: i64,
    pub sources: Vec<Source>,
    pub scores: Vec<(Vec<u8>, Score)>,
    pub relayed_records: Relayed,
    pub risks: Vec<Vec<u8>>,
}
impl Diagnostics {
    pub fn make(
        connected: &[Vec<u8>],
        records: &[Record],
        scores: Vec<(Vec<u8>, Score)>,
        relayed_records: Relayed,
        min_public_sources: i64,
    ) -> Self {
        let mut rows: BTreeMap<Vec<u8>, Source> = BTreeMap::new();
        for record in records {
            let bucket = peer_record::bucket(&record.host);
            let row = rows.entry(bucket.clone()).or_insert_with(|| Source {
                bucket,
                ..Source::default()
            });
            row.records += 1;
        }
        for host in connected {
            let bucket = peer_record::bucket(host);
            let row = rows.entry(bucket.clone()).or_insert_with(|| Source {
                bucket,
                ..Source::default()
            });
            row.connected += 1;
        }
        let sources = rows.into_values().collect::<Vec<_>>();
        let public_sources = sources
            .iter()
            .filter(|row| {
                (row.bucket.starts_with(b"v4:") || row.bucket.starts_with(b"dns:"))
                    && row.records + row.connected > 0
            })
            .count() as i64;
        let known = records.len() as i64;
        let connected = connected.len() as i64;
        let risks = if known + connected > 0 && sources.iter().all(|row| row.bucket == b"local") {
            vec![b"local_only".to_vec()]
        } else if known + connected > 0 && public_sources == 0 {
            vec![b"non_public_only".to_vec()]
        } else if known + connected >= min_public_sources && public_sources < min_public_sources {
            vec![b"low_public_source_diversity".to_vec()]
        } else {
            vec![]
        };
        Self {
            connected,
            known,
            public_sources,
            sources,
            scores,
            relayed_records,
            risks,
        }
    }
    pub fn to_json(&self) -> Vec<u8> {
        let r = &self.relayed_records;
        object(&[
            ("connected", number(self.connected)),
            ("known", number(self.known)),
            ("public_sources", number(self.public_sources)),
            (
                "sources",
                array(self.sources.iter().map(|s| {
                    object(&[
                        ("bucket", string(&s.bucket)),
                        ("records", number(s.records)),
                        ("connected", number(s.connected)),
                    ])
                })),
            ),
            (
                "relayed_records",
                object(&[
                    ("accepted", number(r.accepted)),
                    ("unchanged", number(r.unchanged)),
                    ("rejected", number(r.rejected)),
                    (
                        "rejections",
                        array(r.rejections.iter().map(|(reason, count)| {
                            object(&[("reason", string(reason)), ("count", number(count))])
                        })),
                    ),
                ]),
            ),
            ("risks", array(self.risks.iter().map(string))),
        ])
    }
    pub fn scores_json(&self, now: f64) -> Result<Vec<u8>, crate::oce1::Error> {
        use crate::transaction::native_float;
        let float = |v| {
            native_float(v)
                .map(String::into_bytes)
                .map_err(|e| crate::oce1::Error::from(e.to_string()))
        };
        Ok(array(
            self.scores
                .iter()
                .map(|(key, s)| {
                    Ok(object(&[
                        ("key", string(key)),
                        ("bad_count", number(s.bad_count)),
                        ("conn_count", number(s.connection_count)),
                        ("ban_until", float(s.ban_until)?),
                        ("ban_remaining_sec", float((s.ban_until - now).max(0.))?),
                        ("last_reason", string(&s.last_reason)),
                        ("invalid_frame_count", number(s.invalid_frames)),
                        ("bad_signature_count", number(s.bad_signatures)),
                        ("stale_root_count", number(s.stale_roots)),
                    ]))
                })
                .collect::<Result<Vec<_>, crate::oce1::Error>>()?,
        ))
    }
}
