// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native snapshot layout, byte commitments and certificate decoding. A decoded
//! certificate remains untrusted until its finality authority is verified.
use super::{
    checkpoint::{self, Signature},
    field, fields, int64, integer, list, lower_hex, optional, require, text, Result,
};
use crate::{
    consensus::{hash, Validator, ValidatorSet},
    native_json::{Document, Value},
    network,
    oce1::Writer,
    transaction,
};

pub const FORMAT: &[u8] = b"octra-state-sync";
pub const MANIFEST_LIMIT: usize = 32 * 1024 * 1024;
pub const FILE_LIMIT: usize = 200_000;
pub const CHUNK_LIMIT: usize = 262_144;
pub const CHUNK_MIN: i64 = 1024 * 1024;
pub const CHUNK_MAX: i64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Chunk {
    pub index: i64,
    pub offset: i64,
    pub size: i64,
    pub sha256: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct File {
    pub path: Vec<u8>,
    pub size: i64,
    pub sha256: Vec<u8>,
    pub chunks: Vec<Chunk>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Body {
    pub checkpoint_hash: Vec<u8>,
    pub snapshot_id: Vec<u8>,
    pub irmin_commit: Option<Vec<u8>>,
    pub chunk_size: i64,
    pub total_size: i64,
    pub file_count: i64,
    pub chunk_count: i64,
    pub chunks_root: Vec<u8>,
    pub files: Vec<File>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    pub checkpoint: checkpoint::Body,
    pub checkpoint_hash: Vec<u8>,
    pub manifest: Body,
    pub manifest_hash: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Authority {
    CheckpointQuorum(Vec<Signature>),
    Finalized(Vec<u8>),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Certificate {
    pub draft: Draft,
    pub authority: Authority,
    pub exporters: Vec<Signature>,
}

pub fn valid_path(value: &[u8]) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with(b"/")
        && !value.contains(&0)
        && !value.contains(&b'\\')
        && value
            .split(|b| *b == b'/')
            .all(|s| !s.is_empty() && s != b"." && s != b"..")
}
pub fn reference_file(path: &[u8]) -> bool {
    matches!(
        path,
        b"HEAD.json"
            | b"state_root"
            | b"ready_roots"
            | b"ledger.dat"
            | b"pvac/migration_state.json"
    ) || path
        .strip_prefix(b"pvac/blobs/")
        .and_then(|p| p.strip_suffix(b".pk"))
        .is_some_and(|p| lower_hex(p, 64))
}
fn put_chunk(w: &mut Writer, path: &[u8], chunk: &Chunk) -> Result<()> {
    w.put_bytes(path)?;
    w.put_u32(chunk.index as u32)?;
    w.put_u64(chunk.offset as u64)?;
    w.put_u32(chunk.size as u32)?;
    w.put_hash32(&chunk.sha256)
}
pub fn chunks_root(files: &[File]) -> Result<[u8; 32]> {
    let mut w = Writer::new();
    w.put_u32(files.iter().map(|f| f.chunks.len()).sum::<usize>() as u32)?;
    for file in files {
        for chunk in &file.chunks {
            put_chunk(&mut w, &file.path, chunk)?;
        }
    }
    Ok(network::domain_hash(
        b"octra:state_sync_chunks",
        &w.into_bytes(),
    ))
}
impl Chunk {
    fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(value, &[b"index", b"offset", b"size", b"sha256"], "chunk")?;
        Ok(Self {
            index: integer(field(doc, value, b"index")?)?,
            offset: int64(field(doc, value, b"offset")?)?,
            size: integer(field(doc, value, b"size")?)?,
            sha256: text(field(doc, value, b"sha256")?)?,
        })
    }
}
impl File {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(value, &[b"path", b"size", b"sha256", b"chunks"], "file")?;
        let path = text(field(doc, value, b"path")?)?;
        let size = int64(field(doc, value, b"size")?)?;
        let sha256 = text(field(doc, value, b"sha256")?)?;
        let values = list(doc, field(doc, value, b"chunks")?)?;
        require(
            values.len() <= CHUNK_LIMIT,
            "file chunk count exceeds limit",
        )?;
        Ok(Self {
            path,
            size,
            sha256,
            chunks: values
                .into_iter()
                .map(|v| Chunk::parse(doc, v))
                .collect::<Result<_>>()?,
        })
    }
    pub fn validate(&self, chunk_size: i64) -> Result<()> {
        require(valid_path(&self.path), "invalid file path")?;
        require(self.size >= 0, "negative file size")?;
        require(lower_hex(&self.sha256, 64), "invalid file hash")?;
        require(
            self.size != 0 || self.chunks.is_empty(),
            "empty file has chunks",
        )?;
        require(
            self.size == 0 || !self.chunks.is_empty(),
            "non-empty file has no chunks",
        )?;
        let mut offset = 0_i64;
        for (index, chunk) in self.chunks.iter().enumerate() {
            require(chunk.index == index as i64, "chunk index gap")?;
            require(chunk.offset == offset, "chunk offset gap")?;
            require(
                chunk.size > 0 && chunk.size <= chunk_size,
                "invalid chunk size",
            )?;
            require(lower_hex(&chunk.sha256, 64), "invalid chunk hash")?;
            offset = offset
                .checked_add(chunk.size)
                .ok_or("chunk offset overflow")?;
            require(offset <= self.size, "chunk exceeds file")?;
        }
        require(offset == self.size, "file chunks do not cover file")
    }
}
impl Body {
    pub fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(
            value,
            &[
                b"version",
                b"checkpoint_hash",
                b"snapshot_id",
                b"irmin_commit",
                b"chunk_size",
                b"total_size",
                b"file_count",
                b"chunk_count",
                b"chunks_root",
                b"files",
            ],
            "manifest",
        )?;
        let get = |name: &[u8]| field(doc, value, name);
        require(
            text(get(b"version")?)? == FORMAT,
            "unsupported manifest format",
        )?;
        let checkpoint_hash = text(get(b"checkpoint_hash")?)?;
        let snapshot_id = text(get(b"snapshot_id")?)?;
        let irmin_commit = optional(get(b"irmin_commit")?)?;
        let chunk_size = integer(get(b"chunk_size")?)?;
        let total_size = int64(get(b"total_size")?)?;
        let file_count = integer(get(b"file_count")?)?;
        let chunk_count = integer(get(b"chunk_count")?)?;
        let chunks_root = text(get(b"chunks_root")?)?;
        let values = list(doc, get(b"files")?)?;
        require(values.len() <= FILE_LIMIT, "file count exceeds limit")?;
        Ok(Self {
            checkpoint_hash,
            snapshot_id,
            irmin_commit,
            chunk_size,
            total_size,
            file_count,
            chunk_count,
            chunks_root,
            files: values
                .into_iter()
                .map(|v| File::parse(doc, v))
                .collect::<Result<_>>()?,
        })
    }
    pub fn validate(&self) -> Result<()> {
        require(
            lower_hex(&self.checkpoint_hash, 64),
            "invalid checkpoint hash",
        )?;
        require(
            !self.snapshot_id.is_empty()
                && self.snapshot_id.len() <= 128
                && self
                    .snapshot_id
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(b)),
            "invalid snapshot id",
        )?;
        require(
            self.snapshot_id == self.checkpoint_hash,
            "snapshot id must equal checkpoint hash",
        )?;
        require(
            self.irmin_commit
                .as_ref()
                .map_or(true, |v| !v.is_empty() && v.len() <= 256),
            "invalid irmin commit",
        )?;
        require(
            (CHUNK_MIN..=CHUNK_MAX).contains(&self.chunk_size),
            "invalid manifest chunk size",
        )?;
        require(
            self.file_count == self.files.len() as i64,
            "file count mismatch",
        )?;
        require(
            (1..=FILE_LIMIT as i64).contains(&self.file_count),
            "file count exceeds limit",
        )?;
        require(
            self.files.windows(2).all(|w| w[0].path < w[1].path),
            "file path order is invalid",
        )?;
        let count = self.files.iter().map(|f| f.chunks.len()).sum::<usize>();
        require(count as i64 == self.chunk_count, "chunk count mismatch")?;
        require(
            (1..=CHUNK_LIMIT).contains(&count),
            "chunk count exceeds limit",
        )?;
        let mut size = 0_i64;
        for file in &self.files {
            require(file.size >= 0, "negative file size")?;
            size = size.checked_add(file.size).ok_or("total size overflow")?;
        }
        require(size == self.total_size, "total size mismatch")?;
        for file in &self.files {
            file.validate(self.chunk_size)?;
        }
        require(
            hex::encode(chunks_root(&self.files)?).as_bytes() == self.chunks_root,
            "chunk root mismatch",
        )
    }
    pub fn validate_reference(&self) -> Result<()> {
        self.validate()?;
        for file in &self.files {
            if !reference_file(&file.path) {
                return Err(super::Error::new(
                    [
                        b"reference snapshot file is unsupported: ".as_slice(),
                        &file.path,
                    ]
                    .concat(),
                ));
            }
        }
        for (path, reason) in [
            (b"HEAD.json".as_slice(), "reference snapshot has no HEAD"),
            (b"state_root", "reference snapshot has no state root"),
            (b"ledger.dat", "reference snapshot has no ledger image"),
            (
                b"ready_roots",
                "reference snapshot has no ready root window",
            ),
        ] {
            require(self.files.iter().any(|f| f.path == path), reason)?;
        }
        Ok(())
    }
    pub fn hash(&self) -> Result<[u8; 32]> {
        self.validate()?;
        let mut w = Writer::new();
        w.put_bytes(FORMAT)?;
        w.put_hash32(&self.checkpoint_hash)?;
        w.put_bytes(&self.snapshot_id)?;
        w.put_option(self.irmin_commit.as_ref(), |w, v| w.put_bytes(v))?;
        w.put_u32(self.chunk_size as u32)?;
        w.put_u64(self.total_size as u64)?;
        w.put_u32(self.file_count as u32)?;
        w.put_u32(self.chunk_count as u32)?;
        w.put_hash32(&self.chunks_root)?;
        w.put_list(&self.files, |w, f| {
            w.put_bytes(&f.path)?;
            w.put_u64(f.size as u64)?;
            w.put_hash32(&f.sha256)?;
            w.put_u32(f.chunks.len() as u32)?;
            for c in &f.chunks {
                put_chunk(w, &f.path, c)?;
            }
            Ok(())
        })?;
        Ok(network::domain_hash(
            b"octra:state_sync_manifest",
            &w.into_bytes(),
        ))
    }
}
impl Draft {
    fn common(doc: &Document, value: &Value) -> Result<Self> {
        Ok(Self {
            checkpoint: checkpoint::Body::parse(doc, field(doc, value, b"checkpoint")?)?,
            checkpoint_hash: text(field(doc, value, b"checkpoint_hash")?)?,
            manifest: Body::parse(doc, field(doc, value, b"manifest")?)?,
            manifest_hash: text(field(doc, value, b"manifest_hash")?)?,
        })
    }
    pub fn parse(doc: &Document, value: &Value) -> Result<Self> {
        fields(
            value,
            &[
                b"version",
                b"checkpoint",
                b"checkpoint_hash",
                b"manifest",
                b"manifest_hash",
            ],
            "draft",
        )?;
        require(
            text(field(doc, value, b"version")?)? == FORMAT,
            "unsupported draft format",
        )?;
        Self::common(doc, value)
    }
    pub fn verify(&self) -> Result<()> {
        let hash = hex::encode(self.checkpoint.hash()?);
        require(
            hash.as_bytes() == self.checkpoint_hash,
            "checkpoint hash mismatch",
        )?;
        require(
            hash.as_bytes() == self.manifest.checkpoint_hash,
            "manifest checkpoint binding mismatch",
        )?;
        require(
            hex::encode(self.manifest.hash()?).as_bytes() == self.manifest_hash,
            "manifest hash mismatch",
        )
    }
}
fn signatures(doc: &Document, value: &Value) -> Result<Vec<Signature>> {
    let values = list(doc, value)?;
    require(values.len() <= 1024, "signature count exceeds limit")?;
    values
        .into_iter()
        .map(|v| Signature::parse(doc, v))
        .collect()
}
impl Certificate {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        require(raw.len() <= MANIFEST_LIMIT, "manifest exceeds size limit")?;
        let doc = Document::parse(raw).map_err(|e| super::Error::from(e.to_string()))?;
        let value = doc.root();
        require(
            matches!(value, Value::Object(_)),
            "certificate must be an object",
        )?;
        require(
            text(field(&doc, value, b"version")?)? == FORMAT,
            "unsupported certificate format",
        )?;
        let finalized = doc.field(value, b"finality").is_some();
        if finalized {
            fields(
                value,
                &[
                    b"version",
                    b"checkpoint",
                    b"checkpoint_hash",
                    b"finality",
                    b"manifest",
                    b"manifest_hash",
                    b"exporter_signatures",
                ],
                "certificate",
            )?;
        } else {
            fields(
                value,
                &[
                    b"version",
                    b"checkpoint",
                    b"checkpoint_hash",
                    b"checkpoint_signatures",
                    b"manifest",
                    b"manifest_hash",
                    b"exporter_signature",
                ],
                "certificate",
            )?;
        }
        let checkpoint = checkpoint::Body::parse(&doc, field(&doc, value, b"checkpoint")?)?;
        let checkpoint_hash = text(field(&doc, value, b"checkpoint_hash")?)?;
        let authority = if finalized {
            Authority::Finalized(text(field(&doc, value, b"finality")?)?)
        } else {
            Authority::CheckpointQuorum(signatures(
                &doc,
                field(&doc, value, b"checkpoint_signatures")?,
            )?)
        };
        let manifest = Body::parse(&doc, field(&doc, value, b"manifest")?)?;
        let manifest_hash = text(field(&doc, value, b"manifest_hash")?)?;
        let exporters = if finalized {
            signatures(&doc, field(&doc, value, b"exporter_signatures")?)?
        } else {
            vec![Signature::parse(
                &doc,
                field(&doc, value, b"exporter_signature")?,
            )?]
        };
        Ok(Self {
            draft: Draft {
                checkpoint,
                checkpoint_hash,
                manifest,
                manifest_hash,
            },
            authority,
            exporters,
        })
    }
    pub fn fresh(&self, now: i64) -> bool {
        now.wrapping_add(300) >= self.draft.checkpoint.created_at
            && now <= self.draft.checkpoint.valid_until
    }
}
pub fn validate_signers(set: &ValidatorSet) -> Result<()> {
    require(set.n >= 1, "empty signer set")?;
    require(
        set.validators
            .windows(2)
            .all(|w| w[0].address < w[1].address),
        "duplicate signer address",
    )?;
    for validator in &set.validators {
        checkpoint::raw_pubkey(&validator.pubkey)?;
        require(
            transaction::address_from_public_key(&validator.pubkey) == validator.address,
            "signer address does not match public key",
        )?;
    }
    Ok(())
}
pub fn signer_set(entries: &[Vec<u8>]) -> Result<ValidatorSet> {
    let mut validators = Vec::with_capacity(entries.len());
    for entry in entries {
        let parts = crate::network::endpoint::native_trim(entry)
            .split(|b| *b == b':')
            .collect::<Vec<_>>();
        require(
            parts.len() == 2 && !parts[0].is_empty() && !parts[1].is_empty(),
            "invalid signer entry",
        )?;
        validators.push(Validator {
            address: parts[0].to_vec(),
            pubkey: parts[1].to_vec(),
        });
    }
    let set = ValidatorSet::unweighted(validators);
    validate_signers(&set)?;
    Ok(set)
}
pub fn set_hash(set: &ValidatorSet) -> Result<Vec<u8>> {
    Ok(hex::encode(hash::validator_set_hash(set)?).into_bytes())
}
pub fn verify_exporters(
    set: &ValidatorSet,
    required: usize,
    message: &[u8],
    signatures: &[Signature],
) -> Result<()> {
    require(
        signatures.windows(2).all(|w| w[0].signer < w[1].signer),
        "exporter signatures are not ordered",
    )?;
    require(
        signatures.len() >= required,
        "exporter signature threshold missing",
    )?;
    for signature in signatures {
        checkpoint::verify_signature(set, message, signature)?;
    }
    Ok(())
}
