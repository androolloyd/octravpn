//! Complete, bounded subtrees authenticated at fixed application paths. The
//! assembled projection is never presented as a canonical ledger snapshot.
use super::{MAX_BYTES, MAX_PART};
use crate::vpn::payments::shielded::Pool;
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{
    epoch_index,
    irmin::proof,
    oce1::{Reader, Writer},
};
use octra_node_runtime::{
    canonical::Head,
    ledger_image,
    state_batch::{Snapshot, StateBatch},
};

struct Part {
    proof: Vec<u8>,
    image: Option<Vec<u8>>,
}
pub(super) struct Image {
    ledger: Vec<u8>,
    index: Vec<u8>,
    parts: Vec<Part>,
}
fn paths(source: &Pool) -> Vec<Vec<Vec<u8>>> {
    let mut paths = vec![
        vec![b"meta".to_vec()],
        vec![b"accounts".to_vec(), source.address.to_vec()],
        vec![
            b"accounts".to_vec(),
            source.directory.config.program.as_bytes().to_vec(),
        ],
    ];
    for circle in [
        &source.directory.config.program,
        &source.directory.config.factory,
        &source.config.circle,
        &source.config.factory,
    ] {
        paths.push(vec![b"circles".to_vec(), circle.as_bytes().to_vec()]);
    }
    paths.sort();
    paths.dedup();
    paths
}
fn limits() -> ledger_image::Limits {
    ledger_image::Limits {
        bytes: MAX_PART as u64,
        records: 262_144,
        string_bytes: 4 * 1024 * 1024,
    }
}
impl Image {
    #[cfg(test)]
    pub(super) fn corrupt(&mut self) {
        let image = self
            .parts
            .iter_mut()
            .find_map(|part| part.image.as_mut())
            .unwrap();
        image[0] ^= 1;
    }
    pub(super) async fn at(source: &Pool, head: &Head) -> Result<Self> {
        let mut parts = Vec::new();
        for path in paths(source) {
            let path: Vec<_> = path.iter().map(Vec::as_slice).collect();
            let selected = source
                .directory
                .history
                .read_tree_at(head, &path, MAX_PART)
                .await?;
            let proof = STANDARD.encode(selected.proof).into_bytes();
            ensure!(proof.len() <= MAX_PART, "portable path proof exceeds limit");
            let image = selected
                .tree
                .map(|subtree| {
                    let mut image = Vec::new();
                    ledger_image::write(&subtree, &mut image, limits())?;
                    Ok::<_, anyhow::Error>(image)
                })
                .transpose()?;
            parts.push(Part { proof, image });
            ensure!(
                parts
                    .iter()
                    .map(|p| p.proof.len() + p.image.as_ref().map_or(0, Vec::len))
                    .sum::<usize>()
                    <= MAX_BYTES,
                "portable projection exceeds limit"
            );
        }
        Ok(Self {
            ledger: head.ledger_root.as_bytes().to_vec(),
            index: head.index_root.as_bytes().to_vec(),
            parts,
        })
    }
    pub(super) fn restore(&self, source: &Pool, expected: &[u8]) -> Result<Snapshot> {
        ensure!(
            epoch_index::folded_state_root(&self.ledger, &self.index)?.as_slice() == expected,
            "portable state-root fold differs"
        );
        let paths = paths(source);
        ensure!(
            paths.len() == self.parts.len(),
            "portable projection paths differ"
        );
        let mut state = StateBatch::default();
        state.begin()?;
        for (path, part) in paths.iter().zip(&self.parts) {
            let path: Vec<_> = path.iter().map(Vec::as_slice).collect();
            match (
                proof::verify_tree(&self.ledger, &path, &part.proof)?,
                &part.image,
            ) {
                (None, None) => {}
                (Some(root), Some(image)) => {
                    let restored = ledger_image::restore(
                        image.as_slice(),
                        image.len() as u64,
                        &hex::encode(root),
                        limits(),
                    )?;
                    state.graft(&path, &restored.state)?;
                }
                _ => anyhow::bail!("portable subtree presence differs"),
            }
        }
        Ok(state.snapshot())
    }
    pub(super) fn put(&self, out: &mut Writer) -> Result<()> {
        out.put_bytes(&self.ledger)?;
        out.put_bytes(&self.index)?;
        out.put_u32(self.parts.len().try_into()?)?;
        for part in &self.parts {
            out.put_bytes(&part.proof)?;
            out.put_bool(part.image.is_some())?;
            if let Some(image) = &part.image {
                out.put_bytes(image)?;
            }
        }
        Ok(())
    }
    pub(super) fn get(input: &mut Reader<'_>) -> Result<Self> {
        let ledger = input.get_bytes_bounded(128)?.to_vec();
        let index = input.get_bytes_bounded(64)?.to_vec();
        let count = input.get_u32()?;
        ensure!(
            (1..=7).contains(&count),
            "portable projection count differs"
        );
        let mut parts = Vec::new();
        for _ in 0..count {
            let proof = input.get_bytes_bounded(MAX_PART)?.to_vec();
            let image = if input.get_bool()? {
                Some(input.get_bytes_bounded(MAX_PART)?.to_vec())
            } else {
                None
            };
            parts.push(Part { proof, image });
        }
        ensure!(
            parts
                .iter()
                .map(|p| p.proof.len() + p.image.as_ref().map_or(0, Vec::len))
                .sum::<usize>()
                <= MAX_BYTES,
            "portable projection exceeds limit"
        );
        Ok(Self {
            ledger,
            index,
            parts,
        })
    }
}
