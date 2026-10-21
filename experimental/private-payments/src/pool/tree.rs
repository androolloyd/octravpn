//! An off-chain index; these paths are witnesses, never payment authority.
use super::hash;
use anyhow::{ensure, Result};
use ark_bn254::Fr;
use ark_ff::{BigInt, BigInteger, Zero};
use std::collections::BTreeMap;

pub(super) type Index = BigInt<4>;

#[derive(Clone)]
pub(super) struct Tree {
    depth: usize,
    tag: u64,
    defaults: Vec<Fr>,
    nodes: BTreeMap<(usize, Index), Fr>,
}

impl Tree {
    pub(super) fn new(depth: usize, tag: u64) -> Self {
        let mut defaults = vec![Fr::zero()];
        for height in 0..depth {
            defaults.push(hash::pair(
                tag + height as u64,
                defaults[height],
                defaults[height],
            ));
        }
        Self {
            depth,
            tag,
            defaults,
            nodes: BTreeMap::new(),
        }
    }

    fn get(&self, height: usize, index: Index) -> Fr {
        self.nodes
            .get(&(height, index))
            .copied()
            .unwrap_or(self.defaults[height])
    }

    pub(super) fn root(&self) -> Fr {
        self.get(self.depth, Index::zero())
    }

    pub(super) fn leaf(&self, index: Index) -> Fr {
        self.get(0, index)
    }

    pub(super) fn leaves(&self) -> impl Iterator<Item = (Index, Fr)> + '_ {
        self.nodes
            .iter()
            .filter_map(|(&(height, index), &value)| (height == 0).then_some((index, value)))
    }

    pub(super) fn path(&self, mut index: Index) -> Result<Vec<Fr>> {
        ensure!(
            index.num_bits() as usize <= self.depth,
            "tree index exceeds depth"
        );
        Ok((0..self.depth)
            .map(|height| {
                let mut sibling = index;
                sibling.0[0] ^= 1;
                let value = self.get(height, sibling);
                index >>= 1;
                value
            })
            .collect())
    }
    /// Append-only note prefix. Full subtrees before the boundary are immutable;
    /// only the subtree intersecting the boundary needs recursive rebuilding.
    pub(super) fn prefix_path(&self, index: u32, count: u64) -> Result<Vec<Fr>> {
        ensure!(
            self.depth <= 32 && u64::from(index) < count && count <= 1_u64 << self.depth,
            "note prefix bounds differ"
        );
        Ok((0..self.depth)
            .map(|height| self.prefix_node(height, (u64::from(index) >> height) ^ 1, count))
            .collect())
    }
    fn prefix_node(&self, height: usize, node: u64, count: u64) -> Fr {
        let first = node << height;
        if first >= count {
            self.defaults[height]
        } else if first + (1_u64 << height) <= count {
            self.get(height, Index::from(node))
        } else {
            hash::pair(
                self.tag + (height - 1) as u64,
                self.prefix_node(height - 1, node * 2, count),
                self.prefix_node(height - 1, node * 2 + 1, count),
            )
        }
    }

    pub(super) fn insert(&mut self, mut index: Index, mut value: Fr) -> Result<()> {
        ensure!(self.leaf(index).is_zero(), "tree leaf already occupied");
        let path = self.path(index)?;
        self.nodes.insert((0, index), value);
        for (height, sibling) in path.into_iter().enumerate() {
            value = if index.get_bit(0) {
                hash::pair(self.tag + height as u64, sibling, value)
            } else {
                hash::pair(self.tag + height as u64, value, sibling)
            };
            index >>= 1;
            self.nodes.insert((height + 1, index), value);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn every_append_prefix_path_matches_its_original_root() {
        let mut tree = Tree::new(5, hash::NOTE_TREE);
        let mut snapshots = Vec::new();
        for index in 0_u32..32 {
            tree.insert(
                Index::from(u64::from(index)),
                Fr::from(u64::from(index) + 1),
            )
            .unwrap();
            snapshots.push(tree.clone());
        }
        for count in 1_u64..=32 {
            for index in 0..u32::try_from(count).unwrap() {
                let path = tree.prefix_path(index, count).unwrap();
                let original = &snapshots[usize::try_from(count - 1).unwrap()];
                assert_eq!(path, original.path(Index::from(u64::from(index))).unwrap());
                let mut root = Fr::from(u64::from(index) + 1);
                for (height, sibling) in path.into_iter().enumerate() {
                    root = if (u64::from(index) >> height) & 1 == 0 {
                        hash::pair(hash::NOTE_TREE + height as u64, root, sibling)
                    } else {
                        hash::pair(hash::NOTE_TREE + height as u64, sibling, root)
                    };
                }
                assert_eq!(root, original.root());
            }
        }
        assert!(tree.prefix_path(0, 0).is_err());
        assert!(tree.prefix_path(5, 5).is_err());
        assert!(tree.prefix_path(0, 33).is_err());
    }
}
