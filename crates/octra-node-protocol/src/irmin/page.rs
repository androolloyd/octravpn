//! Canonical native inode preimages. This is not Irmin's pack compression wire.
// Derived from Irmin (ISC); attribution and license in LICENSE-IRMIN.
use super::{digest, step_hash, string, unique, varint, Entry, Hash, Kind, MaxDepth};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Page {
    Values(Vec<Entry>),
    Branch {
        depth: usize,
        length: usize,
        children: Vec<(u8, Hash)>,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("invalid native inode page: {0}")]
pub struct Error(pub &'static str);

impl Page {
    pub fn encode(&self) -> Result<Vec<u8>, Error> {
        let mut out = Vec::new();
        match self {
            Self::Values(entries) => {
                if entries.is_empty()
                    || entries.len() > 32
                    || !entries.windows(2).all(|w| w[0].name < w[1].name)
                {
                    return Err(Error("values order or length"));
                }
                out.push(0);
                varint(&mut out, entries.len());
                for entry in entries {
                    string(&mut out, &entry.name);
                    out.push(u8::from(entry.kind == Kind::Contents));
                    out.extend_from_slice(&entry.hash);
                }
            }
            Self::Branch {
                depth,
                length,
                children,
            } => {
                if *depth >= 10
                    || *length <= 32
                    || children.is_empty()
                    || children.len() > 32
                    || children.iter().any(|(slot, _)| *slot >= 32)
                    || !children.windows(2).all(|w| w[0].0 < w[1].0)
                {
                    return Err(Error("branch order, depth or length"));
                }
                out.push(1);
                varint(&mut out, *depth);
                varint(&mut out, *length);
                varint(&mut out, children.len());
                for (slot, hash) in children {
                    varint(&mut out, usize::from(*slot));
                    out.extend_from_slice(hash);
                }
            }
        }
        Ok(out)
    }

    pub fn hash(&self) -> Result<Hash, Error> {
        Ok(digest(&self.encode()?))
    }

    pub fn children(&self) -> Vec<Hash> {
        match self {
            Self::Values(entries) => entries.iter().map(|entry| entry.hash).collect(),
            Self::Branch { children, .. } => children.iter().map(|(_, hash)| *hash).collect(),
        }
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        let mut reader = Reader { bytes, position: 0 };
        let page = match reader.byte()? {
            0 => {
                let length = reader.number()?;
                if !(1..=32).contains(&length) {
                    return Err(Error("values length"));
                }
                let mut entries = Vec::with_capacity(length);
                for _ in 0..length {
                    let length = reader.number()?;
                    let name = reader.take(length)?.to_vec();
                    let kind = match reader.byte()? {
                        0 => Kind::Node,
                        1 => Kind::Contents,
                        _ => return Err(Error("child kind")),
                    };
                    let hash = reader
                        .take(64)?
                        .try_into()
                        .map_err(|_| Error("hash size"))?;
                    entries.push(Entry { name, kind, hash });
                }
                Self::Values(entries)
            }
            1 => {
                let depth = reader.number()?;
                let length = reader.number()?;
                let count = reader.number()?;
                if count == 0 || count > 32 {
                    return Err(Error("branch count"));
                }
                let mut children = Vec::with_capacity(count);
                for _ in 0..count {
                    let slot = u8::try_from(reader.number()?).map_err(|_| Error("branch slot"))?;
                    let hash = reader
                        .take(64)?
                        .try_into()
                        .map_err(|_| Error("hash size"))?;
                    children.push((slot, hash));
                }
                Self::Branch {
                    depth,
                    length,
                    children,
                }
            }
            _ => return Err(Error("page tag")),
        };
        if reader.position != bytes.len() || page.encode()?.as_slice() != bytes {
            return Err(Error("noncanonical page"));
        }
        Ok(page)
    }
}

struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
}
impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8], Error> {
        let end = self
            .position
            .checked_add(count)
            .ok_or(Error("length overflow"))?;
        let bytes = self
            .bytes
            .get(self.position..end)
            .ok_or(Error("truncated page"))?;
        self.position = end;
        Ok(bytes)
    }
    fn byte(&mut self) -> Result<u8, Error> {
        Ok(self.take(1)?[0])
    }
    fn number(&mut self) -> Result<usize, Error> {
        let mut value = 0usize;
        let mut shift = 0u32;
        loop {
            let byte = self.byte()?;
            let part = usize::from(byte & 127);
            if shift >= usize::BITS || part > (usize::MAX >> shift) {
                return Err(Error("integer overflow"));
            }
            value |= part << shift;
            if byte < 128 {
                return Ok(value);
            }
            shift += 7;
        }
    }
}

/// Native hash-bit routing for a branch at this depth.
pub fn slot(name: &[u8], depth: usize) -> Result<u8, Error> {
    if depth >= 10 {
        return Err(Error("maximum depth"));
    }
    let hash = step_hash(name);
    let bit = depth * 5;
    let word = u16::from_be_bytes([hash[bit / 8], hash[bit / 8 + 1]]);
    Ok(((word >> (11 - bit % 8)) & 31) as u8)
}

/// Children precede parents. Small logical roots use native N commitments and
/// have no inode pages; callers retain their existing flat representation.
pub fn directory(entries: &[Entry]) -> Result<Vec<(Hash, Page)>, MaxDepth> {
    let entries = unique(entries).into_values().cloned().collect::<Vec<_>>();
    if entries.len() <= 256 {
        return Ok(Vec::new());
    }
    let mut pages = Vec::new();
    build(entries, 0, &mut pages)?;
    Ok(pages)
}
fn build(
    entries: Vec<Entry>,
    depth: usize,
    pages: &mut Vec<(Hash, Page)>,
) -> Result<Hash, MaxDepth> {
    let page = if entries.len() <= 32 {
        Page::Values(entries)
    } else {
        if depth >= 10 {
            return Err(MaxDepth(depth));
        }
        let length = entries.len();
        let mut groups: [Vec<Entry>; 32] = std::array::from_fn(|_| Vec::new());
        for entry in entries {
            let index = slot(&entry.name, depth).expect("bounded native inode depth");
            groups[usize::from(index)].push(entry);
        }
        let mut children = Vec::new();
        for (index, group) in groups.into_iter().enumerate() {
            if !group.is_empty() {
                children.push((index as u8, build(group, depth + 1, pages)?));
            }
        }
        Page::Branch {
            depth,
            length,
            children,
        }
    };
    let hash = page.hash().expect("native constructed canonical page");
    pages.push((hash, page));
    Ok(hash)
}

#[cfg(test)]
mod tests;
