// Derived from Irmin proof.ml and repr binary.ml (ISC); see LICENSE-IRMIN.
//! Flat parsing avoids recursive allocation/drop on untrusted proof depth.
use super::{Error, Hash, Key, Kind, Result};

pub(super) enum Part {
    Pending,
    Contents(Vec<u8>),
    BlindedContents(Hash),
    BlindedNode(Hash),
    Node(Vec<(Vec<u8>, usize)>),
    BlindedInode {
        hash: Hash,
        depth: usize,
    },
    Values {
        depth: usize,
        children: Vec<(Vec<u8>, usize)>,
    },
    Inode {
        root: bool,
        depth: usize,
        length: i64,
        children: Vec<(usize, usize)>,
    },
    Extender {
        root: bool,
        depth: usize,
        length: i64,
        segments: Vec<usize>,
        child: usize,
    },
}
pub(super) struct Proof {
    pub before: Key,
    pub after: Key,
    pub parts: Vec<Part>,
    pub order: Vec<usize>,
}
enum Work {
    Part {
        id: usize,
        inode: bool,
        depth: usize,
    },
    Names {
        id: usize,
        count: usize,
    },
    Indices {
        id: usize,
        count: usize,
        depth: usize,
    },
    Finish(usize),
}
struct Cursor<'a> {
    raw: &'a [u8],
    at: usize,
}
fn bounds() -> Error {
    "invalid proof encoding: index out of bounds".into()
}
impl Cursor<'_> {
    fn byte(&mut self) -> Result<u8> {
        let value = *self.raw.get(self.at).ok_or_else(bounds)?;
        self.at += 1;
        Ok(value)
    }
    fn int(&mut self) -> Result<i64> {
        let mut value = 0_u64;
        let mut shift = 0_u32;
        loop {
            let byte = self.byte()?;
            value = value.wrapping_add(u64::from(byte & 127).wrapping_shl(shift))
                & 0x7fff_ffff_ffff_ffff;
            if byte < 128 {
                return Ok(((value << 1) as i64) >> 1);
            }
            shift = shift.wrapping_add(7);
        }
    }
    fn count(&mut self) -> Result<usize> {
        let n = self.int()?;
        if n < 0 || n as usize > self.raw.len() - self.at {
            return Err(bounds());
        }
        Ok(n as usize)
    }
    fn bytes(&mut self, n: usize) -> Result<Vec<u8>> {
        let end = self
            .at
            .checked_add(n)
            .filter(|end| *end <= self.raw.len())
            .ok_or("invalid proof encoding: String.blit / Bytes.blit_string")?;
        let bytes = self.raw[self.at..end].to_vec();
        self.at = end;
        Ok(bytes)
    }
    fn string(&mut self) -> Result<Vec<u8>> {
        let n = self.int()?;
        if n < 0 {
            return Err("invalid proof encoding: String.blit / Bytes.blit_string".into());
        }
        self.bytes(n as usize)
    }
    fn hash(&mut self) -> Result<Hash> {
        Ok(self.bytes(64)?.try_into().expect("hash width"))
    }
    fn key(&mut self) -> Result<Key> {
        let kind = match self.int()? {
            0 => Kind::Contents,
            1 => Kind::Node,
            _ => return Err(bounds()),
        };
        Ok(Key {
            kind,
            hash: self.hash()?,
        })
    }
}
impl Proof {
    pub(super) fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Cursor { raw, at: 0 };
        let before = r.key()?;
        let after = r.key()?;
        let mut out = Self {
            before,
            after,
            parts: vec![Part::Pending],
            order: Vec::new(),
        };
        let mut work = vec![Work::Part {
            id: 0,
            inode: false,
            depth: 0,
        }];
        while let Some(task) = work.pop() {
            match task {
                Work::Finish(id) => out.order.push(id),
                Work::Names { id, count } => {
                    if count == 0 {
                        continue;
                    }
                    let name = r.string()?;
                    let child = out.parts.len();
                    out.parts.push(Part::Pending);
                    match &mut out.parts[id] {
                        Part::Node(children) | Part::Values { children, .. } => {
                            children.push((name, child));
                        }
                        _ => unreachable!(),
                    }
                    work.push(Work::Names {
                        id,
                        count: count - 1,
                    });
                    work.push(Work::Part {
                        id: child,
                        inode: false,
                        depth: 0,
                    });
                }
                Work::Indices { id, count, depth } => {
                    if count == 0 {
                        continue;
                    }
                    let index = r.int()?;
                    if !(0..32).contains(&index) {
                        return Err(bounds());
                    }
                    let child = out.parts.len();
                    out.parts.push(Part::Pending);
                    let Part::Inode { children, .. } = &mut out.parts[id] else {
                        unreachable!()
                    };
                    children.push((index as usize, child));
                    work.push(Work::Indices {
                        id,
                        count: count - 1,
                        depth,
                    });
                    work.push(Work::Part {
                        id: child,
                        inode: true,
                        depth,
                    });
                }
                Work::Part { id, inode, depth } => {
                    let tag = r.int()?;
                    work.push(Work::Finish(id));
                    out.parts[id] = match (inode, tag) {
                        (false, 0) => Part::Contents(r.string()?),
                        (false, 1) => Part::BlindedContents(r.hash()?),
                        (false, 3) => Part::BlindedNode(r.hash()?),
                        (true, 0) => Part::BlindedInode {
                            hash: r.hash()?,
                            depth,
                        },
                        (false, 2) | (true, 1) => {
                            let count = r.count()?;
                            work.push(Work::Names { id, count });
                            if inode {
                                Part::Values {
                                    depth,
                                    children: Vec::new(),
                                }
                            } else {
                                Part::Node(Vec::new())
                            }
                        }
                        (false, 4) | (true, 2) => {
                            let length = r.int()?;
                            let count = r.count()?;
                            work.push(Work::Indices {
                                id,
                                count,
                                depth: depth.checked_add(1).ok_or_else(bounds)?,
                            });
                            Part::Inode {
                                root: !inode,
                                depth,
                                length,
                                children: Vec::new(),
                            }
                        }
                        (false, 5) | (true, 3) => {
                            let length = r.int()?;
                            let count = r.count()?;
                            let mut segments = Vec::new();
                            for _ in 0..count {
                                let index = r.int()?;
                                if !(0..32).contains(&index) {
                                    return Err(bounds());
                                }
                                segments.push(index as usize);
                            }
                            let child = out.parts.len();
                            out.parts.push(Part::Pending);
                            work.push(Work::Part {
                                id: child,
                                inode: true,
                                depth: depth.checked_add(count).ok_or_else(bounds)?,
                            });
                            Part::Extender {
                                root: !inode,
                                depth,
                                length,
                                segments,
                                child,
                            }
                        }
                        _ => return Err(bounds()),
                    };
                }
            }
        }
        if r.at != raw.len() {
            return Err(
                "File \"src/repr/type_binary.ml\", line 379, characters 2-8: Assertion failed"
                    .into(),
            );
        }
        Ok(out)
    }
}
