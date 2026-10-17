//! Native Fhe_image boundary: only immutable serialized bytes and metadata cross
//! the process boundary. Expanded matrices and proof/cipher graphs stay inside.
use super::{
    call,
    tasks::{Request, Response},
    Error,
};
use octra_hfhe::{cipher::Shape, keys::PublicKey};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct Sampling {
    pub m_bits: i32,
    pub n_bits: i32,
    pub x_col_weight: i32,
    pub error_weight: i32,
    pub basis: i32,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Key {
    #[serde(with = "super::tasks::arc_bytes")]
    raw: Arc<[u8]>,
    sampling: Sampling,
    words: Option<u64>,
    size: Option<u64>,
}
impl Key {
    /// Trusted already-expanded host material, never an untrusted decoder.
    pub fn from_public_key(key: &PublicKey) -> Result<Self, octra_hfhe::Error> {
        let p = key.params();
        Ok(Self {
            raw: key.to_bytes()?.into(),
            sampling: Sampling {
                m_bits: p.m_bits,
                n_bits: p.n_bits,
                x_col_weight: p.x_col_weight,
                error_weight: p.error_weight,
                basis: p.basis,
            },
            words: key.bit_words().ok(),
            size: key.image_size().ok(),
        })
    }
    pub(crate) fn read(raw: &[u8], registry: bool) -> Result<Self, Error> {
        match call(Request::Key {
            raw: raw.to_vec(),
            registry,
        })? {
            Response::Key(key) => Ok(key),
            _ => Err(Error::Unavailable("crypto key response differs".into())),
        }
    }
    pub(crate) fn bytes(&self) -> &Arc<[u8]> {
        &self.raw
    }
    pub(crate) fn params(&self) -> &Sampling {
        &self.sampling
    }
    pub(crate) fn bit_words(&self) -> Result<u64, octra_hfhe::Error> {
        self.words.ok_or(octra_hfhe::Error("fhe key words"))
    }
    pub(crate) fn image_size(&self) -> Result<u64, octra_hfhe::Error> {
        self.size.ok_or(octra_hfhe::Error("fhe key size"))
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Cipher {
    #[serde(with = "super::tasks::arc_bytes")]
    raw: Arc<[u8]>,
    shape: Option<[usize; 5]>,
    words: Option<u64>,
}
impl Cipher {
    pub(crate) fn from_value(
        cipher: &octra_hfhe::cipher::Cipher,
    ) -> Result<Self, octra_hfhe::Error> {
        Ok(Self {
            raw: cipher.to_bytes()?.into(),
            shape: cipher
                .shape()
                .ok()
                .map(|s| [s.slots, s.constants, s.layers, s.base_layers, s.edges]),
            words: cipher.bit_words().ok(),
        })
    }
    pub(crate) fn read(raw: &[u8], strict: bool, cap: bool) -> Result<Self, Error> {
        match call(Request::Cipher {
            raw: raw.to_vec(),
            strict,
            cap,
        })? {
            Response::Cipher(cipher) => Ok(cipher),
            _ => Err(Error::Unavailable("crypto cipher response differs".into())),
        }
    }
    pub(crate) fn bytes(&self) -> &Arc<[u8]> {
        &self.raw
    }
    pub(crate) fn slots(&self) -> usize {
        self.shape.map_or(0, |s| s[0])
    }
    pub(crate) fn shape(&self) -> Result<Shape, octra_hfhe::Error> {
        self.shape
            .map(|s| Shape {
                slots: s[0],
                constants: s[1],
                layers: s[2],
                base_layers: s[3],
                edges: s[4],
            })
            .ok_or(octra_hfhe::Error("fhe cipher shape"))
    }
    pub(crate) fn bit_words(&self) -> Result<u64, octra_hfhe::Error> {
        self.words.ok_or(octra_hfhe::Error("fhe cipher words"))
    }
}
