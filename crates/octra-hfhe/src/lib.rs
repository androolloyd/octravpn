//! Pure Rust port of the adopted HFHE/PVAC implementation.
//! Components remain experimental until the complete compatibility gate passes.
mod arithmetic;
pub mod cipher;
mod cipher_wire;
pub mod circuit_prf;
pub mod compression;
pub mod decrypt;
pub mod encrypt;
pub mod field;
mod key_wire;
pub mod keys;
pub mod lpn;
pub mod matrix;
mod product;
pub mod proof;
pub mod recrypt;
pub mod scalar;
pub mod seeded_rng;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("{0}")]
pub struct Error(pub &'static str);

impl Error {
    /// Local resource failure must not become a peer-invalid consensus verdict.
    pub fn is_operational(&self) -> bool {
        matches!(
            self.0,
            "HFHE allocation unavailable"
                | "HFHE entropy unavailable"
                | "HFHE generator cache unavailable"
        )
    }
}
