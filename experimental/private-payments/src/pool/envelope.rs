//! Fixed-size, wallet-compatible amount/rho encryption. Receiving a valid box
//! alone is not payment: match its note commitment to a finalized pool output.
use super::{context_field, decode_field, encode_field, Domain, Note};
use crate::native_stealth::{self, Amount};
use anyhow::{ensure, Result};
use ark_bn254::Fr;
use ark_ff::Zero;
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use zeroize::Zeroizing;

pub const BOX_LEN: usize = 137;

/// The encrypted note omits its owner and context. The signed private invoice
/// supplies the owner; typed call metadata supplies the context. Both are
/// authenticated when recomputing the finalized public commitment.
pub struct Draft {
    note: Note,
    pub ciphertext: String,
}

impl Draft {
    pub fn new(owner: Fr, value: u64, view_public: &[u8; 32]) -> Result<Self> {
        let note = Note::new(owner, value, &[0; 32])?;
        let mut ephemeral = Zeroizing::new([0_u8; 32]);
        OsRng.try_fill_bytes(&mut *ephemeral)?;
        let shared = native_stealth::shared(&ephemeral, view_public)?;
        let amount = Amount::new(value, encode_field(note.rho));
        let ciphertext = format!(
            "{}.{}",
            STANDARD.encode(native_stealth::view_public(&ephemeral)),
            native_stealth::seal(&shared, &amount)?
        );
        Ok(Self { note, ciphertext })
    }

    pub fn bind(&self, context: &[u8; 32]) -> Note {
        let mut note = self.note.clone();
        note.context = context_field(context);
        note
    }
}

pub fn validate(ciphertext: &str) -> Result<()> {
    ensure!(
        ciphertext.is_ascii() && ciphertext.len() == BOX_LEN && ciphertext.as_bytes()[44] == b'.',
        "invalid private note box"
    );
    let (key, payload) = (&ciphertext[..44], &ciphertext[45..]);
    for (part, size) in [(key, 32), (payload, 68)] {
        let raw = STANDARD.decode(part)?;
        ensure!(
            raw.len() == size && STANDARD.encode(raw) == part,
            "noncanonical private note box"
        );
    }
    Ok(())
}

pub fn open(
    domain: Domain,
    owner: Fr,
    view_secret: &[u8; 32],
    ciphertext: &str,
    context: &[u8; 32],
    commitment: Fr,
) -> Result<Note> {
    validate(ciphertext)?;
    let public: [u8; 32] = STANDARD
        .decode(&ciphertext[..44])?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid ephemeral key"))?;
    let shared = native_stealth::shared(view_secret, &public)?;
    let amount = native_stealth::open(&shared, &ciphertext[45..])?;
    let rho = decode_field(amount.blinding())?;
    ensure!(
        !owner.is_zero()
            && !rho.is_zero()
            && amount.value() > 0
            && amount.value() <= i64::MAX as u64,
        "invalid private note opening"
    );
    let note = Note {
        owner,
        rho,
        value: amount.value(),
        context: context_field(context),
    };
    ensure!(
        note.commitment(domain) == commitment,
        "box does not open the finalized private note"
    );
    Ok(note)
}
