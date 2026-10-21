//! A private quote binds the actual pool and note owner. Preparation encrypts
//! an operator output; it grants no bytes until a canonical transition is read.
use super::{decode_field, envelope::Draft};
use crate::invoice::{Consent, Settlement, SignedInvoice};
use anyhow::{bail, Result};

pub struct Purchase {
    pub quote: [u8; 32],
    pub circle: [u8; 47],
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub output: Draft,
}

impl Purchase {
    pub fn call(&self, change: Option<&Draft>, payout: [u8; 47]) -> super::call::Call {
        super::call::Call {
            quote: self.quote,
            valid_from_ms: self.valid_from_ms,
            expires_ms: self.expires_ms,
            payout,
            deposit_ou: 0,
            withdraw_ou: 0,
            boxes: [
                self.output.ciphertext.clone(),
                change.map(|d| d.ciphertext.clone()).unwrap_or_default(),
            ],
        }
    }
}

pub fn prepare(invoice: &SignedInvoice, consent: &Consent) -> Result<Purchase> {
    let quote = invoice.verify(consent)?;
    let Settlement::ShieldedPool { circle, note_owner } = &invoice.invoice.settlement else {
        bail!("native-claim invoice cannot authorize a pool purchase");
    };
    let owner = decode_field(note_owner)?;
    Ok(Purchase {
        quote,
        circle: *circle,
        valid_from_ms: invoice.invoice.valid_from_ms,
        expires_ms: invoice.invoice.expires_ms,
        output: Draft::new(
            owner,
            invoice.invoice.amount_ou()?,
            &invoice.invoice.recipient_view_public()?,
        )?,
    })
}
