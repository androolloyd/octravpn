//! Encrypted purchase proposal. Neither a valid invoice nor this envelope is
//! evidence of a debited balance, a canonical claim or paid byte entitlement.
use crate::{
    invoice::{Consent, SignedInvoice},
    native_stealth::{self, Amount},
};
use anyhow::{ensure, Context, Result};
use rand::{rngs::OsRng, RngCore};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Only native output fields belong in a chain transaction. The invoice ID
/// stays in the encrypted control exchange and must not be published on chain.
pub struct Output {
    pub ephemeral_public: [u8; 32],
    pub tag: [u8; 16],
    pub claim_public: [u8; 32],
    pub encrypted_amount: String,
}
pub struct Proposal {
    pub invoice_id: [u8; 32],
    pub output: Output,
}

/// Generate a fresh native ECDH output after exact local consent verification.
/// The ephemeral private key and shared/claim secrets are wiped on return.
pub fn prepare(invoice: &SignedInvoice, consent: &Consent, amount: &Amount) -> Result<Proposal> {
    let invoice_id = invoice.verify(consent)?;
    ensure!(
        matches!(
            invoice.invoice.settlement,
            crate::invoice::Settlement::NativeClaim
        ),
        "pool invoice cannot fund a native claim"
    );
    ensure!(
        amount.value() == invoice.invoice.amount_ou()?,
        "proposal price differs from invoice"
    );
    let mut ephemeral = Zeroizing::new([0_u8; 32]);
    OsRng
        .try_fill_bytes(&mut *ephemeral)
        .context("stealth ephemeral entropy unavailable")?;
    let recipient = invoice.invoice.recipient_view_public()?;
    let shared = native_stealth::shared(&ephemeral, &recipient)?;
    let secret = native_stealth::claim_secret(&shared);
    Ok(Proposal {
        invoice_id,
        output: Output {
            ephemeral_public: native_stealth::view_public(&ephemeral),
            tag: native_stealth::tag(&shared),
            claim_public: native_stealth::claim_public(
                &secret,
                &invoice.invoice.recipient_address()?,
            ),
            encrypted_amount: native_stealth::seal(&shared, amount)?,
        },
    })
}

/// Authenticate and decrypt an offered price at the intended one-time wallet.
/// A separate amount-commitment/proof check and actual finalized payment remain
/// mandatory. No forwarding or claim capability is returned by this function.
pub fn open(
    invoice: &SignedInvoice,
    consent: &Consent,
    proposal: &Proposal,
    view_secret: &[u8; 32],
) -> Result<Amount> {
    let expected = invoice.verify(consent)?;
    ensure!(
        matches!(
            invoice.invoice.settlement,
            crate::invoice::Settlement::NativeClaim
        ),
        "pool invoice cannot authenticate a native claim"
    );
    ensure!(
        bool::from(expected.ct_eq(&proposal.invoice_id)),
        "proposal invoice differs"
    );
    let recipient = invoice.invoice.recipient_view_public()?;
    ensure!(
        bool::from(recipient.ct_eq(&native_stealth::view_public(view_secret))),
        "proposal claimant key differs"
    );
    let shared = native_stealth::shared(view_secret, &proposal.output.ephemeral_public)?;
    ensure!(
        bool::from(native_stealth::tag(&shared).ct_eq(&proposal.output.tag)),
        "proposal tag differs"
    );
    let secret = native_stealth::claim_secret(&shared);
    let claim = native_stealth::claim_public(&secret, &invoice.invoice.recipient_address()?);
    ensure!(
        bool::from(claim.ct_eq(&proposal.output.claim_public)),
        "proposal claim binding differs"
    );
    let amount = native_stealth::open(&shared, &proposal.output.encrypted_amount)?;
    ensure!(
        amount.value() == invoice.invoice.amount_ou()?,
        "proposal price differs from invoice"
    );
    Ok(amount)
}

#[cfg(test)]
mod tests;
