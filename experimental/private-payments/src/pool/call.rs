//! Typed public call transcript, reconstructed by the immutable Circle before
//! verification. Proof bytes and operator identity are intentionally excluded.
use super::{envelope, Domain, Statement};
use anyhow::{ensure, Result};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Call {
    /// Random, privately signed invoice commitment, or zero for a withdrawal.
    pub quote: [u8; 32],
    pub valid_from_ms: u64,
    pub expires_ms: u64,
    pub payout: [u8; 47],
    pub deposit_ou: u64,
    pub withdraw_ou: u64,
    pub boxes: [String; 2],
}

fn hex(raw: &[u8]) -> String {
    raw.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn address(raw: &[u8; 47]) -> Result<&str> {
    ensure!(
        raw.starts_with(b"oct")
            && raw[3..]
                .iter()
                .all(|c| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(c)),
        "invalid Octra address"
    );
    Ok(std::str::from_utf8(raw)?)
}

impl Call {
    /// The relayer's native address is bound to prevent copying a proof into a
    /// different call. It need not be the private note owner's wallet address.
    pub fn context(
        &self,
        chain: &[u8; 32],
        circle: &[u8; 47],
        relayer: &[u8; 47],
    ) -> Result<[u8; 32]> {
        ensure!(
            self.valid_from_ms < self.expires_ms
                && self.expires_ms <= i64::MAX as u64
                && self.expires_ms - self.valid_from_ms <= 86_400_000,
            "invalid pool validity window"
        );
        ensure!(
            self.deposit_ou <= i64::MAX as u64 && self.withdraw_ou <= i64::MAX as u64,
            "invalid pool value flow"
        );
        for box_ in &self.boxes {
            if !box_.is_empty() {
                envelope::validate(box_)?;
            }
        }
        let circle = address(circle)?;
        let payout = address(&self.payout)?;
        let relayer = address(relayer)?;
        Ok(Sha256::digest(format!(
            "Octranet shielded call v2|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
            hex(chain),
            circle,
            relayer,
            hex(&self.quote),
            self.valid_from_ms,
            self.expires_ms,
            self.deposit_ou,
            self.withdraw_ou,
            payout,
            self.boxes[0],
            self.boxes[1]
        ))
        .into())
    }

    /// Preflight only. The Circle must repeat these checks against its own
    /// state/time and run the native proof before atomically moving any OCT.
    pub fn validate(
        &self,
        statement: &Statement,
        chain: &[u8; 32],
        circle: &[u8; 47],
        relayer: &[u8; 47],
        now_ms: u64,
    ) -> Result<()> {
        ensure!(
            statement.domain == Domain::new(chain, circle)?
                && statement.context == self.context(chain, circle, relayer)?
                && statement.deposit == self.deposit_ou
                && statement.withdraw == self.withdraw_ou,
            "pool call context differs"
        );
        ensure!(
            now_ms >= self.valid_from_ms && now_ms < self.expires_ms,
            "pool call expired or premature"
        );
        for (commitment, box_) in statement.outputs.iter().zip(&self.boxes) {
            use ark_ff::Zero;
            ensure!(
                commitment.is_zero() == box_.is_empty(),
                "private note box/output mismatch"
            );
        }
        Ok(())
    }
}
