use super::{
    debit, escrow_funds, funding, operational, read, refused, required, save, BigInt, Host, Ledger,
    Result, StateBatch, Transaction,
};
use octra_node_protocol::resource_compute::{bill::Bill, call::Header};
use std::collections::BTreeSet;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FundingStatus {
    Due(i64),
    Paid(i64),
}
/// Native settlement service boundary. Implementations must decode and verify
/// the selection/session records against pinned origins, check every funding
/// scope with `funded`, then replay the loaded program/model to produce bills.
/// Absence of this service is operational unavailability, never a soft refusal.
pub trait Settlement {
    fn verify(
        &mut self,
        state: &StateBatch,
        epoch: i64,
        funded: &mut dyn FnMut(&Header) -> Result<FundingStatus>,
        raw: &[u8],
    ) -> Result<Vec<Bill>>;
}
pub fn funded(
    state: &StateBatch,
    chain: &[u8],
    epoch: i64,
    header: &Header,
) -> Result<FundingStatus> {
    let id = header.request().id()?;
    let deposit = read(state, &id)?.ok_or_else(|| refused(b"compute deposit missing"))?;
    let terms = deposit.permission().terms();
    deposit.permission().verify(
        chain,
        deposit.opened_epoch(),
        terms.nonce(),
        funding::escrow(),
        header,
        true,
    )?;
    if deposit.returned_epoch().is_some() {
        return Err(refused(b"compute deposit returned"));
    }
    if deposit.paid().is_some() {
        return Ok(FundingStatus::Paid(deposit.opened_epoch()));
    }
    if epoch < deposit.opened_epoch() || epoch > terms.expires_epoch() {
        return Err(refused(b"compute deposit epoch outside window"));
    }
    Ok(FundingStatus::Due(deposit.opened_epoch()))
}
impl Host<'_> {
    pub(super) fn payment(
        &mut self,
        tx: &Transaction,
        ledger: &mut Ledger,
        state: &mut StateBatch,
        raw: &[u8],
    ) -> Result<()> {
        if ledger
            .account(&tx.from)
            .is_none_or(|account| account.balance < tx.ou || tx.nonce != account.nonce.successor())
        {
            return Err(refused(b"compute payment payer balance or nonce differs"));
        }
        let verifier = self
            .verifier
            .as_mut()
            .ok_or_else(|| operational("compute settlement host unavailable"))?;
        let mut check_funding = |header: &Header| funded(state, self.chain, self.epoch, header);
        let bills = verifier.verify(state, self.epoch, &mut check_funding, raw)?;
        let mut seen = BTreeSet::new();
        let mut payments = Vec::new();
        for bill in bills {
            let id = bill.measured().request_id();
            if !seen.insert(id.to_vec()) {
                return Err(refused(b"compute payment repeated request"));
            }
            let deposit = read(state, id)?.ok_or_else(|| refused(b"compute deposit missing"))?;
            if deposit.paid().is_some_and(|(_, root)| root == bill.root()) {
                continue;
            }
            payments.push(deposit.payment(self.chain, self.epoch, &bill)?);
        }
        if payments.is_empty() {
            return Err(refused(b"compute payment has no unpaid work"));
        }
        let amount = payments
            .iter()
            .map(|(deposit, _)| BigInt::from(deposit.permission().terms().amount()))
            .sum::<BigInt>();
        escrow_funds(ledger, &amount)?;
        debit(ledger, tx, &tx.ou)?;
        required(ledger.debit_amount_only(funding::escrow(), &amount))?;
        for (deposit, credits) in payments {
            for (address, amount) in credits {
                required(ledger.credit(&address, &amount, None))?;
            }
            save(state, &deposit)?;
        }
        Ok(())
    }
}
