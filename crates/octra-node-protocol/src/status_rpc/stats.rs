use super::{head_fields, Head};
use crate::{
    light_rpc::json::{array, number, object, string},
    metrics::format_balance,
    oce1::Error,
};
use num_bigint::BigInt;
use num_traits::ToPrimitive;
pub struct Stats<'a> {
    pub current_epoch: i64,
    pub total_accounts: i64,
    pub active_accounts: i64,
    pub true_total: &'a BigInt,
    pub encrypted: &'a BigInt,
    pub max_supply: &'a BigInt,
    pub total_confirmed: i64,
    pub staging: i64,
    pub recent_tx_count: i64,
    pub latest_epochs: &'a [i64],
    pub head: Option<&'a Head<'a>>,
}
impl Stats<'_> {
    pub fn to_json(&self) -> Result<Vec<u8>, Error> {
        let supply = self.true_total + self.encrypted;
        let remaining = self.max_supply - &supply;
        let pct = supply.to_f64().ok_or("supply float unavailable")?
            / self.max_supply.to_f64().ok_or("supply float unavailable")?
            * 100.;
        let pct = crate::transaction::native_float(pct)
            .map_err(|e| Error::from(e.to_string()))?
            .into_bytes();
        let mut fields = vec![
            ("current_epoch", number(self.current_epoch)),
            ("total_accounts", number(self.total_accounts)),
            ("active_accounts", number(self.active_accounts)),
            ("total_supply", string(format_balance(&supply))),
            ("total_supply_raw", string(supply.to_string())),
            ("circulating_supply", string(format_balance(&supply))),
            ("circulating_supply_raw", string(supply.to_string())),
            ("encrypted_supply", string(format_balance(self.encrypted))),
            ("encrypted_supply_raw", string(self.encrypted.to_string())),
            ("max_supply", string(format_balance(self.max_supply))),
            ("max_supply_raw", string(self.max_supply.to_string())),
            ("supply_remaining", string(format_balance(&remaining))),
            ("supply_pct", pct.clone()),
            ("circulating_pct", pct),
            (
                "total_transactions",
                number(
                    self.total_confirmed
                        .wrapping_add(self.staging)
                        .wrapping_shl(1)
                        >> 1,
                ),
            ),
            ("recent_tx_count", number(self.recent_tx_count)),
            ("staging_size", number(self.staging)),
            (
                "latest_epochs",
                array(self.latest_epochs.iter().map(number)),
            ),
        ];
        fields.extend(head_fields(self.head));
        Ok(object(&fields))
    }
}
