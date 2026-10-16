//! Native epochlog projections from retained execution observations. This
//! auxiliary journal adds no fields to consensus certificates or state roots.
use crate::{
    native_integer,
    rpc::Fault,
    transaction::{json_string, native_float},
};
use num_bigint::BigInt;
use num_traits::{Signed, Zero};
use serde::{Deserialize, Serialize};

pub const MAX_RECORD: usize = 16 * 1024 * 1024;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Recipient {
    pub address: Vec<u8>,
    pub role: String,
    pub amount: String,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub finalized_at: f64,
    pub fees_total: String,
    pub fees_burned: String,
    pub base_reward: String,
    pub total_reward: String,
    pub proposer_reward: String,
    pub validator_reward_each: String,
    pub reward_recipients: Vec<Recipient>,
}
impl Observation {
    pub fn from_rewards(
        finalized_at: f64,
        fees: &BigInt,
        plan: &crate::epoch_rewards::Plan,
        credits: &[crate::epoch_rewards::Credit],
    ) -> Result<Self, String> {
        let reward_recipients = credits
            .iter()
            .filter(|credit| credit.amount.is_positive())
            .map(|credit| {
                let role = match (credit.proposer, credit.validator) {
                    (true, true) => "proposer_validator",
                    (true, false) => "proposer",
                    (false, true) => "validator",
                    (false, false) => return Err("reward recipient has no role".to_owned()),
                };
                Ok(Recipient {
                    address: credit.address.clone(),
                    role: role.to_owned(),
                    amount: credit.amount.to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        let value = Self {
            finalized_at,
            fees_total: fees.to_string(),
            fees_burned: plan.fees_burned.to_string(),
            base_reward: plan.base_reward.to_string(),
            total_reward: plan.total_reward.to_string(),
            proposer_reward: plan.proposer_total.to_string(),
            validator_reward_each: plan.each_validator.to_string(),
            reward_recipients,
        };
        value.validate()?;
        Ok(value)
    }
    pub fn validate(&self) -> Result<(), String> {
        if !self.finalized_at.is_finite() || self.finalized_at < 0. {
            return Err("invalid finalized timestamp".into());
        }
        let amount = |raw: &str| -> Result<BigInt, String> {
            let value =
                native_integer::parse_integer(raw.as_bytes()).ok_or("invalid epoch amount")?;
            if value.is_negative() || value.to_string() != raw {
                return Err("noncanonical epoch amount".into());
            }
            Ok(value)
        };
        let fees = amount(&self.fees_total)?;
        let burned = amount(&self.fees_burned)?;
        let base = amount(&self.base_reward)?;
        let total = amount(&self.total_reward)?;
        amount(&self.proposer_reward)?;
        amount(&self.validator_reward_each)?;
        if burned > fees || base + fees - burned != total {
            return Err("epoch reward totals differ".into());
        }
        if self.reward_recipients.len() > 4097
            || !self
                .reward_recipients
                .windows(2)
                .all(|w| w[0].address < w[1].address)
        {
            return Err("epoch reward recipients are not canonical".into());
        }
        let mut sum = BigInt::zero();
        for row in &self.reward_recipients {
            if row.address.len() < 4
                || row.address.len() > 128
                || !matches!(
                    row.role.as_str(),
                    "proposer" | "validator" | "proposer_validator"
                )
            {
                return Err("invalid epoch recipient".into());
            }
            let value = amount(&row.amount)?;
            if value.is_zero() {
                return Err("zero epoch recipient".into());
            }
            sum += value;
        }
        if sum != total {
            return Err("epoch recipient total differs".into());
        }
        Ok(())
    }
}
pub struct Summary<'a> {
    pub epoch: i64,
    pub state_root: &'a [u8],
    pub parent_commit: &'a [u8],
    pub tx_count: i64,
    pub finalized_by: &'a [u8],
    pub observation: &'a Observation,
}
impl Summary<'_> {
    /// Exact native epochlog JSON used for the page reader's byte budget.
    pub fn header(
        &self,
        previous: &[u8],
        tx_start: i64,
        creator: &[u8],
        round: i64,
        source: &crate::consensus::RewardSource,
    ) -> Result<Vec<u8>, String> {
        use base64::{engine::general_purpose::STANDARD, Engine};
        self.observation.validate()?;
        crate::consensus::reward::validate(source).map_err(|e| e.to_string())?;
        let key = |key: Option<&Vec<u8>>| {
            key.map_or_else(
                || b"null".to_vec(),
                |raw| string(STANDARD.encode(raw).as_bytes()),
            )
        };
        let source = object(&[
            ("proposer_address", string(&source.reward_proposer_addr)),
            (
                "proposer_public_key",
                key(source.reward_proposer_public_key.as_ref()),
            ),
            (
                "members",
                array(source.reward_members.iter().map(|member| {
                    object(&[
                        ("address", string(&member.reward_address)),
                        ("public_key", key(member.reward_public_key.as_ref())),
                        (
                            "weight",
                            string(member.reward_weight.to_string().as_bytes()),
                        ),
                    ])
                })),
            ),
        ]);
        let observation = self.observation;
        let recipients = array(observation.reward_recipients.iter().map(|row| {
            object(&[
                ("address", string(&row.address)),
                ("role", string(row.role.as_bytes())),
                ("amount", string(row.amount.as_bytes())),
            ])
        }));
        Ok(object(&[
            ("id", number(self.epoch)),
            ("state_root", string(self.state_root)),
            ("prev_state_root", string(previous)),
            ("parent_commit", string(self.parent_commit)),
            ("start_txid", string(tx_start.to_string().as_bytes())),
            ("tx_count", number(self.tx_count)),
            ("finalized_by", string(self.finalized_by)),
            (
                "finalized_at",
                native_float(observation.finalized_at)
                    .map_err(|e| e.to_string())?
                    .into_bytes(),
            ),
            ("creator_addr", string(creator)),
            ("commit_round", number(round)),
            ("fees_total", string(observation.fees_total.as_bytes())),
            ("fees_burned", string(observation.fees_burned.as_bytes())),
            ("base_reward", string(observation.base_reward.as_bytes())),
            ("total_reward", string(observation.total_reward.as_bytes())),
            (
                "proposer_reward",
                string(observation.proposer_reward.as_bytes()),
            ),
            (
                "validator_reward_each",
                string(observation.validator_reward_each.as_bytes()),
            ),
            ("reward_recipients", recipients),
            ("reward_source", source),
        ]))
    }
    pub fn encode(&self) -> Result<Vec<u8>, String> {
        self.observation.validate()?;
        let observation = self.observation;
        let rewards = array(observation.reward_recipients.iter().map(|row| {
            object(&[
                ("address", string(&row.address)),
                ("role", string(row.role.as_bytes())),
                ("amount", string(row.amount.as_bytes())),
            ])
        }));
        Ok(object(&[
            ("epoch_id", number(self.epoch)),
            ("tx_count", number(self.tx_count)),
            ("finalized_by", string(self.finalized_by)),
            (
                "finalized_at",
                native_float(observation.finalized_at)
                    .map_err(|e| e.to_string())?
                    .into_bytes(),
            ),
            ("parent_commit", string(self.parent_commit)),
            ("state_root", string(self.state_root)),
            ("tree_hash", string(self.state_root)),
            ("fees_total", string(observation.fees_total.as_bytes())),
            ("fees_burned", string(observation.fees_burned.as_bytes())),
            ("base_reward", string(observation.base_reward.as_bytes())),
            ("total_reward", string(observation.total_reward.as_bytes())),
            (
                "proposer_reward",
                string(observation.proposer_reward.as_bytes()),
            ),
            (
                "validator_reward_each",
                string(observation.validator_reward_each.as_bytes()),
            ),
            ("reward_recipients", rewards),
        ]))
    }
}
pub(crate) fn string(value: &[u8]) -> Vec<u8> {
    let mut raw = Vec::new();
    json_string(&mut raw, value);
    raw
}
// Keep the native owned-input interface and its diagnostic/arena ownership.
#[allow(clippy::needless_pass_by_value)]
pub(crate) fn number(value: impl ToString) -> Vec<u8> {
    value.to_string().into_bytes()
}
pub(crate) fn object(fields: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut raw = vec![b'{'];
    for (i, (name, value)) in fields.iter().enumerate() {
        if i != 0 {
            raw.push(b',');
        }
        json_string(&mut raw, name.as_bytes());
        raw.push(b':');
        raw.extend(value);
    }
    raw.push(b'}');
    raw
}
pub(crate) fn array(values: impl IntoIterator<Item = Vec<u8>>) -> Vec<u8> {
    let mut raw = vec![b'['];
    for (i, value) in values.into_iter().enumerate() {
        if i != 0 {
            raw.push(b',');
        }
        raw.extend(value);
    }
    raw.push(b']');
    raw
}
pub fn summary_ids(
    doc: &crate::native_json::Document,
    params: &crate::native_json::Value,
) -> Vec<i64> {
    use crate::native_json::Value;
    let Value::List(outer) = params else {
        return Vec::new();
    };
    let items = if outer.len() == 1 {
        match doc.get(outer[0]) {
            Some(Value::List(inner)) => inner,
            _ => outer,
        }
    } else {
        outer
    };
    items
        .iter()
        .filter_map(|i| match doc.get(*i) {
            Some(Value::Int(value)) => Some(value.get()),
            _ => None,
        })
        .take(100)
        .collect()
}
pub fn unavailable() -> Fault {
    Fault::new(-32012, b"epoch record is inconsistent")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn observed_amounts_require_conservation_and_actual_recipients() {
        let mut observation = Observation {
            finalized_at: 42.125,
            fees_total: "12".into(),
            fees_burned: "2".into(),
            base_reward: "5".into(),
            total_reward: "15".into(),
            proposer_reward: "15".into(),
            validator_reward_each: "0".into(),
            reward_recipients: vec![Recipient {
                address: b"oct-test".to_vec(),
                role: "proposer".into(),
                amount: "15".into(),
            }],
        };
        assert!(observation.validate().is_ok());
        observation.reward_recipients.clear();
        assert!(observation.validate().is_err());
        observation.total_reward = "0".into();
        assert!(observation.validate().is_err());
    }
}
