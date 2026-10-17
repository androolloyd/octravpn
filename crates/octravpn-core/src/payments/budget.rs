use super::{Error, Result, Tariff};

/// In-memory lifetime plan budget. The host must restore authenticated durable
/// counters and serialize access across both forwarding directions. Reserving
/// capacity does not prove delivery or authorize a chain payment.
#[derive(Clone, Debug)]
pub struct Budget {
    tariff: Tariff,
    budget_ou: u64,
    totals: Vec<u64>,
    charge_ou: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub traffic_class: u8,
    pub total_bytes: u64,
    pub total_charge_ou: u64,
    pub increment_ou: u64,
}
impl Budget {
    /// `budget_ou` is the original allocation, including already redeemed
    /// charges. `totals` must include the matching lifetime class counters.
    pub fn new(tariff: Tariff, budget_ou: u64, totals: Vec<u64>) -> Result<Self> {
        let charge_ou = tariff.total_charge(&totals)?;
        if charge_ou > budget_ou {
            return Err(Error::BudgetExceeded {
                required: charge_ou,
                budget: budget_ou,
            });
        }
        Ok(Self {
            tariff,
            budget_ou,
            totals,
            charge_ou,
        })
    }
    pub fn tariff(&self) -> &Tariff {
        &self.tariff
    }
    pub fn totals(&self) -> &[u64] {
        &self.totals
    }
    pub const fn total_charge_ou(&self) -> u64 {
        self.charge_ou
    }
    pub const fn remaining_ou(&self) -> u64 {
        self.budget_ou - self.charge_ou
    }

    /// Check the aggregate cumulative liability before mutating any counter.
    /// Small packets, reconnects and moving between classes cannot reset cost.
    pub fn reserve(&mut self, class: u8, bytes: u64) -> Result<Reservation> {
        let previous = *self
            .totals
            .get(usize::from(class))
            .ok_or(Error::UnknownClass(class))?;
        let total_bytes = previous.checked_add(bytes).ok_or(Error::Overflow)?;
        let prior_charge = self.tariff.charge(class, previous)?;
        let next_charge = self.tariff.charge(class, total_bytes)?;
        let increment_ou = next_charge
            .checked_sub(prior_charge)
            .ok_or(Error::Overflow)?;
        let total_charge_ou = self
            .charge_ou
            .checked_add(increment_ou)
            .ok_or(Error::Overflow)?;
        if total_charge_ou > self.budget_ou {
            return Err(Error::BudgetExceeded {
                required: total_charge_ou,
                budget: self.budget_ou,
            });
        }
        self.totals[usize::from(class)] = total_bytes;
        self.charge_ou = total_charge_ou;
        Ok(Reservation {
            traffic_class: class,
            total_bytes,
            total_charge_ou,
            increment_ou,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{payments::TrafficClass, Address};
    fn tariff() -> Tariff {
        Tariff::new(
            Address::from_pubkey(&[1; 32]),
            vec![
                TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: 1,
                },
                TrafficClass {
                    name: "premium".into(),
                    rate_ou_per_mib: 2,
                },
            ],
            vec![],
        )
        .unwrap()
    }
    #[test]
    fn aggregate_class_budget_is_atomic_and_survives_counter_restore() {
        let tariff = tariff();
        let mut budget = Budget::new(tariff.clone(), 3, vec![0, 0]).unwrap();
        assert_eq!(budget.reserve(0, 1).unwrap().increment_ou, 1);
        assert_eq!(budget.reserve(1, 1).unwrap().increment_ou, 1);
        assert_eq!(budget.reserve(1, 1_048_575).unwrap().increment_ou, 1);
        assert_eq!(budget.remaining_ou(), 0);
        let before = budget.totals().to_vec();
        assert!(budget.reserve(1, 1).is_err());
        assert_eq!(budget.totals(), before);
        assert_eq!(budget.total_charge_ou(), 3);
        assert!(budget.reserve(2, 1).is_err());
        assert_eq!(budget.totals(), before);
        let mut restarted = Budget::new(tariff, 3, before).unwrap();
        assert!(restarted.reserve(1, 1).is_err());
        assert_eq!(restarted.reserve(0, 1_048_575).unwrap().increment_ou, 0);
        assert!(restarted.reserve(0, 1).is_err());
    }
    #[test]
    fn counter_overflow_and_initial_overcommit_are_refused() {
        let zero = Tariff::new(
            Address::from_pubkey(&[1; 32]),
            vec![TrafficClass {
                name: "free".into(),
                rate_ou_per_mib: 0,
            }],
            vec![],
        )
        .unwrap();
        let mut budget = Budget::new(zero, 0, vec![u64::MAX]).unwrap();
        assert!(budget.reserve(0, 1).is_err());
        assert_eq!(budget.totals(), [u64::MAX]);
        assert_eq!(budget.total_charge_ou(), 0);
        assert!(Budget::new(tariff(), 1, vec![1_048_576, 1]).is_err());
        assert!(Budget::new(tariff(), 3, vec![0]).is_err());
    }
}
