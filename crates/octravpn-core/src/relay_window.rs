//! Checked epoch arithmetic shared by the claim, refund and sweep workers.
//! An unrepresentable deadline fails closed; saturation must never erase a margin.

/// A claim needs a strictly positive confirmation margin before its deadline.
pub fn claim_window_open(epoch: u64, deadline: u64, margin: u64) -> bool {
    epoch
        .checked_add(margin.max(1))
        .is_some_and(|limit| limit <= deadline)
}

/// Refund/sweep is permitted only after the complete grace and positive margin.
pub fn recovery_window_open(epoch: u64, deadline: u64, grace: u64, margin: u64) -> bool {
    deadline
        .checked_add(grace)
        .and_then(|d| d.checked_add(margin.max(1)))
        .is_some_and(|limit| epoch >= limit)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn overflow_never_opens_a_window() {
        assert!(!claim_window_open(u64::MAX, u64::MAX, 1));
        assert!(!recovery_window_open(u64::MAX, u64::MAX, 0, 1));
        assert!(!recovery_window_open(u64::MAX, 1, u64::MAX, 1));
    }
    #[test]
    fn claim_refund_boundaries() {
        assert!(claim_window_open(97, 100, 3));
        assert!(!claim_window_open(98, 100, 3));
        assert!(!claim_window_open(100, 100, 0));
        assert!(!recovery_window_open(102, 100, 0, 3));
        assert!(recovery_window_open(103, 100, 0, 3));
        assert!(!recovery_window_open(100, 100, 0, 0));
    }
}
