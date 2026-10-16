// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Native snapshot download lease bounds; a lease grants no content authority.
pub const RENEW_INTERVAL: f64 = 60.;
pub const ACTIVE_WINDOW: f64 = 900.;
pub const MAX_SNAPSHOT_AGE: f64 = 86_400.;
pub const RETAINED_LIMIT: usize = 8;

#[derive(Clone, Debug, PartialEq)]
pub struct Lease {
    pub snapshot_id: Vec<u8>,
    pub last_seen: f64,
}
pub fn active(now: f64, published_at: f64, last_seen: f64) -> bool {
    // Comparisons deliberately retain the native NaN/infinity behavior.
    last_seen <= now + RENEW_INTERVAL
        && now - last_seen <= ACTIVE_WINDOW
        && published_at <= now + RENEW_INTERVAL
        && now - published_at <= MAX_SNAPSHOT_AGE
}
pub fn retained(leases: &[Lease]) -> Vec<Vec<u8>> {
    let mut leases = leases.to_vec();
    // OCaml Float.compare orders NaN before finite values and equates +/-0.
    fn compare(a: f64, b: f64) -> std::cmp::Ordering {
        use std::cmp::Ordering;
        match (a.is_nan(), b.is_nan()) {
            (true, true) => Ordering::Equal,
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            (false, false) => a.partial_cmp(&b).expect("non-NaN float order"),
        }
    }
    leases
        .sort_by(|a, b| compare(b.last_seen, a.last_seen).then(a.snapshot_id.cmp(&b.snapshot_id)));
    leases
        .into_iter()
        .take(RETAINED_LIMIT)
        .map(|x| x.snapshot_id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn stale_or_future_lease_cannot_keep_old_images_and_active_set_is_bounded() {
        assert!(active(1000., 0., 100.));
        assert!(!active(1000., 0., 99.));
        assert!(active(1000., 1060., 1060.));
        assert!(!active(1000., 1061., 1000.));
        assert!(!active(1000., 0., 1061.));
        assert!(!active(100_000., 0., 100_000.));
        assert!(!active(1000., 0., f64::NAN));
        let leases = (0..10)
            .map(|v| Lease {
                snapshot_id: vec![v],
                last_seen: f64::from(v),
            })
            .collect::<Vec<_>>();
        let kept = retained(&leases);
        assert_eq!(kept.len(), 8);
        assert_eq!(kept[0], vec![9]);
        assert!(!kept.contains(&vec![0]));
    }
}
