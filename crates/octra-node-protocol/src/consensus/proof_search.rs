//! Bounded retry schedule for missing proof-of-lock-change votes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
    pub height: i64,
    pub target: i64,
    pub sent_at: i64,
    pub round: i64,
    pub attempts: u32,
    pub requests: u32,
    recent: Vec<(i64, i64)>,
}
const INTERVAL: i64 = 2_100_000_000;
impl Search {
    pub fn step(
        prior: Option<Self>,
        validators: i64,
        height: i64,
        round: i64,
        known: Option<i64>,
        enabled: bool,
        now: i64,
    ) -> (Option<Self>, Option<i64>) {
        let prior = prior.filter(|p| p.height == height);
        if round <= 0 {
            return (None, None);
        }
        if !enabled {
            return (prior, None);
        }
        let target = known.filter(|t| *t >= 0 && *t < round).unwrap_or_else(|| {
            prior
                .as_ref()
                .filter(|p| p.target + 1 < round)
                .map_or(0, |p| p.target + 1)
        });
        let (attempts, requests) = prior
            .as_ref()
            .filter(|p| p.round == round)
            .map_or((0, 0), |p| {
                (if p.target == target { p.attempts } else { 0 }, p.requests)
            });
        let delay = INTERVAL * (1i64 << attempts.saturating_sub(1));
        let mut recent = prior.as_ref().map_or_else(Vec::new, |p| {
            p.recent
                .iter()
                .filter(|(sent, _)| now < *sent || now - *sent < 60_000_000_000)
                .copied()
                .collect::<Vec<_>>()
        });
        let used: i64 = recent.iter().map(|(_, cost)| cost).sum();
        let cost = 4 * validators.clamp(1, 255) + 4;
        let ready = prior
            .as_ref()
            .is_none_or(|p| now >= p.sent_at && now - p.sent_at >= delay);
        if !ready || attempts >= 4 || requests >= 8 || used + cost > 1024 {
            return (prior, None);
        }
        recent.insert(0, (now, cost));
        (
            Some(Self {
                height,
                target,
                sent_at: now,
                round,
                attempts: attempts + 1,
                requests: requests + 1,
                recent,
            }),
            Some(target),
        )
    }
}
