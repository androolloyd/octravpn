//! IAT (inter-arrival timing) chaff scheduler.
//!
//! WireGuard's flow shape is one of its strongest fingerprints: a
//! tight back-to-back handshake (two ~150 byte packets, ~1 ms apart),
//! then a steady stream of mid-size transport packets at roughly the
//! application's send rate. A passive flow-shape classifier doesn't
//! need to read packet bytes; it can identify WG just from the
//! inter-arrival CDF.
//!
//! The IAT mitigation is to inject a randomised delay between
//! successive outbound frames so the on-wire timing distribution is
//! flat (mode 1) or roughly Pareto-distributed (mode 2, modelling a
//! long-tailed web flow). Mode 0 leaves timing untouched.
//!
//! Numbers match the obfs4 spec's defaults:
//!
//! | mode | distribution     | range        |
//! |------|------------------|--------------|
//! |  0   | none (pass-thru) | —            |
//! |  1   | uniform          | 0…25 ms      |
//! |  2   | Pareto-ish       | 0…200 ms     |
//!
//! `Iat` carries no async runtime dependency: callers query
//! `next_delay()` and decide how to wait (tokio sleep, std sleep, or
//! deferring the send via a queue). The obfs4 transport uses
//! `std::thread::sleep` because the trait's send path is sync.

use std::time::Duration;

use rand::{Rng, RngCore};

/// Selects the IAT delay distribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IatMode {
    /// No injected delay. Cheapest; relies on length randomisation
    /// alone for traffic-shape obfuscation. Default.
    Off,
    /// Uniform 0..25 ms. Cheap, defeats simple "WG sends bursts every
    /// N ms" heuristics.
    Uniform,
    /// Pareto-shaped 0..200 ms. Stronger; introduces user-visible
    /// latency. Recommended only on overlay traffic that already
    /// tolerates RTT (e.g. cross-region tunnels).
    Pareto,
}

impl Default for IatMode {
    fn default() -> Self {
        Self::Off
    }
}

impl IatMode {
    /// Convert from obfs4-spec mode number (0/1/2).
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Off),
            1 => Some(Self::Uniform),
            2 => Some(Self::Pareto),
            _ => None,
        }
    }

    /// To the obfs4-spec mode number (used by the operator-published
    /// TOML config).
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::Uniform => 1,
            Self::Pareto => 2,
        }
    }
}

/// Stateless IAT scheduler. Callers invoke [`Self::next_delay`] once
/// per outbound frame.
#[derive(Debug, Clone, Copy)]
pub struct Iat {
    mode: IatMode,
}

impl Iat {
    /// Construct with the given mode.
    pub fn new(mode: IatMode) -> Self {
        Self { mode }
    }

    /// The IAT mode this scheduler was constructed with.
    pub fn mode(self) -> IatMode {
        self.mode
    }

    /// Pull the next delay from the configured distribution.
    pub fn next_delay<R: RngCore>(&self, rng: &mut R) -> Duration {
        match self.mode {
            IatMode::Off => Duration::ZERO,
            IatMode::Uniform => {
                // 0..25 ms uniform.
                let micros = rng.gen_range(0u64..25_000);
                Duration::from_micros(micros)
            }
            IatMode::Pareto => {
                // Pareto-shaped: heavy-tailed. We approximate with
                // an inverse-CDF on a uniform sample:
                //   delay = scale / (1 - u)^(1/shape)
                // with scale = 5 ms, shape = 1.5; truncate to 200 ms.
                let u: f64 = rng.gen_range(0.0..1.0);
                let raw = 5.0_f64 / (1.0_f64 - u).powf(1.0 / 1.5);
                let ms = raw.min(200.0);
                Duration::from_micros((ms * 1000.0) as u64)
            }
        }
    }
}

/// Convenience: pull a delay from a default thread RNG.
pub fn next_delay(mode: IatMode) -> Duration {
    Iat::new(mode).next_delay(&mut rand::thread_rng())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn off_yields_zero() {
        assert_eq!(Iat::new(IatMode::Off).next_delay(&mut rand::thread_rng()), Duration::ZERO);
    }

    #[test]
    fn uniform_is_bounded() {
        let iat = Iat::new(IatMode::Uniform);
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let d = iat.next_delay(&mut rng);
            assert!(d <= Duration::from_millis(25));
        }
    }

    #[test]
    fn pareto_is_bounded() {
        let iat = Iat::new(IatMode::Pareto);
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let d = iat.next_delay(&mut rng);
            assert!(d <= Duration::from_millis(200));
        }
    }

    #[test]
    fn mode_round_trip() {
        for m in [IatMode::Off, IatMode::Uniform, IatMode::Pareto] {
            assert_eq!(IatMode::from_u8(m.as_u8()), Some(m));
        }
        assert!(IatMode::from_u8(99).is_none());
    }

    #[test]
    fn pareto_distribution_has_spread() {
        // Strong spread check: at least 100 distinct microsecond values
        // across 1000 samples. The previous version only required >1
        // distinct value, which would pass even on a near-degenerate
        // RNG seam.
        let iat = Iat::new(IatMode::Pareto);
        let mut rng = rand::thread_rng();
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            seen.insert(iat.next_delay(&mut rng).as_micros());
        }
        assert!(
            seen.len() >= 100,
            "Pareto draws collapsed to {} distinct values; RNG seam looks weak",
            seen.len()
        );
    }

    /// Mode 0 is near-zero (exactly zero in our impl): a thousand
    /// samples in Off mode must sum to exactly 0 micros.
    #[test]
    fn off_mode_total_is_exactly_zero() {
        let iat = Iat::new(IatMode::Off);
        let mut rng = rand::thread_rng();
        let mut total = 0u128;
        for _ in 0..1000 {
            total += iat.next_delay(&mut rng).as_micros();
        }
        assert_eq!(total, 0, "Off must be exactly zero delay");
    }

    /// Mode 2 (Pareto) must produce *some* "long tail" delays > 25 ms
    /// (which is the upper bound of mode 1). If this fails, mode 2 has
    /// degenerated to mode-1-style uniform.
    #[test]
    fn pareto_has_long_tail_above_uniform_max() {
        let iat = Iat::new(IatMode::Pareto);
        let mut rng = rand::thread_rng();
        let mut tail_count = 0;
        for _ in 0..5000 {
            let d = iat.next_delay(&mut rng);
            if d > Duration::from_millis(25) {
                tail_count += 1;
            }
        }
        // With scale=5ms, shape=1.5, P(>25ms) = (5/25)^1.5 ≈ 0.0894
        // → expect ~447 tail samples in 5000. Use a generous lower
        // bound to avoid flakes; 50 is well below the mean but well
        // above zero, so it would only fire on a fully-degenerate path.
        assert!(
            tail_count >= 50,
            "Pareto generated only {tail_count}/5000 samples > 25 ms; long tail is degenerate"
        );
    }

    /// Mode 1 (Uniform) must NOT produce delays > 25 ms. This is the
    /// converse of the long-tail test for mode 2.
    #[test]
    fn uniform_never_exceeds_25ms() {
        let iat = Iat::new(IatMode::Uniform);
        let mut rng = rand::thread_rng();
        for _ in 0..10_000 {
            let d = iat.next_delay(&mut rng);
            assert!(
                d <= Duration::from_millis(25),
                "Uniform produced {d:?} > 25 ms"
            );
        }
    }

    /// Mode 1 mean lives somewhere mid-range (~12.5 ms). If our impl
    /// silently regresses to "always 0" or "always 25 ms" this fires.
    #[test]
    fn uniform_mean_is_mid_range() {
        let iat = Iat::new(IatMode::Uniform);
        let mut rng = rand::thread_rng();
        let mut sum_us = 0u128;
        const N: u32 = 5_000;
        for _ in 0..N {
            sum_us += iat.next_delay(&mut rng).as_micros();
        }
        let mean_us = sum_us / N as u128;
        // Expected mean = 12500 us. Allow ±25% noise.
        assert!(
            (9_000..16_000).contains(&(mean_us as u64)),
            "Uniform mean is {mean_us} us; expected ~12500 us"
        );
    }

    /// `next_delay(IatMode::Off)` free fn returns zero too (in addition
    /// to the trait method).
    #[test]
    fn free_fn_next_delay_off_is_zero() {
        assert_eq!(next_delay(IatMode::Off), Duration::ZERO);
    }

    /// IatMode round-trip via u8: encoded values 0/1/2 round-trip;
    /// every other byte returns None.
    #[test]
    fn iat_mode_from_u8_exhaustive() {
        for v in 0u8..=255 {
            let parsed = IatMode::from_u8(v);
            match v {
                0 => assert_eq!(parsed, Some(IatMode::Off)),
                1 => assert_eq!(parsed, Some(IatMode::Uniform)),
                2 => assert_eq!(parsed, Some(IatMode::Pareto)),
                _ => assert_eq!(parsed, None, "value {v} should be rejected"),
            }
        }
    }

    /// `mode()` accessor returns whatever we constructed with.
    #[test]
    fn mode_accessor_round_trip() {
        for m in [IatMode::Off, IatMode::Uniform, IatMode::Pareto] {
            assert_eq!(Iat::new(m).mode(), m);
        }
    }
}
