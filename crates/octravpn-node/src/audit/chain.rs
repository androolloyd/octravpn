//! Pure HMAC chain math + key persistence + date math. No async, no
//! mutex. `chain_step` is `pub(crate)` so the verifier and integration
//! tests share the exact algorithm the writer uses (F6 in
//! `/tmp/simplify-reuse-review.md`).

use std::path::Path;

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// The HMAC step shared by writers and verifiers. Exposed so
/// integration tests can build synthetic fixtures without duplicating
/// the algorithm (cf. F6 in `/tmp/simplify-reuse-review.md`).
pub(crate) fn chain_step(key: &[u8; 32], prev_mac: &[u8; 32], record_bytes: &[u8]) -> [u8; 32] {
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(key).expect("HMAC accepts any key");
    mac.update(prev_mac);
    mac.update(record_bytes);
    mac.finalize().into_bytes().into()
}

pub(crate) fn load_or_create_key(dir: &Path) -> Result<[u8; 32]> {
    let p = dir.join(".audit.key");
    if p.exists() {
        let raw = std::fs::read(&p).with_context(|| format!("read {}", p.display()))?;
        if raw.len() != 32 {
            anyhow::bail!(
                "audit key file {} has wrong size ({}); expected 32",
                p.display(),
                raw.len()
            );
        }
        let mut k = [0u8; 32];
        k.copy_from_slice(&raw);
        Ok(k)
    } else {
        let mut k = [0u8; 32];
        OsRng.fill_bytes(&mut k);
        std::fs::write(&p, k).with_context(|| format!("write {}", p.display()))?;
        // Best-effort chmod 0600 on Unix.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600));
        }
        Ok(k)
    }
}

pub(crate) fn ymd_utc(ts_unix: u64) -> String {
    let days = (ts_unix / 86_400) as i64;
    let (y, m, d) = days_to_ymd(days);
    format!("{y:04}-{m:02}-{d:02}")
}

/// Convert days-since-1970-01-01 to (year, month, day). Standard
/// Howard Hinnant algorithm — fast and exact.
fn days_to_ymd(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + (era as i32) * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ymd_conversion_known_dates() {
        assert_eq!(ymd_utc(0), "1970-01-01");
        assert_eq!(ymd_utc(946_684_800), "2000-01-01");
        assert_eq!(ymd_utc(1_704_067_200), "2024-01-01");
    }

    /// `chain_step` is the single source of truth for the HMAC step
    /// (cf. F6 in the reuse review). A writer + reader should agree.
    #[test]
    fn chain_step_is_deterministic_and_keyed() {
        let key = [0x42u8; 32];
        let prev = [0u8; 32];
        let a = chain_step(&key, &prev, b"hello");
        let b = chain_step(&key, &prev, b"hello");
        assert_eq!(a, b, "deterministic");
        let c = chain_step(&[0x43u8; 32], &prev, b"hello");
        assert_ne!(a, c, "key-sensitive");
        let d = chain_step(&key, &[1u8; 32], b"hello");
        assert_ne!(a, d, "prev-mac-sensitive");
    }
}
