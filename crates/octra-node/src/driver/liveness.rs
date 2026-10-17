use super::{now, Host, LivenessContext, Ordering, Validator};
use octra_node_runtime::{consensus_driver::configured_stall_sec, status_read::Release};

pub(super) fn stall_sec(release: Option<&Release>) -> f64 {
    let raw = match release {
        Some(release) => release
            .settings
            .get("OCTRA_BFT_LIVENESS_STALL_SEC")
            .map(<[u8]>::to_vec),
        None => std::env::var_os("OCTRA_BFT_LIVENESS_STALL_SEC")
            .map(|value| value.as_encoded_bytes().to_vec()),
    };
    configured_stall_sec(raw.as_deref())
}

pub(super) fn snapshot<A: Host>(validator: &Validator<A>) -> Option<LivenessContext> {
    let head = validator.node.store.cached_head()?;
    let expected = i64::try_from(head.cursor.epoch.0).ok()?.checked_add(1)?;
    let voting = validator.enabled.load(Ordering::Acquire);
    Some(LivenessContext {
        expected,
        now: now().ok()?,
        stall_sec: validator.liveness_stall_sec,
        observer: !voting,
        voting,
        // Live catch-up owns a stopped driver generation. Any other
        // suspension independently clears the attestation gate below.
        catchup_active: false,
        quarantine_active: validator.node.root_quarantined(),
        state_attested: matches!(validator.node.status(), crate::Status::Serving(serving) if *serving == head),
        pending_finalized: false, // The actor owns its pending certificate.
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_node_protocol::consensus::profile::Settings;
    use std::collections::BTreeMap;

    #[test]
    fn captured_release_uses_native_liveness_bounds_and_default() {
        for (raw, expected) in [
            (None, 150.),
            (Some(b"".as_slice()), 150.),
            (Some(b"149".as_slice()), 150.),
            (Some(b"150".as_slice()), 150.),
            (Some(b"600".as_slice()), 600.),
            (Some(b"3600".as_slice()), 3600.),
            (Some(b"3601".as_slice()), 150.),
            (Some(b"0x258".as_slice()), 600.),
            (Some(b"-1".as_slice()), 150.),
            (Some(b"invalid".as_slice()), 150.),
        ] {
            let values = raw.map_or_else(BTreeMap::new, |value| {
                BTreeMap::from([("OCTRA_BFT_LIVENESS_STALL_SEC".to_owned(), value.to_vec())])
            });
            let release = Release {
                settings: Settings::from_values(values).unwrap(),
                crypto_engine: vec![],
                program_trust: None,
                source_commit: None,
                binary_hash: None,
            };
            assert_eq!(stall_sec(Some(&release)).to_bits(), f64::to_bits(expected));
        }
    }
}
