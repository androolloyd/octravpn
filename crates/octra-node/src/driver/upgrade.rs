//! Local upgrade readiness commits the selected consensus configuration, not
//! the swarm's separate network/profile handshake commitment.
use octra_node_protocol::{
    consensus::{hash, Error},
    validator::config::Config,
};
use octra_node_runtime::{finality::EpochRules, status_read::Release};

pub(super) fn config_hash(
    chain: &[u8],
    number: i64,
    rules: &EpochRules,
    canonical: &Config,
    release: Option<&Release>,
) -> Result<Vec<u8>, Error> {
    // Native prepare_set selects the activation fingerprint only at/after its
    // epoch. Relief selects the same future set early but retains its schedule.
    let active_hash = hash::validator_set_hash(&rules.validators)?;
    let scheduled = match canonical.light_scheduled.as_ref() {
        Some((epoch, set)) if number < *epoch || active_hash != hash::validator_set_hash(set)? => {
            Some((*epoch, set))
        }
        _ => None,
    };
    let profile = release
        .map(|release| {
            release
                .settings
                .hash(chain, number, &release.crypto_engine)
                .map(|hash| hash.to_vec())
        })
        .transpose()?;
    Ok(hash::config_hash(
        chain,
        &rules.validators,
        scheduled,
        release.and_then(|release| release.program_trust.as_ref()),
        profile.as_ref(),
    )?
    .to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use octra_node_protocol::{
        consensus::{profile::Settings, ValidatorSet, CURRENT_VERSION},
        network::domain_hash,
        oce1::Writer,
        validator::config::Build,
    };
    use octra_node_runtime::finality::ReceiptRules;
    use std::collections::BTreeMap;

    const CHAIN: &[u8] = b"upgrade-readiness-fixture";

    fn canonical() -> Config {
        let current = [format!("old-validator:{}", STANDARD.encode([1; 32])).into_bytes()];
        let next = [format!("next-validator:{}", STANDARD.encode([2; 32])).into_bytes()];
        Config::build(Build {
            chain: CHAIN,
            consensus: true,
            height: 10,
            current: &current,
            next: &next,
            chain_pending: &[],
            activate: Some(20),
            program_trust: None,
            runtime_profile: None,
        })
        .unwrap()
    }

    fn rules(validators: ValidatorSet) -> EpochRules {
        EpochRules {
            validators,
            receipts: ReceiptRules {
                required: false,
                crypto_active: false,
                stealth_minimum: 0.into(),
            },
            relief: None,
        }
    }

    // Assemble the native unweighted configuration transcript independently of
    // config_hash, using the already parity-tested set/profile primitives.
    fn expected(
        active: &ValidatorSet,
        scheduled: Option<(i64, &ValidatorSet)>,
        trust: Option<&[u8]>,
        profile: Option<&[u8]>,
    ) -> Vec<u8> {
        assert!(!active.weighted && scheduled.is_none_or(|(_, set)| !set.weighted));
        let mut wire = Writer::new();
        wire.put_bytes(CHAIN).unwrap();
        wire.put_u16(CURRENT_VERSION as u16).unwrap();
        let domain = if let Some(profile) = profile {
            wire.put_u8(u8::from(trust.is_some())).unwrap();
            if let Some(trust) = trust {
                wire.put_hash32(trust).unwrap();
            }
            wire.put_hash32(profile).unwrap();
            b"octra:consensus_config:v3".as_slice()
        } else if let Some(trust) = trust {
            wire.put_hash32(trust).unwrap();
            b"octra:consensus_config:v2".as_slice()
        } else {
            b"octra:consensus_config:v1".as_slice()
        };
        wire.put_hash32(&hash::validator_set_hash(active).unwrap())
            .unwrap();
        wire.put_u8(u8::from(scheduled.is_some())).unwrap();
        if let Some((epoch, set)) = scheduled {
            wire.put_u64(epoch as u64).unwrap();
            wire.put_hash32(&hash::validator_set_hash(set).unwrap())
                .unwrap();
        }
        domain_hash(domain, &wire.into_bytes()).to_vec()
    }

    #[test]
    fn no_release_uses_consensus_membership_domain_without_inventing_a_profile() {
        let mut canonical = canonical();
        let rules = rules(canonical.active.clone());
        // These fields are absent from the canonical membership reader today;
        // only an explicit captured Release supplies their runtime identity.
        canonical.program_trust = Some(vec![9; 32]);
        canonical.runtime_profile = Some(vec![8; 32]);
        let actual = config_hash(CHAIN, 19, &rules, &canonical, None).unwrap();
        let (epoch, scheduled) = canonical.light_scheduled.as_ref().unwrap();
        assert_eq!(
            actual,
            expected(&rules.validators, Some((*epoch, scheduled)), None, None)
        );
        assert_ne!(actual, hash::network_hash(CHAIN, None, None).unwrap());
    }

    #[test]
    fn captured_release_binds_profile_epoch_crypto_engine_and_program_trust() {
        let canonical = canonical();
        let rules = rules(canonical.active.clone());
        let mut release = Release {
            settings: Settings::from_values(BTreeMap::new()).unwrap(),
            crypto_engine: b"fixture-engine".to_vec(),
            program_trust: Some(vec![3; 32]),
            source_commit: None,
            binary_hash: None,
        };
        let profile = release
            .settings
            .hash(CHAIN, 19, &release.crypto_engine)
            .unwrap();
        let (epoch, scheduled) = canonical.light_scheduled.as_ref().unwrap();
        let actual = config_hash(CHAIN, 19, &rules, &canonical, Some(&release)).unwrap();
        assert_eq!(
            actual,
            expected(
                &rules.validators,
                Some((*epoch, scheduled)),
                Some(&[3; 32]),
                Some(&profile)
            )
        );
        assert_ne!(
            actual,
            config_hash(CHAIN, 19, &rules, &canonical, None).unwrap()
        );
        release.crypto_engine.push(b'!');
        assert_ne!(
            actual,
            config_hash(CHAIN, 19, &rules, &canonical, Some(&release)).unwrap()
        );
        release.crypto_engine = b"fixture-engine".to_vec();
        release.program_trust = Some(vec![4; 32]);
        assert_ne!(
            actual,
            config_hash(CHAIN, 19, &rules, &canonical, Some(&release)).unwrap()
        );
    }

    #[test]
    fn profile_cutover_uses_the_epoch_being_voted_on() {
        use octra_node_protocol::{consensus::policy::DEVNET, rules as graph};
        let mut canonical = canonical();
        canonical.light_scheduled = None;
        let rules = rules(canonical.active.clone());
        let release = Release {
            settings: Settings::from_values(BTreeMap::new()).unwrap(),
            crypto_engine: b"fixture-engine".to_vec(),
            program_trust: Some(vec![3; 32]),
            source_commit: None,
            binary_hash: None,
        };
        let epoch = graph::activation(DEVNET, graph::Rule::Standard)
            .unwrap()
            .activation_epoch;
        let before = release
            .settings
            .hash(DEVNET, epoch - 1, &release.crypto_engine)
            .unwrap()
            .to_vec();
        let current = release
            .settings
            .hash(DEVNET, epoch, &release.crypto_engine)
            .unwrap()
            .to_vec();
        assert_ne!(before, current);
        let actual = config_hash(DEVNET, epoch, &rules, &canonical, Some(&release)).unwrap();
        assert_eq!(
            actual,
            hash::config_hash(
                DEVNET,
                &rules.validators,
                None,
                release.program_trust.as_ref(),
                Some(&current),
            )
            .unwrap()
        );
        assert_ne!(
            actual,
            hash::config_hash(
                DEVNET,
                &rules.validators,
                None,
                release.program_trust.as_ref(),
                Some(&before),
            )
            .unwrap()
        );
    }

    #[test]
    fn relief_retains_pending_commitment_and_activation_removes_only_selected_schedule() {
        let canonical = canonical();
        let (epoch, scheduled) = canonical.light_scheduled.as_ref().unwrap();
        let current = rules(canonical.active.clone());
        // The caller authenticates relief and supplies its selected active set.
        let selected = rules(scheduled.clone());
        let before = config_hash(CHAIN, 19, &current, &canonical, None).unwrap();
        let relief = config_hash(CHAIN, 19, &selected, &canonical, None).unwrap();
        assert_eq!(
            relief,
            expected(&selected.validators, Some((*epoch, scheduled)), None, None)
        );
        assert_ne!(relief, before);
        let activated = config_hash(CHAIN, 20, &selected, &canonical, None).unwrap();
        assert_eq!(activated, expected(&selected.validators, None, None, None));
        assert_ne!(activated, relief);
        assert_eq!(
            config_hash(CHAIN, 20, &current, &canonical, None).unwrap(),
            before
        );
    }
}
