// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Trusted transport upgrade schedules; peers cannot select activation rules.
use super::{domain_hash, endpoint::native_trim, peer_record::transport_config_hash, Error};
use crate::{
    native_integer::{parse_int63, parse_int64},
    oce1::Writer,
};
#[derive(Clone, Debug)]
pub struct Target {
    pub epoch: i64,
    pub binary_hash: Vec<u8>,
    pub config_hash: Vec<u8>,
}
#[derive(Clone, Debug)]
pub struct Plan {
    pub target: Target,
    pub rollback: Option<Target>,
}
pub fn normalize_hash(label: &str, raw: &[u8]) -> Result<Vec<u8>, Error> {
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    let raw = native_trim(raw);
    if raw.len() == 32 {
        return Ok(raw.to_vec());
    }
    if raw.len() == 64 {
        let parsed: Option<Vec<_>> = raw
            .chunks_exact(2)
            .map(|pair| {
                parse_int63(&[b"0x".as_slice(), pair].concat()).and_then(|n| u8::try_from(n).ok())
            })
            .collect();
        if let Some(bytes) = parsed {
            return Ok(bytes);
        }
    }
    Err(format!("{label} must be 32 raw bytes or 64 hex chars").into())
}
/// Capture the adopted native `P2p_upgrade_plan.of_env` inputs. The default
/// configuration hash is the original consensus network hash, before runtime
/// profile transitions. Only the trusted launcher supplies these inputs.
pub fn from_inputs<'a>(
    current_config_hash: &[u8],
    require_binary_hash: bool,
    mut get: impl FnMut(&str) -> Option<&'a [u8]>,
) -> Result<Option<Plan>, Error> {
    if !require_binary_hash {
        return Ok(None);
    }
    let (epoch, binary) = match (
        get("OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH"),
        get("OCTRA_P2P_UPGRADE_BINARY_HASH"),
    ) {
        (None, None) => return Ok(None),
        (Some(_), None) => return Err("OCTRA_P2P_UPGRADE_BINARY_HASH is required".into()),
        (None, Some(_)) => return Err("OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH is required".into()),
        (Some(epoch), Some(binary)) => (epoch, binary),
    };
    let epoch =
        parse_int64(native_trim(epoch)).ok_or("OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH is invalid")?;
    if epoch <= 0 {
        return Err("OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH must be positive".into());
    }
    let binary_hash = normalize_hash("OCTRA_P2P_UPGRADE_BINARY_HASH", binary)?;
    let config_hash = normalize_hash(
        "OCTRA_P2P_UPGRADE_CONFIG_HASH",
        get("OCTRA_P2P_UPGRADE_CONFIG_HASH").unwrap_or(current_config_hash),
    )?;
    let rollback = rollback_from_inputs(current_config_hash, epoch, &mut get)?;
    Ok(Some(Plan {
        target: Target {
            epoch,
            binary_hash,
            config_hash,
        },
        rollback,
    }))
}
fn rollback_from_inputs<'a>(
    current_config_hash: &[u8],
    activate_epoch: i64,
    get: &mut impl FnMut(&str) -> Option<&'a [u8]>,
) -> Result<Option<Target>, Error> {
    let (epoch, binary) = match (
        get("OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH"),
        get("OCTRA_P2P_ROLLBACK_BINARY_HASH"),
    ) {
        (None, None) => return Ok(None),
        (Some(_), None) => return Err("OCTRA_P2P_ROLLBACK_BINARY_HASH is required".into()),
        (None, Some(_)) => return Err("OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH is required".into()),
        (Some(epoch), Some(binary)) => (epoch, binary),
    };
    let epoch =
        parse_int64(native_trim(epoch)).ok_or("OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH is invalid")?;
    if epoch <= activate_epoch {
        return Err(
            "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH must be greater than upgrade activation".into(),
        );
    }
    let binary_hash = normalize_hash("OCTRA_P2P_ROLLBACK_BINARY_HASH", binary)?;
    let config_hash = normalize_hash(
        "OCTRA_P2P_ROLLBACK_CONFIG_HASH",
        get("OCTRA_P2P_ROLLBACK_CONFIG_HASH").unwrap_or(current_config_hash),
    )?;
    Ok(Some(Target {
        epoch,
        binary_hash,
        config_hash,
    }))
}
impl Plan {
    pub fn schedule_hash(&self, base: &[u8]) -> Result<[u8; 32], Error> {
        let mut w = Writer::new();
        w.put_hash32(base)?;
        w.put_u64(self.target.epoch as u64)?;
        w.put_hash32(&self.target.binary_hash)?;
        w.put_hash32(&self.target.config_hash)?;
        w.put_option(self.rollback.as_ref(), |w, r| {
            w.put_u64(r.epoch as u64)?;
            w.put_hash32(&r.binary_hash)?;
            w.put_hash32(&r.config_hash)
        })?;
        Ok(domain_hash(
            b"octra:p2p_upgrade_schedule:v1",
            &w.into_bytes(),
        ))
    }
    pub fn active(&self, epoch: i64) -> bool {
        epoch >= self.target.epoch
    }
    pub fn rollback_active(&self, epoch: i64) -> bool {
        self.rollback.as_ref().is_some_and(|r| epoch >= r.epoch)
    }
    pub fn ready(
        &self,
        epoch: i64,
        config: &[u8],
        binary: &[u8],
        require_binary: bool,
    ) -> Result<(), Error> {
        if !self.active(epoch) {
            return Ok(());
        }
        let target = self
            .rollback
            .as_ref()
            .filter(|r| epoch >= r.epoch)
            .unwrap_or(&self.target);
        if require_binary && binary != target.binary_hash {
            Err("binary_hash".into())
        } else if config != target.config_hash {
            Err("config_hash".into())
        } else {
            Ok(())
        }
    }
}
pub fn handshake_hash(
    epoch: i64,
    config: &[u8],
    binary: &[u8],
    require_binary: bool,
    plan: Option<&Plan>,
) -> Result<Vec<u8>, Error> {
    if !require_binary {
        return Ok(config.to_vec());
    }
    match plan {
        Some(p) if !p.active(epoch) => Ok(p.schedule_hash(config)?.to_vec()),
        _ => Ok(transport_config_hash(config, binary)?.to_vec()),
    }
}
pub fn binary_required(epoch: i64, require_binary: bool, plan: Option<&Plan>) -> bool {
    require_binary && plan.is_none_or(|p| p.active(epoch))
}
pub fn expected_binary<'a>(epoch: i64, binary: &'a [u8], plan: Option<&'a Plan>) -> &'a [u8] {
    match plan {
        Some(p) if p.rollback_active(epoch) => &p.rollback.as_ref().unwrap().binary_hash,
        Some(p) if p.active(epoch) => &p.target.binary_hash,
        _ => binary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const UPGRADE_EPOCH: &str = "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH";
    const UPGRADE_BINARY: &str = "OCTRA_P2P_UPGRADE_BINARY_HASH";
    const UPGRADE_CONFIG: &str = "OCTRA_P2P_UPGRADE_CONFIG_HASH";
    const ROLLBACK_EPOCH: &str = "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH";
    const ROLLBACK_BINARY: &str = "OCTRA_P2P_ROLLBACK_BINARY_HASH";
    const ROLLBACK_CONFIG: &str = "OCTRA_P2P_ROLLBACK_CONFIG_HASH";
    const BASE: [u8; 32] = [1; 32];
    const BINARY: [u8; 32] = [2; 32];

    fn parse(values: &[(&str, &[u8])]) -> Result<Option<Plan>, Error> {
        from_inputs(&BASE, true, |name| {
            values
                .iter()
                .find_map(|(key, value)| (*key == name).then_some(*value))
        })
    }
    fn rejected(values: &[(&str, &[u8])], expected: &str) {
        assert_eq!(parse(values).unwrap_err().to_string(), expected);
    }

    #[test]
    fn disabled_binary_enforcement_reads_no_schedule_inputs() {
        assert!(from_inputs(b"invalid unused default", false, |_| {
            panic!("native disabled upgrade must not read configuration")
        })
        .unwrap()
        .is_none());
    }

    #[test]
    fn no_upgrade_ignores_orphan_config_and_rollback_values() {
        assert!(parse(&[]).unwrap().is_none());
        assert!(parse(&[
            (UPGRADE_CONFIG, b"invalid"),
            (ROLLBACK_EPOCH, b"invalid"),
            (ROLLBACK_BINARY, b"invalid"),
            (ROLLBACK_CONFIG, b"invalid"),
        ])
        .unwrap()
        .is_none());
        assert!(parse(&[
            (UPGRADE_EPOCH, b"10"),
            (UPGRADE_BINARY, &BINARY),
            (ROLLBACK_CONFIG, b"invalid unused orphan"),
        ])
        .unwrap()
        .unwrap()
        .rollback
        .is_none());
    }

    #[test]
    fn incomplete_upgrade_and_rollback_inputs_preserve_native_errors() {
        rejected(
            &[(UPGRADE_EPOCH, b"invalid")],
            "OCTRA_P2P_UPGRADE_BINARY_HASH is required",
        );
        rejected(
            &[(UPGRADE_BINARY, b"invalid")],
            "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH is required",
        );
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, &BINARY),
                (ROLLBACK_EPOCH, b"invalid"),
            ],
            "OCTRA_P2P_ROLLBACK_BINARY_HASH is required",
        );
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, &BINARY),
                (ROLLBACK_BINARY, b"invalid"),
            ],
            "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH is required",
        );
    }

    #[test]
    fn activation_uses_native_int64_and_trim_rules() {
        for raw in [
            b"".as_slice(),
            b"_1",
            b"1 0",
            b"\x0b10\x0b",
            b"9223372036854775808",
            b"-9223372036854775809",
        ] {
            rejected(
                &[(UPGRADE_EPOCH, raw), (UPGRADE_BINARY, &BINARY)],
                "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH is invalid",
            );
        }
        for raw in [b"0".as_slice(), b"-1", b"0xffffffffffffffff"] {
            rejected(
                &[(UPGRADE_EPOCH, raw), (UPGRADE_BINARY, &BINARY)],
                "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH must be positive",
            );
        }
        for (raw, epoch) in [
            (b" \t+0x1_0\r\n\x0c".as_slice(), 16),
            (b"0o20", 16),
            (b"0b10000", 16),
            (b"0u16", 16),
            (b"9223372036854775807", i64::MAX),
        ] {
            assert_eq!(
                parse(&[(UPGRADE_EPOCH, raw), (UPGRADE_BINARY, &BINARY)])
                    .unwrap()
                    .unwrap()
                    .target
                    .epoch,
                epoch
            );
        }
    }

    #[test]
    fn upgrade_hash_errors_precede_rollback_parsing() {
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, b"invalid"),
                (ROLLBACK_EPOCH, b"invalid"),
            ],
            "OCTRA_P2P_UPGRADE_BINARY_HASH must be 32 raw bytes or 64 hex chars",
        );
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, &BINARY),
                (UPGRADE_CONFIG, b"invalid"),
                (ROLLBACK_EPOCH, b"invalid"),
            ],
            "OCTRA_P2P_UPGRADE_CONFIG_HASH must be 32 raw bytes or 64 hex chars",
        );
        assert_eq!(
            from_inputs(b"invalid default", true, |name| match name {
                UPGRADE_EPOCH => Some(b"10"),
                UPGRADE_BINARY => Some(&BINARY),
                _ => None,
            })
            .unwrap_err()
            .to_string(),
            "OCTRA_P2P_UPGRADE_CONFIG_HASH must be 32 raw bytes or 64 hex chars"
        );
    }

    #[test]
    fn both_missing_config_hashes_default_to_original_base() {
        let plan = parse(&[
            (UPGRADE_EPOCH, b"10"),
            (UPGRADE_BINARY, &BINARY),
            (ROLLBACK_EPOCH, b"11"),
            (ROLLBACK_BINARY, &[3; 32]),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(plan.target.config_hash, BASE);
        assert_eq!(plan.rollback.unwrap().config_hash, BASE);

        let plan = parse(&[
            (UPGRADE_EPOCH, b"10"),
            (UPGRADE_BINARY, &BINARY),
            (UPGRADE_CONFIG, &[4; 32]),
            (ROLLBACK_EPOCH, b"11"),
            (ROLLBACK_BINARY, &[3; 32]),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(plan.target.config_hash, [4; 32]);
        assert_eq!(plan.rollback.unwrap().config_hash, BASE);
    }

    #[test]
    fn explicit_hashes_keep_native_raw_and_trimmed_hex_forms() {
        let raw = [b' '; 32];
        let hex = format!(" \t{}\r\n", "Af".repeat(32));
        let plan = parse(&[
            (UPGRADE_EPOCH, b"10"),
            (UPGRADE_BINARY, &raw),
            (UPGRADE_CONFIG, hex.as_bytes()),
            (ROLLBACK_EPOCH, b"11"),
            (ROLLBACK_BINARY, hex.as_bytes()),
            (ROLLBACK_CONFIG, &raw),
        ])
        .unwrap()
        .unwrap();
        assert_eq!(plan.target.binary_hash, raw);
        assert_eq!(plan.target.config_hash, [0xaf; 32]);
        let rollback = plan.rollback.unwrap();
        assert_eq!(rollback.binary_hash, [0xaf; 32]);
        assert_eq!(rollback.config_hash, raw);
    }

    #[test]
    fn rollback_epoch_and_hash_errors_are_native_and_ordered() {
        for (raw, expected) in [
            (
                b"invalid".as_slice(),
                "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH is invalid",
            ),
            (
                b"9223372036854775808",
                "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH is invalid",
            ),
            (
                b"10",
                "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH must be greater than upgrade activation",
            ),
            (
                b"9",
                "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH must be greater than upgrade activation",
            ),
        ] {
            rejected(
                &[
                    (UPGRADE_EPOCH, b"10"),
                    (UPGRADE_BINARY, &BINARY),
                    (ROLLBACK_EPOCH, raw),
                    (ROLLBACK_BINARY, b"invalid"),
                ],
                expected,
            );
        }
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, &BINARY),
                (ROLLBACK_EPOCH, b"11"),
                (ROLLBACK_BINARY, b"invalid"),
                (ROLLBACK_CONFIG, b"invalid"),
            ],
            "OCTRA_P2P_ROLLBACK_BINARY_HASH must be 32 raw bytes or 64 hex chars",
        );
        rejected(
            &[
                (UPGRADE_EPOCH, b"10"),
                (UPGRADE_BINARY, &BINARY),
                (ROLLBACK_EPOCH, b"11"),
                (ROLLBACK_BINARY, &BINARY),
                (ROLLBACK_CONFIG, b"invalid"),
            ],
            "OCTRA_P2P_ROLLBACK_CONFIG_HASH must be 32 raw bytes or 64 hex chars",
        );
    }

    #[test]
    fn parsed_plan_drives_exact_activation_and_rollback_boundaries() {
        let plan = parse(&[
            (UPGRADE_EPOCH, b"10"),
            (UPGRADE_BINARY, &BINARY),
            (UPGRADE_CONFIG, &[4; 32]),
            (ROLLBACK_EPOCH, b" \t0xb\n"),
            (ROLLBACK_BINARY, &[3; 32]),
        ])
        .unwrap()
        .unwrap();
        assert!(!plan.active(9));
        assert!(!binary_required(9, true, Some(&plan)));
        assert_eq!(expected_binary(9, &BASE, Some(&plan)), BASE);
        assert_eq!(
            handshake_hash(9, &BASE, &BASE, true, Some(&plan)).unwrap(),
            plan.schedule_hash(&BASE).unwrap()
        );
        assert!(plan.active(10));
        assert!(!plan.rollback_active(10));
        assert!(binary_required(10, true, Some(&plan)));
        assert_eq!(expected_binary(10, &BASE, Some(&plan)), BINARY);
        assert!(plan.ready(10, &[4; 32], &BINARY, true).is_ok());
        assert_eq!(
            plan.ready(10, &BASE, &BINARY, true)
                .unwrap_err()
                .to_string(),
            "config_hash"
        );
        assert!(plan.rollback_active(11));
        assert_eq!(expected_binary(11, &BASE, Some(&plan)), [3; 32]);
        assert!(plan.ready(11, &BASE, &[3; 32], true).is_ok());
        assert_eq!(
            plan.ready(11, &BASE, &BINARY, true)
                .unwrap_err()
                .to_string(),
            "binary_hash"
        );
    }
}
