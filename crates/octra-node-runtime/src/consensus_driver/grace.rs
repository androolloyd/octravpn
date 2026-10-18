// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Local monotonic proposal-work grace, captured from trusted startup settings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GraceConfig {
    build_ms: i64,
    verify_ms: i64,
}
impl Default for GraceConfig {
    fn default() -> Self {
        Self {
            build_ms: 180_000,
            verify_ms: 180_000,
        }
    }
}
impl GraceConfig {
    /// Native int_of_string syntax and bounds; invalid or out-of-range values
    /// use 180s, rather than being clamped. Absence is authoritative.
    pub fn capture(get: impl Fn(&str) -> Option<Vec<u8>>) -> Self {
        fn parse(raw: Option<&[u8]>) -> i64 {
            raw.and_then(octra_node_protocol::native_integer::parse_int63)
                .filter(|value| (0..=300_000).contains(value))
                .unwrap_or(180_000)
        }
        Self {
            build_ms: parse(get("OCTRA_BFT_PROPOSAL_BUILD_GRACE_MS").as_deref()),
            verify_ms: parse(get("OCTRA_BFT_PROPOSAL_VERIFY_GRACE_MS").as_deref()),
        }
    }
    /// Compatibility for standalone embedders. Node launchers pass one
    /// explicit capture to every driver generation instead.
    pub fn from_env() -> Self {
        Self::capture(|name| std::env::var_os(name).map(|value| value.as_encoded_bytes().to_vec()))
    }
    pub fn build_ms(self) -> i64 {
        self.build_ms
    }
    pub fn verify_ms(self) -> i64 {
        self.verify_ms
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_integer_forms_defaults_and_bounds_are_preserved() {
        for (raw, expected) in [
            (None, 180_000),
            (Some(b"".as_slice()), 180_000),
            (Some(b"0".as_slice()), 0),
            (Some(b"300000".as_slice()), 300_000),
            (Some(b"0x493e0".as_slice()), 300_000),
            (Some(b"1_000".as_slice()), 1000),
            (Some(b"+500".as_slice()), 500),
            (Some(b"300001".as_slice()), 180_000),
            (Some(b"-1".as_slice()), 180_000),
            (Some(b" 500".as_slice()), 180_000),
            (Some(b"500 ".as_slice()), 180_000),
            (Some(b"4611686018427387904".as_slice()), 180_000),
            (Some(b"\xff".as_slice()), 180_000),
        ] {
            let config = GraceConfig::capture(|_| raw.map(<[u8]>::to_vec));
            assert_eq!(config.build_ms(), expected, "{raw:?}");
            assert_eq!(config.verify_ms(), expected, "{raw:?}");
        }
        let config = GraceConfig::capture(|name| match name {
            "OCTRA_BFT_PROPOSAL_BUILD_GRACE_MS" => Some(b"0".to_vec()),
            "OCTRA_BFT_PROPOSAL_VERIFY_GRACE_MS" => Some(b"300000".to_vec()),
            _ => panic!("unexpected setting"),
        });
        assert_eq!((config.build_ms(), config.verify_ms()), (0, 300_000));
    }
}
