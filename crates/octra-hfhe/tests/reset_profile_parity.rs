use octra_hfhe::recrypt::profile::{self, Kind, Params};
use serde_json::Value;
use sha2::{Digest, Sha256};
mod common;
#[test]
fn native_reset_profile_overflow_and_admission_arithmetic() {
    let fixture: Value =
        serde_json::from_str(include_str!("fixtures/reset_profiles.json")).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    assert_eq!(
        hex::encode(Sha256::digest(include_bytes!(
            "../../../scripts/node-port/hfhe-reset-profile-oracle.cpp"
        ))),
        fixture["oracle_sha256"]
    );
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 240);
    for (index, case) in cases.iter().enumerate() {
        let n = |key: &str| case[key].as_str().unwrap().parse::<usize>().unwrap();
        let kind = match case["kind"].as_u64().unwrap() {
            0 => Kind::None,
            1 => Kind::FieldNative,
            2 => Kind::ShaCompat,
            n => Kind::Unknown(n as u8),
        };
        let p = profile::plan(kind, n("target"));
        let params = Params {
            target_bits: n("target"),
            rounds: n("rounds"),
            branches: n("branches"),
            opened_branches: n("opened"),
        };
        let actual = [
            p.params.rounds,
            p.params.branches,
            p.params.opened_branches,
            p.params.target_bits,
            p.soundness_bits,
            p.branch_commits,
            p.branch_openings,
            p.trace_units,
            p.commit_bytes,
            p.opening_bytes,
            p.transcript_bytes,
            p.total_bytes,
            p.baseline_bytes,
            p.ratio_milli,
            usize::from(p.compact),
            usize::from(p.admitted),
            profile::rounds_for_target(params.target_bits, params.branches, params.opened_branches),
            params.soundness_bits(),
            params.branch_commits(),
            params.branch_openings(),
            usize::from(params.admitted()),
            profile::profile_bytes(n("units")),
        ];
        let expected = case["expected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| x.as_u64().unwrap() as usize)
            .collect::<Vec<_>>();
        assert_eq!(actual.as_slice(), expected, "profile {index}");
    }
}
