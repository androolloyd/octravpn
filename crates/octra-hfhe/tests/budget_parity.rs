mod common;

use octra_hfhe::{
    encrypt,
    keys::{keygen_from_seed, Params},
};
use serde_json::Value;

#[test]
fn native_noise_budgets_match_at_cancellation_and_floor_boundaries() {
    let fixture_json = std::env::var_os("OCTRA_HFHE_BUDGET_FIXTURE").map_or_else(
        || include_str!("fixtures/noise-budget.json").to_owned(),
        |path| std::fs::read_to_string(path).expect("read native budget fixture"),
    );
    let fixture: Value = serde_json::from_str(&fixture_json).unwrap();
    let sources: Value =
        serde_json::from_str(include_str!("../../../docs/rust-node/source-map.json")).unwrap();
    common::assert_source_pin(&fixture, &sources);
    for (source, hash) in fixture["source_sha256"].as_object().unwrap() {
        assert_eq!(*hash, sources["files"][source]);
    }
    let architecture = std::env::consts::ARCH;
    assert_eq!(fixture["host_os"], std::env::consts::OS,
        "budget fixtures must be generated on this OS/libm; set OCTRA_HFHE_BUDGET_FIXTURE to freshly generated native evidence");
    assert!(
        !fixture["targets"][architecture].is_null(),
        "unqualified native budget architecture"
    );
    assert_eq!(
        fixture["targets"][architecture]["operating_system"],
        std::env::consts::OS
    );
    assert!(
        fixture["targets"][architecture]["contraction_sensitive_cases"]
            .as_u64()
            .unwrap()
            > 0
    );
    for (index, case) in fixture["cases"].as_array().unwrap().iter().enumerate() {
        let float = |name: &str| {
            f64::from_bits(
                u64::from_str_radix(case[format!("{name}_bits")].as_str().unwrap(), 16).unwrap(),
            )
        };
        let params = Params {
            basis: case["basis"].as_i64().unwrap() as i32,
            m_bits: 65,
            n_bits: 17,
            h_col_weight: 13,
            x_col_weight: 7,
            error_weight: 2,
            lpn_n: 65,
            lpn_t: 129,
            noise_entropy_bits: float("entropy"),
            depth_slope_bits: float("slope"),
            tuple2_fraction: float("fraction"),
            ..Params::default()
        };
        let (public, _) = keygen_from_seed(params, &[0; 32]).unwrap();
        let actual = encrypt::plan_noise(&public, case["depth"].as_i64().unwrap() as i32).unwrap();
        assert_eq!(
            actual,
            (
                case["expected"][architecture]["n2"].as_u64().unwrap() as usize,
                case["expected"][architecture]["n3"].as_u64().unwrap() as usize
            ),
            "case {index}: {}",
            case["kind"]
        );
    }
}
