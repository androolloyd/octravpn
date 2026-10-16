//! Native snapshot bytes/root interchange; this grants no finality authority.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_runtime::{
    ledger_image::{self, Limits},
    state_batch::StateBatch,
};
use serde_json::Value;

fn decode(value: &Value) -> Vec<u8> {
    STANDARD.decode(value.as_str().unwrap()).unwrap()
}
fn fixtures() -> Value {
    serde_json::from_str(include_str!("fixtures/ledger-image.json")).unwrap()
}

#[test]
fn native_flat_bytes_and_shared_reference_restore_reproduce_the_exact_ledger_root() {
    let fixture = fixtures();
    assert_eq!(
        fixture["upstream_commit"],
        "7f9be4489870645cfcc95439638cde40f5da9f50"
    );
    let inputs = fixture["inputs"].as_array().unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(inputs.len(), cases.len());
    for (index, (input, expected)) in inputs.iter().zip(cases).enumerate() {
        let mut state = StateBatch::default();
        state.begin().unwrap();
        let mut paths = Vec::new();
        for row in input["rows"].as_array().unwrap() {
            let path = row["path"]
                .as_array()
                .unwrap()
                .iter()
                .map(decode)
                .collect::<Vec<_>>();
            state
                .set(
                    &path.iter().map(Vec::as_slice).collect::<Vec<_>>(),
                    decode(&row["value"]),
                )
                .unwrap();
            paths.push(path);
        }
        let state = state.snapshot();
        assert_eq!(
            hex::encode(state.root().unwrap()),
            expected["flat"]["root"].as_str().unwrap(),
            "native root case {index}"
        );
        let mut encoded = Vec::new();
        let written = ledger_image::write(&state, &mut encoded, Limits::default()).unwrap();
        assert_eq!(
            encoded,
            decode(&expected["flat"]["image_b64"]),
            "native flat bytes case {index}"
        );
        assert_eq!(
            written.records.to_string(),
            expected["flat"]["records"].as_str().unwrap()
        );
        assert_eq!(
            written.bytes.to_string(),
            expected["flat"]["bytes"].as_str().unwrap()
        );
        assert_eq!(
            serde_json::to_value(written.pvac_hashes).unwrap(),
            expected["flat"]["pvac_hashes"]
        );
        for format in ["flat", "shared"] {
            let expected = &expected[format];
            let raw = decode(&expected["image_b64"]);
            let restored = ledger_image::restore(
                raw.as_slice(),
                raw.len() as u64,
                expected["root"].as_str().unwrap(),
                Limits::default(),
            )
            .unwrap();
            assert_eq!(
                restored.state.root().unwrap(),
                state.root().unwrap(),
                "{format} root case {index}"
            );
            assert_eq!(
                restored.records.to_string(),
                expected["records"].as_str().unwrap()
            );
            assert_eq!(restored.bytes, raw.len() as u64);
            for path in &paths {
                let path = path.iter().map(Vec::as_slice).collect::<Vec<_>>();
                assert_eq!(restored.state.get(&path), state.get(&path));
            }
        }
    }
}

#[test]
fn incomplete_trailing_conflicting_and_locally_excessive_images_never_restore() {
    let fixture = fixtures();
    let expected = &fixture["cases"][2];
    for format in ["flat", "shared"] {
        let raw = decode(&expected[format]["image_b64"]);
        let root = expected[format]["root"].as_str().unwrap();
        for end in [0, 1, 8, raw.len() / 2, raw.len() - 1] {
            assert!(
                ledger_image::restore(&raw[..end], end as u64, root, Limits::default()).is_err()
            );
        }
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(ledger_image::restore(
            trailing.as_slice(),
            trailing.len() as u64,
            root,
            Limits::default()
        )
        .is_err());
        assert!(ledger_image::restore(
            raw.as_slice(),
            raw.len() as u64,
            &"0".repeat(128),
            Limits::default()
        )
        .is_err());
        for limits in [
            Limits {
                bytes: raw.len() as u64 - 1,
                ..Limits::default()
            },
            Limits {
                records: 0,
                ..Limits::default()
            },
            Limits {
                string_bytes: 0,
                ..Limits::default()
            },
        ] {
            assert!(ledger_image::restore(raw.as_slice(), raw.len() as u64, root, limits).is_err());
        }
    }
}
