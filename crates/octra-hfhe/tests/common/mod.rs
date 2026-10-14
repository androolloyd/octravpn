pub(crate) fn assert_source_pin(fixture: &serde_json::Value, sources: &serde_json::Value) {
    let pin = fixture["upstream_commit"]
        .as_str()
        .expect("fixture source revision");
    assert!(
        sources["upstream_commit"].as_str() == Some(pin)
            || sources["source_equivalent_commits"]
                .as_array()
                .is_some_and(|pins| pins.iter().any(|prior| prior.as_str() == Some(pin))),
        "unreviewed fixture source revision: {pin}"
    );
}
