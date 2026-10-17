use super::*;
#[test]
fn canonical_markers_are_refused_before_any_native_backend() {
    for name in ["canonical.sqlite", "canonical.sqlite-wal", "exex.db"] {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join(name), b"retained immutable history").unwrap();
        let options = Options {
            directory: directory.path().to_owned(),
            chain_id: "test".into(),
            backend: directory.path().join("not-a-backend"),
            backend_sha256: "00".repeat(32),
        };
        let error = resume(&options).unwrap_err().to_string();
        assert!(error.contains("modern canonical storage"), "{error}");
        assert_eq!(
            fs::read(directory.path().join(name)).unwrap(),
            b"retained immutable history"
        );
    }
}
#[test]
#[cfg(unix)]
fn linked_native_storage_and_canonical_markers_cannot_select_a_backend() {
    let directory = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink("absent", directory.path().join("canonical.sqlite")).unwrap();
    assert!(layout(directory.path())
        .unwrap_err()
        .to_string()
        .contains("modern canonical"));
    fs::remove_file(directory.path().join("canonical.sqlite")).unwrap();
    let other = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(other.path(), directory.path().join("chaindata")).unwrap();
    fs::create_dir(directory.path().join("irmin_store")).unwrap();
    assert!(layout(directory.path())
        .unwrap_err()
        .to_string()
        .contains("missing or linked"));
}
