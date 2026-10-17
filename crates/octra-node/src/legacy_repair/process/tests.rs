use super::*;
use serde_json::json;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    directory: tempfile::TempDir,
    backend: std::path::PathBuf,
    data: std::path::PathBuf,
    sha: String,
}
impl Fixture {
    fn new(body: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backend = directory.path().join("helper");
        let data = directory.path().join("native");
        fs::create_dir(&data).unwrap();
        fs::write(data.join("fork_repair.json"), b"retained-staged-plan").unwrap();
        let bytes = format!("#!/bin/sh\n{body}\n");
        fs::write(&backend, &bytes).unwrap();
        fs::set_permissions(&backend, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            sha: hex::encode(Sha256::digest(bytes.as_bytes())),
            directory,
            backend,
            data,
        }
    }
    fn session(&self) -> Session {
        let mut session =
            Session::open(&self.backend, &self.sha, &self.data, "fixture-chain").unwrap();
        session.timeout = Duration::from_secs(2);
        session.close_timeout = Duration::from_millis(100);
        session
    }
    fn retained(&self) {
        assert_eq!(
            fs::read(self.data.join("fork_repair.json")).unwrap(),
            b"retained-staged-plan"
        );
    }
}
const GREETING: &str = "printf '%s\\n' '{\"ok\":{\"hello\":true}}'";
const BUSY: &str = "while :; do :; done";

#[test]
fn verified_private_image_roundtrips_and_eof_closes_the_helper() {
    let fixture = Fixture::new(&format!(
        "{GREETING}\nwhile IFS= read -r request; do printf '%s\\n' '{{\"ok\":7}}'; done\nprintf closed > \"$1/closed\""
    ));
    let mut session = fixture.session();
    assert_eq!(session.receive().unwrap(), json!({"hello": true}));
    assert_eq!(
        fs::metadata(session.image.as_ref().unwrap().path().join("backend"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o500
    );
    assert_eq!(
        fs::metadata(session.image.as_ref().unwrap().path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    fs::write(&fixture.backend, b"replaced original executable").unwrap();
    assert_eq!(session.request(&json!({"op": "head"})).unwrap(), 7);
    session.close().unwrap();
    assert!(session.child.is_none());
    assert_eq!(fs::read(fixture.data.join("closed")).unwrap(), b"closed");
    assert!(session.receive().is_err());
    fixture.retained();
}

#[test]
fn drop_closes_stdin_and_reaps_before_removing_the_private_image() {
    let fixture = Fixture::new(&format!(
        "{GREETING}\nwhile IFS= read -r request; do :; done\nprintf closed > \"$1/closed\""
    ));
    let mut session = fixture.session();
    session.receive().unwrap();
    let image = session.image.as_ref().unwrap().path().to_owned();
    drop(session);
    assert_eq!(fs::read(fixture.data.join("closed")).unwrap(), b"closed");
    assert!(!image.exists());
    fixture.retained();
}

#[test]
fn wrong_hash_link_nonexecutable_and_oversized_image_never_start() {
    let fixture = Fixture::new("printf started > \"$1/started\"");
    assert!(Session::open(&fixture.backend, &"00".repeat(32), &fixture.data, "chain").is_err());
    let link = fixture.directory.path().join("linked-helper");
    symlink(&fixture.backend, &link).unwrap();
    assert!(Session::open(&link, &fixture.sha, &fixture.data, "chain").is_err());
    fs::set_permissions(&fixture.backend, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(Session::open(&fixture.backend, &fixture.sha, &fixture.data, "chain").is_err());
    fs::set_permissions(&fixture.backend, fs::Permissions::from_mode(0o700)).unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&fixture.backend)
        .unwrap()
        .set_len(MAX_IMAGE + 1)
        .unwrap();
    assert!(Session::open(&fixture.backend, &fixture.sha, &fixture.data, "chain").is_err());
    assert!(!fixture.data.join("started").exists());
    fixture.retained();
}

#[test]
fn malformed_refused_and_incomplete_responses_reap_without_disclosing_payloads() {
    for response in [
        "printf '%s\\n' invalid-json",
        "printf '%s\\n' '{\"error\":\"private-error-value\"}'",
        "printf '%s\\n' '{\"ok\":1,\"error\":\"private-error-value\"}'",
        "printf '%s' '{\"ok\":1}'",
        "exit 7",
    ] {
        let fixture = Fixture::new(response);
        let mut session = fixture.session();
        let error = session.receive().unwrap_err();
        assert!(!error.to_string().contains("private-error-value"));
        assert!(session.child.is_none());
        fixture.retained();
    }
}

#[test]
fn oversized_reply_is_bounded_and_reaps_the_writer() {
    let chunk = "x".repeat(8192);
    let fixture = Fixture::new(&format!(
        "i=0\nwhile [ \"$i\" -lt 129 ]; do printf '%s' '{chunk}'; i=$((i+1)); done\n{BUSY}"
    ));
    let mut session = fixture.session();
    let error = session.receive().unwrap_err();
    assert!(error.to_string().contains("exceeds bound"));
    assert!(session.child.is_none());
    assert!(session.pending.is_empty());
    fixture.retained();
}

#[test]
fn request_limit_includes_its_newline_and_fails_closed() {
    assert_eq!(encode(&json!("x".repeat(MAX - 3))).unwrap().len(), MAX);
    assert!(encode(&json!("x".repeat(MAX - 2))).is_err());
    let fixture = Fixture::new(&format!("{GREETING}\n{BUSY}"));
    let mut session = fixture.session();
    session.receive().unwrap();
    assert!(session.request(&json!("x".repeat(MAX))).is_err());
    assert!(session.child.is_none());
    fixture.retained();
}

#[test]
fn stalled_request_pipe_and_missing_reply_have_finite_deadlines() {
    for request in [json!({"op": "blocked-reply"}), json!("x".repeat(MAX - 3))] {
        let fixture = Fixture::new(&format!("{GREETING}\n{BUSY}"));
        let mut session = fixture.session();
        session.receive().unwrap();
        session.timeout = Duration::from_millis(100);
        let start = Instant::now();
        let error = session.request(&request).unwrap_err();
        assert!(error.to_string().contains("deadline exceeded"));
        assert!(start.elapsed() < Duration::from_secs(5));
        assert!(session.child.is_none());
        fixture.retained();
    }
}

#[test]
fn stalled_greeting_and_close_reap_only_the_owned_helper() {
    let fixture = Fixture::new(BUSY);
    let mut session = fixture.session();
    session.timeout = Duration::from_millis(100);
    assert!(session.receive().is_err());
    assert!(session.child.is_none());
    fixture.retained();

    let fixture = Fixture::new(&format!("{GREETING}\n{BUSY}"));
    let mut session = fixture.session();
    session.receive().unwrap();
    let start = Instant::now();
    assert!(session.close().is_err());
    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(session.child.is_none());
    fixture.retained();
}
