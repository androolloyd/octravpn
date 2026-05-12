//! `chisel` REPL smoke test — feed an EOF and ensure it terminates cleanly.

use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn chisel_quits_on_eof() {
    let mut child = Command::new(assert_cmd::cargo::cargo_bin("octra"))
        .args(["chisel"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Send `list_active_endpoints\n:quit\n` to exercise both the
    // shorthand and the `:quit` meta command.
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin
            .write_all(b"list_active_endpoints\n:quit\n")
            .unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "chisel exited non-zero: {out:?}");
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("octra chisel"), "stdout: {s}");
}
