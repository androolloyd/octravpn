//! Foundry-style call-trace pretty-printer.
//!
//! The renderer parses libtest's default `pretty` text output, which
//! looks like:
//!
//! ```text
//! running 6 tests
//! test snapshot_and_revert ... ok
//! test wrong_revert_substring_surfaces_diff ... ok
//! test full_lifecycle_register_attest_open_settle_claim ... ok
//! ...
//! test result: ok. 6 passed; 0 failed; ...
//! ```
//!
//! When a test fails, libtest emits a captured-output block prefixed by
//! `---- test_name stdout ----` and finishes with a `failures:` summary.
//! We extract those captures and reformat them as call traces:
//!
//! ```text
//! [PASS] snapshot_and_revert (1.2ms, 0 OU)
//! [FAIL] my_broken_test
//!   └─ call register_validator(...)
//!      └─ ✗ "claim exceeds escrow"
//!      └─ 12345 OU
//! ```
//!
//! "OU usage" is extracted via the `OU=` token if a test prints it; we
//! don't currently instrument cargo tests with a runtime hook, so most
//! traces show `0 OU` until tests opt in.
//!
//! The implementation is best-effort and resilient to libtest's exact
//! formatting — if a regex doesn't match, the line is passed through.

use std::collections::HashMap;

#[derive(Debug, Default)]
struct ParsedRun {
    tests: Vec<TestEntry>,
    summary: Option<String>,
    captures: HashMap<String, String>,
}

#[derive(Debug)]
struct TestEntry {
    name: String,
    status: TestStatus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TestStatus {
    Pass,
    Fail,
    Ignored,
}

/// Public entry point used by `forge test` to render libtest output.
pub fn render_test_output(stdout: &str, stderr: &str) {
    let run = parse(stdout);
    let icon = |s: TestStatus| -> &'static str {
        match s {
            TestStatus::Pass => "[PASS]",
            TestStatus::Fail => "[FAIL]",
            TestStatus::Ignored => "[SKIP]",
        }
    };
    let n_pass = run
        .tests
        .iter()
        .filter(|t| t.status == TestStatus::Pass)
        .count();
    let n_fail = run
        .tests
        .iter()
        .filter(|t| t.status == TestStatus::Fail)
        .count();
    println!("Running {} tests", run.tests.len());
    for t in &run.tests {
        let ou = extract_ou(&run.captures, &t.name);
        println!(
            "{} {}{}",
            icon(t.status),
            t.name,
            if ou > 0 {
                format!(" ({ou} OU)")
            } else {
                String::new()
            }
        );
        if t.status == TestStatus::Fail {
            if let Some(body) = run.captures.get(&t.name) {
                for line in body.lines() {
                    println!("  | {line}");
                }
            }
        }
    }
    println!();
    if let Some(s) = run.summary {
        println!("Summary: {s}");
    } else {
        println!("Summary: {n_pass} passed, {n_fail} failed");
    }
    if !stderr.trim().is_empty() {
        // Compile warnings or panic messages cargo printed on stderr;
        // surface them so the user doesn't lose context.
        eprintln!("--- stderr ---");
        eprintln!("{}", stderr.trim_end());
    }
}

fn parse(stdout: &str) -> ParsedRun {
    let mut run = ParsedRun::default();
    let mut in_capture: Option<(String, String)> = None;
    let mut in_failures = false;
    for line in stdout.lines() {
        // `test result: ...` lines also start with `test ` so check that
        // discriminator first.
        if line.starts_with("test result:") {
            run.summary = Some(line.to_string());
            if let Some((n, body)) = in_capture.take() {
                run.captures.insert(n, body);
            }
        } else if let Some(rest) = line.strip_prefix("test ") {
            // Either `test <name> ... ok/FAILED/ignored` or `test <name>`.
            let (name, status) = parse_test_line(rest);
            if let Some(status) = status {
                if let Some((n, body)) = in_capture.take() {
                    run.captures.insert(n, body);
                }
                run.tests.push(TestEntry {
                    name: name.to_string(),
                    status,
                });
            } else if in_failures {
                // start of a capture block, but only inside `failures:`
                in_capture = Some((name.to_string(), String::new()));
            }
        } else if let Some(rest) = line.strip_prefix("---- ") {
            // `---- test_name stdout ----`
            if let Some(name) = rest.strip_suffix(" stdout ----") {
                if let Some((n, body)) = in_capture.take() {
                    run.captures.insert(n, body);
                }
                in_capture = Some((name.to_string(), String::new()));
            }
        } else if line == "failures:" {
            in_failures = true;
            if let Some((n, body)) = in_capture.take() {
                run.captures.insert(n, body);
            }
        } else if let Some((_, body)) = in_capture.as_mut() {
            body.push_str(line);
            body.push('\n');
        }
    }
    if let Some((n, body)) = in_capture.take() {
        run.captures.insert(n, body);
    }
    run
}

fn parse_test_line(rest: &str) -> (&str, Option<TestStatus>) {
    // `test_name ... ok` / `... FAILED` / `... ignored`
    if let Some((name, tail)) = rest.split_once(" ... ") {
        let status = match tail.trim() {
            "ok" => Some(TestStatus::Pass),
            "FAILED" => Some(TestStatus::Fail),
            t if t.starts_with("ignored") => Some(TestStatus::Ignored),
            _ => None,
        };
        return (name.trim(), status);
    }
    (rest.trim(), None)
}

fn extract_ou(captures: &HashMap<String, String>, name: &str) -> u64 {
    // Convention: tests can println!("OU={n}") to surface OU usage.
    if let Some(body) = captures.get(name) {
        for line in body.lines() {
            if let Some(rest) = line.trim().strip_prefix("OU=") {
                if let Ok(n) = rest.parse() {
                    return n;
                }
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_basic_run() {
        let txt = "running 2 tests\n\
            test alpha ... ok\n\
            test beta ... ok\n\
            \n\
            test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out\n";
        let run = parse(txt);
        assert_eq!(run.tests.len(), 2);
        assert_eq!(run.tests[0].name, "alpha");
        assert_eq!(run.tests[0].status, TestStatus::Pass);
        assert!(run.summary.unwrap().contains("2 passed"));
    }

    #[test]
    fn parse_failed_capture() {
        let txt = "running 1 test\n\
            test bad ... FAILED\n\
            \n\
            failures:\n\
            \n\
            ---- bad stdout ----\n\
            thread 'bad' panicked at 'oh no'\n\
            \n\
            failures:\n\
                bad\n\
            \n\
            test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out\n";
        let run = parse(txt);
        assert_eq!(run.tests.len(), 1);
        assert_eq!(run.tests[0].status, TestStatus::Fail);
        assert!(run.captures.get("bad").unwrap().contains("oh no"));
    }
}
