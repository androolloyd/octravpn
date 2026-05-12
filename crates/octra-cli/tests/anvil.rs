//! `octra anvil` — smoke test that the server starts and responds.
//!
//! We pick a high random port to avoid collisions with developer-run
//! services. The child process is killed after a successful probe.

use std::process::Stdio;
use std::time::{Duration, Instant};

use assert_cmd::Command as AssertCommand;

fn cmd() -> AssertCommand {
    AssertCommand::cargo_bin("octra").unwrap()
}

fn pick_port() -> u16 {
    use std::net::TcpListener;
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

#[test]
fn anvil_serves_node_status() {
    let port = pick_port();
    let bin = AssertCommand::cargo_bin("octra")
        .unwrap()
        .get_program()
        .to_owned();
    let mut child = std::process::Command::new(bin)
        .args(["anvil", "--port", &port.to_string()])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    // Wait up to 5s for the listener to come up.
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("anvil failed to start within 5s on port {port}");
        }
        let probe = std::net::TcpStream::connect_timeout(
            &format!("127.0.0.1:{port}").parse().unwrap(),
            Duration::from_millis(50),
        );
        if probe.is_ok() {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Issue an `octra cast rpc node_status` against the running anvil.
    cmd()
        .args(["cast", "rpc", "node_status", "--rpc-url"])
        .arg(format!("http://127.0.0.1:{port}/rpc"))
        .assert()
        .success()
        .stdout(predicates::str::contains("\"epoch\""));
    let _ = child.kill();
    let _ = child.wait();
}
