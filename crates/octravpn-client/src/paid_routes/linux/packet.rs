//! Packet enforcement is necessary even when policy routing rejects a lookup:
//! Linux can synthesize a direct route for SO_BINDTODEVICE sockets.
use super::super::{network::Bypass, validate_interface};
use anyhow::{ensure, Context, Result};
use std::{
    io::Write,
    net::SocketAddrV4,
    process::{Command, Stdio},
};

const CHAIN: &str = "OCTRA_PAID";
const TOOLS: [&str; 2] = ["iptables", "ip6tables"];

#[derive(Clone)]
pub(super) struct Guard {
    rules: [Vec<String>; 2],
}
impl Guard {
    pub(super) fn new(
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        names: &[String],
        mark: Option<u32>,
        bypasses: &[Bypass],
    ) -> Result<Self> {
        ensure!(
            names.len() >= 2 && controls.len() == names.len() && peers.len() + 1 == names.len(),
            "invalid packet-guard route"
        );
        for name in names {
            validate_interface(name)?;
        }
        ensure!(mark != Some(0), "zero chain socket mark");
        let mut v4 = vec![
            format!("-A {CHAIN} -o lo -j RETURN"),
            format!("-A {CHAIN} -d 100.64.0.0/10 -o tailscale0 -j RETURN"),
            format!(
                "-A {CHAIN} -o {} -j RETURN",
                names.last().context("exit interface missing")?
            ),
        ];
        if let Some(mark) = mark {
            v4.push(format!(
                "-A {CHAIN} -o {} -m mark --mark 0x{mark:x} -j RETURN",
                names[0]
            ));
        }
        for (peer, protocol) in [(entry, "udp"), (controls[0], "tcp")] {
            if peer.ip().is_loopback() {
                continue;
            }
            let bypass = bypasses
                .iter()
                .find(|b| b.address == *peer.ip())
                .context("packet guard has no accepted physical endpoint")?;
            validate_interface(&bypass.device)?;
            v4.push(endpoint(&bypass.device, peer, protocol));
        }
        for (index, peer) in peers.iter().enumerate() {
            v4.push(endpoint(&names[index], *peer, "udp"));
            if !controls[index + 1].ip().is_loopback() {
                v4.push(endpoint(&names[index], controls[index + 1], "tcp"));
            }
        }
        v4.push(format!(
            "-A {CHAIN} -j REJECT --reject-with icmp-port-unreachable"
        ));
        Ok(Self {
            rules: [
                v4,
                vec![
                    format!("-A {CHAIN} -o lo -j RETURN"),
                    format!("-A {CHAIN} -j REJECT --reject-with icmp6-port-unreachable"),
                ],
            ],
        })
    }
    pub(super) fn reserve(&self, retained: bool) -> Result<[bool; 2]> {
        let mut present = [false; 2];
        for (index, tool) in TOOLS.iter().enumerate() {
            let output = Command::new(format!("{tool}-save"))
                .args(["-t", "filter"])
                .output()
                .context("inspect paid packet guard")?;
            ensure!(
                output.status.success(),
                "inspect paid packet guard: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            present[index] = inspect(&String::from_utf8(output.stdout)?, &self.rules[index])?;
        }
        ensure!(
            retained || !present.iter().any(|p| *p),
            "unowned paid packet guard already exists"
        );
        Ok(present)
    }
    pub(super) fn install(&self, retained: bool) -> Result<()> {
        let present = self.reserve(retained)?;
        for (index, exists) in present.into_iter().enumerate() {
            if !exists {
                let body = format!(
                    "*filter\n:{CHAIN} - [0:0]\n{}\n-I OUTPUT 1 -j {CHAIN}\nCOMMIT\n",
                    self.rules[index].join("\n")
                );
                restore(TOOLS[index], &body)?;
            }
        }
        self.check()
    }
    pub(super) fn check(&self) -> Result<()> {
        ensure!(
            self.reserve(true)?.into_iter().all(|p| p),
            "paid packet guard is incomplete"
        );
        Ok(())
    }
    pub(super) fn remove(&self) -> Result<()> {
        self.check()?;
        for tool in TOOLS.into_iter().rev() {
            restore(
                tool,
                &format!("*filter\n-D OUTPUT -j {CHAIN}\n-F {CHAIN}\n-X {CHAIN}\nCOMMIT\n"),
            )?;
        }
        Ok(())
    }
}
fn endpoint(device: &str, peer: SocketAddrV4, protocol: &str) -> String {
    format!(
        "-A {CHAIN} -d {}/32 -o {device} -p {protocol} -m {protocol} --dport {} -j RETURN",
        peer.ip(),
        peer.port()
    )
}
fn restore(tool: &str, body: &str) -> Result<()> {
    let mut child = Command::new(format!("{tool}-restore"))
        .args(["--noflush", "--wait", "5"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("start paid packet guard transaction")?;
    let written = child
        .stdin
        .take()
        .context("packet guard stdin missing")?
        .write_all(body.as_bytes());
    let output = child.wait_with_output()?;
    written.context("write paid packet guard transaction")?;
    ensure!(
        output.status.success(),
        "paid packet guard transaction: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

/// Counter values are not authority. Every owned rule, reference and its order
/// must match, and the guard must precede any other OUTPUT rule.
fn inspect(saved: &str, expected: &[String]) -> Result<bool> {
    let header = format!(":{CHAIN} - ");
    let jump = format!("-A OUTPUT -j {CHAIN}");
    let mut found = false;
    let mut rules = Vec::new();
    let mut jumps = 0;
    let mut output_seen = false;
    for line in saved.lines() {
        let words = line.split_whitespace().collect::<Vec<_>>();
        if line.starts_with(&format!(":{CHAIN} ")) {
            ensure!(
                !found
                    && line.starts_with(&header)
                    && line
                        .strip_prefix(&header)
                        .is_some_and(|s| s.starts_with('[')
                            && s.ends_with(']')
                            && s[1..s.len() - 1]
                                .split_once(':')
                                .is_some_and(
                                    |(a, b)| a.parse::<u64>().is_ok() && b.parse::<u64>().is_ok()
                                )),
                "unowned paid packet chain definition"
            );
            found = true;
        } else if words.get(0..2) == Some(&["-A", CHAIN]) {
            rules.push(line.to_owned());
        } else if words.contains(&CHAIN) {
            ensure!(
                line == jump && !output_seen,
                "unowned or shadowed paid packet guard reference"
            );
            jumps += 1;
        }
        if words.get(0..2) == Some(&["-A", "OUTPUT"]) {
            output_seen = true;
        }
    }
    if !found {
        ensure!(jumps == 0 && rules.is_empty(), "orphaned paid packet guard");
        return Ok(false);
    }
    ensure!(
        jumps == 1 && rules == expected,
        "retained paid packet guard differs from accepted route"
    );
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn retained_guard_rejects_foreign_rules_references_and_shadowing() {
        let expected = vec![format!("-A {CHAIN} -o lo -j RETURN")];
        let saved = format!(
            "*filter\n:{CHAIN} - [12:34]\n-A OUTPUT -j {CHAIN}\n{}\nCOMMIT\n",
            expected[0]
        );
        assert!(inspect(&saved, &expected).unwrap());
        assert!(!inspect("*filter\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n", &expected).unwrap());
        for changed in [
            saved.replace("12:34", "invalid"),
            saved.replace("-o lo", "-o eth0"),
            saved.replace("-A OUTPUT", "-A INPUT"),
            saved.replace("-A OUTPUT", "-A OUTPUT -j ACCEPT\n-A OUTPUT"),
            saved.replace("COMMIT", &format!("-A OUTPUT -j {CHAIN}\nCOMMIT")),
            saved.replace("COMMIT", &format!("-A OTHER -g {CHAIN}\nCOMMIT")),
        ] {
            assert!(inspect(&changed, &expected).is_err(), "{changed}");
        }
    }
}
