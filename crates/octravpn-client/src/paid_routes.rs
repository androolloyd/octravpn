//! Opt-in Linux host routes for one authenticated, paid IPv4 exit.
//!
//! This is deliberately separate from the WireGuard transport. Route changes
//! happen only after its handshake, and an unexpected exit retains blackhole
//! routes. Only an explicit `disconnect` restores the host's ordinary routes.
//! Stock Tailscale traffic to 100.64.0.0/10 stays on tailscale0.
//!
//! Recovery after a crash is intentionally manual: verify no paid-exit client
//! still holds `/run/octravpn-paid-exit.lock`, inspect `ip -4 -j route show
//! proto 186` and `ip -6 -j route show proto 186`, and confirm every route has
//! this module's exact prefix/type/device and metric 45678 or 45679. Remove
//! only those verified routes with matching `ip route del` commands. Never
//! flush protocol 186 blindly; it is a numeric Linux route tag, not ownership
//! proof. The /1 blackholes must remain until the user deliberately recovers.

use std::{
    net::{SocketAddr, SocketAddrV4},
    time::Duration,
};

use anyhow::{bail, Result};

/// An armed route lease. Dropping it does not release the kill switch.
/// Call `disconnect` only for a user-requested, clean disconnect.
pub(crate) struct PaidRouteGuard {
    #[cfg(target_os = "linux")]
    lease: linux::Lease,
}

impl PaidRouteGuard {
    /// Resolve and pin a usable public IPv4 operator peer before escrow.
    /// The transport must connect to this exact address and pass the same
    /// authenticated socket peer to `activate`; a second DNS lookup is unsafe.
    pub(crate) async fn resolve_public_peer(endpoint: &str) -> Result<SocketAddrV4> {
        crate::wireguard::validate_endpoint(endpoint)?;
        let addresses =
            tokio::time::timeout(Duration::from_secs(10), tokio::net::lookup_host(endpoint))
                .await
                .map_err(|_| anyhow::anyhow!("operator endpoint DNS lookup timed out"))??;
        addresses
            .filter_map(|address| match address {
                SocketAddr::V4(peer)
                    if octravpn_core::ip_tunnel::public_ipv4(*peer.ip()) && peer.port() != 0 =>
                {
                    Some(peer)
                }
                _ => None,
            })
            .next()
            .ok_or_else(|| {
                anyhow::anyhow!("operator endpoint has no public IPv4 address for paid exit")
            })
    }

    /// Read-only capability check to run before opening paid escrow. The TUN
    /// does not exist yet, so activation repeats all checks after handshake.
    pub(crate) fn preflight(tun_name: &str) -> Result<()> {
        validate_interface(tun_name)?;
        if tun_name == "tailscale0" {
            bail!("paid exit TUN must differ from the personal Tailscale interface");
        }
        #[cfg(target_os = "linux")]
        {
            linux::preflight()
        }
        #[cfg(not(target_os = "linux"))]
        {
            bail!("paid host exit is disabled on this platform until a crash-safe route guard is available");
        }
    }

    /// Finish the read-only pre-escrow check with the pinned peer returned by
    /// `resolve_public_peer`.
    pub(crate) fn preflight_for_peer(tun_name: &str, peer: SocketAddrV4) -> Result<()> {
        Self::preflight(tun_name)?;
        if !octravpn_core::ip_tunnel::public_ipv4(*peer.ip()) || peer.port() == 0 {
            bail!("paid exit requires a public IPv4 operator endpoint");
        }
        #[cfg(target_os = "linux")]
        {
            linux::preflight_peer(tun_name, peer)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = peer;
            Ok(())
        }
    }

    /// `peer` must be the *actual* peer selected by the authenticated UDP
    /// socket, never a second DNS lookup of the operator's hostname.
    pub(crate) fn activate(tun_name: &str, peer: SocketAddr) -> Result<Self> {
        let SocketAddr::V4(peer) = peer else {
            bail!("paid IPv4 exit requires an IPv4 operator endpoint");
        };
        if !octravpn_core::ip_tunnel::public_ipv4(*peer.ip()) {
            bail!("paid exit requires a public IPv4 operator endpoint");
        }
        validate_interface(tun_name)?;
        if tun_name == "tailscale0" {
            bail!("paid exit TUN must differ from the personal Tailscale interface");
        }
        #[cfg(target_os = "linux")]
        {
            Ok(Self {
                lease: linux::Lease::activate(tun_name, peer)?,
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (tun_name, peer);
            bail!("paid host exit is disabled on this platform until a crash-safe route guard is available");
        }
    }

    /// Intentionally restore direct host routing after a clean user disconnect.
    /// An error leaves the remaining blocking routes in place for manual repair.
    pub(crate) fn disconnect(self) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            self.lease.disconnect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(())
        }
    }
}

fn validate_interface(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("invalid paid exit TUN name");
    }
    Ok(())
}

#[cfg(any(target_os = "linux", test))]
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
mod linux {
    use std::{fs::File, net::SocketAddrV4, os::unix::fs::MetadataExt, process::Command};

    use anyhow::{anyhow, bail, Context, Result};
    use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags, CWD};
    use serde_json::Value;

    // Unique to this app's route lease; collisions are rejected before edits.
    const PROTO: &str = "186";
    const PAID_METRIC: &str = "45678";
    const BLOCK_METRIC: &str = "45679";

    #[derive(Clone, Debug, Eq, PartialEq)]
    struct Route {
        family: &'static str,
        args: Vec<String>,
    }

    impl Route {
        fn new(family: &'static str, args: &[&str]) -> Self {
            Self {
                family,
                args: args.iter().map(|s| (*s).to_owned()).collect(),
            }
        }

        fn call(&self, runner: &impl Runner, verb: &str) -> Result<()> {
            let mut args = vec![self.family.to_owned(), "route".into(), verb.into()];
            args.extend(self.args.iter().cloned());
            runner.run(&args).map(|_| ())
        }
    }

    trait Runner {
        fn run(&self, args: &[String]) -> Result<String>;
    }

    struct System;

    impl Runner for System {
        fn run(&self, args: &[String]) -> Result<String> {
            let output = Command::new("ip")
                .args(args)
                .output()
                .with_context(|| format!("start `ip {}`", args.join(" ")))?;
            if !output.status.success() {
                bail!(
                    "`ip {}` failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&output.stderr).trim()
                );
            }
            String::from_utf8(output.stdout).context("ip command returned non-UTF8 output")
        }
    }

    pub(super) struct Lease {
        _lock: File,
        routes: Vec<Route>,
    }

    pub(super) fn preflight() -> Result<()> {
        let status = std::fs::read_to_string("/proc/self/status")
            .context("read Linux effective capabilities")?;
        let effective_uid = status
            .lines()
            .find_map(|line| line.strip_prefix("Uid:").map(str::trim))
            .and_then(|fields| fields.split_whitespace().nth(1))
            .context("Linux effective uid is unavailable")?;
        if effective_uid != "0" {
            bail!("paid host exit requires root before opening escrow");
        }
        let cap_eff = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:").map(str::trim))
            .context("Linux CapEff is unavailable")?;
        let caps = u64::from_str_radix(cap_eff, 16).context("parse Linux CapEff")?;
        if caps & (1 << 12) == 0 {
            bail!("paid host exit requires CAP_NET_ADMIN before opening escrow");
        }
        match std::fs::symlink_metadata("/run/octravpn-paid-exit.lock") {
            Ok(metadata) => verify_lock_metadata(&metadata)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect paid-exit route lock"),
        }
        let runner = System;
        reject_stale(&runner)?;
        require_address(&runner, "tailscale0", true)?;
        require_physical_public_path(&runner)?;
        require_ipv6_guard_capability(&runner)?;
        Ok(())
    }

    pub(super) fn preflight_peer(tun_name: &str, peer: SocketAddrV4) -> Result<()> {
        let output = System.run(&vec![
            "-4".into(),
            "-j".into(),
            "route".into(),
            "get".into(),
            peer.ip().to_string(),
        ])?;
        let route = json_array(&output)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no pre-exit route to operator endpoint"))?;
        let dev = route["dev"]
            .as_str()
            .context("operator route has no device")?;
        super::validate_interface(dev)?;
        if dev == tun_name || dev == "tailscale0" {
            bail!("operator endpoint has no independent physical bypass route");
        }
        if let Some(gateway) = route["gateway"].as_str() {
            gateway
                .parse::<std::net::Ipv4Addr>()
                .context("operator bypass gateway is not IPv4")?;
        }
        Ok(())
    }

    impl Lease {
        pub(super) fn activate(tun_name: &str, peer: SocketAddrV4) -> Result<Self> {
            // A process lock prevents two paid exits from racing for host routes.
            // On crash the lock releases, but stale blackholes remain and cause
            // the next preflight to refuse rather than silently restore traffic.
            let lock = File::from(
                openat(
                    CWD,
                    "/run/octravpn-paid-exit.lock",
                    OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                    Mode::RUSR | Mode::WUSR,
                )
                .context("open paid-exit host route lock (root privileges required)")?,
            );
            verify_lock_metadata(&lock.metadata().context("inspect paid-exit route lock")?)?;
            flock(&lock, FlockOperation::NonBlockingLockExclusive)
                .context("another paid-exit route lease is active")?;
            let routes = activate_with(&System, tun_name, peer)?;
            Ok(Self {
                _lock: lock,
                routes,
            })
        }

        pub(super) fn disconnect(self) -> Result<()> {
            disconnect_with(&System, &self.routes)
        }
    }

    fn disconnect_with(runner: &impl Runner, routes: &[Route]) -> Result<()> {
        // Do not remove the blackholes if any earlier deletion fails.
        // A route-management error requires explicit operator repair.
        for (index, route) in routes.iter().enumerate().rev() {
            // Closing the TUN removes its two device routes in the kernel.
            // The caller normally reaches us after `ready.run` has dropped
            // that interface, so absence of precisely those routes is fine.
            if index >= routes.len() - 2 && !paid_route_present(runner, route)? {
                continue;
            }
            route.call(runner, "del")?;
        }
        Ok(())
    }

    fn verify_lock_metadata(metadata: &std::fs::Metadata) -> Result<()> {
        if !metadata.is_file()
            || metadata.uid() != 0
            || metadata.mode() & 0o777 != 0o600
            || metadata.nlink() != 1
        {
            bail!("paid-exit route lock has unsafe owner, mode, or link count");
        }
        Ok(())
    }

    fn paid_route_present(runner: &impl Runner, route: &Route) -> Result<bool> {
        let output = runner.run(&vec![
            "-4".into(),
            "-j".into(),
            "route".into(),
            "show".into(),
            "proto".into(),
            PROTO.into(),
        ])?;
        let prefix = route.args.first().context("paid route has no prefix")?;
        let device = route.args.get(2).context("paid route has no device")?;
        Ok(json_array(&output)?.iter().any(|item| {
            item["dst"].as_str() == Some(prefix.as_str())
                && item["dev"].as_str() == Some(device.as_str())
                && item["metric"].as_u64() == Some(45_678)
        }))
    }

    // Routes are returned in insertion order. The paid routes are added last;
    // disconnect deletes them first while the blockers are still present.
    fn activate_with(
        runner: &impl Runner,
        tun_name: &str,
        peer: SocketAddrV4,
    ) -> Result<Vec<Route>> {
        reject_stale(runner)?;
        require_address(runner, tun_name, false)?;
        require_address(runner, "tailscale0", true)?;
        require_physical_public_path(runner)?;
        let route_get = runner.run(&vec![
            "-4".into(),
            "-j".into(),
            "route".into(),
            "get".into(),
            peer.ip().to_string(),
        ])?;
        let first = json_array(&route_get)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("no pre-exit route to operator endpoint"))?;
        let dev = first["dev"]
            .as_str()
            .context("operator route has no device")?;
        super::validate_interface(dev)?;
        if dev == tun_name || dev == "tailscale0" {
            bail!("operator endpoint has no independent physical bypass route");
        }
        let gateway = first["gateway"].as_str();
        if let Some(gateway) = gateway {
            gateway
                .parse::<std::net::Ipv4Addr>()
                .context("operator bypass gateway is not IPv4")?;
        }
        let routes = plan(tun_name, peer, dev, gateway);
        let mut installed: Vec<Route> = Vec::new();
        let mut blockers_complete = false;
        for (index, route) in routes.iter().enumerate() {
            if let Err(error) = route.call(runner, "add") {
                if blockers_complete {
                    // Paid routes (the final two entries) may have been added.
                    // Remove only those, leaving the IPv4/IPv6 kill switch.
                    for paid in installed.iter().skip(routes.len() - 2).rev() {
                        let _ = paid.call(runner, "del");
                    }
                    return Err(
                        error.context("paid-exit activation failed; blocking routes retained")
                    );
                }
                for installed_route in installed.iter().rev() {
                    let _ = installed_route.call(runner, "del");
                }
                return Err(error.context("paid-exit activation failed before traffic diversion"));
            }
            installed.push(route.clone());
            if index == routes.len() - 3 {
                blockers_complete = true;
            }
        }
        // Check the effective routes, including any stock Tailscale policy
        // rules. A mismatch leaves the kill switch armed for explicit repair.
        for (address, expected) in [
            ("1.1.1.1".to_owned(), tun_name),
            ("129.0.0.1".to_owned(), tun_name),
            ("100.100.100.100".to_owned(), "tailscale0"),
            (peer.ip().to_string(), dev),
        ] {
            let output = runner.run(&vec![
                "-4".into(),
                "-j".into(),
                "route".into(),
                "get".into(),
                address.clone(),
            ])?;
            let observed = json_array(&output)?;
            let got = observed
                .first()
                .and_then(|route| route["dev"].as_str())
                .unwrap_or("");
            if got != expected {
                bail!("paid-exit route check for {address} selected {got:?}, expected {expected:?}; blocking routes retained");
            }
        }
        Ok(installed)
    }

    fn reject_stale(runner: &impl Runner) -> Result<()> {
        for family in ["-4", "-6"] {
            let output = runner.run(&vec![
                family.into(),
                "-j".into(),
                "route".into(),
                "show".into(),
                "proto".into(),
                PROTO.into(),
            ])?;
            if !json_array(&output)?.is_empty() {
                bail!("existing octravpn paid-exit routes detected; explicit recovery is required before another session");
            }
        }
        Ok(())
    }

    fn require_physical_public_path(runner: &impl Runner) -> Result<()> {
        for address in ["1.1.1.1", "129.0.0.1"] {
            let output = runner.run(&vec![
                "-4".into(),
                "-j".into(),
                "route".into(),
                "get".into(),
                address.into(),
            ])?;
            let route = json_array(&output)?
                .first()
                .cloned()
                .ok_or_else(|| anyhow!("no pre-exit route for {address}"))?;
            if route["dev"].as_str() == Some("tailscale0") {
                bail!(
                    "another Tailscale exit is active; disable it before opening paid-exit escrow"
                );
            }
        }
        Ok(())
    }

    fn require_ipv6_guard_capability(runner: &impl Runner) -> Result<()> {
        let output = runner.run(&vec![
            "-6".into(),
            "-j".into(),
            "address".into(),
            "show".into(),
            "dev".into(),
            "lo".into(),
        ])?;
        let loopback_present = json_array(&output)?.iter().any(|row| {
            row["addr_info"].as_array().is_some_and(|addresses| {
                addresses
                    .iter()
                    .any(|address| address["family"] == "inet6" && address["local"] == "::1")
            })
        });
        if !loopback_present {
            bail!("IPv6 route guard is unavailable; paid exit cannot safely block IPv6 leaks");
        }
        Ok(())
    }

    fn require_address(runner: &impl Runner, interface: &str, tailnet: bool) -> Result<()> {
        let output = runner.run(&vec![
            "-4".into(),
            "-j".into(),
            "address".into(),
            "show".into(),
            "dev".into(),
            interface.into(),
        ])?;
        let rows = json_array(&output)?;
        let has_ipv4 = rows.iter().any(|row| {
            row["addr_info"].as_array().is_some_and(|addresses| {
                addresses.iter().any(|address| {
                    address["family"] == "inet"
                        && address["local"].as_str().is_some_and(|ip| {
                            if !tailnet {
                                return true;
                            }
                            ip.parse::<std::net::Ipv4Addr>().is_ok_and(|ip| {
                                let [a, b, ..] = ip.octets();
                                a == 100 && (64..=127).contains(&b)
                            })
                        })
                })
            })
        });
        if !has_ipv4 {
            bail!("{interface} has no expected IPv4 address; paid exit requires an active TUN and personal Tailscale mesh");
        }
        Ok(())
    }

    fn json_array(text: &str) -> Result<Vec<Value>> {
        serde_json::from_str::<Vec<Value>>(text).context("parse ip -j output")
    }

    fn plan(tun: &str, peer: SocketAddrV4, physical: &str, gateway: Option<&str>) -> Vec<Route> {
        let mut endpoint = vec![format!("{}/32", peer.ip())];
        if let Some(gateway) = gateway {
            endpoint.extend(["via".into(), gateway.into()]);
        }
        endpoint.extend([
            "dev".into(),
            physical.into(),
            "proto".into(),
            PROTO.into(),
            "metric".into(),
            PAID_METRIC.into(),
        ]);
        let mut routes = vec![Route {
            family: "-4",
            args: endpoint,
        }];
        routes.push(Route::new(
            "-4",
            &[
                "100.64.0.0/10",
                "dev",
                "tailscale0",
                "proto",
                PROTO,
                "metric",
                PAID_METRIC,
            ],
        ));
        routes.push(Route::new(
            "-4",
            &[
                "blackhole",
                "100.64.0.0/10",
                "proto",
                PROTO,
                "metric",
                BLOCK_METRIC,
            ],
        ));
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            routes.push(Route::new(
                "-4",
                &["blackhole", prefix, "proto", PROTO, "metric", BLOCK_METRIC],
            ));
        }
        for prefix in ["::/1", "8000::/1"] {
            routes.push(Route::new(
                "-6",
                &["blackhole", prefix, "proto", PROTO, "metric", BLOCK_METRIC],
            ));
        }
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            routes.push(Route::new(
                "-4",
                &[prefix, "dev", tun, "proto", PROTO, "metric", PAID_METRIC],
            ));
        }
        routes
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::{cell::RefCell, net::Ipv4Addr};

        #[derive(Default)]
        struct Fake {
            calls: RefCell<Vec<Vec<String>>>,
            fail_add: Option<usize>,
        }

        impl Runner for Fake {
            fn run(&self, args: &[String]) -> Result<String> {
                let mut calls = self.calls.borrow_mut();
                calls.push(args.to_vec());
                if args.get(2).is_some_and(|arg| arg == "add")
                    && self.fail_add.is_some_and(|n| {
                        calls
                            .iter()
                            .filter(|call| call.get(2).is_some_and(|verb| verb == "add"))
                            .count()
                            == n
                    })
                {
                    bail!("injected route-add failure");
                }
                if args.contains(&"address".to_owned()) {
                    let local = if args.last().is_some_and(|arg| arg == "tailscale0") {
                        "100.101.102.103"
                    } else {
                        "10.1.2.3"
                    };
                    return Ok(format!(
                        r#"[{{"addr_info":[{{"family":"inet","local":"{local}"}}]}}]"#
                    ));
                }
                if args.contains(&"get".to_owned()) {
                    let address = args.last().map(String::as_str).unwrap_or("");
                    let dev = match address {
                        "100.100.100.100" => "tailscale0",
                        "1.1.1.1" | "129.0.0.1" => "octvpn0",
                        _ => "eth0",
                    };
                    return Ok(format!(r#"[{{"dev":"{dev}","gateway":"192.0.2.1"}}]"#));
                }
                Ok("[]".into())
            }
        }

        fn peer() -> SocketAddrV4 {
            SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 51820)
        }

        #[test]
        fn plan_keeps_peer_and_personal_mesh_direct() {
            let routes = plan("octvpn0", peer(), "eth0", Some("192.0.2.1"));
            assert_eq!(routes.len(), 9);
            assert!(routes[0]
                .args
                .join(" ")
                .contains("8.8.4.4/32 via 192.0.2.1 dev eth0"));
            assert!(routes[1]
                .args
                .join(" ")
                .contains("100.64.0.0/10 dev tailscale0"));
            assert!(routes[2].args.join(" ").contains("blackhole 100.64.0.0/10"));
            assert!(routes[3..7]
                .iter()
                .all(|route| route.args[0] == "blackhole"));
            assert!(routes[7..]
                .iter()
                .all(|route| route.args.join(" ").contains("dev octvpn0")));
        }

        #[test]
        fn activation_checks_effective_routes() {
            let fake = Fake::default();
            let routes = activate_with(&fake, "octvpn0", peer()).unwrap();
            assert_eq!(routes.len(), 9);
            assert_eq!(
                fake.calls
                    .borrow()
                    .iter()
                    .filter(|args| args.get(2).is_some_and(|verb| verb == "add"))
                    .count(),
                9
            );
        }

        #[test]
        fn failure_before_blockers_rolls_back() {
            let fake = Fake {
                fail_add: Some(3),
                ..Fake::default()
            };
            let error = activate_with(&fake, "octvpn0", peer())
                .unwrap_err()
                .to_string();
            assert!(error.contains("before traffic diversion"));
            assert_eq!(
                fake.calls
                    .borrow()
                    .iter()
                    .filter(|args| args.get(2).is_some_and(|verb| verb == "del"))
                    .count(),
                2
            );
        }

        #[test]
        fn failure_after_blockers_keeps_kill_switch() {
            let fake = Fake {
                fail_add: Some(9),
                ..Fake::default()
            };
            let error = activate_with(&fake, "octvpn0", peer())
                .unwrap_err()
                .to_string();
            assert!(error.contains("blocking routes retained"));
            assert_eq!(
                fake.calls
                    .borrow()
                    .iter()
                    .filter(|args| args.get(2).is_some_and(|verb| verb == "del"))
                    .count(),
                1
            );
        }

        #[test]
        fn clean_disconnect_handles_kernel_removed_tun_routes() {
            let fake = Fake::default();
            let routes = plan("octvpn0", peer(), "eth0", Some("192.0.2.1"));
            disconnect_with(&fake, &routes).unwrap();
            let calls = fake.calls.borrow();
            let deleted: Vec<_> = calls
                .iter()
                .filter(|args| args.get(2).is_some_and(|verb| verb == "del"))
                .collect();
            assert_eq!(deleted.len(), 7);
            assert_eq!(deleted[0][0], "-6");
            assert_eq!(deleted[0][4], "8000::/1");
            assert!(deleted.last().unwrap().join(" ").contains("8.8.4.4/32"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refuses_invalid_interface_or_endpoint() {
        assert!(validate_interface("octvpn0").is_ok());
        assert!(validate_interface("bad name").is_err());
        assert!(
            PaidRouteGuard::activate("octvpn0", "100.100.100.100:51820".parse().unwrap()).is_err()
        );
    }
}
