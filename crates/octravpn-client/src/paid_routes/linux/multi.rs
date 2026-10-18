//! Nested exits share the existing exclusive route namespace. Every downstream
//! endpoint has a persistent /32 blackhole beneath its paid carrier route.
use super::{
    json_array, reject_stale, require_ipv6_guard_capability, require_physical_public_path,
    verify_lock_metadata, Route, Runner, System, BLOCK_METRIC, PAID_METRIC, PROTO,
};
use anyhow::{ensure, Context, Result};
use rustix::fs::{flock, openat, FlockOperation, Mode, OFlags, CWD};
use std::{
    collections::BTreeSet,
    fs::File,
    net::{Ipv4Addr, SocketAddrV4},
};

pub(in crate::paid_routes) struct Lease {
    _lock: File,
    routes: Vec<Route>,
    downstream: BTreeSet<Ipv4Addr>,
}
impl Lease {
    pub(in crate::paid_routes) fn arm(
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        interfaces: &[String],
    ) -> Result<Self> {
        let lock = File::from(openat(
            CWD,
            "/run/octravpn-paid-exit.lock",
            OFlags::CREATE | OFlags::RDWR | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )?);
        verify_lock_metadata(&lock.metadata()?)?;
        flock(&lock, FlockOperation::NonBlockingLockExclusive)
            .context("another paid route lease is active")?;
        let runner = System;
        reject_stale(&runner)?;
        for family in ["-4", "-6"] {
            let rules = json_array(&runner.run(&[
                family.into(),
                "-j".into(),
                "rule".into(),
                "show".into(),
            ])?)?;
            ensure!(
                rules
                    .iter()
                    .filter(|rule| rule["priority"]
                        .as_u64()
                        .is_some_and(|priority| priority <= 1))
                    .all(standard_local_rule),
                "higher-precedence foreign policy rule prevents a safe composite route"
            );
            let routes = json_array(&runner.run(&[
                family.into(),
                "-j".into(),
                "route".into(),
                "show".into(),
                "table".into(),
                "all".into(),
            ])?)?;
            ensure!(
                !routes
                    .iter()
                    .any(|route| route["table"].as_u64() == Some(186)
                        || route["table"].as_str() == Some("186")),
                "composite routing table is already in use"
            );
        }
        require_ipv6_guard_capability(&runner)?;
        require_physical_public_path(&runner)?;
        let links = json_array(&runner.run(&["-j".into(), "link".into(), "show".into()])?)?;
        for name in interfaces {
            super::super::validate_interface(name)?;
            ensure!(
                name != "tailscale0"
                    && !links
                        .iter()
                        .any(|link| link["ifname"].as_str() == Some(name.as_str())),
                "composite TUN name is already in use"
            );
        }
        // Capture all management routes before installing any blocking route.
        let mut management = BTreeSet::from([*entry.ip()]);
        management.extend(
            controls
                .iter()
                .map(|peer| *peer.ip())
                .filter(|ip| !ip.is_loopback()),
        );
        let downstream: BTreeSet<_> = peers.iter().map(|peer| *peer.ip()).collect();
        ensure!(
            management.is_disjoint(&downstream),
            "downstream operator overlaps a direct management exception"
        );
        let mut direct = Vec::new();
        for ip in management {
            direct.push(physical(&runner, ip, interfaces)?);
        }
        let mut routes = blockers(&downstream);
        routes.extend(direct);
        let mut lease = Self {
            _lock: lock,
            routes: Vec::new(),
            downstream,
        };
        install_with(&runner, &mut lease.routes, routes)?;
        // These rules precede ordinary/Tailscale route tables, after the
        // kernel local table. Once installed, carrier removal cannot reveal
        // a lower-priority physical route to a downstream operator.
        for family in ["-6", "-4"] {
            runner
                .run(&[
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    "1".into(),
                    "lookup".into(),
                    "186".into(),
                ])
                .context("composite policy activation failed; blocking routes retained")?;
        }
        Ok(lease)
    }

    pub(in crate::paid_routes) fn next(
        &mut self,
        previous: &crate::Interface,
        peer: SocketAddrV4,
    ) -> Result<()> {
        ensure!(
            self.downstream.contains(peer.ip()),
            "unaccepted downstream endpoint"
        );
        super::require_address(&System, &previous.name, false)?;
        let route = via_interface(&format!("{}/32", peer.ip()), previous);
        route.call(&System, "add")?;
        self.routes.push(route);
        selected(&System, &peer.ip().to_string(), &previous.name)?;
        Ok(())
    }

    pub(in crate::paid_routes) fn finish(&mut self, exit: &crate::Interface) -> Result<()> {
        super::require_address(&System, &exit.name, false)?;
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            let route = via_interface(prefix, exit);
            route.call(&System, "add")?;
            self.routes.push(route);
        }
        selected(&System, "1.1.1.1", &exit.name)?;
        selected(&System, "129.0.0.1", &exit.name)?;
        Ok(())
    }

    pub(in crate::paid_routes) fn disconnect(self) -> Result<()> {
        disconnect_with(&System, &self.routes)?;
        for family in ["-4", "-6"] {
            System.run(&[
                family.into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                "1".into(),
                "lookup".into(),
                "186".into(),
            ])?;
        }
        Ok(())
    }
}

fn install_with(
    runner: &impl Runner,
    installed: &mut Vec<Route>,
    routes: Vec<Route>,
) -> Result<()> {
    for mut route in routes {
        route.args.extend(["table".into(), "186".into()]);
        // On failure retain all installed blockers; no purchase is possible
        // until the complete lease and every prepared journal have succeeded.
        route
            .call(runner, "add")
            .context("composite activation failed; installed blocking routes retained")?;
        installed.push(route);
    }
    Ok(())
}
fn standard_local_rule(rule: &serde_json::Value) -> bool {
    rule["priority"].as_u64() == Some(0)
        && (rule["table"].as_str() == Some("local") || rule["table"].as_u64() == Some(255))
        && rule["src"].as_str().is_none_or(|src| src == "all")
        && rule["dst"].as_str().is_none_or(|dst| dst == "all")
        && rule.as_object().is_some_and(|fields| {
            fields.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "priority" | "table" | "src" | "dst" | "protocol"
                )
            })
        })
}
fn physical(runner: &impl Runner, ip: Ipv4Addr, interfaces: &[String]) -> Result<Route> {
    let rows = json_array(&runner.run(&[
        "-4".into(),
        "-j".into(),
        "route".into(),
        "get".into(),
        ip.to_string(),
    ])?)?;
    let row = rows.first().context("missing management route")?;
    let dev = row["dev"]
        .as_str()
        .context("management route has no device")?;
    super::super::validate_interface(dev)?;
    ensure!(
        dev != "tailscale0" && !interfaces.iter().any(|name| name == dev),
        "management endpoint has no independent physical path"
    );
    let mut args = vec![format!("{ip}/32")];
    if let Some(gateway) = row["gateway"].as_str() {
        gateway
            .parse::<Ipv4Addr>()
            .context("management gateway is not IPv4")?;
        args.extend(["via".into(), gateway.into(), "onlink".into()]);
    }
    args.extend([
        "dev".into(),
        dev.into(),
        "proto".into(),
        PROTO.into(),
        "metric".into(),
        PAID_METRIC.into(),
    ]);
    Ok(Route { family: "-4", args })
}
fn blockers(downstream: &BTreeSet<Ipv4Addr>) -> Vec<Route> {
    let mut routes = vec![Route::new(
        "-4",
        &[
            "throw",
            "100.64.0.0/10",
            "proto",
            PROTO,
            "metric",
            BLOCK_METRIC,
        ],
    )];
    for (family, prefixes) in [
        ("-4", ["0.0.0.0/1", "128.0.0.0/1"]),
        ("-6", ["::/1", "8000::/1"]),
    ] {
        for prefix in prefixes {
            routes.push(Route::new(
                family,
                &["blackhole", prefix, "proto", PROTO, "metric", BLOCK_METRIC],
            ));
        }
    }
    for peer in downstream {
        routes.push(Route::new(
            "-4",
            &[
                "blackhole",
                &format!("{peer}/32"),
                "proto",
                PROTO,
                "metric",
                BLOCK_METRIC,
            ],
        ));
    }
    routes
}
fn via_interface(prefix: &str, interface: &crate::Interface) -> Route {
    Route::new(
        "-4",
        &[
            prefix,
            "dev",
            &interface.name,
            "src",
            &interface.address.to_string(),
            "proto",
            PROTO,
            "metric",
            PAID_METRIC,
            "table",
            "186",
        ],
    )
}
fn selected(runner: &impl Runner, ip: &str, expected: &str) -> Result<()> {
    let routes = json_array(&runner.run(&[
        "-4".into(),
        "-j".into(),
        "route".into(),
        "get".into(),
        ip.into(),
    ])?)?;
    ensure!(
        routes.first().and_then(|route| route["dev"].as_str()) == Some(expected),
        "composite route selected an unexpected interface; blockers retained"
    );
    Ok(())
}
fn disconnect_with(runner: &impl Runner, routes: &[Route]) -> Result<()> {
    // The data tasks and TUNs are already closed. Missing TUN routes are
    // expected, but never hide failures removing management or blocking routes.
    for route in routes.iter().rev() {
        if route.args.iter().any(|arg| arg == "src") {
            let current = json_array(&runner.run(&[
                route.family.into(),
                "-j".into(),
                "route".into(),
                "show".into(),
                "table".into(),
                "186".into(),
                "proto".into(),
                PROTO.into(),
            ])?)?;
            let prefix = &route.args[0];
            let dev = &route.args[2];
            if !current.iter().any(|row| {
                row["dst"].as_str() == Some(prefix.as_str())
                    && row["dev"].as_str() == Some(dev.as_str())
                    && row["metric"].as_u64() == Some(45_678)
            }) {
                continue;
            }
        }
        route.call(runner, "del")?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<Vec<String>>>,
        fail_add: Option<usize>,
    }
    impl Runner for Fake {
        fn run(&self, args: &[String]) -> Result<String> {
            self.calls.borrow_mut().push(args.to_vec());
            if args.get(2).is_some_and(|verb| verb == "add")
                && self.fail_add.is_some_and(|fail| {
                    self.calls
                        .borrow()
                        .iter()
                        .filter(|call| call.get(2).is_some_and(|verb| verb == "add"))
                        .count()
                        == fail
                })
            {
                anyhow::bail!("injected route add failure");
            }
            if args.iter().any(|arg| arg == "get") {
                return Ok(r#"[{"dev":"eth0","gateway":"192.0.2.1"}]"#.into());
            }
            Ok("[]".into())
        }
    }
    #[test]
    fn every_downstream_endpoint_has_a_specific_persistent_blackhole() {
        let peer = Ipv4Addr::new(8, 8, 4, 4);
        let routes = blockers(&BTreeSet::from([peer]));
        assert_eq!(routes.len(), 6);
        assert_eq!(
            routes[5].args,
            ["blackhole", "8.8.4.4/32", "proto", "186", "metric", "45679"]
        );
        let carrier = crate::Interface {
            name: "octroute0".into(),
            address: Ipv4Addr::new(198, 18, 0, 2),
            mtu: 1280,
        };
        let allowed = via_interface("8.8.4.4/32", &carrier);
        assert_eq!(
            allowed.args,
            [
                "8.8.4.4/32",
                "dev",
                "octroute0",
                "src",
                "198.18.0.2",
                "proto",
                "186",
                "metric",
                "45678",
                "table",
                "186"
            ]
        );
        assert!(!allowed.args.iter().any(|arg| arg == "eth0"));
    }
    #[test]
    fn management_route_cannot_be_an_existing_paid_or_tailnet_interface() {
        let fake = Fake::default();
        assert!(physical(&fake, Ipv4Addr::new(8, 8, 8, 8), &["eth0".into()]).is_err());
        assert!(physical(&fake, Ipv4Addr::new(8, 8, 8, 8), &["octroute0".into()]).is_ok());
    }
    #[test]
    fn clean_disconnect_removes_management_before_any_blocker() {
        let fake = Fake::default();
        let mut routes = blockers(&BTreeSet::from([Ipv4Addr::new(8, 8, 4, 4)]));
        routes.push(physical(&fake, Ipv4Addr::new(8, 8, 8, 8), &[]).unwrap());
        fake.calls.borrow_mut().clear();
        disconnect_with(&fake, &routes).unwrap();
        let calls = fake.calls.borrow();
        assert_eq!(calls[0][3], "8.8.8.8/32");
        assert!(calls[1..calls.len() - 1]
            .iter()
            .all(|call| call[3] == "blackhole"));
        assert_eq!(calls.last().unwrap()[3], "throw");
    }
    #[test]
    fn policy_precedence_accepts_only_standard_local_rule() {
        assert!(standard_local_rule(
            &serde_json::json!({"priority":0,"src":"all","table":"local","protocol":"kernel"})
        ));
        for rule in [
            serde_json::json!({"priority":1,"src":"all","table":"main"}),
            serde_json::json!({"priority":0,"src":"all","table":186}),
            serde_json::json!({"priority":0,"src":"all","table":"local","iif":"eth0"}),
        ] {
            assert!(!standard_local_rule(&rule));
        }
    }
    #[test]
    fn partial_activation_never_removes_an_installed_blocker() {
        for fail in 1..=6 {
            let fake = Fake {
                fail_add: Some(fail),
                ..Fake::default()
            };
            let mut installed = Vec::new();
            assert!(install_with(
                &fake,
                &mut installed,
                blockers(&BTreeSet::from([Ipv4Addr::new(8, 8, 4, 4)]))
            )
            .is_err());
            assert_eq!(installed.len(), fail - 1);
            assert!(fake.calls.borrow().iter().all(|call| call[2] == "add"));
            assert!(installed
                .iter()
                .all(|route| route.args.ends_with(&["table".into(), "186".into()])));
        }
    }
}
