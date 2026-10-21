//! Nested exits share the existing exclusive route namespace. Every downstream
//! peer and non-loopback control IP has a persistent /32 blackhole beneath its
//! paid carrier route. Only the entry may use a physical management exception.
use super::packet::Guard;
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
#[cfg(all(test, target_os = "linux"))]
#[path = "multi_kernel.rs"]
mod kernel;
#[path = "multi_recovery.rs"]
mod recovery;

pub(in crate::paid_routes) struct Lease {
    _lock: File,
    routes: Vec<Route>,
    downstream: BTreeSet<Ipv4Addr>,
    priority: u32,
    chain_routes: Vec<Route>,
    chain_interface: Option<String>,
    pending: Vec<Route>,
    network: Option<crate::paid_routes::Network>,
    restored: Option<recovery::Recovery>,
    guard: Guard,
}
impl Lease {
    pub(in crate::paid_routes) fn arm(
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        interfaces: &[String],
        chain: bool,
    ) -> Result<Self> {
        let mut lease = Self::reserve(entry, controls, peers, interfaces, chain, 0, None)?;
        lease.activate()?;
        Ok(lease)
    }
    pub(in crate::paid_routes) fn reserve(
        entry: SocketAddrV4,
        controls: &[SocketAddrV4],
        peers: &[SocketAddrV4],
        interfaces: &[String],
        chain: bool,
        mark: u32,
        previous: Option<&crate::paid_routes::Network>,
    ) -> Result<Self> {
        super::require_host_capabilities()?;
        ensure!(
            !chain || mark != 0,
            "chain policy requires a privileged socket mark"
        );
        let priority = if chain { 2 } else { 1 };
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
        let (_, downstream) = route_endpoints(entry, controls, peers)?;
        if chain {
            if let Some(previous) = previous {
                if let Some(restored) = recovery::reserve(
                    &runner,
                    previous,
                    entry,
                    controls,
                    peers,
                    interfaces,
                    mark,
                    downstream.clone(),
                )? {
                    return Ok(Self {
                        _lock: lock,
                        routes: Vec::new(),
                        downstream,
                        priority,
                        chain_routes: Vec::new(),
                        chain_interface: None,
                        pending: Vec::new(),
                        network: Some(previous.clone()),
                        guard: restored.packet_guard(),
                        restored: Some(restored),
                    });
                }
            }
        }
        reject_stale(&runner)?;
        for family in ["-4", "-6"] {
            let rules = json_array(&runner.run(&[
                family.into(),
                "-j".into(),
                "rule".into(),
                "show".into(),
            ])?)?;
            ensure!(
                !rules.iter().any(|rule| rule["table"].as_u64() == Some(186)
                    || rule["table"].as_str() == Some("186")
                    || (chain
                        && (rule["table"].as_u64() == Some(185)
                            || rule["table"].as_str() == Some("185")))),
                "composite routing table already has a policy owner"
            );
            ensure!(
                rules
                    .iter()
                    .filter(|rule| rule["priority"]
                        .as_u64()
                        .is_some_and(|p| p <= u64::from(priority)))
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
                        || route["table"].as_str() == Some("186")
                        || (chain
                            && (route["table"].as_u64() == Some(185)
                                || route["table"].as_str() == Some("185")))),
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
        let (management, downstream) = route_endpoints(entry, controls, peers)?;
        let mut direct = Vec::new();
        for ip in management {
            direct.push(physical(&runner, ip, interfaces)?);
        }
        let bypasses = recovery::bypasses(&direct, &links)?;
        let guard = Guard::new(
            entry,
            controls,
            peers,
            interfaces,
            chain.then_some(mark),
            &bypasses,
        )?;
        guard.reserve(false)?;
        let network = chain
            .then(|| recovery::plan(entry, controls, peers, interfaces, mark, bypasses))
            .transpose()?;
        let mut routes = blockers(&downstream);
        routes.extend(direct);
        Ok(Self {
            _lock: lock,
            routes: Vec::new(),
            downstream,
            priority,
            chain_routes: Vec::new(),
            chain_interface: None,
            pending: routes,
            network,
            restored: None,
            guard,
        })
    }
    pub(in crate::paid_routes) fn activate(&mut self) -> Result<()> {
        ensure!(
            self.routes.is_empty() && (!self.pending.is_empty() || self.restored.is_some()),
            "composite policy is already active"
        );
        let runner = System;
        if let Some(restored) = &self.restored {
            let (routes, chain) = restored.activate(&runner)?;
            self.routes = routes;
            self.chain_routes = chain;
            self.restored = None;
            return Ok(());
        }
        self.guard.install(false)?;
        let routes = std::mem::take(&mut self.pending);
        install_with(&runner, &mut self.routes, routes)?;
        if self.priority == 2 {
            for route in recovery::chain_blockers() {
                route.call(&runner, "add")?;
                self.chain_routes.push(route);
            }
        }
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
                    self.priority.to_string(),
                    "lookup".into(),
                    "186".into(),
                ])
                .context("composite policy activation failed; blocking routes retained")?;
        }
        Ok(())
    }
    pub(in crate::paid_routes) fn network(&self) -> Result<crate::paid_routes::Network> {
        self.network
            .clone()
            .context("route has no coordinated kernel plan")
    }

    pub(in crate::paid_routes) fn chain(&mut self, entry: &crate::Interface) -> Result<()> {
        self.guard.check()?;
        ensure!(
            self.priority == 2 && self.chain_interface.is_none(),
            "chain policy is absent or already active"
        );
        super::require_address(&System, &entry.name, false)?;
        let mark = self.network()?.socket_mark();
        for prefix in ["0.0.0.0/1", "128.0.0.0/1"] {
            let mut route = via_interface(prefix, entry);
            *route.args.last_mut().context("chain route table missing")? = "185".into();
            route.call(&System, "add")?;
            self.chain_routes.push(route);
        }
        for family in ["-6", "-4"] {
            System.run(&[
                family.into(),
                "rule".into(),
                "add".into(),
                "priority".into(),
                "1".into(),
                "fwmark".into(),
                format!("0x{mark:08x}/0xffffffff"),
                "oif".into(),
                entry.name.clone(),
                "lookup".into(),
                "185".into(),
            ])?;
        }
        self.chain_interface = Some(entry.name.clone());
        let rows = json_array(&System.run(&[
            "-4".into(),
            "-j".into(),
            "route".into(),
            "get".into(),
            "1.1.1.1".into(),
            "mark".into(),
            mark.to_string(),
            "oif".into(),
            entry.name.clone(),
        ])?)?;
        ensure!(
            rows.first().and_then(|row| row["dev"].as_str()) == Some(entry.name.as_str()),
            "trusted chain policy selected an unexpected interface"
        );
        Ok(())
    }

    pub(in crate::paid_routes) fn next(
        &mut self,
        previous: &crate::Interface,
        peer: SocketAddrV4,
        control: SocketAddrV4,
    ) -> Result<()> {
        self.guard.check()?;
        ensure!(
            self.downstream.contains(peer.ip()),
            "unaccepted downstream endpoint"
        );
        ensure!(
            control.ip().is_loopback() || self.downstream.contains(control.ip()),
            "unaccepted downstream control endpoint"
        );
        super::require_address(&System, &previous.name, false)?;
        for route in next_routes(previous, peer, control) {
            let target = route.args[0].trim_end_matches("/32").to_owned();
            route.call(&System, "add")?;
            self.routes.push(route);
            selected(&System, &target, &previous.name)?;
        }
        Ok(())
    }

    pub(in crate::paid_routes) fn finish(&mut self, exit: &crate::Interface) -> Result<()> {
        self.guard.check()?;
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
        self.guard.check()?;
        disconnect_with(&System, &self.routes)?;
        disconnect_with(&System, &self.chain_routes)?;
        if self.chain_interface.is_some() {
            for family in ["-4", "-6"] {
                System.run(&[
                    family.into(),
                    "rule".into(),
                    "del".into(),
                    "priority".into(),
                    "1".into(),
                    "lookup".into(),
                    "185".into(),
                ])?;
            }
        }
        for family in ["-4", "-6"] {
            System.run(&[
                family.into(),
                "rule".into(),
                "del".into(),
                "priority".into(),
                self.priority.to_string(),
                "lookup".into(),
                "186".into(),
            ])?;
        }
        self.guard.remove()
    }
}

fn route_endpoints(
    entry: SocketAddrV4,
    controls: &[SocketAddrV4],
    peers: &[SocketAddrV4],
) -> Result<(BTreeSet<Ipv4Addr>, BTreeSet<Ipv4Addr>)> {
    ensure!(
        controls.len() == peers.len() + 1 && !controls.is_empty(),
        "each route hop requires a control pin"
    );
    let mut management = BTreeSet::from([*entry.ip()]);
    if !controls[0].ip().is_loopback() {
        management.insert(*controls[0].ip());
    }
    let mut downstream: BTreeSet<_> = peers.iter().map(|peer| *peer.ip()).collect();
    downstream.extend(
        controls[1..]
            .iter()
            .map(|control| *control.ip())
            .filter(|ip| !ip.is_loopback()),
    );
    ensure!(
        management.is_disjoint(&downstream),
        "downstream endpoint overlaps an entry physical exception"
    );
    Ok((management, downstream))
}

fn next_routes(
    previous: &crate::Interface,
    peer: SocketAddrV4,
    control: SocketAddrV4,
) -> Vec<Route> {
    let mut targets = BTreeSet::from([*peer.ip()]);
    if !control.ip().is_loopback() {
        targets.insert(*control.ip());
    }
    targets
        .into_iter()
        .map(|target| via_interface(&format!("{target}/32"), previous))
        .collect()
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
        && (matches!(rule["table"].as_str(), Some("local" | "255"))
            || rule["table"].as_u64() == Some(255))
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
            let current = json_array(
                &runner.run(&[
                    route.family.into(),
                    "-j".into(),
                    "route".into(),
                    "show".into(),
                    "table".into(),
                    route
                        .args
                        .windows(2)
                        .find(|pair| pair[0] == "table")
                        .map_or("186", |pair| pair[1].as_str())
                        .into(),
                    "proto".into(),
                    PROTO.into(),
                ])?,
            )?;
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
    fn downstream_control_is_blocked_until_its_carrier_exists() {
        let entry = "8.8.8.8:51820".parse().unwrap();
        let controls = [
            "8.8.8.7:443".parse().unwrap(),
            "9.9.9.7:443".parse().unwrap(),
        ];
        let peers = ["9.9.9.9:51820".parse().unwrap()];
        let (management, downstream) = route_endpoints(entry, &controls, &peers).unwrap();
        assert_eq!(
            management,
            BTreeSet::from(["8.8.8.8".parse().unwrap(), "8.8.8.7".parse().unwrap()])
        );
        assert_eq!(
            downstream,
            BTreeSet::from(["9.9.9.9".parse().unwrap(), "9.9.9.7".parse().unwrap()])
        );
        let blocked = blockers(&downstream);
        for ip in downstream {
            assert!(blocked
                .iter()
                .any(|route| route.args[0] == "blackhole" && route.args[1] == format!("{ip}/32")));
        }
        let carrier = crate::Interface {
            name: "octroute0".into(),
            address: "198.18.0.2".parse().unwrap(),
            mtu: 1280,
        };
        let routes = next_routes(&carrier, peers[0], controls[1]);
        assert_eq!(routes.len(), 2);
        assert!(routes
            .iter()
            .all(|route| route.args.contains(&"octroute0".into())));
        assert!(routes.iter().any(|route| route.args[0] == "9.9.9.7/32"));
        assert!(routes.iter().any(|route| route.args[0] == "9.9.9.9/32"));
        assert_eq!(next_routes(&carrier, peers[0], peers[0]).len(), 1);
        assert!(route_endpoints(entry, &[controls[0], entry], &peers).is_err());
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
