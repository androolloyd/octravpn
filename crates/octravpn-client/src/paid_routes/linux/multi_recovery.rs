//! Adopt only a sealed plan's exact remnants, under the exclusive host lease.
use super::{
    blockers, json_array, standard_local_rule, BTreeSet, Context, Guard, Ipv4Addr, Result, Route,
    Runner, SocketAddrV4, BLOCK_METRIC, PAID_METRIC, PROTO,
};
use crate::paid_routes::{
    network::{Bypass, Namespace},
    Network,
};
use anyhow::ensure;
use serde_json::Value;

pub(super) struct Recovery {
    network: Network,
    names: Vec<String>,
    downstream: BTreeSet<Ipv4Addr>,
    guard: Guard,
}
struct Snapshot {
    rows: Vec<(&'static str, Value)>,
    rules: Vec<(&'static str, Value)>,
    links: Vec<Value>,
}
fn table(row: &Value, value: u64) -> bool {
    row["table"].as_u64() == Some(value)
        || row["table"].as_str() == Some(value.to_string().as_str())
}
fn protocol(row: &Value) -> bool {
    row["protocol"].as_u64() == Some(186) || row["protocol"].as_str() == Some("186")
}
fn code(value: &Value, number: u64, name: &str) -> bool {
    value.as_u64() == Some(number)
        || value
            .as_str()
            .is_some_and(|s| s == name || s.parse::<u64>().ok() == Some(number))
}
fn namespace() -> Result<Namespace> {
    use std::os::unix::fs::MetadataExt;
    Ok(Namespace {
        boot: std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?
            .trim()
            .to_owned(),
        network: std::fs::metadata("/proc/self/ns/net")?.ino(),
    })
}
impl Snapshot {
    fn read(runner: &impl Runner) -> Result<Self> {
        let mut rows = Vec::new();
        let mut rules = Vec::new();
        for family in ["-4", "-6"] {
            rows.extend(
                json_array(&runner.run(&[
                    family.into(),
                    "-N".into(),
                    "-j".into(),
                    "route".into(),
                    "show".into(),
                    "table".into(),
                    "all".into(),
                ])?)?
                .into_iter()
                .map(|row| (family, row)),
            );
            rules.extend(
                json_array(&runner.run(&[
                    family.into(),
                    "-N".into(),
                    "-j".into(),
                    "rule".into(),
                    "show".into(),
                ])?)?
                .into_iter()
                .map(|row| (family, row)),
            );
        }
        Ok(Self {
            rows,
            rules,
            links: json_array(&runner.run(&["-j".into(), "link".into(), "show".into()])?)?,
        })
    }
    fn retained(&self) -> bool {
        self.rows
            .iter()
            .any(|(_, r)| table(r, 185) || table(r, 186) || protocol(r))
            || self
                .rules
                .iter()
                .any(|(_, r)| table(r, 185) || table(r, 186))
    }
}
pub(super) fn plan(
    entry: SocketAddrV4,
    controls: &[SocketAddrV4],
    peers: &[SocketAddrV4],
    names: &[String],
    mark: u32,
    bypasses: Vec<Bypass>,
) -> Result<Network> {
    Network::new(entry, controls, peers, names, mark, namespace()?, bypasses)
}
pub(super) fn bypasses(direct: &[Route], links: &[Value]) -> Result<Vec<Bypass>> {
    let mut bypasses = Vec::new();
    for route in direct {
        let get = |key: &str| {
            route
                .args
                .windows(2)
                .find(|p| p[0] == key)
                .map(|p| p[1].as_str())
        };
        let device = get("dev")
            .context("physical route device missing")?
            .to_owned();
        let index = links
            .iter()
            .find(|link| link["ifname"].as_str() == Some(&device))
            .and_then(|link| link["ifindex"].as_u64())
            .context("physical device identity missing")?;
        bypasses.push(Bypass {
            address: route.args[0]
                .strip_suffix("/32")
                .context("physical route prefix differs")?
                .parse()?,
            device,
            index,
            gateway: get("via").map(str::parse).transpose()?,
        });
    }
    Ok(bypasses)
}
pub(super) fn reserve(
    runner: &impl Runner,
    saved: &Network,
    entry: SocketAddrV4,
    controls: &[SocketAddrV4],
    peers: &[SocketAddrV4],
    names: &[String],
    mark: u32,
    downstream: BTreeSet<Ipv4Addr>,
) -> Result<Option<Recovery>> {
    saved.bindings(entry, controls, peers, names, mark)?;
    let current = Snapshot::read(runner)?;
    let guard = Guard::new(entry, controls, peers, names, Some(mark), &saved.bypasses)?;
    let present = guard.reserve(true)?;
    if !current.retained() && !present.into_iter().any(|p| p) {
        return Ok(None);
    }
    let recovered = Recovery {
        network: saved.clone(),
        names: names.to_vec(),
        downstream,
        guard,
    };
    recovered.validate(&current)?;
    Ok(Some(recovered))
}
pub(super) fn chain_blockers() -> Vec<Route> {
    [
        ("-4", ["0.0.0.0/1", "128.0.0.0/1"]),
        ("-6", ["::/1", "8000::/1"]),
    ]
    .into_iter()
    .flat_map(|(family, prefixes)| {
        prefixes.map(|prefix| {
            Route::new(
                family,
                &[
                    "blackhole",
                    prefix,
                    "proto",
                    PROTO,
                    "metric",
                    BLOCK_METRIC,
                    "table",
                    "185",
                ],
            )
        })
    })
    .collect()
}
fn direct(network: &Network) -> Vec<Route> {
    network
        .bypasses
        .iter()
        .map(|b| {
            let mut args = vec![format!("{}/32", b.address)];
            if let Some(gateway) = b.gateway {
                args.extend(["via".into(), gateway.to_string(), "onlink".into()]);
            }
            args.extend([
                "dev".into(),
                b.device.clone(),
                "proto".into(),
                PROTO.into(),
                "metric".into(),
                PAID_METRIC.into(),
            ]);
            Route { family: "-4", args }
        })
        .collect()
}
fn global_routes(network: &Network, downstream: &BTreeSet<Ipv4Addr>) -> Vec<Route> {
    let mut routes = blockers(downstream);
    routes.extend(direct(network));
    for route in &mut routes {
        route.args.extend(["table".into(), "186".into()]);
    }
    routes
}
fn matches(route: &Route, row: &Value) -> bool {
    let get = |key: &str| {
        route
            .args
            .windows(2)
            .find(|p| p[0] == key)
            .map(|p| p[1].as_str())
    };
    let kind = match route.args[0].as_str() {
        "blackhole" => "blackhole",
        "throw" => "throw",
        _ => "unicast",
    };
    let prefix = &route.args[usize::from(kind != "unicast")];
    let flags = row["flags"]
        .as_array()
        .and_then(|values| values.iter().map(Value::as_str).collect::<Option<Vec<_>>>());
    let expected_flags = if route.args.iter().any(|a| a == "onlink") {
        vec!["onlink"]
    } else {
        vec![]
    };
    let kind_number = match kind {
        "blackhole" => 6,
        "throw" => 9,
        _ => 1,
    };
    let prefix_matches = row["dst"]
        .as_str()
        .is_some_and(|p| p == prefix || prefix.strip_suffix("/32") == Some(p));
    let scope = if kind == "unicast" && get("via").is_none() {
        (253, "link")
    } else {
        (0, "global")
    };
    // Linux reports its implicit loopback device for IPv6 blackholes. It is
    // not an accepted forwarding device for any other retained route.
    let device_matches = row["dev"].as_str() == get("dev")
        || (route.family == "-6"
            && kind == "blackhole"
            && get("dev").is_none()
            && row["dev"].as_str() == Some("lo"));
    protocol(row)
        && (row.get("type").is_none() && kind == "unicast" || code(&row["type"], kind_number, kind))
        && prefix_matches
        && table(row, get("table").unwrap_or("186").parse().unwrap_or(0))
        && row["metric"].as_u64() == get("metric").and_then(|m| m.parse().ok())
        && device_matches
        && row["gateway"].as_str() == get("via")
        && row.get("prefsrc").is_none()
        && flags.as_ref() == Some(&expected_flags)
        && row.get("scope").is_none_or(|v| code(v, scope.0, scope.1))
        && row.get("pref").is_none_or(|v| code(v, 0, "medium"))
        && row.as_object().is_some_and(|fields| {
            fields.keys().all(|key| {
                matches!(
                    key.as_str(),
                    "type"
                        | "dst"
                        | "table"
                        | "protocol"
                        | "metric"
                        | "flags"
                        | "dev"
                        | "gateway"
                        | "scope"
                        | "pref"
                )
            })
        })
}

fn marked(value: &Value, expected: u32) -> bool {
    value.as_u64() == Some(u64::from(expected))
        || value.as_str().is_some_and(|s| {
            s.strip_prefix("0x").map_or_else(
                || s.parse::<u32>().ok(),
                |s| u32::from_str_radix(s, 16).ok(),
            ) == Some(expected)
        })
}
fn rule(row: &Value, chain: bool, name: &str, mark: u32) -> bool {
    let accepted_mark = if chain {
        marked(&row["fwmark"], mark) && row.get("fwmask").is_none_or(|v| marked(v, u32::MAX))
    } else {
        row.get("fwmark").is_none() && row.get("fwmask").is_none()
    };
    table(row, if chain { 185 } else { 186 })
        && row["priority"].as_u64() == Some(if chain { 1 } else { 2 })
        && row["src"].as_str().is_none_or(|s| s == "all")
        && row["dst"].as_str().is_none_or(|s| s == "all")
        && row["oif"].as_str() == chain.then_some(name)
        && accepted_mark
        && row.get("protocol").is_none_or(|v| code(v, 3, "boot"))
        && row.as_object().is_some_and(|fields| {
            fields.iter().all(|(key, value)| match key.as_str() {
                "priority" | "src" | "dst" | "table" | "protocol" | "oif" => true,
                "oif_detached" => chain && value.is_null(),
                "fwmark" | "fwmask" => chain,
                _ => false,
            })
        })
}
impl Recovery {
    pub(super) fn packet_guard(&self) -> Guard {
        self.guard.clone()
    }
    fn validate(&self, current: &Snapshot) -> Result<()> {
        self.guard.reserve(true)?;
        ensure!(
            self.network.namespace == namespace()?,
            "retained routing namespace differs from sealed plan"
        );
        ensure!(
            self.names.iter().all(|name| !current
                .links
                .iter()
                .any(|l| l["ifname"].as_str() == Some(name))),
            "retained route interface is still present"
        );
        for bypass in &self.network.bypasses {
            ensure!(
                current
                    .links
                    .iter()
                    .any(|link| link["ifname"].as_str() == Some(&bypass.device)
                        && link["ifindex"].as_u64() == Some(bypass.index)),
                "retained physical device identity changed"
            );
        }
        let mut expected = global_routes(&self.network, &self.downstream);
        expected.extend(chain_blockers());
        for (family, row) in &current.rows {
            if table(row, 185) || table(row, 186) || protocol(row) {
                ensure!(
                    expected
                        .iter()
                        .any(|route| route.family == *family && matches(route, row)),
                    "unowned route prevents retained-plan recovery"
                );
            }
        }
        for route in &expected {
            ensure!(
                current
                    .rows
                    .iter()
                    .filter(|(family, row)| *family == route.family && matches(route, row))
                    .count()
                    <= 1,
                "duplicate retained route"
            );
        }
        for (family, row) in &current.rules {
            if table(row, 185)
                || table(row, 186)
                || row["priority"].as_u64().is_some_and(|p| p <= 2)
            {
                ensure!(
                    standard_local_rule(row)
                        || rule(row, false, &self.names[0], self.network.socket_mark())
                        || rule(row, true, &self.names[0], self.network.socket_mark()),
                    "unowned policy prevents retained-plan recovery"
                );
            }
            for chain in [false, true] {
                ensure!(
                    current
                        .rules
                        .iter()
                        .filter(|(f, r)| f == family
                            && rule(r, chain, &self.names[0], self.network.socket_mark()))
                        .count()
                        <= 1,
                    "duplicate retained policy"
                );
            }
        }
        Ok(())
    }
    pub(super) fn activate(&self, runner: &impl Runner) -> Result<(Vec<Route>, Vec<Route>)> {
        let current = Snapshot::read(runner)?;
        self.validate(&current)?;
        self.guard.install(true)?;
        let global = global_routes(&self.network, &self.downstream);
        let chain = chain_blockers();
        for route in global.iter().chain(&chain) {
            if !current
                .rows
                .iter()
                .any(|(family, row)| *family == route.family && matches(route, row))
            {
                route.call(runner, "add")?;
            }
        }
        // Both families remain blocked before any detached old entry rule is removed.
        for family in ["-6", "-4"] {
            if !current.rules.iter().any(|(f, r)| {
                *f == family && rule(r, false, &self.names[0], self.network.socket_mark())
            }) {
                runner.run(&[
                    family.into(),
                    "rule".into(),
                    "add".into(),
                    "priority".into(),
                    "2".into(),
                    "lookup".into(),
                    "186".into(),
                ])?;
            }
        }
        for family in ["-4", "-6"] {
            if current.rules.iter().any(|(f, r)| {
                *f == family && rule(r, true, &self.names[0], self.network.socket_mark())
            }) {
                // The kernel retains the name, but ip cannot resolve a deleted
                // device for an oif argument. Validation proved this exact
                // priority/table has one original-entry rule and no others.
                runner.run(&[
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
        Ok((global, chain))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn ipv6_blackhole_accepts_only_its_implicit_loopback_device() {
        let route = chain_blockers()
            .into_iter()
            .find(|r| r.family == "-6")
            .unwrap();
        let row = serde_json::json!({"type":"6","dst":"::/1","dev":"lo",
            "table":"185","protocol":"186","metric":45679,"flags":[],"pref":"medium"});
        assert!(matches(&route, &row));
        for (key, value) in [
            ("dev", serde_json::json!("eth0")),
            ("type", serde_json::json!("1")),
            ("gateway", serde_json::json!("::1")),
            ("metric", serde_json::json!(45678)),
        ] {
            let mut changed = row.clone();
            changed[key] = value;
            assert!(!matches(&route, &changed), "{changed}");
        }
        let ipv4 = chain_blockers()
            .into_iter()
            .find(|r| r.family == "-4")
            .unwrap();
        let mut changed = row;
        changed["dst"] = serde_json::json!("0.0.0.0/1");
        assert!(!matches(&ipv4, &changed));
    }
}
