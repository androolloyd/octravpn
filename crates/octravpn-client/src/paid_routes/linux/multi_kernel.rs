//! Explicit isolated-kernel test. No payment, public peer or host TUN is used.
use super::*;
const MARK: u32 = 0x4f43_544e;

fn ip(args: &[&str]) -> Result<String> {
    System.run(&args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>())
}
fn device(name: &str, address: &str) {
    ip(&["link", "add", name, "type", "dummy"]).unwrap();
    ip(&["link", "set", "dev", name, "addrgenmode", "none"]).unwrap();
    ip(&["address", "add", address, "dev", name]).unwrap();
    ip(&["link", "set", name, "up"]).unwrap();
}
fn dev(args: &[&str]) -> String {
    json_array(&ip(args).unwrap()).unwrap()[0]["dev"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn firewall(tool: &str, args: &[&str]) -> String {
    let output = std::process::Command::new(tool)
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn state() -> Vec<String> {
    ["-4", "-6"]
        .into_iter()
        .flat_map(|family| {
            [
                ip(&[family, "-N", "-j", "rule", "show"]).unwrap(),
                ip(&[family, "-N", "-j", "route", "show", "table", "all"]).unwrap(),
                firewall(
                    if family == "-4" {
                        "iptables-save"
                    } else {
                        "ip6tables-save"
                    },
                    &["-t", "filter"],
                )
                .lines()
                .filter(|l| !l.starts_with('#'))
                .collect::<Vec<_>>()
                .join("\n"),
            ]
        })
        .collect()
}
fn unmarked_entry_is_blocked() {
    // Route queries can synthesize an on-link result for a bound device.
    // Check actual packet rejection and device counters instead.
    for device in ["octchain0", "octscopeuplink"] {
        packet(device, "1.1.1.1", 12345, None, true, false);
    }
}
fn packet(device: &str, peer: &str, port: u16, mark: Option<u32>, ordinary: bool, allowed: bool) {
    use std::os::unix::process::CommandExt;
    let counter = || {
        json_array(&ip(&["-s", "-j", "link", "show", device]).unwrap()).unwrap()[0]["stats64"]["tx"]
            ["packets"]
            .as_u64()
            .unwrap()
    };
    let before = counter();
    let mut command = std::process::Command::new("python3");
    command.args(["-c", r"
import os,socket,json,sys
device,peer,port,mark,ordinary=sys.argv[1:]
if ordinary=='1':
 assert os.geteuid()==1000
 assert int(next(s.split(':')[1] for s in open('/proc/self/status') if s.startswith('CapEff:')),16)==0
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,device.encode()+bytes([0]))
assert s.getsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,16).rstrip(bytes([0]))==device.encode()
if mark!='none': s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,int(mark))
sent=False;error=None
try: s.sendto(b'isolated-filter-probe',(peer,int(port)));sent=True
except OSError as e: error=e.errno
print(json.dumps({'sent':sent,'errno':error,'uid':os.geteuid()}))
", device, peer, &port.to_string(), &mark.map_or_else(|| "none".into(), |m| m.to_string()), if ordinary {"1"} else {"0"}]);
    if ordinary {
        command.uid(1000);
    }
    let result = command.output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(result["sent"], allowed, "{result}");
    assert_eq!(counter() - before, u64::from(allowed), "{device}: {result}");
}

#[test]
#[ignore = "Requires isolated Linux UID1000 with all capabilities dropped"]
fn ordinary_device_binding_cannot_acquire_the_chain_mark() {
    assert_eq!(
        std::env::var("OCTRA_ROUTE_SCOPE_TEST_ISOLATED").as_deref(),
        Ok("1")
    );
    let output = std::process::Command::new("python3")
        .args([
            "-c",
            r"
import os,socket,json
assert os.geteuid()==1000
s=socket.socket(); bound=False
try: s.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,b'lo\0'); bound=True
except PermissionError: pass
try: s.setsockopt(socket.SOL_SOCKET,socket.SO_MARK,0x4f43544e)
except PermissionError: print(json.dumps({'mark_denied':True,'device_bound':bound}))
else: raise AssertionError('unprivileged socket acquired chain mark')
",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["mark_denied"], true);
}

#[test]
#[ignore = "Requires an empty isolated Linux namespace with all capabilities dropped"]
fn reserve_refuses_missing_net_admin_before_state_changes() {
    assert_eq!(
        std::env::var("OCTRA_ROUTE_SCOPE_TEST_ISOLATED").as_deref(),
        Ok("1")
    );
    let before = ip(&["-j", "link", "show"]).unwrap();
    assert!(json_array(&before)
        .unwrap()
        .iter()
        .all(|link| link["ifname"].as_str() == Some("lo")));
    let error = Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &[
            "8.8.8.7:443".parse().unwrap(),
            "9.9.9.7:443".parse().unwrap(),
        ],
        &["9.9.9.9:51820".parse().unwrap()],
        &["octchain0".into(), "octchain1".into()],
        true,
        MARK,
        None,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("CAP_NET_ADMIN"));
    assert_eq!(before, ip(&["-j", "link", "show"]).unwrap());
}

#[test]
#[ignore = "Requires an empty isolated Linux network namespace and NET_ADMIN"]
fn bound_chain_and_ordered_control_keep_their_own_routes() {
    assert_eq!(
        std::env::var("OCTRA_ROUTE_SCOPE_TEST_ISOLATED").as_deref(),
        Ok("1")
    );
    let links = json_array(&ip(&["-j", "link", "show"]).unwrap()).unwrap();
    assert!(links
        .iter()
        .all(|link| link["ifname"].as_str() == Some("lo")));
    device("octscopeuplink", "192.0.2.2/24");
    ip(&[
        "route",
        "add",
        "default",
        "via",
        "192.0.2.1",
        "dev",
        "octscopeuplink",
    ])
    .unwrap();
    let controls = [
        "8.8.8.7:443".parse().unwrap(),
        "9.9.9.7:443".parse().unwrap(),
    ];
    let peers = ["9.9.9.9:51820".parse().unwrap()];
    let mut lease = Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &["octchain0".into(), "octchain1".into()],
        true,
        MARK,
        None,
    )
    .unwrap();
    assert_eq!(
        dev(&["-4", "-j", "route", "get", "1.1.1.1"]),
        "octscopeuplink"
    );
    for family in ["-4", "-6"] {
        let rules = json_array(&ip(&[family, "-j", "rule", "show"]).unwrap()).unwrap();
        assert!(rules
            .iter()
            .all(|rule| ![Some(185), Some(186)].contains(&rule["table"].as_u64())));
    }
    lease.activate().unwrap();
    let network = lease.network().unwrap();
    let before = state();
    assert!(Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &["octchain0".into(), "octchain1".into()],
        true,
        MARK,
        Some(&network)
    )
    .is_err());
    assert_eq!(before, state());
    assert!(ip(&["-4", "route", "get", "1.1.1.1"]).is_err());
    assert!(ip(&["-4", "route", "get", "9.9.9.7"]).is_err());
    device("octchain0", "198.18.0.2/32");
    let entry = crate::Interface {
        name: "octchain0".into(),
        address: "198.18.0.2".parse().unwrap(),
        mtu: 1280,
    };
    lease.chain(&entry).unwrap();
    unmarked_entry_is_blocked();
    packet("octchain0", "1.1.1.1", 12345, Some(MARK), false, true);
    assert_eq!(
        dev(&[
            "-4",
            "-j",
            "route",
            "get",
            "1.1.1.1",
            "mark",
            "0x4f43544e",
            "oif",
            "octchain0"
        ]),
        "octchain0"
    );
    assert!(ip(&["-4", "route", "get", "1.1.1.1"]).is_err());
    lease.next(&entry, peers[0], controls[1]).unwrap();
    packet("octchain0", "9.9.9.9", 51820, None, false, true);
    assert_eq!(dev(&["-4", "-j", "route", "get", "9.9.9.7"]), "octchain0");
    device("octchain1", "198.18.1.2/32");
    let exit = crate::Interface {
        name: "octchain1".into(),
        address: "198.18.1.2".parse().unwrap(),
        mtu: 1280,
    };
    lease.finish(&exit).unwrap();
    unmarked_entry_is_blocked();
    packet("octchain1", "1.1.1.1", 12345, None, true, true);
    assert_eq!(dev(&["-4", "-j", "route", "get", "1.1.1.1"]), "octchain1");
    assert_eq!(
        dev(&[
            "-4",
            "-j",
            "route",
            "get",
            "1.1.1.1",
            "mark",
            "0x4f43544e",
            "oif",
            "octchain0"
        ]),
        "octchain0"
    );
    ip(&["link", "del", "octchain1"]).unwrap();
    assert!(ip(&["-4", "route", "get", "1.1.1.1"]).is_err());
    ip(&["link", "del", "octchain0"]).unwrap();
    assert!(ip(&["-4", "route", "get", "9.9.9.7"]).is_err());
    assert!(ip(&["-6", "route", "get", "2606:4700:4700::1111"]).is_err());
    // A process crash releases the flock and closes its nonpersistent TUNs,
    // while all base blockers and the detached entry policy remain.
    drop(lease);
    let names = ["octchain0".into(), "octchain1".into()];
    for args in [
        vec!["-I", "OCTRA_PAID", "1", "-j", "ACCEPT"],
        vec!["-I", "OUTPUT", "1", "-j", "ACCEPT"],
    ] {
        firewall("iptables", &args);
        let foreign = state();
        assert!(Lease::reserve(
            "8.8.8.8:51820".parse().unwrap(),
            &controls,
            &peers,
            &names,
            true,
            MARK,
            Some(&network)
        )
        .is_err());
        assert_eq!(foreign, state());
        firewall("iptables", &["-D", args[1], "1"]);
    }
    let before = state();
    for mutation in 0..5 {
        let mut bad = serde_json::to_value(&network).unwrap();
        match mutation {
            0 => bad["namespace"]["network"] = serde_json::json!(u64::MAX),
            1 => bad["bypasses"][0]["index"] = serde_json::json!(u64::MAX),
            2 => bad["bypasses"][0]["address"] = serde_json::json!("7.7.7.7"),
            3 => bad["mark"] = serde_json::json!(MARK ^ 1),
            _ => {
                let byte = bad["scope"][0].as_u64().unwrap();
                bad["scope"][0] = serde_json::json!(byte ^ 1);
            }
        }
        let bad: crate::PrivateRouteNetwork = serde_json::from_value(bad).unwrap();
        assert!(Lease::reserve(
            "8.8.8.8:51820".parse().unwrap(),
            &controls,
            &peers,
            &names,
            true,
            MARK,
            Some(&bad)
        )
        .is_err());
        assert_eq!(before, state());
    }
    device("octchain0", "198.18.0.2/32");
    let live = state();
    assert!(Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &names,
        true,
        MARK,
        Some(&network)
    )
    .is_err());
    assert_eq!(live, state());
    ip(&["link", "del", "octchain0"]).unwrap();
    ip(&[
        "-4",
        "route",
        "add",
        "7.7.7.0/24",
        "dev",
        "octscopeuplink",
        "proto",
        "186",
        "table",
        "186",
    ])
    .unwrap();
    let foreign = state();
    assert!(Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &names,
        true,
        MARK,
        Some(&network)
    )
    .is_err());
    assert_eq!(foreign, state());
    ip(&[
        "-4",
        "route",
        "del",
        "7.7.7.0/24",
        "dev",
        "octscopeuplink",
        "proto",
        "186",
        "table",
        "186",
    ])
    .unwrap();
    ip(&[
        "-4",
        "rule",
        "add",
        "priority",
        "1",
        "uidrange",
        "1000-1000",
        "lookup",
        "186",
    ])
    .unwrap();
    let foreign = state();
    assert!(Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &names,
        true,
        MARK,
        Some(&network)
    )
    .is_err());
    assert_eq!(foreign, state());
    ip(&[
        "-4",
        "rule",
        "del",
        "priority",
        "1",
        "uidrange",
        "1000-1000",
        "lookup",
        "186",
    ])
    .unwrap();
    // A matching interface alone grants no chain privilege. Retained rules
    // must carry the exact mark and full mask accepted by the sealed plan.
    for selector in ["0x4f43544f/0xffffffff", "0x4f43544e/0xfffffffe"] {
        device("octchain0", "198.18.0.2/32");
        ip(&[
            "-4",
            "rule",
            "add",
            "priority",
            "1",
            "fwmark",
            selector,
            "oif",
            "octchain0",
            "lookup",
            "185",
        ])
        .unwrap();
        ip(&["link", "del", "octchain0"]).unwrap();
        let foreign = state();
        assert!(Lease::reserve(
            "8.8.8.8:51820".parse().unwrap(),
            &controls,
            &peers,
            &names,
            true,
            MARK,
            Some(&network),
        )
        .is_err());
        assert_eq!(foreign, state());
        ip(&[
            "-4", "rule", "del", "priority", "1", "fwmark", selector, "lookup", "185",
        ])
        .unwrap();
    }
    // A partially installed plan can be repaired, but reservation is read-only.
    firewall("ip6tables", &["-D", "OUTPUT", "-j", "OCTRA_PAID"]);
    firewall("ip6tables", &["-F", "OCTRA_PAID"]);
    firewall("ip6tables", &["-X", "OCTRA_PAID"]);
    ip(&[
        "-6",
        "route",
        "del",
        "blackhole",
        "::/1",
        "proto",
        "186",
        "metric",
        "45679",
        "table",
        "185",
    ])
    .unwrap();
    let partial = state();
    let mut lease = Lease::reserve(
        "8.8.8.8:51820".parse().unwrap(),
        &controls,
        &peers,
        &names,
        true,
        MARK,
        Some(&network),
    )
    .unwrap();
    assert_eq!(partial, state());
    lease.activate().unwrap();
    assert!(ip(&["-4", "route", "get", "1.1.1.1"]).is_err());
    assert!(ip(&["-6", "route", "get", "2606:4700:4700::1111"]).is_err());
    device("octchain0", "198.18.0.2/32");
    lease.chain(&entry).unwrap();
    lease.next(&entry, peers[0], controls[1]).unwrap();
    device("octchain1", "198.18.1.2/32");
    lease.finish(&exit).unwrap();
    unmarked_entry_is_blocked();
    assert_eq!(dev(&["-4", "-j", "route", "get", "1.1.1.1"]), "octchain1");
    assert_eq!(
        dev(&[
            "-4",
            "-j",
            "route",
            "get",
            "1.1.1.1",
            "mark",
            "0x4f43544e",
            "oif",
            "octchain0"
        ]),
        "octchain0"
    );
    ip(&["link", "del", "octchain1"]).unwrap();
    ip(&["link", "del", "octchain0"]).unwrap();
    lease.disconnect().unwrap();
    assert_eq!(
        dev(&["-4", "-j", "route", "get", "1.1.1.1"]),
        "octscopeuplink"
    );
    for family in ["-4", "-6"] {
        let rules = json_array(&ip(&[family, "-j", "rule", "show"]).unwrap()).unwrap();
        assert!(rules
            .iter()
            .all(|rule| ![Some(185), Some(186)].contains(&rule["table"].as_u64())));
    }
    ip(&["link", "del", "octscopeuplink"]).unwrap();
}
