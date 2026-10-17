use std::{collections::BTreeSet, net::IpAddr};

use serde::{Deserialize, Serialize};

use super::{
    native, native_address, Address, Error, Result, BYTES_PER_MIB, MAX_CLASSES, MAX_SELECTORS,
    MAX_TARIFF_BYTES,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Any,
    Tcp,
    Udp,
    Icmp,
    IcmpV6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Direction {
    Outbound,
    Inbound,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "PrefixInput")]
pub struct IpPrefix {
    network: IpAddr,
    prefix_len: u8,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrefixInput {
    network: IpAddr,
    prefix_len: u8,
}
impl TryFrom<PrefixInput> for IpPrefix {
    type Error = Error;
    fn try_from(value: PrefixInput) -> Result<Self> {
        Self::new(value.network, value.prefix_len)
    }
}
impl IpPrefix {
    pub fn new(network: IpAddr, prefix_len: u8) -> Result<Self> {
        let canonical = match network {
            IpAddr::V4(ip) if prefix_len <= 32 => {
                u32::from(ip) & mask32(prefix_len) == u32::from(ip)
            }
            IpAddr::V6(ip) if prefix_len <= 128 => {
                u128::from(ip) & mask128(prefix_len) == u128::from(ip)
            }
            _ => false,
        };
        if !canonical {
            return Err(Error::Invalid("prefix length or host bits"));
        }
        Ok(Self {
            network,
            prefix_len,
        })
    }
    pub const fn network(&self) -> IpAddr {
        self.network
    }
    pub const fn prefix_len(&self) -> u8 {
        self.prefix_len
    }
    pub fn contains(&self, remote: IpAddr) -> bool {
        match (self.network, remote) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                u32::from(ip) & mask32(self.prefix_len) == u32::from(network)
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                u128::from(ip) & mask128(self.prefix_len) == u128::from(network)
            }
            _ => false,
        }
    }
}
fn mask32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}
fn mask128(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficClass {
    pub name: String,
    pub rate_ou_per_mib: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Selector {
    pub prefix: IpPrefix,
    pub protocol: Protocol,
    pub port: Option<u16>,
    pub traffic_class: u8,
}

/// Ordered selectors select a named price class; index zero is the default.
/// All prices concern observable network endpoints, never inferred application
/// names or decrypted TLS. An accepted instance cannot be mutated in place.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "TariffInput")]
pub struct Tariff {
    version: u8,
    #[serde(with = "native_address")]
    operator: Address,
    classes: Vec<TrafficClass>,
    selectors: Vec<Selector>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TariffInput {
    version: u8,
    #[serde(with = "native_address")]
    operator: Address,
    classes: Vec<TrafficClass>,
    selectors: Vec<Selector>,
}
impl TryFrom<TariffInput> for Tariff {
    type Error = Error;
    fn try_from(value: TariffInput) -> Result<Self> {
        if value.version != 1 {
            return Err(Error::Invalid("unsupported tariff version"));
        }
        Self::new(value.operator, value.classes, value.selectors)
    }
}
impl Tariff {
    pub fn new(
        operator: Address,
        classes: Vec<TrafficClass>,
        selectors: Vec<Selector>,
    ) -> Result<Self> {
        native(&operator)?;
        if classes.is_empty() || classes.len() > MAX_CLASSES || selectors.len() > MAX_SELECTORS {
            return Err(Error::Invalid("tariff class or selector count"));
        }
        let mut names = BTreeSet::new();
        for class in &classes {
            if class.name.is_empty()
                || class.name.len() > 64
                || !class
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
                || !names.insert(class.name.as_str())
            {
                return Err(Error::Invalid(
                    "class names must be distinct lowercase ASCII labels",
                ));
            }
        }
        for selector in &selectors {
            if usize::from(selector.traffic_class) >= classes.len() {
                return Err(Error::UnknownClass(selector.traffic_class));
            }
            if selector.port.is_some()
                && matches!(selector.protocol, Protocol::Icmp | Protocol::IcmpV6)
            {
                return Err(Error::Invalid("ICMP selectors cannot specify a port"));
            }
            if matches!(
                (selector.prefix.network(), selector.protocol),
                (IpAddr::V4(_), Protocol::IcmpV6) | (IpAddr::V6(_), Protocol::Icmp)
            ) {
                return Err(Error::Invalid("selector protocol/address family mismatch"));
            }
        }
        Ok(Self {
            version: 1,
            operator,
            classes,
            selectors,
        })
    }
    pub const fn version(&self) -> u8 {
        self.version
    }
    pub fn operator(&self) -> &Address {
        &self.operator
    }
    pub fn classes(&self) -> &[TrafficClass] {
        &self.classes
    }
    pub fn selectors(&self) -> &[Selector] {
        &self.selectors
    }

    pub fn from_bytes(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_TARIFF_BYTES {
            return Err(Error::Invalid("tariff exceeds byte bound"));
        }
        Ok(serde_json::from_slice(raw)?)
    }
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        crate::v3_canonical::canonical_write(&serde_json::to_value(self)?, &mut bytes);
        if bytes.len() > MAX_TARIFF_BYTES {
            return Err(Error::Invalid("tariff exceeds byte bound"));
        }
        Ok(bytes)
    }
    pub fn hash_hex(&self) -> Result<String> {
        Ok(crate::v3_canonical::sha256_hex(&self.canonical_bytes()?))
    }

    pub fn classify(&self, remote: IpAddr, protocol: Protocol, port: Option<u16>) -> Result<u8> {
        if protocol == Protocol::Any
            || matches!(protocol, Protocol::Tcp | Protocol::Udp) && port.is_none()
            || matches!(protocol, Protocol::Icmp | Protocol::IcmpV6) && port.is_some()
            || matches!(
                (remote, protocol),
                (IpAddr::V4(_), Protocol::IcmpV6) | (IpAddr::V6(_), Protocol::Icmp)
            )
        {
            return Err(Error::Invalid("incomplete or inconsistent packet endpoint"));
        }
        Ok(self
            .selectors
            .iter()
            .find(|selector| {
                selector.prefix.contains(remote)
                    && (selector.protocol == Protocol::Any || selector.protocol == protocol)
                    && selector.port.is_none_or(|expected| port == Some(expected))
            })
            .map_or(0, |selector| selector.traffic_class))
    }

    /// Match the remote destination/port outbound and source/port inbound.
    /// The existing strict parser refuses truncated or fragmented packets.
    pub fn classify_ipv4(&self, packet: &[u8], direction: Direction) -> Result<u8> {
        let parsed = crate::ip_tunnel::parse(packet)?;
        let remote = match direction {
            Direction::Outbound => parsed.destination,
            Direction::Inbound => parsed.source,
        };
        let protocol = match packet[9] {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            _ => return Err(Error::Invalid("unsupported packet protocol")),
        };
        let port = if protocol == Protocol::Icmp {
            None
        } else {
            let offset = match direction {
                Direction::Outbound => 22,
                Direction::Inbound => 20,
            };
            Some(u16::from_be_bytes([packet[offset], packet[offset + 1]]))
        };
        self.classify(IpAddr::V4(remote), protocol, port)
    }

    pub fn charge(&self, class: u8, total_bytes: u64) -> Result<u64> {
        let class = self
            .classes
            .get(usize::from(class))
            .ok_or(Error::UnknownClass(class))?;
        let raw = u128::from(total_bytes)
            .checked_mul(u128::from(class.rate_ou_per_mib))
            .ok_or(Error::Overflow)?;
        u64::try_from(raw.div_ceil(u128::from(BYTES_PER_MIB))).map_err(|_| Error::Overflow)
    }
    pub fn total_charge(&self, totals: &[u64]) -> Result<u64> {
        if totals.len() != self.classes.len() {
            return Err(Error::Invalid("counter/class count mismatch"));
        }
        totals
            .iter()
            .enumerate()
            .try_fold(0_u64, |sum, (class, bytes)| {
                sum.checked_add(self.charge(class as u8, *bytes)?)
                    .ok_or(Error::Overflow)
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    fn tariff() -> Tariff {
        Tariff::new(
            Address::from_pubkey(&[1; 32]),
            vec![
                TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: 10,
                },
                TrafficClass {
                    name: "premium".into(),
                    rate_ou_per_mib: 100,
                },
            ],
            vec![Selector {
                prefix: IpPrefix::new("203.0.113.0".parse().unwrap(), 24).unwrap(),
                protocol: Protocol::Tcp,
                port: Some(443),
                traffic_class: 1,
            }],
        )
        .unwrap()
    }
    #[test]
    fn selectors_are_ordered_and_require_complete_endpoint_information() {
        let tariff = tariff();
        assert_eq!(
            tariff
                .classify("203.0.113.1".parse().unwrap(), Protocol::Tcp, Some(443))
                .unwrap(),
            1
        );
        assert_eq!(
            tariff
                .classify("203.0.113.1".parse().unwrap(), Protocol::Udp, Some(443))
                .unwrap(),
            0
        );
        assert_eq!(
            tariff
                .classify("203.0.113.1".parse().unwrap(), Protocol::Tcp, Some(80))
                .unwrap(),
            0
        );
        assert!(tariff
            .classify("203.0.113.1".parse().unwrap(), Protocol::Tcp, None)
            .is_err());
        assert!(tariff
            .classify("203.0.113.1".parse().unwrap(), Protocol::Any, Some(443))
            .is_err());
        let mut selectors = tariff.selectors().to_vec();
        selectors.insert(
            0,
            Selector {
                prefix: IpPrefix::new("0.0.0.0".parse().unwrap(), 0).unwrap(),
                protocol: Protocol::Any,
                port: None,
                traffic_class: 0,
            },
        );
        let broad_first = Tariff::new(
            tariff.operator().clone(),
            tariff.classes().to_vec(),
            selectors,
        )
        .unwrap();
        assert_eq!(
            broad_first
                .classify("203.0.113.1".parse().unwrap(), Protocol::Tcp, Some(443))
                .unwrap(),
            0
        );
    }
    #[test]
    fn classification_of_both_directions_uses_the_remote_endpoint() {
        let tariff = tariff();
        fn packet(source: [u8; 4], dest: [u8; 4], source_port: u16, dest_port: u16) -> Vec<u8> {
            let mut bytes = vec![0; 28];
            bytes[0] = 0x45;
            bytes[2..4].copy_from_slice(&28_u16.to_be_bytes());
            bytes[8] = 64;
            bytes[9] = 17;
            bytes[12..16].copy_from_slice(&source);
            bytes[16..20].copy_from_slice(&dest);
            bytes[20..22].copy_from_slice(&source_port.to_be_bytes());
            bytes[22..24].copy_from_slice(&dest_port.to_be_bytes());
            bytes[24..26].copy_from_slice(&8_u16.to_be_bytes());
            let mut sum: u32 = bytes[..20]
                .chunks_exact(2)
                .map(|v| u32::from(u16::from_be_bytes([v[0], v[1]])))
                .sum();
            while sum >> 16 != 0 {
                sum = (sum & 65535) + (sum >> 16);
            }
            bytes[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
            bytes
        }
        let mut rules = tariff.selectors().to_vec();
        rules[0].protocol = Protocol::Udp;
        let tariff =
            Tariff::new(tariff.operator().clone(), tariff.classes().to_vec(), rules).unwrap();
        let outbound = packet([198, 18, 1, 1], [203, 0, 113, 5], 40000, 443);
        let inbound = packet([203, 0, 113, 5], [198, 18, 1, 1], 443, 40000);
        assert_eq!(
            tariff
                .classify_ipv4(&outbound, Direction::Outbound)
                .unwrap(),
            1
        );
        assert_eq!(
            tariff.classify_ipv4(&inbound, Direction::Inbound).unwrap(),
            1
        );
        assert!(tariff
            .classify_ipv4(&outbound[..27], Direction::Outbound)
            .is_err());
    }
    #[test]
    fn prefix_and_tariff_inputs_are_strict_and_hashes_are_canonical() {
        assert!(IpPrefix::new("192.0.2.1".parse().unwrap(), 24).is_err());
        assert!(IpPrefix::new("0.0.0.0".parse().unwrap(), 33).is_err());
        let v6 = IpPrefix::new("2001:db8::".parse().unwrap(), 32).unwrap();
        assert!(v6.contains("2001:db8:1::3".parse().unwrap()));
        assert!(!v6.contains("192.0.2.1".parse().unwrap()));
        let tariff = tariff();
        let bytes = tariff.canonical_bytes().unwrap();
        assert_eq!(Tariff::from_bytes(&bytes).unwrap(), tariff);
        assert_eq!(
            tariff.hash_hex().unwrap(),
            crate::v3_canonical::sha256_hex(&bytes)
        );
        let mut value = serde_json::to_value(&tariff).unwrap();
        value["extra"] = json!(true);
        assert!(serde_json::from_value::<Tariff>(value).is_err());
        let mut value = serde_json::to_value(&tariff).unwrap();
        value["selectors"][0]["traffic_class"] = json!(2);
        assert!(serde_json::from_value::<Tariff>(value).is_err());
        assert!(Tariff::new(tariff.operator().clone(), vec![], vec![]).is_err());
        assert!(Tariff::from_bytes(&vec![b' '; MAX_TARIFF_BYTES + 1]).is_err());
    }
    #[test]
    fn prices_use_cumulative_per_class_rounding_and_checked_arithmetic() {
        let tariff = tariff();
        assert_eq!(tariff.charge(0, 0).unwrap(), 0);
        assert_eq!(tariff.charge(0, 1).unwrap(), 1);
        assert_eq!(tariff.charge(0, 1_048_576).unwrap(), 10);
        assert_eq!(tariff.charge(1, 1_048_576).unwrap(), 100);
        assert_eq!(tariff.total_charge(&[1_048_576, 1_048_576]).unwrap(), 110);
        assert!(tariff.charge(2, 0).is_err());
        let large = Tariff::new(
            tariff.operator().clone(),
            vec![TrafficClass {
                name: "all".into(),
                rate_ou_per_mib: u64::MAX,
            }],
            vec![],
        )
        .unwrap();
        assert!(large.charge(0, u64::MAX).is_err());
        assert_eq!(large.charge(0, 1_048_576).unwrap(), u64::MAX);
    }
}
