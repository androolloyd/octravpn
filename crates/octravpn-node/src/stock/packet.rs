//! Address translation preserves raw IP length and the tariff's remote endpoint.
use anyhow::{ensure, Result};
use octravpn_core::ip_tunnel::{self, Packet};
use std::net::Ipv4Addr;

pub(crate) fn portal(packet: &Packet<'_>, config: &super::Config) -> bool {
    packet.destination == config.operator_ipv4
        && packet.bytes[9] == 6
        && u16::from_be_bytes([packet.bytes[22], packet.bytes[23]]) == config.portal_port
}
pub(crate) fn circle(packet: &Packet<'_>, config: &super::Config) -> bool {
    config.circle_gateway
        && packet.destination == super::CIRCLE_GATEWAY
        && packet.bytes[9] == 6
        && packet.bytes[22..24] == 443u16.to_be_bytes()
}
pub(crate) fn circle_return(packet: &Packet<'_>) -> bool {
    packet.source == ip_tunnel::GATEWAY
        && packet.bytes[9] == 6
        && packet.bytes[20..22] == 8443u16.to_be_bytes()
}
pub(crate) fn portal_return(packet: &Packet<'_>, port: u16) -> bool {
    packet.source == ip_tunnel::GATEWAY
        && packet.bytes[9] == 6
        && u16::from_be_bytes([packet.bytes[20], packet.bytes[21]]) == port
}
#[cfg(test)]
pub(crate) fn translate(bytes: &[u8], source: Ipv4Addr, destination: Ipv4Addr) -> Result<Vec<u8>> {
    rewrite(bytes, source, destination, None, None)
}
pub(crate) fn rewrite(
    bytes: &[u8],
    source: Ipv4Addr,
    destination: Ipv4Addr,
    source_port: Option<u16>,
    destination_port: Option<u16>,
) -> Result<Vec<u8>> {
    ip_tunnel::parse(bytes)?;
    let mut raw = bytes.to_vec();
    if source_port.is_some() || destination_port.is_some() {
        ensure!(matches!(raw[9], 6 | 17), "port rewrite requires TCP or UDP");
        if let Some(port) = source_port {
            raw[20..22].copy_from_slice(&port.to_be_bytes());
        }
        if let Some(port) = destination_port {
            raw[22..24].copy_from_slice(&port.to_be_bytes());
        }
    }
    let zero_udp = raw[9] == 17 && raw[26..28] == [0, 0];
    raw[12..16].copy_from_slice(&source.octets());
    raw[16..20].copy_from_slice(&destination.octets());
    raw[10..12].fill(0);
    let ip = checksum(&raw[..20]);
    raw[10..12].copy_from_slice(&ip.to_be_bytes());
    let index = match raw[9] {
        6 => Some(36),
        17 if !zero_udp => Some(26),
        _ => None,
    };
    if let Some(index) = index {
        raw[index..index + 2].fill(0);
        let mut pseudo = raw[12..20].to_vec();
        pseudo.extend_from_slice(&[0, raw[9]]);
        pseudo.extend_from_slice(&((raw.len() - 20) as u16).to_be_bytes());
        pseudo.extend_from_slice(&raw[20..]);
        let sum = checksum(&pseudo);
        let sum = if raw[9] == 17 && sum == 0 {
            u16::MAX
        } else {
            sum
        };
        raw[index..index + 2].copy_from_slice(&sum.to_be_bytes());
    }
    ensure!(raw.len() == bytes.len(), "stock packet length changed");
    ip_tunnel::parse(&raw)?;
    Ok(raw)
}
fn checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for pair in bytes.chunks(2) {
        sum += u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)]));
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn udp() -> Vec<u8> {
        let mut raw = vec![0; 31];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&31u16.to_be_bytes());
        raw[8] = 64;
        raw[9] = 17;
        raw[12..16].copy_from_slice(&[100, 64, 0, 2]);
        raw[16..20].copy_from_slice(&[8, 8, 8, 8]);
        raw[20..22].copy_from_slice(&3000u16.to_be_bytes());
        raw[22..24].copy_from_slice(&53u16.to_be_bytes());
        raw[24..26].copy_from_slice(&11u16.to_be_bytes());
        raw[28..].copy_from_slice(b"dns");
        let sum = checksum(&raw[..20]);
        raw[10..12].copy_from_slice(&sum.to_be_bytes());
        raw
    }
    #[test]
    fn translation_round_trip_preserves_length_and_validates_transport() {
        let raw = udp();
        let internal = "198.18.4.5".parse().unwrap();
        let remote = "8.8.8.8".parse().unwrap();
        let mapped = translate(&raw, internal, remote).unwrap();
        assert_eq!(mapped.len(), raw.len());
        ip_tunnel::validate_outbound(&mapped, internal).unwrap();
        assert_eq!(
            translate(&mapped, "100.64.0.2".parse().unwrap(), remote).unwrap(),
            raw
        );
        let mut bad = raw;
        bad[12] ^= 1;
        assert!(translate(&bad, internal, remote).is_err());
    }
    #[test]
    fn ipv6_fragments_private_routes_and_spoofed_sources_are_not_accepted() {
        assert!(translate(
            &[0x60; 40],
            "198.18.0.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap()
        )
        .is_err());
        let mut raw = udp();
        raw[6] = 0x20;
        assert!(ip_tunnel::parse(&raw).is_err());
    }
}

#[cfg(test)]
mod gateway_tests {
    use super::*;
    fn tcp(
        source: Ipv4Addr,
        destination: Ipv4Addr,
        source_port: u16,
        destination_port: u16,
    ) -> Vec<u8> {
        let mut raw = vec![0; 40];
        raw[0] = 0x45;
        raw[2..4].copy_from_slice(&40u16.to_be_bytes());
        raw[8] = 64;
        raw[9] = 6;
        raw[12..16].copy_from_slice(&source.octets());
        raw[16..20].copy_from_slice(&destination.octets());
        raw[20..22].copy_from_slice(&source_port.to_be_bytes());
        raw[22..24].copy_from_slice(&destination_port.to_be_bytes());
        raw[32] = 0x50;
        raw[33] = 2;
        let sum = checksum(&raw[..20]);
        raw[10..12].copy_from_slice(&sum.to_be_bytes());
        let mut pseudo = raw[12..20].to_vec();
        pseudo.extend_from_slice(&[0, 6, 0, 20]);
        pseudo.extend_from_slice(&raw[20..]);
        let sum = checksum(&pseudo);
        raw[36..38].copy_from_slice(&sum.to_be_bytes());
        ip_tunnel::parse(&raw).unwrap();
        raw
    }
    #[test]
    fn free_portal_and_paid_circle_are_distinct_exact_destinations_and_ports() {
        let config = super::super::Config {
            operator_ipv4: "100.64.0.1".parse().unwrap(),
            portal_port: 443,
            circle_gateway: true,
            endpoints: vec![],
        };
        let client = "100.64.0.2".parse().unwrap();
        let portal_packet = tcp(client, config.operator_ipv4, 45000, 443);
        assert!(portal(&ip_tunnel::parse(&portal_packet).unwrap(), &config));
        assert!(!circle(&ip_tunnel::parse(&portal_packet).unwrap(), &config));
        let paid = tcp(client, super::super::CIRCLE_GATEWAY, 45000, 443);
        assert!(!portal(&ip_tunnel::parse(&paid).unwrap(), &config));
        assert!(circle(&ip_tunnel::parse(&paid).unwrap(), &config));
        let assigned = "198.18.7.9".parse().unwrap();
        let mapped = rewrite(&paid, assigned, ip_tunnel::GATEWAY, None, Some(8443)).unwrap();
        assert_eq!(paid.len(), mapped.len());
        assert_eq!(&mapped[22..24], &8443u16.to_be_bytes());
        let response = tcp(ip_tunnel::GATEWAY, assigned, 8443, 45000);
        assert!(circle_return(&ip_tunnel::parse(&response).unwrap()));
        assert!(!portal_return(&ip_tunnel::parse(&response).unwrap(), 443));
        let restored = rewrite(
            &response,
            super::super::CIRCLE_GATEWAY,
            client,
            Some(443),
            None,
        )
        .unwrap();
        assert_eq!(
            ip_tunnel::parse(&restored).unwrap().source,
            super::super::CIRCLE_GATEWAY
        );
        assert_eq!(&restored[20..22], &443u16.to_be_bytes());
        let wrong = tcp(client, config.operator_ipv4, 45000, 8443);
        assert!(!portal(&ip_tunnel::parse(&wrong).unwrap(), &config));
        assert!(!circle(&ip_tunnel::parse(&wrong).unwrap(), &config));
        let mut disabled = config;
        disabled.circle_gateway = false;
        assert!(!circle(&ip_tunnel::parse(&paid).unwrap(), &disabled));
    }
}
