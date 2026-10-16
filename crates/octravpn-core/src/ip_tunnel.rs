//! Versioned raw IPv4 mode inside an authenticated session/onion frame.
//! Address assignment is local VPN transport policy, never consensus state.
use std::net::Ipv4Addr;

use sha2::{Digest, Sha256};

use crate::session::SessionId;

pub const PREFIX: &[u8] = b"OVIP\x01";
pub const MTU: usize = 1280;
pub const GATEWAY: Ipv4Addr = Ipv4Addr::new(198, 18, 0, 1);

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("raw VPN packet exceeds the configured MTU")]
    TooLarge,
    #[error("invalid complete IPv4 VPN packet")]
    Invalid,
    #[error("IPv4 VPN options and fragments are unsupported")]
    Fragment,
    #[error("IPv4 VPN packet checksum mismatch")]
    Checksum,
    #[error("unsupported IPv4 VPN transport protocol")]
    Protocol,
    #[error("IPv4 VPN source does not match the authenticated session")]
    Source,
    #[error("IPv4 VPN destination is outside the permitted route")]
    Destination,
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub source: Ipv4Addr,
    pub destination: Ipv4Addr,
    pub bytes: &'a [u8],
}

/// Reserve .0, the gateway .1, and the /15 broadcast. Collisions are possible
/// in this finite pool; the server must retain and refuse conflicting ownership
/// for as long as kernel/NAT state for this transport identity can survive.
pub fn address(session: &SessionId, wireguard_key: &[u8; 32]) -> Ipv4Addr {
    let mut hash = Sha256::new();
    hash.update(b"octravpn:raw-ip:address:v1\0");
    hash.update(session.as_bytes());
    hash.update(wireguard_key);
    let digest = hash.finalize();
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    let offset = value % 131_069 + 2;
    Ipv4Addr::from(u32::from(Ipv4Addr::new(198, 18, 0, 0)) + offset)
}

pub fn encode(packet: &[u8]) -> Result<Vec<u8>, Error> {
    parse(packet)?;
    let mut payload = Vec::with_capacity(PREFIX.len() + packet.len());
    payload.extend_from_slice(PREFIX);
    payload.extend_from_slice(packet);
    Ok(payload)
}

pub fn decode(payload: &[u8]) -> Result<&[u8], Error> {
    let packet = payload.strip_prefix(PREFIX).ok_or(Error::Invalid)?;
    parse(packet)?;
    Ok(packet)
}

pub fn validate_outbound(packet: &[u8], assigned: Ipv4Addr) -> Result<Packet<'_>, Error> {
    let parsed = parse(packet)?;
    if parsed.source != assigned {
        return Err(Error::Source);
    }
    if !public_ipv4(parsed.destination) {
        return Err(Error::Destination);
    }
    Ok(parsed)
}

pub fn validate_inbound(packet: &[u8], assigned: Ipv4Addr) -> Result<Packet<'_>, Error> {
    let parsed = parse(packet)?;
    if !public_ipv4(parsed.source) {
        return Err(Error::Source);
    }
    if parsed.destination != assigned {
        return Err(Error::Destination);
    }
    Ok(parsed)
}

/// Complete packets only. OS TUNs operate on packet boundaries and WireGuard
/// authenticates the outer frame; accepting truncation, IP options or IP
/// fragmentation here would weaken source/destination policy inspection.
pub fn parse(packet: &[u8]) -> Result<Packet<'_>, Error> {
    if packet.len() > MTU {
        return Err(Error::TooLarge);
    }
    if packet.len() < 20
        || packet[0] >> 4 != 4
        || packet[8] == 0
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
    {
        return Err(Error::Invalid);
    }
    if packet[0] != 0x45 || u16::from_be_bytes([packet[6], packet[7]]) & 0xbfff != 0 {
        return Err(Error::Fragment);
    }
    if checksum(&packet[..20]) != 0 {
        return Err(Error::Checksum);
    }
    let body = &packet[20..];
    match packet[9] {
        1 => {
            if body.len() < 8 {
                return Err(Error::Invalid);
            }
            if checksum(body) != 0 {
                return Err(Error::Checksum);
            }
        }
        6 => {
            if body.len() < 20 {
                return Err(Error::Invalid);
            }
            let header = usize::from(body[12] >> 4) * 4;
            if header < 20 || header > body.len() {
                return Err(Error::Invalid);
            }
            if transport_checksum(packet, body) != 0 {
                return Err(Error::Checksum);
            }
        }
        17 => {
            if body.len() < 8 || usize::from(u16::from_be_bytes([body[4], body[5]])) != body.len() {
                return Err(Error::Invalid);
            }
            // A zero UDP checksum is valid on IPv4. The packet still has
            // authenticated transport protection on the VPN segment.
            if body[6..8] != [0, 0] && transport_checksum(packet, body) != 0 {
                return Err(Error::Checksum);
            }
        }
        _ => return Err(Error::Protocol),
    }
    Ok(Packet {
        source: Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]),
        destination: Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]),
        bytes: packet,
    })
}

pub fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, _] = ip.octets();
    !(a == 0
        || a == 10
        || a == 127
        || a >= 224
        || (a == 100 && (64..=127).contains(&b))
        || (a == 169 && b == 254)
        || (a == 172 && (16..=31).contains(&b))
        || (a == 192 && b == 168)
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 198 && (b == 18 || b == 19))
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113))
}

fn transport_checksum(ip: &[u8], body: &[u8]) -> u16 {
    let mut sum = word_sum(&ip[12..20]) + u32::from(ip[9]) + body.len() as u32;
    sum += word_sum(body);
    finish(sum)
}

fn checksum(bytes: &[u8]) -> u16 {
    finish(word_sum(bytes))
}

fn word_sum(bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    let mut sum = chunks
        .by_ref()
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    if let Some(last) = chunks.remainder().first() {
        sum += u32::from(*last) << 8;
    }
    sum
}

fn finish(mut sum: u32) -> u16 {
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn repair_ip(packet: &mut [u8]) {
        packet[10..12].fill(0);
        let value = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&value.to_be_bytes());
    }
    fn udp(source: Ipv4Addr, destination: Ipv4Addr, data: &[u8]) -> Vec<u8> {
        let length = 28 + data.len();
        let mut packet = vec![0; length];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&(length as u16).to_be_bytes());
        packet[6] = 0x40;
        packet[8] = 64;
        packet[9] = 17;
        packet[12..16].copy_from_slice(&source.octets());
        packet[16..20].copy_from_slice(&destination.octets());
        packet[20..22].copy_from_slice(&1000u16.to_be_bytes());
        packet[22..24].copy_from_slice(&2000u16.to_be_bytes());
        packet[24..26].copy_from_slice(&((length - 20) as u16).to_be_bytes());
        packet[28..].copy_from_slice(data);
        repair_ip(&mut packet);
        packet
    }
    #[test]
    fn assigned_source_and_public_destination_are_required_in_both_directions() {
        let sid = SessionId::from_u64(19);
        let assigned = address(&sid, &[11; 32]);
        let public = Ipv4Addr::new(93, 184, 216, 34);
        assert_ne!(assigned, GATEWAY);
        assert!(u32::from(assigned) > u32::from(GATEWAY));
        assert!(!public_ipv4(assigned));
        let packet = udp(assigned, public, b"payload");
        validate_outbound(&packet, assigned).unwrap();
        let framed = encode(&packet).unwrap();
        assert_eq!(decode(&framed).unwrap(), packet);
        assert_eq!(
            validate_outbound(&packet, GATEWAY).unwrap_err(),
            Error::Source
        );
        assert_eq!(
            validate_outbound(&udp(assigned, Ipv4Addr::LOCALHOST, b"x"), assigned).unwrap_err(),
            Error::Destination
        );
        validate_inbound(&udp(public, assigned, b"reply"), assigned).unwrap();
        assert_eq!(
            validate_inbound(&packet, assigned).unwrap_err(),
            Error::Source
        );
        assert_eq!(
            validate_inbound(&udp(public, GATEWAY, b"x"), assigned).unwrap_err(),
            Error::Destination
        );
        let mut wrong_version = framed;
        wrong_version[4] = 2;
        assert_eq!(decode(&wrong_version).unwrap_err(), Error::Invalid);
    }
    #[test]
    fn truncated_fragmented_options_and_bad_transport_checksums_are_rejected() {
        let packet = udp(
            Ipv4Addr::new(198, 18, 1, 2),
            Ipv4Addr::new(93, 184, 216, 34),
            b"x",
        );
        for length in 0..packet.len() {
            assert!(parse(&packet[..length]).is_err(), "truncation {length}");
        }
        let mut changed = packet.clone();
        changed[6] = 0x20;
        repair_ip(&mut changed);
        assert_eq!(parse(&changed).unwrap_err(), Error::Fragment);
        let mut changed = packet.clone();
        changed[7] = 1;
        repair_ip(&mut changed);
        assert_eq!(parse(&changed).unwrap_err(), Error::Fragment);
        let mut changed = packet.clone();
        changed[0] = 0x46;
        repair_ip(&mut changed);
        assert_eq!(parse(&changed).unwrap_err(), Error::Fragment);
        let mut changed = packet.clone();
        changed[10] ^= 1;
        assert_eq!(parse(&changed).unwrap_err(), Error::Checksum);
        let mut changed = packet.clone();
        changed[26] = 1;
        assert_eq!(parse(&changed).unwrap_err(), Error::Checksum);
        let mut changed = packet.clone();
        changed[24..26].copy_from_slice(&8u16.to_be_bytes());
        assert_eq!(parse(&changed).unwrap_err(), Error::Invalid);
        let mut changed = packet;
        changed[9] = 99;
        repair_ip(&mut changed);
        assert_eq!(parse(&changed).unwrap_err(), Error::Protocol);
    }
    #[test]
    fn mtu_is_a_complete_packet_boundary_and_private_ranges_never_egress() {
        let source = Ipv4Addr::new(198, 18, 1, 2);
        let public = Ipv4Addr::new(93, 184, 216, 34);
        parse(&udp(source, public, &vec![1; MTU - 28])).unwrap();
        assert_eq!(
            parse(&udp(source, public, &vec![1; MTU - 27])).unwrap_err(),
            Error::TooLarge
        );
        for address in [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "192.168.0.1",
            "192.0.2.1",
            "198.18.0.2",
            "198.51.100.1",
            "203.0.113.1",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(!public_ipv4(address.parse().unwrap()), "{address}");
        }
    }
}
