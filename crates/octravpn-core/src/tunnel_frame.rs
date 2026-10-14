//! Session datagrams carried inside authenticated WireGuard IPv4 packets.
//! WireGuard transports IP; a bare session/onion blob is not an IP packet.
use crate::session::SessionId;

const PREFIX: &[u8] = b"OVPN\x01";
const HEADER: usize = 28;
const PORT: u16 = 51822;
const SOURCE: [u8; 4] = [100, 64, 0, 1];
const DESTINATION: [u8; 4] = [100, 64, 0, 2];
// IPv4 UDP permits 65,507 payload bytes. WireGuard adds 32 bytes and rounds
// the inner packet to a 16-byte boundary: floor((65507 - 32) / 16) * 16.
const MAX_INNER_PACKET: usize = 65_472;
pub const MAX_PAYLOAD: usize = MAX_INNER_PACKET - HEADER - PREFIX.len() - 32;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("VPN datagram exceeds the WireGuard UDP transport limit")]
    TooLarge,
    #[error("invalid VPN WireGuard frame")]
    Invalid,
}

fn checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum();
    while sum > u32::from(u16::MAX) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn encode(session: &SessionId, payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > MAX_PAYLOAD {
        return Err(Error::TooLarge);
    }
    let size = HEADER + PREFIX.len() + 32 + payload.len();
    let mut packet = vec![0; HEADER];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&(size as u16).to_be_bytes());
    packet[6] = 0x40; // Do not fragment the authenticated inner datagram.
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&SOURCE);
    packet[16..20].copy_from_slice(&DESTINATION);
    let sum = checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet[20..22].copy_from_slice(&PORT.to_be_bytes());
    packet[22..24].copy_from_slice(&PORT.to_be_bytes());
    packet[24..26].copy_from_slice(&((size - 20) as u16).to_be_bytes());
    // IPv4 permits an omitted UDP checksum; WireGuard authenticates the packet.
    packet.extend_from_slice(PREFIX);
    packet.extend_from_slice(session.as_bytes());
    packet.extend_from_slice(payload);
    Ok(packet)
}

/// Return the session prefix and payload only after validating the complete
/// inner frame. No IP options, fragments, unrelated ports or trailing bytes.
pub fn decode(packet: &[u8]) -> Result<&[u8], Error> {
    if packet.len() < HEADER + PREFIX.len() + 32
        || packet.len() > MAX_INNER_PACKET
        || packet[0] != 0x45
        || packet[9] != 17
        || packet[8] == 0
        || packet[6..8] != [0x40, 0]
        || usize::from(u16::from_be_bytes([packet[2], packet[3]])) != packet.len()
        || checksum(&packet[..20]) != 0
        || packet[12..16] != SOURCE
        || packet[16..20] != DESTINATION
        || packet[20..22] != PORT.to_be_bytes()
        || packet[22..24] != PORT.to_be_bytes()
        || usize::from(u16::from_be_bytes([packet[24], packet[25]])) != packet.len() - 20
        || packet[26..28] != [0, 0]
        || &packet[HEADER..HEADER + PREFIX.len()] != PREFIX
    {
        return Err(Error::Invalid);
    }
    Ok(&packet[HEADER + PREFIX.len()..])
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wireguard_inner_frame_is_length_delimited_and_authenticated_by_its_outer_tunnel() {
        let id = SessionId::from_u64(17);
        for payload in [vec![], vec![0, 255, 42], vec![17; MAX_PAYLOAD]] {
            let packet = encode(&id, &payload).unwrap();
            let decoded = decode(&packet).unwrap();
            assert_eq!(&decoded[..32], id.as_bytes());
            assert_eq!(&decoded[32..], payload);
            for size in 0..packet.len().min(70) {
                assert!(decode(&packet[..size]).is_err());
            }
            for offset in [0, 2, 3, 6, 9, 10, 12, 16, 20, 22, 24, 26, 28] {
                let mut bad = packet.clone();
                bad[offset] ^= 1;
                assert!(decode(&bad).is_err(), "offset {offset}");
            }
            let mut trailing = packet;
            trailing.push(0);
            assert!(decode(&trailing).is_err());
        }
        assert_eq!(encode(&id, &vec![0; MAX_PAYLOAD + 1]), Err(Error::TooLarge));
    }
}
