use anyhow::{ensure, Context, Result};
use octravpn_core::{
    ip_tunnel,
    onion::{build_fresh_onion, HopBuildInput},
    session::SessionId,
    tunnel_frame,
};

// The actual serializer supplies framing overhead, including single-Egress
// onion JSON. Every nested carrier is complete IPv4(20)+UDP(8)+WG(32), with
// WireGuard16-byte standards padding is conservatively allowed. The pinned
// boringtun currently omits that padding; these are profile limits, not the
// largest packets its current emitter could fit. Amnezia is off here.
fn overhead() -> Result<usize> {
    let key = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from([19; 32]));
    let onion = build_fresh_onion(
        &[HopBuildInput {
            static_pubkey: key.to_bytes(),
            endpoint: String::new(),
        }],
        ip_tunnel::PREFIX,
    )?;
    Ok(tunnel_frame::encode(&SessionId::from_u64(1), &onion)?.len())
}
pub(super) fn route_mtus(count: usize) -> Result<Vec<u16>> {
    ensure!(
        (2..=octravpn_core::onion::MAX_HOPS).contains(&count),
        "invalid composite hop count"
    );
    let overhead = overhead()?;
    let mut mtus = vec![ip_tunnel::MTU as u16];
    for _ in 1..count {
        let parent = usize::from(*mtus.last().context("missing parent MTU")?);
        let next = ((parent.checked_sub(60).context("carrier MTU too small")? / 16) * 16)
            .checked_sub(overhead)
            .context("carrier framing exceeds MTU")?;
        ensure!(next >= 68, "nested IPv4 MTU is below minimum");
        mtus.push(u16::try_from(next)?);
    }
    Ok(mtus)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn datagram(raw: usize) -> usize {
        60 + (raw + overhead().unwrap()).div_ceil(16) * 16
    }
    #[test]
    fn serialized_headers_and_padding_safe_profile_bound_every_carrier() {
        let mtus = route_mtus(3).unwrap();
        assert_eq!(mtus, [1280, 1075, 867]);
        for pair in mtus.windows(2) {
            let parent = usize::from(pair[0]);
            let raw = usize::from(pair[1]);
            assert!(datagram(raw) <= parent);
            // One more byte exceeds the conservative profile budget; it need
            // not exceed the current unpadded boringtun emitter size.
            assert!(datagram(raw + 1) > parent);
            // Return frames omit the71-byte onion and are strictly smaller.
            let return_frame = tunnel_frame::encode(
                &SessionId::from_u64(1),
                &vec![0; ip_tunnel::PREFIX.len() + raw],
            )
            .unwrap();
            assert!(60 + return_frame.len().div_ceil(16) * 16 <= parent);
        }
        assert!(route_mtus(1).is_err());
        assert!(route_mtus(4).is_err());
    }
}
