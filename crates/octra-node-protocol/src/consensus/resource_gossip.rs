// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2023-2026 Octra Labs <dev@octra.org>
//! Disabled native RESOURCE_ATTESTATION handling, without enabling committees.
use crate::oce1::{Error, Reader};

/// A well-encoded gossip is rejected while the native node's committee config
/// is None. Malformed encodings are logged without peer penalty, as upstream.
pub fn disabled_reason(chain: &[u8], raw: &[u8]) -> Result<&'static [u8], Error> {
    let mut outer = Reader::new(raw);
    let gossip_chain = outer.get_bytes_bounded(128)?;
    let _seen_epoch = outer.get_u64()?;
    let raw_attestation = outer.get_bytes_bounded(256 * 1024)?;
    let mut attestation = Reader::new(raw_attestation);
    let _chain = attestation.get_bytes_bounded(128)?;
    let _epoch = attestation.get_u64()?;
    let _node = attestation.get_bytes_bounded(128)?;
    match attestation.get_u8()? {
        1..=4 => (),
        _ => return Err("bad resource attestation kind".into()),
    }
    let _commitment = attestation.get_bytes_bounded(64 * 1024)?;
    let _proof_hash = attestation.get_hash32()?;
    let _weight = attestation.get_u64()?;
    let _score = attestation.get_hash32()?;
    let _signature = attestation.get_sig64()?;
    attestation.finish()?;
    // Native decode_gossip parses the nested attestation before completing its
    // outer OCE1 decoder; preserve that malformed-input precedence.
    outer.finish()?;
    Ok(if gossip_chain == chain {
        b"invalid_resource_attestation"
    } else {
        b"resource_attestation_chain_mismatch"
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::oce1::Writer;
    fn gossip(chain: &[u8], kind: u8) -> Vec<u8> {
        let mut att = Writer::new();
        att.put_bytes(b"inner-chain").unwrap();
        att.put_u64(u64::MAX).unwrap();
        att.put_bytes(b"node").unwrap();
        att.put_u8(kind).unwrap();
        att.put_bytes(b"commitment").unwrap();
        att.put_hash32(&[3; 32]).unwrap();
        att.put_u64(u64::MAX).unwrap();
        att.put_hash32(&[4; 32]).unwrap();
        att.put_sig64(&[5; 64]).unwrap();
        let mut outer = Writer::new();
        outer.put_bytes(chain).unwrap();
        outer.put_u64(9).unwrap();
        outer.put_bytes(&att.into_bytes()).unwrap();
        outer.into_bytes()
    }
    #[test]
    fn disabled_gossip_decodes_before_chain_rejection_and_never_admits() {
        for kind in 1..=4 {
            assert_eq!(
                disabled_reason(b"chain", &gossip(b"chain", kind)).unwrap(),
                b"invalid_resource_attestation"
            );
        }
        assert_eq!(
            disabled_reason(b"chain", &gossip(b"other", 1)).unwrap(),
            b"resource_attestation_chain_mismatch"
        );
        assert!(disabled_reason(b"chain", &gossip(b"other", 0)).is_err());
        let mut encoded = gossip(b"chain", 1);
        encoded.push(0);
        assert!(disabled_reason(b"chain", &encoded).is_err());
        assert!(disabled_reason(b"chain", &gossip(b"chain", 1)[..5]).is_err());
    }
}
