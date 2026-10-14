//! First-party VPN discovery implemented as a Circle application.
//!
//! An advertisement is not a stake or funding certificate. Admission must
//! independently check the referenced settlement app's finalized state.
//! Caller identity and epoch come from the Circle host, never request JSON.

pub mod codec;
#[cfg(target_arch = "wasm32")]
#[allow(unsafe_code)] // The isolated guest ABI passes guest-memory pointers to the Circle host.
mod guest;
#[cfg(all(feature = "host", not(target_arch = "wasm32")))]
pub mod projection;

use serde::{Deserialize, Serialize};

pub const MAX_REQUEST_BYTES: usize = 8192;
pub const MAX_RECORD_BYTES: usize = 4096;
pub const EVENT_TOPIC: &str = "octra.vpn.operator.v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Offer {
    pub settlement_circle: String,
    pub control_url: String,
    pub wireguard_endpoint: String,
    pub wireguard_key_hex: String,
    pub receipt_key_hex: String,
    pub region: String,
    pub exit: bool,
    pub relay: bool,
    pub price_ou_per_mib: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PublishRequest {
    pub expected_revision: u64,
    pub offer: Offer,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperatorRecord {
    pub operator: String,
    pub revision: u64,
    pub updated_epoch: u64,
    pub retired: bool,
    pub offer: Offer,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum Error {
    #[error("invalid Octra address")]
    Address,
    #[error("invalid operator offer")]
    Offer,
    #[error("operator revision mismatch")]
    Revision,
    #[error("operator revision exhausted")]
    RevisionExhausted,
    #[error("operator not registered")]
    Missing,
    #[error("stored operator identity mismatch")]
    Identity,
    #[error("epoch regressed")]
    Epoch,
    #[error("invalid Circle request frame")]
    Frame,
}

pub fn valid_address(address: &str) -> bool {
    let Some(body) = address.strip_prefix("oct") else {
        return false;
    };
    if body.len() != 44 || !body.is_ascii() {
        return false;
    }
    bs58::decode(body.trim_start_matches('1'))
        .into_vec()
        .is_ok_and(|bytes| bytes.len() <= 32)
}

/// Native Circle IDs cycle a short base58 digest to 44 characters. They are
/// not wallet addresses and may decode to more than 32 bytes.
pub fn valid_circle_id(circle: &str) -> bool {
    circle.strip_prefix("oct").is_some_and(|body| {
        body.len() == 44
            && body
                .bytes()
                .all(|b| b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz".contains(&b))
    })
}

pub fn storage_key(operator: &str) -> Result<String, Error> {
    if !valid_address(operator) {
        return Err(Error::Address);
    }
    Ok(format!("vpn/operator/{operator}"))
}

fn valid_key(key: &str) -> bool {
    key.len() == 64
        && key
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && key.bytes().any(|b| b != b'0')
}

impl Offer {
    pub fn validate(&self) -> Result<(), Error> {
        let url = url::Url::parse(&self.control_url).map_err(|_| Error::Offer)?;
        if !valid_circle_id(&self.settlement_circle)
            || url.scheme() != "https"
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.query().is_some()
            || url.fragment().is_some()
            || self.control_url.len() > 512
            || !self.control_url.is_ascii()
            || self
                .control_url
                .bytes()
                .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
            || self.control_url.contains(['@', '#', '?', '\\'])
            || self
                .wireguard_endpoint
                .parse::<std::net::SocketAddr>()
                .map_or(true, |a| a.port() == 0)
            || !valid_key(&self.wireguard_key_hex)
            || !valid_key(&self.receipt_key_hex)
            || self.region.len() != 2
            || !self.region.bytes().all(|b| b.is_ascii_uppercase())
            || (!self.exit && !self.relay)
            || self.price_ou_per_mib == 0
        {
            return Err(Error::Offer);
        }
        Ok(())
    }
}

fn next_revision(
    previous: Option<&OperatorRecord>,
    caller: &str,
    epoch: u64,
    expected: u64,
) -> Result<u64, Error> {
    if !valid_address(caller) {
        return Err(Error::Address);
    }
    if let Some(record) = previous {
        if record.operator != caller {
            return Err(Error::Identity);
        }
        if epoch < record.updated_epoch {
            return Err(Error::Epoch);
        }
    }
    let current = previous.map_or(0, |record| record.revision);
    if expected != current {
        return Err(Error::Revision);
    }
    current.checked_add(1).ok_or(Error::RevisionExhausted)
}

pub fn publish(
    previous: Option<&OperatorRecord>,
    caller: &str,
    epoch: u64,
    request: PublishRequest,
) -> Result<OperatorRecord, Error> {
    request.offer.validate()?;
    let revision = next_revision(previous, caller, epoch, request.expected_revision)?;
    Ok(OperatorRecord {
        operator: caller.into(),
        revision,
        updated_epoch: epoch,
        retired: false,
        offer: request.offer,
    })
}

pub fn retire(
    previous: &OperatorRecord,
    caller: &str,
    epoch: u64,
    expected: u64,
) -> Result<OperatorRecord, Error> {
    let revision = next_revision(Some(previous), caller, epoch, expected)?;
    Ok(OperatorRecord {
        revision,
        updated_epoch: epoch,
        retired: true,
        ..previous.clone()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    fn address(n: u8) -> String {
        format!("oct{:1>44}", bs58::encode([n; 32]).into_string())
    }
    fn request() -> PublishRequest {
        PublishRequest {
            expected_revision: 0,
            offer: Offer {
                settlement_circle: address(2),
                control_url: "https://vpn.example/control".into(),
                wireguard_endpoint: "203.0.113.7:51820".into(),
                wireguard_key_hex: "11".repeat(32),
                receipt_key_hex: "22".repeat(32),
                region: "CA".into(),
                exit: true,
                relay: false,
                price_ou_per_mib: 100,
            },
        }
    }
    #[test]
    fn caller_owns_record_and_replay_cannot_replace_it() {
        let first = publish(None, &address(1), 10, request()).unwrap();
        assert_eq!(
            publish(Some(&first), &address(1), 11, request()),
            Err(Error::Revision)
        );
        assert_eq!(retire(&first, &address(3), 11, 1), Err(Error::Identity));
        let retired = retire(&first, &address(1), 11, 1).unwrap();
        assert!(retired.retired);
        assert_eq!(retired.revision, 2);
        let mut fresh = request();
        fresh.expected_revision = 2;
        let resumed = publish(Some(&retired), &address(1), 12, fresh).unwrap();
        assert_eq!(resumed.revision, 3);
        assert!(!resumed.retired);
    }
    #[test]
    fn malformed_offer_and_epoch_regression_fail_closed() {
        for url in [
            "http://vpn.example",
            "https://user@vpn.example",
            "https://vpn.example/#x",
            "https://",
        ] {
            let mut bad = request();
            bad.offer.control_url = url.into();
            assert_eq!(publish(None, &address(1), 10, bad), Err(Error::Offer));
        }
        let mut bad = request();
        bad.offer.wireguard_key_hex = "00".repeat(32);
        assert_eq!(publish(None, &address(1), 10, bad), Err(Error::Offer));
        let first = publish(None, &address(1), 10, request()).unwrap();
        assert_eq!(retire(&first, &address(1), 9, 1), Err(Error::Epoch));
        assert!(!valid_address(&format!("oct{}", "z".repeat(44))));
    }
    #[test]
    fn native_circle_id_is_not_decoded_as_a_wallet_address() {
        let circle = "octJfWXtvbohUBeXcvDAWJQ71Pog5ueFWDrzqgnn6x1yPeJ";
        assert!(!valid_address(circle));
        assert!(valid_circle_id(circle));
        let mut offer = request().offer;
        offer.settlement_circle = circle.into();
        offer.validate().unwrap();
        assert!(!valid_circle_id(&format!("oct{}", "0".repeat(44))));
    }
    #[test]
    fn revision_overflow_and_unrecognized_request_fields_are_rejected() {
        let mut first = publish(None, &address(1), 10, request()).unwrap();
        first.revision = u64::MAX;
        assert_eq!(
            retire(&first, &address(1), 11, u64::MAX),
            Err(Error::RevisionExhausted)
        );
        let mut json = serde_json::to_value(request()).unwrap();
        json["caller"] = serde_json::json!(address(3));
        assert!(serde_json::from_value::<PublishRequest>(json).is_err());
    }
}
