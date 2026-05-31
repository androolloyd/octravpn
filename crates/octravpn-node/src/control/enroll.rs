//! Wallet-native enrollment service + its storage seam.
//!
//! The HTTP handler ([`super::handlers::enroll`]) is a thin axum wrapper;
//! the actual logic lives in [`EnrollService`] so it is unit-testable
//! without a server or a chain. The service is storage-agnostic — it
//! talks to the circle-resident member set + allowlist through the
//! [`EnrollStore`] trait. Production uses a circle-backed impl (reads
//! sealed assets, re-anchors `circle_state_root` — wired in a later
//! stage); tests use [`InMemoryEnrollStore`].
//!
//! Flow (see [`octravpn_core::enroll`] for the wire types):
//!
//! 1. `issue_challenge(wallet)` → a single-use nonce bound to `(wallet,
//!    expiry)`, cached in a TTL map.
//! 2. `enroll(req)` → verify the wallet signature, consume the nonce,
//!    check the wallet is on the operator's allowlist, append a
//!    [`Member`] to the tailnet's member set, persist + re-anchor, and
//!    return the device's deterministic IP + the current peer set.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use octravpn_core::{
    bounded::BoundedMap,
    enroll::{
        EnrollChallenge, EnrollPeer, EnrollRequest, EnrollResponse, CHALLENGE_TTL_SECS, NONCE_LEN,
    },
    v3_members::{Member, TailnetMembers},
};
use octravpn_mesh::ip_alloc::TailnetIpAllocator;
use rand::RngCore;

/// Failure modes of an enrollment attempt. The handler maps these to
/// HTTP status codes; keeping them as a typed enum (rather than strings)
/// means the status mapping lives in one place and the service stays
/// transport-agnostic.
#[derive(Debug, thiserror::Error)]
pub(crate) enum EnrollError {
    #[error("bad wallet signature")]
    BadSignature,
    #[error("request targets tailnet {got}, this operator serves {want}")]
    WrongTailnet { want: u64, got: u64 },
    #[error("request targets circle {got:?}, this operator serves {want:?}")]
    WrongCircle { want: String, got: String },
    #[error("unknown or expired challenge nonce")]
    StaleNonce,
    #[error("nonce was issued for a different wallet")]
    NonceWalletMismatch,
    #[error("wallet {0} is not on the tailnet allowlist")]
    NotAuthorized(String),
    #[error("member set rejected the new entry: {0}")]
    Members(#[from] octravpn_core::v3_members::V3MembersError),
    #[error("enrollment store unavailable: {0}")]
    Store(String),
}

/// Owner-maintained set of wallet addresses permitted to enroll into a
/// tailnet. Sealed at `oct://<circle>/auth/allowed.json`. The allowlist
/// is the authorization layer: a device may prove possession of any
/// wallet, but only listed wallets are admitted. Maintained out-of-band
/// by the tailnet owner (`octravpn-node auth allow/revoke`).
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub(crate) struct AllowList {
    /// Authorized `oct…` wallet addresses.
    pub wallets: Vec<String>,
}

impl AllowList {
    pub(crate) fn contains(&self, wallet: &str) -> bool {
        self.wallets.iter().any(|w| w == wallet)
    }
}

/// What the enroll flow reads from the store in one shot — the admission
/// allowlist + the current member set. The circle-backed impl fetches the
/// `circle_state_root` anchor *once* to produce both.
pub(crate) struct EnrollState {
    pub allowlist: AllowList,
    pub members: TailnetMembers,
}

/// Persistence seam for the enrollment service. The circle-backed impl
/// reads/writes sealed assets in the operator circle and re-anchors
/// `circle_state_root`; [`InMemoryEnrollStore`] backs the tests.
#[async_trait]
pub(crate) trait EnrollStore: Send + Sync {
    /// Load the allowlist + member set for `tailnet_id` together — a
    /// single on-chain anchor fetch for the circle-backed impl.
    async fn load_enroll_state(&self, tailnet_id: u64) -> Result<EnrollState, EnrollError>;

    /// Persist `members` — re-seal `members.json` and re-anchor
    /// `circle_state_root` — and return the new monotonic version.
    async fn commit_members(
        &self,
        tailnet_id: u64,
        members: &TailnetMembers,
    ) -> Result<u64, EnrollError>;
}

/// Per-nonce metadata held in the challenge cache while a device signs.
#[derive(Clone, Debug)]
struct Challenge {
    wallet: String,
    expires_at: u64,
}

/// The wallet-native enrollment service for a single tailnet/circle this
/// operator hosts. Cheap to clone (everything behind `Arc`).
#[derive(Clone)]
pub(crate) struct EnrollService {
    tailnet_id: u64,
    circle: String,
    store: Arc<dyn EnrollStore>,
    /// Single-use, TTL-expiring nonce cache keyed by the hex nonce.
    challenges: Arc<BoundedMap<String, Challenge>>,
}

impl EnrollService {
    #[allow(dead_code)] // wired by the Hub when an operator hosts a tailnet
    pub(crate) fn new(tailnet_id: u64, circle: impl Into<String>, store: Arc<dyn EnrollStore>) -> Self {
        Self {
            tailnet_id,
            circle: circle.into(),
            store,
            challenges: Arc::new(BoundedMap::new(
                4096,
                Duration::from_secs(CHALLENGE_TTL_SECS + 5),
            )),
        }
    }

    /// Mint a single-use challenge nonce bound to `wallet`, valid for
    /// [`CHALLENGE_TTL_SECS`]. `now` is injected (wall-clock seconds) so
    /// the service is deterministic under test.
    pub(crate) fn issue_challenge(&self, wallet: &str, now: u64) -> EnrollChallenge {
        let mut raw = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut raw);
        let nonce = hex::encode(raw);
        let expires_at = now + CHALLENGE_TTL_SECS;
        self.challenges.insert(
            nonce.clone(),
            Challenge {
                wallet: wallet.to_string(),
                expires_at,
            },
        );
        EnrollChallenge {
            tailnet_id: self.tailnet_id,
            circle: self.circle.clone(),
            nonce,
            issued_at: now,
            expires_at,
        }
    }

    /// Verify + admit an enrollment request. Returns the device's IP and
    /// the current peer set on success.
    pub(crate) async fn enroll(
        &self,
        req: &EnrollRequest,
        now: u64,
    ) -> Result<EnrollResponse, EnrollError> {
        // 1. Possession of the wallet key (binds wallet ↔ wg key ↔
        //    tailnet ↔ circle ↔ nonce).
        req.verify_signature().map_err(|_| EnrollError::BadSignature)?;

        // 2. This operator actually serves the named tailnet/circle.
        if req.tailnet_id != self.tailnet_id {
            return Err(EnrollError::WrongTailnet {
                want: self.tailnet_id,
                got: req.tailnet_id,
            });
        }
        if req.circle != self.circle {
            return Err(EnrollError::WrongCircle {
                want: self.circle.clone(),
                got: req.circle.clone(),
            });
        }

        // 3. Consume the single-use nonce (replay guard). `remove`
        //    makes it one-shot; the TTL map also drops stale entries.
        let challenge = self.challenges.remove(&req.nonce).ok_or(EnrollError::StaleNonce)?;
        if now > challenge.expires_at {
            return Err(EnrollError::StaleNonce);
        }

        // 4. The admitted identity is derived from the key, never
        //    asserted. The nonce was issued for this wallet.
        let wallet = req.wallet_address();
        if challenge.wallet != wallet {
            return Err(EnrollError::NonceWalletMismatch);
        }

        // 5. One anchor fetch: the owner's allowlist + the current member
        //    set (the circle store reads both under a single state-root).
        let state = self.store.load_enroll_state(self.tailnet_id).await?;
        if !state.allowlist.contains(&wallet) {
            return Err(EnrollError::NotAuthorized(wallet));
        }

        // 6. Read-modify-write the member set: replace this wallet's
        //    entry if it is re-enrolling a new device key, else append.
        let mut members = state.members;
        let wg_pubkey_b64 = octravpn_core::b64::encode(req.device_wg_pubkey);
        let entry = Member {
            wallet: wallet.clone(),
            wg_pubkey_b64,
            joined_epoch: now,
        };
        match members.members.iter_mut().find(|m| m.wallet == wallet) {
            Some(existing) => *existing = entry,
            None => members.members.push(entry),
        }
        // Catch a malformed set (bad wg key, dup, …) before we anchor it.
        members.validate()?;

        // 7. Persist + re-anchor.
        let version = self.store.commit_members(self.tailnet_id, &members).await?;

        // 8. Build the response: the device's deterministic IP + every
        //    *other* member as a reachable peer.
        let allocator = TailnetIpAllocator::with_salt(
            self.tailnet_id.to_string(),
            salt_u32(&members.ip_salt),
        );
        let assigned_ip = allocator.allocate(&wallet).to_string();
        let peers = members
            .members
            .iter()
            .filter(|m| m.wallet != wallet)
            .map(|m| EnrollPeer {
                wallet: m.wallet.clone(),
                wg_pubkey_b64: m.wg_pubkey_b64.clone(),
                ip: allocator.allocate(&m.wallet).to_string(),
            })
            .collect();

        Ok(EnrollResponse {
            admitted: true,
            assigned_ip,
            members_version: version,
            peers,
        })
    }
}

/// Derive the `TailnetIpAllocator`'s `u32` salt from the member set's
/// 64-hex `ip_salt`, so the IP a device is told matches what every other
/// member derives. Takes the leading 8 hex chars; falls back to 0 for a
/// malformed/short salt (the allocator stays deterministic either way).
fn salt_u32(ip_salt_hex: &str) -> u32 {
    u32::from_str_radix(ip_salt_hex.get(..8).unwrap_or("0"), 16).unwrap_or(0)
}

/// In-memory [`EnrollStore`] for tests + offline dev. Holds the member
/// set + allowlist per tailnet behind a mutex and bumps a version
/// counter on each commit.
#[allow(dead_code)] // test/dev EnrollStore; CircleEnrollStore is the prod impl
pub(crate) struct InMemoryEnrollStore {
    ip_salt: String,
    members: Mutex<HashMap<u64, TailnetMembers>>,
    allowed: Mutex<HashMap<u64, HashSet<String>>>,
    version: Mutex<HashMap<u64, u64>>,
}

#[allow(dead_code)] // test/dev helpers
impl InMemoryEnrollStore {
    /// `ip_salt` is the 64-hex salt the empty member set is seeded with.
    pub(crate) fn new(ip_salt: impl Into<String>) -> Self {
        Self {
            ip_salt: ip_salt.into(),
            members: Mutex::new(HashMap::new()),
            allowed: Mutex::new(HashMap::new()),
            version: Mutex::new(HashMap::new()),
        }
    }

    /// Seed the owner allowlist for a tailnet (test/dev convenience).
    pub(crate) fn allow(&self, tailnet_id: u64, wallet: impl Into<String>) {
        self.allowed
            .lock()
            .unwrap()
            .entry(tailnet_id)
            .or_default()
            .insert(wallet.into());
    }
}

#[async_trait]
impl EnrollStore for InMemoryEnrollStore {
    async fn load_enroll_state(&self, tailnet_id: u64) -> Result<EnrollState, EnrollError> {
        let mut wallets: Vec<String> = self
            .allowed
            .lock()
            .unwrap()
            .get(&tailnet_id)
            .map(|s| s.iter().cloned().collect())
            .unwrap_or_default();
        wallets.sort();
        let members = self
            .members
            .lock()
            .unwrap()
            .get(&tailnet_id)
            .cloned()
            .unwrap_or_else(|| TailnetMembers::new_v1(tailnet_id, self.ip_salt.clone(), vec![], 0, 0));
        Ok(EnrollState {
            allowlist: AllowList { wallets },
            members,
        })
    }

    async fn commit_members(
        &self,
        tailnet_id: u64,
        members: &TailnetMembers,
    ) -> Result<u64, EnrollError> {
        self.members.lock().unwrap().insert(tailnet_id, members.clone());
        let mut v = self.version.lock().unwrap();
        let next = v.get(&tailnet_id).copied().unwrap_or(0) + 1;
        v.insert(tailnet_id, next);
        Ok(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{enroll::enroll_signing_payload, sig::KeyPair};
    use std::net::Ipv4Addr;

    const SALT: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    fn service_with_allow(tailnet_id: u64, circle: &str, wallet: &str) -> (EnrollService, Arc<InMemoryEnrollStore>) {
        let store = Arc::new(InMemoryEnrollStore::new(SALT));
        store.allow(tailnet_id, wallet);
        let svc = EnrollService::new(tailnet_id, circle, store.clone());
        (svc, store)
    }

    fn signed_request(kp: &KeyPair, tailnet_id: u64, circle: &str, nonce: &str) -> EnrollRequest {
        let device_wg_pubkey = [9u8; 32];
        let wallet_sig = kp.sign(&enroll_signing_payload(
            tailnet_id,
            circle,
            &kp.public,
            &device_wg_pubkey,
            nonce,
        ));
        EnrollRequest {
            tailnet_id,
            circle: circle.to_string(),
            wallet_pubkey: kp.public,
            device_wg_pubkey,
            device_name: "laptop".to_string(),
            nonce: nonce.to_string(),
            wallet_sig,
        }
    }

    #[tokio::test]
    async fn happy_path_admits_and_returns_ip() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        let (svc, store) = service_with_allow(7, "octCircle", &wallet);

        let ch = svc.issue_challenge(&wallet, 1000);
        let req = signed_request(&kp, 7, "octCircle", &ch.nonce);
        let resp = svc.enroll(&req, 1001).await.expect("admitted");

        assert!(resp.admitted);
        assert!(resp.assigned_ip.parse::<Ipv4Addr>().is_ok());
        assert_eq!(resp.members_version, 1);
        // The member set now holds exactly this wallet.
        let members = store.load_enroll_state(7).await.unwrap().members;
        assert_eq!(members.members.len(), 1);
        assert_eq!(members.members[0].wallet, wallet);
    }

    #[tokio::test]
    async fn unauthorized_wallet_is_rejected() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        // Service whose allowlist does NOT contain this wallet.
        let store = Arc::new(InMemoryEnrollStore::new(SALT));
        let svc = EnrollService::new(7, "octCircle", store.clone());

        let ch = svc.issue_challenge(&wallet, 1000);
        let req = signed_request(&kp, 7, "octCircle", &ch.nonce);
        let err = svc.enroll(&req, 1001).await.unwrap_err();
        assert!(matches!(err, EnrollError::NotAuthorized(_)));
        assert_eq!(
            store.load_enroll_state(7).await.unwrap().members.members.len(),
            0
        );
    }

    #[tokio::test]
    async fn nonce_is_single_use() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        let (svc, _store) = service_with_allow(7, "octCircle", &wallet);

        let ch = svc.issue_challenge(&wallet, 1000);
        let req = signed_request(&kp, 7, "octCircle", &ch.nonce);
        svc.enroll(&req, 1001).await.expect("first use ok");
        // Replaying the same nonce must fail — it was consumed.
        let err = svc.enroll(&req, 1002).await.unwrap_err();
        assert!(matches!(err, EnrollError::StaleNonce));
    }

    #[tokio::test]
    async fn forged_request_without_challenge_is_rejected() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        let (svc, _store) = service_with_allow(7, "octCircle", &wallet);
        // A validly-signed request, but for a nonce the service never issued.
        let req = signed_request(&kp, 7, "octCircle", "never-issued");
        let err = svc.enroll(&req, 1001).await.unwrap_err();
        assert!(matches!(err, EnrollError::StaleNonce));
    }

    #[tokio::test]
    async fn wrong_tailnet_is_rejected() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        let (svc, _store) = service_with_allow(7, "octCircle", &wallet);
        let ch = svc.issue_challenge(&wallet, 1000);
        // Sign + send for tailnet 9 against a service serving tailnet 7.
        let req = signed_request(&kp, 9, "octCircle", &ch.nonce);
        let err = svc.enroll(&req, 1001).await.unwrap_err();
        assert!(matches!(err, EnrollError::WrongTailnet { want: 7, got: 9 }));
    }

    #[tokio::test]
    async fn re_enroll_replaces_device_key_not_duplicates() {
        let kp = KeyPair::generate();
        let wallet = octravpn_core::Address::from_pubkey(&kp.public.0).display().to_string();
        let (svc, store) = service_with_allow(7, "octCircle", &wallet);

        let ch1 = svc.issue_challenge(&wallet, 1000);
        svc.enroll(&signed_request(&kp, 7, "octCircle", &ch1.nonce), 1001)
            .await
            .unwrap();
        let ch2 = svc.issue_challenge(&wallet, 2000);
        let v2 = svc
            .enroll(&signed_request(&kp, 7, "octCircle", &ch2.nonce), 2001)
            .await
            .unwrap();

        // Same wallet, two enrollments → one member, version bumped.
        assert_eq!(v2.members_version, 2);
        assert_eq!(
            store.load_enroll_state(7).await.unwrap().members.members.len(),
            1
        );
    }
}
