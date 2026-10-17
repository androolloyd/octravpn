//! Real signed control messages and durable meters; only canonical host state
//! and the final kernel handoff are explicit fixtures. No public-chain or TUN
//! qualification is inferred from this in-process control-plane coverage.
use super::super::{Grant, Guard};
use super::*;
use crate::payment_meter::Credit;
use axum::{
    body::{to_bytes, Body},
    http::{Method, Request},
};
use octravpn_core::{
    payments::{
        Connect, Deployment, Direction, IpPrefix, PlanBinding, Protocol, Selector, Tariff,
        TrafficClass, Usage, BYTES_PER_MIB,
    },
    Address,
};
use parking_lot::{Mutex, RwLock};
use serde::{de::DeserializeOwned, Serialize};
use std::{
    io,
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tower::ServiceExt as _;

/// Revocation has the same synchronous publication boundary required of the
/// native host: a revoked guard cannot begin another handoff.
struct HostGuard {
    publication: RwLock<()>,
    revoked: AtomicBool,
}
impl HostGuard {
    fn new() -> Self {
        Self {
            publication: RwLock::new(()),
            revoked: AtomicBool::new(false),
        }
    }
    fn revoke(&self) {
        let _publication = self.publication.write();
        self.revoked.store(true, Ordering::Release);
    }
}
impl Guard for HostGuard {
    fn live(&self) -> bool {
        !self.revoked.load(Ordering::Acquire)
    }
    fn current(&self, action: &mut dyn FnMut() -> Result<()>) -> Result<()> {
        let _publication = self.publication.read();
        ensure!(self.live(), "fixture canonical state revoked");
        action()
    }
}

#[derive(Clone)]
struct CanonicalPlan {
    binding: PlanBinding,
    receipt_key: octravpn_core::PublicKey,
    tariff: Tariff,
    original_budget_ou: u64,
    remaining_ou: u64,
    redeemed_totals: Vec<u64>,
    canonical_ms: u64,
    claim_deadline_ms: u64,
    admissible: bool,
    guard: Arc<HostGuard>,
}
struct Host(RwLock<CanonicalPlan>);
#[async_trait::async_trait]
impl Authority for Host {
    async fn plan(&self, binding: &PlanBinding) -> Result<Grant> {
        let plan = self.0.read().clone();
        ensure!(&plan.binding == binding, "fixture plan is not canonical");
        Ok(Grant {
            binding: plan.binding,
            receipt_key: plan.receipt_key,
            tariff: plan.tariff,
            original_budget_ou: plan.original_budget_ou,
            remaining_ou: plan.remaining_ou,
            redeemed_totals: plan.redeemed_totals,
            canonical_ms: plan.canonical_ms,
            claim_deadline_ms: Some(plan.claim_deadline_ms),
            admissible: plan.admissible,
            guard: plan.guard,
        })
    }
}

/// Success represents an exact cumulative claim already reflected in the
/// fixture's canonical model; merely queuing a request never returns success.
struct CanonicalSettlement {
    host: Arc<Host>,
    fail: AtomicBool,
    attempts: AtomicUsize,
    accepted: Mutex<Vec<SignedUsage>>,
}
#[async_trait::async_trait]
impl Settlement for CanonicalSettlement {
    async fn confirm(&self, usage: SignedUsage) -> Result<()> {
        self.attempts.fetch_add(1, Ordering::AcqRel);
        ensure!(
            !self.fail.load(Ordering::Acquire),
            "fixture canonical commit unavailable"
        );
        usage.verify()?;
        let mut plan = self.host.0.write();
        ensure!(
            usage.usage.binding() == plan.binding,
            "fixture claim deployment differs"
        );
        ensure!(
            usage.receipt_key == plan.receipt_key,
            "fixture claim receipt key differs"
        );
        ensure!(
            plan.canonical_ms < plan.claim_deadline_ms,
            "fixture claim deadline elapsed"
        );
        let class = usize::from(usage.usage.traffic_class);
        let floor = *plan
            .redeemed_totals
            .get(class)
            .context("fixture unknown class")?;
        ensure!(usage.usage.total_bytes >= floor, "fixture claim regressed");
        let mut accepted = self.accepted.lock();
        if let Some(previous) = accepted
            .iter()
            .rev()
            .find(|previous| previous.usage.traffic_class == usage.usage.traffic_class)
        {
            if previous == &usage {
                return Ok(());
            }
            ensure!(
                usage.usage.sequence > previous.usage.sequence,
                "fixture claim replay"
            );
        }
        let mut redeemed = plan.redeemed_totals.clone();
        redeemed[class] = usage.usage.total_bytes;
        let charge = plan.tariff.total_charge(&redeemed)?;
        ensure!(
            charge <= plan.original_budget_ou,
            "fixture claim exceeds original budget"
        );
        plan.remaining_ou = plan.original_budget_ou - charge;
        plan.redeemed_totals = redeemed;
        accepted.push(usage);
        Ok(())
    }
}

struct Fixture {
    _root: tempfile::TempDir,
    path: PathBuf,
    payer: Arc<KeyPair>,
    operator: Arc<KeyPair>,
    host: Arc<Host>,
    settlement: Arc<CanonicalSettlement>,
    credit: Credit,
}
impl Fixture {
    fn new(credit_bytes: u64) -> Self {
        let root = tempfile::tempdir().unwrap();
        let payer = Arc::new(KeyPair::from_secret_bytes(&[5; 32]));
        let operator = Arc::new(KeyPair::from_secret_bytes(&[6; 32]));
        let tariff = Tariff::new(
            Address::from_pubkey(&operator.public.0),
            vec![
                TrafficClass {
                    name: "default".into(),
                    rate_ou_per_mib: BYTES_PER_MIB,
                },
                TrafficClass {
                    name: "premium".into(),
                    rate_ou_per_mib: 2 * BYTES_PER_MIB,
                },
            ],
            vec![Selector {
                prefix: IpPrefix::new(Ipv4Addr::new(8, 8, 8, 8).into(), 32).unwrap(),
                protocol: Protocol::Udp,
                port: Some(53),
                traffic_class: 1,
            }],
        )
        .unwrap();
        let binding = PlanBinding {
            deployment: Deployment {
                domain: "a".repeat(64),
                program: Address::from_pubkey(&[1; 32]),
            },
            payer: Address::from_pubkey(&payer.public.0),
            generation: 1,
            plan: 7,
            offer: 9,
            manifest_hash: tariff.hash_hex().unwrap(),
        };
        let host = Arc::new(Host(RwLock::new(CanonicalPlan {
            binding,
            receipt_key: payer.public,
            tariff,
            original_budget_ou: 10_000,
            remaining_ou: 10_000,
            redeemed_totals: vec![0, 0],
            canonical_ms: 1_000,
            claim_deadline_ms: 86_401_000,
            admissible: true,
            guard: Arc::new(HostGuard::new()),
        })));
        let settlement = Arc::new(CanonicalSettlement {
            host: host.clone(),
            fail: AtomicBool::new(false),
            attempts: AtomicUsize::new(0),
            accepted: Mutex::new(Vec::new()),
        });
        Self {
            path: root.path().join("paid"),
            _root: root,
            payer,
            operator,
            host,
            settlement,
            credit: Credit {
                max_unacknowledged_bytes: credit_bytes,
                max_unacknowledged_ou: credit_bytes * 2,
            },
        }
    }
    fn start(&self) -> Arc<Control> {
        self.start_with_authority(self.host.clone())
    }
    fn start_with_authority(&self, authority: Arc<dyn Authority>) -> Arc<Control> {
        let wireguard = [42; 32];
        let identity =
            serde_json::to_vec(&(1_u8, self.operator.public, wireguard, self.credit)).unwrap();
        let writer = open_directory(&self.path, &identity).unwrap();
        Arc::new(Control {
            registry: Arc::new(Registry::new(
                self.path.clone(),
                authority,
                Arc::new(writer),
                self.credit,
            )),
            settlement: self.settlement.clone(),
            operator: self.operator.clone(),
            wireguard,
            slots: Arc::new(Semaphore::new(32)),
        })
    }
    fn connect(&self, sequence: u64, wireguard_key: [u8; 32]) -> SignedConnect {
        SignedConnect::sign(
            Connect {
                binding: self.host.0.read().binding.clone(),
                sequence,
                wireguard_key,
            },
            &self.payer,
        )
        .unwrap()
    }
    fn usage(&self, class: u8, sequence: u64, bytes: u64) -> SignedUsage {
        SignedUsage::sign(
            Usage::from_binding(self.host.0.read().binding.clone(), class, sequence, bytes)
                .unwrap(),
            &self.payer,
        )
        .unwrap()
    }
}

struct PublishingHost {
    plans: RwLock<Vec<CanonicalPlan>>,
    unavailable: AtomicBool,
}
#[async_trait::async_trait]
impl Authority for PublishingHost {
    async fn plan(&self, binding: &PlanBinding) -> Result<Grant> {
        ensure!(
            !self.unavailable.load(Ordering::Acquire),
            "fixture publishing canonical state"
        );
        let plan = self
            .plans
            .read()
            .iter()
            .find(|plan| &plan.binding == binding)
            .cloned()
            .context("fixture unknown canonical plan")?;
        Ok(Grant {
            binding: plan.binding,
            receipt_key: plan.receipt_key,
            tariff: plan.tariff,
            original_budget_ou: plan.original_budget_ou,
            remaining_ou: plan.remaining_ou,
            redeemed_totals: plan.redeemed_totals,
            canonical_ms: plan.canonical_ms,
            claim_deadline_ms: Some(plan.claim_deadline_ms),
            admissible: plan.admissible,
            guard: plan.guard,
        })
    }
}

#[tokio::test]
async fn unrelated_status_poll_preserves_suspended_connection_across_publication() {
    let fixture = Fixture::new(256);
    let first_plan = fixture.host.0.read().clone();
    let mut second_plan = first_plan.clone();
    second_plan.binding.plan += 1;
    second_plan.guard = Arc::new(HostGuard::new());
    let first = fixture.connect(1, [11; 32]);
    let second = SignedConnect::sign(
        Connect {
            binding: second_plan.binding.clone(),
            sequence: 1,
            wireguard_key: [12; 32],
        },
        &fixture.payer,
    )
    .unwrap();
    let host = Arc::new(PublishingHost {
        plans: RwLock::new(vec![first_plan, second_plan]),
        unavailable: AtomicBool::new(false),
    });
    let control = fixture.start_with_authority(host.clone());
    let first_connection = connected(&control, &first).await;
    let second_connection = connected(&control, &second).await;
    host.unavailable.store(true, Ordering::Release);
    for plan in &*host.plans.read() {
        plan.guard.revoke();
    }
    control.registry.refresh().await;
    assert!(!first_connection.live());
    assert!(!second_connection.live());
    assert!(Arc::ptr_eq(
        &control.registry.get(&[11; 32]).unwrap(),
        &first_connection
    ));
    assert!(Arc::ptr_eq(
        &control.registry.get(&[12; 32]).unwrap(),
        &second_connection
    ));
    assert_eq!(
        post(&control, "/payments/status", &first).await.0,
        StatusCode::FORBIDDEN
    );
    // The new tree is visible, but refresh has not updated the existing Arcs.
    for plan in &mut *host.plans.write() {
        plan.guard = Arc::new(HostGuard::new());
        plan.canonical_ms += 1;
    }
    host.unavailable.store(false, Ordering::Release);
    let status: SignedStatus = decode(&post(&control, "/payments/status", &first).await);
    status.verify().unwrap();
    assert!(Arc::ptr_eq(
        &control.registry.get(&[11; 32]).unwrap(),
        &first_connection
    ));
    assert!(Arc::ptr_eq(
        &control.registry.get(&[12; 32]).unwrap(),
        &second_connection
    ));
    assert!(
        !second_connection.live(),
        "unrelated poll does not grant admission"
    );
    control.registry.refresh().await;
    assert!(Arc::ptr_eq(
        &control.registry.get(&[11; 32]).unwrap(),
        &first_connection
    ));
    assert!(Arc::ptr_eq(
        &control.registry.get(&[12; 32]).unwrap(),
        &second_connection
    ));
    assert!(first_connection.live());
    assert!(second_connection.live());
    let mut sent = false;
    second_connection
        .current(&mut || {
            sent = true;
            Ok(())
        })
        .unwrap();
    assert!(sent);
}

#[tokio::test]
async fn revoked_lease_suspends_but_authenticated_exit_retires_connection() {
    let fixture = Fixture::new(256);
    let control = fixture.start();
    let connect = fixture.connect(1, [11; 32]);
    let connection = connected(&control, &connect).await;
    fixture.host.0.read().guard.revoke();
    control.registry.refresh().await;
    assert!(!connection.live());
    assert!(Arc::ptr_eq(
        &control.registry.get(&[11; 32]).unwrap(),
        &connection
    ));
    fixture.host.0.write().guard = Arc::new(HostGuard::new());
    control.registry.refresh().await;
    assert!(connection.live());
    fixture.host.0.write().admissible = false;
    control.registry.refresh().await;
    assert!(!connection.live());
    assert!(control.registry.get(&[11; 32]).is_none());
}

#[tokio::test]
async fn restarted_exiting_plan_recovers_receipts_without_transport_admission() {
    let fixture = Fixture::new(64);
    let connect = fixture.connect(1, [11; 32]);
    let usage = fixture.usage(0, 1, 64);
    {
        let control = fixture.start();
        let connection = connected(&control, &connect).await;
        forward(&connection, &packet(false, false, 36), Direction::Outbound).await;
    }
    fixture.host.0.write().admissible = false;
    fixture.host.0.read().guard.revoke();
    let control = fixture.start();
    assert!(control.registry.connections.read().is_empty());
    assert!(control.registry.meters.read().is_empty());
    assert_eq!(
        post(&control, "/payments/connect", &connect).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        fixture.settlement.attempts.load(Ordering::Acquire),
        0,
        "revoked leases cannot recover claims"
    );
    fixture.host.0.write().guard = Arc::new(HostGuard::new());
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::OK
    );
    let session = usage.usage.binding().session_id().unwrap();
    let recovered = control
        .registry
        .meters
        .read()
        .get(&session)
        .cloned()
        .unwrap();
    assert_eq!(recovered.snapshot().unwrap().committed_totals, [64, 0]);
    assert_eq!(recovered.authorizations().unwrap(), [usage.clone()]);
    assert_eq!(fixture.host.0.read().redeemed_totals, [64, 0]);
    assert!(
        control.registry.connections.read().is_empty(),
        "receipt recovery creates no tunnel capability"
    );
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::OK
    );
    assert!(Arc::ptr_eq(
        &control.registry.meters.read().get(&session).unwrap(),
        &recovered
    ));
    assert_eq!(
        post(&control, "/payments/connect", &connect).await.0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn missing_delivery_journal_never_creates_claim_history_or_admission() {
    let fixture = Fixture::new(64);
    fixture.host.0.write().admissible = false;
    let usage = fixture.usage(0, 1, 64);
    let plan_path = fixture
        .path
        .join(usage.usage.binding().session_id().unwrap().to_hex());
    let control = fixture.start();
    assert!(!plan_path.exists());
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(
        !plan_path.exists(),
        "claim recovery must not invent delivery history"
    );
    assert!(control.registry.meters.read().is_empty());
    assert!(control.registry.connections.read().is_empty());
    assert_eq!(fixture.settlement.attempts.load(Ordering::Acquire), 0);
}

async fn request(
    control: &Arc<Control>,
    method: Method,
    path: &str,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let response = router(control.clone())
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header("content-type", "application/json")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    (
        status,
        to_bytes(response.into_body(), 262_144)
            .await
            .unwrap()
            .to_vec(),
    )
}
async fn post<T: Serialize>(
    control: &Arc<Control>,
    path: &str,
    value: &T,
) -> (StatusCode, Vec<u8>) {
    request(
        control,
        Method::POST,
        path,
        serde_json::to_vec(value).unwrap(),
    )
    .await
}
fn decode<T: DeserializeOwned>(response: &(StatusCode, Vec<u8>)) -> T {
    assert_eq!(
        response.0,
        StatusCode::OK,
        "{}",
        String::from_utf8_lossy(&response.1)
    );
    serde_json::from_slice(&response.1).unwrap()
}
async fn connected(control: &Arc<Control>, connect: &SignedConnect) -> Arc<Connection> {
    let signed: SignedStatus = decode(&post(control, "/payments/connect", connect).await);
    signed.verify().unwrap();
    control
        .registry
        .get(&connect.request.wireguard_key)
        .unwrap()
}

fn packet(premium: bool, inbound: bool, payload: usize) -> Vec<u8> {
    let remote = if premium { [8, 8, 8, 8] } else { [1, 1, 1, 1] };
    let local = [198, 18, 0, 2];
    let mut packet = vec![0; 28 + payload];
    let length = u16::try_from(packet.len()).unwrap();
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&length.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    let (source, destination, source_port, destination_port) = if inbound {
        (remote, local, 53_u16, 40_000_u16)
    } else {
        (local, remote, 40_000_u16, 53_u16)
    };
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet[20..22].copy_from_slice(&source_port.to_be_bytes());
    packet[22..24].copy_from_slice(&destination_port.to_be_bytes());
    packet[24..26].copy_from_slice(&(length - 20).to_be_bytes());
    let mut sum = packet[..20]
        .chunks_exact(2)
        .map(|word| u32::from(u16::from_be_bytes([word[0], word[1]])))
        .sum::<u32>();
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!(sum as u16)).to_be_bytes());
    packet
}
async fn forward(connection: &Connection, bytes: &[u8], direction: Direction) {
    let ticket = connection.meter.reserve(bytes, direction).await.unwrap();
    connection
        .handoff(ticket, bytes.len(), || Ok(bytes.len()))
        .await
        .unwrap();
}

#[tokio::test]
async fn signed_status_binds_exact_plan_tariff_keys_sequence_and_counters() {
    let fixture = Fixture::new(256);
    let control = fixture.start();
    let connect = fixture.connect(1, [11; 32]);
    let status: SignedStatus = decode(&post(&control, "/payments/connect", &connect).await);
    status.verify().unwrap();
    assert_eq!(status.operator_key, fixture.operator.public);
    assert_eq!(status.status.binding, connect.request.binding);
    assert_eq!(status.status.connect_sequence, 1);
    assert_eq!(status.status.client_wireguard_key, [11; 32]);
    assert_eq!(status.status.server_wireguard_key, [42; 32]);
    assert_eq!(status.status.tariff, fixture.host.0.read().tariff);
    assert_eq!(status.status.original_budget_ou, 10_000);
    assert_eq!(status.status.committed_totals, [0, 0]);
    assert_eq!(status.status.redeemed_totals, [0, 0]);
    assert_eq!(status.status.canonical_ms, 1_000);
    assert_eq!(status.status.claim_deadline_ms, 86_401_000);
    let connection = control.registry.get(&[11; 32]).unwrap();
    let outgoing = packet(true, false, 4);
    let incoming = packet(true, true, 6);
    forward(&connection, &outgoing, Direction::Outbound).await;
    forward(&connection, &incoming, Direction::Inbound).await;
    let status: SignedStatus = decode(&post(&control, "/payments/status", &connect).await);
    status.verify().unwrap();
    assert_eq!(
        status.status.committed_totals,
        [0, (outgoing.len() + incoming.len()) as u64]
    );
    let mut tampered = status;
    tampered.status.connect_sequence += 1;
    assert!(tampered.verify().is_err());
}

#[tokio::test]
async fn paid_router_has_no_legacy_admission_or_proxy_routes_and_bounds_input() {
    let fixture = Fixture::new(256);
    let control = fixture.start();
    for path in [
        "/announce",
        "/announce_session",
        "/receipt",
        "/receipts",
        "/session",
        "/proxy",
        "/mesh/join",
        "/admin/preauth",
        "/health",
    ] {
        assert_eq!(
            request(&control, Method::POST, path, b"{}".to_vec())
                .await
                .0,
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
    assert_eq!(
        request(&control, Method::GET, "/payments/connect", Vec::new())
            .await
            .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        request(
            &control,
            Method::POST,
            "/payments/connect",
            vec![b'x'; 131_073]
        )
        .await
        .0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    assert_eq!(
        request(
            &control,
            Method::POST,
            "/payments/connect",
            b"null".to_vec()
        )
        .await
        .0,
        StatusCode::UNPROCESSABLE_ENTITY
    );
}

#[tokio::test]
async fn invalid_signatures_keys_bindings_and_sequence_replays_never_revoke_current_connection() {
    let fixture = Fixture::new(256);
    let control = fixture.start();
    let request = fixture.connect(7, [11; 32]);
    let connection = connected(&control, &request).await;
    let mut invalid = fixture.connect(8, [12; 32]);
    invalid.signature.0[0] ^= 1;
    assert_eq!(
        post(&control, "/payments/connect", &invalid).await.0,
        StatusCode::FORBIDDEN
    );
    let wrong = KeyPair::from_secret_bytes(&[9; 32]);
    let invalid = SignedConnect::sign(fixture.connect(8, [12; 32]).request, &wrong).unwrap();
    assert_eq!(
        post(&control, "/payments/connect", &invalid).await.0,
        StatusCode::FORBIDDEN
    );
    let mut invalid = fixture.connect(8, [12; 32]).request;
    invalid.binding.generation += 1;
    let invalid = SignedConnect::sign(invalid, &fixture.payer).unwrap();
    assert_eq!(
        post(&control, "/payments/connect", &invalid).await.0,
        StatusCode::FORBIDDEN
    );
    for invalid in [fixture.connect(6, [12; 32]), fixture.connect(7, [12; 32])] {
        assert_eq!(
            post(&control, "/payments/connect", &invalid).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(connection.live());
        let mut called = false;
        connection
            .current(&mut || {
                called = true;
                Ok(())
            })
            .unwrap();
        assert!(called);
    }
    let retry = connected(&control, &request).await;
    assert!(Arc::ptr_eq(&connection, &retry));
    assert!(connection.live());
}

#[tokio::test]
async fn wireguard_rotation_persists_across_restart_without_resetting_delivery_or_replaying_old_key(
) {
    let fixture = Fixture::new(256);
    let old = fixture.connect(1, [11; 32]);
    let rotated = fixture.connect(2, [12; 32]);
    let bytes = packet(false, false, 4);
    {
        let control = fixture.start();
        let previous = connected(&control, &old).await;
        forward(&previous, &bytes, Direction::Outbound).await;
        let current = connected(&control, &rotated).await;
        assert!(!previous.live());
        assert!(current.live());
        assert_eq!(
            post(&control, "/payments/connect", &old).await.0,
            StatusCode::FORBIDDEN
        );
        assert!(current.live());
        assert_eq!(
            post(&control, "/payments/connect", &fixture.connect(2, [13; 32]))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
        assert!(current.live());
        assert_eq!(
            current.meter.snapshot().unwrap().committed_totals,
            [bytes.len() as u64, 0]
        );
    }
    let control = fixture.start();
    assert_eq!(
        post(&control, "/payments/connect", &old).await.0,
        StatusCode::FORBIDDEN
    );
    let current = connected(&control, &rotated).await;
    assert_eq!(
        current.meter.snapshot().unwrap().committed_totals,
        [bytes.len() as u64, 0]
    );
    let third = connected(&control, &fixture.connect(3, [13; 32])).await;
    assert!(!current.live());
    assert!(third.live());
    assert_eq!(
        third.meter.snapshot().unwrap().committed_totals,
        [bytes.len() as u64, 0]
    );
}

#[tokio::test]
async fn revoked_canonical_guard_and_service_stop_prevent_kernel_handoff_and_new_admission() {
    for stop_service in [false, true] {
        let fixture = Fixture::new(256);
        let control = fixture.start();
        let connection = connected(&control, &fixture.connect(1, [11; 32])).await;
        let bytes = packet(false, false, 4);
        let ticket = connection
            .meter
            .reserve(&bytes, Direction::Outbound)
            .await
            .unwrap();
        if stop_service {
            drop(Stop(control.registry.clone()));
        } else {
            fixture.host.0.read().guard.revoke();
        }
        assert!(!connection.live());
        let mut sent = false;
        assert!(connection
            .handoff(ticket, bytes.len(), || {
                sent = true;
                Ok(bytes.len())
            })
            .await
            .is_err());
        assert!(!sent);
        let snapshot = connection.meter.snapshot().unwrap();
        assert_eq!(snapshot.committed_totals, [0, 0]);
        assert_eq!(snapshot.pending_totals, [0, 0]);
        assert_eq!(snapshot.uncertain_totals, [0, 0]);
        assert_eq!(
            post(&control, "/payments/connect", &fixture.connect(2, [12; 32]))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let fixture = Fixture::new(256);
    let control = fixture.start();
    let connection = connected(&control, &fixture.connect(1, [11; 32])).await;
    fixture.host.0.write().admissible = false;
    control.registry.refresh().await;
    assert!(!connection.live());
    assert!(connection.current(&mut || Ok(())).is_err());
}

#[tokio::test]
async fn only_confirmed_metered_bytes_can_reach_canonical_settlement() {
    let fixture = Fixture::new(256);
    let control = fixture.start();
    let connect = fixture.connect(1, [11; 32]);
    let connection = connected(&control, &connect).await;
    let bytes = packet(false, false, 4);
    let ticket = connection
        .meter
        .reserve(&bytes, Direction::Outbound)
        .await
        .unwrap();
    let usage = fixture.usage(0, 1, bytes.len() as u64);
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.settlement.attempts.load(Ordering::Acquire), 0);
    ticket.cancel().await.unwrap();
    let ticket = connection
        .meter
        .reserve(&bytes, Direction::Outbound)
        .await
        .unwrap();
    assert!(connection
        .handoff(ticket, bytes.len(), || Err(io::Error::from(
            io::ErrorKind::WouldBlock
        )))
        .await
        .is_err());
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.settlement.attempts.load(Ordering::Acquire), 0);
    let ticket = connection
        .meter
        .reserve(&bytes, Direction::Outbound)
        .await
        .unwrap();
    assert!(connection
        .handoff(ticket, bytes.len(), || Ok(bytes.len() - 1))
        .await
        .is_err());
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        while connection.meter.snapshot().unwrap().pending_totals[0] != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    let snapshot = connection.meter.snapshot().unwrap();
    assert_eq!(snapshot.committed_totals, [0, 0]);
    assert_eq!(snapshot.uncertain_totals, [bytes.len() as u64, 0]);
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.settlement.attempts.load(Ordering::Acquire), 0);
    forward(&connection, &bytes, Direction::Outbound).await;
    assert_eq!(
        post(
            &control,
            "/payments/usage",
            &fixture.usage(0, 1, bytes.len() as u64 + 1)
        )
        .await
        .0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(fixture.settlement.attempts.load(Ordering::Acquire), 0);
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::OK
    );
    assert_eq!(connection.meter.authorizations().unwrap(), vec![usage]);
    assert_eq!(
        fixture.host.0.read().redeemed_totals,
        [bytes.len() as u64, 0]
    );
    assert_eq!(
        connection.meter.snapshot().unwrap().uncertain_totals,
        [bytes.len() as u64, 0]
    );
}

#[tokio::test]
async fn failed_canonical_settlement_never_restores_credit_even_after_restart() {
    let fixture = Fixture::new(64);
    let connect = fixture.connect(1, [11; 32]);
    let bytes = packet(false, false, 36);
    assert_eq!(bytes.len(), 64);
    let usage = fixture.usage(0, 1, 64);
    fixture.settlement.fail.store(true, Ordering::Release);
    {
        let control = fixture.start();
        let connection = connected(&control, &connect).await;
        forward(&connection, &bytes, Direction::Outbound).await;
        assert!(connection.meter.reserve_class(0, 1).await.is_err());
        assert_eq!(
            post(&control, "/payments/usage", &usage).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert!(connection.meter.authorizations().unwrap().is_empty());
        assert!(connection.meter.reserve_class(0, 1).await.is_err());
        assert_eq!(fixture.host.0.read().redeemed_totals, [0, 0]);
    }
    let control = fixture.start();
    let connection = connected(&control, &connect).await;
    assert!(connection.meter.reserve_class(0, 1).await.is_err());
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(connection.meter.authorizations().unwrap().is_empty());
    assert!(connection.meter.reserve_class(0, 1).await.is_err());
    fixture.settlement.fail.store(false, Ordering::Release);
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::OK
    );
    assert_eq!(
        connection.meter.authorizations().unwrap(),
        vec![usage.clone()]
    );
    let ticket = connection.meter.reserve_class(0, 1).await.unwrap();
    ticket.cancel().await.unwrap();
    // Exact retry is idempotent and does not reset original lifetime liability.
    assert_eq!(
        post(&control, "/payments/usage", &usage).await.0,
        StatusCode::OK
    );
    assert_eq!(connection.meter.snapshot().unwrap().capacity_charge_ou, 64);
    assert_eq!(connection.meter.snapshot().unwrap().remaining_ou, 9_936);
}

#[tokio::test]
async fn wrong_receipt_key_or_bad_signature_cannot_restore_credit() {
    let fixture = Fixture::new(64);
    let control = fixture.start();
    let connection = connected(&control, &fixture.connect(1, [11; 32])).await;
    forward(&connection, &packet(false, false, 36), Direction::Outbound).await;
    let valid = fixture.usage(0, 1, 64);
    let mut invalid = valid.clone();
    invalid.signature.0[0] ^= 1;
    assert_eq!(
        post(&control, "/payments/usage", &invalid).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    let invalid = SignedUsage::sign(valid.usage, &KeyPair::from_secret_bytes(&[8; 32])).unwrap();
    assert_eq!(
        post(&control, "/payments/usage", &invalid).await.0,
        StatusCode::SERVICE_UNAVAILABLE
    );
    assert!(connection.meter.authorizations().unwrap().is_empty());
    assert!(connection.meter.reserve_class(0, 1).await.is_err());
    assert_eq!(fixture.host.0.read().redeemed_totals, [0, 0]);
}

#[tokio::test]
async fn usage_replay_and_unknown_class_cannot_replace_durable_authorization() {
    let fixture = Fixture::new(128);
    let control = fixture.start();
    let connection = connected(&control, &fixture.connect(1, [11; 32])).await;
    let bytes = packet(false, false, 4);
    forward(&connection, &bytes, Direction::Outbound).await;
    let first = fixture.usage(0, 1, bytes.len() as u64);
    assert_eq!(
        post(&control, "/payments/usage", &first).await.0,
        StatusCode::OK
    );
    forward(&connection, &bytes, Direction::Outbound).await;
    let current = fixture.usage(0, 3, 2 * bytes.len() as u64);
    assert_eq!(
        post(&control, "/payments/usage", &current).await.0,
        StatusCode::OK
    );
    for invalid in [
        first,
        fixture.usage(0, 2, 2 * bytes.len() as u64),
        fixture.usage(2, 4, 1),
    ] {
        assert_eq!(
            post(&control, "/payments/usage", &invalid).await.0,
            StatusCode::SERVICE_UNAVAILABLE
        );
        assert_eq!(
            connection.meter.authorizations().unwrap(),
            vec![current.clone()]
        );
        assert_eq!(
            fixture.host.0.read().redeemed_totals,
            [2 * bytes.len() as u64, 0]
        );
    }
}
