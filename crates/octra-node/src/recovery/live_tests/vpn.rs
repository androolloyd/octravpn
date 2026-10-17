use crate::{vpn::Settlement, Committed};
use anyhow::Result;
use octravpn_core::{
    address::Address,
    control::{announce_opener_binding_payload, announce_signing_payload, AnnounceSessionRequest},
    receipt::ReceiptContext,
    session::SessionId,
    sig::KeyPair,
};
use octravpn_node::admission::{FundedSession, RelayLifecycle};
use std::{path::Path, sync::Arc};
use x25519_dalek::{PublicKey, StaticSecret};

pub(super) struct Vpn {
    pub(super) request: AnnounceSessionRequest,
    pub(super) domain: ReceiptContext,
    pub(super) settlement: Arc<Funded>,
}
pub(super) struct Funded(FundedSession);
#[async_trait::async_trait]
impl Settlement for Funded {
    async fn session(
        &self,
        view: &Committed,
        _: &AnnounceSessionRequest,
        domain: &ReceiptContext,
    ) -> Result<Option<FundedSession>> {
        anyhow::ensure!(domain == &self.0.domain, "unexpected settlement domain");
        let mut session = self.0.clone();
        session.current_epoch = view.head().cursor.epoch.0;
        Ok(Some(session))
    }
    async fn lifecycle(
        &self,
        _: &Committed,
        session: &SessionId,
        domain: &ReceiptContext,
    ) -> Result<RelayLifecycle> {
        anyhow::ensure!(
            session == &self.0.session_id && domain == &self.0.domain,
            "wrong session"
        );
        Ok(RelayLifecycle::Open)
    }
}
impl Vpn {
    pub(super) fn new() -> Self {
        let opener = KeyPair::from_secret_bytes(&[11; 32]);
        let client = KeyPair::from_secret_bytes(&[21; 32]);
        let wg = PublicKey::from(&StaticSecret::from([51; 32])).to_bytes();
        let session_id = SessionId::from_u64(73);
        let hash = "ab".repeat(32);
        let domain = ReceiptContext::v2(
            Address::from_pubkey(&[61; 32]),
            999,
            Address::from_pubkey(&[71; 32]),
        );
        let request = AnnounceSessionRequest {
            client_sig: client.sign(&announce_signing_payload(
                &session_id,
                &client.public,
                &wg,
                &hash,
            )),
            opener_sig: opener.sign(&announce_opener_binding_payload(
                &session_id,
                &client.public,
                &wg,
                &hash,
            )),
            session_id: session_id.clone(),
            client_pubkey: client.public,
            client_wg_pubkey: wg,
            open_tx_hash: hash.clone(),
            opener_pubkey: opener.public,
        };
        Self {
            request,
            domain: domain.clone(),
            settlement: Arc::new(Funded(FundedSession {
                domain,
                session_id,
                opener: Address::from_pubkey(&opener.public.0),
                client_pubkey: client.public,
                client_wg_pubkey: wg,
                open_tx_hash: hash,
                current_epoch: 1,
                expires_epoch: 100,
                escrow_ou: 100,
                open: true,
            })),
        }
    }
    pub(super) fn config(&self, directory: &Path) -> octravpn_node::embedded::Config {
        octravpn_node::embedded::Config {
            control_listen: "127.0.0.1:0".parse().unwrap(),
            tunnel_listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: directory.to_owned(),
            receipt_key: Arc::new(KeyPair::from_secret_bytes(&[31; 32])),
            wireguard_secret: StaticSecret::from([41; 32]),
            receipt_context: self.domain.clone(),
        }
    }
}
