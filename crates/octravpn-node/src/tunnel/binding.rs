//! Transport identity independent of the selected payment application.
use super::AllowedClient;
use crate::payments::{Connection, Registry};
use octravpn_core::{bounded::BoundedMap, session::SessionId};
use std::sync::Arc;

#[derive(Clone)]
#[expect(
    clippy::large_enum_variant,
    reason = "Keep the existing bounded admission value inline; boxing would allocate on every legacy packet lookup."
)]
pub(super) enum Binding {
    Legacy(AllowedClient),
    Paid(Arc<Connection>),
    StockPortal(Arc<crate::stock::Peer>),
}
impl Binding {
    pub(super) fn live(&self) -> bool {
        match self {
            Self::Legacy(b) => b.live(),
            Self::Paid(b) => b.live(),
            Self::StockPortal(b) => b.live(),
        }
    }
    pub(super) fn retain_peer(&self) -> bool {
        match self {
            Self::Legacy(b) => b.retain_peer(),
            Self::Paid(_) => true,
            Self::StockPortal(b) => b.live(),
        }
    }
    pub(super) fn session(&self) -> &SessionId {
        match self {
            Self::Legacy(b) => &b.request.session_id,
            Self::Paid(b) => &b.session,
            Self::StockPortal(b) => &b.session,
        }
    }
    pub(super) fn key(&self) -> [u8; 32] {
        match self {
            Self::Legacy(b) => b.request.client_wg_pubkey,
            Self::Paid(b) => b.request.request.wireguard_key,
            Self::StockPortal(b) => b.registration.node_key,
        }
    }
    pub(super) fn same(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Legacy(a), Self::Legacy(b)) => Arc::ptr_eq(&a.request, &b.request),
            (Self::Paid(a), Self::Paid(b)) => Arc::ptr_eq(a, b),
            (Self::StockPortal(a), Self::StockPortal(b)) => Arc::ptr_eq(a, b),
            _ => false,
        }
    }
    pub(super) fn stock(&self) -> Option<&crate::stock::Registration> {
        match self {
            Self::Paid(b) => b.stock_registration(),
            Self::StockPortal(b) => Some(&b.registration),
            Self::Legacy(_) => None,
        }
    }
    pub(super) fn portal(&self) -> Option<&Arc<crate::stock::Peer>> {
        if let Self::StockPortal(peer) = self {
            Some(peer)
        } else {
            None
        }
    }
    pub(super) fn paid(&self) -> Option<&Arc<Connection>> {
        match self {
            Self::Paid(b) => Some(b),
            Self::Legacy(_) | Self::StockPortal(_) => None,
        }
    }
}

pub(super) fn lookup(
    legacy: &BoundedMap<[u8; 32], AllowedClient>,
    paid: Option<&Registry>,
    key: &[u8; 32],
) -> Option<Binding> {
    if let Some(paid) = paid {
        match paid.get(key) {
            Some(connection) if connection.stock_registration().is_none() || connection.live() => {
                Some(Binding::Paid(connection))
            }
            _ => paid.stock_peer(key).map(Binding::StockPortal),
        }
    } else {
        legacy.get(key).map(Binding::Legacy)
    }
}
