use super::{Binding, Server};
use octravpn_core::ip_tunnel;
use std::net::SocketAddr;
impl Server {
    pub(super) async fn dispatch_stock(
        &self,
        raw: &[u8],
        source: SocketAddr,
        mut binding: Binding,
        identity: std::sync::Arc<super::stock_peer::Identity>,
    ) {
        if !binding.live() {
            return;
        }
        let Some(registration) = binding.stock() else {
            return;
        };
        // IPv6, fragments, TSMP and malformed transport never enter the paid
        // IPv4 kernel path. Advertising ::/0 prevents client IPv6 escape.
        let Ok(packet) = ip_tunnel::parse(raw) else {
            return;
        };
        if packet.source != registration.ipv4 {
            return;
        }
        let Some(registry) = &self.payments else {
            return;
        };
        let Some(portal) = registry.stock_peer(&binding.key()) else {
            return;
        };
        let Some(exit) = portal.exit() else {
            return;
        };
        if crate::stock::packet::portal(&packet, &exit.config) {
            binding = Binding::StockPortal(portal);
        } else if binding.paid().is_none()
            || !(ip_tunnel::public_ipv4(packet.destination)
                || crate::stock::packet::circle(&packet, &exit.config))
        {
            return;
        }
        let Some(tunnel) = &self.ip_tunnel else {
            return;
        };
        let path = self.stock_return_path(binding.session(), source, &binding, identity);
        if let Err(error) = tunnel.forward_stock(path, raw).await {
            tracing::debug!(%error,"stock packet refused");
        }
    }
}
