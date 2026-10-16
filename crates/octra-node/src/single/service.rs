//! Full native RPC/application service lifecycle for an explicit private Single
//! node. The canonical producer remains the sole writer throughout shutdown.
use super::{facade::Facade, launch::Config, Node};
use anyhow::{ensure, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{net::TcpListener, sync::watch, task::JoinSet};
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Services {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub browser: Option<SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gateway: Option<crate::gateway::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn: Option<Vpn>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<super::network::Config>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grpc: Option<SocketAddr>,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Vpn {
    pub control: SocketAddr,
    pub tunnel: SocketAddr,
    pub settlement: crate::vpn::Config,
}
fn now() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
struct Stop {
    facade: Arc<Facade>,
    signal: watch::Sender<bool>,
    context: Arc<crate::rpc::Context>,
    swarm: Option<octra_node_protocol::network::swarm::Swarm>,
}
impl Drop for Stop {
    fn drop(&mut self) {
        self.facade.close();
        self.signal.send_replace(true);
        self.context.http.shutdown();
        if let (Some(tokens), Ok(runtime)) =
            (&self.context.tokens, tokio::runtime::Handle::try_current())
        {
            let tokens = tokens.clone();
            runtime.spawn(async move {
                tokens.shutdown().await;
            });
        }
        if let Some(swarm) = &self.swarm {
            swarm.stop();
        }
    }
}
pub async fn run(
    config: &Config,
    node: Arc<Node>,
    services: Services,
    mut shutdown: watch::Receiver<bool>,
) -> Result<()> {
    let key = crate::identity::read(&config.key)?;
    let mut network = match &services.network {
        Some(network) => {
            Some(super::network::Network::bind(network, node.clone(), key.clone()).await?)
        }
        None => None,
    };
    let swarm = network.as_ref().map(|network| network.swarm.clone());
    let facade = Facade::open(node.clone(), swarm.clone()).await?;
    let context = facade.context(
        &key,
        &config.data,
        services
            .vpn
            .as_ref()
            .map(|vpn| vpn.settlement.program.clone()),
    )?;
    let (stop, stopped) = watch::channel(false);
    let archive_status = node
        .extension_status("private-single-archive")
        .await
        .context("Single archive ExEx status missing")?;
    let guard = Stop {
        facade: facade.clone(),
        signal: stop.clone(),
        context: context.clone(),
        swarm,
    };
    let mut tasks = JoinSet::new();
    let mut archive_guard = tokio::spawn(crate::launch::supervise_archive(
        archive_status,
        stopped.clone(),
    ));
    let mut archive_done = false;
    let work = Box::pin(async {
        tasks.spawn(facade.clone().run(stopped.clone()));
        if let Some(mut network) = network.take() {
            let inbox = network.inbox.take().context("Single peer inbox missing")?;
            tasks.spawn(super::network::ingress(
                node.clone(),
                facade.clone(),
                network.swarm.clone(),
                inbox,
                stopped.clone(),
            ));
            tasks.spawn(network.run(stopped.clone()));
        }
        if let Some(browser) = services.browser {
            ensure!(
                browser.ip().is_loopback(),
                "Single browser must bind loopback"
            );
            let listener = TcpListener::bind(browser).await?;
            let router = crate::services::browser_router(facade.published().shared.clone());
            let mut stop = stopped.clone();
            tasks.spawn(async move {
                axum::serve(listener, router)
                    .with_graceful_shutdown(async move {
                        let _ = stop.wait_for(|value| *value).await;
                    })
                    .await?;
                Ok(())
            });
        }
        if let Some(gateway) = services.gateway {
            let service = facade.published().bind_gateway(gateway).await?;
            tasks.spawn(service.run(stopped.clone()));
        }
        if let Some(vpn) = services.vpn {
            let keys = crate::vpn::Keys::derive(&key);
            let domain = vpn.settlement.domain()?;
            let mut ip_tunnel = vpn.settlement.ip_tunnel.clone();
            if let Some(tun) = &mut ip_tunnel {
                tun.validate()?;
                crate::vpn::storage::transport_book(&config.data, tun);
            }
            let pinned = Arc::new(crate::vpn::Pinned::new(
                vpn.settlement,
                node.store().reader(),
                keys.receipt.public,
            )?);
            pinned.validate(&facade.snapshot()?)?;
            let directories = crate::vpn::storage::paid(
                &config.data,
                node.store().chain(),
                pinned.application(),
                &domain,
            )
            .await?;
            let (publisher, claims) = crate::vpn::settlement::Service::open(
                context.clone(),
                pinned.clone(),
                domain.clone(),
                keys.receipt.public,
                key.clone(),
                directories.claims,
            )
            .await?;
            let service = octravpn_node::embedded::EmbeddedVpn::bind_with_ip_tunnel(
                octravpn_node::embedded::Config {
                    control_listen: vpn.control,
                    tunnel_listen: vpn.tunnel,
                    data_dir: directories.receipts,
                    receipt_key: keys.receipt,
                    wireguard_secret: keys.wireguard,
                    receipt_context: domain,
                },
                facade.published().vpn_authority(pinned),
                ip_tunnel,
            )
            .await?
            .with_settlement(publisher);
            tasks.spawn(claims.run(stopped.clone()));
            tasks.spawn(service.run(stopped.clone()));
        }
        if let Some(listen) = services.grpc {
            let grpc = octra_node_protocol::grpc::Config::capture(|name| match name {
                "OCTRA_GRPC_ENABLE" => Some(b"true".to_vec()),
                "OCTRA_GRPC_HOST" => Some(listen.ip().to_string().into_bytes()),
                "OCTRA_GRPC_PORT" => Some(listen.port().to_string().into_bytes()),
                _ => None,
            })
            .map_err(anyhow::Error::msg)?
            .context("Single gRPC configuration missing")?;
            let service = crate::rpc::grpc::Service::bind(grpc, context.clone()).await?;
            tasks.spawn(service.run(stopped.clone()));
        }
        let listener = TcpListener::bind(config.rpc).await?;
        let router = crate::rpc::router_with_limit(context.clone(), config.maximum_http_body);
        let mut http_stop = stopped.clone();
        tasks.spawn(async move {
            axum::serve(listener, router)
                .with_graceful_shutdown(async move {
                    let _ = http_stop.wait_for(|value| *value).await;
                })
                .await?;
            Ok(())
        });
        loop {
            if *shutdown.borrow_and_update() {
                break;
            }
            tokio::select! {
                change = shutdown.changed() => {
                    if change.is_err() || *shutdown.borrow_and_update() { break; }
                },
                result = tasks.join_next() => match result {
                    Some(Ok(Err(error))) => return Err(error),
                    Some(Err(error)) => return Err(error.into()),
                    _ => anyhow::bail!("Single service stopped unexpectedly"),
                },
                () = tokio::time::sleep(Duration::from_secs(10)) => {
                    let time = now()?;
                    node.tick(time, time as i64).await?;
                }
            }
        }
        Ok(())
    });
    let result = tokio::select! {
        result = work => result,
        archive = &mut archive_guard => {
            archive_done = true;
            Err(crate::launch::service_stopped(Some(archive)))
        },
    };
    drop(guard);
    if !archive_done
        && tokio::time::timeout(Duration::from_secs(6), &mut archive_guard)
            .await
            .is_err()
    {
        archive_guard.abort();
        let _ = archive_guard.await;
    }
    // A dispatched canonical/proof operation retains its owned leases; join it
    // before closing the runtime and only then bound auxiliary service drains.
    let shutdown_result = node.shutdown().await;
    if tokio::time::timeout(Duration::from_secs(6), async {
        while tasks.join_next().await.is_some() {}
    })
    .await
    .is_err()
    {
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
    }
    shutdown_result?;
    result
}
