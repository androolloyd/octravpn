//! Diagnose a public-network handshake without starting another node or writer.
use anyhow::{bail, Context, Result};
use base64::Engine as _;
use octra_node_protocol::{
    network::session::{self, LocalNode, Timeouts},
    transaction::address_from_public_key,
};
use rand::{rngs::OsRng, RngCore};
use std::{net::SocketAddr, path::PathBuf};

#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let config = PathBuf::from(
        args.next()
            .context("usage: peer_probe NETWORK_JSON PEER_IP:PORT")?,
    );
    let peer: SocketAddr = args
        .next()
        .context("usage: peer_probe NETWORK_JSON PEER_IP:PORT")?
        .to_str()
        .context("peer endpoint is not UTF-8")?
        .parse()?;
    if args.next().is_some() {
        bail!("usage: peer_probe NETWORK_JSON PEER_IP:PORT");
    }
    let config = octra_node::network::read(&config)?;
    let status: serde_json::Value = reqwest::get(format!("http://{}/operator/status", config.rpc))
        .await?
        .error_for_status()?
        .json()
        .await?;
    let epoch = status["epoch"].as_u64().context("missing local epoch")?;
    let root: [u8; 32] = hex::decode(
        status["state_root"]
            .as_str()
            .context("missing local state root")?,
    )?
    .try_into()
    .map_err(|_| anyhow::anyhow!("invalid local state root"))?;
    let chain = config.network.identity.chain_id.as_bytes();
    let profile = octra_node::network_profile::Profile::new(
        octra_node::network_profile::parse_env(&std::fs::read(&config.environment)?)?,
    )?;
    let allowed = profile
        .settings
        .get("OCTRA_VALIDATORS")
        .context("missing configured validator keys")?
        .split(|byte| *byte == b',')
        .map(|entry| {
            let colon = entry
                .iter()
                .position(|byte| *byte == b':')
                .context("invalid validator entry")?;
            let key = &entry[colon + 1..];
            base64::engine::general_purpose::STANDARD
                .decode(key)
                .context("invalid validator public key")
        })
        .collect::<Result<Vec<_>>>()?;
    let allowed = if std::env::var_os("OCTRA_PROBE_ALLOW_ANY").is_some() {
        Vec::new()
    } else {
        allowed
    };
    let wire_hash: [u8; 32] = profile
        .wire_hash(chain, i64::try_from(epoch)? + 1)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid wire hash"))?;
    // A disposable observer identity avoids colliding with the running node's
    // session on the remote validator.
    let mut seed = zeroize::Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(&mut seed[..]);
    let key = ed25519_dalek::SigningKey::from_bytes(&seed);
    let address = address_from_public_key(
        base64::engine::general_purpose::STANDARD
            .encode(key.verifying_key().as_bytes())
            .as_bytes(),
    );
    let local = LocalNode {
        chain_id: chain.to_vec(),
        node_address: address,
        config_hash: wire_hash,
        listen_port: config.p2p.port(),
        best_epoch: i64::try_from(epoch)?,
        best_root: root,
    };
    let stream = octra_node_protocol::network::proxy::connect(
        &octra_node_protocol::network::endpoint::Endpoint {
            host: peer.ip().to_string().into_bytes(),
            port: peer.port(),
        },
        config.p2p_proxy,
    )
    .await?;
    match session::dial(
        stream,
        &local,
        &key,
        &allowed,
        &mut OsRng,
        Timeouts::default(),
    )
    .await
    {
        Ok(mut connection) => {
            println!(
                "verified responder {} at {peer}",
                String::from_utf8_lossy(&connection.peer().node_address)
            );
            match tokio::time::timeout(std::time::Duration::from_secs(2), connection.receive())
                .await
            {
                Ok(Ok(frame)) => println!("first frame: 0x{:02x}", frame.message),
                Ok(Err(error)) => println!("peer closed after handshake: {error}"),
                Err(_) => println!("no frame within two seconds"),
            }
        }
        Err(error) => bail!("peer {peer} rejected handshake: {error}"),
    }
    Ok(())
}
