//! Optional private Single peer transport. Transactions use the real ingress;
//! legacy epoch messages are decoded diagnostics and never synchronize state.
use super::{facade::Facade, Node, Settings};
use anyhow::{ensure, Context, Result};
use ed25519_dalek::SigningKey;
use octra_exex::CommittedEpochSource;
use octra_node_protocol::{
    legacy_epoch,
    network::{
        endpoint::Endpoint,
        frame::Frame,
        session::{Peer, Timeouts},
        swarm::{self, Handler, MessageFuture, Swarm},
    },
    transaction::Transaction,
};
use octra_node_runtime::{
    account_store,
    p2p_transaction::{self, Effect},
    state_batch::StateBatch,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::TcpListener,
    sync::{mpsc, watch},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub bootstrap: Vec<SocketAddr>,
    pub config_hash: String,
    pub binary_hash: String,
    pub require_binary_hash: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upgrade: Option<Upgrade>,
    pub maximum_peers: i64,
    #[serde(default)]
    pub allow_dynamic_peers: bool,
}
mod upgrade;
pub use upgrade::{Target, Upgrade};
pub(super) struct Network {
    listener: TcpListener,
    pub swarm: Swarm,
    pub inbox: Option<mpsc::Receiver<(Peer, Frame)>>,
    handler: Arc<Inbox>,
}
struct Inbox(mpsc::Sender<(Peer, Frame)>);
impl Handler for Inbox {
    fn message(&self, peer: Peer, frame: Frame) -> MessageFuture {
        if frame.message == 0x20 || frame.message == legacy_epoch::FRAME_TYPE {
            let _ = self.0.try_send((peer, frame));
        }
        Box::pin(async { Ok(()) })
    }
}
fn hash(raw: &str) -> Result<Vec<u8>> {
    ensure!(
        raw.len() == 64
            && raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Single transport hash must be64lowerhex"
    );
    Ok(hex::decode(raw)?)
}
fn endpoint(address: SocketAddr) -> Result<Endpoint> {
    ensure!(
        address.is_ipv4() && address.ip().is_loopback() && address.port() != 0,
        "private Single peer endpoint must be IPv4 loopback with nonzero port"
    );
    Ok(Endpoint {
        host: address.ip().to_string().into_bytes(),
        port: address.port(),
    })
}
fn validator_keys(settings: &Settings, committed_epoch: u64) -> Result<Vec<Vec<u8>>> {
    let next = i64::try_from(committed_epoch)?
        .checked_add(1)
        .context("Single epoch exhausted")?;
    settings
        .validators(next)
        .iter()
        .map(|(_, key)| {
            octra_node_protocol::transaction::decode_base64(key).map_err(anyhow::Error::new)
        })
        .collect()
}
fn role_schedule(config: &Config, settings: &Settings, committed_epoch: u64) -> Result<()> {
    let next = i64::try_from(committed_epoch)?
        .checked_add(1)
        .context("Single epoch exhausted")?;
    let rotating =
        settings.next_validators.is_some() && settings.activation.is_some_and(|epoch| epoch > next);
    ensure!(
        !rotating || config.allow_dynamic_peers,
        "Single peer rotation requires explicit dynamic peer admission; the closed handshake filter is immutable"
    );
    Ok(())
}
fn refresh_validators(swarm: &Swarm, settings: &Settings, committed_epoch: u64) -> Result<()> {
    // This selected role set is independent of handshake authentication. A
    // scheduled key admitted dynamically remains an observer until activation.
    Ok(swarm.set_validators(validator_keys(settings, committed_epoch)?)?)
}
impl Network {
    pub(super) async fn bind(config: &Config, node: Arc<Node>, key: SigningKey) -> Result<Self> {
        ensure!(
            config.listen.is_ipv4() && config.listen.ip().is_loopback(),
            "private Single peer listener must be IPv4 loopback"
        );
        ensure!(
            (1..=256).contains(&config.maximum_peers) && config.bootstrap.len() <= 256,
            "Single peer capacity outside limit"
        );
        let head = node.head().await?;
        role_schedule(config, node.settings(), head.cursor.epoch.0)?;
        let allowed = validator_keys(node.settings(), head.cursor.epoch.0)?;
        let bootstrap = config
            .bootstrap
            .iter()
            .map(|value| endpoint(*value))
            .collect::<Result<Vec<_>>>()?;
        let config_hash = hash(&config.config_hash)?;
        let binary_hash = hash(&config.binary_hash)?;
        let upgrade = config
            .upgrade
            .as_ref()
            .map(|upgrade| upgrade.plan(&config_hash, config.require_binary_hash))
            .transpose()?
            .flatten();
        let listener = TcpListener::bind(config.listen).await?;
        let advertised = endpoint(listener.local_addr()?)?;
        let view = node.clone();
        let swarm = Swarm::new(
            swarm::Config {
                chain_id: node.store().chain().chain_id.as_bytes().to_vec(),
                node_address: node.settings().wallet_address.clone(),
                config_hash,
                binary_hash,
                require_binary_hash: config.require_binary_hash,
                upgrade,
                profiles: vec![],
                allowed_public_keys: if config.allow_dynamic_peers {
                    vec![]
                } else {
                    allowed.clone()
                },
                bootstrap,
                maximum_validators: config.maximum_peers,
                advertised,
                timeouts: Timeouts::default(),
                head: Arc::new(move || {
                    let head = view.store().cached_head().unwrap_or_else(|| head.clone());
                    (head.cursor.epoch.0 as i64, head.cursor.state_root.0)
                }),
            },
            key,
        )?;
        swarm.set_validators(allowed)?;
        let (sender, inbox) = mpsc::channel(256);
        Ok(Self {
            listener,
            swarm,
            inbox: Some(inbox),
            handler: Arc::new(Inbox(sender)),
        })
    }
    pub(super) async fn run(self, mut stop: watch::Receiver<bool>) -> Result<()> {
        let running = self.swarm.clone();
        let result = tokio::select! {result=running.run(self.listener,self.handler)=>result.map_err(anyhow::Error::new),_=stop.wait_for(|value|*value)=>Ok(())};
        self.swarm.stop();
        result
    }
}
struct Captured {
    node: Arc<Node>,
    now: f64,
    pending: BTreeMap<Vec<u8>, Transaction>,
    ledger: octra_node_protocol::state::Ledger,
    transactions: Vec<Transaction>,
    effects: Vec<Effect>,
}
impl p2p_transaction::Host for Captured {
    fn now(&self) -> f64 {
        self.now
    }
    fn has(&self, hash: &[u8]) -> bool {
        self.pending.contains_key(hash)
    }
    fn find(&self, hash: &[u8]) -> Option<Transaction> {
        self.pending.get(hash).cloned()
    }
    fn sender_key(&self, tx: &Transaction) -> Option<Vec<u8>> {
        self.node
            .account_for_read(&tx.from, self.ledger.account(&tx.from).cloned())
            .ok()
            .flatten()
            .and_then(|a| a.public_key)
            .or(tx.public_key.clone())
    }
    fn add(&mut self, tx: Transaction) -> std::result::Result<Vec<u8>, String> {
        self.transactions.push(tx);
        Err("admission queued".into())
    }
    fn emit(&mut self, effect: Effect) {
        self.effects.push(effect);
    }
}
fn now() -> Result<f64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs_f64())
}
pub(super) async fn ingress(
    node: Arc<Node>,
    facade: Arc<Facade>,
    swarm: Swarm,
    mut inbox: mpsc::Receiver<(Peer, Frame)>,
    mut stop: watch::Receiver<bool>,
) -> Result<()> {
    let mut ingress = p2p_transaction::Ingress::default();
    let mut changed = facade.updates();
    let mut last = node.head().await?.cursor.sequence;
    if let Some(head) = facade.completed_head() {
        refresh_validators(&swarm, node.settings(), head.cursor.epoch.0)?;
    }
    loop {
        if *stop.borrow_and_update() {
            break;
        }
        tokio::select! {
            change=stop.changed()=>{
                if change.is_err() || *stop.borrow_and_update(){break;}
            }
            change=changed.changed()=>{
                if change.is_err(){break;}
                let Some(head)=facade.completed_head() else{continue;};
                refresh_validators(&swarm,node.settings(),head.cursor.epoch.0)?;
                while last<head.cursor.sequence {
                    last=octra_exex::Sequence(last.0.checked_add(1).context("Single broadcast sequence exhausted")?);
                    if swarm.peers().is_empty(){continue;}
                    let record=node.store().record(last).await?;
                    let events=node.store().source().load(last).await?.context("Single broadcast events unavailable")?;
                    // The archive retains identity bytes (including null
                    // optionals). Native 0x40 uses Transaction.to_yojson, which
                    // omits absent fields, in the actual confirmed order.
                    let txs=events.events.iter().map(|event| {
                        let document=octra_node_protocol::native_json::Document::parse(&event.transaction)?;
                        let transaction=Transaction::from_document(&document)?;
                        transaction.to_json_bytes().map_err(anyhow::Error::new)
                    }).collect::<Result<Vec<_>>>()?;
                    let payload=legacy_epoch::payload(i64::try_from(record.head.cursor.epoch.0)?,hex::encode(record.head.cursor.state_root.0).as_bytes(),i64::try_from(txs.len())?,&record.proposer,&txs)?;
                    // Successful durable commit/local cleanup precedes this
                    // notification. No historical replay is sent on startup.
                    swarm.broadcast(Frame{message:legacy_epoch::FRAME_TYPE,payload},None,false).await?;
                }
            }
            input=inbox.recv()=>{
                let Some((peer,frame))=input else{break;};
                if frame.message==legacy_epoch::FRAME_TYPE {
                    let _=legacy_epoch::observer_event(false,&frame.payload);
                    continue;
                }
                let Ok(view)=facade.snapshot() else{continue;};
                refresh_validators(&swarm,node.settings(),view.head().cursor.epoch.0)?;
                let ledger=account_store::ledger(&StateBatch::from_snapshot(view.state().clone()))?;
                let pending=node.inspect_pool(|pool|pool.all().cloned().collect::<Vec<_>>())?.into_iter().map(|tx|Ok((hex::encode(tx.hash()?).into_bytes(),tx))).collect::<Result<_>>()?;
                let mut captured=Captured{node:node.clone(),now:now()?,pending,ledger,transactions:vec![],effects:vec![]};
                if ingress.receive(&peer.hello().node_id,&frame.payload,p2p_transaction::Rules{max_drift:node.settings().maximum_timestamp_drift,duty:None,bft:false},&mut captured).is_err(){continue;}
                for effect in captured.effects {p2p_transaction::deliver(&swarm,&peer,effect).await?;}
                for tx in captured.transactions {if let Ok(hash)=node.submit(tx,now()?).await {let _=facade.announce(hash,Some(&peer.hello().node_id)).await;}}
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use octra_node_protocol::network::budget::PeerClass;
    fn key(id: u8) -> SigningKey {
        SigningKey::from_bytes(&[id; 32])
    }
    fn public(id: u8) -> Vec<u8> {
        STANDARD
            .encode(key(id).verifying_key().as_bytes())
            .into_bytes()
    }
    fn member(id: u8) -> Vec<u8> {
        let public = public(id);
        [
            octra_node_protocol::transaction::address_from_public_key(&public).as_slice(),
            b":",
            &public,
        ]
        .concat()
    }
    fn settings() -> Settings {
        Settings {
            mode: "single".into(),
            private_prior_fixture: true,
            wallet_address: octra_node_protocol::transaction::address_from_public_key(&public(4)),
            wallet_public: public(4),
            validators: Some([member(4), member(6)].join(&[b','][..])),
            next_validators: Some([member(5), member(6)].join(&[b','][..])),
            activation: Some(2),
            fee_recipient: None,
            epoch_capacity: "100".into(),
            stealth_minimum: "1000".into(),
            maximum_defer: 3,
            inline_ranges: false,
            maximum_timestamp_drift: 300.,
            preverify_ttl: 60.,
            preverify_maximum: 64,
        }
    }
    fn config(dynamic: bool) -> Config {
        Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            bootstrap: vec![],
            config_hash: hex::encode([9; 32]),
            binary_hash: hex::encode([8; 32]),
            require_binary_hash: true,
            upgrade: None,
            maximum_peers: 16,
            allow_dynamic_peers: dynamic,
        }
    }
    struct Ignore;
    impl Handler for Ignore {
        fn message(&self, _: Peer, _: Frame) -> MessageFuture {
            Box::pin(async { Ok(()) })
        }
    }
    struct Stop(Vec<Swarm>);
    impl Drop for Stop {
        fn drop(&mut self) {
            for swarm in &self.0 {
                swarm.stop();
            }
        }
    }
    #[tokio::test]
    async fn authenticated_scheduled_peers_follow_selected_epoch_roles() {
        let settings = settings();
        assert!(role_schedule(&config(false), &settings, 0).is_err());
        assert!(role_schedule(&config(true), &settings, 0).is_ok());
        // A restart after activation starts with the actual selected closed set.
        assert!(role_schedule(&config(false), &settings, 1).is_ok());
        let mut swarms = vec![];
        let mut listeners = vec![];
        for _ in 0..3 {
            listeners.push(TcpListener::bind("127.0.0.1:0").await.unwrap());
        }
        let addresses = listeners
            .iter()
            .map(|listener| listener.local_addr().unwrap())
            .collect::<Vec<_>>();
        for (index, id) in [6, 4, 5].into_iter().enumerate() {
            let selected = validator_keys(&settings, 0).unwrap();
            let swarm = Swarm::new(
                swarm::Config {
                    chain_id: b"single-role-test".to_vec(),
                    node_address: octra_node_protocol::transaction::address_from_public_key(
                        &public(id),
                    ),
                    config_hash: vec![9; 32],
                    binary_hash: vec![8; 32],
                    require_binary_hash: true,
                    upgrade: None,
                    profiles: vec![],
                    allowed_public_keys: vec![],
                    bootstrap: if index == 0 {
                        addresses[1..]
                            .iter()
                            .map(|address| endpoint(*address).unwrap())
                            .collect()
                    } else {
                        vec![]
                    },
                    maximum_validators: 16,
                    advertised: endpoint(addresses[index]).unwrap(),
                    timeouts: Timeouts::default(),
                    head: Arc::new(|| (0, [0; 32])),
                },
                key(id),
            )
            .unwrap();
            swarm.set_validators(selected).unwrap();
            swarms.push(swarm);
        }
        let stop = Stop(swarms.clone());
        let mut running = vec![];
        for (swarm, listener) in swarms.iter().cloned().zip(listeners) {
            running.push(tokio::spawn(async move {
                swarm.run(listener, Arc::new(Ignore)).await
            }));
        }
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            while swarms[0].peers().len() != 2 {
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
        let peers = swarms[0].peers();
        let prior = peers
            .iter()
            .find(|peer| peer.hello().public_key == key(4).verifying_key().to_bytes().to_vec())
            .unwrap();
        let scheduled = peers
            .iter()
            .find(|peer| peer.hello().public_key == key(5).verifying_key().to_bytes().to_vec())
            .unwrap();
        assert_eq!(prior.peer_class(), PeerClass::Validator);
        assert_eq!(scheduled.peer_class(), PeerClass::Observer);
        // Use the same helper called on completed canonical notifications and
        // before peer transaction work, with the actual Settings epoch rule.
        refresh_validators(&swarms[0], &settings, 1).unwrap();
        assert_eq!(prior.peer_class(), PeerClass::Observer);
        assert_eq!(scheduled.peer_class(), PeerClass::Validator);
        assert!(prior.is_connected() && scheduled.is_connected());
        drop(stop);
        for task in running {
            task.await.unwrap().unwrap();
        }
    }
}
