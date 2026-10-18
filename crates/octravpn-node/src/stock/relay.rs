//! In-process operator DERP endpoint. Each source gets a bounded, key-pinned
//! loopback UDP association; ciphertext is never a meter input.
use super::{Exit, Registration};
use anyhow::{ensure, Context, Result};
use crypto_box::{
    aead::{Aead, AeadCore},
    Nonce, PublicKey, SalsaBox, SecretKey,
};
use headscale_core::derp::protocol::Frame;
use std::{
    collections::HashMap,
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{net::UdpSocket, sync::mpsc, task::AbortHandle};
pub(crate) const MAGIC: &[u8] = b"TS\xf0\x9f\x92\xac";
const MAX: usize = 4096;
const IDLE: Duration = Duration::from_secs(600);
pub(super) struct Disco(SecretKey);
impl Disco {
    pub(super) fn public(&self) -> [u8; 32] {
        self.0.public_key().to_bytes()
    }
    pub(super) fn open(directory: &Path) -> Result<Self> {
        let path = directory.join("stock-disco.key");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options
                .mode(0o600)
                .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
        }
        let bytes = match options.open(&path) {
            Ok(mut file) => {
                let key = SecretKey::generate(&mut rand::rngs::OsRng);
                let bytes = key.to_bytes();
                file.write_all(&bytes)?;
                file.sync_all()?;
                std::fs::File::open(directory)?.sync_all()?;
                bytes
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let mut options = std::fs::OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32);
                }
                let mut file = options.open(path)?;
                let metadata = file.metadata()?;
                ensure!(
                    metadata.is_file() && metadata.len() == 32,
                    "invalid stock Disco key file"
                );
                #[cfg(unix)]
                {
                    use std::os::unix::fs::{MetadataExt, PermissionsExt};
                    ensure!(
                        metadata.permissions().mode().trailing_zeros() >= 6
                            && metadata.nlink() == 1
                            && metadata.uid() == std::fs::metadata(directory)?.uid(),
                        "stock Disco key must be a private regular file"
                    );
                }
                let mut bytes = [0; 32];
                file.read_exact(&mut bytes)?;
                bytes
            }
            Err(error) => return Err(error.into()),
        };
        let mut bytes = bytes;
        let key = SecretKey::from(bytes);
        zeroize::Zeroize::zeroize(&mut bytes);
        Ok(Self(key))
    }
    /// Tailscale v1.104.1 disco/disco.go Ping/Pong and authenticated NaCl box.
    /// Only a registered source's current Disco key may elicit a bounded pong.
    fn reply(
        &self,
        exit: &Exit,
        source: &[u8; 32],
        packet: &[u8],
        endpoint: SocketAddr,
    ) -> Option<Vec<u8>> {
        if packet.len() < 78 || packet.len() > 4096 || !packet.starts_with(MAGIC) {
            return None;
        }
        let peer = exit.machines.get(&hex::encode(source))?;
        let expected = peer.disco_key?.strip_prefix("discokey:")?.to_owned();
        if hex::encode(&packet[6..38]) != expected {
            return None;
        }
        let public: [u8; 32] = packet[6..38].try_into().ok()?;
        let cipher = SalsaBox::new(&PublicKey::from(public), &self.0);
        let decoded = cipher
            .decrypt(Nonce::from_slice(&packet[38..62]), &packet[62..])
            .ok()?;
        if decoded.len() < 14 || decoded[0] != 1 || decoded[1] != 0 {
            return None;
        }
        if decoded.len() >= 46 && decoded[14..46] != [0; 32] && decoded[14..46] != *source {
            return None;
        }
        let mut body = vec![2, 0];
        body.extend_from_slice(&decoded[2..14]);
        let ip = match endpoint.ip() {
            std::net::IpAddr::V4(ip) => ip.to_ipv6_mapped(),
            std::net::IpAddr::V6(ip) => ip,
        };
        body.extend_from_slice(&ip.octets());
        body.extend_from_slice(&endpoint.port().to_be_bytes());
        let nonce = SalsaBox::generate_nonce(&mut rand::rngs::OsRng);
        let sealed = cipher.encrypt(&nonce, body.as_slice()).ok()?;
        let mut reply = MAGIC.to_vec();
        reply.extend_from_slice(&self.public());
        reply.extend_from_slice(&nonce);
        reply.extend_from_slice(&sealed);
        Some(reply)
    }
}
struct Proxy {
    socket: Arc<UdpSocket>,
    registration: Registration,
    last: Instant,
    task: AbortHandle,
    exit: Arc<Exit>,
    address: SocketAddr,
}
impl Drop for Proxy {
    fn drop(&mut self) {
        self.task.abort();
        self.exit.sources.lock().remove(&self.address);
    }
}
struct Session {
    relay: headscale_core::derp::native::NativeDerpRelay,
    key: [u8; 32],
    id: u64,
}
impl Drop for Session {
    fn drop(&mut self) {
        let relay = self.relay.clone();
        let key = self.key;
        let id = self.id;
        tokio::spawn(async move {
            relay.disconnect_session(&key, id).await;
        });
    }
}
impl Exit {
    pub(crate) fn disco_reply(
        &self,
        packet: &[u8],
        endpoint: SocketAddr,
    ) -> Option<(Registration, Vec<u8>)> {
        if packet.len() < 78 || packet.len() > 4096 || !packet.starts_with(MAGIC) {
            return None;
        }
        let key = format!("discokey:{}", hex::encode(&packet[6..38]));
        let snapshot = self.machines.snapshot();
        let mut records = snapshot
            .values()
            .filter(|r| r.disco_key.as_ref() == Some(&key));
        let record = records.next()?;
        if records.next().is_some() {
            return None;
        }
        let registration = self
            .registration(&hex::decode(&record.node_key_hex).ok()?.try_into().ok()?)
            .ok()?;
        let reply =
            self.disco
                .lock()
                .as_ref()?
                .reply(self, &registration.node_key, packet, endpoint)?;
        Some((registration, reply))
    }
    pub(crate) fn current_registration(
        &self,
        registration: &Registration,
        action: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        self.guard
            .current(&mut || self.with_registration(registration, action))
    }
    pub(crate) async fn run_relay(self: Arc<Self>, mut tunnel: SocketAddr) -> Result<()> {
        if tunnel.ip().is_unspecified() {
            tunnel.set_ip(std::net::Ipv4Addr::LOCALHOST.into());
        }
        ensure!(
            tunnel.ip().is_loopback(),
            "DERP bridge needs a local tunnel endpoint"
        );
        let mut session = self.relay.connect(self.operator_key).await;
        let _session = Session {
            relay: self.relay.clone(),
            key: self.operator_key,
            id: session.session_id(),
        };
        let operator = self
            .machines
            .get(&hex::encode(self.operator_key))
            .context("stock operator registration missing")?;
        // Advertise Online only for the lifetime of an actual owned operator
        // transport session, never merely because the HTTP mesh was bound.
        let _online = octravpn_mesh::MachineRegistry::track_stream_connection(
            self.machines.clone(),
            operator.stable_node_id(),
        );
        let (send, mut receive) = mpsc::channel::<([u8; 32], Registration, Vec<u8>)>(1024);
        let mut proxies: HashMap<[u8; 32], Proxy> = HashMap::new();
        let mut sweep = tokio::time::interval(Duration::from_secs(1));
        loop {
            tokio::select! {
                _=sweep.tick()=>{proxies.retain(|_,p|p.last.elapsed()<IDLE && self.current(&p.registration));},
                returned=receive.recv()=>{
                    let (destination,registration,packet)=returned.context("stock DERP return queue stopped")?;
                    if self.current(&registration) && self.adjacent(&self.operator_key,&destination) {
                        session.handle_frame(Frame::SendPacket{destination,packet}).await?;
                    }
                },
                incoming=session.recv()=>{
                    let frame=incoming.context("stock DERP session stopped")?;
                    let Frame::RecvPacket{source,packet}=frame else {continue;};
                    let Ok(registration)=self.registration(&source) else {continue;};
                    if packet.starts_with(MAGIC) {
                        let response=self.disco.lock().as_ref().and_then(|d|d.reply(&self,&source,&packet,"127.3.3.40:1".parse().expect("DERP magic endpoint")));
                        if let Some(packet)=response {session.handle_frame(Frame::SendPacket{destination:source,packet}).await?;}
                        continue;
                    }
                    if packet.len()>2048 {continue;}
                    if proxies.get(&source).is_some_and(|p|p.registration!=registration) {proxies.remove(&source);}
                    if !proxies.contains_key(&source) {
                        if proxies.len()>=MAX {continue;}
                        let socket=Arc::new(UdpSocket::bind("127.0.0.1:0").await?);socket.connect(tunnel).await?;
                        let address=socket.local_addr()?;self.sources.lock().insert(address,source);
                        let output=send.clone();let reader=socket.clone();let pinned=registration.clone();
                        let task=tokio::spawn(async move {let mut buf=[0;2048];while let Ok(n)=reader.recv(&mut buf).await {if output.try_send((source,pinned.clone(),buf[..n].to_vec())).is_err(){break;}}}).abort_handle();
                        proxies.insert(source,Proxy{socket,registration:registration.clone(),last:Instant::now(),task,exit:self.clone(),address});
                    }
                    if let Some(proxy)=proxies.get_mut(&source) {
                        // Registered DERP identity and WireGuard static identity
                        // are checked independently by the transport before IO.
                        if self.current(&registration) {let _=proxy.socket.try_send(&packet);proxy.last=Instant::now();}
                    }
                },
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::aead::Aead;
    #[test]
    fn disco_ping_pong_authenticates_registered_keys_without_free_packet_relay() {
        let (exit, _guard) = super::super::tests::fixture();
        let node = [4; 32];
        super::super::tests::register(&exit.machines, node, "100.64.0.2".parse().unwrap());
        let client = SecretKey::generate(&mut rand::rngs::OsRng);
        let server = Disco(SecretKey::generate(&mut rand::rngs::OsRng));
        let mut record = exit.machines.get(&hex::encode(node)).unwrap();
        record.disco_key = Some(format!(
            "discokey:{}",
            hex::encode(client.public_key().to_bytes())
        ));
        exit.machines.upsert(hex::encode(node), record);
        let cipher = SalsaBox::new(&PublicKey::from(server.public()), &client);
        let nonce = SalsaBox::generate_nonce(&mut rand::rngs::OsRng);
        let mut body = vec![1, 0];
        body.extend_from_slice(&[7; 12]);
        body.extend_from_slice(&node);
        let wrap = |body: &[u8]| {
            let mut packet = MAGIC.to_vec();
            packet.extend_from_slice(&client.public_key().to_bytes());
            packet.extend_from_slice(&nonce);
            packet.extend_from_slice(&cipher.encrypt(&nonce, body).unwrap());
            packet
        };
        let packet = wrap(&body);
        let reply = server
            .reply(&exit, &node, &packet, "192.0.2.7:41641".parse().unwrap())
            .unwrap();
        let plain = cipher
            .decrypt(Nonce::from_slice(&reply[38..62]), &reply[62..])
            .unwrap();
        assert_eq!(&plain[..14], &[vec![2, 0], vec![7; 12]].concat());
        assert_eq!(&plain[26..30], &[192, 0, 2, 7]);
        assert_eq!(&plain[30..32], &41641u16.to_be_bytes());
        assert!(reply.len() < 128);
        assert!(server
            .reply(&exit, &[5; 32], &packet, "127.3.3.40:1".parse().unwrap())
            .is_none());
        body[14] ^= 1;
        assert!(server
            .reply(&exit, &node, &wrap(&body), "127.3.3.40:1".parse().unwrap())
            .is_none());
        let mut tampered = packet;
        *tampered.last_mut().unwrap() ^= 1;
        assert!(server
            .reply(&exit, &node, &tampered, "127.3.3.40:1".parse().unwrap())
            .is_none());
    }
}
