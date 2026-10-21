//! Test-only TLS frontend for the real canonical loopback purchase service.
use std::{net::SocketAddr, sync::Arc};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::watch,
    task::JoinHandle,
};
pub(super) struct Server {
    pub(super) origin: String,
    pub(super) ca: String,
    pub(super) spki: [u8; 32],
    stop: watch::Sender<bool>,
    task: JoinHandle<()>,
}
impl Server {
    pub(super) async fn new(backend: SocketAddr) -> Self {
        use tokio_rustls::{
            rustls::{self, pki_types::PrivatePkcs8KeyDer},
            TlsAcceptor,
        };
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let ca = cert.cert.pem();
        let spki =
            octravpn_core::spki_verifier::SpkiPinVerifier::fingerprint(cert.cert.der()).unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.cert.der().clone()],
            PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der()).into(),
        )
        .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!(
            "https://localhost:{}/",
            listener.local_addr().unwrap().port()
        );
        let (stop, mut stopped) = watch::channel(false);
        let task = tokio::spawn(async move {
            let mut workers = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    _=stopped.wait_for(|v| *v)=>break,
                    connection=listener.accept()=>{
                        let (socket,_)=connection.unwrap(); let acceptor=acceptor.clone();
                        workers.spawn(async move {
                            if let Ok(mut tls)=acceptor.accept(socket).await {
                                let mut upstream=TcpStream::connect(backend).await.unwrap();
                                let _=tokio::io::copy_bidirectional(&mut tls,&mut upstream).await;
                            }
                        });
                    },
                    _=workers.join_next(),if !workers.is_empty()=>(),
                }
            }
            workers.abort_all();
            while workers.join_next().await.is_some() {}
        });
        Self {
            origin,
            ca,
            spki,
            stop,
            task,
        }
    }
    pub(super) fn control(
        &self,
        target: octravpn_core::payments::PrivateTarget,
    ) -> octravpn_client::PrivateControl {
        octravpn_client::PrivateControl::new(&self.origin, target, &self.ca, vec![self.spki])
            .unwrap()
    }
    pub(super) async fn close(self) {
        self.stop.send(true).unwrap();
        self.task.await.unwrap();
    }
}
