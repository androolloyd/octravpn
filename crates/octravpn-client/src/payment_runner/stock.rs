//! Control-only prepaid purchases for a separately registered stock Tailscale
//! node. This never reads the node's secret, installs a TUN, or changes routes.
use super::*;
pub struct StockOptions {
    pub plan: Plan,
    pub journal: PathBuf,
    pub receipt_key: Arc<octravpn_core::KeyPair>,
    /// Public Tailscale nodekey (not its machine key or private key).
    pub node_key: String,
    pub mode: OpenMode,
}
pub struct StockClient {
    plan: Plan,
    journal: Accounting,
    origin: reqwest::Url,
    connect: SignedConnect,
    http: reqwest::Client,
    initial: Observation,
}
impl StockClient {
    pub async fn open(options: StockOptions) -> Result<Self> {
        let StockOptions {
            plan,
            journal: path,
            receipt_key: key,
            node_key,
            mode,
        } = options;
        let raw = node_key
            .strip_prefix("nodekey:")
            .context("stock key requires nodekey: prefix")?;
        ensure!(
            raw.len() == 64
                && raw
                    .bytes()
                    .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
            "stock public node key must be canonical lowercase hex"
        );
        let public: [u8; 32] = hex::decode(raw)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid stock key"))?;
        ensure!(public != [0; 32], "zero stock public key");
        let origin = plan.origin()?;
        let accepted = plan.clone();
        let journal = Accounting::new(
            tokio::task::spawn_blocking(move || Journal::open_stock(&path, &accepted, key, mode))
                .await??,
        );
        let connect = journal.with(move |journal| journal.connect(public)).await?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(60))
            .no_proxy()
            .build()?;
        let initial = Observation::new(status_mode(&http, &origin, &connect, &plan, true).await?);
        let initial = prepay_mode(&http, &origin, &connect, &plan, &journal, initial, true).await?;
        Ok(Self {
            plan,
            journal,
            origin,
            connect,
            http,
            initial,
        })
    }
    pub async fn run(
        self,
        shutdown: impl std::future::Future<Output = Result<()>>,
    ) -> Result<Summary> {
        let Self {
            plan,
            journal,
            origin,
            connect,
            http,
            initial,
        } = self;
        let (stop, stopped) = tokio::sync::watch::channel(false);
        // Stock transport delivery is operator-metered; this controller never
        // fabricates local packet counters from signed operator status.
        supervise(
            journal,
            std::future::pending(),
            control_mode(http, origin, connect, plan, initial, stopped, true),
            stop,
            shutdown,
        )
        .await
    }
}
