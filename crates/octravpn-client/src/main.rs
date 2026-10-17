//! `octravpn` command-line entry point.
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    octravpn_client::cli::run().await
}
