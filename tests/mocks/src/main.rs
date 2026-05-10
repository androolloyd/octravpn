use std::net::SocketAddr;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "octravpn-mock-rpc")]
struct Cli {
    #[arg(long, default_value = "0.0.0.0:18080")]
    listen: SocketAddr,
    #[arg(long, default_value = "octPROGRAMaddress0000000000000000000000")]
    program_addr: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();
    let cli = Cli::parse();
    octravpn_mock_rpc::serve(cli.listen, cli.program_addr).await
}
