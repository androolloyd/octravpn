//! Private startup authenticates genesis before deriving its portable opt-in.
//! An imported store uses explicit local trust, never downloaded network.json.
use super::{root, state, Config};
use anyhow::{ensure, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_node_protocol::{epoch_index, rules::Graph, state_sync::manifest};
use octra_node_runtime::canonical::CanonicalStore;

pub(super) async fn open(config: &Config) -> Result<(CanonicalStore, Graph)> {
    let initial = state(&config.genesis)?;
    let origin = config
        .genesis
        .chain
        .genesis_root()
        .context("local devnet requires genesis origin")?;
    ensure!(root(&initial)? == origin, "genesis commitment differs");
    let mut graph = Graph::new(config.genesis.chain.chain_id.as_bytes().to_vec(), None);
    if config.genesis.activated_applications {
        graph = Graph::isolated_applications(
            config.genesis.chain.chain_id.as_bytes().to_vec(),
            None,
            origin.0,
        )
        .map_err(anyhow::Error::msg)?;
        let profile = graph
            .application_fixture()
            .context("private application profile missing")?;
        let (_, index) =
            epoch_index::next_root(hex::encode(epoch_index::genesis_root()).as_bytes(), 0, &[])?;
        let proof = STANDARD.encode(
            initial
                .snapshot()
                .read_proof(&[b"meta", profile.metadata_key()], false)?,
        );
        graph = graph
            .with_application_opt_in_proof(
                hex::encode(initial.root()?).as_bytes(),
                hex::encode(index).as_bytes(),
                proof.as_bytes(),
            )
            .map_err(anyhow::Error::msg)?;
    }
    let ordinary = config.data.join("canonical.db");
    let imported = config.data.join("canonical.sqlite");
    ensure!(
        !(ordinary.try_exists()? && imported.try_exists()?),
        "ambiguous private stores; select one data directory"
    );
    let store = if let Some(trust) = &config.checkpoint_trust {
        ensure!(
            trust.identity == config.genesis.chain && trust.migration_root.is_none(),
            "private checkpoint chain or migration differs"
        );
        let members = |values: &[String]| {
            manifest::signer_set(
                &values
                    .iter()
                    .map(|v| v.as_bytes().to_vec())
                    .collect::<Vec<_>>(),
            )
        };
        ensure!(
            manifest::set_hash(&members(&trust.validators)?)?
                == manifest::set_hash(&members(&config.genesis.validators)?)?,
            "private checkpoint validators differ from genesis"
        );
        let authority = crate::bootstrap::Authority::new(trust.clone())?;
        ensure!(
            imported.try_exists()? && !ordinary.try_exists()?,
            "private checkpoint store must already be imported"
        );
        authority.reopen(&config.data).await?
    } else {
        ensure!(
            !imported.try_exists()?,
            "imported private store requires configured checkpoint trust"
        );
        if ordinary.try_exists()? {
            CanonicalStore::open(&ordinary, &config.genesis.chain).await?
        } else {
            CanonicalStore::create(
                &ordinary,
                config.genesis.chain.clone(),
                initial.snapshot(),
                0,
            )
            .await?
        }
    };
    Ok((store, graph))
}
