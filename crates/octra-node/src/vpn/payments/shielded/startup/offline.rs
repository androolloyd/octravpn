//! Strict CLI dispatch; public trust and local genesis are never interchangeable.
use super::Action;
use anyhow::{bail, Result};
use octra_node_runtime::circle::CircleRuntime;
use std::path::{Path, PathBuf};

pub async fn run(path: &Path, runtime: CircleRuntime, action: Action) -> Result<PathBuf> {
    Box::pin(run_with_runtime_factory(path, |_| Ok(runtime), action)).await
}

pub async fn run_with_runtime_factory(
    path: &Path,
    make_runtime: impl FnOnce(
        Option<&octra_node_protocol::consensus::profile::Settings>,
    ) -> Result<CircleRuntime>,
    action: Action,
) -> Result<PathBuf> {
    let value: serde_json::Value =
        serde_json::from_slice(&crate::bootstrap::read_limited(path, 1024 * 1024)?)?;
    match (
        value.get("genesis"),
        value.get("network"),
        value.get("role"),
    ) {
        (Some(_), None, None) => {
            Box::pin(crate::devnet::private_wallet_action(
                crate::devnet::read(path)?,
                make_runtime(None)?,
                action,
            ))
            .await
        }
        (None, Some(_), None) => {
            Box::pin(crate::network::private_wallet_action_with_runtime_factory(
                crate::network::read(path)?,
                |settings| make_runtime(Some(settings)),
                action,
            ))
            .await
        }
        _ => bail!(
            "private action requires exactly one public network or isolated genesis configuration"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn ambiguous_or_unsupported_actions_refuse_before_runtime_or_state_access() {
        for value in [
            serde_json::json!({"genesis":{},"network":{}}),
            serde_json::json!({"role":"single","single":{}}),
            serde_json::json!({}),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("node.json");
            std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
            let result = run_with_runtime_factory(
                &path,
                |_| panic!("invalid action constructed a runtime"),
                Action::Payer,
            )
            .await;
            assert!(result.unwrap_err().to_string().contains("exactly one"));
            assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1);
        }
    }
}
