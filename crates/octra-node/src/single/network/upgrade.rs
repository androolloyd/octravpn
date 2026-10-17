//! Explicit private-network transport schedules use the same native parser as
//! the public launcher's captured environment. They do not replace a binary.
use octra_node_protocol::network::upgrade::{self, Plan};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    pub epoch: i64,
    pub binary_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upgrade {
    pub target: Target,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback: Option<Target>,
}

impl Upgrade {
    pub(super) fn plan(&self, base: &[u8], required: bool) -> anyhow::Result<Option<Plan>> {
        let mut values = BTreeMap::new();
        for (prefix, target) in [
            ("OCTRA_P2P_UPGRADE", Some(&self.target)),
            ("OCTRA_P2P_ROLLBACK", self.rollback.as_ref()),
        ] {
            if let Some(target) = target {
                values.insert(format!("{prefix}_ACTIVATE_EPOCH"), target.epoch.to_string());
                values.insert(format!("{prefix}_BINARY_HASH"), target.binary_hash.clone());
                if let Some(hash) = &target.config_hash {
                    values.insert(format!("{prefix}_CONFIG_HASH"), hash.clone());
                }
            }
        }
        Ok(upgrade::from_inputs(base, required, |name| {
            values.get(name).map(String::as_bytes)
        })?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn private_schedule_preserves_native_defaults_and_activation_validation() {
        let mut schedule: Upgrade = serde_json::from_value(json!({
            "target": {"epoch": 10, "binary_hash": hex::encode([2; 32]), "config_hash": hex::encode([3; 32])},
            "rollback": {"epoch": 20, "binary_hash": hex::encode([4; 32])}
        }))
        .unwrap();
        let parsed = schedule.plan(&[1; 32], true).unwrap().unwrap();
        assert_eq!(parsed.target.epoch, 10);
        assert_eq!(parsed.target.binary_hash, [2; 32]);
        assert_eq!(parsed.target.config_hash, [3; 32]);
        let rollback = parsed.rollback.unwrap();
        assert_eq!(rollback.epoch, 20);
        assert_eq!(rollback.binary_hash, [4; 32]);
        assert_eq!(rollback.config_hash, [1; 32]);
        schedule.rollback.as_mut().unwrap().epoch = 10;
        assert_eq!(
            schedule.plan(&[1; 32], true).unwrap_err().to_string(),
            "OCTRA_P2P_ROLLBACK_ACTIVATE_EPOCH must be greater than upgrade activation"
        );
        // Native disabled enforcement ignores the entire schedule.
        assert!(schedule.plan(&[1; 32], false).unwrap().is_none());
        schedule.target.epoch = 0;
        assert_eq!(
            schedule.plan(&[1; 32], true).unwrap_err().to_string(),
            "OCTRA_P2P_UPGRADE_ACTIVATE_EPOCH must be positive"
        );
    }

    #[test]
    fn private_transport_config_roundtrips_optional_schedule_and_rejects_unknown_fields() {
        let raw = json!({
            "listen": "127.0.0.1:0", "bootstrap": [],
            "config_hash": hex::encode([1; 32]), "binary_hash": hex::encode([2; 32]),
            "require_binary_hash": true, "maximum_peers": 4
        });
        let config: super::super::Config = serde_json::from_value(raw.clone()).unwrap();
        assert!(config.upgrade.is_none());
        assert!(serde_json::to_value(config)
            .unwrap()
            .get("upgrade")
            .is_none());
        let mut configured = raw;
        configured["upgrade"] =
            json!({"target": {"epoch": 10, "binary_hash": hex::encode([2; 32])}});
        let config: super::super::Config = serde_json::from_value(configured.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(config).unwrap()["upgrade"],
            configured["upgrade"]
        );
        configured["upgrade"]["target"]["untrusted"] = json!(true);
        assert!(serde_json::from_value::<super::super::Config>(configured).is_err());
    }
}
