//! One captured runtime profile supplies both execution settings and native
//! handshake commitments. A peer cannot negotiate alternative execution rules.
use anyhow::{ensure, Result};
use octra_node_protocol::{
    consensus::{hash, profile::Settings},
    network::swarm::Activation,
    program_trust::Keys,
    rules,
};
use std::collections::BTreeMap;
pub struct Profile {
    pub settings: Settings,
    pub keys: Keys,
    crypto_engine: Vec<u8>,
}
impl Profile {
    pub fn status_release(&self) -> octra_node_runtime::status_read::Release {
        use octra_node_protocol::status_rpc::release_hash;
        octra_node_runtime::status_read::Release {
            settings: self.settings.clone(),
            crypto_engine: self.crypto_engine.clone(),
            program_trust: self.keys.config_hash(),
            source_commit: release_hash(self.settings.get("OCTRA_SOURCE_COMMIT"), 40),
            binary_hash: release_hash(self.settings.get("OCTRA_BINARY_HASH"), 64),
        }
    }
    pub fn new(values: BTreeMap<String, Vec<u8>>) -> Result<Self> {
        let keys = Keys::parse(values.get("OCTRA_PROGRAM_RELEASE_KEYS").map(Vec::as_slice))?;
        Ok(Self {
            settings: Settings::from_values(values)?,
            keys,
            crypto_engine: hex::encode(octra_hfhe::seeded_rng::aes_kat()).into_bytes(),
        })
    }
    pub fn hash(&self, chain: &[u8], epoch: i64) -> Result<Vec<u8>> {
        Ok(self
            .settings
            .hash(chain, epoch, &self.crypto_engine)?
            .to_vec())
    }
    pub fn wire_hash(&self, chain: &[u8], epoch: i64) -> Result<Vec<u8>> {
        Ok(hash::network_hash(
            chain,
            self.keys.config_hash().as_ref(),
            Some(&self.hash(chain, epoch)?),
        )?
        .to_vec())
    }
    pub fn ready_hash(&self, chain: &[u8]) -> Result<Vec<u8>> {
        let runtime = self
            .settings
            .compatibility_hash(&self.crypto_engine)?
            .to_vec();
        Ok(hex::encode(hash::network_hash(
            chain,
            self.keys.config_hash().as_ref(),
            Some(&runtime),
        )?)
        .into_bytes())
    }
    pub fn transitions(&self, chain: &[u8]) -> Result<Vec<Activation>> {
        rules::profile_epochs(chain)
            .into_iter()
            .map(|epoch| {
                Ok(Activation {
                    epoch,
                    config_hash: self.wire_hash(chain, epoch)?,
                    profile_hash: self.hash(chain, epoch)?,
                })
            })
            .collect()
    }
}
/// Read configuration data without executing shell input or expanding variables.
/// Native distributed network.env files use one unquoted assignment per line.
pub fn parse_env(raw: &[u8]) -> Result<BTreeMap<String, Vec<u8>>> {
    ensure!(
        raw.len() <= 1024 * 1024,
        "network environment exceeds byte limit"
    );
    let mut values = BTreeMap::new();
    for line in raw.split(|b| *b == b'\n') {
        let line = octra_node_protocol::network::endpoint::native_trim(line);
        if line.is_empty() || line[0] == b'#' {
            continue;
        }
        let at = line
            .iter()
            .position(|b| *b == b'=')
            .ok_or_else(|| anyhow::anyhow!("invalid network assignment"))?;
        let name = &line[..at];
        let value = &line[at + 1..];
        ensure!(
            name.starts_with(b"OCTRA_")
                && name
                    .iter()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || *b == b'_'),
            "invalid network setting name"
        );
        ensure!(
            !value.contains(&0) && !value.contains(&b'\r'),
            "invalid network setting value"
        );
        let name = std::str::from_utf8(name)?.to_owned();
        ensure!(
            values.insert(name, value.to_vec()).is_none(),
            "duplicate network setting"
        );
    }
    Ok(values)
}
