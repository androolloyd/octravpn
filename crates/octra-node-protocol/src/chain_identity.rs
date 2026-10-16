//! Local store/extension identity. An origin is an independently configured
//! binding, not a substitute for consensus, exporter or finality verification.
use serde::{
    de::Error as _, ser::SerializeStruct, Deserialize, Deserializer, Serialize, Serializer,
};
use sha2::{Digest, Sha256};

/// A folded consensus state commitment, distinct from a host namespace digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StateRoot(pub [u8; 32]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ChainOrigin {
    Genesis {
        #[serde(with = "root_hex")]
        state_root: StateRoot,
    },
    /// A published, independently pinned checkpoint. This does not claim that
    /// the original genesis commitment is known or retained locally.
    Checkpoint {
        epoch: u64,
        #[serde(with = "root_hex")]
        state_root: StateRoot,
    },
}
impl ChainOrigin {
    pub fn epoch(self) -> u64 {
        match self {
            Self::Genesis { .. } => 0,
            Self::Checkpoint { epoch, .. } => epoch,
        }
    }
    pub fn state_root(self) -> StateRoot {
        match self {
            Self::Genesis { state_root } | Self::Checkpoint { state_root, .. } => state_root,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainIdentity {
    pub chain_id: String,
    pub origin: ChainOrigin,
}
impl ChainIdentity {
    pub fn genesis(chain_id: impl Into<String>, state_root: StateRoot) -> Self {
        Self {
            chain_id: chain_id.into(),
            origin: ChainOrigin::Genesis { state_root },
        }
    }
    pub fn checkpoint(chain_id: impl Into<String>, epoch: u64, state_root: StateRoot) -> Self {
        Self {
            chain_id: chain_id.into(),
            origin: ChainOrigin::Checkpoint { epoch, state_root },
        }
    }
    pub fn genesis_root(&self) -> Option<StateRoot> {
        match self.origin {
            ChainOrigin::Genesis { state_root } => Some(state_root),
            ChainOrigin::Checkpoint { .. } => None,
        }
    }
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.chain_id.is_empty() {
            Err("empty chain identity")
        } else if self.origin.epoch() > (1_u64 << 62) - 1 {
            Err("checkpoint origin epoch exceeds native range")
        } else {
            Ok(())
        }
    }
    /// Check only the configured origin relationship. The caller must first
    /// authenticate the supplied checkpoint through its native trust policy.
    pub fn bind_checkpoint(&self, epoch: u64, state_root: StateRoot) -> Result<(), &'static str> {
        self.validate()?;
        match self.origin {
            ChainOrigin::Genesis { state_root: root } if epoch == 0 && state_root != root => {
                Err("snapshot differs from configured genesis origin")
            }
            ChainOrigin::Checkpoint { epoch: origin, .. } if epoch < origin => {
                Err("snapshot precedes configured checkpoint origin")
            }
            ChainOrigin::Checkpoint {
                epoch: origin,
                state_root: root,
            } if epoch == origin && state_root != root => {
                Err("snapshot differs from configured checkpoint origin")
            }
            _ => Ok(()),
        }
    }
    /// Durable host namespace only; never a consensus state root. Genesis
    /// retains the existing key exactly so old extension sinks cannot replay.
    pub fn namespace_key(&self) -> [u8; 32] {
        match self.origin {
            ChainOrigin::Genesis { state_root } => state_root.0,
            ChainOrigin::Checkpoint { epoch, state_root } => {
                let mut hash = Sha256::new();
                hash.update(b"octra:checkpoint-origin:v1\0");
                hash.update((self.chain_id.len() as u64).to_be_bytes());
                hash.update(self.chain_id.as_bytes());
                hash.update(epoch.to_be_bytes());
                hash.update(state_root.0);
                hash.finalize().into()
            }
        }
    }
}
impl Serialize for ChainIdentity {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut fields = serializer.serialize_struct("ChainIdentity", 2)?;
        fields.serialize_field("chain_id", &self.chain_id)?;
        match self.origin {
            ChainOrigin::Genesis { state_root } => {
                fields.serialize_field("genesis_root", &state_root)?;
            }
            ChainOrigin::Checkpoint { .. } => fields.serialize_field("origin", &self.origin)?,
        }
        fields.end()
    }
}
impl<'de> Deserialize<'de> for ChainIdentity {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Fields {
            chain_id: String,
            genesis_root: Option<StateRoot>,
            origin: Option<ChainOrigin>,
        }
        let fields = Fields::deserialize(deserializer)?;
        let origin = match (fields.genesis_root, fields.origin) {
            (Some(state_root), None) => ChainOrigin::Genesis { state_root },
            (None, Some(origin)) => origin,
            _ => {
                return Err(D::Error::custom(
                    "chain identity requires exactly one origin",
                ))
            }
        };
        let identity = Self {
            chain_id: fields.chain_id,
            origin,
        };
        identity.validate().map_err(D::Error::custom)?;
        Ok(identity)
    }
}
mod root_hex {
    use super::*;
    pub(super) fn serialize<S: Serializer>(
        root: &StateRoot,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(root.0))
    }
    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<StateRoot, D::Error> {
        let raw = String::deserialize(deserializer)?;
        if raw.len() != 64
            || !raw
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(D::Error::custom("origin root must be lowercase SHA256 hex"));
        }
        let mut root = [0; 32];
        hex::decode_to_slice(raw, &mut root).map_err(D::Error::custom)?;
        Ok(StateRoot(root))
    }
}
