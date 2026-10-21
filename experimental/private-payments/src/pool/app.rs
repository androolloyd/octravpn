//! Reviewable immutable Circle source, not an automatic deployment. A public
//! factory must spawn it with parent ownership and finalize initialize first.
use super::{encode_field, PoolIndex, INPUTS};
use anyhow::{ensure, Result};
use base64::{engine::general_purpose::STANDARD, Engine};

pub const TEMPLATE: &str = include_str!("../../program/shielded-pool.aml.in");
pub const FACTORY: &str = include_str!("../../program/shielded-pool-factory.aml");

pub fn source(chain: &[u8; 32], native_vk: &[u8], custody_cap: u64) -> Result<String> {
    ensure!(
        *chain != [0; 32] && custody_cap > 0 && custody_cap <= i64::MAX as u64,
        "invalid immutable pool terms"
    );
    ensure!(
        native_vk.len() == 458 + (INPUTS + 1) * 64
            && native_vk.get(..6) == Some(b"OG16V1")
            && native_vk.get(6..10) == Some((INPUTS as u32).to_be_bytes().as_slice()),
        "wrong native pool verification key shape"
    );
    let (notes, spent, _) = PoolIndex::default().roots();
    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
    Ok(TEMPLATE
        .replace("$CHAIN", &hex(chain))
        .replace("$VK", &STANDARD.encode(native_vk))
        .replace("$CAP", &custody_cap.to_string())
        .replace("$NOTES", &hex(&encode_field(notes)))
        .replace("$SPENT", &hex(&encode_field(spent))))
}
