//! `octravpn slash-evidence ...` — capture and verify equivocation
//! evidence for protocol-layer slashing.
//!
//! When an endpoint signs two contradictory receipts for the same
//! `(session_id, seq)`, anyone holding both signatures can prove the
//! equivocation. This tool packages such evidence into a portable
//! JSON blob and verifies it locally before publishing.

use std::{fs, path::Path};

use anyhow::{Context, Result};
use octravpn_core::{
    receipt::Receipt,
    session::Blind,
    session::SessionId,
    sig::{self, PublicKey, Signature},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct EquivocationEvidence {
    pub endpoint_addr: String,
    /// Hex-encoded ed25519 receipt-signing pubkey published by the
    /// endpoint when it registered.
    pub receipt_pubkey_hex: String,
    pub session_id_hex: String,
    pub seq: u64,
    pub receipt_a: ReceiptBlob,
    pub receipt_b: ReceiptBlob,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct ReceiptBlob {
    pub bytes_used: u64,
    pub blind_hex: String,
    /// Hex-encoded 64-byte ed25519 signature.
    pub sig_hex: String,
}

impl EquivocationEvidence {
    /// Reconstruct the two `Receipt` structs that this evidence claims
    /// were signed.
    pub(crate) fn receipts(&self) -> Result<(Receipt, Receipt, [u8; 32], Signature, Signature)> {
        let sid_bytes = decode_hex_32(&self.session_id_hex, "session_id")?;
        let blind_a = decode_hex_32(&self.receipt_a.blind_hex, "blind_a")?;
        let blind_b = decode_hex_32(&self.receipt_b.blind_hex, "blind_b")?;
        let pk = decode_hex_32(&self.receipt_pubkey_hex, "receipt_pubkey")?;
        let sig_a = decode_hex_64(&self.receipt_a.sig_hex, "sig_a")?;
        let sig_b = decode_hex_64(&self.receipt_b.sig_hex, "sig_b")?;
        let ra = Receipt {
            session_id: SessionId::new(sid_bytes),
            seq: self.seq,
            bytes_used: self.receipt_a.bytes_used,
            blind: Blind::new(blind_a),
        };
        let rb = Receipt {
            session_id: SessionId::new(sid_bytes),
            seq: self.seq,
            bytes_used: self.receipt_b.bytes_used,
            blind: Blind::new(blind_b),
        };
        Ok((ra, rb, pk, sig_a, sig_b))
    }

    /// Verify that both signatures validate under `receipt_pubkey` and
    /// that the two receipts are genuinely distinct (so this isn't
    /// just the same receipt twice). Returns `Ok(true)` when the
    /// evidence is real, `Ok(false)` when the receipts are identical
    /// (no equivocation), and `Err(_)` when a signature doesn't
    /// validate (forged evidence).
    pub(crate) fn verify(&self) -> Result<bool> {
        let (ra, rb, pk_bytes, sig_a, sig_b) = self.receipts()?;
        let pk = PublicKey(pk_bytes);
        let msg_a = ra.signing_payload();
        let msg_b = rb.signing_payload();
        sig::verify(&pk, &msg_a, &sig_a).context("sig_a does not verify")?;
        sig::verify(&pk, &msg_b, &sig_b).context("sig_b does not verify")?;
        Ok(ra.bytes_used != rb.bytes_used || ra.blind.as_bytes() != rb.blind.as_bytes())
    }
}

fn decode_hex_32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = hex::decode(s).with_context(|| format!("hex {what}"))?;
    if v.len() != 32 {
        anyhow::bail!("{what} not 32 bytes (got {})", v.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

fn decode_hex_64(s: &str, what: &str) -> Result<Signature> {
    let v = hex::decode(s).with_context(|| format!("hex {what}"))?;
    if v.len() != 64 {
        anyhow::bail!("{what} not 64 bytes (got {})", v.len());
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&v);
    Ok(Signature(out))
}

/// Subcommand dispatch.
#[derive(clap::Parser, Clone, Debug)]
pub(crate) enum SlashCmd {
    /// Load `<blob>.json` and verify both signatures + distinctness.
    Verify { blob: std::path::PathBuf },
    /// Build evidence from two receipt blobs and write to `out`.
    Build {
        #[arg(long)]
        endpoint_addr: String,
        #[arg(long)]
        receipt_pubkey: String,
        #[arg(long)]
        session_id: String,
        #[arg(long)]
        seq: u64,
        #[arg(long)]
        bytes_a: u64,
        #[arg(long)]
        blind_a: String,
        #[arg(long)]
        sig_a: String,
        #[arg(long)]
        bytes_b: u64,
        #[arg(long)]
        blind_b: String,
        #[arg(long)]
        sig_b: String,
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

pub(crate) fn run(cmd: SlashCmd) -> Result<()> {
    match cmd {
        SlashCmd::Verify { blob } => {
            let ev = load(&blob)?;
            match ev.verify() {
                Ok(true) => {
                    println!("VALID equivocation evidence");
                    println!("  endpoint     : {}", ev.endpoint_addr);
                    println!("  session_id   : {}", ev.session_id_hex);
                    println!("  seq          : {}", ev.seq);
                    println!(
                        "  bytes        : a={} / b={}",
                        ev.receipt_a.bytes_used, ev.receipt_b.bytes_used
                    );
                    Ok(())
                }
                Ok(false) => {
                    anyhow::bail!("both receipts identical — no equivocation to slash on")
                }
                Err(e) => Err(e),
            }
        }
        SlashCmd::Build {
            endpoint_addr,
            receipt_pubkey,
            session_id,
            seq,
            bytes_a,
            blind_a,
            sig_a,
            bytes_b,
            blind_b,
            sig_b,
            out,
        } => {
            let ev = EquivocationEvidence {
                endpoint_addr,
                receipt_pubkey_hex: receipt_pubkey,
                session_id_hex: session_id,
                seq,
                receipt_a: ReceiptBlob {
                    bytes_used: bytes_a,
                    blind_hex: blind_a,
                    sig_hex: sig_a,
                },
                receipt_b: ReceiptBlob {
                    bytes_used: bytes_b,
                    blind_hex: blind_b,
                    sig_hex: sig_b,
                },
            };
            // Round-trip verify before writing so we never serialise
            // garbage as "evidence".
            ev.verify()
                .context("evidence verification failed; refusing to write")?;
            let body = serde_json::to_string_pretty(&ev)?;
            fs::write(&out, body).with_context(|| format!("write {}", out.display()))?;
            println!("wrote {}", out.display());
            Ok(())
        }
    }
}

fn load(path: &Path) -> Result<EquivocationEvidence> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    serde_json::from_str(&raw).context("decode evidence JSON")
}

#[cfg(test)]
mod tests {
    use super::*;
    use octravpn_core::{
        receipt::Receipt,
        session::{Blind, SessionId},
        sig::KeyPair,
    };

    fn signed_receipt_blob(
        kp: &KeyPair,
        sid: [u8; 32],
        seq: u64,
        bytes_used: u64,
        blind: [u8; 32],
    ) -> ReceiptBlob {
        let r = Receipt {
            session_id: SessionId::new(sid),
            seq,
            bytes_used,
            blind: Blind::new(blind),
        };
        let sig = kp.sign(&r.signing_payload());
        ReceiptBlob {
            bytes_used,
            blind_hex: hex::encode(blind),
            sig_hex: hex::encode(sig.0),
        }
    }

    #[test]
    fn verify_real_equivocation_returns_true() {
        let kp = KeyPair::generate();
        let sid = [7u8; 32];
        let a = signed_receipt_blob(&kp, sid, 5, 100, [1u8; 32]);
        let b = signed_receipt_blob(&kp, sid, 5, 200, [2u8; 32]); // distinct bytes & blind
        let ev = EquivocationEvidence {
            endpoint_addr: "octV".into(),
            receipt_pubkey_hex: hex::encode(kp.public.0),
            session_id_hex: hex::encode(sid),
            seq: 5,
            receipt_a: a,
            receipt_b: b,
        };
        assert!(ev.verify().unwrap());
    }

    #[test]
    fn verify_identical_receipts_is_not_equivocation() {
        let kp = KeyPair::generate();
        let sid = [3u8; 32];
        let a = signed_receipt_blob(&kp, sid, 1, 100, [9u8; 32]);
        let b = a.clone();
        let ev = EquivocationEvidence {
            endpoint_addr: "octV".into(),
            receipt_pubkey_hex: hex::encode(kp.public.0),
            session_id_hex: hex::encode(sid),
            seq: 1,
            receipt_a: a,
            receipt_b: b,
        };
        assert!(!ev.verify().unwrap(), "identical receipts must not slash");
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let real = KeyPair::generate();
        let attacker = KeyPair::generate();
        let sid = [4u8; 32];
        let a = signed_receipt_blob(&attacker, sid, 1, 1, [1u8; 32]);
        let b = signed_receipt_blob(&attacker, sid, 1, 2, [2u8; 32]);
        let ev = EquivocationEvidence {
            endpoint_addr: "octVREAL".into(),
            receipt_pubkey_hex: hex::encode(real.public.0), // wrong pubkey
            session_id_hex: hex::encode(sid),
            seq: 1,
            receipt_a: a,
            receipt_b: b,
        };
        assert!(ev.verify().is_err());
    }
}
