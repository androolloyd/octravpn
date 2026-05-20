//! `seal-keys` / `unseal-keys` (P1-6). Pure file-system surface — no
//! Hub, no chain. The destination of `unseal-keys` MUST live on a
//! memory-volatile filesystem; the `seal::check_tmpfs` gate enforces
//! that.

use anyhow::{Context as _, Result};
use async_trait::async_trait;

use crate::config::NodeConfig;
use crate::seal;

use super::{CliContext, Subcommand};

/// `octravpn-node seal-keys [--passphrase|--passphrase-file|--passphrase-stdin] [--remove-plaintext]`
#[derive(clap::Args, Debug)]
pub(crate) struct SealKeysArgs {
    /// Pass the passphrase inline. Warns about shell history.
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
    /// Path to a file whose first line is the passphrase. Ideal
    /// for ops platforms that mount secrets via tmpfs.
    #[arg(long)]
    pub(crate) passphrase_file: Option<std::path::PathBuf>,
    /// Read the passphrase as one line from stdin (for `echo $PP
    /// | octravpn-node seal-keys --passphrase-stdin`).
    #[arg(long)]
    pub(crate) passphrase_stdin: bool,
    /// Delete the plaintext source files after a successful seal.
    /// Off by default — operators should verify the sealed file
    /// reads back before unlinking. Combine with `--rotate` once
    /// confident.
    #[arg(long)]
    pub(crate) remove_plaintext: bool,
}

#[async_trait]
impl Subcommand for SealKeysArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        let cfg = ctx.load_config()?;
        run_seal_keys(
            &cfg,
            self.passphrase.as_deref(),
            self.passphrase_file.as_deref(),
            self.passphrase_stdin,
            self.remove_plaintext,
        )?;
        Ok(0)
    }
}

/// `octravpn-node unseal-keys --tmpdir <dir> [--passphrase…]`
#[derive(clap::Args, Debug)]
pub(crate) struct UnsealKeysArgs {
    /// Directory on a tmpfs/ramfs mount where the unsealed
    /// `wallet.key` and `wg.key` files will be written.
    #[arg(long)]
    pub(crate) tmpdir: std::path::PathBuf,
    #[arg(long)]
    pub(crate) passphrase: Option<String>,
    #[arg(long)]
    pub(crate) passphrase_file: Option<std::path::PathBuf>,
    #[arg(long)]
    pub(crate) passphrase_stdin: bool,
}

#[async_trait]
impl Subcommand for UnsealKeysArgs {
    fn needs_hub(&self) -> bool {
        false
    }
    async fn dispatch(self, ctx: CliContext<'_>) -> Result<i32> {
        let cfg = ctx.load_config()?;
        run_unseal_keys(
            &cfg,
            &self.tmpdir,
            self.passphrase.as_deref(),
            self.passphrase_file.as_deref(),
            self.passphrase_stdin,
        )?;
        Ok(0)
    }
}

// ---------------------------------------------------------------------------
// Worker functions — kept `pub(crate)` so the existing `main_tests` module
// (still hosted in `main.rs`) can drive them directly without a binary
// harness.
// ---------------------------------------------------------------------------

pub(crate) fn run_seal_keys(
    cfg: &NodeConfig,
    explicit: Option<&str>,
    file: Option<&std::path::Path>,
    from_stdin: bool,
    remove_plaintext: bool,
) -> Result<()> {
    let mut pp = seal::resolve_passphrase(explicit, file, from_stdin)?;
    let targets = seal::targets_from_config(cfg);
    let mut n_sealed = 0_u32;
    for t in &targets {
        match seal::seal_one(t, &pp) {
            Ok(true) => {
                n_sealed += 1;
                println!("sealed {} → {}", t.src.display(), t.dst.display());
            }
            Ok(false) => {
                println!(
                    "skipped {} (already sealed at {})",
                    t.label,
                    t.dst.display()
                );
            }
            Err(e) => {
                // Best-effort wipe of the passphrase before bailing
                // out so we don't leave it sitting in the heap
                // alongside the error message.
                use zeroize::Zeroize;
                pp.zeroize();
                return Err(e);
            }
        }
    }
    if remove_plaintext {
        for t in &targets {
            if t.dst.exists() && t.src.exists() {
                std::fs::remove_file(&t.src)
                    .with_context(|| format!("remove plaintext {}", t.src.display()))?;
                println!("removed plaintext {}", t.src.display());
            }
        }
    }
    use zeroize::Zeroize;
    pp.zeroize();
    println!(
        "seal-keys: {n_sealed} newly sealed, {} total target(s); plaintext {}",
        targets.len(),
        if remove_plaintext { "removed" } else { "kept" }
    );
    Ok(())
}

pub(crate) fn run_unseal_keys(
    cfg: &NodeConfig,
    tmpdir: &std::path::Path,
    explicit: Option<&str>,
    file: Option<&std::path::Path>,
    from_stdin: bool,
) -> Result<()> {
    // Refuse to write plaintext anywhere that's not a memory-volatile
    // mount. This is best-effort but it catches the obvious mistake of
    // pointing the dir at $HOME.
    std::fs::create_dir_all(tmpdir).with_context(|| format!("mkdir {}", tmpdir.display()))?;
    seal::check_tmpfs(tmpdir)?;
    let mut pp = seal::resolve_passphrase(explicit, file, from_stdin)?;
    let sealed_targets = seal::targets_from_config(cfg);
    for orig in &sealed_targets {
        // Source is the .sealed file; destination is in the tmpdir.
        let src = orig.dst.clone();
        let dst = tmpdir.join(
            orig.src
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new(orig.label)),
        );
        let t = seal::SealTarget {
            label: orig.label,
            src,
            dst: dst.clone(),
        };
        if let Err(e) = seal::unseal_one(&t, &pp) {
            use zeroize::Zeroize;
            pp.zeroize();
            return Err(e);
        }
        println!("unsealed {} → {}", t.src.display(), t.dst.display());
    }
    use zeroize::Zeroize;
    pp.zeroize();
    println!(
        "unseal-keys: wrote {} plaintext key(s) under {}",
        sealed_targets.len(),
        tmpdir.display()
    );
    Ok(())
}
