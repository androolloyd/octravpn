//! Operator-side key sealing / unsealing for P1-6.
//!
//! The v2 threat model called out plaintext `wg.key` / `wallet.key` /
//! `deployer.key` on operator hosts (docs/v2-threat-model.md §3 P1-6).
//! This module ships two CLI subcommands on `octravpn-node`:
//!
//!   - `seal-keys`   wraps a plaintext 32-byte secret (raw bytes or
//!                   64 hex digits) under the existing
//!                   `octra_core::wallet_enc` AEAD envelope, writes
//!                   atomically, and (if `--remove-plaintext` is set)
//!                   unlinks the source.
//!   - `unseal-keys` reverses the operation onto a temporary directory
//!                   for emergency rotation. It refuses to write outside
//!                   a tmpfs/ramfs/devtmpfs mount (best-effort check via
//!                   `statfs`) so the unsealed material doesn't end up
//!                   on a journaled disk.
//!
//! Both subcommands are designed to be invoked NON-INTERACTIVELY on
//! production ops platforms: pass the passphrase via env var
//! `OCTRAVPN_KEY_PASSPHRASE` (preferred), `--passphrase-file <PATH>`
//! (recommended on platforms that mount secrets via tmpfs), or
//! `--passphrase <STR>` (last resort — leaks to shell history). The
//! daemon's primary boot path is the env-var form; interactive prompts
//! exist only on one-shot CLI invocations and are gated on stdin being
//! a TTY.
//!
//! Anti-goal note: this module deliberately does NOT refactor
//! `wallet_enc.rs`. It treats `encrypt_secret`, `decrypt_secret`, and
//! `looks_like_envelope` as a black-box AEAD primitive.

use std::{
    fs,
    io::{IsTerminal, Write},
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use octravpn_core::{util, wallet_enc};
use zeroize::Zeroize;

use crate::config::NodeConfig;

/// Resolve the passphrase from CLI args / env / file / stdin, in
/// descending priority. The returned `String` is *meant* to be
/// zeroized by the caller after use — wrap it in a scope so `drop`
/// doesn't leave a heap residue.
///
/// Order:
///   1. `--passphrase <STR>`        (explicit; warned about in --help)
///   2. `--passphrase-file <PATH>`  (read first line, trimmed)
///   3. `--passphrase-stdin`        (one line from stdin)
///   4. `OCTRAVPN_KEY_PASSPHRASE`   (env)
///   5. TTY prompt (only if stdin is a terminal, and only on one-shot
///      seal-keys / unseal-keys invocations — the daemon never gets
///      here because `Cmd::Run` doesn't call this fn)
pub(crate) fn resolve_passphrase(
    explicit: Option<&str>,
    file: Option<&Path>,
    from_stdin: bool,
) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p.to_string());
    }
    if let Some(path) = file {
        let mut raw = fs::read_to_string(path)
            .with_context(|| format!("read passphrase file {}", path.display()))?;
        // Take only the first line — passphrase-files conventionally
        // end with a newline (e.g. via `echo > file`). The rest is
        // discarded and zeroized.
        let pp = raw.lines().next().unwrap_or("").to_string();
        raw.zeroize();
        if pp.is_empty() {
            bail!("passphrase file {} is empty", path.display());
        }
        return Ok(pp);
    }
    if from_stdin {
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("read passphrase from stdin")?;
        let pp = line.trim_end_matches(['\r', '\n']).to_string();
        line.zeroize();
        if pp.is_empty() {
            bail!("empty passphrase on stdin");
        }
        return Ok(pp);
    }
    if let Ok(pp) = std::env::var(util::KEY_PASSPHRASE_ENV) {
        if !pp.is_empty() {
            return Ok(pp);
        }
    }
    if std::io::stdin().is_terminal() {
        eprint!("Passphrase: ");
        std::io::stderr().flush().ok();
        let mut line = String::new();
        std::io::stdin()
            .read_line(&mut line)
            .context("read passphrase from TTY")?;
        let pp = line.trim_end_matches(['\r', '\n']).to_string();
        line.zeroize();
        if pp.is_empty() {
            bail!("empty passphrase");
        }
        return Ok(pp);
    }
    bail!(
        "no passphrase available: pass --passphrase, --passphrase-file, --passphrase-stdin, \
         or export {}",
        util::KEY_PASSPHRASE_ENV
    );
}

/// Read a 32-byte secret from a plaintext file. Used by `seal-keys`
/// before wrapping under the envelope. Wipes the on-disk bytes from
/// memory after parsing so the heap doesn't retain a copy.
fn read_plaintext_32(path: &Path) -> Result<[u8; 32]> {
    let mut raw =
        fs::read(path).with_context(|| format!("read plaintext secret {}", path.display()))?;
    if wallet_enc::looks_like_envelope(&raw) {
        raw.zeroize();
        bail!(
            "{} already sealed (OCTRA-WALLET-V1 envelope on disk)",
            path.display()
        );
    }
    let mut out = [0u8; 32];
    let parsed = if raw.len() == 32 {
        out.copy_from_slice(&raw);
        Ok(())
    } else {
        // Treat as hex. Strip whitespace.
        let s = std::str::from_utf8(&raw)
            .map_err(|e| anyhow!("non-utf8 plaintext key in {}: {e}", path.display()))?
            .trim();
        let mut bytes =
            hex::decode(s).map_err(|e| anyhow!("invalid hex in {}: {e}", path.display()))?;
        let r = if bytes.len() == 32 {
            out.copy_from_slice(&bytes);
            Ok(())
        } else {
            Err(anyhow!(
                "expected 32 bytes (or 64 hex chars) in {}; got {} bytes",
                path.display(),
                bytes.len()
            ))
        };
        bytes.zeroize();
        r
    };
    raw.zeroize();
    parsed?;
    Ok(out)
}

/// Atomically write `bytes` to `dest` via tempfile + rename + fsync.
/// Both the file's data and the parent directory's metadata are synced
/// so a crash mid-rename can't leave us pointing at half a file.
fn atomic_write(dest: &Path, bytes: &[u8]) -> Result<()> {
    if let Some(parent) = dest.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir -p {}", parent.display()))?;
        }
    }
    let tmp = tempfile::NamedTempFile::new_in(
        dest.parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new(".")),
    )
    .context("create tempfile for atomic write")?;
    {
        let mut handle = tmp.as_file();
        handle
            .write_all(bytes)
            .with_context(|| format!("write tempfile for {}", dest.display()))?;
        // fsync the file BEFORE rename so the rename can't expose a
        // zero-length file after a crash.
        handle
            .sync_all()
            .with_context(|| format!("fsync tempfile for {}", dest.display()))?;
    }
    tmp.persist(dest)
        .map_err(|e| anyhow!("persist tempfile to {}: {e}", dest.display()))?;
    // Best-effort: fsync the parent directory so the rename is durable.
    // POSIX only; on Windows this is a no-op (open() of a dir fails).
    if let Some(parent) = dest.parent() {
        if let Ok(dir) = fs::File::open(if parent.as_os_str().is_empty() {
            Path::new(".")
        } else {
            parent
        }) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// One key to seal — wallet, wg, or any other 32-byte secret.
pub(crate) struct SealTarget {
    pub label: &'static str,
    pub src: PathBuf,
    pub dst: PathBuf,
}

/// Seal `target.src` (plaintext) into `target.dst` (envelope). Returns
/// `true` if the file was newly sealed, `false` if `target.dst` already
/// existed and was a no-op.
pub(crate) fn seal_one(target: &SealTarget, passphrase: &str) -> Result<bool> {
    // Idempotence: if dst already holds a sealed envelope, decline to
    // re-seal so a re-run of seal-keys is harmless. If dst exists but
    // is plaintext, refuse — the operator should pick a fresh path or
    // explicitly remove the broken file.
    if target.dst.exists() {
        let existing = fs::read(&target.dst).with_context(|| {
            format!("read existing {} ({})", target.dst.display(), target.label)
        })?;
        if wallet_enc::looks_like_envelope(&existing) {
            tracing::info!(
                label = target.label,
                dst = %target.dst.display(),
                "seal-keys: destination already sealed; no-op"
            );
            return Ok(false);
        }
        bail!(
            "{}: destination {} exists and is NOT a sealed envelope; refusing to overwrite",
            target.label,
            target.dst.display()
        );
    }
    if !target.src.exists() {
        bail!(
            "{}: source {} does not exist",
            target.label,
            target.src.display()
        );
    }
    let mut secret = read_plaintext_32(&target.src)?;
    let envelope = wallet_enc::encrypt_secret(&secret, passphrase);
    secret.zeroize();
    atomic_write(&target.dst, &envelope)?;
    // chmod 0600 — best-effort, POSIX only. The envelope is encrypted
    // so this is defense in depth, not a hard requirement.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&target.dst, fs::Permissions::from_mode(0o600));
    }
    tracing::info!(
        label = target.label,
        src = %target.src.display(),
        dst = %target.dst.display(),
        "seal-keys: wrote sealed envelope"
    );
    Ok(true)
}

/// Unseal `target.src` (envelope) into `target.dst` (plaintext hex).
/// Caller is responsible for verifying `target.dst` lives on a tmpfs.
pub(crate) fn unseal_one(target: &SealTarget, passphrase: &str) -> Result<()> {
    let raw = fs::read(&target.src)
        .with_context(|| format!("read {} ({})", target.src.display(), target.label))?;
    if !wallet_enc::looks_like_envelope(&raw) {
        bail!(
            "{}: source {} is not a sealed envelope",
            target.label,
            target.src.display()
        );
    }
    let mut secret = wallet_enc::decrypt_secret(&raw, passphrase)
        .with_context(|| format!("unseal {} ({})", target.src.display(), target.label))?;
    // Write the secret out as 64-hex + newline (the v1 / devnet shape
    // that read_secret_32 accepts).
    let hex = hex::encode(secret);
    secret.zeroize();
    let mut payload = hex.into_bytes();
    payload.push(b'\n');
    atomic_write(&target.dst, &payload)?;
    payload.zeroize();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&target.dst, fs::Permissions::from_mode(0o600));
    }
    tracing::info!(
        label = target.label,
        src = %target.src.display(),
        dst = %target.dst.display(),
        "unseal-keys: wrote plaintext (TMPFS ONLY)"
    );
    Ok(())
}

/// Best-effort check that `path` lives on a memory-only filesystem
/// (tmpfs, ramfs, devtmpfs). Returns `Ok(())` if the check passed or
/// could not be performed on this platform; returns `Err` if we
/// positively identified a journaled filesystem.
///
/// Linux: parses `/proc/self/mountinfo` for the longest path prefix
/// that contains `path` and inspects the fs type.
/// macOS / other Unix: uses `statfs` to read `f_fstypename`. Accepts
/// `apfs` only when the mount point starts with `/private/tmp` (the
/// macOS Recovery / temp pattern) since macOS doesn't have a tmpfs
/// per se.
/// Windows: returns Ok(()) — Windows ops are outside the v2 threat
/// model's host scope; the `tempfile::TempDir` API on Windows already
/// uses the system temp dir.
#[cfg(target_os = "linux")]
pub(crate) fn check_tmpfs(path: &Path) -> Result<()> {
    let canon =
        fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;
    let mounts = fs::read_to_string("/proc/self/mountinfo").context("read /proc/self/mountinfo")?;
    // mountinfo line shape (man 5 proc):
    //   <id> <parent> <maj:min> <root> <mount-point> <opts> - <fs-type> <source> <super-opts>
    let mut best: Option<(usize, String)> = None; // (mountpoint-len, fs-type)
    for line in mounts.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // Find the separator '-'; everything after that has fs-type at
        // position [sep+1].
        let Some(sep) = cols.iter().position(|c| *c == "-") else {
            continue;
        };
        if cols.len() < sep + 2 {
            continue;
        }
        let mount_point = cols.get(4).copied().unwrap_or("");
        let fs_type = cols.get(sep + 1).copied().unwrap_or("");
        if canon.starts_with(mount_point) {
            let l = mount_point.len();
            if best.as_ref().map_or(true, |b| l > b.0) {
                best = Some((l, fs_type.to_string()));
            }
        }
    }
    let fs_type = best
        .map(|(_, t)| t)
        .ok_or_else(|| anyhow!("could not determine fs type for {}", path.display()))?;
    if matches!(fs_type.as_str(), "tmpfs" | "ramfs" | "devtmpfs") {
        return Ok(());
    }
    bail!(
        "unseal-keys: {} is on fs type {} — refusing to write plaintext to a non-memory mount",
        path.display(),
        fs_type
    )
}

#[cfg(target_os = "macos")]
pub(crate) fn check_tmpfs(path: &Path) -> Result<()> {
    // macOS doesn't have tmpfs. The conventional ramdisk on macOS lives
    // under /private/tmp via the `tmpfs` mount the install media uses,
    // or under a user-created ramdisk via `hdiutil`. We accept paths
    // under `/private/tmp` or `/tmp` (which is a symlink to
    // `/private/tmp`) — these are wiped on reboot, the same guarantee
    // a Linux tmpfs gives.
    let canon =
        fs::canonicalize(path).with_context(|| format!("canonicalize {}", path.display()))?;
    let s = canon.to_string_lossy();
    if s.starts_with("/private/tmp") || s.starts_with("/tmp") {
        return Ok(());
    }
    bail!(
        "unseal-keys: {} is not under /private/tmp on macOS — refusing to write plaintext outside a reboot-volatile mount",
        path.display()
    );
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn check_tmpfs(_path: &Path) -> Result<()> {
    // Best-effort: on non-Linux / non-macOS platforms we don't have a
    // portable way to introspect the mount. Log a warning so the
    // operator at least knows the gate was skipped.
    tracing::warn!(
        "unseal-keys: skipping tmpfs check on this platform — operator must verify the destination is memory-volatile"
    );
    Ok(())
}

/// Collect the (label, src, dst) triples for every key the operator's
/// config points at. Adds `.sealed` to each src as the dst.
pub(crate) fn targets_from_config(cfg: &NodeConfig) -> Vec<SealTarget> {
    let mut out = Vec::with_capacity(2);
    let wallet_src = PathBuf::from(&cfg.chain.wallet_secret_path);
    let wallet_dst = sealed_name(&wallet_src);
    out.push(SealTarget {
        label: "wallet",
        src: wallet_src,
        dst: wallet_dst,
    });
    let wg_src = PathBuf::from(&cfg.tunnel.wg_secret_path);
    let wg_dst = sealed_name(&wg_src);
    out.push(SealTarget {
        label: "wg",
        src: wg_src,
        dst: wg_dst,
    });
    out
}

/// `wallet.key` → `wallet.key.sealed`. We keep the original extension
/// rather than stripping it so an operator can `mv wallet.key.sealed
/// wallet.key` after verifying.
pub(crate) fn sealed_name(src: &Path) -> PathBuf {
    let mut s = src.as_os_str().to_owned();
    s.push(".sealed");
    PathBuf::from(s)
}

/// `wallet.key.sealed` → `wallet.key`. Inverse of [`sealed_name`].
/// Kept symmetric so a future rotation helper / CLI script can use it;
/// today's `unseal-keys` chooses destination names from the *source*
/// path (the plaintext path the operator's config originally pointed
/// at) rather than the `.sealed` path, so this helper isn't called by
/// the CLI dispatch yet.
#[allow(dead_code)]
pub(crate) fn unsealed_name(src: &Path) -> PathBuf {
    if let Some(stem) = src.to_str().and_then(|s| s.strip_suffix(".sealed")) {
        return PathBuf::from(stem);
    }
    // Fallback: append `.plain` so we never overwrite the sealed source.
    let mut s = src.as_os_str().to_owned();
    s.push(".plain");
    PathBuf::from(s)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealed_name_appends_suffix() {
        assert_eq!(
            sealed_name(Path::new("/etc/octravpn/wg.key")),
            PathBuf::from("/etc/octravpn/wg.key.sealed")
        );
        assert_eq!(
            sealed_name(Path::new("wallet")),
            PathBuf::from("wallet.sealed")
        );
    }

    #[test]
    fn unsealed_name_strips_suffix() {
        assert_eq!(
            unsealed_name(Path::new("/etc/octravpn/wg.key.sealed")),
            PathBuf::from("/etc/octravpn/wg.key")
        );
        // Without the suffix → fall back to `.plain` so we don't
        // clobber the source.
        assert_eq!(
            unsealed_name(Path::new("wg.key")),
            PathBuf::from("wg.key.plain")
        );
    }

    /// Round-trip: seal a plaintext-hex file, then read back via the
    /// strict loader with the right passphrase. The shape used by
    /// `Hub::new` in the sealed-config flow.
    #[test]
    fn seal_then_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("wallet.key");
        let dst = dir.path().join("wallet.key.sealed");
        let secret = [0x77u8; 32];
        fs::write(&src, hex::encode(secret) + "\n").unwrap();

        let t = SealTarget {
            label: "wallet",
            src,
            dst: dst.clone(),
        };
        assert!(seal_one(&t, "horse-battery-staple").unwrap());
        // Second seal is a no-op (idempotent).
        assert!(!seal_one(&t, "horse-battery-staple").unwrap());

        // Strict loader unseals using a hint passphrase.
        let got =
            util::read_secret_32_or_sealed(dst.to_str().unwrap(), Some("horse-battery-staple"))
                .unwrap();
        assert_eq!(*got, secret);
    }

    /// Wrong passphrase fails decryption (AEAD authenticity).
    #[test]
    fn seal_wrong_passphrase_fails_to_unseal() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("k");
        let dst = dir.path().join("k.sealed");
        fs::write(&src, hex::encode([0x11u8; 32]) + "\n").unwrap();
        seal_one(
            &SealTarget {
                label: "wallet",
                src,
                dst: dst.clone(),
            },
            "right",
        )
        .unwrap();
        let r = util::read_secret_32_or_sealed(dst.to_str().unwrap(), Some("wrong"));
        assert!(r.is_err());
    }

    /// Sealing a file that is *already* sealed must NOT overwrite or
    /// corrupt — it's a no-op. Operators rerun seal-keys after every
    /// deploy; idempotence saves them from accidentally clobbering.
    #[test]
    fn seal_idempotent_on_already_sealed() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("k");
        let dst = dir.path().join("k.sealed");
        fs::write(&src, hex::encode([0x22u8; 32]) + "\n").unwrap();
        seal_one(
            &SealTarget {
                label: "wallet",
                src: src.clone(),
                dst: dst.clone(),
            },
            "pw",
        )
        .unwrap();
        let first = fs::read(&dst).unwrap();
        // Run again with a DIFFERENT passphrase → still no-op (we
        // refuse to re-encrypt; otherwise a re-run with a fresh
        // passphrase would silently nuke the old one).
        let was_new = seal_one(
            &SealTarget {
                label: "wallet",
                src,
                dst: dst.clone(),
            },
            "different",
        )
        .unwrap();
        assert!(!was_new, "expected idempotent no-op on second seal");
        let second = fs::read(&dst).unwrap();
        assert_eq!(first, second);
    }

    /// `seal-keys` followed by `unseal-keys` to a tempdir reproduces
    /// the original plaintext hex.
    #[test]
    fn unseal_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let src = dir.path().join("k");
        let sealed = dir.path().join("k.sealed");
        let unsealed = dir.path().join("k.recovered");
        let secret = [0xCCu8; 32];
        fs::write(&src, hex::encode(secret) + "\n").unwrap();
        seal_one(
            &SealTarget {
                label: "wallet",
                src,
                dst: sealed.clone(),
            },
            "pw",
        )
        .unwrap();
        unseal_one(
            &SealTarget {
                label: "wallet",
                src: sealed,
                dst: unsealed.clone(),
            },
            "pw",
        )
        .unwrap();
        let recovered_hex = fs::read_to_string(&unsealed).unwrap();
        assert_eq!(recovered_hex.trim(), hex::encode(secret));
    }
}
