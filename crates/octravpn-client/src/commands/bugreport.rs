//! `octravpn bugreport` — collect a redacted diagnostic bundle.
//!
//! Produces a tar.gz archive at `out_path` containing:
//!
//! * `config.toml`      — the loaded `ClientConfig` re-serialised with secret
//!                        file *contents* redacted (paths are preserved).
//! * `system.txt`       — host OS / arch / `uname` / client version.
//! * `recent-logs/`     — best-effort copy of log files from
//!                        `~/.octravpn/logs/` and `/var/log/octravpn/`.
//! * `state.json`       — machine-readable snapshot: timestamp, config path,
//!                        wallet path, plus the same fields as `system.txt`.
//!
//! Tar entries are inserted in lexicographic order so two runs against the
//! same inputs produce byte-identical archives (modulo the timestamp inside
//! the bundle), which keeps snapshot-style tests stable.

use std::{
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use flate2::{write::GzEncoder, Compression};
use serde_json::json;

use crate::config::ClientConfig;

/// Run the `bugreport` subcommand.
pub(crate) fn run(config_path: &str, out_path: Option<&str>) -> Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let default_name = format!("./octravpn-bugreport-{ts}.tar.gz");
    let out = out_path.unwrap_or(&default_name);

    // Best-effort config load. If the config is missing or invalid the user
    // still benefits from a partial bundle with system info, so we capture
    // the load error as a string instead of failing outright.
    let (config_obj, config_load_error) = match ClientConfig::load(config_path) {
        Ok(c) => (Some(c), None),
        Err(e) => (None, Some(format!("{e:#}"))),
    };

    // Build all entries up front so we can sort by name.
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let redacted_config = render_redacted_config(config_obj.as_ref(), config_path);
    entries.push(("config.toml".into(), redacted_config.into_bytes()));

    let sys = SystemInfo::collect();
    entries.push(("system.txt".into(), sys.render_text().into_bytes()));

    let state = json!({
        "timestamp": ts,
        "config_path": config_path,
        "config_load_error": config_load_error,
        "wallet_path": config_obj.as_ref().map(|c| c.wallet.secret_path.clone()),
        "system": {
            "os":    sys.os,
            "arch":  sys.arch,
            "client_version": sys.client_version,
            "uname": sys.uname,
        }
    });
    let state_bytes = serde_json::to_vec_pretty(&state).context("serialise state.json")?;
    entries.push(("state.json".into(), state_bytes));

    // Collect logs from each candidate directory. Entries are namespaced by
    // their source directory's basename to avoid collisions between
    // `~/.octravpn/logs/foo.log` and `/var/log/octravpn/foo.log`.
    for (label, dir) in candidate_log_dirs() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for ent in rd.flatten() {
            let Ok(meta) = ent.metadata() else { continue };
            if !meta.is_file() {
                continue;
            }
            let name = ent.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            let arc_name = format!("recent-logs/{label}/{name_str}");
            // Skip anything containing "secret" or "wallet" in the file name
            // out of paranoia — these dirs should only hold logs, but we
            // belt-and-brace.
            if name_str.contains("secret") || name_str.contains("wallet") {
                continue;
            }
            if let Ok(bytes) = fs::read(ent.path()) {
                entries.push((arc_name, bytes));
            }
        }
    }

    // Deterministic ordering.
    entries.sort_by(|a, b| a.0.cmp(&b.0));

    write_archive(Path::new(out), &entries).with_context(|| format!("write archive {out}"))?;

    println!("wrote {out}");
    println!(
        "  config:  {} (secrets redacted)",
        if config_obj.is_some() {
            config_path
        } else {
            "<not loaded>"
        }
    );
    println!("  entries: {}", entries.len());
    Ok(())
}

/// Re-serialise the loaded config as TOML with secret file contents
/// redacted. When the config could not be loaded we emit a stub that points
/// the recipient at the source path so the bundle is still self-describing.
fn render_redacted_config(cfg: Option<&ClientConfig>, source_path: &str) -> String {
    if let Some(cfg) = cfg {
        // We intentionally rewrite by hand rather than using `toml::to_string`
        // — the `ClientConfig` struct is `Deserialize` only, and we want the
        // redaction policy to be obvious to reviewers.
        let v2_block =
            if cfg.is_v2() || cfg.v2.sealed_passphrase.is_some() || !cfg.v2.cache_dir.is_empty() {
                let pp_redaction = if cfg.v2.sealed_passphrase.is_some() {
                    "# sealed_passphrase: <redacted>"
                } else {
                    "# sealed_passphrase: (unset)"
                };
                format!(
                    "\n[v2]\nkey_id     = \"{kid}\"\ncache_dir  = \"{cache}\"\n{pp}\n",
                    kid = cfg.v2.key_id,
                    cache = cfg.v2.cache_dir,
                    pp = pp_redaction,
                )
            } else {
                String::new()
            };
        format!(
            r#"# octravpn bugreport — redacted snapshot of {src}

[chain]
rpc_url          = "{rpc}"
program_addr     = "{prog}"
protocol_version = "{proto}"

[wallet]
addr        = "{addr}"
secret_path = "{wallet}"
# secret file contents: <redacted>
{v2}"#,
            src = source_path,
            rpc = cfg.chain.rpc_url,
            prog = cfg.chain.program_addr,
            proto = cfg.chain.protocol_version,
            addr = cfg.wallet.addr,
            wallet = cfg.wallet.secret_path,
            v2 = v2_block,
        )
    } else {
        format!(
            "# octravpn bugreport\n# original config path: {source_path}\n# could not load config; see state.json for the error.\n"
        )
    }
}

struct SystemInfo {
    os: String,
    arch: String,
    client_version: String,
    uname: Option<String>,
}

impl SystemInfo {
    fn collect() -> Self {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();
        let client_version = env!("CARGO_PKG_VERSION").to_string();
        let uname = uname_output();
        Self {
            os,
            arch,
            client_version,
            uname,
        }
    }

    fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "os:             {}", self.os);
        let _ = writeln!(s, "arch:           {}", self.arch);
        let _ = writeln!(s, "client_version: {}", self.client_version);
        s.push_str("uname:\n");
        match &self.uname {
            Some(u) => {
                for line in u.lines() {
                    let _ = writeln!(s, "  {line}");
                }
            }
            None => s.push_str("  <unavailable>\n"),
        }
        s
    }
}

fn uname_output() -> Option<String> {
    #[cfg(unix)]
    {
        use std::process::Command;
        let out = Command::new("uname").arg("-a").output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }
    #[cfg(not(unix))]
    {
        None
    }
}

fn candidate_log_dirs() -> Vec<(&'static str, PathBuf)> {
    let mut out = Vec::new();
    if let Some(home) = home_dir() {
        out.push(("home", home.join(".octravpn").join("logs")));
    }
    out.push(("system", PathBuf::from("/var/log/octravpn")));
    out
}

fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

fn write_archive(out: &Path, entries: &[(String, Vec<u8>)]) -> Result<()> {
    if let Some(parent) = out.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).with_context(|| format!("mkdir {}", parent.display()))?;
        }
    }
    let file = fs::File::create(out).with_context(|| format!("create {}", out.display()))?;
    let gz = GzEncoder::new(file, Compression::default());
    let mut tar = tar::Builder::new(gz);
    // Don't follow symlinks — safer when scraping log dirs.
    tar.follow_symlinks(false);

    for (name, bytes) in entries {
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        // Fixed mtime keeps archives deterministic across runs.
        header.set_mtime(0);
        header.set_cksum();
        tar.append_data(&mut header, name, bytes.as_slice())
            .with_context(|| format!("append {name}"))?;
    }

    let gz = tar.into_inner().context("finalise tar")?;
    gz.finish().context("finalise gzip")?;
    Ok(())
}
