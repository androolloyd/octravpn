//! `octravpn serve` / `octravpn funnel` subcommands.
//!
//! Both surfaces share a single on-disk registry — `~/.octravpn/serve.toml`
//! — with each entry carrying a `funnel: bool` discriminator. The
//! difference between the two CLI surfaces is purely in which value of
//! that flag they set; everything else (storage, listing, removal) is
//! shared.
//!
//! The store is intentionally minimal:
//!
//! ```toml
//! [[entries]]
//! local_port    = 8080
//! local_proto   = "tcp"
//! external_path = "/v1"
//! funnel        = false
//! ```
//!
//! Entries are keyed by `local_port` in memory (BTreeMap) so writes are
//! deterministic — re-running `add` against the same port replaces the
//! previous entry, matching the runtime semantics of
//! `octravpn_mesh::ServeRegistry`.
//!
//! The actual packet-forwarding data-plane is a separate concern; this
//! module only owns the bookkeeping.

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Environment variable that overrides the default `~/.octravpn` config
/// directory. Used by integration tests so they don't touch the
/// developer's real home dir.
pub(crate) const SERVE_DIR_ENV: &str = "OCTRAVPN_SERVE_DIR";

/// Operations shared by `serve` and `funnel`. The variants mirror the
/// CLI subcommands one-to-one.
#[derive(Clone, Debug)]
pub(crate) enum Op {
    Add { port: u16, path: String },
    Remove { port: u16 },
    List,
}

/// On-disk schema for `serve.toml`. The `entries` field is a `Vec` for
/// TOML friendliness, but we keep it sorted by `local_port` so two runs
/// against the same inputs produce byte-identical files.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub(crate) struct ServeFile {
    #[serde(default)]
    pub entries: Vec<PersistedEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
pub(crate) struct PersistedEntry {
    pub local_port: u16,
    pub local_proto: String,
    pub external_path: String,
    pub funnel: bool,
}

/// Run a `serve` subcommand (`funnel = false`).
pub(crate) fn run_serve(op: Op) -> Result<()> {
    run(op, false)
}

/// Run a `funnel` subcommand (`funnel = true`).
pub(crate) fn run_funnel(op: Op) -> Result<()> {
    run(op, true)
}

fn run(op: Op, funnel_flag: bool) -> Result<()> {
    let path = serve_toml_path()?;
    let label = if funnel_flag { "funnel" } else { "serve" };

    match op {
        Op::Add { port, path: ext } => {
            let mut map = load_as_map(&path)?;
            map.insert(
                port,
                PersistedEntry {
                    local_port: port,
                    local_proto: "tcp".into(),
                    external_path: ext.clone(),
                    funnel: funnel_flag,
                },
            );
            save_from_map(&path, &map)?;
            println!("added {label} entry: tcp/{port} -> {ext} (funnel={funnel_flag})");
        }
        Op::Remove { port } => {
            let mut map = load_as_map(&path)?;
            let removed = map.remove(&port).is_some();
            save_from_map(&path, &map)?;
            if removed {
                println!("removed {label} entry for port {port}");
            } else {
                println!("no {label} entry for port {port}");
            }
        }
        Op::List => {
            let map = load_as_map(&path)?;
            let filtered: Vec<_> = map
                .values()
                .filter(|e| e.funnel == funnel_flag)
                .collect();
            if filtered.is_empty() {
                println!("no {label} entries");
            } else {
                println!("PORT   PROTO  PATH                  FUNNEL");
                for e in filtered {
                    println!(
                        "{port:<6} {proto:<6} {path:<22} {funnel}",
                        port = e.local_port,
                        proto = e.local_proto,
                        path = e.external_path,
                        funnel = e.funnel,
                    );
                }
            }
        }
    }
    Ok(())
}

/// Resolve the path to `serve.toml`, honoring `OCTRAVPN_SERVE_DIR` so
/// tests can sandbox the registry. Falls back to `~/.octravpn/`.
pub(crate) fn serve_toml_path() -> Result<PathBuf> {
    let dir = serve_dir()?;
    Ok(dir.join("serve.toml"))
}

fn serve_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(SERVE_DIR_ENV) {
        return Ok(PathBuf::from(dir));
    }
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("HOME not set; set OCTRAVPN_SERVE_DIR to override")?;
    Ok(home.join(".octravpn"))
}

fn load_as_map(path: &Path) -> Result<BTreeMap<u16, PersistedEntry>> {
    let file = load_file(path)?;
    let mut map = BTreeMap::new();
    for e in file.entries {
        map.insert(e.local_port, e);
    }
    Ok(map)
}

fn save_from_map(path: &Path, map: &BTreeMap<u16, PersistedEntry>) -> Result<()> {
    let entries: Vec<PersistedEntry> = map.values().cloned().collect();
    save_file(path, &ServeFile { entries })
}

fn load_file(path: &Path) -> Result<ServeFile> {
    if !path.exists() {
        return Ok(ServeFile::default());
    }
    let s = fs::read_to_string(path)
        .with_context(|| format!("read {}", path.display()))?;
    let f: ServeFile = toml::from_str(&s)
        .with_context(|| format!("parse {}", path.display()))?;
    Ok(f)
}

fn save_file(path: &Path, file: &ServeFile) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("mkdir {}", parent.display()))?;
    }
    let s = toml::to_string_pretty(file)
        .with_context(|| format!("serialise {}", path.display()))?;
    fs::write(path, s).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn with_env_dir<F: FnOnce()>(dir: &Path, f: F) {
        // The integration tests run a subprocess so they don't race
        // here; in-process tests inside this module are serialized via
        // the unit-test runner because we touch a process-global env
        // var. The runner is single-threaded for `cargo test --test`
        // by default for tests in the same module by virtue of the
        // mutex below.
        let _g = ENV_MUTEX.lock();
        std::env::set_var(SERVE_DIR_ENV, dir);
        f();
        std::env::remove_var(SERVE_DIR_ENV);
    }

    static ENV_MUTEX: parking_lot::Mutex<()> = parking_lot::Mutex::new(());

    #[test]
    fn add_then_remove_roundtrip_via_file() {
        let dir = tempdir().unwrap();
        with_env_dir(dir.path(), || {
            run_serve(Op::Add {
                port: 8080,
                path: "/v1".into(),
            })
            .unwrap();
            let path = serve_toml_path().unwrap();
            let body = fs::read_to_string(&path).unwrap();
            assert!(body.contains("local_port = 8080"));
            assert!(body.contains("external_path = \"/v1\""));
            assert!(body.contains("funnel = false"));

            run_serve(Op::Remove { port: 8080 }).unwrap();
            let body2 = fs::read_to_string(&path).unwrap();
            assert!(!body2.contains("local_port = 8080"));
        });
    }

    #[test]
    fn funnel_sets_funnel_true() {
        let dir = tempdir().unwrap();
        with_env_dir(dir.path(), || {
            run_funnel(Op::Add {
                port: 9000,
                path: "/pub".into(),
            })
            .unwrap();
            let path = serve_toml_path().unwrap();
            let body = fs::read_to_string(&path).unwrap();
            assert!(body.contains("local_port = 9000"));
            assert!(body.contains("funnel = true"));
        });
    }

    #[test]
    fn second_add_replaces_first() {
        let dir = tempdir().unwrap();
        with_env_dir(dir.path(), || {
            run_serve(Op::Add {
                port: 8080,
                path: "/v1".into(),
            })
            .unwrap();
            run_serve(Op::Add {
                port: 8080,
                path: "/v2".into(),
            })
            .unwrap();
            let path = serve_toml_path().unwrap();
            let body = fs::read_to_string(&path).unwrap();
            // Only one `[[entries]]` block.
            assert_eq!(body.matches("[[entries]]").count(), 1);
            assert!(body.contains("external_path = \"/v2\""));
        });
    }
}
