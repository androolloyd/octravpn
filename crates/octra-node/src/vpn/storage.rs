//! Receipt floors belong to the full chain/application domain, independent of
//! transport key or code rotations. Legacy files are never silently adopted.
use super::Application;
use anyhow::{ensure, Context, Result};
use octra_exex::ChainIdentity;
use octravpn_core::receipt::ReceiptContext;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    fs::OpenOptions,
    io::Read,
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Binding {
    version: u32,
    chain: ChainIdentity,
    application: Application,
    domain: ReceiptContext,
}
pub(crate) struct Directories {
    pub receipts: PathBuf,
    pub claims: PathBuf,
}
fn read(path: &Path) -> Result<Option<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(
            (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
        );
    }
    let mut file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= 16_384,
        "invalid VPN scope manifest"
    );
    let mut bytes = Vec::new();
    file.by_ref().take(16_385).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= 16_384, "VPN scope manifest exceeds bound");
    Ok(Some(bytes))
}
fn directory(path: &Path) -> Result<bool> {
    match std::fs::symlink_metadata(path) {
        Ok(meta) => {
            ensure!(
                meta.is_dir() && !meta.file_type().is_symlink(),
                "VPN storage directory must be regular"
            );
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                ensure!(
                    meta.permissions().mode() & 0o022 == 0,
                    "VPN storage directory is writable by another user"
                );
            }
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}
#[allow(clippy::verbose_bit_mask)] // The octal mask directly expresses private Unix permission bits.
fn private_directory(path: &Path) -> Result<()> {
    if directory(path)? {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                std::fs::metadata(path)?.permissions().mode() & 0o077 == 0,
                "VPN scope directory must be private"
            );
        }
        return Ok(());
    }
    let mut builder = std::fs::DirBuilder::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    Ok(())
}
pub(crate) fn transport_book(data: &Path, config: &mut octravpn_node::embedded::IpTunnelConfig) {
    if config.address_book.is_none() {
        config.address_book = Some(
            data.join("vpn")
                .join(format!("ip-owners-{}.bin", config.name)),
        );
    }
}
fn only_transport_books(base: &Path) -> Result<bool> {
    for (count, entry) in std::fs::read_dir(base)?.enumerate() {
        ensure!(count < 4096, "legacy VPN directory exceeds entry bound");
        let entry = entry?;
        let name = entry.file_name();
        let Some(interface) = name
            .to_str()
            .and_then(|s| s.strip_prefix("ip-owners-"))
            .and_then(|s| s.strip_suffix(".bin"))
        else {
            return Ok(false);
        };
        if interface.is_empty()
            || interface.len() > 15
            || !interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
        {
            return Ok(false);
        }
        let metadata = std::fs::symlink_metadata(entry.path())?;
        if !metadata.is_file() || metadata.file_type().is_symlink() {
            return Ok(false);
        }
    }
    Ok(true)
}
fn legacy(base: &Path, expected: &Binding, identity: &str, context: &str) -> Result<bool> {
    if !directory(base)? {
        return Ok(false);
    }
    if let Some(bytes) = read(&base.join("scope.json"))? {
        let prior: Binding = serde_json::from_slice(&bytes)?;
        ensure!(prior.version == 1, "unsupported legacy VPN scope version");
        return Ok(prior == *expected);
    }
    if let Some(bytes) = read(&base.join(identity))? {
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        let domain: ReceiptContext = serde_json::from_value(
            value
                .get(context)
                .context("legacy VPN receipt identity unavailable")?
                .clone(),
        )?;
        ensure!(domain!=expected.domain,"legacy paid VPN storage {} lacks an authenticated full chain/application binding; explicit evidence-verified migration is required",base.display());
        // A different signed receipt domain cannot replay into this one. Its
        // original files and identity guard remain untouched.
        return Ok(false);
    }
    ensure!(
        (identity == "vpn-identity.json" && only_transport_books(base)?)
            || std::fs::read_dir(base)?.next().is_none(),
        "unbound legacy VPN storage {}; explicit evidence-verified migration is required",
        base.display()
    );
    Ok(false)
}
#[allow(clippy::needless_pass_by_value)] // Keep the owned authenticated domain at the blocking namespace boundary.
fn open(data: &Path, binding: Binding) -> Result<Directories> {
    let bytes = serde_json::to_vec(&binding)?;
    let mut hash = Sha256::new();
    hash.update(b"octra:native-vpn:storage:v1\0");
    hash.update(&bytes);
    let scopes = data.join("vpn-scopes");
    private_directory(&scopes)?;
    let scoped = scopes.join(hex::encode(hash.finalize()));
    let old_receipts = data.join("vpn");
    let old_claims = data.join("vpn-claims");
    let use_receipts = legacy(&old_receipts, &binding, "vpn-identity.json", "context")?;
    let use_claims = legacy(&old_claims, &binding, "identity.json", "domain")?;
    private_directory(&scoped)?;
    let manifest = scoped.join("scope.json");
    if let Some(raw) = read(&manifest)? {
        let prior: Binding =
            serde_json::from_slice(&raw).context("decode existing VPN scope binding")?;
        ensure!(
            prior == binding,
            "VPN scope binding differs from the full chain/application domain"
        );
    } else {
        ensure!(
            std::fs::read_dir(&scoped)?.next().is_none(),
            "partially populated VPN namespace lacks its binding"
        );
        crate::storage::publish(&manifest, &bytes)?;
    }
    Ok(Directories {
        receipts: if use_receipts {
            old_receipts
        } else {
            scoped.join("receipts")
        },
        claims: if use_claims {
            old_claims
        } else {
            scoped.join("claims")
        },
    })
}
pub(crate) async fn paid(
    data: &Path,
    chain: &ChainIdentity,
    application: Application,
    domain: &ReceiptContext,
) -> Result<Directories> {
    let data = data.to_owned();
    let binding = Binding {
        version: 1,
        chain: chain.clone(),
        application,
        domain: domain.clone(),
    };
    tokio::task::spawn_blocking(move || open(&data, binding)).await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use octra_exex::StateRoot;
    use octravpn_core::Address;
    fn binding() -> Binding {
        Binding {
            version: 1,
            chain: ChainIdentity::genesis("local-storage", StateRoot([7; 32])),
            application: Application::Program,
            domain: ReceiptContext::v2(
                Address::from_pubkey(&[3; 32]),
                9,
                Address::from_pubkey(&[4; 32]),
            ),
        }
    }
    fn legacy_receipts(data: &Path, binding: &Binding, bound: bool) {
        let path = data.join("vpn");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("vpn-identity.json"),
            serde_json::to_vec(&serde_json::json!({"version":1,"context":binding.domain})).unwrap(),
        )
        .unwrap();
        std::fs::write(
            path.join("receipt-sequence.bin"),
            b"retained original floor",
        )
        .unwrap();
        if bound {
            std::fs::write(
                path.join("scope.json"),
                serde_json::to_vec(binding).unwrap(),
            )
            .unwrap();
        }
    }
    #[test]
    fn native_vpn_directories_unfunded_and_paid_domains_coexist_and_restart() {
        let root = tempfile::tempdir().unwrap();
        let mut unfunded = binding();
        unfunded.domain.program_addr = Address::from_pubkey(&[8; 32]);
        legacy_receipts(root.path(), &unfunded, false);
        let first = open(root.path(), binding()).unwrap();
        assert_ne!(first.receipts, root.path().join("vpn"));
        std::fs::create_dir(&first.receipts).unwrap();
        std::fs::write(first.receipts.join("receipt-sequence.bin"), b"paid floor").unwrap();
        let second = open(root.path(), binding()).unwrap();
        assert_eq!(first.receipts, second.receipts);
        assert_eq!(first.claims, second.claims);
        assert_eq!(
            std::fs::read(second.receipts.join("receipt-sequence.bin")).unwrap(),
            b"paid floor"
        );
        assert_eq!(
            std::fs::read(root.path().join("vpn/receipt-sequence.bin")).unwrap(),
            b"retained original floor"
        );
        let text = String::from_utf8(serde_json::to_vec(&binding()).unwrap()).unwrap();
        assert!(!text.contains("key") && !text.contains("code"));
    }
    #[test]
    fn native_vpn_directories_reuse_only_fully_bound_legacy_identity() {
        let root = tempfile::tempdir().unwrap();
        legacy_receipts(root.path(), &binding(), true);
        assert_eq!(
            open(root.path(), binding()).unwrap().receipts,
            root.path().join("vpn")
        );
        let mut other = binding();
        other.application = Application::Circle;
        assert_ne!(
            open(root.path(), other).unwrap().receipts,
            root.path().join("vpn")
        );
        let mut other = binding();
        other.chain = ChainIdentity::checkpoint("local-storage", 10, StateRoot([7; 32]));
        assert_ne!(
            open(root.path(), other).unwrap().receipts,
            root.path().join("vpn")
        );
        assert_eq!(
            std::fs::read(root.path().join("vpn/receipt-sequence.bin")).unwrap(),
            b"retained original floor"
        );
    }
    #[test]
    fn native_vpn_directories_refuse_ambiguous_paid_legacy_without_resetting_floors() {
        let root = tempfile::tempdir().unwrap();
        legacy_receipts(root.path(), &binding(), false);
        let Err(error) = open(root.path(), binding()) else {
            panic!("unbound paid receipt adopted")
        };
        assert!(error.to_string().contains("evidence-verified migration"));
        assert_eq!(
            std::fs::read(root.path().join("vpn/receipt-sequence.bin")).unwrap(),
            b"retained original floor"
        );
    }
    #[test]
    fn native_vpn_directories_reject_unbound_paid_claims_and_partial_namespace() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("vpn-claims");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(
            path.join("identity.json"),
            serde_json::to_vec(
                &serde_json::json!({"version":1,"chain":binding().chain,"domain":binding().domain}),
            )
            .unwrap(),
        )
        .unwrap();
        assert!(open(root.path(), binding()).is_err());
        std::fs::remove_file(path.join("identity.json")).unwrap();
        std::fs::remove_dir(&path).unwrap();
        let dirs = open(root.path(), binding()).unwrap();
        let scope = dirs.receipts.parent().unwrap();
        std::fs::remove_file(scope.join("scope.json")).unwrap();
        std::fs::write(scope.join("partial"), b"unbound").unwrap();
        assert!(open(root.path(), binding()).is_err());
    }
    #[test]
    fn native_vpn_directories_keep_kernel_ownership_global_across_application_scopes() {
        let root = tempfile::tempdir().unwrap();
        let mut config = octravpn_node::embedded::IpTunnelConfig {
            name: "vpn-node".into(),
            address_book: None,
        };
        transport_book(root.path(), &mut config);
        let book = config.address_book.clone().unwrap();
        assert_eq!(book, root.path().join("vpn/ip-owners-vpn-node.bin"));
        std::fs::create_dir(root.path().join("vpn")).unwrap();
        std::fs::write(&book, b"retained ownership").unwrap();
        let first = open(root.path(), binding()).unwrap();
        let mut other = binding();
        other.application = Application::Circle;
        let second = open(root.path(), other).unwrap();
        assert_ne!(first.receipts, second.receipts);
        transport_book(root.path(), &mut config);
        assert_eq!(config.address_book.as_ref(), Some(&book));
        assert_eq!(std::fs::read(&book).unwrap(), b"retained ownership");
        config.address_book = Some(root.path().join("explicit-owner-book"));
        transport_book(root.path(), &mut config);
        assert_eq!(
            config.address_book,
            Some(root.path().join("explicit-owner-book"))
        );
    }
    #[test]
    fn native_vpn_directories_reject_tampered_bindings_without_rewriting() {
        let root = tempfile::tempdir().unwrap();
        let dirs = open(root.path(), binding()).unwrap();
        let manifest = dirs.receipts.parent().unwrap().join("scope.json");
        let mut wrong_origin = binding();
        wrong_origin.chain = ChainIdentity::checkpoint("local-storage", 10, StateRoot([7; 32]));
        let mut wrong_app = binding();
        wrong_app.application = Application::Circle;
        let mut wrong_version = binding();
        wrong_version.version = 2;
        for prior in [wrong_origin, wrong_app, wrong_version] {
            let raw = serde_json::to_vec(&prior).unwrap();
            std::fs::write(&manifest, &raw).unwrap();
            assert!(open(root.path(), binding()).is_err());
            assert_eq!(std::fs::read(&manifest).unwrap(), raw);
        }
        let raw = serde_json::to_vec_pretty(&binding()).unwrap();
        std::fs::write(&manifest, &raw).unwrap();
        open(root.path(), binding()).unwrap();
        assert_eq!(std::fs::read(&manifest).unwrap(), raw);
        std::fs::write(&manifest, b"{").unwrap();
        assert!(open(root.path(), binding()).is_err());
        assert_eq!(std::fs::read(&manifest).unwrap(), b"{");
    }
    #[cfg(unix)]
    #[test]
    fn native_vpn_directories_require_private_scopes_and_preserve_readonly_legacy() {
        use std::os::unix::fs::PermissionsExt;
        let root = tempfile::tempdir().unwrap();
        let mut unfunded = binding();
        unfunded.domain.program_addr = Address::from_pubkey(&[8; 32]);
        legacy_receipts(root.path(), &unfunded, false);
        std::fs::set_permissions(
            root.path().join("vpn"),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        let dirs = open(root.path(), binding()).unwrap();
        let scopes = root.path().join("vpn-scopes");
        std::fs::set_permissions(&scopes, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(open(root.path(), binding()).is_err());
        std::fs::set_permissions(&scopes, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(
            dirs.receipts.parent().unwrap(),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(open(root.path(), binding()).is_err());
        std::fs::set_permissions(
            dirs.receipts.parent().unwrap(),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        std::fs::set_permissions(
            root.path().join("vpn"),
            std::fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert!(open(root.path(), binding()).is_err());
    }
}
