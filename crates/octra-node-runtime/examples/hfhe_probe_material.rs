//! Generate retained test material for a fresh wallet's public FHE probe.
//! Does not contact a network or register/rotate a key.
use base64::{engine::general_purpose::STANDARD, Engine};
use octra_hfhe::keys::{keygen_from_seed, Params};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
};

fn write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let target = std::env::args_os()
        .nth(1)
        .ok_or("provide a fresh private directory")?;
    let target = Path::new(&target);
    fs::create_dir(target)?;
    fs::set_permissions(target, fs::Permissions::from_mode(0o700))?;
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    fs::File::open("/dev/urandom")?.read_exact(seed.as_mut())?;
    let (key, secret) = keygen_from_seed(Params::default(), &seed)?;
    let public = key.to_bytes()?;
    write(&target.join("public-key.bin"), &public)?;
    write(&target.join("secret-key.bin"), &secret.to_bytes())?;
    let report = serde_json::json!({"public_key_bytes": public.len(),
        "public_key_sha256":hex::encode(Sha256::digest(&public)),
        "serialized_key_sha256":hex::encode(Sha256::digest(STANDARD.encode(&public))),
        "aes_kat_hex":hex::encode(octra_hfhe::seeded_rng::aes_kat()),
        "registered":false});
    write(
        &target.join("public.json"),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    fs::File::open(target)?.sync_all()?;
    println!("{report}");
    Ok(())
}
