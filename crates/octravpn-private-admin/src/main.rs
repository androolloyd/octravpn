use anyhow::{ensure, Result};
use ark_bn254::Bn254;
use ark_groth16::{Groth16, ProvingKey};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{engine::general_purpose::STANDARD, Engine};
use clap::{Parser, Subcommand};
use octravpn_private_admin::{authorize, encode_vk, AdminCircuit, Credential, Request, CIRCUIT_ID};
use rand::{rngs::OsRng, RngCore};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(about = "Private AML administration; private witnesses never enter calldata")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Local single-party setup. Deliberately unavailable for production ceremonies.
    Setup {
        #[arg(long)]
        development: bool,
        #[arg(long)]
        out: PathBuf,
    },
    /// Recipient creates its own fresh credential; only commitment goes to sender.
    Credential {
        #[arg(long)]
        out: PathBuf,
    },
    /// Produce exact relayer calldata for a reviewed typed administration request.
    Authorize {
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        proving_key: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        domain: String,
        #[arg(long)]
        program: String,
        #[arg(long)]
        nonce: u64,
        #[arg(long)]
        out: PathBuf,
    },
}

fn write_new(path: &Path, data: &[u8], private: bool) -> Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(if private { 0o600 } else { 0o644 });
    }
    #[cfg(not(unix))]
    ensure!(
        !private,
        "private credential creation needs an OS permission implementation"
    );
    options.open(path)?.write_all(data)?;
    Ok(())
}

/// Check and read the same opened regular file; bound growth after metadata check.
fn read_input(path: &Path, limit: u64, private: bool) -> Result<Zeroizing<Vec<u8>>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    ensure!(metadata.is_file(), "input must be a regular file");
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::PermissionsExt;
        ensure!(
            metadata.permissions().mode().trailing_zeros() >= 6,
            "credential must be accessible only to its owner"
        );
    }
    #[cfg(not(unix))]
    ensure!(
        !private,
        "credential permission checking needs an OS implementation"
    );
    ensure!(metadata.len() <= limit, "input exceeds size bound");
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= limit, "input grew beyond size bound");
    Ok(bytes)
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Setup { development, out } => {
            ensure!(
                development,
                "single-party setup is test-only; pass --development for isolated tests"
            );
            fs::create_dir(&out)?;
            let pk = Groth16::<Bn254>::generate_random_parameters_with_reduction(
                AdminCircuit {
                    secret: [1; 32],
                    challenge: [2; 32],
                    commitment: [0; 32],
                    tag: [0; 32],
                },
                &mut OsRng,
            )?;
            let mut serialized = Vec::new();
            pk.serialize_compressed(&mut serialized)?;
            let vk = encode_vk(&pk.vk)?;
            write_new(&out.join("proving-key.bin"), &serialized, false)?;
            write_new(&out.join("verification-key.bin"), &vk, false)?;
            let manifest = json!({ "circuit": CIRCUIT_ID, "development_only": true, "production_ready": false, "verification_key_b64": STANDARD.encode(&vk), "verification_key_sha256": hex::encode(Sha256::digest(&vk)), "proving_key_sha256": hex::encode(Sha256::digest(&serialized)), "warning": "Production requires an independently reviewed circuit and a verified multiparty setup transcript." });
            write_new(
                &out.join("manifest.json"),
                &serde_json::to_vec_pretty(&manifest)?,
                false,
            )?;
            println!("Development setup created: {}", out.display());
        }
        Command::Credential { out } => {
            let mut secret = Zeroizing::new([0; 32]);
            OsRng.fill_bytes(secret.as_mut());
            write_new(&out, secret.as_ref(), true)?;
            let credential = Credential(secret);
            println!(
                "{}",
                json!({ "commitment": hex::encode(credential.commitment()) })
            );
        }
        Command::Authorize {
            credential,
            proving_key,
            request,
            domain,
            program,
            nonce,
            out,
        } => {
            let raw = read_input(&credential, 32, true)?;
            ensure!(raw.len() == 32, "credential must be exactly 32 bytes");
            let mut secret = Zeroizing::new([0; 32]);
            secret.copy_from_slice(&raw);
            let credential = Credential(secret);
            let raw = read_input(&proving_key, 256 * 1024 * 1024, false)?;
            let mut reader = raw.as_slice();
            let pk = ProvingKey::<Bn254>::deserialize_compressed(&mut reader)?;
            ensure!(reader.is_empty(), "trailing proving key bytes");
            let request: Request =
                serde_json::from_slice(&read_input(&request, 1024 * 1024, false)?)?;
            let authorization = authorize(&pk, &credential, &request, &domain, &program, nonce)?;
            write_new(&out, &serde_json::to_vec_pretty(&authorization)?, false)?;
            println!("Authorization created: {}", out.display());
        }
    }
    Ok(())
}
