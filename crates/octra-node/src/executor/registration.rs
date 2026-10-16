//! Read-only native registration comparison. Only key_switch execution binds a
//! new PVAC hash in canonical state; this compatibility API never writes keys.
use super::Native;
use octra_node_protocol::registration_rpc::{Existing, Pvac};
use octra_node_runtime::execution::Error;
use std::io::Read;

impl Native {
    pub(crate) fn registration_existing(
        &self,
        committed: &crate::Committed,
        request: &Pvac,
    ) -> Result<Existing, Error> {
        if !octra_node_protocol::transaction::is_valid_address(&request.address) {
            return Err(Error("invalid public key address".into()));
        }
        match committed.state().get(&[b"pvac_hashes", &request.address]) {
            Some(b"none") => Ok(Existing::Absent),
            Some(hash) => {
                let raw = self
                    .key_blob(hash)?
                    .ok_or_else(|| Error("pvac blob unavailable".into()))?;
                Ok(if raw == request.incoming {
                    Existing::Same
                } else {
                    Existing::Different
                })
            }
            None => Ok(self.legacy_registration_existing(request)),
        }
    }
    fn legacy_registration_existing(&self, request: &Pvac) -> Existing {
        // Ledger.get_pvac_pubkey retains this local-file fallback only when no
        // canonical binding exists. A validated address cannot escape its directory.
        let Ok(address) = std::str::from_utf8(&request.address) else {
            return Existing::Absent;
        };
        let path = self.config.pvac_dir.join(format!("{address}.pk"));
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(
                (rustix::fs::OFlags::NOFOLLOW | rustix::fs::OFlags::NONBLOCK).bits() as i32,
            );
        }
        let Ok(mut file) = options.open(path) else {
            return Existing::Absent;
        };
        let Ok(metadata) = file.metadata() else {
            return Existing::Absent;
        };
        if !metadata.is_file() {
            return Existing::Absent;
        }
        if metadata.len() != request.incoming.len() as u64 {
            return Existing::Different;
        }
        // Incoming registration is bounded to 5MB. A differently sized legacy
        // blob is already unequal and never needs to be allocated.
        let mut raw = vec![0; request.incoming.len()];
        if file.read_exact(&mut raw).is_err() {
            Existing::Absent
        } else if raw == request.incoming {
            Existing::Same
        } else {
            Existing::Different
        }
    }
}
