use super::Admission;
use octravpn_mesh::tailscale_wire::{RegistrationAdmission, RegistrationGate};
use std::sync::Arc;

pub(super) struct GuardedRegistration {
    admission: Admission,
    members: Option<Arc<dyn RegistrationGate>>,
    reserved: Option<[u8; 32]>,
}

impl GuardedRegistration {
    pub(super) fn new(admission: Admission, members: Option<Arc<dyn RegistrationGate>>) -> Self {
        Self {
            admission,
            members,
            reserved: None,
        }
    }

    pub(super) fn reserved(mut self, key: Option<[u8; 32]>) -> Self {
        self.reserved = key;
        self
    }
    fn check(&self) -> Result<(), String> {
        if (self.admission)() {
            Ok(())
        } else {
            Err("Octranet host is not serving authenticated state".into())
        }
    }
}

#[async_trait::async_trait]
impl RegistrationGate for GuardedRegistration {
    async fn admit(&self, request: RegistrationAdmission<'_>) -> Result<(), String> {
        self.check()?;
        if self
            .reserved
            .is_some_and(|key| hex::encode(key) == request.node_key_hex)
        {
            return Err("operator virtual key cannot register as a client".into());
        }
        if let Some(members) = &self.members {
            members.admit(request).await?;
        }
        self.check()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    fn request() -> RegistrationAdmission<'static> {
        RegistrationAdmission {
            node_key_hex: "node",
            machine_key_hex: "machine",
            hostname: None,
        }
    }

    struct Members {
        calls: Arc<AtomicUsize>,
        live: Arc<AtomicBool>,
        revoke: bool,
        allowed: bool,
    }
    #[async_trait::async_trait]
    impl RegistrationGate for Members {
        async fn admit(&self, _: RegistrationAdmission<'_>) -> Result<(), String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            tokio::task::yield_now().await;
            if self.revoke {
                self.live.store(false, Ordering::SeqCst);
            }
            if self.allowed {
                Ok(())
            } else {
                Err("not a member".into())
            }
        }
    }

    #[tokio::test]
    async fn availability_is_read_again_on_each_attempt() {
        let live = Arc::new(AtomicBool::new(false));
        let observed = live.clone();
        let gate =
            GuardedRegistration::new(Arc::new(move || observed.load(Ordering::SeqCst)), None);
        assert!(gate.admit(request()).await.is_err());
        live.store(true, Ordering::SeqCst);
        gate.admit(request()).await.unwrap();
        live.store(false, Ordering::SeqCst);
        assert!(gate.admit(request()).await.is_err());
    }

    #[tokio::test]
    async fn membership_is_preserved_and_unavailable_host_skips_it() {
        let live = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = live.clone();
        let gate = GuardedRegistration::new(
            Arc::new(move || observed.load(Ordering::SeqCst)),
            Some(Arc::new(Members {
                calls: calls.clone(),
                live: live.clone(),
                revoke: false,
                allowed: false,
            })),
        );
        assert!(gate.admit(request()).await.is_err());
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        live.store(true, Ordering::SeqCst);
        assert_eq!(gate.admit(request()).await.unwrap_err(), "not a member");
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn availability_loss_during_membership_await_refuses_registration() {
        let live = Arc::new(AtomicBool::new(true));
        let observed = live.clone();
        let gate = GuardedRegistration::new(
            Arc::new(move || observed.load(Ordering::SeqCst)),
            Some(Arc::new(Members {
                calls: Arc::new(AtomicUsize::new(0)),
                live,
                revoke: true,
                allowed: true,
            })),
        );
        assert!(gate.admit(request()).await.is_err());
    }
}
