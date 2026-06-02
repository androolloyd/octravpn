//! `WireStateBuilder` — construct a [`WireState`] with octra-sane
//! defaults baked in.
//!
//! `WireState` (defined upstream in `headscale-api`) carries ~14 fields,
//! most of which every octra embedder fills with the identical default.
//! Two call sites — `mesh serve` (`octravpn-node`'s `cli::mesh`) and the
//! chain-aware boot path (`hub::spawn`) — used to enumerate every field
//! by hand, so each upstream field addition (`pings`, `runtime_config`,
//! `mapresponse_debug`, …) broke *both* consumers in lock-step.
//!
//! This builder centralises the defaults in the crate that already owns
//! the `headscale-api` dependency: a new upstream field defaults here,
//! once, instead of rippling into every daemon call site. Only the
//! inputs that genuinely vary are exposed:
//!   - the five shared handles (`server_noise_key`, `preauth`,
//!     `ip_allocator`, `machines`, `policy`) plus the DERP map store, via
//!     [`WireStateBuilder::new`];
//!   - `knock` (defaults to disabled) and `base_domain` (defaults to
//!     `octra.test`), via chainable setters.

use std::sync::Arc;

use headscale_api::dns::{DnsConfigSpec, DnsStore};
use headscale_api::policy::PolicyStore;
use headscale_api::tailscale_wire::{
    DerpMapStore, IpAllocator, KnockConfig, MachineRegistry, MapResponseDebugStore, PingTracker,
    PreauthRedeemer, RegistrationCache, RuntimeConfigSnapshot, ServerNoiseKey, WireState,
};

/// Builds a [`WireState`] from the handles an octra wire surface must
/// supply, defaulting every other field. See the module docs for why
/// this lives here rather than at each call site.
pub struct WireStateBuilder {
    server_noise_key: Arc<ServerNoiseKey>,
    preauth: Arc<dyn PreauthRedeemer>,
    ip_allocator: Arc<dyn IpAllocator>,
    machines: Arc<MachineRegistry>,
    policy: Arc<PolicyStore>,
    derp_map: Arc<DerpMapStore>,
    knock: KnockConfig,
    base_domain: String,
}

impl WireStateBuilder {
    /// Start from the handles every octra wire surface must supply. The
    /// remaining `WireState` fields take octra defaults: no durable
    /// registration store, MagicDNS under `octra.test`, knock disabled,
    /// no public control URL, and fresh empty runtime/registration/ping
    /// caches. Override `knock` / `base_domain` via the setters.
    pub fn new(
        server_noise_key: Arc<ServerNoiseKey>,
        preauth: Arc<dyn PreauthRedeemer>,
        ip_allocator: Arc<dyn IpAllocator>,
        machines: Arc<MachineRegistry>,
        policy: Arc<PolicyStore>,
        derp_map: Arc<DerpMapStore>,
    ) -> Self {
        Self {
            server_noise_key,
            preauth,
            ip_allocator,
            machines,
            policy,
            derp_map,
            knock: KnockConfig::disabled(),
            base_domain: "octra.test".to_string(),
        }
    }

    /// Enable the PSK-gated knock layer (defaults to disabled).
    #[must_use]
    pub fn knock(mut self, knock: KnockConfig) -> Self {
        self.knock = knock;
        self
    }

    /// Set the MagicDNS base domain (defaults to `octra.test`).
    #[must_use]
    pub fn base_domain(mut self, base_domain: impl Into<String>) -> Self {
        self.base_domain = base_domain.into();
        self
    }

    /// Materialise the [`WireState`].
    #[must_use]
    pub fn build(self) -> WireState {
        WireState {
            server_noise_key: self.server_noise_key,
            preauth: self.preauth,
            ip_allocator: self.ip_allocator,
            machines: self.machines,
            registration_store: None,
            derp_map: self.derp_map,
            native_derp: None,
            policy: self.policy,
            knock: self.knock,
            dns: Arc::new(DnsStore::from_spec(DnsConfigSpec {
                base_domain: self.base_domain,
                ..Default::default()
            })),
            public_control_url: None,
            runtime_config: Arc::new(RuntimeConfigSnapshot::default()),
            registration_cache: Arc::new(RegistrationCache::new()),
            pings: Arc::new(PingTracker::new()),
            mapresponse_debug: Arc::new(MapResponseDebugStore::disabled()),
        }
    }
}
