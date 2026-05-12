//! Domain helpers for the `OctraVPN` AML program.
//!
//! These functions build canonical JSON envelopes matching the AML
//! method signatures (see `program/main.aml`) and submit them via
//! [`ForgeCtx::submit`]. They mirror what a real client SDK would build,
//! so tests using these helpers exercise the same field structure the
//! HTTP RPC path expects.

use serde_json::{json, Value};

use crate::{ForgeCtx, SubmitError, SubmitResult};

/// Default address used as `from` when no prank is active.
pub const DEFAULT_CALLER: &str = "octFORGEDEFAULTCALLER000000000000000000001";

impl ForgeCtx {
    /// "Deploy" `OctraVPN`. The mock returns hard-coded params today;
    /// this is a no-op that returns the program address (matching
    /// Foundry's `forge.deploy_contract(...)` ergonomics).
    pub fn deploy_octravpn(
        &mut self,
        _min_session_deposit: u64,
        _min_tailnet_deposit: u64,
    ) -> String {
        self.program_addr.clone()
    }

    /// Mark `addr` as an Octra protocol validator on the mock chain.
    /// Required before `call_register_endpoint` will succeed.
    pub fn become_octra_validator(&mut self, addr: &str) {
        self.app.add_octra_validator(addr);
    }

    /// `register_endpoint(endpoint, wg_pubkey, receipt_pubkey, view_pubkey, region, price_per_mb)`.
    ///
    /// Caller (which defaults to [`DEFAULT_CALLER`] or the pranked address)
    /// must already be an Octra validator — see [`Self::become_octra_validator`].
    #[allow(clippy::too_many_arguments)]
    pub fn call_register_endpoint(
        &mut self,
        endpoint: &str,
        wg_pubkey_hex: &str,
        receipt_pubkey_hex: &str,
        view_pubkey_hex: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_endpoint",
            "params": [
                endpoint,
                wg_pubkey_hex,
                receipt_pubkey_hex,
                view_pubkey_hex,
                region,
                price_per_mb,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `update_endpoint(endpoint, region, price_per_mb)`.
    pub fn call_update_endpoint(
        &mut self,
        endpoint: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_endpoint",
            "params": [endpoint, region, price_per_mb],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `rotate_keys(wg, receipt, view)`.
    pub fn call_rotate_keys(
        &mut self,
        wg_pubkey_hex: &str,
        receipt_pubkey_hex: &str,
        view_pubkey_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "rotate_keys",
            "params": [wg_pubkey_hex, receipt_pubkey_hex, view_pubkey_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `retire_endpoint()`.
    pub fn call_retire_endpoint(&mut self) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "retire_endpoint",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `create_tailnet(acl_policy)` — `value` is the initial treasury.
    pub fn call_create_tailnet(
        &mut self,
        acl_policy_hex: &str,
        treasury: u64,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "create_tailnet",
            "params": [acl_policy_hex],
            "value": treasury,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `add_member(tailnet_id, member)`.
    pub fn call_add_member(
        &mut self,
        tailnet_id: &str,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "add_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `remove_member(tailnet_id, member)`.
    pub fn call_remove_member(
        &mut self,
        tailnet_id: &str,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "remove_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `deposit_to_tailnet(tailnet_id)` — `value` is the deposit amount.
    pub fn call_deposit_to_tailnet(
        &mut self,
        tailnet_id: &str,
        amount: u64,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "deposit_to_tailnet",
            "params": [tailnet_id],
            "value": amount,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `configure_tailnet_exit(tailnet_id, exit_addr)`.
    pub fn call_configure_tailnet_exit(
        &mut self,
        tailnet_id: &str,
        exit_addr: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "configure_tailnet_exit",
            "params": [tailnet_id, exit_addr],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `update_acl(tailnet_id, new_acl_policy)`.
    pub fn call_update_acl(
        &mut self,
        tailnet_id: &str,
        new_acl_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_acl",
            "params": [tailnet_id, new_acl_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `open_session(tailnet_id, route_commit, client_session_pubkey, deposit)`.
    pub fn call_open_session(
        &mut self,
        tailnet_id: &str,
        route_commit: &[&str],
        client_session_pubkey_hex: &str,
        deposit: u64,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "open_session",
            "params": [
                tailnet_id,
                route_commit,
                client_session_pubkey_hex,
                deposit,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `settle_session(session_id, seq, bytes_used, blind, client_sig, node_sig, route_open)`.
    ///
    /// `openings` is `[(node_addr, blind_hex, split_bps), ...]`.
    pub fn call_settle_session(
        &mut self,
        session_id: &str,
        seq: u64,
        bytes_used: u64,
        blind_hex: &str,
        openings: &[(&str, &str, u16)],
    ) -> Result<SubmitResult, SubmitError> {
        let openings_json: Vec<Value> = openings
            .iter()
            .map(|(addr, blind, split)| {
                json!({ "node_addr": addr, "blind": blind, "split_bps": *split })
            })
            .collect();
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_session",
            "params": [
                session_id,
                seq,
                bytes_used,
                blind_hex,
                "11".repeat(32),  // client_sig — mock ignores
                "22".repeat(32),  // node_sig   — mock ignores
                openings_json,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `claim_no_show(session_id)`.
    pub fn call_claim_no_show(&mut self, session_id: &str) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_no_show",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `sweep_expired_session(session_id)`.
    pub fn call_sweep_expired_session(
        &mut self,
        session_id: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "sweep_expired_session",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `claim_earnings(claimed_amount, claimed_blind, stealth_output)`.
    pub fn call_claim_earnings(
        &mut self,
        amount: u64,
        blind_hex: &str,
        stealth_output_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_earnings",
            "params": [amount, blind_hex, stealth_output_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `set_view_pubkey(pubkey)` — publish this wallet's X25519 view pubkey.
    pub fn call_set_view_pubkey(
        &mut self,
        view_pubkey_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "set_view_pubkey",
            "params": [view_pubkey_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `register_device(device_addr)` — attach a device to the calling wallet.
    pub fn call_register_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }

    /// `revoke_device(device_addr)`.
    pub fn call_revoke_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        let call = json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "revoke_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        });
        self.submit(call)
    }
}
