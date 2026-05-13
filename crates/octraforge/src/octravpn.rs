//! Domain helpers for the `OctraVPN` AML program.
//!
//! Builds canonical JSON envelopes matching the AML method signatures
//! in `program/main.aml` and submits them via [`ForgeCtx::submit`].
//! Mirrors what a real client SDK would build.

use serde_json::{json, Value};

use crate::{ForgeCtx, SubmitError, SubmitResult};

/// Default address used as `from` when no prank is active.
pub const DEFAULT_CALLER: &str = "octFORGEDEFAULTCALLER000000000000000000001";

/// Stand-in HFHE pubkey + zero-ciphertext used by tests. Real Octra
/// keys are produced by the operator's wallet; the mock just stores
/// the bytes opaquely.
pub const MOCK_HFHE_PUBKEY: &str = "fefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefefe";
pub const MOCK_INITIAL_ENC_ZERO: &str =
    "00000000000000000000000000000000000000000000000000000000000000ab";

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

    /// Mark `addr` as an Octra protocol validator on the mock chain
    /// AND seed enough stake for `register_endpoint` to succeed. The
    /// AML no longer gates on validator status (uses stake), but
    /// keeping both turn-ons here keeps existing tests un-churned.
    pub fn become_octra_validator(&mut self, addr: &str) {
        self.app.add_octra_validator(addr);
        self.app.seed_endpoint_stake(addr, octravpn_mock_rpc::MIN_ENDPOINT_STAKE);
    }

    /// Seed `addr` with `amount` OU of operator stake, skipping the
    /// real `bond_endpoint` tx.
    pub fn seed_endpoint_stake(&mut self, addr: &str, amount: u64) {
        self.app.seed_endpoint_stake(addr, amount);
    }

    /// Set the program owner (governance wallet). Tests that exercise
    /// `gov_slash_operator` / `withdraw_program_treasury` need this.
    pub fn set_program_owner(&mut self, addr: &str) {
        self.app.set_owner(addr);
    }

    /// `bond_endpoint()` — value-bearing.
    pub fn call_bond_endpoint(&mut self, amount: u64) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "bond_endpoint",
            "params": [],
            "value": amount,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `unbond_endpoint()`.
    pub fn call_unbond_endpoint(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "unbond_endpoint",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `finalize_unbond()`.
    pub fn call_finalize_unbond(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "finalize_unbond",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `gov_slash_operator(operator_addr, reason)`. Owner only.
    pub fn call_gov_slash_operator(
        &mut self,
        operator: &str,
        reason: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "gov_slash_operator",
            "params": [operator, reason],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `register_endpoint(endpoint, wg_pubkey, hfhe_pubkey, initial_enc_zero, region, price_per_mb)`.
    ///
    /// Caller must have at least `MIN_ENDPOINT_STAKE` bonded.
    #[allow(clippy::too_many_arguments)]
    pub fn call_register_endpoint(
        &mut self,
        endpoint: &str,
        wg_pubkey_hex: &str,
        hfhe_pubkey_hex: &str,
        initial_enc_zero_hex: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_endpoint",
            "params": [
                endpoint,
                wg_pubkey_hex,
                hfhe_pubkey_hex,
                initial_enc_zero_hex,
                region,
                price_per_mb,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// Convenience over `call_register_endpoint` using mock HFHE values.
    pub fn call_register_endpoint_simple(
        &mut self,
        endpoint: &str,
        wg_pubkey_hex: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.call_register_endpoint(
            endpoint,
            wg_pubkey_hex,
            MOCK_HFHE_PUBKEY,
            MOCK_INITIAL_ENC_ZERO,
            region,
            price_per_mb,
        )
    }

    /// `update_endpoint(endpoint, region, price_per_mb)`.
    pub fn call_update_endpoint(
        &mut self,
        endpoint: &str,
        region: &str,
        price_per_mb: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_endpoint",
            "params": [endpoint, region, price_per_mb],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `rotate_keys(new_wg, new_hfhe, new_initial_enc_zero)`.
    pub fn call_rotate_keys(
        &mut self,
        new_wg_pubkey_hex: &str,
        new_hfhe_pubkey_hex: &str,
        new_initial_enc_zero_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "rotate_keys",
            "params": [
                new_wg_pubkey_hex,
                new_hfhe_pubkey_hex,
                new_initial_enc_zero_hex,
            ],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `retire_endpoint()`.
    pub fn call_retire_endpoint(&mut self) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "retire_endpoint",
            "params": [],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `create_tailnet(acl_policy)` — `value` is the initial treasury.
    pub fn call_create_tailnet(
        &mut self,
        acl_policy_hex: &str,
        treasury: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "create_tailnet",
            "params": [acl_policy_hex],
            "value": treasury,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `add_member(tailnet_id, member)`.
    pub fn call_add_member(
        &mut self,
        tailnet_id: &str,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "add_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `remove_member(tailnet_id, member)`.
    pub fn call_remove_member(
        &mut self,
        tailnet_id: &str,
        member: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "remove_member",
            "params": [tailnet_id, member],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `deposit_to_tailnet(tailnet_id)` — `value` is the deposit amount.
    pub fn call_deposit_to_tailnet(
        &mut self,
        tailnet_id: &str,
        amount: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "deposit_to_tailnet",
            "params": [tailnet_id],
            "value": amount,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `configure_tailnet_exit(tailnet_id, exit_addr)`.
    pub fn call_configure_tailnet_exit(
        &mut self,
        tailnet_id: &str,
        exit_addr: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "configure_tailnet_exit",
            "params": [tailnet_id, exit_addr],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `update_acl(tailnet_id, new_acl_policy)`.
    pub fn call_update_acl(
        &mut self,
        tailnet_id: &str,
        new_acl_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "update_acl",
            "params": [tailnet_id, new_acl_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `open_session(tailnet_id, exit_addr, max_pay)` — single-hop in v1.
    pub fn call_open_session(
        &mut self,
        tailnet_id: &str,
        exit_addr: &str,
        max_pay: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "open_session",
            "params": [tailnet_id, exit_addr, max_pay],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `settle_session(session_id, bytes_used)` — validator-only call.
    pub fn call_settle_session(
        &mut self,
        session_id: &str,
        bytes_used: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "settle_session",
            "params": [session_id, bytes_used],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `claim_no_show(session_id)`.
    pub fn call_claim_no_show(&mut self, session_id: &str) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_no_show",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `sweep_expired_session(session_id)`.
    pub fn call_sweep_expired_session(
        &mut self,
        session_id: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "sweep_expired_session",
            "params": [session_id],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `claim_earnings(amount, proof)` — verifies FHE zero-proof.
    /// The mock simplifies the proof to an exact-equality check.
    pub fn call_claim_earnings(
        &mut self,
        amount: u64,
        proof_hex: &str,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "claim_earnings",
            "params": [amount, proof_hex],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `withdraw_program_treasury(to, amount)`. Owner only.
    pub fn call_withdraw_program_treasury(
        &mut self,
        to: &str,
        amount: u64,
    ) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "withdraw_program_treasury",
            "params": [to, amount],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `register_device(device_addr)`.
    pub fn call_register_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "register_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }

    /// `revoke_device(device_addr)`.
    pub fn call_revoke_device(&mut self, device: &str) -> Result<SubmitResult, SubmitError> {
        self.submit(json!({
            "kind": "contract_call",
            "from": DEFAULT_CALLER,
            "to": self.program_addr,
            "method": "revoke_device",
            "params": [device],
            "value": 0u64,
            "fee": 10u64,
            "nonce": 0u64,
        }))
    }
}

// Suppress unused-import warning when `Value` isn't otherwise referenced.
#[allow(dead_code)]
const _: fn() -> Value = || Value::Null;
