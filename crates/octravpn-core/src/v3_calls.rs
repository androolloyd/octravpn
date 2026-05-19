//! Shared builder for v3 (`program/main-v3.aml`) `contract_call`
//! JSON envelopes.
//!
//! Both the operator daemon (`octravpn-node::chain_v3`) and the client
//! CLI (`octravpn-client::chain_v3`) emit the legacy
//! `{"kind":"contract_call", "from", "to", "method", "params", "value",
//! "fee", "nonce"}` shape that `octra_core::tx::sign_call` translates
//! to the on-wire OctraTx envelope. Before this module existed each
//! crate carried its own `build_<method>_call` fan with hard-coded
//! method-name string literals and `json!({...})` boilerplate that
//! drifted independently — see `/tmp/simplify-reuse-review.md` (F2,
//! F4). This module is the single source of truth for the wire shape;
//! both consumers delegate every `build_*_call` to it so a future
//! schema change lands in exactly one place.
//!
//! The contract is intentionally minimal: a [`ContractCallBuilder`]
//! owns the program addr + caller wallet addr, and exposes one
//! `<method>_call(&self, params, value, fee, nonce) -> Value` per AML
//! entrypoint. Each method delegates to [`ContractCallBuilder::call`]
//! after substituting the corresponding [`method`] constant — so the
//! method name never appears as a stringly-typed literal at the call
//! site. Cross-reference against
//! `docker/devnet/{v3-smoke.sh, e2e-adversarial-v3.sh}` for the source-
//! of-truth wire shapes; the unit tests at the bottom pin each
//! method's exact JSON output.

use octra_core::address::Address;
use serde_json::{json, Value};

/// String constants for every v3 AML entrypoint covered by this
/// builder. Centralising them here means each call site uses
/// `method::REGISTER_CIRCLE` instead of repeating `"register_circle"`
/// as a string literal; a typo or rename becomes a compile error.
pub mod method {
    /// `payable register_circle(circle, state_root, receipt_pubkey)`.
    pub const REGISTER_CIRCLE: &str = "register_circle";
    /// `update_circle_state(circle, new_state_root)`.
    pub const UPDATE_CIRCLE_STATE: &str = "update_circle_state";
    /// `rotate_receipt_pubkey(circle, new_pubkey)`.
    pub const ROTATE_RECEIPT_PUBKEY: &str = "rotate_receipt_pubkey";
    /// `retire_circle(circle)`.
    pub const RETIRE_CIRCLE: &str = "retire_circle";
    /// `payable bond_endpoint(circle)`.
    pub const BOND_ENDPOINT: &str = "bond_endpoint";
    /// `unbond_endpoint(circle)`.
    pub const UNBOND_ENDPOINT: &str = "unbond_endpoint";
    /// `nonreentrant finalize_unbond(circle)`.
    pub const FINALIZE_UNBOND: &str = "finalize_unbond";
    /// `slash_double_sign(circle, payload_a, sig_a, payload_b, sig_b)`.
    pub const SLASH_DOUBLE_SIGN: &str = "slash_double_sign";
    /// `payable create_tailnet(members_root)`.
    pub const CREATE_TAILNET: &str = "create_tailnet";
    /// `update_members_root(tailnet_id, new_members_root)`.
    pub const UPDATE_MEMBERS_ROOT: &str = "update_members_root";
    /// `retire_tailnet(tailnet_id)`.
    pub const RETIRE_TAILNET: &str = "retire_tailnet";
    /// `payable deposit_to_tailnet(tailnet_id)`.
    pub const DEPOSIT_TO_TAILNET: &str = "deposit_to_tailnet";
    /// `withdraw_tailnet_treasury(tailnet_id, amount)`.
    pub const WITHDRAW_TAILNET_TREASURY: &str = "withdraw_tailnet_treasury";
    /// `open_session(tailnet_id, circle, max_pay) -> int`.
    pub const OPEN_SESSION: &str = "open_session";
    /// `settle_claim(session_id, bytes_used)`.
    pub const SETTLE_CLAIM: &str = "settle_claim";
    /// `nonreentrant settle_confirm(session_id, bytes_used, net, settle_blinding)`.
    pub const SETTLE_CONFIRM: &str = "settle_confirm";
    /// `claim_no_show(session_id)`.
    pub const CLAIM_NO_SHOW: &str = "claim_no_show";
    /// `nonreentrant sweep_expired_session(session_id)`.
    pub const SWEEP_EXPIRED_SESSION: &str = "sweep_expired_session";
    /// `nonreentrant claim_earnings(circle, amount)`.
    pub const CLAIM_EARNINGS: &str = "claim_earnings";
}

/// Builds the legacy `{"kind":"contract_call", ...}` JSON envelope
/// that `octra_core::tx::sign_call` translates into the on-wire
/// OctraTx shape. Owns the program addr + caller wallet addr; the
/// per-call inputs (params, value, fee, nonce) are supplied at call
/// time.
///
/// Both [`octravpn-node::chain_v3::ChainCtxV3`] and
/// [`octravpn-client::chain_v3::ChainCtxV3`] hold a private builder
/// internally and forward every `build_<method>_call` to the matching
/// method here. Adding a new AML entrypoint means:
///
/// 1. Add a `pub const FOO: &str = "foo"` to [`method`].
/// 2. Add a `pub fn foo_call(&self, ...)` here.
/// 3. Wire the consumer's `build_foo_call` to delegate.
///
/// The unit tests at the bottom of this module pin each method's
/// exact JSON shape; the consumers' own tests then check that their
/// delegation produces the same bytes.
#[derive(Clone, Debug)]
pub struct ContractCallBuilder {
    program_addr: Address,
    wallet_addr: Address,
}

impl ContractCallBuilder {
    /// Construct a builder for a given v3 program + caller wallet.
    /// `program_addr` is the deployed `program/main-v3.aml` address;
    /// `wallet_addr` is the `from` field of every emitted call.
    pub fn new(program_addr: Address, wallet_addr: Address) -> Self {
        Self {
            program_addr,
            wallet_addr,
        }
    }

    /// Borrow the program address this builder is bound to.
    pub fn program_addr(&self) -> &Address {
        &self.program_addr
    }

    /// Borrow the caller wallet address this builder is bound to.
    pub fn wallet_addr(&self) -> &Address {
        &self.wallet_addr
    }

    /// Generic `contract_call` envelope construction. All
    /// per-method wrappers below delegate here; exposed publicly so a
    /// future AML entrypoint with no dedicated wrapper can still ride
    /// this builder rather than re-hand-rolling the JSON.
    pub fn call(&self, method: &str, params: &[Value], value: u64, fee: u64, nonce: u64) -> Value {
        json!({
            "kind": "contract_call",
            "from": self.wallet_addr.display(),
            "to": self.program_addr.display(),
            "method": method,
            "params": params,
            "value": value,
            "fee": fee,
            "nonce": nonce,
        })
    }

    // ============================================================
    // Circle registry — register / update / rotate / retire
    // ============================================================

    /// Build a `register_circle` call.
    /// `params` order: `[circle_id, state_root_hex, receipt_pubkey_b64]`.
    pub fn register_circle_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::REGISTER_CIRCLE, params, value, fee, nonce)
    }

    /// Build an `update_circle_state` call.
    /// `params` order: `[circle_id, new_state_root_hex]`.
    pub fn update_circle_state_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::UPDATE_CIRCLE_STATE, params, value, fee, nonce)
    }

    /// Build a `rotate_receipt_pubkey` call.
    /// `params` order: `[circle_id, new_pubkey_b64]`.
    pub fn rotate_receipt_pubkey_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::ROTATE_RECEIPT_PUBKEY, params, value, fee, nonce)
    }

    /// Build a `retire_circle` call.
    /// `params` order: `[circle_id]`.
    pub fn retire_circle_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::RETIRE_CIRCLE, params, value, fee, nonce)
    }

    // ============================================================
    // Bond / unbond / finalize
    // ============================================================

    /// Build a `bond_endpoint` call.
    /// `params` order: `[circle_id]`. `value` is the bond top-up.
    pub fn bond_endpoint_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::BOND_ENDPOINT, params, value, fee, nonce)
    }

    /// Build an `unbond_endpoint` call.
    /// `params` order: `[circle_id]`.
    pub fn unbond_endpoint_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::UNBOND_ENDPOINT, params, value, fee, nonce)
    }

    /// Build a `finalize_unbond` call.
    /// `params` order: `[circle_id]`.
    pub fn finalize_unbond_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::FINALIZE_UNBOND, params, value, fee, nonce)
    }

    // ============================================================
    // Slash
    // ============================================================

    /// Build a `slash_double_sign` call.
    /// `params` order: `[circle, payload_a, sig_a_b64, payload_b, sig_b_b64]`.
    pub fn slash_double_sign_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::SLASH_DOUBLE_SIGN, params, value, fee, nonce)
    }

    // ============================================================
    // Tailnets
    // ============================================================

    /// Build a `create_tailnet` call.
    /// `params` order: `[members_root_hex]`. `value` is the initial deposit.
    pub fn create_tailnet_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::CREATE_TAILNET, params, value, fee, nonce)
    }

    /// Build an `update_members_root` call.
    /// `params` order: `[tailnet_id, new_members_root_hex]`.
    pub fn update_members_root_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::UPDATE_MEMBERS_ROOT, params, value, fee, nonce)
    }

    /// Build a `retire_tailnet` call.
    /// `params` order: `[tailnet_id]`.
    pub fn retire_tailnet_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::RETIRE_TAILNET, params, value, fee, nonce)
    }

    /// Build a `deposit_to_tailnet` call.
    /// `params` order: `[tailnet_id]`. `value` is the deposit.
    pub fn deposit_to_tailnet_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::DEPOSIT_TO_TAILNET, params, value, fee, nonce)
    }

    /// Build a `withdraw_tailnet_treasury` call.
    /// `params` order: `[tailnet_id, amount]`.
    pub fn withdraw_tailnet_treasury_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::WITHDRAW_TAILNET_TREASURY, params, value, fee, nonce)
    }

    // ============================================================
    // Sessions
    // ============================================================

    /// Build an `open_session` call.
    /// `params` order: `[tailnet_id, circle_id, max_pay]`.
    pub fn open_session_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::OPEN_SESSION, params, value, fee, nonce)
    }

    /// Build a `settle_claim` call.
    /// `params` order: `[session_id, bytes_used]`.
    pub fn settle_claim_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::SETTLE_CLAIM, params, value, fee, nonce)
    }

    /// Build a `settle_confirm` call.
    /// `params` order: `[session_id, bytes_used, net, settle_blinding]`.
    pub fn settle_confirm_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::SETTLE_CONFIRM, params, value, fee, nonce)
    }

    /// Build a `claim_no_show` call.
    /// `params` order: `[session_id]`.
    pub fn claim_no_show_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::CLAIM_NO_SHOW, params, value, fee, nonce)
    }

    /// Build a `sweep_expired_session` call.
    /// `params` order: `[session_id]`.
    pub fn sweep_expired_session_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::SWEEP_EXPIRED_SESSION, params, value, fee, nonce)
    }

    // ============================================================
    // Earnings
    // ============================================================

    /// Build a `claim_earnings` call.
    /// `params` order: `[circle_id, amount]`.
    pub fn claim_earnings_call(
        &self,
        params: &[Value],
        value: u64,
        fee: u64,
        nonce: u64,
    ) -> Value {
        self.call(method::CLAIM_EARNINGS, params, value, fee, nonce)
    }
}

// ============================================================
// Tests — one per builder method. Each pins the exact JSON shape
// against a hand-crafted `serde_json::json!()` expected value so a
// silent drift on either side (constants, params, value/fee/nonce
// placement) becomes a test failure rather than a runtime mismatch
// against `docker/devnet/v3-smoke.sh`.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    const PROG: &str = "oct7MofanKjxSBwCQXGgx5Aah2D2aUj1uNCjCTruhHUusf3";
    const WALLET: &str = "octB3oySs3p4qNDk2yQngLAoZWLcENWFb8X8d2QmJVtN2HM";

    fn builder() -> ContractCallBuilder {
        ContractCallBuilder::new(Address::from_display(PROG), Address::from_display(WALLET))
    }

    fn anchor_hex() -> String {
        "1111111111111111111111111111111111111111111111111111111111111111".to_string()
    }

    #[test]
    fn register_circle_shape() {
        let b = builder();
        let got = b.register_circle_call(
            &[
                json!("octCID"),
                json!(anchor_hex()),
                json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="),
            ],
            150_000_000,
            1_000,
            42,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "register_circle",
            "params": ["octCID", anchor_hex(), "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="],
            "value": 150_000_000u64,
            "fee": 1_000u64,
            "nonce": 42u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn update_circle_state_shape() {
        let b = builder();
        let got = b.update_circle_state_call(
            &[json!("octCID"), json!(anchor_hex())],
            0,
            500,
            7,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "update_circle_state",
            "params": ["octCID", anchor_hex()],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 7u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn rotate_receipt_pubkey_shape() {
        let b = builder();
        let got = b.rotate_receipt_pubkey_call(
            &[json!("octCID"), json!("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA=")],
            0,
            500,
            9,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "rotate_receipt_pubkey",
            "params": ["octCID", "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA="],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 9u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn retire_circle_shape() {
        let b = builder();
        let got = b.retire_circle_call(&[json!("octCID")], 0, 500, 10);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "retire_circle",
            "params": ["octCID"],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 10u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn bond_endpoint_shape() {
        let b = builder();
        let got = b.bond_endpoint_call(&[json!("octCID")], 50_000_000, 500, 11);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "bond_endpoint",
            "params": ["octCID"],
            "value": 50_000_000u64,
            "fee": 500u64,
            "nonce": 11u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn unbond_endpoint_shape() {
        let b = builder();
        let got = b.unbond_endpoint_call(&[json!("octCID")], 0, 500, 12);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "unbond_endpoint",
            "params": ["octCID"],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 12u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn finalize_unbond_shape() {
        let b = builder();
        let got = b.finalize_unbond_call(&[json!("octCID")], 0, 500, 13);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "finalize_unbond",
            "params": ["octCID"],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 13u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn slash_double_sign_shape() {
        let b = builder();
        let got = b.slash_double_sign_call(
            &[
                json!("octCID"),
                json!("payload_a"),
                json!("AAAA"),
                json!("payload_b"),
                json!("BBBB"),
            ],
            0,
            500,
            14,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "slash_double_sign",
            "params": ["octCID", "payload_a", "AAAA", "payload_b", "BBBB"],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 14u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn create_tailnet_shape() {
        let b = builder();
        let got = b.create_tailnet_call(&[json!(anchor_hex())], 10_000_000, 500, 15);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "create_tailnet",
            "params": [anchor_hex()],
            "value": 10_000_000u64,
            "fee": 500u64,
            "nonce": 15u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn update_members_root_shape() {
        let b = builder();
        let got = b.update_members_root_call(
            &[json!(0u64), json!(anchor_hex())],
            0,
            500,
            16,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "update_members_root",
            "params": [0u64, anchor_hex()],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 16u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn retire_tailnet_shape() {
        let b = builder();
        let got = b.retire_tailnet_call(&[json!(3u64)], 0, 500, 17);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "retire_tailnet",
            "params": [3u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 17u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn deposit_to_tailnet_shape() {
        let b = builder();
        let got = b.deposit_to_tailnet_call(&[json!(2u64)], 500_000, 500, 18);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "deposit_to_tailnet",
            "params": [2u64],
            "value": 500_000u64,
            "fee": 500u64,
            "nonce": 18u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn withdraw_tailnet_treasury_shape() {
        let b = builder();
        let got = b.withdraw_tailnet_treasury_call(
            &[json!(2u64), json!(100_000u64)],
            0,
            500,
            11,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "withdraw_tailnet_treasury",
            "params": [2u64, 100_000u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 11u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn open_session_shape() {
        let b = builder();
        let got = b.open_session_call(
            &[json!(0u64), json!("octCID"), json!(1500u64)],
            0,
            500,
            19,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "open_session",
            "params": [0u64, "octCID", 1500u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 19u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn settle_claim_shape() {
        let b = builder();
        let got = b.settle_claim_call(&[json!(0u64), json!(1_048_576u64)], 0, 500, 20);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "settle_claim",
            "params": [0u64, 1_048_576u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 20u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn settle_confirm_shape() {
        let b = builder();
        let got = b.settle_confirm_call(
            &[
                json!(0u64),
                json!(1_048_576u64),
                json!(1000u64),
                json!("f8d1aa00bb22cc33"),
            ],
            0,
            500,
            21,
        );
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "settle_confirm",
            "params": [0u64, 1_048_576u64, 1000u64, "f8d1aa00bb22cc33"],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 21u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn claim_no_show_shape() {
        let b = builder();
        let got = b.claim_no_show_call(&[json!(5u64)], 0, 500, 22);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "claim_no_show",
            "params": [5u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 22u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn sweep_expired_session_shape() {
        let b = builder();
        let got = b.sweep_expired_session_call(&[json!(5u64)], 0, 500, 23);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "sweep_expired_session",
            "params": [5u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 23u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn claim_earnings_shape() {
        let b = builder();
        let got = b.claim_earnings_call(&[json!("octCID"), json!(995u64)], 0, 500, 24);
        let want = json!({
            "kind": "contract_call",
            "from": WALLET,
            "to": PROG,
            "method": "claim_earnings",
            "params": ["octCID", 995u64],
            "value": 0u64,
            "fee": 500u64,
            "nonce": 24u64,
        });
        assert_eq!(got, want);
    }

    #[test]
    fn generic_call_uses_supplied_method_name() {
        // Catch-all: the `call()` escape hatch must produce the same
        // envelope shape as the dedicated wrappers when handed a
        // matching method string. Pins the generic path so a future
        // entrypoint added via `call()` directly never drifts from the
        // shape the wrappers emit.
        let b = builder();
        let got = b.call(
            method::OPEN_SESSION,
            &[json!(0u64), json!("octCID"), json!(1500u64)],
            0,
            500,
            19,
        );
        let want = b.open_session_call(
            &[json!(0u64), json!("octCID"), json!(1500u64)],
            0,
            500,
            19,
        );
        assert_eq!(got, want);
    }

    #[test]
    fn method_constants_match_string_literals() {
        // Self-documentation: every method-name constant must equal the
        // string the wrappers emit. If someone renames a constant but
        // forgets to update the wrappers (or vice versa) this fires.
        assert_eq!(method::REGISTER_CIRCLE, "register_circle");
        assert_eq!(method::UPDATE_CIRCLE_STATE, "update_circle_state");
        assert_eq!(method::ROTATE_RECEIPT_PUBKEY, "rotate_receipt_pubkey");
        assert_eq!(method::RETIRE_CIRCLE, "retire_circle");
        assert_eq!(method::BOND_ENDPOINT, "bond_endpoint");
        assert_eq!(method::UNBOND_ENDPOINT, "unbond_endpoint");
        assert_eq!(method::FINALIZE_UNBOND, "finalize_unbond");
        assert_eq!(method::SLASH_DOUBLE_SIGN, "slash_double_sign");
        assert_eq!(method::CREATE_TAILNET, "create_tailnet");
        assert_eq!(method::UPDATE_MEMBERS_ROOT, "update_members_root");
        assert_eq!(method::RETIRE_TAILNET, "retire_tailnet");
        assert_eq!(method::DEPOSIT_TO_TAILNET, "deposit_to_tailnet");
        assert_eq!(method::WITHDRAW_TAILNET_TREASURY, "withdraw_tailnet_treasury");
        assert_eq!(method::OPEN_SESSION, "open_session");
        assert_eq!(method::SETTLE_CLAIM, "settle_claim");
        assert_eq!(method::SETTLE_CONFIRM, "settle_confirm");
        assert_eq!(method::CLAIM_NO_SHOW, "claim_no_show");
        assert_eq!(method::SWEEP_EXPIRED_SESSION, "sweep_expired_session");
        assert_eq!(method::CLAIM_EARNINGS, "claim_earnings");
    }
}
