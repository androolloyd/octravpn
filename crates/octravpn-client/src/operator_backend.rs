//! Operator settlement backend.
//!
//! Today the client SDK talks directly to a v1 main-net AML
//! operator (a public `octV…` address). In v2 (see
//! `docs/v2-circles-design.md`), the operator is a Circle reached
//! through a proxy contract. The settle flow is the same — the
//! client decides whether to confirm or dispute, and submits a
//! `settle_confirm` — but the *target address* differs:
//!
//!   v1: settle_confirm is called on the OctraVPN main-net program
//!       with the operator's address recorded in the session row.
//!   v2: settle_confirm is called on the same v2 main-net program,
//!       but the session row records a proxy address, and behind
//!       the scenes the proxy forwards events into the Circle.
//!
//! From the client's perspective, the only thing that changes is
//! which address it points at. This trait formalizes that so the
//! rest of the SDK doesn't have to branch.
//!
//! The v2 impl is a stub today — wire-up follows once Octra ships
//! the Circle DSL (see `docs/v2-circles-design.md` §9).

use async_trait::async_trait;

use crate::runner::Client;

/// Settlement backend for an operator. Used by `settler::settle_active`.
#[async_trait]
pub(crate) trait OperatorBackend: Send + Sync {
    /// Submit `settle_confirm(session_id, bytes_used)` to the chain.
    /// The chain decides whether settlement applies (bytes match
    /// the operator's prior claim) or whether a dispute is recorded.
    async fn settle_confirm(
        &self,
        client: &Client,
        session_id: u64,
        bytes_used: u64,
    ) -> anyhow::Result<String>;
}

/// v1 operator: a public address with a session row on the OctraVPN
/// main-net program. The opaque-to-callers "proxy address" doesn't
/// exist; the address in the session row IS the operator.
pub(crate) struct MainnetOperator;

#[async_trait]
impl OperatorBackend for MainnetOperator {
    async fn settle_confirm(
        &self,
        client: &Client,
        session_id: u64,
        bytes_used: u64,
    ) -> anyhow::Result<String> {
        use serde_json::json;
        let bal = client.rpc().balance(client.wallet_addr()).await?;
        let nonce = bal.pending_nonce.max(bal.nonce);
        let fee = client
            .rpc()
            .recommended_fee(Some("contract_call"))
            .await?
            .recommended;
        let call = json!({
            "kind": "contract_call",
            "from": client.wallet_addr().display(),
            "to": client.program_addr().display(),
            "method": "settle_confirm",
            "params": [session_id, bytes_used],
            "value": 0,
            "fee": fee,
            "nonce": nonce,
        });
        let signed = crate::runner::sign_call(client.wallet_kp(), call)?;
        let r = client.rpc().submit(&signed).await?;
        Ok(r.hash)
    }
}

/// v2 operator: a Circle reached via a proxy contract. The settle
/// flow is identical from the client's POV — the target program is
/// the v2 OctraVPN AML, not the proxy, and the session row inside
/// the v2 program holds the proxy address. The proxy enforces
/// settlement-side rules (HFHE balance updates, slashing) on its
/// side; the client just submits.
///
/// Stubbed until the v2 AML is deployed and the Circle DSL ships
/// (see `docs/v2-circles-design.md` §9). The wire format will be
/// identical to v1; what changes is the program address and the
/// way the session row resolves to an operator.
#[allow(dead_code)]
pub(crate) struct CircleOperator;

#[async_trait]
impl OperatorBackend for CircleOperator {
    async fn settle_confirm(
        &self,
        _client: &Client,
        _session_id: u64,
        _bytes_used: u64,
    ) -> anyhow::Result<String> {
        Err(anyhow::anyhow!(
            "CircleOperator settlement not yet implemented — pending Octra Circle DSL (see docs/v2-circles-design.md §9)"
        ))
    }
}
