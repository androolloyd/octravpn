//! Canonical invariants for the `OctraVPN` AML program (v1 model).
//!
//! These are the load-bearing security properties expressed as Rust
//! predicates over the mock-chain state. The invariant runner asserts
//! each after every step in a fuzz sequence.
//!
//! When you add an AML entrypoint, add an invariant that captures
//! any new safety property it introduces. Tighter invariants → more
//! bugs surfaced by the fuzzer.

use crate::ForgeCtx;

/// Result of a single invariant check.
pub type InvariantResult = Result<(), String>;

type InvariantFn = fn(&ForgeCtx) -> InvariantResult;

pub fn check_all(ctx: &ForgeCtx) -> InvariantResult {
    let checks: &[(&str, InvariantFn)] = &[
        ("active_endpoints_have_stake", active_endpoints_have_stake),
        ("slashed_endpoints_have_zero_stake", slashed_endpoints_have_zero_stake),
        ("unbonding_excludes_live_stake", unbonding_excludes_live_stake),
        ("session_status_is_valid", session_status_is_valid),
        ("settled_sessions_have_recorded_exit", settled_sessions_have_recorded_exit),
        ("active_endpoints_view_matches_state", active_endpoints_view_matches_state),
        ("tailnet_owner_is_member", tailnet_owner_is_member),
        ("session_exits_are_configured_for_tailnet", session_exits_are_configured_for_tailnet),
    ];
    let mut errs = Vec::new();
    for (name, f) in checks {
        if let Err(e) = f(ctx) {
            errs.push(format!("{name}: {e}"));
        }
    }
    if errs.is_empty() {
        Ok(())
    } else {
        Err(errs.join("; "))
    }
}

/// **SECURITY**: every endpoint reported as active MUST have at
/// least `MIN_ENDPOINT_STAKE` of bonded OU and not be slashed. If
/// violated, an unbonded address managed to keep collecting traffic
/// payments.
pub fn active_endpoints_have_stake(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (addr, ep) in &s.endpoints {
        if !ep.active {
            continue;
        }
        if s.endpoint_slashed.contains(addr) {
            return Err(format!("endpoint {addr} is active but slashed"));
        }
        let stake = s.endpoint_stake.get(addr).copied().unwrap_or(0);
        if stake < octravpn_mock_rpc::MIN_ENDPOINT_STAKE {
            return Err(format!(
                "endpoint {addr} is active but stake {stake} < MIN_ENDPOINT_STAKE"
            ));
        }
    }
    Ok(())
}

/// **SECURITY**: slashed operators MUST have zero live stake.
pub fn slashed_endpoints_have_zero_stake(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for addr in &s.endpoint_slashed {
        let live = s.endpoint_stake.get(addr).copied().unwrap_or(0);
        if live != 0 {
            return Err(format!("slashed operator {addr} retains live stake {live}"));
        }
        if let Some((unb_amt, _)) = s.endpoint_unbonding.get(addr) {
            if *unb_amt != 0 {
                return Err(format!(
                    "slashed operator {addr} retains unbonding stake {unb_amt}"
                ));
            }
        }
    }
    Ok(())
}

/// **SECURITY**: an address with in-flight unbonding cannot also
/// hold live stake — the unbond transition moves everything across.
pub fn unbonding_excludes_live_stake(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (addr, (unb_amt, _)) in &s.endpoint_unbonding {
        if *unb_amt == 0 {
            continue;
        }
        let live = s.endpoint_stake.get(addr).copied().unwrap_or(0);
        if live != 0 {
            return Err(format!(
                "{addr} has both unbonding={unb_amt} and live={live}"
            ));
        }
    }
    Ok(())
}

/// Session.status is always in `{0,1,2}` (open / settled / refunded).
pub fn session_status_is_valid(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (sid, sess) in &s.sessions {
        if sess.status > 2 {
            return Err(format!(
                "session {sid} has invalid status {}",
                sess.status
            ));
        }
    }
    Ok(())
}

/// Settled sessions retain a non-empty exit address. (Replaces the
/// old `last_seq > 0` check; v1 settle is single-shot so we just
/// confirm the session was bound to an exit.)
pub fn settled_sessions_have_recorded_exit(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (sid, sess) in &s.sessions {
        if sess.status == 1 && sess.exit.is_empty() {
            return Err(format!("settled session {sid} has empty exit"));
        }
    }
    Ok(())
}

/// `list_active_endpoints` matches what's actually active in state.
pub fn active_endpoints_view_matches_state(ctx: &ForgeCtx) -> InvariantResult {
    let view_result = ctx
        .view(
            "list_active_endpoints",
            vec![serde_json::json!(0u64), serde_json::json!(1_000u64)],
        )
        .map_err(|e| format!("view failed: {e}"))?;
    let view_set: std::collections::HashSet<String> = view_result
        .as_array()
        .ok_or_else(|| "list_active_endpoints returned non-array".to_string())?
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    let s = ctx.app.state.read();
    let state_set: std::collections::HashSet<String> = s
        .endpoints
        .iter()
        .filter(|(addr, e)| {
            e.active
                && !s.endpoint_slashed.contains(*addr)
                && s.endpoint_stake.get(*addr).copied().unwrap_or(0)
                    >= octravpn_mock_rpc::MIN_ENDPOINT_STAKE
        })
        .map(|(addr, _)| addr.clone())
        .collect();
    if view_set != state_set {
        return Err(format!(
            "list_active_endpoints disagrees with state: view={view_set:?} state={state_set:?}"
        ));
    }
    Ok(())
}

/// A tailnet's owner is always in its members set.
pub fn tailnet_owner_is_member(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (tid, t) in &s.tailnets {
        if !t.members.contains(&t.owner) {
            return Err(format!(
                "tailnet {tid}: owner {} not in members",
                t.owner
            ));
        }
    }
    Ok(())
}

/// Every open or settled session's `exit` address is configured as
/// an exit on its tailnet. (We don't enforce this for refunded
/// sessions because the tailnet may have evicted the exit by then.)
pub fn session_exits_are_configured_for_tailnet(ctx: &ForgeCtx) -> InvariantResult {
    let s = ctx.app.state.read();
    for (sid, sess) in &s.sessions {
        if sess.status == 2 {
            continue;
        }
        let Some(t) = s.tailnets.get(&sess.tailnet_id) else {
            return Err(format!("session {sid} references missing tailnet"));
        };
        if !t.exits.contains(&sess.exit) {
            return Err(format!(
                "session {sid} exit {} no longer configured for tailnet",
                sess.exit
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ForgeCtx;

    #[test]
    fn fresh_context_satisfies_all_invariants() {
        let ctx = ForgeCtx::new();
        check_all(&ctx).expect("fresh context should be invariant-compatible");
    }

    #[test]
    fn rogue_unstaked_endpoint_violates_active_stake_invariant() {
        let mut ctx = ForgeCtx::new();
        // Inject a rogue active endpoint without bonding.
        ctx.store().endpoint(
            "octROGUE",
            octravpn_mock_rpc::EndpointRow {
                addr: "octROGUE".into(),
                active: true,
                endpoint: "1.2.3.4:51820".into(),
                wg_pubkey: "00".repeat(32),
                hfhe_pubkey: "00".repeat(32),
                initial_enc_zero: "00".repeat(32),
                region: "x".into(),
                price_per_mb: 1,
                registered_at: 1,
                reputation: 0,
            },
        );
        let r = active_endpoints_have_stake(&ctx);
        assert!(r.is_err(), "rogue endpoint should violate stake invariant");
    }

    #[test]
    fn tailnet_owner_is_always_member() {
        let mut ctx = ForgeCtx::new();
        ctx.prank("octOWN");
        ctx.call_create_tailnet(&"ab".repeat(32), 1000).unwrap();
        check_all(&ctx).expect("create_tailnet must keep owner-in-members");
    }
}
