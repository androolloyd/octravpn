/-!
# AML ↔ Lean linkage scaffold.

Placeholder API contract: every spec entrypoint declares the AML
function name it claims to model, so a future linker can confirm
coverage. v1 surface.
-/

namespace OctraVPN.AmlLink

/-- Hand-curated map: spec function name → AML entrypoint name.
    Once the AML AST is exposed, this becomes a checked theorem. -/
def specToAml : List (String × String) :=
  [ ("bondEndpoint",         "bond_endpoint"),
    ("unbondEndpoint",       "unbond_endpoint"),
    ("finalizeUnbond",       "finalize_unbond"),
    ("govSlashOperator",     "gov_slash_operator"),
    ("registerEndpoint",     "register_endpoint"),
    ("retireEndpoint",       "retire_endpoint"),
    ("createTailnet",        "create_tailnet"),
    ("addMember",            "add_member"),
    ("depositToTailnet",     "deposit_to_tailnet"),
    ("configureTailnetExit", "configure_tailnet_exit"),
    ("openSession",          "open_session"),
    ("settleSession",        "settle_session"),
    ("claimNoShow",          "claim_no_show"),
    ("claimEarnings",        "claim_earnings") ]

/-- Trivial sanity check: every spec name appears at most once. -/
theorem specToAml_no_dup :
    (specToAml.map Prod.fst).Nodup := by
  decide

end OctraVPN.AmlLink
