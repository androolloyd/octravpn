# Headscale-Go Remaining Parity Audit

Date: 2026-06-02

Audited upstream:

- `github.com/juanfont/headscale` `v0.29.0-beta.2`
- Tag and upstream `main` commit: `171fd7a3c54156965753a63639cdcafcd50c8d67`
- Tailscale dependency: `tailscale.com v1.98.3`
- Local source used: `/Users/androolloyd/go/pkg/mod/github.com/juanfont/headscale@v0.29.0-beta.2`

This is a delegation backlog, not a proof of completion. Items below are
remaining when either implementation is missing, stock-client/production
coverage is missing, or current evidence is too narrow to claim replacement
parity.

## Live Delegation Status

Ready for review/merge:

- Native DERP runtime: `origin/agent/derp-runtime-20260602`
  (`36bb59a0845ec9d7e2e9fd3609b92bac7dbccc42`).
- CLI residual snapshots: `origin/agent/cli-snapshot-parity`
  (`1a3b373`).
- Postgres production local-gRPC mutation restart coverage:
  `origin/agent/postgres-prod-parity` (`ad14840a80f6138885a70f929ba7886612ee34d8`).
- gRPC/gateway registration error text:
  `origin/agent/grpc-error-parity` (`1c2f4af2a988cc739e374a675cf8faa69859fd69`).
- Route no-op map churn suppression:
  `origin/agent/route-nodestore-churn` (`446845d6030c0872d3210aedfd0d1f17aa86f94b`).

Currently delegated:

- Native DERP stock-client smoke: Carver (`019e87e7-bb0e-7fd0-ae82-811f54353d65`).
- Cross-surface source inventory audit: Rawls (`019e87ee-9159-7741-a13b-2027e01449c4`).
- SSH client-facing parity: Curie (`019e87f1-6c8b-7a80-b04f-7513220c8a7e`).
- DNS live resolver parity: Franklin (`019e87f1-6cbb-7632-a4e7-4906da68bbc0`).
- Config/TLS/ACME/RealIP parity: Huygens (`019e87f1-6ce7-7f80-b511-3425be8bb6c7`).
- Generated surface inventory tooling: Turing (`019e87f1-9647-7330-a8b5-0c1a52de1cc8`).

## Delegation Lanes

### P0-Audit: Current-Head Completeness Harness

1. Build a generated surface inventory for every upstream command, proto RPC,
   public route, debug route, config key, DB model/migration, and integration
   test, then diff it against headscale-rs evidence.
   - Upstream evidence: `proto/headscale/v1/headscale.proto:14`,
     `hscontrol/app.go:553`, `hscontrol/noise.go:172`,
     `hscontrol/debug.go:56`, `hscontrol/types/config.go:859`,
     `cmd/headscale/cli/*.go`, `integration/*_test.go`.
   - Rust likely files: `docs/headscale-go-parity.md`,
     `tools/parity/**`, `tools/real-client/smoke-matrix.sh`,
     `headscale-api/proto/**`, `headscale-cli/tests/**`.
   - Type: evidence/tooling.

2. Add a machine-readable backlog file consumed by CI that lists known gaps and
   prevents a future "full parity" claim while blockers remain.
   - Upstream evidence: all lanes below.
   - Rust likely files: `docs/**`, `.github/workflows/**`, `scripts/**`.
   - Type: evidence/tooling.

### P0: Native DERP/STUN Replacement

3. Finish native DERP keepalive, restart, and health scheduling semantics.
   - Upstream evidence: `hscontrol/derp/server/derp_server.go`,
     `integration/embedded_derp_test.go:21`,
     `integration/embedded_derp_test.go:71`, Tailscale DERP server in
     `tailscale.com@v1.98.3/derp/derpserver`.
   - Rust likely files: `headscale-core/src/derp.rs`,
     `headscale-api/src/tailscale_wire/derp.rs`.
   - Type: implementation.
   - Status: ready for review on `origin/agent/derp-runtime-20260602`.

4. Add stock-client native embedded DERP smoke coverage, separate from the
   supported upstream `derper` sidecar rows.
   - Upstream evidence: `/derp`, `/derp/probe`, `/derp/latency-check`,
     `/bootstrap-dns` mounted in `hscontrol/app.go:572`.
   - Rust likely files: `tools/real-client/online-lastseen-common.sh`,
     `tools/real-client/postgres-derp-native-smoke.sh`,
     `tools/real-client/smoke-matrix.sh`.
   - Type: coverage/evidence.
   - Status: delegated to Carver.

5. Prove native DERP verify-client behavior against real clients over both raw
   DERP and DERP-over-WebSocket.
   - Upstream evidence: `integration/derp_verify_endpoint_test.go`,
     `hscontrol/derp/server/derp_server.go`.
   - Rust likely files: `headscale-api/src/tailscale_wire/derp.rs`,
     `tools/real-client/*derp*`.
   - Type: coverage/evidence.

### P0: Production Postgres and Upgrade/Drop-In Behavior

6. Broaden production Postgres process-level serve/mutation rows beyond the
   existing stock-client matrix.
   - Upstream evidence: `hscontrol/db/**`, `hscontrol/types/config.go:844`,
     integration CLI/API tests.
   - Rust likely files: `headscale-db/migrations/postgres/**`,
     `headscale-cli/src/server.rs`, `tools/real-client/postgres-*.sh`.
   - Type: coverage/evidence, possible implementation.
   - Status: one local-gRPC restart mutation row ready for review on
     `origin/agent/postgres-prod-parity`; broader rows remain.

7. Add database upgrade/drop-in compatibility tests from recent headscale-go
   schemas, including pre-0.25 unsupported upgrade boundaries and current
   v0.29 tag/preauth/node schema changes.
   - Upstream evidence: release notes and `hscontrol/db/migrations/**`.
   - Rust likely files: `headscale-db/tests/headscale_go_migrations.rs`,
     `headscale-db/migrations/**`.
   - Type: implementation/evidence.

8. Expand Postgres admin/gateway lifecycle coverage for users, preauth keys,
   API keys, nodes, policy, route approval, and auth sessions through the same
   production server process.
   - Upstream evidence: `integration/cli_test.go`, `integration/api_auth_test.go`,
     `proto/headscale/v1/headscale.proto:14`.
   - Rust likely files: `headscale-cli/tests/cli_process.rs`,
     `headscale-api/tests/grpc_gateway_e2e.rs`, `tools/real-client/postgres-*`.
   - Type: coverage/evidence.

### P0: Register, Map, NodeStore, and Batcher Churn

9. Mirror upstream map-session replacement, disconnect grace, multi-connection,
   rapid reconnect, pending-delete, and race/stress behavior.
   - Upstream evidence: `hscontrol/poll.go:50`,
     `hscontrol/mapper/batcher_test.go:487`,
     `hscontrol/servertest/race_test.go:26`,
     `hscontrol/servertest/stress_test.go:24`.
   - Rust likely files: `headscale-api/src/tailscale_wire/map.rs`,
     `headscale-api/src/tailscale_wire/register.rs`,
     `headscale-api/src/tailscale_wire/mod.rs`.
   - Type: implementation/evidence.

10. Exhaustively pin `Change` merge/filter semantics, including targeted
    updates, self-only updates, PingRequest preservation, policy/runtime peer
    computation, DNS/DERP/domain inclusion, and peer patch reasons.
    - Upstream evidence: `hscontrol/types/change/change.go:56`.
    - Rust likely files: `headscale-api/src/tailscale_wire/map.rs`,
      `tools/parity/scenarios/wire-map-response-deltas-control.json`.
    - Type: implementation/evidence.
    - Status: route no-op churn slice ready for review on
      `origin/agent/route-nodestore-churn`; broader `Change` semantics remain.

11. Broaden NodeStore hostname/GivenName collision and concurrent update parity.
    - Upstream evidence: `hscontrol/state/node_store_hostname_test.go:17`,
      `hscontrol/state/node_store_test.go:18`.
    - Rust likely files: `headscale-db/src/headscale_nodes.rs`,
      `headscale-api/src/tailscale_wire/register.rs`.
    - Type: coverage/evidence.

12. Expand ephemeral node deletion/logout race coverage.
    - Upstream evidence: `hscontrol/state/ephemeral_test.go:17`.
    - Rust likely files: `headscale-api/src/tailscale_wire/mod.rs`,
      `headscale-db/src/headscale_nodes.rs`.
    - Type: coverage/evidence, possible implementation.

### P1: Routes, HA, and Grants Via

13. Continue current-upstream route-via and route-health edge coverage beyond
    the mirrored default/Postgres reload/restart rows.
    - Upstream evidence: `integration/route_test.go`,
      `hscontrol/servertest/routes_test.go:22`,
      `hscontrol/state/primaries_property_test.go:416`.
    - Rust likely files: `headscale-api/src/tailscale_wire/routes.rs`,
      `tools/real-client/route-*.sh`.
    - Type: coverage/evidence.

14. Mirror route primary property tests and randomized/property invariants.
    - Upstream evidence: `hscontrol/state/primaries_property_test.go:416`.
    - Rust likely files: `headscale-api/src/tailscale_wire/routes.rs`,
      `headscale-api/tests/**`.
    - Type: coverage/evidence.

15. Audit and cover recent grants/via issue tests, especially broader
    destination and `autogroup:internet` exit visibility.
    - Upstream evidence: `hscontrol/policy/v2/issue_3233_test.go:24`,
      `hscontrol/policy/v2/issue_3267_test.go:26`,
      `hscontrol/servertest/grants_test.go:664`.
    - Rust likely files: `headscale-api/src/policy/**`,
      `tools/parity/scenarios/route-via-*.json`.
    - Type: implementation/evidence.

### P1: SSH and SSH Check Flow

16. Broaden stock-client SSH stderr/status parity outside the covered
    allow/deny/check/profile rows.
    - Upstream evidence: `integration/ssh_test.go`.
    - Rust likely files: `tools/real-client/ssh-*.sh`,
      `headscale-api/src/tailscale_wire/ssh.rs`.
    - Type: coverage/evidence.
    - Status: delegated to Curie.

17. Pin SSH check-period, OIDC approval, wrong-user, cancelled, expired, and
    repeated approval behavior across restart and Postgres.
    - Upstream evidence: `hscontrol/policy/v2/sshtest_test.go:91`,
      `hscontrol/noise.go:541`, `integration/ssh_test.go`.
    - Rust likely files: `headscale-api/src/tailscale_wire/ssh.rs`,
      `headscale-api/src/oidc.rs`, `tools/real-client/ssh-oidc-*.sh`.
    - Type: coverage/evidence, possible implementation.

18. Expand SSH policy compiler parity for trimming, invalid users, SaaS
    validation, check-period duration rendering, and test failure text.
    - Upstream evidence: `hscontrol/policy/v2/types_test.go:2985`,
      `hscontrol/policy/v2/types_test.go:4365`,
      `hscontrol/policy/v2/types_test.go:4637`,
      `hscontrol/policy/v2/sshtest_test.go:961`.
    - Rust likely files: `headscale-api/src/policy/ssh.rs`,
      `headscale-api/src/policy/check.rs`, `tools/parity/scenarios/ssh-*.json`.
    - Type: implementation/evidence.

### P1: Policy, ACL, Tags, and CapMap

19. Audit remaining policy v2 compatibility tests against Tailscale ACL,
    grants, nodeAttrs, SSH, routes, and policy tester data.
    - Upstream evidence: `hscontrol/policy/v2/tailscale_acl_data_compat_test.go`,
      `tailscale_grants_compat_test.go`, `tailscale_routes_data_compat_test.go`,
      `tailscale_ssh_data_compat_test.go`.
    - Rust likely files: `tools/parity/scenarios/**`,
      `headscale-api/src/policy/**`.
    - Type: evidence/tooling, possible implementation.

20. Expand tag-owner and tag mutation parity for new v0.29 behavior:
    user-owned-to-tagged conversion, no tagged-to-user reversal, stored tags as
    source of truth, preauth tagged devices ignoring advertised tags, and
    unauthorized advertised tags.
    - Upstream evidence: `integration/tags_test.go`,
      `hscontrol/types/node_tags_test.go`, release notes for v0.29 beta.
    - Rust likely files: `headscale-api/src/admin/machines.rs`,
      `headscale-api/src/tailscale_wire/register.rs`,
      `tools/real-client/tag-*.sh`.
    - Type: implementation/evidence.

21. Broaden file-sharing/Taildrop and CapMap policy nodeAttr coverage.
    - Upstream evidence: `integration/grant_cap_test.go:75`,
      `hscontrol/policy/v2/nodeattrs_test.go:82`.
    - Rust likely files: `headscale-api/src/tailscale_wire/map.rs`,
      `tools/real-client/taildrop-capmap-*.sh`.
    - Type: coverage/evidence.

### P1: OIDC and Web Auth

22. Expand OIDC/web user lifecycle coverage, including profile updates,
    allowed domains/users/groups, email verification, PKCE, token-expiry use,
    and client secret file loading.
    - Upstream evidence: `integration/auth_oidc_test.go`,
      `hscontrol/oidc.go:97`, `hscontrol/types/config.go:1175`.
    - Rust likely files: `headscale-api/src/oidc.rs`,
      `headscale-cli/src/config.rs`, `tools/real-client/oidc-*.sh`.
    - Type: implementation/evidence.

23. Cover registration confirmation page/CSRF/cookie behavior and failure text.
    - Upstream evidence: `hscontrol/oidc_confirm_test.go:23`,
      `hscontrol/oidc.go:654`, `integration/auth_web_flow_test.go`.
    - Rust likely files: `headscale-api/src/oidc.rs`,
      `headscale-api/src/tailscale_wire/basic_handlers.rs`.
    - Type: coverage/evidence.

24. Cover auth-cache bounds, invalid auth IDs, wrong-kind auth IDs, repeated
    follow-up refreshes, and abandoned web/OIDC auth sessions.
    - Upstream evidence: `hscontrol/state/auth_cache_test.go:17`,
      `hscontrol/auth_test.go`.
    - Rust likely files: `headscale-api/src/admin/auth.rs`,
      `headscale-api/src/tailscale_wire/register.rs`.
    - Type: coverage/evidence.

### P1: Public HTTP, Debug, Metrics, Ping, and Platform Routes

25. Pin every public control route response shape, method rejection, content
    type, security header, and body limit.
    - Upstream evidence: `hscontrol/app.go:553`, `hscontrol/handlers.go:131`,
      `hscontrol/handlers_test.go:18`, `hscontrol/app_test.go:13`.
    - Rust likely files: `headscale-api/src/tailscale_wire/basic_handlers.rs`,
      `headscale-api/src/tailscale_wire/serve.rs`.
    - Type: evidence, possible implementation.

26. Expand debug route parity beyond `/debug/config` and `/debug/ping` to
    overview, policy, filter, ssh, derp, nodestore, registration-cache, routes,
    policy-manager, mapresponses, batcher, statsviz, and metrics.
    - Upstream evidence: `hscontrol/debug.go:56`, `hscontrol/debug.go:377`.
    - Rust likely files: `headscale-api/src/tailscale_wire/basic_handlers.rs`,
      `headscale-api/src/tailscale_wire/map.rs`.
    - Type: implementation/evidence.

27. Broaden `/debug/ping` and `/machine/ping-response` parity for non-HEAD
    rejection, duplicate pings to same node, disconnected targets, hostname
    resolution, and concurrent tracker behavior.
    - Upstream evidence: `hscontrol/servertest/ping_test.go:21`,
      `hscontrol/state/ping_test.go:17`.
    - Rust likely files: `headscale-api/src/tailscale_wire/basic_handlers.rs`,
      `headscale-api/src/tailscale_wire/map.rs`,
      `tools/real-client/ping-lifecycle-*.sh`.
    - Type: coverage/evidence.

28. Pin Apple/Windows profile route templates and request-derived fallback URL
    behavior.
    - Upstream evidence: `hscontrol/platform_config.go`,
      `hscontrol/templates/apple.go:93`,
      `hscontrol/templates/windows.go`.
    - Rust likely files: `headscale-api/src/tailscale_wire/basic_handlers.rs`.
    - Type: coverage/evidence.

### P1: DNS and MagicDNS

29. Add broader live resolver behavior using real Tailscale clients, including
    peer MagicDNS `tailscale debug resolve`, split DNS resolver behavior,
    disabled MagicDNS fallback, and extra-record query types.
    - Upstream evidence: `integration/dns_test.go`,
      `hscontrol/types/config.go:859`, `hscontrol/types/config.go:958`.
    - Rust likely files: `headscale-api/src/dns.rs`,
      `tools/real-client/*dns*`, `tools/real-client/*magicdns*`.
    - Type: coverage/evidence.
    - Status: delegated to Franklin.

30. Audit NextDNS/nodeAttrs per-requester metadata against current headscale-go
    and stock clients.
    - Upstream evidence: `hscontrol/dns/**`, `hscontrol/policy/v2/nodeattrs_test.go`.
    - Rust likely files: `headscale-api/src/dns.rs`,
      `tools/parity/scenarios/wire-dns-nextdns-nodeattrs.json`.
    - Type: implementation/evidence.

31. Pin all DNS config env/Viper coercions and failure text, including
    structured resolver objects, split maps, extra-record arrays/path, and
    MagicDNS base-domain validation.
    - Upstream evidence: `hscontrol/types/config.go:869`,
      `hscontrol/types/config_test.go`.
    - Rust likely files: `headscale-cli/src/config.rs`, `headscale-api/src/dns.rs`.
    - Type: coverage/evidence.

### P1: gRPC, Gateway, Proto, and API Auth

32. Keep proto surface exact for active RPCs and commented non-active device
    RPCs; prevent Octra-only routes from entering headscale-go parity claims.
    - Upstream evidence: `proto/headscale/v1/headscale.proto:14`,
      `proto/headscale/v1/device.proto:32`.
    - Rust likely files: `headscale-api/proto/**`,
      `headscale-api/src/generated/headscale_descriptor.bin`,
      `headscale-api/src/grpc.rs`.
    - Type: implementation/evidence.

33. Finish narrower gRPC/gateway auth, parser, remote/server, and direct gRPC
    error text matrices.
    - Upstream evidence: `integration/api_auth_test.go`,
      `proto/headscale/v1/headscale.proto:14`.
    - Rust likely files: `headscale-api/src/grpc.rs`,
      `headscale-api/src/grpc_gateway.rs`,
      `headscale-api/tests/grpc_gateway_e2e.rs`.
    - Type: coverage/evidence.
    - Status: one registration error-text slice ready for review on
      `origin/agent/grpc-error-parity`; broader matrices remain.

34. Add process coverage for public grpc-gateway and local/remote gRPC across
    all admin slices under SQLite and Postgres.
    - Upstream evidence: `hscontrol/app.go:580`, `integration/cli_test.go`.
    - Rust likely files: `headscale-cli/tests/cli_process.rs`,
      `headscale-api/tests/grpc_gateway_e2e.rs`.
    - Type: coverage/evidence.

### P2: CLI Exactness

35. Merge and review the pending CLI snapshot branch, then update the tracker.
    - Agent branch: `agent/cli-snapshot-parity`, commit `1a3b373`.
    - Rust likely files: `headscale-cli/tests/cli_process.rs`,
      `headscale-cli/tests/snapshots/**`.
    - Type: review/merge.
    - Status: ready for review on `origin/agent/cli-snapshot-parity`.

36. Continue byte-for-byte CLI output/error snapshots for residual live-server
    cases, especially config-load warning timestamp drift, server/runtime
    failures, and command-boundary parser behavior.
    - Upstream evidence: `cmd/headscale/cli/*.go`, `integration/cli_test.go`.
    - Rust likely files: `headscale-cli/tests/cli_process.rs`,
      `headscale-cli/tests/snapshots/**`.
    - Type: coverage/evidence.

37. Audit CLI config discovery and env interactions with `HEADSCALE_CONFIG`,
    top-level `--config`, `--output`, `cli.address`, `cli.api_key`,
    `cli.timeout`, and `cli.insecure` under utility commands.
    - Upstream evidence: `cmd/headscale/cli/root.go:26`,
      `hscontrol/types/config.go:1086`.
    - Rust likely files: `headscale-cli/src/main.rs`,
      `headscale-cli/src/config.rs`, `headscale-cli/tests/cli_process.rs`.
    - Type: coverage/evidence.

### P2: Config, Serving Topology, TLS, and ACME

38. Broaden HTTP-01/TLS-ALPN live-CA and failure-mode smokes beyond controlled
    local-CA tests.
    - Upstream evidence: `hscontrol/app.go:1054`,
      `hscontrol/types/config.go:1247`.
    - Rust likely files: `headscale-cli/src/acme_issuer.rs`,
      `headscale-api/src/tailscale_wire/acme.rs`,
      `headscale-api/src/tailscale_wire/tls.rs`.
    - Type: coverage/evidence.
    - Status: delegated to Huygens.

39. Audit config env/Viper parity for every server, database, DNS, DERP, OIDC,
    TLS, ACME, CLI, taildrop, auto-update, node route HA, and tuning key.
    - Upstream evidence: `hscontrol/types/config.go:1086`,
      `hscontrol/types/config.go:1209`, `hscontrol/types/config.go:1292`.
    - Rust likely files: `headscale-cli/src/config.rs`,
      `headscale-cli/tests/cli_process.rs`.
    - Type: coverage/evidence, possible implementation.

40. Cover trusted-proxy RealIP behavior, unsafe proxy rejection, and control
    route logging/address effects.
    - Upstream evidence: `hscontrol/realip.go:25`,
      `hscontrol/realip_test.go:191`, `hscontrol/noise.go:303`.
    - Rust likely files: `headscale-api/src/tailscale_wire/serve.rs`,
      `headscale-api/src/tailscale_wire/raw_tls.rs`.
    - Type: coverage/evidence.

41. Audit tailsql/debug-only listener behavior and whether replacement parity
    should implement, explicitly exclude, or document it.
    - Upstream evidence: `hscontrol/tailsql.go:104`.
    - Rust likely files: `docs/headscale-go-parity.md`,
      `headscale-api/src/tailscale_wire/basic_handlers.rs`.
    - Type: product decision/evidence.

### P2: Wire Model and Tailcfg Drift

42. Refresh tailcfg JSON shape parity against Tailscale `v1.98.3`, including
    `MapRequest`, `MapResponse`, `MapNode`, `Hostinfo`, `NetInfo`,
    `DNSConfig`, `DERPMap`, `SSHPolicy`, `PacketFilters`, `CapMap`, and
    peer delta shapes.
    - Upstream evidence: `tailscale.com@v1.98.3/tailcfg`,
      `hscontrol/mapper/**`, `hscontrol/types/node.go:116`.
    - Rust likely files: `headscale-api/src/tailscale_wire/wire.rs`,
      `headscale-api/tests/wire_serde_coverage.rs`,
      `tools/parity/scenarios/wire-*.json`.
    - Type: implementation/evidence.

43. Add golden/differential cases for current v0.29 beta Node API tag
    simplification and route/admin response changes.
    - Upstream evidence: `proto/headscale/v1/node.proto:17`,
      v0.29 beta release notes.
    - Rust likely files: `headscale-api/proto/node.proto`,
      `headscale-api/src/grpc.rs`, `headscale-cli/tests/snapshots/**`.
    - Type: implementation/evidence.

### P2: CI, Fuzz, Coverage, and Formal Status

44. Add CI gates that run the generated current-head surface inventory, focused
    differential parity scenarios, 10k fuzz, stale-corpus checks, and selected
    real-client rows.
    - Upstream evidence: all lanes above.
    - Rust likely files: `.github/workflows/**`, `headscale-core/fuzz/**`,
      `tools/parity/**`, `tools/real-client/**`.
    - Type: tooling/evidence.

45. Restore or explicitly document absent formal verification/Lean proof status.
    - Upstream evidence: not applicable.
    - Rust likely files: `docs/headscale-go-parity.md`, `docs/**`, `lean/**`
      if restored.
    - Type: tooling/evidence.

46. Add coverage threshold reporting by crate/module and identify parity lanes
    without executable evidence.
    - Upstream evidence: all lanes above.
    - Rust likely files: `.github/workflows/coverage.yml`, `scripts/**`.
    - Type: tooling/evidence.

### P2: Octra Boundary

47. Keep Octra-specific admin mounting, preauth store unification, embedded CLI
    docs, and settlement/billing policy behavior out of headscale-go parity
    claims and tests.
    - Upstream evidence: headscale-go has no Octra surfaces.
    - Rust likely files: Octra repo side plus `docs/headscale-go-parity.md`.
    - Type: downstream adaptation/evidence.

48. Add guard tests/docs proving public grpc-gateway and CLI surfaces expose
    upstream-compatible headscale routes only, with Octra extensions explicitly
    namespaced or excluded.
    - Upstream evidence: `proto/headscale/v1/headscale.proto:14`,
      `hscontrol/app.go:580`.
    - Rust likely files: `headscale-api/tests/grpc_gateway_e2e.rs`,
      `docs/headscale-go-parity.md`.
    - Type: coverage/evidence.

## Suggested Delegation Order

1. Native DERP runtime implementation.
2. Native DERP stock-client smoke.
3. Generated current-head surface inventory.
4. Postgres production process coverage.
5. NodeStore/batcher/map churn.
6. Route/grants/via edge tests.
7. SSH client-facing parity.
8. gRPC/gateway error text.
9. DNS live resolver behavior.
10. OIDC/web lifecycle.
11. Config/TLS/ACME/RealIP.
12. Wire/tailcfg drift refresh.
13. CLI residual output drift.
14. CI/fuzz/coverage gates.
15. Octra boundary guard.
