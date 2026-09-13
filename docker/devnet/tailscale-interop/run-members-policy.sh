#!/usr/bin/env bash
# run-members-policy.sh — live proof of design item 4 in its **packet-filter**
# posture: the anchored member set decides what a registered device may reach,
# against a REAL lite_node (sequence 12) and the deployed main-v4 program.
# Registration itself is open here (`enforce_registration = false`), so a
# non-member registers, is visible in a member's netmap, and is mute.
#
# Its sibling, `run-members-registration.sh`, proves the admission posture:
# a non-member cannot register at all. Both share `lib-members-policy.sh`.
#
# What this proves, in order (each step is an assertion):
#   1. a fresh native circle gets its first anchor via `circle bootstrap`
#      (sealed /state-root.json + register_circle) and reads back;
#   2. mesh-control boots with --members-policy-circle and installs a
#      deny-all packet filter before any member is anchored;
#   3. two stock tailscale peers join; with NO members anchored, an ICMP
#      ping (subject to the packet filter) between them FAILS;
#   4. `auth members admit` peer-a  → within an epoch the policy re-renders
#      (matched=1): a→b succeeds, b→a still fails (b is not a member) — and
#      b is still *visible* to a, which is exactly what the filter-only
#      posture means;
#   5. admit peer-b → both directions succeed;
#   6. `auth members evict` peer-a → a→b fails again, b→a still succeeds.
#
# Exit codes, env knobs: see lib-members-policy.sh.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-members-policy.sh"

# Start from an empty registration store as well: a stale row from an
# earlier run would show up as a duplicate peer in the netmap assertions.
MP_RESET_REGISTRATIONS=1 mp_setup false

step "4/ stock tailscale peers join"
PREAUTH_KEY=$(mp_preauth_key)
for peer in tsi-peer-a tsi-peer-b; do mp_join_or_fail "${peer}" "${PREAUTH_KEY}"; done
mp_wait_ips
KEY_A=$(peer_key tsi-peer-a); KEY_B=$(peer_key tsi-peer-b)
ok "peer-a ${IP_A} ${KEY_A}"; ok "peer-b ${IP_B} ${KEY_B}"

step "5/ no members anchored ⇒ the wire is closed"
require_peers_running
expect_ping tsi-peer-a "${IP_B}" no "deny-all"
expect_ping tsi-peer-b "${IP_A}" no "deny-all"

step "6/ admit peer-a ⇒ a→b opens, b→a stays closed"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${OPERATOR_ADDR}" --node-key "${KEY_A}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 1
expect_ping tsi-peer-a "${IP_B}" yes "member a → non-member b"
expect_ping tsi-peer-b "${IP_A}" no  "non-member b → member a"
# The contrast with the admission posture: b is still registered, so it is
# still a peer in a's netmap — filtered, not invisible.
expect_peers tsi-peer-a "tsi-peer-b" "filter-only: the non-member stays visible"

step "7/ admit peer-b ⇒ both directions open"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${MEMBER_WALLET_B}" --node-key "${KEY_B}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 2
expect_ping tsi-peer-a "${IP_B}" yes "member a → member b"
expect_ping tsi-peer-b "${IP_A}" yes "member b → member a"

step "8/ evict peer-a ⇒ a→b closes again"
mark_logs
node_cli auth --circle "${CIRCLE}" members evict --wallet "${OPERATOR_ADDR}" 2>&1 | sed 's/^/    /' >&2
wait_policy_log 1
expect_ping tsi-peer-a "${IP_B}" no  "evicted a → member b"
expect_ping tsi-peer-b "${IP_A}" yes "member b → evicted a (b is still a member)"

step "final anchored set"
node_cli auth --circle "${CIRCLE}" members list 2>&1 | sed 's/^/    /' >&2
echo >&2; echo "MEMBERS-POLICY PROOF (filter posture): PASS (circle ${CIRCLE})" >&2
