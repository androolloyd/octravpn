#!/usr/bin/env bash
# run-members-registration.sh — live proof of the **admission** posture:
# with `enforce_registration = true` the chain-anchored member set decides who
# may register at all, so a non-member never appears in a member's netmap.
#
# Its sibling, `run-members-policy.sh`, proves the filter-only posture (every
# key registers; the packet filter decides reachability). Both share
# `lib-members-policy.sh`.
#
# What this proves, in order (each step is an assertion):
#   1-3. same chain setup as the filter proof: circle anchored, mesh-control
#        up with --members-policy-circle, anchored member set empty — plus a
#        wiped registration store, so no peer starts out registered;
#   4.   peer-a's `tailscale up` is REFUSED while it is not a member, the
#        client is told why, nothing lands in the roster, and the operator
#        learns the device's **machine key** from the refusal — the identity
#        that survives the node-key rotation a refusal triggers;
#   5.   `auth members admit --machine-key` → the client's own retry
#        completes the login, with no second `tailscale up`. peer-b, still
#        not a member, is refused, and is absent from peer-a's netmap
#        entirely (not merely filtered);
#   6.   admit peer-b → it joins too, the two see each other and ICMP works
#        both ways;
#   7.   `auth members evict` peer-a → its registration is deleted: it
#        leaves peer-b's netmap and it cannot register again.
#
# Exit codes, env knobs: see lib-members-policy.sh.
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-members-policy.sh"

# Every peer must start unregistered for "refused" to mean anything.
MP_RESET_REGISTRATIONS=1 mp_setup true

step "3b/ every peer starts logged out"
mp_logout_peers

expect_refusal() { # expect_refusal <peer> <label>
  local peer="$1"
  if mp_try_join "${peer}" "${PREAUTH_KEY}" 45; then
    fail "$2: ${peer} registered while it is not an anchored member" 60
  fi
  command grep -qE 'not in the tailnet.s anchored member set' "${MP_UP_LOG}" \
    || { sed 's/^/      /' "${MP_UP_LOG}" | tail -5 >&2; fail "$2: ${peer} was refused, but not with the membership reason" 60; }
  ok "$2: ${peer} refused, and told why"
}

step "4/ a non-member cannot register"
PREAUTH_KEY=$(mp_preauth_key)
mark_logs
if mp_try_join tsi-peer-a "${PREAUTH_KEY}" 45; then
  fail "no membership: tsi-peer-a registered while it is not an anchored member" 60
fi
command grep -qE 'not in the tailnet.s anchored member set' "${MP_UP_LOG}" \
  || { tail -5 "${MP_UP_LOG}" | sed 's/^/      /' >&2; fail "no membership: tsi-peer-a was refused, but not with the membership reason" 60; }
ok "no membership: tsi-peer-a refused, and told why"
MKEY_A=$(refused_machine_key tsi-peer-a)
[[ -n "${MKEY_A}" ]] || { mc_logs_since_mark | tail -5 >&2; fail "the refusal did not name peer-a's machine key" 60; }
ok "operator learns peer-a's stable identity from the refusal: mkey:${MKEY_A}"
ROSTER=$(curl -fsS --max-time 5 -H "Authorization: Bearer ${ADMIN_TOKEN}" http://127.0.0.1:51821/api/v1/machines 2>/dev/null || true)
if printf '%s' "${ROSTER}" | command grep -q "${MKEY_A}"; then
  fail "the refused device is in the roster: ${ROSTER}" 60
fi
ok "nothing landed in the roster"

step "5/ admit that machine key ⇒ the client's own retry gets in; peer-b stays out"
# A login attempt is left running in the background: admitting the machine key
# mid-attempt is the operator flow, and the client finishes by itself.
mp_start_join tsi-peer-a "${PREAUTH_KEY}"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${OPERATOR_ADDR}" --machine-key "${MKEY_A}" 2>&1 | sed 's/^/    /' >&2
wait_members_loaded 1
wait_peer_running tsi-peer-a 180
IP_A=$(peer_ip tsi-peer-a)
ok "peer-a joined as an anchored member: ${IP_A}"
mark_logs
if mp_try_join tsi-peer-b "${PREAUTH_KEY}" 45; then
  fail "still not a member: tsi-peer-b registered" 60
fi
MKEY_B=$(refused_machine_key tsi-peer-b)
[[ -n "${MKEY_B}" ]] || fail "the refusal did not name peer-b's machine key" 60
ok "still not a member: tsi-peer-b refused (mkey:${MKEY_B})"
expect_peers tsi-peer-a "-" "admission posture: the non-member is invisible, not filtered"

step "6/ admit peer-b ⇒ it joins and the two members reach each other"
mp_start_join tsi-peer-b "${PREAUTH_KEY}"
mark_logs
node_cli auth --circle "${CIRCLE}" members admit --wallet "${MEMBER_WALLET_B}" --machine-key "${MKEY_B}" 2>&1 | sed 's/^/    /' >&2
wait_members_loaded 2
wait_peer_running tsi-peer-b 180
mp_wait_ips
require_peers_running
expect_peers tsi-peer-a "tsi-peer-b" "members see each other (a)"
expect_peers tsi-peer-b "tsi-peer-a" "members see each other (b)"
expect_ping tsi-peer-a "${IP_B}" yes "member a → member b"
expect_ping tsi-peer-b "${IP_A}" yes "member b → member a"

step "7/ evict peer-a ⇒ its registration is deleted and it cannot rejoin"
mark_logs
node_cli auth --circle "${CIRCLE}" members evict --wallet "${OPERATOR_ADDR}" 2>&1 | sed 's/^/    /' >&2
DELETED=""
for _ in $(seq 1 24); do
  if mc_logs_since_mark | command grep -q 'members policy: registration deleted'; then DELETED=1; break; fi
  sleep 5
done
[[ -n "${DELETED}" ]] || { mc_logs_since_mark | tail -6 >&2; fail "the evicted device's registration was never deleted" 60; }
ok "mesh-control deleted the evicted device's registration"
expect_peers tsi-peer-b "-" "the evicted device leaves the member's netmap"
mark_logs
if mp_try_join tsi-peer-a "${PREAUTH_KEY}" 45; then
  fail "evicted: tsi-peer-a registered again" 60
fi
ok "evicted: tsi-peer-a cannot register again"

step "final anchored set"
node_cli auth --circle "${CIRCLE}" members list 2>&1 | sed 's/^/    /' >&2
echo >&2; echo "MEMBERS-REGISTRATION PROOF (admission posture): PASS (circle ${CIRCLE})" >&2
