# VPN settlement amount binding

The current v5 application advertises `get_settlement_version() == 2`.
Clients must check this capability before funding. Its operator call is
`settle_claim(session_id, bytes_used, net)`, with `net` in raw microOCT.
The claim binds both values, requires `net <= session_deposit`, and permits a
zero-byte close only with zero payment. Repeating the same pair is idempotent.
Changing either value follows the existing operator-equivocation path: refund
the escrow, close the session and leave slashing to governance adjudication.
The original claim remains available as evidence, including an explicit amount
dispute event. Settlement credits the entire agreed traffic payment; the
protocol takes no commission.

`settle_confirm` requires an explicitly recorded operator amount and an exact
match before changing confirmation state or moving value. An opener cannot
turn a paid claim into a zero-credit close by keeping the same byte count.
Receipt v1 signatures authenticate usage and session identity; they do not
independently sign a price or a net amount. The operator's authenticated claim
and the opener's matching confirmation supply that amount agreement.

`write_session` captures the operator's current immutable policy anchor in
`session_policy_root` in the same application execution that creates escrow.
Changing the operator's advertised policy later cannot replace those opening
terms. Clients verify the captured anchor before forwarding traffic and load
the corresponding immutable, hash-verified policy. A policy read from the end
of the opening epoch alone is insufficient: an anchor can change later in the
same epoch.

The three new maps are appended after the existing state declarations. An old
bytes-only claim has no `operator_claim_net_set` flag and cannot be confirmed
as an implied zero amount. Its authenticated operator may bind an amount by
resubmitting the same byte count through the new three-argument call. A legacy
session without a captured policy anchor cannot obtain an authenticated
historical quote; the client fails closed rather than substituting the current
policy. Existing timeout/refund paths remain available. This is an application
migration constraint, not an automatic upgrade or a consensus change.

This remains cooperative two-transaction settlement. A malicious opener can
refuse to confirm a valid claim; after the existing stretched sweep deadline,
the escrow is refunded with the configured keeper bounty and the operator
receives no traffic credit. An amount check does not solve that noncooperation
or prove delivery. Operators must bound outstanding unpaid traffic, and a
production decision must explicitly accept this economic assumption or adopt a
separately reviewed payment mechanism. The relay lane likewise requires an
opener commitment and has its own timeout/refund rules; it is not an implicit
unilateral recovery path for every two-transaction session.

The native security transcript runs production method bodies with isolated AML
test fragments and records successful transfer callbacks. It proves VM state,
effort, events and refusal behavior, rather than real account funding. The
combined node/client gate separately qualifies actual escrow and transfers.
