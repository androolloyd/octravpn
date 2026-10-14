# OctraVPN v5 private administration review candidate

The v5 candidate replaces the program-owner address with a private credential
commitment and action-bound Groth16 authorization. No consensus rules, node
upgrade policy or activation plan were changed. v4 and its prior evidence remain
historical artifacts; they do not support private program administration.

The implementation covers every former program-owner action: pause, economic
parameters, program treasury withdrawal, operator registration approval and
governed slashing. Ownership transfer becomes recipient-accepted credential
handoff; credential rotation uses the same two-phase flow. Pending handoffs freeze
ordinary administration and can be cancelled using current authority. Each
successful operation consumes a nonce; reverts preserve it. Slashing payouts bind
an explicit beneficiary so a relayer cannot redirect the bounty.

| Verification | Result and scope |
| --- | --- |
| Native private administration integration | 114 checks passed with a fresh development setup and fresh credentials; real compiler, factory spawn, native metadata policy, AML VM, Groth16 worker, journal and Irmin storage |
| Handoff, rotation and revocation | Recipient acceptance required; cancelled/stale acceptance, sender impersonation, outsiders and fresh-nonce use of revoked credentials rejected |
| Replay and mutation | Exact/rerandomized replay, concurrent nonce reuse, changed program/domain/action/parameters/tag/proof rejected; nonce and commitment persisted across restart |
| Transfer atomicity | Failed bounty and treasury transfers rolled back all storage including credential nonce; the same authorization succeeded after the host recovered |
| AML fixtures | 21 v5 and 18 v4 tests passed against actual production method bodies; three negative controls and empty-test selection also passed |
| Circuit and CLI | Six Rust tests passed: relation/secret/message mutation, domain separation, typed transcripts, private-file permissions, exclusive creation and development-only setup gating |
| Native upgrade bypass | Child metadata owner is the factory; deployer/relayer wallet upgrade attempts rejected by unchanged native upgrade policy |
| Compiler regression | Original standalone compiler reproduced duplicate jump destinations in a large legacy dispatcher; tooling-only allocator patch passed the 105-method regression and preserved production v5 bytecode |
| Deployment verification | Correct private-admin/factory snapshot passed; six state/metadata mutations and missing factory evidence rejected |
| Strict workspace Clippy | Passed with all targets and features |

The native integration uses existing Active VM modes directly, rather than an
isolated chain's Prior profile. Its Prior-profile refusal is a required negative
control. Host balances and terminal-nonce seeding are explicit fixtures. This
does not certify transactions or execution on a selected mainnet network.

The program must be deployed through the reviewed factory. A direct wallet deploy
would preserve a public native upgrade authority outside AML. Under current
upstream policy, factory deployment prevents wallet upgrades of the child; it
does not implement private in-place native upgrades. Changing that native check
would change consensus execution rules and is outside this work's authorization.

Privacy covers administrator credentials and identity when independently relayed.
Commitments, handoff linkage, nonces, administrative actions/parameters, timing and
funding paths can remain observable. Operator/tailnet ownership is unchanged.
There is no hidden wallet fallback or recovery authority. Losing current authority
before successful handoff can permanently lock administration.

Launch is still **NOT_READY**. Required work includes selected chain/genesis/RPC
and proof profile, reviewed initial credential/domain/key fingerprint, independent
review of the circuit and contract, verified multiparty Groth16 setup, approved
economics, target-specific money/daemon tests and deployment/recovery rehearsal.
The local single-party setup is explicitly development-only. Repository changes
and standalone compiler patch must also be published/pinned before remote CI can
reproduce the reviewed source state; no GitHub CI run is claimed.

Implementation and operational details: [private administration](../private-administration.md).
Evidence: `out/private-admin-evidence-20261011/`. The public fixtures include
representative requests/proof packages and the development verification key,
never private credential files or proving keys. The unsigned v5 review bundle is
`out/mainnet-private-admin-candidate-20261011/`; it leaves unselected target and
administration parameters null rather than inventing a launch transaction.
