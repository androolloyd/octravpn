# Private administration for OctraVPN v5

`program/main-v5.aml` retains the v4 escrow paths and replaces the program owner's
public address with a SHA256 commitment to a random 32-byte administration
credential. The credential is a private prover witness. Neither its secret nor
an administrator wallet address is submitted to the program. v1-v4 remain
historical compatibility artifacts; they do not acquire these protections.
The current v5 settlement capability also binds the operator's byte count and
payment and captures the opening policy anchor; see [settlement-v5.md](settlement-v5.md)
for migration requirements and the remaining cooperative-payment assumption.

This implementation is a review candidate. Deployment still requires an
activated target proof profile, independent circuit/security review, a verified
multiparty Groth16 setup, selected network/genesis, approved economics and a
recovery rehearsal. No production setup or mainnet deployment is performed here.

## Authorization

The pinned arkworks 0.5 circuit verifies both:

```
commitment = SHA256("OctraVPN admin credential v1\0" || secret)
tag = SHA256("OctraVPN admin action v1\0" || secret || challenge)
challenge = SHA256("OctraVPN private admin v1|" || domain || "|" ||
                   program_address || "|" || decimal_nonce || "|" || action)
```

The domain is a reviewed SHA256 identifier for the protocol, network and genesis.
It is immutable constructor state, not an automatically discovered network ID.
Deployment tooling must bind it to the actual selected target. Reusing a domain
for another network weakens cross-network separation.

Public inputs are commitment, challenge and tag, each split into two big-endian
128-bit halves. Each half occupies a canonical 32-byte BN254 scalar. The contract
constructs those six fields itself, encodes them as canonical base64, and calls
the existing `groth16_verify_bn254` primitive. The verification key is immutable;
deploy verification pins its hash. The public `get_admin_verification_key_hash`
hashes the canonical **base64 text**, whereas the development setup manifest's
`verification_key_sha256` hashes the raw OG16 key bytes. They are different
fingerprints; do not interchange them.

Only typed decimal integers, valid Octra addresses and lowercase 64-character
digests enter the action transcript. Every administration parameter is bound.
The slashing beneficiary is explicit and proof-bound, rather than being the
transaction caller. Relayers may publish an unchanged authorization but cannot
redirect payouts or alter actions. The credential nonce advances only with the
successful action. Native journal rollback restores it on proof failure, business
revert or failed transfer. At `u64::MAX` administration fails closed.

The circuit and proving key are specific to this protocol. Local key generation
is deliberately exposed only as `setup --development` and writes
`development_only: true`, `production_ready: false`. Single-party setup does not
provide the trust guarantees needed for production. The CLI uses OS randomness
for credentials, setup and proof blinding; credential files are created exclusively
with mode 0600, and unsafe file permissions are rejected before proving. These
files need a separately reviewed backup/at-rest-encryption policy for launch.

## Handoff and rotation

The recipient creates its own credential and sends only its commitment to the
current administrator. The sender never needs the recipient's secret.

1. Current credential authorizes `propose_admin(next_commitment, kind, ...)`;
   kind 0 means handoff, kind 1 means rotation. The new commitment must differ.
2. A fresh handoff ID commits to current/pending commitments and the consumed
   nonce. Ordinary administration freezes while the handoff is pending.
3. Recipient authorizes `accept_admin(next_commitment, handoff_id, ...)` under the
   new credential. Acceptance consumes the current nonce, replaces authority and
   clears pending state atomically.

The current credential can instead authorize `cancel_admin(handoff_id, ...)`.
Cancellation consumes a nonce and invalidates queued acceptance. A later proposal
gets another handoff ID. Handoff, rotation and cancellation remain available while
the VPN is paused. Losing the only current credential before a recipient accepts
can permanently lock administration; this version has no hidden recovery wallet
or administrator-address fallback. Recovery must be designed/rehearsed explicitly.

Public commitments, action tags, nonces, proposed commitments, handoff linkage,
parameters and timing are observable. This hides administrator identity and secret
witnesses; it does not hide administrative activity. Use an independent relayer
to avoid revealing the administrator through the transaction sender/funding path.
Circle operator and tailnet-owner addresses remain part of their existing APIs.

## Native upgrade authority

Removing `self.owner` does not remove the native deployer's upgrade permission.
Upstream `Contract.upgrade` authorizes against program metadata before AML runs.
Changing that native check to verify private credentials would change consensus
execution rules and is outside the user's authorized scope.

Deploy v5 through `program/private-admin-factory.aml`. Its existing native `deploy`
primitive makes the factory program address the child's metadata owner. A wallet
cannot sign a native upgrade as that program address. The factory exposes child
deployment only, and the VM has no native child-upgrade capability available to
AML. Even the wallet that deployed the factory has no direct child-upgrade right
under the inspected upstream policy. Verify actual child metadata and both code
hashes; direct wallet deployment is not an acceptable private-admin launch route.

This route deliberately prevents in-place native upgrades under the current
runtime. A future application migration may use the same private authorization,
but must separately preserve escrow, state and client routing. No proxy,
delegatecall or automatic migration is claimed here.

## Tooling and tests

Build `cargo build --release -p octravpn-private-admin`. For isolated tests:

```
target/release/octravpn-private-admin setup --development --out /tmp/admin-setup
target/release/octravpn-private-admin credential --out /tmp/recipient.credential
```

The second command prints only the commitment. Create a public request file such
as `{"method":"set_paused","params":[1]}` and authorize it:

```
target/release/octravpn-private-admin authorize \
  --credential /tmp/recipient.credential \
  --proving-key /tmp/admin-setup/proving-key.bin \
  --request /tmp/request.json --domain REVIEWED_DOMAIN_HEX \
  --program DEPLOYED_VPN_ADDRESS --nonce CURRENT_NONCE \
  --out /tmp/authorization.json
```

Review the resulting method/params before a relayer submits them. For handoff the
request is `propose_admin` with `[recipient_commitment,0]`; acceptance is
`accept_admin` with `[recipient_commitment,handoff_id]`. Rotation uses kind 1 and
the identical acceptance flow. Cancellation uses `[handoff_id]`. Files containing
proofs are public authorization data, not credential backups.

`scripts/private-admin/run-e2e.sh` builds the pinned native builder and a test-only
adapter around the unchanged compiler, deployment/spawn/upgrade policy, VM,
Groth16 worker, journal and Irmin store. It runs with networking disabled. It uses
the existing Active VM modes; an explicit Prior-profile rejection control must
also pass. There is no verifier stub, signature surrogate, consensus edit or
test-only AML authorization bypass. Balances and terminal-nonce seeding are
explicit host fixtures. The test exercises cancellation, handoff, rotation,
revocation, action/parameter/domain/program binding, exact and rerandomized replay,
nonce races, rollback, storage restart and deployer upgrade rejection. This is
native host integration, not selected-chain transaction certification.

The standalone compiler also needs `scripts/private-admin/standalone-label-fix.patch`
on the pinned amlc source. It reserves dispatcher labels before allocating branch
labels for legacy contracts with many methods, fixing the collision exposed by
the appended v5 test suite. CI applies this tooling patch and runs a 105-method
regression. Native node/compiler/consensus sources are unchanged. Record the patch
hash with `prepare --compiler-patch scripts/private-admin/standalone-label-fix.patch`.

Prepare a fresh unsigned review bundle using `scripts/ceremony/prepare-candidate.py
prepare --program-version 5 --params ceremony/private-admin-candidate.toml.example
--amlc PATH --out FRESH_DIRECTORY`. Unselected admin fields remain explicit nulls
in the intent, never a fabricated deployable transaction. All readiness gates
remain unsatisfied until independently certified.

Pass `--compiler-upstream-commit FULL_COMMIT` only when the compiler's build
record identifies that source. The bundle records an unknown source commit when
this is omitted. A node reference pin does not establish compiler provenance;
the compiler binary and supplied patch files are always hashed separately.


## Canary security changes

V5 construction now has nine arguments: five economics, commitment, verification
key, domain, and immutable `max_locked_value`. The limited RC uses 200,000,000 OU
(200 OCT), including its 100 OCT stake. Zero means unbounded for a separately
reviewed release. Every payable funding method checks the native balance, which
already includes attached value. Unsolicited native transfers can bypass that
funding-method admission check; do not send native funds directly to the program.

Accepted admin commitments cannot be reused, including after a handoff or rotation.
Cancellation leaves an unused recipient available for a fresh proposal. Pause
blocks new admission while existing obligations remain recoverable without an
admin proof. The factory emits `VPNDeployed(child)` so the confirmed native receipt
identifies the child even when function return values are omitted.

See the [canary security review](audit/2026-10-11-canary-security.md) for the bounded
zero-escrow qualification runner, current evidence and remaining transport limits.
