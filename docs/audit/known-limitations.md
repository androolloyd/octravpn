# Known Limitations / Open TODOs

Every `TODO`, `FIXME`, `XXX`, `HACK`, `punted`, `Punted`, "not yet
wired", or "not yet implemented" comment in the in-scope tree
(crates/, fuzz/fuzz_targets/, docs/operators/) at the commit
recorded in `manifest.json`.

> Reproduce this list:
>
> ```sh
> grep -rn "TODO\|FIXME\|XXX\|HACK\|punted\|Punted\|not yet wired\|not yet implemented\|stub today" \
>   crates/ fuzz/fuzz_targets/ docs/operators/ \
>   | grep -v "/target/" | grep -v ".proptest-regressions"
> ```
>
> The vendored `aws-lc-sys` build artifacts under
> `fuzz/target/.../aws-lc-sys-*/out/include/openssl/*.h` are NOT
> first-party code and are excluded (they ship a few hundred upstream
> BoringSSL TODOs).

Each entry is classified:
- **S** — Security-relevant. Must be addressed before audit can
  certify the corresponding property.
- **P** — Performance / observability only. No security impact.
- **D** — Documentation only.

---

## crates/

### `crates/octravpn-core/src/v3_canonical.rs:181`

> `// serde_json::to_string emits raw UTF-8 (no \uXXXX escapes) for
> //   BMP chars >= 0x80. Match that.`

**Class: D (documentation comment, not a TODO).** Grep matched the
literal word "TODO" inside a normal-prose explanation of how the
canonical encoder matches `serde_json` behaviour. No outstanding
work.

---

### `crates/octra-circle-sim/src/lib.rs:29`

> `//!     CircleSim via the (TODO) HTTP control plane.`

**Class: P.** `octra-circle-sim` is an in-process simulator used by
tests only; it is not built into any production binary. The "HTTP
control plane" alluded to is for richer test ergonomics, not
correctness. Excluding it from scope (also called out in
`file-index.md` §9). No security exposure.

---

### `crates/octravpn-client/src/operator_backend.rs:20`

> `//! The v2 impl is a stub today — wire-up follows once Octra ships
> //! the Circle DSL (see docs/v2-circles-design.md §9).`

**Class: S, but cleanly fail-closed.** The v2 `CircleOperator`
settlement backend is unimplemented. The stub at line 102 returns
`anyhow::anyhow!("CircleOperator settlement not yet implemented …")`,
so any caller that tries to settle through the v2-circle backend
errors loudly rather than silently dropping receipts. v3 is the
production path; v2-circle is reachable only with
`v3_runner=false` + a v2-circle-configured operator backend.

**Action for auditor:** confirm there is no code path that catches
this error and treats it as success. Grep:

```sh
grep -rn "operator_backend\|CircleOperator" crates/
```

---

### `crates/octravpn-client/src/operator_backend.rs:103`

> `"CircleOperator settlement not yet implemented — pending Octra
> Circle DSL (see docs/v2-circles-design.md §9)"`

**Class: S (same item as above).** The error-message companion to
the stub comment. Same disposition.

---

### `crates/octravpn-node/src/tunnel.rs:131`

> `// TODO: instrument exact handshake completion when
> //   boringtun surfaces it.`

**Class: P.** Today the node bumps `wg_handshake_success_total` on
any `TunnResult::WriteToNetwork`, which is a conservative proxy that
over-counts keepalives. This is a Prometheus-metric accuracy issue,
not a security property. boringtun does not surface a "handshake
complete" event; until it does, the conservative bump is what we have.
No effect on AEAD safety, on receipt signing, or on the slash path.

---

### `crates/octravpn-node/src/control.rs:189`

> `// dashboard panel \`settled-vs-no-show ratio\` for the TODO.`

**Class: P.** Talks about a dashboard panel for a
`session_no_shows_total` counter that the settlement-side cross-
check has not yet started populating. The counter exists; the
cross-check that would bump it is the v3 settler integration. The
no-show condition is still detected by the on-chain `sweep_session`
path (drill: `e2e-adversarial-v3.sh` category E), so the absence of
the daemon-side counter is observability, not security.

---

## docs/operators/

### `docs/operators/mainnet-deployment.md:245`

> *TODO (production-readiness P0 item #3, task #216).* A future
> `octravpn-node v3 deploy-circle` subcommand will fold this into
> the daemon CLI. Until it lands, the manual `octra cast` step
> above is the path.

**Class: P (operator-ergonomic).** Folding `deploy_circle` into the
daemon does not change the on-chain semantics; the existing manual
flow signs exactly the same tx. The mainnet-deployment doc is the
canonical procedure today.

---

### `docs/operators/mainnet-deployment.md:359`

> *TODO (gap).* The `octravpn-node attest` one-shot verb the unit
> invokes is not wired yet (`Cmd::Attest` is absent in
> `crates/octravpn-node/src/main.rs`). The long-running daemon
> handles attestation refresh via the `[attestation]` poll loop;
> the timer is harmless but currently a no-op.

**Class: S (low-severity).** The systemd `octravpn-attest.timer`
unit references a CLI subcommand that does not exist. Until the
subcommand is added, the timer is a no-op. The daemon's in-process
attestation refresh runs unconditionally, so the security property
("the node periodically re-attests") is held — but an operator who
relies *only* on the timer (e.g. with the daemon disabled in
attestation mode) will see no attestations refresh. The
documentation calls this out; the timer should either be removed
from the systemd bundle or the `Cmd::Attest` verb added.

---

### `docs/operators/mainnet-deployment.md:423`

> There is no graceful-drain CLI today (TODO, task #216). The
> practical equivalent is to firewall-drop :443 for new
> connections while leaving :51820/udp open until in-flight
> sessions close (~`SESSION_GRACE` s).

**Class: P.** Decommissioning ergonomics. The lack of a one-shot
drain verb does not affect the slash, settle, or unbond invariants.
The documented `iptables` recipe achieves the same effect.

---

## fuzz/

No `TODO`/`FIXME` entries in `fuzz/fuzz_targets/` itself. The
generated `fuzz/target/` build artifacts contain many BoringSSL
upstream TODOs and are explicitly excluded.

---

## Punted items from release / threat-model docs

These are outside the `crates/ fuzz/ docs/operators/` grep but are
referenced from threat-model docs and are tracked here for the
auditor's awareness:

- **`docs/release.md` §7 "Punted (deferred follow-ups)"** —
  Windows + macOS release builds, OCI image publishing, Homebrew
  tap, SBOM publishing. **Class: D / supply-chain hygiene**, no
  runtime exposure.

- **PVAC / HFHE bridge not yet enabled on devnet.** Per memory
  `octra_aml_fhe_load_pk_blocked.md`, the chain does not currently
  execute `fhe_*` host calls for our deploys, so the HFHE-private
  earnings ledger is anchored as a sha256 hash chain
  (`crates/octravpn-core/src/earnings.rs`) rather than via Pedersen
  commitments under HFHE. **Class: S (residual privacy degradation
  vs the design target).** The current scheme provides
  tamper-evidence; it does not hide amounts from the chain. The
  threat-model summary marks this as a known privacy limitation.

- **Circles not yet executable on devnet.** Per memory
  `octra_circles_not_executable.md`, `deploy_circle` accepts +
  persists `code_b64` and computes a real `code_hash`, but
  `contract_call` returns `bytecode not found` on devnet. The v3
  architecture (`docs/v3-circle-resident-architecture.md`) is the
  workaround. **Class: D / design**, with a path forward marked
  forward-compatible.

- **JSON-RPC body cap 1 MiB on devnet.** Per memory
  `octra_devnet_rpc_body_cap.md`, the devnet nginx terminator
  rejects POST bodies > 1 MiB, which blocks PVAC pubkey
  registration (~4 MB). Mainnet accepts. **Class: D
  (configuration)**, no exposure on the audit surface.

- **AML map[address]string truncates at 4 KiB.** Per memory
  `octra_aml_string_cap_4kb.md`. We do not store anything larger
  than 4 KiB in a map value (only sha256 anchors); off-chain
  blob storage lives in circle sealed assets. **Class: D / design
  constraint** baked into the v3 schemas.

---

## Three items to flag first for the auditor

These are the items the OctraVPN team would want the auditor to
look at on day one, ranked by realistic blast radius:

1. **`crates/octravpn-client/src/operator_backend.rs` v2-circle
   stub.** The error message is the right shape, but the cleanness
   of fail-closed depends on every caller propagating the error.
   Specifically check that no caller in `settler.rs` or the v2
   runner downgrades the error to a warning that lets a session
   close "successfully" without a real settled receipt. If such a
   path exists, it lets a malicious operator + complicit client
   close a session without burning the bond evidence.

2. **`docs/operators/mainnet-deployment.md:359` —
   `octravpn-attest.timer` is a no-op.** A defense-in-depth check
   for the operator's on-disk attestation freshness is silently
   not running. The daemon's in-process loop is the load-bearing
   path; if a misconfiguration disables the daemon's attestation
   poll while the operator is relying on the timer, attestations
   go stale and a chain verifier could (rightly) refuse to slash
   or settle. Either remove the timer file from the systemd
   bundle or add `Cmd::Attest`.

3. **HFHE bridge unwired → earnings amounts visible on chain.**
   The hash-chain commit is tamper-evident but NOT hiding. Any
   on-chain observer who tracks a circle's per-epoch
   `claim_earnings` calls learns the per-epoch earnings amounts.
   This is a privacy degradation relative to the v2 threat model's
   design target. The audit-prep `threat-model-summary.md` flags
   this as a known privacy limitation, not a confidentiality
   defect, but auditors evaluating the privacy claims should be
   handed this constraint up front.
