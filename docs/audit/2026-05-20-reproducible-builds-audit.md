# Reproducible Builds + Signing-Chain Audit — 2026-05-20

**Scope.** Three sibling workspaces that ship binaries together:
- `octra/` — `octravpn-node`, `octravpn-client` (binary name `octravpn`),
  and `octra-pvac-sidecar` (C++ under `pvac-sidecar/`).
- `octra-foundry/` — `octraforge`, `octra-mock-rpc`.
- `headscale-rs/` — `headscale-cli` (binary `headscale`).

**Audited HEADs.** `octra` `aa25abc1ac1869dd0e1e98bf5d58faf5305fe83f`
(measurements at original worktree head
`11f83a198b7b04e5a79ebc00a238d7326888337a`; the worktree updated mid-audit
when another agent merged the supply-chain audit — signing-chain analysis
is unchanged at either tip).
`octra-foundry` `42f4b22e648b0b7726185f10252c98b8961e4765`.
`headscale-rs` `fd95f57f702a429126be8392624d8dda84885a7e`.

**Methodology.** `cargo build --release -p <crate>` twice into disjoint
`CARGO_TARGET_DIR=/tmp/repro/{t1,t2,…}`s, on macOS 25.1 / Apple Silicon
/ rustc 1.88.0 / cargo 1.88.0 — same toolchain the `release.yml`
`stable` channel selects. Full workspace build is 16-20 min per pass;
per the audit's extrapolation clause, `octravpn-client` (built in the
same cargo pass as the node), `headscale-cli`, `octraforge`, and the
C++ `octra-pvac-sidecar` were not built twice — same non-determinism
classes apply. Cross-reference: §6 of
`docs/audit/2026-05-20-supply-chain-audit.md` covers the same ground
at the exec-summary altitude. This is the byte-level deep dive.

---

## 1. Reproducibility status

### 1.1 Headline result

| Artifact            | Build pair              | Hash                                                               | Identical? |
|---------------------|-------------------------|--------------------------------------------------------------------|------------|
| `octravpn-node`     | `t1` ↔ `t2` (same host) | `0651671c4dc19ca96d91e6b272e228c5a344fa035a379bfe9c79ddb628483f5c` | **YES**    |
| `octra-mock-rpc`    | `f1` ↔ `f2` (same host) | `9c14ce1e315f34505a37ba4553ffe7d3d83b32738a2163ae16253654bdf3c346` | **YES**    |
| `octra-mock-rpc`    | `f1` ↔ `f3` (different source path, same host) | same hash as above           | **YES**    |
| `octravpn-client`   | extrapolated (single-cargo-pass with node) | — (not measured separately) | likely YES |
| `octraforge`        | not measured            | —                                                                  | unknown    |
| `headscale-cli`     | not measured            | —                                                                  | unknown    |
| `octra-pvac-sidecar` (C++) | not measured     | —                                                                  | unknown    |

**Surprising finding.** Two clean cargo builds of `octravpn-node`
from the same source tree on the same host, into disjoint
`CARGO_TARGET_DIR`s, produced **byte-identical** binaries (SHA-256
`0651671…`). The same held for `octra-mock-rpc`, **even when the
source tree itself was relocated** (`/Users/.../octra-foundry/` vs
`/tmp/repro/foundry-clone/`). Cargo's release-mode output is
deterministic when the toolchain, `$CARGO_HOME`, target triple,
and lockfile are all held constant — even without
`--remap-path-prefix` or `SOURCE_DATE_EPOCH`.

This contradicts what most people (including §6 of the supply-chain
audit) assume about Rust reproducibility. The non-determinism
classes that bite production releases are still real; they just
don't fire on this measurement pair. They will fire across the
following dimensions:

### 1.2 Non-deterministic dimensions (predicted, not all measured)

| # | Source                                                                                                                            | Severity | Today? | Fix                                                       |
|---|-----------------------------------------------------------------------------------------------------------------------------------|----------|--------|-----------------------------------------------------------|
| R1 | Embedded `$CARGO_HOME` path (`/Users/androolloyd/.cargo/registry/…`) appears 530 times in `octravpn-node`'s `.rodata`              | high     | yes (cross-machine) | `--remap-path-prefix $HOME/.cargo=/cargo`           |
| R2 | Embedded workspace path (`/Users/androolloyd/Development/octra/crates/…`) appears 11 times in `octravpn-node`'s `.rodata`         | high     | yes (cross-machine) | `--remap-path-prefix $PWD=/build`                   |
| R3 | rustc commit (e.g. `/rustc/6b00bc3880198600130e1cf62b8f8a93494488cc/library/...`) embedded in panic strings of `std`               | medium   | yes (cross-toolchain) | Pin `rust-toolchain.toml` to an exact stable patch like `1.88.0` (already done — but CI uses `dtolnay/rust-toolchain@master` with `toolchain: stable`, which **ignores** the file unless explicitly told to read it) |
| R4 | `cargo deb` and `cargo generate-rpm` embed a build timestamp in package headers                                                  | medium   | yes    | Export `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` before the package step in `release.yml` |
| R5 | `tar -czf` (line 178 of `release.yml`) embeds mtime + uid/gid into the gzip stream                                                | medium   | yes    | Replace with `tar --sort=name --owner=0 --group=0 --mtime=@$SOURCE_DATE_EPOCH \| gzip -n` |
| R6 | `cargo` chooses a target-dir-relative incremental cache hash; we *avoid* this by using `--release` (incremental off in release)  | low      | no     | already mitigated                                          |
| R7 | The `Swatinem/rust-cache@v2` step on CI uses a cache that may keep stale `target/build/` build-script outputs across runs        | low      | possibly | `cache: false` on the release lane only (CI: caches are fine on the lint lane) |
| R8 | C++ sidecar Makefile invokes `g++` with `-march=native` on the host (only `-march=x86-64-v2` / `armv8-a+crypto` inside Docker)   | high     | yes (host build) | The Docker build path is already arch-pinned; the Makefile host path is a developer-convenience tool only — document that release builds MUST go through the Dockerfile |
| R9 | `headscale-api/build.rs` invokes `tonic-build`/`prost-build` which writes generated `.rs` into `src/generated/` on every build    | medium   | unknown | `tonic-build` is reproducible upstream as of 0.13; verify the version pinned in `headscale-rs/Cargo.toml` is ≥ 0.13. |

**Why R1 + R2 are filed "yes (cross-machine)" but didn't fire on
this measurement.** The single-machine pair holds `$CARGO_HOME`
constant (both builds saw `/Users/androolloyd/.cargo/registry`),
so the string is identical in both binaries. The moment a CI
runner whose `$HOME=/home/runner` rebuilds the same tag, the
embedded path becomes `/home/runner/.cargo/registry` → different
bytes → different SHA-256.

> **Fixed in this commit** (`modularize-4-audit-v2`, "audit: 4
> launch-critical follow-ups"). `.cargo/config.toml` now sets
> workspace-wide `RUSTFLAGS` with three `--remap-path-prefix`
> rewrites collapsing `/Users/`, `/home/`, and `/root/` prefixes
> to a host-independent `user/` stand-in. This addresses R1+R2
> at the source level so the same flags fire on local
> `cargo build --release` and CI alike — no `release.yml`-only
> override required. The remaining cross-env work (R3 rustc
> commit string, R4 deb/rpm timestamp, R5 tar gzip header) is
> still §6 T2.1 follow-up; R3 in particular needs the rustc
> toolchain path remap which only `release.yml` can plumb
> through (CARGO_HOME / RUSTUP_HOME are not stable at config-
> load time on a fresh CI runner).

### 1.3 The `.deb` + `.rpm` packaging step

`cargo deb` and `cargo generate-rpm` embed a build timestamp
(`Date:` in deb control, `BuildTime` in rpm header) and preserve
the binary's `mtime` into the archive. `cargo-deb` 3.0+ honours
`SOURCE_DATE_EPOCH` (the v3.7 pin in `release.yml` line 120 is
new enough); `cargo-generate-rpm` needs explicit `--metadata`
plumbing for a fixed `BuildTime`. Without `SOURCE_DATE_EPOCH`,
every release rebuilt at a different wall-clock instant yields
a different `.deb`/`.rpm`/`.tar.gz` SHA-256 from the same git tag
(`tar.gz` because the staging dir mtime lands in the gzip stream
header).

### 1.4 What was actually measured

```sh
$ sha256sum /tmp/repro/t1/release/octravpn-node /tmp/repro/t2/release/octravpn-node
0651671c4dc19ca96d91e6b272e228c5a344fa035a379bfe9c79ddb628483f5c  /tmp/repro/t1/release/octravpn-node
0651671c4dc19ca96d91e6b272e228c5a344fa035a379bfe9c79ddb628483f5c  /tmp/repro/t2/release/octravpn-node

$ sha256sum /tmp/repro/foundry1/release/octra-mock-rpc /tmp/repro/foundry2/release/octra-mock-rpc /tmp/repro/foundry3/release/octra-mock-rpc
9c14ce1e315f34505a37ba4553ffe7d3d83b32738a2163ae16253654bdf3c346  /tmp/repro/foundry1/release/octra-mock-rpc
9c14ce1e315f34505a37ba4553ffe7d3d83b32738a2163ae16253654bdf3c346  /tmp/repro/foundry2/release/octra-mock-rpc
9c14ce1e315f34505a37ba4553ffe7d3d83b32738a2163ae16253654bdf3c346  /tmp/repro/foundry3/release/octra-mock-rpc
```

`cmp` exit codes were 0 for both pairs. Build 3 was from a
different source directory (`/tmp/repro/foundry-clone/`) but the
same `$CARGO_HOME` — confirming R2 only bites when crate code
contains a `panic!()`/`assert!()` whose backtrace references a
workspace-local file, *and* the source path differs.

`octra-mock-rpc` happens to contain no `panic!()` invocations of
its own (only library calls into deps which embed their own
crates.io paths), so R2 didn't fire. `octravpn-node` does, and
its 11 workspace-local strings would differ on a CI runner.

---

## 2. Signing-chain trace

### 2.1 Workflow path

`v*` tag push → `.github/workflows/release.yml` →
1. Build (`cargo build --release -p octravpn-node -p octravpn-client`) on `ubuntu-latest`.
2. Package (`cargo deb`, `cargo generate-rpm`, `tar -czf`).
3. **Sign** (`gpg --detach-sign --armor`), gated on `secrets.RELEASE_GPG_KEY` being set.
4. Compute `SHA256SUMS`.
5. Upload to a **draft** GitHub release.

No other path produces an "official" artifact — there is no
manual `workflow_dispatch`, no PR-triggered release.

### 2.2 Key material

| Field                | Value                                                                |
|----------------------|----------------------------------------------------------------------|
| Algorithm            | GPG (per `docs/release.md` §5, recommendation is ed25519/cv25519)    |
| Storage              | GitHub Actions **encrypted secret** `RELEASE_GPG_KEY` (base64 ASCII-armored private key) + `RELEASE_GPG_PASSPHRASE` |
| Decryption           | Materialised at job scope into `env:` (workaround for GitHub's restriction on `secrets.*` in `if:` predicates) |
| In-CI key handling   | Decoded into a temp file, imported into the runner's GPG keyring, temp file `trap rm`'d on EXIT |
| Public-key publication | `docs/release.md` §5 lists three placeholders (Fingerprint / Key URL / Algorithm) all marked **_UNSET_** |
| Verification fingerprint | **Not yet pinned anywhere** — neither in `SECURITY.md`, `README.md`, nor `docs/release.md` |

The signing block was added but never activated: the workflow
runs green today producing **unsigned** `.deb` / `.rpm` / `.tar.gz`
artifacts plus an unsigned `SHA256SUMS`.

### 2.3 Verification command (the one downstream operators will run)

The aspirational verification path from `docs/release.md` §6:

```sh
curl -fsSL https://octra.org/keys/octravpn-release.asc | gpg --import
gpg --verify octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz.sig \
            octravpn-0.1.0-x86_64-unknown-linux-gnu.tar.gz
sha256sum -c SHA256SUMS --ignore-missing
```

**This will fail today** because:
1. `https://octra.org/keys/octravpn-release.asc` is not an active URL.
2. `SHA256SUMS` itself is unsigned — `gpg --verify SHA256SUMS.sig SHA256SUMS` is in §6 but `release.yml` does not actually sign `SHA256SUMS` (it's globbed into the same `for artifact in dist/*` loop, but the loop runs **before** `SHA256SUMS` is generated; line 223-228 generates `SHA256SUMS-<target>` *after* the sign step at line 194-221).
3. The fingerprint table in §5 is empty.

**There is a more critical, separate mismatch.** `deploy/install.sh`
lines 108-123 — the *POSIX universal installer at
`curl -fsSL https://octravpn.org/install.sh | sh`* — looks for a
**`.minisig` sidecar** (minisign signatures, not GPG) and a
pubkey at `$HOME/.minisign/octravpn.pub`. The release workflow
produces `.sig` (GPG armored detached) sidecars instead.
**Operators using the documented one-liner installer will never
verify a signature** — the script silently warns and proceeds
with the unverified tarball.

### 2.4 Key rotation

`docs/maintenance/rotation-master.md` covers wallet keys, attestation
keys, TLS keys — but **not** the release signing key. There is no
runbook, no calendar reminder, no subkey expiry, no published
revocation procedure. The `RELEASE_GPG_KEY` GitHub secret, once
populated, would persist indefinitely.

---

## 3. Single-point-of-failure register

| # | SPOF                                                                                                                                              | Blast radius                                                                              | Detection                                       |
|---|---------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------|-------------------------------------------------|
| S1 | **GitHub Actions secret `RELEASE_GPG_KEY` is the sole signing key.** No HSM, no offline master, no subkey hierarchy.                              | Every release since the secret was first populated is suspect on compromise.              | None — no transparency log, no public key history. |
| S2 | The GitHub organisation `octra-labs/octravpn` write-access set is the trust root. A maintainer account compromise → can push a malicious `v*` tag. | The push triggers `release.yml` which signs the malicious tag with the legitimate key.    | None automatic; PR review doesn't cover tag-push. |
| S3 | The `dtolnay/rust-toolchain@master` step on every run pulls a non-content-addressed action revision (`@master`).                                  | A typosquat or maintainer compromise on the action can inject `RUSTFLAGS` into the build. | `git log` on `dtolnay/rust-toolchain` (manual). |
| S4 | `actions/checkout@v4`, `Swatinem/rust-cache@v2`, `actions/upload-artifact@v4`, `actions/download-artifact@v4`, `softprops/action-gh-release@v2` — all pinned by major version tag (mutable), not commit SHA. | Same as S3, multiplied by 5 actions.                                                      | None — mutable tags can be re-pointed. |
| S5 | `crates.io` registry — every `cargo build` resolves 542 transitive crates from a single index host (`index.crates.io`).                          | A registry compromise (or a sidecar typosquat) injects code into the binary.              | `cargo audit` catches *known* RUSTSEC entries; no general SBOM diff between releases today. |
| S6 | The `cargo install cargo-deb --version ^3.7` and `cargo install cargo-generate-rpm --version ^0.16` invocations in `release.yml` lines 120-121 pull from crates.io at release time with caret-range. | A malicious patch release (3.7.x) of either tool is automatically picked up.              | Cache key bumps require operator action. |
| S7 | Pvac-sidecar Dockerfile uses `debian:bookworm-slim` without digest pinning.                                                                       | Debian image-tag retargeting can swap the base image.                                     | None automatic. |
| S8 | `docs/release.md`'s aspirational pubkey URL (`https://octra.org/keys/octravpn-release.asc`) is not served. A DNS/HTTP MITM on first download is undetectable. | First-fetch-trust (TOFU) verification only.                                              | TLS pinning + key-server fingerprint comparison. |

**The single biggest SPOF is S1 — the GH-secret-only signing key.**
A compromise of any GitHub admin account ⇒ signature authority
over the entire fleet, with no offline verification anchor.

---

## 4. Provenance gaps

What an external auditor (e.g. a Linux distro packager, a corporate
security review) would expect to see, mapped against what we ship:

| Provenance artefact                                                                          | Expected | Shipped today |
|----------------------------------------------------------------------------------------------|----------|---------------|
| **SLSA-level attestation** — `actions/attest-build-provenance` or `slsa-github-generator` produces a verifiable predicate (builder identity, source commit, build inputs). | SLSA L3 | None |
| **CycloneDX / SPDX SBOM** — full transitive-dep manifest pinned by hash, attached to the release. | Yes (CycloneDX from `cargo-cyclonedx`) | None. `docs/release.md` §7 explicitly notes "SBOM publishing is not yet attached — the prior workflow had a `sbom` job; it'll come back". |
| **Sigstore/Rekor transparency entry** — `cosign sign-blob --bundle` writes an entry to the public log so a future "this artifact was signed at time T by key K" claim is independently verifiable. | Yes | None |
| **Reproducibility manifest** — a published `BUILD_INPUTS.txt` listing toolchain version, `Cargo.lock` SHA-256, packager versions, runner image digest, so a downstream verifier can recreate the env. | Yes | None |
| **Signed `Cargo.lock`** — the lockfile is in-repo and committed, but a fresh checkout could in principle have its `Cargo.lock` swapped before build. | Lock pinned by tag's commit SHA | The release lane checks out by tag via `actions/checkout@v4`; the resolved commit pins the lockfile, but the binary doesn't *embed* the Cargo.lock SHA-256, so a verifier can only check by re-cloning. |
| **Runner image digest** — `ubuntu-latest` is a moving target; SLSA wants the exact runner SHA recorded. | Yes (`runs-on: ubuntu-24.04` + image digest annotation) | None — uses bare `ubuntu-latest` everywhere. |
| **Embedded `--version` output containing commit + toolchain** — operators can run `octravpn-node --version` and compare. | Yes | `octravpn-node --version` prints the workspace `Cargo.toml` version (`0.1.0`). No git commit, no rustc version, no build timestamp. (Confirmed: no `build.rs` in `crates/octravpn-node/`; no `vergen` / `git2` / `env!("VERGEN_*")` usage.) |

**The minimum increment that makes the chain useful to a third-party
verifier** is rows 1, 2, 3, 4, and 7. Row 7 (commit + rustc in
`--version`) is the easiest — adding `vergen` to `octravpn-node`
exposes the commit hash inside the binary, so even without
reproducibility a `sha256sum` of the binary plus a trusted
`--version` output gives a one-step "this is the right commit"
check.

---

## 5. Distribution channels + TUF considerations

### 5.1 Today's channels

| Channel                                                                                  | URL                                                                            | TLS? | Pinned? |
|------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------|------|---------|
| GitHub Releases                                                                          | `https://github.com/octra-labs/octravpn/releases/<tag>/`                       | yes  | TLS via GitHub's cert chain; no SPKI pin |
| One-liner installer                                                                       | `curl -fsSL https://octravpn.org/install.sh \| sh`                              | yes  | No SPKI pin on the script URL; no pinning of the downloaded binaries either |
| Homebrew tap (skeleton)                                                                  | `deploy/homebrew/octravpn.rb` (not yet published per `docs/release.md` §7)     | n/a  | n/a (deferred) |
| Debian APT / RPM repo                                                                    | None — operators download the `.deb`/`.rpm` and `dpkg -i` / `rpm -i` directly | —    | — |
| OCI containers                                                                           | None — `docs/release.md` §7 calls this out as deferred                          | —    | — |

The installer downloads from `${OCTRAVPN_RELEASES_URL:-https://github.com/octra-labs/octravpn/releases}` (line 22) — so the canonical download is through GitHub's CDN. GitHub's TLS chain is the **only** authentication of the binary if the minisign verification path is absent (which it is — see §2.3).

### 5.2 TUF (The Update Framework) gap analysis

If auto-update is added later (production-readiness doc contemplates
this but doesn't schedule it), the minimum useful TUF deployment is
the standard 4-role layout: `root` (2-of-3 multi-sig across offline
YubiKey + `octra.org` infra + external third party; rotated ≈5y),
`targets` (signs every release binary's hash, in-CI delegated key),
`snapshot` (auto-rotated weekly, prevents mix-and-match rollback),
`timestamp` (auto-rotated daily, freshness). Without TUF, today's
auto-update story is "trust the GPG sig over latest GitHub release"
— fine for manual install but fragile for background updates: no
key-revocation propagation, no rollback-attack detection, no
recovery from a single compromised signing key. **Recommendation:
do not add auto-update before TUF lands.**

---

## 6. Remediation plan (ranked by effort)

Ranked by `(impact ÷ effort)` — highest leverage first.

### Tier 1 — same-day, hours of work

**T1.1 — Publish the GPG fingerprint NOW, even before a key is generated.** 
Decide the algorithm (ed25519 subkey under an offline master is
the standard), generate it offline, populate the `RELEASE_GPG_KEY`
secret, and write the fingerprint into `SECURITY.md` and
`docs/release.md` §5. Effort: <1 day. Impact: every downstream
user gets a canonical key to pin.

**T1.2 — Fix the installer / release mismatch.** Decide GPG **or**
minisign and make both `release.yml` and `deploy/install.sh` agree.
Recommended: stay on GPG (broader operator tool baseline), patch
the installer to fetch `.sig` not `.minisig`, and ship a
`octravpn-release.asc` to `https://octravpn.org/keys/`. Effort: <1 day.

**T1.3 — Hard-fail unsigned releases on `v*` tags.** Change
`release.yml` line 200 from
`if: ${{ env.RELEASE_GPG_KEY != '' }}` to a job-level guard that
fails when the secret is missing on a `v*` tag (allow it to skip
only on `v0.0.*-rc*` candidate tags). Effort: 1 hour.

**T1.4 — Sign `SHA256SUMS` itself.** Move the `gpg --detach-sign`
loop to run **after** `SHA256SUMS-<target>` is generated, or add
a follow-up sign call in the `publish:` job after `SHA256SUMS` is
consolidated. Effort: 1 hour.

### Tier 2 — one week, single-engineer

- **T2.1 — Add `--remap-path-prefix` + `SOURCE_DATE_EPOCH` to `release.yml`.** Set `RUSTFLAGS="--remap-path-prefix ${{ github.workspace }}=/build --remap-path-prefix /home/runner/.cargo=/cargo"` and `SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)` before the build step. Fixes R1 + R2 + R3 + R4. Effort: 1 day.
- **T2.2 — Bake commit + toolchain into `--version`.** Add `vergen` + `build.rs` to `crates/octravpn-node`; emit `GIT_COMMIT`, `RUSTC_VERSION`, `BUILD_TIMESTAMP` for `octravpn-node --version`. Effort: 2h.
- **T2.3 — Pin GitHub Actions by commit SHA.** Replace every `@v4`/`@v2` with the resolved SHA; configure Dependabot for the actions ecosystem. Closes S3 + S4. Effort: 90min.
- **T2.4 — CycloneDX SBOM per release.** Wire `cargo-cyclonedx` into `release.yml`; attach `octravpn-<version>.cdx.json` to the release. Effort: half a day.

### Tier 3 — month-long, multi-engineer

- **T3.1 — Offline GPG master + 90-day subkey to GitHub.** Master on YubiKey in a safe; `[S]` subkey with `expire 90d` in `RELEASE_GPG_KEY`. Add quarterly calendar + `docs/maintenance/release-key-rotation.md`. Effort: 1 week + 0.5d/quarter.
- **T3.2 — Sigstore/cosign alongside GPG.** `cosign sign-blob --bundle` per artifact; Rekor transparency log answers S1's "no detection" problem. Effort: 1 week.
- **T3.3 — SLSA L3 via `slsa-github-generator`.** Replace hand-rolled build step with the SLSA reusable workflow; produces a signed provenance attestation. Effort: 2 weeks incl. parallel-run.
- **T3.4 — Containerise the release build.** Pinned `debian:bookworm-...@sha256:...` builder on `ghcr.io/octra-labs/release-builder`. Closes S7. Effort: 1 week.

### Tier 4 — quarter-long / strategic

- **T4.1 — TUF deployment** (defer until auto-update requested; see §5.2). 4-6 weeks.
- **T4.2 — Independent reproducible-build verifier.** Public `verify.octra.org` that rebuilds at each tag and publishes its own SHA256SUMS. 3 weeks.

---

## Report summary

- **Commit hashes audited.**
  - octra `aa25abc1ac1869dd0e1e98bf5d58faf5305fe83f`
    (measurements at `11f83a198b7b04e5a79ebc00a238d7326888337a`).
  - octra-foundry `42f4b22e648b0b7726185f10252c98b8961e4765`.
  - headscale-rs `fd95f57f702a429126be8392624d8dda84885a7e`.
- **Binaries reproducible (measured, same-host pairs):** 2 of 2.
  (`octravpn-node`, `octra-mock-rpc`. Cross-host reproducibility is
  predicted to fail without R1-R5 mitigations.)
- **Binaries not measured but in scope:** 4
  (`octravpn-client`, `octraforge`, `headscale-cli`, `octra-pvac-sidecar`).
- **Biggest signing-chain SPOF.** S1 — the GPG release key lives
  *only* as a GitHub Actions secret, with no offline master, no
  subkey hierarchy, no transparency-log shadow record, and no
  rotation runbook. A single org-account compromise gives
  signature authority over every release.
- **Highest-leverage one-line remediation.** **Pin the GPG
  fingerprint in `SECURITY.md` and `docs/release.md` §5** (T1.1).
  No code changes; gives every downstream verifier a canonical key
  to compare against, immediately unblocking the documented
  `gpg --verify` flow.
