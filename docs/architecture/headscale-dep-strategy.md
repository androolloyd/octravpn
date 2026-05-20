# headscale-rs / octra-foundry dependency strategy

**Status.** Decision. Picks **Option D (hybrid path-dep + version-pin)**
for the `octra` ↔ `headscale-rs` ↔ `octra-foundry` triangle. Supersedes
the ad-hoc sibling-checkout pattern that has bitten CI twice
([`722fbe2`](#cited-commits) and [`0273183`](#cited-commits)).

**Owner.** `andrew@golast.xyz` (also de-facto upstream maintainer of
`headscale-rs` — see [§ Operational reality](#operational-reality)).

**Scope.** Build-system + release strategy only. Does not touch runtime
APIs, ABI, or operator-facing CLI surfaces.

---

## 1. Problem

Three repos sit as siblings on disk:

```
~/Development/
├── octra/            # this repo
├── octra-foundry/    # chain primitives (octra-core, etc.)
└── headscale-rs/     # tailscale control-plane port (headscale-api, etc.)
```

Two `Cargo.toml` files in this repo path-dep into the other two:

- [`crates/octravpn-mesh/Cargo.toml:23`](../../crates/octravpn-mesh/Cargo.toml)
  → `headscale-api = { path = "../../../headscale-rs/headscale-api", default-features = false }`
- [`crates/octravpn-core/Cargo.toml:11`](../../crates/octravpn-core/Cargo.toml)
  → `octra-core = { path = "../../../octra-foundry/crates/octra-core" }`

This works for the canonical maintainer's laptop and nowhere else.
Concrete pain:

- **CI fragility (bitten twice).**
  - [`0273183`](#cited-commits) — the nightly fuzz workflow failed at
    cargo resolution because only `octra` was checked out; every fuzz
    target died before reaching libfuzzer. Fix: clone
    `octra-foundry` as a sibling in the same job.
  - [`722fbe2`](#cited-commits) — every cargo step in `ci.yml`
    (fmt, clippy, test, criterion, bench-gate) failed at workspace
    manifest resolution after `headscale-api` was added as a path-dep.
    Fix: add a third `actions/checkout` for `headscale-rs` to **10
    job sites**.
  - [`f682495`](#cited-commits) is adjacent — a fuzz dep gap masked
    by the same sibling-checkout failure mode.
- **New-contributor onboarding.** Clone *three* repos in the right
  order, into the right relative layout, before any `cargo build`
  works. `git clone https://github.com/.../octra` produces a tree that
  fails to build with no hint of what's missing.
- **Cross-repo atomic changes.** Wall 7 (PSK-knock) needed matching
  edits in `headscale-api/src/tailscale_wire/knock.rs` **and**
  `octravpn-node`. With sibling repos, this is two PRs in two repos
  with no atomic merge primitive — one merges first, breaks the other
  side until the second merges.
- **Downstream consumers.** Anyone who wants `octravpn-client` from
  crates.io today: impossible. The crate refuses to publish because
  path-deps without a version are unpublishable. Even after that's
  fixed, consumers still need a way to consume just what they need.
- **Release versioning.** Mainnet readiness needs a clean "we shipped
  version X" story across all three repos. Today: no story.

## 2. Options considered

### Option A — Git submodules

`headscale-rs` and `octra-foundry` become submodules of `octra` at
`vendor/headscale-rs` and `vendor/octra-foundry`.

| Aspect              | Outcome                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| CI fragility        | Solved (`git clone --recursive`).                                         |
| Onboarding          | One command (`--recursive`), but `git pull` does **not** update submodules — `git submodule update` is a separate step engineers routinely forget. |
| Atomic changes      | Half-solved: one commit per repo + one bumping the submodule SHA.         |
| Downstream consumers| Bad. `crates.io` can't see submodules; a published `octravpn-client` still couldn't compile downstream.                                              |
| Release versioning  | OK — submodule SHA is the version.                                        |
| Reputational        | Submodules are a recurring footgun (detached HEAD, missed updates, merges that resolve to "you forgot to update the submodule"). Half the engineering world avoids them on principle. |

**Verdict.** Solves CI + onboarding, fails downstream + has a long tail
of UX traps. Pass.

### Option B — Single monorepo workspace

Merge all three repos. `octra-foundry/` and `headscale-rs/` become
subdirectories of `octra/`. Top-level `Cargo.toml` workspace lists
everything.

| Aspect              | Outcome                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| CI fragility        | Solved.                                                                   |
| Onboarding          | Best: one `git clone`, `cargo build`.                                     |
| Atomic changes      | Best: one PR, one merge.                                                  |
| Downstream consumers| Mixed. Still need to publish per-crate to crates.io for downstream pulls. |
| Release versioning  | Mixed — one version covers all three or per-crate versions diverge inside one repo. |
| History surgery     | Painful — `git subtree merge` preserves history but produces a tangled DAG. Alternative `git filter-repo` loses cross-repo blame. |
| Repo identity       | `headscale-rs` loses its standalone identity. Some folks specifically want a separate `juanfont/headscale`-style Rust port repo to PR to. We currently don't have those folks, but the option to attract them disappears here. |
| External contributors | Bad. Anyone who wants to PR just to `headscale-rs` would have to clone all of OctraVPN. Discoverability collapses. |

**Verdict.** Operationally best for *us today* but burns the bridge to
a community-maintained `headscale-rs` and is expensive to reverse. Pass
unless we explicitly decide we never want external `headscale-rs`
contributors.

### Option C — Publish to crates.io, version-pin

`headscale-api`, `octra-core`, etc. become published crates.
`octravpn-mesh/Cargo.toml` deps `headscale-api = "0.3.2"`.

| Aspect              | Outcome                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| CI fragility        | Solved (`cargo fetch` against crates.io).                                 |
| Onboarding          | Best: one `git clone`, `cargo build`.                                     |
| Atomic changes      | **Worst.** Cross-repo change needs a 2-PR dance: publish `headscale-api 0.3.3` *first*, then PR `octravpn-mesh` to bump the version. Reverts are a 2-step rollback. Pre-release coordination (a `headscale-api 0.3.3-rc.1`) is awkward. |
| Downstream consumers| Best: standard cargo workflow, semver expectations honoured.              |
| Release versioning  | Best: explicit, semver, dated.                                            |
| Release cadence     | Forces it. **This is a feature, not a bug** for mainnet readiness — but it's a discipline tax for daily dev (right now: ~5 cross-repo changes per week during Wall 7/8/9 work). |

**Verdict.** Right end-state. Wrong *current* state — we're still in
weekly cross-repo-edit cadence. Adopting today would slow Wall 7/8/9
work to a crawl. Use as the *target* state with a defined cutover.

### Option D — Hybrid path-dep + version-pin

`Cargo.toml` declares **both** a registry version and a sibling path:

```toml
headscale-api = { version = "0.3", path = "../../../headscale-rs/headscale-api", default-features = false }
```

Cargo's documented behaviour: when a `path` is present and the path
resolves, the path wins. When the path is absent (e.g. a downstream
consumer's machine, or a `--frozen` CI lane that strips path-deps via
`[patch.crates-io]` overrides) the registry version wins.

| Aspect              | Outcome                                                                   |
| ------------------- | ------------------------------------------------------------------------- |
| CI fragility        | Solved for the registry lane. The sibling-checkout lane still exists for fast iteration, but is no longer load-bearing — if it fails, the registry lane catches it.                  |
| Onboarding          | Good. `git clone octra && cargo build` works *without* the siblings (pulls from registry). Sibling checkouts remain a power-user opt-in. |
| Atomic changes      | Good. Editing both sides locally still works (path wins). Cross-repo PR pair publishes a new `headscale-api` and bumps the version in `octra` — same dance as Option C, but **only at release boundaries**, not for every dev iteration. |
| Downstream consumers| Good. `cargo install octravpn-client` works against published crates. |
| Release versioning  | Good. Registry version is the source of truth.                            |
| Hazard              | **"Works on my machine, fails in CI"** if the local sibling path drifts from the published version. Mitigated by (1) `cargo publish --dry-run` in CI on every PR that touches the sibling, (2) a `--frozen` CI lane that explicitly disables sibling resolution. |

**Verdict.** Picked. Captures Option C's downstream + versioning wins
without paying the daily-cadence tax until we choose to.

## 3. Decision

**Option D — hybrid path-dep + version-pin.**

Rationale:

1. We're going to need Option C eventually (mainnet needs a "we
   shipped version X" story). Option D is the on-ramp that gets us the
   downstream-consumer + versioning wins now without disrupting weekly
   cross-repo edits.
2. The CI-fragility class of bug ([`722fbe2`](#cited-commits) +
   [`0273183`](#cited-commits)) is solved either way once we have a
   `--frozen` lane that doesn't depend on sibling checkouts.
3. Submodules (A) introduce a worse UX than path-deps; monorepo (B)
   burns optionality on `headscale-rs` standalone identity. Both fail
   the downstream-consumer test.

**Fatal-flaw check (per the maintainer prior on D).** Reviewed the
"works on my machine, fails in CI" hazard. It's a real hazard, but it's
the same hazard `[patch.crates-io]` users in major Rust projects
(rustc, cargo itself, tokio) live with daily. Two mitigations make it
manageable:

- The CI **registry lane** (running `cargo build --frozen` with no
  sibling checkouts) is mandatory on every PR. If a local path-dep
  shipped an API the registry doesn't have, this lane reds.
- The release cadence (see [§ 6](#6-long-term-implications)) caps the
  drift window at one week.

## 4. Migration plan

### 4.1 Per-repo changes

#### `octra-foundry`

- Publish `octra-core` (and any other crates `octra` directly path-deps)
  to crates.io. Today the path-deps point at `crates/octra-core`; that
  crate's manifest needs `publish = true`, a clean `description`,
  `license`, and `repository` field.
- CI: add a `cargo publish --dry-run -p octra-core` gate on every PR
  that touches `crates/octra-core/**`.
- Cadence: cut a release whenever this crate's surface changes
  (initially weekly during the migration; see [§ 6](#6-long-term-implications)).

#### `headscale-rs`

- Publish `headscale-api` to crates.io. Same checklist: `publish =
  true`, `description`, `license`, `repository`.
- Note: `headscale-rs` is `andrew@golast.xyz`-maintained in practice
  (see [§ Operational reality](#operational-reality)) — no upstream
  coordination needed.
- CI: same `--dry-run` gate.
- Cadence: weekly during the Wall 7/8/9 push.

#### `octra` (this repo)

- Add `version = "..."` next to every path-dep that points at the
  siblings. Cargo accepts the dual form; downstream pulls use the
  version, local builds use the path.
- Add a `[patch.crates-io]` table at workspace root that **explicitly
  overrides** the registry version with the sibling path. This makes
  the override discoverable in one place rather than scattered across
  per-crate manifests.
- Add a new CI lane (`registry-build`) that runs `cargo build
  --frozen --locked` after deleting the sibling checkouts. This is
  the lane that catches drift.

### 4.2 `Cargo.toml` diffs

All diffs below were parsed through `tomllib` and confirmed
syntactically valid.

**`crates/octravpn-mesh/Cargo.toml`** (line 23):

```diff
-headscale-api = { path = "../../../headscale-rs/headscale-api", default-features = false }
+# Hybrid: registry version is the source-of-truth; `path` is used when
+# the sibling checkout is present (local dev). CI's registry lane runs
+# with `--frozen` and the sibling deleted, so it resolves from crates.io.
+# See: docs/architecture/headscale-dep-strategy.md
+headscale-api = { version = "0.3", path = "../../../headscale-rs/headscale-api", default-features = false }
```

**`crates/octravpn-core/Cargo.toml`** (line 11):

```diff
-octra-core  = { path = "../../../octra-foundry/crates/octra-core" }
+# Hybrid path + version: see docs/architecture/headscale-dep-strategy.md
+octra-core  = { version = "0.4", path = "../../../octra-foundry/crates/octra-core" }
```

**Workspace `Cargo.toml`** (new section appended after `[workspace]`):

```diff
+# When a sibling checkout is present at the conventional path
+# (../headscale-rs, ../octra-foundry), prefer it over the registry
+# version. `cargo build --frozen` ignores this table, so the
+# registry lane is unaffected.
+# See: docs/architecture/headscale-dep-strategy.md
+[patch.crates-io]
+headscale-api = { path = "../headscale-rs/headscale-api" }
+octra-core    = { path = "../octra-foundry/crates/octra-core" }
```

### 4.3 CI workflow diffs

**`.github/workflows/ci.yml`** — add a new job after `bench-regression`:

```diff
+  registry-build:
+    # Drift-catcher: builds the workspace against published crates.io
+    # versions of headscale-api + octra-core with NO sibling checkout.
+    # If a local path-dep ships an API the registry doesn't have, this
+    # job reds — forcing a sibling publish before the PR can merge.
+    # See: docs/architecture/headscale-dep-strategy.md
+    name: registry-only build
+    runs-on: ubuntu-latest
+    defaults:
+      run:
+        working-directory: octra
+    steps:
+      - uses: actions/checkout@v4
+        with: { path: octra }
+      - uses: ./octra/.github/actions/setup-rust
+      # Strip the [patch.crates-io] sibling-path overrides so cargo
+      # resolves from crates.io. `--frozen` keeps it honest.
+      - run: |
+          sed -i '/^\[patch\.crates-io\]/,/^$/d' Cargo.toml
+      - run: cargo build --workspace --frozen --locked --all-targets
```

The existing dual-/triple-checkout sibling pattern (lines 22–25, 41–44,
…, in `ci.yml`) stays in place during the migration window — it's still
the fastest local-equivalent lane. After two clean weeks of
`registry-build` green, **delete** the sibling-checkout pattern from
every job and rely on the registry lane.

**`.github/workflows/fuzz.yml`** — same treatment: keep the sibling
checkout for now; add a sibling-less smoke build that runs
`cargo +nightly fuzz build` against registry crates.

### 4.4 Operator-side impact

**None.** Operators consume:

- Pre-built binaries from `release.yml`-produced GitHub Releases.
- Docker images from `docker-compose.yml`.

Neither cares whether the crates were resolved from a sibling checkout
or from crates.io. The container build switches from "ARG sibling path"
to "fetch from crates.io" but the resulting binary is byte-equivalent.

The one operator-facing change: `docs/install.md` line 109 currently
tells operators to `git clone octra-foundry` for `octra cast`. That
stays — `octra cast` is still a separately-built binary from
`octra-foundry`, unaffected by the dep-resolution strategy. The
`headscale-rs` clone disappears from any operator-facing doc that
mentions it (there were none).

### 4.5 First three PRs (in order)

1. **PR #1 — `octra-foundry`: prep `octra-core` for crates.io publish.**
   Adds `publish = true`, `description`, `license`, `repository` to
   `crates/octra-core/Cargo.toml`. Adds CI `cargo publish --dry-run` gate.
   Cuts the first release as `octra-core 0.4.0` and confirms `cargo
   install octra-core` works in a clean container. Owner:
   `octra-foundry` maintainer (same person, different hat).

2. **PR #2 — `headscale-rs`: prep `headscale-api` for crates.io publish.**
   Same checklist, target version `headscale-api 0.3.0`. Cuts the first
   release. The audit-noted feature-flagging bug
   (`hmac` / `sha2` unconditional imports under `optional = true`,
   per `docs/audit/2026-05-20-claims-audit.md` lines 708–724) must be
   fixed in the same PR — otherwise the published crate won't compile
   downstream.

3. **PR #3 — `octra` (this repo): switch to hybrid layout.**
   Applies the three Cargo.toml diffs from [§ 4.2](#42-cargotoml-diffs).
   Adds the `registry-build` CI lane from [§ 4.3](#43-ci-workflow-diffs).
   Updates `docs/install.md` to drop the implicit
   "you also need to clone `headscale-rs`" assumption. Does **not**
   yet delete the sibling-checkout pattern from existing jobs — that's
   a follow-up PR after two weeks of `registry-build` green.

PRs #1 and #2 can land in parallel; PR #3 blocks on both.

## 5. Cited commits

Verified present in `git log` at the time of writing (worktree
`agent-a8e3fcbf01b80d705`, branch `worktree-agent-a8e3fcbf01b80d705`):

- [`722fbe2`](../../../) — `ci: checkout sibling headscale-rs in every job (workspace dep)` (10-site fix)
- [`0273183`](../../../) — `fuzz: check out octra-foundry sibling so nightly cargo-fuzz can build`
- [`f682495`](../../../) — `fuzz: declare x25519-dalek dep so onion_peel actually builds` (adjacent dep-fragility hit during the same fuzz workflow bring-up)

All three resolved cleanly via `git cat-file -e <sha>`. See
`docs/audit/2026-05-20-claims-audit.md` §U6 for the orthogonal "sibling
HEAD pinning" issue that this strategy *also* fixes (versions in
`Cargo.lock` become the pin once we go hybrid).

## 6. Long-term implications

**We need a release cadence.** Hybrid path/version-pin only works if
the version on the right-hand side of `=` is plausibly recent. The
proposal:

- **Weekly cadence** during the Wall 7/8/9 push (now through mainnet
  readiness). Every Monday: cut a `headscale-api` release if anything
  changed in its surface that week, then bump the version in this
  repo. Mechanically: one shell script
  (`scripts/cut-headscale-release.sh`, to be written) that runs
  `cargo publish` on the sibling, captures the version, and opens a
  follow-up PR here to bump it.
- **Per-merge cadence** is too tight: it forces a publish-then-bump
  for every cross-repo edit and we'd burn a crates.io publish quota
  on rough-cut work.
- **Per-mainnet-release** is too loose: drift between local path-deps
  and the registry version compounds, and the `registry-build` CI
  lane reds for weeks at a time, eroding the signal.

**Doc on how to cut a release** (TODO, owner: post-PR-#3): a
`docs/release.md` section titled "Cutting a sibling release" with the
shell-script invocation, the version-bump checklist, and the
`registry-build` green-check requirement before the PR merges.

**Long-term endgame.** After 3–6 months of stable weekly cadence, we
re-evaluate dropping the `path = "..."` half of the hybrid (going full
Option C). If by then `headscale-rs` has external contributors, we
keep the standalone-repo + registry-pin model permanently. If not, we
revisit Option B (monorepo) with the optionality argument settled by
revealed preference.

## Operational reality

`headscale-rs` is, in practice, maintained by `andrew@golast.xyz`.
Wall 7 (PSK-knock), DERP scaffolding, MagicDNS shape, full
`MapResponse` field set, ACL feature parity with `headscale-go/policy/v2`
— all of these were added in *this* fork's lineage, not upstream
`juanfont/headscale`. They are **not upstreamable** (OctraVPN-specific
auth model, chain-anchored identity, sealed-asset shape).

Practical consequence: cutting a `headscale-api` release does not
require coordinating with an external `juanfont/headscale` maintainer.
The "external contributor lost when we monorepo" argument from Option
B is **theoretical**, not current. It's still a real consideration —
optionality has a value — but the day-to-day operational cost of
Option B today is borne entirely by this team. That informs the
"re-evaluate in 6 months" hedge above.

---

**Related docs.**

- [`docs/headscale-gap-analysis.md`](../headscale-gap-analysis.md) — feature-level delta to `juanfont/headscale`. Sibling-repo layout note at line 7 now references this doc.
- [`docs/audit/2026-05-20-claims-audit.md`](../audit/2026-05-20-claims-audit.md) §U6 — sibling-HEAD pinning gap that this strategy resolves.
- [`docs/install.md`](../install.md) — operator-facing build instructions; updated in PR #3.
- [`.github/workflows/ci.yml`](../../.github/workflows/ci.yml), [`fuzz.yml`](../../.github/workflows/fuzz.yml), [`demo.yml`](../../.github/workflows/demo.yml), [`release.yml`](../../.github/workflows/release.yml), [`proof.yml`](../../.github/workflows/proof.yml) — CI workflows that currently clone siblings; targeted in PR #3 + follow-up.
