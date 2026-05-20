# License + GPL-Isolation Audit — 2026-05-20

| Field | Value |
|---|---|
| Octra commit | `11f83a198b7b04e5a79ebc00a238d7326888337a` |
| Octra-foundry commit | `42f4b22e648b0b7726185f10252c98b8961e4765` |
| Headscale-rs commit | `fd95f57f702a429126be8392624d8dda84885a7e` |
| Auditor | claude-code (deep audit) |
| Tooling | `cargo-deny 0.19.6` (cargo-license not installed) |

Working tree clean except for an unrelated WIP `audit.rs` rename in
`octravpn-node` — irrelevant to license posture.

---

## 1. GPL isolation status — **PASS**

Evidence (`grep`, `Cargo.lock`, `find`):

1. The PVAC sidecar is a **C++ binary** built with `make`, *not* a Rust crate.
   It has no `Cargo.toml`. Its build is:
   - `pvac-sidecar/Makefile` → `g++` compiles `src/main.cpp` +
     `vendor/pvac/pvac_c_api.cpp` → standalone binary
     `pvac-sidecar/octra-pvac-sidecar`.
   - `pvac-sidecar/Dockerfile` ships it as a separate image.
2. The only Rust crate inside `pvac-sidecar/` is
   `pvac-sidecar/ipc-tests/` — a workspace member with
   `publish = false`, listing only permissive Rust deps
   (`anyhow`, `serde`, `serde_json`, `hex`, `base64`, `tempfile`).
   `grep '"pvac-sidecar"' octra/Cargo.lock` returns **only**
   `pvac-sidecar-ipc-tests` and its permissive deps. No GPL crate enters
   the lockfile.
3. `grep -rn 'pvac' --include='Cargo.toml'` across all three workspaces
   matches only the workspace-member registration
   (`octra/Cargo.toml:13: "pvac-sidecar/ipc-tests"`). **No `[dependencies]`
   entry, in any crate, anywhere, references `pvac-sidecar` or its
   vendored C++.**
4. `find -name build.rs` across all three workspaces returns exactly two:
   - `headscale-rs/headscale-api/build.rs` — `tonic_build` only (gRPC proto).
   - `octra-foundry/crates/octra-cli/src/forge/build.rs` — *not a Cargo
     build script*, it's a regular Rust module that happens to be named
     `build.rs` (path is under `src/`).
   Neither invokes `cc::Build` / `cxx` / `bindgen`. **Zero native C/C++
   compilation in any Rust crate.**
5. The Rust-side caller (`octravpn-node/src/pvac.rs`) reaches the sidecar
   exclusively via `tokio::process::Command::new(&cfg.binary_path)` +
   piped stdin/stdout (line 619, `spawn_child`). No FFI, no
   `#[link(name="pvac")]`, no `extern "C"`. Confirmed with
   `grep '#\[link.*pvac\|extern.*pvac' --include='*.rs'` returning zero
   hits.
6. `LICENSE.NOTICE.md` boundary statement is in place and matches reality.

The C++ sidecar's vendored PVAC tree is never `#include`d from any other
build target — only `pvac-sidecar/src/main.cpp` and the sidecar Makefile
reference `vendor/pvac/*`.

**Conclusion:** the GPL-2-or-later sidecar is runtime-only. The Rust
workspaces keep their `MIT OR Apache-2.0` license intact at the link
boundary. This is the FSF-recommended IPC pattern, executed correctly.

---

## 2. License-header coverage — **FAIL (0 %)**

```
                         total .rs  with SPDX-License-Identifier
octra/                   206        0
octra-foundry/           82         0
headscale-rs/            123        0
                         ----       --
                         411        0  (0.0 %)
```

Workspace `Cargo.toml`s declare `license = "MIT OR Apache-2.0"` and every
member uses `license.workspace = true`, so the **package-level** metadata
is correct. But no source file carries an
`// SPDX-License-Identifier: Apache-2.0 OR MIT` header. This is a common
auditor finding — SPDX headers per file are best practice (REUSE 3.0,
linux-kernel style) but not legally required when the LICENSE file is
present and the Cargo metadata declares it. Remediation: add a one-line
SPDX header to each file via a tree-wide `sed` patch.

The sidecar `src/main.cpp` carries the full GPL-2+ header inline. The
vendored `vendor/pvac/**.{hpp,cpp}` files (36 files) do **not** carry
the upstream GPL header verbatim — `grep -l "GPL\|GNU General"` returns 0.
`LICENSE.NOTICE.md` claims "The full GPL header is preserved verbatim on
every vendored file under `vendor/pvac/`" — that claim is **false today**
and is the #1 remediation item.

---

## 3. Transitive license table

Generated via `cargo deny list --layout crate` against the workspace
Cargo.lock files. Counts are unique crate-versions; the same license name
may be reported alongside the chosen-license alternative for
dual-licensed crates (cargo-deny lists both).

| License | octra | octra-foundry | headscale-rs | Notes |
|---|---:|---:|---:|---|
| Apache-2.0 | 310 | (subset) | (subset) | Primary copyleft-compatible perm. |
| MIT | 381 | (subset) | (subset) | Primary perm. |
| Apache-2.0 WITH LLVM-exception | 7 | – | – | rustix, wasi, wit-bindgen |
| BSD-3-Clause | 12 | – | – | ed25519-dalek, curve25519-dalek, x25519-dalek, boringtun, neli, encoding_rs |
| BSD-2-Clause | 4 | – | – | ip_network, zerocopy |
| BSD-1-Clause | 1 | – | – | fiat-crypto |
| ISC | 8 | – | – | ring, rustls, untrusted, aws-lc-rs |
| 0BSD | 1 | – | – | adler2 (also Apache+MIT) |
| BSL-1.0 | 1 | – | – | ryu (also Apache+MIT) |
| CC0-1.0 | 1 | – | – | dunce (also MIT) |
| CDLA-Permissive-2.0 | 1 | – | – | webpki-roots |
| Unicode-3.0 | 19 | – | – | icu_* family |
| Unlicense | 3 | – | – | aho-corasick, byteorder, memchr (all also MIT) |
| WTFPL | 1 | – | – | `tun` 0.7.22 |
| Zlib | 2 | – | – | foldhash, miniz_oxide |
| MIT-0 | 2 | – | – | aws-lc-sys, dunce |
| **LGPL-2.1-or-later** | **2** | **2** | **1** | `r-efi 5.3.0`, `r-efi 6.0.0` — but **tri-licensed `MIT OR Apache-2.0 OR LGPL-2.1-or-later`**, choose MIT. Verified at `~/.cargo/registry/src/.../r-efi-{5.3,6.0}.0/Cargo.toml`. **No taint.** |

`cargo deny check licenses` against `octra/deny.toml`:
- `octra` workspace: **`licenses ok`**.
- `octra-foundry` workspace (with octra's deny.toml): **`licenses ok`**.
- `headscale-rs` workspace (with octra's deny.toml): **`licenses ok`**.

No AGPL, MPL, EPL, CDDL, SSPL, BUSL, or any other forbidden license
appears in the transitive trees. The only copyleft hit is r-efi, which
is tri-licensed and we elect MIT/Apache-2.0.

**Shippable under `Apache-2.0 OR MIT`:** yes (with the caveats in §6).

`octra-foundry` and `headscale-rs` have **no `deny.toml`** of their own.
Reusing octra's passes; add per-repo files for CI.

---

## 4. Trademark usage

| Term | Files | Usage | Risk | Mitigation |
|---|---|---|---|---|
| `Tailscale` (the company / product) | `octra/README.md:7,75,301`, `headscale-rs/README.md:3` | Descriptive ("Tailscale-style mesh") | **Low–Medium** — Tailscale Inc. owns "Tailscale" as a US trademark. Using it as a comparator/adjective is nominative fair use, but a disclaimer is best practice. | Add a "Trademarks" section to each README: *"Tailscale® is a registered trademark of Tailscale Inc. This project is not affiliated with, sponsored by, or endorsed by Tailscale Inc."* |
| `WireGuard` | `octra/README.md:10,161,186`, `headscale-rs/README.md:4` | Names the protocol (we ship `boringtun`, a Rust WireGuard implementation by Cloudflare under BSD-3-Clause). | **Medium** — "WireGuard" is a registered trademark of Jason A. Donenfeld; the trademark policy requires the disclaimer below. | Add to every README: *"WireGuard is a registered trademark of Jason A. Donenfeld."* (Per https://www.wireguard.com/trademark-policy/.) |
| `headscale` | `octra/README.md:301,312,313`, `headscale-rs/` (every crate name) | Names the Go upstream + our Rust reimplementation. | **Low** — `juanfont/headscale` is BSD-3-Clause; no registered trademark known. The crate name `headscale-rs` is descriptive. | Add an attribution line: *"`headscale-rs` is an independent Rust reimplementation; the original Go project is © juanfont and contributors, BSD-3-Clause."* |
| `boringtun` | `octra/README.md:114,156,161`, `octra/CHANGELOG.md:45` | Names the dependency. | **Low** — Cloudflare BSD-3-Clause, no trademark concerns for descriptive use. | Note the dep in README. |

No trademark used as a branded mark (e.g., as part of a product name or
logo) on our side. All uses are nominative/descriptive.

---

## 5. Attribution status

| Upstream | License | Required attribution | In place? |
|---|---|---|---|
| `octra-labs/webcli` (PVAC) | GPL-2-or-later + OpenSSL exemption | (a) Verbatim GPL header on every vendored file; (b) full LICENSE text; (c) source-availability notice | **PARTIAL** — `pvac-sidecar/LICENSE` is the GPL-2 text. `pvac-sidecar/LICENSE.NOTICE.md` documents the boundary. `src/main.cpp` carries a GPL-2+ header. **The 36 vendored `vendor/pvac/**.{hpp,cpp}` files do not carry the upstream GPL header.** README/CHANGELOG do not mention the upstream URL or authors (David A., Alex T., Vadim S., Julia L.). |
| `juanfont/headscale` (Go) | BSD-3-Clause | Copyright + license notice in distribution | **MISSING** — `headscale-rs/README.md` says "Tailscale-style mesh" but does not credit `juanfont/headscale` as the prior art, nor preserve the upstream BSD-3-Clause notice. No `THIRDPARTY-NOTICES.md` exists. |
| `tailscale.com/control` (protocol spec) | n/a (protocol; reference impl is BSD-3-Clause) | Spec credit | **MISSING** — `octra/README.md` and `headscale-rs/README.md` reference Tailscale-style mesh + use Tailscale's wire types (`tailscale_wire/` per the workspace lints) but never credit Tailscale Inc. as the protocol designer. |
| `octra-labs/HFHE` (math) | (assumed GPL-2-or-later via the webcli vendoring) | Algorithmic credit | **MISSING** — `octra-foundry/crates/octra-mock-rpc/src/aml/host_fhe.rs` calls itself "honest mock implementation of Octra's HFHE AML host calls" but the README is empty (`grep -ni 'lic\|copyright' octra-foundry/README.md` → no hits). |
| `cloudflare/boringtun` | BSD-3-Clause | Copyright notice in distribution | **PARTIAL** — Mentioned by name in README + CHANGELOG; the BSD-3-Clause text from the boringtun crate is satisfied automatically by cargo (license metadata in Cargo.lock) but our top-level distribution should include a `THIRDPARTY-NOTICES.md` aggregating these. |
| `snow` (rust-noise) | Apache-2.0 OR MIT | Standard | **OK** by Cargo metadata; not specifically credited in README. |

The README for `octra-foundry` is essentially empty (no copyright, no
license note). The README for `headscale-rs` has no license/attribution
section at all.

**Top-3 attribution gaps:**
1. `vendor/pvac/**` lacks per-file GPL headers (LICENSE.NOTICE.md
   asserts their presence — fix the assertion or fix the files).
2. `juanfont/headscale` (BSD-3-Clause) is not credited anywhere in the
   `headscale-rs` repo despite being the direct upstream.
3. `octra-foundry` and `headscale-rs` have **no top-level LICENSE
   file** on disk — only `license = "MIT OR Apache-2.0"` in
   `Cargo.toml`. Crates.io/cargo-publish will reject this. (`octra` is
   correct: `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE` all present.)

---

## 6. Remediation (ranked)

| # | Gap | Severity | Action |
|---|---|---|---|
| 1 | `octra-foundry` + `headscale-rs` have no on-disk `LICENSE` / `LICENSE-MIT` / `LICENSE-APACHE` files | **HIGH** — blocks shipping / blocks `cargo publish` | Copy the three files from `octra/` into each repo root. |
| 2 | Vendored `pvac-sidecar/vendor/pvac/**.{hpp,cpp}` carry no upstream GPL-2 header (36 files) | **HIGH** — GPL §1 (preserve copyright notices) | Either (a) re-vendor with headers intact from `octra-labs/webcli`, or (b) prepend a minimal SPDX/copyright stub to each file pointing to LICENSE. Update LICENSE.NOTICE.md's "preserved verbatim" claim to match reality. |
| 3 | No SPDX-License-Identifier headers on any of 411 Rust source files | **MEDIUM** — best-practice (REUSE 3.0); some auditors require | One-shot tree-wide patch: `find . -name '*.rs' -exec sed -i '' '1i\\n// SPDX-License-Identifier: Apache-2.0 OR MIT\n' {} \\;` (with the conventional blank-line treatment). |
| 4 | No trademark disclaimer for "WireGuard" (required by upstream trademark policy) | **MEDIUM** — risk of cease-and-desist | Add a `## Trademarks` section to each top-level README. |
| 5 | `juanfont/headscale` not credited in `headscale-rs` README | **MEDIUM** — BSD-3-Clause §3 (attribution) | Add upstream credit + BSD-3-Clause copyright notice in `headscale-rs/README.md`. |
| 6 | No aggregated `THIRDPARTY-NOTICES.md` per shipping artifact | **MEDIUM** — common audit requirement | Generate via `cargo about` or `cargo-bundle-licenses` and check it in. |
| 7 | `octra-foundry/README.md` and `headscale-rs/README.md` have no license/attribution section | **LOW** | Add a one-paragraph copyright + license + upstream-credits block. |
| 8 | No per-repo `deny.toml` in `octra-foundry` / `headscale-rs` | **LOW** — CI hygiene | Copy `octra/deny.toml`. |
| 9 | `tun = 0.7.22` is WTFPL-only (in octra) | **LOW** — WTFPL is FSF Free; mention in NOTICES. | Document; consider switching to `tun-rs` (Apache-2.0/MIT) which is already in the tree. |
| 10 | LGPL-2.1-or-later listing for `r-efi` (informational) | **NONE** | Tri-licensed; we elect MIT. No action. |

---

## Bottom line

- **GPL isolation: PASS** (subprocess-only; no Rust crate links the
  sidecar; verified by `Cargo.lock`, `grep`, and `find`).
- **License-header coverage: 0 %** for Rust SPDX headers; sidecar src
  yes, vendored GPL src no.
- **Top-3 attribution gaps:**
  1. Vendored `vendor/pvac/**` files missing the upstream GPL header.
  2. `juanfont/headscale` un-credited in `headscale-rs/README.md`.
  3. `octra-foundry` + `headscale-rs` repos have no `LICENSE*` files
     on disk (Cargo metadata is correct, but the files are absent).
- **Shipping a binary today: LEGALLY CLEAN with caveats.**
  - The Rust binaries (`octravpn-node`, `octravpn-client`,
    `headscale-rs/headscale-cli`, `octra-cli`, etc.) are linkable and
    distributable under `MIT OR Apache-2.0`. No mandatory copyleft
    transitive deps. `cargo deny check licenses` passes.
  - The PVAC sidecar binary is distributable under GPL-2-or-later and
    must ship as a **separate artifact** with its `LICENSE` and source
    availability. Today this is satisfied by `pvac-sidecar/Dockerfile`
    + `LICENSE` + `LICENSE.NOTICE.md`.
  - Two **documentation gaps** to close before public release: per-file
    GPL headers on vendored sources, and top-level `LICENSE*` files in
    `octra-foundry` + `headscale-rs`. Neither blocks internal builds
    but both should land before any external distribution.
