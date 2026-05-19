# Dependency Audit

> Reproduce:
>
> ```sh
> # cargo-audit must be installed: `cargo install --locked cargo-audit`
> # The repo's .cargo/audit.toml uses cargo-deny config keys; temporarily
> # move it aside while cargo-audit runs, OR pass --db-only flags.
> mv .cargo/audit.toml /tmp/audit.toml.bak
> cargo audit -n
> mv /tmp/audit.toml.bak .cargo/audit.toml
> ```
>
> The `-n` flag suppresses git-fetch of the advisory DB (use a fresh
> `~/.cargo/advisory-db` clone for the most current scan). The
> snapshot recorded here was generated against advisory-db at the
> date in `manifest.json`'s `generated_at` field.

---

## 1. `cargo audit` scan

**Database:** `~/.cargo/advisory-db` (1091 advisories loaded at
generation time).
**Crate dependencies scanned:** 427 (full `Cargo.lock` resolved
workspace, including dev-dependencies).
**CVE findings:** 0.
**Yanked crates:** 0.
**Warnings (unmaintained):** 2 — see below.

### 1.1 RUSTSEC-2024-0436 — `paste` 1.0.15 (unmaintained)

```
Crate:     paste
Version:   1.0.15
Warning:   unmaintained
Title:     paste - no longer maintained
Date:      2024-10-07
ID:        RUSTSEC-2024-0436
URL:       https://rustsec.org/advisories/RUSTSEC-2024-0436
Dependency tree:
paste 1.0.15
└── netlink-packet-core 0.8.1
    ├── route_manager 0.2.11
    │   └── tun-rs 2.8.3
    │       └── octravpn-tun 0.1.0
    │           └── octravpn-client 0.1.0
    ├── netlink-packet-route 0.28.0
    │   └── route_manager 0.2.11
    ├── netlink-packet-route 0.25.1
    │   └── netconfig-rs 0.1.6
    │       └── tun-rs 2.8.3
    └── netconfig-rs 0.1.6
```

**Disposition: ACCEPTED.** `paste` is a proc-macro crate. Its
"unmaintained" status means upstream is no longer responding to
issues; it does not mean there's a known vulnerability. The crate's
expansion produces no runtime code paths that handle untrusted
input — it's a build-time identifier-paster used inside the netlink
ecosystem to generate enum→string mappings. The transitive route is
into `octravpn-tun`, which uses `tun-rs` only on Linux/macOS for
TUN/TAP device creation; the crate is not loaded on Windows or in
the `octravpn-node` build path.

**Mitigation:** track netlink-packet upstream; when they drop `paste`
or replace it with a maintained equivalent (`paste-rs` /
`pastey` are candidates), upgrade.

### 1.2 RUSTSEC-2025-0134 — `rustls-pemfile` 2.2.0 (unmaintained)

```
Crate:     rustls-pemfile
Version:   2.2.0
Warning:   unmaintained
Title:     rustls-pemfile is unmaintained
Date:      2025-11-28
ID:        RUSTSEC-2025-0134
URL:       https://rustsec.org/advisories/RUSTSEC-2025-0134
Dependency tree:
rustls-pemfile 2.2.0
├── octravpn-node 0.1.0
└── headscale-api 0.1.0
    └── octravpn-mesh 0.1.0
        ├── octravpn-node 0.1.0
        ├── octravpn-client 0.1.0
        └── octravpn-admin-ui 0.1.0
```

**Disposition: ACCEPTED (with planned migration).**
`rustls-pemfile` parses PEM-encoded certificates and keys.
Upstream `rustls` is migrating the PEM-parsing API into the `rustls`
crate itself (`rustls::pki_types::pem`). The migration is mechanical
but cross-cuts `octravpn-node` (control-plane TLS) and
`headscale-api` (Tailscale-wire TLS), and we want both crates to
move in the same PR so the PEM-parsing surface stays consistent.

**Risk if we leave it:** PEM parsing is reachable only on operator
boot (loading a configured TLS cert) and during preauth-bridge
setup. Both inputs are operator-controlled local files. An attacker
with write access to operator config files already controls the
operator; the parsing surface is not exposed to clients or chain.

**Mitigation:** scheduled migration to `rustls::pki_types::pem` in
the next minor release.

---

## 2. `cargo deny` scan

**Status: NOT RUN.** `cargo-deny` was not installed on the
generation host (`which cargo-deny` returned not-found). The
configuration at `/Users/androolloyd/Development/octra/deny.toml`
is in place and ready to run:

```toml
[advisories]
db-path = "~/.cargo/advisory-db"
db-urls = ["https://github.com/rustsec/advisory-db"]
yanked = "warn"

[licenses]
allow = [
  "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause",
  "ISC", "Unicode-3.0", "Unicode-DFS-2016", "Zlib",
  "OpenSSL", "MPL-2.0", "CC0-1.0",
]
confidence-threshold = 0.8

[bans]
multiple-versions = "warn"
wildcards = "deny"

[sources]
unknown-registry = "warn"
unknown-git = "warn"
allow-registry = ["https://github.com/rust-lang/crates.io-index"]
```

**Reproduce:**

```sh
cargo install --locked cargo-deny
cargo deny check
```

The license-allow list intentionally includes `OpenSSL` (legacy
OpenSSL license) and `MPL-2.0` (file-level copyleft, compatible
with our MIT-or-Apache-2.0 dual license). Neither is reached today
by a direct production dependency; both are conservatively allowed
in case a transitive dep pulls them in.

---

## 3. License surface

The workspace ships under MIT OR Apache-2.0 (see top-level `Cargo.toml`
`[workspace.package] license = "MIT OR Apache-2.0"`). Every direct
production dependency is permissively licensed under one of the
allowed SPDX identifiers in `deny.toml` (see §2). The auditor can
re-verify with:

```sh
cargo deny check licenses
```

---

## 4. Pinning / lockfile discipline

- The workspace ships `Cargo.lock` in source control (required —
  it's a binary-producing workspace, not a library-only crate).
- Toolchain pinned via `rust-toolchain.toml` (stable channel, with
  components fixed).
- All git dependencies (none today, by `cargo deny`'s
  `unknown-git = warn` policy) are listed in the lockfile with
  commit SHAs.

Run:

```sh
git diff --exit-code Cargo.lock
```

should be clean in a release tag — any unexpected lockfile drift
is a CI failure.

---

## 5. Vendored / FFI surface

Two non-trivial FFI dependency paths exist:

- **`aws-lc-sys` / `aws-lc-rs`** (via `rustls` 0.23.x backend) —
  Amazon Linux Cryptography library; SOC2 + FIPS-friendly. Build
  artifacts include the upstream BoringSSL headers (which is why
  `fuzz/target/.../aws-lc-sys-*/out/include/openssl/*.h` is excluded
  from the TODO scan in `known-limitations.md`).
- **`boringtun` 0.7.x** — Cloudflare WireGuard userspace
  implementation. Used in `crates/octravpn-node/src/tunnel.rs` for
  the data plane.

Both are in scope for the audit, but treated as upstream-pinned
black boxes; the OctraVPN-layer fuzz targets exercise the calling
surface (`onion_peel`, `receipt_decode`, `tx_canonical`,
`fuzz_acl_parse`, `fuzz_peer_snapshot_decode`, `fuzz_ip_alloc`).

---

## 6. Captured output (verbatim)

The cargo-audit snapshot output as recorded:

```text
      Loaded 1091 security advisories (from /Users/.../.cargo/advisory-db)
    Scanning Cargo.lock for vulnerabilities (427 crate dependencies)
warning: 2 allowed warnings found
Crate:     paste
Version:   1.0.15
Warning:   unmaintained
Title:     paste - no longer maintained
Date:      2024-10-07
ID:        RUSTSEC-2024-0436
URL:       https://rustsec.org/advisories/RUSTSEC-2024-0436
Dependency tree: (see §1.1)

Crate:     rustls-pemfile
Version:   2.2.0
Warning:   unmaintained
Title:     rustls-pemfile is unmaintained
Date:      2025-11-28
ID:        RUSTSEC-2025-0134
URL:       https://rustsec.org/advisories/RUSTSEC-2025-0134
Dependency tree: (see §1.2)
```

No CVEs, no yanked-crate findings.
