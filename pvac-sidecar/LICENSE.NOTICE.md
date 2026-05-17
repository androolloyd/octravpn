# License boundary notice

## TL;DR

- `pvac-sidecar/` is licensed **GPL-2.0-or-later** (with OpenSSL exemption).
- The surrounding `octra/` Rust workspace stays **MIT OR Apache-2.0**.
- The two communicate **only over a JSON stdin/stdout IPC boundary**.
  No GPL source, no GPL object, no GPL symbol is linked into the Rust
  workspace's binaries.

## Why we did this

The PVAC (HFHE) implementation that produces blobs the Octra v2 chain
accepts lives in [`octra-labs/webcli`](https://github.com/octra-labs/webcli)
under `pvac/` and is GPL-2-or-later (with an OpenSSL exemption). Their
wire format — `"PVAC"` magic byte sequence + version + tag + body, see
`pvac_serialize.hpp` — is implementation-defined; anything else gets
rejected at chain-side deserialization.

Vendoring those C++ sources directly into our MIT/Apache Rust crates,
even via `cc` or `bindgen`, would force the resulting Rust binaries
under the GPL. We don't want that for `octravpn-node`, `octravpn-client`,
the operator-circle node software, or `octra-foundry`.

The well-established workaround (used by, e.g., the GNU project's own
documentation on FSF-recommended IPC, and by countless commercial
products that ship alongside GPL'd tools) is to keep the GPL code in a
**separate executable** and have the proprietary / permissively-licensed
code interact with it as a child process over a documented IPC boundary
(stdio, pipes, sockets). That is exactly what this sidecar does.

## What's in the sidecar

The sidecar build (everything under `pvac-sidecar/`):

- Vendors the full `octra-labs/webcli/pvac/` tree under `vendor/pvac/`.
- Vendors a tiny base64 helper extracted from `octra-labs/webcli/crypto_utils.hpp`
  (no OpenSSL pulled in — pure C++ string manipulation), under `vendor/lib/b64.hpp`.
- Vendors `nlohmann/json` (`vendor/lib/json.hpp`, MIT-licensed) for JSON parsing.
- `src/main.cpp` (this repo) — the JSON-over-stdio dispatcher.

All of the above is treated as a single combined GPL-2+ work, distributed
under the terms in [`LICENSE`](./LICENSE).

## What stays out of the sidecar

- No Rust code from the `octra/` workspace is built into this image.
- The sidecar does not link any Rust object files, static libraries,
  or shared libraries.
- The sidecar runs as a child process spawned by the Rust caller. The
  only data exchanged is line-delimited JSON over stdin/stdout.

## What stays out of the Rust workspace

- No `pvac/` headers are `#include`d into any `*-sys` crate.
- No `pvac/*.{cpp,c}` source is compiled by `build.rs` / `cc` / `cxx` /
  `bindgen` anywhere in `octra/` or `octra-foundry/`.
- The Rust side talks to the sidecar via `std::process::Command` /
  `tokio::process` exclusively.

## Distribution checklist

When packaging a release that includes both the sidecar and the Rust
binaries:

1. Ship the sidecar as a separate Docker image (or separate binary
   artifact) with its own GPL-2+ LICENSE file and source-availability
   notice ("source is available at the configured upstream and at
   `pvac-sidecar/vendor/`").
2. Do not bundle the sidecar binary into a single static archive with
   the MIT/Apache binaries; keep them as two artifacts.
3. The Rust binaries' documentation should mention that the sidecar
   is GPL-2+ and that it is not linked or statically embedded — only
   spawned as a child process if/when the user wants HFHE features.

## Upstream credit

PVAC was authored by Octra Labs (David A., Alex T., Vadim S., Julia L.,
2025-2026). The full GPL header is preserved verbatim on every
vendored file under `vendor/pvac/`. Patches to the PVAC core are
not expected here; if they happen, they should be upstreamed to
`octra-labs/webcli` first and then re-vendored.
