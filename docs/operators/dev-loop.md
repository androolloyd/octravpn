# Local dev loop: running demo tapes

This page is for engineers who want to render the VHS demo tapes
(`demo/tapes/*.tape`) **locally** on their dev machine — typically to
preview a change before pushing, or to debug a tape that's failing in
CI. CI itself has its own pre-built binary pipeline; nothing here
touches that path.

## Prereqs

- [`docker`](https://docs.docker.com/get-docker/) — the bringup
  scripts spin up containers, and the Linux binaries we mount in are
  built **inside** docker (the rust toolchain image IS Linux, so we
  get matching ELF without an actual cross-compile).
- [`vhs`](https://github.com/charmbracelet/vhs) — `brew install vhs`
  on macOS.
- The repo's sibling checkouts present at `..` relative to the repo
  root:
  - `../octra-foundry` — hosts the `octra-mock-rpc` crate the demo
    chain uses.
  - `../headscale-rs` — path dep of the mesh crate's protobuf bridge.

## One-shot: build the Linux binaries

```sh
demo/lib/build-linux-binaries.sh
```

This produces, under `target/linux-debug/debug/`:

- `octravpn` — the client CLI (used by tapes 01, 02, 11, 15, 16, 17, …).
- `octravpn-node` — the daemon (used by the mesh + audit fixtures).
- `octravpn-analytics` — the analytics indexer.
- `octra-mock-rpc` — the in-memory mock chain (built from the sibling
  foundry workspace).

It's idempotent — every binary is checked against its source `main.rs`
mtime, so a re-run with nothing changed is sub-second. Exit codes:

| Code | Meaning |
|------|---------|
| 0    | All requested binaries present + fresh. |
| 10   | `cargo build` inside docker failed (check the log above). |
| 20   | Docker daemon not reachable. |
| 30   | Sibling repo missing at `../octra-foundry` or `../headscale-rs`. |

Observed timings on an Apple M-series host (see the script header for
detail):

- **Cold** (`rm -rf target/linux-debug && time bash …`): ~100 s real.
- **Warm** (every artefact fresh): ~0.2 s.

You can also override the builder image with `OCTRA_BUILDER_IMAGE=…`
and force a rebuild with `BUILD_LINUX_FORCE=1`.

## Rendering a tape

Once the binaries are in place, the bringup scripts the tape calls
(e.g. `demo/lib/keygen-fixture-bringup.sh`) just mount them straight
into a `debian:bookworm-slim` container. So:

```sh
vhs demo/tapes/01-init-keygen.tape
```

writes the GIF + MP4 under `demo/recordings/`.

If the Linux binary isn't built yet, the bringup script will trigger
`build-linux-binaries.sh` automatically (which is a no-op when the
artefact is already fresh, so it stays cheap in CI). You only need to
invoke the build helper manually when you want to pre-warm or
sanity-check the artefacts.

## Why a separate `target/linux-debug/`?

The default `target/` on macOS holds darwin-arm64 binaries — they
can't `exec` inside a Linux container. Routing the Linux build through
`target/linux-debug/` keeps both architectures' caches independent, so
swapping between native dev (`cargo test`, etc.) and demo tapes is
zero-cost.

## See also

- `demo/lib/3node-mesh-bringup.sh` — the canonical mesh fixture; the
  build path here mirrors what it does inline.
- `.github/workflows/demo-tapes.yml` — the CI workflow that builds the
  same set of binaries by other means. We deliberately keep the
  local script in sync with the CI step rather than sharing it, so
  CI changes don't accidentally break local dev or vice versa.
