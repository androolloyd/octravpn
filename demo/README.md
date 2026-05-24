# OctraVPN demo scaffolding

This directory holds the reproducible bits of the OctraVPN demo: VHS
`.tape` files that re-render CLI walkthroughs as gif + mp4, helper
scripts to bring up the dependencies each tape needs, and the top-level
orchestrator that renders everything in one shot.

Browser-UI segments (portal interstitial, admin GUI, Grafana) are
documented as a screen-record runbook in `docs/demo.md` because they
need a human-with-OBS pass; this directory only owns the CLI flows.

## Install vhs

```sh
brew install vhs            # macOS
# linux: see https://github.com/charmbracelet/vhs#installation
```

## Render every tape

```sh
./demo/run-demo.sh
```

Outputs land in `demo/recordings/`. Re-run is idempotent; gifs are
overwritten in place.

To render a single tape pass any unique substring:

```sh
./demo/run-demo.sh 03-audit          # only 03-audit-replay.tape
```

## Tape catalogue

| Tape | Captures | Requires |
|---|---|---|
| `01-init-keygen.tape` | `octravpn init` + `octravpn keygen` + `identity` | `octravpn` on PATH |
| `02-portal-fetch.tape` | `octravpn fetch` (stdout / `--save` / `-i` interactive) | `octravpn`, a portal config under `demo/state/portal/` |
| `03-audit-replay.tape` | `octravpn-node audit replay` + `audit verify` | `octravpn-node`, fixture audit + receipt journal at `demo/state/node/` |
| `04-mesh-preauth.tape` | `mesh mint-preauth` (CLI + HTTP) | `octravpn-node` |
| `05-v3-smoke.tape` | `docker/devnet/v3-smoke.sh` full lifecycle | funded `deployer.key`, foundry binary, devnet RPC |
| `06-tailscale-interop.tape` | `docker/devnet/tailscale-interop/run-interop.sh` exit 0 | Docker, `octra-foundry` + `headscale-rs` checkouts (default siblings; override headscale with `HEADSCALE_RS_PATH`), openssl |
| `07-headscale-cli.tape` | `headscale users create / preauthkeys create / nodes list` | `headscale` binary (from `headscale-rs`) |

Each tape leads with a comment block stating exact prereqs. Tapes
that need an out-of-band process (e.g. the portal) `Source` a helper
under `demo/lib/`; the helpers are idempotent so a re-run is a no-op
when the dependency is already live.

## Manual / browser segments

For segments that need a real browser (portal interstitial, admin GUI,
Grafana, the headline cold-open), follow the runbook in
`docs/demo.md`. That doc:

- has assembly cues for OBS (region capture, 1080p, 60fps, no system audio)
- lists every voiceover beat for the 5-minute headline + 15-minute deep dive
- documents the ffmpeg concat command that stitches everything into
  `demo/recordings/octravpn-headline.mp4`

## Helpers

- `demo/lib/start-portal.sh` — spawns `octravpn portal` in the
  background, polls `/healthz`. Idempotent. Sourced by 02-portal-fetch.
- `demo/lib/start-devnet.sh` — `docker compose up -d` for the devnet
  stack (mock-rpc + node1/2/3). Idempotent. Sourced by tapes that
  need a chain that does not exist on the real devnet.
- `demo/lib/teardown.sh` — kills the portal PID + `docker compose
  down` the devnet + interop stacks. Always safe to run.

## Follow-ups (intentionally not shipped)

- Nightly regeneration in CI. The optional `.github/workflows/demo.yml`
  carries the action wiring; it is a separate file from the in-flight
  #241/#243 batches so the merge is decoupled.
- Audio voiceover track. The .tape recordings are silent; voiceover is
  laid in by OBS during the human pass per `docs/demo.md`.
