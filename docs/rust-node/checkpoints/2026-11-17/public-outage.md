# Public observer outage, October 21 to present

Recorded 2026-11-17 from the stopped containers' own state (`docker inspect`,
`docker logs`) and an external probe. Nothing here was changed: no container
was started, stopped or removed.

## What happened

| When (UTC) | Event |
| --- | --- |
| 2026-10-21 13:00:46 | The observer container (`octra-devnet-private-alpha-v32-20261021`) starts. |
| 2026-10-21 16:00:47 | It exits with code 1: `awaiting current-head attestation: epoch 1727802 matching 0 responses 1 required 13 target 1727802`. Not an OOM kill (`OOMKilled=false`, 48 GiB limit). |
| 2026-11-08 22:31:54 | The gateway and private-control helper containers exit with code 0. |
| 2026-11-17 | `https://octra.to` answers HTTP 502 on every path. The relay's certificate is valid (62 days left), so the relay and its proxy are up; nothing behind them answers. |

All three containers ran with restart policy `no`. The node process is built
to exit when it cannot reach serving state, on the expectation that something
restarts it; nothing did. The site was down for 27 days before anyone looked,
because nothing was looking from outside.

## Why restarting it is not the fix

The stopped node is the October 21 build. Since then devnet has activated
consensus changes that build does not implement: the Rust node's adopted pin
moved to lite_node `c49de45` on November 12 (never deployed), and the signed
release marker now requires `8f785a93` (sequence 42, "weighted quorum,
execution time slices and store gc", issued November 14).

A node that lacks a rule the network has activated cannot verify new epochs.
It falls behind its peers, quarantines its root and refuses to serve — which
is the correct, fail-closed behaviour, and also means a restart would spend
hours restoring more than 100 GB of retained state at roughly 43 GiB of
memory and then stop serving again. Restoring public service is blocked on
adopting the required upstream release, then redeploying.

## What changed in the repository

- `.github/workflows/public-probe.yml` probes the front door every 30 minutes
  from outside and keeps one `public-probe` issue open while it is not
  serving. `scripts/public-probe.sh` distinguishes the relay being down, the
  node being down behind it, and the node being up but not at head.
- `.github/workflows/octra-release-canary.yml` now compares the signed
  release with the commit the node implements and keeps one `release-canary`
  issue current, so a required upstream release is announced when it is
  issued rather than discovered after the node stops following the chain.
- `scripts/devnet-relay/README.md` has a supervision section: restart
  policies, a memory ceiling, and keeping qualification runs off the
  observer's host.

## Still required before testers are invited

1. Adopt the required upstream release (the `release-canary` issue carries
   the commit list and checklist).
2. Redeploy the node and its helpers under supervision, per the README.
3. Sustained sync at head, then the funded public canary — both were open
   launch gates before the outage and remain so.
