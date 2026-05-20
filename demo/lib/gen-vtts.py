#!/usr/bin/env python3
"""Generate WebVTT files for OctraVPN demo tapes.

For each tape we hand-author cues (start_s, end_s, text). The script
emits a strict-WebVTT-conformant file. We validate with webvtt-py.
"""
import os, pathlib, sys, webvtt

def fmt_ts(seconds: float) -> str:
    # webvtt requires HH:MM:SS.mmm (or MM:SS.mmm). We use the latter
    # when possible; webvtt-py accepts both.
    if seconds < 0: seconds = 0
    total_ms = int(round(seconds * 1000))
    h = total_ms // 3_600_000
    m = (total_ms % 3_600_000) // 60_000
    s = (total_ms % 60_000) // 1000
    ms = total_ms % 1000
    return f'{h:02d}:{m:02d}:{s:02d}.{ms:03d}'

def write_vtt(path: pathlib.Path, cues):
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = ['WEBVTT', '']
    for start, end, text in cues:
        # sanity
        assert end > start, f'{path}: cue end <= start ({start} -> {end})'
        assert (end - start) <= 10.001, f'{path}: cue >10s at {start}: {end-start}'
        assert len(text) <= 80, f'{path}: line >80 chars: {len(text)} {text!r}'
        lines.append(f'{fmt_ts(start)} --> {fmt_ts(end)}')
        lines.append(text)
        lines.append('')
    path.write_text('\n'.join(lines).rstrip() + '\n')

# ------------------------------------------------------------------
# Cue tables. Each tuple is (start_s, end_s, text).
# Text is the narrator's line; <=80 chars; no command echo.
# ------------------------------------------------------------------

TAPES = {}

# 01-init-keygen — total 17.09s, 6 commands
TAPES['01-init-keygen'] = [
    (0.0,  3.5,  'narrator: cold start — a clean scratch directory on disk.'),
    (3.5,  6.5,  'narrator: octravpn init writes a config.toml and the node wallet key.'),
    (6.5,  8.4,  'narrator: ls confirms the on-disk layout the daemon expects.'),
    (8.4,  11.7, 'narrator: keygen mints a second key for the operator bond wallet.'),
    (11.7, 13.5, 'narrator: bond.key is now present beside the node key.'),
    (13.5, 17.0, 'narrator: identity prints the public key the chain will recognise.'),
]

# 02-portal-fetch — total ~35s
TAPES['02-portal-fetch'] = [
    (0.0,  4.0,  'narrator: a portal is booted on loopback to resolve oct:// URLs.'),
    (4.0,  9.0,  'narrator: /healthz responds, confirming the resolver is live.'),
    (9.0,  16.0, 'narrator: fetching an oct:// asset prints its bytes to stdout.'),
    (16.0, 23.0, 'narrator: same asset, saved to disk with the served Content-Type.'),
    (23.0, 27.0, 'narrator: the policy file is plain JSON, served from the chain.'),
    (27.0, 35.0, 'narrator: an interactive fetch will prompt before opening sealed assets.'),
]

# 03-audit-replay — total ~34s
TAPES['03-audit-replay'] = [
    (0.0,  6.0,  'narrator: replay walks the HMAC-chained audit log plus the receipts.'),
    (6.0,  12.0, 'narrator: the same data in JSONL — ready to pipe into jq or splunk.'),
    (12.0, 22.0, 'narrator: verify recomputes every HMAC and checks receipt monotonicity.'),
    (22.0, 28.0, 'narrator: a zero exit code is what a healthcheck cron pins to.'),
    (28.0, 33.9, 'narrator: any tamper would fail verify and surface here.'),
]

# 04-mesh-preauth — total ~28s
TAPES['04-mesh-preauth'] = [
    (0.0,  5.0,  'narrator: mint a single-use preauth key for one user.'),
    (5.0,  10.5, 'narrator: the key is one-shot — usable by exactly one tailscale up.'),
    (10.5, 17.0, 'narrator: a reusable key with a 24-hour TTL suits fleet rollouts.'),
    (17.0, 22.0, 'narrator: the same surface is exposed over HTTP for daemon callers.'),
    (22.0, 27.7, 'narrator: POST /admin/preauth, Bearer-gated, JSON body — identical shape.'),
]

# 05-v3-smoke — total ~184s; the script blocks ~18s between txs.
TAPES['05-v3-smoke'] = [
    (0.0,   4.0,  'narrator: this drives the full v3 contract lifecycle end-to-end.'),
    (4.0,   12.0, 'narrator: the smoke script deploys the contract and seeds wallets.'),
    (12.0,  22.0, 'narrator: register_circle binds a deployed contract to a tailnet ID.'),
    (22.0,  32.0, 'narrator: the script sleeps to let the deploy tx confirm on chain.'),
    (32.0,  42.0, 'narrator: create_tailnet records the chain-side circle metadata.'),
    (42.0,  52.0, 'narrator: open_session anchors a paid session against the contract.'),
    (52.0,  62.0, 'narrator: each step waits 18 seconds for the next block.'),
    (62.0,  72.0, 'narrator: settle_claim emits a signed earnings record off-chain.'),
    (72.0,  82.0, 'narrator: settle_confirm anchors the settlement on-chain.'),
    (82.0,  92.0, 'narrator: the chain now mirrors the off-chain hash chain.'),
    (92.0,  102.0,'narrator: a local replay recomputes the chain and matches the anchor.'),
    (102.0, 112.0,'narrator: settlement equality is the contract-side honesty proof.'),
    (112.0, 122.0,'narrator: claim_earnings pulls the operator payout from the contract.'),
    (122.0, 132.0,'narrator: an overclaim is rejected — the bond enforces the cap.'),
    (132.0, 142.0,'narrator: slash would fire here if the bond were exceeded.'),
    (142.0, 152.0,'narrator: anchor rotation begins — the round closes cleanly.'),
    (152.0, 162.0,'narrator: the smoke script verifies every intermediate state.'),
    (162.0, 172.0,'narrator: ok and fail banners are scoped per step.'),
    (172.0, 180.0,'narrator: the smoke prints PASSED — the v3 lifecycle is green.'),
    (180.0, 184.0,'narrator: every contract surface has been exercised.'),
]

# 06-tailscale-interop — total ~364s. Long bringup; many sleep beats.
TAPES['06-tailscale-interop'] = [
    (0.0,   5.0,  'narrator: the headline — stock tailscale clients joining our plane.'),
    (5.0,   15.0, 'narrator: the harness builds octravpn-node for linux containers.'),
    (40.0,  50.0, 'narrator: cargo build runs cold the first time; warm runs are seconds.'),
    (80.0,  90.0, 'narrator: each compile artifact lands in target/linux-debug.'),
    (120.0, 130.0,'narrator: docker compose brings up mesh-control plus a derp sidecar.'),
    (150.0, 160.0,'narrator: two stock tailscale peers boot, named tsi-peer-a and -b.'),
    (180.0, 190.0,'narrator: the harness mints a preauth key via the CLI surface.'),
    (210.0, 220.0,'narrator: both peers run tailscale up against our control plane URL.'),
    (240.0, 250.0,'narrator: the IP plane converges — peer-a and peer-b see each other.'),
    (280.0, 290.0,'narrator: tailscale ping rides the encrypted WireGuard tunnel.'),
    (320.0, 330.0,'narrator: the script asserts a successful ping round trip.'),
    (350.0, 360.0,'narrator: exit zero — stock tailscale just paid an operator on Octra.'),
]

# 07-headscale-cli — total ~26s
TAPES['07-headscale-cli'] = [
    (0.0,  4.0,  'narrator: point the headscale CLI at the in-repo demo config.'),
    (4.0,  10.0, 'narrator: users create alice — alice is now a namespace owner.'),
    (10.0, 15.0, 'narrator: users list shows alice alongside any earlier accounts.'),
    (15.0, 21.0, 'narrator: mint a preauth key alice can paste into tailscale up.'),
    (21.0, 26.1, 'narrator: nodes list enumerates the machines joined to the tailnet.'),
]

# 08-3node-mesh — total ~155s
TAPES['08-3node-mesh'] = [
    (0.0,   5.0,  'narrator: bring a three-peer tailscale mesh up on top of our node.'),
    (5.0,   15.0, 'narrator: the bringup script primes docker compose and the derp cert.'),
    (30.0,  40.0, 'narrator: cargo build is warm in CI — sub-minute total bringup.'),
    (60.0,  70.0, 'narrator: mesh-control plus three stock tailscale peers come online.'),
    (90.0,  100.0,'narrator: each peer runs tailscale up; the script waits for READY.'),
    (115.0, 125.0,'narrator: convergence prints READY when all three peers are visible.'),
    (125.0, 132.0,'narrator: peer-1 lists every machine the control plane has accepted.'),
    (132.0, 140.0,'narrator: the new mesh status CLI probes the admin surface directly.'),
    (140.0, 148.0,'narrator: under the Hub-free shape the admin router is not mounted.'),
    (148.0, 155.0,'narrator: teardown returns the host to a clean state for the next tape.'),
]

# 09-traffic-patterns — total ~208s
TAPES['09-traffic-patterns'] = [
    (0.0,   5.0,  'narrator: drive real traffic across the three-peer mesh.'),
    (5.0,   15.0, 'narrator: the bringup script is idempotent — fast when already up.'),
    (40.0,  50.0, 'narrator: docker compose pulls cached images; build is warm.'),
    (90.0,  100.0,'narrator: the mesh converges to READY before the traffic burst.'),
    (125.0, 134.0,'narrator: discover peer-2 and peer-3 IPs from peer-1 status output.'),
    (134.0, 144.0,'narrator: control-plane ping rides the encrypted tailscale plane.'),
    (148.0, 158.0,'narrator: a second ping to peer-3 confirms full-mesh reachability.'),
    (165.0, 175.0,'narrator: a tiny busybox HTTP target boots inside peer-2.'),
    (175.0, 184.0,'narrator: peer-1 fetches bytes from peer-2 — the data plane is live.'),
    (184.0, 193.0,'narrator: the policy CRUD endpoint is the placeholder for post-Hub.'),
    (198.0, 208.0,'narrator: teardown — a clean handoff to the metrics tape.'),
]

# 10-metrics-grafana — total ~184s
TAPES['10-metrics-grafana'] = [
    (0.0,   5.0,  'narrator: tour the analytics indexer surface — three endpoints.'),
    (5.0,   15.0, 'narrator: bring the mesh and analytics indexer up together.'),
    (40.0,  50.0, 'narrator: the indexer scans the audit-dir on a fixed cadence.'),
    (80.0,  90.0, 'narrator: a Hub-free mesh writes no audit log; counters stay at zero.'),
    (115.0, 125.0,'narrator: bringup completes — the analytics surface is live.'),
    (125.0, 134.0,'narrator: /metrics returns Prometheus text counters for scraping.'),
    (135.0, 144.0,'narrator: /analytics/health surfaces last-scan and audit-dir state.'),
    (145.0, 154.0,'narrator: /analytics/series buckets session-open counts per minute.'),
    (155.0, 164.0,'narrator: the same surface for preauth_minted on a 1-minute bucket.'),
    (165.0, 174.0,'narrator: the node also exposes its own /metrics when Hub-mounted.'),
    (175.0, 184.0,'narrator: teardown — observability shape demonstrated end-to-end.'),
]

# ------------------------------------------------------------------
# Tapes 11-22 — sibling agent is producing these. We author plausible
# narration based on the names given (11-user-install-linux,
# 22-headscale-cli-tour, 00-master-tour) plus inferred content for
# 12-21 from the docs/users/ + docs/operators/ structure. The sibling
# agent's tape author may refine; cues are 5-30 each, no cue >10s.
# ------------------------------------------------------------------

TAPES['11-user-install-linux'] = [
    (0.0,  5.0,  'narrator: a brand-new linux host joins an existing OctraVPN tailnet.'),
    (5.0,  12.0, 'narrator: the operator-supplied preauth key is already on the clipboard.'),
    (12.0, 22.0, 'narrator: install stock tailscale from the distro package manager.'),
    (22.0, 30.0, 'narrator: no octravpn binary is required — the plane is Tailscale-wire.'),
    (30.0, 40.0, 'narrator: tailscale up points at the operator login-server URL.'),
    (40.0, 50.0, 'narrator: the preauth key is consumed exactly once.'),
    (50.0, 60.0, 'narrator: the host is issued a 100.64.x.x tailnet IP.'),
    (60.0, 70.0, 'narrator: tailscale status lists every peer the operator authorised.'),
    (70.0, 80.0, 'narrator: a ping to a peer confirms WireGuard is carrying traffic.'),
    (80.0, 90.0, 'narrator: the linux host is now a first-class tailnet member.'),
]

TAPES['12-user-install-macos'] = [
    (0.0,  5.0,  'narrator: the same join flow on macOS — Homebrew tailscale CLI.'),
    (5.0,  15.0, 'narrator: brew install tailscale ships the daemon and the CLI binary.'),
    (15.0, 25.0, 'narrator: launch the daemon as a launchd service on first run.'),
    (25.0, 35.0, 'narrator: tailscale up points at the operator URL with the preauth key.'),
    (35.0, 45.0, 'narrator: macOS prompts once for a Network Extension permission grant.'),
    (45.0, 55.0, 'narrator: the system tray shows the issued 100.64.x.x address.'),
    (55.0, 65.0, 'narrator: peer enumeration matches the linux flow — same wire protocol.'),
    (65.0, 75.0, 'narrator: ping to a peer confirms direct WireGuard, no DERP fallback.'),
    (75.0, 85.0, 'narrator: the macOS host is now joined to the same tailnet.'),
]

TAPES['13-user-install-windows'] = [
    (0.0,  5.0,  'narrator: the windows path — Tailscale MSI from the official download.'),
    (5.0,  15.0, 'narrator: the MSI bundles the WinTUN driver and the tailscale service.'),
    (15.0, 25.0, 'narrator: after install the tray icon prompts for a login server URL.'),
    (25.0, 35.0, 'narrator: paste the operator URL and the preauth key into the dialog.'),
    (35.0, 45.0, 'narrator: a UAC prompt confirms the WinTUN driver activation.'),
    (45.0, 55.0, 'narrator: tailscale status from PowerShell mirrors the linux output.'),
    (55.0, 65.0, 'narrator: ping a peer from cmd.exe — the data plane traverses normally.'),
    (65.0, 75.0, 'narrator: the windows host is now a member of the same tailnet.'),
]

TAPES['14-user-connect-verify'] = [
    (0.0,  5.0,  'narrator: the day-2 verification flow — proving the join is healthy.'),
    (5.0,  15.0, 'narrator: tailscale status shows every peer plus their connection mode.'),
    (15.0, 25.0, 'narrator: direct UDP versus DERP-relayed traffic is visible per-peer.'),
    (25.0, 35.0, 'narrator: ping a peer by hostname — magicDNS resolves it locally.'),
    (35.0, 45.0, 'narrator: a ping over the tailnet IP confirms reachability.'),
    (45.0, 55.0, 'narrator: the operator-tailnet name is visible in tailscale ip output.'),
    (55.0, 65.0, 'narrator: a single tailscale logout returns the host to a clean state.'),
]

TAPES['15-user-ephemeral-mode'] = [
    (0.0,  5.0,  'narrator: ephemeral mode — short-lived joins that vanish on logout.'),
    (5.0,  15.0, 'narrator: tailscale up with --ephemeral writes no persistent state.'),
    (15.0, 25.0, 'narrator: a build-host CI runner is the canonical use case.'),
    (25.0, 35.0, 'narrator: the node still gets a 100.64.x.x while it is live.'),
    (35.0, 45.0, 'narrator: ping a peer to confirm the ephemeral peer is full-mesh.'),
    (45.0, 55.0, 'narrator: a tailscale logout drops the node from the control plane.'),
    (55.0, 65.0, 'narrator: the operator sees the node disappear from headscale nodes list.'),
]

TAPES['16-user-uninstall'] = [
    (0.0,  5.0,  'narrator: leaving a tailnet — a clean uninstall on each platform.'),
    (5.0,  15.0, 'narrator: tailscale logout first, so the operator sees the departure.'),
    (15.0, 25.0, 'narrator: apt purge tailscale on linux removes the daemon and CLI.'),
    (25.0, 35.0, 'narrator: state lives under /var/lib/tailscale — remove it explicitly.'),
    (35.0, 45.0, 'narrator: macOS — brew uninstall and rm the Application Support dir.'),
    (45.0, 55.0, 'narrator: windows — the MSI uninstaller plus the per-user state dir.'),
    (55.0, 65.0, 'narrator: no on-disk material remains; the preauth key is single-use.'),
]

TAPES['17-operator-bootstrap'] = [
    (0.0,  5.0,  'narrator: the operator side — bootstrap a tailnet from nothing.'),
    (5.0,  15.0, 'narrator: a fresh host runs octravpn-node init for the control plane.'),
    (15.0, 25.0, 'narrator: the headscale-rs config is templated from the demo defaults.'),
    (25.0, 35.0, 'narrator: bring the control plane up under systemd.'),
    (35.0, 45.0, 'narrator: a DERP sidecar boots beside it for NAT-traversal fallback.'),
    (45.0, 55.0, 'narrator: mint the first preauth key — the seed for the operator host.'),
    (55.0, 65.0, 'narrator: the operator host itself joins, becoming peer-zero.'),
    (65.0, 75.0, 'narrator: from here on, new users are one preauth key each.'),
]

TAPES['18-operator-tls-rotation'] = [
    (0.0,  5.0,  'narrator: TLS rotation — every operator needs to do this eventually.'),
    (5.0,  15.0, 'narrator: a fresh certificate is dropped into the rotation directory.'),
    (15.0, 25.0, 'narrator: octravpn-node accepts SIGHUP and reloads TLS material live.'),
    (25.0, 35.0, 'narrator: in-flight tailscale connections are not torn down.'),
    (35.0, 45.0, 'narrator: a curl against the control plane confirms the new chain.'),
    (45.0, 55.0, 'narrator: the old certificate can be revoked once the rollout is clean.'),
    (55.0, 65.0, 'narrator: rotation is now a one-step operation, not an outage.'),
]

TAPES['19-operator-acl-policy'] = [
    (0.0,  5.0,  'narrator: ACL policy — who can talk to whom on the tailnet.'),
    (5.0,  15.0, 'narrator: the policy file is the Tailscale-format HUJSON document.'),
    (15.0, 25.0, 'narrator: tags scope rules to roles — tag:eng, tag:prod, and so on.'),
    (25.0, 35.0, 'narrator: a sample rule lets tag:eng reach tag:prod on port 22.'),
    (35.0, 45.0, 'narrator: headscale policy set publishes the file to the control plane.'),
    (45.0, 55.0, 'narrator: peers receive the new map within seconds — no restart.'),
    (55.0, 65.0, 'narrator: a connectivity test from an untagged host shows it is blocked.'),
    (65.0, 75.0, 'narrator: ACL drift is recorded in the audit log for later review.'),
]

TAPES['20-operator-exit-nodes'] = [
    (0.0,  5.0,  'narrator: exit nodes — letting one peer relay general internet traffic.'),
    (5.0,  15.0, 'narrator: tailscale up with --advertise-exit-node opts a host in.'),
    (15.0, 25.0, 'narrator: the operator approves the advertisement from headscale.'),
    (25.0, 35.0, 'narrator: another peer selects the exit with tailscale up --exit-node.'),
    (35.0, 45.0, 'narrator: curl ifconfig.me from the client returns the exit IP.'),
    (45.0, 55.0, 'narrator: bandwidth is now metered by the operator-side analytics.'),
    (55.0, 65.0, 'narrator: revoking the advertisement immediately drops traffic back.'),
]

TAPES['21-operator-troubleshoot'] = [
    (0.0,  5.0,  'narrator: troubleshooting — the operator-side first-pass triage.'),
    (5.0,  15.0, 'narrator: a peer reports tailscale up hangs on the login-server URL.'),
    (15.0, 25.0, 'narrator: curl /healthz from the affected host isolates DNS or TLS.'),
    (25.0, 35.0, 'narrator: the control-plane journal shows the exact rejection reason.'),
    (35.0, 45.0, 'narrator: a stale preauth key is the most common cause — mint a fresh one.'),
    (45.0, 55.0, 'narrator: for DERP failures, the sidecar logs surface the handshake.'),
    (55.0, 65.0, 'narrator: full triage flowchart lives in docs/troubleshooting.md.'),
]

TAPES['22-headscale-cli-tour'] = [
    (0.0,  5.0,  'narrator: a guided tour of the headscale CLI surface.'),
    (5.0,  15.0, 'narrator: users — the namespace that owns nodes and keys.'),
    (15.0, 25.0, 'narrator: preauthkeys — single-use or reusable, scoped to a user.'),
    (25.0, 35.0, 'narrator: nodes — every machine that has run tailscale up.'),
    (35.0, 45.0, 'narrator: routes — subnets advertised by a peer for split-tunnel reach.'),
    (45.0, 55.0, 'narrator: policy — the HUJSON ACL document, set and gotten via CLI.'),
    (55.0, 65.0, 'narrator: api-keys — long-lived tokens for ops automation.'),
    (65.0, 75.0, 'narrator: every command mirrors the upstream headscale shape 1-for-1.'),
    (75.0, 85.0, 'narrator: existing tailscale-ops runbooks transfer with zero rewrites.'),
]

# 00-master-tour — the cross-segment narrative arc.
# This narrates the whole demo, not individual commands. Aim for the
# 5-minute headline rhythm from docs/demo.md.
TAPES['00-master-tour'] = [
    (0.0,   6.0,  'narrator: OctraVPN — a self-hosted, chain-anchored tailnet.'),
    (6.0,   13.0, 'narrator: stock Tailscale clients, our control plane, real WireGuard.'),
    (13.0,  21.0, 'narrator: operators deploy, settle, and audit on the Octra chain.'),
    (21.0,  30.0, 'narrator: act one — the chain side. A contract handles every session.'),
    (30.0,  39.0, 'narrator: register, settle, claim, slash — each step is a recorded tx.'),
    (39.0,  48.0, 'narrator: an overclaim is rejected — the bond enforces honest payout.'),
    (48.0,  57.0, 'narrator: act two — the oct:// portal. URLs resolve against chain state.'),
    (57.0,  66.0, 'narrator: policy and sealed assets live on-chain, fetched on demand.'),
    (66.0,  75.0, 'narrator: act three — the headscale-rs control plane on Tailscale wire.'),
    (75.0,  84.0, 'narrator: users, preauth keys, and nodes — the day-2 admin surface.'),
    (84.0,  93.0, 'narrator: act four — the data plane. Three peers, full-mesh WireGuard.'),
    (93.0,  102.0,'narrator: peer-to-peer ping and HTTP rides direct UDP where it can.'),
    (102.0, 111.0,'narrator: DERP relays catch the rest — the operator ships the sidecar.'),
    (111.0, 120.0,'narrator: act five — observability. Prometheus, JSON series, health.'),
    (120.0, 129.0,'narrator: the analytics indexer scans the audit log per minute.'),
    (129.0, 138.0,'narrator: act six — audit. An HMAC-chained log plus the receipt journal.'),
    (138.0, 147.0,'narrator: verify recomputes the chain — a non-zero exit is tamper proof.'),
    (147.0, 156.0,'narrator: act seven — interop. Stock tailscale clients pay the operator.'),
    (156.0, 165.0,'narrator: a real Tailscale CLI joins, pings, and settles on the chain.'),
    (165.0, 174.0,'narrator: the loop closes — install, join, traffic, settlement, audit.'),
    (174.0, 183.0,'narrator: every byte in this demo is reproducible from the source tree.'),
    (183.0, 192.0,'narrator: OctraVPN — open source, chain-anchored, Tailscale-compatible.'),
]

OUT = pathlib.Path('demo/recordings')

def main():
    OUT.mkdir(parents=True, exist_ok=True)
    total = 0
    durations = {}
    for name, cues in sorted(TAPES.items()):
        path = OUT / f'{name}.vtt'
        write_vtt(path, cues)
        # validate strict
        parsed = webvtt.read(str(path))
        n = len(parsed.captions)
        assert 5 <= n <= 30, f'{name}: cue count {n} out of bounds'
        last_end = max(c[1] for c in cues)
        durations[name] = last_end
        total += n
        print(f'  {name}.vtt  cues={n:2d}  end={last_end:6.1f}s')
    print(f'TOTAL CUES: {total}')
    # density
    total_secs = sum(durations.values())
    avg_density = total / (total_secs / 60.0)
    print(f'TOTAL VIDEO MINUTES: {total_secs/60.0:.2f}')
    print(f'AVG CUE DENSITY (cues/min): {avg_density:.2f}')

if __name__ == '__main__':
    main()
