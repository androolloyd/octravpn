# 10-metrics-grafana.tape
#
# Tour the analytics indexer's surface. Hits the three live
# endpoints exposed by `octravpn-analytics --listen 0.0.0.0:51822`:
#
#   GET /metrics              — Prometheus text format.
#   GET /analytics/series     — per-metric bucketed JSON.
#   GET /analytics/health     — readiness + last-scan timestamps.
#
# Note: the demo's `mesh serve` doesn't currently write an audit log
# (it runs Hub-free; only the wire surfaces are mounted). The
# indexer's audit-dir is therefore empty, so counters surface as
# zero. The endpoints still render — this tape demonstrates the
# observability *shape*, not live-traffic numbers.
#
# Standalone — runs its own bringup + teardown so it can be re-rendered
# in isolation.
#
# REQUIRES:
#   - Same as tapes 08/09: Docker, sibling repos, openssl, ~6 min cold cache.
#   - `jq` on the host (most CI images have it; brew install jq locally).
#
# Re-run with: vhs demo/tapes/10-metrics-grafana.tape

Output demo/recordings/10-metrics-grafana.gif
Output demo/recordings/10-metrics-grafana.mp4

Set FontSize 13
Set Width 1280
Set Height 800
Set Theme "Dracula"
Set TypingSpeed 35ms

Type "# Bring the 3-peer mesh + analytics indexer up"
Enter
Type "bash demo/lib/3node-mesh-bringup.sh"
Enter
Sleep 420s

Type "# /metrics — Prometheus exposition (head 30 lines)"
Enter
Type "curl -fsS http://127.0.0.1:51822/metrics | head -30"
Enter
Sleep 5s

Type "# /analytics/health — last scan + audit-dir status"
Enter
Type "curl -fsS http://127.0.0.1:51822/analytics/health | jq ."
Enter
Sleep 5s

Type "# /analytics/series — sessions_opened, 1-minute buckets"
Enter
Type "curl -fsS 'http://127.0.0.1:51822/analytics/series?metric=sessions_opened&bucket=1m' | jq ."
Enter
Sleep 5s

Type "# /analytics/series — preauth_minted, 1-minute buckets"
Enter
Type "curl -fsS 'http://127.0.0.1:51822/analytics/series?metric=preauth_minted&bucket=1m' | jq ."
Enter
Sleep 5s

Type "# (Optional) the node's own /metrics endpoint"
Enter
Type "docker exec mesh-demo-control sh -c 'curl -fsS http://127.0.0.1:51821/metrics 2>/dev/null | head -20' || echo '(mesh serve does not expose /metrics under the Hub-free shape)'"
Enter
Sleep 5s

Type "# Teardown"
Enter
Type "bash demo/lib/3node-mesh-teardown.sh"
Enter
Sleep 10s
