#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
task_context=${OCTRA_NATIVE_VPN_CONTEXT:-$(dirname "$task_root")}
task_image=${OCTRA_NATIVE_VPN_IMAGE:-octra-native-vpn-qualification:local}
task_builder=${OCTRAVPN_BUILDER_IMAGE:-octravpn-builder:latest}
task_gate=${OCTRA_NATIVE_VPN_GATE:-legacy}
case "$task_gate" in
    legacy) task_entry=/usr/local/bin/qualify.py ;;
    payments) task_entry=/usr/local/bin/payments_qualify.py ;;
    *) printf 'Unknown native VPN gate: %s\n' "$task_gate" >&2; exit 2 ;;
esac
task_output=${1:?provide a fresh evidence output directory}
for task_source in octra octra-foundry headscale-rs; do test -d "$task_context/$task_source"; done
test ! -e "$task_output"
mkdir -m 700 "$task_output"
if test "${OCTRA_NATIVE_VPN_SKIP_BUILD:-0}" = 1; then
    docker image inspect --format '{{.Id}}' "$task_image" | tee "$task_output/build.log"
else
    docker build --build-arg "BUILDER_IMAGE=$task_builder" -f "$task_root/docker/native-vpn/Dockerfile" -t "$task_image" "$task_context" 2>&1 | tee "$task_output/build.log"
fi
task_volume=$(docker volume create)
task_hop_volume=''
task_container=''
task_target=''
cleanup() {
    if test -n "$task_container"; then docker rm -f "$task_container" >/dev/null; fi
    if test -n "$task_target"; then docker rm -f "$task_target" >/dev/null; fi
    if test -n "$task_hop_volume"; then docker volume rm "$task_hop_volume" >/dev/null; fi
    docker volume rm "$task_volume" >/dev/null
}
trap cleanup EXIT
task_hop_volume=$(docker volume create)
task_target=$(docker create --network none --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m --mount "type=volume,src=$task_volume,dst=/evidence" --mount "type=volume,src=$task_hop_volume,dst=/hop" --entrypoint python3 "$task_image" -u /usr/local/bin/packet_target.py)
# Shared client/operator TCP sockets must not take a cached local receive route
# before the explicit fixture policy routes traverse both actual VPN TUNs.
task_container=$(docker create --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.ip_early_demux=0 --sysctl net.ipv4.tcp_early_demux=0 --sysctl net.ipv4.conf.all.rp_filter=0 --sysctl net.ipv4.conf.default.rp_filter=0 --sysctl net.ipv4.conf.all.accept_local=1 --sysctl net.ipv4.conf.default.accept_local=1 --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=1g --mount "type=volume,src=$task_volume,dst=/evidence" --mount "type=volume,src=$task_hop_volume,dst=/hop" --entrypoint python3 "$task_image" -u "$task_entry")
docker image inspect "$task_image" > "$task_output/image.json"
docker start "$task_target" >/dev/null
task_ready=0
for task_attempt in {1..100}; do
    if test "$(docker inspect --format '{{.State.Running}}' "$task_target")" != true; then break; fi
    if docker exec "$task_target" test -S /hop/target.sock; then task_ready=1; break; fi
    sleep .1
done
if test "$task_ready" -ne 1; then
    docker logs "$task_target" > "$task_output/target.log" 2>&1
    exit 1
fi
set +e
docker start -a "$task_container" 2>&1 | tee "$task_output/run.log"
task_status=${PIPESTATUS[0]}
set -e
docker stop --time 10 "$task_target" >/dev/null
docker logs "$task_target" > "$task_output/target.log" 2>&1
docker cp "$task_container:/evidence/." "$task_output/"
task_exit=$(docker inspect --format '{{.State.ExitCode}}' "$task_container")
if test "$task_status" -eq 0; then task_status=$task_exit; fi
task_target_exit=$(docker inspect --format '{{.State.ExitCode}}' "$task_target")
if test "$task_status" -eq 0; then task_status=$task_target_exit; fi
python3 - "$task_output" "$task_status" "$task_exit" "$task_target_exit" <<'PY'
import json,pathlib,sys
output=pathlib.Path(sys.argv[1])
journal=json.loads((output/'journal.json').read_text()) if (output/'journal.json').exists() else {}
status,main,target=map(int,sys.argv[2:])
value={'qualified':status==0 and journal.get('qualified') is True,'main_exit':main,'target_exit':target,'run_exit':status,'scope':journal.get('scope','incomplete isolated native VPN qualification')}
(output/'qualification.json').write_text(json.dumps(value,indent=2)+'\n')
PY
exit "$task_status"
