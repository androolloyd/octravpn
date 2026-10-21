#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
task_output=${1:?provide a new evidence output directory}
task_image=${OCTRA_PRIVATE_KERNEL_IMAGE:-octra-private-kernel:local}
task_builder=${OCTRA_PRIVATE_KERNEL_BUILDER:-octra-private-payer-service:20261020}
task_runtime=${OCTRA_PRIVATE_KERNEL_RUNTIME:-octra-private-route-20261019:v6-admission}
test ! -e "$task_output"
mkdir -m 700 "$task_output"
task_output=$(cd "$task_output" && pwd)
docker image inspect "$task_builder" "$task_runtime" > "$task_output/base-images.json"
python3 "$task_root/docker/native-vpn/private_context.py" "$task_output/context" > "$task_output/context.log"
docker build --network none --build-arg "BUILDER_IMAGE=$task_builder" --build-arg "RUNTIME_IMAGE=$task_runtime" --progress plain -t "$task_image" "$task_output/context" > "$task_output/build.log" 2>&1
task_volume=$(docker volume create)
task_hop=$(docker volume create)
task_main=''
task_target=''
cleanup() {
    if test -n "$task_main"; then docker rm -f "$task_main" >/dev/null; fi
    if test -n "$task_target"; then docker rm -f "$task_target" >/dev/null; fi
    docker volume rm "$task_hop" "$task_volume" >/dev/null
}
trap cleanup EXIT
task_target=$(docker create --network none --cap-drop ALL --cap-add NET_ADMIN --device /dev/net/tun --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=32m --mount "type=volume,src=$task_volume,dst=/evidence" --mount "type=volume,src=$task_hop,dst=/hop" --entrypoint python3 "$task_image" -u /usr/local/bin/packet_target.py)
task_main=$(docker create --network none --cap-drop ALL --cap-add NET_ADMIN --cap-add NET_RAW --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 --sysctl net.ipv4.ip_early_demux=0 --sysctl net.ipv4.tcp_early_demux=0 --sysctl net.ipv4.conf.all.rp_filter=0 --sysctl net.ipv4.conf.default.rp_filter=0 --sysctl net.ipv4.conf.all.accept_local=1 --sysctl net.ipv4.conf.default.accept_local=1 --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=2g --tmpfs /work/octra/out:rw,nosuid,nodev,size=64m --mount "type=volume,src=$task_volume,dst=/evidence" --mount "type=volume,src=$task_hop,dst=/hop" "$task_image")
docker image inspect "$task_image" > "$task_output/image.json"
docker start "$task_target" >/dev/null
task_ready=0
for task_attempt in {1..100}; do
    if docker exec "$task_target" test -f /evidence/target.json; then task_ready=1; break; fi
    sleep .1
done
test "$task_ready" -eq 1
set +e
docker start -a "$task_main" > "$task_output/run.log" 2>&1
task_run=$?
set -e
docker stop --time 10 "$task_target" >/dev/null
docker logs "$task_target" > "$task_output/target.log" 2>&1
docker cp "$task_main:/evidence/." "$task_output/"
docker inspect "$task_main" "$task_target" > "$task_output/containers.json"
python3 - "$task_output" "$task_run" <<'PY'
import json,pathlib,sys
root=pathlib.Path(sys.argv[1]); rows=json.loads((root/'containers.json').read_text())
j=json.loads((root/'journal.json').read_text()) if (root/'journal.json').exists() else {}
exits=[row['State']['ExitCode'] for row in rows]
qualified=int(sys.argv[2])==0 and exits==[0,0] and j.get('qualified') is True
(root/'qualification.json').write_text(json.dumps({'qualified':qualified,'container_exits':exits,'scope':j.get('scope')},indent=2)+'\n')
raise SystemExit(0 if qualified else 1)
PY
