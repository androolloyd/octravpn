#!/usr/bin/env bash
set -euo pipefail
task_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
task_parent=$(dirname "$task_root")
task_image=${OCTRAVPN_TRANSPORT_IMAGE:-octra-vpn-transport-qualification:local}
task_builder=${OCTRAVPN_BUILDER_IMAGE:-octravpn-builder:latest}
docker image inspect "$task_builder" >/dev/null
docker build --build-arg "BUILDER_IMAGE=$task_builder" -f "$task_root/docker/vpn-transport/Dockerfile" -t "$task_image" "$task_parent"
docker run --rm --network none --cap-drop ALL --cap-add NET_ADMIN \
  --security-opt no-new-privileges --device /dev/net/tun --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,size=128m "$task_image"
