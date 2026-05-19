#!/usr/bin/env bash
# OctraVPN — devcontainer post-create hook.
#
# Idempotent: safe to re-run on a re-created container. Each step is
# a no-op if its effect is already present.
#
# Runs inside the mcr.microsoft.com/devcontainers/rust:1-bookworm image
# (Linux x86_64). The vhs install line below is Linux-x86_64-specific —
# Mac hosts running Codespaces locally won't hit this code path
# (Codespaces always provisions a Linux container).
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> warming cargo cache (workspace fetch + build)..."
# `cargo fetch` populates the registry cache; the offline-then-online
# pattern lets the build short-circuit if the cache is already warm.
cargo fetch --workspace || true
cargo build --workspace --offline 2>/dev/null || cargo build --workspace || {
  echo "::warning::workspace build did not complete cleanly; the user can re-run \`cargo build --workspace\` from the integrated terminal"
}

echo "==> installing demo tooling (charmbracelet/vhs)..."
# vhs is the recorder for the demo/recordings/* assets. The release
# tarball ships a single static binary; this step is best-effort.
if ! command -v vhs >/dev/null 2>&1; then
  if curl -fsSL https://github.com/charmbracelet/vhs/releases/latest/download/vhs_Linux_x86_64.tar.gz \
       -o /tmp/vhs.tar.gz; then
    sudo tar -xz -C /usr/local/bin -f /tmp/vhs.tar.gz vhs 2>/dev/null \
      || tar -xz -C "$HOME/.local/bin" -f /tmp/vhs.tar.gz vhs 2>/dev/null \
      || echo "::warning::vhs extract failed; demo regeneration will be unavailable"
    rm -f /tmp/vhs.tar.gz
  else
    echo "::warning::vhs download failed; continuing without it"
  fi
fi

echo "==> seeding devnet config (docker/devnet/.env)..."
if [ -f docker/devnet/.env.example ] && [ ! -f docker/devnet/.env ]; then
  cp docker/devnet/.env.example docker/devnet/.env
fi

cat <<'EOF'

  OctraVPN dev container ready.

  Try these:
    bash docker/devnet/v3-smoke.sh                       # chain-side smoke
    bash docker/devnet/tailscale-interop/run-interop.sh  # interop test
    cd demo && bash run-demo.sh                          # regenerate VHS recordings

  Forwarded ports (Codespaces auto-forwards localhost):
    127.0.0.1:51823  -> oct:// portal / node3 admin
    127.0.0.1:51822  -> node2 admin GUI (login token: see node.toml)
    127.0.0.1:3000   -> Grafana dashboards (when deploy/observability is up)
    127.0.0.1:9090   -> Prometheus
EOF
