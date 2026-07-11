#!/bin/sh
set -e
mkdir -p /etc/orion-belt
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
fi

cat <<'EOF'

Orion Belt agent installed.
────────────────────────────────────────
  1. Edit /etc/orion-belt/agent.yaml (gateway host, port 2222)
  2. systemctl enable --now orion-belt-agent
  3. Register this host with the server (UI Setup guide / Agents)

EOF
