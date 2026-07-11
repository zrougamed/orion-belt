#!/bin/sh
set -e
mkdir -p /etc/orion-belt
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  echo "Configure /etc/orion-belt/agent.yaml then: systemctl enable --now orion-belt-agent"
fi
