#!/bin/sh
set -e

if ! getent group orionbelt >/dev/null 2>&1; then
  groupadd --system orionbelt || addgroup -S orionbelt 2>/dev/null || true
fi
if ! getent passwd orionbelt >/dev/null 2>&1; then
  useradd --system --gid orionbelt --home-dir /var/lib/orion-belt --shell /usr/sbin/nologin orionbelt \
    || adduser -S -G orionbelt -h /var/lib/orion-belt -s /sbin/nologin orionbelt 2>/dev/null || true
fi

mkdir -p /var/lib/orion-belt/recordings /var/log/orion-belt /etc/orion-belt
chown -R orionbelt:orionbelt /var/lib/orion-belt /var/log/orion-belt 2>/dev/null || true
chmod 750 /var/lib/orion-belt /var/log/orion-belt /etc/orion-belt 2>/dev/null || true

if [ ! -f /etc/orion-belt/ssh_host_key ]; then
  if command -v ssh-keygen >/dev/null 2>&1; then
    ssh-keygen -t ed25519 -f /etc/orion-belt/ssh_host_key -N "" -C "orion-belt-host"
    chown orionbelt:orionbelt /etc/orion-belt/ssh_host_key /etc/orion-belt/ssh_host_key.pub 2>/dev/null || true
    chmod 600 /etc/orion-belt/ssh_host_key
  fi
fi

if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || true
  echo "Enable with: systemctl enable --now orion-belt-server"
fi
