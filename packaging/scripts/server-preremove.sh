#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop orion-belt-server 2>/dev/null || true
  systemctl disable orion-belt-server 2>/dev/null || true
fi
