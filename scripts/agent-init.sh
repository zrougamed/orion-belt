#!/bin/sh

# Agent initialization script
# Generates SSH keys if needed and starts services

echo "[INIT] Starting agent initialization..."

# Generate SSH keys if they don't exist
if [ ! -f /root/.ssh/id_rsa ]; then
    echo "[INIT] Generating SSH keys..."
    mkdir -p /root/.ssh
    ssh-keygen -t rsa -f /root/.ssh/id_rsa -N "" -q
    chmod 600 /root/.ssh/id_rsa
    chmod 644 /root/.ssh/id_rsa.pub
    echo "[INIT] SSH keys generated"
else
    echo "[INIT] SSH keys already exist"
fi

# Show public key for debugging
echo "[INIT] Public key fingerprint:"
ssh-keygen -lf /root/.ssh/id_rsa.pub

# Generate SSH host keys for sshd
echo "[INIT] Generating SSH host keys..."
ssh-keygen -A

# Start SSH daemon
echo "[INIT] Starting SSH daemon..."
/usr/sbin/sshd

# Wait a moment for sshd to start
sleep 1

# Start the Orion-Belt agent
echo "[INIT] Starting Orion-Belt agent..."
exec /app/orion-belt-agent -c /app/config.yaml -l debug