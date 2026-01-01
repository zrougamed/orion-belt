#!/bin/bash

# Orion-Belt Docker Quick Start Script
# This script helps you quickly set up and test Orion-Belt with Docker

set -e

echo "╔════════════════════════════════════════════════════════════╗"
echo "║         Orion-Belt Docker Quick Start                     ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""

# Function to wait for service
wait_for_service() {
    local service=$1
    local max_attempts=30
    local attempt=0
    
    echo "Waiting for $service to be ready..."
    while [ $attempt -lt $max_attempts ]; do
        if docker compose ps | grep -q "$service.*Up"; then
            echo "✓ $service is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 2
    done
    
    echo "✗ $service failed to start"
    return 1
}

# Check if docker compose is installed
if ! command -v docker compose &> /dev/null; then
    echo "Error: docker compose is not installed"
    echo "Please install docker compose first: https://docs.docker.com/compose/install/"
    exit 1
fi

echo "Step 1: Building Docker images..."
docker compose build

echo ""
echo "Step 2: Starting services..."
docker compose up -d

echo ""
echo "Step 3: Waiting for services to initialize..."
sleep 5

# Wait specifically for agents to be ready
echo "Waiting for agents to start..."
for i in {1..30}; do
    if docker exec orion-agent-web-01 ls /root/.ssh/id_rsa.pub >/dev/null 2>&1 && \
       docker exec orion-agent-db-01 ls /root/.ssh/id_rsa.pub >/dev/null 2>&1; then
        echo "✓ Agents are ready"
        break
    fi
    if [ $i -eq 30 ]; then
        echo "⚠ Warning: Agents took too long to start"
    fi
    sleep 2
done

wait_for_service "postgres"
wait_for_service "server"

echo ""
echo "Step 4: Setting up test data..."
sleep 3

echo ""
echo "Step 5: Generating SSH keys for testing..."

# Generate SSH key in client container
docker exec orion-belt-client sh -c '
if [ ! -f /root/.ssh/id_rsa ]; then
    ssh-keygen -t rsa -f /root/.ssh/id_rsa -N ""
fi
'

# Get the public key
CLIENT_PUBLIC_KEY=$(docker exec orion-belt-client cat /root/.ssh/id_rsa.pub)

echo ""
echo "Step 6: Registering SSH keys in database..."

# Wait for setup container to finish
sleep 5

# Get agent public keys
WEB01_KEY=$(docker exec orion-agent-web-01 cat /root/.ssh/id_rsa.pub 2>/dev/null || echo "")
DB01_KEY=$(docker exec orion-agent-db-01 cat /root/.ssh/id_rsa.pub 2>/dev/null || echo "")

# Update users with actual SSH keys
docker exec orion-belt-db psql -U orionbelt -d orionbelt <<EOF
-- Update client users
UPDATE users SET public_key = '$CLIENT_PUBLIC_KEY' WHERE username = 'admin';
UPDATE users SET public_key = '$CLIENT_PUBLIC_KEY' WHERE username = 'developer';

-- Register agent users
INSERT INTO users (id, username, email, public_key, is_admin, created_at, updated_at)
VALUES (
    'agent-web-01-user',
    'web-01',
    'web-01@orion-belt.local',
    '$WEB01_KEY',
    false,
    NOW(),
    NOW()
) ON CONFLICT (username) DO UPDATE SET public_key = EXCLUDED.public_key;

INSERT INTO users (id, username, email, public_key, is_admin, created_at, updated_at)
VALUES (
    'agent-db-01-user',
    'db-01',
    'db-01@orion-belt.local',
    '$DB01_KEY',
    false,
    NOW(),
    NOW()
) ON CONFLICT (username) DO UPDATE SET public_key = EXCLUDED.public_key;

-- Update machine records
UPDATE machines SET agent_id = 'agent-web-01-user' WHERE name = 'web-01';
UPDATE machines SET agent_id = 'agent-db-01-user' WHERE name = 'db-01';
EOF

echo ""
echo "╔════════════════════════════════════════════════════════════╗"
echo "║                  Setup Complete! ✓                         ║"
echo "╚════════════════════════════════════════════════════════════╝"
echo ""
echo "Available test users:"
echo "  • admin - Full access to all machines"
echo "  • developer - Limited access to web-01"
echo ""
echo "Available machines:"
echo "  • web-01 (agent-web-01:22)"
echo "  • db-01 (agent-db-01:22)"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "Try these commands:"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "1. Enter the client container:"
echo "   docker exec -it orion-belt-client /bin/sh"
echo ""
echo "2. Connect to web-01 (as admin):"
echo "   /app/osh web-01"
echo ""
echo "3. Request access to db-01:"
echo "   /app/osh --request-access db-01 --reason \"Testing\" --duration 3600"
echo ""
echo "4. View logs:"
echo "   docker compose logs -f server"
echo ""
echo "5. Access database:"
echo "   docker exec -it orion-belt-db psql -U orionbelt -d orionbelt"
echo ""
echo "6. Stop services:"
echo "   docker compose down"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "For detailed testing instructions, see DOCKER_TESTING.md"
echo ""