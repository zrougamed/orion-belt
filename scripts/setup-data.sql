-- Setup test data for Orion-Belt
-- This script creates test users, machines, and permissions

-- Wait for tables to be created by server migration
\echo 'Setting up test data...'

-- Create admin user
-- Note: You'll need to replace 'YOUR_SSH_PUBLIC_KEY' with an actual public key
INSERT INTO users (id, username, email, public_key, is_admin, created_at, updated_at)
VALUES (
    'admin-001',
    'admin',
    'admin@orion-belt.local',
    'ssh-rsa <key> admin@orion-belt',
    true,
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;

-- Create regular user
INSERT INTO users (id, username, email, public_key, is_admin, created_at, updated_at)
VALUES (
    'user-001',
    'developer',
    'developer@orion-belt.local',
    'ssh-rsa <key> developer@orion-belt',
    false,
    NOW(),
    NOW()
) ON CONFLICT (username) DO NOTHING;

-- Create machines
INSERT INTO machines (id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at)
VALUES (
    'machine-001',
    'web-01',
    'agent-web-01',
    22,
    '{"environment": "docker", "role": "web"}',
    NULL,
    false,
    NOW(),
    NOW(),
    NOW()
) ON CONFLICT (name) DO NOTHING;

INSERT INTO machines (id, name, hostname, port, tags, agent_id, is_active, last_seen_at, created_at, updated_at)
VALUES (
    'machine-002',
    'db-01',
    'agent-db-01',
    22,
    '{"environment": "docker", "role": "database"}',
    NULL,
    false,
    NOW(),
    NOW(),
    NOW()
) ON CONFLICT (name) DO NOTHING;

-- Grant admin full access to all machines
INSERT INTO permissions (id, user_id, machine_id, access_type, granted_by, granted_at, expires_at)
VALUES (
    'perm-001',
    'admin-001',
    'machine-001',
    'both',
    'admin-001',
    NOW(),
    NULL
) ON CONFLICT (id) DO NOTHING;

INSERT INTO permissions (id, user_id, machine_id, access_type, granted_by, granted_at, expires_at)
VALUES (
    'perm-002',
    'admin-001',
    'machine-002',
    'both',
    'admin-001',
    NOW(),
    NULL
) ON CONFLICT (id) DO NOTHING;

-- Grant developer limited access
INSERT INTO permissions (id, user_id, machine_id, access_type, granted_by, granted_at, expires_at)
VALUES (
    'perm-003',
    'user-001',
    'machine-001',
    'ssh',
    'admin-001',
    NOW(),
    NOW() + INTERVAL '30 days'
) ON CONFLICT (id) DO NOTHING;

-- Create a sample access request
INSERT INTO access_requests (id, user_id, machine_id, reason, duration, status, requested_at, reviewed_at, reviewed_by, expires_at)
VALUES (
    'req-001',
    'user-001',
    'machine-002',
    'Need to check database performance issues',
    3600,
    'pending',
    NOW(),
    NULL,
    NULL,
    NULL
) ON CONFLICT (id) DO NOTHING;

\echo 'Test data setup complete!'
\echo ''
\echo 'Created users:'
\echo '  - admin (admin@orion-belt.local) - Admin user'
\echo '  - developer (developer@orion-belt.local) - Regular user'
\echo ''
\echo 'Created machines:'
\echo '  - web-01 (agent-web-01:22)'
\echo '  - db-01 (agent-db-01:22)'
\echo ''
\echo 'Permissions:'
\echo '  - admin: Full access to all machines'
\echo '  - developer: SSH access to web-01 (expires in 30 days)'
\echo ''
\echo 'Pending access requests:'
\echo '  - developer requesting access to db-01'