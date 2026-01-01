-- Initialize Orion-Belt Database
-- This script is run automatically when the PostgreSQL container starts

-- Database is created by Docker environment variable
-- Tables will be created by the server migration on first start

-- Create extension for UUID support (optional, if needed)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Grant necessary permissions
GRANT ALL PRIVILEGES ON DATABASE orionbelt TO orionbelt;