-- migrations/002_alter_users.sql
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS name TEXT;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS institute_id UUID REFERENCES institutes(id) ON DELETE SET NULL;

ALTER TABLE users
  ADD COLUMN IF NOT EXISTS academic_year_id UUID;

-- Ensure password column exists with expected name used by controllers
ALTER TABLE users
  ADD COLUMN IF NOT EXISTS password TEXT;

-- Optional: create helpful indexes
CREATE INDEX IF NOT EXISTS idx_users_institute ON users(institute_id);
CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);