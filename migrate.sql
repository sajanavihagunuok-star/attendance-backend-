-- migrate.sql
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT,
  role TEXT NOT NULL,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  id TEXT PRIMARY KEY,
  course_code TEXT,
  course_name TEXT,
  start_ts BIGINT,
  end_ts BIGINT,
  pin TEXT,
  created_at BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS attendance (
  id SERIAL PRIMARY KEY,
  session_id TEXT REFERENCES sessions(id) ON DELETE CASCADE,
  student_id TEXT,
  student_name TEXT,
  marked_at BIGINT,
  pin TEXT
);

CREATE INDEX IF NOT EXISTS idx_attendance_session ON attendance(session_id);
