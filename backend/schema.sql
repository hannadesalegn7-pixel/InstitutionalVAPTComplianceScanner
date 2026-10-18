CREATE TABLE IF NOT EXISTS scans (
  id TEXT PRIMARY KEY,
  target TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TIMESTAMP DEFAULT NOW(),
  completed_at TIMESTAMP,
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS findings (
  id SERIAL PRIMARY KEY,
  scan_id TEXT REFERENCES scans(id),
  finding_id TEXT,
  title TEXT,
  port INTEGER,
  protocol TEXT,
  service TEXT,
  severity TEXT,
  evidence TEXT,
  confidence TEXT,
  recommendation TEXT
);